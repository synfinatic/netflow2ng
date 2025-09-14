package transport

/*
 * ZMQ Transport for goflow2 supporting JSON/Protobuf/TLV
 *
 * The zmq Transport accepts formatted data from goflow2 and and sends over
 * [ZMQ](https://zeromq.org) and is intended to interop
 * with [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/), filling
 * the same role a [nProbe](https://www.ntop.org/products/netflow/nprobe/) or your
 * own solution.
 */

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"

	zmq "github.com/pebbe/zmq4"
)

/*
 * For more info on this you'll want to read:
 * include/ntop_typedefs.h, include/ntop_defines.h & src/ZMQCollectorInterface.cpp from
 * https://github.com/ntop/ntopng
 */
const ZMQ_MSG_VERSION_4 = 4 // ntop message version for zmq_msg_hdr_v3 in ntop_defines.h
const ZMQ_TOPIC = "flow"    // ntopng only really cares about the first character!

const ZMQ_MSG_V4_FLAG_TLV = 2
const ZMQ_MSG_V4_FLAG_COMPRESSED = 4

const (
	PBUF MsgFormat = iota
	JSON
	TLV
)

type MsgFormat int

type ZmqDriver struct {
	listenAddress string
	context       *zmq.Context
	publisher     *zmq.Socket
	sourceId      int
	msgType       MsgFormat
	compress      bool
	lock          *sync.RWMutex
}

// This is the latest header as of ntopng 6.4
type zmqHeaderV3 struct {
	url               string // must be 16 bytes long
	version           uint8  // use only with ZMQ_MSG_VERSION_4
	flags             uint8
	uncompressed_size uint32
	compressed_size   uint32
	msg_id            uint32
	source_id         uint32
}

var messageId uint32 = 0                         // Every ZMQ message we send should have a uniq ID
const maxMessageId uint32 = math.MaxUint32 - 100 // Wrap around before we hit max uint32

func (d *ZmqDriver) Prepare() error {
	// Ideally the code in transport.RegisterZmq would be in here, but I don't
	// know how to get the kong CLI flags into this function.
	return nil
}

func (d *ZmqDriver) Init() error {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.context, _ = zmq.NewContext()
	d.publisher, _ = d.context.NewSocket(zmq.PUB)
	if err := d.publisher.Bind(d.listenAddress); err != nil {
		log.Fatalf("Unable to bind: %s", err.Error())
	}

	log.Infof("Started ZMQ listener on: %s", d.listenAddress)

	//  Ensure subscriber connection has time to complete
	time.Sleep(time.Second)
	return nil
}

func (d *ZmqDriver) Send(key, data []byte) error {
	var err error
	orig_len := uint32(len(data))
	compressed_len := orig_len

	// Should only compress JSON
	if d.msgType == JSON && d.compress {
		var zbuf bytes.Buffer
		z := zlib.NewWriter(&zbuf)
		if _, err = z.Write(data); err != nil {
			return err
		}
		if err = z.Close(); err != nil {
			return err
		}
		// replace data with zlib compressed buffer
		data = zbuf.Bytes()
		compressed_len = uint32(len(data))
	}

	// Lock before accessing messageId or zmq header to ensure messageId is unique
	d.lock.Lock()
	defer d.lock.Unlock()

	if messageId == 1 {
		log.Info("Sending first ZMQ message.")
	} else if messageId%1000 == 0 {
		log.Debugf("Sending ZMQ message id %d.", messageId)
	} else if messageId >= maxMessageId {
		log.Debug("Wrapping message id back to 1 to avoid overflow")
		messageId = 1
	}
	header := d.newZmqHeaderV3(orig_len, compressed_len)

	// send our header with the topic first as a multi-part message
	hbytes, err := header.bytes()
	if err != nil {
		log.Errorf("Unable to serialize header: %s", err.Error())
		return err
	}

	bytes, err := d.publisher.SendBytes(hbytes, zmq.SNDMORE)
	if err != nil {
		log.Errorf("Unable to send header: %s", err.Error())
		return err
	}
	if bytes != len(hbytes) {
		log.Errorf("Wrote the wrong number of header bytes: %d", bytes)
		return err
	}

	// now send the actual payload
	if _, err = d.publisher.SendBytes(data, 0); err != nil {
		log.Error(err)
		return err
	}

	switch d.msgType {
	case PBUF:
		log.Tracef("Sent %d bytes of pbuf:\n%s", orig_len, hex.Dump(data))
	case JSON:
		if d.compress {
			log.Tracef("Sent %d bytes of zlib json:\n%s", compressed_len, hex.Dump(data))
		} else {
			log.Tracef("Sent %d bytes of json: %s", orig_len, string(data))
		}
	case TLV:
		log.Tracef("Sent %d bytes of ntop tlv:\n%s", orig_len, hex.Dump(data))
	default:
		log.Errorf("Sent %d bytes of unknown message type %d", orig_len, d.msgType)
	}

	return err
}

func (d *ZmqDriver) Close() error {
	// Do stuff here
	return nil
}

func (d *ZmqDriver) newZmqHeaderV3(orig_length uint32, compressed_len uint32) *zmqHeaderV3 {
	var flags uint8 = 0
	if d.msgType == TLV {
		flags |= ZMQ_MSG_V4_FLAG_TLV
	}
	if d.compress {
		flags |= ZMQ_MSG_V4_FLAG_COMPRESSED
	}

	z := &zmqHeaderV3{
		url:               ZMQ_TOPIC,
		version:           ZMQ_MSG_VERSION_4,
		flags:             flags,
		uncompressed_size: orig_length,
		compressed_size:   compressed_len,
		msg_id:            messageId,
		source_id:         uint32(d.sourceId),
	}
	messageId++

	return z
}

func (zh *zmqHeaderV3) bytes() ([]byte, error) {
	header := []byte{}
	bBuf := bytes.NewBuffer(header)

	url := []byte{}
	uBuf := bytes.NewBuffer(url)

	i, err := uBuf.Write([]byte(zh.url))
	if err != nil {
		return nil, err
	}

	// pad out to 16 bytes
	for ; i < 16; i++ {
		if _, err = uBuf.Write([]byte{0}); err != nil {
			return nil, err
		}
	}

	i, err = bBuf.Write(uBuf.Bytes())
	if err != nil {
		return nil, err
	}
	if i != 16 {
		return nil, fmt.Errorf("URL was %d bytes instead of 16", i)
	}

	if _, err = bBuf.Write([]byte{zh.version, zh.flags}); err != nil {
		return nil, err
	}
	// Need two bytes of padding to align next uint32 on 4-byte boundary
	if _, err = bBuf.Write([]byte{0, 0}); err != nil {
		return nil, err
	}

	// Both uncompressed_size and compressed_size need to be in little-endian
	le32Buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(le32Buf, zh.uncompressed_size)
	if _, err = bBuf.Write(le32Buf); err != nil {
		return nil, err
	}

	le32Buf = make([]byte, 4)
	binary.LittleEndian.PutUint32(le32Buf, zh.compressed_size)
	if _, err = bBuf.Write(le32Buf); err != nil {
		return nil, err
	}

	be32Buf := make([]byte, 4)
	binary.BigEndian.PutUint32(be32Buf, zh.msg_id)
	if _, err = bBuf.Write(be32Buf); err != nil {
		return nil, err
	}

	be32Buf = make([]byte, 4)
	binary.BigEndian.PutUint32(be32Buf, zh.source_id)
	if _, err = bBuf.Write(be32Buf); err != nil {
		return nil, err
	}
	return bBuf.Bytes(), nil
}
