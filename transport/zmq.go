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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	zmq "github.com/pebbe/zmq4"
)

/*
 * For more info on this you'll want to read:
 * include/ntop_typedefs.h, include/ntop_defines.h & src/ZMQCollectorInterface.cpp from
 * https://github.com/ntop/ntopng
 */
const ZMQ_MSG_VERSION_OLD = 2 // ntopng message version 2 for ntopng less than v6.4
const ZMQ_MSG_VERSION_TLV = 3 // ntop message version for TLV for ntopng v6.4 and later.
const ZMQ_TOPIC = "flow"      // ntopng only really cares about the first character!

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

type zmqHeader struct {
	url       string
	version   uint8
	source_id uint8
	length    uint16
	msg_id    uint32
}

var messageId uint32 = 0 // Every ZMQ message we send should have a uniq ID

func (d *ZmqDriver) Prepare() error {
	// Ideally the code in transport.RegisterZmq would be in here, but I don't
	// know how to get the kong CLI flags into this function.
	return nil
}

func (d *ZmqDriver) Init() error {
	d.lock.Lock()
	d.context, _ = zmq.NewContext()
	d.publisher, _ = d.context.NewSocket(zmq.PUB)
	if err := d.publisher.Bind(d.listenAddress); err != nil {
		d.lock.Unlock()
		log.Fatalf("Unable to bind: %s", err.Error())
	}

	log.Infof("Started ZMQ listener on: %s", d.listenAddress)

	//  Ensure subscriber connection has time to complete
	time.Sleep(time.Second)
	d.lock.Unlock()
	return nil
}

func (d *ZmqDriver) Send(key, data []byte) error {
	var err error

	msg_len := uint16(len(data))
	header := d.newZmqHeader(msg_len)

	// send our header with the topic first as a multi-part message
	hbytes, err := header.bytes()
	if err != nil {
		log.Errorf("Unable to serialize header: %s", err.Error())
		return err
	}

	d.lock.Lock()
	bytes, err := d.publisher.SendBytes(hbytes, zmq.SNDMORE)
	if err != nil {
		log.Errorf("Unable to send header: %s", err.Error())
		d.lock.Unlock()
		return err
	}
	if bytes != len(hbytes) {
		log.Errorf("Wrote the wrong number of header bytes: %d", bytes)
		d.lock.Unlock()
		return err
	}

	// now send the actual payload
	if _, err = d.publisher.SendBytes(data, 0); err != nil {
		log.Error(err)
		d.lock.Unlock()
		return err
	}
	d.lock.Unlock()

	switch d.msgType {
	case PBUF:
		log.Debugf("sent %d bytes of pbuf:\n%s", msg_len, hex.Dump(data))
	case JSON:
		if d.compress {
			log.Debugf("sent %d bytes of zlib json:\n%s", msg_len, hex.Dump(data))
		} else {
			log.Debugf("sent %d bytes of json: %s", msg_len, string(data))
		}
	case TLV:
		log.Debugf("sent %d bytes of ntop tlv:\n%s", msg_len, hex.Dump(data))
	default:
		log.Errorf("sent %d bytes of unknown message type %d", msg_len, d.msgType)
	}

	return err
}

func (d *ZmqDriver) Close() error {
	// Do stuff here
	return nil
}

func (d *ZmqDriver) newZmqHeader(length uint16) *zmqHeader {
	var version uint8 = ZMQ_MSG_VERSION_TLV
	if d.msgType != TLV {
		version = ZMQ_MSG_VERSION_OLD
	}
	z := &zmqHeader{
		url:       ZMQ_TOPIC,
		version:   version,
		source_id: uint8(d.sourceId),
		length:    length,
		msg_id:    messageId,
	}
	messageId++

	return z
}

// Serialize our zmqHeader into a byte array
func (zh *zmqHeader) bytes() ([]byte, error) {
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

	if _, err = bBuf.Write([]byte{zh.version, zh.source_id}); err != nil {
		return nil, err
	}

	be16Buf := make([]byte, 2)
	binary.BigEndian.PutUint16(be16Buf, zh.length)
	if _, err = bBuf.Write(be16Buf); err != nil {
		return nil, err
	}

	be32Buf := make([]byte, 4)
	binary.BigEndian.PutUint32(be32Buf, zh.msg_id)
	if _, err = bBuf.Write(be32Buf); err != nil {
		return nil, err
	}
	return bBuf.Bytes(), nil
}
