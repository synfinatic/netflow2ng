package main

/*
 * ZMQ Transport v2 supporting JSON/Protobuf
 *
 * The zmq transport serializes the NetFlow/sFlow data as JSON objects or protobuf
 * and sends over [ZMQ](https://zeromq.org) and is intended to interop
 * with [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/), filling
 * the same role a [nProbe](https://www.ntop.org/products/netflow/nprobe/) or your
 * own solution.
 */

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	flowmessage "github.com/netsampler/goflow2/v2/pb"

	// nolint SA1019 the new google.golang.org/protobuf/proto package is not backwards compatible
	"github.com/golang/protobuf/proto"
	zmq "github.com/pebbe/zmq4"
)

type ZmqState struct {
	context   *zmq.Context
	publisher *zmq.Socket
	source_id int
	serialize string
	compress  bool
}

func StartZmqProducer() (*ZmqState, error) {
	context, _ := zmq.NewContext()
	publisher, _ := context.NewSocket(zmq.PUB)
	if err := publisher.Bind(rctx.cli.ListenZmq); err != nil {
		log.Fatalf("Unable to bind: %s", err.Error())
	}

	serialize := "json"
	if rctx.cli.Protobuf {
		serialize = "pbuf"
	} else if rctx.cli.TLV {
		serialize = "tlv"
	}

	log.Infof("Started ZMQ listener on: %s", rctx.cli.ListenZmq)

	//  Ensure subscriber connection has time to complete
	time.Sleep(time.Second)
	return &ZmqState{
		context:   context,
		publisher: publisher,
		source_id: int(rctx.cli.SourceId),
		serialize: serialize,
		compress:  rctx.cli.Compress,
	}, nil
}

/*
 * For more info on this you'll want to read:
 * include/ntop_typedefs.h, include/ntop_defines.h & src/ZMQCollectorInterface.cpp from
 * https://github.com/ntop/ntopng
 */
const ZMQ_MSG_VERSION_OLD = 2 // ntopng message version 2 for ntopng less than v6.4
const ZMQ_MSG_VERSION_TLV = 3 // ntop message version for TLV for ntopng v6.4 and later.
const ZMQ_TOPIC = "flow"      // ntopng only really cares about the first character!

var MessageId uint32 = 0 // Every ZMQ message we send should have a uniq ID

// This is zmq_msg_hdr_v1 from ntop_typedefs.h May want to update to zmq_msg_hdr_v2?
type ZmqHeader struct {
	url       string
	version   uint8
	source_id uint8
	length    uint16
	msg_id    uint32
}

func (zs *ZmqState) NewZmqHeader(length uint16) *ZmqHeader {
	var version uint8 = ZMQ_MSG_VERSION_TLV
	if !rctx.cli.TLV {
		version = ZMQ_MSG_VERSION_OLD
	}
	z := &ZmqHeader{
		url:       ZMQ_TOPIC,
		version:   version,
		source_id: uint8(rctx.cli.SourceId),
		length:    length,
		msg_id:    MessageId,
	}
	MessageId++
	return z
}

// Serialize our ZmqHeader into a byte array
func (zh *ZmqHeader) Bytes() ([]byte, error) {
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

func (zs *ZmqState) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		zs.SendZmqMessage(msg)
	}
}

func (zs *ZmqState) SendZmqMessage(flowMessage *flowmessage.FlowMessage) {
	var msg []byte
	var err error

	switch zs.serialize {
	case "pbuf":
		msg, err = proto.Marshal(flowMessage)
	case "json":
		//msg, err = zs.toJSON(flowMessage)
	default:
		//msg, err = zs.toTLV(flowMessage)
	}

	if err != nil {
		log.Error(err)
		return
	}
	msg_len := uint16(len(msg))

	header := zs.NewZmqHeader(msg_len)

	// send our header with the topic first as a multi-part message
	hbytes, err := header.Bytes()
	if err != nil {
		log.Errorf("Unable to serialize header: %s", err.Error())
		return
	}

	bytes, err := zs.publisher.SendBytes(hbytes, zmq.SNDMORE)
	if err != nil {
		log.Errorf("Unable to send header: %s", err.Error())
		return
	}
	if bytes != len(hbytes) {
		log.Errorf("Wrote the wrong number of header bytes: %d", bytes)
		return
	}

	// now send the actual JSON payload
	if _, err = zs.publisher.SendBytes(msg, 0); err != nil {
		log.Error(err)
		return
	}

	switch zs.serialize {
	case "pbuf":
		log.Debugf("sent %d bytes of pbuf:\n%s", msg_len, hex.Dump(msg))
	case "json":
		if zs.compress {
			log.Debugf("sent %d bytes of zlib json:\n%s", msg_len, hex.Dump(msg))
		} else {
			log.Debugf("sent %d bytes of json: %s", msg_len, string(msg))
		}
	default:
		log.Debugf("sent %d bytes of ntop tlv:\n%s", msg_len, hex.Dump(msg))
	}
}
