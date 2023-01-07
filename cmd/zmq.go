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
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/cloudflare/goflow/v3/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
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
const ZMQ_MSG_VERSION = 2 // ntopng message version 2
const ZMQ_TOPIC = "flow"  // ntopng only really cares about the first character!

var MessageId uint32 = 0 // Every ZMQ message we send should have a uniq ID

type ZmqHeader struct {
	url       string
	version   uint8
	source_id uint8
	length    uint16
	msg_id    uint32
}

func (zs *ZmqState) NewZmqHeader(length uint16) *ZmqHeader {
	z := &ZmqHeader{
		url:       ZMQ_TOPIC,
		version:   ZMQ_MSG_VERSION,
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

/*
 * Converts a FlowMessage to JSON for ntopng
 */
func (zs *ZmqState) toJSON(flowMessage *flowmessage.FlowMessage) ([]byte, error) {
	ip6 := make(net.IP, net.IPv6len)
	ip4 := make(net.IP, net.IPv4len)
	hwaddr := make(net.HardwareAddr, 6)
	_hwaddr := make([]byte, binary.MaxVarintLen64)
	var icmp_type uint16
	retmap := make(map[string]interface{})

	// Stats + direction
	if flowMessage.FlowDirection == 0 {
		// ingress == 0
		retmap[strconv.Itoa(netflow.NFV9_FIELD_DIRECTION)] = 0
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_BYTES)] = flowMessage.Bytes
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_PKTS)] = flowMessage.Packets
	} else {
		// egress == 1
		retmap[strconv.Itoa(netflow.NFV9_FIELD_DIRECTION)] = 1
		retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_BYTES)] = flowMessage.Bytes
		retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_PKTS)] = flowMessage.Packets
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FIRST_SWITCHED)] = flowMessage.TimeFlowStart
	retmap[strconv.Itoa(netflow.NFV9_FIELD_LAST_SWITCHED)] = flowMessage.TimeFlowEnd

	// L4
	retmap[strconv.Itoa(netflow.NFV9_FIELD_PROTOCOL)] = flowMessage.Proto
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_SRC_PORT)] = flowMessage.SrcPort
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_DST_PORT)] = flowMessage.DstPort

	// Network
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_AS)] = flowMessage.SrcAS
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DST_AS)] = flowMessage.DstAS

	// Interfaces
	retmap[strconv.Itoa(netflow.NFV9_FIELD_INPUT_SNMP)] = flowMessage.InIf
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUTPUT_SNMP)] = flowMessage.OutIf
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FORWARDING_STATUS)] = flowMessage.ForwardingStatus
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_TOS)] = flowMessage.IPTos
	retmap[strconv.Itoa(netflow.NFV9_FIELD_TCP_FLAGS)] = flowMessage.TCPFlags
	retmap[strconv.Itoa(netflow.NFV9_FIELD_MIN_TTL)] = flowMessage.IPTTL

	// IP
	if flowMessage.Etype == 0x800 {
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 4
		// IPv4
		copy(ip4, flowMessage.SrcAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_ADDR)] = ip4.String()
		copy(ip4, flowMessage.DstAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_ADDR)] = ip4.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_PREFIX)] = flowMessage.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_PREFIX)] = flowMessage.DstNet
		copy(ip4, flowMessage.NextHop)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_NEXT_HOP)] = ip4.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_IDENT)] = flowMessage.FragmentId
		retmap[strconv.Itoa(netflow.NFV9_FIELD_FRAGMENT_OFFSET)] = flowMessage.FragmentOffset
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = flowMessage.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = flowMessage.DstNet
	} else {
		// 0x86dd IPv6
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 6
		copy(ip6, flowMessage.SrcAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_ADDR)] = ip6.String()
		copy(ip6, flowMessage.DstAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_ADDR)] = ip6.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = flowMessage.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = flowMessage.DstNet
		copy(ip6, flowMessage.NextHop)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_NEXT_HOP)] = ip6.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_FLOW_LABEL)] = flowMessage.IPv6FlowLabel
	}

	// ICMP
	icmp_type = uint16((uint16(flowMessage.IcmpType) << 8) + uint16(flowMessage.IcmpCode))
	retmap[strconv.Itoa(netflow.NFV9_FIELD_ICMP_TYPE)] = icmp_type

	// MAC
	binary.PutUvarint(_hwaddr, flowMessage.DstMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_DST_MAC)] = hwaddr.String()
	binary.PutUvarint(_hwaddr, flowMessage.SrcMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_SRC_MAC)] = hwaddr.String()

	// VLAN
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_VLAN)] = flowMessage.SrcVlan
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DST_VLAN)] = flowMessage.DstVlan

	// Flow Exporter IP
	if len(flowMessage.SamplerAddress) == 4 {
		copy(ip4, flowMessage.SamplerAddress)
		retmap[strconv.Itoa(netflow.IPFIX_FIELD_exporterIPv4Address)] = ip4.String()
	} else if len(flowMessage.SamplerAddress) == 16 {
		copy(ip6, flowMessage.SamplerAddress)
		retmap[strconv.Itoa(netflow.IPFIX_FIELD_exporterIPv6Address)] = ip6.String()
	}

	// convert to JSON
	jdata, err := json.Marshal(retmap)
	if err != nil {
		return jdata, err
	}

	if zs.compress {
		var zbuf bytes.Buffer
		z := zlib.NewWriter(&zbuf)
		if _, err = z.Write(jdata); err != nil {
			return []byte{}, err
		}
		if err = z.Close(); err != nil {
			return []byte{}, err
		}
		// must set jdata[0] = '\0' to indicate compressed data
		jdata = nil // zero current buffer
		jdata = append(jdata, 0)
		jdata = append(jdata, zbuf.Bytes()...)
	}
	return jdata, nil
}

func (zs *ZmqState) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		zs.SendZmqMessage(msg)
	}
}

func (zs *ZmqState) SendZmqMessage(flowMessage *flowmessage.FlowMessage) {
	var msg []byte
	var err error

	if zs.serialize == "pbuf" {
		msg, err = proto.Marshal(flowMessage)
	} else {
		msg, err = zs.toJSON(flowMessage)
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

	if zs.serialize == "json" {
		if zs.compress {
			log.Debugf("sent %d bytes of zlib json:\n%s", msg_len, hex.Dump(msg))
		} else {
			log.Debugf("sent %d bytes of json: %s", msg_len, string(msg))
		}
	} else {
		log.Debugf("sent %d bytes of pbuf:\n%s", msg_len, hex.Dump(msg))
	}
}
