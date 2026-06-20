package formatter

/*
 * Encapulate the TLV format accepted by ntop tools.
 *
 * Ntopng parses this format using ndpi_serializer.c code in the ntop nDPI repository
 * This code implements a subset of that format.
 *
 * A flow message a 2-byte header (always 0x01 0x01), a list of key/value pairs called 'items'
 * and then a final end_of_record byte. For each item, the format is:
 * Types        - 1 byte. left most 4 bit are key type, right most are value type.
 * Key Length   - 2 bytes. Optional, only used when key type is string.
 * Key          - 0-4 bytes if a uint/int type, "Key Length" bytes if string.
 * Value Length - 2 bytes. Optional, only used when value type is string.
 * Value        - 0-4 bytes if a uint/int type, "Value Length" bytes if string.
 *
 * Examples:
 * 0x22 0x0a 0x0b
 * ^^^ K is unit8, V is unit8. K=10,V=11.
 * 0x23 0x0b 0x1f46
 * ^^^ K is unit8, V is unit16, K=11, V=8006
 * 0x2b 0x82 0x000c 0x31 0x37 0x32 0x2e 0x31 0x36 0x2e 0x31 0x2e 0x32 0x35 0x34
 * ^^^ K is unit8, V is string, K=130, v length is 12, V='172.16.1.254'
 *
 * Another feature of this format is that numeric keys and values are reduced to a smaller size
 * if possible. Example: A uint64 value of '8006' will be serialized as value type of uint16 and
 * only two bytes used for the value.
 */

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/synfinatic/netflow2ng/proto"
)

// Taken From ntop nDPI's ndpi_typedefs.h. We're only using a subset.
const (
	//ndpi_serialization_unknown        uint8 = 0
	ndpi_serialization_end_of_record uint8 = 1
	ndpi_serialization_uint8         uint8 = 2
	ndpi_serialization_uint16        uint8 = 3
	ndpi_serialization_uint32        uint8 = 4
	ndpi_serialization_uint64        uint8 = 5
	ndpi_serialization_int8          uint8 = 6
	ndpi_serialization_int16         uint8 = 7
	ndpi_serialization_int32         uint8 = 8
	ndpi_serialization_int64         uint8 = 9
	//ndpi_serialization_float          uint8 = 10
	ndpi_serialization_string uint8 = 11
	//ndpi_serialization_start_of_block uint8 = 12
	//ndpi_serialization_end_of_block   uint8 = 13
	//ndpi_serialization_start_of_list  uint8 = 14
	//ndpi_serialization_end_of_list    uint8= 15
)

// According to the nDPI library, key's can only be uint32 or string. But for our use all keys
// will be from netflow/nfv9.go, so always uint16.
type ndpiItem struct {
	Key   uint16
	Value interface{}
}

type NtopngTlv struct {
}

func (d *NtopngTlv) Prepare() error {
	return nil
}

func (d *NtopngTlv) Init() error {
	return nil
}

func (d *NtopngTlv) Format(data interface{}) ([]byte, []byte, error) {
	// The Transport might use "key", but we don't care about it here.
	// Key() may panic if the ProtoProducerMessage was not initialized via the goflow2 producer
	// pipeline (e.g., in tests); recover so that key stays nil and formatting continues.
	var key []byte
	if dataIf, ok := data.(interface{ Key() []byte }); ok {
		func() {
			defer func() { recover() }()
			key = dataIf.Key()
		}()
	}

	extFlowMsg, err := castToExtendedFlowMsg(data)
	if err != nil {
		return key, nil, errors.New("skipping non-ExtendedFlowMessage")
	}

	tdata, err := d.toTLV(extFlowMsg)
	if err != nil {
		return key, nil, err
	}
	return key, tdata, nil
}

/*
 * Converts a FlowMessage to ntop's TLV format
 *
 * ExtendedFlowMessage is our protobuf message that contains the remapped IN/OUT fields
 * using Formatter.MappingYamlStr
 */
func (d *NtopngTlv) toTLV(extFlow *proto.ExtendedFlowMessage) ([]byte, error) {
	fd := extractFlowData(extFlow)
	baseFlow := extFlow.BaseFlow
	var items []ndpiItem

	// Stats + direction
	items = append(items,
		ndpiItem{Key: netflow.NFV9_FIELD_DIRECTION, Value: 0},
		ndpiItem{Key: netflow.NFV9_FIELD_IN_BYTES, Value: fd.inBytes},
		ndpiItem{Key: netflow.NFV9_FIELD_IN_PKTS, Value: fd.inPackets},
		ndpiItem{Key: netflow.NFV9_FIELD_OUT_BYTES, Value: fd.outBytes},
		ndpiItem{Key: netflow.NFV9_FIELD_OUT_PKTS, Value: fd.outPackets},
	)
	items = append(items,
		ndpiItem{Key: netflow.NFV9_FIELD_FIRST_SWITCHED, Value: fd.startSec},
		ndpiItem{Key: netflow.NFV9_FIELD_LAST_SWITCHED, Value: fd.endSec},
	)

	items = append(items,
		// L4
		ndpiItem{Key: netflow.NFV9_FIELD_PROTOCOL, Value: baseFlow.Proto},
		ndpiItem{Key: netflow.NFV9_FIELD_L4_SRC_PORT, Value: baseFlow.SrcPort},
		ndpiItem{Key: netflow.NFV9_FIELD_L4_DST_PORT, Value: baseFlow.DstPort},
		// Network
		ndpiItem{Key: netflow.NFV9_FIELD_SRC_AS, Value: baseFlow.SrcAs},
		ndpiItem{Key: netflow.NFV9_FIELD_DST_AS, Value: baseFlow.DstAs},

		// Interfaces
		ndpiItem{Key: netflow.NFV9_FIELD_INPUT_SNMP, Value: baseFlow.InIf},
		ndpiItem{Key: netflow.NFV9_FIELD_OUTPUT_SNMP, Value: baseFlow.OutIf},
		ndpiItem{Key: netflow.NFV9_FIELD_FORWARDING_STATUS, Value: baseFlow.ForwardingStatus},
		ndpiItem{Key: netflow.NFV9_FIELD_SRC_TOS, Value: baseFlow.IpTos},
		ndpiItem{Key: netflow.NFV9_FIELD_TCP_FLAGS, Value: baseFlow.TcpFlags},
		ndpiItem{Key: netflow.NFV9_FIELD_MIN_TTL, Value: baseFlow.IpTtl},
	)

	// IP
	if fd.isIPv4 {
		items = append(items,
			ndpiItem{Key: netflow.NFV9_FIELD_IP_PROTOCOL_VERSION, Value: 4},
			ndpiItem{Key: netflow.NFV9_FIELD_IPV4_SRC_PREFIX, Value: fd.srcNet},
			ndpiItem{Key: netflow.NFV9_FIELD_IPV4_DST_PREFIX, Value: fd.dstNet},
			ndpiItem{Key: netflow.NFV9_FIELD_IPV4_IDENT, Value: fd.fragmentId},
			ndpiItem{Key: netflow.NFV9_FIELD_FRAGMENT_OFFSET, Value: fd.fragmentOffset},
			ndpiItem{Key: netflow.NFV9_FIELD_IPV6_SRC_MASK, Value: fd.srcNet},
			ndpiItem{Key: netflow.NFV9_FIELD_IPV6_DST_MASK, Value: fd.dstNet},
		)
		items = append(items, ndpiItem{Key: netflow.NFV9_FIELD_IPV4_SRC_ADDR, Value: fd.srcIP})
		items = append(items, ndpiItem{Key: netflow.NFV9_FIELD_IPV4_DST_ADDR, Value: fd.dstIP})
		items = append(items, ndpiItem{Key: netflow.NFV9_FIELD_IPV4_NEXT_HOP, Value: fd.nextHop})
	} else {
		items = append(items,
			ndpiItem{Key: netflow.NFV9_FIELD_IP_PROTOCOL_VERSION, Value: 6},
			ndpiItem{Key: netflow.NFV9_FIELD_IPV6_SRC_MASK, Value: fd.srcNet},
			ndpiItem{Key: netflow.NFV9_FIELD_IPV6_DST_MASK, Value: fd.dstNet},
			ndpiItem{Key: netflow.NFV9_FIELD_IPV6_FLOW_LABEL, Value: fd.ipv6FlowLabel},
		)
		items = append(items, ndpiItem{Key: netflow.NFV9_FIELD_IPV6_SRC_ADDR, Value: fd.srcIP})
		items = append(items, ndpiItem{Key: netflow.NFV9_FIELD_IPV6_DST_ADDR, Value: fd.dstIP})
		items = append(items, ndpiItem{Key: netflow.NFV9_FIELD_IPV6_NEXT_HOP, Value: fd.nextHop})
	}

	// ICMP
	items = append(items, ndpiItem{Key: netflow.NFV9_FIELD_ICMP_TYPE, Value: fd.icmpType})

	// MAC
	items = append(items, ndpiItem{Key: netflow.NFV9_FIELD_IN_DST_MAC, Value: fd.dstMac})
	items = append(items, ndpiItem{Key: netflow.NFV9_FIELD_OUT_SRC_MAC, Value: fd.srcMac})

	// VLAN
	items = append(items,
		ndpiItem{Key: netflow.NFV9_FIELD_SRC_VLAN, Value: fd.srcVlan},
		ndpiItem{Key: netflow.NFV9_FIELD_DST_VLAN, Value: fd.dstVlan},
	)

	// Flow Exporter IP
	if fd.samplerIPStr != "" {
		items = append(items, ndpiItem{Key: uint16(fd.samplerIPFieldID), Value: fd.samplerIPStr})
	}

	// Serialize and make a flow record.
	tlvbuf, err := serializeTlvRecord(items)
	if err != nil {
		return tlvbuf, err
	}

	return tlvbuf, nil
}

// minimalBytesUint encodes v using the smallest unsigned integer type that fits.
// This matches ndpi_serialize_* functions in nDPI which compact to smallest possible size.
func minimalBytesUint(v uint64) (minType uint8, minBytes []byte) {
	if v <= 0xff {
		minType = ndpi_serialization_uint8
		minBytes = []byte{byte(v)}
	} else if v <= 0xffff {
		minType = ndpi_serialization_uint16
		minBytes = make([]byte, 2)
		binary.BigEndian.PutUint16(minBytes, uint16(v))
	} else if v <= 0xffffffff {
		minType = ndpi_serialization_uint32
		minBytes = make([]byte, 4)
		binary.BigEndian.PutUint32(minBytes, uint32(v))
	} else {
		minType = ndpi_serialization_uint64
		minBytes = make([]byte, 8)
		binary.BigEndian.PutUint64(minBytes, v)
	}
	return minType, minBytes
}

// minimalBytesInt encodes v using the smallest signed integer type that fits.
// This matches ndpi_serialize_* functions in nDPI which compact to smallest possible size.
func minimalBytesInt(v int64) (minType uint8, minBytes []byte) {
	if v >= math.MinInt8 && v <= math.MaxInt8 {
		minType = ndpi_serialization_int8
		minBytes = []byte{byte(v)}
	} else if v >= math.MinInt16 && v <= math.MaxInt16 {
		minType = ndpi_serialization_int16
		minBytes = make([]byte, 2)
		binary.BigEndian.PutUint16(minBytes, uint16(v))
	} else if v >= math.MinInt32 && v <= math.MaxInt32 {
		minType = ndpi_serialization_int32
		minBytes = make([]byte, 4)
		binary.BigEndian.PutUint32(minBytes, uint32(v))
	} else {
		minType = ndpi_serialization_int64
		minBytes = make([]byte, 8)
		binary.BigEndian.PutUint64(minBytes, uint64(v))
	}
	return minType, minBytes
}

func serializeTlvItem(item ndpiItem) ([]byte, error) {
	buf := new(bytes.Buffer)
	keyType := uint8(0)
	valueType := uint8(0)
	var minBytes []byte
	var err error

	keyType, minBytes = minimalBytesUint(uint64(item.Key))
	if err = binary.Write(buf, binary.BigEndian, minBytes); err != nil {
		return nil, err
	}

	switch v := item.Value.(type) {
	case int, int8, int16, int32, int64:
		vi := int64(reflect.ValueOf(v).Int())
		valueType, minBytes = minimalBytesInt(vi)
		if err = binary.Write(buf, binary.BigEndian, minBytes); err != nil {
			return nil, err
		}
	case uint, uint8, uint16, uint32, uint64:
		vu := reflect.ValueOf(v).Uint()
		valueType, minBytes = minimalBytesUint(vu)
		if err = binary.Write(buf, binary.BigEndian, minBytes); err != nil {
			return nil, err
		}
	case string:
		valueType = ndpi_serialization_string
		strLen := uint16(len(v))
		if err = binary.Write(buf, binary.BigEndian, strLen); err != nil {
			return nil, err
		}
		if _, err = buf.Write([]byte(v)); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unknown value type for key: %s. Type was: %T",
			netflow.NFv9TypeToString(uint16(item.Key)), item.Value)
	}

	// Write types byte first
	bytes := buf.Bytes()
	ret := append([]byte{(keyType << 4) | (valueType & 0x0F)}, bytes...)
	return ret, nil
}

func serializeTlvRecord(items []ndpiItem) ([]byte, error) {
	var out bytes.Buffer
	// ndpi_init_serializer_ll() in ndpi_serializer.c writes out 0x01 0x01 at the beginning of each TLV record.
	out.WriteByte(0x01)
	out.WriteByte(0x01)

	for _, it := range items {
		b, err := serializeTlvItem(it)

		if err != nil {
			return nil, err
		}
		out.Write(b)
	}
	out.WriteByte(ndpi_serialization_end_of_record)

	return out.Bytes(), nil
}
