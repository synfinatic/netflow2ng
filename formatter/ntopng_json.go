package formatter

import (
	"encoding/json"
	"strconv"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/synfinatic/netflow2ng/proto"
)

type NtopngJson struct {
}

func (d *NtopngJson) Prepare() error {
	return nil
}

func (d *NtopngJson) Init() error {
	return nil
}

func (d *NtopngJson) Format(data interface{}) ([]byte, []byte, error) {
	// The Transport might use "key", but we don't care about it here.
	// Key() may panic if the ProtoProducerMessage was not initialized via the goflow2 producer
	// pipeline (e.g., in tests); recover so that key stays nil and formatting continues.
	var key []byte
	if dataIf, ok := data.(interface{ Key() []byte }); ok {
		func() {
			defer func() { _ = recover() }()
			key = dataIf.Key()
		}()
	}

	extFlowMsg, err := castToExtendedFlowMsg(data)
	if err != nil {
		return key, nil, err
	}

	jdata, err := d.toJSON(extFlowMsg)
	if err != nil {
		return key, nil, err
	}
	return key, jdata, nil
}

/*
 * Converts a FlowMessage to JSON for ntopng
 *
 * ExtendedFlowMessage is our protobuf message that contains the remapped IN/OUT fields
 * using Formatter.MappingYamlStr
 */
func (d *NtopngJson) toJSON(extFlow *proto.ExtendedFlowMessage) ([]byte, error) {
	fd := extractFlowData(extFlow)
	baseFlow := extFlow.BaseFlow
	retmap := make(map[string]interface{})

	// Stats + direction
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DIRECTION)] = 0
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_BYTES)] = fd.inBytes
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_PKTS)] = fd.inPackets
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_BYTES)] = fd.outBytes
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_PKTS)] = fd.outPackets
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FIRST_SWITCHED)] = fd.startSec
	retmap[strconv.Itoa(netflow.NFV9_FIELD_LAST_SWITCHED)] = fd.endSec

	// L4
	retmap[strconv.Itoa(netflow.NFV9_FIELD_PROTOCOL)] = baseFlow.Proto
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_SRC_PORT)] = baseFlow.SrcPort
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_DST_PORT)] = baseFlow.DstPort

	// Network
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_AS)] = baseFlow.SrcAs
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DST_AS)] = baseFlow.DstAs

	// Interfaces
	retmap[strconv.Itoa(netflow.NFV9_FIELD_INPUT_SNMP)] = baseFlow.InIf
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUTPUT_SNMP)] = baseFlow.OutIf
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FORWARDING_STATUS)] = baseFlow.ForwardingStatus
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_TOS)] = baseFlow.IpTos
	retmap[strconv.Itoa(netflow.NFV9_FIELD_TCP_FLAGS)] = baseFlow.TcpFlags
	retmap[strconv.Itoa(netflow.NFV9_FIELD_MIN_TTL)] = baseFlow.IpTtl

	// IP
	if fd.isIPv4 {
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 4
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_ADDR)] = fd.srcIP
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_ADDR)] = fd.dstIP
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_PREFIX)] = fd.srcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_PREFIX)] = fd.dstNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_NEXT_HOP)] = fd.nextHop
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_IDENT)] = fd.fragmentId
		retmap[strconv.Itoa(netflow.NFV9_FIELD_FRAGMENT_OFFSET)] = fd.fragmentOffset
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = fd.srcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = fd.dstNet
	} else {
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 6
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_ADDR)] = fd.srcIP
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_ADDR)] = fd.dstIP
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = fd.srcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = fd.dstNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_NEXT_HOP)] = fd.nextHop
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_FLOW_LABEL)] = fd.ipv6FlowLabel
	}

	// ICMP
	retmap[strconv.Itoa(netflow.NFV9_FIELD_ICMP_TYPE)] = fd.icmpType

	// MAC
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_DST_MAC)] = fd.dstMac
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_SRC_MAC)] = fd.srcMac

	// VLAN
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_VLAN)] = fd.srcVlan
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DST_VLAN)] = fd.dstVlan

	// Flow Exporter IP
	if fd.samplerIPStr != "" {
		retmap[strconv.Itoa(fd.samplerIPFieldID)] = fd.samplerIPStr
	}

	// convert to JSON
	return json.Marshal(retmap)
}
