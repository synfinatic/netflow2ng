package formatter

import (
	"encoding/binary"
	"encoding/json"
	"net"
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
	var key []byte
	if dataIf, ok := data.(interface{ Key() []byte }); ok {
		key = dataIf.Key()
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
	ip6 := make(net.IP, net.IPv6len)
	ip4 := make(net.IP, net.IPv4len)
	hwaddr := make(net.HardwareAddr, 6)
	_hwaddr := make([]byte, binary.MaxVarintLen64)
	var icmp_type uint16
	retmap := make(map[string]interface{})
	// goflow2 FlowMessage protobuf is embedded in ExtendedFlowMessage
	baseFlow := extFlow.BaseFlow

	// Stats + direction
	// goflow2 only supports unidirectional flows. There is no Direction field and only one
	// Bytes/Packets field. Data flow is always Src -> Dst.
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DIRECTION)] = 0
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_BYTES)] = extFlow.InBytes
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_PKTS)] = extFlow.InPackets
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_BYTES)] = extFlow.OutBytes
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_PKTS)] = extFlow.OutPackets
	// Goflow2 protobuf provides time in ns, but it ntopng expects time in seconds.
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FIRST_SWITCHED)] =
		uint32(baseFlow.TimeFlowStartNs / 1_000_000_000)
	retmap[strconv.Itoa(netflow.NFV9_FIELD_LAST_SWITCHED)] =
		uint32(baseFlow.TimeFlowEndNs / 1_000_000_000)

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
	if baseFlow.Etype == 0x800 {
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 4
		// IPv4
		copy(ip4, baseFlow.SrcAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_ADDR)] = ip4.String()
		copy(ip4, baseFlow.DstAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_ADDR)] = ip4.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_PREFIX)] = baseFlow.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_PREFIX)] = baseFlow.DstNet
		copy(ip4, baseFlow.NextHop)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_NEXT_HOP)] = ip4.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_IDENT)] = baseFlow.FragmentId
		retmap[strconv.Itoa(netflow.NFV9_FIELD_FRAGMENT_OFFSET)] = baseFlow.FragmentOffset
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = baseFlow.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = baseFlow.DstNet
	} else {
		// 0x86dd IPv6
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 6
		copy(ip6, baseFlow.SrcAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_ADDR)] = ip6.String()
		copy(ip6, baseFlow.DstAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_ADDR)] = ip6.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = baseFlow.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = baseFlow.DstNet
		copy(ip6, baseFlow.NextHop)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_NEXT_HOP)] = ip6.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_FLOW_LABEL)] = baseFlow.Ipv6FlowLabel
	}

	// ICMP
	icmp_type = uint16((uint16(baseFlow.IcmpType) << 8) + uint16(baseFlow.IcmpCode))
	retmap[strconv.Itoa(netflow.NFV9_FIELD_ICMP_TYPE)] = icmp_type

	// MAC
	binary.PutUvarint(_hwaddr, baseFlow.DstMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_DST_MAC)] = hwaddr.String()
	binary.PutUvarint(_hwaddr, baseFlow.SrcMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_SRC_MAC)] = hwaddr.String()

	// VLAN
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_VLAN)] = baseFlow.SrcVlan
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DST_VLAN)] = baseFlow.DstVlan

	// Flow Exporter IP
	if len(baseFlow.SamplerAddress) == 4 {
		copy(ip4, baseFlow.SamplerAddress)
		retmap[strconv.Itoa(netflow.IPFIX_FIELD_exporterIPv4Address)] = ip4.String()
	} else if len(baseFlow.SamplerAddress) == 16 {
		copy(ip6, baseFlow.SamplerAddress)
		retmap[strconv.Itoa(netflow.IPFIX_FIELD_exporterIPv6Address)] = ip6.String()
	}

	// convert to JSON
	return json.Marshal(retmap)
}
