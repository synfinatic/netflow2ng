package formatter

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	flowmessage "github.com/netsampler/goflow2/v2/pb"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
)

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
	var key []byte
	if dataIf, ok := data.(interface{ Key() []byte }); ok {
		key = dataIf.Key()
	}

	flowMsg, ok := data.(*protoproducer.ProtoProducerMessage)
	if !ok {
		return key, nil, errors.New("skipping non-ProtoProducerMessage")
	}

	tdata, err := toTLV(&flowMsg.FlowMessage)
	if err != nil {
		return key, nil, err
	}
	return key, tdata, nil
}

/*
 * Converts a FlowMessage to ntop's TLV format
 *
 * TODO: Figure out how to get remapped IN/OUT bytes/pkts here. This still usesoriginal Bytes/Packets
 * fields, which are overwritten with FreeBSD NFv9 sensors.
 */
func toTLV(flowMessage *flowmessage.FlowMessage) ([]byte, error) {
	ip6 := make(net.IP, net.IPv6len)
	ip4 := make(net.IP, net.IPv4len)
	hwaddr := make(net.HardwareAddr, 6)
	_hwaddr := make([]byte, binary.MaxVarintLen64)
	var icmp_type uint16
	var items []NdpiItem

	// Stats + direction
	// goflow2 only supports unidirectional flows. There is no Direction field and only one
	// Bytes/Packets field. Data flow is always Src -> Dst
	items = append(items,
		NdpiItem{Key: netflow.NFV9_FIELD_DIRECTION, Value: 0},
		NdpiItem{Key: netflow.NFV9_FIELD_IN_BYTES, Value: flowMessage.Bytes},
		NdpiItem{Key: netflow.NFV9_FIELD_IN_PKTS, Value: flowMessage.Packets},
	)
	// Goflow2 protobuf provides time in ns, but it ntopng expects time in seconds.
	items = append(items,
		NdpiItem{Key: netflow.NFV9_FIELD_FIRST_SWITCHED,
			Value: uint32(flowMessage.TimeFlowStartNs / 1_000_000_000)},
		NdpiItem{Key: netflow.NFV9_FIELD_LAST_SWITCHED,
			Value: uint32(flowMessage.TimeFlowEndNs / 1_000_000_000)},
	)

	items = append(items,
		// L4
		NdpiItem{Key: netflow.NFV9_FIELD_PROTOCOL, Value: flowMessage.Proto},
		NdpiItem{Key: netflow.NFV9_FIELD_L4_SRC_PORT, Value: flowMessage.SrcPort},
		NdpiItem{Key: netflow.NFV9_FIELD_L4_DST_PORT, Value: flowMessage.DstPort},
		// Network
		NdpiItem{Key: netflow.NFV9_FIELD_SRC_AS, Value: flowMessage.SrcAs},
		NdpiItem{Key: netflow.NFV9_FIELD_DST_AS, Value: flowMessage.DstAs},

		// Interfaces
		NdpiItem{Key: netflow.NFV9_FIELD_INPUT_SNMP, Value: flowMessage.InIf},
		NdpiItem{Key: netflow.NFV9_FIELD_OUTPUT_SNMP, Value: flowMessage.OutIf},
		NdpiItem{Key: netflow.NFV9_FIELD_FORWARDING_STATUS, Value: flowMessage.ForwardingStatus},
		NdpiItem{Key: netflow.NFV9_FIELD_SRC_TOS, Value: flowMessage.IpTos},
		NdpiItem{Key: netflow.NFV9_FIELD_TCP_FLAGS, Value: flowMessage.TcpFlags},
		NdpiItem{Key: netflow.NFV9_FIELD_MIN_TTL, Value: flowMessage.IpTtl},
	)

	// IP
	if flowMessage.Etype == 0x800 {
		// IPv4
		items = append(items,
			NdpiItem{Key: netflow.NFV9_FIELD_IP_PROTOCOL_VERSION, Value: 4},
			NdpiItem{Key: netflow.NFV9_FIELD_IPV4_SRC_PREFIX, Value: flowMessage.SrcNet},
			NdpiItem{Key: netflow.NFV9_FIELD_IPV4_DST_PREFIX, Value: flowMessage.DstNet},
			NdpiItem{Key: netflow.NFV9_FIELD_IPV4_IDENT, Value: flowMessage.FragmentId},
			NdpiItem{Key: netflow.NFV9_FIELD_FRAGMENT_OFFSET, Value: flowMessage.FragmentOffset},
			NdpiItem{Key: netflow.NFV9_FIELD_IPV6_SRC_MASK, Value: flowMessage.SrcNet},
			NdpiItem{Key: netflow.NFV9_FIELD_IPV6_DST_MASK, Value: flowMessage.DstNet},
		)
		copy(ip4, flowMessage.SrcAddr)
		items = append(items, NdpiItem{Key: netflow.NFV9_FIELD_IPV4_SRC_ADDR, Value: ip4.String()})
		copy(ip4, flowMessage.DstAddr)
		items = append(items, NdpiItem{Key: netflow.NFV9_FIELD_IPV4_DST_ADDR, Value: ip4.String()})
		copy(ip4, flowMessage.NextHop)
		items = append(items, NdpiItem{Key: netflow.NFV9_FIELD_IPV4_NEXT_HOP, Value: ip4.String()})

	} else {
		// 0x86dd IPv6
		items = append(items,
			NdpiItem{Key: netflow.NFV9_FIELD_IP_PROTOCOL_VERSION, Value: 6},
			NdpiItem{Key: netflow.NFV9_FIELD_IPV6_SRC_MASK, Value: flowMessage.SrcNet},
			NdpiItem{Key: netflow.NFV9_FIELD_IPV6_DST_MASK, Value: flowMessage.DstNet},
			NdpiItem{Key: netflow.NFV9_FIELD_IPV6_FLOW_LABEL, Value: flowMessage.Ipv6FlowLabel},
		)
		copy(ip6, flowMessage.SrcAddr)
		items = append(items, NdpiItem{Key: netflow.NFV9_FIELD_IPV6_SRC_ADDR, Value: ip6.String()})
		copy(ip6, flowMessage.DstAddr)
		items = append(items, NdpiItem{Key: netflow.NFV9_FIELD_IPV6_DST_ADDR, Value: ip6.String()})
		copy(ip6, flowMessage.NextHop)
		items = append(items, NdpiItem{Key: netflow.NFV9_FIELD_IPV6_NEXT_HOP, Value: ip6.String()})
	}

	// ICMP
	icmp_type = uint16((uint16(flowMessage.IcmpType) << 8) + uint16(flowMessage.IcmpCode))
	items = append(items, NdpiItem{Key: netflow.NFV9_FIELD_ICMP_TYPE, Value: icmp_type})

	// MAC
	binary.PutUvarint(_hwaddr, flowMessage.DstMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	items = append(items, NdpiItem{Key: netflow.NFV9_FIELD_IN_DST_MAC, Value: hwaddr.String()})
	binary.PutUvarint(_hwaddr, flowMessage.SrcMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	items = append(items, NdpiItem{Key: netflow.NFV9_FIELD_OUT_SRC_MAC, Value: hwaddr.String()})

	// VLAN
	items = append(items,
		NdpiItem{Key: netflow.NFV9_FIELD_SRC_VLAN, Value: flowMessage.SrcVlan},
		NdpiItem{Key: netflow.NFV9_FIELD_DST_VLAN, Value: flowMessage.DstVlan},
	)

	// Flow Exporter IP
	if len(flowMessage.SamplerAddress) == 4 {
		copy(ip4, flowMessage.SamplerAddress)
		items = append(items, NdpiItem{Key: netflow.IPFIX_FIELD_exporterIPv4Address, Value: ip4.String()})
	} else if len(flowMessage.SamplerAddress) == 16 {
		copy(ip6, flowMessage.SamplerAddress)
		items = append(items, NdpiItem{Key: netflow.IPFIX_FIELD_exporterIPv6Address, Value: ip6.String()})
	}

	// Serialize and make a flow record.
	tlvbuf, err := SerializeTlvRecord(items)
	if err != nil {
		return tlvbuf, err
	}

	return tlvbuf, nil
}
