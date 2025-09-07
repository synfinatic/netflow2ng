package formatter

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strconv"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
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

	ppMsg, ok := data.(*protoproducer.ProtoProducerMessage)
	if !ok {
		return key, nil, errors.New("skipping non-ProtoProducerMessage")
	}

	jdata, err := toJSON(ppMsg)
	if err != nil {
		return key, nil, err
	}
	return key, jdata, nil
}

/*
 * Converts a FlowMessage to JSON for ntopng
 *
 * TODO: Figure out how to get remapped IN/OUT bytes/pkts here. This still usesoriginal Bytes/Packets
 * fields, which are overwritten with FreeBSD NFv9 sensors.
 */
func toJSON(ppMsg *protoproducer.ProtoProducerMessage) ([]byte, error) {
	ip6 := make(net.IP, net.IPv6len)
	ip4 := make(net.IP, net.IPv4len)
	hwaddr := make(net.HardwareAddr, 6)
	_hwaddr := make([]byte, binary.MaxVarintLen64)
	var icmp_type uint16
	retmap := make(map[string]interface{})

	// Stats + direction
	// goflow2 only supports unidirectional flows. There is no Direction field and only one
	// Bytes/Packets field. Data flow is always Src -> Dst.
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DIRECTION)] = 0
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_BYTES)] = ppMsg.Bytes
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_PKTS)] = ppMsg.Packets

	// Goflow2 protobuf provides time in ns, but it ntopng expects time in seconds.
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FIRST_SWITCHED)] =
		uint32(ppMsg.TimeFlowStartNs / 1_000_000_000)
	retmap[strconv.Itoa(netflow.NFV9_FIELD_LAST_SWITCHED)] =
		uint32(ppMsg.TimeFlowEndNs / 1_000_000_000)

	// L4
	retmap[strconv.Itoa(netflow.NFV9_FIELD_PROTOCOL)] = ppMsg.Proto
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_SRC_PORT)] = ppMsg.SrcPort
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_DST_PORT)] = ppMsg.DstPort

	// Network
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_AS)] = ppMsg.SrcAs
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DST_AS)] = ppMsg.DstAs

	// Interfaces
	retmap[strconv.Itoa(netflow.NFV9_FIELD_INPUT_SNMP)] = ppMsg.InIf
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUTPUT_SNMP)] = ppMsg.OutIf
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FORWARDING_STATUS)] = ppMsg.ForwardingStatus
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_TOS)] = ppMsg.IpTos
	retmap[strconv.Itoa(netflow.NFV9_FIELD_TCP_FLAGS)] = ppMsg.TcpFlags
	retmap[strconv.Itoa(netflow.NFV9_FIELD_MIN_TTL)] = ppMsg.IpTtl

	// IP
	if ppMsg.Etype == 0x800 {
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 4
		// IPv4
		copy(ip4, ppMsg.SrcAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_ADDR)] = ip4.String()
		copy(ip4, ppMsg.DstAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_ADDR)] = ip4.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_PREFIX)] = ppMsg.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_PREFIX)] = ppMsg.DstNet
		copy(ip4, ppMsg.NextHop)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_NEXT_HOP)] = ip4.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_IDENT)] = ppMsg.FragmentId
		retmap[strconv.Itoa(netflow.NFV9_FIELD_FRAGMENT_OFFSET)] = ppMsg.FragmentOffset
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = ppMsg.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = ppMsg.DstNet
	} else {
		// 0x86dd IPv6
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 6
		copy(ip6, ppMsg.SrcAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_ADDR)] = ip6.String()
		copy(ip6, ppMsg.DstAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_ADDR)] = ip6.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = ppMsg.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = ppMsg.DstNet
		copy(ip6, ppMsg.NextHop)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_NEXT_HOP)] = ip6.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_FLOW_LABEL)] = ppMsg.Ipv6FlowLabel
	}

	// ICMP
	icmp_type = uint16((uint16(ppMsg.IcmpType) << 8) + uint16(ppMsg.IcmpCode))
	retmap[strconv.Itoa(netflow.NFV9_FIELD_ICMP_TYPE)] = icmp_type

	// MAC
	binary.PutUvarint(_hwaddr, ppMsg.DstMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_DST_MAC)] = hwaddr.String()
	binary.PutUvarint(_hwaddr, ppMsg.SrcMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_SRC_MAC)] = hwaddr.String()

	// VLAN
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_VLAN)] = ppMsg.SrcVlan
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DST_VLAN)] = ppMsg.DstVlan

	// Flow Exporter IP
	if len(ppMsg.SamplerAddress) == 4 {
		copy(ip4, ppMsg.SamplerAddress)
		retmap[strconv.Itoa(netflow.IPFIX_FIELD_exporterIPv4Address)] = ip4.String()
	} else if len(ppMsg.SamplerAddress) == 16 {
		copy(ip6, ppMsg.SamplerAddress)
		retmap[strconv.Itoa(netflow.IPFIX_FIELD_exporterIPv6Address)] = ip6.String()
	}

	// convert to JSON
	jdata, err := json.Marshal(retmap)
	if err != nil {
		return jdata, err
	}

	// TODO
	/*if zs.compress {
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
	}*/
	return jdata, nil
}
