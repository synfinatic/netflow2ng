package formatter

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/netsampler/goflow2/v2/format"
	gf2proto "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/sirupsen/logrus"
	"github.com/synfinatic/netflow2ng/proto"
	googleproto "google.golang.org/protobuf/proto"
)

const (
	PROTO_REMAPPED_IN_BYTES  = 200
	PROTO_REMAPPED_IN_PKTS   = 201
	PROTO_REMAPPED_OUT_BYTES = 202
	PROTO_REMAPPED_OUT_PKTS  = 203
)

//go:embed mapping.yaml
var MappingYaml string
var log *logrus.Logger //nolint:unused

func SetLogger(l *logrus.Logger) {
	log = l
}

func init() {
	format.RegisterFormatDriver("ntopjson", &NtopngJson{})
	format.RegisterFormatDriver("ntoptlv", &NtopngTlv{})
}

func castToExtendedFlowMsg(data interface{}) (*proto.ExtendedFlowMessage, error) {

	ppm, ok := data.(*gf2proto.ProtoProducerMessage)
	if !ok {
		return nil, errors.New("could not cast Format data to ProtoProducerMessage")
	}

	// Marshal to binary
	bin, err := googleproto.Marshal(ppm)
	if err != nil {
		return nil, fmt.Errorf("could not marshal ProtoProducerMessage to binary: %w", err)
	}
	// Unmarshal into your custom struct
	efm := &proto.ExtendedFlowMessage{}
	if err := googleproto.Unmarshal(bin, efm); err != nil {
		return nil, fmt.Errorf("could not unmarshal binary to ExtendedFlowMsg: %w", err)
	}

	// Need to assign the BaseFlow field explicitly, as it is not Unmarshalled automatically.
	efm.BaseFlow = &ppm.FlowMessage

	return efm, nil
}

// flowData holds pre-computed fields shared by both the JSON and TLV formatters.
type flowData struct {
	// Traffic stats (with NFv5 fallback for inBytes/inPackets)
	inBytes    uint64
	inPackets  uint64
	outBytes   uint64
	outPackets uint64
	startSec   uint32
	endSec     uint32

	// L3/L4 common
	icmpType uint16
	srcMac   string
	dstMac   string
	srcVlan  uint32
	dstVlan  uint32

	// IP (common to v4 and v6)
	isIPv4  bool
	srcIP   string
	dstIP   string
	nextHop string
	srcNet  uint32
	dstNet  uint32

	// IPv4-specific
	fragmentId     uint32
	fragmentOffset uint32

	// IPv6-specific
	ipv6FlowLabel uint32

	// Flow exporter: non-empty when sampler address is present
	samplerIPStr    string
	samplerIPFieldID int // netflow.IPFIX_FIELD_exporterIPv4Address or IPv6
}

// extractFlowData computes all derived fields shared between the JSON and TLV formatters,
// eliminating duplicated extraction logic in each formatter.
func extractFlowData(extFlow *proto.ExtendedFlowMessage) flowData {
	baseFlow := extFlow.BaseFlow
	ip6 := make(net.IP, net.IPv6len)
	ip4 := make(net.IP, net.IPv4len)
	hwaddr := make(net.HardwareAddr, 6)
	_hwaddr := make([]byte, binary.MaxVarintLen64)

	fd := flowData{}

	// Stats — goflow2 only supports unidirectional flows. For NetFlow v9/IPFIX,
	// bytes/packets arrive via the mapping.yaml remapping (fields 200-203). For
	// NetFlow v5 (fixed format), the producer writes directly to FlowMessage.Bytes/Packets,
	// so fall back to those when the custom fields are unpopulated.
	fd.inBytes = uint64(extFlow.InBytes)
	if fd.inBytes == 0 {
		fd.inBytes = baseFlow.Bytes
	}
	fd.inPackets = uint64(extFlow.InPackets)
	if fd.inPackets == 0 {
		fd.inPackets = baseFlow.Packets
	}
	fd.outBytes = uint64(extFlow.OutBytes)
	fd.outPackets = uint64(extFlow.OutPackets)

	// Timestamps: goflow2 provides nanoseconds; ntopng expects seconds.
	fd.startSec = uint32(baseFlow.TimeFlowStartNs / 1_000_000_000)
	fd.endSec = uint32(baseFlow.TimeFlowEndNs / 1_000_000_000)

	// ICMP combined type+code
	fd.icmpType = uint16((uint16(baseFlow.IcmpType) << 8) + uint16(baseFlow.IcmpCode))

	// MAC addresses
	binary.PutUvarint(_hwaddr, baseFlow.DstMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	fd.dstMac = hwaddr.String()
	binary.PutUvarint(_hwaddr, baseFlow.SrcMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	fd.srcMac = hwaddr.String()

	// VLAN
	fd.srcVlan = baseFlow.SrcVlan
	fd.dstVlan = baseFlow.DstVlan

	// IP addresses and protocol version
	fd.srcNet = baseFlow.SrcNet
	fd.dstNet = baseFlow.DstNet
	fd.isIPv4 = baseFlow.Etype == 0x800
	if fd.isIPv4 {
		copy(ip4, baseFlow.SrcAddr)
		fd.srcIP = ip4.String()
		copy(ip4, baseFlow.DstAddr)
		fd.dstIP = ip4.String()
		copy(ip4, baseFlow.NextHop)
		fd.nextHop = ip4.String()
		fd.fragmentId = baseFlow.FragmentId
		fd.fragmentOffset = baseFlow.FragmentOffset
	} else {
		copy(ip6, baseFlow.SrcAddr)
		fd.srcIP = ip6.String()
		copy(ip6, baseFlow.DstAddr)
		fd.dstIP = ip6.String()
		copy(ip6, baseFlow.NextHop)
		fd.nextHop = ip6.String()
		fd.ipv6FlowLabel = baseFlow.Ipv6FlowLabel
	}

	// Flow exporter IP
	if len(baseFlow.SamplerAddress) == 4 {
		copy(ip4, baseFlow.SamplerAddress)
		fd.samplerIPStr = ip4.String()
		fd.samplerIPFieldID = netflow.IPFIX_FIELD_exporterIPv4Address
	} else if len(baseFlow.SamplerAddress) == 16 {
		copy(ip6, baseFlow.SamplerAddress)
		fd.samplerIPStr = ip6.String()
		fd.samplerIPFieldID = netflow.IPFIX_FIELD_exporterIPv6Address
	}

	return fd
}
