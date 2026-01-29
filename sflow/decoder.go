package sflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/synfinatic/netflow2ng/sampling"
)

var log *logrus.Logger

func SetLogger(l *logrus.Logger) {
	log = l
}

// sFlow v5 constants
const (
	SFlowVersion5 = 5

	// Sample types
	SFlowTypeFlowSample         = 1
	SFlowTypeCounterSample      = 2
	SFlowTypeExpandedFlowSample = 3
	SFlowTypeExpandedCounter    = 4

	// Flow record types (enterprise = 0)
	SFlowFlowRawPacketHeader    = 1
	SFlowFlowEthernetFrame      = 2
	SFlowFlowIPv4               = 3
	SFlowFlowIPv6               = 4
	SFlowFlowExtendedSwitch     = 1001
	SFlowFlowExtendedRouter     = 1002
	SFlowFlowExtendedGateway    = 1003
	SFlowFlowExtendedUser       = 1004
	SFlowFlowExtendedURL        = 1005
	SFlowFlowExtendedMpls       = 1006
	SFlowFlowExtendedNat        = 1007
	SFlowFlowExtendedMplsTunnel = 1008
	SFlowFlowExtendedMplsVC     = 1009
	SFlowFlowExtendedMpls_FTN   = 1010
	SFlowFlowExtendedMpls_LDP   = 1011
	SFlowFlowExtendedVlanTunnel = 1012
)

// SFlowDatagram represents an sFlow v5 datagram
type SFlowDatagram struct {
	Version        uint32
	AgentAddress   net.IP
	SubAgentID     uint32
	SequenceNumber uint32
	SysUptime      uint32 // milliseconds since boot
	NumSamples     uint32
	Samples        []SFlowSample
	ReceivedAt     time.Time
}

// SFlowSample is the interface for all sFlow sample types
type SFlowSample interface {
	GetType() uint32
}

// SFlowFlowSample represents a flow sample
type SFlowFlowSample struct {
	SequenceNumber   uint32
	SourceID         uint32
	SamplingRate     uint32
	SamplePool       uint32
	Drops            uint32
	InputInterface   uint32
	OutputInterface  uint32
	NumFlowRecords   uint32
	FlowRecords      []SFlowFlowRecord
	// For expanded samples
	SourceIDType  uint32
	SourceIDIndex uint32
}

func (s *SFlowFlowSample) GetType() uint32 {
	return SFlowTypeFlowSample
}

// SFlowFlowRecord represents a flow record within a sample
type SFlowFlowRecord struct {
	Enterprise uint32
	Format     uint32
	Length     uint32
	Data       interface{} // Parsed record data
}

// SFlowRawPacketHeader represents a raw packet header record
type SFlowRawPacketHeader struct {
	Protocol       uint32 // Header protocol (1 = Ethernet)
	FrameLength    uint32 // Original frame length
	Stripped       uint32 // Bytes stripped from packet
	HeaderLength   uint32
	HeaderData     []byte
	// Parsed from header
	SrcMAC         net.HardwareAddr
	DstMAC         net.HardwareAddr
	EtherType      uint16
	SrcIP          net.IP
	DstIP          net.IP
	SrcPort        uint16
	DstPort        uint16
	Protocol_L4    uint8
	TCPFlags       uint8
	SrcVLAN        uint16
	DstVLAN        uint16
	IPVersion      uint8
	ToS            uint8
	TTL            uint8
	NextHop        net.IP
	ICMP_Type      uint8
	ICMP_Code      uint8
	IPv6FlowLabel  uint32
	FragmentOffset uint16
	FragmentID     uint32
}

// SFlowExtendedSwitch represents extended switch data
type SFlowExtendedSwitch struct {
	SrcVLAN     uint32
	SrcPriority uint32
	DstVLAN     uint32
	DstPriority uint32
}

// SFlowExtendedRouter represents extended router data
type SFlowExtendedRouter struct {
	NextHop   net.IP
	SrcMask   uint32
	DstMask   uint32
}

// FlowMessage represents a decoded flow that can be passed to formatters
type FlowMessage struct {
	// Core flow identification
	SrcAddr    net.IP
	DstAddr    net.IP
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	EtherType  uint16
	IPVersion  uint8

	// Statistics (will be upscaled by sampling rate)
	Bytes      uint64
	Packets    uint64

	// Sampling info
	SamplingRate uint32

	// Timing
	TimeFlowStartNs uint64
	TimeFlowEndNs   uint64

	// Interface info
	InIf  uint32
	OutIf uint32

	// Layer 2
	SrcMAC   uint64
	DstMAC   uint64
	SrcVLAN  uint32
	DstVLAN  uint32

	// Layer 3
	ToS            uint8
	TTL            uint8
	TCPFlags       uint8
	NextHop        net.IP
	SrcNet         uint32
	DstNet         uint32
	FragmentOffset uint16
	FragmentId     uint32
	IPv6FlowLabel  uint32

	// ICMP
	IcmpType uint8
	IcmpCode uint8

	// Exporter info
	SamplerAddress net.IP
	SourceID       uint32
	SequenceNumber uint32
}

// Decoder handles sFlow v5 decoding
type Decoder struct {
	samplingTracker *sampling.SamplingTracker
}

// NewDecoder creates a new sFlow decoder
func NewDecoder(tracker *sampling.SamplingTracker) *Decoder {
	return &Decoder{
		samplingTracker: tracker,
	}
}

// DecodeDatagram decodes an sFlow v5 datagram
func (d *Decoder) DecodeDatagram(data []byte, srcAddr net.IP) (*SFlowDatagram, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("sflow datagram too short: %d bytes", len(data))
	}

	buf := bytes.NewReader(data)
	dg := &SFlowDatagram{
		ReceivedAt: time.Now(),
	}

	// Read header
	if err := binary.Read(buf, binary.BigEndian, &dg.Version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}

	if dg.Version != SFlowVersion5 {
		return nil, fmt.Errorf("unsupported sflow version: %d", dg.Version)
	}

	// Read agent address type
	var agentAddrType uint32
	if err := binary.Read(buf, binary.BigEndian, &agentAddrType); err != nil {
		return nil, fmt.Errorf("failed to read agent address type: %w", err)
	}

	// Read agent address
	switch agentAddrType {
	case 1: // IPv4
		addr := make([]byte, 4)
		if _, err := buf.Read(addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 agent address: %w", err)
		}
		dg.AgentAddress = net.IP(addr)
	case 2: // IPv6
		addr := make([]byte, 16)
		if _, err := buf.Read(addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv6 agent address: %w", err)
		}
		dg.AgentAddress = net.IP(addr)
	default:
		return nil, fmt.Errorf("unknown agent address type: %d", agentAddrType)
	}

	// Read remaining header fields
	if err := binary.Read(buf, binary.BigEndian, &dg.SubAgentID); err != nil {
		return nil, fmt.Errorf("failed to read sub-agent ID: %w", err)
	}
	if err := binary.Read(buf, binary.BigEndian, &dg.SequenceNumber); err != nil {
		return nil, fmt.Errorf("failed to read sequence number: %w", err)
	}
	if err := binary.Read(buf, binary.BigEndian, &dg.SysUptime); err != nil {
		return nil, fmt.Errorf("failed to read sys uptime: %w", err)
	}
	if err := binary.Read(buf, binary.BigEndian, &dg.NumSamples); err != nil {
		return nil, fmt.Errorf("failed to read num samples: %w", err)
	}

	// Parse samples
	dg.Samples = make([]SFlowSample, 0, dg.NumSamples)
	for i := uint32(0); i < dg.NumSamples; i++ {
		sample, err := d.decodeSample(buf)
		if err != nil {
			if log != nil {
				log.WithError(err).Debug("Failed to decode sFlow sample")
			}
			// Try to continue with remaining samples
			break
		}
		if sample != nil {
			dg.Samples = append(dg.Samples, sample)
		}
	}

	return dg, nil
}

func (d *Decoder) decodeSample(buf *bytes.Reader) (SFlowSample, error) {
	var sampleType, sampleLength uint32

	if err := binary.Read(buf, binary.BigEndian, &sampleType); err != nil {
		return nil, fmt.Errorf("failed to read sample type: %w", err)
	}
	if err := binary.Read(buf, binary.BigEndian, &sampleLength); err != nil {
		return nil, fmt.Errorf("failed to read sample length: %w", err)
	}

	// Extract enterprise and format from sample type
	enterprise := sampleType >> 12
	format := sampleType & 0xFFF

	if enterprise != 0 {
		// Skip enterprise-specific samples
		buf.Seek(int64(sampleLength), 1)
		return nil, nil
	}

	switch format {
	case SFlowTypeFlowSample:
		return d.decodeFlowSample(buf, false)
	case SFlowTypeExpandedFlowSample:
		return d.decodeFlowSample(buf, true)
	case SFlowTypeCounterSample, SFlowTypeExpandedCounter:
		// Skip counter samples for now (we're focused on flow data)
		buf.Seek(int64(sampleLength), 1)
		return nil, nil
	default:
		// Skip unknown sample types
		buf.Seek(int64(sampleLength), 1)
		return nil, nil
	}
}

func (d *Decoder) decodeFlowSample(buf *bytes.Reader, expanded bool) (*SFlowFlowSample, error) {
	sample := &SFlowFlowSample{}

	if err := binary.Read(buf, binary.BigEndian, &sample.SequenceNumber); err != nil {
		return nil, err
	}

	if expanded {
		if err := binary.Read(buf, binary.BigEndian, &sample.SourceIDType); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.BigEndian, &sample.SourceIDIndex); err != nil {
			return nil, err
		}
		sample.SourceID = sample.SourceIDIndex
	} else {
		if err := binary.Read(buf, binary.BigEndian, &sample.SourceID); err != nil {
			return nil, err
		}
	}

	if err := binary.Read(buf, binary.BigEndian, &sample.SamplingRate); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &sample.SamplePool); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &sample.Drops); err != nil {
		return nil, err
	}

	if expanded {
		var inputType, outputType uint32
		if err := binary.Read(buf, binary.BigEndian, &inputType); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.BigEndian, &sample.InputInterface); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.BigEndian, &outputType); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.BigEndian, &sample.OutputInterface); err != nil {
			return nil, err
		}
	} else {
		if err := binary.Read(buf, binary.BigEndian, &sample.InputInterface); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.BigEndian, &sample.OutputInterface); err != nil {
			return nil, err
		}
	}

	if err := binary.Read(buf, binary.BigEndian, &sample.NumFlowRecords); err != nil {
		return nil, err
	}

	// Parse flow records
	sample.FlowRecords = make([]SFlowFlowRecord, 0, sample.NumFlowRecords)
	for i := uint32(0); i < sample.NumFlowRecords; i++ {
		record, err := d.decodeFlowRecord(buf)
		if err != nil {
			if log != nil {
				log.WithError(err).Debug("Failed to decode flow record")
			}
			break
		}
		sample.FlowRecords = append(sample.FlowRecords, record)
	}

	return sample, nil
}

func (d *Decoder) decodeFlowRecord(buf *bytes.Reader) (SFlowFlowRecord, error) {
	var record SFlowFlowRecord

	var recordType uint32
	if err := binary.Read(buf, binary.BigEndian, &recordType); err != nil {
		return record, err
	}
	record.Enterprise = recordType >> 12
	record.Format = recordType & 0xFFF

	if err := binary.Read(buf, binary.BigEndian, &record.Length); err != nil {
		return record, err
	}

	// Only parse standard (enterprise=0) records
	if record.Enterprise != 0 {
		buf.Seek(int64(record.Length), 1)
		return record, nil
	}

	switch record.Format {
	case SFlowFlowRawPacketHeader:
		header, err := d.decodeRawPacketHeader(buf, record.Length)
		if err != nil {
			return record, err
		}
		record.Data = header
	case SFlowFlowExtendedSwitch:
		sw, err := d.decodeExtendedSwitch(buf)
		if err != nil {
			return record, err
		}
		record.Data = sw
	case SFlowFlowExtendedRouter:
		router, err := d.decodeExtendedRouter(buf)
		if err != nil {
			return record, err
		}
		record.Data = router
	default:
		// Skip unknown record types
		buf.Seek(int64(record.Length), 1)
	}

	return record, nil
}

func (d *Decoder) decodeRawPacketHeader(buf *bytes.Reader, length uint32) (*SFlowRawPacketHeader, error) {
	header := &SFlowRawPacketHeader{}

	if err := binary.Read(buf, binary.BigEndian, &header.Protocol); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.FrameLength); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.Stripped); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.HeaderLength); err != nil {
		return nil, err
	}

	// Read header data (padded to 4-byte boundary)
	paddedLen := (header.HeaderLength + 3) & ^uint32(3)
	header.HeaderData = make([]byte, paddedLen)
	if _, err := buf.Read(header.HeaderData); err != nil {
		return nil, err
	}
	header.HeaderData = header.HeaderData[:header.HeaderLength]

	// Parse the packet header (Ethernet)
	if header.Protocol == 1 && len(header.HeaderData) >= 14 {
		d.parseEthernetHeader(header)
	}

	return header, nil
}

func (d *Decoder) parseEthernetHeader(header *SFlowRawPacketHeader) {
	data := header.HeaderData

	// Ethernet header: 6 bytes dst MAC, 6 bytes src MAC, 2 bytes ethertype
	if len(data) < 14 {
		return
	}

	header.DstMAC = net.HardwareAddr(data[0:6])
	header.SrcMAC = net.HardwareAddr(data[6:12])
	header.EtherType = binary.BigEndian.Uint16(data[12:14])

	offset := 14

	// Handle VLAN tags (0x8100)
	for header.EtherType == 0x8100 {
		if len(data) < offset+4 {
			return
		}
		vlanTag := binary.BigEndian.Uint16(data[offset : offset+2])
		header.SrcVLAN = vlanTag & 0x0FFF
		header.DstVLAN = header.SrcVLAN
		header.EtherType = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
	}

	// Parse IP header
	switch header.EtherType {
	case 0x0800: // IPv4
		header.IPVersion = 4
		if len(data) < offset+20 {
			return
		}
		header.ToS = data[offset+1]
		header.TTL = data[offset+8]
		header.Protocol_L4 = data[offset+9]
		header.SrcIP = net.IP(data[offset+12 : offset+16])
		header.DstIP = net.IP(data[offset+16 : offset+20])

		ihl := int(data[offset]&0x0F) * 4
		header.FragmentOffset = binary.BigEndian.Uint16(data[offset+6:offset+8]) & 0x1FFF
		header.FragmentID = uint32(binary.BigEndian.Uint16(data[offset+4 : offset+6]))

		// Parse L4 header
		if len(data) >= offset+ihl+4 {
			d.parseL4Header(header, data[offset+ihl:])
		}

	case 0x86DD: // IPv6
		header.IPVersion = 6
		if len(data) < offset+40 {
			return
		}
		header.ToS = (data[offset] << 4) | (data[offset+1] >> 4)
		header.IPv6FlowLabel = uint32(data[offset+1]&0x0F)<<16 | uint32(binary.BigEndian.Uint16(data[offset+2:offset+4]))
		header.Protocol_L4 = data[offset+6]
		header.TTL = data[offset+7]
		header.SrcIP = net.IP(data[offset+8 : offset+24])
		header.DstIP = net.IP(data[offset+24 : offset+40])

		// Parse L4 header
		if len(data) >= offset+40+4 {
			d.parseL4Header(header, data[offset+40:])
		}
	}
}

func (d *Decoder) parseL4Header(header *SFlowRawPacketHeader, data []byte) {
	if len(data) < 4 {
		return
	}

	switch header.Protocol_L4 {
	case 6: // TCP
		header.SrcPort = binary.BigEndian.Uint16(data[0:2])
		header.DstPort = binary.BigEndian.Uint16(data[2:4])
		if len(data) >= 14 {
			header.TCPFlags = data[13]
		}
	case 17: // UDP
		header.SrcPort = binary.BigEndian.Uint16(data[0:2])
		header.DstPort = binary.BigEndian.Uint16(data[2:4])
	case 1: // ICMP
		header.ICMP_Type = data[0]
		header.ICMP_Code = data[1]
	case 58: // ICMPv6
		header.ICMP_Type = data[0]
		header.ICMP_Code = data[1]
	}
}

func (d *Decoder) decodeExtendedSwitch(buf *bytes.Reader) (*SFlowExtendedSwitch, error) {
	sw := &SFlowExtendedSwitch{}

	if err := binary.Read(buf, binary.BigEndian, &sw.SrcVLAN); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &sw.SrcPriority); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &sw.DstVLAN); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &sw.DstPriority); err != nil {
		return nil, err
	}

	return sw, nil
}

func (d *Decoder) decodeExtendedRouter(buf *bytes.Reader) (*SFlowExtendedRouter, error) {
	router := &SFlowExtendedRouter{}

	var addrType uint32
	if err := binary.Read(buf, binary.BigEndian, &addrType); err != nil {
		return nil, err
	}

	switch addrType {
	case 1: // IPv4
		addr := make([]byte, 4)
		if _, err := buf.Read(addr); err != nil {
			return nil, err
		}
		router.NextHop = net.IP(addr)
	case 2: // IPv6
		addr := make([]byte, 16)
		if _, err := buf.Read(addr); err != nil {
			return nil, err
		}
		router.NextHop = net.IP(addr)
	}

	if err := binary.Read(buf, binary.BigEndian, &router.SrcMask); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &router.DstMask); err != nil {
		return nil, err
	}

	return router, nil
}

// ToFlowMessages converts an sFlow datagram to flow messages
func (d *Decoder) ToFlowMessages(dg *SFlowDatagram) []*FlowMessage {
	var messages []*FlowMessage

	for _, sample := range dg.Samples {
		flowSample, ok := sample.(*SFlowFlowSample)
		if !ok {
			continue
		}

		// Update sampling tracker if we have one
		if d.samplingTracker != nil && flowSample.SamplingRate > 0 {
			d.samplingTracker.UpdateSamplingRate(
				dg.AgentAddress,
				flowSample.SourceID,
				flowSample.SamplingRate,
				sampling.SamplingDeterministic,
				sampling.SourceSFlowHeader,
			)
		}

		msg := d.flowSampleToMessage(dg, flowSample)
		if msg != nil {
			messages = append(messages, msg)
		}
	}

	return messages
}

func (d *Decoder) flowSampleToMessage(dg *SFlowDatagram, sample *SFlowFlowSample) *FlowMessage {
	msg := &FlowMessage{
		SamplerAddress: dg.AgentAddress,
		SourceID:       sample.SourceID,
		SequenceNumber: dg.SequenceNumber,
		SamplingRate:   sample.SamplingRate,
		InIf:           sample.InputInterface,
		OutIf:          sample.OutputInterface,
		Packets:        1, // sFlow samples individual packets
	}

	now := time.Now().UnixNano()
	msg.TimeFlowStartNs = uint64(now)
	msg.TimeFlowEndNs = uint64(now)

	// Process flow records
	var rawHeader *SFlowRawPacketHeader
	var extSwitch *SFlowExtendedSwitch
	var extRouter *SFlowExtendedRouter

	for _, record := range sample.FlowRecords {
		switch data := record.Data.(type) {
		case *SFlowRawPacketHeader:
			rawHeader = data
		case *SFlowExtendedSwitch:
			extSwitch = data
		case *SFlowExtendedRouter:
			extRouter = data
		}
	}

	if rawHeader == nil {
		return nil // No usable packet data
	}

	// Fill in from raw header
	msg.SrcAddr = rawHeader.SrcIP
	msg.DstAddr = rawHeader.DstIP
	msg.SrcPort = rawHeader.SrcPort
	msg.DstPort = rawHeader.DstPort
	msg.Protocol = rawHeader.Protocol_L4
	msg.EtherType = rawHeader.EtherType
	msg.IPVersion = rawHeader.IPVersion
	msg.Bytes = uint64(rawHeader.FrameLength)
	msg.ToS = rawHeader.ToS
	msg.TTL = rawHeader.TTL
	msg.TCPFlags = rawHeader.TCPFlags
	msg.IcmpType = rawHeader.ICMP_Type
	msg.IcmpCode = rawHeader.ICMP_Code
	msg.FragmentOffset = rawHeader.FragmentOffset
	msg.FragmentId = rawHeader.FragmentID
	msg.IPv6FlowLabel = rawHeader.IPv6FlowLabel
	msg.NextHop = rawHeader.NextHop
	msg.SrcVLAN = uint32(rawHeader.SrcVLAN)
	msg.DstVLAN = uint32(rawHeader.DstVLAN)

	// Convert MAC addresses to uint64
	if len(rawHeader.SrcMAC) == 6 {
		msg.SrcMAC = macToUint64(rawHeader.SrcMAC)
	}
	if len(rawHeader.DstMAC) == 6 {
		msg.DstMAC = macToUint64(rawHeader.DstMAC)
	}

	// Override with extended data if available
	if extSwitch != nil {
		msg.SrcVLAN = extSwitch.SrcVLAN
		msg.DstVLAN = extSwitch.DstVLAN
	}

	if extRouter != nil {
		msg.NextHop = extRouter.NextHop
		msg.SrcNet = extRouter.SrcMask
		msg.DstNet = extRouter.DstMask
	}

	return msg
}

func macToUint64(mac net.HardwareAddr) uint64 {
	if len(mac) != 6 {
		return 0
	}
	return uint64(mac[0])<<40 | uint64(mac[1])<<32 | uint64(mac[2])<<24 |
		uint64(mac[3])<<16 | uint64(mac[4])<<8 | uint64(mac[5])
}
