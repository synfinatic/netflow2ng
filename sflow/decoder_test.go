package sflow

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// buildSFlowDatagram creates a minimal sFlow v5 datagram for testing
func buildSFlowDatagram(agentIP net.IP, subAgentID, seqNum uint32, samples []byte) []byte {
	buf := new(bytes.Buffer)

	// Version (5)
	binary.Write(buf, binary.BigEndian, uint32(5))

	// Agent address type and address
	if agentIP.To4() != nil {
		binary.Write(buf, binary.BigEndian, uint32(1)) // IPv4
		buf.Write(agentIP.To4())
	} else {
		binary.Write(buf, binary.BigEndian, uint32(2)) // IPv6
		buf.Write(agentIP.To16())
	}

	// Sub-agent ID
	binary.Write(buf, binary.BigEndian, subAgentID)

	// Sequence number
	binary.Write(buf, binary.BigEndian, seqNum)

	// System uptime (ms)
	binary.Write(buf, binary.BigEndian, uint32(12345678))

	// Number of samples
	numSamples := uint32(0)
	if len(samples) > 0 {
		numSamples = 1
	}
	binary.Write(buf, binary.BigEndian, numSamples)

	// Samples
	buf.Write(samples)

	return buf.Bytes()
}

// buildFlowSample creates a flow sample with raw packet header
func buildFlowSample(samplingRate, inputIf, outputIf uint32, header []byte) []byte {
	buf := new(bytes.Buffer)

	// Sample type (1 = flow sample) | length placeholder
	sampleType := uint32(1) // flow sample
	binary.Write(buf, binary.BigEndian, sampleType)

	// Sample data
	sampleBuf := new(bytes.Buffer)

	// Sequence number
	binary.Write(sampleBuf, binary.BigEndian, uint32(1))

	// Source ID
	binary.Write(sampleBuf, binary.BigEndian, uint32(0))

	// Sampling rate
	binary.Write(sampleBuf, binary.BigEndian, samplingRate)

	// Sample pool
	binary.Write(sampleBuf, binary.BigEndian, uint32(1000))

	// Drops
	binary.Write(sampleBuf, binary.BigEndian, uint32(0))

	// Input interface
	binary.Write(sampleBuf, binary.BigEndian, inputIf)

	// Output interface
	binary.Write(sampleBuf, binary.BigEndian, outputIf)

	// Number of flow records
	binary.Write(sampleBuf, binary.BigEndian, uint32(1))

	// Flow record (raw packet header)
	recordBuf := new(bytes.Buffer)

	// Protocol (1 = Ethernet)
	binary.Write(recordBuf, binary.BigEndian, uint32(1))

	// Frame length
	binary.Write(recordBuf, binary.BigEndian, uint32(len(header)))

	// Stripped
	binary.Write(recordBuf, binary.BigEndian, uint32(0))

	// Header length
	binary.Write(recordBuf, binary.BigEndian, uint32(len(header)))

	// Header data (padded to 4 bytes)
	recordBuf.Write(header)
	for recordBuf.Len()%4 != 0 {
		recordBuf.WriteByte(0)
	}

	// Record type (1 = raw packet header) and length
	binary.Write(sampleBuf, binary.BigEndian, uint32(1)) // record type
	binary.Write(sampleBuf, binary.BigEndian, uint32(recordBuf.Len()+16)) // 16 for fields above
	sampleBuf.Write(recordBuf.Bytes())

	// Write sample length
	binary.Write(buf, binary.BigEndian, uint32(sampleBuf.Len()))
	buf.Write(sampleBuf.Bytes())

	return buf.Bytes()
}

// buildEthernetIPv4TCPHeader builds a simple Ethernet + IPv4 + TCP header
func buildEthernetIPv4TCPHeader(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	buf := new(bytes.Buffer)

	// Ethernet header
	// Dst MAC
	buf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	// Src MAC
	buf.Write([]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	// EtherType (IPv4)
	binary.Write(buf, binary.BigEndian, uint16(0x0800))

	// IPv4 header (20 bytes)
	buf.WriteByte(0x45) // Version + IHL
	buf.WriteByte(0x00) // ToS
	binary.Write(buf, binary.BigEndian, uint16(40)) // Total length
	binary.Write(buf, binary.BigEndian, uint16(0)) // Identification
	binary.Write(buf, binary.BigEndian, uint16(0)) // Flags + Fragment offset
	buf.WriteByte(64) // TTL
	buf.WriteByte(6)  // Protocol (TCP)
	binary.Write(buf, binary.BigEndian, uint16(0)) // Header checksum
	buf.Write(srcIP.To4())
	buf.Write(dstIP.To4())

	// TCP header (at least 4 bytes for ports)
	binary.Write(buf, binary.BigEndian, srcPort)
	binary.Write(buf, binary.BigEndian, dstPort)
	binary.Write(buf, binary.BigEndian, uint32(0)) // Seq
	binary.Write(buf, binary.BigEndian, uint32(0)) // Ack
	buf.WriteByte(0x50) // Data offset
	buf.WriteByte(0x02) // Flags (SYN)
	binary.Write(buf, binary.BigEndian, uint16(65535)) // Window

	return buf.Bytes()
}

func TestDecoder_DecodeDatagram_Basic(t *testing.T) {
	decoder := NewDecoder(nil)

	agentIP := net.ParseIP("192.168.1.1")
	data := buildSFlowDatagram(agentIP, 0, 1, nil)

	dg, err := decoder.DecodeDatagram(data, agentIP)
	if err != nil {
		t.Fatalf("Failed to decode datagram: %v", err)
	}

	if dg.Version != 5 {
		t.Errorf("Expected version 5, got %d", dg.Version)
	}

	if !dg.AgentAddress.Equal(agentIP) {
		t.Errorf("Expected agent address %s, got %s", agentIP, dg.AgentAddress)
	}

	if dg.SequenceNumber != 1 {
		t.Errorf("Expected sequence 1, got %d", dg.SequenceNumber)
	}
}

func TestDecoder_DecodeDatagram_InvalidVersion(t *testing.T) {
	decoder := NewDecoder(nil)

	// Build a datagram with wrong version
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(4)) // Wrong version
	binary.Write(buf, binary.BigEndian, uint32(1)) // IPv4
	buf.Write(net.ParseIP("192.168.1.1").To4())
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, uint32(1))
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, uint32(0))

	_, err := decoder.DecodeDatagram(buf.Bytes(), nil)
	if err == nil {
		t.Error("Expected error for invalid version")
	}
}

func TestDecoder_DecodeDatagram_TooShort(t *testing.T) {
	decoder := NewDecoder(nil)

	data := []byte{0, 0, 0, 5} // Just version
	_, err := decoder.DecodeDatagram(data, nil)
	if err == nil {
		t.Error("Expected error for short datagram")
	}
}

func TestDecoder_ParseEthernetHeader_IPv4TCP(t *testing.T) {
	header := &SFlowRawPacketHeader{
		Protocol: 1,
		HeaderData: buildEthernetIPv4TCPHeader(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			12345, 80,
		),
	}

	decoder := NewDecoder(nil)
	decoder.parseEthernetHeader(header)

	if header.EtherType != 0x0800 {
		t.Errorf("Expected EtherType 0x0800, got 0x%04x", header.EtherType)
	}

	if !header.SrcIP.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("Expected SrcIP 192.168.1.100, got %s", header.SrcIP)
	}

	if !header.DstIP.Equal(net.ParseIP("192.168.1.200")) {
		t.Errorf("Expected DstIP 192.168.1.200, got %s", header.DstIP)
	}

	if header.SrcPort != 12345 {
		t.Errorf("Expected SrcPort 12345, got %d", header.SrcPort)
	}

	if header.DstPort != 80 {
		t.Errorf("Expected DstPort 80, got %d", header.DstPort)
	}

	if header.Protocol_L4 != 6 {
		t.Errorf("Expected Protocol 6 (TCP), got %d", header.Protocol_L4)
	}

	if header.IPVersion != 4 {
		t.Errorf("Expected IP version 4, got %d", header.IPVersion)
	}
}

func TestDecoder_ToFlowMessages(t *testing.T) {
	decoder := NewDecoder(nil)

	// Build a complete datagram with a flow sample
	agentIP := net.ParseIP("192.168.1.1")
	header := buildEthernetIPv4TCPHeader(
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
		54321, 443,
	)
	sample := buildFlowSample(128, 1, 2, header)
	data := buildSFlowDatagram(agentIP, 0, 100, sample)

	dg, err := decoder.DecodeDatagram(data, agentIP)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	messages := decoder.ToFlowMessages(dg)

	if len(messages) == 0 {
		t.Fatal("Expected at least one flow message")
	}

	msg := messages[0]

	if msg.SamplingRate != 128 {
		t.Errorf("Expected sampling rate 128, got %d", msg.SamplingRate)
	}

	if msg.InIf != 1 {
		t.Errorf("Expected input interface 1, got %d", msg.InIf)
	}

	if msg.OutIf != 2 {
		t.Errorf("Expected output interface 2, got %d", msg.OutIf)
	}
}

func TestMacToUint64(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	expected := uint64(0x001122334455)

	result := macToUint64(mac)
	if result != expected {
		t.Errorf("Expected %x, got %x", expected, result)
	}
}

func TestMacToUint64_Invalid(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11} // Too short
	result := macToUint64(mac)
	if result != 0 {
		t.Errorf("Expected 0 for invalid MAC, got %x", result)
	}
}

func BenchmarkDecoder_DecodeDatagram(b *testing.B) {
	decoder := NewDecoder(nil)
	agentIP := net.ParseIP("192.168.1.1")
	header := buildEthernetIPv4TCPHeader(
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
		54321, 443,
	)
	sample := buildFlowSample(128, 1, 2, header)
	data := buildSFlowDatagram(agentIP, 0, 100, sample)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder.DecodeDatagram(data, agentIP)
	}
}
