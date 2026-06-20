package formatter

import (
	"testing"

	pb "github.com/netsampler/goflow2/v2/pb"
	gf2proto "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/sirupsen/logrus"
	"github.com/synfinatic/netflow2ng/proto"
)

func TestSetLogger(t *testing.T) {
	l := logrus.New()
	SetLogger(l)
	if log != l {
		t.Error("SetLogger did not set the package logger")
	}
}

func TestNtopngJson_Init(t *testing.T) {
	d := &NtopngJson{}
	if err := d.Init(); err != nil {
		t.Errorf("NtopngJson.Init() unexpected error: %v", err)
	}
}

func TestNtopngTlv_Init(t *testing.T) {
	d := &NtopngTlv{}
	if err := d.Init(); err != nil {
		t.Errorf("NtopngTlv.Init() unexpected error: %v", err)
	}
}

// newTestProtoMsg builds a minimal ProtoProducerMessage for testing castToExtendedFlowMsg.
func newTestProtoMsg() *gf2proto.ProtoProducerMessage {
	ppm := &gf2proto.ProtoProducerMessage{}
	ppm.SrcAddr = []byte{10, 0, 0, 1}
	ppm.DstAddr = []byte{192, 168, 1, 1}
	ppm.Etype = 0x800
	ppm.Bytes = 1000
	ppm.Packets = 10
	return ppm
}

// newTestExtFlow builds an ExtendedFlowMessage directly for testing formatters.
func newTestExtFlowIPv4() *proto.ExtendedFlowMessage {
	return &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			SrcAddr:         []byte{10, 0, 0, 1},
			DstAddr:         []byte{192, 168, 1, 1},
			NextHop:         []byte{10, 0, 0, 254},
			Etype:           0x800,
			Proto:           6,
			SrcPort:         12345,
			DstPort:         80,
			SrcAs:           64512,
			DstAs:           64513,
			InIf:            1,
			OutIf:           2,
			IpTos:           0,
			TcpFlags:        0x18,
			IpTtl:           64,
			IcmpType:        3,
			IcmpCode:        4,
			SrcMac:          0x001122334455,
			DstMac:          0x665544332211,
			SrcVlan:         100,
			DstVlan:         200,
			SrcNet:          24,
			DstNet:          16,
			FragmentId:      42,
			FragmentOffset:  0,
			TimeFlowStartNs: 1_700_000_000_000_000_000,
			TimeFlowEndNs:   1_700_000_001_000_000_000,
		},
		InBytes:    1000,
		InPackets:  10,
		OutBytes:   500,
		OutPackets: 5,
	}
}

func newTestExtFlowIPv6() *proto.ExtendedFlowMessage {
	return &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			SrcAddr: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			DstAddr: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
			NextHop: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254},
			Etype:   0x86dd,
			SrcNet:  48,
			DstNet:  48,
			Ipv6FlowLabel: 12345,
			TimeFlowStartNs: 1_700_000_000_000_000_000,
			TimeFlowEndNs:   1_700_000_001_000_000_000,
		},
		InBytes:   2000,
		InPackets: 20,
	}
}

func TestCastToExtendedFlowMsg_Valid(t *testing.T) {
	ppm := newTestProtoMsg()
	efm, err := castToExtendedFlowMsg(ppm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if efm == nil {
		t.Fatal("expected non-nil ExtendedFlowMessage")
	}
	if efm.BaseFlow == nil {
		t.Fatal("expected non-nil BaseFlow")
	}
	// BaseFlow is set to the original ppm.FlowMessage
	if efm.BaseFlow.Bytes != 1000 {
		t.Errorf("expected BaseFlow.Bytes=1000, got %d", efm.BaseFlow.Bytes)
	}
}

func TestCastToExtendedFlowMsg_Invalid(t *testing.T) {
	_, err := castToExtendedFlowMsg("not a ProtoProducerMessage")
	if err == nil {
		t.Fatal("expected error for wrong type, got nil")
	}
}

func TestCastToExtendedFlowMsg_InvalidNil(t *testing.T) {
	_, err := castToExtendedFlowMsg(42)
	if err == nil {
		t.Fatal("expected error for int type, got nil")
	}
}

func TestExtractFlowData_InBytesFallback(t *testing.T) {
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			Bytes:   9999,
			Packets: 77,
		},
		InBytes:   0, // trigger fallback
		InPackets: 0, // trigger fallback
	}
	fd := extractFlowData(extFlow)
	if fd.inBytes != 9999 {
		t.Errorf("expected inBytes=9999 (fallback), got %d", fd.inBytes)
	}
	if fd.inPackets != 77 {
		t.Errorf("expected inPackets=77 (fallback), got %d", fd.inPackets)
	}
}

func TestExtractFlowData_InBytesNonZero(t *testing.T) {
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			Bytes:   9999,
			Packets: 77,
		},
		InBytes:   1234,
		InPackets: 56,
	}
	fd := extractFlowData(extFlow)
	// Custom fields take priority over baseFlow.Bytes/Packets
	if fd.inBytes != 1234 {
		t.Errorf("expected inBytes=1234, got %d", fd.inBytes)
	}
	if fd.inPackets != 56 {
		t.Errorf("expected inPackets=56, got %d", fd.inPackets)
	}
}

func TestExtractFlowData_Timestamps(t *testing.T) {
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			TimeFlowStartNs: 1_700_000_005_000_000_000, // 1700000005 seconds
			TimeFlowEndNs:   1_700_000_010_000_000_000, // 1700000010 seconds
		},
	}
	fd := extractFlowData(extFlow)
	if fd.startSec != 1700000005 {
		t.Errorf("expected startSec=1700000005, got %d", fd.startSec)
	}
	if fd.endSec != 1700000010 {
		t.Errorf("expected endSec=1700000010, got %d", fd.endSec)
	}
}

func TestExtractFlowData_ICMP(t *testing.T) {
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			IcmpType: 3,
			IcmpCode: 4,
		},
	}
	fd := extractFlowData(extFlow)
	expected := uint16((3 << 8) | 4)
	if fd.icmpType != expected {
		t.Errorf("expected icmpType=%d, got %d", expected, fd.icmpType)
	}
}

func TestExtractFlowData_SamplerIPv4(t *testing.T) {
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			SamplerAddress: []byte{172, 16, 1, 254},
		},
	}
	fd := extractFlowData(extFlow)
	if fd.samplerIPStr != "172.16.1.254" {
		t.Errorf("expected samplerIPStr=172.16.1.254, got %q", fd.samplerIPStr)
	}
	if fd.samplerIPFieldID != 130 { // IPFIX_FIELD_exporterIPv4Address
		t.Errorf("expected samplerIPFieldID=130, got %d", fd.samplerIPFieldID)
	}
}

func TestExtractFlowData_SamplerIPv6(t *testing.T) {
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			SamplerAddress: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
	}
	fd := extractFlowData(extFlow)
	if fd.samplerIPStr != "2001:db8::1" {
		t.Errorf("expected samplerIPStr=2001:db8::1, got %q", fd.samplerIPStr)
	}
	if fd.samplerIPFieldID != 131 { // IPFIX_FIELD_exporterIPv6Address
		t.Errorf("expected samplerIPFieldID=131, got %d", fd.samplerIPFieldID)
	}
}

func TestExtractFlowData_SamplerNone(t *testing.T) {
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{},
	}
	fd := extractFlowData(extFlow)
	if fd.samplerIPStr != "" {
		t.Errorf("expected empty samplerIPStr, got %q", fd.samplerIPStr)
	}
}

func TestExtractFlowData_IPv4Addresses(t *testing.T) {
	extFlow := newTestExtFlowIPv4()
	fd := extractFlowData(extFlow)
	if !fd.isIPv4 {
		t.Error("expected isIPv4=true")
	}
	if fd.srcIP != "10.0.0.1" {
		t.Errorf("expected srcIP=10.0.0.1, got %q", fd.srcIP)
	}
	if fd.dstIP != "192.168.1.1" {
		t.Errorf("expected dstIP=192.168.1.1, got %q", fd.dstIP)
	}
	if fd.nextHop != "10.0.0.254" {
		t.Errorf("expected nextHop=10.0.0.254, got %q", fd.nextHop)
	}
}

func TestExtractFlowData_IPv6Addresses(t *testing.T) {
	extFlow := newTestExtFlowIPv6()
	fd := extractFlowData(extFlow)
	if fd.isIPv4 {
		t.Error("expected isIPv4=false for IPv6 flow")
	}
	if fd.srcIP != "2001:db8::1" {
		t.Errorf("expected srcIP=2001:db8::1, got %q", fd.srcIP)
	}
	if fd.dstIP != "2001:db8::2" {
		t.Errorf("expected dstIP=2001:db8::2, got %q", fd.dstIP)
	}
	if fd.ipv6FlowLabel != 12345 {
		t.Errorf("expected ipv6FlowLabel=12345, got %d", fd.ipv6FlowLabel)
	}
}
