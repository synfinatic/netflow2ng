package formatter

import (
	"encoding/json"
	"strconv"
	"testing"

	pb "github.com/netsampler/goflow2/v2/pb"
	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/synfinatic/netflow2ng/proto"
)

// decodeJSON is a helper that unmarshals JSON bytes into a map[string]interface{}.
func decodeJSON(t *testing.T, data []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	return m
}

func fieldKey(id int) string {
	return strconv.Itoa(id)
}

func TestNtopngJson_toJSON_IPv4(t *testing.T) {
	d := &NtopngJson{}
	extFlow := newTestExtFlowIPv4()
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := decodeJSON(t, data)

	// IP version
	if v := m[fieldKey(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)]; v != float64(4) {
		t.Errorf("expected IP version 4, got %v", v)
	}
	// Source address
	if v := m[fieldKey(netflow.NFV9_FIELD_IPV4_SRC_ADDR)]; v != "10.0.0.1" {
		t.Errorf("expected srcAddr=10.0.0.1, got %v", v)
	}
	// Destination address
	if v := m[fieldKey(netflow.NFV9_FIELD_IPV4_DST_ADDR)]; v != "192.168.1.1" {
		t.Errorf("expected dstAddr=192.168.1.1, got %v", v)
	}
	// Next hop
	if v := m[fieldKey(netflow.NFV9_FIELD_IPV4_NEXT_HOP)]; v != "10.0.0.254" {
		t.Errorf("expected nextHop=10.0.0.254, got %v", v)
	}
	// Fragment ID
	if v := m[fieldKey(netflow.NFV9_FIELD_IPV4_IDENT)]; v != float64(42) {
		t.Errorf("expected fragmentId=42, got %v", v)
	}
	// Prefix masks also set for IPv4
	if _, ok := m[fieldKey(netflow.NFV9_FIELD_IPV6_SRC_MASK)]; !ok {
		t.Error("expected IPV6_SRC_MASK to be set for IPv4 flow")
	}
	// IPv6 fields should NOT be present
	if _, ok := m[fieldKey(netflow.NFV9_FIELD_IPV6_SRC_ADDR)]; ok {
		t.Error("unexpected IPV6_SRC_ADDR in IPv4 flow")
	}
}

func TestNtopngJson_toJSON_IPv6(t *testing.T) {
	d := &NtopngJson{}
	extFlow := newTestExtFlowIPv6()
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := decodeJSON(t, data)

	// IP version
	if v := m[fieldKey(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)]; v != float64(6) {
		t.Errorf("expected IP version 6, got %v", v)
	}
	// Source address
	if v := m[fieldKey(netflow.NFV9_FIELD_IPV6_SRC_ADDR)]; v != "2001:db8::1" {
		t.Errorf("expected srcAddr=2001:db8::1, got %v", v)
	}
	// Destination address
	if v := m[fieldKey(netflow.NFV9_FIELD_IPV6_DST_ADDR)]; v != "2001:db8::2" {
		t.Errorf("expected dstAddr=2001:db8::2, got %v", v)
	}
	// Flow label
	if v := m[fieldKey(netflow.NFV9_FIELD_IPV6_FLOW_LABEL)]; v != float64(12345) {
		t.Errorf("expected ipv6FlowLabel=12345, got %v", v)
	}
	// IPv4 fields should NOT be present
	if _, ok := m[fieldKey(netflow.NFV9_FIELD_IPV4_SRC_ADDR)]; ok {
		t.Error("unexpected IPV4_SRC_ADDR in IPv6 flow")
	}
}

func TestNtopngJson_toJSON_Stats(t *testing.T) {
	d := &NtopngJson{}
	extFlow := newTestExtFlowIPv4()
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := decodeJSON(t, data)

	if v := m[fieldKey(netflow.NFV9_FIELD_IN_BYTES)]; v != float64(1000) {
		t.Errorf("expected inBytes=1000, got %v", v)
	}
	if v := m[fieldKey(netflow.NFV9_FIELD_IN_PKTS)]; v != float64(10) {
		t.Errorf("expected inPackets=10, got %v", v)
	}
	if v := m[fieldKey(netflow.NFV9_FIELD_OUT_BYTES)]; v != float64(500) {
		t.Errorf("expected outBytes=500, got %v", v)
	}
	if v := m[fieldKey(netflow.NFV9_FIELD_OUT_PKTS)]; v != float64(5) {
		t.Errorf("expected outPackets=5, got %v", v)
	}
	if v := m[fieldKey(netflow.NFV9_FIELD_DIRECTION)]; v != float64(0) {
		t.Errorf("expected direction=0, got %v", v)
	}
}

func TestNtopngJson_toJSON_V5Fallback(t *testing.T) {
	d := &NtopngJson{}
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			Etype:   0x800,
			SrcAddr: []byte{1, 2, 3, 4},
			DstAddr: []byte{5, 6, 7, 8},
			NextHop: []byte{0, 0, 0, 0},
			Bytes:   8888,
			Packets: 44,
		},
		InBytes:   0,
		InPackets: 0,
	}
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := decodeJSON(t, data)
	if v := m[fieldKey(netflow.NFV9_FIELD_IN_BYTES)]; v != float64(8888) {
		t.Errorf("expected NFv5 fallback inBytes=8888, got %v", v)
	}
	if v := m[fieldKey(netflow.NFV9_FIELD_IN_PKTS)]; v != float64(44) {
		t.Errorf("expected NFv5 fallback inPackets=44, got %v", v)
	}
}

func TestNtopngJson_toJSON_Timestamps(t *testing.T) {
	d := &NtopngJson{}
	extFlow := newTestExtFlowIPv4()
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := decodeJSON(t, data)
	// 1_700_000_000_000_000_000 ns = 1700000000 seconds
	if v := m[fieldKey(netflow.NFV9_FIELD_FIRST_SWITCHED)]; v != float64(1700000000) {
		t.Errorf("expected firstSwitched=1700000000, got %v", v)
	}
	if v := m[fieldKey(netflow.NFV9_FIELD_LAST_SWITCHED)]; v != float64(1700000001) {
		t.Errorf("expected lastSwitched=1700000001, got %v", v)
	}
}

func TestNtopngJson_toJSON_ICMP(t *testing.T) {
	d := &NtopngJson{}
	extFlow := newTestExtFlowIPv4() // has IcmpType=3, IcmpCode=4
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := decodeJSON(t, data)
	// (3 << 8) | 4 = 772
	if v := m[fieldKey(netflow.NFV9_FIELD_ICMP_TYPE)]; v != float64(772) {
		t.Errorf("expected icmpType=772, got %v", v)
	}
}

func TestNtopngJson_toJSON_MAC(t *testing.T) {
	d := &NtopngJson{}
	extFlow := newTestExtFlowIPv4()
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := decodeJSON(t, data)

	// Verify MAC fields are present and are non-empty MAC address strings.
	// Encoding uses binary.BigEndian.PutUint64 into [8]byte, then copies the low 6 bytes.
	srcMac, ok := m[fieldKey(netflow.NFV9_FIELD_OUT_SRC_MAC)].(string)
	if !ok || srcMac == "" {
		t.Errorf("expected non-empty srcMac string, got %v", m[fieldKey(netflow.NFV9_FIELD_OUT_SRC_MAC)])
	}
	dstMac, ok := m[fieldKey(netflow.NFV9_FIELD_IN_DST_MAC)].(string)
	if !ok || dstMac == "" {
		t.Errorf("expected non-empty dstMac string, got %v", m[fieldKey(netflow.NFV9_FIELD_IN_DST_MAC)])
	}
	if srcMac == dstMac {
		t.Errorf("expected srcMac != dstMac, both were %q", srcMac)
	}

	// SrcMac=0x001122334455 → BigEndian 8 bytes [00 00 00 11 22 33 44 55], low 6 = 00:11:22:33:44:55
	if srcMac != "00:11:22:33:44:55" {
		t.Errorf("srcMac BigEndian encoding wrong: expected 00:11:22:33:44:55, got %q", srcMac)
	}
	// DstMac=0x665544332211 → BigEndian 8 bytes [00 00 66 55 44 33 22 11], low 6 = 66:55:44:33:22:11
	if dstMac != "66:55:44:33:22:11" {
		t.Errorf("dstMac BigEndian encoding wrong: expected 66:55:44:33:22:11, got %q", dstMac)
	}
}

func TestNtopngJson_toJSON_SamplerIPv4(t *testing.T) {
	d := &NtopngJson{}
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			Etype:          0x800,
			SrcAddr:        []byte{1, 2, 3, 4},
			DstAddr:        []byte{5, 6, 7, 8},
			NextHop:        []byte{0, 0, 0, 0},
			SamplerAddress: []byte{172, 16, 1, 254},
		},
	}
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := decodeJSON(t, data)
	// IPFIX_FIELD_exporterIPv4Address = 130
	if v := m[fieldKey(netflow.IPFIX_FIELD_exporterIPv4Address)]; v != "172.16.1.254" {
		t.Errorf("expected exporter=172.16.1.254, got %v", v)
	}
	// IPv6 exporter should NOT be set
	if _, ok := m[fieldKey(netflow.IPFIX_FIELD_exporterIPv6Address)]; ok {
		t.Error("unexpected IPv6 exporter field in IPv4 sampler flow")
	}
}

func TestNtopngJson_toJSON_SamplerIPv6(t *testing.T) {
	d := &NtopngJson{}
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			Etype:          0x86dd,
			SrcAddr:        make([]byte, 16),
			DstAddr:        make([]byte, 16),
			NextHop:        make([]byte, 16),
			SamplerAddress: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
	}
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := decodeJSON(t, data)
	// IPFIX_FIELD_exporterIPv6Address = 131
	if v := m[fieldKey(netflow.IPFIX_FIELD_exporterIPv6Address)]; v != "2001:db8::1" {
		t.Errorf("expected exporter=2001:db8::1, got %v", v)
	}
}

func TestNtopngJson_Format_Invalid(t *testing.T) {
	d := &NtopngJson{}
	_, _, err := d.Format("not a flow message")
	if err == nil {
		t.Fatal("expected error for invalid input, got nil")
	}
}

func TestNtopngJson_toJSON_AllFieldsPresent(t *testing.T) {
	// Verify that toJSON produces valid, non-empty JSON for a well-formed flow.
	d := &NtopngJson{}
	extFlow := newTestExtFlowIPv4()
	data, err := d.toJSON(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON payload")
	}
	m := decodeJSON(t, data)
	// Spot-check a handful of required keys are present.
	required := []int{
		netflow.NFV9_FIELD_IN_BYTES,
		netflow.NFV9_FIELD_IN_PKTS,
		netflow.NFV9_FIELD_PROTOCOL,
		netflow.NFV9_FIELD_L4_SRC_PORT,
		netflow.NFV9_FIELD_FIRST_SWITCHED,
	}
	for _, key := range required {
		if _, ok := m[fieldKey(key)]; !ok {
			t.Errorf("expected key %d in JSON output", key)
		}
	}
}

// staticKeyData wraps a byte slice and returns it as a ZMQ key.
type staticKeyData struct {
	key []byte
}

func (s *staticKeyData) Key() []byte { return s.key }

func TestNtopngJson_Format_IgnoresNonFlowKey(t *testing.T) {
	// A value that implements Key() but is not a ProtoProducerMessage should
	// return an error from castToExtendedFlowMsg but still return the key bytes.
	d := &NtopngJson{}
	data := &staticKeyData{key: []byte("test-key")}
	_, _, err := d.Format(data)
	if err == nil {
		t.Fatal("expected error for non-ProtoProducerMessage, got nil")
	}
}

// TestNtopngJson_Format_Success tests the full Format() success path.
// Key() on an uninitialized ProtoProducerMessage panics; Format() recovers from it.
func TestNtopngJson_Format_Success(t *testing.T) {
	d := &NtopngJson{}
	ppm := newTestProtoMsg()
	_, data, err := d.Format(ppm)
	if err != nil {
		t.Fatalf("Format() unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("Format() returned empty data")
	}
}
