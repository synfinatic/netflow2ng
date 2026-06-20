package formatter

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"math"
	"testing"

	pb "github.com/netsampler/goflow2/v2/pb"
	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/synfinatic/netflow2ng/proto"
)

// --- minimalBytesUint ---

func TestMinimalBytesUint_Uint8_Zero(t *testing.T) {
	minType, b := minimalBytesUint(0)
	if minType != ndpi_serialization_uint8 {
		t.Errorf("expected uint8, got %d", minType)
	}
	if len(b) != 1 || b[0] != 0 {
		t.Errorf("expected [0x00], got %v", b)
	}
}

func TestMinimalBytesUint_Uint8_Max(t *testing.T) {
	minType, b := minimalBytesUint(0xff)
	if minType != ndpi_serialization_uint8 {
		t.Errorf("expected uint8, got %d", minType)
	}
	if len(b) != 1 || b[0] != 0xff {
		t.Errorf("expected [0xff], got %v", b)
	}
}

func TestMinimalBytesUint_Uint16_Min(t *testing.T) {
	minType, b := minimalBytesUint(0x100)
	if minType != ndpi_serialization_uint16 {
		t.Errorf("expected uint16, got %d", minType)
	}
	if len(b) != 2 {
		t.Errorf("expected 2 bytes, got %d", len(b))
	}
	if binary.BigEndian.Uint16(b) != 0x100 {
		t.Errorf("expected 0x0100, got 0x%04x", binary.BigEndian.Uint16(b))
	}
}

func TestMinimalBytesUint_Uint16_Max(t *testing.T) {
	minType, b := minimalBytesUint(0xffff)
	if minType != ndpi_serialization_uint16 {
		t.Errorf("expected uint16, got %d", minType)
	}
	if len(b) != 2 {
		t.Errorf("expected 2 bytes, got %d", len(b))
	}
}

func TestMinimalBytesUint_Uint32_Min(t *testing.T) {
	minType, b := minimalBytesUint(0x10000)
	if minType != ndpi_serialization_uint32 {
		t.Errorf("expected uint32, got %d", minType)
	}
	if len(b) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(b))
	}
	if binary.BigEndian.Uint32(b) != 0x10000 {
		t.Errorf("expected 0x00010000, got 0x%08x", binary.BigEndian.Uint32(b))
	}
}

func TestMinimalBytesUint_Uint32_Max(t *testing.T) {
	minType, b := minimalBytesUint(0xffffffff)
	if minType != ndpi_serialization_uint32 {
		t.Errorf("expected uint32, got %d", minType)
	}
	if len(b) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(b))
	}
}

func TestMinimalBytesUint_Uint64(t *testing.T) {
	v := uint64(0x100000000)
	minType, b := minimalBytesUint(v)
	if minType != ndpi_serialization_uint64 {
		t.Errorf("expected uint64, got %d", minType)
	}
	if len(b) != 8 {
		t.Errorf("expected 8 bytes, got %d", len(b))
	}
	if binary.BigEndian.Uint64(b) != v {
		t.Errorf("expected %d, got %d", v, binary.BigEndian.Uint64(b))
	}
}

// --- minimalBytesInt ---

func TestMinimalBytesInt_Int8_Min(t *testing.T) {
	minType, b := minimalBytesInt(math.MinInt8)
	if minType != ndpi_serialization_int8 {
		t.Errorf("expected int8, got %d", minType)
	}
	if len(b) != 1 {
		t.Errorf("expected 1 byte, got %d", len(b))
	}
	if int8(b[0]) != math.MinInt8 {
		t.Errorf("expected %d, got %d", math.MinInt8, int8(b[0]))
	}
}

func TestMinimalBytesInt_Int8_Max(t *testing.T) {
	minType, b := minimalBytesInt(math.MaxInt8)
	if minType != ndpi_serialization_int8 {
		t.Errorf("expected int8, got %d", minType)
	}
	if len(b) != 1 || int8(b[0]) != math.MaxInt8 {
		t.Errorf("expected %d, got %v", math.MaxInt8, b)
	}
}

func TestMinimalBytesInt_Int16_Positive(t *testing.T) {
	// 200 > MaxInt8 (127), must use int16
	minType, b := minimalBytesInt(200)
	if minType != ndpi_serialization_int16 {
		t.Errorf("expected int16 for 200, got %d", minType)
	}
	if len(b) != 2 {
		t.Errorf("expected 2 bytes, got %d", len(b))
	}
	if int16(binary.BigEndian.Uint16(b)) != 200 {
		t.Errorf("expected 200, got %d", int16(binary.BigEndian.Uint16(b)))
	}
}

func TestMinimalBytesInt_Int16_Negative(t *testing.T) {
	// -200 < MinInt8 (-128), must use int16
	minType, b := minimalBytesInt(-200)
	if minType != ndpi_serialization_int16 {
		t.Errorf("expected int16 for -200, got %d", minType)
	}
	if len(b) != 2 {
		t.Errorf("expected 2 bytes, got %d", len(b))
	}
	if int16(binary.BigEndian.Uint16(b)) != -200 {
		t.Errorf("expected -200, got %d", int16(binary.BigEndian.Uint16(b)))
	}
}

func TestMinimalBytesInt_Int32(t *testing.T) {
	v := int64(math.MaxInt16 + 1)
	minType, b := minimalBytesInt(v)
	if minType != ndpi_serialization_int32 {
		t.Errorf("expected int32, got %d", minType)
	}
	if len(b) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(b))
	}
}

func TestMinimalBytesInt_Int64(t *testing.T) {
	v := int64(math.MaxInt32 + 1)
	minType, b := minimalBytesInt(v)
	if minType != ndpi_serialization_int64 {
		t.Errorf("expected int64, got %d", minType)
	}
	if len(b) != 8 {
		t.Errorf("expected 8 bytes, got %d", len(b))
	}
	if int64(binary.BigEndian.Uint64(b)) != v {
		t.Errorf("expected %d, got %d", v, int64(binary.BigEndian.Uint64(b)))
	}
}

// --- serializeTlvItem ---

func TestSerializeTlvItem_UintKeyUintValue(t *testing.T) {
	// Example from file header: 0x22 0x0a 0x0b → K=uint8(10), V=uint8(11)
	item := ndpiItem{Key: 10, Value: uint8(11)}
	b, err := serializeTlvItem(item)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// type byte: (uint8 << 4) | uint8 = (2 << 4) | 2 = 0x22
	if b[0] != 0x22 {
		t.Errorf("expected type byte 0x22, got 0x%02x", b[0])
	}
	if b[1] != 0x0a {
		t.Errorf("expected key byte 0x0a, got 0x%02x", b[1])
	}
	if b[2] != 0x0b {
		t.Errorf("expected value byte 0x0b, got 0x%02x", b[2])
	}
	if len(b) != 3 {
		t.Errorf("expected 3 bytes, got %d", len(b))
	}
}

func TestSerializeTlvItem_UintKeyUint16Value(t *testing.T) {
	// Example: 0x23 0x0b 0x1f46 → K=uint8(11), V=uint16(8006)
	item := ndpiItem{Key: 11, Value: uint16(8006)}
	b, err := serializeTlvItem(item)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// type byte: (uint8 << 4) | uint16 = (2 << 4) | 3 = 0x23
	if b[0] != 0x23 {
		t.Errorf("expected type byte 0x23, got 0x%02x", b[0])
	}
	if b[1] != 0x0b {
		t.Errorf("expected key byte 0x0b, got 0x%02x", b[1])
	}
	v := binary.BigEndian.Uint16(b[2:4])
	if v != 8006 {
		t.Errorf("expected value 8006, got %d", v)
	}
}

func TestSerializeTlvItem_UintKeyStringValue(t *testing.T) {
	// Example: K=uint8(130), V="172.16.1.254" (12 bytes)
	// 0x2b 0x82 0x000c [12 bytes]
	item := ndpiItem{Key: 130, Value: "172.16.1.254"}
	b, err := serializeTlvItem(item)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// type byte: (uint8 << 4) | string = (2 << 4) | 11 = 0x2b
	if b[0] != 0x2b {
		t.Errorf("expected type byte 0x2b, got 0x%02x", b[0])
	}
	// key byte: 130 = 0x82
	if b[1] != 0x82 {
		t.Errorf("expected key byte 0x82, got 0x%02x", b[1])
	}
	// string length: 12 = 0x000c
	strLen := binary.BigEndian.Uint16(b[2:4])
	if strLen != 12 {
		t.Errorf("expected string length 12, got %d", strLen)
	}
	// string content
	if string(b[4:]) != "172.16.1.254" {
		t.Errorf("expected '172.16.1.254', got %q", string(b[4:]))
	}
}

func TestSerializeTlvItem_IntValue(t *testing.T) {
	// Value 0 as untyped int (direction field)
	item := ndpiItem{Key: uint16(netflow.NFV9_FIELD_DIRECTION), Value: 0}
	b, err := serializeTlvItem(item)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty serialization")
	}
}

func TestSerializeTlvItem_UnknownType(t *testing.T) {
	item := ndpiItem{Key: 1, Value: float64(3.14)}
	_, err := serializeTlvItem(item)
	if err == nil {
		t.Fatal("expected error for float64 value type, got nil")
	}
}

// --- serializeTlvRecord ---

func TestSerializeTlvRecord_MagicAndTerminator(t *testing.T) {
	items := []ndpiItem{
		{Key: 10, Value: uint8(11)},
	}
	b, err := serializeTlvRecord(items)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// First two bytes must be magic header 0x01 0x01
	if b[0] != 0x01 || b[1] != 0x01 {
		t.Errorf("expected magic bytes 0x01 0x01, got 0x%02x 0x%02x", b[0], b[1])
	}
	// Last byte must be end-of-record 0x01
	if b[len(b)-1] != ndpi_serialization_end_of_record {
		t.Errorf("expected end-of-record byte 0x01, got 0x%02x", b[len(b)-1])
	}
}

func TestSerializeTlvRecord_Empty(t *testing.T) {
	b, err := serializeTlvRecord(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 magic bytes + 1 terminator = 3 bytes
	if len(b) != 3 {
		t.Errorf("expected 3 bytes for empty record, got %d", len(b))
	}
}

func TestSerializeTlvRecord_SerializationError(t *testing.T) {
	// float64 value triggers an error in serializeTlvItem
	items := []ndpiItem{{Key: 1, Value: float64(1.0)}}
	_, err := serializeTlvRecord(items)
	if err == nil {
		t.Fatal("expected error for unknown type, got nil")
	}
}

// --- NtopngTlv.toTLV ---

func TestNtopngTlv_toTLV_IPv4_Valid(t *testing.T) {
	d := &NtopngTlv{}
	extFlow := newTestExtFlowIPv4()
	b, err := d.toTLV(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Must start with magic bytes and end with terminator
	if len(b) < 3 {
		t.Fatalf("output too short: %d bytes", len(b))
	}
	if b[0] != 0x01 || b[1] != 0x01 {
		t.Errorf("expected magic header 0x01 0x01, got 0x%02x 0x%02x", b[0], b[1])
	}
	if b[len(b)-1] != ndpi_serialization_end_of_record {
		t.Errorf("expected end-of-record terminator, got 0x%02x", b[len(b)-1])
	}
}

func TestNtopngTlv_toTLV_IPv6_Valid(t *testing.T) {
	d := &NtopngTlv{}
	extFlow := newTestExtFlowIPv6()
	b, err := d.toTLV(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) < 3 {
		t.Fatalf("output too short: %d bytes", len(b))
	}
	if b[0] != 0x01 || b[1] != 0x01 {
		t.Errorf("expected magic header 0x01 0x01, got 0x%02x 0x%02x", b[0], b[1])
	}
}

func TestNtopngTlv_toTLV_SamplerIPv4(t *testing.T) {
	d := &NtopngTlv{}
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			Etype:          0x800,
			SrcAddr:        []byte{1, 2, 3, 4},
			DstAddr:        []byte{5, 6, 7, 8},
			NextHop:        []byte{0, 0, 0, 0},
			SamplerAddress: []byte{10, 0, 0, 1},
		},
	}
	b, err := d.toTLV(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("expected non-empty TLV output")
	}
}

func TestNtopngTlv_toTLV_SamplerIPv6(t *testing.T) {
	d := &NtopngTlv{}
	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow: &pb.FlowMessage{
			Etype:          0x86dd,
			SrcAddr:        make([]byte, 16),
			DstAddr:        make([]byte, 16),
			NextHop:        make([]byte, 16),
			SamplerAddress: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
	}
	b, err := d.toTLV(extFlow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("expected non-empty TLV output")
	}
}

func TestNtopngTlv_Format_Invalid(t *testing.T) {
	d := &NtopngTlv{}
	_, _, err := d.Format("not a flow message")
	if err == nil {
		t.Fatal("expected error for invalid input, got nil")
	}
}

// --- compressJSON (transport package exposes this via formatter test reach-through) ---
// We test the zlib round-trip here since zlib is used in the TLV/JSON path.

// TestNtopngTlv_Format_Success tests the full Format() success path.
// Key() on an uninitialized ProtoProducerMessage panics; Format() recovers from it.
func TestNtopngTlv_Format_Success(t *testing.T) {
	d := &NtopngTlv{}
	ppm := newTestProtoMsg()
	_, data, err := d.Format(ppm)
	if err != nil {
		t.Fatalf("Format() unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("Format() returned empty data")
	}
}

func TestZlibRoundTrip(t *testing.T) {
	original := []byte(`{"key": "value", "number": 42}`)

	// Compress
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(original); err != nil {
		t.Fatalf("write error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	compressed := buf.Bytes()

	if len(compressed) == 0 {
		t.Fatal("expected non-empty compressed output")
	}

	// Decompress
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("zlib reader error: %v", err)
	}
	defer r.Close()
	decompressed, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Errorf("round-trip failed: got %q, want %q", decompressed, original)
	}
}
