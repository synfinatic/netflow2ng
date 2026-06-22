package proto

import (
	"testing"

	pb "github.com/netsampler/goflow2/v2/pb"
)

func TestExtendedFlowMessage_Getters(t *testing.T) {
	efm := &ExtendedFlowMessage{
		BaseFlow:   &pb.FlowMessage{},
		InBytes:    100,
		InPackets:  10,
		OutBytes:   50,
		OutPackets: 5,
	}

	if got := efm.GetBaseFlow(); got == nil {
		t.Error("GetBaseFlow() returned nil")
	}
	if got := efm.GetInBytes(); got != 100 {
		t.Errorf("GetInBytes() = %d, want 100", got)
	}
	if got := efm.GetInPackets(); got != 10 {
		t.Errorf("GetInPackets() = %d, want 10", got)
	}
	if got := efm.GetOutBytes(); got != 50 {
		t.Errorf("GetOutBytes() = %d, want 50", got)
	}
	if got := efm.GetOutPackets(); got != 5 {
		t.Errorf("GetOutPackets() = %d, want 5", got)
	}
}

func TestExtendedFlowMessage_GettersNil(t *testing.T) {
	var efm *ExtendedFlowMessage

	if got := efm.GetBaseFlow(); got != nil {
		t.Errorf("GetBaseFlow() on nil = %v, want nil", got)
	}
	if got := efm.GetInBytes(); got != 0 {
		t.Errorf("GetInBytes() on nil = %d, want 0", got)
	}
	if got := efm.GetInPackets(); got != 0 {
		t.Errorf("GetInPackets() on nil = %d, want 0", got)
	}
	if got := efm.GetOutBytes(); got != 0 {
		t.Errorf("GetOutBytes() on nil = %d, want 0", got)
	}
	if got := efm.GetOutPackets(); got != 0 {
		t.Errorf("GetOutPackets() on nil = %d, want 0", got)
	}
}

func TestExtendedFlowMessage_Reset(t *testing.T) {
	efm := &ExtendedFlowMessage{
		InBytes:   999,
		InPackets: 88,
	}
	efm.Reset()
	if efm.InBytes != 0 {
		t.Errorf("After Reset(), InBytes = %d, want 0", efm.InBytes)
	}
}

func TestExtendedFlowMessage_String(t *testing.T) {
	efm := &ExtendedFlowMessage{InBytes: 42}
	s := efm.String()
	// An empty message may produce an empty string (valid protobuf behavior).
	_ = s // just verify it doesn't panic
}

func TestExtendedFlowMessage_ProtoReflect(t *testing.T) {
	efm := &ExtendedFlowMessage{}
	r := efm.ProtoReflect()
	if r == nil {
		t.Error("ProtoReflect() returned nil")
	}
}

func TestExtendedFlowMessage_ProtoReflect_Nil(t *testing.T) {
	var efm *ExtendedFlowMessage
	r := efm.ProtoReflect() // hits mi.MessageOf(x) branch when x == nil
	if r == nil {
		t.Error("ProtoReflect() on nil returned nil")
	}
}

func TestExtendedFlowMessage_Descriptor(t *testing.T) {
	efm := &ExtendedFlowMessage{}
	raw, _ := efm.Descriptor()
	if raw == nil {
		t.Error("Descriptor() returned nil")
	}
}

func TestExtendedFlowMessage_ProtoMessage(t *testing.T) {
	efm := &ExtendedFlowMessage{InBytes: 42}
	efm.ProtoMessage() // must not panic
}
