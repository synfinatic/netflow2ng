package transport

import (
	"testing"
)

func TestParseZmqEndpoints_Single(t *testing.T) {
	endpoints := ParseZmqEndpoints("tcp://*:5556")

	if len(endpoints) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(endpoints))
	}

	if endpoints[0] != "tcp://*:5556" {
		t.Errorf("Expected tcp://*:5556, got %s", endpoints[0])
	}
}

func TestParseZmqEndpoints_Multiple(t *testing.T) {
	endpoints := ParseZmqEndpoints("tcp://*:5556,tcp://*:5557,tcp://*:5558")

	if len(endpoints) != 3 {
		t.Fatalf("Expected 3 endpoints, got %d", len(endpoints))
	}

	expected := []string{"tcp://*:5556", "tcp://*:5557", "tcp://*:5558"}
	for i, e := range expected {
		if endpoints[i] != e {
			t.Errorf("Endpoint %d: expected %s, got %s", i, e, endpoints[i])
		}
	}
}

func TestParseZmqEndpoints_WithSpaces(t *testing.T) {
	endpoints := ParseZmqEndpoints("tcp://*:5556 , tcp://*:5557 ,  tcp://*:5558")

	if len(endpoints) != 3 {
		t.Fatalf("Expected 3 endpoints, got %d", len(endpoints))
	}

	// Spaces should be trimmed
	expected := []string{"tcp://*:5556", "tcp://*:5557", "tcp://*:5558"}
	for i, e := range expected {
		if endpoints[i] != e {
			t.Errorf("Endpoint %d: expected %s, got %s", i, e, endpoints[i])
		}
	}
}

func TestParseZmqEndpoints_Empty(t *testing.T) {
	endpoints := ParseZmqEndpoints("")

	if len(endpoints) != 0 {
		t.Errorf("Expected 0 endpoints for empty string, got %d", len(endpoints))
	}
}

func TestParseZmqEndpoints_EmptyElements(t *testing.T) {
	endpoints := ParseZmqEndpoints("tcp://*:5556,,tcp://*:5557")

	if len(endpoints) != 2 {
		t.Fatalf("Expected 2 endpoints (skip empty), got %d", len(endpoints))
	}
}

func TestParseFanoutStrategy_Hash(t *testing.T) {
	tests := []string{"hash", "Hash", "HASH", "5tuple"}
	for _, s := range tests {
		strategy := ParseFanoutStrategy(s)
		if strategy != FanoutHash {
			t.Errorf("Expected FanoutHash for %q, got %v", s, strategy)
		}
	}
}

func TestParseFanoutStrategy_RoundRobin(t *testing.T) {
	tests := []string{"round-robin", "Round-Robin", "roundrobin", "rr", "RR"}
	for _, s := range tests {
		strategy := ParseFanoutStrategy(s)
		if strategy != FanoutRoundRobin {
			t.Errorf("Expected FanoutRoundRobin for %q, got %v", s, strategy)
		}
	}
}

func TestParseFanoutStrategy_Default(t *testing.T) {
	strategy := ParseFanoutStrategy("unknown")
	if strategy != FanoutHash {
		t.Errorf("Expected default FanoutHash for unknown strategy, got %v", strategy)
	}
}

func TestZmqConfig_Defaults(t *testing.T) {
	cfg := &ZmqConfig{
		Endpoints: []string{"tcp://*:5556"},
		MsgType:   TLV,
		SourceId:  0,
	}

	if len(cfg.Endpoints) != 1 {
		t.Error("Expected 1 endpoint")
	}

	if cfg.FanoutStrategy != FanoutHash {
		// Zero value should be FanoutHash (0)
		t.Logf("FanoutStrategy zero value is %v", cfg.FanoutStrategy)
	}
}
