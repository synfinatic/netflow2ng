package sampling

import (
	"net"
	"testing"
)

func TestSamplingTracker_UpdateAndGet(t *testing.T) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: true,
	})

	ip := net.ParseIP("192.168.1.1")
	observationDom := uint32(100)

	// Initially should return default
	info := tracker.GetSamplingRate(ip, observationDom)
	if info.Rate != 1 {
		t.Errorf("Expected default rate 1, got %d", info.Rate)
	}
	if info.Source != SourceUnknown {
		t.Errorf("Expected source Unknown, got %v", info.Source)
	}

	// Update sampling rate
	tracker.UpdateSamplingRate(ip, observationDom, 100, SamplingDeterministic, SourceIPFIXOptions)

	info = tracker.GetSamplingRate(ip, observationDom)
	if info.Rate != 100 {
		t.Errorf("Expected rate 100, got %d", info.Rate)
	}
	if info.Source != SourceIPFIXOptions {
		t.Errorf("Expected source IPFIXOptions, got %v", info.Source)
	}
	if info.Algorithm != SamplingDeterministic {
		t.Errorf("Expected algorithm Deterministic, got %v", info.Algorithm)
	}
}

func TestSamplingTracker_ScaleFlow(t *testing.T) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: true,
	})

	ip := net.ParseIP("192.168.1.1")
	observationDom := uint32(100)

	// Set sampling rate
	tracker.UpdateSamplingRate(ip, observationDom, 10, SamplingDeterministic, SourceSFlowHeader)

	// Scale flow
	bytes := uint64(1000)
	packets := uint64(5)

	scaledBytes, scaledPackets := tracker.ScaleFlow(ip, observationDom, bytes, packets)

	if scaledBytes != 10000 {
		t.Errorf("Expected scaled bytes 10000, got %d", scaledBytes)
	}
	if scaledPackets != 50 {
		t.Errorf("Expected scaled packets 50, got %d", scaledPackets)
	}
}

func TestSamplingTracker_ScalingDisabled(t *testing.T) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: false,
	})

	ip := net.ParseIP("192.168.1.1")
	observationDom := uint32(100)

	// Set sampling rate
	tracker.UpdateSamplingRate(ip, observationDom, 10, SamplingDeterministic, SourceSFlowHeader)

	// Scale flow - should NOT scale when disabled
	bytes := uint64(1000)
	packets := uint64(5)

	scaledBytes, scaledPackets := tracker.ScaleFlow(ip, observationDom, bytes, packets)

	if scaledBytes != 1000 {
		t.Errorf("Expected bytes 1000 (unscaled), got %d", scaledBytes)
	}
	if scaledPackets != 5 {
		t.Errorf("Expected packets 5 (unscaled), got %d", scaledPackets)
	}
}

func TestSamplingTracker_ZeroSampleRate(t *testing.T) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: true,
	})

	ip := net.ParseIP("192.168.1.1")
	observationDom := uint32(100)

	// Update with zero rate - should be treated as 1
	tracker.UpdateSamplingRate(ip, observationDom, 0, SamplingUnknown, SourceSFlowHeader)

	info := tracker.GetSamplingRate(ip, observationDom)
	if info.Rate != 1 {
		t.Errorf("Expected rate 1 (zero converted), got %d", info.Rate)
	}
}

func TestSamplingTracker_MultipleExporters(t *testing.T) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: true,
	})

	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")

	tracker.UpdateSamplingRate(ip1, 100, 10, SamplingDeterministic, SourceIPFIXOptions)
	tracker.UpdateSamplingRate(ip2, 100, 50, SamplingRandom, SourceSFlowHeader)
	tracker.UpdateSamplingRate(ip1, 200, 25, SamplingDeterministic, SourceNetFlowV9)

	info1 := tracker.GetSamplingRate(ip1, 100)
	info2 := tracker.GetSamplingRate(ip2, 100)
	info3 := tracker.GetSamplingRate(ip1, 200)

	if info1.Rate != 10 {
		t.Errorf("Expected rate 10 for ip1:100, got %d", info1.Rate)
	}
	if info2.Rate != 50 {
		t.Errorf("Expected rate 50 for ip2:100, got %d", info2.Rate)
	}
	if info3.Rate != 25 {
		t.Errorf("Expected rate 25 for ip1:200, got %d", info3.Rate)
	}
}

func TestSamplingTracker_ManualOverride(t *testing.T) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: true,
	})

	ip := net.ParseIP("192.168.1.1")

	// Set via protocol
	tracker.UpdateSamplingRate(ip, 100, 10, SamplingDeterministic, SourceIPFIXOptions)

	// Override manually
	tracker.SetManualRate(ip, 100, 500)

	info := tracker.GetSamplingRate(ip, 100)
	if info.Rate != 500 {
		t.Errorf("Expected manual rate 500, got %d", info.Rate)
	}
	if info.Source != SourceManual {
		t.Errorf("Expected source Manual, got %v", info.Source)
	}
}

func TestSamplingTracker_ClearExporter(t *testing.T) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: true,
	})

	ip := net.ParseIP("192.168.1.1")
	tracker.UpdateSamplingRate(ip, 100, 50, SamplingDeterministic, SourceIPFIXOptions)

	// Verify it's set
	info := tracker.GetSamplingRate(ip, 100)
	if info.Rate != 50 {
		t.Error("Rate not set correctly")
	}

	// Clear
	tracker.ClearExporter(ip, 100)

	// Should return default now
	info = tracker.GetSamplingRate(ip, 100)
	if info.Rate != 1 {
		t.Errorf("Expected default rate 1 after clear, got %d", info.Rate)
	}
	if info.Source != SourceUnknown {
		t.Errorf("Expected source Unknown after clear, got %v", info.Source)
	}
}

func TestSamplingTracker_GetAllSamplingInfo(t *testing.T) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: true,
	})

	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")

	tracker.UpdateSamplingRate(ip1, 100, 10, SamplingDeterministic, SourceIPFIXOptions)
	tracker.UpdateSamplingRate(ip2, 200, 20, SamplingRandom, SourceSFlowHeader)

	all := tracker.GetAllSamplingInfo()

	if len(all) != 2 {
		t.Errorf("Expected 2 exporters, got %d", len(all))
	}
}

func TestSamplingTracker_ToggleScaling(t *testing.T) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: true,
	})

	if !tracker.IsScalingEnabled() {
		t.Error("Scaling should be enabled initially")
	}

	tracker.SetScalingEnabled(false)

	if tracker.IsScalingEnabled() {
		t.Error("Scaling should be disabled after toggle")
	}
}

func BenchmarkSamplingTracker_ScaleFlow(b *testing.B) {
	tracker := NewSamplingTracker(&SamplingTrackerConfig{
		DefaultRate:    1,
		ScalingEnabled: true,
	})

	ip := net.ParseIP("192.168.1.1")
	tracker.UpdateSamplingRate(ip, 100, 128, SamplingDeterministic, SourceIPFIXOptions)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker.ScaleFlow(ip, 100, 1500, 1)
	}
}
