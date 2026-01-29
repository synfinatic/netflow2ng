package dedup

import (
	"net"
	"testing"
	"time"
)

func TestDedupCache_BasicDuplication(t *testing.T) {
	cache := NewDedupCache(&DedupCacheConfig{
		MaxSize: 1000,
		TTL:     time.Minute,
	})
	defer cache.Stop()

	key := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	// First occurrence - should NOT be duplicate
	isDup := cache.CheckDuplicate(&key, 1000, 10, 1)
	if isDup {
		t.Error("First occurrence should not be duplicate")
	}

	// Immediate second occurrence with same values - should be duplicate
	isDup = cache.CheckDuplicate(&key, 1000, 10, 1)
	if !isDup {
		t.Error("Immediate repeat should be duplicate")
	}
}

func TestDedupCache_UpdatedFlow(t *testing.T) {
	cache := NewDedupCache(&DedupCacheConfig{
		MaxSize: 1000,
		TTL:     time.Minute,
	})
	defer cache.Stop()

	key := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	// First occurrence
	cache.CheckDuplicate(&key, 1000, 10, 1)

	// Updated flow with more bytes - should NOT be duplicate
	isDup := cache.CheckDuplicate(&key, 2000, 20, 2)
	if isDup {
		t.Error("Flow with increased bytes should not be duplicate")
	}
}

func TestDedupCache_SequenceAdvance(t *testing.T) {
	cache := NewDedupCache(&DedupCacheConfig{
		MaxSize: 1000,
		TTL:     time.Minute,
	})
	defer cache.Stop()

	key := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	// First occurrence
	cache.CheckDuplicate(&key, 1000, 10, 1)

	// Same bytes/packets but sequence advanced - should NOT be duplicate
	isDup := cache.CheckDuplicate(&key, 1000, 10, 2)
	if isDup {
		t.Error("Flow with advanced sequence should not be duplicate")
	}
}

func TestDedupCache_DifferentFlows(t *testing.T) {
	cache := NewDedupCache(&DedupCacheConfig{
		MaxSize: 1000,
		TTL:     time.Minute,
	})
	defer cache.Stop()

	key1 := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	key2 := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.3"), // Different dst
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	// Both should not be duplicates
	isDup1 := cache.CheckDuplicate(&key1, 1000, 10, 1)
	isDup2 := cache.CheckDuplicate(&key2, 1000, 10, 1)

	if isDup1 || isDup2 {
		t.Error("Different flows should not be duplicates")
	}
}

func TestDedupCache_TTLExpiry(t *testing.T) {
	cache := NewDedupCache(&DedupCacheConfig{
		MaxSize:         1000,
		TTL:             50 * time.Millisecond,
		CleanupInterval: 10 * time.Millisecond,
	})
	defer cache.Stop()

	key := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	// First occurrence
	cache.CheckDuplicate(&key, 1000, 10, 1)

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Should not be duplicate after TTL
	isDup := cache.CheckDuplicate(&key, 1000, 10, 1)
	if isDup {
		t.Error("Flow after TTL expiry should not be duplicate")
	}
}

func TestDedupCache_Eviction(t *testing.T) {
	cache := NewDedupCache(&DedupCacheConfig{
		MaxSize:   8,
		TTL:       time.Minute,
		NumShards: 2, // 4 per shard
	})
	defer cache.Stop()

	// Fill cache with more than capacity
	for i := 0; i < 20; i++ {
		key := MakeFlowKey(
			net.ParseIP("192.168.1.1"),
			net.IP{192, 168, 1, byte(i)},
			uint16(i), 80, 6,
			net.ParseIP("10.0.0.1"),
			100,
		)
		cache.CheckDuplicate(&key, 1000, 10, 1)
	}

	// Size should be bounded
	size := cache.Size()
	if size > 16 { // Some slack due to sharding
		t.Errorf("Cache size %d exceeds expected max", size)
	}
}

func TestDedupCache_Clear(t *testing.T) {
	cache := NewDedupCache(&DedupCacheConfig{
		MaxSize: 1000,
		TTL:     time.Minute,
	})
	defer cache.Stop()

	// Add some entries
	for i := 0; i < 10; i++ {
		key := MakeFlowKey(
			net.ParseIP("192.168.1.1"),
			net.IP{192, 168, 1, byte(i)},
			uint16(i), 80, 6,
			net.ParseIP("10.0.0.1"),
			100,
		)
		cache.CheckDuplicate(&key, 1000, 10, 1)
	}

	if cache.Size() != 10 {
		t.Errorf("Expected size 10, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", cache.Size())
	}
}

func TestMakeFlowKey_IPv4(t *testing.T) {
	key := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	if key.SrcPort != 12345 {
		t.Errorf("Expected src port 12345, got %d", key.SrcPort)
	}
	if key.DstPort != 80 {
		t.Errorf("Expected dst port 80, got %d", key.DstPort)
	}
	if key.Protocol != 6 {
		t.Errorf("Expected protocol 6, got %d", key.Protocol)
	}
}

func TestMakeFlowKey_IPv6(t *testing.T) {
	key := MakeFlowKey(
		net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8::2"),
		12345, 443, 6,
		net.ParseIP("2001:db8::100"),
		200,
	)

	if key.SrcPort != 12345 {
		t.Errorf("Expected src port 12345, got %d", key.SrcPort)
	}
	if key.SourceID != 200 {
		t.Errorf("Expected source ID 200, got %d", key.SourceID)
	}
}

func TestFlowKey_Hash(t *testing.T) {
	key1 := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	key2 := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	key3 := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.3"), // Different
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	if key1.Hash() != key2.Hash() {
		t.Error("Same keys should have same hash")
	}

	if key1.Hash() == key3.Hash() {
		t.Error("Different keys should have different hash")
	}
}

func BenchmarkDedupCache_CheckDuplicate(b *testing.B) {
	cache := NewDedupCache(&DedupCacheConfig{
		MaxSize: 100000,
		TTL:     time.Minute,
	})
	defer cache.Stop()

	key := MakeFlowKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		12345, 80, 6,
		net.ParseIP("10.0.0.1"),
		100,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.CheckDuplicate(&key, uint64(i), uint64(i), uint64(i))
	}
}

func BenchmarkDedupCache_ManyFlows(b *testing.B) {
	cache := NewDedupCache(&DedupCacheConfig{
		MaxSize: 100000,
		TTL:     time.Minute,
	})
	defer cache.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := MakeFlowKey(
			net.ParseIP("192.168.1.1"),
			net.IP{192, 168, byte(i >> 8), byte(i)},
			uint16(i%65535), 80, 6,
			net.ParseIP("10.0.0.1"),
			100,
		)
		cache.CheckDuplicate(&key, 1000, 10, uint64(i))
	}
}
