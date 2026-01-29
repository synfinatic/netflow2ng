package dedup

import (
	"encoding/binary"
	"hash/fnv"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func SetLogger(l *logrus.Logger) {
	log = l
}

// FlowKey represents the unique identifier for a flow (5-tuple + exporter)
type FlowKey struct {
	SrcIP    [16]byte // IPv6 capable
	DstIP    [16]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	// Include exporter info to handle same flow from multiple exporters
	ExporterIP [16]byte
	SourceID   uint32
}

// Hash returns a hash of the flow key
func (k *FlowKey) Hash() uint64 {
	h := fnv.New64a()
	h.Write(k.SrcIP[:])
	h.Write(k.DstIP[:])
	binary.Write(h, binary.BigEndian, k.SrcPort)
	binary.Write(h, binary.BigEndian, k.DstPort)
	h.Write([]byte{k.Protocol})
	h.Write(k.ExporterIP[:])
	binary.Write(h, binary.BigEndian, k.SourceID)
	return h.Sum64()
}

// FlowEntry represents a cached flow entry
type FlowEntry struct {
	Key          FlowKey
	FirstSeen    time.Time
	LastSeen     time.Time
	Bytes        uint64
	Packets      uint64
	FlowSeq      uint64 // Sequence number for ordering
	hash         uint64
	prev, next   *FlowEntry // LRU list pointers
}

// DedupCache implements a per-exporter deduplication cache with TTL and size bounds
type DedupCache struct {
	// Configuration
	maxSize  int
	ttl      time.Duration

	// Per-exporter caches using sharding to reduce lock contention
	shards     []*cacheShard
	numShards  int

	// Metrics
	metrics *DedupMetrics

	// Background cleanup
	cleanupTicker *time.Ticker
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// cacheShard is a single shard of the cache
type cacheShard struct {
	entries map[uint64]*FlowEntry
	// LRU list
	head, tail *FlowEntry
	size       int
	maxSize    int
	mu         sync.Mutex
}

// DedupMetrics holds prometheus metrics for deduplication
type DedupMetrics struct {
	CacheHits        prometheus.Counter
	CacheMisses      prometheus.Counter
	DuplicatesFound  prometheus.Counter
	Evictions        prometheus.Counter
	ExpiredEvictions prometheus.Counter
	CacheSize        prometheus.Gauge
	CacheCapacity    prometheus.Gauge
}

// NewDedupMetrics creates prometheus metrics for deduplication
func NewDedupMetrics(namespace string) *DedupMetrics {
	return &DedupMetrics{
		CacheHits: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dedup",
			Name:      "cache_hits_total",
			Help:      "Total number of cache hits (duplicate flows)",
		}),
		CacheMisses: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dedup",
			Name:      "cache_misses_total",
			Help:      "Total number of cache misses (new flows)",
		}),
		DuplicatesFound: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dedup",
			Name:      "duplicates_total",
			Help:      "Total number of duplicate flows suppressed",
		}),
		Evictions: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dedup",
			Name:      "evictions_total",
			Help:      "Total number of cache evictions due to size limit",
		}),
		ExpiredEvictions: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "dedup",
			Name:      "expired_evictions_total",
			Help:      "Total number of cache evictions due to TTL expiry",
		}),
		CacheSize: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "dedup",
			Name:      "cache_size",
			Help:      "Current number of entries in the cache",
		}),
		CacheCapacity: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "dedup",
			Name:      "cache_capacity",
			Help:      "Maximum capacity of the cache",
		}),
	}
}

// DedupCacheConfig holds configuration for the dedup cache
type DedupCacheConfig struct {
	MaxSize         int            // Maximum total entries across all shards
	TTL             time.Duration  // Time-to-live for entries
	NumShards       int            // Number of shards (default: 16)
	CleanupInterval time.Duration  // How often to run cleanup (default: TTL/4)
	Metrics         *DedupMetrics
}

// NewDedupCache creates a new deduplication cache
func NewDedupCache(cfg *DedupCacheConfig) *DedupCache {
	if cfg.NumShards <= 0 {
		cfg.NumShards = 16
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = cfg.TTL / 4
		if cfg.CleanupInterval < time.Second {
			cfg.CleanupInterval = time.Second
		}
	}

	maxPerShard := cfg.MaxSize / cfg.NumShards
	if maxPerShard < 1 {
		maxPerShard = 1
	}

	shards := make([]*cacheShard, cfg.NumShards)
	for i := range shards {
		shards[i] = &cacheShard{
			entries: make(map[uint64]*FlowEntry),
			maxSize: maxPerShard,
		}
	}

	c := &DedupCache{
		maxSize:   cfg.MaxSize,
		ttl:       cfg.TTL,
		shards:    shards,
		numShards: cfg.NumShards,
		metrics:   cfg.Metrics,
		stopCh:    make(chan struct{}),
	}

	if cfg.Metrics != nil {
		cfg.Metrics.CacheCapacity.Set(float64(cfg.MaxSize))
	}

	// Start background cleanup
	c.cleanupTicker = time.NewTicker(cfg.CleanupInterval)
	c.wg.Add(1)
	go c.cleanupLoop()

	return c
}

func (c *DedupCache) getShard(hash uint64) *cacheShard {
	return c.shards[hash%uint64(c.numShards)]
}

// CheckDuplicate checks if a flow is a duplicate. Returns true if this is a duplicate
// that should be suppressed. Updates the cache entry if not suppressed.
//
// Deduplication heuristics:
// - A flow is considered duplicate if we've seen it within the TTL window
// - Long-lived flows: We update the entry but don't suppress if the flow
//   has been active for more than TTL (allows periodic updates through)
// - We track bytes/packets to detect flow continuations vs true duplicates
func (c *DedupCache) CheckDuplicate(key *FlowKey, bytes, packets uint64, flowSeq uint64) (isDuplicate bool) {
	hash := key.Hash()
	shard := c.getShard(hash)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := time.Now()
	entry, exists := shard.entries[hash]

	if exists {
		// Check if entry has expired
		if now.Sub(entry.LastSeen) > c.ttl {
			// Entry expired, treat as new flow
			entry.FirstSeen = now
			entry.LastSeen = now
			entry.Bytes = bytes
			entry.Packets = packets
			entry.FlowSeq = flowSeq
			shard.moveToFront(entry)

			if c.metrics != nil {
				c.metrics.CacheMisses.Inc()
			}
			return false
		}

		// Entry exists and is still valid - check for duplicate
		//
		// Heuristic: If bytes/packets haven't changed and we're within TTL,
		// this is likely a duplicate. However, for long-lived flows that
		// send periodic updates, we want to allow through if:
		// 1. The flow sequence has advanced
		// 2. The byte/packet counts have increased
		// 3. The flow has been active longer than TTL (periodic refresh)

		isDuplicate = true

		// Allow through if flow data has increased (continuation, not duplicate)
		if bytes > entry.Bytes || packets > entry.Packets {
			isDuplicate = false
		}

		// Allow through if sequence number advanced (prevents suppressing updates)
		if flowSeq > entry.FlowSeq && flowSeq != 0 {
			isDuplicate = false
		}

		// For long-lived flows (active > TTL), allow periodic updates through
		// This prevents legitimate flow updates from being suppressed
		flowAge := now.Sub(entry.FirstSeen)
		if flowAge > c.ttl && now.Sub(entry.LastSeen) > c.ttl/2 {
			isDuplicate = false
		}

		// Update entry regardless
		entry.LastSeen = now
		if bytes > entry.Bytes {
			entry.Bytes = bytes
		}
		if packets > entry.Packets {
			entry.Packets = packets
		}
		if flowSeq > entry.FlowSeq {
			entry.FlowSeq = flowSeq
		}
		shard.moveToFront(entry)

		if c.metrics != nil {
			c.metrics.CacheHits.Inc()
			if isDuplicate {
				c.metrics.DuplicatesFound.Inc()
			}
		}

		return isDuplicate
	}

	// New flow - add to cache
	entry = &FlowEntry{
		Key:       *key,
		FirstSeen: now,
		LastSeen:  now,
		Bytes:     bytes,
		Packets:   packets,
		FlowSeq:   flowSeq,
		hash:      hash,
	}

	// Evict if at capacity
	if shard.size >= shard.maxSize {
		shard.evictOldest()
		if c.metrics != nil {
			c.metrics.Evictions.Inc()
		}
	}

	shard.entries[hash] = entry
	shard.addToFront(entry)
	shard.size++

	if c.metrics != nil {
		c.metrics.CacheMisses.Inc()
		c.metrics.CacheSize.Inc()
	}

	return false
}

// moveToFront moves an entry to the front of the LRU list
func (s *cacheShard) moveToFront(entry *FlowEntry) {
	if s.head == entry {
		return
	}

	// Remove from current position
	if entry.prev != nil {
		entry.prev.next = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	}
	if s.tail == entry {
		s.tail = entry.prev
	}

	// Add to front
	entry.prev = nil
	entry.next = s.head
	if s.head != nil {
		s.head.prev = entry
	}
	s.head = entry
	if s.tail == nil {
		s.tail = entry
	}
}

// addToFront adds a new entry to the front of the LRU list
func (s *cacheShard) addToFront(entry *FlowEntry) {
	entry.prev = nil
	entry.next = s.head
	if s.head != nil {
		s.head.prev = entry
	}
	s.head = entry
	if s.tail == nil {
		s.tail = entry
	}
}

// evictOldest removes the oldest entry from the cache
func (s *cacheShard) evictOldest() {
	if s.tail == nil {
		return
	}

	entry := s.tail

	// Remove from list
	if entry.prev != nil {
		entry.prev.next = nil
	}
	s.tail = entry.prev
	if s.head == entry {
		s.head = nil
	}

	// Remove from map
	delete(s.entries, entry.hash)
	s.size--
}

// cleanupLoop runs periodic cleanup of expired entries
func (c *DedupCache) cleanupLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.cleanupTicker.C:
			c.cleanupExpired()
		case <-c.stopCh:
			return
		}
	}
}

// cleanupExpired removes expired entries from the cache
func (c *DedupCache) cleanupExpired() {
	now := time.Now()
	var totalSize atomic.Int64

	for _, shard := range c.shards {
		shard.mu.Lock()

		// Walk from tail (oldest) and remove expired
		entry := shard.tail
		for entry != nil {
			if now.Sub(entry.LastSeen) > c.ttl {
				prev := entry.prev

				// Remove from list
				if entry.prev != nil {
					entry.prev.next = entry.next
				}
				if entry.next != nil {
					entry.next.prev = entry.prev
				}
				if shard.head == entry {
					shard.head = entry.next
				}
				if shard.tail == entry {
					shard.tail = entry.prev
				}

				// Remove from map
				delete(shard.entries, entry.hash)
				shard.size--

				if c.metrics != nil {
					c.metrics.ExpiredEvictions.Inc()
				}

				entry = prev
			} else {
				// Since list is ordered by access time, no more expired entries
				break
			}
		}

		totalSize.Add(int64(shard.size))
		shard.mu.Unlock()
	}

	if c.metrics != nil {
		c.metrics.CacheSize.Set(float64(totalSize.Load()))
	}
}

// Size returns the current total size of the cache
func (c *DedupCache) Size() int {
	var total int
	for _, shard := range c.shards {
		shard.mu.Lock()
		total += shard.size
		shard.mu.Unlock()
	}
	return total
}

// Clear removes all entries from the cache
func (c *DedupCache) Clear() {
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.entries = make(map[uint64]*FlowEntry)
		shard.head = nil
		shard.tail = nil
		shard.size = 0
		shard.mu.Unlock()
	}

	if c.metrics != nil {
		c.metrics.CacheSize.Set(0)
	}
}

// Stop stops the background cleanup routine
func (c *DedupCache) Stop() {
	close(c.stopCh)
	c.cleanupTicker.Stop()
	c.wg.Wait()
}

// MakeFlowKey creates a FlowKey from flow parameters
func MakeFlowKey(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, exporterIP net.IP, sourceID uint32) FlowKey {
	key := FlowKey{
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
		SourceID: sourceID,
	}

	// Handle IPv4 and IPv6
	if srcIP4 := srcIP.To4(); srcIP4 != nil {
		copy(key.SrcIP[12:], srcIP4)
	} else {
		copy(key.SrcIP[:], srcIP.To16())
	}

	if dstIP4 := dstIP.To4(); dstIP4 != nil {
		copy(key.DstIP[12:], dstIP4)
	} else {
		copy(key.DstIP[:], dstIP.To16())
	}

	if expIP4 := exporterIP.To4(); expIP4 != nil {
		copy(key.ExporterIP[12:], expIP4)
	} else if exporterIP != nil {
		copy(key.ExporterIP[:], exporterIP.To16())
	}

	return key
}
