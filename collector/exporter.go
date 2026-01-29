package collector

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ExporterKey uniquely identifies a flow exporter
type ExporterKey struct {
	IP       string
	SourceID uint32
}

// ExporterStats holds statistics for a single exporter
type ExporterStats struct {
	key             ExporterKey
	packetsReceived atomic.Uint64
	bytesReceived   atomic.Uint64
	flowsProcessed  atomic.Uint64
	lastSeen        atomic.Int64 // Unix timestamp
	errors          atomic.Uint64
}

// NewExporterStats creates a new exporter stats tracker
func NewExporterStats(key ExporterKey) *ExporterStats {
	return &ExporterStats{
		key: key,
	}
}

// RecordPacket records a received packet from this exporter
func (e *ExporterStats) RecordPacket(bytes int) {
	e.packetsReceived.Add(1)
	e.bytesReceived.Add(uint64(bytes))
	e.lastSeen.Store(time.Now().Unix())
}

// RecordFlows records processed flows from this exporter
func (e *ExporterStats) RecordFlows(count int) {
	e.flowsProcessed.Add(uint64(count))
}

// RecordError records an error from this exporter
func (e *ExporterStats) RecordError() {
	e.errors.Add(1)
}

// GetStats returns current statistics
func (e *ExporterStats) GetStats() (packets, bytes, flows, errors uint64, lastSeen time.Time) {
	return e.packetsReceived.Load(),
		e.bytesReceived.Load(),
		e.flowsProcessed.Load(),
		e.errors.Load(),
		time.Unix(e.lastSeen.Load(), 0)
}

// ExporterRegistry tracks all known exporters and their statistics
type ExporterRegistry struct {
	exporters map[ExporterKey]*ExporterStats
	mu        sync.RWMutex
	metrics   *ExporterMetrics
}

// ExporterMetrics holds prometheus metrics for exporter tracking
type ExporterMetrics struct {
	PacketsReceived *prometheus.CounterVec
	BytesReceived   *prometheus.CounterVec
	FlowsProcessed  *prometheus.CounterVec
	Errors          *prometheus.CounterVec
	LastSeen        *prometheus.GaugeVec
	ActiveExporters prometheus.Gauge
}

// NewExporterMetrics creates prometheus metrics for exporter tracking
func NewExporterMetrics(namespace string) *ExporterMetrics {
	return &ExporterMetrics{
		PacketsReceived: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "exporter",
			Name:      "packets_received_total",
			Help:      "Total packets received per exporter",
		}, []string{"exporter_ip", "source_id"}),
		BytesReceived: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "exporter",
			Name:      "bytes_received_total",
			Help:      "Total bytes received per exporter",
		}, []string{"exporter_ip", "source_id"}),
		FlowsProcessed: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "exporter",
			Name:      "flows_processed_total",
			Help:      "Total flows processed per exporter",
		}, []string{"exporter_ip", "source_id"}),
		Errors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "exporter",
			Name:      "errors_total",
			Help:      "Total errors per exporter",
		}, []string{"exporter_ip", "source_id"}),
		LastSeen: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "exporter",
			Name:      "last_seen_timestamp",
			Help:      "Unix timestamp of last packet from exporter",
		}, []string{"exporter_ip", "source_id"}),
		ActiveExporters: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "exporter",
			Name:      "active_count",
			Help:      "Number of active exporters",
		}),
	}
}

// NewExporterRegistry creates a new exporter registry
func NewExporterRegistry(metrics *ExporterMetrics) *ExporterRegistry {
	return &ExporterRegistry{
		exporters: make(map[ExporterKey]*ExporterStats),
		metrics:   metrics,
	}
}

// GetOrCreate returns an existing exporter stats or creates a new one
func (r *ExporterRegistry) GetOrCreate(ip net.IP, sourceID uint32) *ExporterStats {
	key := ExporterKey{
		IP:       ip.String(),
		SourceID: sourceID,
	}

	r.mu.RLock()
	if stats, ok := r.exporters[key]; ok {
		r.mu.RUnlock()
		return stats
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if stats, ok := r.exporters[key]; ok {
		return stats
	}

	stats := NewExporterStats(key)
	r.exporters[key] = stats

	if r.metrics != nil {
		r.metrics.ActiveExporters.Set(float64(len(r.exporters)))
	}

	if log != nil {
		log.WithField("exporter", key.IP).WithField("source_id", key.SourceID).Info("New exporter registered")
	}

	return stats
}

// RecordPacket records a packet from an exporter
func (r *ExporterRegistry) RecordPacket(ip net.IP, sourceID uint32, bytes int) {
	stats := r.GetOrCreate(ip, sourceID)
	stats.RecordPacket(bytes)

	if r.metrics != nil {
		labels := prometheus.Labels{
			"exporter_ip": ip.String(),
			"source_id":   string(rune(sourceID)),
		}
		r.metrics.PacketsReceived.With(labels).Inc()
		r.metrics.BytesReceived.With(labels).Add(float64(bytes))
		r.metrics.LastSeen.With(labels).SetToCurrentTime()
	}
}

// RecordFlows records flows from an exporter
func (r *ExporterRegistry) RecordFlows(ip net.IP, sourceID uint32, count int) {
	stats := r.GetOrCreate(ip, sourceID)
	stats.RecordFlows(count)

	if r.metrics != nil {
		labels := prometheus.Labels{
			"exporter_ip": ip.String(),
			"source_id":   string(rune(sourceID)),
		}
		r.metrics.FlowsProcessed.With(labels).Add(float64(count))
	}
}

// RecordError records an error from an exporter
func (r *ExporterRegistry) RecordError(ip net.IP, sourceID uint32) {
	stats := r.GetOrCreate(ip, sourceID)
	stats.RecordError()

	if r.metrics != nil {
		labels := prometheus.Labels{
			"exporter_ip": ip.String(),
			"source_id":   string(rune(sourceID)),
		}
		r.metrics.Errors.With(labels).Inc()
	}
}

// ExporterStatsSnapshot is a point-in-time snapshot of exporter statistics
type ExporterStatsSnapshot struct {
	Key             ExporterKey
	PacketsReceived uint64
	BytesReceived   uint64
	FlowsProcessed  uint64
	Errors          uint64
	LastSeen        time.Time
}

// GetAllExporters returns a snapshot of all exporter statistics
func (r *ExporterRegistry) GetAllExporters() map[ExporterKey]ExporterStatsSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[ExporterKey]ExporterStatsSnapshot, len(r.exporters))
	for k, v := range r.exporters {
		packets, bytes, flows, errors, lastSeen := v.GetStats()
		result[k] = ExporterStatsSnapshot{
			Key:             k,
			PacketsReceived: packets,
			BytesReceived:   bytes,
			FlowsProcessed:  flows,
			Errors:          errors,
			LastSeen:        lastSeen,
		}
	}
	return result
}
