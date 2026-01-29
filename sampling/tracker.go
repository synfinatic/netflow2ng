package sampling

import (
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func SetLogger(l *logrus.Logger) {
	log = l
}

// SamplingAlgorithm represents the IPFIX sampling algorithm types
type SamplingAlgorithm uint8

const (
	SamplingUnknown            SamplingAlgorithm = 0
	SamplingDeterministic      SamplingAlgorithm = 1 // Systematic count-based (1:N)
	SamplingRandom             SamplingAlgorithm = 2 // Random n-out-of-N
	SamplingUniformProbability SamplingAlgorithm = 3 // Uniform probabilistic
	SamplingPropertyMatch      SamplingAlgorithm = 4 // Property match
	SamplingHashBased          SamplingAlgorithm = 5 // Hash-based
)

// SamplingInfo holds sampling configuration for an exporter
type SamplingInfo struct {
	Rate         uint32            // Sampling rate (1:N means rate=N)
	Algorithm    SamplingAlgorithm // Algorithm used
	Source       SamplingSource    // Where the sampling info came from
	LastUpdated  time.Time         // When this info was last updated
	ExporterIP   net.IP            // Exporter address
	ExporterPort uint32            // Observation domain / source ID
}

// SamplingSource indicates where sampling information was obtained
type SamplingSource uint8

const (
	SourceUnknown      SamplingSource = 0
	SourceIPFIXOptions SamplingSource = 1 // From IPFIX options template
	SourceNetFlowV9    SamplingSource = 2 // From NetFlow v9 options
	SourceSFlowHeader  SamplingSource = 3 // From sFlow datagram header
	SourceManual       SamplingSource = 4 // Manually configured
)

func (s SamplingSource) String() string {
	switch s {
	case SourceIPFIXOptions:
		return "ipfix_options"
	case SourceNetFlowV9:
		return "netflow_v9"
	case SourceSFlowHeader:
		return "sflow_header"
	case SourceManual:
		return "manual"
	default:
		return "unknown"
	}
}

// ExporterSamplingKey uniquely identifies a sampling context
type ExporterSamplingKey struct {
	IP             string
	ObservationDom uint32
}

// SamplingTracker tracks sampling rates per exporter
type SamplingTracker struct {
	exporters     map[ExporterSamplingKey]*SamplingInfo
	mu            sync.RWMutex
	defaultRate   uint32 // Default rate if not known (1 = no sampling)
	scalingEnabled bool  // Whether to apply scaling
	metrics       *SamplingMetrics
}

// SamplingMetrics holds prometheus metrics for sampling tracking
type SamplingMetrics struct {
	SamplingRate       *prometheus.GaugeVec
	ScaledBytes        *prometheus.CounterVec
	ScaledPackets      *prometheus.CounterVec
	SamplingInfoSource *prometheus.GaugeVec
}

// NewSamplingMetrics creates prometheus metrics for sampling
func NewSamplingMetrics(namespace string) *SamplingMetrics {
	return &SamplingMetrics{
		SamplingRate: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "sampling",
			Name:      "rate",
			Help:      "Current sampling rate per exporter (1:N)",
		}, []string{"exporter_ip", "observation_domain", "source"}),
		ScaledBytes: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "sampling",
			Name:      "scaled_bytes_total",
			Help:      "Total bytes after upscaling",
		}, []string{"exporter_ip"}),
		ScaledPackets: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "sampling",
			Name:      "scaled_packets_total",
			Help:      "Total packets after upscaling",
		}, []string{"exporter_ip"}),
		SamplingInfoSource: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "sampling",
			Name:      "info_source",
			Help:      "Source of sampling information (1=ipfix, 2=netflow, 3=sflow, 4=manual)",
		}, []string{"exporter_ip", "observation_domain"}),
	}
}

// SamplingTrackerConfig holds configuration for the sampling tracker
type SamplingTrackerConfig struct {
	DefaultRate    uint32          // Default sampling rate (1 = no sampling)
	ScalingEnabled bool            // Whether to apply upscaling
	Metrics        *SamplingMetrics
}

// NewSamplingTracker creates a new sampling tracker
func NewSamplingTracker(cfg *SamplingTrackerConfig) *SamplingTracker {
	defaultRate := cfg.DefaultRate
	if defaultRate == 0 {
		defaultRate = 1 // No sampling by default
	}

	return &SamplingTracker{
		exporters:      make(map[ExporterSamplingKey]*SamplingInfo),
		defaultRate:    defaultRate,
		scalingEnabled: cfg.ScalingEnabled,
		metrics:        cfg.Metrics,
	}
}

// UpdateSamplingRate updates the sampling rate for an exporter
func (t *SamplingTracker) UpdateSamplingRate(ip net.IP, observationDom uint32, rate uint32, algorithm SamplingAlgorithm, source SamplingSource) {
	if rate == 0 {
		rate = 1 // Treat 0 as no sampling
	}

	key := ExporterSamplingKey{
		IP:             ip.String(),
		ObservationDom: observationDom,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.exporters[key]
	if !exists {
		info = &SamplingInfo{
			ExporterIP:   ip,
			ExporterPort: observationDom,
		}
		t.exporters[key] = info
	}

	oldRate := info.Rate
	info.Rate = rate
	info.Algorithm = algorithm
	info.Source = source
	info.LastUpdated = time.Now()

	if t.metrics != nil {
		labels := prometheus.Labels{
			"exporter_ip":        ip.String(),
			"observation_domain": string(rune(observationDom)),
			"source":             source.String(),
		}
		t.metrics.SamplingRate.With(labels).Set(float64(rate))

		srcLabels := prometheus.Labels{
			"exporter_ip":        ip.String(),
			"observation_domain": string(rune(observationDom)),
		}
		t.metrics.SamplingInfoSource.With(srcLabels).Set(float64(source))
	}

	if log != nil && (oldRate != rate || !exists) {
		log.WithFields(logrus.Fields{
			"exporter":           ip.String(),
			"observation_domain": observationDom,
			"rate":               rate,
			"algorithm":          algorithm,
			"source":             source.String(),
		}).Info("Sampling rate updated")
	}
}

// GetSamplingRate returns the sampling rate for an exporter
func (t *SamplingTracker) GetSamplingRate(ip net.IP, observationDom uint32) *SamplingInfo {
	key := ExporterSamplingKey{
		IP:             ip.String(),
		ObservationDom: observationDom,
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if info, ok := t.exporters[key]; ok {
		// Return a copy to avoid race conditions
		copyInfo := *info
		return &copyInfo
	}

	// Return default info
	return &SamplingInfo{
		Rate:       t.defaultRate,
		Algorithm:  SamplingUnknown,
		Source:     SourceUnknown,
		ExporterIP: ip,
	}
}

// ScaleFlow applies sampling upscaling to bytes and packets
// Returns the scaled values. If scaling is disabled, returns original values
func (t *SamplingTracker) ScaleFlow(ip net.IP, observationDom uint32, bytes, packets uint64) (scaledBytes, scaledPackets uint64) {
	if !t.scalingEnabled {
		return bytes, packets
	}

	info := t.GetSamplingRate(ip, observationDom)
	rate := uint64(info.Rate)
	if rate <= 1 {
		return bytes, packets
	}

	scaledBytes = bytes * rate
	scaledPackets = packets * rate

	if t.metrics != nil {
		labels := prometheus.Labels{"exporter_ip": ip.String()}
		t.metrics.ScaledBytes.With(labels).Add(float64(scaledBytes - bytes))
		t.metrics.ScaledPackets.With(labels).Add(float64(scaledPackets - packets))
	}

	return scaledBytes, scaledPackets
}

// SetScalingEnabled enables or disables sampling upscaling
func (t *SamplingTracker) SetScalingEnabled(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scalingEnabled = enabled
	if log != nil {
		log.WithField("enabled", enabled).Info("Sampling upscaling toggled")
	}
}

// IsScalingEnabled returns whether scaling is enabled
func (t *SamplingTracker) IsScalingEnabled() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.scalingEnabled
}

// GetAllSamplingInfo returns a snapshot of all sampling information
func (t *SamplingTracker) GetAllSamplingInfo() map[ExporterSamplingKey]SamplingInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[ExporterSamplingKey]SamplingInfo, len(t.exporters))
	for k, v := range t.exporters {
		result[k] = *v
	}
	return result
}

// SetManualRate sets a manual sampling rate override for an exporter
func (t *SamplingTracker) SetManualRate(ip net.IP, observationDom uint32, rate uint32) {
	t.UpdateSamplingRate(ip, observationDom, rate, SamplingUnknown, SourceManual)
}

// ClearExporter removes sampling information for an exporter
func (t *SamplingTracker) ClearExporter(ip net.IP, observationDom uint32) {
	key := ExporterSamplingKey{
		IP:             ip.String(),
		ObservationDom: observationDom,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.exporters, key)

	if log != nil {
		log.WithFields(logrus.Fields{
			"exporter":           ip.String(),
			"observation_domain": observationDom,
		}).Info("Sampling info cleared")
	}
}
