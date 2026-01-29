package collector

import (
	"context"
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

// PacketWork represents a unit of work for packet processing
type PacketWork struct {
	Data       []byte
	Length     int
	RemoteAddr net.Addr
	ReceivedAt time.Time
}

// RingBuffer is a fixed-size circular buffer for packet work items
type RingBuffer struct {
	items    []PacketWork
	size     uint64
	head     uint64 // Write position (producer)
	tail     uint64 // Read position (consumer)
	mask     uint64
	mu       sync.Mutex
	notEmpty *sync.Cond
	notFull  *sync.Cond
	closed   atomic.Bool
}

// NewRingBuffer creates a new ring buffer with the given size (must be power of 2)
func NewRingBuffer(size int) *RingBuffer {
	// Round up to nearest power of 2
	actualSize := uint64(1)
	for actualSize < uint64(size) {
		actualSize <<= 1
	}

	rb := &RingBuffer{
		items: make([]PacketWork, actualSize),
		size:  actualSize,
		mask:  actualSize - 1,
	}
	rb.notEmpty = sync.NewCond(&rb.mu)
	rb.notFull = sync.NewCond(&rb.mu)
	return rb
}

// Push adds an item to the buffer. Returns false if buffer is full (non-blocking)
func (rb *RingBuffer) Push(work PacketWork) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.closed.Load() {
		return false
	}

	// Check if full
	if rb.head-rb.tail >= rb.size {
		return false
	}

	rb.items[rb.head&rb.mask] = work
	rb.head++
	rb.notEmpty.Signal()
	return true
}

// PushBlocking adds an item to the buffer, blocking if full
func (rb *RingBuffer) PushBlocking(ctx context.Context, work PacketWork) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for rb.head-rb.tail >= rb.size && !rb.closed.Load() {
		// Check context before waiting
		select {
		case <-ctx.Done():
			return false
		default:
		}
		rb.notFull.Wait()
	}

	if rb.closed.Load() {
		return false
	}

	rb.items[rb.head&rb.mask] = work
	rb.head++
	rb.notEmpty.Signal()
	return true
}

// Pop removes and returns an item from the buffer. Blocks if empty
func (rb *RingBuffer) Pop(ctx context.Context) (PacketWork, bool) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for rb.head == rb.tail && !rb.closed.Load() {
		select {
		case <-ctx.Done():
			return PacketWork{}, false
		default:
		}
		rb.notEmpty.Wait()
	}

	if rb.closed.Load() && rb.head == rb.tail {
		return PacketWork{}, false
	}

	work := rb.items[rb.tail&rb.mask]
	// Clear the reference to help GC
	rb.items[rb.tail&rb.mask] = PacketWork{}
	rb.tail++
	rb.notFull.Signal()
	return work, true
}

// Len returns the current number of items in the buffer
func (rb *RingBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return int(rb.head - rb.tail)
}

// Close closes the ring buffer
func (rb *RingBuffer) Close() {
	rb.closed.Store(true)
	rb.mu.Lock()
	rb.notEmpty.Broadcast()
	rb.notFull.Broadcast()
	rb.mu.Unlock()
}

// WorkerPool manages a fixed pool of workers that process packets
type WorkerPool struct {
	numWorkers   int
	ringBuffer   *RingBuffer
	bytePool     *ByteBufferPool
	workPool     *WorkItemPool
	handler      PacketHandler
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	metrics      *PoolMetrics
	dropCallback func(PacketWork)
}

// PacketHandler is the function signature for packet processing
type PacketHandler func(ctx context.Context, work *PacketWork) error

// PoolMetrics holds prometheus metrics for the worker pool
type PoolMetrics struct {
	PacketsReceived   prometheus.Counter
	PacketsProcessed  prometheus.Counter
	PacketsDropped    prometheus.Counter
	QueueDepth        prometheus.Gauge
	ProcessingLatency prometheus.Histogram
	WorkersBusy       prometheus.Gauge
}

func NewPoolMetrics(namespace string) *PoolMetrics {
	return &PoolMetrics{
		PacketsReceived: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_received_total",
			Help:      "Total number of packets received",
		}),
		PacketsProcessed: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_processed_total",
			Help:      "Total number of packets successfully processed",
		}),
		PacketsDropped: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_dropped_total",
			Help:      "Total number of packets dropped due to queue overflow",
		}),
		QueueDepth: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "queue_depth",
			Help:      "Current number of packets waiting in queue",
		}),
		ProcessingLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "processing_latency_seconds",
			Help:      "Time from packet receipt to processing completion",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .05, .1, .5, 1},
		}),
		WorkersBusy: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "workers_busy",
			Help:      "Number of workers currently processing packets",
		}),
	}
}

// WorkerPoolConfig holds configuration for the worker pool
type WorkerPoolConfig struct {
	NumWorkers      int
	QueueSize       int
	MaxPacketSize   int
	Handler         PacketHandler
	Metrics         *PoolMetrics
	DropCallback    func(PacketWork)
	Blocking        bool // If true, block on full queue instead of dropping
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(cfg *WorkerPoolConfig) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	if cfg.MaxPacketSize == 0 {
		cfg.MaxPacketSize = 65535 // Max UDP packet size
	}

	pool := &WorkerPool{
		numWorkers:   cfg.NumWorkers,
		ringBuffer:   NewRingBuffer(cfg.QueueSize),
		bytePool:     NewByteBufferPool(cfg.MaxPacketSize),
		workPool:     NewWorkItemPool(),
		handler:      cfg.Handler,
		ctx:          ctx,
		cancel:       cancel,
		metrics:      cfg.Metrics,
		dropCallback: cfg.DropCallback,
	}

	return pool
}

// Start launches the worker goroutines
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}

	// Start metrics updater
	go wp.metricsUpdater()
}

func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	_ = id // Worker ID can be used for debugging/metrics

	for {
		work, ok := wp.ringBuffer.Pop(wp.ctx)
		if !ok {
			return
		}

		if wp.metrics != nil {
			wp.metrics.WorkersBusy.Inc()
		}

		if err := wp.handler(wp.ctx, &work); err != nil {
			if log != nil {
				log.WithError(err).Debug("Error processing packet")
			}
		}

		if wp.metrics != nil {
			wp.metrics.PacketsProcessed.Inc()
			wp.metrics.ProcessingLatency.Observe(time.Since(work.ReceivedAt).Seconds())
			wp.metrics.WorkersBusy.Dec()
		}

		// Return the byte buffer to the pool
		wp.bytePool.Put(work.Data)
	}
}

func (wp *WorkerPool) metricsUpdater() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case <-ticker.C:
			if wp.metrics != nil {
				wp.metrics.QueueDepth.Set(float64(wp.ringBuffer.Len()))
			}
		}
	}
}

// Submit submits work to the pool. Returns false if the work was dropped
func (wp *WorkerPool) Submit(data []byte, length int, remoteAddr net.Addr) bool {
	if wp.metrics != nil {
		wp.metrics.PacketsReceived.Inc()
	}

	// Get a buffer from the pool and copy data
	buf := wp.bytePool.Get()
	copy(buf[:length], data[:length])

	work := PacketWork{
		Data:       buf[:length],
		Length:     length,
		RemoteAddr: remoteAddr,
		ReceivedAt: time.Now(),
	}

	if !wp.ringBuffer.Push(work) {
		// Queue is full, drop the packet
		if wp.metrics != nil {
			wp.metrics.PacketsDropped.Inc()
		}
		if wp.dropCallback != nil {
			wp.dropCallback(work)
		}
		wp.bytePool.Put(buf)
		return false
	}

	return true
}

// SubmitBlocking submits work and blocks if the queue is full
func (wp *WorkerPool) SubmitBlocking(ctx context.Context, data []byte, length int, remoteAddr net.Addr) bool {
	if wp.metrics != nil {
		wp.metrics.PacketsReceived.Inc()
	}

	buf := wp.bytePool.Get()
	copy(buf[:length], data[:length])

	work := PacketWork{
		Data:       buf[:length],
		Length:     length,
		RemoteAddr: remoteAddr,
		ReceivedAt: time.Now(),
	}

	if !wp.ringBuffer.PushBlocking(ctx, work) {
		wp.bytePool.Put(buf)
		return false
	}

	return true
}

// Stop gracefully shuts down the worker pool
func (wp *WorkerPool) Stop() {
	wp.cancel()
	wp.ringBuffer.Close()
	wp.wg.Wait()
}

// QueueLen returns the current queue depth
func (wp *WorkerPool) QueueLen() int {
	return wp.ringBuffer.Len()
}
