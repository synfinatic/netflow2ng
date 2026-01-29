package transport

/*
 * ZMQ Transport for goflow2 supporting JSON/Protobuf/TLV
 *
 * The zmq Transport accepts formatted data from goflow2 and and sends over
 * [ZMQ](https://zeromq.org) and is intended to interop
 * with [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/), filling
 * the same role a [nProbe](https://www.ntop.org/products/netflow/nprobe/) or your
 * own solution.
 *
 * This implementation supports multi-endpoint fan-out with configurable
 * distribution strategies (hash-based or round-robin).
 */

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	zmq "github.com/pebbe/zmq4"
)

/*
 * For more info on this you'll want to read:
 * include/ntop_typedefs.h, include/ntop_defines.h & src/ZMQCollectorInterface.cpp from
 * https://github.com/ntop/ntopng
 */
const ZMQ_MSG_VERSION_4 = 4 // ntop message version for zmq_msg_hdr_v3 in ntop_defines.h
const ZMQ_TOPIC = "flow"    // ntopng only really cares about the first character!

const ZMQ_MSG_V4_FLAG_TLV = 2
const ZMQ_MSG_V4_FLAG_COMPRESSED = 4

const (
	PBUF MsgFormat = iota
	JSON
	TLV
)

type MsgFormat int

// FanoutStrategy determines how flows are distributed across multiple endpoints
type FanoutStrategy int

const (
	// FanoutHash distributes flows by hashing exporter IP + 5-tuple
	FanoutHash FanoutStrategy = iota
	// FanoutRoundRobin distributes flows in round-robin fashion
	FanoutRoundRobin
)

// ZmqEndpoint represents a single ZMQ endpoint
type ZmqEndpoint struct {
	Address   string
	Context   *zmq.Context
	Publisher *zmq.Socket
	MessageID uint32
	Active    bool
	LastError error
	mu        sync.RWMutex
}

type ZmqDriver struct {
	endpoints      []*ZmqEndpoint
	fanoutStrategy FanoutStrategy
	sourceId       int
	msgType        MsgFormat
	compress       bool
	topic          string
	lock           *sync.RWMutex
	rrIndex        atomic.Uint64 // Round-robin index
	metrics        *ZmqMetrics
}

// ZmqMetrics holds prometheus metrics for ZMQ transport
type ZmqMetrics struct {
	MessagesSent    *prometheus.CounterVec
	BytesSent       *prometheus.CounterVec
	Errors          *prometheus.CounterVec
	EndpointsActive prometheus.Gauge
	MessageLatency  prometheus.Histogram
}

// NewZmqMetrics creates prometheus metrics for ZMQ transport
func NewZmqMetrics(namespace string) *ZmqMetrics {
	return &ZmqMetrics{
		MessagesSent: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "zmq",
			Name:      "messages_sent_total",
			Help:      "Total ZMQ messages sent per endpoint",
		}, []string{"endpoint"}),
		BytesSent: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "zmq",
			Name:      "bytes_sent_total",
			Help:      "Total bytes sent per endpoint",
		}, []string{"endpoint"}),
		Errors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "zmq",
			Name:      "errors_total",
			Help:      "Total errors per endpoint",
		}, []string{"endpoint", "error_type"}),
		EndpointsActive: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "zmq",
			Name:      "endpoints_active",
			Help:      "Number of active ZMQ endpoints",
		}),
		MessageLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "zmq",
			Name:      "message_latency_seconds",
			Help:      "Time to send a ZMQ message",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .05, .1},
		}),
	}
}

// This is the latest header as of ntopng 6.4
type zmqHeaderV3 struct {
	url               string // must be 16 bytes long
	version           uint8  // use only with ZMQ_MSG_VERSION_4
	flags             uint8
	uncompressed_size uint32
	compressed_size   uint32
	msg_id            uint32
	source_id         uint32
}

var messageId uint32 = 0                         // Every ZMQ message we send should have a uniq ID
const maxMessageId uint32 = math.MaxUint32 - 100 // Wrap around before we hit max uint32

func (d *ZmqDriver) Prepare() error {
	// Ideally the code in transport.RegisterZmq would be in here, but I don't
	// know how to get the kong CLI flags into this function.
	return nil
}

func (d *ZmqDriver) Init() error {
	d.lock.Lock()
	defer d.lock.Unlock()

	activeCount := 0
	for _, ep := range d.endpoints {
		ep.mu.Lock()
		ep.Context, _ = zmq.NewContext()
		ep.Publisher, _ = ep.Context.NewSocket(zmq.PUB)

		if err := ep.Publisher.Bind(ep.Address); err != nil {
			log.Errorf("Unable to bind to %s: %s", ep.Address, err.Error())
			ep.Active = false
			ep.LastError = err
		} else {
			ep.Active = true
			activeCount++
			log.Infof("Started ZMQ publisher on: %s", ep.Address)
		}
		ep.mu.Unlock()
	}

	if activeCount == 0 {
		log.Fatal("No ZMQ endpoints could be bound")
	}

	if d.metrics != nil {
		d.metrics.EndpointsActive.Set(float64(activeCount))
	}

	// Ensure subscriber connection has time to complete
	time.Sleep(time.Second)
	return nil
}

// selectEndpoint chooses an endpoint based on the configured strategy
func (d *ZmqDriver) selectEndpoint(key []byte) *ZmqEndpoint {
	d.lock.RLock()
	defer d.lock.RUnlock()

	activeEndpoints := make([]*ZmqEndpoint, 0, len(d.endpoints))
	for _, ep := range d.endpoints {
		ep.mu.RLock()
		if ep.Active {
			activeEndpoints = append(activeEndpoints, ep)
		}
		ep.mu.RUnlock()
	}

	if len(activeEndpoints) == 0 {
		return nil
	}

	if len(activeEndpoints) == 1 {
		return activeEndpoints[0]
	}

	var idx int
	switch d.fanoutStrategy {
	case FanoutHash:
		// Hash on the key (which contains exporter + flow info)
		h := fnv.New64a()
		h.Write(key)
		idx = int(h.Sum64() % uint64(len(activeEndpoints)))
	case FanoutRoundRobin:
		idx = int(d.rrIndex.Add(1) % uint64(len(activeEndpoints)))
	default:
		idx = 0
	}

	return activeEndpoints[idx]
}

func (d *ZmqDriver) Send(key, data []byte) error {
	var err error
	start := time.Now()
	orig_len := uint32(len(data))
	compressed_len := orig_len

	// Select endpoint
	endpoint := d.selectEndpoint(key)
	if endpoint == nil {
		if d.metrics != nil {
			d.metrics.Errors.With(prometheus.Labels{
				"endpoint":   "none",
				"error_type": "no_active_endpoints",
			}).Inc()
		}
		return fmt.Errorf("no active ZMQ endpoints available")
	}

	// Should only compress JSON
	if d.msgType == JSON && d.compress {
		var zbuf bytes.Buffer
		z := zlib.NewWriter(&zbuf)
		if _, err = z.Write(data); err != nil {
			return err
		}
		if err = z.Close(); err != nil {
			return err
		}
		// replace data with zlib compressed buffer
		data = zbuf.Bytes()
		compressed_len = uint32(len(data))
	}

	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()

	// Wrap message ID
	if endpoint.MessageID >= maxMessageId {
		log.Debug("Wrapping message id back to 1 to avoid overflow")
		endpoint.MessageID = 1
	}

	if endpoint.MessageID == 1 {
		log.Infof("Sending first ZMQ message to %s", endpoint.Address)
	} else if endpoint.MessageID%1000 == 0 {
		log.Debugf("Sending ZMQ message id %d to %s", endpoint.MessageID, endpoint.Address)
	}

	header := d.newZmqHeaderV3(endpoint, orig_len, compressed_len)

	// send our header with the topic first as a multi-part message
	hbytes, err := header.bytes()
	if err != nil {
		log.Errorf("Unable to serialize header: %s", err.Error())
		if d.metrics != nil {
			d.metrics.Errors.With(prometheus.Labels{
				"endpoint":   endpoint.Address,
				"error_type": "header_serialize",
			}).Inc()
		}
		return err
	}

	bytesSent, err := endpoint.Publisher.SendBytes(hbytes, zmq.SNDMORE)
	if err != nil {
		log.Errorf("Unable to send header to %s: %s", endpoint.Address, err.Error())
		if d.metrics != nil {
			d.metrics.Errors.With(prometheus.Labels{
				"endpoint":   endpoint.Address,
				"error_type": "send_header",
			}).Inc()
		}
		return err
	}
	if bytesSent != len(hbytes) {
		log.Errorf("Wrote the wrong number of header bytes: %d", bytesSent)
		return err
	}

	// now send the actual payload
	payloadBytes, err := endpoint.Publisher.SendBytes(data, 0)
	if err != nil {
		log.Error(err)
		if d.metrics != nil {
			d.metrics.Errors.With(prometheus.Labels{
				"endpoint":   endpoint.Address,
				"error_type": "send_payload",
			}).Inc()
		}
		return err
	}

	endpoint.MessageID++

	if d.metrics != nil {
		d.metrics.MessagesSent.With(prometheus.Labels{"endpoint": endpoint.Address}).Inc()
		d.metrics.BytesSent.With(prometheus.Labels{"endpoint": endpoint.Address}).Add(float64(bytesSent + payloadBytes))
		d.metrics.MessageLatency.Observe(time.Since(start).Seconds())
	}

	switch d.msgType {
	case PBUF:
		log.Tracef("Sent %d bytes of pbuf to %s:\n%s", orig_len, endpoint.Address, hex.Dump(data))
	case JSON:
		if d.compress {
			log.Tracef("Sent %d bytes of zlib json to %s:\n%s", compressed_len, endpoint.Address, hex.Dump(data))
		} else {
			log.Tracef("Sent %d bytes of json to %s: %s", orig_len, endpoint.Address, string(data))
		}
	case TLV:
		log.Tracef("Sent %d bytes of ntop tlv to %s:\n%s", orig_len, endpoint.Address, hex.Dump(data))
	default:
		log.Errorf("Sent %d bytes of unknown message type %d", orig_len, d.msgType)
	}

	return err
}

func (d *ZmqDriver) Close() error {
	d.lock.Lock()
	defer d.lock.Unlock()

	for _, ep := range d.endpoints {
		ep.mu.Lock()
		if ep.Publisher != nil {
			ep.Publisher.Close()
		}
		if ep.Context != nil {
			ep.Context.Term()
		}
		ep.Active = false
		ep.mu.Unlock()
	}
	return nil
}

func (d *ZmqDriver) newZmqHeaderV3(ep *ZmqEndpoint, orig_length uint32, compressed_len uint32) *zmqHeaderV3 {
	var flags uint8 = 0
	if d.msgType == TLV {
		flags |= ZMQ_MSG_V4_FLAG_TLV
	}
	if d.compress {
		flags |= ZMQ_MSG_V4_FLAG_COMPRESSED
	}

	topic := d.topic
	if topic == "" {
		topic = ZMQ_TOPIC
	}

	z := &zmqHeaderV3{
		url:               topic,
		version:           ZMQ_MSG_VERSION_4,
		flags:             flags,
		uncompressed_size: orig_length,
		compressed_size:   compressed_len,
		msg_id:            ep.MessageID,
		source_id:         uint32(d.sourceId),
	}

	return z
}

func (zh *zmqHeaderV3) bytes() ([]byte, error) {
	header := []byte{}
	bBuf := bytes.NewBuffer(header)

	url := []byte{}
	uBuf := bytes.NewBuffer(url)

	i, err := uBuf.Write([]byte(zh.url))
	if err != nil {
		return nil, err
	}

	// pad out to 16 bytes
	for ; i < 16; i++ {
		if _, err = uBuf.Write([]byte{0}); err != nil {
			return nil, err
		}
	}

	i, err = bBuf.Write(uBuf.Bytes())
	if err != nil {
		return nil, err
	}
	if i != 16 {
		return nil, fmt.Errorf("URL was %d bytes instead of 16", i)
	}

	if _, err = bBuf.Write([]byte{zh.version, zh.flags}); err != nil {
		return nil, err
	}
	// Need two bytes of padding to align next uint32 on 4-byte boundary
	if _, err = bBuf.Write([]byte{0, 0}); err != nil {
		return nil, err
	}

	// Both uncompressed_size and compressed_size need to be in little-endian
	le32Buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(le32Buf, zh.uncompressed_size)
	if _, err = bBuf.Write(le32Buf); err != nil {
		return nil, err
	}

	le32Buf = make([]byte, 4)
	binary.LittleEndian.PutUint32(le32Buf, zh.compressed_size)
	if _, err = bBuf.Write(le32Buf); err != nil {
		return nil, err
	}

	be32Buf := make([]byte, 4)
	binary.BigEndian.PutUint32(be32Buf, zh.msg_id)
	if _, err = bBuf.Write(be32Buf); err != nil {
		return nil, err
	}

	be32Buf = make([]byte, 4)
	binary.BigEndian.PutUint32(be32Buf, zh.source_id)
	if _, err = bBuf.Write(be32Buf); err != nil {
		return nil, err
	}
	return bBuf.Bytes(), nil
}

// GetActiveEndpoints returns a list of active endpoint addresses
func (d *ZmqDriver) GetActiveEndpoints() []string {
	d.lock.RLock()
	defer d.lock.RUnlock()

	result := make([]string, 0, len(d.endpoints))
	for _, ep := range d.endpoints {
		ep.mu.RLock()
		if ep.Active {
			result = append(result, ep.Address)
		}
		ep.mu.RUnlock()
	}
	return result
}

// SetEndpointActive sets the active state of an endpoint (for reconnection logic)
func (d *ZmqDriver) SetEndpointActive(address string, active bool) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	for _, ep := range d.endpoints {
		if ep.Address == address {
			ep.mu.Lock()
			ep.Active = active
			ep.mu.Unlock()

			// Update metrics
			if d.metrics != nil {
				activeCount := 0
				for _, e := range d.endpoints {
					e.mu.RLock()
					if e.Active {
						activeCount++
					}
					e.mu.RUnlock()
				}
				d.metrics.EndpointsActive.Set(float64(activeCount))
			}
			return
		}
	}
}
