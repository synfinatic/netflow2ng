package sflow

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	flowpb "github.com/netsampler/goflow2/v2/pb"
	"github.com/synfinatic/netflow2ng/collector"
	"github.com/synfinatic/netflow2ng/sampling"
)

// SFlowCollector handles sFlow v5 packet collection
type SFlowCollector struct {
	listenAddr      string
	listenPort      int
	decoder         *Decoder
	samplingTracker *sampling.SamplingTracker
	workerPool      *collector.WorkerPool
	conn            *net.UDPConn
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	flowHandler     FlowHandler
	metrics         *SFlowMetrics
}

// FlowHandler is called for each decoded sFlow message
type FlowHandler func(*FlowMessage) error

// SFlowMetrics holds prometheus metrics for sFlow collection
type SFlowMetrics struct {
	DatagramsReceived prometheus.Counter
	SamplesDecoded    prometheus.Counter
	FlowsProduced     prometheus.Counter
	DecodeErrors      prometheus.Counter
	BytesReceived     prometheus.Counter
}

// NewSFlowMetrics creates prometheus metrics for sFlow collection
func NewSFlowMetrics(namespace string) *SFlowMetrics {
	return &SFlowMetrics{
		DatagramsReceived: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "sflow",
			Name:      "datagrams_received_total",
			Help:      "Total sFlow datagrams received",
		}),
		SamplesDecoded: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "sflow",
			Name:      "samples_decoded_total",
			Help:      "Total sFlow samples decoded",
		}),
		FlowsProduced: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "sflow",
			Name:      "flows_produced_total",
			Help:      "Total flow messages produced from sFlow",
		}),
		DecodeErrors: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "sflow",
			Name:      "decode_errors_total",
			Help:      "Total sFlow decode errors",
		}),
		BytesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "sflow",
			Name:      "bytes_received_total",
			Help:      "Total bytes received from sFlow",
		}),
	}
}

// SFlowCollectorConfig holds configuration for the sFlow collector
type SFlowCollectorConfig struct {
	ListenAddr      string
	ListenPort      int
	NumWorkers      int
	QueueSize       int
	SamplingTracker *sampling.SamplingTracker
	FlowHandler     FlowHandler
	Metrics         *SFlowMetrics
	PoolMetrics     *collector.PoolMetrics
}

// NewSFlowCollector creates a new sFlow collector
func NewSFlowCollector(cfg *SFlowCollectorConfig) *SFlowCollector {
	ctx, cancel := context.WithCancel(context.Background())

	c := &SFlowCollector{
		listenAddr:      cfg.ListenAddr,
		listenPort:      cfg.ListenPort,
		decoder:         NewDecoder(cfg.SamplingTracker),
		samplingTracker: cfg.SamplingTracker,
		ctx:             ctx,
		cancel:          cancel,
		flowHandler:     cfg.FlowHandler,
		metrics:         cfg.Metrics,
	}

	// Create worker pool
	poolCfg := &collector.WorkerPoolConfig{
		NumWorkers:    cfg.NumWorkers,
		QueueSize:     cfg.QueueSize,
		MaxPacketSize: 65535,
		Handler:       c.processPacket,
		Metrics:       cfg.PoolMetrics,
	}
	c.workerPool = collector.NewWorkerPool(poolCfg)

	return c
}

// Start starts the sFlow collector
func (c *SFlowCollector) Start() error {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(c.listenAddr),
		Port: c.listenPort,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%d: %w", c.listenAddr, c.listenPort, err)
	}
	c.conn = conn

	// Set receive buffer size
	if err := conn.SetReadBuffer(16 * 1024 * 1024); err != nil {
		if log != nil {
			log.WithError(err).Warn("Failed to set UDP receive buffer size")
		}
	}

	// Start worker pool
	c.workerPool.Start()

	// Start receiver goroutine
	c.wg.Add(1)
	go c.receiveLoop()

	if log != nil {
		log.WithField("addr", addr.String()).Info("sFlow collector started")
	}

	return nil
}

func (c *SFlowCollector) receiveLoop() {
	defer c.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Set read deadline to allow periodic context checks
		c.conn.SetReadDeadline(time.Now().Add(time.Second))

		n, remoteAddr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if c.ctx.Err() != nil {
				return
			}
			if log != nil {
				log.WithError(err).Error("Error reading UDP packet")
			}
			continue
		}

		if c.metrics != nil {
			c.metrics.BytesReceived.Add(float64(n))
		}

		// Submit to worker pool
		c.workerPool.Submit(buf[:n], n, remoteAddr)
	}
}

func (c *SFlowCollector) processPacket(ctx context.Context, work *collector.PacketWork) error {
	// Extract source address
	var srcIP net.IP
	if udpAddr, ok := work.RemoteAddr.(*net.UDPAddr); ok {
		srcIP = udpAddr.IP
	}

	// Decode the datagram
	dg, err := c.decoder.DecodeDatagram(work.Data, srcIP)
	if err != nil {
		if c.metrics != nil {
			c.metrics.DecodeErrors.Inc()
		}
		return err
	}

	if c.metrics != nil {
		c.metrics.DatagramsReceived.Inc()
		c.metrics.SamplesDecoded.Add(float64(len(dg.Samples)))
	}

	// Convert to flow messages
	messages := c.decoder.ToFlowMessages(dg)

	// Process each flow message
	for _, msg := range messages {
		if c.flowHandler != nil {
			if err := c.flowHandler(msg); err != nil {
				if log != nil {
					log.WithError(err).Debug("Error handling sFlow message")
				}
			} else if c.metrics != nil {
				c.metrics.FlowsProduced.Inc()
			}
		}
	}

	return nil
}

// Stop stops the sFlow collector
func (c *SFlowCollector) Stop() error {
	c.cancel()

	if c.conn != nil {
		c.conn.Close()
	}

	c.workerPool.Stop()
	c.wg.Wait()

	if log != nil {
		log.Info("sFlow collector stopped")
	}

	return nil
}

// GetQueueDepth returns the current queue depth
func (c *SFlowCollector) GetQueueDepth() int {
	return c.workerPool.QueueLen()
}

// ConvertToGoflowMessage converts our sFlow message to goflow2's FlowMessage format
// This allows reuse of the existing formatters
func ConvertToGoflowMessage(msg *FlowMessage) *flowpb.FlowMessage {
	fm := &flowpb.FlowMessage{
		Type:             flowpb.FlowMessage_SFLOW_5,
		TimeFlowStartNs:  msg.TimeFlowStartNs,
		TimeFlowEndNs:    msg.TimeFlowEndNs,
		Bytes:            msg.Bytes,
		Packets:          msg.Packets,
		SrcPort:          uint32(msg.SrcPort),
		DstPort:          uint32(msg.DstPort),
		Proto:            uint32(msg.Protocol),
		Etype:            uint32(msg.EtherType),
		InIf:             msg.InIf,
		OutIf:            msg.OutIf,
		SrcMac:           msg.SrcMAC,
		DstMac:           msg.DstMAC,
		SrcVlan:          msg.SrcVLAN,
		DstVlan:          msg.DstVLAN,
		IpTos:            uint32(msg.ToS),
		IpTtl:            uint32(msg.TTL),
		TcpFlags:         uint32(msg.TCPFlags),
		IcmpType:         uint32(msg.IcmpType),
		IcmpCode:         uint32(msg.IcmpCode),
		FragmentOffset:   uint32(msg.FragmentOffset),
		FragmentId:       msg.FragmentId,
		Ipv6FlowLabel:    msg.IPv6FlowLabel,
		SrcNet:           msg.SrcNet,
		DstNet:           msg.DstNet,
		SamplingRate:     uint64(msg.SamplingRate),
	}

	// Set addresses
	if msg.SrcAddr != nil {
		if ip4 := msg.SrcAddr.To4(); ip4 != nil {
			fm.SrcAddr = ip4
		} else {
			fm.SrcAddr = msg.SrcAddr.To16()
		}
	}

	if msg.DstAddr != nil {
		if ip4 := msg.DstAddr.To4(); ip4 != nil {
			fm.DstAddr = ip4
		} else {
			fm.DstAddr = msg.DstAddr.To16()
		}
	}

	if msg.NextHop != nil {
		if ip4 := msg.NextHop.To4(); ip4 != nil {
			fm.NextHop = ip4
		} else {
			fm.NextHop = msg.NextHop.To16()
		}
	}

	if msg.SamplerAddress != nil {
		if ip4 := msg.SamplerAddress.To4(); ip4 != nil {
			fm.SamplerAddress = ip4
		} else {
			fm.SamplerAddress = msg.SamplerAddress.To16()
		}
	}

	return fm
}
