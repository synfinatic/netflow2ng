package transport

import (
	"strings"
	"sync"

	"github.com/netsampler/goflow2/v2/transport"
	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func SetLogger(l *logrus.Logger) {
	log = l
}

// ZmqConfig holds configuration for ZMQ transport
type ZmqConfig struct {
	Endpoints      []string       // List of ZMQ bind addresses
	MsgType        MsgFormat      // Message format (TLV, JSON, PBUF)
	SourceId       int            // Source ID for NetFlow
	Compress       bool           // Enable compression (JSON only)
	FanoutStrategy FanoutStrategy // How to distribute flows
	Topic          string         // ZMQ topic
	Metrics        *ZmqMetrics    // Prometheus metrics
}

// RegisterZmq registers a ZMQ transport driver with the given configuration
// Deprecated: Use RegisterZmqWithConfig instead for multi-endpoint support
func RegisterZmq(zmqListen string, msgType MsgFormat, sourceId int, compress bool) {
	RegisterZmqWithConfig(&ZmqConfig{
		Endpoints:      []string{zmqListen},
		MsgType:        msgType,
		SourceId:       sourceId,
		Compress:       compress,
		FanoutStrategy: FanoutHash,
		Topic:          ZMQ_TOPIC,
	})
}

// RegisterZmqWithConfig registers a ZMQ transport driver with full configuration
func RegisterZmqWithConfig(cfg *ZmqConfig) {
	endpoints := make([]*ZmqEndpoint, 0, len(cfg.Endpoints))
	for _, addr := range cfg.Endpoints {
		endpoints = append(endpoints, &ZmqEndpoint{
			Address: addr,
		})
	}

	z := &ZmqDriver{
		endpoints:      endpoints,
		sourceId:       cfg.SourceId,
		msgType:        cfg.MsgType,
		compress:       cfg.Compress,
		fanoutStrategy: cfg.FanoutStrategy,
		topic:          cfg.Topic,
		lock:           &sync.RWMutex{},
		metrics:        cfg.Metrics,
	}
	transport.RegisterTransportDriver("zmq", z)
}

// ParseZmqEndpoints parses a comma-separated list of ZMQ endpoints
// Format: "tcp://*:5556,tcp://*:5557" or single endpoint "tcp://*:5556"
func ParseZmqEndpoints(endpoints string) []string {
	parts := strings.Split(endpoints, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// ParseFanoutStrategy parses a string into a FanoutStrategy
func ParseFanoutStrategy(strategy string) FanoutStrategy {
	switch strings.ToLower(strategy) {
	case "round-robin", "roundrobin", "rr":
		return FanoutRoundRobin
	case "hash", "5tuple":
		return FanoutHash
	default:
		return FanoutHash
	}
}
