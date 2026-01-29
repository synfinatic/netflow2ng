# netflow2ng

High-throughput NetFlow v9/IPFIX/sFlow collector for [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/)

[![Tests](https://github.com/synfinatic/netflow2ng/actions/workflows/tests.yml/badge.svg)](https://github.com/synfinatic/netflow2ng/actions/workflows/tests.yml)
[![codeql-analysis.yml](https://github.com/synfinatic/netflow2ng/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/synfinatic/netflow2ng/actions/workflows/codeql-analysis.yml)
[![golangci-lint](https://github.com/synfinatic/netflow2ng/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/synfinatic/netflow2ng/actions/workflows/golangci-lint.yaml)

## Overview

ntopng is a free/commercial network traffic analysis console suitable for a variety of use cases. However, if you want to collect NetFlow, IPFIX, or sFlow data and load it into ntopng, you typically need [nProbe](https://www.ntop.org/products/netflow/nprobe/) which may be cost-prohibitive for home/SOHO use.

**netflow2ng** provides a high-performance, open-source alternative optimized for:
- Predictable but high-bandwidth environments (cameras, NVRs, intercoms, switches)
- Collector mode with ZMQ publisher interoperability with ntopng
- Per-exporter sampling rate tracking and upscaling
- Multi-endpoint ZMQ fan-out for scaling

## Features

### Protocol Support
- **NetFlow v9** - Full template-based support
- **IPFIX (NetFlow v10)** - Full support including options templates
- **sFlow v5** - Native packet sampling support

### Performance Features
- **Fixed worker pool** with bounded queue (no goroutine per packet)
- **sync.Pool** for byte buffers to reduce GC pressure
- **Ring buffer** for efficient packet queuing
- **Metrics** for queue depth, drops, and per-exporter throughput

### Sampling & Accuracy
- **Automatic sampling rate detection** from:
  - IPFIX options templates
  - sFlow datagram headers
- **Configurable upscaling** of bytes/packets before sending to ntopng
- **Manual rate override** for exporters that pre-scale

### Flow Relay / Fan-out
- **Multi-endpoint ZMQ** publishing to multiple ntopng instances
- **Hash-based distribution** (exporter + 5-tuple) for flow affinity
- **Round-robin distribution** for load balancing

### Deduplication
- **Per-exporter dedup cache** with configurable TTL and size bounds
- **Heuristics** to avoid false positives on long-lived flows

## Installation

### Build From Source

```bash
# Ensure you have Go 1.23+ and libzmq development files
apt-get install libzmq3-dev  # Debian/Ubuntu
brew install zeromq          # macOS

git clone https://github.com/synfinatic/netflow2ng.git
cd netflow2ng
make
# Binary will be in dist/
```

### Docker

```bash
git clone https://github.com/synfinatic/netflow2ng.git
cd netflow2ng
docker compose up
```

**Important**: When using Docker, you must use host networking due to NAT causing the source port to change for inbound flow packets.

## Configuration

### Command Line Options

```
Usage: netflow2ng [flags]

High-throughput NetFlow v9/IPFIX/sFlow collector for ntopng

Flags:
  -h, --help                      Show context-sensitive help.

NetFlow/IPFIX Configuration:
  -a, --listen=0.0.0.0:2055       NetFlow/IPFIX listen address:port
      --reuse                     Enable SO_REUSEPORT for NetFlow/IPFIX listen port
  -w, --workers=2                 Number of NetFlow workers

sFlow Configuration:
      --sflow-listen=ADDRESS      sFlow listen address:port (empty to disable)
      --sflow-workers=2           Number of sFlow workers

Metrics/Health:
  -m, --metrics=0.0.0.0:8080      Metrics listen address

ZMQ Configuration:
  -z, --listen-zmq="tcp://*:5556" ZMQ bind address(es), comma-separated for fan-out
      --fanout-strategy="hash"    ZMQ fan-out strategy [hash|round-robin]
      --topic="flow"              ZMQ Topic
      --source-id=0               NetFlow SourceId (0-255)
  -f, --format="tlv"              Output format [tlv|json|jcompress|proto]

Sampling Configuration:
      --disable-upscaling         Disable sampling rate upscaling (use when exporters pre-scale)
      --default-sample-rate=1     Default sampling rate when not reported by exporter

Deduplication Configuration:
      --dedup-enabled             Enable flow deduplication
      --dedup-max-size=100000     Maximum dedup cache size
      --dedup-ttl=60s             Dedup cache entry TTL

Queue Configuration:
      --queue-size=1000000        Packet queue size

Logging:
  -l, --log-level="info"          Log level [error|warn|info|debug|trace]
      --log-format="default"      Log format [default|json]

  -v, --version                   Print version and copyright info
```

### Examples

#### Basic Usage (NetFlow/IPFIX only)

```bash
netflow2ng -a 0.0.0.0:2055 -z tcp://*:5556
```

#### With sFlow Support

```bash
netflow2ng -a 0.0.0.0:2055 --sflow-listen 0.0.0.0:6343 -z tcp://*:5556
```

#### Multi-Endpoint Fan-out (Hash-based)

Distribute flows across multiple ntopng instances with flow affinity:

```bash
netflow2ng -a 0.0.0.0:2055 \
  -z "tcp://*:5556,tcp://*:5557,tcp://*:5558" \
  --fanout-strategy hash
```

#### Multi-Endpoint Fan-out (Round-Robin)

Load balance across ntopng instances:

```bash
netflow2ng -a 0.0.0.0:2055 \
  -z "tcp://*:5556,tcp://*:5557" \
  --fanout-strategy round-robin
```

#### With Sampling Upscaling Disabled

Use when your exporters already account for sampling in reported values:

```bash
netflow2ng -a 0.0.0.0:2055 --disable-upscaling
```

#### With Deduplication Enabled

Enable flow deduplication to suppress duplicate flow records:

```bash
netflow2ng -a 0.0.0.0:2055 \
  --dedup-enabled \
  --dedup-max-size 200000 \
  --dedup-ttl 120s
```

#### High-Throughput Configuration

For high-volume environments:

```bash
netflow2ng -a 0.0.0.0:2055 \
  --sflow-listen 0.0.0.0:6343 \
  -w 8 \
  --sflow-workers 4 \
  --queue-size 2000000 \
  -z "tcp://*:5556,tcp://*:5557" \
  --fanout-strategy hash \
  --dedup-enabled \
  --dedup-max-size 500000
```

### ntopng Configuration

Configure ntopng to subscribe to netflow2ng:

```bash
ntopng -i tcp://192.168.1.1:5556
```

For multi-endpoint setups, run multiple ntopng instances or use ntopng's multi-interface support:

```bash
ntopng -i tcp://192.168.1.1:5556 -i tcp://192.168.1.1:5557
```

## HTTP Endpoints

netflow2ng exposes several HTTP endpoints on the metrics port (default 8080):

| Endpoint | Description |
|----------|-------------|
| `/__health` | Health check (503 until collecting, 200 when ready) |
| `/metrics` | Prometheus metrics |
| `/templates` | NetFlow/IPFIX template cache (JSON) |
| `/sampling` | Per-exporter sampling rate information (JSON) |
| `/dedup` | Deduplication cache statistics (JSON, if enabled) |

## Prometheus Metrics

netflow2ng exports comprehensive Prometheus metrics:

### Queue Metrics
- `netflow2ng_packets_received_total` - Total packets received
- `netflow2ng_packets_processed_total` - Total packets processed
- `netflow2ng_packets_dropped_total` - Packets dropped due to queue overflow
- `netflow2ng_queue_depth` - Current queue depth
- `netflow2ng_workers_busy` - Number of workers currently processing

### Exporter Metrics
- `netflow2ng_exporter_packets_received_total{exporter_ip,source_id}` - Per-exporter packets
- `netflow2ng_exporter_bytes_received_total{exporter_ip,source_id}` - Per-exporter bytes
- `netflow2ng_exporter_flows_processed_total{exporter_ip,source_id}` - Per-exporter flows

### Sampling Metrics
- `netflow2ng_sampling_rate{exporter_ip,observation_domain,source}` - Current sampling rate
- `netflow2ng_sampling_scaled_bytes_total{exporter_ip}` - Bytes added by upscaling
- `netflow2ng_sampling_scaled_packets_total{exporter_ip}` - Packets added by upscaling

### ZMQ Metrics
- `netflow2ng_zmq_messages_sent_total{endpoint}` - Messages sent per endpoint
- `netflow2ng_zmq_bytes_sent_total{endpoint}` - Bytes sent per endpoint
- `netflow2ng_zmq_errors_total{endpoint,error_type}` - Errors per endpoint
- `netflow2ng_zmq_endpoints_active` - Number of active endpoints

### Deduplication Metrics (when enabled)
- `netflow2ng_dedup_cache_hits_total` - Cache hits (potential duplicates)
- `netflow2ng_dedup_cache_misses_total` - Cache misses (new flows)
- `netflow2ng_dedup_duplicates_total` - Actual duplicates suppressed
- `netflow2ng_dedup_cache_size` - Current cache size
- `netflow2ng_dedup_evictions_total` - Evictions due to size limit
- `netflow2ng_dedup_expired_evictions_total` - Evictions due to TTL

### sFlow Metrics (when enabled)
- `netflow2ng_sflow_datagrams_received_total` - sFlow datagrams received
- `netflow2ng_sflow_samples_decoded_total` - sFlow samples decoded
- `netflow2ng_sflow_flows_produced_total` - Flow messages produced
- `netflow2ng_sflow_decode_errors_total` - Decode errors

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│ NetFlow/IPFIX   │     │     sFlow       │
│   Exporters     │     │   Exporters     │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│  UDP Receiver   │     │  UDP Receiver   │
│  (port 2055)    │     │  (port 6343)    │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│   Ring Buffer   │     │   Ring Buffer   │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│  Worker Pool    │     │  Worker Pool    │
│  (decode/prod)  │     │  (decode/prod)  │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     │
                     ▼
         ┌─────────────────────┐
         │  Sampling Tracker   │
         │  (upscale if enabled)│
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  Dedup Cache        │
         │  (if enabled)       │
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  Formatter          │
         │  (TLV/JSON)         │
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  ZMQ Publisher      │
         │  (fan-out)          │
         └──────────┬──────────┘
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
    ┌────────┐ ┌────────┐ ┌────────┐
    │ntopng 1│ │ntopng 2│ │ntopng 3│
    └────────┘ └────────┘ └────────┘
```

## Deduplication Heuristics

The deduplication cache uses several heuristics to avoid false positives:

1. **Flow identification**: Flows are keyed by exporter IP + 5-tuple (src/dst IP, ports, protocol)
2. **Update detection**: Flows with increased bytes/packets are not considered duplicates
3. **Sequence tracking**: Flows with advancing sequence numbers pass through
4. **Long-lived flow handling**: Periodic updates for flows active longer than TTL are allowed

This ensures that legitimate flow updates are not suppressed while true duplicates (same packet reported multiple times) are filtered.

## Ports

Default listening ports (configurable via flags):

| Port | Protocol | Description |
|------|----------|-------------|
| 2055 | UDP | NetFlow v9/IPFIX |
| 6343 | UDP | sFlow (when enabled) |
| 5556 | TCP | ZMQ Publisher |
| 8080 | TCP | Metrics/Health/Templates |

## Differences from nProbe

| Feature | netflow2ng | nProbe |
|---------|-----------|--------|
| Price | Free | 199 Euro |
| Probe mode | No | Yes |
| Collector mode | Yes | Yes |
| NetFlow v5 | No | Yes |
| NetFlow v9 | Yes | Yes |
| IPFIX | Yes | Yes |
| sFlow | Yes | Yes |
| Multi-endpoint fan-out | Yes | Via configuration |
| Sampling upscaling | Yes | Yes |
| Deduplication | Yes | Yes |
| MySQL/disk export | No | Yes |
| Commercial support | No | Yes |

## Contributing

Contributions are welcome! Please ensure:
1. Code passes `go vet` and `golangci-lint`
2. New features include tests
3. Documentation is updated

## License

See [LICENSE](LICENSE) file.
