# netflow2ng Project Structure

## Overview

netflow2ng is a NetFlow v9/IPFIX collector that forwards flow data to [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/) via ZeroMQ. It serves as a free alternative to nProbe for home/SOHO use cases.

## Architecture

```
┌─────────────────┐  NetFlow v9/IPFIX ┌─────────────────┐      ZMQ       ┌─────────────────┐
│  Network Device │ ──────────────▶  │   netflow2ng    │ ─────────────▶ │     ntopng      │
│  (Router/Switch)│    UDP:2055      │   (collector)   │   TCP:5556     │   (analyzer)    │
└─────────────────┘                  └─────────────────┘                └─────────────────┘
```

## Directory Structure

### `cmd/`
**Main application entry point**
- [netflow2ng.go](../cmd/netflow2ng.go) - CLI parsing (using Kong), application initialization, and main loop. Sets up the NetFlow listener, formatter, transport, and Prometheus metrics server.

### `formatter/`
**Output formatters for ntopng compatibility**
- [formatter.go](../formatter/formatter.go) - Common formatter utilities and registration. Handles conversion from goflow2's `ProtoProducerMessage` to our `ExtendedFlowMessage`.
- [ntopng_tlv.go](../formatter/ntopng_tlv.go) - TLV (Type-Length-Value) format encoder for ntopng. This is the default and recommended format.
- [ntopng_json.go](../formatter/ntopng_json.go) - JSON format encoder for ntopng (legacy, for ntopng v6.3 and earlier).
- [mapping.yaml](../formatter/mapping.yaml) - Field mapping configuration for goflow2's protobuf producer. Remaps IN/OUT bytes/packets fields to avoid overwrites.

### `transport/`
**ZeroMQ transport layer**
- [transport.go](../transport/transport.go) - Transport driver registration and logger setup.
- [zmq.go](../transport/zmq.go) - ZMQ publisher implementation. Handles message framing with ntopng's `zmqHeaderV3` format, optional zlib compression, and multi-part message sending.

### `proto/`
**Protocol Buffer definitions**
- [extended_flow.proto](../proto/extended_flow.proto) - Extends goflow2's `FlowMessage` with remapped IN/OUT byte/packet counters.
- [extended_flow.pb.go](../proto/extended_flow.pb.go) - Auto-generated Go bindings (regenerate with `make protobuf`).

### `package/`
**Deployment and packaging files**
- [Dockerfile](../package/Dockerfile) - Multi-stage Docker build for creating distributable packages.
- [netflow2ng.service](../package/netflow2ng.service) - systemd service unit file.
- [netflow2ng.env](../package/netflow2ng.env) - Environment variable configuration template.

### Root Files
- [Makefile](../Makefile) - Build targets for compilation, testing, Docker, and package creation.
- [Dockerfile](../Dockerfile) - Development/runtime Docker image.
- [docker-compose.yaml](../docker-compose.yaml) - Docker Compose configuration for running with ntopng.
- [go.mod](../go.mod) - Go module dependencies.

## Key Dependencies

- **[goflow2](https://github.com/netsampler/goflow2)** - NetFlow/sFlow/IPFIX decoder library
- **[pebbe/zmq4](https://github.com/pebbe/zmq4)** - ZeroMQ bindings for Go
- **[kong](https://github.com/alecthomas/kong)** - CLI argument parser
- **[logrus](https://github.com/sirupsen/logrus)** - Structured logging
- **[prometheus/client_golang](https://github.com/prometheus/client_golang)** - Metrics exposition

## Data Flow

1. **Collection**: goflow2 receives NetFlow v9/IPFIX packets on UDP port 2055
2. **Decoding**: goflow2 decodes packets into `ProtoProducerMessage` using our custom `mapping.yaml` (both protocols auto-detected)
3. **Conversion**: Formatter converts messages to `ExtendedFlowMessage` to preserve IN/OUT byte counters
4. **Encoding**: Formatter encodes to TLV or JSON format for ntopng
5. **Transport**: ZMQ transport wraps data in `zmqHeaderV3` and publishes on TCP port 5556
6. **Consumption**: ntopng subscribes and ingests flow data

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| TLV | `--format tlv` | Default. Binary format using nDPI serialization. Most efficient. |
| JSON | `--format json` | JSON key-value pairs. For ntopng ≤6.3. |
| JSON Compressed | `--format jcompress` | zlib-compressed JSON. |

## Default Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 2055 | UDP | NetFlow v9/IPFIX listener |
| 5556 | TCP | ZMQ publisher for ntopng |
| 8080 | TCP | Prometheus metrics & `/templates` endpoint |

## Building

```bash
make                    # Build for current platform
make test               # Run tests
make protobuf           # Regenerate protobuf bindings
make docker             # Build Docker image
```
