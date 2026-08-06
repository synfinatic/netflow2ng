# netflow2ng
NetFlow v9 / IPFIX collector for [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/)

[![Tests](https://github.com/synfinatic/netflow2ng/actions/workflows/tests.yml/badge.svg)](https://github.com/synfinatic/netflow2ng/actions/workflows/tests.yml)
[![codeql-analysis.yml](https://github.com/synfinatic/netflow2ng/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/synfinatic/netflow2ng/actions/workflows/codeql-analysis.yml)
[![golangci-lint](https://github.com/synfinatic/netflow2ng/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/synfinatic/netflow2ng/actions/workflows/golangci-lint.yaml)

### TL;DR

ntopng is a free/commercial NetFlow/sFlow analysis console suitible for a
variety of use cases.  However, if you want to collect NetFlow or sFlow
data and load that into ntopng you currently have no choice but to spend
199Euro on [nProbe](https://www.ntop.org/products/netflow/nprobe/) which
in my case is more expensive than the
[Ubiquiti USG](https://www.ui.com/unifi-routing/usg/) that I wanted to
collect NetFlow stats from. The same is true for IPFIX exporters, including
OpenBSD's [pflow(4)](https://man.openbsd.org/pflow.4) with `pflowproto 10`.

Hence, I created netflow2ng.

### Installing

##### Build From Source
 1. Make sure you have a recent version of go.  I used 1.14.2.   Older versions
    may have problems.
 1. `git clone https://github.com/synfinatic/netflow2ng.git`
 1. `cd netflow2ng`
 1. `make`
 1. The binary should now be in the `dist` directory.  Copy it somewhere
    appropriate and create the necessary startup script(s).

##### Install via Docker

 1. Pull the repository using `git clone https://github.com/synfinatic/netflow2ng.git`.
 1. Use the optional [docker-compose.yaml](docker-compose.yaml) file with `docker compose up`.

 **Important**: When using Docker, you must use host networking due to NAT causing the source
 port to change for inbound Netflow packets which breaks `netflow2ng`.

### Configuration

 1. For a list of configuration arguments, run `netflow2ng -h`. As of v0.1.1, netflow2ng
    defaults to the ntopng TLV format instead of JSON. If you want to use JSON, you must
    use it with `ntopng` v6.3 or earlier.
 1. Configure your network device(s) to send NetFlow or IPFIX stats to netflow2ng.
    For OpenBSD: `ifconfig pflow0 flowsrc <bsd-ip> flowdst <netflow2ng-ip>:2055 pflowproto 10`.
 1. Configure your [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/)
    service to read from netflow2ng: `ntopng -i tcp://192.168.1.1:5556` where
    "192.168.1.1" is the IP address of your netflow2ng server.

### Features

 * Collect NetFlow v9 and IPFIX stats from one or more probes (incl. OpenBSD `pflow(4)`)
 * Run a ZMQ Publisher for ntopng to collect metrics from
 * Prometheus metrics
 * NetFlow / IPFIX templates available via /templates HTTP endpoint

### Ports

By default, netflow2ng listens on all addresses on the following ports. This can be changed via configuration arguments.
 * NetFlow/IPFIX: 2055
 * ZMQ connections (TCP): 5556
 * Metrics: 8080

### NetFlow v9 / IPFIX Support

netflow2ng utilizes [goflow2](https://github.com/netsampler/goflow2) for NetFlow
and IPFIX decoding. The same UDP listener accepts NetFlow v9 (version 9) and IPFIX
(version 10) packets — goflow2 dispatches by the version field in the packet
header, so no per-protocol configuration is required. For more information on what
fields are supported, please read the goflow docs.

OpenBSD's [pflow(4)](https://man.openbsd.org/pflow.4) `pflowproto 10` exporter is
known to work; it emits unidirectional flows so only the inbound byte/packet
counters are populated per record. Bidirectional IPFIX exporters additionally
populate the outbound counters (postOctetDeltaCount / postPacketDeltaCount).

### sFlow / NetFlow v5 support?

Not currently supported. Both would require additional decoder wiring and
producer-side changes; this codebase only implements the NetFlow v9 / IPFIX path.

### How is netflow2ng different from nProbe?

 * Not 199Euro
 * Doesn't support any probe features (sniffing traffic directly)
 * Can't write stats to MySQL/disk or act as a NetFlow proxy
 * Not tested with lots of probes or on 10Gbit networks
 * Targeted for Home/SOHO use.
 * No commercial support, etc.
 * May not support the latest versions/features of ntopng
 * Written in GoLang instead of C/C++
