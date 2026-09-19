# netflow2ng
NetFlow v9 collector for [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/)

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
collect NetFlow stats from.

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
 1. Configure your network device(s) to send NetFlow stats to netflow2ng
 1. Configure your [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/)
    service to read from netflow2ng: `ntopng -i tcp://192.168.1.1:5556` where
    "192.168.1.1" is the IP address of your netflow2ng server.
 1. netflow2ng encrypts the ZMQ feed by default.  See
    [ZMQ Encryption](#zmq-encryption) below -- especially if you are running
    ntopng older than 6.7.280831.

### ZMQ Encryption

**Upgrade warning:** starting with v0.3.0, netflow2ng **encrypts its ZMQ flow
feed by default**.  This mirrors ntop's own change in ntopng 6.7.280831
(Sept 2026), where [secure ZMQ flow collection became the
default](https://www.ntop.org/secure-zmq-flow-collection-now-enabled-by-default/)
and an ntopng collector silently discards cleartext flows.  If you run
**ntopng 6.7.280831 or newer, you do not need to change anything** — netflow2ng
and ntopng will agree out of the box.  If you run an **older ntopng**, add
`--zmq-disable-encryption` to netflow2ng or no flows will show up.

Encryption uses [CurveZMQ](http://curvezmq.org), the same mechanism nProbe
uses.  ntopng always takes the CURVE *server* role (it owns the keypair) and
netflow2ng takes the CURVE *client* role, regardless of which side binds the
socket.  So netflow2ng needs **ntopng's public key** — never its private key.

#### Options

| Flag | Environment variable | Purpose |
|------|----------------------|---------|
| `--zmq-encryption-key` | `NETFLOW2NG_ZMQ_ENCRYPTION_KEY` | ntopng's 40 character Z85 public key |
| `--zmq-encryption-key-file` | `NETFLOW2NG_ZMQ_ENCRYPTION_KEY_FILE` | Path to a file holding that key (eg: ntopng's `zmq-key.pub`) |
| `--zmq-disable-encryption` | `NETFLOW2NG_ZMQ_DISABLE_ENCRYPTION` | Send cleartext; required for ntopng older than 6.7.280831 |
| `--zmq-client-priv-key` | `NETFLOW2NG_ZMQ_CLIENT_PRIV_KEY` | Pin netflow2ng's own private key instead of generating a throwaway one at startup |

Precedence is `--zmq-encryption-key` > `--zmq-encryption-key-file` >
ntopng's built-in default key.  A flag always beats its environment variable.

netflow2ng generates a fresh client keypair every time it starts.  ntopng does
not authenticate client keys, so there is normally no reason to set
`--zmq-client-priv-key`.

#### Finding ntopng's public key

Run ntopng with `--zmq-encryption`.  It writes a keypair to its data directory
and shows the public key on the interface's status page in the web UI:

```bash
# on the ntopng host, default datadir:
cat /var/lib/ntopng/zmq-key.pub
```

Then point netflow2ng at it:

```bash
netflow2ng --zmq-encryption-key '<the 40 char key>'
# or, if the file is readable from the netflow2ng host:
netflow2ng --zmq-encryption-key-file /var/lib/ntopng/zmq-key.pub
```

If you configure *neither* flag, netflow2ng uses the public key that ntopng
itself falls back to when no key has been configured.  That works against a
stock ntopng, but the key pair is published in ntopng's source, so anyone who
can see your network traffic can decrypt the flows.  netflow2ng logs a warning
when this happens.  Use a dedicated key for anything that matters.

#### Running without encryption

Both sides have to agree.  For ntopng older than 6.7.280831 — or if you would
rather not encrypt on a trusted link — disable it on both:

```bash
netflow2ng --zmq-disable-encryption
ntopng -i tcp://192.168.1.1:5556 --zmq-disable-encryption
```

#### Troubleshooting

* **No flows in ntopng, no errors anywhere.** The two sides disagree about
  encryption, or about the key.  A CURVE mismatch fails silently at the ZMQ
  layer: netflow2ng keeps publishing and ntopng simply never receives
  anything.  Check that netflow2ng's startup log and ntopng's `--zmq-*`
  settings match, and compare the key netflow2ng logs against ntopng's
  `zmq-key.pub`.
* **`this build of libzmq has no CURVE support`.** Your libzmq was built
  without libsodium.  Rebuild it with libsodium, install a distro package that
  has it, or run with `--zmq-disable-encryption`.  The official netflow2ng
  Docker image includes CURVE support.

### Features

 * Collect NetFlow v9 stats from one or more probes
 * Run a ZMQ Publisher for ntopng to collect metrics from
 * Encrypted (CurveZMQ) flow delivery, on by default, matching ntopng 6.7.280831+
 * Prometheus metrics
 * NetFlow Templates available via /templates HTTP endpoint

### Ports

By default, netflow2ng listens on all addresses on the following ports. This can be changed via configuration arguments.
 * NetFlow/IPFIX: 2055
 * ZMQ connections (TCP): 5556
 * Metrics: 8080

### NetFlow v9 Support

netflow2ng utilizes [goflow2](https://github.com/netsampler/goflow2) for NetFlow
decoding.  For more information on what NetFlow fields are supported in
netflow2ng, please read the goflow docs.

### sFlow/IPFIX/etc support?

In theory, adding sFlow/IPFIX/NetFlow v5 support should be pretty trivial, but
isn't something I plan on doing due to lack of hardware for testing/need.

### How is netflow2ng different from nProbe?

 * Not 199Euro
 * Doesn't support any probe features (sniffing traffic directly)
 * Can't write stats to MySQL/disk or act as a NetFlow proxy
 * Not tested with lots of probes or on 10Gbit networks
 * Targeted for Home/SOHO use.
 * No commercial support, etc.
 * May not support the latest versions/features of ntopng
 * Written in GoLang instead of C/C++
