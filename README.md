# netflow2ng
NetFlow v9 collector for [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/)

### TL;DR

ntopng is a free/commercial NetFlow/sFlow analysis console suitible for a
variety of use cases.  However, if you want to collect NetFlow or sFlow
data and load that into ntopng you currently have no choice but to spend
199Euro on [nProbe](https://www.ntop.org/products/netflow/nprobe/) which
in my case is more expensive than the 
[Ubiquiti USG](https://www.ui.com/unifi-routing/usg/) that I wanted to 
collect NetFlow stats from.

Hence, I created netflow2ng.

### Features

 * Collect NetFlow v9 stats from one or more probes
 * Run a ZMQ Publisher for ntopng to collect metrics from
 * Prometheus metrics
 * NetFlow Templates

### NetFlow v9 Support

netflow2ng utilizes [goflow](https://github.com/cloudflare/goflow) for NetFlow
decoding.  For more information on what NetFlow fields are supported in 
netflow2ng, please read the goflow docs.

### sFlow/IPFIX/etc support?

In theory, adding sFlow/IPFIX/NetFlow v5 support should be pretty trivial, but
I haven't bothered at this time.

### How is netflow2ng different from nProbe?

 * Not 199Euro
 * Doesn't support any probe features (sniffing traffic directly)
 * Can't write stats to MySQL/disk or act as a NetFlow proxy
 * Not tested with lots of probes or on 10Gbit networks
 * Targeted for Home/SOHO use.
 * No commercial support, etc.
 * May not support the latest versions/features of ntopng
