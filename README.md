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

### Installing

 1. Make sure you have a recent version of go.  I used 1.14.2.   Older versions
    may have problems.
 1. `git clone https://github.com/synfinatic/netflow2ng.git`
 1. `cd netflow2ng`
 1. `make`
 1. The binary should now be in the `dist` directory.  Copy it somewhere
    appropriate and create the necessary startup script(s).
 1. For a list of configuration arguments, run `netflow2ng -h`
 1. Configure your network device(s) to send NetFlow stats to netflow2ng
 1. Configure your [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/)
    service to read from netflow2ng: `ntopng -i tcp://192.168.1.1:5556` where
    "192.168.1.1" is the IP address of your netflow2ng server.

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
 * Written in GoLang instead of C/C++

### Project Status

I created netflow2ng to:

 1. Learn GoLang
 2. Have better network visibilty on my home network

I suppose #1 was successful (well to a point... there's still more to learn
about Go), but #2 is basically on hold until I get better hardware.

Unfortunately, I learned that enabling NetFlow on my USG reduced it's throughput
by 90% (apparently turning on netflow disables hardware acceleration).  Hence,
I'm not really able to use this until I get better hardware.  So until that
happens you may not see much in terms of updates.
