# pflua-bench

This repository is a benchmarking suite for the [pflua packet filtering
library](https://github.com/Igalia/pflua).  It compares the following
pflang implementations:

* *libpcap*: The user-space Berkeley Packet Filter (BPF) interpreter
  from [`libpcap`](https://github.com/the-tcpdump-group/libpcap).

* *linux-bpf*: The old Linux kernel-space [BPF
   compiler](http://lwn.net/Articles/437981/) from 2011.  We have
   adapted this library to work as a loadable user-space module
   ([source](https://github.com/Igalia/pflua-bench/tree/master/linux-bpf-jit)).

* *linux-ebpf*: The new Linux kernel-space [BPF
   compiler](http://lwn.net/Articles/599755/) from 2014, also adapted to
   user-space
   ([source](https://github.com/Igalia/pflua-bench/tree/master/linux-ebpf-jit)).

* *bpf*: BPF bytecodes, cross-compiled to Lua by pflua.

* *pflua*: Pflang compiled directly to Lua by pflua.

See https://github.com/Igalia/pflua for more on pflua's two execution
engines, and for more resources on pflang and BPF.

# Experimental environment

To benchmark a pflang implementation, we use the implementation to run a
set of pflang expressions over saved packet captures.  The result is a
corresponding set of benchmark scores measured in millions of packets
per second (MPPS).  The first set of results is thrown away as a warmup.
After warmup, the run is repeated 50 times within the same process to
get multiple result sets.  Each run checks to see that the filter
matches the the expected number of packets, to verify that each
implementation does the same thing, and also to ensure that the loop is
not dead.

In all cases the same Lua program is used to drive the benchmark.  We
have tested a native C loop when driving libpcap and gotten similar
results, so we consider that the LuaJIT interface to C is not a
performance bottleneck.

There are three test workloads:

* A synthetic capture of about 1.1 GB of zeroes transferred between two
  machines over TCP port 5555; about 1.1M packets.  The throughput is
  ultimately bottlenecked by memory bandwidth, but it is a useful test
  to check if filter overhead is significant when compared to memory
  bandwidth.

* A synthetic capture of 64 MB of pings from one machine to another;
  about 1M packets.  Here we test per-packet overhead for very small but
  similar packets.

* A real-world capture of 37 MB of traffic to `wingolog.org`, which
  mostly operates as a web server.  About 20K packets.

Each packet is captured with the ethernet frame, and has 16 additional
bytes of overhead due to the `libpcap` savefile format.

Of course, we can't argue that any of these workloads reflect
performance in real-world conditions, and this consideration applies to
the benchmarking script itself as well.

The following measurements were made on a i7-3770 system, in x86-64
mode, under Debian GNU/Linux (3.14-2), on an otherwise unloaded machine.

# One gigabyte: 1.1M kilobytes of zeroes

![Benchmark results](http://wingolog.org/pub/pflua-1gb-1kb-tcp-port-5555.png)

# Ping flood: 1M ping packets

![Benchmark results](http://wingolog.org/pub/pflua-ping-flood.png)

# Web server: 20K packets from `wingolog.org`

![Benchmark results](http://wingolog.org/pub/pflua-wingolog.png)
