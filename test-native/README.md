Usage
====

```
make check
```

Example
====

```
./pf_test_native "" ../savefiles/one-gigabyte.pcap 1166716
"" on ../savefiles/one-gigabyte.pcap: 19.5 MPPS
./pf_test_native "portrange 0-6000" ../savefiles/one-gigabyte.pcap 1166716
"portrange 0-6000" on ../savefiles/one-gigabyte.pcap: 12.8 MPPS
./pf_test_native "" ../savefiles/ping-flood.pcap 961180
"" on ../savefiles/ping-flood.pcap: 110.6 MPPS
./pf_test_native "icmp" ../savefiles/ping-flood.pcap 961180
"icmp" on ../savefiles/ping-flood.pcap: 73.9 MPPS
```

Interpretation
====

This is as fast as C and libpcap can be -- it's hand-coded tight mmap
loop with a pcap_offline_filter call in the middle.  The results are
similar to the bench.lua harness's results for libpcap, even though
bench.lua is written in Lua.
