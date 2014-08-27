PATH := ../deps/pflua/deps/luajit/usr/local/bin:$(PATH)

all: linux-jit

linux-jit:
	make -C ref/linux-bpf-jit
	make -C ref/linux-ebpf-jit

GUILE=guile

check-png-deps:
	@$(GUILE) -c '(exit (string-prefix? "2." (effective-version)))' 2>/dev/null || ( \
	  echo "Guile 2.x required to make graphs.  Try 'sudo apt-get install guile-2.0'."; \
	  echo; \
	  exit 1 )
	@$(GUILE) -c '(use-modules (cairo))' 2>/dev/null || ( \
	  echo "Guile-Cairo required to make graphs."; \
	  echo "Install from http://www.nongnu.org/guile-cairo/; probably you will"; \
	  echo "want to run its configure with --prefix=/usr."; \
	  echo; \
	  exit 1 )
	@$(GUILE) -c '(use-modules (charting))' 2>/dev/null || ( \
	  echo "Guile-Charting required to make graphs."; \
	  echo "Check out from https://gitorious.org/guile-charting."; \
	  echo "I recommend not installing it.  Instead after configuring"; \
	  echo "and building, run this make target within the 'env' script"; \
	  echo "in the guile-charting build directory."; \
	  exit 1 )

ts/pcaps/igalia/one-gigabyte.pcap: ts/pcaps/igalia/one-gigabyte.pcap.xz
	unxz -k $<

1gb-1kb-tcp-port-555-csv: ts/pcaps/igalia/one-gigabyte.pcap
	luajit bench.lua ts/pcaps/igalia/one-gigabyte.pcap libpcap | tee libpcap.csv
	luajit bench.lua ts/pcaps/igalia/one-gigabyte.pcap linux_bpf | tee linux-bpf.csv
	luajit bench.lua ts/pcaps/igalia/one-gigabyte.pcap linux_ebpf | tee linux-ebpf.csv
	luajit bench.lua ts/pcaps/igalia/one-gigabyte.pcap bpf | tee bpf.csv
	luajit bench.lua ts/pcaps/igalia/one-gigabyte.pcap pflua | tee pflua.csv

ping-flood-csv:
	luajit bench.lua ts/pcaps/igalia/ping-flood.pcap libpcap | tee libpcap.csv
	luajit bench.lua ts/pcaps/igalia/ping-flood.pcap linux_bpf | tee linux-bpf.csv
	luajit bench.lua ts/pcaps/igalia/ping-flood.pcap linux_ebpf | tee linux-ebpf.csv
	luajit bench.lua ts/pcaps/igalia/ping-flood.pcap bpf | tee bpf.csv
	luajit bench.lua ts/pcaps/igalia/ping-flood.pcap pflua | tee pflua.csv

pflua-1gb-1kb-tcp-port-5555.png: check-png-deps 1gb-1kb-tcp-port-555-csv
	~/src/guile-charting/examples/plot-data.scm \
	  "Millions of packets/second, 1GB of 1kB packets on TCP port 5555" \
	  pflua-1gb-1kb-tcp-port-5555.png libpcap.csv linux-bpf.csv linux-ebpf.csv bpf.csv pflua.csv

pflua-ping-flood.png: check-png-deps ping-flood-csv
	~/src/guile-charting/examples/plot-data.scm \
	  "Millions of packets/second, 60MB of ICMP pings" \
	  pflua-ping-flood.png libpcap.csv linux-bpf.csv linux-ebpf.csv bpf.csv pflua.csv

graphs: pflua-1gb-1kb-tcp-port-5555.png pflua-ping-flood.png

clean:
