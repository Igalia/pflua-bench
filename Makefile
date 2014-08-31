PATH := deps/pflua/deps/luajit/usr/local/bin:$(PATH)

all: check_submodules
	$(MAKE) -C deps/pflua all
	$(MAKE) -C linux-bpf-jit
	$(MAKE) -C linux-ebpf-jit

check:
	$(MAKE) -C deps/pflua check
	$(MAKE) -C linux-bpf-jit
	$(MAKE) -C linux-ebpf-jit

clean:
	$(MAKE) -C deps/pflua clean
	$(MAKE) -C linux-bpf-jit
	$(MAKE) -C linux-ebpf-jit

check_submodules:
	@if [ ! -f deps/pflua/Makefile ]; then \
	    echo "Can't find deps/pflua/. You might need to: git submodule update --init"; exit 1; \
	fi

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

savefiles/one-gigabyte.pcap: savefiles/one-gigabyte.pcap.xz
	unxz -k $<

1gb-1kb-tcp-port-5555-csv: savefiles/one-gigabyte.pcap
	set -e; luajit bench.lua savefiles/one-gigabyte.pcap libpcap > libpcap.csv
	set -e; luajit bench.lua savefiles/one-gigabyte.pcap linux_bpf > linux-bpf.csv
	set -e; luajit bench.lua savefiles/one-gigabyte.pcap linux_ebpf > linux-ebpf.csv
	set -e; luajit bench.lua savefiles/one-gigabyte.pcap bpf > bpf.csv
	set -e; luajit bench.lua savefiles/one-gigabyte.pcap pflua > pflua.csv

ping-flood-csv:
	set -e; luajit bench.lua savefiles/ping-flood.pcap libpcap > libpcap.csv
	set -e; luajit bench.lua savefiles/ping-flood.pcap linux_bpf > linux-bpf.csv
	set -e; luajit bench.lua savefiles/ping-flood.pcap linux_ebpf > linux-ebpf.csv
	set -e; luajit bench.lua savefiles/ping-flood.pcap bpf > bpf.csv
	set -e; luajit bench.lua savefiles/ping-flood.pcap pflua > pflua.csv

wingolog-csv:
	set -e; luajit bench.lua savefiles/wingolog.org.pcap libpcap > libpcap.csv
	set -e; luajit bench.lua savefiles/wingolog.org.pcap linux_bpf > linux-bpf.csv
	set -e; luajit bench.lua savefiles/wingolog.org.pcap linux_ebpf > linux-ebpf.csv
	set -e; luajit bench.lua savefiles/wingolog.org.pcap bpf > bpf.csv
	set -e; luajit bench.lua savefiles/wingolog.org.pcap pflua > pflua.csv

pflua-1gb-1kb-tcp-port-5555.png: check-png-deps 1gb-1kb-tcp-port-5555-csv
	~/src/guile-charting/examples/plot-data.scm \
	  "Millions of packets/second, 1GB of 1kB packets on TCP port 5555" \
	  pflua-1gb-1kb-tcp-port-5555.png libpcap.csv linux-bpf.csv linux-ebpf.csv bpf.csv pflua.csv

pflua-ping-flood.png: check-png-deps ping-flood-csv
	~/src/guile-charting/examples/plot-data.scm \
	  "Millions of packets/second, 60MB of ICMP pings" \
	  pflua-ping-flood.png libpcap.csv linux-bpf.csv linux-ebpf.csv bpf.csv pflua.csv

pflua-wingolog.png: check-png-deps wingolog-csv
	~/src/guile-charting/examples/plot-data.scm \
	  "Millions of packets/second, wingolog.org" \
	  pflua-wingolog.png libpcap.csv linux-bpf.csv linux-ebpf.csv bpf.csv pflua.csv

graphs: pflua-1gb-1kb-tcp-port-5555.png pflua-ping-flood.png pflua-wingolog.png

.SERIAL: all
