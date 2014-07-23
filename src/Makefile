PATH := ../deps/pflua/deps/luajit/usr/local/bin:$(PATH)

all: check test-all

check:
	make -C ref/bpf-jit-kernel clean lib && \
	luajit -e 'print("check passed!")'

test: test-bpf-libpcap test-bpf-pflua test-bpf-kernel

test-bpf-libpcap:
	luajit -l bpf_libpcap_ts -e 'bpf_libpcap_ts.run()'

test-bpf-pflua:
	luajit -l bpf_pflua_ts -e 'bpf_pflua_ts.run()'

test-bpf-kernel:
	luajit -l bpf_kernel_ts -e 'bpf_kernel_ts.run()'

csv: csv-bpf-libpcap csv-bpf-pflua csv-bpf-kernel

csv-bpf-libpcap:
	luajit -l gen_dataset -e 'gen_dataset.run(5, "make test-bpf-libpcap", "bpf-libpcap.csv")'

csv-bpf-pflua:
	luajit -l gen_dataset -e 'gen_dataset.run(5, "make test-bpf-pflua", "bpf-pflua.csv")'

csv-bpf-kernel:
	luajit -l gen_dataset -e 'gen_dataset.run(5, "make test-bpf-kernel", "bpf-kernel.csv")'

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

csv2:
	luajit bench.lua ts/pcaps/igalia/one-gigabyte.pcap libpcap | tee libpcap.csv
	luajit bench.lua ts/pcaps/igalia/one-gigabyte.pcap bpf | tee bpf.csv
	luajit bench.lua ts/pcaps/igalia/one-gigabyte.pcap pflua | tee pflua.csv

csv3:
	luajit bench.lua ts/pcaps/igalia/ping-flood.pcap libpcap | tee libpcap.csv
	luajit bench.lua ts/pcaps/igalia/ping-flood.pcap bpf | tee bpf.csv
	luajit bench.lua ts/pcaps/igalia/ping-flood.pcap pflua | tee pflua.csv

pflua-1gb-1kb-tcp-port-5555.png: check-png-deps csv2
	~/src/guile-charting/examples/plot-data.scm \
	  "Millions of packets/second, 1GB of 1kB packets on TCP port 5555" \
	  pflua-1gb-1kb-tcp-port-5555.png libpcap.csv bpf.csv pflua.csv

pflua-ping-flood.png: check-png-deps csv3
	~/src/guile-charting/examples/plot-data.scm \
	  "Millions of packets/second, 60MB of ICMP pings" \
	  pflua-ping-flood.png libpcap.csv bpf.csv pflua.csv

graphs: pflua-1gb-1kb-tcp-port-5555.png

clean:
