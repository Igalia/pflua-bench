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

.SERIAL: all

SCENARIOS:=1gb-1kb-tcp-port-5555 ping-flood wingolog.org-1 wingolog.org-2

maintainer-clean:
	for i in $(SCENARIOS); do make -C results/$$i maintainer-clean; done

bench:
	for i in $(SCENARIOS); do make -C results/$$i; done

clean-bench: maintainer-clean bench
