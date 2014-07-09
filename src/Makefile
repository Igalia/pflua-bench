PATH := .:../../pflua/deps/luajit/usr/local/bin:$(PATH)

all: check test-all

check:
	luajit -e 'print("check passed!")'

test-all: test-bpf-libpcap

test-bpf-libpcap:
	luajit -l bpf_libpcap_ts -e 'bpf_libpcap_ts.run()'

clean:
