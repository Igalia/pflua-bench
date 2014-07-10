PATH := .:deps/pflua/deps/luajit/usr/local/bin:$(PATH)

all: check test-all

check:
	luajit -e 'print("check passed!")'

test-all: test-bpf-libpcap

test-bpf-libpcap:
	luajit -l bpf_libpcap_ts -e 'bpf_libpcap_ts.run()'

csv: csv-bpf-libpcap csv-bpf-pflua

csv-bpf-libpcap:
	luajit -l gen_dataset -e 'gen_dataset.run(5, "make test-bpf-libpcap", "bpf-libpcap.csv")'

csv-bpf-pflua:
	luajit -l gen_dataset -e 'gen_dataset.run(5, "make -C deps/pflua/src test", "bpf-pflua.csv")'

clean:
