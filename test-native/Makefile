all: pf_test_native

check: pf_test_native
	./pf_test_native "" ../savefiles/one-gigabyte.pcap 1166716
	./pf_test_native "portrange 0-6000" ../savefiles/one-gigabyte.pcap 1166716
	./pf_test_native "" ../savefiles/ping-flood.pcap 961180
	./pf_test_native "icmp" ../savefiles/ping-flood.pcap 961180

pf_test_native: pf_test_native.c
	gcc -o pf_test_native pf_test_native.c -lpcap -O3 -g -Wall

clean:
	rm -f pf_test_native

#luajit -l pf_test_native -e 'pf_test_native.run()'
