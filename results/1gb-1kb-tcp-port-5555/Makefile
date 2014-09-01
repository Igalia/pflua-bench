top_srcdir := ../..

SAVEFILE:=$(top_srcdir)/savefiles/one-gigabyte.pcap
TITLE:="Millions of packets/second, 1GB of 1kB packets on TCP port 5555"
STEM:=$(notdir $(shell pwd))
PNG:=$(STEM).png

include $(top_srcdir)/bench.mk

$(SAVEFILE): $(SAVEFILE).xz
	unxz -k $<
