CC=gcc
CFLAGS=

all: rel

dbg: CFLAGS += -g -DDBG
dbg: rel

rel: bpf_jit_comp.o bpf_jit.o hack.o bpf_jit_kernel.o
	$(CC) $(CFLAGS) -o bpf_jit_kernel $^

pf_jit_comp.o: bpf_jit_comp.c
bpf_jit.o: bpf_jit.S
hack.o: hack.c hack.h
bpf_jit_kernel.o: bpf_jit_kernel.c bpf_jit_kernel.h

clean:
	rm -rf *.o bpf_jit_kernel

.PHONY: clean all
