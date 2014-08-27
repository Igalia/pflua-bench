CC= gcc
CFLAGS=-g -Wall -fPIC -O3

OBJECTS= bpf_jit_comp.o bpf_jit.o hack.o core.o filter.o

all: linux-ebpf-jit.so

linux-ebpf-jit.so: $(OBJECTS)
	$(CC) -shared $(CFLAGS) -g -o $@ $(OBJECTS)

%.o: %.c
	gcc -c -o $@ $< $(CFLAGS)

clean:
	rm -rf *.o linux-ebpf-jit.so

.PHONY: clean all
