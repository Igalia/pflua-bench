CC= gcc
CFLAGS=-g -Wall -fPIC -O3

OBJECTS= bpf_jit_comp.o bpf_jit.o hack.o bpf_jit_kernel.o

all: linux-bpf-jit.so

linux-bpf-jit.so: $(OBJECTS)
	$(CC) -shared $(CFLAGS) -g -o $@ $(OBJECTS)
%.o: %.c
	gcc -c -o $@ $< $(CFLAGS)

clean:
	rm -rf *.o linux-bpf-jit.so

.PHONY: clean all
