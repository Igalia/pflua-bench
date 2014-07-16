CC= gcc
CFLAGS=

OBJECTS= bpf_jit_comp.o bpf_jit.o hack.o bpf_jit_kernel.o

all: rel

dbg: CFLAGS += -g -DDBG
dbg: rel

rel: $(OBJECTS)
	$(CC) $(CFLAGS) -o bpf_jit_kernel $^

lib: CFLAGS += -fPIC
lib: $(OBJECTS)
	$(CC) -shared $(CFLAGS) -o libbpf_jit_kernel.so.1.0.0 -Wl,-soname,libbpf_jit_kernel.so.1 $(OBJECTS) -lc

%.o: %.c
	gcc -c -o $@ $< $(CFLAGS)

clean:
	rm -rf *.o bpf_jit_kernel libbpf_jit_kernel.so.1.0.0

.PHONY: clean all
