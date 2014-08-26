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
	$(CC) -shared $(CFLAGS) -g -o libbpf_jit_kernel.so.1.0.0 -Wl,-soname,libbpf_jit_kernel.so.1 $(OBJECTS) -lc
	$(CC) $(CFLAGS) -g -o test_lib test_lib.c -ldl

%.o: %.c
	gcc -c -o $@ $< $(CFLAGS)

clean:
	rm -rf *.o bpf_jit_kernel libbpf_jit_kernel.so.1.0.0 test_lib

.PHONY: clean all
