CC= gcc
CFLAGS=-g -Wall -fPIC

OBJECTS= bpf_jit_comp.o bpf_jit.o hack.o core.o filter.o

all: libbpfe_jit_kernel.so.1.0.0

libbpfe_jit_kernel.so.1.0.0: $(OBJECTS)
	$(CC) -shared $(CFLAGS) -g -o $@ -Wl,-soname,libbpfe_jit_kernel.so.1 $(OBJECTS) -lc

%.o: %.c
	gcc -c -o $@ $< $(CFLAGS)

clean:
	rm -rf *.o libbpfe_jit_kernel.so.1.0.0

.PHONY: clean all
