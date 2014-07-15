all:
	gcc -c hack.c -o hack.o
	gcc -c bpf_jit.S -o bpf_jit.o
	gcc -c bpf_jit_comp.c -o bpf_jit_comp.o
	gcc -c bpf_jit_kernel.c -o bpf_jit_kernel.o
	gcc -o bpf_jit_kernel bpf_jit_comp.o bpf_jit.o hack.o bpf_jit_kernel.o
