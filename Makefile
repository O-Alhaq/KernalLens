BPF_SRC := ebpf/network/xdp_test.bpf.c
BPF_OBJ := build/xdp_test.bpf.o

BPF_CFLAGS := -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu

.PHONY: all ebpf clean

all: ebpf

ebpf:
	mkdir -p build
	clang $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

clean:
	rm -rf build
