BPF_SRC := ebpf/network/xdp_test.bpf.c
BPF_OBJ := build/xdp_test.bpf.o
BPF_SKEL := build/xdp_test.skel.h
AGENT := build/kernellens-agent
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

BPF_CFLAGS := -O2 -g -target bpf -Wall -Werror -isystem ebpf/include
CFLAGS ?= -O2 -g
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf)

.PHONY: all ebpf clean test

all: $(AGENT)

ebpf: $(BPF_OBJ)

build:
	mkdir -p build

$(BPF_OBJ): $(BPF_SRC) ebpf/include/vmlinux.h ebpf/include/event.h | build
	$(CLANG) $(BPF_CFLAGS) $(LIBBPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@

$(AGENT): agent/main.c ebpf/include/event.h $(BPF_SKEL)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror $(LIBBPF_CFLAGS) -Iebpf/include -Ibuild $< -o $@ $(LDFLAGS) $(LIBBPF_LIBS)

test: all
	bash tests/m2_pipeline.sh

clean:
	rm -rf build
