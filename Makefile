BPF_SRC := ebpf/network/xdp_test.bpf.c
BPF_OBJ := build/xdp_test.bpf.o
BPF_SKEL := build/xdp_test.skel.h
HOST_OBJ := build/host.bpf.o
HOST_SKEL := build/host.skel.h
AGENT := build/kernellens-agent
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

BPF_CFLAGS := -O2 -g -target bpf -Wall -Werror -isystem ebpf/include
CFLAGS ?= -O2 -g
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf)

.PHONY: all ebpf clean test test-m2 test-m3 test-m4 test-m5

all: $(AGENT)

ebpf: $(BPF_OBJ) $(HOST_OBJ)

build:
	mkdir -p build

$(BPF_OBJ): $(BPF_SRC) ebpf/include/vmlinux.h ebpf/include/event.h ebpf/include/packet_parser.h | build
	$(CLANG) $(BPF_CFLAGS) $(LIBBPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@

$(HOST_OBJ): ebpf/process/host.bpf.c ebpf/include/vmlinux.h ebpf/include/host_event.h | build
	$(CLANG) $(BPF_CFLAGS) $(LIBBPF_CFLAGS) -c $< -o $@

$(HOST_SKEL): $(HOST_OBJ)
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@

$(AGENT): agent/main.c agent/ipc.c agent/ipc.h ebpf/include/event.h ebpf/include/host_event.h $(BPF_SKEL) $(HOST_SKEL)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror $(LIBBPF_CFLAGS) -Iebpf/include -Ibuild agent/main.c agent/ipc.c -o $@ $(LDFLAGS) $(LIBBPF_LIBS)

build/ipc-driver: tests/ipc_driver.c agent/ipc.c agent/ipc.h ebpf/include/event.h ebpf/include/host_event.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -Iagent -Iebpf/include tests/ipc_driver.c agent/ipc.c -o $@ $(LDFLAGS)

build/packet-parser-test: tests/packet_parser.c ebpf/include/packet_parser.h ebpf/include/event.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -Iebpf/include $< -o $@ $(LDFLAGS)

test: all build/ipc-driver build/packet-parser-test
	./build/packet-parser-test
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py' -v

test-m2: all
	bash tests/m2_pipeline.sh

test-m3: all
	KERNELLENS_TEST_M3=1 bash tests/m2_pipeline.sh

test-m4: all
	KERNELLENS_TEST_M3=1 KERNELLENS_TEST_M4=1 bash tests/m2_pipeline.sh

build/host-activity: tests/host_activity.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror $< -o $@ $(LDFLAGS)

test-m5: all build/host-activity
	KERNELLENS_TEST_M3=1 KERNELLENS_TEST_M4=1 KERNELLENS_TEST_M5=1 bash tests/m2_pipeline.sh

clean:
	rm -rf build
