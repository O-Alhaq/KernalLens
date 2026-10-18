# KernelLens

KernelLens is a real-time eBPF-based telemetry framework for hybrid host and network threat detection.

## Current Milestone
M3 - C Agent ↔ Python IPC

The C XDP program sends packet events through a BPF ring buffer to a C
libbpf agent. Every packet returns `XDP_PASS`, including when the ring buffer
is full (in that case the event is skipped). No packet parsing or detection is
performed. The agent can also serve a Python receiver over a Unix domain socket.
Python only validates and prints messages; no detection or later milestone
functionality is included.

Prerequisites: Linux with BTF, BPF ring buffers and XDP BPF-link support,
Clang/LLVM with the BPF target, libbpf development headers, bpftool, pkg-config,
Make, a C compiler, and Python 3 (standard library only). The existing
`ebpf/include/vmlinux.h` supplies kernel
types for the CO-RE build; the target kernel must expose BTF.

## Build
```bash
make
```

This builds `build/xdp_test.bpf.o`, generates `build/xdp_test.skel.h`, and links
`build/kernellens-agent`. `make clean` removes generated build files.

Run on a selected interface with BPF/network administration privileges:

```bash
sudo ./build/kernellens-agent INTERFACE
```

The agent uses a native XDP BPF link and refuses conflicting attachments.
The selected interface/driver must support this attachment mode. It prints
`timestamp=... ifindex=... packet_length=...` for ingress packets. Timestamp
is monotonic nanoseconds since boot; packet length is the XDP packet length
in bytes, including the Ethernet header. Press Ctrl-C or send SIGTERM to
detach and exit. The unpinned link is also released if the process exits
unexpectedly.

For M3, create a private runtime directory and pass an absolute socket path.
Run these in separate terminals, starting the agent first:

```bash
sudo install -d -m 700 /run/kernellens
sudo ./build/kernellens-agent INTERFACE /run/kernellens/events.sock
```

```bash
sudo python3 backend/receiver.py /run/kernellens/events.sock
```

The socket is accessible only to its owner (root in this example). The agent
continues printing M2 terminal events. The Python receiver prints validated
event envelopes as JSON to stdout and connection status to stderr:

```json
{"message_type":"event","schema_version":1,"event":{"timestamp":123456789,"ifindex":2,"packet_length":86}}
```

Each UTF-8 JSON object ends with a newline. Schema version 1 has exactly the
three event fields shown above: a uint64 timestamp, a positive uint32 interface
index, and a uint32 packet length. A new connection first receives
`{"message_type":"status","schema_version":1,"status":"ready"}`. There are
no client commands or request/response operations in this milestone.

Only one receiver is supported at a time; additional connections are closed.
If the receiver disconnects, the agent keeps collecting and accepts a new
receiver. Restart the Python command to reconnect. There is no event backlog
or replay: events without a connected receiver are omitted from IPC. A slow
receiver is disconnected rather than blocking ring-buffer processing. A partial
record at disconnect is rejected by Python. Invalid, oversized (over 4096 bytes),
or unsupported messages cause Python to report an error and exit nonzero;
an EOF between complete records exits normally.

Ctrl-C/SIGTERM on the agent detaches XDP, closes the connection, and removes its
socket file. Existing socket paths are never overwritten. After an ungraceful
exit, manually remove a stale socket only after confirming its agent has exited.
The runtime directory is left in place.

Run non-privileged validation and real C-to-Python socket tests:

```bash
make test
```

Run the privileged integration tests after building:

```bash
sudo make test-m2
sudo make test-m3
```

The test requires `ip`, `ping`, `unshare`, `nsenter`, and `timeout`. It creates a veth pair
between temporary network namespaces, confirms ping delivery and printed events,
checks attachment conflict handling and signal cleanup, then destroys the
namespace. It does not attach to the host's active interfaces.
The M3 test additionally starts the Python receiver, requires a validated event
with the receiving interface index and the expected ping packet length, and
checks clean receiver EOF and socket removal after agent shutdown. Both targets
share the isolated network fixture in `tests/m2_pipeline.sh`.
