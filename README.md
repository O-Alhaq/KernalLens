# KernelLens

KernelLens is a real-time eBPF-based telemetry framework for hybrid host and network threat detection.

## Current Milestone
M4 - Network Telemetry

The C XDP program sends packet events through a BPF ring buffer to a C
libbpf agent. Every packet returns `XDP_PASS`, including when the ring buffer
is full (in that case the event is skipped). The program parses Ethernet, IPv4,
TCP, and UDP headers for telemetry. The agent serves a Python receiver over a Unix domain socket.
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

For network events in Python, create a private runtime directory and pass an absolute socket path.
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
{"message_type":"event","schema_version":1,"event":{"timestamp":123456789,"ifindex":2,"packet_length":74,"src_ip":"192.0.2.1","dst_ip":"192.0.2.2","src_port":45678,"dst_port":80,"protocol":"TCP","tcp_flags":2}}
```

Each UTF-8 JSON object ends with a newline. The envelope retains `message_type`
and `schema_version: 1`. M4 expands the three M3 fields to the nine fields above;
rebuild the agent and use the matching receiver together. Timestamp is uint64,
interface index is positive uint32, packet length is uint32, ports are uint16,
and TCP flags are uint8 (SYN=2, ACK=16, PSH=8; flags may be combined).
IPv4 addresses are dotted strings and ports are printed in host byte order.
Protocol is `TCP`, `UDP`, `ICMP`, or `IPPROTO_N` for another IPv4 protocol number.
A new connection first receives
`{"message_type":"status","schema_version":1,"status":"ready"}`. There are
no client commands or request/response operations in this milestone.

The parser checks both packet boundaries and declared IPv4/transport lengths,
including variable IPv4/TCP header sizes. For IPv4 fragments it reports IPs and
protocol with zero ports/flags (no reassembly). ICMP and other IPv4 protocols
also have zero ports/flags. For truncated or malformed headers it reports only
fields validated before the error, leaving remaining fields zero. Unsupported
Ethernet types, including ARP, IPv6 and VLAN, use `0.0.0.0` IPs, zero ports/flags,
and protocol `OTHER`. Packet checksums are left to the normal network stack.
No packet contents are modified and every program path returns `XDP_PASS`.

A per-CPU array map named `counters` tracks observed packets/bytes, IPv4, TCP,
UDP, malformed headers, and dropped ring-buffer events. TCP/UDP counters count
IPv4 protocol identifiers, including fragments and malformed transport headers.
Counters never influence packet actions. The agent sums them and prints a
`Telemetry:` summary to stderr after detach; counters reset when the agent exits.

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

Run non-privileged parser, validation and real C-to-Python socket tests:

```bash
make test
```

Run the privileged integration tests after building:

```bash
sudo make test-m2
sudo make test-m3
sudo make test-m4
```

The test requires `ip`, `ping`, `unshare`, `nsenter`, and `timeout`. It creates a veth pair
between temporary network namespaces, confirms ping delivery and printed events,
checks attachment conflict handling and signal cleanup, then destroys the
namespace. It does not attach to the host's active interfaces.
The M3 test additionally starts the Python receiver, requires a validated event
with the receiving interface index and the expected ping packet length, and
checks clean receiver EOF and socket removal after agent shutdown. All targets
share the isolated network fixture in `tests/m2_pipeline.sh`.
The M4 test additionally sends TCP echo traffic from `192.0.2.1:45000` to
`192.0.2.2:32080` and UDP echo traffic from `192.0.2.1:45001` to
`192.0.2.2:32081`. It checks Python's captured JSON for exact addresses/ports,
TCP SYN and PSH/ACK flags, UDP's zero TCP flags and packet length, and positive
protocol counters. Both echoes must succeed, demonstrating ordinary traffic
passes while XDP is attached. The fixture verifies detach and reattachment,
deletes the veth pair, and releases its temporary namespaces on exit.
