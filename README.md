# KernelLens

KernelLens is a real-time eBPF-based telemetry framework for hybrid host and network threat detection.

## Current Milestone
M6 - Unified Event Pipeline

The C XDP program sends packet events through a BPF ring buffer to a C
libbpf agent. Every packet returns `XDP_PASS`, including when the ring buffer
is full (in that case the event is skipped). The program parses Ethernet, IPv4,
TCP, and UDP headers for telemetry. The agent serves a Python receiver over a Unix domain socket.
Python validates and normalizes all telemetry into `SecurityEvent` objects,
routes them to subscribers, and prints the unified model as JSON. No later
milestone functionality is included.

Host telemetry is opt-in. The network-only invocation below remains unchanged;
add `--host` to collect process, syscall, and privilege records alongside packets.
The C wire formats remain unchanged; normalization happens entirely in Python.

Prerequisites: Linux with BTF, BPF ring buffers and XDP BPF-link support,
Clang/LLVM with the BPF target, libbpf development headers, bpftool, pkg-config,
Make, a C compiler, and Python 3 (standard library only). The existing
`ebpf/include/vmlinux.h` supplies kernel
types for the CO-RE build; the target kernel must expose BTF.

## Build
```bash
make
```

This builds `build/xdp_test.bpf.o` and `build/host.bpf.o`, generates both libbpf
skeletons, and links
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

To enable host telemetry, start the agent with:

```bash
sudo ./build/kernellens-agent --host INTERFACE /run/kernellens/events.sock
```

The interface must still support XDP. The agent loads host tracepoints after
attaching XDP and reuses that program's ring-buffer map FD. If a required host
hook cannot load or attach, startup fails and releases all its resources,
including XDP; it does not silently run a partial host sensor. Host support
requires BTF/CO-RE, BPF task helpers, `CONFIG_FTRACE_SYSCALLS` and these hooks:

| Tracepoints | Collected activity |
| --- | --- |
| `sched:sched_process_exec` | Successful execution, command name and exec filename |
| `syscalls:sys_enter_setuid`, `syscalls:sys_exit_setuid` | Completed setuid attempts and return values |
| `syscalls:sys_enter_setgid`, `syscalls:sys_exit_setgid` | Completed setgid attempts and return values |
| `sched:sched_process_exit` | Remove pending per-thread syscall state; emits no exit event |

No kprobes are used. `setuid` and `setgid` are a deliberately small set of
security-relevant credential operations. Successful calls that change an
effective UID/GID produce an additional `privilege_change` event. Failed calls
and successful no-ops produce syscall telemetry only. This compares actual
credentials; it does not classify a change as an attack or take any response.
Other credential syscalls, saved/filesystem IDs, and supplementary groups are
not collected in M5.

Host records use the same JSON envelope and schema version as network events:

```json
{"message_type":"event","schema_version":1,"event":{"timestamp":123456789,"event_category":"process","event_type":"process_exec","pid":4217,"ppid":4100,"uid":1000,"gid":1000,"process_name":"bash","process_path":"/usr/bin/bash","syscall":null,"syscall_return":null,"previous_uid":null,"previous_gid":null}}
```

The category/type pairs are `process`/`process_exec`, `syscall`/`syscall_event`,
and `privilege`/`privilege_change`. PID is the process TGID, PPID is the immediate
parent TGID, and UID/GID are effective credentials as represented in the initial
user namespace. Host tracepoints observe system-wide activity, including when
the agent runs in a temporary network namespace; there is no ancestor-chain or
process-to-network tracking. Timestamp uses the same monotonic clock as packets.

`process_name` holds up to 15 bytes. `process_path` is the bounded exec filename
from the successful-exec tracepoint (up to 255 bytes), not a canonical resolved
path; it may be relative or name a script. A read failure or unavailable path
is `null`. Syscall and privilege records have a null path, `syscall` equal to
`setuid` or `setgid`, and a signed kernel `syscall_return` (negative errno on
failure). Only privilege records contain numeric `previous_uid`/`previous_gid`;
other records set them to null. Filenames and names are JSON escaped, with
non-ASCII bytes represented individually as `\u00XX` to handle arbitrary Linux
filename bytes safely.

The agent dispatches the two distinct binary record sizes and the host kind
discriminator. Network JSON is unchanged. The Python receiver validates each
category's fields before normalization. Host entry/exit matching uses
a bounded 4096-entry per-thread map, removed on completion/thread exit. A full
map or ring buffer may omit telemetry; there is no replay. This state only
pairs monitored syscall entries/exits and is not process lineage. Closing the
agent destroys its unpinned tracepoint links and maps on normal exit or failure.

The socket is accessible only to its owner (root in this example). The agent
continues printing M2 terminal events. The agent sends network event envelopes over the socket (shown below). The
Python receiver prints normalized SecurityEvent JSON to stdout and connection
status to stderr:

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

## Unified Python event pipeline (M6)

`backend/events.py` defines the shared standard-library dataclass `SecurityEvent`.
All fields from specification section 7 are serialized, including null fields.
Every normalization assigns a new UUID4 `event_id`, and preserves the original
uint64 monotonic nanosecond `timestamp` without converting it to wall time.
Container and cgroup identity are null because the current sensors do not supply them.

| Input | Category / type | Source | Metadata |
| --- | --- | --- | --- |
| M4 packet | network / network_packet | xdp | packet_length |
| M5 exec | process / process_exec | tracepoint | empty object |
| M5 syscall | syscall / syscall_event | tracepoint | syscall_return |
| M5 credential change | privilege / privilege_change | tracepoint | syscall_return, previous_uid, previous_gid |

Network `ifindex` becomes `interface`. Network events have null host fields;
host events have null network fields. Network zero ports/flags and `OTHER`
addresses retain the M4 parser defaults, including partially parsed packets.
Host names, paths, syscall names, IDs, and credentials retain M5 semantics.

`backend/validation.py` retains strict wire validation. The receiver re-exports
`validate_message` and `receive_messages` for existing wire consumers.
`normalize_message` accepts only validated event envelopes; status messages are
handled separately. `SecurityEvent.from_dict` validates the complete unified
schema, UUID, source/type/category, applicable fields, ranges, and metadata
semantics using the same sensor constraints. Unsupported or malformed input
raises `ValueError`; the CLI reports the error to stderr and exits nonzero.

`backend.pipeline.receive_events(connection, on_status=...)` yields only
`SecurityEvent` objects. `EventRouter.subscribe(consumer, category=None)` registers
synchronous subscribers for all events or a single category. `route(event)`
validates the model and delivers it to matching consumers without exposing the
wire format. Subscriber failures propagate to the caller; there is no queue,
retry, persistence, or replay. For example:

```python
from backend.pipeline import EventRouter, receive_events

router = EventRouter()
router.subscribe(lambda event: print(event.to_dict()))
for event in receive_events(connection):
    router.route(event)
```

The CLI's stdout changed from raw envelopes to one complete unified event per
line. Agent JSON and Unix socket framing remain at schema version 1. The
privileged regression checkers validate the new stdout schema before checking
packet endpoints and controlled host activity. No storage, API, detection,
alerting, correlation, response, or frontend is implemented in M6.

Run non-privileged parser, validation and real C-to-Python socket tests:

```bash
make test
```

Run the privileged integration tests after building:

```bash
sudo make test-m2
sudo make test-m3
sudo make test-m4
sudo make test-m5
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

The M5 target also enables host collection, runs `build/host-activity` as a
short-lived child, and verifies exec metadata, successful/denied/no-op syscall
records, and exactly two real effective UID/GID changes in Python's output.
Only the test child drops its own credentials to UID/GID 65534 (GID 65533 if
already 65534); the shell and agent retain theirs. The test snapshots only the
agent's BPF program IDs and verifies they are unloaded after exit, checks socket
cleanup, and repeats the M4 TCP/UDP traffic tests while host sensing is enabled.
