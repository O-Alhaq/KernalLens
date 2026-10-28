# KernelLens

KernelLens is a real-time eBPF-based telemetry framework for hybrid host and network threat detection.

## Current Milestone
M8 - Rule Engine

The C XDP program sends packet events through a BPF ring buffer to a C
libbpf agent. Every packet returns `XDP_PASS`, including when the ring buffer
is full (in that case the event is skipped). The program parses Ethernet, IPv4,
TCP, and UDP headers for telemetry. The agent serves a Python receiver over a Unix domain socket.
Python validates and normalizes all telemetry into `SecurityEvent` objects,
routes them to subscribers, and prints the unified model as JSON. Optional SQLite
persistence and a read-only FastAPI REST API provide the M7 foundation. M8 adds
an opt-in Python rule engine with YAML configuration and structured alerts.

Host telemetry is opt-in. The network-only invocation below remains unchanged;
add `--host` to collect process, syscall, and privilege records alongside packets.
The C wire formats remain unchanged; normalization happens entirely in Python.

Prerequisites: Linux with BTF, BPF ring buffers and XDP BPF-link support,
Clang/LLVM with the BPF target, libbpf development headers, bpftool, pkg-config,
Make, a C compiler, and Python 3. The collection/normalization/storage path uses
the standard library; detection requires PyYAML, and the API additionally
requires FastAPI and Uvicorn. The existing
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
retry, persistence, or replay in the router itself. The M8 rule subscriber
contains its own failures; existing storage subscribers retain fail-fast behavior.
For example:

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
packet endpoints and controlled host activity. M6 remains the normalization
boundary. M7 adds storage/API and M8 adds opt-in detection as described below.

## SQLite persistence and REST API (M7)

Install the runtime dependencies in a virtual environment (add HTTPX for tests):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
# For runtime only, use requirements.txt instead.
```

The original receiver command still prints normalized events without storage.
To also persist them, pass `--database` with a file path. Its parent directory
must already exist. Start the agent as described above, then run:

```bash
sudo .venv/bin/python backend/receiver.py /run/kernellens/events.sock --database /var/lib/kernellens/events.db
```

Create `/var/lib/kernellens` first when using that example. Run the API in a
separate process with filesystem access to the same database and its directory:

```bash
KERNELLENS_DATABASE=/var/lib/kernellens/events.db .venv/bin/uvicorn backend.api:app --host 127.0.0.1 --port 8000
```

`KERNELLENS_DATABASE` defaults to `kernellens.db` in the API working directory.
The receiver stores only when `--database` is explicitly supplied. Use matching
absolute paths so both processes share the same file. API startup initializes
its database; importing the app does not create a file. The API does not connect
to the agent or start a second collector. `/health` reports API/database access,
not sensor connectivity.

```bash
curl http://127.0.0.1:8000/health
curl 'http://127.0.0.1:8000/events?limit=20&offset=0&event_category=network'
curl 'http://127.0.0.1:8000/events?event_type=process_exec'
curl http://127.0.0.1:8000/events/EVENT_UUID
```

`GET /health` returns `{"status":"ok","database":"ok"}` after checking
schema/table access. `GET /events` returns a JSON array of complete M6 records,
including null fields and decoded metadata. It defaults to `limit=100` and
`offset=0`; limit is 1–1000, offset is non-negative. Results are in insertion
order, oldest first. Optional `event_category` and `event_type` filters are exact
matches combined with AND. Unknown filters yield an empty array. Pagination
operates on matching events; invalid parameters return 422. Missing event IDs
return 404. Database operation failures return 503 without database details.
There are no event-write API endpoints.

`backend/storage.py` implements file-backed `EventStore` using standard
`sqlite3`. `initialize()` creates schema version 1 transactionally using
`PRAGMA user_version`, preserves existing records on repeat startup, and rejects
unknown versions. Future migrations can extend this versioned initialization;
there is no schema reset. One `events` table contains every SecurityEvent field,
with indexes on category/type, a unique primary-key event ID, and JSON text
metadata. Timestamp uses decimal TEXT because SQLite INTEGER cannot represent
the full sensor uint64 range; reads restore the original integer. API responses
therefore retain the M6 JSON types and values. Container/cgroup fields retain
the current M6 null constraints.

Each store operation closes its own connection; writes commit before returning.
WAL mode and a five-second lock timeout allow the receiver and API to share a
local database. Persistence is synchronous: storage errors propagate, the receiver
reports them and exits nonzero, and there is no buffering/retry/replay. Duplicate
IDs fail without overwriting records. Store reads and writes validate against
the existing SecurityEvent model. Normalization has no database dependency.
Any future Python consumer can register persistence with
`router.subscribe(store.insert)` after initializing its store.

Tests use temporary SQLite files and include a real C IPC driver → receiver →
SQLite → REST round trip for network, process, syscall, and privilege telemetry.
No real project database is used by the tests.

## Configurable rule engine (M8)

Install the updated requirements, then opt into detection with `--rules`:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
sudo .venv/bin/python backend/receiver.py /run/kernellens/events.sock --rules config/rules.yaml --database /var/lib/kernellens/events.db
```

The `--database` flag remains optional. Normalized events still go to stdout.
Each alert is a single JSON object prefixed with `Alert: ` on stderr, alongside
agent status/error messages. Without `--rules`, M2–M7 behavior is unchanged and
the receiver does not import PyYAML. The engine runs in Python, with no C/eBPF,
SQLite schema, or API changes.

`backend/alerts.py` defines `Alert` with a UUID4 `alert_id`, sensor-time
`timestamp`, `rule_id`, `rule_name`, `alert_type`, configured `severity`,
`description`, `source_event_ids`, `event_category`, and JSON-compatible
`metadata`. Alerts are returned by `RuleEngine.evaluate(event)`. Register
callbacks with `engine.subscribe(consumer)`, then register the engine itself as
an event subscriber to evaluate and publish alerts:

```python
from backend.pipeline import EventRouter
from backend.rule_config import load_rules
from backend.rules import RuleEngine

engine = RuleEngine(load_rules("config/rules.yaml"))
engine.subscribe(lambda alert: print(alert.to_dict()))
router = EventRouter()
router.subscribe(engine)
# Independently, after EventStore initialization: router.subscribe(store.insert)
# Feed normalized SecurityEvent objects using router.route(event).
```

The serial engine validates and copies each SecurityEvent, and gives each rule
an independent snapshot. Per-rule errors are logged and other rules continue.
Engine boundary and alert callback errors are also contained by the subscriber,
so detection failures do not stop event storage or stdout. Invalid configuration
fails receiver startup before connecting; it never silently loads a partial
policy. Alerts/state are not stored in SQLite or exposed through new API routes.
No alert history is retained internally; callers can consume returned alerts.

Rules use `schema_version: 1` and a `rules` list in YAML. Every entry requires
`id`, `name`, `enabled` (boolean), `category`, `type`, `severity`, and `description`.
IDs must be unique, including disabled entries. Static severity is one of
`info`, `low`, `medium`, `high`, or `critical`; there is no risk score.
`backend/rule_config.py` uses a restricted [PyYAML SafeLoader](https://pyyaml.org/wiki/PyYAMLDocumentation)
with duplicate-key rejection. Unknown fields, malformed selectors, unsupported
category/type pairs, duplicate IDs, and invalid numeric values are errors.
The file limit is 256 KiB and the rule limit is 128. Even disabled entries must
be valid. An empty rule list is allowed. Configuration is loaded once at startup.

| Category / type | Condition |
| --- | --- |
| network / port_scan | Distinct destination ports among TCP SYN attempts, grouped by source and destination IP |
| network / syn_flood | Count of TCP SYN attempts per source/destination IP pair |
| network / traffic_flood | Count of IPv4 packets per source/destination IP pair, across ports/protocols |
| process / process_match | Exact process name and/or path selectors |
| syscall / syscall_match | Configured setuid/setgid and optional return value, process name, UID/GID selectors |
| privilege / privilege_change | Configured current/previous UID/GID or credential-change conditions |

A TCP attempt requires SYN set and ACK clear, with a nonzero destination port.
SYN/ACKs and unavailable port defaults do not count as connection attempts.
`OTHER` Ethernet events and zero source/destination IPs are excluded from network
rules. Traffic flood includes TCP, UDP, ICMP, and other reported IPv4 protocols.

Network rules require `threshold` (integer 1–4096) and `window_seconds` (a finite
positive number representing 1 ns through 86400 seconds). They also accept:

```yaml
threshold: 10
window_seconds: 5
quiet_seconds: 3
max_detection_seconds: 60
max_event_ids: 64
max_groups: 128
```

`quiet_seconds` defaults to 3 and `max_detection_seconds` to 60; both have the
same positive finite duration bounds as `window_seconds`. Older configurations
receive these defaults. As a configuration consistency requirement, the maximum
duration must be at least both `window_seconds` and `quiet_seconds`; shorter
values raise `RuleConfigError`. The active lifetime still starts at confirmation,
not at the first candidate packet. `max_event_ids` is 2–256 (default 64), and `max_groups`
is 1–4096 (default 128). No host `match` selectors apply to network rules.

Each rule maintains independent sessions keyed by `(src_ip, dst_ip)`. Before
confirmation, a sliding window retains the most recent timestamp per distinct
port for scans, or one timestamp per packet ID for floods. Samples at or before
`watermark - window` expire. Confirmation requires `threshold` distinct scan
ports or matching flood packets inside that window. Repeated attempts to one
port do not confirm a scan. Candidates disappear without alerting when their
entire window expires. For a continuously observed candidate, aggregate totals
and first/last timestamps include activity from its beginning, even if older
confirmation samples have expired.

At threshold the session becomes active **without emitting an alert**. It keeps
accumulating complete activity totals and distinct ports, independently of the
confirmation window. Every matching packet, including a repeated scan port,
updates its last-activity timestamp; unrelated packets and SYN/ACKs do not.
Exactly one final alert is emitted when either the quiet deadline or maximum
active duration is reached. The maximum duration starts at `threshold_timestamp`.
A packet at a deadline closes the old session before starting a new candidate.
Continued traffic can therefore start a new session after a maximum-duration
boundary, rather than after every threshold-sized batch.

Network alert metadata contains `matching_event_count` for total observed matching
packets, `first_timestamp`, `threshold_timestamp`, `last_timestamp`, `duration_ns`
(last minus first, excluding the quiet wait), thresholds/durations, IPs, endpoint
UUIDs, and `finalization_reason` (`quiet` or `max_duration`). Scan alerts additionally
contain the exact `unique_port_count` and complete sorted `destination_ports`.
There is no ambiguous `count` field. Alert `timestamp` is the finalization deadline;
it never predates confirmation, including when a late event confirms old activity.

Memory remains bounded. Pending confirmation retains fewer than `threshold`
samples between evaluations; active sessions retain no per-packet window history.
Scans use a fixed 8192-byte bitmap covering every possible destination port, so
neither the final unique count nor port list is truncated. Each session keeps at
most `max_event_ids` sampled source UUIDs (including the first/last observed event)
and a recent-UUID cache of the same bound. `source_event_ids_truncated` explicitly
indicates sampled evidence. Counts continue growing after the UUID cap is reached;
there is no unbounded UUID/history collection. Recent replayed IDs are ignored,
but arbitrary old replays outside the bounded cache cannot be fully deduplicated.
M6 supplies a fresh UUID for each actual collected event.

The group limit applies across pending and active sessions. At capacity the oldest
pending candidate is evicted first. If all groups are active, new IP pairs are
ignored until space becomes available; active evidence is never silently discarded
or finalized early to make room. This can miss new sources at capacity. A separate
closed-session boundary cache is capped at `max_groups` and expires with the
confirmation window, preventing recent delayed packets from reopening old sessions
while their boundary remains retained.

The engine uses original monotonic nanosecond timestamps and a nondecreasing high
watermark. Every event can advance finalization, even an unrelated host event.
For deterministic offline consumers, `engine.advance_time(timestamp)` returns
finalized alerts without publishing; `engine.tick(timestamp)` also publishes them
and contains timer/sink failures. Pass time in the same monotonic clock domain as
the events. With only `evaluate()` and no later input/tick, event time does not
advance and quiet sessions remain pending; the next watermark advance finalizes
them. The rule engine never sleeps or reads a system clock itself.
Backward time cannot reopen or extend a session. Late matching input
inside a retained session can contribute without regressing its last timestamp.

The live receiver polls idle sockets (at most 250 ms between polls, with a 1 ms
minimum for very small configured durations) and calls `tick(time.monotonic_ns())`.
On Linux this clock matches the sensors' `bpf_ktime_get_ns()`. A quiet stream
therefore finalizes alerts while the agent remains connected, without waiting for
another packet. Polling preserves partial newline-delimited JSON records and does
not change the receiver's default blocking behavior when rules are disabled.
`engine.flush()` publishes remaining confirmed sessions at end-of-stream and
clears candidates; repeated flushes do not duplicate alerts. The receiver flushes
on EOF (`finalization_reason: stream_end`) or Ctrl-C/error cleanup (`shutdown`),
explicitly marking these early finalizations rather than claiming a quiet timeout.
Host matching/alert timing, SQLite, and API behavior are unchanged.

Host rules require nonempty `match` conditions. Each field is a nonempty list
of exact accepted values; values within a list use OR, different fields use AND.
To match a name OR a path independently, configure separate rules. There are no
regexes, globs, or expression evaluation. Available fields are:

- `process_match`: `process_name`, `process_path`.
- `syscall_match`: required `syscall` (`setuid`/`setgid`), optional
  `syscall_return`, `process_name`, `uid`, `gid`.
- `privilege_change`: `syscall`, `process_name`, `uid`, `gid`, `previous_uid`,
  `previous_gid`, plus boolean `uid_changed` and `gid_changed`. At least one
  credential selector/change condition is required. Change booleans compare
  current credentials with M5 metadata.

Host alerts use the matching event timestamp and preserve the original event ID
and credential/syscall evidence. The shipped policy enables a basic scan rule,
a SYN flood rule, EPERM (`syscall_return: [-1]`) credential-syscall monitoring,
and a real UID transition to root. It does not flag every syscall or credential
change. Process and traffic-flood examples are disabled for local configuration;
thresholds and policy choices should be tuned to the intended environment.
There is no dynamic severity/scoring, correlation, incident handling, WebSocket,
frontend, enrichment, or response action in M8.

Run all non-privileged parser, validation, storage/API, rule, and C IPC tests:

```bash
make test PYTHON=.venv/bin/python
# Rule-engine tests only (after building the C IPC fixture):
.venv/bin/python -m unittest discover -s tests -p test_rules.py -v
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
