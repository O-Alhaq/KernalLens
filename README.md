# KernelLens

KernelLens is a Linux security observatory for a single monitored machine. It
collects network and selected host activity, detects configured patterns, assigns
risk scores, and groups related detections into explainable Incidents. A local,
read-only dashboard lets you inspect the evidence. It does not currently block
traffic or perform response actions.

## Architecture

```text
Network / Host
      ↓
eBPF
      ↓
C libbpf Agent
      ↓
Unix Socket
      ↓
Python Security Core
      ↓
SQLite
      ↓
FastAPI + WebSocket
      ↓
React Dashboard
```

- **Network/host sensors:** eBPF (extended Berkeley Packet Filter) runs verified
  observation programs in the Linux kernel. Network capture uses XDP (eXpress
  Data Path), an early incoming-packet hook; host tracepoints observe execution
  and selected credential syscalls. Network packets continue with `XDP_PASS`.
- **C libbpf agent:** loads/attaches the sensors and reads their bounded event
  buffer. This is the privileged part of the stack.
- **Unix socket:** a local filesystem-addressed connection carries telemetry
  from the agent to the normal-user Python receiver.
- **Python security core:** validates Events, evaluates detection rules, scores
  Alerts and correlates Incidents. Configuration is explicit YAML, not dashboard
  logic; no browser is required for detection to continue.
- **SQLite:** persists Events, Alerts and Incidents, plus bounded live-change
  references. Receiver and API share one user-owned database file.
- **FastAPI/WebSocket:** ordinary HTTP endpoints provide history; a WebSocket is
  a persistent browser/server connection carrying live database changes.
- **React dashboard:** displays evidence and reconnects/reloads history when
  needed. Security windows use monotonic timestamps (nanoseconds since boot),
  while independent persisted UTC times are displayed in `Asia/Amman`.

## Requirements

The automatic development setup targets **Ubuntu 26.04 LTS** on Linux, matching
the current Ubuntu 26.04.1/generic-kernel lab. You need sudo access, internet access
for dependency downloads, and an interface/driver supporting native XDP BPF links.
The kernel needs BTF type information, BPF ring buffers/task helpers and the
required host syscall tracepoints. A successful build does not prove a restricted
VM/container or interface supports attachment.

Setup checks/prepares clang/LLVM, bpftool, libbpf/libelf, build tooling, Python and
venv support, Node **22.12+**, npm **10+**, and project dependencies. If packaged
npm is older, setup uses a project-local npm 11 without changing global npm.
A desktop/browser is optional. See [SETUP.md](docs/SETUP.md) for details.

## Quick start

```bash
git clone https://github.com/O-Alhaq/KernalLens.git
cd KernalLens
./scripts/setup.sh
make dashboard
```

Run these as your **normal user**. Setup previews and asks before missing Ubuntu
packages are installed with sudo; Python/npm installs and project builds remain
unprivileged. Dashboard startup authenticates sudo for only the agent and required
socket setup. Setup does not start capture automatically.

Useful overrides:

```bash
make dashboard INTERFACE=ens33          # your actual monitored interface
make dashboard DATABASE=/tmp/test.db
make dashboard OPEN_BROWSER=0
```

Without `INTERFACE`, the launcher detects the unique lowest-metric default-route
interface. It waits for receiver/API/frontend readiness, then opens
**http://127.0.0.1:5173/**. Do not expose this unauthenticated development dashboard
publicly. Run `make help` for supported commands.

## Stop and runtime files

**Press Ctrl+C in the launcher terminal.** Successful intentional shutdown stops
launcher-owned components, detaches the agent and removes its socket, then returns
cleanly. Genuine startup/runtime/cleanup failures remain non-zero.

- Database: `/tmp/kernellens.db`, or the exact `DATABASE` override shared by receiver/API.
  `/tmp` is disposable; use a persistent user-writable location for important history.
- Logs: `/tmp/kernellens-runtime-<uid>/run-<unique>/`, printed at startup. Separate
  agent/receiver/API/frontend logs keep high-volume telemetry out of the terminal.
- Runtime socket: `/run/kernellens/events.sock`; its development permissions are
  prepared automatically. Do not manually remove an active socket.

## Dashboard

Overview shows persisted totals, severity distribution and connection status.
Alerts show individual detections and their scores; Incidents show related Alerts
and correlation evidence; Telemetry shows normalized Events. Select a row/card for
metadata and technical details. Light/Dark preference is saved locally. API Online
and Live Connected describe API/database/browser-stream availability, not complete
sensor or packet-capture health.

## Configuration

Read [RULES.md](docs/RULES.md) before editing:

- `config/rules.yaml`: matching, enabled flags, thresholds and session timing.
- `config/scoring.yaml`: risk after detection; severity remains score-derived.
- `config/correlation.yaml`: Alert grouping into Incidents and correlation windows.

Always validate before restarting:

```bash
make validate-config
make dashboard
```

There is no hot reload: stop the current session, validate edits, then restart.
Existing persisted evidence is not rewritten by policy edits.

## Troubleshooting

Start with [SETUP.md](docs/SETUP.md), which covers missing venv/modules, interface
selection, occupied ports, sudo/kernel/XDP failures, logs, runtime sockets and
SQLite ownership. Do not work around permissions by running the whole stack as
root or by deleting/chowning arbitrary databases. Setup can be rerun safely.

## Technical reference and milestone history

The detailed implementation material below is preserved for deeper study.
For everyday setup/runtime operations, use the workflow above and SETUP.md.
Manual component examples require the same normal-user database ownership and
operator socket access as the launcher; use the launcher's automatic permissions
rather than running Python under sudo. Historical design/specification documents
may also describe future scope, not currently implemented response features.

## Current Milestone
M11 - Real-Time Dashboard

The C XDP program sends packet events through a BPF ring buffer to a C
libbpf agent. Every packet returns `XDP_PASS`, including when the ring buffer
is full (in that case the event is skipped). The program parses Ethernet, IPv4,
TCP, and UDP headers for telemetry. The agent serves a Python receiver over a Unix domain socket.
Python validates and normalizes all telemetry into `SecurityEvent` objects,
routes them to subscribers, and prints the unified model as JSON. Optional SQLite
persistence and a read-only FastAPI REST API provide the M7 foundation. M8 adds
an opt-in Python rule engine with YAML configuration and structured alerts.
M9 scores finalized alerts; M10 correlates related alerts into explainable incidents,
with optional SQLite persistence and read-only incident retrieval. M11 adds a
React dashboard with bounded WebSocket delivery of committed data.

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
.venv/bin/python backend/receiver.py /run/kernellens/events.sock
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
receiver remains connected while the agent retains up to 65536 unsent bytes.
Nonblocking sends retry from the existing agent loop, including idle iterations;
each flush attempts at most 16 sends. EAGAIN/EWOULDBLOCK retain the queued bytes,
and partial sends retain their exact suffix before any subsequent record.
At capacity, only whole new records are dropped; queued bytes are never discarded
to make room. The first overflow and total dropped-record count at shutdown are
logged. Sustained overload can therefore lose telemetry and affect detection
counts, but does not force a reconnect. EPIPE/ECONNRESET and other fatal send
errors close the client with the syscall return and errno logged; ETIMEDOUT is
fatal, not treated as ordinary nonblocking backpressure. No send timeout is set.
Real disconnect/shutdown clears the queue rather than replaying it to another
receiver. A partial record at actual disconnect is rejected by Python. Invalid, oversized (over 4096 bytes),
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
.venv/bin/python backend/receiver.py /run/kernellens/events.sock --database /var/lib/kernellens/events.db
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
`sqlite3`. `initialize()` creates the M7 event schema and applies the M10 version-2 and M11 version-3/version-4
migrations transactionally using `PRAGMA user_version`. It preserves existing
records on repeat startup and rejects unknown versions; there is no schema reset.
The `events` table contains every SecurityEvent field,
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
.venv/bin/python backend/receiver.py /run/kernellens/events.sock --rules config/rules.yaml --database /var/lib/kernellens/events.db
```

The `--database` flag remains optional. Normalized events still go to stdout.
Each alert is a single JSON object prefixed with `Alert: ` on stderr, alongside
agent status/error messages. Without `--rules`, M2–M7 behavior is unchanged and
the receiver does not import PyYAML. The engine runs in Python, with no C/eBPF,
SQLite schema, or API changes.

`backend/alerts.py` defines `Alert` with a UUID4 `alert_id`, sensor-time
`timestamp`, `rule_id`, `rule_name`, `alert_type`, score-derived `severity`,
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
policy. M8 alone does not store Alerts/state or add API routes; the optional
M10 subscriber adds detection persistence and incident retrieval below.
No alert history is retained internally; callers can consume returned alerts.

Rules use `schema_version: 1` and a `rules` list in YAML. Every entry requires
`id`, `name`, `enabled` (boolean), `category`, `type`, and `description`.
IDs must be unique, including disabled entries. Optional `base_score` overrides
the family base in M9; old `severity` keys are rejected.
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
M9 adds deterministic scoring below. There is no correlation, incident handling, WebSocket,
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

## Scoring and severity (M9)

Scoring happens in `backend/scoring.py` when each rule constructs its final Alert.
Network evidence is scored only after session finalization, including quiet,
maximum-duration, and stream termination paths. Host matches score immediately.
No transport, SQLite, API, eBPF, or C-agent scoring logic is added in M9.
M10 optionally consumes these finalized Alerts for persistence and correlation, as
described below; scoring itself remains independent.

`config/scoring.yaml` is the default versioned scoring policy, resolved relative
to the repository package rather than the working directory. To select another:

```bash
.venv/bin/python backend/receiver.py SOCKET --rules config/rules.yaml --scoring config/scoring.yaml
```

| Family | Base | Rationale |
| --- | --- | --- |
| port_scan | 30 | Reconnaissance is suspicious, but does not establish compromise |
| syn_flood | 60 | Connection-attempt volume can disrupt availability |
| traffic_flood | 50 | High traffic merits investigation but can be legitimate |
| process_match | 30 | A configured name/path match alone is limited evidence |
| syscall_match | 20 | The default policy detects denied credential calls, not successful escalation |
| privilege_change | 50 | An actual credential change warrants greater attention |

Each rule can optionally set an integer `base_score` from 0–100 for its specific
context. For port scans, the scoring policy is authoritative: a per-rule base
override must equal its configured base score or scoring rejects it. Policy base
scores remain in 20–49, and selected tiers are absolute scores.
M8 `severity` fields have been removed and are rejected, not silently
interpreted as final severity. Customize policy/overrides for local host rules.

Port scans have a separate absolute scale based only on `unique_port_count`:

| Unique ports | Risk score | Severity |
| --- | --- | --- |
| 1–19 (including the default detection threshold of 10) | 30 | medium |
| 20–49 | 35 | medium |
| 50–99 | 40 | medium |
| 100–199 | 45 | medium |
| 200–65535 | 49 | medium |

Reconnaissance volume alone does not establish compromise or availability impact,
so it cannot produce high/critical scan severity. Detection thresholds still
control whether a session is confirmed, but do not scale its risk score. The YAML
entry under `scoring` is:

```yaml
port_scan:
  base_score: 30
  tiers:
    - {min_unique_ports: 20, score: 35}
    - {min_unique_ports: 50, score: 40}
    - {min_unique_ports: 100, score: 45}
    - {min_unique_ports: 200, score: 49}
```

The highest matching tier supplies the absolute score. An explanatory
`port_scan_scope` modifier records the difference from the base score; tiers do
not stack. Port-scan policies require 1–8 tiers, strictly increasing integer
port thresholds (2–65535), and nondecreasing integer scores from the base upward.
Base and tier scores are restricted to 20–49. Unknown/duplicate fields, booleans,
malformed tiers, decreasing thresholds/scores, and scores above 49 are rejected.

SYN and traffic floods retain their original highest-matching volume tier: +10
at 2 times threshold or +20 at 5 times threshold, using `matching_event_count`.
Comparisons use integer multiplication and exclusive tiers prevent stacking.
Privilege changes add +25 only when evidence shows an effective UID transition
from nonzero to zero; root remaining root while GID changes gets no root bonus.
There are no process/syscall bonuses, duration bonuses, or cross-alert modifiers.

The final score is `max(0, min(100, base_score + sum(modifier points)))`.
Severity is derived exclusively from the final integer score:

| Score | Severity |
| --- | --- |
| 0–19 | low |
| 20–49 | medium |
| 50–79 | high |
| 80–100 | critical |

Alerts expose `risk_score`, `base_score`, `score_modifiers` (name, signed points,
and evidence-based reason), and `severity`. Validation rejects booleans/floats
as scores, out-of-range scores, inconsistent arithmetic, and mismatched severity.
UUID generation does not influence scoring; identical evidence and policy always
produce the same score/explanation. Scoring copies metadata and snapshots policy.

Example projection of a final 50-port scan alert with threshold 10:

```json
{
  "alert_type": "port_scan",
  "risk_score": 40,
  "base_score": 30,
  "severity": "medium",
  "score_modifiers": [
    {"name": "port_scan_scope", "points": 10, "reason": "unique_port_count=50 falls in the 50-99 port tier"}
  ],
  "metadata": {"unique_port_count": 50, "threshold": 10}
}
```

The actual alert retains the complete M8 metadata and sampled source IDs.
Calculation: 50 ports selects the 50–99 tier with score 40. The explanation
records base 30 plus scope adjustment 10 = 40/medium. A 1000-port scan remains
49/medium. A threshold-level
SYN flood is 60/high; a 5x SYN flood is 80/critical. A UID change to root is
50 + 25 = 75/high, compared with a generic credential change at 50/high.

Scoring YAML requires exactly all six families, their base scores, port-scan `tiers`, flood
`volume_tiers`, and privilege `root_uid_points`. Unknown/missing fields and
duplicate YAML keys fail startup with `RuleConfigError`. Base scores are 0–100;
modifier points are signed integers in −100–100. Negative adjustments are allowed
for explicit local policy discounts, although defaults only increase risk.
Flood tiers are limited to eight, with strictly increasing integer multiples
from 2–1000. The file has the same 256 KiB limit and restricted SafeLoader as
rules. New policy instances are required to apply changes; there is no hot reload.

Run M9 tests with:

```bash
.venv/bin/python -m unittest discover -s tests -p test_scoring.py -v
```

## Hybrid correlation and incidents (M10)

`SecurityEvent` is normalized telemetry. An `Alert` is one finalized, scored rule
detection. An `Incident` groups at least two related detections. A single scan or
repeated detections of only one type do not automatically become incidents.

```text
SecurityEvent → RuleEngine → finalized evidence → M9 Scorer → Alert
                                                              ↓
                                                     CorrelationEngine
                                                              ↓
                                                           Incident
```

`backend/correlation.py` is a synchronous, independently testable Alert consumer.
It uses no transport, database, clock reads, timers, or threads. It snapshots and
revalidates incoming Alerts, retaining only small correlation summaries, not
packet lists or source-event UUIDs. It never changes M8 sessions or M9 scores.
`evaluate(alert)` returns newly created/updated Incident snapshots;
`correlation(alert)` also publishes to `subscribe(consumer)` callbacks. Rule and
subscriber exceptions are logged and contained. Each incident subscriber receives
its own copy. Incidents are created immediately when the second qualifying type
arrives; later related alerts update that same incident ID.

| Correlation type | Required evidence | Group key | Default window |
| --- | --- | --- | --- |
| `network_sequence` | At least two different types among port scan, SYN flood, traffic flood | `(src_ip, dst_ip)` | 60 seconds |
| `host_sequence` | At least two different types among process match, credential-syscall match, privilege change | positive `pid` | 30 seconds |
| `hybrid_activity` | SYN/traffic flood with score ≥50 against a configured local IP, plus a successful non-root→root privilege change with score ≥50 | `(src_ip, dst_ip, pid)` | 60 seconds |

Host pairing means configured suspicious detections, not arbitrary telemetry.
All three host types are useful but not required. PID identity is contextual:
short windows reduce PID-reuse ambiguity but cannot prove process lifetime;
process lineage and exact process identity across reuse are outside M10.
Network and host groups never merge different IP pairs or PIDs respectively.
An Alert can participate in different correlation families, so a network incident
and a hybrid incident can share evidence while expressing different relationships.
Within each family it is assigned only once. If a hybrid alert has several
eligible contexts, it joins the lexicographically first qualifying IP-pair/PID
context; it is not broadcast into many new incidents.

**M10 hybrid correlation is temporal/contextual.
It does not claim exact process-to-network attribution.**

Hybrid evidence requires a network destination explicitly listed in
`monitored_ips`, plus a privilege Alert whose `uid` is 0, `previous_uid` is a
positive uint32, and `syscall_return` is 0. Mere process matches, denied syscalls,
generic credential changes, scans alone, and traffic to unconfigured destinations
do not qualify. The receiver must be collecting from the single host owning those
configured addresses. KernelLens does not infer address ownership from traffic.
The shipped list is empty: configure real local addresses to enable hybrid matches.
There is no distributed/multi-host correlation, process→connection mapping,
external enrichment, response action, or dashboard in M10.

Enable correlation explicitly:

```bash
.venv/bin/python backend/receiver.py SOCKET --rules config/rules.yaml \
  --scoring config/scoring.yaml --correlation config/correlation.yaml \
  --database kernellens.db
```

`--correlation` requires `--rules`. Without it, rule output remains unchanged.
Without `--database`, Incident snapshots still appear as `Incident: {JSON}` on
stderr alongside `Alert: {JSON}`; normalized events remain on stdout. With both
flags, Alerts are persisted before they are passed to correlation, and Incident
creation/updates are persisted by a separate subscriber. Scoring policy and
correlation policy remain separate.

The complete configuration format is:

```yaml
schema_version: 1
monitored_ips: []  # e.g. [192.0.2.2], only if this address belongs to this host
limits:
  max_pending_alerts: 1024
  max_open_incidents: 256
  max_alerts_per_incident: 128
  max_seen_alerts: 4096
correlation:
  network_sequence:
    enabled: true
    window_seconds: 60
  host_sequence:
    enabled: true
    window_seconds: 30
  hybrid_activity:
    enabled: true
    window_seconds: 60
```

All fields and all three families are required, including disabled families.
Unknown/duplicate keys, unsupported versions, executable tags, malformed YAML,
wrong types (including booleans as numbers), and missing fields are rejected.
Configuration is limited to 256 KiB, uses the existing restricted SafeLoader, and
is loaded once. Windows must convert exactly to integer nanoseconds between 1 ns
and 86400 seconds. Up to 32 unique, canonical local unicast IPv4 addresses are
accepted. Limits are bounded integers: pending summaries 2–16384, open incidents
1–4096, references per incident 2–1024, and replay IDs 2–65536.

Correlation time uses **finalized Alert timestamps**, in the sensors' monotonic
nanoseconds, not packet first/last timestamps or wall time. For network sessions
this includes their finalization delay. A group qualifies when
`max(member timestamps) - min(member timestamps) <= window_ns`; the exact boundary
is included. Windows never slide beyond this full-span limit. An incident starts
at its earliest member timestamp and updates to its latest. Late accepted evidence
can move the beginning earlier; it cannot move the updated timestamp backward.

Every valid Alert advances a nondecreasing watermark. A rule ignores input older
than `watermark - its_window`; incidents expire from active memory once
`earliest_timestamp + window < watermark`. Pending summaries and replay IDs expire
after the largest enabled window. `advance_time(timestamp)` explicitly expires
state without producing incidents. The receiver does not feed idle wall time into
correlation: with no later Alerts or explicit advance, bounded state remains in
memory. No incident needs a quiet-time flush; it was already emitted when its
qualifying evidence arrived. Historical late Alerts cannot reopen expired windows.
Results are deterministic for the same ordered Alert stream and policy, apart
from UUID4 identities. Arbitrarily reordered input can change admission once a
watermark or capacity bound has been crossed. Use one engine per host/boot stream.

Memory caps apply to all families together. Pending summaries are bounded by
`max_pending_alerts`; capacity removes the oldest timestamp (UUID breaks ties).
There are at most `max_open_incidents` groups, each retaining at most
`max_alerts_per_incident` summaries/references. At incident capacity, new groups
are deferred; existing ones can still update. A full incident advertises
`alert_limit_reached: true` and ignores further members until its window expires;
it does not create overflow incidents. This deliberately sacrifices evidence at
capacity, rather than claiming complete coverage. Scoring reflects retained members.
Recently seen UUIDs are capped separately; retained pending/incident members also
suppress duplicates. Old replay protection is bounded, not a persistent lifetime
UUID index. These limits can miss correlations under overload and after restart.

Incident risk is deliberately simple:

```text
risk_score = min(100, highest_member_alert_score + 5)
```

The single +5 represents corroboration from distinct supported detections. It is
not added per alert/type, and hybrid incidents get no extra bonus. Stronger member
evidence can increase risk; repetition alone cannot inflate it. Metadata exposes
`highest_alert_score`, `correlation_points`, and `score_reason`. Individual Alert
scores remain unchanged. Severity reuses M9 exactly: 0–19 low, 20–49 medium,
50–79 high, 80–100 critical. The Incident model validates score arithmetic, severity,
UUID4 identity, distinct member IDs, timestamp ordering/window, status, and JSON
evidence. Status is always `open`; expiring runtime context does not close the
persisted incident or implement an incident-management workflow.

Examples with the default M9 policy:

- A 50-port scan (40) and threshold-level SYN flood (60), same pair within 60 s:
  `max(40, 60) + 5 = 65 / high`.
- Process match (30) and denied credential syscall (20), same PID within 30 s:
  `max(30, 20) + 5 = 35 / medium`. Adding a successful root transition (75)
  within that original window updates the same incident to `80 / critical`.
- Threshold-level SYN flood (60) to a configured local IP and successful root
  transition (75), within 60 s: `80 / critical`, with explicit contextual language.
  The high score reflects the root transition plus corroboration, not proven causality.

Example network Incident JSON (IDs are illustrative UUID4s):

```json
{
  "incident_id": "c722cc1b-8814-412d-9cc5-79ac0d352413",
  "created_timestamp": 1000000000,
  "updated_timestamp": 10000000000,
  "incident_type": "network_sequence",
  "title": "Network Sequence",
  "description": "Different detection types share the same source/destination IP pair within the configured correlation window.",
  "severity": "high",
  "risk_score": 65,
  "status": "open",
  "alert_ids": ["4d445df2-38f3-4a94-aedd-d2a7b795b2cf", "ec27040f-ae0e-4c2f-a23b-57597920b0c2"],
  "primary_entities": {"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2"},
  "metadata": {
    "correlation_rule": "network_sequence",
    "correlation_window_ns": 60000000000,
    "relationship": "shared_entities",
    "exact_process_network_attribution": false,
    "shared_entities": {"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2"},
    "alert_types": ["port_scan", "syn_flood"],
    "highest_alert_score": 60,
    "correlation_points": 5,
    "score_reason": "Highest member alert score plus 5 for corroborating detections",
    "alert_limit_reached": false
  }
}
```

SQLite initialization now migrates v1→v2 atomically. The existing `events` table
and data are unchanged. `alerts` stores immutable full M9 JSON snapshots by UUID;
`incidents` stores the latest validated snapshot plus indexed type/severity;
`incident_alerts` has a composite primary key and foreign keys to both tables.
Full Alert snapshots are the minimum addition needed to make incident references
inspectable and durable. JSON retains uint64 timestamps without signed SQLite
integer loss. Identical Alert replays are idempotent; conflicting IDs are rejected.
Incident updates and associations commit together; missing Alert references roll
back the write. No correlation runtime state is persisted or rebuilt on startup.

Detection persistence is synchronous, using the existing connection/WAL/lock-timeout
conventions. Subscriber failures are logged and contained so events and other
consumers can continue. There is no retry queue: a failed write can leave missing
output until explicitly retried; foreign keys prevent dangling incident references.
Persisted history grows on disk as events already do; in-memory limits are not
retention/deletion policies. A restart starts a fresh correlation context, so
cross-restart grouping/replay deduplication is not provided.

The existing API gains only read endpoints:

- `GET /incidents?limit=100&offset=0&incident_type=network_sequence&severity=high`
- `GET /incidents/{incident_id}` (404 when missing)

Lists use insertion order, AND filters, limit 1–1000, and nonnegative offset, as
in M7. Updates do not move an incident's list position. Responses expose the full
Incident snapshot, including Alert IDs. There is no new alert-management API,
incident status mutation, dashboard streaming, WebSocket, or response endpoint.
Existing `/events` and `/health` behavior remains available. Tests use temporary
SQLite databases only.

Run dedicated M10 tests, then all non-privileged regressions:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_correlation*.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_incident*.py' -v
.venv/bin/python -m unittest discover -s tests -v
make clean
make test PYTHON=.venv/bin/python
make build/host-activity
bash -n tests/m2_pipeline.sh
make -n test-m2 test-m3 test-m4 test-m5
git diff --check
```

The last two fixture commands prepare/check the privileged M2–M5 tests; they do
not load BPF programs. Running those tests still requires separate approval.

## Real-time dashboard (M11)

M11 adds read-only operator visibility. Detection, session aggregation, scoring,
correlation, and the C agent's bounded IPC queue remain unchanged.

```text
C agent → Unix socket → receiver / security core
                              ↓ committed persistence
                            SQLite
                  events / alerts / incidents
                  + bounded change-reference journal
                              ↓ once per second, worker-thread read
                        FastAPI process
                      REST       WebSocket
                         ↘       ↙
                       React / Vite
```

The receiver and API are **separate processes sharing the same database file**.
There is no shared-memory publisher between them. Database triggers atomically
write change references with persisted records; the API reads committed changes
off its event loop and publishes them to connected browsers. No browser, WebSocket,
or API process is required for detection to continue. Alerts now persist whenever
`--rules` and `--database` are set, including without `--correlation`.

### Install and start

Use Node **22.12+** and npm **10+** (npm 11 is verified), plus the existing Python
virtual environment. Dependencies and exact frontend versions are in the lockfile.

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
npm --prefix frontend install
```

If the system npm is 9.2.0 and fails with an Arborist `edgesOut` error, use a current
npm without a global/root install:

```bash
npx --yes --package npm@11 npm --prefix frontend install
```

The primary development/demo workflow is now one foreground command from the
repository directory, as your **normal user**:

```bash
make dashboard
```

Optional overrides:

```bash
make dashboard INTERFACE=ens33
make dashboard DATABASE=/tmp/test.db
make dashboard OPEN_BROWSER=0
# Combine options as needed:
make dashboard INTERFACE=ens33 DATABASE=/tmp/test.db OPEN_BROWSER=0
```

If no interface is specified, the launcher reads `ip -j route show default` and
selects the unique lowest-metric interface. An absent/ambiguous route produces an
error asking for `INTERFACE=<name>`. It prints the selected interface and absolute
database path before starting capture. The default database is `/tmp/kernellens.db`.
Existing history is preserved; a new database is created/migrated by the normal
user. Both receiver and FastAPI receive the exact same absolute path.

The launcher checks occupied ports 8000/5173, active telemetry sockets, database
and WAL/SHM ownership/writability, the venv and installed frontend packages. It
runs an incremental `make all`, then authenticates sudo once in the terminal.
Only the C/eBPF agent and its small runtime/cleanup helper run privileged. The
agent starts with `--host` to enable the existing network and host sensors.
Receiver, FastAPI and Vite remain normal-user processes. No dependency installation
is performed automatically. `DASHBOARD_PYTHON=/absolute/path/to/python` can select
another prepared interpreter; the default is `.venv/bin/python`.

Startup waits up to 20 seconds per readiness stage. The root helper creates or
validates the fixed `/run/kernellens` directory, waits for the agent's socket,
sets directory mode **0711**, and assigns `events.sock` to the launching UID/GID
with mode **0660**. The receiver starts only after those permissions are ready;
its actual agent-ready handshake must succeed before API startup continues.
A stale socket is removed only when it is a real socket and `/proc/net/unix`
shows no owning socket. Active sockets, symlinks and other files are never removed.
The agent itself also refuses an existing path when binding.

The API must answer `/health` with a healthy database, and Vite must answer HTTP
before `xdg-open` is invoked. The launcher supplies the existing frontend config
variables for `http://127.0.0.1:8000` and
`ws://127.0.0.1:8000/ws/live`; Vite binds only to `127.0.0.1:5173` with a strict
port. If no desktop/opener is available, it prints the URL and keeps running.
`OPEN_BROWSER=0` suppresses automatic opening.

**Press Ctrl+C in the launcher terminal to stop the stack.** SIGTERM, SIGHUP,
startup failures and unexpected component exits also invoke cleanup. Shell traps
forward terminal signals to the supervisor and wait for cleanup. The supervisor
tracks child PIDs and owned process groups, including npm/Vite descendants; it
never uses broad process-name killing. The receiver receives SIGINT so its existing
finalization path runs. Closing the root helper's control pipe requests agent
SIGTERM and the agent's existing XDP/tracepoint/socket cleanup, without needing
another sudo authentication after a long session. No background daemon or PID-file
stop command is required for this foreground workflow.

Each launch prints a private log directory, normally:

```text
/tmp/kernellens-runtime-<uid>/run-<unique>/
    dependencies.log
    build.log
    agent.log
    receiver.log
    api.log
    frontend.log
    browser.log       # when an opener is started
```

Detailed telemetry stays in logs. A per-user lock prevents duplicate launchers;
a separate root runtime lock protects the shared agent socket across users.
Logs are retained for troubleshooting and are not automatically rotated/deleted.

Common startup errors:

- **Port or socket occupied:** stop its owning service deliberately and retry;
  the launcher does not stop pre-existing processes or connect to an active socket.
- **Database ownership/readonly error:** choose a user-owned `DATABASE` or repair
  that specific database and its WAL/SHM files separately. The launcher never
  chowns, deletes or recreates an existing configured database.
- **Missing .venv/packages/build prerequisite:** install the dependencies above
  (plus clang, bpftool and libbpf for the agent); inspect `dependencies.log` or
  `build.log`. No sudo pip/npm installation is added.
- **Socket/receiver/API/frontend readiness timeout:** inspect that component's
  log. Started components are stopped; the browser is not opened prematurely.
- **Unsafe runtime directory:** `/run/kernellens` must be a real root-owned
  directory without group/other write access. The launcher refuses a symlink or
  unsafe existing directory instead of changing an arbitrary directory's owner.
- **Sudo/terminal failure:** run from an interactive terminal as the normal user
  with sudo permission. Do not run `sudo make dashboard`.

This is a Linux **development/demo runtime policy** for the existing M11 stack.
A production deployment may use systemd `RuntimeDirectory`, a dedicated KernelLens
group, service User/Group settings or tmpfiles.d. A service-manager redesign is
outside this change. SIGKILL/power loss cannot run shell cleanup traps; inspect
remaining runtime state before a new session. The root helper still observes
control-pipe EOF if its normal supervisor disappears. The launcher does not
replace sensor health monitoring or add security response actions.

#### Manual component startup (optional troubleshooting)

Run API and receiver as the **same operating-system user** so SQLite database,
WAL and shared-memory files remain accessible. Both need the same absolute path:

```bash
# API terminal (creates/migrates the database; binds only to loopback)
KERNELLENS_DATABASE=/tmp/kernellens-m11.db \
  .venv/bin/python -m uvicorn backend.api:app --host 127.0.0.1 --port 8000

# Receiver terminal, after the operator has access to the agent socket
.venv/bin/python backend/receiver.py /run/kernellens/events.sock \
  --rules config/rules.yaml --scoring config/scoring.yaml \
  --correlation config/correlation.yaml --database /tmp/kernellens-m11.db \
  > /tmp/kernellens-events.jsonl

# Frontend terminal
npm --prefix frontend run dev
```

Open **http://127.0.0.1:5173**. The API is **http://127.0.0.1:8000** and the stream
is **ws://127.0.0.1:8000/ws/live**. For a root-owned agent socket, see the manual lab
setup in [M11_REPORT.md](docs/M11_REPORT.md); the API does not need root privileges.

Optional frontend configuration goes in `frontend/.env.local`:

```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_WS_URL=ws://127.0.0.1:8000/ws/live
```

These are build-time public URLs, not secrets. The defaults above are centralized
in `frontend/src/config.js`. `frontend/.env.example` is provided. Restart Vite or
rebuild after changes. Development origins default only to
`http://localhost:5173` and `http://127.0.0.1:5173`. Set the comma-separated
`KERNELLENS_UI_ORIGINS` for other explicit origins; `*` is rejected. The same list
is enforced for browser WebSocket handshakes. There is no authentication/RBAC in
M11: keep services local or within a trusted controlled lab, not publicly exposed.

### Read-only endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Existing API/database health |
| `GET /events`, `GET /events/{event_id}` | Existing normalized telemetry |
| `GET /alerts`, `GET /alerts/{alert_id}` | Stored final scored Alerts |
| `GET /incidents`, `GET /incidents/{incident_id}` | Stored Incident snapshots |
| `GET /dashboard/summary` | Transactionally maintained totals and severity distributions |
| `GET /dashboard/snapshot` | One consistent read of recent records, summary and live cursor |
| `WS /ws/live` | Versioned live notifications and database/stream status |

List endpoints keep `limit=100`, maximum 1000, and nonnegative `offset`. Existing
oldest-first ordering remains the default; `newest_first=true` is optional.
Events filter by `event_category`/`event_type`; Alerts by
`severity`/`event_category`/`alert_type`; Incidents by `severity`/`incident_type`.
Filters combine with AND; missing IDs return 404, invalid pagination 422. No
write/action endpoints were added. IDs are treated as lookup keys, including an
unknown/malformed ID returning 404, consistent with M7.

`/dashboard/snapshot` returns `cursor`, `summary`, `events`, `alerts`, and
`incidents`. It is a single SQLite read transaction, capped at 100 Events, 100
Alerts, and 50 Incidents. Events/Alerts use latest insertion order; Incidents use
latest change order, so a recently updated existing Incident appears again.
Summary totals count all persisted records, not just visible recent rows. Counts
and per-severity totals are maintained transactionally; requests do not repeatedly
scan the full event history. No ambiguous wall-clock “last hour” counters are added.

The versioned WebSocket envelope is:

```json
{
  "schema_version": 1,
  "message_type": "alert",
  "sequence": 123,
  "data": {"alert_id": "...", "risk_score": 40, "severity": "medium"}
}
```

The example projects a few fields; actual `data` contains the unchanged complete
Event, Alert or Incident model. Types are `event`, `alert`, `incident`, `status`.
A `status` message can contain `database`, `summary`, and `resync_required`; the
initial connection status has no sequence. Data messages use the persisted change
sequence; Incident references resolve to the newest snapshot/revision in the
read transaction. Browser-to-server application messages are rejected with 1008.

### Bounds and recovery

| Resource | Bound/behavior |
| --- | --- |
| SQLite change journal | 512 ID-only references per family (1536 total) |
| Read batch | At most 128 references per family per poll |
| Poll interval | One second, only while clients are connected |
| WebSocket clients | 16 per API process |
| Each client queue | 256 messages and 4 MiB queued payload |
| Individual live message | 1 MiB; oversized messages disconnect for REST recovery |
| Send timeout | 5 seconds |
| Frontend recent lists | 100 Events, 100 Alerts, 50 Incidents |
| Frontend REST handoff buffer | 256 live messages |

Queues are owned by the API event loop. SQLite work runs in a worker thread and
never touches those queues. Queue overflow or stalled sends disconnect the slow
client (1013); other clients and security processing continue. A detected journal
gap sends `resync_required`; it does not pretend the live feed is complete.
Large bursts may produce sampled live activity, but persisted records remain
queryable. Database history grows as before; bounded journal retention is not a
historical data-retention policy.

The dashboard loads REST history immediately and starts another authoritative
snapshot after each WebSocket handshake. It buffers live messages during that
read, ignores changes at/before its snapshot cursor, then merges newer records by
`event_id`, `alert_id`, or `incident_id`. Repeated Incident snapshots update one
entry and any open detail panel. Counters come from backend summaries, not browser
risk calculations or guessed increments. On disconnection, it shows Reconnecting,
retries after 1, 2, 4, 8, 16, then at most 30 seconds, and reloads REST after
reconnection. Backoff resets only after a stable 30-second connection. REST errors
retain existing rows and retry after five seconds; malformed live data triggers
reconnection. API restarts/reloads recover through REST, not a permanent replay log.

### Dashboard and timestamps

Overview provides totals, severity distribution, API/database status, and live
connection status. Alerts expose rule, type, risk, severity, category and entities;
Incidents expose risk, status, member count and primary entities. Telemetry shows
source, event type, process/PID and network context. Rows/cards open a detail panel
with metadata and complete evidence available on demand. Incident details show
member IDs and correlation reason. Hybrid details explicitly state that temporal/
contextual correlation does **not** prove exact process-to-network attribution.

Risk and the four severity labels come directly from the backend. Color is paired
with visible text. Empty/loading/error states are explicit. Layouts support
narrow screens with horizontally scrollable data tables.

Security timestamps remain **monotonic nanoseconds since boot**, exact in
storage and browser memory and available in technical details. Security logic
never uses calendar time. Additive schema v4 stores independent UTC persistence
clocks in `operator_times`; REST/live presentation exposes `wall_clock_timestamp`
for Events/Alerts and `created_at` / `updated_at` for Incidents. React converts
these with `Intl.DateTimeFormat` in `Asia/Amman`. Legacy or invalid calendar
values show `Time unavailable`; no boot timestamp is interpreted as Unix time.
Display clocks describe persistence and depend on host clock accuracy.

The header Light/Dark button switches shared semantic CSS tokens. Explicit
choices persist in localStorage as `kernellens-theme`; saved choices override
the initial operating-system preference. Theme initializes before React renders.
Both modes retain labelled severity, status, details and responsive tables.
Theme changes preserve records and the live connection. “API: Online” means a
dashboard/database read succeeded, not that the agent is healthy.

### Validation and manual demonstration

```bash
npm --prefix frontend test
npm --prefix frontend run build
.venv/bin/python -m unittest discover -s tests -p test_dashboard.py -v
.venv/bin/python -m unittest discover -s tests -v
make clean
make test PYTHON=.venv/bin/python
make build/host-activity
bash -n tests/m2_pipeline.sh
make -n test-m2 test-m3 test-m4 test-m5
git diff --check
```

See [docs/M11_REPORT.md](docs/M11_REPORT.md) for results, the controlled nmap/SYN
lab demonstration, troubleshooting, and known limitations. The frontend production
bundle is `frontend/dist/`; `npm --prefix frontend run preview -- --port 5173`
previews it locally with the default allowed origin. Deployment hosting and
public access controls are outside this milestone.
