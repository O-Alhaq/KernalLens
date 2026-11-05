# M11 — Real-Time Dashboard

## Objective and outcome

M11 provides a read-only React dashboard for persisted SecurityEvents, finalized
M9 Alerts, and M10 Incidents. It adds historical REST queries and bounded live
WebSocket updates without moving detection/scoring/correlation into React.

The receiver and API remain separate processes. M8–M10 security models/policies,
network-session aggregation, and the C agent's 64 KiB backpressure queue are
unchanged. No M12 response functionality, blocking, process/file actions,
authentication/RBAC, enrichment, AI, or multi-host monitoring was added.

## Architecture

```text
XDP / host sensors → C agent → Unix telemetry socket → receiver/security core
                                                        ↓
                                              SQLite transaction
                                    authoritative rows + counters + change IDs
                                                        ↓
                                   separate FastAPI process, paced journal reader
                                        ↙                         ↘
                               bounded REST                  /ws/live
                                        ↘                         ↙
                                            React / Vite UI
```

Persistence is authoritative. A browser never consumes agent stdout or connects
to the telemetry socket. The receiver has no dashboard socket dependency. With
`--rules --database`, Alerts are persisted even without `--correlation`; with
correlation enabled, Incident snapshots and associations use the existing store.
Live consumers only see committed database output.

SQLite is the minimal cross-process bridge. No Redis, extra Unix socket, shared
in-process global, or receiver/API runtime rewrite is required. The API's async
poll task runs one bounded SQLite read through `asyncio.to_thread`, then publishes
on its own event loop. It polls once per second while clients exist, never every
few milliseconds. Each REST handler runs synchronous SQLite work in FastAPI's
worker pool. The async loop owns all subscriber queues; worker threads do not
modify them. Live delivery can fail independently of security collection.

## Persistence and migration

Schema version 3 adds the existing M11 live layer:

- `live_changes(sequence, family, object_id)`: bounded ID-only change references,
  with indexes by family/sequence and family/object/sequence.
- `live_pruned`: one expiry marker per family for gap detection.
- `dashboard_counts`: totals plus four severity counters for Alerts/Incidents.
- An internal `incidents.live_sequence` and index for recently updated Incident
  ordering in dashboard snapshots.
- Expression indexes for Alert severity, category and type filters.

Triggers update journal references and counters inside the same transaction as
Event/Alert inserts and Incident insert/update operations. Identical Incident
snapshots do not publish again. Updates change severity counters without adding
another logical Incident. Existing Events/Alerts/Incidents retain their public
schemas and IDs. Internal `live_sequence` is not exposed in Incident JSON.

Migration seeds counts once from existing history and preserves all rows; old
history is loaded through REST rather than republished as new notifications.
Summary reads touch a fixed number of counter rows, not full telemetry history.
Only supported stores should write data: direct ad hoc SQL deletion/modification
is outside M11 and can invalidate the counters. Stored history grows on disk;
change-journal bounds are not a historical deletion policy.

Schema version 4 adds `operator_times(family, object_id, created_at, updated_at)`
with a composite primary key and persistence-only triggers. No security-model
field or stored security record is changed. Migration is atomic and accepts
existing v1/v2/v3 databases. Existing rows are deliberately not backfilled.

### Operator clock architecture

```text
sensor monotonic nanoseconds → detection / quiet-finalization / correlation / scoring
SQLite UTC persistence clock → API presentation fields → React Asia/Amman display
```

SQLite `strftime('%Y-%m-%dT%H:%M:%fZ', 'now')` generates ISO-8601 UTC text
with millisecond precision in the write transaction. Event and Alert inserts
capture their persistence time; Incident inserts capture both creation and update
times. Content-changing Incident updates preserve `created_at` and advance
`updated_at`. An identical replay changes neither clock nor journal revision.
An update to a legacy Incident leaves its unknown creation time null.

Shared projections expose `wall_clock_timestamp` on Events and Alerts and
`created_at` / `updated_at` on Incidents through list/detail REST, transactional
REST snapshots, and the live journal reader. Nullable fields are additive API
presentation fields, never passed into `SecurityEvent`, `Alert`, or `Incident`.
REST collections use a bounded read transaction for clock projections; mutable
Incident evidence and its clocks are reread together. Refresh/read operations
never generate or persist a timestamp.

These clocks describe persistence, not the exact packet-observation instant or
the beginning of an Alert's detection window. Host clock accuracy and adjustments
can affect them. Monotonic nanoseconds remain authoritative for all security
windows, ordering and evidence. No epoch conversion or boot-clock mapping is used.

## REST

All endpoints are read-only. Existing Event and Incident endpoint defaults remain
unchanged: insertion order, oldest first, with bounded pagination.

| Endpoint | Behavior |
| --- | --- |
| `/health` | Existing API/database health response |
| `/events`, `/events/{event_id}` | Existing normalized events |
| `/alerts`, `/alerts/{alert_id}` | Existing stored scored Alert representations |
| `/incidents`, `/incidents/{incident_id}` | Existing current Incident snapshots |
| `/dashboard/summary` | Exact persisted totals and severity distributions |
| `/dashboard/snapshot` | Consistent cursor, summary and bounded recent records |

List query parameters: `limit` 1–1000, `offset` ≥0, optional `newest_first`.
Event filters: `event_category`, `event_type`. Alert filters: `severity`,
`event_category`, `alert_type`. Incident filters: `severity`, `incident_type`.
Filters use parameterized SQL and combine with AND. Missing/invalid lookup IDs
return 404, invalid pagination 422, and SQLite failures 503 without private paths.
There are no write, action, arbitrary file, or arbitrary SQL endpoints.

The dashboard snapshot is one read transaction containing:

```text
cursor
summary:
  total_events, total_alerts, total_incidents
  alerts_by_severity, incidents_by_severity
 events: latest 100 insertions
 alerts: latest 100 insertions
 incidents: latest 50 changes (including updates to older Incidents)
```

No “last hour” statistics are invented from kernel monotonic timestamps.

## WebSocket protocol and bounds

Endpoint: `/ws/live`. Explicit message types: `event`, `alert`, `incident`, `status`.

```json
{
  "schema_version": 1,
  "message_type": "incident",
  "sequence": 123,
  "data": {
    "incident_id": "...",
    "risk_score": 65,
    "severity": "high"
  }
}
```

This is a projection: actual data messages include the complete existing model.
The initial `status` contains `stream: connected` and `resync_required: true`;
it has no sequence. Subsequent status messages include database status, summary,
sequence, and a resync flag. Immutable Event/Alert messages use their actual journal
sequence. Incident references resolve to the latest snapshot and revision in that
read transaction, so multiple references can safely describe the same object.

| Resource | Bound |
| --- | ---: |
| Journal per family | 512 references |
| Total retained journal | 1536 references |
| Poll batch per family | 128 references |
| Maximum batch references | 384 |
| Poll pacing | One second, only with clients |
| WebSocket clients per API process | 16 |
| Queued messages per client | 256 |
| Queued payload bytes per client | 4 MiB |
| Individual live payload | 1 MiB |
| Send timeout | 5 seconds |
| Browser snapshot handoff buffer | 256 messages |
| Browser Events / Alerts / Incidents | 100 / 100 / 50 |

A sender yields between publications so ready clients can drain. Queue or byte
limits, oversized messages, and send timeouts disconnect affected clients with
1013; they recover from REST. There is at most one in-flight message in addition
to each client queue. Browser application commands are rejected with 1008. Peer
disconnects cancel connection tasks and release the subscriber. No-client
publication retains no in-memory history. Journal gaps request a snapshot rather
than claiming lossless live delivery. Event bursts cannot evict the separate
Alert or Incident journal allocation. API read failures report unavailable status
and retry without changing the receiver or its database writes.

Database reads have the existing five-second SQLite timeout. The journal/triggers
add bounded per-write bookkeeping; this is not a throughput benchmark or a claim
that synchronous per-event SQLite persistence is free. The preserved IPC queue can
still drop whole new records under sustained overload, as documented in M10.

## Frontend structure and behavior

Stack: React 19, Vite 8, plain CSS, built-in React state/effects. Vitest 4,
Testing Library and jsdom provide a small component/controller test suite.
`json-bigint` preserves large kernel timestamps without changing backend JSON.
No global state library, chart framework, external asset CDN, or icon dependency.

- `App.jsx`: overview, Alerts, Incidents, telemetry navigation; shared status and
  counts; severity filter; bounded lists; selected record details.
- `components.jsx`: labelled severity/risk, Alert rows, Incident cards, entities,
  empty states and detail panel.
- `client.js`: REST/live handoff, request cancellation, queue limits and reconnect.
- `data.js`: envelope/response validation, stable-ID replacement, bounded lists,
  lossless JSON decoding and monotonic formatting. No security scoring logic.
- `config.js`: centralized public API/WebSocket URLs.
- `styles.css`: responsive sidebar/layout, severity text/color, tables and details.

Overview shows persisted counts, severity distribution, API/database and live
connection status. Alert rows show rule/type/category, risk, severity and available
IPs/PID/process name. Incidents show type/title, status, risk/severity, timestamps,
entities and member count. Detail panels expose original metadata, source/member
IDs, complete records and score/correlation explanations on demand. An open
Incident detail panel follows updates to its stable ID. Hybrid details explicitly
state: “This correlation is temporal/contextual. It does not prove exact
process-to-network attribution.”

Risk is displayed as the supplied number out of 100. Severity labels are only
low/medium/high/critical, always text as well as color. Empty, loading, disconnected,
malformed-message and failed-request states are handled. Existing rows remain
visible after request failures. Data tables scroll horizontally on narrow screens
rather than breaking IPs and event names into unreadable fragments.

### Snapshot/reconnect ordering

1. Load an initial REST snapshot so history remains useful even if live is offline.
2. After each WebSocket handshake, begin a fresh authoritative snapshot; invalidate
   any pre-handshake request that could leave a delivery gap.
3. Buffer up to 256 messages during the REST read.
4. Replace recent lists/summary from the snapshot; ignore queued data at or before
   its cursor; apply newer data by stable Event/Alert/Incident ID.
5. On journal gaps, fetch another snapshot. Repeated Incident snapshots replace
   existing entries; they never increment counts locally.
6. On disconnect, show Reconnecting and retry after 1, 2, 4, 8, 16, then 30 seconds.
   Reset backoff only after a stable 30-second connection. Refresh REST on reconnect.
7. REST has a ten-second request timeout and five-second failure retry. Stop/unmount
   aborts requests, closes the socket and cancels retries. Buffer overflow or malformed
   live data reconnects rather than retaining unbounded/untrusted state.

Snapshot/counter cursors are operational SQLite revisions, not detection timestamps.
A configured database is expected to remain the same file while an API process is
running. Restart API/receiver when intentionally replacing it.

### Time and status semantics

Main Event/Alert rows and Incident cards/details prioritize calendar time.
The central `formatAmmanTime` uses `Intl.DateTimeFormat('en-US', ...)` with the
IANA `timeZone: 'Asia/Amman'`, seconds and a 12-hour clock. No fixed UTC offset
is used. Labels distinguish Observed, Detected, Created and Updated; details name
Amman explicitly. Missing/invalid UTC values display `Time unavailable`. Legacy
records remain readable, with original monotonic values in technical details.
Numeric values and numeric strings are never accepted as calendar timestamps.
Large monotonic JSON integers retain every digit as decimal strings in browser
memory, with BigInt used for seconds-since-boot formatting.
API Online means a snapshot/database request succeeded; it does not establish
agent, interface, sensor attachment, or collection health.

### Light and dark themes

The existing components/layout share semantic CSS variables for background,
surface, elevated surface, text, secondary text, border, accent, code surface,
status, and all four severity foreground/background pairs. Dark mode uses layered
navy/slate surfaces and readable teal/amber/pink accents; severity retains its
text labels. The established sidebar and KernelLens identity remain intact.
Tables, filters, buttons, empty/error states, metadata and JSON use the same tokens.

A native button at the top-right header shows `Light` or `Dark`, with an accessible
label naming the current theme and the switch action. Native keyboard activation
and a visible focus outline are retained. The same responsive layout supports
both themes, including horizontal table scrolling on narrow screens.

`kernellens-theme` in localStorage stores only explicit operator choices. On a
first visit or invalid saved value, `prefers-color-scheme` supplies the initial
theme; a saved light/dark choice overrides it. Later OS changes do not override
the session choice. A small inline head initializer applies the preference before
render, and `theme.js` uses the same fallback rules. If storage is unavailable,
the toggle still works for the session. No database/backend theme preference is
introduced. Theme state is independent of the dashboard transport effect, data,
selection and reconnect controller.

## One-command development launcher

**Issue:** Operating the dashboard required four terminals and repeated manual
startup/permission commands.

**Improvement:** A supervised one-command launcher was added.

**Result:** The complete local dashboard stack can be started from one terminal
while preserving privilege separation.

```bash
make dashboard
make dashboard INTERFACE=ens33
make dashboard DATABASE=/tmp/test.db
make dashboard OPEN_BROWSER=0
```

The Makefile exports configuration directly to `scripts/start_dashboard.sh`,
which forwards signals with shell traps and waits for
`scripts/dashboard_runtime.py`. Make values containing spaces/quotes do not pass
through shell interpolation. `.venv/bin/python` is selected independently of the
existing `PYTHON` setting used by regression targets; `DASHBOARD_PYTHON` can select
another installed interpreter. No backend/frontend security code or dependency
versions are changed by the launcher.

The standard-library Python supervisor validates the explicit interface or detects
a unique lowest-metric IPv4 default-route interface with `ip -j route show default`.
It checks both loopback ports and the active Unix-socket table without connecting
to or disturbing an existing receiver. It validates owner/mode/access for the
database and its WAL/SHM files, then creates/migrates the database unprivileged.
Receiver/API use the same absolute path. Existing files are not repaired, chowned
or deleted. Missing venv/packages and incremental build failures stop startup
with component logs rather than performing automatic dependency installation.

`sudo -v` authenticates once. A root helper starts only the existing C agent
(`--host INTERFACE /run/kernellens/events.sock`), validates/creates the fixed runtime
directory, and polls for its socket with a bounded timeout. After socket creation
it sets `/run/kernellens` to 0711, socket ownership to the launching UID/GID, and
socket mode to 0660. Only then does it report readiness. A real stale socket may
be removed if absent from `/proc/net/unix`; an active socket, symlink or other file
is refused. Root/per-user locks prevent overlapping launchers. Existing unsafe
or non-root-owned runtime directories require deliberate operator correction.

The receiver's actual ready handshake gates API startup. API `/health` must return
`status=ok,database=ok`, and the frontend must return HTTP 200 before browser
opening. Each readiness stage has a 20-second default timeout. Vite receives the
existing `VITE_API_BASE_URL`/`VITE_WS_URL` environment variables, binds to loopback
with a strict 5173 port, and uses the same REST/WebSocket architecture. The API
binds to loopback port 8000. `xdg-open` is optional and `OPEN_BROWSER=0` disables it.

The launcher remains in the foreground. Ctrl+C, SIGTERM, SIGHUP, startup failure
or unexpected component exit stop owned processes/groups in reverse order.
Receiver SIGINT preserves its existing flush/finalization path. A control-pipe
EOF requests root-helper agent SIGTERM/cleanup, so shutdown does not require a
fresh sudo prompt after credentials expire. Agent cleanup failures/timeouts are
reported; no unconditional XDP-detach claim is made. The normal components have
bounded shutdown grace periods, with a forced-stop fallback for a stuck child.
No broad `pkill` or unrelated-process termination is used. Ctrl+C is the stop
interface; this is not a background service or PID-file daemon.

Logs are in a fresh mode-0700 directory under
`/tmp/kernellens-runtime-<uid>/run-<unique>/` (or the normal temporary directory).
Files are `dependencies.log`, `build.log`, `agent.log`, `receiver.log`, `api.log`,
`frontend.log` and optional `browser.log`. High-volume events do not flood the
launcher terminal. Logs remain for troubleshooting; no rotation is added.

This automates the validated **development/demo** permissions, not a production
service policy. Future deployment can use systemd RuntimeDirectory, a dedicated
group, service User/Group or tmpfiles.d. Uncatchable SIGKILL/power loss cannot run
shell traps; the root helper observes supervisor pipe EOF while it remains alive.
The fixed local ports/shared socket allow one local stack. No M12 features,
response controls, policy/scoring changes or production service redesign are added.

Launcher validation adds **30 unprivileged tests**, including default/explicit/
missing interfaces, occupied ports, active/stale/non-socket paths, database and
sidecar ownership/modes/symlinks, private-directory locks, missing venv/packages,
actual setup-command logs/failure, build failure, socket timeout, HTTP health
content and proxy bypass, readiness failure, exact shared database/frontend URLs,
PID/group cleanup (including a Vite-like grandchild), preservation of an unrelated
process, browser-disabled/unavailable behavior, root-helper permission ordering
and EOF/timeout cleanup, Make overrides, and shell Ctrl+C/SIGTERM forwarding.
Root identity/ownership operations and component executables are stubbed; no sudo,
eBPF attachment or privileged M2–M5 tests run automatically. Real privileged
launcher startup and leak-free shutdown subsequently succeeded as recorded below;
signal/exit-status refinements use unprivileged tests.

Launcher files created: `scripts/start_dashboard.sh`,
`scripts/dashboard_runtime.py`, `tests/test_dashboard_launcher.py`.
Files modified for this addition: `Makefile`, `README.md`, `docs/M11_REPORT.md`.

### Real launcher validation and intentional shutdown

Real privileged `make dashboard` validation succeeded: the complete stack reached
`Press Ctrl+C to stop KernelLens`. After Ctrl+C, Frontend, API, Receiver and Agent
stopped; verification found no remaining agent, receiver, uvicorn or Vite process,
and `/run/kernellens/events.sock` was removed. This is the supplied real validation
result; no privileged capture or M2–M5 tests were rerun for this exit-status fix.

The wrapper previously returned Bash's interrupted `wait` status (130) even though
the supervisor completed cleanup successfully. It now repeats `wait` only when a
launcher signal trap interrupted it, then returns the supervisor's actual result.
A successful requested shutdown prints `KernelLens stopped.` and exits zero.
No blanket status-130 conversion or Make error suppression is used. Genuine
startup/component failures, cleanup failures, and an actual supervisor exit 130
remain non-zero. SIGTERM retains supervised cleanup and now also propagates the
supervisor's completed result. Architecture and security behavior are unchanged.

Signal integration tests now assert final status for Ctrl+C and SIGTERM and verify
owned children have stopped. Added coverage checks a failing supervisor after
Ctrl+C, startup/Agent/Receiver/API/Frontend failures, cleanup failure overriding
success, and a genuine exit 130. Existing unrelated-process and helper socket/EOF
cleanup tests remain in the full regression run.

## Teammate onboarding and configuration usability

The new entry point is `./scripts/setup.sh`, followed by `make dashboard`.
Automatic OS preparation explicitly targets Ubuntu 26.04 LTS, matching the current
lab. The Bash entry delegates to a standard-library Python helper, which previews
missing OS packages, asks before apt installation (or accepts explicit `--yes`),
checks kernel BTF and available kernel configuration, verifies BPF build tools,
reuses `.venv`, installs Python dependencies unprivileged, selects supported npm,
reuses valid frontend dependencies, builds incrementally and validates policy.
No dashboard, eBPF attachment, apt repository, OS upgrade or production service
is started/added by setup. Read-only `--check` inspects OS prerequisites without
installation/build writes. Existing unsafe ownership is diagnosed, not repaired.

The Ubuntu npm 9 resolver issue is handled with user-owned project-local npm 11
under `.tools/npm` when needed; global npm is untouched. Frontend manifest hashes
and a dependency-tree check allow reuse on a second setup run. Changed/incomplete
trees are explicitly rebuilt through lockfile-based npm ci, including dev tools.
Python pip reuses satisfied requirements; no venv reset or build clean is added.

`make validate-config` delegates to the actual `load_rules`, `Scorer.from_file`
and correlation `load_policy` loaders. It reports the failing file and parser
reason (plus YAML line/column where available), validates all three files, returns
non-zero on error and shows no normal configuration-error traceback. It requires
no root privileges, database, network capture or build toolchain. `make help`
shows only existing targets/the setup script and now works without pkg-config or
libbpf installed; library flags are expanded lazily when a build needs them.

README now begins with a newcomer architecture, requirements, clone/setup/start,
stop, dashboard, configuration and troubleshooting workflow. Existing technical
material stays below the onboarding sections. `docs/SETUP.md` covers the platform,
manual preparation, package/sudo behavior, runtime overrides/paths, readiness,
cleanup and common failures. `docs/RULES.md` explains all six shipped rules,
network confirmation/finalization, exact SYN 1000/5s (200/s average equivalent),
scan distinct-port scope, all scoring tiers/modifiers, correlation eligibility,
60/30/60-second windows, hybrid limitations and validated editing examples.
YAML comments improve units/default/disabled-example explanations without changing
any parsed policy value; a comparison against the original policies confirmed
this. Kernel/security algorithms and launcher supervision are unchanged; launcher
missing-dependency errors now point directly to setup.

Onboarding adds **26 unprivileged tests** for real-loader successes/errors,
structural/semantic policy rejection, help/validate targets, preserved defaults,
OS/platform/kernel checks, package consent/command scope, venv reuse/creation,
local npm bootstrap/reuse, frontend dependency idempotency, manifest changes,
artifact ownership, root refusal, read-only preflight and normal-user pip/build
paths. No OS package installation or privileged attachment runs in these tests.
Actual `setup.sh --check` correctly reported missing `python3-pip` on this system;
full apt/download setup was not performed automatically. A clean-machine OS
installation and driver/kernel attachment remain manual validation steps.

Files created: `scripts/setup.sh`, `scripts/setup_environment.py`,
`scripts/validate_config.py`, `tests/test_onboarding.py`, `docs/SETUP.md`,
`docs/RULES.md`. Files modified for onboarding: `README.md`, `Makefile`,
`.gitignore`, all three `config/*.yaml`, `scripts/start_dashboard.sh`,
`scripts/dashboard_runtime.py`, and this report. No dependency versions,
response functionality, commit or push are added.

## Installation and startup

Node 22.12+ and npm 10+ are declared; npm 11 was used successfully. Python's existing
`websockets>=14,<17` range is unchanged from the initial M11 work; 16.1.1 is verified.

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
npm --prefix frontend install
# If the system npm has the documented 9.2.0 resolver issue:
npx --yes --package npm@11 npm --prefix frontend install
```

Set the same absolute `KERNELLENS_DATABASE`/`--database` path in API and receiver.
Run both processes as the same OS user to avoid SQLite/WAL permission conflicts.
API binds to loopback; the frontend defaults to port 5173. Optional public build
settings are `VITE_API_BASE_URL` and `VITE_WS_URL` in `frontend/.env.local`.
Allowed HTTP/WebSocket browser origins default only to localhost:5173 and
127.0.0.1:5173; configure explicit comma-separated `KERNELLENS_UI_ORIGINS` if needed.
Wildcard origins are rejected. There is no authentication; use local/trusted lab
access. No destructive functionality is present.

## Manual controlled-lab demonstration

The completed real M11 test reported API Online, Live Connected, real
SecurityEvents, a real `port_scan` Alert and a real `syn_flood` Alert. One
`network_sequence` Incident correlated the two Alerts at **65/high**, source
`192.168.150.134`, destination `192.168.150.138`. This is the supplied successful
lab evidence. The refinement did not rerun privileged capture or M2–M5 tests.
The following procedure remains available for a future authorized repeat.

Use a dedicated victim interface/IP and a second lab machine. Replace `ens33` and
`VICTIM_IP` with the lab values. Use the same attacker/source IP for both detections.
No commands below are run automatically.

1. Prepare a private operator-owned runtime directory, then start the privileged
   agent in its own terminal. The root agent will initially own the new socket.

```bash
sudo install -d -m 711 -o "$(id -u)" -g "$(id -g)" /run/kernellens
sudo ./build/kernellens-agent --host ens33 /run/kernellens/events.sock
```

2. After the agent has created the socket, grant only the chosen local operator
   ownership of that socket; then the receiver and API can both run unprivileged.
   Repeat the socket ownership step after each agent restart.

```bash
sudo chmod 0711 /run/kernellens
sudo chown "$(id -u):$(id -g)" /run/kernellens/events.sock
sudo chmod 0660 /run/kernellens/events.sock
```

3. Start API, receiver and frontend in separate terminals:

```bash
KERNELLENS_DATABASE=/tmp/kernellens-m11.db \
  .venv/bin/python -m uvicorn backend.api:app --host 127.0.0.1 --port 8000

.venv/bin/python backend/receiver.py /run/kernellens/events.sock \
  --rules config/rules.yaml --scoring config/scoring.yaml \
  --correlation config/correlation.yaml --database /tmp/kernellens-m11.db \
  > /tmp/kernellens-events.jsonl

npm --prefix frontend run dev
```

Open http://127.0.0.1:5173. Confirm API Online and Live Connected. Existing records
load through REST. An empty database shows explicit empty states. For hybrid demos,
configure the victim's actual local IP in `config/correlation.yaml`; the network
sequence below does not require hybrid matching.

4. On the authorized attacker machine:

```bash
sudo nmap -sS -Pn -p 20-69 VICTIM_IP
```

Wait for quiet finalization (default three seconds after the last matching packet).
A complete 50-port scan produces one Alert at 40/medium. Repeated packet attempts
can increase matching counts without changing the distinct 50-port scope.

5. While still within the configured 60-second network correlation window, send
   controlled SYN activity to a single port, then let it become quiet:

```bash
sudo hping3 -S -p 32080 -c 1100 -i u2000 VICTIM_IP
```

This targets 1100 SYN attempts over roughly 2.2 seconds. With at least 1000 and
fewer than 2000 observed matching attempts in the finalized session, the shipped
SYN rule scores 60/high. The same source/destination pair yields one Incident:
`max(40,60)+5 = 65/high`. Inspect its entities, two member Alert IDs and correlation
reason. No value is hardcoded into the dashboard. Packet loss, IPC drops, other
traffic, existing sessions, delays or different policy can change results; inspect
actual Alert evidence. This is a controlled lab demonstration, not a throughput test.

6. Refresh the page: persisted records reappear with no duplicate Incident.
   Restart the API while leaving receiver/agent running: the UI shows reconnecting,
   backs off, reloads history and resumes. Detection does not need a browser.

7. Production bundle preview and prepared privileged regression commands:

```bash
npm --prefix frontend run build
npm --prefix frontend run preview -- --port 5173
# Privileged regressions only when explicitly approved:
sudo make test-m2
sudo make test-m3
sudo make test-m4
sudo make test-m5
```

## Tests and validation

- Dedicated M11 backend tests: **85**, all pass (29 dashboard/operator-clock +30 launcher +26 onboarding tests).
- Complete Python regression suite: **218** (133 existing +85 M11), all pass.
- Frontend tests: **39**, all pass across six files.
- Frontend production build: **PASS**.
- `make test PYTHON=.venv/bin/python`: **PASS**, including C parser/backpressure
  executables and all 218 Python tests.
- Unique automated regressions: **257** Python/frontend tests plus **2** C
  regression executables (**259** combined; repeated make Python run not double-counted).
- Host helper build, privileged fixture syntax check and Make dry runs: **PASS**.
- Real nmap/SYN demonstration: previously successful as recorded above; privileged
  sensor tests and capture were not rerun for this refinement.
- `git diff --check`: **PASS**; intended working-tree files reviewed.

Commands:

```bash
.venv/bin/python -m unittest discover -s tests -p test_dashboard.py -v
.venv/bin/python -m unittest discover -s tests -v
make clean
make test PYTHON=.venv/bin/python
make build/host-activity
bash -n tests/m2_pipeline.sh
make -n test-m2 test-m3 test-m4 test-m5
npm --prefix frontend test
npm --prefix frontend run build
git diff --check
git status --short
```

Additional non-privileged Chromium smoke testing used a temporary SQLite database,
a real localhost Uvicorn process, a separate writer process, and the React server.
It verified REST history, actual live Alert/Incident arrival at 65/high, detail
inspection, reconnect, refresh deduplication, desktop/mobile layouts and no browser
page errors. These fixtures are synthetic test evidence, not a privileged capture.

Backend coverage includes Alert/Incident endpoints, pagination/filtering/404s,
empty snapshots, counters on Incident severity changes, v2 migration, transaction
visibility, original-message cursor preservation, journal caps/gaps, per-family
isolation, receiver Alert persistence without correlation, multiple WebSocket
clients, origin checks, rejected commands, slow/oversized queue bounds, send timeout,
disconnect cleanup, no-client behavior, poll recovery and pipeline independence.
Frontend coverage includes severity/risk rendering, rows/cards/details, hybrid
limitation, ID replacement, caps, exact uint64 time formatting, malformed data,
empty/disconnected/error states, pre-handshake snapshot races, buffered replay,
journal-gap resync, bounded reconnect and cleanup.

## Issues found and fixed during M11

| Issue | Cause | Fix | Verification |
| --- | --- | --- | --- |
| npm install failed | npm 9.2.0 Arborist crashed with `Cannot read properties of null (reading 'edgesOut')` while resolving peers; the cache and inspected files were user-owned, not root-owned | Used isolated npm 11, retained the project dependencies, generated the lockfile and documented supported tooling; no sudo npm/global ownership change or cache deletion | Install completed, audit reported zero vulnerabilities; tests/build pass |
| Old journal data could look newer than a REST snapshot | Initial implementation stamped every notification with the latest poll cursor | Preserve original immutable-record sequence and use current Incident revision | Backend cursor regression and frontend snapshot-floor tests |
| Initial REST request could leave a connect-time gap | An in-flight pre-handshake request prevented a post-handshake snapshot | Cancel/invalidate it and begin a fresh snapshot after socket registration | Controller race test plus actual browser reconnect/refresh |
| Recently updated old Incident could disappear after refresh | Recent lists originally ordered Incidents only by insertion rowid | Internal indexed latest-change sequence for dashboard snapshot ordering | Old-Incident update ordering test |
| A stalled sender could release state without an explicit retry close | Timeout handling did not issue a close frame | Bounded close with 1013 and cleanup on send timeout | Injected stalled-socket test |
| Narrow tables broke identifiers into small fragments | Automatic table width squeezed entity columns on mobile | Minimum table width inside a horizontally scrollable container | Mobile layout inspection and viewport overflow check |
| Alerts required correlation to be persisted | M10 wired the Alert store only inside correlation setup | Subscribe Alert persistence whenever rules and a database are enabled | Receiver-without-correlation regression |

### SQLite readonly database

**Issue:** Receiver failed with `attempt to write a readonly database`.

**Cause:** The shared M11 SQLite database and its WAL/SHM files had been created
as root:root with permissions that prevented the normal KernelLens user from
writing to them.

**Fix:** The temporary M11 database was recreated under the normal KernelLens
user so the receiver and FastAPI could use the same database consistently.

**Verification:** Receiver successfully wrote Events, Alerts, and Incidents and
FastAPI read the same database.

### Unix socket permission issue

**Issue:** Running the receiver as the normal user failed with
`Errno 13 Permission denied`.

**Cause:** The privileged C agent created `/run/kernellens` with mode 0700, so the
normal receiver process could not traverse the directory. The Unix socket was
also initially root-owned.

**Validation fix:** `/run/kernellens` changed to 0711; `events.sock` assigned to
the KernelLens user; socket changed to 0660.

**Verification:** The unprivileged receiver successfully connected to the
privileged C agent. This manual permission adjustment is suitable for current
validation; a proper startup/runtime ownership policy should replace manual
chmod/chown later. No agent runtime policy is changed by this refinement.

### Live cursor sequencing and npm resolver

Journal messages originally inherited the poll's latest sequence. An older
queued Event could therefore appear newer than a freshly loaded REST snapshot.
Each journal record now carries its actual change sequence, while Incident
updates resolve to their latest persisted revision. Regression tests cover
snapshot/backlog sequencing and reconnect behavior. This fix is retained.

npm cache ownership was checked; root ownership was not the problem. npm 9.2.0
failed internally during dependency resolution. An isolated temporary npm 11 was
used; global npm and project dependencies were not unnecessarily changed.

### Refinement validation

Six backend tests cover independent UTC persistence, exact uint64 security time,
Alert timestamps/replay, Incident creation/update/replay, v3 legacy migration,
legacy Incident updates, and REST/WebSocket/snapshot/read-only-refresh agreement.
Fifteen added frontend tests cover Amman conversion, invalid/missing/numeric
clock rejection, legacy display, exact uint64 decoding, REST/live consistency,
light/dark/system/saved themes, toggling, localStorage, remount restoration,
storage failures and unchanged records/details/connection across toggles.
The existing snapshot ordering, reconnect, queue bounds and deduplication tests
remain passing. WebSocket integration tests explicitly finish disconnect
exchange before TestClient teardown to avoid cancellation races.

A fresh Chromium smoke pass used a separate temporary SQLite fixture and local
API/frontend ports. Both themes passed at 1440px and 390px, including 65/high
Incident details, Amman times, JSON surfaces, reload persistence, unchanged
persisted times, one connection across theme toggles, one Incident, no document
overflow and no browser errors. This synthetic refinement check is separate from
the completed real lab result above. Screenshots were inspected for dark surfaces
and severity/status readability. Automated checks are not a full accessibility
audit. Sandboxed FastAPI TestClient execution stalled; the non-privileged backend
suite and make validation completed successfully outside that restriction.

Refinement requirements: **PASS**. Existing M11 work and architecture retained;
M8–M10 security behavior unchanged. No commit/push or M12 work.

## Known limitations

- Automatic setup targets Ubuntu 26.04 only; other systems require manual
  preparation and are not claimed as validated. Full apt/registry bootstrap has
  stub coverage and requires a separate clean-machine test.
- Setup checks prerequisites but does not load sensors or establish interface
  driver support. Package/registry access, administrator consent and a supported
  kernel/interface remain necessary. Python requirements are bounded, not pinned
  to an exact environment lock.

- Live delivery is best-effort with roughly one-second polling latency, plus bounded
  backlog/read/send time. Gaps or slow clients recover recent state from REST.
- Only recent lists are rendered. Full history uses bounded list API pagination;
  the dashboard does not provide an unbounded historical explorer.
- No sensor heartbeat or attachment-health source exists; API/stream status must
  not be interpreted as proof of collection health.
- Legacy records have no reliable calendar time. New display clocks describe
  persistence time and depend on host wall-clock accuracy; they do not provide
  an exact sensor-time mapping or a multi-host security timeline.
- Clock precision is milliseconds; multiple writes can share a display timestamp.
  Security ordering uses original monotonic values and live journal revisions.
- The launcher automates the current development/demo permission policy. A
  production startup/runtime ownership policy should replace it later.
- Real privileged launcher startup/shutdown succeeded as recorded above. The
  exit-status refinement is tested without automatically repeating capture.
- Launcher logs grow on disk and are not rotated. Fixed loopback ports and the
  shared telemetry socket support one local development stack at a time.
- Journals and queues are bounded, but authoritative history grows on disk. No
  deletion/retention management is added.
- One API worker is recommended for this local deployment. Each additional worker
  would have its own 16-client limit and journal reader, not a shared client cap.
- No public deployment/authentication/access-control system. Only explicit origins
  are accepted for browser streams. API/receiver need compatible SQLite ownership.
- Existing synchronous persistence and IPC overload loss remain possible; the live
  UI cannot restore telemetry that never reached persistence.

## Requirement checklist

| Original M11 requirements | Result | Implementation |
| --- | --- | --- |
| 1–2: functional observability, inspection/architecture first | PASS | Existing architecture retained; dashboard implemented after review |
| 3–4: REST and lightweight summaries | PASS | Bounded routes, transactional counters/snapshot |
| 5–9: versioned live delivery, bounded queues, authoritative persistence | PASS | Separate live module and committed SQLite journal |
| 10–15: React UI, sections/details, severity/risk | PASS | Overview/Alerts/Incidents/Telemetry and evidence details |
| 16–18: live updates, ID deduplication, reconnect | PASS | Stable-ID replacement, cursor handoff, bounded backoff |
| 19: precise status | PASS | API/database and stream only; no invented sensor health |
| 20–23: separated live layer and processes, async safety, paced reads | PASS | Worker-thread SQLite read, loop-owned queues, one-second pacing |
| 24–29: narrow origins, central URLs, errors, serialization, time/read-only safety | PASS | Validated parameters/envelopes, lossless integer parsing, no write actions |
| 30: bounded performance design | PASS | Indexed/capped reads, journals, queues and frontend lists |
| 31–32: backend/frontend tests | PASS | 85 dedicated backend +39 frontend tests |
| 33: manual demonstration | PASS | Successful real 65/high network sequence reported above; no privileged rerun |
| 34: M10 IPC preservation | PASS | Agent sources unchanged; C backpressure tests pass |
| 35–36: documentation/troubleshooting | PASS | README and this report, issue/cause/fix/verification table |
| 37: browser talks to FastAPI | PASS | REST/WebSocket only; no stdout or agent connection |
| 38: scope exclusions | PASS | No M12 or excluded features |
| 39–40: validation and final reporting | PASS | Commands, counts, files, limitations and demo documented |

## File inventory

Created backend/test files:

- `backend/dashboard_storage.py`
- `backend/live.py`
- `tests/test_dashboard.py`

Created frontend files:

- `frontend/package.json`, `frontend/package-lock.json`, `frontend/vite.config.js`
- `frontend/index.html`, `frontend/.env.example`
- `frontend/src/App.jsx`, `frontend/src/components.jsx`, `frontend/src/client.js`
- `frontend/src/config.js`, `frontend/src/data.js`, `frontend/src/main.jsx`
- `frontend/src/styles.css`
- `frontend/tests/fixtures.js`, `frontend/tests/app.test.jsx`
- `frontend/tests/client.test.js`, `frontend/tests/components.test.jsx`
- `frontend/tests/data.test.js`

Created documentation: `docs/M11_REPORT.md`.

Modified:

- `backend/api.py` — REST/live endpoints, lifespan and explicit origins.
- `backend/storage.py` — additive v3 migration and optional newest-first listing.
- `backend/incident_storage.py` — Alert listing and internal-column-safe insert.
- `backend/receiver.py` — persist Alerts independently of correlation flag.
- `requirements.txt` — WebSocket transport dependency.
- `tests/test_incident_storage.py` — migration table inventory assertion.
- `.gitignore` — generated frontend bundle and local environment files.
- `README.md` — M11 setup, architecture, behavior and validation.

`requirements-dev.txt`, Makefile, agent/eBPF sources, M8–M10 detection/scoring/
correlation code and policies remain unchanged. No commit or push was performed.

### Refinement file inventory

Created: `backend/operator_time.py`, `frontend/src/theme.js`,
`frontend/tests/theme.test.jsx`, `frontend/tests/time.test.jsx`.

Modified: `backend/storage.py`, `backend/dashboard_storage.py`, `backend/api.py`,
`frontend/index.html`, `frontend/src/App.jsx`, `frontend/src/components.jsx`,
`frontend/src/data.js`, `frontend/src/styles.css`, `tests/test_api.py`,
`tests/test_incident_storage.py`, `tests/test_dashboard.py`, `README.md`,
`docs/M11_REPORT.md`. Prior uncommitted M11 files remain in the working tree.
