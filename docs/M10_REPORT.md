# M10 implementation and validation report

M10 adds Python Alert → Incident correlation. M9 Alert scoring is unchanged.
No kernel/C-agent changes, M11 dashboard, or response features were implemented.
No commit or push was performed.

## Correlation rules

| Type | Qualifying evidence | Grouping key | Window |
| --- | --- | --- | --- |
| network_sequence | Two distinct types among port_scan, syn_flood, traffic_flood | (src_ip, dst_ip) | 60 seconds |
| host_sequence | Two distinct types among process_match, syscall_match, privilege_change | positive pid | 30 seconds |
| hybrid_activity | SYN/traffic flood scored at least 50 against an explicitly configured local destination, plus successful non-root→root change scored at least 50 | (src_ip, dst_ip, pid) | 60 seconds |

Hybrid requires current UID 0, previous UID >0, and syscall return 0. The default
`monitored_ips: []` requires operator configuration before hybrid matches occur.
Each engine represents one host/boot stream. Hybrid correlation is explicitly
**temporal/contextual and does not claim exact process-to-network attribution**.
PID reuse cannot be resolved by existing telemetry; short windows only reduce
that ambiguity. No process lineage or distributed correlation was added.

The inclusive test is `max(timestamp) - min(timestamp) <= window_ns`, using final
Alert timestamps. Incidents emit immediately at qualification; no quiet timer is
needed. Subsequent accepted alerts update the same ID. The full-span window does
not slide indefinitely. A nondecreasing watermark expires incidents when
`earliest + window < watermark`; inputs older than a family's retained window are
ignored. Late accepted alerts can move the beginning earlier but never regress
updated time. Input ordering matters when crossing expiry/capacity boundaries.

An Alert is assigned at most once within a correlation family. A hybrid Alert
with multiple qualifying contexts joins the lexicographically first matching
context. Different correlation families may reference the same Alert because they
explain different relationships. Identical replay does not append duplicate IDs.

## Incident model and scoring

`Incident` is a frozen dataclass with:

```text
incident_id: canonical UUID4 string
created_timestamp: uint64 monotonic nanoseconds of earliest member
updated_timestamp: uint64 monotonic nanoseconds of latest member
incident_type: network_sequence | host_sequence | hybrid_activity
title: nonempty string
description: nonempty explanatory string
severity: low | medium | high | critical
risk_score: integer 0..100
status: open
alert_ids: tuple of unique canonical UUID4 strings (JSON array)
primary_entities: JSON object
metadata: JSON object
```

Instances validate UUIDs, timestamp ordering/span, at least two bounded member
references, JSON-compatible evidence, score arithmetic and severity consistency.
Metadata includes correlation rule/window, relationship, shared entities, alert
types, highest Alert score, correlation points/reason, explicit absence of exact
process/network attribution, and an alert-cap indicator.

Formula: `min(100, highest_member_alert_score + 5)`. The single five-point bonus
recognizes corroboration, never accumulates per Alert/type, and does not give
hybrid detections another bonus. Severity uses the existing M9 function:
0–19 low, 20–49 medium, 50–79 high, 80–100 critical. Source Alerts are copied for
validation/evidence extraction; their scores and metadata are unchanged.

## Bounded state

Defaults across all enabled families:

| State | Limit |
| --- | ---: |
| Pending compact Alert summaries | 1024 |
| Open Incident contexts | 256 |
| Retained member summaries/IDs per Incident | 128 |
| Recent replay UUIDs | 4096 |

No source-event UUID arrays, packet metadata lists, or full Alerts are retained by
correlation. Pending capacity evicts the oldest timestamp, with UUID tie-breaking.
Open-context capacity defers new groups. Full incidents ignore additions until
expiry without spawning overflow incidents; `alert_limit_reached` exposes this.
Scores reflect retained members. Capacity can therefore omit correlations or
later evidence. Pending/replay context expires after the largest enabled window;
active incident windows expire independently. Replay protection is bounded.

Only later Alerts or explicit `advance_time(timestamp)` advance correlation time.
If input stops, bounded state remains in memory, while previously emitted
Incidents remain visible. There are no correlation sleeps, clock reads, new timers,
or background threads. Runtime state is not restored after receiver restart.

## Persistence and API

The specification's database/API design motivated a minimal SQLite v2 migration:

- Existing `events` table/data remain unchanged.
- `alerts`: immutable full scored Alert JSON, keyed by alert_id.
- `incidents`: latest Incident JSON, keyed by incident_id, indexed type/severity.
- `incident_alerts`: unique incident/alert pairs and foreign keys to both records.

Full Alert records preserve the evidence behind durable associations. Identical
Alert replay is idempotent; conflicting IDs are rejected. Incident updates and
association writes are atomic; missing Alert references roll back the write.
JSON preserves uint64 timestamps. No correlation runtime state is persisted.
Persistence is opt-in through receiver `--correlation CONFIG --database PATH`.
Without a database, incidents are still returned/published and printed to stderr.

Persistence callbacks are synchronous and failure-contained; no retry queue was
added. Database errors can leave missing output but cannot create dangling links.
Disk history is not bounded by in-memory correlation limits; no retention policy
was added. Restart begins a new correlation context, not a replay of stored Alerts.

Read-only endpoints:

```text
GET /incidents?limit=100&offset=0&incident_type=network_sequence&severity=high
GET /incidents/{incident_id}
```

Limits are 1–1000; offsets nonnegative; filters combine with AND. Missing IDs
return 404, invalid pagination 422, SQLite errors 503. Existing event/health API
behavior remains available. No alert/status mutation API or WebSockets added.

## Worked examples

1. **Network:** at 1 s, a 50-port scan scores 40/medium; at 10 s, threshold-level
   SYN flooding from the same source to the same destination scores 60/high.
   Span 9 s ≤60 s. One network_sequence Incident scores `max(40,60)+5=65/high`.
   Another flood within the original span updates that Incident's ID/membership.
2. **Host:** at 1 s, process match scores 30; at 2 s, denied credential syscall
   for the same PID scores 20. One host_sequence Incident scores 35/medium.
   At 3 s, successful non-root→root change for that PID scores 75; updating the
   same Incident produces `max(30,20,75)+5=80/critical`.
3. **Hybrid:** threshold SYN flood (60) against configured local `192.0.2.2` at
   1 s plus a successful root transition (75) for PID 42 at 2 s gives
   `max(60,75)+5=80/critical`. Key `(192.0.2.1,192.0.2.2,42)` identifies the
   contextual group; metadata and description explicitly reject exact process
   attribution. This is not evidence that PID 42 generated the traffic.

## Validation results

| Command | Result |
| --- | --- |
| `.venv/bin/python -m unittest discover -s tests -p test_correlation.py -v` | PASS, 23 tests |
| `.venv/bin/python -m unittest discover -s tests -p test_correlation_receiver.py -v` | PASS, 2 tests |
| `.venv/bin/python -m unittest discover -s tests -p 'test_correlation*.py' -v` | PASS, 25 tests combined |
| `.venv/bin/python -m unittest discover -s tests -p 'test_incident*.py' -v` | PASS, 9 tests |
| `.venv/bin/python -m unittest discover -s tests -v` | PASS, 130 tests |
| `make clean` | PASS |
| `make test PYTHON=.venv/bin/python` | PASS, clean eBPF/agent build, C parser tests, all 130 Python tests |
| `make build/host-activity` | PASS |
| `bash -n tests/m2_pipeline.sh` | PASS |
| `make -n test-m2 test-m3 test-m4 test-m5` | PASS, privileged commands prepared only |
| `git diff --check` | PASS |
| `git status --short` | Reviewed; only intended M10 files |

There are **34 dedicated M10 tests** and **96 existing regression tests**, totaling
130. The new pipeline regression proves 50 ports still produce one complete
40/medium scan Alert before correlation, followed by one related Incident.
Tests cover real normalized network/host models, receiver wiring, temporary SQLite
round trips, migration rollback, foreign keys, pagination, APIs, bounded state,
malformed configuration, boundaries, failure containment, and immutability.

The initial sandboxed Incident/API test attempt stalled in FastAPI TestClient and
was interrupted. It passed on rerun outside the sandbox. Full regressions and
`make test` also ran outside the sandbox for their local socket fixtures. These
are non-privileged tests; **privileged M2–M5 sensor tests were not executed**.
An existing Starlette/httpx deprecation warning remains; it does not fail tests.

Repository inspection/review also used `pwd`, `ls -a`, `rg --files`, `rg -n`,
`cat`, `head`, `sed -n`, `wc -l`, `git diff --stat`, `git diff --numstat`, and scoped
`git diff` commands. `ps -eo pid,ppid,args | rg 'unittest discover|test_incident'`
was used to inspect the stalled test attempt. Edits used apply_patch, file-writing
heredocs and a Python README update. No dependencies were added or installed.

## Requirement checklist

| User requirement | Result | Evidence |
| --- | --- | --- |
| 1. Related Alerts become Incidents, not every Alert | PASS | Two distinct supported types required |
| 2. User-space only | PASS | No eBPF, agent, maps or wire-format edits |
| 3. Structured Incident model | PASS | UUID4, timestamps, entities, member IDs, validated risk |
| 4. Simple status | PASS | Only open; no management workflow |
| 5. Explainability | PASS | Rule/window/shared-context/type and score evidence |
| 6. Strict bounded YAML | PASS | Version, exact fields/types, windows, duplicates, unsafe YAML tested |
| 7. Network correlation | PASS | Same pair, distinct types, inclusive time window |
| 8. Host correlation | PASS | Same positive PID, two of three host types |
| 9. Conservative hybrid capability | PASS | Explicit local destination plus high-risk flood/root transition |
| 10. Avoid false correlation | PASS | Independent IP pairs/PIDs, conservative hybrid eligibility |
| 11. Deterministic time | PASS | Alert timestamps, bounded late admission, exact-boundary tests |
| 12. Deduplication/updates | PASS | Stable ID, unique memberships, capped contexts and replay memory |
| 13. Incident risk | PASS | max Alert score +5, capped at 100, existing M9 severity mapping |
| 14. Alert immutability | PASS | Snapshot extraction, mutation regression tests |
| 15. Persistence decision/implementation | PASS | v2 migration, full Alerts, Incidents, foreign-key association table |
| 16. Minimal API visibility | PASS | Two read-only Incident endpoints, bounded pagination/404 |
| 17. Separate architecture | PASS | Dedicated model/config/engine/store, receiver wiring only |
| 18. Memory bounds | PASS | Pending/open/member/replay caps and expiration tests |
| 19. Dedicated and regression tests | PASS | 34 new +96 existing, all 130 pass after clean build |
| 20. Documentation | PASS | README config, distinction, rules/windows, limitations and JSON example |
| 21. Scope exclusions | PASS | No M11, response, enrichment, ML, lineage or exact attribution |

## Files

Created:

- `backend/correlation.py`
- `backend/correlation_config.py`
- `backend/incidents.py`
- `backend/incident_storage.py`
- `config/correlation.yaml`
- `tests/test_correlation.py`
- `tests/test_correlation_receiver.py`
- `tests/test_incident_storage.py`
- `docs/M10_REPORT.md`

Modified:

- `backend/storage.py` — additive v2 migration and connection foreign-key enforcement.
- `backend/api.py` — read-only Incident endpoints and app version.
- `backend/receiver.py` — optional correlation/persistence subscriber wiring.
- `tests/test_storage.py` — current/future migration-version assertions.
- `README.md` — current milestone, migration description and complete M10 guide.

M8 rules, M9 scoring/model/policies, normalized events, C agent and eBPF sources
have no changes in this milestone.
