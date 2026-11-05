# Editing KernelLens detection configuration

KernelLens observes activity; this dashboard does not block traffic or perform
response actions. Edit configuration as your normal user. Begin with the shipped
policy, change one thing at a time, and compare results with normal baseline
traffic on an authorized test interface.

Three different objects travel through the security core:

- **Event:** one normalized observation, such as a packet or completed syscall.
- **Alert:** a rule's confirmed detection, with scored evidence.
- **Incident:** related Alerts grouped by shared entities and time.

| File | Question it answers |
| --- | --- |
| `config/rules.yaml` | What activity matches, and when is it a detection? |
| `config/scoring.yaml` | How risky is an already confirmed detection? |
| `config/correlation.yaml` | Which finalized Alerts belong in an Incident? |

After **every** edit:

```bash
make validate-config
```

Stop a running launcher with Ctrl+C, validate, then restart `make dashboard` to
apply changes. There is no hot reload. Existing persisted Alerts/Incidents retain
the scores/evidence they originally received; edits do not rescore history.

## Timing and matching essentials

All security windows use **monotonic timestamps**: nanoseconds counted since boot,
which do not jump with calendar-clock corrections. Independent UTC persistence
timestamps supply the dashboard's Amman calendar display; they never drive rules.

For the three network rule types:

| Setting | Actual behavior |
| --- | --- |
| `threshold` | Confirmation count: distinct destination ports for `port_scan`; matching packet events for the two flood types. Integer 1–4096. |
| `window_seconds` | Rolling event-time window in which the confirmation count must be reached. Samples at or before the left cutoff expire. |
| `quiet_seconds` | After confirmation, matching activity must stop for this long before the session is finalized into one Alert. |
| `max_detection_seconds` | Maximum **confirmed** session lifetime, measured from threshold confirmation, even if matching traffic continues. Must be at least both the window and quiet duration. |
| `max_event_ids` | Bounded source UUID evidence sample, 2–256; aggregate counts are maintained independently. Shipped value 64. |
| `max_groups` | Bound on tracked source/destination groups per rule, 1–4096. Shipped value 128. Capacity can limit observable detections. |

Durations are seconds, numeric (not quoted strings), positive, representable as
whole nanoseconds, and at most 86400 seconds. Network defaults in all shipped
rules are a 5-second confirmation window, 3-second quiet period, and 60-second
maximum confirmed lifetime.

Crossing a threshold confirms a session; it does **not** immediately publish the
network Alert. Matching packets continue contributing aggregates until quiet or
maximum-lifetime finalization. A confirmed session is also finalized on orderly
receiver shutdown/stream end. Unconfirmed candidates do not become Alerts on
shutdown. Finalized counts/scope describe the session, not a permanent
packets-per-second rate or just the final five seconds. No packet-by-packet
Alert stream is produced for a sustained session.

Host rules match each eligible event immediately. They do **not** have a group,
threshold, confirmation window, quiet period or maximum-session setting. Do not
add network-only fields to host rules: the parser rejects them.

## Shipped rules (`rules.yaml`)

The top level is `schema_version: 1` and `rules: [...]`. Every rule needs `id`,
`name`, `enabled`, `category`, `type` and `description`. IDs must be unique.
Unknown fields, duplicate YAML keys, executable YAML tags, wrong types, unsupported
categories/types and invalid bounds are rejected, including inside disabled rules.
There can be at most 128 rules; a file is bounded to 256 KiB.

### `port_scan_basic` — enabled

- **Purpose/type:** `network` / `port_scan`; Alert type `port_scan`.
- **Events/fields:** network events with `protocol: TCP`, SYN set and ACK clear
  (`tcp_flags & 0x12 == 0x02`), a nonzero `dst_port`, and usable source/destination
  IPv4 addresses. This is SYN-attempt observation, not proof of a completed connection.
- **Grouping:** `(src_ip, dst_ip)`; destination port is counted distinctly inside
  that group, not used as a separate group key.
- **Confirmation:** 10 distinct destination ports within 5 seconds.
- **Finalization:** 3 seconds of matching quiet, or 60 seconds after confirmation.
- **Example:** one source contacts ports 20–69 on one destination quickly enough
  to confirm a scan. Fifty distinct ports at finalization score 40/Medium.

Repeated SYNs to one port increase raw matching count but do not increase scan
scope. Retries to 50 distinct ports remain 50 distinct ports, not a wider scan.
The shipped scoring tiers change score with scope but stay **Medium**. Port scan
alone does not become High merely because many packets/ports are observed.

### `syn_flood_basic` — enabled

- **Purpose/type:** `network` / `syn_flood`; Alert type `syn_flood`.
- **Events/fields:** the same TCP SYN-without-ACK, nonzero destination-port and
  valid-address selection as the scan rule.
- **Grouping:** `(src_ip, dst_ip)` across destination ports; not per-port and not
  one global counter across all source IPs.
- **Exact shipped confirmation:** **1000 matching SYN events within 5 seconds**.
  This is an average equivalent of **200 SYNs/second over five seconds**, not an
  instantaneous rate limit. Bursts can confirm, too.
- **Finalization:** quiet 3 seconds; maximum confirmed lifetime 60 seconds.
- **Example:** 1100 observed SYN attempts from one source to one destination in
  roughly 2 seconds confirm one session. After quiet, it scores 60/High under
  the shipped policy, provided the final session count remains below 2000.

Tune against normal traffic: busy services, retrying clients, packet loss,
network visibility and the agent's bounded telemetry queues affect observations.
The onboarding setup does not change the 1000/5 policy.

### `traffic_flood_example` — disabled

- **Purpose/type:** `network` / `traffic_flood`; Alert type `traffic_flood`.
- **Events/fields:** recognized IPv4 TCP/UDP network events with usable IPs;
  `protocol: OTHER` is excluded. Unlike the SYN rule, flags and destination port
  do not restrict the match.
- **Grouping:** `(src_ip, dst_ip)`, including matching TCP and UDP activity.
- **Confirmation:** 2000 matching events within 5 seconds (average equivalent
  400 events/second over that window).
- **Finalization:** quiet 3 seconds; maximum confirmed lifetime 60 seconds.
- **Example:** a source sends 2200 observed UDP packets to one destination within
  five seconds. If enabled and then quiet, this produces a 50/High Alert.

This is an example, not a general-purpose bandwidth detector. It counts packet
events, not bytes. Enable only after tuning for your monitored environment.

### `process_example` — disabled

- **Purpose/type:** `process` / `process_match`; Alert type `process_match`.
- **Events/fields:** `process_exec` with `process_name` exactly `example-tool`.
  Supported selectors are `process_name` and `process_path`.
- **Grouping/threshold/timing:** none; one matching execution produces an Alert.
- **Example:** after configuring a relevant command name and enabling the rule,
  execution with that exact observed name produces 30/Medium.

Names/paths are exact allow-lists, not glob/regex patterns. Names are limited to
15 characters by the parser and the sensor's command-name constraints. The
reported exec filename is not guaranteed to be a canonical absolute path.

### `denied_credential_syscall` — enabled

- **Purpose/type:** `syscall` / `syscall_match`; Alert type `syscall_match`.
- **Events/fields:** `syscall_event`, `syscall` in `[setuid, setgid]` **and**
  `metadata.syscall_return` in `[-1]` (negative EPERM, permission denied).
- **Grouping/threshold/timing:** none; immediate per matching completed syscall.
- **Example:** a process attempts a monitored UID change without permission; a
  returned `-1` produces 20/Medium. Another negative errno does not match this rule.

Supported selectors: `syscall`, `syscall_return`, `uid`, `gid`, `process_name`.
`syscall` is required, and only the currently monitored `setuid`/`setgid` names
are accepted. Values within a list are alternatives; different selector fields
must all match. This is selected credential-syscall telemetry, not every syscall.

### `uid_change_to_root` — enabled

- **Purpose/type:** `privilege` / `privilege_change`; Alert type `privilege_change`.
- **Events/fields:** `privilege_change`, current `uid` in `[0]`, and
  `uid_changed: true` comparing current UID to `metadata.previous_uid`.
  The sensor emits these records for successful monitored credential transitions.
- **Grouping/threshold/timing:** none; immediate per matching event.
- **Example:** a process with the required privileges successfully performs a
  monitored `setuid(0)` transition from effective UID 1000. It scores 75/High.
  Already being UID 0 does not satisfy the UID-changed condition.

Supported selectors: `syscall`, `uid`, `gid`, `previous_uid`, `previous_gid`,
`process_name`, `uid_changed`, `gid_changed`. Changed selectors are booleans;
other selectors are nonempty lists. At least one credential condition is required.
This rule is not proof of exploitation and does not capture every route to root.

## Scoring (`scoring.yaml`)

**Detection comes first.** Scoring assigns risk to a finalized detection; raising
a score does not make a rule match more traffic. Each of the six families must
appear in `scoring`. Scores are clamped to 0–100, with these fixed severity bands:

| Score | Severity |
| --- | --- |
| 0–19 | Low |
| 20–49 | Medium |
| 50–79 | High |
| 80–100 | Critical |

### Scan scope

`port_scan.base_score` is 30. Tier `score` values are **absolute scores**, not
bonuses; choose the highest reached `min_unique_ports` tier:

| Final distinct ports | Score/severity |
| --- | --- |
| Below 20 (but detection confirmed) | 30/Medium |
| 20–49 | 35/Medium |
| 50–99 | 40/Medium |
| 100–199 | 45/Medium |
| 200+ | 49/Medium |

The parser requires port-scan base/tier scores in 20–49, strictly increasing port
boundaries and nondecreasing scores. Do not try to tune scan severity to High via
unsupported tier values.

### SYN and traffic volume

For `syn_flood`, base is **60**. At finalization, compare
`matching_event_count` with the rule's `threshold`:

| Final count at threshold 1000 | Applied tier | Score |
| --- | --- | --- |
| 1000–1999 | base only | 60/High |
| 2000–4999 | 2× threshold: +10 | 70/High |
| 5000+ | 5× threshold: +20 | 80/Critical |

Only the highest reached volume bonus applies: 5× gives +20, **not +10+20**.
The session can accumulate beyond the confirmation window after confirming.
`traffic_flood` uses base 50 with the same 2×/+10 and 5×/+20 scheme; with its
threshold 2000, counts 2000/4000/10000 produce scores 50/60/70 respectively.

### Host scoring

- `process_match`: base 30; no configured modifiers.
- `syscall_match`: base 20; no configured modifiers.
- `privilege_change`: base 50, plus `root_uid_points: 25` when previous UID is
  nonzero and current UID is zero. The shipped root-transition rule yields 75/High;
  other privilege rules without that transition use the base.

Prefer changing family scoring here. `rules.yaml` supports an advanced optional
`base_score` override, but a port-scan override must equal its configured family
base or runtime scoring rejects it. The validator checks the actual parsers; it
is not a traffic simulation or a guarantee that arbitrary policies are useful.
Leave this override absent in the beginner workflow.

## Correlation (`correlation.yaml`)

Finalized Alerts are evaluated first; correlation does not consume packet Events
or change their detection scores. The exact current policy is:

| Family | Enabled | Window | Group and eligibility |
| --- | --- | --- | --- |
| `network_sequence` | true | 60 seconds | Same `(src_ip, dst_ip)`; at least two different network Alert types from scan/SYN/traffic flood. |
| `host_sequence` | true | 30 seconds | Same `pid`; at least two different host Alert types from process/syscall/privilege. |
| `hybrid_activity` | true | 60 seconds | `(src_ip, dst_ip, pid)` context: flood score ≥50 targeting an explicitly monitored local IP plus successful non-root→root Alert score ≥50. |

Windows use finalized Alert monotonic timestamps, include their endpoints, and
bound the complete Incident span; repeated updates do not extend a fixed sequence
forever. A given Alert is used at most once per correlation family. The engine is
for one serial host/boot stream, not cross-host or PID-reuse-proof attribution.

`monitored_ips: []` means **hybrid matching is effectively disabled** even though
its family's `enabled` flag is true. Set actual IPv4 addresses assigned to this
monitored host to allow hybrid matching; observed traffic is not ownership proof.
The shipped bounds are 1024 pending Alerts, 256 open Incidents, 128 Alerts per
Incident and 4096 replay IDs. Keep them bounded; parser limits are enforced.

All Incident types score:

```text
min(100, highest member Alert score + 5)
```

A scan 40 plus SYN flood 60 becomes one 65/High network Incident when the IP pair
and 60-second window match. Two Alerts do not automatically mean one Incident:
the grouping, different-type and time requirements must also hold.

**Hybrid correlation is contextual/temporal. It does not prove exact
process-to-network attribution.** The current sensors do not link each observed
network packet to the process that caused it. These windows are configurable
defaults, not universal optimal values.

## Safe editing examples

These are edits to an existing field/block, not extra top-level YAML documents.
Keep the remaining required fields intact.

### Change the SYN confirmation threshold

In the `syn_flood_basic` rule, replace its current threshold with:

```yaml
threshold: 2000
```

At the unchanged 5-second window this is an average equivalent of 400 SYNs/second.
Scoring multiples now refer to 2000, so 2×/5× mean 4000/10000 final session events.

```bash
make validate-config
```

### Disable a rule

Inside the chosen rule, set:

```yaml
enabled: false
```

Do not delete required fields from disabled rules; they are still validated.

```bash
make validate-config
```

### Change a correlation window

Edit the existing `network_sequence` block under `correlation`:

```yaml
correlation:
  network_sequence:
    enabled: true
    window_seconds: 90
```

Retain `host_sequence`, `hybrid_activity`, `limits`, `monitored_ips` and
`schema_version`; the snippet is not a complete file.

```bash
make validate-config
```

### Change a host family score

In the existing scoring document:

```yaml
scoring:
  syscall_match:
    base_score: 25
```

Retain all other families. This changes risk after detection, not syscall matching.

```bash
make validate-config
```

Finally stop/restart the launcher and verify on an authorized lab workload. Back
up your YAML or review `git diff -- config/` before sharing changes. Validation
reports structural errors but cannot determine a suitable baseline threshold,
actual sensor support, traffic visibility, or whether an IP belongs to your host.
