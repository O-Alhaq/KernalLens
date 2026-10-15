## 1. Project definition

**KernelLens: A Real-Time eBPF-Based Telemetry Framework for Hybrid Host and Network Threat Detection**

KernelLens will run primarily on a single Ubuntu machine and use eBPF to collect both network-level and host/runtime telemetry. A second Ubuntu VM may be used as an attacker/test machine.

The system will use eBPF for efficient kernel-level telemetry and selected enforcement, while detection, correlation, scoring, storage, and response orchestration will primarily happen in user space.

## 2. Core scope

| Area                 | Core functionality                               |
| -------------------- | ------------------------------------------------ |
| Network telemetry    | XDP-based monitoring                             |
| Network detection    | Port scan and flood detection                    |
| Host telemetry       | Process monitoring                               |
| Runtime telemetry    | selected security-relevant syscall monitoring    |
| Privilege monitoring | Privilege-escalation detection                   |
| Detection            | Rule-based                                       |
| Correlation          | Hybrid host/network correlation                  |
| Kernel state         | eBPF maps                                        |
| Risk                 | Point-based scoring + severity                   |
| Alerts               | Real-time                                        |
| Dashboard            | React-based                                      |
| Network response     | Manual block/unblock and other selected controls |
| Host response        | Process and file actions                         |
| Evaluation           | Performance metrics                              |

## 3. Later scope

|Later feature|Purpose|
|---|---|
|Automatic IP blocking|Automated network response|
|Process lineage|Parent/child process chains|
|Process-to-network correlation|Connect network activity directly to processes|
|Automated response|Rules automatically trigger response|
|VirusTotal enrichment|External reputation information|
|AI alert analysis|Explain/summarize alerts|

## 4. Technology stack

| Component                  | Decision                                             |
| -------------------------- | ---------------------------------------------------- |
| OS                         | **Ubuntu 26.04 LTS**                                 |
| Kernel                     | **7.0.0-34-generic**                                 |
| eBPF language              | **C**                                                |
| eBPF framework             | **libbpf + CO-RE**                                   |
| User-space eBPF controller | **Small C agent**                                    |
| Compiler                   | **Clang/LLVM**                                       |
| eBPF debugging/inspection  | **bpftool**                                          |
| Network monitoring         | **XDP**                                              |
| Host instrumentation       | **Tracepoints primarily; kprobes where necessary**   |
| Kernel state               | **eBPF maps**                                        |
| Kernel → agent events      | **BPF ring buffer**                                  |
| Agent ↔ Python             | **Unix domain socket**                               |
| Agent ↔ Python format      | **JSON initially**                                   |
| User-space security logic  | **Python**                                           |
| Backend                    | **FastAPI**                                          |
| Real-time transport        | **WebSockets**                                       |
| Database                   | **SQLite**                                           |
| Frontend                   | **React**                                            |
| Container runtime          | **Docker**                                           |
| Configuration/rules        | **YAML**                                             |
| Source control             | **Git + GitHub**                                     |
| Testing                    | **pytest + controlled Linux/network security tests** |
| Build                      | **Makefile initially**                               |


## 5. Architecture

                             Ubuntu Host
                                 │
                ┌────────────────┴────────────────┐
                │                                 │
         NETWORK TELEMETRY                  HOST TELEMETRY
                │                                 │
             NIC/XDP                      Tracepoints / kprobes
                │                                 │
       eBPF network programs                eBPF host programs
                │                                 │
                │                       ┌─────────┼──────────┐
                │                       │         │          │
                │                   Processes  Syscalls  Privileges
                │                       │         │          │
                └──────────────┬────────┴─────────┴──────────┘
                               │
                        Maps + Ring Buffer
                               │
                         C libbpf Agent
                               ⇅
                      Unix Domain Socket
                               ⇅
                      Python Security Core
                               │
            ┌──────────────────┼────────────────────┐
            │                  │                    │
       Rule Engine       Correlation Engine    Scoring Engine
            │                  │                    │
            └──────────────────┼────────────────────┘
                               │
                         Alert / Incident
                               │
                 ┌─────────────┼──────────────┐
                 │             │              │
             Database      Response       FastAPI
              SQLite        Engine         │
                                            │
                                    ┌───────┴────────┐
                                    │                │
                                   REST          WebSockets
                                    │                │
                                    └───────┬────────┘
                                            │
                                     React Dashboard


## 6. Module responsibilities

#### eBPF programs
	packet inspection
	packet metadata
	process events
	selected runtime events
	privilege-related events
	counters
	map lookups
	simple enforcement

#### C libbpf agent
	Load eBPF programs
	Attach eBPF programs
	Read ring-buffer events
	Manage eBPF maps
	Send events to Python
	Receive eBPF-related commands from Python
	Report sensor status/errors


#### Python security core
	event normalization
	rule evaluation
	event correlation
	risk scoring
	alert generation
	incident management
	host response
	database interaction

#### FastAPI
	GET alerts
	GET incidents
	GET metrics
	GET blocked IPs
	
	POST block IP
	POST unblock IP
	POST kill process
	POST quarantine file
	
	WebSocket real-time alerts

## 7. Unified event model
	SecurityEvent
	
	event_id
	timestamp
	
	event_type
	event_category
	source
	
	pid
	ppid
	uid
	gid
	
	process_name
	process_path
	
	src_ip
	dst_ip
	src_port
	dst_port
	protocol
	tcp_flags
	interface
	
	syscall
	
	container_id
	cgroup_id
	
	metadata


## First detection categories
|Domain|Detection|
|---|---|
|Network|Port scan|
|Network|SYN/traffic flood|
|Host|Suspicious process activity|
|Host|Selected sensitive syscall activity|
|Host|Privilege escalation|
|Hybrid|Correlated host/network suspicious activity|

## Scoring system
|Score|Severity|
|--:|---|
|0–19|Low|
|20–49|Medium|
|50–79|High|
|80–100|Critical|

## Hybrid correlation
	time proximity
	event type
	frequency
	source IP where applicable
	host identity
	related suspicious behavior

## Database model

|Data|Purpose|
|---|---|
|`events`|Selected/raw security telemetry|
|`alerts`|Rules that triggered|
|`incidents`|Correlated alerts|
|`incident_alerts`|Connect alerts to incidents|
|`blocked_ips`|Current network block state|
|`response_actions`|Actions performed|
|`performance_metrics`|System measurements|
|`audit_log`|Administrative/security actions|

## Response system
network response:
	Block IP
	Unblock IP
	Temporary block
	Temporary allowlist
	Rate limit
	Remove rate limit
	Drop matching malicious traffic
Host responses:
	Kill process
	Suspend process
	Resume process
	Quarantine file
	Delete file
	Pause container
	Stop container

## Response safety

	Detection = automatic
	
	Alert generation = automatic
	
	Response = primarily manual
Later:
	Automatic response
## Dashboard

| View             | Function                                   |
| ---------------- | ------------------------------------------ |
| Overview         | Current system/security status             |
| Real-time alerts | Live alert feed                            |
| Alert details    | Evidence, score, related events, responses |
| Incidents        | Correlated alerts                          |
| Blocked IPs      | View/add/remove blocks                     |
| Responses        | Perform manual actions                     |
| Performance      | CPU, memory, throughput, latency           |
| Events           | Optional raw/filtered telemetry viewer     |
| Settings         | Threshold/configuration management later   |

Later:
	VirusTotal enrichment
	AI explanation

## Performance metrics

|Metric|Meaning|
|---|---|
|CPU utilization|KernelLens CPU cost|
|Memory utilization|Memory overhead|
|Packets/sec|Network processing ability|
|Events/sec|Host telemetry throughput|
|Detection latency|Event → alert|
|Dashboard latency|Alert → dashboard|
|Ring-buffer dropped events|Telemetry loss|
|Packet drops|Network behavior|
|False positives|Incorrect alerts|
|False negatives|Missed attacks|
## Container scope
	
	Recognize container-related processes
	
	Associate events with container_id/cgroup_id where possible
	
	Allow pause/stop container as a response
More advanced container behavioral detection can come later.

## Explicitly out of scope

	Distributed/multi-host KernelLens agents
	Kubernetes
	SmartNIC acceleration
	Full deep-packet inspection
	Full SIEM functionality
	Enterprise multi-tenancy
	In-kernel machine learning
	Large-scale cloud deployment
	Automatic destructive response in v1

The platform uses a configurable heuristic risk-scoring model. Each detection rule is assigned a base score, while contextual factors such as event repetition, cross-domain correlation, and related suspicious activity adjust the final score. The resulting score is mapped to a severity category.

KernelLens should not push complexity into eBPF merely because eBPF can perform the operation. Kernel-space programs should remain focused on efficient telemetry collection, state tracking, and selected enforcement, while complex detection, correlation, scoring, storage, and response orchestration should remain in user space.

## Milestones

|Milestone|Goal|Main deliverables|Completion criteria|
|---|---|---|---|
|**M1 – Project Foundation**|Prepare the development environment and repository structure|Repo folders, Makefile, config structure, build dependencies, basic README|Project builds cleanly; eBPF toolchain and bpftool are verified|
|**M2 – Basic eBPF Event Pipeline**|Prove end-to-end kernel → userspace telemetry|Minimal eBPF program, ring buffer, C libbpf agent, one event type|An event generated in the kernel is received and printed by the C agent|
|**M3 – C Agent ↔ Python IPC**|Connect the eBPF side to the Python security core|Unix domain socket, JSON message protocol, Python receiver, status/response messages|Python successfully receives validated events from the C agent|
|**M4 – Network Telemetry**|Implement the core XDP monitoring path|XDP packet parsing, network event structure, eBPF maps/counters|Python receives network telemetry with src/dst IP, ports, protocol, TCP flags|
|**M5 – Host Telemetry**|Implement core host/runtime monitoring|Process events, selected syscall events, privilege-related events|Python receives normalized process/syscall/privilege events|
|**M6 – Unified Event Pipeline**|Normalize all telemetry into the SecurityEvent model|Common schema, validation, event routing, error handling|Network and host telemetry enter Python using the same normalized model|
|**M7 – Persistence and API Foundation**|Store and expose KernelLens data|SQLite schema, event/alert models, FastAPI REST endpoints|Events can be stored and queried through the API|
|**M8 – Rule Engine**|Build detection infrastructure and initial rules|YAML rule loading, rule evaluation, port scan, SYN/flood, host rules|Selected test scenarios generate expected alerts|
|**M9 – Scoring and Severity**|Implement heuristic risk scoring|Base scores, modifiers, 0–100 cap, Low/Medium/High/Critical mapping|Alerts receive reproducible scores and severity levels|
|**M10 – Hybrid Correlation**|Correlate related host/network security events|Correlation windows, related-alert grouping, incident creation|Multiple related alerts can be grouped into a single incident|
|**M11 – Real-Time Dashboard**|Create operator-facing visibility|React dashboard, alert feed, alert details, blocked IP view, performance tab|New alerts appear in real time through WebSockets|
|**M12 – Manual Response**|Add controlled network and host response|Block/unblock, temporary block, rate limit, kill/suspend, quarantine/delete, container pause/stop|Actions can be launched from the dashboard and are audit logged|
|**M13 – Performance Monitoring**|Measure KernelLens itself|CPU, memory, events/sec, packets/sec, latency, dropped events|Metrics are stored and displayed on the dashboard|
|**M14 – Validation and Evaluation**|Test the full platform under controlled scenarios|Network tests, host tests, false-positive tests, baseline comparison|Results are documented and suitable for the graduation report|
|**M15 – Optional Enhancements**|Implement later features only if core is stable|Process lineage, process-to-network correlation, VirusTotal, auto response, AI analysis|Optional and not required for v1 completion|

```
KernelLens v1 is complete when:

- Network and host telemetry are collected successfully
- Events reach the Python security core
- Detection rules generate alerts
- Alerts receive severity scores
- Related alerts can form incidents
- Dashboard receives alerts in real time
- Manual network and host responses work
- Response actions are audit logged
- Performance metrics are collected
- Controlled evaluation has been completed
```