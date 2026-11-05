# Setting up KernelLens

KernelLens is a single-host Linux security observatory. It collects network and
selected host activity, detects configured patterns, scores Alerts, correlates
Incidents, and displays persisted evidence in a local read-only dashboard. It
currently has no blocking or other response controls.

## Supported platform

The automatic setup target is **Ubuntu 26.04 LTS**, matching the current development
system (Ubuntu 26.04.1, generic 7.0 kernel). Other distributions/releases are not
claimed to be automatically supported. Use an ordinary user account with sudo
access, an internet connection to Ubuntu/Python/npm registries, and a graphical
desktop if you want automatic browser opening.

**eBPF** (extended Berkeley Packet Filter) runs small verified programs inside the
Linux kernel. **XDP** (eXpress Data Path) is an early incoming-packet hook used by
the network sensor; the interface/driver must support the agent's native XDP BPF
link attachment. A supported kernel must expose BTF (BPF Type Format) at
`/sys/kernel/btf/vmlinux`, support BPF ring buffers/task helpers and syscall
tracepoints, and permit privileged attachment. VM drivers, restricted containers,
kernel lockdown or security policy can prevent attachment even when a build works.
Do not disable security policy blindly to bypass a load error.

Host capture needs `sched_process_exec`, `sched_process_exit`, and entry/exit
tracepoints for `setuid` and `setgid`, including `CONFIG_FTRACE_SYSCALLS=y`.
Tracefs is often root-readable; setup does not change its permissions. The agent
checks actual attachment at runtime and fails with cleanup if required hooks
cannot attach. Setup does not load an eBPF program or prove driver compatibility.

## Clone and prepare

```bash
git clone https://github.com/O-Alhaq/KernalLens.git
cd KernalLens
./scripts/setup.sh
```

The repository directory is spelled `KernalLens`; the product name is KernelLens.
Do not run setup, pip, npm or the complete dashboard with sudo.

Setup performs these steps:

1. Check Ubuntu 26.04, readable kernel BTF and available kernel configuration.
2. Check existing build/venv/dependency directories belong to your user; refuse
   unsafe symlinked output directories or another user's artifacts.
3. Print missing Ubuntu packages and ask before installing them. Only this step
   uses `sudo apt-get update/install`; no repository is added or OS upgrade run.
4. Verify clang's BPF backend, bpftool and libbpf/libelf through actual commands.
5. Create `.venv` if absent, otherwise reuse a valid existing venv. Install
   `requirements-dev.txt` there (which includes runtime requirements), then run
   `pip check`. Already satisfied Python packages are reused.
6. Require Node 22.12+ and select npm 10+ if available. If Ubuntu's npm is older,
   install **npm 11 locally under `.tools/npm`**, using the normal user. Global npm
   is untouched. No downloaded shell installer is executed.
7. Reuse a valid `frontend/node_modules` tree when manifests have not changed.
   Verify with npm's dependency-tree check. Otherwise run lockfile-based `npm ci`,
   which replaces an incomplete/outdated tree. A hash under `.tools` tracks
   manifest changes; no project lockfile is regenerated.
8. Run incremental `make all` and the actual configuration loaders. Print readiness
   and the next command, without starting capture/dashboard.

Running setup twice preserves the venv, database, configuration, valid dependency
tree and up-to-date build outputs. It does not reset Git changes or history.
Setup output includes underlying package/build errors for diagnosis.

Read-only OS preflight (not a complete dependency/build validation):

```bash
./scripts/setup.sh --check
```

To preapprove the **printed** missing-package list in an unattended setup:

```bash
./scripts/setup.sh --yes
```

Without `--yes`, noninteractive setup fails rather than silently installing OS
packages. Network downloads and Python/frontend dependency installation are part
of normal setup. Review package/lockfile changes before rerunning on an untrusted
checkout. Setup never repairs arbitrary ownership with recursive sudo chown.

## Dependencies and manual preparation

Ubuntu package names used by setup:

```text
build-essential make clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev
pkg-config python3 python3-venv python3-pip nodejs npm iproute2 ca-certificates
```

Optional `xdg-utils` supplies `xdg-open`; a browser is optional and setup does not
install one. `git` is needed for the initial clone. The bundled `vmlinux.h` and
Makefile provide the existing build path; setup does not regenerate kernel types
or alter kernel boot settings. The Python code needs Python 3.10+; Ubuntu 26.04's
system Python is used to create the venv. Frontend versions come from the committed
lockfile, with Node/npm minimums also declared in `frontend/package.json`.

If Node is too old after package preparation, install a supported version as a
normal user from the [official Node.js download page](https://nodejs.org/en/download/)
and rerun setup. Setup does not add a third-party apt repository. See also the
[official npm installation guide](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm/)
and [Ubuntu package management guide](https://ubuntu.com/server/docs/how-to/software/package-management/).
The packaged bpftool for this target is listed in
[Ubuntu's package catalogue](https://packages.ubuntu.com/resolute/bpftool).

After manually installing OS dependencies, the equivalent project steps are:

```bash
python3 -m venv .venv                  # only if absent
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip check
# With a supported npm, or use setup's project-local npm preparation:
npm --prefix frontend ci
make
make validate-config
```

Do not use system npm 9 for the frontend resolver. `npm ci` replaces the existing
node_modules tree; prefer the idempotent setup script for routine repeated setup.
Python dependencies are bounded by requirements, not an exact platform lock;
OS/Python registry availability and versions can vary.

## Start, observe and stop

```bash
make validate-config
make dashboard
```

The foreground launcher detects the unique lowest-metric default-route interface,
builds incrementally, authenticates sudo once, starts the C agent with host capture,
prepares socket access, then starts receiver, FastAPI and Vite. Each stage has a
bounded readiness wait. It verifies the receiver's ready handshake, API health,
and frontend HTTP response before opening a browser.

Overrides can be combined:

```bash
make dashboard INTERFACE=ens33
make dashboard DATABASE=/tmp/test.db
make dashboard OPEN_BROWSER=0
make dashboard INTERFACE=ens33 DATABASE=/tmp/test.db OPEN_BROWSER=0
```

Use the actual interface from `ip -brief link`; `ens33` is only an example.
To select another prepared interpreter, use `DASHBOARD_PYTHON=/absolute/path/to/python`.
Stop with **Ctrl+C in the same terminal**. Clean intentional shutdown returns zero,
prints `KernelLens stopped.`, and leaves genuine failures non-zero. SIGTERM/startup
failure also invoke cleanup. Only launcher-owned PIDs/groups are stopped; existing
services are never killed to make ports available. The receiver's existing flush
path and the agent's detach/socket cleanup are retained.

The normal user owns receiver/API/Vite, configuration, logs and SQLite. Only the
C agent and required runtime/socket helper are privileged. A control pipe lets the
helper stop the agent without another sudo prompt after a long session. Do not
run `sudo make dashboard`.

## Paths and addresses

| Item | Default/location |
| --- | --- |
| Dashboard | `http://127.0.0.1:5173/` |
| API and health | `http://127.0.0.1:8000`, `/health` |
| WebSocket | `ws://127.0.0.1:8000/ws/live` |
| SQLite | `/tmp/kernellens.db` (override with `DATABASE`) |
| Telemetry Unix socket | `/run/kernellens/events.sock` |
| Logs | `/tmp/kernellens-runtime-<uid>/run-<unique>/`, printed at startup |
| Local tooling/state | `.venv/`, `frontend/node_modules/`, `.tools/`, `build/` |

A **Unix domain socket** is a local process-to-process connection represented by
a filesystem path. Here it carries agent telemetry to the receiver. A **WebSocket**
is a persistent browser/server connection; here FastAPI sends live database changes
to React, which also loads history through ordinary HTTP requests.

Logs are `dependencies.log`, `build.log`, `agent.log`, `receiver.log`, `api.log`,
`frontend.log` and optional `browser.log`. Detailed events stay in logs rather than
flooding the terminal. Logs and authoritative history grow; no rotation is added.
`/tmp` is disposable and may be cleared by the OS: choose a writable persistent
`DATABASE` location for history that must survive cleanup/reboot. Both receiver and
API always use the same absolute database path supplied by the launcher.

The development helper uses a root-owned real `/run/kernellens`, mode 0711, and
an operator-owned socket, mode 0660. It refuses active sockets, symlinks and unsafe
directories. A real stale socket is removed only if absent from `/proc/net/unix`.
This is a development/demo policy, not a production systemd service design.
The dashboard is local and unauthenticated; do not expose it publicly.

## Troubleshooting

### No default network interface

Inspect `ip route show default` and `ip -brief link`. If the route is absent or
ambiguous, choose the intended monitored interface explicitly with `INTERFACE`.
A VPN/tunnel may be the default without supporting native XDP; choose an appropriate
physical/VM Ethernet interface for the authorized lab.

### Sudo, eBPF or kernel permission errors

Run as the normal user from an interactive terminal with sudo access. Read
`agent.log` for the load/attach error. A successful build alone is insufficient.
Check BTF, kernel feature availability and driver XDP support. Use a supported
Ubuntu generic kernel/VM; obtain administrator guidance for lockdown/container
restrictions rather than changing broad permissions or disabling protections.

### Runtime socket problems

Check for an existing agent before retrying. Do not delete an actively owned socket
or run a second receiver against it. The launcher refuses conflicts and cleans
its own socket on normal shutdown. An unsafe/non-root-owned `/run/kernellens`
requires administrator inspection and correction of that exact runtime directory;
never recursively chown `/run` or make it world-writable. Check `agent.log` and
`receiver.log`. This policy is already automated by the launcher; repeated manual
chmod/chown should not be part of normal startup.

### Root-owned or readonly SQLite/WAL/SHM

Stop processes using the database first. Inspect the exact file and its `-wal` /
`-shm` sidecars with `ls -l`. Use a new user-owned path, for example
`make dashboard DATABASE="$HOME/kernellens-demo.db"`, or ask the administrator to
repair only the confirmed project database files. Do not delete arbitrary data or
run receiver/API with sudo. Setup/launcher refuse unsafe ownership; they do not
silently recreate an existing database.

### Port 8000 or 5173 occupied

Use `ss -ltnp` to identify the owning service. Deliberately stop your old development
session or choose when to run KernelLens. The launcher will not kill unrelated
Python/Node processes and Vite will not silently switch ports. Fixed ports and the
shared socket support one complete local stack at a time.

### Missing venv, Node/npm or frontend modules

Run `./scripts/setup.sh` from the repository. Check `node --version` (22.12+) and
npm output. The setup-local npm is invoked as
`node .tools/npm/node_modules/npm/bin/npm-cli.js --version` when global npm is old.
If the venv is incomplete or outputs are owned by root, inspect and repair that
specific artifact; setup will not delete/recreate an existing venv or recursively
change project ownership. Do not use sudo pip/npm. Registry/network failures must
be fixed before retrying; use your institution's approved network/proxy settings.

### Agent build or unsupported functionality

Read the setup output / `build.log`. Verify `clang -target bpf`, `bpftool version`,
`pkg-config --modversion libbpf`, and the installed development packages. Missing
Ubuntu package candidates may require enabling the appropriate official Ubuntu
package component through your administrator; setup does not add repositories.
Do not run `make clean` routinely: incremental builds are intended. Unsupported
kernel hooks or interface attachment need an appropriate kernel/interface, not a
change to detection policy. Actual privileged load/attachment validation remains
a manual operator step through `make dashboard`.

### Configuration rejected or no expected Alert

Run `make validate-config`, then follow [RULES.md](RULES.md). Syntax acceptance does
not prove traffic is visible or thresholds are suitable. Network sessions publish
after quiet/maximum finalization; API Online/Live Connected indicate database and
browser stream status, not proof that every packet was captured. Security time is
monotonic nanoseconds since boot; Amman calendar display uses independent persisted
UTC times. Legacy records can display `Time unavailable`.

## Regression checks

```bash
make validate-config
make test PYTHON=.venv/bin/python
npm --prefix frontend test
npm --prefix frontend run build
git diff --check
```

If global npm is 9, use `node .tools/npm/node_modules/npm/bin/npm-cli.js --prefix frontend test`
and the equivalent `run build` invocation. No npm/global upgrade is necessary.
Privileged M2–M5 tests are separate, **manual**, and must use an authorized lab:

```bash
sudo make test-m2
sudo make test-m3
sudo make test-m4
sudo make test-m5
```

Setup and the non-privileged suite do not run these commands automatically.
