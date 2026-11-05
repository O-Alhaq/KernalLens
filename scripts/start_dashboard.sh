#!/usr/bin/env bash
# Keep terminal signals connected to the supervisor and wait for its cleanup.
set -u
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." || exit 1
python="${KERNELLENS_DASHBOARD_PYTHON:-${PYTHON:-.venv/bin/python}}"
if [[ ! -x "$python" ]]; then
    echo '[KernelLens] Missing Python venv. Run ./scripts/setup.sh first.' >&2
    exit 1
fi
"$python" -B scripts/dashboard_runtime.py "$@" &
supervisor=$!
stop_requests=0
forward_stop() {
    stop_requests=$((stop_requests + 1))
    kill -TERM "$supervisor" 2>/dev/null || true
}
cleanup() {
    trap - EXIT INT TERM HUP
    forward_stop
    wait "$supervisor" 2>/dev/null || true
}
trap forward_stop INT TERM HUP
trap cleanup EXIT
# A trapped signal interrupts Bash's wait before the supervisor has finished.
# Re-wait only after that interruption; propagate the supervisor's actual result.
while :; do
    requests_before_wait=$stop_requests
    wait "$supervisor"
    result=$?
    if (( stop_requests == requests_before_wait )); then
        break
    fi
done
trap - EXIT INT TERM HUP
if (( stop_requests > 0 && result == 0 )); then
    echo '[KernelLens] KernelLens stopped.'
fi
exit "$result"
