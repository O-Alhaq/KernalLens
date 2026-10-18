#!/usr/bin/env bash
# Root is required; all interfaces are created inside a disposable namespace.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${1:-} != --isolated ]]; then
    if [[ $EUID != 0 ]]; then
        echo 'Run sudo make test-m2, test-m3, or test-m4 (requires BPF and network administration privileges).' >&2
        exit 1
    fi
    exec unshare --net bash "$0" --isolated
fi

test_dir=$(mktemp -d)
agent_pid=
sender_pid=
receiver_pid=
traffic_pid=
cleanup() {
    if [[ -n $traffic_pid ]]; then
        kill -TERM "$traffic_pid" 2>/dev/null || true
        wait "$traffic_pid" 2>/dev/null || true
    fi
    if [[ -n $receiver_pid ]]; then
        kill -TERM "$receiver_pid" 2>/dev/null || true
        wait "$receiver_pid" 2>/dev/null || true
    fi
    if [[ -n $agent_pid ]]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
    fi
    if [[ -n $sender_pid ]]; then
        kill -TERM "$sender_pid" 2>/dev/null || true
        wait "$sender_pid" 2>/dev/null || true
    fi
    rm -rf "$test_dir"
}
trap cleanup EXIT

ip link add kl-send type veth peer name kl-recv
# Keep sender and receiver in different namespaces so traffic crosses the veth
# instead of taking the kernel's local-delivery shortcut.
unshare --net sh -c 'touch "$1"; exec sleep 120' sh "$test_dir/sender-ready" &
sender_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
    [[ -e $test_dir/sender-ready ]] && break
    sleep 0.05
done
test -e "$test_dir/sender-ready"
ip link set kl-send netns "$sender_pid"
nsenter -t "$sender_pid" -n ip address add 192.0.2.1/24 dev kl-send
nsenter -t "$sender_pid" -n ip link set kl-send up
ip address add 192.0.2.2/24 dev kl-recv
ip link set kl-recv up
expected_ifindex=$(ip -o link show kl-recv | awk -F': ' '{print $1}')

ipc_arguments=()
if [[ ${KERNELLENS_TEST_M3:-0} == 1 ]]; then
    ipc_arguments=("$test_dir/agent.sock")
fi
./build/kernellens-agent kl-recv "${ipc_arguments[@]}" >"$test_dir/events" 2>"$test_dir/agent.log" &
agent_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
    if grep -q 'Attached XDP_PASS' "$test_dir/agent.log"; then
        break
    fi
    if ! kill -0 "$agent_pid" 2>/dev/null; then
        cat "$test_dir/agent.log" >&2
        exit 1
    fi
    sleep 0.05
done
grep -q 'Attached XDP_PASS' "$test_dir/agent.log"
if [[ ${KERNELLENS_TEST_M3:-0} == 1 ]]; then
    timeout 45 python3 backend/receiver.py "$test_dir/agent.sock" >"$test_dir/python.events" 2>"$test_dir/python.log" &
    receiver_pid=$!
    for ((attempt=0; attempt<100; attempt++)); do
        grep -q 'Agent status: ready' "$test_dir/python.log" && break
        sleep 0.05
    done
    grep -q 'Agent status: ready' "$test_dir/python.log"
fi

# A second instance must fail without replacing the first instance's program.
if timeout --signal=TERM 3 ./build/kernellens-agent kl-recv >"$test_dir/second.out" 2>"$test_dir/second.log"; then
    echo 'FAIL: second attachment unexpectedly succeeded' >&2
    exit 1
fi
grep -q 'Cannot attach XDP' "$test_dir/second.log"
nsenter -t "$sender_pid" -n ping -I kl-send -c 3 -W 2 192.0.2.2
if [[ ${KERNELLENS_TEST_M4:-0} == 1 ]]; then
    python3 tests/network_traffic.py server --ready "$test_dir/traffic-ready" >"$test_dir/traffic.log" 2>&1 &
    traffic_pid=$!
    for ((attempt=0; attempt<100; attempt++)); do
        [[ -e $test_dir/traffic-ready ]] && break
        sleep 0.05
    done
    test -e "$test_dir/traffic-ready"
    nsenter -t "$sender_pid" -n python3 tests/network_traffic.py client
    wait "$traffic_pid"
    traffic_pid=
    for ((attempt=0; attempt<100; attempt++)); do
        python3 tests/check_network_events.py "$test_dir/python.events" "$expected_ifindex" --quiet && break
        sleep 0.05
    done
    python3 tests/check_network_events.py "$test_dir/python.events" "$expected_ifindex"
fi
for ((attempt=0; attempt<100; attempt++)); do
    if grep -q 'packet_length=98$' "$test_dir/events"; then
        break
    fi
    sleep 0.05
done
kill -INT "$agent_pid"
wait "$agent_pid"
agent_pid=
cat "$test_dir/agent.log"
cat "$test_dir/events"
awk -v idx="$expected_ifindex" '
    /^timestamp=[0-9]+ ifindex=[0-9]+ packet_length=[0-9]+$/ {
        split($1, ts, "="); split($2, iface, "="); split($3, len, "=");
        if (ts[2] > 0 && iface[2] == idx && len[2] == 98) found=1;
    }
    END { exit !found }
' "$test_dir/events"
grep -q 'Detached XDP' "$test_dir/agent.log"
if [[ ${KERNELLENS_TEST_M4:-0} == 1 ]]; then
    grep -Eq 'Telemetry: packets=[1-9][0-9]* bytes=[1-9][0-9]* ipv4=[1-9][0-9]* tcp=[1-9][0-9]* udp=[1-9][0-9]*' "$test_dir/agent.log"
fi
if [[ ${KERNELLENS_TEST_M3:-0} == 1 ]]; then
    wait "$receiver_pid"
    receiver_pid=
    test ! -e "$test_dir/agent.sock"
    python3 - "$test_dir/python.events" "$expected_ifindex" <<'PY'
import json
import sys
from backend.receiver import validate_message

with open(sys.argv[1]) as stream:
    messages = [validate_message(json.loads(line)) for line in stream]
assert any(message["event"]["ifindex"] == int(sys.argv[2])
           and message["event"]["timestamp"] > 0
           and message["event"]["packet_length"] == 98 for message in messages)
print("PASS: eBPF → C agent → Unix socket → validated Python event")
for message in messages:
    print(json.dumps(message))
PY
fi
if ip -details link show kl-recv | grep -q 'prog/xdp'; then
    echo 'FAIL: XDP remains attached' >&2
    exit 1
fi

# Reattachment also verifies that cleanup released the attachment.
./build/kernellens-agent kl-recv >"$test_dir/restart.out" 2>"$test_dir/restart.log" &
agent_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
    if grep -q 'Attached XDP_PASS' "$test_dir/restart.log"; then
        break
    fi
    sleep 0.05
done
grep -q 'Attached XDP_PASS' "$test_dir/restart.log"
kill -TERM "$agent_pid"
wait "$agent_pid"
agent_pid=
grep -q 'Detached XDP' "$test_dir/restart.log"
ip link delete kl-recv
if ip link show kl-recv >/dev/null 2>&1 || nsenter -t "$sender_pid" -n ip link show kl-send >/dev/null 2>&1; then
    echo 'FAIL: temporary veth networking remains' >&2
    exit 1
fi
echo 'PASS: temporary veth pair removed; namespace processes cleaned up on exit'
echo 'PASS: packet events, XDP_PASS delivery, attachment conflict, SIGINT/SIGTERM cleanup, reattach'
