"""Check events actually printed by the Python receiver during M4 traffic."""

import argparse
import json
from pathlib import Path
import sys

# Also support direct invocation from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.events import SecurityEvent


def check(path, ifindex):
    with open(path) as stream:
        events = [SecurityEvent.from_dict(json.loads(line)).to_dict() for line in stream]
    matching = [event for event in events if event.get("interface") == ifindex
                and event["timestamp"] > 0 and event["src_ip"] == "192.0.2.1"
                and event["dst_ip"] == "192.0.2.2"]
    tcp = [event for event in matching if event["protocol"] == "TCP"
           and event["src_port"] == 45000 and event["dst_port"] == 32080]
    udp = [event for event in matching if event["protocol"] == "UDP"
           and event["src_port"] == 45001 and event["dst_port"] == 32081]
    assert any(event["tcp_flags"] == 2 for event in tcp), "missing TCP SYN with exact endpoints"
    assert any(event["tcp_flags"] & 0x18 == 0x18 for event in tcp), "missing TCP PSH/ACK"
    assert any(event["tcp_flags"] == 0 and event["metadata"]["packet_length"] == 42 + len(b"kernellens-udp") for event in udp), "missing UDP datagram"
    return tcp + udp


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    parser.add_argument("ifindex", type=int)
    parser.add_argument("--quiet", action="store_true")
    arguments = parser.parse_args()
    try:
        matched = check(arguments.path, arguments.ifindex)
    except (AssertionError, ValueError) as error:
        if not arguments.quiet:
            print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    if not arguments.quiet:
        print("PASS: Python received real TCP/UDP addresses, ports, protocol and flags")
        for event in matched:
            print(json.dumps(event))
