"""Assert controlled host activity reached Python through the production path."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.events import SecurityEvent


def check(path, metadata, executable):
    with open(path) as stream:
        all_events = [SecurityEvent.from_dict(json.loads(line)).to_dict() for line in stream]
    events = [event for event in all_events if event.get("pid") == metadata["pid"]]
    assert events, "no host events for controlled process"
    assert all(event["ppid"] == metadata["ppid"] and event["timestamp"] > 0
               and event["process_name"] == "host-activity" for event in events)
    executions = [event for event in events if event["event_category"] == "process"]
    assert any(event["process_path"] == executable and event["event_type"] == "process_exec"
               and event["uid"] == metadata["old_uid"] and event["gid"] == metadata["old_gid"]
               for event in executions), "missing successful exec and path"
    calls = [event for event in events if event["event_category"] == "syscall"]
    assert any(event["syscall"] == "setgid" and event["metadata"]["syscall_return"] == 0
               and event["gid"] == metadata["target_gid"] for event in calls)
    uid_calls = [event for event in calls if event["syscall"] == "setuid"]
    assert sum(event["metadata"]["syscall_return"] == 0 for event in uid_calls) == 2, "missing setuid/no-op"
    assert any(event["metadata"]["syscall_return"] == -1 and event["uid"] == metadata["target_uid"]
               for event in uid_calls), "missing denied setuid"
    changes = [event for event in events if event["event_category"] == "privilege"]
    assert len(changes) == 2, "expected only two real credential changes"
    assert any(event["syscall"] == "setgid" and event["metadata"]["previous_gid"] == metadata["old_gid"]
               and event["gid"] == metadata["target_gid"]
               and event["metadata"]["previous_uid"] == event["uid"] == metadata["old_uid"]
               for event in changes), "missing effective GID change"
    assert any(event["syscall"] == "setuid" and event["metadata"]["previous_uid"] == metadata["old_uid"]
               and event["uid"] == metadata["target_uid"]
               and event["metadata"]["previous_gid"] == event["gid"] == metadata["target_gid"]
               for event in changes), "missing effective UID change"
    return events


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events")
    parser.add_argument("metadata")
    parser.add_argument("executable")
    parser.add_argument("--quiet", action="store_true")
    arguments = parser.parse_args()
    try:
        with open(arguments.metadata) as stream:
            metadata = json.load(stream)
        events = check(arguments.events, metadata, arguments.executable)
    except (AssertionError, ValueError) as error:
        if not arguments.quiet:
            print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    if not arguments.quiet:
        print("PASS: Python received real process, syscall and privilege events")
        for event in events:
            print(json.dumps(event))
