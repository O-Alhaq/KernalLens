"""Unix socket receiver and unified M6 telemetry pipeline."""

import argparse
import json
import socket
import sqlite3
import sys

if __package__:
    from .storage import EventStore
    from .validation import validate_host_event, validate_message
    from .pipeline import EventRouter, receive_events
else:
    from storage import EventStore
    from validation import validate_host_event, validate_message
    from pipeline import EventRouter, receive_events

MAX_RECORD = 4096


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def receive_messages(connection):
    """Decode newline-delimited JSON regardless of stream read boundaries."""
    pending = b""
    while True:
        chunk = connection.recv(MAX_RECORD)
        if not chunk:
            if pending:
                raise ValueError("truncated JSON record at disconnect")
            return
        pending += chunk
        while b"\n" in pending:
            record, pending = pending.split(b"\n", 1)
            if len(record) > MAX_RECORD:
                raise ValueError("JSON record too large")
            message = json.loads(record.decode("utf-8"), object_pairs_hook=unique_object)
            yield validate_message(message)
        if len(pending) > MAX_RECORD:
            raise ValueError("JSON record too large")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket_path", help="Unix socket exposed by the C agent")
    parser.add_argument("--database", help="persist normalized events to this SQLite file")
    parser.add_argument("--rules", help="evaluate rules from this YAML file; alerts go to stderr")
    arguments = parser.parse_args()
    try:
        engine = None
        if arguments.rules:
            # Optional detection dependency; the M2–M7 receiver works without YAML.
            if __package__:
                from .rule_config import load_rules
                from .rules import RuleEngine
            else:
                from rule_config import load_rules
                from rules import RuleEngine
            engine = RuleEngine(load_rules(arguments.rules))
            engine.subscribe(lambda alert: print(
                "Alert: " + json.dumps(alert.to_dict(), separators=(",", ":")),
                file=sys.stderr, flush=True))
        store = None
        if arguments.database:
            store = EventStore(arguments.database)
            store.initialize()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(arguments.socket_path)
            router = EventRouter()
            if engine is not None:
                router.subscribe(engine)
            if store is not None:
                router.subscribe(store.insert)
            router.subscribe(lambda event: print(
                json.dumps(event.to_dict(), separators=(",", ":")), flush=True))
            for event in receive_events(connection, on_status=lambda message: print(
                    "Agent status: ready", file=sys.stderr, flush=True)):
                router.route(event)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Receiver error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
