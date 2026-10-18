"""Unix socket receiver for validated M4 network telemetry."""

import argparse
import ipaddress
import json
import socket
import sys

MAX_RECORD = 4096


def validate_message(message):
    if not isinstance(message, dict):
        raise ValueError("message must be an object")
    if type(message.get("schema_version")) is not int or message["schema_version"] != 1:
        raise ValueError("unsupported schema_version")
    if message.get("message_type") == "status":
        if set(message) != {"message_type", "schema_version", "status"} or message["status"] != "ready":
            raise ValueError("invalid status message")
        return message
    if message.get("message_type") != "event" or set(message) != {"message_type", "schema_version", "event"}:
        raise ValueError("invalid event envelope")
    event = message["event"]
    if not isinstance(event, dict) or set(event) != {
        "timestamp", "ifindex", "packet_length", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "tcp_flags",
    }:
        raise ValueError("invalid event fields")
    for field, maximum, minimum in (
        ("timestamp", (1 << 64) - 1, 0),
        ("ifindex", (1 << 32) - 1, 1),
        ("packet_length", (1 << 32) - 1, 0),
        ("src_port", 65535, 0),
        ("dst_port", 65535, 0),
        ("tcp_flags", 255, 0),
    ):
        if type(event[field]) is not int or not minimum <= event[field] <= maximum:
            raise ValueError(f"invalid {field}")
    for field in ("src_ip", "dst_ip"):
        if not isinstance(event[field], str):
            raise ValueError(f"invalid {field}")
        ipaddress.IPv4Address(event[field])
    protocol = event["protocol"]
    if not isinstance(protocol, str):
        raise ValueError("invalid protocol")
    if protocol not in {"TCP", "UDP", "ICMP", "OTHER"}:
        number = protocol.removeprefix("IPPROTO_")
        if not number.isascii() or not number.isdecimal() or not 0 <= int(number) <= 255 or protocol != f"IPPROTO_{int(number)}" or int(number) in {1, 6, 17}:
            raise ValueError("invalid protocol")
    if protocol != "TCP" and event["tcp_flags"] != 0:
        raise ValueError("TCP flags only apply to TCP")
    if protocol not in {"TCP", "UDP"} and (event["src_port"] or event["dst_port"]):
        raise ValueError("ports only apply to TCP/UDP")
    if protocol == "OTHER" and (event["src_ip"] != "0.0.0.0" or event["dst_ip"] != "0.0.0.0"):
        raise ValueError("unsupported Ethernet must have zero addresses")
    return message


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
    arguments = parser.parse_args()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(arguments.socket_path)
            for message in receive_messages(connection):
                if message["message_type"] == "status":
                    print("Agent status: ready", file=sys.stderr, flush=True)
                else:
                    print(json.dumps(message, separators=(",", ":")), flush=True)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError) as error:
        print(f"Receiver error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
