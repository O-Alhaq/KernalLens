"""Strict M4/M5 agent wire-format validation."""

import ipaddress


def validate_host_event(event):
    fields = {
        "timestamp", "event_category", "event_type", "pid", "ppid", "uid", "gid",
        "process_name", "process_path", "syscall", "syscall_return",
        "previous_uid", "previous_gid",
    }
    if set(event) != fields:
        raise ValueError("invalid host event fields")
    for field, maximum, minimum in (
        ("timestamp", (1 << 64) - 1, 0), ("pid", (1 << 32) - 1, 1),
        ("ppid", (1 << 32) - 1, 0), ("uid", (1 << 32) - 1, 0),
        ("gid", (1 << 32) - 1, 0),
    ):
        if type(event[field]) is not int or not minimum <= event[field] <= maximum:
            raise ValueError(f"invalid host {field}")
    if not isinstance(event["process_name"], str) or len(event["process_name"]) > 15 or "\0" in event["process_name"]:
        raise ValueError("invalid process_name")
    path = event["process_path"]
    if path is not None and (not isinstance(path, str) or not 1 <= len(path) <= 255 or "\0" in path):
        raise ValueError("invalid process_path")
    category = event["event_category"]
    if category == "process":
        if event["event_type"] != "process_exec" or any(event[field] is not None for field in
                ("syscall", "syscall_return", "previous_uid", "previous_gid")):
            raise ValueError("invalid process event")
    elif category in ("syscall", "privilege"):
        expected = "syscall_event" if category == "syscall" else "privilege_change"
        result = event["syscall_return"]
        if event["event_type"] != expected or event["syscall"] not in ("setuid", "setgid"):
            raise ValueError("invalid host syscall/type")
        if type(result) is not int or not -(1 << 63) <= result < (1 << 63):
            raise ValueError("invalid syscall_return")
        if path is not None:
            raise ValueError("syscall path unavailable")
        if category == "privilege":
            for field in ("previous_uid", "previous_gid"):
                if type(event[field]) is not int or not 0 <= event[field] < (1 << 32):
                    raise ValueError(f"invalid {field}")
            if result != 0 or (event["previous_uid"], event["previous_gid"]) == (event["uid"], event["gid"]):
                raise ValueError("privilege event requires a successful credential change")
        elif event["previous_uid"] is not None or event["previous_gid"] is not None:
            raise ValueError("previous credentials only apply to privilege events")
    else:
        raise ValueError("unsupported host category")


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
    if isinstance(event, dict) and "event_category" in event:
        validate_host_event(event)
        return message
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


