"""M6 normalization, schema validation, and format-independent routing."""

import copy
import json
import unittest
from uuid import UUID

from backend.events import SecurityEvent, normalize_message
from backend.pipeline import EventRouter, receive_events
from test_host import host_message
from test_ipc import Chunks, EVENT, STATUS


class UnifiedEventTests(unittest.TestCase):
    def test_all_categories_defaults_and_preserved_values(self):
        for message in [EVENT] + [host_message(category) for category in
                                  ("process", "syscall", "privilege")]:
            original = copy.deepcopy(message)
            event = normalize_message(message)
            self.assertIsInstance(event, SecurityEvent)
            self.assertEqual(event.timestamp, message["event"]["timestamp"])
            self.assertIsNone(event.container_id)
            self.assertIsNone(event.cgroup_id)
            self.assertEqual(SecurityEvent.from_dict(event.to_dict()), event)
            self.assertEqual(message, original)
            if event.event_category == "network":
                self.assertEqual((event.source, event.event_type, event.interface),
                                 ("xdp", "network_packet", 2))
                self.assertEqual(event.metadata, {"packet_length": 86})
                for key in ("pid", "ppid", "uid", "gid", "process_name", "process_path", "syscall"):
                    self.assertIsNone(getattr(event, key))
                for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "tcp_flags"):
                    self.assertEqual(getattr(event, key), message["event"][key])
            else:
                self.assertEqual(event.source, "tracepoint")
                for key in ("pid", "ppid", "uid", "gid", "process_name", "process_path", "syscall", "event_type"):
                    self.assertEqual(getattr(event, key), message["event"][key])
                for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "tcp_flags", "interface"):
                    self.assertIsNone(getattr(event, key))
                expected = {key: value for key, value in message["event"].items()
                            if key in ("syscall_return", "previous_uid", "previous_gid") and value is not None}
                self.assertEqual(event.metadata, expected)

    def test_network_defaults_and_timestamp_limits(self):
        for protocol in ("TCP", "UDP", "ICMP", "IPPROTO_47", "OTHER"):
            message = copy.deepcopy(EVENT)
            message["event"].update(protocol=protocol, timestamp=2**64 - 1,
                                    src_port=0, dst_port=0, tcp_flags=0)
            if protocol == "OTHER":
                message["event"].update(src_ip="0.0.0.0", dst_ip="0.0.0.0")
            event = normalize_message(message)
            self.assertEqual(event.timestamp, 2**64 - 1)
            self.assertEqual((event.src_port, event.dst_port, event.tcp_flags), (0, 0, 0))
            self.assertEqual(event.protocol, protocol)

    def test_host_model_rejects_invalid_metadata_and_fields(self):
        for category in ("process", "syscall", "privilege"):
            message = host_message(category)
            if category != "process":
                message["event"]["syscall"] = "setgid"
            base = normalize_message(message).to_dict()
            for key, value in (("pid", 0), ("uid", True), ("src_port", 0),
                               ("source", "xdp"), ("event_category", "unknown"),
                               ("metadata", {"unexpected": 1})):
                with self.subTest(category=category, key=key), self.assertRaises(ValueError):
                    SecurityEvent.from_dict({**base, key: value})
            if category != "process":
                for result in (True, 2**63, None):
                    with self.assertRaises(ValueError):
                        SecurityEvent.from_dict({**base, "metadata": {
                            **base["metadata"], "syscall_return": result}})

    def test_unique_uuid_per_event_even_with_identical_input(self):
        identifiers = [normalize_message(EVENT).event_id for _ in range(100)]
        self.assertEqual(len(set(identifiers)), 100)
        self.assertTrue(all(UUID(value).version == 4 for value in identifiers))

    def test_invalid_input_and_unified_schema(self):
        for value in (None, [], {}, STATUS, {**EVENT, "schema_version": 2},
                      {**EVENT, "event": {**EVENT["event"], "protocol": "invalid"}},
                      host_message("unknown")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_message(value)
        base = normalize_message(EVENT).to_dict()
        for key, value in (("event_id", "bad"), ("timestamp", True), ("pid", 1),
                           ("source", "tracepoint"), ("event_type", "unknown"),
                           ("metadata", {}), ("metadata", []), ("interface", 0),
                           ("container_id", "unsupported"), ("src_ip", "bad")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                SecurityEvent.from_dict({**base, key: value})
        for value in ({}, {**base, "extra": 0}, {key: val for key, val in base.items() if key != "pid"}):
            with self.assertRaises(ValueError):
                SecurityEvent.from_dict(value)

    def test_stream_and_router_share_one_model(self):
        messages = [STATUS, EVENT] + [host_message(c) for c in ("process", "syscall", "privilege")]
        wire = ''.join(json.dumps(message) + '\n' for message in messages).encode()
        statuses, all_events, host_events = [], [], []
        router = EventRouter()
        router.subscribe(all_events.append)
        router.subscribe(host_events.append, category="process")
        for event in receive_events(Chunks(*(bytes([byte]) for byte in wire)), statuses.append):
            router.route(event)
        self.assertEqual(statuses, [STATUS])
        self.assertEqual([e.event_category for e in all_events], ["network", "process", "syscall", "privilege"])
        self.assertEqual(host_events, [all_events[1]])
        with self.assertRaises(ValueError):
            router.route(EVENT)
        with self.assertRaises(ValueError):
            router.subscribe(None)
        with self.assertRaises(ValueError):
            router.subscribe(all_events.append, category="unknown")
        all_events[0].metadata.clear()
        with self.assertRaises(ValueError):
            router.route(all_events[0])

    def test_stream_rejects_malformed_and_unsupported_records(self):
        for wire in (b'not json\n', b'{}\n', b'{"schema_version":2}\n', b'{}'):
            with self.assertRaises(ValueError):
                list(receive_events(Chunks(wire)))
