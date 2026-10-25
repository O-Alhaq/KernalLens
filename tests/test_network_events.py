"""Verify that the integration checker rejects wrong endpoints and TCP flags."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from check_network_events import check
from backend.events import normalize_message


class NetworkCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "events"
        base = {
            "timestamp": 123, "ifindex": 2, "packet_length": 74,
            "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2",
            "src_port": 45000, "dst_port": 32080, "protocol": "TCP", "tcp_flags": 2,
        }
        self.events = [base, {**base, "tcp_flags": 24},
                       {**base, "src_port": 45001, "dst_port": 32081,
                        "protocol": "UDP", "tcp_flags": 0, "packet_length": 56}]

    def write_events(self, events):
        self.path.write_text("".join(json.dumps(normalize_message({
            "message_type": "event", "schema_version": 1, "event": event,
        }).to_dict()) + "\n" for event in events))

    def test_expected_capture(self):
        self.write_events(self.events)
        self.assertEqual(len(check(self.path, 2)), 3)

    def test_wrong_ip_interface_ports_and_flags_fail(self):
        for field, value in (("src_ip", "192.0.2.3"), ("dst_ip", "192.0.2.4"),
                             ("src_port", 45002), ("dst_port", 32082),
                             ("tcp_flags", 16)):
            events = copy.deepcopy(self.events)
            events[0][field] = value
            self.write_events(events)
            with self.subTest(field=field), self.assertRaises(AssertionError):
                check(self.path, 2)
        self.write_events(self.events)
        with self.assertRaises(AssertionError):
            check(self.path, 3)

    def test_missing_udp_or_tcp_payload_fails(self):
        for missing in (1, 2):
            self.write_events([event for index, event in enumerate(self.events) if index != missing])
            with self.assertRaises(AssertionError):
                check(self.path, 2)


if __name__ == "__main__":
    unittest.main()
