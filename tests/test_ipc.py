import copy
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import unittest

from backend.receiver import receive_messages, validate_message
from backend.events import SecurityEvent, normalize_message

ROOT = Path(__file__).resolve().parents[1]
EVENT = {"message_type": "event", "schema_version": 1,
         "event": {"timestamp": 123456789, "ifindex": 2, "packet_length": 86,
                   "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2",
                   "src_port": 45678, "dst_port": 80, "protocol": "TCP", "tcp_flags": 2}}
STATUS = {"message_type": "status", "schema_version": 1, "status": "ready"}


class Chunks:
    def __init__(self, *chunks):
        self.chunks = iter(chunks)

    def recv(self, _size):
        return next(self.chunks, b"")


class ValidationTests(unittest.TestCase):
    def test_valid_messages_and_integer_limits(self):
        self.assertEqual(validate_message(EVENT), EVENT)
        self.assertEqual(validate_message(STATUS), STATUS)
        message = copy.deepcopy(EVENT)
        message["event"].update(timestamp=2**64 - 1, ifindex=2**32 - 1,
                                packet_length=2**32 - 1)
        validate_message(message)

    def test_invalid_fields_types_and_ranges(self):
        for field in EVENT["event"]:
            for bad in (True, "1", 1.5, -1, 2**64, None):
                message = copy.deepcopy(EVENT)
                message["event"][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                    validate_message(message)
            if field in {"src_port", "dst_port", "tcp_flags"}:
                message = copy.deepcopy(EVENT)
                message["event"][field] = 65536 if field != "tcp_flags" else 256
                with self.assertRaises(ValueError):
                    validate_message(message)
            message = copy.deepcopy(EVENT)
            del message["event"][field]
            with self.assertRaises(ValueError):
                validate_message(message)
        for bad in (None, [], {}, {**EVENT, "schema_version": True},
                    {**EVENT, "schema_version": 2}, {**EVENT, "message_type": "request"},
                    {**EVENT, "extra": 0}, {**EVENT, "event": []},
                    {**EVENT, "event": {**EVENT["event"], "ifindex": 0}},
                    {**STATUS, "status": "other"}):
            with self.subTest(message=bad), self.assertRaises(ValueError):
                validate_message(bad)

    def test_protocol_defaults_and_invalid_network_fields(self):
        for protocol in ("UDP", "ICMP", "OTHER", "IPPROTO_47"):
            message = copy.deepcopy(EVENT)
            message["event"].update(protocol=protocol, tcp_flags=0, src_port=0, dst_port=0)
            if protocol == "OTHER":
                message["event"].update(src_ip="0.0.0.0", dst_ip="0.0.0.0")
            validate_message(message)
        for field, values in {
            "src_ip": ("::1", "999.0.0.1", "192.0.2.01"),
            "dst_ip": ("invalid", "::ffff:192.0.2.1"),
            "protocol": ("", "SCTP", "IPPROTO_256", "IPPROTO_06", "IPPROTO_6"),
        }.items():
            for value in values:
                message = copy.deepcopy(EVENT)
                message["event"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_message(message)
        for protocol in ("UDP", "ICMP", "OTHER"):
            message = copy.deepcopy(EVENT)
            message["event"]["protocol"] = protocol
            with self.assertRaises(ValueError):
                validate_message(message)

    def test_stream_fragmentation_and_multiple_records(self):
        wire = (json.dumps(STATUS) + "\n" + json.dumps(EVENT) + "\n").encode()
        self.assertEqual(list(receive_messages(Chunks(*(bytes([byte]) for byte in wire)))),
                         [STATUS, EVENT])
        self.assertEqual(list(receive_messages(Chunks(wire))), [STATUS, EVENT])

    def test_idle_callbacks_preserve_fragmented_records_and_default_timeout_behavior(self):
        wire = (json.dumps(STATUS) + "\n" + json.dumps(EVENT) + "\n").encode()
        class TimedChunks:
            def __init__(self):
                self.chunks = iter((None, wire[:20], None, wire[20:], b""))

            def recv(self, size):
                chunk = next(self.chunks, b"")
                if chunk is None:
                    raise TimeoutError()
                return chunk
        calls = []
        self.assertEqual(list(receive_messages(TimedChunks(), on_idle=lambda: calls.append(True))),
                         [STATUS, EVENT])
        self.assertEqual(len(calls), 2)
        with self.assertRaises(TimeoutError):
            list(receive_messages(TimedChunks()))

    def test_malformed_truncated_duplicate_and_oversized(self):
        for wire in (b"not-json\n", b"\xff\n", b"{}", b"x" * 4097,
                     b"x" * 4097 + b"\n", b'{"schema_version":1,"schema_version":1}\n'):
            with self.subTest(wire=wire[:40]), self.assertRaises(ValueError):
                list(receive_messages(Chunks(wire)))


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / "agent.sock")
        self.driver = subprocess.Popen([str(ROOT / "build/ipc-driver"), self.path],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(self.stop_driver)
        self.assertEqual(self.line(), "ready\n")

    def stop_driver(self):
        if self.driver.poll() is None:
            self.driver.stdin.close()
            try:
                self.driver.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.driver.kill()
                self.driver.wait()
        self.driver.stdout.close()
        if not self.driver.stdin.closed:
            self.driver.stdin.close()

    def line(self):
        self.assertTrue(select.select([self.driver.stdout], [], [], 3)[0],
                        "C IPC driver timed out")
        return self.driver.stdout.readline()

    def command(self, command):
        self.driver.stdin.write(command + "\n")
        self.driver.stdin.flush()
        self.assertEqual(self.line(), "ok\n")

    def connect(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.settimeout(3)
        client.connect(self.path)
        self.command("poll")
        self.assertEqual(json.loads(client.recv(4096)), STATUS)
        return client

    def test_c_serialization_reconnect_and_cleanup(self):
        first = self.connect()
        self.command("event")
        message = json.loads(first.recv(4096))
        self.assertEqual(validate_message(message), EVENT)
        first.close()
        second = self.connect()
        self.command("event")
        self.assertEqual(json.loads(second.recv(4096)), EVENT)
        self.stop_driver()
        self.assertEqual(second.recv(4096), b"")
        self.assertFalse(Path(self.path).exists())

    def test_slow_client_does_not_block_and_can_reconnect(self):
        client = self.connect()
        self.command("flood")
        while client.recv(65536):
            pass
        self.connect()

    def test_second_client_is_rejected(self):
        first = self.connect()
        second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(second.close)
        second.settimeout(3)
        second.connect(self.path)
        self.command("poll")
        self.assertEqual(second.recv(1), b"")
        self.command("event")
        self.assertEqual(json.loads(first.recv(4096)), EVENT)

    def test_socket_permissions_and_existing_path_preserved(self):
        self.assertEqual(Path(self.path).stat().st_mode & 0o777, 0o700)
        result = subprocess.run([str(ROOT / "build/ipc-driver"), self.path], timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.connect()

    def test_cleanup_preserves_replacement_file(self):
        Path(self.path).unlink()
        Path(self.path).write_text("replacement")
        self.stop_driver()
        self.assertEqual(Path(self.path).read_text(), "replacement")

    def test_python_cli_receives_from_real_c_server(self):
        receiver = subprocess.Popen(
            ["python3", "backend/receiver.py", self.path], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # Wait until Python's connect has entered the listener backlog.
            for _ in range(100):
                self.command("poll")
                if select.select([receiver.stderr], [], [], 0.05)[0]:
                    break
            else:
                self.fail("Python receiver did not connect")
            self.command("event")
            self.stop_driver()
            output, errors = receiver.communicate(timeout=3)
            self.assertEqual(receiver.returncode, 0, errors)
            self.assertIn("Agent status: ready", errors)
            actual = SecurityEvent.from_dict(json.loads(output)).to_dict()
            expected = normalize_message(EVENT).to_dict()
            actual.pop("event_id")
            expected.pop("event_id")
            self.assertEqual(actual, expected)
        finally:
            if receiver.poll() is None:
                receiver.kill()
            receiver.communicate()


if __name__ == "__main__":
    unittest.main()
