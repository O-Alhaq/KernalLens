import copy
import json
import select
import subprocess
import unittest

from backend.receiver import validate_message
from backend.events import SecurityEvent, normalize_message
import test_ipc


def host_message(category="process"):
    event = {
        "timestamp": 123456789, "event_category": category, "event_type": "process_exec",
        "pid": 4217, "ppid": 4100, "uid": 1000, "gid": 1000,
        "process_name": "host-helper", "process_path": "/usr/bin/true",
        "syscall": None, "syscall_return": None, "previous_uid": None, "previous_gid": None,
    }
    if category != "process":
        event.update(event_type="syscall_event", syscall="setuid", syscall_return=-1, process_path=None)
    if category == "privilege":
        event.update(event_type="privilege_change", syscall_return=0, previous_uid=0, previous_gid=1000)
    return {"message_type": "event", "schema_version": 1, "event": event}


class HostValidationTests(unittest.TestCase):
    def test_all_host_categories(self):
        for category in ("process", "syscall", "privilege"):
            message = host_message(category)
            self.assertEqual(validate_message(message), message)

    def test_missing_and_invalid_fields(self):
        for category in ("process", "syscall", "privilege"):
            base = host_message(category)
            for field in base["event"]:
                message = copy.deepcopy(base)
                del message["event"][field]
                with self.subTest(category=category, missing=field), self.assertRaises(ValueError):
                    validate_message(message)
        for field, values in {
            "timestamp": (True, -1, 2**64), "pid": (0, True, "4217"),
            "ppid": (-1, None), "uid": (False, -1, 2**32), "gid": (-1, 2**32),
            "process_name": (None, "x" * 16, "a\0b"),
            "process_path": ("", "a\0b", "x" * 256, 3),
            "event_category": ("network", None), "event_type": ("syscall_event", None),
            "syscall": ("setuid",), "syscall_return": (0,), "previous_uid": (0,),
        }.items():
            for value in values:
                message = host_message()
                message["event"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_message(message)

    def test_syscall_and_privilege_semantics(self):
        for field, value in (("syscall", "execve"), ("syscall_return", True),
                             ("syscall_return", 2**63), ("syscall_return", None),
                             ("process_path", "/path"), ("previous_uid", 0)):
            message = host_message("syscall")
            message["event"][field] = value
            with self.assertRaises(ValueError):
                validate_message(message)
        for field, value in (("syscall_return", -1), ("previous_uid", None),
                             ("previous_gid", True), ("previous_uid", 1000)):
            message = host_message("privilege")
            message["event"][field] = value
            with self.assertRaises(ValueError):
                validate_message(message)


class HostTransportTests(unittest.TestCase):
    # Share the real C IPC-driver fixture, not a mock of serialization/routing.
    setUp = test_ipc.TransportTests.setUp
    stop_driver = test_ipc.TransportTests.stop_driver
    line = test_ipc.TransportTests.line
    command = test_ipc.TransportTests.command
    connect = test_ipc.TransportTests.connect

    def test_mixed_network_and_host_routing(self):
        client = self.connect()
        for category, command in (("process", "host_exec"), ("syscall", "host_syscall"),
                                  ("privilege", "host_privilege")):
            self.command(command)
            message = json.loads(client.recv(4096))
            self.assertEqual(validate_message(message), host_message(category))
        self.command("event")
        self.assertEqual(json.loads(client.recv(4096)), test_ipc.EVENT)

    def test_escaping_and_maximum_record(self):
        client = self.connect()
        self.command("host_escape")
        message = validate_message(json.loads(client.recv(4096)))
        self.assertEqual(message["event"]["process_name"], 'a"\\\n\u00ff')
        self.assertEqual(message["event"]["process_path"], '/tmp/a"\\\n\u00ff')
        self.command("host_max")
        wire = client.recv(4096)
        self.assertLess(len(wire), 4096)
        event = validate_message(json.loads(wire))["event"]
        self.assertEqual(event["process_path"], "\u00ff" * 255)
        self.assertEqual(event["process_name"], "\u00ff" * 15)

    def test_unknown_binary_record_rejected(self):
        client = self.connect()
        for command in ("bad_size", "host_bad_kind", "host_bad_syscall"):
            self.driver.stdin.write(command + "\n")
            self.driver.stdin.flush()
            self.assertEqual(self.line(), "rejected\n")
        client.settimeout(0.05)
        with self.assertRaises(TimeoutError):
            client.recv(4096)
        client.settimeout(3)
        self.command("event")
        self.assertEqual(json.loads(client.recv(4096)), test_ipc.EVENT)

    def test_python_cli_receives_all_host_categories(self):
        receiver = subprocess.Popen(
            ["python3", "backend/receiver.py", self.path], cwd=test_ipc.ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(100):
                self.command("poll")
                if select.select([receiver.stderr], [], [], 0.05)[0]:
                    break
            else:
                self.fail("Python did not connect")
            for command in ("host_exec", "host_syscall", "host_privilege", "event"):
                self.command(command)
            self.stop_driver()
            output, errors = receiver.communicate(timeout=3)
            self.assertEqual(receiver.returncode, 0, errors)
            messages = [SecurityEvent.from_dict(json.loads(line)).to_dict() for line in output.splitlines()]
            expected = [normalize_message(message).to_dict() for message in
                        [host_message(category) for category in
                         ("process", "syscall", "privilege")] + [test_ipc.EVENT]]
            for event in messages + expected:
                event.pop("event_id")
            self.assertEqual(messages, expected)
        finally:
            if receiver.poll() is None:
                receiver.kill()
            receiver.communicate()


if __name__ == "__main__":
    unittest.main()
