import copy
import json
from pathlib import Path
import tempfile
import unittest

from check_host_events import check
from test_host import host_message
from test_ipc import EVENT


class HostCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "events"
        self.executable = "/repo/build/host-activity"
        self.metadata = {"pid": 4217, "ppid": 4100, "old_uid": 0, "old_gid": 0,
                         "target_uid": 65534, "target_gid": 65534}
        process = host_message()["event"]
        process.update(uid=0, gid=0, process_name="host-activity", process_path=self.executable)
        gid_call = host_message("syscall")["event"]
        gid_call.update(uid=0, gid=65534, process_name="host-activity", syscall="setgid", syscall_return=0)
        gid_change = {**gid_call, "event_category": "privilege", "event_type": "privilege_change",
                      "previous_uid": 0, "previous_gid": 0}
        uid_call = {**gid_call, "uid": 65534, "syscall": "setuid"}
        uid_change = {**uid_call, "event_category": "privilege", "event_type": "privilege_change",
                      "previous_uid": 0, "previous_gid": 65534}
        self.events = [process, gid_call, gid_change, uid_call, uid_change,
                       copy.deepcopy(uid_call), {**uid_call, "syscall_return": -1}]

    def write(self, events):
        self.path.write_text(json.dumps(EVENT) + "\n" + "".join(json.dumps({
            "message_type": "event", "schema_version": 1, "event": event,
        }) + "\n" for event in events))

    def test_capture_with_network_and_all_host_categories(self):
        self.write(self.events)
        self.assertEqual(len(check(self.path, self.metadata, self.executable)), 7)

    def test_wrong_identity_and_missing_categories_rejected(self):
        self.write(self.events)
        for field in ("pid", "ppid", "old_uid", "old_gid", "target_uid", "target_gid"):
            metadata = {**self.metadata, field: self.metadata[field] + 1}
            with self.subTest(field=field), self.assertRaises(AssertionError):
                check(self.path, metadata, self.executable)
        for index in range(len(self.events)):
            self.write([event for position, event in enumerate(self.events) if position != index])
            with self.subTest(missing=index), self.assertRaises(AssertionError):
                check(self.path, self.metadata, self.executable)

    def test_extra_privilege_change_rejected(self):
        self.write(self.events + [self.events[4]])
        with self.assertRaises(AssertionError):
            check(self.path, self.metadata, self.executable)


if __name__ == "__main__":
    unittest.main()
