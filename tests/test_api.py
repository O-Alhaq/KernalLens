"""M7 REST tests with temporary SQLite files and the real M6 model."""

from pathlib import Path
import select
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.api import create_app

from backend.storage import EventStore
import test_ipc
from test_storage import sample_events


def security_only(value):
    if isinstance(value, list):
        return [security_only(item) for item in value]
    return {key: item for key, item in value.items() if key != "wall_clock_timestamp"}



class ApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "events.db"
        self.app = create_app(self.path)
        self.assertFalse(self.path.exists())  # Construction/import has no DB side effects.
        self.client = self.enterContext(TestClient(self.app))
        self.store = EventStore(self.path)

    def test_health_initializes_database_and_empty_list(self):
        self.assertTrue(self.path.exists())
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "database": "ok"})
        self.assertEqual(self.client.get("/events").json(), [])

    def test_all_events_and_individual_events_round_trip_through_api(self):
        events = sample_events()
        for event in events:
            self.store.insert(event)
        response = self.client.get("/events")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(security_only(response.json()), [event.to_dict() for event in events])
        for event in events:
            response = self.client.get(f"/events/{event.event_id}")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(security_only(response.json()), event.to_dict())
        # A separate app/connection can see committed telemetry.
        with TestClient(create_app(self.path)) as reopened:
            self.assertEqual(security_only(reopened.get("/events").json()), [event.to_dict() for event in events])

    def test_filters_pagination_missing_and_invalid_parameters(self):
        events = sample_events()
        for event in events:
            self.store.insert(event)
        response = self.client.get("/events", params={"limit": 2, "offset": 1})
        self.assertEqual(security_only(response.json()), [event.to_dict() for event in events[1:3]])
        for event in events:
            response = self.client.get("/events", params={"event_category": event.event_category,
                                                         "event_type": event.event_type})
            self.assertEqual(security_only(response.json()), [event.to_dict()])
        for params in ({"event_category": "unknown"}, {"offset": 100},
                       {"event_category": "network", "event_type": "process_exec"},
                       {"event_type": "' OR 1=1 --"}):
            self.assertEqual(self.client.get("/events", params=params).json(), [])
        for params in ({"limit": 0}, {"limit": -1}, {"limit": 1001},
                       {"limit": "bad"}, {"offset": -1}, {"offset": 2**63}):
            self.assertEqual(self.client.get("/events", params=params).status_code, 422)
        for event_id in (str(uuid4()), "not-an-event"):
            response = self.client.get(f"/events/{event_id}")
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json(), {"detail": "Event not found"})
        self.assertEqual(self.client.post("/events", json={}).status_code, 405)

    def test_database_failures_report_service_unavailable_without_details(self):
        for method, path in (("check_health", "/health"), ("list_events", "/events"),
                             ("get", f"/events/{uuid4()}")):
            with patch.object(EventStore, method, side_effect=sqlite3.OperationalError("private path")):
                with self.assertLogs("backend.api", level="ERROR"):
                    response = self.client.get(path)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json(), {"detail": "Event database unavailable"})


class PersistentTransportTests(unittest.TestCase):
    setUp = test_ipc.TransportTests.setUp
    stop_driver = test_ipc.TransportTests.stop_driver
    line = test_ipc.TransportTests.line
    command = test_ipc.TransportTests.command

    def test_c_agent_receiver_storage_and_rest_all_categories(self):
        database = Path(self.directory.name) / "events.db"
        receiver = subprocess.Popen(
            ["python3", "backend/receiver.py", self.path, "--database", str(database)],
            cwd=test_ipc.ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(100):
                self.command("poll")
                if select.select([receiver.stderr], [], [], 0.05)[0]:
                    break
            else:
                self.fail("receiver did not connect")
            for command in ("event", "host_exec", "host_syscall", "host_privilege"):
                self.command(command)
            self.stop_driver()
            output, errors = receiver.communicate(timeout=3)
            self.assertEqual(receiver.returncode, 0, errors)
            import json
            printed = [json.loads(line) for line in output.splitlines()]
            self.assertEqual(len(printed), 4)
            with TestClient(create_app(database)) as client:
                response = client.get("/events")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(security_only(response.json()), printed)
                self.assertEqual([event["event_category"] for event in printed],
                                 ["network", "process", "syscall", "privilege"])
                for event in printed:
                    self.assertEqual(security_only(client.get(f'/events/{event["event_id"]}').json()), event)
        finally:
            if receiver.poll() is None:
                receiver.kill()
            receiver.communicate()
