"""File-backed SQLite tests; no production database is opened."""

from contextlib import closing
from dataclasses import fields
from pathlib import Path
import sqlite3
import tempfile
import unittest

from backend.events import SecurityEvent, normalize_message
from backend.pipeline import EventRouter, receive_events
from backend.storage import EventStore
from test_host import host_message
from test_ipc import Chunks, EVENT, STATUS
import json


def sample_events():
    return [normalize_message(message) for message in
            [EVENT] + [host_message(category) for category in ("process", "syscall", "privilege")]]


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "events.db"
        self.store = EventStore(self.path)
        self.store.initialize()

    def test_initialization_is_versioned_idempotent_and_complete(self):
        self.assertTrue(self.path.is_file())
        self.store.initialize()
        self.store.check_health()
        self.assertEqual(self.store.list_events(), [])
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
            self.assertEqual(columns, {item.name for item in fields(SecurityEvent)})

    def test_round_trip_all_categories_and_metadata_after_reopen(self):
        events = sample_events()
        for event in events:
            self.store.insert(event)
        reopened = EventStore(self.path)
        reopened.initialize()
        self.assertEqual(reopened.list_events(), events)
        for event in events:
            self.assertEqual(reopened.get(event.event_id).to_dict(), event.to_dict())
        with closing(sqlite3.connect(self.path)) as connection:
            metadata = connection.execute("SELECT metadata FROM events WHERE event_id = ?",
                                          (events[-1].event_id,)).fetchone()[0]
            self.assertEqual(json.loads(metadata), events[-1].metadata)

    def test_timestamp_uint64_and_unicode_are_lossless(self):
        record = sample_events()[1].to_dict()
        record.update(timestamp=2**64 - 1, process_name='a"\\\n\u00ff', process_path='/tmp/\u00ff')
        event = SecurityEvent.from_dict(record)
        self.store.insert(event)
        self.assertEqual(self.store.get(event.event_id), event)

    def test_missing_id_filters_pagination_and_parameterized_queries(self):
        events = sample_events()
        for event in events:
            self.store.insert(event)
        self.assertIsNone(self.store.get("absent"))
        self.assertEqual(self.store.list_events(limit=2, offset=1), events[1:3])
        self.assertEqual(self.store.list_events(offset=100), [])
        for event in events:
            self.assertEqual(self.store.list_events(event_category=event.event_category), [event])
            self.assertEqual(self.store.list_events(event_type=event.event_type), [event])
        self.assertEqual(self.store.list_events(event_category="network", event_type="process_exec"), [])
        self.assertEqual(self.store.list_events(event_category="unknown"), [])
        self.assertEqual(self.store.list_events(event_type="' OR 1=1 --"), [])
        self.assertIsNone(self.store.get("' OR 1=1 --"))
        for options in ({"limit": 0}, {"limit": 1001}, {"limit": True},
                        {"offset": -1}, {"offset": 2**63}, {"event_type": []}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.store.list_events(**options)

    def test_duplicate_and_invalid_events_do_not_overwrite_or_poison_store(self):
        event = sample_events()[0]
        self.store.insert(event)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.insert(event)
        self.assertEqual(self.store.get(event.event_id), event)
        with self.assertRaises(ValueError):
            self.store.insert(EVENT)
        invalid = sample_events()[0]
        invalid.metadata.clear()
        with self.assertRaises(ValueError):
            self.store.insert(invalid)
        second = sample_events()[1]
        self.store.insert(second)
        self.assertEqual(self.store.list_events(), [event, second])

    def test_future_schema_is_rejected_without_migration(self):
        future = Path(self.directory.name) / "future.db"
        with closing(sqlite3.connect(future)) as connection:
            connection.execute("PRAGMA user_version=2")
        with self.assertRaisesRegex(ValueError, "unsupported database schema"):
            EventStore(future).initialize()
        with closing(sqlite3.connect(future)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(), [])

    def test_receiver_stream_routes_all_categories_to_storage_subscriber(self):
        messages = [STATUS, EVENT] + [host_message(category) for category in ("process", "syscall", "privilege")]
        wire = ''.join(json.dumps(message) + '\n' for message in messages).encode()
        router = EventRouter()
        router.subscribe(self.store.insert)
        observed = []
        router.subscribe(observed.append)
        for event in receive_events(Chunks(wire)):
            router.route(event)
        self.assertEqual(self.store.list_events(), observed)
        self.assertEqual(len(observed), 4)
