"""M10 SQLite migration, referential integrity, API and pipeline integration."""

from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.api import create_app
from backend.correlation import CorrelationEngine
from backend.incident_storage import IncidentStore
from backend.pipeline import EventRouter
from backend.rule_config import parse_rules
from backend.rules import RuleEngine
from backend.storage import EventStore, MIGRATION_1, SCHEMA_VERSION
from test_correlation import alert, policy, NS
from test_rules import network, rule, host
from test_storage import sample_events


class IncidentStorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/"test.db"
        self.store = IncidentStore(self.path)
        self.store.initialize()

    def sequence(self):
        engine = CorrelationEngine(policy("network_sequence"))
        engine.subscribe(self.store.save_incident)
        items = [alert(), alert("syn_flood", 2), alert("traffic_flood", 3)]
        snapshots = []
        for item in items:
            self.store.insert_alert(item)
            snapshots.extend(engine(item))
        return items, snapshots

    def test_v1_migration_is_atomic_idempotent_and_keeps_event_rows(self):
        path = Path(self.directory.name)/"legacy.db"
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute(MIGRATION_1)
            connection.execute("PRAGMA user_version=1")
        legacy = EventStore(path)
        events = sample_events()
        for event in events:
            legacy.insert(event)
        legacy.initialize()
        legacy.initialize()
        self.assertEqual(legacy.list_events(), events)
        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual({row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")},
                             {"events", "alerts", "incidents", "incident_alerts"})
            self.assertEqual(len(connection.execute("PRAGMA foreign_key_list(incident_alerts)").fetchall()), 2)

    def test_migration_failure_rolls_back_without_losing_telemetry(self):
        path = Path(self.directory.name)/"conflicting.db"
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute(MIGRATION_1)
            connection.execute("CREATE TABLE incidents (preexisting TEXT)")
            connection.execute("PRAGMA user_version=1")
        event = sample_events()[0]
        store = EventStore(path)
        store.insert(event)
        with self.assertRaises(sqlite3.Error):
            store.initialize()
        self.assertEqual(store.get(event.event_id), event)
        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='alerts'").fetchone())

    def test_alert_roundtrip_all_families_uint64_metadata_and_duplicate_ids(self):
        for kind in ("port_scan", "syn_flood", "traffic_flood", "process_match", "syscall_match", "privilege_change"):
            item = replace(alert(kind), timestamp=2**64-1)
            self.store.insert_alert(item)
            self.store.insert_alert(item)
            self.assertEqual(self.store.get_alert(item.alert_id), item)
            with self.assertRaisesRegex(ValueError, "conflicting"):
                self.store.insert_alert(replace(item, description="changed"))
        self.assertIsNone(self.store.get_alert("missing"))
        with self.assertRaises(ValueError):
            self.store.insert_alert({})

    def test_incident_update_roundtrip_and_normalized_links(self):
        items, snapshots = self.sequence()
        initial, updated = snapshots
        self.assertEqual(self.store.list_incidents(), [updated])
        self.assertEqual(self.store.get_incident(updated.incident_id), updated)
        self.store.save_incident(updated)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.store.save_incident(initial)
        self.assertEqual(self.store.get_incident(updated.incident_id), updated)
        with closing(sqlite3.connect(self.path)) as connection:
            rows = connection.execute("SELECT alert_id FROM incident_alerts WHERE incident_id=?", (updated.incident_id,)).fetchall()
            self.assertEqual({row[0] for row in rows}, {item.alert_id for item in items})
            self.assertEqual(len(rows), 3)
        reopened = IncidentStore(self.path)
        reopened.initialize()
        self.assertEqual(reopened.get_incident(updated.incident_id).metadata, updated.metadata)

    def test_missing_alert_foreign_key_rolls_back_whole_incident_write(self):
        engine = CorrelationEngine(policy("network_sequence"))
        engine.evaluate(alert())
        item, = engine.evaluate(alert("syn_flood", 2))
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.save_incident(item)
        self.assertEqual(self.store.list_incidents(), [])
        self.assertIsNone(self.store.get_incident("missing"))
        with self.assertRaises(ValueError):
            self.store.save_incident({})

    def test_filters_pagination_and_sql_parameterization(self):
        _, network_incidents = self.sequence()
        engine = CorrelationEngine(policy("host_sequence"))
        members = [alert("process_match"), alert("syscall_match", 2)]
        for member in members:
            self.store.insert_alert(member)
        engine.evaluate(members[0])
        host_incident, = engine.evaluate(members[1])
        self.store.save_incident(host_incident)
        self.assertEqual(self.store.list_incidents(limit=1, offset=1), [host_incident])
        self.assertEqual(self.store.list_incidents(incident_type="network_sequence", severity="high"), [network_incidents[-1]])
        self.assertEqual(self.store.list_incidents(severity="medium"), [host_incident])
        self.assertEqual(self.store.list_incidents(incident_type="' OR 1=1 --"), [])
        self.assertIsNone(self.store.get_incident("' OR 1=1 --"))
        for options in ({"limit": 0}, {"limit": 1001}, {"offset": -1}, {"limit": True}, {"severity": []}):
            with self.assertRaises(ValueError):
                self.store.list_incidents(**options)

    def test_incident_api_read_only_filters_pagination_and_404(self):
        _, snapshots = self.sequence()
        item = snapshots[-1]
        with TestClient(create_app(self.path)) as client:
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/incidents").json(), [item.to_dict()])
            self.assertEqual(client.get(f"/incidents/{item.incident_id}").json(), item.to_dict())
            self.assertEqual(client.get("/incidents/missing").status_code, 404)
            self.assertEqual(client.get("/incidents", params={"incident_type": "network_sequence", "severity": "high"}).json(), [item.to_dict()])
            self.assertEqual(client.get("/incidents", params={"offset": 1, "limit": 1}).json(), [])
            self.assertEqual(client.get("/incidents", params={"severity": "low"}).json(), [])
            self.assertEqual(client.post("/incidents", json={}).status_code, 405)
            self.assertEqual(client.patch(f"/incidents/{item.incident_id}", json={}).status_code, 405)
            for params in ({"limit": 1001}, {"offset": -1}, {"limit": "bad"}, {"offset": 2**63}):
                self.assertEqual(client.get("/incidents", params=params).status_code, 422)
            for method, path in (("get_incident", "/incidents/x"), ("list_incidents", "/incidents")):
                with patch.object(IncidentStore, method, side_effect=sqlite3.OperationalError("private")), self.assertLogs("backend.api", level="ERROR"):
                    self.assertEqual(client.get(path).status_code, 503)

    def test_fifty_port_session_through_scoring_correlation_storage_and_api(self):
        rules = parse_rules({"schema_version": 1, "rules": [rule(threshold=10),
                            rule("syn_flood", threshold=30, base_score=60)]})
        engine = RuleEngine(rules)
        correlation = CorrelationEngine(policy("network_sequence"))
        alerts, incidents = [], []
        engine.subscribe(alerts.append)
        engine.subscribe(self.store.insert_alert)
        engine.subscribe(correlation)
        correlation.subscribe(self.store.save_incident)
        correlation.subscribe(incidents.append)
        router = EventRouter()
        router.subscribe(engine)
        router.subscribe(self.store.insert)
        for port in range(1000, 1050):
            event = network(timestamp=NS, dst_port=port)
            before = event.to_dict()
            router.route(event)
            self.assertEqual(event.to_dict(), before)
        self.assertEqual(alerts, [])
        engine.tick(4*NS)
        scan, flood = alerts
        self.assertEqual(scan.metadata["unique_port_count"], 50)
        self.assertEqual(scan.risk_score, 40)
        self.assertEqual(flood.risk_score, 60)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].risk_score, 65)
        engine.flush()
        self.assertEqual(len(alerts), 2)
        with TestClient(create_app(self.path)) as client:
            self.assertEqual(len(client.get("/events").json()), 50)
            self.assertEqual(client.get("/incidents").json(), [incidents[0].to_dict()])

    def test_host_normalization_to_incident_and_api(self):
        rules = parse_rules({"schema_version": 1, "rules": [rule("process_match", base_score=30),
                            rule("syscall_match", base_score=20)]})
        engine = RuleEngine(rules)
        correlation = CorrelationEngine(policy("host_sequence"))
        engine.subscribe(self.store.insert_alert)
        engine.subscribe(correlation)
        correlation.subscribe(self.store.save_incident)
        process = host("process", timestamp=NS)
        syscall = host("syscall", timestamp=2*NS, pid=process.pid, syscall_return=-1)
        for event in (process, syscall):
            before = event.to_dict()
            engine(event)
            self.assertEqual(before, event.to_dict())
        result, = self.store.list_incidents()
        self.assertEqual(result.risk_score, 35)
        self.assertEqual(result.primary_entities, {"pid": process.pid})
        with TestClient(create_app(self.path)) as client:
            self.assertEqual(client.get(f"/incidents/{result.incident_id}").json(), result.to_dict())
