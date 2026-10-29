"""M10 deterministic correlation against real validated M9 Alerts."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

import yaml

from backend.alerts import severity_for_score
from backend.correlation import CorrelationEngine
from backend.correlation_config import DEFAULT_POLICY, load_policy, parse_policy, CorrelationConfigError
from backend.incidents import Incident
from backend.scoring import Scorer
from backend.rule_config import MAX_CONFIG_BYTES, TYPE_CATEGORIES

NS = 1_000_000_000
SRC, DST = "192.0.2.1", "192.0.2.2"
SCORER = Scorer.from_file()


def policy(*families, **limits):
    document = yaml.safe_load(DEFAULT_POLICY.read_text())
    document["monitored_ips"] = [DST]
    if families:
        for name, config in document["correlation"].items():
            config["enabled"] = name in families
    document["limits"].update(limits)
    return document


def alert(kind="port_scan", seconds=1, *, base_override=None, **metadata):
    evidence = {"src_ip": SRC, "dst_ip": DST, "pid": 42, "uid": 0, "previous_uid": 1000,
                "syscall_return": 0, "unique_port_count": 50, "threshold": 10,
                "matching_event_count": 10, "process_name": "test-helper"}
    evidence.update(metadata)
    return SCORER.alert(timestamp=int(seconds * NS), rule_id=kind, rule_name=kind,
                        alert_type=kind, event_category=TYPE_CATEGORIES[kind],
                        source_event_ids=(str(uuid4()),), description="Test detection",
                        metadata=evidence, base_override=base_override)


class CorrelationConfigTests(unittest.TestCase):
    def test_shipped_policy_and_exact_nanoseconds(self):
        loaded = load_policy()
        self.assertEqual([rule.window_ns for rule in loaded.rules], [60*NS, 30*NS, 60*NS])
        self.assertEqual(loaded.monitored_ips, ())
        document = policy()
        document["correlation"]["network_sequence"]["window_seconds"] = 0.000000001
        self.assertEqual(parse_policy(document).rules[0].window_ns, 1)
        self.assertEqual(CorrelationEngine.from_file(DEFAULT_POLICY).policy, loaded)
        document["limits"]["max_pending_alerts"] = 2
        engine = CorrelationEngine(document)
        document["limits"].clear()
        self.assertEqual(engine.policy.max_pending_alerts, 2)

    def test_invalid_schema_unknown_missing_fields_and_types(self):
        bad = [None, [], {}, {**policy(), "unknown": 1}, {**policy(), "schema_version": True},
               {**policy(), "schema_version": 2}, {**policy(), "monitored_ips": [DST, DST]},
               {**policy(), "monitored_ips": [None]}, {**policy(), "monitored_ips": ["0.0.0.0"]},
               {**policy(), "monitored_ips": ["224.0.0.1"]}, {**policy(), "monitored_ips": ["::1"]},
               {**policy(), "monitored_ips": "192.0.2.2"}, {**policy(), "monitored_ips": [DST]*33}]
        for key, value in (("window_seconds", 0), ("window_seconds", -1), ("window_seconds", True),
                           ("window_seconds", 86401), ("window_seconds", 1e-10),
                           ("window_seconds", float("inf")), ("window_seconds", float("nan")),
                           ("window_seconds", "60"), ("enabled", 1), ("extra", 2)):
            doc = policy()
            doc["correlation"]["network_sequence"][key] = value
            bad.append(doc)
        for part, key in (("correlation", "host_sequence"), ("limits", "max_seen_alerts")):
            doc = policy(); del doc[part][key]; bad.append(doc)
        for key in policy()["limits"]:
            for value in (0, -1, True, 1.5, "2", 10**9):
                doc = policy(); doc["limits"][key] = value; bad.append(doc)
        for doc in bad:
            with self.subTest(document=doc), self.assertRaises(CorrelationConfigError):
                parse_policy(doc)

    def test_malformed_duplicate_executable_and_oversized_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"correlation.yaml"
            for text in ("[", "!!python/object:bad {}", DEFAULT_POLICY.read_text()+"\nschema_version: 1\n",
                         DEFAULT_POLICY.read_text().replace("window_seconds: 60", "window_seconds: 60\n    window_seconds: 30", 1),
                         "#"*(MAX_CONFIG_BYTES+1)):
                path.write_text(text)
                with self.assertRaises(CorrelationConfigError):
                    load_policy(path)
            path.write_bytes(b"\xff")
            with self.assertRaises(CorrelationConfigError):
                load_policy(path)

    def test_disabled_rules_do_not_create_incidents(self):
        document = policy()
        for config in document["correlation"].values():
            config["enabled"] = False
        engine = CorrelationEngine(document)
        for kind in TYPE_CATEGORIES:
            self.assertEqual(engine.evaluate(alert(kind)), [])
        self.assertEqual(engine.state_counts["pending_alerts"], 0)


class CorrelationTests(unittest.TestCase):
    def test_network_scan_alone_and_same_type_are_not_incidents(self):
        engine = CorrelationEngine(policy("network_sequence"))
        self.assertEqual(engine.evaluate(alert()), [])
        self.assertEqual(engine.evaluate(alert(seconds=2)), [])

    def test_network_pair_creates_and_updates_one_incident(self):
        engine = CorrelationEngine(policy("network_sequence"))
        scan, flood, extra = alert(), alert("syn_flood", 10), alert("traffic_flood", 20)
        self.assertEqual(engine.evaluate(scan), [])
        first, = engine.evaluate(flood)
        updated, = engine.evaluate(extra)
        self.assertEqual(first.incident_id, updated.incident_id)
        self.assertEqual(updated.alert_ids, (scan.alert_id, flood.alert_id, extra.alert_id))
        self.assertEqual(first.alert_ids, (scan.alert_id, flood.alert_id))
        self.assertEqual(updated.primary_entities, {"src_ip": SRC, "dst_ip": DST})
        self.assertEqual(updated.risk_score, 65)
        self.assertEqual(updated.severity, "high")
        self.assertEqual(updated.status, "open")
        self.assertEqual(updated.updated_timestamp, 20*NS)
        self.assertEqual(UUID(updated.incident_id).version, 4)
        for item in (scan, flood, extra, extra):
            self.assertEqual(engine.evaluate(item), [])

    def test_network_sources_and_destinations_are_isolated(self):
        engine = CorrelationEngine(policy("network_sequence"))
        a = alert()
        engine.evaluate(a)
        self.assertEqual(engine.evaluate(alert("syn_flood", 2, src_ip="192.0.2.3")), [])
        self.assertEqual(engine.evaluate(alert("syn_flood", 2, dst_ip="192.0.2.4")), [])
        first, = engine.evaluate(alert("syn_flood", 3))
        second, = engine.evaluate(alert(seconds=4, src_ip="192.0.2.3"))
        third, = engine.evaluate(alert(seconds=4, dst_ip="192.0.2.4"))
        self.assertEqual(len({first.incident_id, second.incident_id, third.incident_id}), 3)

    def test_window_inclusive_boundary_and_one_nanosecond_outside(self):
        for family, first_kind, second_kind, window in (
                ("network_sequence", "port_scan", "syn_flood", 60),
                ("host_sequence", "process_match", "syscall_match", 30),
                ("hybrid_activity", "syn_flood", "privilege_change", 60)):
            for delta, expected in ((0, 1), (1, 0)):
                engine = CorrelationEngine(policy(family))
                engine.evaluate(alert(first_kind))
                second = replace(alert(second_kind), timestamp=(window+1)*NS+delta)
                with self.subTest(family=family, delta=delta):
                    self.assertEqual(len(engine.evaluate(second)), expected)

    def test_out_of_order_is_bounded_and_does_not_regress_updated_time(self):
        engine = CorrelationEngine(policy("network_sequence"))
        engine.evaluate(alert("syn_flood", 20))
        first, = engine.evaluate(alert(seconds=10))
        self.assertEqual((first.created_timestamp, first.updated_timestamp), (10*NS, 20*NS))
        updated, = engine.evaluate(alert("traffic_flood", 5))
        self.assertEqual(updated.incident_id, first.incident_id)
        self.assertEqual((updated.created_timestamp, updated.updated_timestamp), (5*NS, 20*NS))
        engine.advance_time(100*NS)
        self.assertEqual(engine.evaluate(alert(seconds=2)), [])
        self.assertEqual(engine.state_counts["open_incidents"], 0)

    def test_fixed_window_does_not_slide_forever_or_reuse_old_members(self):
        engine = CorrelationEngine(policy("network_sequence"))
        engine.evaluate(alert(seconds=1))
        old, = engine.evaluate(alert("syn_flood", 2))
        engine.evaluate(alert("syn_flood", 60))
        self.assertEqual(engine.evaluate(alert("syn_flood", 62)), [])
        new, = engine.evaluate(alert(seconds=63))
        self.assertNotEqual(old.incident_id, new.incident_id)
        self.assertEqual(len(new.alert_ids), 2)
        self.assertEqual(new.created_timestamp, 62*NS)

    def test_host_two_types_same_pid_then_three_types(self):
        engine = CorrelationEngine(policy("host_sequence"))
        process, syscall, privilege = alert("process_match"), alert("syscall_match", 2), alert("privilege_change", 3)
        self.assertEqual(engine.evaluate(process), [])
        first, = engine.evaluate(syscall)
        self.assertEqual(first.risk_score, 35)
        updated, = engine.evaluate(privilege)
        self.assertEqual(updated.incident_id, first.incident_id)
        self.assertEqual(updated.risk_score, 80)
        self.assertEqual(updated.severity, "critical")
        self.assertEqual(updated.primary_entities, {"pid": 42})
        self.assertEqual(updated.metadata["alert_types"], sorted(("process_match", "syscall_match", "privilege_change")))

    def test_host_all_distinct_type_pairs_and_pid_isolation(self):
        for left, right in (("process_match", "syscall_match"), ("process_match", "privilege_change"),
                            ("syscall_match", "privilege_change")):
            engine = CorrelationEngine(policy("host_sequence"))
            engine.evaluate(alert(left))
            self.assertEqual(engine.evaluate(alert(right, 2, pid=999)), [])
            self.assertEqual(engine.evaluate(alert(left, 2)), [])
            self.assertEqual(len(engine.evaluate(alert(right, 3))), 1)

    def test_unavailable_or_invalid_entities_and_unknown_alert_types_are_ignored(self):
        engine = CorrelationEngine(policy())
        for item in (alert(pid=0, src_ip="bad"), alert(dst_ip=None),
                     alert("process_match", pid=None), alert("process_match", pid=True),
                     alert("syscall_match", pid=0), replace(alert(), alert_type="unknown"),
                     replace(alert(), event_category="process")):
            self.assertEqual(engine.evaluate(item), [])
        self.assertEqual(engine.state_counts["pending_alerts"], 0)

    def test_hybrid_requires_configured_destination_strong_flood_and_successful_root_change(self):
        for network, host_alert in (
                (alert(), alert("privilege_change")),
                (alert("syn_flood", dst_ip="192.0.2.9"), alert("privilege_change")),
                (alert("syn_flood", base_override=40), alert("privilege_change")),
                (alert("syn_flood"), alert("process_match")),
                (alert("syn_flood"), alert("syscall_match")),
                (alert("syn_flood"), alert("privilege_change", syscall_return=-1)),
                (alert("syn_flood"), alert("privilege_change", previous_uid=0)),
                (alert("syn_flood"), alert("privilege_change", uid=1000)),
                (alert("syn_flood"), alert("privilege_change", base_override=0))):
            engine = CorrelationEngine(policy("hybrid_activity"))
            engine.evaluate(network)
            self.assertEqual(engine.evaluate(host_alert), [])
        engine = CorrelationEngine()
        engine.evaluate(alert("syn_flood"))
        self.assertEqual(engine.evaluate(alert("privilege_change")), [])

    def test_hybrid_both_arrival_orders_explicit_context_not_attribution(self):
        for reverse in (False, True):
            engine = CorrelationEngine(policy("hybrid_activity"))
            items = [alert("traffic_flood", 1), alert("privilege_change", 2)]
            if reverse:
                items.reverse()
            self.assertEqual(engine.evaluate(items[0]), [])
            result, = engine.evaluate(items[1])
            self.assertEqual(result.risk_score, 80)
            self.assertEqual(result.metadata["relationship"], "temporal_contextual")
            self.assertIs(result.metadata["exact_process_network_attribution"], False)
            self.assertIn("does not establish process-to-network attribution", result.description)
            self.assertEqual(result.metadata["shared_entities"], {"monitored_ip": DST})
            self.assertEqual(result.primary_entities, {"src_ip": SRC, "dst_ip": DST, "pid": 42})

    def test_hybrid_reuses_context_for_updates_without_pair_fanout(self):
        engine = CorrelationEngine(policy("hybrid_activity"))
        engine.evaluate(alert("syn_flood", src_ip="192.0.2.3"))
        engine.evaluate(alert("syn_flood"))
        first, = engine.evaluate(alert("privilege_change", 2))
        self.assertEqual(first.primary_entities["src_ip"], SRC)
        updated, = engine.evaluate(alert("traffic_flood", 3))
        self.assertEqual(first.incident_id, updated.incident_id)
        other, = engine.evaluate(alert("privilege_change", 4, pid=43))
        self.assertEqual(other.primary_entities["src_ip"], "192.0.2.3")
        self.assertNotEqual(first.incident_id, other.incident_id)

    def test_scoring_deterministic_capped_and_alerts_unchanged(self):
        items = [alert("process_match", base_override=99), alert("syscall_match", 2)]
        originals = [item.to_dict() for item in items]
        results = []
        for _ in range(2):
            engine = CorrelationEngine(policy("host_sequence"))
            engine.evaluate(items[0])
            result, = engine.evaluate(items[1])
            results.append(result)
        self.assertEqual(results[0].risk_score, 100)
        self.assertEqual(results[0].severity, severity_for_score(100))
        self.assertEqual(results[0].metadata, results[1].metadata)
        results[0].primary_entities["pid"] = 1
        results[0].metadata["alert_types"].clear()
        self.assertEqual([item.to_dict() for item in items], originals)

    def test_incident_score_uses_existing_severity_boundaries(self):
        for highest, score in ((0, 5), (14, 19), (15, 20), (44, 49), (45, 50), (74, 79), (75, 80), (100, 100)):
            engine = CorrelationEngine(policy("host_sequence"))
            engine.evaluate(alert("process_match", base_override=highest))
            incident, = engine.evaluate(alert("syscall_match", base_override=0))
            self.assertEqual(incident.risk_score, score)
            self.assertEqual(incident.severity, severity_for_score(score))

    def test_expiration_and_all_state_bounds_under_large_input(self):
        engine = CorrelationEngine(policy("network_sequence", max_pending_alerts=5,
                                         max_open_incidents=2, max_alerts_per_incident=3, max_seen_alerts=6))
        for source in (SRC, "192.0.2.3", "192.0.2.4"):
            engine.evaluate(alert(src_ip=source))
            engine.evaluate(alert("syn_flood", 2, src_ip=source))
        self.assertEqual(engine.state_counts["open_incidents"], 2)
        for index in range(1000):
            engine.evaluate(alert("syn_flood", 3, src_ip=SRC if index % 2 else "192.0.2.8"))
            counts = engine.state_counts
            self.assertLessEqual(counts["pending_alerts"], 5)
            self.assertLessEqual(counts["seen_alerts"], 6)
            self.assertLessEqual(counts["incident_alert_references"], 6)
            self.assertLessEqual(counts["open_incidents"], 2)
        engine.advance_time(100*NS)
        self.assertEqual(engine.state_counts, dict(pending_alerts=0, seen_alerts=0, open_incidents=0, incident_alert_references=0))

    def test_incident_alert_cap_does_not_spawn_overflow_incidents(self):
        engine = CorrelationEngine(policy("network_sequence", max_alerts_per_incident=3, max_seen_alerts=2,
                                         max_pending_alerts=2))
        first_alert = alert()
        engine.evaluate(first_alert)
        first, = engine.evaluate(alert("syn_flood", 2))
        full, = engine.evaluate(alert("traffic_flood", 3))
        self.assertEqual(first.incident_id, full.incident_id)
        self.assertTrue(full.metadata["alert_limit_reached"])
        for _ in range(10):
            self.assertEqual(engine.evaluate(alert("syn_flood", 4)), [])
        self.assertEqual(engine.evaluate(first_alert), [])
        self.assertEqual(engine.state_counts["open_incidents"], 1)

    def test_expired_pending_alerts_and_backward_clock(self):
        engine = CorrelationEngine(policy("host_sequence"))
        engine.evaluate(alert("process_match"))
        engine.advance_time(32*NS)
        engine.advance_time(0)
        self.assertEqual(engine.state_counts["pending_alerts"], 0)
        for value in (True, -1, 2**64, 1.2):
            with self.assertRaises(ValueError):
                engine.advance_time(value)

    def test_rule_failure_isolation_and_subscriber_snapshot_isolation(self):
        engine = CorrelationEngine(policy())
        engine.evaluate(alert("syn_flood"))
        engine.evaluate(alert("process_match"))
        original = engine._evaluate_rule
        def broken(family, item):
            if family == "host_sequence":
                raise RuntimeError("test failure")
            return original(family, item)
        with patch.object(engine, "_evaluate_rule", side_effect=broken), self.assertLogs("backend.correlation", level="ERROR"):
            result, = engine.evaluate(alert("privilege_change", 2))
        self.assertEqual(result.incident_type, "hybrid_activity")
        observed = []
        def bad_sink(incident):
            incident.metadata.clear()
            raise RuntimeError("sink failed")
        engine.subscribe(bad_sink)
        engine.subscribe(observed.append)
        with self.assertLogs("backend.correlation", level="ERROR"):
            engine(alert("traffic_flood", 3))
        self.assertTrue(observed)
        self.assertTrue(all(item.metadata for item in observed))
        with self.assertRaises(ValueError):
            engine.evaluate({})
        with self.assertLogs("backend.correlation", level="ERROR"):
            self.assertEqual(engine({}), [])

    def test_incident_model_validation_and_json_roundtrip(self):
        engine = CorrelationEngine(policy("network_sequence"))
        engine.evaluate(alert())
        item, = engine.evaluate(alert("syn_flood", 2))
        self.assertEqual(Incident.from_dict(item.to_dict()), item)
        for changes in ({"risk_score": True}, {"risk_score": 101}, {"severity": "medium"},
                        {"status": "closed"}, {"alert_ids": (item.alert_ids[0],)*2},
                        {"alert_ids": ()}, {"incident_id": "bad"}, {"updated_timestamp": 0},
                        {"metadata": {}}, {"primary_entities": []}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(item, **changes)
