"""M8 rules against real M6 normalization, deterministic event time, and IPC."""

import copy
import json
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

import yaml

from backend.alerts import Alert
from backend.events import normalize_message
from backend.pipeline import EventRouter, receive_events
from backend.rule_config import MAX_CONFIG_BYTES, RuleConfigError, load_rules, parse_rules
from backend.rules import RuleEngine
from backend.storage import EventStore
from test_host import host_message
import test_ipc

NS = 1_000_000_000


def rule(kind="port_scan", **overrides):
    category = {"process_match": "process", "syscall_match": "syscall",
                "privilege_change": "privilege"}.get(kind, "network")
    result = {"id": kind, "name": f"Test {kind}", "enabled": True,
              "category": category, "type": kind, "base_score": 30 if kind == "port_scan" else 35,
              "description": "Configured test condition"}
    if category == "network":
        result.update(threshold=3, window_seconds=5, max_groups=4)
    else:
        result["match"] = {"process_match": {"process_name": ["host-helper"]},
                           "syscall_match": {"syscall": ["setuid"], "syscall_return": [-1]},
                           "privilege_change": {"uid": [0], "uid_changed": True}}[kind]
    result.update(overrides)
    return result


def engine(*rules):
    return RuleEngine(parse_rules({"schema_version": 1, "rules": list(rules)}))


def network(timestamp=NS, **values):
    message = copy.deepcopy(test_ipc.EVENT)
    message["event"].update(timestamp=timestamp, **values)
    return normalize_message(message)


def host(category="process", timestamp=NS, **values):
    message = host_message(category)
    message["event"].update(timestamp=timestamp, **values)
    return normalize_message(message)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "rules.yaml"

    def write(self, data):
        self.path.write_text(data)
        return load_rules(self.path)

    def test_load_shipped_yaml_and_empty_configuration(self):
        rules = load_rules(test_ipc.ROOT / "config/rules.yaml")
        self.assertEqual({item.type for item in rules},
                         {"port_scan", "syn_flood", "traffic_flood", "process_match",
                          "syscall_match", "privilege_change"})
        self.assertEqual(len({item.id for item in rules}), len(rules))
        self.assertEqual(engine().evaluate(network()), [])
        self.assertEqual(self.write("schema_version: 1\nrules: []\n"), ())
        with self.assertRaises(TypeError):
            rules[-1].match["uid"] = (1000,)

    def test_fractional_nanosecond_windows_convert_without_float_timestamp_math(self):
        rules = parse_rules({"schema_version": 1, "rules": [rule(window_seconds=0.001)]})
        self.assertEqual(rules[0].window_ns, 1_000_000)
        self.assertEqual(rules[0].quiet_ns, 3 * NS)
        self.assertEqual(rules[0].max_detection_ns, 60 * NS)
        self.assertEqual(rules[0].max_event_ids, 64)
        custom = parse_rules({"schema_version": 1, "rules": [
            rule(window_seconds=0.001, quiet_seconds=0.01, max_detection_seconds=0.5)]})[0]
        self.assertEqual((custom.quiet_ns, custom.max_detection_ns), (10_000_000, 500_000_000))

    def test_invalid_rules_are_rejected_including_disabled_entries(self):
        bad_values = [rule(id="bad id"), rule(enabled="false"), rule(enabled=1),
                      rule(base_score="urgent"), rule(type="unknown"), rule(category="process"),
                      rule(threshold=0), rule(threshold=True), rule(threshold=4097),
                      rule(threshold=1.5), rule(window_seconds=0), rule(window_seconds=True),
                      rule(window_seconds=float("nan")), rule(window_seconds=float("inf")),
                      rule(window_seconds=1e-10), rule(window_seconds=86401),
                      rule(max_groups=0), rule(max_groups=4097), rule(extra=True),
                      rule(quiet_seconds=0), rule(quiet_seconds=True),
                      rule(quiet_seconds=float("nan")), rule(quiet_seconds=86401),
                      rule(max_detection_seconds=0), rule(max_detection_seconds=True),
                      rule(max_detection_seconds=float("inf")), rule(max_detection_seconds=86401),
                      rule(max_detection_seconds=4),
                      rule(window_seconds=1, quiet_seconds=3, max_detection_seconds=2),
                      rule(quiet_seconds=1e-10), rule(max_detection_seconds=1e-10),
                      rule(quiet_seconds="3"), rule(max_detection_seconds="60"),
                      rule(max_event_ids=1), rule(max_event_ids=257), rule(max_event_ids=True),
                      rule(name=""), rule(description=None),
                      rule("process_match", match={}),
                      rule("process_match", match={"process_name": "bash"}),
                      rule("process_match", match={"process_name": ["x" * 16]}),
                      rule("process_match", match={"process_path": [None]}),
                      rule("process_match", match={"unknown": ["bash"]}),
                      rule("syscall_match", match={"syscall_return": [-1]}),
                      rule("syscall_match", match={"syscall": ["execve"]}),
                      rule("syscall_match", match={"syscall": ["setuid"], "uid": [True]}),
                      rule("syscall_match", match={"syscall": ["setuid"], "syscall_return": [2**63]}),
                      rule("privilege_change", match={"syscall": ["setuid"]}),
                      rule("privilege_change", match={"uid_changed": "yes"}),
                      rule("privilege_change", match={"previous_uid": [-1]}),
                      rule("port_scan", enabled=False, threshold=-1), [], None]
        missing = rule()
        del missing["threshold"]
        bad_values.append(missing)
        for value in bad_values:
            with self.subTest(value=value), self.assertRaises(RuleConfigError):
                parse_rules({"schema_version": 1, "rules": [value]})
        for document in (None, {}, [], {"schema_version": True, "rules": []},
                         {"schema_version": 2, "rules": []}, {"schema_version": 1, "rules": {}},
                         {"schema_version": 1, "rules": [rule(), rule()]},
                         {"schema_version": 1, "rules": [rule()] * 129}):
            with self.subTest(document=document), self.assertRaises(RuleConfigError):
                parse_rules(document)

    def test_malformed_duplicate_unsafe_and_oversized_yaml(self):
        valid = yaml.safe_dump({"schema_version": 1, "rules": [rule()]})
        for text in ("rules: [", "!!python/object/apply:os.system ['echo bad']",
                     valid + "schema_version: 1\n", valid.replace("enabled: true", "enabled: true\n  enabled: false"),
                     "schema_version: 1\nrules: []\n? [non, scalar]\n: key\n",
                     " " * (MAX_CONFIG_BYTES + 1)):
            with self.subTest(text=text[:80]), self.assertRaises(RuleConfigError):
                self.write(text)
        self.path.write_bytes(b'\xff')
        with self.assertRaises(RuleConfigError):
            load_rules(self.path)
        with self.assertRaises(OSError):
            load_rules(self.path.with_name("missing.yaml"))


class HostRuleTests(unittest.TestCase):
    def test_disabled_rules_do_not_match_or_allocate_state(self):
        detector = engine(rule(enabled=False, threshold=1), rule("process_match", enabled=False))
        self.assertEqual(detector.evaluate(network()), [])
        self.assertEqual(detector.evaluate(host()), [])
        self.assertEqual(detector._runtimes, [])

    def test_process_name_and_path_matching_and_conjunction(self):
        names = engine(rule("process_match"))
        self.assertEqual(len(names.evaluate(host())), 1)
        self.assertEqual(names.evaluate(host(process_name="bash")), [])
        paths = engine(rule("process_match", match={"process_path": ["/usr/bin/true", "/tmp/tool"]}))
        self.assertEqual(len(paths.evaluate(host())), 1)
        self.assertEqual(paths.evaluate(host(process_path=None)), [])
        self.assertEqual(paths.evaluate(host(process_path="/usr/bin/true-extra")), [])
        both = engine(rule("process_match", match={"process_name": ["host-helper"],
                                                   "process_path": ["/tmp/tool"]}))
        self.assertEqual(both.evaluate(host()), [])
        self.assertEqual(len(both.evaluate(host(process_path="/tmp/tool"))), 1)
        self.assertEqual(names.evaluate(host("syscall")), [])

    def test_sensitive_syscall_matches_only_configured_conditions(self):
        detector = engine(rule("syscall_match", match={"syscall": ["setuid", "setgid"],
                                                       "syscall_return": [-1], "uid": [1000]}))
        for syscall in ("setuid", "setgid"):
            alerts = detector.evaluate(host("syscall", syscall=syscall))
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].metadata["syscall_return"], -1)
        self.assertEqual(detector.evaluate(host("syscall", syscall_return=0)), [])
        self.assertEqual(detector.evaluate(host("syscall", uid=0)), [])
        self.assertEqual(detector.evaluate(host("privilege")), [])

    def test_privilege_requires_configured_credential_change(self):
        detector = engine(rule("privilege_change"))
        self.assertEqual(detector.evaluate(host("privilege")), [])  # root -> user is not this condition.
        root = host("privilege", uid=0, previous_uid=1000)
        self.assertEqual(len(detector.evaluate(root)), 1)
        # Remaining root while changing GID is not a UID change to root.
        self.assertEqual(detector.evaluate(host("privilege", uid=0, previous_uid=0,
                                                gid=0, previous_gid=1000)), [])
        gids = engine(rule("privilege_change", match={"gid": [0], "previous_gid": [1000],
                                                       "gid_changed": True, "syscall": ["setgid"]}))
        self.assertEqual(len(gids.evaluate(host("privilege", syscall="setgid", previous_uid=1000,
                                                 gid=0, previous_gid=1000))), 1)
        self.assertEqual(gids.evaluate(root), [])

    def test_shipped_policy_does_not_alert_on_all_syscalls_or_privileges(self):
        detector = RuleEngine(load_rules(test_ipc.ROOT / "config/rules.yaml"))
        self.assertEqual(detector.evaluate(host()), [])
        self.assertEqual(detector.evaluate(host("syscall", syscall_return=0)), [])
        self.assertEqual(detector.evaluate(host("privilege")), [])
        self.assertEqual([alert.rule_id for alert in detector.evaluate(host("syscall"))],
                         ["denied_credential_syscall"])

    def test_alert_structure_scored_severity_unique_ids_and_event_immutability(self):
        event = host("privilege", uid=0, previous_uid=1000)
        before = event.to_dict()
        detector = engine(rule("privilege_change", base_score=50))
        first, second = detector.evaluate(event)[0], detector.evaluate(event)[0]
        self.assertIsInstance(first, Alert)
        self.assertEqual(UUID(first.alert_id).version, 4)
        self.assertNotEqual(first.alert_id, second.alert_id)
        self.assertEqual(first.timestamp, event.timestamp)
        self.assertEqual(first.source_event_ids, (event.event_id,))
        self.assertEqual(first.severity, "high")
        self.assertEqual(first.metadata["previous_uid"], 1000)
        self.assertEqual(first.to_dict()["source_event_ids"], [event.event_id])
        self.assertEqual(json.loads(json.dumps(first.to_dict())), first.to_dict())
        first.metadata["previous_uid"] = 99
        self.assertEqual(event.to_dict(), before)


class NetworkRuleTests(unittest.TestCase):
    def test_fifty_port_scan_emits_one_complete_alert_after_quiet(self):
        detector = engine(rule(threshold=10, max_event_ids=8))
        events = [network(timestamp=NS + index * 50_000_000, dst_port=1000 + index)
                  for index in range(50)]
        for index, event in enumerate(events, 1):
            before = event.to_dict()
            self.assertEqual(detector.evaluate(event), [])
            self.assertEqual(event.to_dict(), before)
            if index in (10, 20, 30, 50):
                self.assertEqual(len(detector._runtimes[0].groups), 1)
                self.assertTrue(next(iter(detector._runtimes[0].groups.values())).active)
        last = events[-1].timestamp
        self.assertEqual(detector.advance_time(last + 3 * NS - 1), [])
        alerts = detector.advance_time(last + 3 * NS)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.metadata["unique_port_count"], 50)
        self.assertEqual(alert.metadata["matching_event_count"], 50)
        self.assertEqual(alert.metadata["destination_ports"], list(range(1000, 1050)))
        self.assertEqual(alert.metadata["first_timestamp"], events[0].timestamp)
        self.assertEqual(alert.metadata["threshold_timestamp"], events[9].timestamp)
        self.assertEqual(alert.metadata["last_timestamp"], last)
        self.assertEqual(alert.metadata["duration_ns"], last - events[0].timestamp)
        self.assertEqual(alert.metadata["finalization_reason"], "quiet")
        self.assertLessEqual(len(alert.source_event_ids), 8)
        self.assertIn(events[0].event_id, alert.source_event_ids)
        self.assertIn(events[-1].event_id, alert.source_event_ids)
        self.assertTrue(alert.metadata["source_event_ids_truncated"])
        self.assertEqual(detector.advance_time(last + 10 * NS), [])
        self.assertEqual(detector.flush(), [])
        self.assertEqual(detector._runtimes[0].groups, {})

    def test_new_ten_port_scan_after_fifty_port_session_gets_its_own_alert(self):
        detector = engine(rule(threshold=10))
        for port in range(1000, 1050):
            self.assertEqual(detector.evaluate(network(timestamp=NS, dst_port=port)), [])
        first = detector.advance_time(4 * NS)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0].metadata["unique_port_count"], 50)
        for port in range(2000, 2010):
            self.assertEqual(detector.evaluate(network(timestamp=5 * NS, dst_port=port)), [])
        second = detector.advance_time(8 * NS)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first[0].alert_id, second[0].alert_id)
        self.assertEqual(second[0].metadata["unique_port_count"], 10)
        self.assertEqual(second[0].metadata["destination_ports"], list(range(2000, 2010)))
        self.assertEqual(detector.flush(), [])

    def test_repeated_ports_do_not_confirm_scan_but_all_attempts_extend_active_session(self):
        detector = engine(rule())
        for _ in range(20):
            self.assertEqual(detector.evaluate(network(dst_port=80)), [])
        session = next(iter(detector._runtimes[0].groups.values()))
        self.assertFalse(session.active)
        self.assertEqual(len(session.pending), 1)
        detector.evaluate(network(timestamp=2 * NS, dst_port=81))
        detector.evaluate(network(timestamp=3 * NS, dst_port=82))
        self.assertTrue(session.active)
        detector.evaluate(network(timestamp=5 * NS, dst_port=80))
        self.assertEqual(detector.advance_time(6 * NS), [])  # repeated port extended quiet deadline
        alert = detector.advance_time(8 * NS)[0]
        self.assertEqual(alert.metadata["unique_port_count"], 3)
        self.assertEqual(alert.metadata["matching_event_count"], 23)
        self.assertEqual(alert.metadata["first_timestamp"], NS)
        self.assertEqual(alert.metadata["threshold_timestamp"], 3 * NS)

    def test_floods_accumulate_full_activity_not_threshold_batches(self):
        for kind in ("syn_flood", "traffic_flood"):
            with self.subTest(kind=kind):
                detector = engine(rule(kind, threshold=5, max_event_ids=8))
                events = [network(timestamp=NS + index * 1_000_000) for index in range(100)]
                for event in events:
                    self.assertEqual(detector.evaluate(event), [])
                alert = detector.advance_time(events[-1].timestamp + 3 * NS)[0]
                self.assertEqual(alert.metadata["matching_event_count"], 100)
                self.assertNotIn("count", alert.metadata)
                self.assertNotIn("unique_port_count", alert.metadata)
                self.assertEqual(alert.metadata["threshold_timestamp"], events[4].timestamp)
                self.assertEqual(alert.metadata["last_timestamp"], events[-1].timestamp)
                self.assertLessEqual(len(alert.source_event_ids), 8)
                self.assertEqual(detector.flush(), [])

    def test_syn_attempt_filter_and_duplicate_event_replays(self):
        detector = engine(rule("syn_flood"))
        for flags in (0, 16, 18):
            self.assertEqual(detector.evaluate(network(tcp_flags=flags)), [])
        self.assertEqual(detector.evaluate(network(protocol="UDP", tcp_flags=0)), [])
        events = [network() for _ in range(3)]
        for event in events:
            self.assertEqual(detector.evaluate(event), [])
            self.assertEqual(detector.evaluate(event), [])
        self.assertEqual(detector.evaluate(events[0]), [])  # replay while ACTIVE
        alert = detector.advance_time(4 * NS)[0]
        self.assertEqual(set(alert.source_event_ids), {event.event_id for event in events})
        self.assertEqual(alert.metadata["matching_event_count"], 3)
        self.assertFalse(alert.metadata["source_event_ids_truncated"])

    def test_traffic_flood_includes_tcp_udp_icmp_and_excludes_other(self):
        detector = engine(rule("traffic_flood"))
        other = network(protocol="OTHER", src_ip="0.0.0.0", dst_ip="0.0.0.0",
                        src_port=0, dst_port=0, tcp_flags=0)
        self.assertEqual(detector.evaluate(other), [])
        self.assertEqual(detector.evaluate(network()), [])
        self.assertEqual(detector.evaluate(network(protocol="UDP", tcp_flags=0)), [])
        self.assertEqual(detector.evaluate(network(protocol="ICMP", tcp_flags=0,
                                                    src_port=0, dst_port=0)), [])
        self.assertEqual(detector.advance_time(4 * NS)[0].metadata["matching_event_count"], 3)

    def test_sources_destinations_and_rules_have_independent_sessions(self):
        detector = engine(rule(threshold=1, quiet_seconds=2),
                          rule(threshold=1, id="second", quiet_seconds=3))
        for values in ({}, {"src_ip": "192.0.2.3"}, {"dst_ip": "192.0.2.4"}):
            self.assertEqual(detector.evaluate(network(**values)), [])
        first = detector.advance_time(3 * NS)
        self.assertEqual(len(first), 3)
        self.assertTrue(all(alert.rule_id == "port_scan" for alert in first))
        second = detector.advance_time(4 * NS)
        self.assertEqual(len(second), 3)
        self.assertTrue(all(alert.rule_id == "second" for alert in second))
        pairs = {(alert.metadata["src_ip"], alert.metadata["dst_ip"]) for alert in first}
        self.assertEqual(len(pairs), 3)

    def test_other_source_and_destination_finalize_while_first_session_is_still_active(self):
        detector = engine(rule(threshold=2))
        first = {"src_ip": "192.168.150.134", "dst_ip": "192.168.150.138"}
        other_source = {**first, "src_ip": "192.168.150.200"}
        other_destination = {**first, "dst_ip": "192.168.150.139"}
        for values, timestamp in ((first, NS), (other_source, 2 * NS),
                                  (other_destination, 2 * NS + NS // 2)):
            for port in (80, 81):
                detector.evaluate(network(timestamp=timestamp, dst_port=port, **values))
        # Keep the first session alive while the other two become quiet.
        detector.evaluate(network(timestamp=3 * NS + NS // 2, dst_port=82, **first))
        alerts = detector.advance_time(5 * NS)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].metadata["src_ip"], other_source["src_ip"])
        self.assertEqual(alerts[0].metadata["dst_ip"], first["dst_ip"])
        self.assertIn((first["src_ip"], first["dst_ip"]), detector._runtimes[0].groups)
        alerts = detector.advance_time(5 * NS + NS // 2)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].metadata["dst_ip"], other_destination["dst_ip"])
        last = detector.advance_time(6 * NS + NS // 2)
        self.assertEqual(len(last), 1)
        self.assertEqual(last[0].metadata["src_ip"], first["src_ip"])
        self.assertEqual(last[0].metadata["unique_port_count"], 3)

    def test_below_threshold_expires_without_alert_and_window_cutoff_is_exclusive(self):
        for kind in ("port_scan", "syn_flood", "traffic_flood"):
            with self.subTest(kind=kind):
                detector = engine(rule(kind, threshold=2, window_seconds=1))
                detector.evaluate(network(timestamp=NS, dst_port=80))
                self.assertEqual(detector.evaluate(network(timestamp=2 * NS, dst_port=81)), [])
                session = next(iter(detector._runtimes[0].groups.values()))
                self.assertFalse(session.active)
                self.assertEqual(session.matching_event_count, 1)
                self.assertEqual(detector.advance_time(3 * NS), [])
                self.assertEqual(detector._runtimes[0].groups, {})
                self.assertEqual(detector.flush(), [])

    def test_confirmation_window_is_separate_from_full_candidate_activity_totals(self):
        for kind in ("port_scan", "syn_flood", "traffic_flood"):
            detector = engine(rule(kind, threshold=3, window_seconds=2))
            for second in (1, 2, 3):
                self.assertEqual(detector.evaluate(network(timestamp=second * NS, dst_port=80 + second)), [])
            session = next(iter(detector._runtimes[0].groups.values()))
            self.assertFalse(session.active)  # Three overall, only two inside confirmation window.
            detector.evaluate(network(timestamp=3 * NS + 1, dst_port=84))
            self.assertTrue(session.active)
            alert = detector.advance_time(6 * NS + 1)[0]
            self.assertEqual(alert.metadata["matching_event_count"], 4)
            self.assertEqual(alert.metadata["first_timestamp"], NS)
            if kind == "port_scan":
                self.assertEqual(alert.metadata["unique_port_count"], 4)

    def test_confirmed_state_outlives_confirmation_window_and_host_events_finalize(self):
        detector = engine(rule(threshold=2, window_seconds=1, quiet_seconds=3))
        detector.evaluate(network(timestamp=NS, dst_port=80))
        detector.evaluate(network(timestamp=NS + 1, dst_port=81))
        detector.evaluate(network(timestamp=3 * NS, dst_port=82))
        self.assertEqual(detector.advance_time(5 * NS), [])
        alerts = detector.evaluate(host(timestamp=6 * NS))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].metadata["unique_port_count"], 3)
        self.assertEqual(alerts[0].metadata["first_timestamp"], NS)

    def test_out_of_order_events_and_backwards_ticks_do_not_regress_time(self):
        detector = engine(rule(threshold=3, window_seconds=2))
        detector.evaluate(network(timestamp=10 * NS, dst_port=80))
        detector.evaluate(network(timestamp=8 * NS, dst_port=81))  # outside window
        detector.evaluate(network(timestamp=9 * NS, dst_port=81))
        self.assertEqual(detector.evaluate(network(timestamp=9 * NS + 1, dst_port=82)), [])
        self.assertEqual(detector.advance_time(7 * NS), [])
        self.assertEqual(detector._watermark, 10 * NS)
        detector.evaluate(network(timestamp=8 * NS, dst_port=83))  # still too old
        alert = detector.advance_time(13 * NS)[0]
        self.assertEqual(alert.metadata["unique_port_count"], 3)
        self.assertEqual(alert.metadata["threshold_timestamp"], 10 * NS)
        self.assertEqual(alert.metadata["first_timestamp"], 9 * NS)
        self.assertEqual(alert.metadata["last_timestamp"], 10 * NS)
        # Delayed packets from the finalized session cannot reopen it.
        self.assertEqual(detector.evaluate(network(timestamp=10 * NS, dst_port=84)), [])
        self.assertEqual(detector._runtimes[0].groups, {})

    def test_late_confirmation_never_finalizes_before_threshold_timestamp(self):
        detector = engine(rule(threshold=3, window_seconds=5, quiet_seconds=1))
        detector.evaluate(network(timestamp=16 * NS, dst_port=80))
        detector.evaluate(network(timestamp=17 * NS, dst_port=81))
        detector.advance_time(20 * NS)
        alert = detector.evaluate(network(timestamp=18 * NS, dst_port=82))[0]
        self.assertEqual(alert.metadata["unique_port_count"], 3)
        self.assertEqual(alert.metadata["threshold_timestamp"], 20 * NS)
        self.assertEqual(alert.timestamp, 20 * NS)
        self.assertEqual(detector.flush(), [])

    def test_maximum_active_lifetime_splits_continuous_activity_at_time_not_count(self):
        for kind in ("port_scan", "syn_flood", "traffic_flood"):
            with self.subTest(kind=kind):
                detector = engine(rule(kind, threshold=1, quiet_seconds=3, max_detection_seconds=5))
                alerts = []
                for second in range(1, 11):
                    alerts.extend(detector.evaluate(network(timestamp=second * NS, dst_port=80 + second)))
                self.assertEqual(len(alerts), 1)
                first = alerts[0]
                self.assertEqual(first.timestamp, 6 * NS)
                self.assertEqual(first.metadata["finalization_reason"], "max_duration")
                self.assertEqual(first.metadata["matching_event_count"], 5)
                self.assertEqual(first.metadata["last_timestamp"], 5 * NS)
                second = detector.advance_time(11 * NS)[0]
                self.assertEqual(second.metadata["matching_event_count"], 5)
                self.assertEqual(second.metadata["first_timestamp"], 6 * NS)
                self.assertEqual(detector.advance_time(20 * NS), [])

    def test_max_duration_starts_at_confirmation_not_first_candidate(self):
        detector = engine(rule(threshold=2, window_seconds=1, quiet_seconds=1,
                               max_detection_seconds=2))
        detector.evaluate(network(timestamp=NS, dst_port=80))
        confirmed = NS + NS // 2
        detector.evaluate(network(timestamp=confirmed, dst_port=81))
        detector.evaluate(network(timestamp=2 * NS + 400_000_000, dst_port=82))
        detector.evaluate(network(timestamp=3 * NS + 300_000_000, dst_port=83))
        self.assertEqual(detector.advance_time(confirmed + 2 * NS - 1), [])
        alert = detector.advance_time(confirmed + 2 * NS)[0]
        self.assertEqual(alert.metadata["threshold_timestamp"], confirmed)
        self.assertEqual(alert.metadata["finalization_reason"], "max_duration")
        self.assertEqual(alert.metadata["unique_port_count"], 4)

    def test_next_activity_at_quiet_boundary_starts_a_new_session(self):
        detector = engine(rule(threshold=1, quiet_seconds=2))
        detector.evaluate(network(timestamp=NS, dst_port=80))
        alerts = detector.evaluate(network(timestamp=3 * NS, dst_port=81))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].metadata["destination_ports"], [80])
        self.assertEqual(detector.advance_time(5 * NS)[0].metadata["destination_ports"], [81])
        self.assertEqual(detector.advance_time(20 * NS), [])

    def test_unrelated_or_nonmatching_traffic_does_not_extend_quiet_time(self):
        detector = engine(rule("syn_flood", threshold=1))
        detector.evaluate(network(timestamp=NS))
        detector.evaluate(network(timestamp=2 * NS, tcp_flags=18))
        self.assertEqual(detector.advance_time(4 * NS)[0].metadata["matching_event_count"], 1)

    def test_group_limit_evicts_pending_candidates_but_never_discards_active_sessions(self):
        detector = engine(rule(threshold=2, max_groups=2))
        detector.evaluate(network(src_ip="192.0.2.1", dst_port=80))
        detector.evaluate(network(src_ip="192.0.2.1", dst_port=81))  # active
        detector.evaluate(network(src_ip="192.0.2.2", dst_port=80))  # pending
        detector.evaluate(network(src_ip="192.0.2.3", dst_port=80))  # replaces pending
        groups = detector._runtimes[0].groups
        self.assertEqual(len(groups), 2)
        self.assertNotIn(("192.0.2.2", "192.0.2.2"), groups)
        detector.evaluate(network(src_ip="192.0.2.3", dst_port=81))  # second active
        self.assertEqual(detector.evaluate(network(src_ip="192.0.2.4", dst_port=80)), [])
        self.assertNotIn(("192.0.2.4", "192.0.2.2"), groups)
        detector.evaluate(network(src_ip="192.0.2.1", dst_port=82))
        alerts = detector.advance_time(4 * NS)
        self.assertEqual(sorted(alert.metadata["unique_port_count"] for alert in alerts), [2, 3])
        self.assertEqual(groups, {})

    def test_large_session_counts_and_ports_stay_complete_with_capped_uuid_memory(self):
        for kind in ("port_scan", "syn_flood", "traffic_flood"):
            with self.subTest(kind=kind):
                detector = engine(rule(kind, threshold=3, max_event_ids=4))
                events = [network(dst_port=index + 1) for index in range(700)]
                events.append(network(dst_port=65535))
                for event in events:
                    self.assertEqual(detector.evaluate(event), [])
                session = next(iter(detector._runtimes[0].groups.values()))
                self.assertEqual(session.pending, {})
                self.assertLessEqual(len(session.evidence), 2)
                self.assertLessEqual(len(session.recent_ids), 4)
                if kind == "port_scan":
                    self.assertEqual(len(session.ports), 8192)
                alert = detector.advance_time(4 * NS)[0]
                self.assertEqual(alert.metadata["matching_event_count"], 701)
                self.assertLessEqual(len(alert.source_event_ids), 4)
                self.assertTrue(alert.metadata["source_event_ids_truncated"])
                if kind == "port_scan":
                    self.assertEqual(alert.metadata["unique_port_count"], 701)
                    self.assertEqual(alert.metadata["destination_ports"], list(range(1, 701)) + [65535])

    def test_large_flood_retains_true_total_after_uuid_sample_fills(self):
        detector = engine(rule("syn_flood", threshold=10, max_event_ids=8))
        for index in range(10_000):
            self.assertEqual(detector.evaluate(network(timestamp=NS + index)), [])
            if index in (9, 99, 999, 9999):
                session = next(iter(detector._runtimes[0].groups.values()))
                self.assertTrue(session.active)
                self.assertEqual(session.pending, {})
                self.assertLessEqual(len(session.evidence) + 2, 8)
                self.assertLessEqual(len(session.recent_ids), 8)
        alerts = detector.advance_time(4 * NS + 9999)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].metadata["matching_event_count"], 10_000)
        self.assertTrue(1 <= len(alerts[0].source_event_ids) <= 8)
        self.assertEqual(detector.flush(), [])

    def test_closed_session_cache_is_bounded_and_event_id_sample_can_be_two(self):
        detector = engine(rule(threshold=1, max_groups=2, max_event_ids=2, quiet_seconds=0.1))
        for index in range(6):
            timestamp = NS + index * 200_000_000
            first = network(timestamp=timestamp, src_ip=f"192.0.2.{index + 1}")
            last = network(timestamp=timestamp + 1, src_ip=first.src_ip, dst_port=81)
            detector.evaluate(first)
            detector.evaluate(last)
            alert = detector.advance_time(timestamp + 100_000_001)[0]
            self.assertEqual(alert.source_event_ids, (first.event_id, last.event_id))
            self.assertLessEqual(len(detector._runtimes[0].closed_before), 2)

    def test_unavailable_ports_do_not_become_scan_or_syn_attempts(self):
        detector = engine(rule(threshold=1), rule("syn_flood", threshold=1))
        self.assertEqual(detector.evaluate(network(dst_port=0)), [])
        self.assertEqual(detector.evaluate(network(src_ip="0.0.0.0")), [])
        self.assertEqual(detector.flush(), [])

    def test_timer_and_flush_publish_once_and_discard_unconfirmed_candidates(self):
        detector = engine(rule(threshold=2))
        alerts = []
        detector.subscribe(alerts.append)
        detector(network(dst_port=80))
        self.assertEqual(detector.flush(), [])
        detector(network(dst_port=81))
        detector(network(dst_port=82))
        self.assertEqual(alerts, [])
        flushed = detector.flush(reason="shutdown")
        self.assertEqual(alerts, flushed)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].metadata["finalization_reason"], "shutdown")
        self.assertEqual(detector.flush(), [])
        self.assertEqual(detector.tick(4 * NS), [])
        detector(network(timestamp=5 * NS, dst_port=80))
        detector(network(timestamp=5 * NS, dst_port=81))
        self.assertEqual(detector.tick(8 * NS), alerts[1:])
        self.assertEqual(len(alerts), 2)
        for timestamp in (True, -1, 2**64, 1.5):
            with self.assertRaises(ValueError):
                detector.advance_time(timestamp)


class RuleIsolationTests(unittest.TestCase):
    def test_failed_rule_and_alert_subscriber_do_not_break_other_rules_or_storage(self):
        first = rule("syscall_match", id="broken")
        detector = engine(first, rule("syscall_match", id="working"))
        received = []
        def fail_alert(alert):
            raise RuntimeError("simulated alert consumer failure")
        detector.subscribe(fail_alert)
        detector.subscribe(received.append)
        event = host("syscall")
        before = event.to_dict()
        def fail_rule(snapshot, watermark):
            snapshot.metadata["syscall_return"] = 0
            raise RuntimeError("simulated rule failure")
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.db")
            store.initialize()
            router = EventRouter()
            router.subscribe(detector)
            router.subscribe(store.insert)
            with patch.object(detector._runtimes[0], "evaluate", side_effect=fail_rule):
                with self.assertLogs("backend.rules", level="ERROR"):
                    router.route(event)
            self.assertEqual(store.get(event.event_id).to_dict(), before)
        self.assertEqual([alert.rule_id for alert in received], ["working"])
        self.assertEqual(event.to_dict(), before)

    def test_timer_and_flush_failures_do_not_break_other_rules_or_alert_consumers(self):
        for method in ("advance", "flush"):
            detector = engine(rule(threshold=1, id="broken"), rule(threshold=1, id="working"))
            received = []
            def fail_alert(alert):
                raise RuntimeError("simulated sink failure")
            detector.subscribe(fail_alert)
            detector.subscribe(received.append)
            detector(network())
            with patch.object(detector._runtimes[0], method, side_effect=RuntimeError("failed")):
                with self.assertLogs("backend.rules", level="ERROR"):
                    alerts = detector.tick(4 * NS) if method == "advance" else detector.flush()
            self.assertEqual([alert.rule_id for alert in alerts], ["working"])
            self.assertEqual(received, alerts)

    def test_engine_boundary_failure_is_contained(self):
        detector = engine(rule())
        observed = []
        router = EventRouter()
        router.subscribe(detector)
        router.subscribe(observed.append)
        event = network()
        with patch.object(detector, "evaluate", side_effect=RuntimeError("engine failed")):
            with self.assertLogs("backend.rules", level="ERROR"):
                router.route(event)
        self.assertEqual(observed, [event])
        with self.assertRaises(ValueError):
            detector.evaluate({})
        with self.assertRaises(ValueError):
            detector.subscribe(None)

    def test_normalized_stream_routes_to_rules_and_storage_without_event_mutation(self):
        detector = engine(rule("process_match"), rule("syscall_match"))
        alerts, events = [], []
        detector.subscribe(alerts.append)
        messages = [test_ipc.STATUS, test_ipc.EVENT, host_message(), host_message("syscall")]
        wire = ''.join(json.dumps(value) + '\n' for value in messages).encode()
        router = EventRouter()
        router.subscribe(detector)
        router.subscribe(events.append)
        for event in receive_events(test_ipc.Chunks(wire)):
            router.route(event)
        self.assertEqual([alert.rule_id for alert in alerts], ["process_match", "syscall_match"])
        self.assertEqual([event.event_category for event in events], ["network", "process", "syscall"])
        self.assertEqual(alerts[0].source_event_ids, (events[1].event_id,))


class RuleTransportTests(unittest.TestCase):
    setUp = test_ipc.TransportTests.setUp
    stop_driver = test_ipc.TransportTests.stop_driver
    line = test_ipc.TransportTests.line
    command = test_ipc.TransportTests.command

    def test_c_transport_rules_alerts_and_persistence(self):
        path = Path(self.directory.name) / "rules.yaml"
        path.write_text(yaml.safe_dump({"schema_version": 1, "rules": [
            rule(threshold=1), rule("process_match"), rule("syscall_match"),
            rule("privilege_change", match={"uid": [1000], "previous_uid": [0]})]}))
        database = Path(self.directory.name) / "events.db"
        receiver = subprocess.Popen(
            [sys.executable, "backend/receiver.py", self.path, "--rules", str(path),
             "--database", str(database)], cwd=test_ipc.ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(100):
                self.command("poll")
                if select.select([receiver.stderr], [], [], 0.05)[0]:
                    break
            else:
                self.fail("rule-enabled receiver did not connect")
            for command in ("event", "host_exec", "host_syscall", "host_privilege"):
                self.command(command)
            self.stop_driver()
            output, errors = receiver.communicate(timeout=3)
            self.assertEqual(receiver.returncode, 0, errors)
            events = [json.loads(line) for line in output.splitlines()]
            alerts = [json.loads(line.removeprefix("Alert: "))
                      for line in errors.splitlines() if line.startswith("Alert: ")]
            self.assertEqual(len(events), 4)
            self.assertEqual(len(alerts), 4)
            self.assertEqual({tuple(alert["source_event_ids"]) for alert in alerts},
                             {(event["event_id"],) for event in events})
            network_alert = next(alert for alert in alerts if alert["event_category"] == "network")
            self.assertEqual(network_alert["metadata"]["finalization_reason"], "stream_end")
            self.assertEqual([event.to_dict() for event in EventStore(database).list_events()], events)
        finally:
            if receiver.poll() is None:
                receiver.kill()
            receiver.communicate()

    def test_idle_socket_finalizes_without_another_event_or_disconnect(self):
        path = Path(self.directory.name) / "rules.yaml"
        path.write_text(yaml.safe_dump({"schema_version": 1, "rules": [
            rule("syn_flood", threshold=2, quiet_seconds=0.05, max_event_ids=4)]}))
        receiver = subprocess.Popen(
            [sys.executable, "backend/receiver.py", self.path, "--rules", str(path)],
            cwd=test_ipc.ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(100):
                self.command("poll")
                if select.select([receiver.stderr], [], [], 0.05)[0]:
                    break
            else:
                self.fail("rule-enabled receiver did not connect")
            self.assertEqual(receiver.stderr.readline().strip(), "Agent status: ready")
            for _ in range(10):
                self.command("event")
            self.assertTrue(select.select([receiver.stderr], [], [], 3)[0], "missing idle alert")
            line = receiver.stderr.readline()
            self.assertTrue(line.startswith("Alert: "), line)
            alert = json.loads(line.removeprefix("Alert: "))
            self.assertEqual(alert["metadata"]["matching_event_count"], 10)
            self.assertEqual(alert["metadata"]["finalization_reason"], "quiet")
            self.assertLessEqual(len(alert["source_event_ids"]), 4)
            self.assertIsNone(receiver.poll())
            self.assertIsNone(self.driver.poll())  # Both ends still open when the alert arrives.
            self.stop_driver()
            output, errors = receiver.communicate(timeout=3)
            self.assertEqual(receiver.returncode, 0, errors)
            self.assertEqual(len(output.splitlines()), 10)
            self.assertNotIn("Alert: ", errors)  # EOF does not emit the same session again.
        finally:
            if receiver.poll() is None:
                receiver.kill()
            receiver.communicate()

    def test_invalid_configuration_fails_before_connecting(self):
        path = Path(self.directory.name) / "rules.yaml"
        path.write_text("rules: []")
        result = subprocess.run([sys.executable, "backend/receiver.py", self.path,
                                 "--rules", str(path)], cwd=test_ipc.ROOT,
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Receiver error:", result.stderr)
        self.assertNotIn("Agent status: ready", result.stderr)
        self.assertEqual(result.stdout, "")
