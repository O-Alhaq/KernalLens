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
              "category": category, "type": kind, "severity": "medium",
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

    def test_invalid_rules_are_rejected_including_disabled_entries(self):
        bad_values = [rule(id="bad id"), rule(enabled="false"), rule(enabled=1),
                      rule(severity="urgent"), rule(type="unknown"), rule(category="process"),
                      rule(threshold=0), rule(threshold=True), rule(threshold=4097),
                      rule(threshold=1.5), rule(window_seconds=0), rule(window_seconds=True),
                      rule(window_seconds=float("nan")), rule(window_seconds=float("inf")),
                      rule(window_seconds=1e-10), rule(window_seconds=86401),
                      rule(max_groups=0), rule(max_groups=4097), rule(extra=True),
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

    def test_alert_structure_static_severity_unique_ids_and_event_immutability(self):
        event = host("privilege", uid=0, previous_uid=1000)
        before = event.to_dict()
        detector = engine(rule("privilege_change", severity="high"))
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
    def test_port_scan_distinct_ports_and_nonoverlapping_alert_batches(self):
        detector = engine(rule())
        events = [network(timestamp=(index + 1) * NS, dst_port=80 + index) for index in range(3)]
        self.assertEqual(detector.evaluate(events[0]), [])
        self.assertEqual(detector.evaluate(network(timestamp=NS, dst_port=80)), [])
        self.assertEqual(detector.evaluate(events[1]), [])
        before = events[2].to_dict()
        alerts = detector.evaluate(events[2])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].metadata["destination_ports"], [80, 81, 82])
        # Repeated port replaces evidence with its newest observed attempt.
        self.assertEqual(len(alerts[0].source_event_ids), 3)
        self.assertEqual(alerts[0].source_event_ids[-2:], (events[1].event_id, events[2].event_id))
        self.assertEqual(events[2].to_dict(), before)
        self.assertEqual(detector._runtimes[0].groups, {})
        self.assertEqual(detector.evaluate(network(timestamp=4 * NS, dst_port=83)), [])

    def test_syn_flood_counts_attempts_not_distinct_ports_and_ignores_syn_ack(self):
        detector = engine(rule("syn_flood"))
        for flags in (0, 16, 18):
            self.assertEqual(detector.evaluate(network(tcp_flags=flags)), [])
        self.assertEqual(detector.evaluate(network(protocol="UDP", tcp_flags=0)), [])
        events = [network() for _ in range(3)]
        self.assertEqual(detector.evaluate(events[0]), [])
        self.assertEqual(detector.evaluate(events[0]), [])  # same event ID is not another packet
        self.assertEqual(detector.evaluate(events[1]), [])
        alert = detector.evaluate(events[2])[0]
        self.assertEqual(alert.source_event_ids, tuple(event.event_id for event in events))
        self.assertEqual(alert.metadata["count"], 3)

    def test_traffic_flood_includes_tcp_udp_icmp_and_excludes_other(self):
        detector = engine(rule("traffic_flood"))
        other = network(protocol="OTHER", src_ip="0.0.0.0", dst_ip="0.0.0.0",
                        src_port=0, dst_port=0, tcp_flags=0)
        self.assertEqual(detector.evaluate(other), [])
        self.assertEqual(detector.evaluate(network()), [])
        self.assertEqual(detector.evaluate(network(protocol="UDP", tcp_flags=0)), [])
        self.assertEqual(len(detector.evaluate(network(protocol="ICMP", tcp_flags=0,
                                                        src_port=0, dst_port=0))), 1)

    def test_sources_and_destinations_are_separate_groups(self):
        detector = engine(rule(threshold=2))
        for values in ({}, {"src_ip": "192.0.2.3"}, {"dst_ip": "192.0.2.4"}):
            self.assertEqual(detector.evaluate(network(**values)), [])
        alert = detector.evaluate(network(dst_port=81))[0]
        self.assertEqual((alert.metadata["src_ip"], alert.metadata["dst_ip"]),
                         ("192.0.2.1", "192.0.2.2"))
        self.assertEqual(len(detector._runtimes[0].groups), 2)

    def test_time_windows_expire_at_cutoff_and_unrelated_events_prune_all_keys(self):
        for kind in ("port_scan", "syn_flood", "traffic_flood"):
            with self.subTest(kind=kind):
                detector = engine(rule(kind, threshold=2, window_seconds=1))
                first = network(timestamp=NS, dst_port=80)
                self.assertEqual(detector.evaluate(first), [])
                second = network(timestamp=2 * NS, dst_port=81)
                self.assertEqual(detector.evaluate(second), [])  # first expired exactly at cutoff
                third = network(timestamp=2 * NS + 1, dst_port=82)
                self.assertEqual(len(detector.evaluate(third)), 1)
                detector.evaluate(network(timestamp=3 * NS))
                detector.evaluate(network(timestamp=3 * NS, src_ip="192.0.2.3"))
                detector.evaluate(host(timestamp=5 * NS))
                self.assertEqual(detector._runtimes[0].groups, {})

    def test_out_of_order_events_use_non_decreasing_watermark(self):
        detector = engine(rule(threshold=3, window_seconds=2))
        self.assertEqual(detector.evaluate(network(timestamp=10 * NS, dst_port=80)), [])
        self.assertEqual(detector.evaluate(network(timestamp=8 * NS, dst_port=81)), [])
        self.assertEqual(detector.evaluate(network(timestamp=9 * NS, dst_port=81)), [])
        alert = detector.evaluate(network(timestamp=9 * NS + 1, dst_port=82))[0]
        self.assertEqual(alert.timestamp, 10 * NS)
        self.assertEqual(alert.metadata["first_timestamp"], 9 * NS)
        self.assertEqual(detector._watermark, 10 * NS)

    def test_group_count_and_sample_count_are_bounded_with_lru_eviction(self):
        detector = engine(rule(threshold=3, max_groups=2))
        detector.evaluate(network(src_ip="192.0.2.1", dst_port=80))
        detector.evaluate(network(src_ip="192.0.2.2", dst_port=80))
        detector.evaluate(network(src_ip="192.0.2.1", dst_port=81))
        detector.evaluate(network(src_ip="192.0.2.3", dst_port=80))
        groups = detector._runtimes[0].groups
        self.assertEqual(len(groups), 2)
        self.assertNotIn(("192.0.2.2", "192.0.2.2"), groups)
        for port in range(100, 110):
            detector.evaluate(network(src_ip="192.0.2.1", dst_port=port))
            self.assertTrue(all(len(samples) < 3 for samples in groups.values()))
        self.assertEqual(detector.evaluate(network(src_ip="192.0.2.2", dst_port=81)), [])

    def test_unavailable_ports_do_not_become_scan_or_syn_attempts(self):
        detector = engine(rule(threshold=1), rule("syn_flood", threshold=1))
        self.assertEqual(detector.evaluate(network(dst_port=0)), [])
        self.assertEqual(detector.evaluate(network(src_ip="0.0.0.0")), [])


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
            self.assertEqual([alert["source_event_ids"] for alert in alerts],
                             [[event["event_id"]] for event in events])
            self.assertEqual([event.to_dict() for event in EventStore(database).list_events()], events)
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
