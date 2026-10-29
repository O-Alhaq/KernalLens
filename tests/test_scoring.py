"""M9 deterministic policy, validation, boundaries, and aggregated evidence."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

import yaml
from backend.alerts import severity_for_score
from backend.scoring import Scorer, DEFAULT_POLICY
from backend.rule_config import RuleConfigError, load_rules
from backend.rules import RuleEngine
from test_rules import network, NS


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.document = yaml.safe_load(DEFAULT_POLICY.read_text())
        self.scorer = Scorer(self.document)

    def alert(self, family, metadata=None, scorer=None, **overrides):
        data = {"unique_port_count": 10, "matching_event_count": 10, "threshold": 10,
                "uid": 1000, "previous_uid": 0} if metadata is None else metadata
        return (scorer or self.scorer).alert(
            timestamp=NS, rule_id="test", rule_name="Test", alert_type=family,
            description="Configured detection", source_event_ids=(str(uuid4()),),
            event_category="network" if family in ("port_scan", "syn_flood", "traffic_flood") else
            {"process_match": "process", "syscall_match": "syscall", "privilege_change": "privilege"}[family],
            metadata=data, **overrides)

    def test_all_family_bases_and_determinism(self):
        for family, base in (("port_scan", 30), ("syn_flood", 60), ("traffic_flood", 50),
                             ("process_match", 30), ("syscall_match", 20), ("privilege_change", 50)):
            first, second = self.alert(family), self.alert(family)
            self.assertEqual(first.risk_score, base)
            self.assertEqual(first.base_score, base)
            self.assertEqual(first.risk_score, second.risk_score)
            self.assertEqual(first.score_modifiers, second.score_modifiers)
            self.assertEqual(first.severity, severity_for_score(base))

    def test_exact_severity_boundaries(self):
        for score, severity in ((0,"low"),(19,"low"),(20,"medium"),(49,"medium"),
                                (50,"high"),(79,"high"),(80,"critical"),(100,"critical")):
            self.assertEqual(severity_for_score(score), severity)
            self.assertEqual(self.alert("process_match", base_override=score).severity, severity)

    def test_scan_volume_highest_tier_only_and_metadata_not_mutated(self):
        for count, expected in ((10,30),(19,30),(20,35),(49,35),(50,40),(99,40),
                                (100,45),(199,45),(200,49),(1000,49),(65535,49)):
            metadata = {"unique_port_count": count, "threshold": 10}
            original = deepcopy(metadata)
            result = self.alert("port_scan", metadata)
            self.assertEqual(result.risk_score, expected)
            self.assertEqual(result.severity, "medium")
            repeated = self.alert("port_scan", metadata)
            self.assertEqual((repeated.risk_score, repeated.score_modifiers),
                             (result.risk_score, result.score_modifiers))
            self.assertLessEqual(len(result.score_modifiers), 1)
            self.assertEqual(metadata, original)
            result.metadata["unique_port_count"] = 1
            self.assertEqual(metadata, original)

    def test_scan_scale_is_absolute_configurable_and_never_high(self):
        for threshold in (1, 10, 100):
            result = self.alert("port_scan", {"unique_port_count":50,"threshold":threshold})
            self.assertEqual(result.risk_score, 40)
            self.assertEqual(result.score_modifiers[0].name, "port_scan_scope")
            self.assertEqual(result.score_modifiers[0].points, 10)
        for count in (10, 19, 20, 49, 50, 99, 100, 199, 200, 1000, 65535):
            result = self.alert("port_scan", {"unique_port_count":count,"threshold":10}, base_override=30)
            self.assertTrue(20 <= result.risk_score <= 49)
        for base in (0, 19, 20, 35, 45, 49, 50, 100):
            with self.subTest(base=base), self.assertRaises(ValueError):
                self.alert("port_scan", base_override=base)
        doc = deepcopy(self.document)
        doc["scoring"]["port_scan"]["tiers"][1]["score"] = 42
        result = self.alert("port_scan", {"unique_port_count":50,"threshold":10}, scorer=Scorer(doc))
        self.assertEqual(result.risk_score,42)

    def test_scan_scores_are_monotonic_with_authoritative_policy_base(self):
        counts = (1, 10, 19, 20, 49, 50, 99, 100, 199, 200, 1000, 65535)
        scores = [self.alert("port_scan", {"unique_port_count":count,"threshold":1},
                             base_override=30).risk_score for count in counts]
        self.assertEqual(scores, sorted(scores))
        self.assertEqual(scores, [30,30,30,35,35,40,40,45,45,49,49,49])
        doc = deepcopy(self.document)
        doc["scoring"]["port_scan"]["base_score"] = 32
        scorer = Scorer(doc)
        self.assertEqual(self.alert("port_scan", scorer=scorer, base_override=32).risk_score, 32)
        with self.assertRaises(ValueError):
            self.alert("port_scan", scorer=scorer, base_override=30)

    def test_invalid_port_scan_tiers_and_duplicate_fields(self):
        invalid = [None, {}, [], [{"min_unique_ports":20}],
                   [{"min_unique_ports":20,"score":35,"extra":0}],
                   [{"min_unique_ports":20,"score":50}],
                   [{"min_unique_ports":20,"score":-1}],
                   [{"min_unique_ports":20,"score":101}],
                   [{"min_unique_ports":True,"score":35}],
                   [{"min_unique_ports":20,"score":True}],
                   [{"min_unique_ports":65536,"score":35}],
                   [{"min_unique_ports":50,"score":40},{"min_unique_ports":20,"score":45}],
                   [{"min_unique_ports":20,"score":35},{"min_unique_ports":20,"score":40}],
                   [{"min_unique_ports":20,"score":29}],
                   [{"min_unique_ports":20,"score":40},{"min_unique_ports":50,"score":35}]]
        for tiers in invalid:
            doc = deepcopy(self.document)
            doc["scoring"]["port_scan"]["tiers"] = tiers
            with self.subTest(tiers=tiers), self.assertRaises(RuleConfigError):
                Scorer(doc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"policy.yaml"
            path.write_text(DEFAULT_POLICY.read_text().replace(
                "min_unique_ports: 20, score: 35", "min_unique_ports: 20, score: 35, score: 40"))
            with self.assertRaises(RuleConfigError):
                Scorer.from_file(path)

    def test_flood_volume_and_root_transition(self):
        for family, base in (("syn_flood",60),("traffic_flood",50)):
            for count, bonus in ((1000,0),(2000,10),(5000,20),(10**15,20)):
                self.assertEqual(self.alert(family, {"matching_event_count":count,"threshold":1000}).risk_score,
                                 base + bonus)
        root = self.alert("privilege_change", {"uid":0,"previous_uid":1000})
        generic = self.alert("privilege_change", {"uid":1000,"previous_uid":0})
        unchanged_root = self.alert("privilege_change", {"uid":0,"previous_uid":0})
        self.assertEqual(root.risk_score, 75)
        self.assertGreater(root.risk_score, generic.risk_score)
        self.assertEqual(unchanged_root.risk_score, generic.risk_score)

    def test_clamping_and_policy_snapshot(self):
        for points, base, expected in ((100,90,100),(-100,10,0)):
            doc = deepcopy(self.document)
            doc["scoring"]["syn_flood"]["volume_tiers"] = [{"multiple":2,"points":points}]
            scorer = Scorer(doc)
            doc["scoring"].clear()
            result = self.alert("syn_flood", {"matching_event_count":20,"threshold":10},
                                scorer=scorer, base_override=base)
            self.assertEqual(result.risk_score, expected)
            self.assertEqual(result.score_modifiers[0].points, points)

    def test_alert_rejects_invalid_score_severity_and_arithmetic(self):
        result = self.alert("port_scan")
        for value in (-1,101,True,35.0,"35",None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(result, risk_score=value)
        for changes in ({"risk_score":85,"severity":"medium"}, {"severity":"critical"},
                        {"base_score":False}, {"risk_score":36}, {"score_modifiers":[]}):
            with self.assertRaises(ValueError):
                replace(result, **changes)

    def test_invalid_policy_and_duplicate_yaml(self):
        invalid = [None, {}, {**self.document,"extra":1}, {**self.document,"schema_version":True}]
        for family, key, value in (("port_scan","base_score",101),("port_scan","base_score",True),
                                  ("syn_flood","volume_tiers",{}),
                                  ("syn_flood","volume_tiers",[{"multiple":1,"points":10}]),
                                  ("syn_flood","volume_tiers",[{"multiple":2,"points":101}]),
                                  ("syn_flood","volume_tiers",[{"multiple":2,"points":True}]),
                                  ("syn_flood","volume_tiers",[{"multiple":2,"points":1,"extra":1}]),
                                  ("syn_flood","volume_tiers",[{"multiple":2,"points":1}]*2),
                                  ("privilege_change","root_uid_points",-101)):
            doc = deepcopy(self.document); doc["scoring"][family][key] = value; invalid.append(doc)
        for mutate in (lambda d:d["scoring"].pop("syscall_match"),
                       lambda d:d["scoring"]["process_match"].pop("base_score"),
                       lambda d:d["scoring"]["process_match"].update(extra=1)):
            doc = deepcopy(self.document); mutate(doc); invalid.append(doc)
        for doc in invalid:
            with self.subTest(doc=doc), self.assertRaises(RuleConfigError):
                Scorer(doc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"scoring.yaml"
            for content in (DEFAULT_POLICY.read_text()+"\nschema_version: 1\n", "scoring: [", "!!python/object:bad {}"):
                path.write_text(content)
                with self.assertRaises(RuleConfigError):
                    Scorer.from_file(path)

    def test_invalid_evidence_rejected(self):
        for metadata in ({}, {"threshold":True,"unique_port_count":50},
                         {"threshold":0,"unique_port_count":50}):
            with self.assertRaises(ValueError):
                self.alert("port_scan", metadata)
        with self.assertRaises(ValueError):
            self.alert("privilege_change", {"uid":0})

    def test_fifty_ports_one_final_scored_alert_and_original_events_unchanged(self):
        engine = RuleEngine(load_rules(DEFAULT_POLICY.with_name("rules.yaml")))
        for port in range(1000,1050):
            event = network(timestamp=NS, dst_port=port)
            original = event.to_dict()
            self.assertEqual(engine.evaluate(event), [])
            self.assertEqual(event.to_dict(), original)
        results = engine.advance_time(4*NS)
        scan = [alert for alert in results if alert.alert_type == "port_scan"]
        self.assertEqual(len(scan),1)
        self.assertEqual(scan[0].metadata["unique_port_count"],50)
        self.assertEqual(scan[0].risk_score,40)
        self.assertEqual(scan[0].severity,"medium")
        self.assertEqual(engine.flush(),[])
