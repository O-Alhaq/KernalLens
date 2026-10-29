"""M10 receiver wiring with normalized input; no privileged sensors required."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

from backend.incident_storage import IncidentStore
from backend.receiver import main
from test_correlation import policy
from test_rules import network, rule, NS


class CorrelationReceiverTests(unittest.TestCase):
    def test_receiver_flush_scores_then_persists_and_correlates(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            database = directory/"events.db"
            rules = directory/"rules.yaml"
            config = directory/"correlation.yaml"
            rules.write_text(yaml.safe_dump({"schema_version": 1, "rules": [rule(threshold=10),
                                           rule("syn_flood", threshold=30, base_score=60)]}))
            config.write_text(yaml.safe_dump(policy("network_sequence")))
            events = [network(timestamp=NS, dst_port=port) for port in range(1000, 1050)]
            output, errors = io.StringIO(), io.StringIO()
            arguments = ["receiver.py", "unused.sock", "--rules", str(rules),
                         "--correlation", str(config), "--database", str(database)]
            with patch("sys.argv", arguments), patch("backend.receiver.socket.socket", return_value=MagicMock()), \
                    patch("backend.receiver.receive_events", return_value=iter(events)), \
                    redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(main(), 0)
            self.assertEqual(len(output.getvalue().splitlines()), 50)
            alerts = [json.loads(line.removeprefix("Alert: ")) for line in errors.getvalue().splitlines() if line.startswith("Alert: ")]
            incidents = [json.loads(line.removeprefix("Incident: ")) for line in errors.getvalue().splitlines() if line.startswith("Incident: ")]
            self.assertEqual(len(alerts), 2)
            self.assertEqual(alerts[0]["metadata"]["unique_port_count"], 50)
            self.assertEqual(alerts[0]["risk_score"], 40)
            self.assertEqual(len(incidents), 1)
            store = IncidentStore(database)
            self.assertEqual(store.list_incidents()[0].to_dict(), incidents[0])
            self.assertEqual(len(store.list_events()), 50)
            for item in alerts:
                self.assertEqual(store.get_alert(item["alert_id"]).to_dict(), item)

    def test_correlation_flag_requires_rules(self):
        with patch("sys.argv", ["receiver.py", "unused.sock", "--correlation", "unused.yaml"]), \
                redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main()
        self.assertEqual(error.exception.code, 2)
