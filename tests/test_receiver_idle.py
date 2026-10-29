"""Idle polling must not terminate the stream or replace correlation state."""
import json
import unittest
from unittest.mock import Mock

from backend.pipeline import receive_events
from backend.receiver import receive_messages
from backend.rule_config import parse_rules
from backend.rules import RuleEngine
from backend.correlation import CorrelationEngine
from test_correlation import policy
from test_rules import rule, NS
from test_ipc import EVENT
from copy import deepcopy


class ReceiverIdleTests(unittest.TestCase):
    def test_idle_finalization_later_alert_correlation_and_real_eof(self):
        engine = RuleEngine(parse_rules({"schema_version": 1, "rules": [
            rule(threshold=10), rule("syn_flood", threshold=100, base_score=60)]}))
        correlation = CorrelationEngine(policy("network_sequence"))
        alerts, incidents = [], []
        engine.subscribe(alerts.append)
        engine.subscribe(correlation)
        correlation.subscribe(incidents.append)

        def wire(timestamp, ports):
            messages = []
            for port in ports:
                message = deepcopy(EVENT)
                message["event"].update(timestamp=timestamp, dst_port=port)
                messages.append(json.dumps(message) + '\n')
            return ''.join(messages).encode()

        stages = iter([wire(NS, range(1000, 1050)), TimeoutError(),
                       wire(5*NS, [80]*100), TimeoutError(), TimeoutError(), b''])
        polls = []
        def recv(size):
            stage = next(stages)
            if isinstance(stage, TimeoutError):
                raise stage
            if stage and polls:
                self.assertEqual(len(alerts), 1)
                self.assertEqual(alerts[0].metadata['unique_port_count'], 50)
                self.assertEqual(alerts[0].metadata['finalization_reason'], 'quiet')
            if stage == b'':
                self.assertEqual(len(alerts), 2)
                self.assertEqual(len(incidents), 1)
                self.assertEqual(incidents[0].risk_score, 65)
            return stage
        def idle():
            timestamp = (4 if not polls else 8)*NS
            polls.append(timestamp)
            return engine.tick(timestamp)  # Both nonempty and empty results must be ignored.
        connection = Mock()
        connection.recv.side_effect = recv
        received = 0
        for event in receive_events(connection, on_idle=idle):
            engine(event)
            received += 1
        self.assertEqual(received, 150)
        self.assertEqual(len(polls), 3)
        self.assertEqual(connection.recv.call_count, 6)
        self.assertEqual(engine.flush(), [])

    def test_fatal_socket_error_is_not_idle_or_eof(self):
        connection = Mock()
        connection.recv.side_effect = ConnectionResetError('peer reset')
        idle = Mock()
        with self.assertRaises(ConnectionResetError):
            list(receive_messages(connection, on_idle=idle))
        idle.assert_not_called()

    def test_real_eof_is_clean_but_partial_record_is_rejected(self):
        connection = Mock()
        connection.recv.return_value = b''
        self.assertEqual(list(receive_messages(connection, on_idle=Mock())), [])
        connection.recv.side_effect = [b'{', b'']
        with self.assertRaisesRegex(ValueError, 'truncated'):
            list(receive_messages(connection, on_idle=Mock()))
