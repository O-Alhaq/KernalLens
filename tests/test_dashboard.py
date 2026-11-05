"""M11 read-only dashboard, committed journal and bounded live delivery."""
import asyncio
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from backend.api import create_app
from backend.dashboard_storage import DashboardStore, JOURNAL_PER_FAMILY, BATCH_PER_FAMILY
from backend.incident_storage import IncidentStore
from backend.storage import EventStore, MIGRATION_1, MIGRATION_2
from backend.live import LiveHub, CLIENT_QUEUE, CLIENT_BYTES, MAX_CLIENTS, poll_store
from backend.correlation import CorrelationEngine
from backend.pipeline import EventRouter
from backend.rules import RuleEngine
from backend.rule_config import parse_rules
from test_correlation import alert, policy
from test_rules import rule, network, NS
from test_storage import sample_events


class DashboardStorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'dashboard.db'
        self.store = IncidentStore(self.path)
        self.store.initialize()
        self.dashboard = DashboardStore(self.path)

    def sequence(self):
        engine = CorrelationEngine(policy('network_sequence'))
        snapshots = []
        for item in (alert(), alert('syn_flood', 2), alert('traffic_flood', 3)):
            self.store.insert_alert(item)
            for incident in engine.evaluate(item):
                self.store.save_incident(incident)
                snapshots.append(incident)
        return snapshots

    def test_empty_snapshot_and_constant_summary(self):
        value = self.dashboard.snapshot()
        self.assertEqual(value['cursor'], 0)
        self.assertEqual(value['events'], [])
        self.assertEqual(value['alerts'], [])
        self.assertEqual(value['incidents'], [])
        self.assertEqual(value['summary']['total_events'], 0)
        self.assertEqual(value['summary']['alerts_by_severity'], dict(low=0, medium=0, high=0, critical=0))

    def test_summary_update_does_not_double_count_incident_or_alert_replay(self):
        initial, updated = self.sequence()
        self.store.save_incident(updated)
        member = self.store.get_alert(updated.alert_ids[0])
        self.store.insert_alert(member)
        summary = self.dashboard.summary()
        self.assertEqual(summary['total_alerts'], 3)
        self.assertEqual(summary['total_incidents'], 1)
        self.assertEqual(summary['incidents_by_severity']['high'], 1)
        snapshot = self.dashboard.snapshot()
        self.assertEqual(snapshot['incidents'], [self.dashboard.operator_record("incident", updated.to_dict())])
        self.assertEqual(len(self.store.list_incidents()), 1)

    def test_severity_counter_changes_with_incident_score(self):
        engine = CorrelationEngine(policy('host_sequence'))
        for item in (alert('process_match'), alert('syscall_match', 2), alert('privilege_change', 3)):
            self.store.insert_alert(item)
            for incident in engine.evaluate(item):
                self.store.save_incident(incident)
        summary = self.dashboard.summary()
        self.assertEqual(summary['total_incidents'], 1)
        self.assertEqual(summary['incidents_by_severity']['medium'], 0)
        self.assertEqual(summary['incidents_by_severity']['critical'], 1)

    def test_journal_bounds_gap_detection_and_per_family_isolation(self):
        self.sequence()
        for _ in range(JOURNAL_PER_FAMILY + 20):
            self.store.insert(sample_events()[0])
        with closing(sqlite3.connect(self.path)) as connection:
            counts = dict(connection.execute('SELECT family, count(*) FROM live_changes GROUP BY family'))
        self.assertEqual(counts['event'], JOURNAL_PER_FAMILY)
        self.assertEqual(counts['alert'], 3)
        self.assertEqual(counts['incident'], 2)
        messages, cursors, gap, status = self.dashboard.changes({})
        self.assertTrue(gap)
        self.assertTrue(status['data']['resync_required'])
        self.assertEqual(sum(m['message_type'] == 'event' for m in messages), BATCH_PER_FAMILY)
        self.assertEqual(len(self.dashboard.snapshot()['events']), 100)
        self.assertEqual(status['data']['summary']['total_events'], JOURNAL_PER_FAMILY + 20)
        _, _, gap, _ = self.dashboard.changes(cursors)
        self.assertFalse(gap)

    def test_original_sequences_prevent_old_backlog_from_overwriting_snapshot(self):
        old = sample_events()[0]
        self.store.insert(old)
        snapshot = self.dashboard.snapshot()
        newer = sample_events()[0]
        self.store.insert(newer)
        messages, _, _, status = self.dashboard.changes({})
        by_id = {m['data']['event_id']: m for m in messages}
        self.assertLessEqual(by_id[old.event_id]['sequence'], snapshot['cursor'])
        self.assertGreater(by_id[newer.event_id]['sequence'], snapshot['cursor'])
        self.assertGreater(status['sequence'], snapshot['cursor'])

    def test_incident_reference_resolves_latest_revision_without_schema_changes(self):
        initial, updated = self.sequence()
        messages, _, _, _ = self.dashboard.changes({})
        values = [m for m in messages if m['message_type'] == 'incident']
        self.assertEqual(len(values), 2)
        self.assertEqual(values[0]['sequence'], values[1]['sequence'])
        self.assertEqual(values[0]['data'], self.dashboard.operator_record("incident", updated.to_dict()))
        self.assertNotIn('live_sequence', values[0]['data'])
        self.assertEqual(values[0]['data']['incident_id'], initial.incident_id)

    def test_transactions_publish_only_committed_records_and_rollback_counters(self):
        event = sample_events()[0]
        self.store.insert(event)
        before = self.dashboard.snapshot()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute('BEGIN')
            connection.execute("UPDATE dashboard_counts SET value=999 WHERE name='events'")
            self.assertEqual(self.dashboard.summary()['total_events'], 1)
            connection.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.insert(event)
        self.assertEqual(self.dashboard.snapshot(), before)

    def test_v2_upgrade_seeds_existing_totals_without_republishing_history(self):
        path = Path(self.directory.name)/'v2.db'
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute(MIGRATION_1)
            for statement in MIGRATION_2:
                connection.execute(statement)
            connection.execute('PRAGMA user_version=2')
        store = IncidentStore(path)
        store.insert(sample_events()[0])
        store.insert_alert(alert())
        store.initialize()
        store.initialize()
        snap = DashboardStore(path).snapshot()
        self.assertEqual(snap['summary']['total_events'], 1)
        self.assertEqual(snap['summary']['total_alerts'], 1)
        self.assertEqual(snap['cursor'], 0)

    def test_updated_incident_moves_to_front_of_dashboard_snapshot(self):
        initial, updated = self.sequence()
        other_engine = CorrelationEngine(policy('network_sequence'))
        for item in (alert(src_ip='192.0.2.99'), alert('syn_flood', 2, src_ip='192.0.2.99')):
            self.store.insert_alert(item)
            for other in other_engine.evaluate(item):
                self.store.save_incident(other)
        self.assertNotEqual(self.dashboard.snapshot()['incidents'][0]['incident_id'], updated.incident_id)
        # An actual append changes the stored record and its dashboard revision.
        member = alert('syn_flood', 4)
        self.store.insert_alert(member)
        from backend.incidents import Incident
        revised = Incident.from_dict({**updated.to_dict(), 'updated_timestamp': 4*NS,
                                      'alert_ids': [*updated.alert_ids, member.alert_id]})
        self.store.save_incident(revised)
        self.assertEqual(self.dashboard.snapshot()['incidents'][0]['incident_id'], updated.incident_id)

    def test_receiver_persists_alerts_when_correlation_is_disabled(self):
        from contextlib import redirect_stdout, redirect_stderr
        import io
        from unittest.mock import MagicMock
        import yaml
        from backend.receiver import main
        from test_rules import host
        rules_path = Path(self.directory.name)/'rules.yaml'
        rules_path.write_text(yaml.safe_dump({'schema_version': 1, 'rules': [rule('process_match', base_score=30)]}))
        arguments = ['receiver.py', 'unused.sock', '--rules', str(rules_path), '--database', str(self.path)]
        with patch('sys.argv', arguments), patch('backend.receiver.socket.socket', return_value=MagicMock()), \
                patch('backend.receiver.receive_events', return_value=iter([host()])), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(), 0)
        self.assertEqual(self.dashboard.summary()['total_alerts'], 1)
        self.assertEqual(self.dashboard.summary()['total_incidents'], 0)

    def test_pipeline_scoring_correlation_persistence_without_any_websocket(self):
        rules = RuleEngine(parse_rules({'schema_version': 1, 'rules': [rule(threshold=10), rule('syn_flood', threshold=30, base_score=60)]}))
        correlation = CorrelationEngine(policy('network_sequence'))
        rules.subscribe(self.store.insert_alert)
        rules.subscribe(correlation)
        correlation.subscribe(self.store.save_incident)
        router = EventRouter()
        router.subscribe(rules)
        router.subscribe(self.store.insert)
        for port in range(1000, 1050):
            router.route(network(timestamp=NS, dst_port=port))
        rules.tick(4*NS)
        snap = self.dashboard.snapshot()
        self.assertEqual(snap['summary']['total_events'], 50)
        self.assertEqual(snap['summary']['total_alerts'], 2)
        self.assertEqual(snap['incidents'][0]['risk_score'], 65)
        messages, _, _, _ = self.dashboard.changes({})
        self.assertEqual({m['message_type'] for m in messages}, {'event', 'alert', 'incident'})


class DashboardApiTests(unittest.TestCase):
    setUp = DashboardStorageTests.setUp
    sequence = DashboardStorageTests.sequence

    def client(self):
        self.app = create_app(self.path)
        return self.enterContext(TestClient(self.app))

    def test_empty_lists_invalid_ids_pagination_and_read_only(self):
        client = self.client()
        for kind in ('events', 'alerts', 'incidents'):
            self.assertEqual(client.get(f'/{kind}').json(), [])
            self.assertEqual(client.get(f'/{kind}/not-a-uuid').status_code, 404)
            self.assertEqual(client.post(f'/{kind}', json={}).status_code, 405)
            for options in ({'limit': 0}, {'limit': 1001}, {'offset': -1}, {'offset': 2**63}):
                self.assertEqual(client.get(f'/{kind}', params=options).status_code, 422)
        self.assertEqual(client.get('/dashboard/summary').json(), self.dashboard.summary())
        self.assertEqual(client.get('/dashboard/snapshot').json(), self.dashboard.snapshot())

    def test_alert_incident_lists_get_filters_and_newest_first(self):
        initial, updated = self.sequence()
        client = self.client()
        alerts = [self.dashboard.operator_record("alert", item) for item in self.store.list_alerts()]
        self.assertEqual(client.get('/alerts', params={'limit': 1, 'offset': 1}).json(), alerts[1:2])
        self.assertEqual(client.get('/alerts', params={'newest_first': True}).json(), list(reversed(alerts)))
        for item in alerts:
            self.assertEqual(client.get('/alerts/' + item['alert_id']).json(), item)
            self.assertEqual(client.get('/alerts', params={'severity': item['severity'], 'alert_type': item['alert_type'], 'event_category': 'network'}).json(), [item])
        self.assertEqual(client.get('/alerts', params={'alert_type': "' OR 1=1 --"}).json(), [])
        self.assertEqual(client.get('/incidents/' + updated.incident_id).json(), self.dashboard.operator_record("incident", updated.to_dict()))
        self.assertEqual(client.get('/incidents', params={'incident_type': 'network_sequence', 'severity': 'high'}).json(), [self.dashboard.operator_record("incident", updated.to_dict())])
        self.assertEqual(client.get('/incidents', params={'severity': 'low'}).json(), [])
        for event in sample_events():
            self.store.insert(event)
        self.assertEqual(client.get('/events', params={'newest_first': True}).json(), [self.dashboard.operator_record("event", e.to_dict()) for e in self.store.list_events(newest_first=True)])

    def test_websocket_committed_event_alert_incident_and_multiple_clients(self):
        client = self.client()
        with client.websocket_connect('/ws/live') as one, client.websocket_connect('/ws/live') as two:
            self.assertEqual(one.receive_json()['schema_version'], 1)
            self.assertEqual(two.receive_json()['message_type'], 'status')
            self.store.insert(sample_events()[0])
            _, updated = self.sequence()
            for ws in (one, two):
                seen = set()
                for _ in range(12):
                    envelope = ws.receive_json()
                    self.assertEqual(envelope['schema_version'], 1)
                    if envelope['message_type'] != 'status':
                        self.assertIsInstance(envelope['sequence'], int)
                        seen.add(envelope['message_type'])
                        if envelope['message_type'] == 'incident':
                            self.assertEqual(envelope['data'], self.dashboard.operator_record("incident", updated.to_dict()))
                    if seen == {'event', 'alert', 'incident'}:
                        break
                self.assertEqual(seen, {'event', 'alert', 'incident'})
            one.close()
            two.close()
            client.portal.call(asyncio.sleep, 0.02)
        # Synchronize on the API loop after both ASGI sessions have ended.
        self.assertEqual(client.portal.call(lambda: len(self.app.state.live.clients)), 0)

    def test_websocket_origin_and_client_commands_rejected(self):
        client = self.client()
        with self.assertRaises(WebSocketDisconnect):
            with client.websocket_connect('/ws/live', headers={'origin': 'https://untrusted.example'}):
                pass
        with client.websocket_connect('/ws/live', headers={'origin': 'http://localhost:5173'}) as ws:
            ws.receive_json()
            ws.send_text('delete')
            with self.assertRaises(WebSocketDisconnect) as error:
                ws.receive_json()
            self.assertEqual(error.exception.code, 1008)
        response = client.get('/health', headers={'origin': 'http://localhost:5173'})
        self.assertEqual(response.headers['access-control-allow-origin'], 'http://localhost:5173')
        self.assertNotIn('access-control-allow-origin', client.get('/health', headers={'origin': 'https://untrusted.example'}).headers)

    def test_websocket_overflow_closes_and_cleans_client(self):
        client = self.client()
        with client.websocket_connect('/ws/live') as ws:
            ws.receive_json()
            def flood():
                for _ in range(CLIENT_QUEUE + 1):
                    self.app.state.live.publish({'schema_version': 1, 'message_type': 'status', 'data': {}})
            client.portal.call(flood)
            with self.assertRaises(WebSocketDisconnect) as error:
                for _ in range(CLIENT_QUEUE + 2):
                    ws.receive_json()
            self.assertEqual(error.exception.code, 1013)
        self.assertEqual(client.portal.call(lambda: len(self.app.state.live.clients)), 0)

    def test_rest_database_failure_is_service_unavailable(self):
        client = self.client()
        for method, endpoint in (('summary', '/dashboard/summary'), ('snapshot', '/dashboard/snapshot')):
            with patch.object(DashboardStore, method, side_effect=sqlite3.OperationalError('private path')), self.assertLogs('backend.api', level='ERROR'):
                response = client.get(endpoint)
            self.assertEqual(response.status_code, 503)
            self.assertNotIn('private path', response.text)


class LiveHubTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_clients_and_client_capacity(self):
        hub = LiveHub()
        hub.publish({'invalid': object()})  # Nothing retained or serialized without consumers.
        clients = [hub.connect() for _ in range(MAX_CLIENTS)]
        self.assertIsNone(hub.connect())
        for client in clients:
            hub.disconnect(client)
        self.assertFalse(hub.clients)

    async def test_queue_count_and_byte_bounds(self):
        hub = LiveHub()
        client = hub.connect()
        for _ in range(CLIENT_QUEUE + 100):
            hub.publish({'schema_version': 1, 'message_type': 'status', 'data': {}})
        self.assertEqual(client.queue.qsize(), CLIENT_QUEUE)
        self.assertTrue(client.overflow.is_set())
        hub.disconnect(client)
        client = hub.connect()
        for _ in range(8):
            hub.publish({'data': 'x' * 900000})
        self.assertLessEqual(client.bytes, CLIENT_BYTES)
        self.assertTrue(client.overflow.is_set())

    async def test_slow_client_does_not_affect_draining_client(self):
        hub = LiveHub()
        slow, fast = hub.connect(), hub.connect()
        for n in range(CLIENT_QUEUE + 5):
            hub.publish({'schema_version': 1, 'message_type': 'status', 'data': {'n': n}})
            text, size = fast.queue.get_nowait()
            fast.bytes -= size
            self.assertEqual(json.loads(text)['data']['n'], n)
        self.assertTrue(slow.overflow.is_set())
        self.assertFalse(fast.overflow.is_set())

    async def test_poll_failure_reports_status_and_recovers(self):
        hub = LiveHub()
        client = hub.connect()
        class Store:
            calls = 0
            def changes(self, cursors):
                self.calls += 1
                if self.calls == 1:
                    raise sqlite3.OperationalError('unavailable')
                return [], {}, False, {'schema_version': 1, 'message_type': 'status', 'data': {'database': 'ok'}}
        store = Store()
        # Pace only this test's poll loop; wait on the queue rather than sleeping.
        with patch('backend.live.POLL_SECONDS', .01), self.assertLogs('backend.live', level='ERROR'):
            task = asyncio.create_task(poll_store(store, hub))
            try:
                first, _ = await asyncio.wait_for(client.queue.get(), 2)
                second, _ = await asyncio.wait_for(client.queue.get(), 2)
                self.assertEqual(json.loads(first)['data']['database'], 'unavailable')
                self.assertEqual(json.loads(second)['data']['database'], 'ok')
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_live_send_failure_cannot_modify_persisted_security_output(self):
        hub = LiveHub()
        class BrokenSocket:
            async def accept(self): pass
            async def send_json(self, message): raise OSError('browser gone')
        await hub.serve(BrokenSocket())
        self.assertFalse(hub.clients)
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory)/'events.db')
            store.initialize()
            item = alert()
            before = item.to_dict()
            store.insert_alert(item)
            hub.publish({'schema_version': 1, 'message_type': 'alert', 'data': item.to_dict()})
            self.assertEqual(store.get_alert(item.alert_id).to_dict(), before)
            self.assertEqual(item.to_dict(), before)

    async def test_stalled_send_is_closed_with_retry_code(self):
        hub = LiveHub()
        class StalledSocket:
            code = None
            async def accept(self): pass
            async def send_json(self, message): await asyncio.Event().wait()
            async def close(self, code, reason): self.code = code
        socket = StalledSocket()
        with patch('backend.live.SEND_TIMEOUT', .01):
            await hub.serve(socket)
        self.assertEqual(socket.code, 1013)
        self.assertFalse(hub.clients)


class OperatorTimeTests(unittest.TestCase):
    setUp = DashboardStorageTests.setUp
    sequence = DashboardStorageTests.sequence

    def test_event_clock_is_independent_and_uint64_remains_exact(self):
        from datetime import datetime, timezone
        event = replace(sample_events()[0], timestamp=2**64-1)
        before = datetime.now(timezone.utc)
        self.store.insert(event)
        value = self.dashboard.snapshot()['events'][0]
        observed = datetime.fromisoformat(value['wall_clock_timestamp'])
        self.assertLess(abs((observed-before).total_seconds()), 5)
        self.assertEqual(value['timestamp'], 2**64-1)
        self.assertEqual(self.store.get(event.event_id), event)
        self.assertNotIn('wall_clock_timestamp', event.to_dict())

    def test_alert_clock_and_idempotent_replay(self):
        item = alert()
        self.store.insert_alert(item)
        before = self.dashboard.snapshot()
        self.assertTrue(before['alerts'][0]['wall_clock_timestamp'].endswith('Z'))
        self.store.insert_alert(item)
        self.assertEqual(self.dashboard.snapshot(), before)
        self.assertEqual(self.store.get_alert(item.alert_id).to_dict(), item.to_dict())

    def test_incident_update_clock_and_identical_replay(self):
        import time
        engine = CorrelationEngine(policy('network_sequence'))
        values = []
        for item in (alert(), alert('syn_flood', 2), alert('traffic_flood', 3)):
            self.store.insert_alert(item)
            for incident in engine.evaluate(item):
                self.store.save_incident(incident)
                values.append(self.dashboard.snapshot()['incidents'][0])
                time.sleep(0.02)
        initial, updated = values
        self.assertEqual(initial['created_at'], updated['created_at'])
        self.assertLess(initial['updated_at'], updated['updated_at'])
        self.assertEqual(updated['updated_timestamp'], incident.updated_timestamp)
        self.store.save_incident(incident)
        self.assertEqual(self.dashboard.snapshot()['incidents'][0], updated)

    def legacy_database(self):
        self.store.insert(sample_events()[0])
        _, updated = self.sequence()
        with self.store._connection() as connection, connection:
            for name in ('operator_event_insert', 'operator_alert_insert', 'operator_incident_insert', 'operator_incident_update'):
                connection.execute(f'DROP TRIGGER {name}')
            connection.execute('DROP TABLE operator_times')
            connection.execute('PRAGMA user_version=3')
        self.store.initialize()
        return updated

    def test_v3_legacy_records_have_no_fabricated_calendar_time(self):
        self.legacy_database()
        value = self.dashboard.snapshot()
        self.assertIsNone(value['events'][0]['wall_clock_timestamp'])
        self.assertIsNone(value['alerts'][0]['wall_clock_timestamp'])
        self.assertIsNone(value['incidents'][0]['created_at'])
        self.assertIsNone(value['incidents'][0]['updated_at'])
        from uuid import uuid4
        self.store.insert(replace(sample_events()[0], event_id=str(uuid4())))
        self.assertIsNotNone(self.dashboard.snapshot()['events'][0]['wall_clock_timestamp'])

    def test_legacy_incident_update_keeps_creation_unknown(self):
        old = self.legacy_database()
        changed = replace(old, description=old.description + ' Updated evidence')
        self.store.save_incident(changed)
        value = self.dashboard.snapshot()['incidents'][0]
        self.assertIsNone(value['created_at'])
        self.assertIsNotNone(value['updated_at'])

    def test_snapshot_rest_and_live_clocks_match_and_refresh_is_read_only(self):
        self.store.insert(sample_events()[0])
        self.sequence()
        before = self.dashboard.snapshot()
        with TestClient(create_app(self.path)) as client:
            for _ in range(2):
                self.assertEqual(client.get('/dashboard/snapshot').json(), before)
                for family, table in (('event', 'events'), ('alert', 'alerts'), ('incident', 'incidents')):
                    rows = client.get('/'+table, params={'newest_first': True}).json()
                    self.assertEqual(rows, before[table])
                    for row in rows:
                        self.assertEqual(client.get(f'/{table}/{row[family+"_id"]}').json(), row)
            with client.websocket_connect('/ws/live') as ws:
                ws.receive_json()
                seen = set()
                for _ in range(15):
                    message = ws.receive_json()
                    family = message['message_type']
                    if family != 'status':
                        table = family+'s' if family != 'incident' else 'incidents'
                        self.assertIn(message['data'], before[table])
                        seen.add(family)
                    if len(seen) == 3:
                        break
                self.assertEqual(seen, {'event', 'alert', 'incident'})
                ws.close()
                client.portal.call(asyncio.sleep, 0.02)
        self.assertEqual(self.dashboard.snapshot(), before)
