export const alert = (id = 'a', changes = {}) => ({ alert_id: id, timestamp: 64526968131894,
  rule_name: 'Basic TCP Port Scan', alert_type: 'port_scan', event_category: 'network',
  severity: 'medium', risk_score: 40, base_score: 30, score_modifiers: [], source_event_ids: ['e'],
  description: 'TCP SYN attempts to distinct ports', metadata: { src_ip: '192.0.2.1', dst_ip: '192.0.2.2', unique_port_count: 50 }, ...changes });
export const incident = (id = 'i', changes = {}) => ({ incident_id: id, created_timestamp: 1000000000, updated_timestamp: 10000000000,
  title: 'Network Sequence', incident_type: 'network_sequence', description: 'Same source/destination within 60 seconds',
  severity: 'high', risk_score: 65, status: 'open', alert_ids: ['a', 'b'], primary_entities: { src_ip: '192.0.2.1', dst_ip: '192.0.2.2' },
  metadata: { correlation_rule: 'network_sequence', correlation_window_ns: 60000000000 }, ...changes });
export const event = (id = 'e') => ({ event_id: id, timestamp: 1000000000, event_type: 'network_packet', event_category: 'network', source: 'xdp', metadata: {}, src_ip: '192.0.2.1', dst_ip: '192.0.2.2', protocol: 'TCP' });
export const summary = { total_events: 0, total_alerts: 0, total_incidents: 0,
  alerts_by_severity: { low: 0, medium: 0, high: 0, critical: 0 }, incidents_by_severity: { low: 0, medium: 0, high: 0, critical: 0 } };
export const snapshot = (cursor = 0, changes = {}) => ({ cursor, events: [], alerts: [], incidents: [], summary, ...changes });
export const envelope = (message_type, data, sequence = 1) => ({ schema_version: 1, message_type, sequence, data });
