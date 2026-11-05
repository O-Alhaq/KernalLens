import JSONbig from 'json-bigint';
export const parseJSON = JSONbig({ storeAsString: true, protoAction: 'error', constructorAction: 'error' }).parse;
export const CAPS = { events: 100, alerts: 100, incidents: 50 };
export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const IDS = { events: 'event_id', alerts: 'alert_id', incidents: 'incident_id' };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = value => typeof value === 'string' && value.length > 0;
const timestamp = value => (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) ||
  (typeof value === 'string' && /^\d+$/.test(value));
export function validRecord(kind, item) {
  if (!object(item) || !text(item[IDS[kind]]) || !object(item.metadata)) return false;
  if (kind === 'events') return timestamp(item.timestamp) && text(item.event_type) && text(item.event_category) && text(item.source) &&
    [item.process_name, item.src_ip, item.dst_ip, item.protocol].every(v => v == null || typeof v === 'string');
  if (!Number.isInteger(item.risk_score) || item.risk_score < 0 || item.risk_score > 100 || !SEVERITIES.includes(item.severity)) return false;
  return kind === 'alerts' ? timestamp(item.timestamp) && text(item.rule_name) && text(item.description) && text(item.alert_type) && text(item.event_category) :
    timestamp(item.created_timestamp) && timestamp(item.updated_timestamp) && text(item.title) && text(item.description) &&
    text(item.incident_type) && text(item.status) && object(item.primary_entities) && Array.isArray(item.alert_ids) && item.alert_ids.every(text);
}
export function validSummary(value) {
  return object(value) && ['events', 'alerts', 'incidents'].every(k => Number.isSafeInteger(value[`total_${k}`]) && value[`total_${k}`] >= 0) &&
    ['alerts', 'incidents'].every(k => object(value[`${k}_by_severity`]) && SEVERITIES.every(s => Number.isSafeInteger(value[`${k}_by_severity`][s]) && value[`${k}_by_severity`][s] >= 0));
}
export function validateSnapshot(value) {
  if (!object(value) || !Number.isSafeInteger(value.cursor) || value.cursor < 0 || !validSummary(value.summary) ||
      !Object.keys(CAPS).every(k => Array.isArray(value[k]) && value[k].length <= CAPS[k] && value[k].every(v => validRecord(k, v)))) throw new Error('Invalid dashboard response');
  return value;
}
export function upsert(items, item, kind) {
  return [item, ...items.filter(old => old[IDS[kind]] !== item[IDS[kind]])].slice(0, CAPS[kind]);
}
export function applyMessage(state, message, floor = 0) {
  if (!object(message) || message.schema_version !== 1 || !object(message.data)) throw new Error('Unsupported live message');
  if (message.message_type === 'status') {
    if (message.data.summary && !validSummary(message.data.summary)) throw new Error('Invalid live summary');
    if (message.sequence != null && message.sequence <= floor) return state;
    return message.data.summary ? { ...state, summary: message.data.summary } : state;
  }
  const kind = { event: 'events', alert: 'alerts', incident: 'incidents' }[message.message_type];
  if (!kind || !Number.isSafeInteger(message.sequence) || !validRecord(kind, message.data)) throw new Error('Invalid live record');
  if (message.sequence <= floor) return state;
  return { ...state, [kind]: upsert(state[kind], message.data, kind) };
}
export function bootTime(value) {
  try {
    const ns = BigInt(value);
    return `+${(ns / 1000000000n).toLocaleString()}.${((ns % 1000000000n) / 1000000n).toString().padStart(3, '0')} s`;
  } catch { return 'Unavailable'; }
}
export const pretty = value => JSON.stringify(value, null, 2);

const ammanFormatter = new Intl.DateTimeFormat('en-US', {
  timeZone: 'Asia/Amman', year: 'numeric', month: 'short', day: 'numeric',
  hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true,
});
export function formatAmmanTime(value) {
  // Accept only explicit canonical UTC strings, never numeric sensor clocks.
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)) return 'Time unavailable';
  const date = new Date(value);
  return (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 19) !== value.slice(0, 19)) ? 'Time unavailable' : ammanFormatter.format(date);
}
