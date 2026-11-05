import { describe, it, expect } from 'vitest';
import { applyMessage, bootTime, CAPS, parseJSON, upsert, validateSnapshot } from '../src/data';
import { alert, incident, event, envelope, snapshot } from './fixtures';

describe('bounded live data', () => {
  it('replaces duplicate alert IDs without changing backend risk', () => {
    const state = snapshot(0, { alerts: [alert()] });
    const next = applyMessage(state, envelope('alert', alert('a', { risk_score: 49 })));
    expect(next.alerts).toHaveLength(1);
    expect(next.alerts[0].risk_score).toBe(49);
    expect(state.alerts[0].risk_score).toBe(40);
  });
  it('replaces incident updates instead of duplicating records', () => {
    let state = applyMessage(snapshot(), envelope('incident', incident()));
    state = applyMessage(state, envelope('incident', incident('i', { alert_ids: ['a', 'b', 'c'] }), 2));
    expect(state.incidents).toHaveLength(1);
    expect(state.incidents[0].alert_ids).toHaveLength(3);
  });
  it('deduplicates events and bounds every list', () => {
    for (const [kind, factory] of Object.entries({ events: event, alerts: alert, incidents: incident })) {
      let items = [];
      for (let i = 0; i < 300; i++) items = upsert(items, factory(String(i)), kind);
      expect(items).toHaveLength(CAPS[kind]);
      items = upsert(items, factory('299'), kind);
      expect(items).toHaveLength(CAPS[kind]);
    }
  });
  it('ignores messages already covered by the authoritative snapshot', () => {
    const state = snapshot(10, { alerts: [alert()] });
    expect(applyMessage(state, envelope('alert', alert('old'), 9), 10)).toBe(state);
    expect(applyMessage(state, envelope('alert', alert('equal'), 10), 10)).toBe(state);
    expect(applyMessage(state, envelope('alert', alert('new'), 11), 10).alerts).toHaveLength(2);
  });
  it('rejects unknown versions, message types and malformed records', () => {
    for (const message of [null, {}, { ...envelope('alert', alert()), schema_version: 2 }, envelope('command', {}), envelope('alert', {}), envelope('alert', alert('a', { description: {} })), envelope('status', { summary: {} })]) {
      expect(() => applyMessage(snapshot(), message)).toThrow();
    }
    expect(() => validateSnapshot({})).toThrow();
    expect(() => validateSnapshot(snapshot(0, { events: Array(101).fill(event()) }))).toThrow();
  });
  it('preserves uint64 timestamps and displays monotonic time, not dates', () => {
    const value = parseJSON('{"timestamp":18446744073709551615}');
    expect(value.timestamp).toBe('18446744073709551615');
    expect(bootTime(value.timestamp)).toContain('.709 s');
    expect(bootTime(1000000000)).toBe('+1.000 s');
    expect(bootTime('bad')).toBe('Unavailable');
  });
  it('accepts empty snapshots and status-only updates', () => {
    expect(validateSnapshot(snapshot())).toEqual(snapshot());
    const next = applyMessage(snapshot(), envelope('status', { summary: { ...snapshot().summary, total_events: 1000 } }));
    expect(next.summary.total_events).toBe(1000);
    expect(next.events).toEqual([]);
  });
});
