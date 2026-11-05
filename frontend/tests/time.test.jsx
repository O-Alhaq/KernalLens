import React from 'react';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { formatAmmanTime, parseJSON, applyMessage, validateSnapshot } from '../src/data';
import { Detail, AlertRow } from '../src/components';
import { alert, incident, snapshot, envelope } from './fixtures';
afterEach(cleanup);
const utc = '2026-10-31T16:34:51.000Z';
it('converts UTC to Asia/Amman with calendar date and seconds', () => {
  expect(formatAmmanTime(utc)).toBe('Oct 31, 2026, 7:34:51 PM');
});
it('never treats monotonic values as Unix dates and safely handles absent or invalid clocks', () => {
  for (const v of [null, undefined, '', 'bad', '2026-99-99T00:00:00Z', 72331395000000, '72331395000000', 18446744073709551615n]) expect(formatAmmanTime(v)).toBe('Time unavailable');
});
it('renders alert detection calendar time', () => {
  render(<table><tbody><AlertRow alert={alert('a', { wall_clock_timestamp: utc })} onSelect={() => {}}/></tbody></table>);
  expect(screen.getByText('Oct 31, 2026, 7:34:51 PM')).toBeTruthy();
});
it('renders created and updated Amman times alongside exact monotonic details', () => {
  render(<Detail kind="incidents" item={incident('i', { created_at: utc, updated_at: '2026-10-31T16:34:54Z' })} onClose={() => {}}/>);
  expect(screen.getByText('Oct 31, 2026, 7:34:51 PM')).toBeTruthy();
  expect(screen.getByText('Oct 31, 2026, 7:34:54 PM')).toBeTruthy();
  expect(screen.getByText('Amman (Asia/Amman)')).toBeTruthy(); expect(screen.getByText(/not a calendar date/)).toBeTruthy();
});
it('preserves uint64 security clocks while REST and live display clocks agree', () => {
  const item = parseJSON(JSON.stringify(alert('a', { wall_clock_timestamp: utc })).replace(/"timestamp":\d+/, '"timestamp":18446744073709551615'));
  const rest = validateSnapshot(snapshot(1, { alerts: [item] }));
  const live = applyMessage(rest, envelope('alert', item, 2), 1);
  expect(live.alerts).toHaveLength(1); expect(live.alerts[0].timestamp).toBe('18446744073709551615');
  expect(formatAmmanTime(live.alerts[0].wall_clock_timestamp)).toBe(formatAmmanTime(rest.alerts[0].wall_clock_timestamp));
});
it('renders a safe fallback for a legacy event', () => {
  render(<Detail kind="events" item={{event_id:'e',event_type:'network_packet',timestamp:'18446744073709551615',metadata:{}}} onClose={() => {}}/>);
  expect(screen.getByText('Time unavailable')).toBeTruthy(); expect(screen.getByText('+18,446,744,073.709 s')).toBeTruthy();
});
