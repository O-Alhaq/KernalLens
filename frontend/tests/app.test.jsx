import React from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { INITIAL } from '../src/client';
import { alert, incident, summary } from './fixtures';
const transport = vi.hoisted(() => ({ callback: null, refresh: vi.fn(), stop: vi.fn() }));
vi.mock('../src/client', async importOriginal => ({ ...(await importOriginal()), startDashboard: options => {
  transport.callback = options.onChange;
  return { refresh: transport.refresh, stop: transport.stop };
} }));
import App from '../src/App';
afterEach(cleanup);
it('shows independent API/live status and empty states', () => {
  render(<App/>);
  act(() => transport.callback({ ...INITIAL, loading: false, api: 'Online', live: 'Reconnecting', summary }));
  expect(screen.getByText('API: Online')).toBeTruthy();
  expect(screen.getByText('Live: Reconnecting')).toBeTruthy();
  expect(screen.getByText('No alerts yet')).toBeTruthy();
  expect(screen.getByText('No correlated incidents yet')).toBeTruthy();
  expect(screen.getByText(/API health does not establish sensor health/)).toBeTruthy();
});
it('updates open incident details from the live state by stable ID', () => {
  render(<App/>);
  const state = { ...INITIAL, loading: false, api: 'Online', live: 'Connected', summary, alerts: [alert()], incidents: [incident()] };
  act(() => transport.callback(state));
  fireEvent.click(screen.getByRole('button', { name: /Network Sequence/ }));
  expect(screen.getByText('Member Alert IDs (2)')).toBeTruthy();
  act(() => transport.callback({ ...state, incidents: [incident('i', { alert_ids: ['a', 'b', 'c'] })] }));
  expect(screen.getByText('Member Alert IDs (3)')).toBeTruthy();
  expect(screen.queryByText('Member Alert IDs (2)')).toBeNull();
});
it('keeps records visible with a request error and offers retry', () => {
  render(<App/>);
  act(() => transport.callback({ ...INITIAL, loading: false, api: 'Unavailable', error: 'Backend offline', alerts: [alert()] }));
  expect(screen.getByRole('alert').textContent).toContain('Backend offline');
  expect(screen.getByText('Basic TCP Port Scan')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: /Refresh history/ }));
  expect(transport.refresh).toHaveBeenCalled();
});
