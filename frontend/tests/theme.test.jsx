import React from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { INITIAL } from '../src/client';
import { alert, incident, summary } from './fixtures';
import { THEME_KEY } from '../src/theme';
const transport = vi.hoisted(() => ({ callback: null, starts: vi.fn(), stop: vi.fn() }));
vi.mock('../src/client', async original => ({ ...(await original()), startDashboard: options => {
  transport.starts(); transport.callback = options.onChange;
  return { refresh: vi.fn(), stop: transport.stop };
} }));
import App from '../src/App';
const system = dark => vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: dark })));
beforeEach(() => { localStorage.clear(); transport.starts.mockClear(); transport.stop.mockClear(); system(false); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const theme = () => document.documentElement.dataset.theme;
const toggle = () => fireEvent.click(screen.getByRole('button', { name: /Switch theme/ }));
it('renders light on a light system without saving an explicit preference', () => {
  render(<App/>); expect(theme()).toBe('light'); expect(screen.getByRole('button', { name: /Theme: Light/ })).toBeTruthy();
  expect(localStorage.getItem(THEME_KEY)).toBeNull();
});
it('uses dark system preference on first visit', () => {
  system(true); render(<App/>); expect(theme()).toBe('dark'); expect(screen.getByRole('button', { name: /Theme: Dark/ })).toBeTruthy();
});
it('saved light overrides a dark system', () => {
  system(true); localStorage.setItem(THEME_KEY, 'light'); render(<App/>); expect(theme()).toBe('light');
});
it('saved dark overrides a light system', () => {
  localStorage.setItem(THEME_KEY, 'dark'); render(<App/>); expect(theme()).toBe('dark');
});
it('toggles both directions and persists the explicit choice', () => {
  render(<App/>); toggle(); expect(theme()).toBe('dark'); expect(localStorage.getItem(THEME_KEY)).toBe('dark');
  toggle(); expect(theme()).toBe('light'); expect(localStorage.getItem(THEME_KEY)).toBe('light');
});
it('restores the saved theme after a new mount', () => {
  const view = render(<App/>); toggle(); view.unmount(); render(<App/>); expect(theme()).toBe('dark');
});
it('ignores an invalid saved choice and uses system preference', () => {
  system(true); localStorage.setItem(THEME_KEY, 'invalid'); render(<App/>); expect(theme()).toBe('dark');
});
it('keeps alert and incident records, details and live connection across theme changes', () => {
  render(<App/>);
  act(() => transport.callback({ ...INITIAL, loading: false, api: 'Online', live: 'Connected', summary, alerts: [alert()], incidents: [incident()] }));
  fireEvent.click(screen.getByRole('button', { name: /Network Sequence/ }));
  toggle(); toggle();
  expect(screen.getAllByText('Basic TCP Port Scan')).toHaveLength(1);
  expect(screen.getByText('Member Alert IDs (2)')).toBeTruthy();
  expect(screen.getAllByRole('button', { name: /Network Sequence/ })).toHaveLength(1);
  expect(screen.getByText('Live: Connected')).toBeTruthy(); expect(screen.getByText('API: Online')).toBeTruthy();
  expect(transport.starts).toHaveBeenCalledTimes(1); expect(transport.stop).not.toHaveBeenCalled();
});
it('keeps the toggle usable when storage is unavailable', () => {
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw Error('blocked'); });
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw Error('blocked'); });
  render(<App/>); toggle(); expect(theme()).toBe('dark'); vi.restoreAllMocks();
});
