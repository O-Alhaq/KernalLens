import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { reconnectDelay, startDashboard } from '../src/client';
import { alert, envelope, snapshot } from './fixtures';
let clients = [];
class FakeSocket {
  static instances = [];
  constructor(url) { this.url = url; FakeSocket.instances.push(this); }
  open() { this.onopen?.(); }
  message(value) { this.onmessage?.({ data: typeof value === 'string' ? value : JSON.stringify(value) }); }
  close() { this.onclose?.(); }
}
const response = value => ({ ok: true, text: async () => JSON.stringify(value) });
function setup(fetcher = vi.fn().mockResolvedValue(response(snapshot()))) {
  let state;
  const client = startDashboard({ api: 'http://test', wsUrl: 'ws://test/ws/live', Socket: FakeSocket, fetcher, onChange: next => { state = next; } });
  clients.push(client);
  return { client, fetcher, state: () => state, socket: () => FakeSocket.instances.at(-1) };
}
async function settle() { for (let n = 0; n < 10; n++) await Promise.resolve(); }
beforeEach(() => { vi.useFakeTimers(); FakeSocket.instances = []; });
afterEach(() => { clients.forEach(c => c.stop()); clients = []; vi.useRealTimers(); });

it('loads history, shows disconnected/reconnecting and refreshes on reconnect', async () => {
  const app = setup(); await settle();
  expect(app.state().api).toBe('Online');
  app.socket().open(); await settle();
  expect(app.state().live).toBe('Connected');
  app.socket().close();
  expect(app.state().live).toBe('Reconnecting');
  expect(FakeSocket.instances).toHaveLength(1);
  await vi.advanceTimersByTimeAsync(999);
  expect(FakeSocket.instances).toHaveLength(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(FakeSocket.instances).toHaveLength(2);
  app.socket().open(); await settle();
  expect(app.fetcher).toHaveBeenCalledTimes(3);
});
it('buffers messages during REST, ignores covered IDs and applies newer changes', async () => {
  let finish;
  const app = setup(vi.fn().mockImplementation(() => new Promise(resolve => { finish = resolve; })));
  app.socket().open();
  app.socket().message(envelope('alert', alert('already'), 10));
  app.socket().message(envelope('alert', alert('new'), 11));
  finish(response(snapshot(10, { alerts: [alert('already')] })));
  await settle();
  expect(app.state().alerts.map(a => a.alert_id)).toEqual(['new', 'already']);
});
it('starts a fresh snapshot after socket opens even if initial REST is pending', async () => {
  const completions = [];
  const app = setup(vi.fn().mockImplementation(() => new Promise(resolve => completions.push(resolve))));
  app.socket().open();
  expect(app.fetcher).toHaveBeenCalledTimes(2);
  completions[1](response(snapshot(20, { alerts: [alert('current')] })));
  await settle();
  completions[0](response(snapshot(1, { alerts: [alert('stale')] })));
  await settle();
  expect(app.state().alerts[0].alert_id).toBe('current');
});
it('caps reconnect delays and cleans timers when stopped', async () => {
  expect([0, 1, 2, 3, 4, 5, 50].map(reconnectDelay)).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000]);
  const app = setup();
  app.socket().open(); await settle(); app.client.stop();
  await vi.advanceTimersByTimeAsync(60000);
  expect(FakeSocket.instances).toHaveLength(1);
});
it('handles REST failure with a visible error and bounded retry', async () => {
  const app = setup(vi.fn().mockRejectedValue(new Error('Offline')));
  await settle();
  expect(app.state().api).toBe('Unavailable');
  expect(app.state().error).toContain('Offline');
  await vi.advanceTimersByTimeAsync(4999);
  expect(app.fetcher).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(app.fetcher).toHaveBeenCalledTimes(2);
});
it('malformed live data does not crash the controller', async () => {
  const app = setup(); app.socket().open(); await settle();
  app.socket().message('not json');
  expect(app.state().error).toContain('Invalid live message');
  expect(app.state().live).toBe('Reconnecting');
});
it('reloads the REST snapshot on journal gap', async () => {
  const app = setup(); app.socket().open(); await settle();
  const before = app.fetcher.mock.calls.length;
  app.socket().message(envelope('status', { resync_required: true }, 10));
  await settle();
  expect(app.fetcher.mock.calls.length).toBe(before + 1);
});
it('bounds messages accumulated while REST is unavailable', () => {
  const app = setup(vi.fn().mockImplementation(() => new Promise(() => {})));
  app.socket().open();
  for (let n = 0; n < 257; n++) app.socket().message(envelope('alert', alert(String(n)), n + 1));
  expect(app.state().live).toBe('Reconnecting');
  expect(app.state().alerts).toHaveLength(0);
});
