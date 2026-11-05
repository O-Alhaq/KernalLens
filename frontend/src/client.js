import { applyMessage, parseJSON, validateSnapshot } from './data';
export const reconnectDelay = attempt => Math.min(30000, 1000 * 2 ** Math.min(attempt, 5));
export const INITIAL = { events: [], alerts: [], incidents: [], summary: null, api: 'Checking', live: 'Connecting', loading: true, error: '' };

export function startDashboard({ api, wsUrl, onChange, fetcher = fetch, Socket = WebSocket }) {
  let state = { ...INITIAL }, socket, stopped = false, retry, refreshRetry, request;
  let attempt = 0, floor = 0, loading = false, buffer = [], generation = 0;
  const emit = changes => { if (!stopped) { state = { ...state, ...changes }; onChange(state); } };
  function invalidateRequest() {
    generation++; request?.abort(); loading = false; buffer = [];
    clearTimeout(refreshRetry);
  }
  async function refresh() {
    if (stopped || loading) return;
    clearTimeout(refreshRetry);
    loading = true;
    const current = generation;
    buffer = [];
    const controller = new AbortController();
    request = controller;
    const timeout = setTimeout(() => controller.abort(), 10000);
    emit({ loading: true });
    let resyncAgain = false;
    try {
      const response = await fetcher(`${api}/dashboard/snapshot`, { signal: controller.signal });
      if (!response.ok) throw new Error(`API returned ${response.status}`);
      const snapshot = validateSnapshot(parseJSON(await response.text()));
      if (stopped || generation !== current) return;
      floor = snapshot.cursor;
      state = { ...state, ...snapshot, api: 'Online', error: '', loading: false };
      for (const message of buffer) {
        state = applyMessage(state, message, floor);
        if (message.message_type === 'status' && message.data.resync_required && message.sequence > floor)
          resyncAgain = true;
      }
      emit({});
    } catch (error) {
      if (!stopped && generation === current) {
        emit({ api: 'Unavailable', loading: false, error: `Could not load history: ${error.message}` });
        refreshRetry = setTimeout(refresh, 5000);
      }
    } finally {
      clearTimeout(timeout);
      if (generation === current) {
        loading = false; buffer = [];
        if (resyncAgain) refreshRetry = setTimeout(refresh, 1000);
      }
    }
  }
  function connect() {
    if (stopped) return;
    emit({ live: attempt ? 'Reconnecting' : 'Connecting' });
    let active;
    try { active = new Socket(wsUrl); } catch {
      emit({ live: 'Reconnecting', error: 'Could not open live connection. Check the WebSocket URL.' });
      retry = setTimeout(connect, reconnectDelay(attempt++));
      return;
    }
    socket = active;
    const handshake = setTimeout(() => active.close(), 10000);
    let closed = false;
    active.onopen = () => {
      clearTimeout(handshake);
      if (stopped || active !== socket) return;
      // The authoritative snapshot must begin AFTER this socket is registered.
      // An earlier request may otherwise leave a gap between REST and live delivery.
      invalidateRequest();
      emit({ live: 'Connected' });
      active.stableTimer = setTimeout(() => { attempt = 0; }, 30000);
      refresh();
    };
    active.onmessage = event => {
      if (stopped || active !== socket || closed) return;
      try {
        if (event.data.length > 1024 * 1024) throw new Error('Oversized live message');
        const message = parseJSON(event.data);
        applyMessage(state, message, floor);
        if (loading) {
          if (buffer.length >= 256) { active.close(); return; }
          buffer.push(message);
        } else {
          state = applyMessage(state, message, floor);
          emit({});
          if (message.message_type === 'status' && (message.data.resync_required ||
              (message.data.database === 'ok' && state.api !== 'Online'))) refresh();
        }
        if (message.message_type === 'status' && message.data.database === 'unavailable')
          emit({ api: 'Unavailable', error: 'Live database read unavailable; showing retained data.' });
      } catch { emit({ error: 'Invalid live message ignored. Reconnecting to refresh history.' }); active.close(); }
    };
    active.onerror = () => { emit({ live: 'Disconnected' }); active.close(); };
    active.onclose = () => {
      clearTimeout(handshake);
      clearTimeout(active.stableTimer);
      if (stopped || active !== socket || closed) return;
      closed = true;
      invalidateRequest();
      emit({ live: 'Reconnecting', api: 'Unknown', loading: false });
      retry = setTimeout(connect, reconnectDelay(attempt++));
    };
  }
  emit({});
  refresh();
  connect();
  return { refresh, stop() {
    stopped = true; invalidateRequest();
    clearTimeout(retry); clearTimeout(socket?.stableTimer);
    socket?.close();
  } };
}
