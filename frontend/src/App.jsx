import React, { useEffect, useState } from 'react';
import { API_BASE, WS_URL } from './config';
import { INITIAL, startDashboard } from './client';
import { formatAmmanTime, SEVERITIES } from './data';
import { initialTheme, applyTheme } from './theme';
import { AlertRow, IncidentCard, Detail, Empty } from './components';

export default function App() {
  const [theme, setTheme] = useState(initialTheme);
  useEffect(() => { applyTheme(theme); }, [theme]);
  const toggleTheme = () => { const next = theme === 'dark' ? 'light' : 'dark'; applyTheme(next, true); setTheme(next); };
  const [state, setState] = useState(INITIAL);
  const [section, setSection] = useState('Overview');
  const [filter, setFilter] = useState('all');
  const [selected, setSelected] = useState(null);
  const [refresh, setRefresh] = useState(null);
  useEffect(() => {
    const client = startDashboard({ api: API_BASE, wsUrl: WS_URL, onChange: setState });
    setRefresh(() => client.refresh);
    return () => client.stop();
  }, []);
  const show = name => section === 'Overview' || section === name;
  const selectedItem = selected && (state[selected.kind].find(item => item[selected.key] === selected.id) || selected.item);
  const choose = (kind, item) => {
    const key = { alerts: 'alert_id', incidents: 'incident_id', events: 'event_id' }[kind];
    setSelected({ kind, item, id: item[key], key });
  };
  const alerts = state.alerts.filter(a => filter === 'all' || a.severity === filter);
  return <div className="app-shell"><aside className="sidebar"><a className="brand" href="#" onClick={() => setSection('Overview')}><span className="brand-mark">K<span>⌁</span></span><span>KernelLens<small>SECURITY OBSERVATORY</small></span></a>
    <div className="workspace"><span className="host-dot"/><div>Local host<small>Single-sensor workspace</small></div><span className="workspace-icon">⌘</span></div>
    <p className="nav-label">MONITOR</p><nav>{['Overview', 'Alerts', 'Incidents', 'Telemetry'].map((name, i) => <button className={section === name ? 'active' : ''} onClick={() => { setSection(name); setSelected(null); }} key={name}><span className="nav-icon">{['▦', '◈', '▱', '≋'][i]}</span>{name}{name === 'Alerts' && <span className="nav-count">{state.summary?.total_alerts ?? '—'}</span>}</button>)}</nav>
    <div className="sidebar-foot"><span className="readonly">◉ READ-ONLY</span><p>Observe. Investigate.<br/>Understand the evidence.</p><small>KernelLens · M11</small></div></aside>
    <main><header className="topbar"><span>Workspace <span className="slash">/</span> <strong>{section}</strong></span><div className="status-row"><button className="theme-toggle" aria-label={`Theme: ${theme === 'dark' ? 'Dark' : 'Light'}. Switch theme`} onClick={toggleTheme}>{theme === 'dark' ? 'Dark' : 'Light'}</button><span className={`status ${state.api === 'Online' ? 'good' : 'warn'}`}><i/>API: {state.api}</span><span className={`status ${state.live === 'Connected' ? 'good' : 'warn'}`}><i/>Live: {state.live}</span></div></header>
    <div className="content"><div className="page-heading"><div><p className="eyebrow">HOST & NETWORK VISIBILITY</p><h1>{section === 'Overview' ? 'Security overview' : section === 'Telemetry' ? 'Recent telemetry' : section}</h1><p className="subtitle">{section === 'Overview' ? 'A clear view of detections, correlated activity, and the evidence behind them.' : 'Persisted evidence, updated live from the security core.'}</p></div><button className="refresh" disabled={state.loading} onClick={() => refresh?.()}>{state.loading ? 'Loading…' : '↻ Refresh history'}</button></div>
    {state.error && <div className="error" role="alert">{state.error} Retained records remain visible.</div>}
    <div className="metrics">{[['events', 'Security events', 'Normalized telemetry'], ['alerts', 'Rule detections', 'Finalized, scored alerts'], ['incidents', 'Correlated incidents', 'Related security detections']].map(([key, label, note], i) => <article className="metric" key={key}><span className="metric-label">{label}<span>{['≋', '◈', '▱'][i]}</span></span><strong>{state.summary ? state.summary[`total_${key}`].toLocaleString() : '—'}</strong><small>{note} <span>Persisted total</span></small></article>)}</div>
    {selected && selectedItem && <Detail kind={selected.kind} item={selectedItem} onClose={() => setSelected(null)}/>}
    {show('Alerts') && <section className="panel"><div className="section-heading"><div><h2>Recent alerts <span className="pill">{state.alerts.length}</span></h2><p>Confirmed detections · backend-calculated severity</p></div><label className="filter">Severity <select value={filter} onChange={e => setFilter(e.target.value)}><option value="all">All severities</option>{SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}</select></label></div>
      <div className="severity-strip">{SEVERITIES.map(s => <div key={s}><span className={`severity ${s}`}><i/>{s}</span><strong>{state.summary?.alerts_by_severity[s] ?? '—'}</strong></div>)}</div>
      {alerts.length ? <div className="table-scroll"><table><thead><tr><th>Detection</th><th>Severity</th><th>Risk score</th><th>Entities</th><th>Category</th><th>Detected · Amman</th></tr></thead><tbody>{alerts.map(a => <AlertRow key={a.alert_id} alert={a} onSelect={a => choose('alerts', a)}/>)}</tbody></table></div> : <Empty>{state.loading ? 'Loading recent alerts…' : filter === 'all' ? 'No alerts yet' : `No ${filter} alerts in the recent feed`}</Empty>}
      <div className="panel-foot">Latest 100 persisted alerts <span>Scores are supplied by the security core</span></div></section>}
    {show('Incidents') && <section className="panel"><div className="section-heading"><div><h2>Recent incidents <span className="pill">{state.incidents.length}</span></h2><p>Related detections, connected by explicit correlation rules</p></div><span className="section-note">Select to investigate ↗</span></div>{state.incidents.length ? <div className="incident-grid">{state.incidents.map(i => <IncidentCard key={i.incident_id} incident={i} onSelect={i => choose('incidents', i)}/>)}</div> : <Empty>{state.loading ? 'Loading incidents…' : 'No correlated incidents yet'}</Empty>}<div className="panel-foot">Latest 50 incidents <span>Hybrid relationships are contextual, not process attribution</span></div></section>}
    {show('Telemetry') && <section className="panel"><div className="section-heading"><div><h2>Recent telemetry <span className="pill">{state.events.length}</span></h2><p>Normalized SecurityEvents from XDP and host tracepoints</p></div><span className="section-note">Bounded live feed</span></div>{state.events.length ? <div className="table-scroll"><table><thead><tr><th>Event</th><th>Source</th><th>Process</th><th>Network</th><th>Observed · Amman</th></tr></thead><tbody>{state.events.map(e => <tr key={e.event_id}><td><button className="row-link" onClick={() => choose('events', e)}>{e.event_type}<small>{e.event_category}</small></button></td><td><span className="source-tag">{e.source}</span></td><td>{e.process_name || '—'}<small>{e.pid != null ? `PID ${e.pid}` : 'No process attribution'}</small></td><td className="mono">{e.src_ip ? `${e.src_ip} → ${e.dst_ip}` : '—'}<small>{e.protocol || 'Host activity'}</small></td><td className="mono time">{formatAmmanTime(e.wall_clock_timestamp)}</td></tr>)}</tbody></table></div> : <Empty>{state.loading ? 'Loading telemetry…' : 'No persisted telemetry yet'}</Empty>}<div className="panel-foot">Latest 100 events · live delivery may be sampled during bursts<span>History remains in SQLite</span></div></section>}
    <footer><span>KernelLens / Local security observatory</span><span>API health does not establish sensor health · Display timezone: Amman</span></footer></div></main></div>;
}
