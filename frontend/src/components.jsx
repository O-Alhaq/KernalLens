import React from 'react';
import { bootTime, pretty, formatAmmanTime } from './data';
export function Severity({ value }) { return <span className={`severity ${value}`}><i/>{value}</span>; }
export function Risk({ value }) { return <span className="risk"><strong>{value}</strong><span> / 100</span></span>; }
export function Empty({ children }) { return <div className="empty"><span className="empty-icon">◇</span><p>{children}</p><small>Persisted detections will appear here as they arrive.</small></div>; }
export function Entities({ value }) {
  const pairs = Object.entries(value || {}).filter(([, v]) => v != null && ['string', 'number'].includes(typeof v));
  return <span className="entities">{pairs.length ? pairs.map(([k, v]) => <span key={k}><small>{k.replaceAll('_', ' ')}</small> {String(v)}</span>) : 'No entities available'}</span>;
}
export function AlertRow({ alert, onSelect }) {
  return <tr><td><button className="row-link" onClick={() => onSelect(alert)}>{alert.rule_name}<small>{alert.alert_type.replaceAll('_', ' ')}</small></button></td>
    <td><Severity value={alert.severity}/></td><td><Risk value={alert.risk_score}/></td>
    <td><Entities value={{ src_ip: alert.metadata.src_ip, dst_ip: alert.metadata.dst_ip, pid: alert.metadata.pid, process_name: alert.metadata.process_name }}/></td>
    <td className="muted">{alert.event_category}</td><td className="mono time">{formatAmmanTime(alert.wall_clock_timestamp)}</td></tr>;
}
export function IncidentCard({ incident, onSelect }) {
  return <button className="incident-card" onClick={() => onSelect(incident)}><div className="card-top"><span className="eyebrow">{incident.incident_type.replaceAll('_', ' ')}</span><span className="open-state">{incident.status}</span></div>
    <h3>{incident.title}</h3><Entities value={incident.primary_entities}/><div className="incident-bottom"><Severity value={incident.severity}/><Risk value={incident.risk_score}/><span>{incident.alert_ids.length} alerts ↗</span></div>
    <div className="card-time">Created {formatAmmanTime(incident.created_at)} · Updated {formatAmmanTime(incident.updated_at)}</div></button>;
}
export function Detail({ item, kind, onClose }) {
  const incident = kind === 'incidents';
  const id = item[incident ? 'incident_id' : kind === 'alerts' ? 'alert_id' : 'event_id'];
  return <section className="detail" aria-label="Detection details"><div className="section-heading"><div><p className="eyebrow">{kind.slice(0, -1)} details</p><h2>{item.title || item.rule_name || item.event_type}</h2></div><button className="close" onClick={onClose}>Close ×</button></div>
    <p className="mono id">{id}</p>{kind !== 'events' && <div className="detail-score"><Severity value={item.severity}/><Risk value={item.risk_score}/>{incident && <span>Status: {item.status}</span>}</div>}
    <p>{item.description}</p>{incident && item.incident_type === 'hybrid_activity' && <p className="notice">This correlation is temporal/contextual. It does not prove exact process-to-network attribution.</p>}
    <dl><dt>Type</dt><dd>{item.incident_type || item.alert_type || item.event_type}</dd><dt>{incident ? 'Created' : kind === 'events' ? 'Observed' : 'Detected'}</dt><dd>{formatAmmanTime(incident ? item.created_at : item.wall_clock_timestamp)}</dd>
      {incident && <><dt>Updated</dt><dd>{formatAmmanTime(item.updated_at)}</dd></>}<dt>Timezone</dt><dd>Amman (Asia/Amman)</dd><dt>Monotonic</dt><dd className="mono">{incident ? `${bootTime(item.created_timestamp)} / ${bootTime(item.updated_timestamp)}` : bootTime(item.timestamp)}</dd>
      <dt>Clock</dt><dd>Monotonic time since boot; not a calendar date.</dd></dl>
    {incident && <><h3>Primary entities</h3><Entities value={item.primary_entities}/><h3>Correlation reason</h3><p>{item.description}</p><h3>Member Alert IDs ({item.alert_ids.length})</h3><ul className="member-list">{item.alert_ids.map(id => <li className="mono" key={id}>{id}</li>)}</ul></>}
    <details open><summary>{incident ? 'Correlation metadata' : 'Detection metadata'}</summary><pre>{pretty(item.metadata)}</pre></details>
    {kind === 'alerts' && <details><summary>Score explanation & source events</summary><pre>{pretty({ base_score: item.base_score, score_modifiers: item.score_modifiers, source_event_ids: item.source_event_ids })}</pre></details>}
    <details><summary>Complete persisted record</summary><pre>{pretty(item)}</pre></details></section>;
}
