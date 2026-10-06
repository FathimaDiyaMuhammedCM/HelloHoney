import React from 'react';
import { Link } from 'react-router-dom';
import SeverityBadge from '../SeverityBadge/SeverityBadge.jsx';
import StatusBadge from '../StatusBadge/StatusBadge.jsx';
import { fmt } from '../../utils/helpers.js';

export function EventTable({ items }) {
  if (!items?.length) return <div className="empty">No events found.</div>;
  return <table><thead><tr><th>Timestamp</th><th>Source IP</th><th>Service</th><th>Type</th><th>User</th><th>Severity</th><th>Status</th></tr></thead>
    <tbody>{items.map(e => <tr key={e._id || e.eventId}><td><Link to={`/events/${e.eventId}`}>{fmt(e.timestamp)}</Link></td><td>{e.sourceIP}</td><td>{e.service}</td><td>{e.eventType}{e.simulated ? ' (SIMULATED)' : ''}</td><td>{e.username || '-'}</td><td><SeverityBadge value={e.severity} /></td><td>{e.status}</td></tr>)}</tbody></table>;
}

export function AlertTable({ items, onStatus }) {
  if (!items?.length) return <div className="empty">No alerts. Honeypot is watching…</div>;
  return <table><thead><tr><th>Timestamp</th><th>Alert</th><th>Source IP</th><th>Attack</th><th>Severity</th><th>Risk</th><th>Status</th>{onStatus && <th>Action</th>}</tr></thead>
    <tbody>{items.map(a => <tr key={a._id || a.alertId}><td>{fmt(a.timestamp)}</td><td><Link to={`/alerts/${a.alertId}`}>{a.alertId}</Link></td><td>{a.sourceIP}</td><td>{a.attackType}</td><td><SeverityBadge value={a.severity} /></td><td>{a.riskScore}</td><td><StatusBadge value={a.status} /></td>{onStatus && <td><select value={a.status} onChange={e => onStatus(a, e.target.value)}><option>OPEN</option><option>INVESTIGATING</option><option>RESOLVED</option><option>FALSE_POSITIVE</option></select></td>}</tr>)}</tbody></table>;
}
