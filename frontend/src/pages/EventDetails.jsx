import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import SeverityBadge from '../components/SeverityBadge/SeverityBadge.jsx';
import { EventTable } from '../components/AlertTable/AlertTable.jsx';
import Timeline from '../components/Timeline/Timeline.jsx';
import { fmt } from '../utils/helpers.js';

export default function EventDetails() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  useEffect(() => { api.get(`/events/${id}`).then(r => setData(r.data)).catch(() => {}); }, [id]);
  if (!data) return <div className="layout"><Sidebar /><div className="main"><Navbar /><div className="content">Loading…</div></div></div>;
  const e = data.event;
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><Link to="/events">← Events</Link><h2>Event Investigation: {e.eventId}</h2>
      <div className="card"><div className="kv">
        <b>Timestamp</b><span>{fmt(e.timestamp)}</span>
        <b>Source</b><span>{e.sourceIP}:{e.sourcePort}</span>
        <b>Destination</b><span>{e.destinationIP}:{e.destinationPort}</span>
        <b>Service / Proto</b><span>{e.service} / {e.protocol}</span>
        <b>Type</b><span>{e.eventType}</span>
        <b>Username</b><span>{e.username || '-'}</span>
        <b>Status</b><span>{e.status}</span>
        <b>Severity</b><span><SeverityBadge value={e.severity} /></span>
        <b>Session</b><span>{e.sessionId}</span>
        <b>Simulated</b><span>{e.simulated ? 'SIMULATED (lab)' : 'honeypot'}</span>
        <b>Metadata</b><span><pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(e.metadata, null, 2)}</pre></span>
      </div></div>
      <div className="card" style={{ marginTop: 12 }}><b>RELATED ACTIVITY (same IP)</b><EventTable items={data.related} /></div>
      <div className="card" style={{ marginTop: 12 }}><b>TIMELINE</b><Timeline items={(data.related || []).slice(0, 10).map(x => ({ message: `${x.eventType} via ${x.service}`, at: x.timestamp }))} /></div>
    </div></div></div>;
}
