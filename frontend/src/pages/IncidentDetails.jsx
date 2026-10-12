import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import Timeline from '../components/Timeline/Timeline.jsx';

export default function IncidentDetails() {
  const { id } = useParams();
  const [inc, setInc] = useState(null);
  const [note, setNote] = useState('');
  const load = () => api.get(`/incidents/${id}`).then(r => setInc(r.data)).catch(() => {});
  useEffect(load, [id]);
  if (!inc) return <div className="layout"><Sidebar /><div className="main"><Navbar /><div className="content">Loading…</div></div></div>;
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><Link to="/incidents">← Incidents</Link><h2>{inc.incidentId}: {inc.title}</h2>
      <div className="card"><div className="kv">
        <b>Severity / Risk</b><span>{inc.severity} / {inc.riskScore} (HelloHoney Risk Score)</span>
        <b>Status</b><span>{inc.status}</span>
        <b>Source IPs</b><span>{(inc.sourceIPs || []).join(', ')}</span>
        <b>Alerts</b><span>{(inc.relatedAlertIds || []).join(', ')}</span>
        <b>Assigned</b><span>{inc.assignedTo || '-'}</span>
        <b>Description</b><span>{inc.description}</span>
      </div>
        <div className="toolbar" style={{ marginTop: 10 }}>
          {['OPEN', 'INVESTIGATING', 'RESOLVED'].map(s => <button key={s} className="btn ghost" onClick={() => api.patch(`/incidents/${inc.incidentId}`, { status: s }).then(load)}>{s}</button>)}
          <input placeholder="Assign analyst" id="asg" /><button className="btn ghost" onClick={() => api.patch(`/incidents/${inc.incidentId}`, { assignedTo: document.getElementById('asg').value }).then(load)}>Assign</button>
        </div></div>
      <div className="card" style={{ marginTop: 12 }}><b>TIMELINE</b><Timeline items={inc.timeline} /></div>
      <div className="card" style={{ marginTop: 12 }}><b>NOTES</b>
        {(inc.notes || []).map((n, i) => <div key={i} style={{ fontSize: 13 }}>• {n.text} <span style={{ color: 'var(--muted)' }}>— {n.by}</span></div>)}
        <div className="toolbar" style={{ marginTop: 8 }}><input placeholder="Add investigation note" value={note} onChange={e => setNote(e.target.value)} /><button className="btn" onClick={() => api.post(`/incidents/${inc.incidentId}/notes`, { text: note }).then(() => { setNote(''); load(); })}>Add note</button></div>
      </div>
    </div></div></div>;
}
