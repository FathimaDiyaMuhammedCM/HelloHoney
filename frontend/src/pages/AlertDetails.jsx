import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import SeverityBadge from '../components/SeverityBadge/SeverityBadge.jsx';
import StatusBadge from '../components/StatusBadge/StatusBadge.jsx';
import { EventTable } from '../components/AlertTable/AlertTable.jsx';
import { fmt } from '../utils/helpers.js';

export default function AlertDetails() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const load = () => api.get(`/alerts/${id}`).then(r => setData(r.data)).catch(() => {});
  useEffect(load, [id]);
  if (!data) return <div className="layout"><Sidebar /><div className="main"><Navbar /><div className="content">Loading…</div></div></div>;
  const a = data.alert;
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><Link to="/alerts">← Alerts</Link><h2>Alert {a.alertId}</h2>
      <div className="card"><div className="kv">
        <b>Attack</b><span>{a.attackType}</span>
        <b>Source IP</b><span><Link to={`/attackers/${a.sourceIP}`}>{a.sourceIP}</Link></span>
        <b>Severity</b><span><SeverityBadge value={a.severity} /></span>
        <b>Status</b><span><StatusBadge value={a.status} /></span>
        <b>Risk</b><span>{a.riskScore}</span>
        <b>Rule</b><span>{a.ruleName}</span>
        <b>Time</b><span>{fmt(a.timestamp)}</span>
        <b>Description</b><span>{a.description}</span>
      </div>
        <div className="toolbar" style={{ marginTop: 10 }}>
          {['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map(s => <button key={s} className="btn ghost" onClick={() => api.patch(`/alerts/${a.alertId}/status`, { status: s }).then(load)}>{s}</button>)}
        </div>
      </div>
      <div className="card" style={{ marginTop: 12 }}><b>LINKED EVENTS</b><EventTable items={data.events} /></div>
    </div></div></div>;
}
