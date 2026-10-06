import React, { useState, useCallback } from 'react';
import api from '../services/api';
import { usePolling } from '../hooks/usePolling.js';
import { AlertTable } from '../components/AlertTable/AlertTable.jsx';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';

export default function Alerts() {
  const [items, setItems] = useState([]);
  const [f, setF] = useState({ severity: '', status: '', sourceIP: '' });
  const load = useCallback(async () => {
    const p = new URLSearchParams({ limit: 30, ...Object.fromEntries(Object.entries(f).filter(([, v]) => v)) });
    const { data } = await api.get(`/alerts?${p}`);
    setItems(data.items);
  }, [f]);
  usePolling(load, 5000);
  const onStatus = async (a, status) => {
    await api.patch(`/alerts/${a.alertId}/status`, { status });
    load();
  };
  const makeIncident = async (a) => {
    await api.post('/incidents', { title: `Investigate ${a.attackType} from ${a.sourceIP}`, severity: a.severity, sourceIPs: [a.sourceIP], relatedAlertIds: [a.alertId], relatedEventIds: a.relatedEventIds });
    alert('Incident created');
  };
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><h2>Alerts</h2>
      <div className="toolbar">
        <select value={f.severity} onChange={e => setF({ ...f, severity: e.target.value })}><option value="">All severity</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select>
        <select value={f.status} onChange={e => setF({ ...f, status: e.target.value })}><option value="">All status</option><option>OPEN</option><option>INVESTIGATING</option><option>RESOLVED</option><option>FALSE_POSITIVE</option></select>
        <input placeholder="Source IP" value={f.sourceIP} onChange={e => setF({ ...f, sourceIP: e.target.value })} />
        <button className="btn" onClick={load}>Filter</button>
      </div>
      <div className="card"><AlertTable items={items} onStatus={onStatus} /></div>
      <div className="card" style={{ marginTop: 12 }}><b>Create incident from alert</b>
        {items.slice(0, 5).map(a => <div key={a.alertId} style={{ fontSize: 13 }}>{a.alertId} <button className="btn ghost" onClick={() => makeIncident(a)}>Create incident</button></div>)}
      </div>
    </div></div></div>;
}
