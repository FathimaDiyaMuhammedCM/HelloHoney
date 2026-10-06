import React, { useState } from 'react';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';

export default function Reports() {
  const [f, setF] = useState({ type: 'Security Summary', from: '2026-09-01', to: '2026-09-22', severity: '' });
  const pdf = async () => {
    const res = await api.post('/reports/pdf', f, { responseType: 'blob' });
    const url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
    const a = document.createElement('a'); a.href = url; a.download = 'hellohoney-report.pdf'; a.click();
  };
  const csv = (kind) => { window.open(`/api/reports/${kind}/csv`, '_blank'); };
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><h2>Reports</h2>
      <div className="card"><div className="toolbar">
        <select value={f.type} onChange={e => setF({ ...f, type: e.target.value })}><option>Security Summary</option><option>Event Report</option><option>Alert Report</option><option>Incident Report</option><option>Attack Activity Report</option></select>
        <input type="date" value={f.from} onChange={e => setF({ ...f, from: e.target.value })} />
        <input type="date" value={f.to} onChange={e => setF({ ...f, to: e.target.value })} />
        <select value={f.severity} onChange={e => setF({ ...f, severity: e.target.value })}><option value="">All severity</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
        <button className="btn" onClick={pdf}>Generate PDF</button>
        <button className="btn ghost" onClick={() => csv('events')}>Events CSV</button>
        <button className="btn ghost" onClick={() => csv('alerts')}>Alerts CSV</button>
        <button className="btn ghost" onClick={() => csv('incidents')}>Incidents CSV</button>
      </div><p style={{ color: 'var(--muted)', fontSize: 12 }}>PDF uses live MongoDB data. Passwords are never included.</p></div>
    </div></div></div>;
}
