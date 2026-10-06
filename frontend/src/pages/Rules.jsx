import React, { useEffect, useState } from 'react';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';

export default function Rules() {
  const [rules, setRules] = useState([]);
  const [form, setForm] = useState({ name: '', description: '', eventType: 'FAILED_LOGIN', threshold: 5, timeWindow: 60, severity: 'HIGH', ruleType: 'BRUTE_FORCE', attackType: '' });
  const load = () => api.get('/rules').then(r => setRules(r.data)).catch(() => {});
  useEffect(load, []);
  const save = async () => {
    await api.post('/rules', { ...form, enabled: true });
    setForm({ name: '', description: '', eventType: 'FAILED_LOGIN', threshold: 5, timeWindow: 60, severity: 'HIGH', ruleType: 'BRUTE_FORCE', attackType: '' });
    load();
  };
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><h2>Detection Rules</h2>
      <div className="card"><table><thead><tr><th>Rule</th><th>Threshold</th><th>Window</th><th>Severity</th><th>Enabled</th><th>Actions</th></tr></thead>
        <tbody>{rules.map(r => <tr key={r._id}><td>{r.name}<div style={{ color: 'var(--muted)', fontSize: 11 }}>{r.description}</div></td><td>{r.threshold}</td><td>{r.timeWindow}s</td><td>{r.severity}</td><td>{String(r.enabled)}</td>
          <td><button className="btn ghost" onClick={() => api.patch(`/rules/${r._id}`, { enabled: !r.enabled }).then(load)}>{r.enabled ? 'Disable' : 'Enable'}</button><button className="btn danger" onClick={() => api.delete(`/rules/${r._id}`).then(load)}>Delete</button></td></tr>)}</tbody></table></div>
      <div className="card" style={{ marginTop: 12 }}><b>Create rule</b>
        <div className="toolbar"><input placeholder="Name" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /><input placeholder="Attack type" value={form.attackType} onChange={e => setForm({ ...form, attackType: e.target.value })} />
          <input type="number" placeholder="Threshold" value={form.threshold} onChange={e => setForm({ ...form, threshold: +e.target.value })} /><input type="number" placeholder="Window(s)" value={form.timeWindow} onChange={e => setForm({ ...form, timeWindow: +e.target.value })} />
          <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select>
          <button className="btn" onClick={save}>Create</button></div></div>
    </div></div></div>;
}
