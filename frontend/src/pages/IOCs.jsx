import React, { useEffect, useState } from 'react';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';

export default function IOCs() {
  const [items, setItems] = useState([]);
  const [form, setForm] = useState({ type: 'IP', value: '', description: '', severity: 'MEDIUM' });
  const load = () => api.get('/iocs').then(r => setItems(r.data)).catch(() => {});
  useEffect(load, []);
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><h2>IOCs (lab only)</h2>
      <div className="card"><table><thead><tr><th>Type</th><th>Value</th><th>Severity</th><th>Description</th><th>Action</th></tr></thead>
        <tbody>{items.map(i => <tr key={i._id}><td>{i.type}</td><td>{i.value}</td><td>{i.severity}</td><td>{i.description}</td><td><button className="btn danger" onClick={() => api.delete(`/iocs/${i._id}`).then(load)}>Delete</button></td></tr>)}</tbody></table></div>
      <div className="card" style={{ marginTop: 12 }}><div className="toolbar">
        <select value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}><option>IP</option><option>DOMAIN</option><option>URL</option><option>HASH</option><option>USERNAME</option></select>
        <input placeholder="Value" value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} />
        <input placeholder="Description" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
        <button className="btn" onClick={() => api.post('/iocs', form).then(() => { setForm({ ...form, value: '', description: '' }); load(); })}>Add IOC</button></div></div>
    </div></div></div>;
}
