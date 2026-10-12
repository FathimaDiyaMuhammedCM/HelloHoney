import React, { useState, useCallback } from 'react';
import api from '../services/api';
import { usePolling } from '../hooks/usePolling.js';
import { EventTable } from '../components/AlertTable/AlertTable.jsx';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import UploadModal from '../components/UploadModal/UploadModal.jsx';

export default function Events() {
  const [items, setItems] = useState([]);
  const [showUpload, setShowUpload] = useState(false);
  const [f, setF] = useState({ q: '', service: '', severity: '', eventType: '', sourceIP: '' });
  const load = useCallback(async () => {
    const p = new URLSearchParams({ limit: 30, ...Object.fromEntries(Object.entries(f).filter(([, v]) => v)) });
    const { data } = await api.get(`/events?${p}`);
    setItems(data.items);
  }, [f]);
  usePolling(load, 5000);
  return (
    <div className="layout"><Sidebar /><div className="main"><Navbar onUploadSuccess={load} />
      <div className="content">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2>Events</h2>
          <button className="btn" onClick={() => setShowUpload(true)}>
            📥 Upload Log File
          </button>
        </div>
        <div className="toolbar">
          <input placeholder="Search IP / ID / user" value={f.q} onChange={e => setF({ ...f, q: e.target.value })} />
          <input placeholder="Source IP" value={f.sourceIP} onChange={e => setF({ ...f, sourceIP: e.target.value })} />
          <select value={f.service} onChange={e => setF({ ...f, service: e.target.value })}><option value="">All services</option><option>SSH</option><option>HTTP</option><option>TCP</option></select>
          <select value={f.severity} onChange={e => setF({ ...f, severity: e.target.value })}><option value="">All severity</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option><option>INFO</option></select>
          <select value={f.eventType} onChange={e => setF({ ...f, eventType: e.target.value })}><option value="">All types</option><option>CONNECTION</option><option>FAILED_LOGIN</option><option>TEST_LOGIN</option><option>PORT_PROBE</option><option>WEB_PROBE</option><option>SUSPICIOUS_REQUEST</option><option>DISCONNECT</option></select>
          <button className="btn" onClick={load}>Search</button>
        </div>
        <UploadModal
          isOpen={showUpload}
          onClose={() => setShowUpload(false)}
          onUploadSuccess={load}
        />
        <div className="card"><EventTable items={items} /></div>
      </div>
    </div></div>
  );
}
