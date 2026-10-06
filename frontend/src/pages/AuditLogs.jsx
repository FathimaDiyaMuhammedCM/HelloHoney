import React, { useEffect, useState } from 'react';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import { fmt } from '../utils/helpers.js';

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  useEffect(() => { api.get('/audit-logs').then(r => setLogs(r.data)).catch(() => {}); }, []);
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><h2>Audit Logs</h2>
      <div className="card"><table><thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Resource</th><th>Details</th><th>IP</th></tr></thead>
        <tbody>{logs.map((l, i) => <tr key={i}><td>{fmt(l.timestamp)}</td><td>{l.userName}</td><td>{l.action}</td><td>{l.resource}</td><td>{l.details}</td><td>{l.sourceIP}</td></tr>)}</tbody></table></div>
    </div></div></div>;
}
