import React, { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { usePolling } from '../hooks/usePolling.js';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import SeverityBadge from '../components/SeverityBadge/SeverityBadge.jsx';
import StatusBadge from '../components/StatusBadge/StatusBadge.jsx';
import { fmt } from '../utils/helpers.js';

export default function Incidents() {
  const [items, setItems] = useState([]);
  const load = useCallback(async () => {
    const { data } = await api.get('/incidents');
    setItems(data.items);
  }, []);
  usePolling(load, 5000);
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><h2>Incidents (Attack Campaigns)</h2>
      <div className="card"><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Risk</th><th>Status</th><th>Updated</th></tr></thead>
        <tbody>{items.map(i => <tr key={i._id}><td><Link to={`/incidents/${i.incidentId}`}>{i.incidentId}</Link></td><td>{i.title}</td><td><SeverityBadge value={i.severity} /></td><td>{i.riskScore}</td><td><StatusBadge value={i.status} /></td><td>{fmt(i.updatedAt)}</td></tr>)}</tbody></table>
        {!items.length && <div className="empty">No incidents yet. Trigger a brute-force simulation to create one.</div>}</div>
    </div></div></div>;
}
