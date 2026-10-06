import React, { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { usePolling } from '../hooks/usePolling.js';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import { fmt } from '../utils/helpers.js';

export default function Attackers() {
  const [items, setItems] = useState([]);
  const load = useCallback(async () => {
    const { data } = await api.get('/attackers');
    setItems(data.items);
  }, []);
  usePolling(load, 5000);
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><h2>Attackers (by Source IP)</h2>
      <div className="card"><table><thead><tr><th>IP</th><th>Events</th><th>Alerts</th><th>Incidents</th><th>First seen</th><th>Last seen</th><th>Severity</th><th>Risk</th></tr></thead>
        <tbody>{items.map(a => <tr key={a._id}><td><Link to={`/attackers/${a.sourceIP}`}>{a.sourceIP}</Link></td><td>{a.totalEvents}</td><td>{a.alerts}</td><td>{a.incidents}</td><td>{fmt(a.firstSeen)}</td><td>{fmt(a.lastSeen)}</td><td>{a.highestSeverity}</td><td>{a.riskScore}</td></tr>)}</tbody></table>
        {!items.length && <div className="empty">No attackers observed yet.</div>}</div>
    </div></div></div>;
}
