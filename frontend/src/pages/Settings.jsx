import React, { useEffect, useState } from 'react';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';

export default function Settings() {
  const [s, setS] = useState(null);
  useEffect(() => { api.get('/system/status').then(r => setS(r.data)).catch(() => {}); }, []);
  return <div className="layout"><Sidebar /><div className="main"><Navbar system={s} />
    <div className="content"><h2>Settings & System Health</h2>
      <div className="card"><div className="kv">
        <b>API</b><span>{s?.api}</span><b>MongoDB</b><span>{s?.mongodb}</span>
        <b>Honeypot</b><span>{s?.honeypot}</span><b>Detection</b><span>{s?.detectionEngine}</span>
        <b>SSH port</b><span>{s?.sshPort}</span><b>HTTP port</b><span>{s?.httpPort}</span>
        <b>Simulation</b><span>{String(s?.simulationMode)}</span><b>Last event</b><span>{s?.lastEventAt || '-'}</span>
        <b>Events</b><span>{s?.eventsProcessed}</span><b>Alerts</b><span>{s?.alertsGenerated}</span>
      </div></div>
    </div></div></div>;
}
