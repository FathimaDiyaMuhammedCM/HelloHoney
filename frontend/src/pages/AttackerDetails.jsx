import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import { EventTable, AlertTable } from '../components/AlertTable/AlertTable.jsx';
import Timeline from '../components/Timeline/Timeline.jsx';

export default function AttackerDetails() {
  const { ip } = useParams();
  const [data, setData] = useState(null);
  useEffect(() => { api.get(`/attackers/${ip}`).then(r => setData(r.data)).catch(() => {}); }, [ip]);
  if (!data) return <div className="layout"><Sidebar /><div className="main"><Navbar /><div className="content">Loading…</div></div></div>;
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><Link to="/attackers">← Attackers</Link><h2>Attacker {data.attacker.sourceIP} (Risk {data.attacker.riskScore})</h2>
      <div className="card"><div className="kv"><b>Events</b><span>{data.attacker.totalEvents}</span><b>Failed logins</b><span>{data.attacker.failedLogins}</span><b>Services</b><span>{(data.attacker.services || []).join(', ')}</span><b>Highest severity</b><span>{data.attacker.highestSeverity}</span></div></div>
      <div className="card" style={{ marginTop: 12 }}><b>ATTACK TIMELINE</b><Timeline items={data.events.slice(0, 15).map(e => ({ message: `${e.eventType} via ${e.service}`, at: e.timestamp }))} /></div>
      <div className="card" style={{ marginTop: 12 }}><b>ALERTS</b><AlertTable items={data.alerts} /></div>
      <div className="card" style={{ marginTop: 12 }}><b>EVENTS</b><EventTable items={data.events} /></div>
    </div></div></div>;
}
