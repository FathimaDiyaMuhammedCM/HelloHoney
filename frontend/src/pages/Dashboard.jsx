import React, { useState, useCallback, useRef, useEffect } from 'react';
import api from '../services/api';
import { useRealtime } from '../hooks/useRealtime.js';
import StatCard from '../components/StatCard/StatCard.jsx';
import { EventTable } from '../components/AlertTable/AlertTable.jsx';
import { AttackChart, TimelineChart } from '../components/AttackChart/AttackChart.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import { fmt, riskLevel } from '../utils/helpers.js';

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [system, setSystem] = useState(null);
  const [lastUpdated, setLastUpdated] = useState('');
  const [live, setLive] = useState([]);
  const [uploading, setUploading] = useState(false);
  const fileRef = useRef(null);

  const load = useCallback(async () => {
    try {
      const [s, a, e, at, tl, sys] = await Promise.all([
        api.get('/analytics/summary'), api.get('/alerts?limit=8'),
        api.get('/events?limit=8'), api.get('/analytics/attacks'),
        api.get('/analytics/timeline?days=1'), api.get('/system/status')
      ]);
      setSummary(s.data); setAlerts(a.data.items); setEvents(e.data.items);
      setAttacks(at.data); setTimeline(tl.data); setSystem(sys.data);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (e) { console.warn(e.message); }
  }, []);

  useRealtime((kind, d) => {
    if (kind === 'event') {
      setEvents(prev => [d, ...prev].slice(0, 20));
      setLive(prev => [d, ...prev].slice(0, 30));
    } else if (kind === 'alert') {
      setAlerts(prev => [d, ...prev].slice(0, 15));
    } else if (kind === 'incident') {
      setSummary(s => s ? { ...s, openIncidents: s.openIncidents + 1 } : s);
    }
  }, true);

  useEffect(() => { load(); }, [load]);

  const handleUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const form = new FormData();
      form.append('file', file);
      const { data } = await api.post('/logs/upload', form);
      alert(`Success: ${data.eventsStored} events stored (${data.eventsParsed} parsed from ${data.uploaded})`);
      await load();
    } catch (err) {
      const msg = err.response?.data?.error || err.response?.data?.message || err.message;
      alert('Upload failed: ' + msg);
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  return (
    <div className="layout"><Sidebar /><div className="main"><Navbar system={system} lastUpdated={lastUpdated} />
      <div className="content">
        <h2>HONEYWATCH SOC — LIVE</h2>
        <div className="toolbar">
          <span style={{ fontSize: 12, color: 'var(--muted)' }}>UPLOAD LOGS (realtime):</span>
          <input type="file" accept=".log,.csv,.json,.txt,.pcap" ref={fileRef} onChange={handleUpload} style={{ display: 'none' }} />
          <button className="btn" onClick={() => fileRef.current?.click()}>
            {uploading ? 'Uploading…' : 'Upload Log File'}
          </button>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>Supports .log/.csv/.json/.txt (syslog, CSV, JSON)</span>
        </div>
        <div className="cards">
          <StatCard label="Total Events" value={summary?.totalEvents ?? '-'} />
          <StatCard label="Active Alerts" value={summary?.activeAlerts ?? '-'} />
          <StatCard label="High Severity" value={summary?.highSeverity ?? '-'} />
          <StatCard label="Open Incidents" value={summary?.openIncidents ?? '-'} />
          <StatCard label="Unique Attackers" value={summary?.uniqueAttackers ?? '-'} />
          <StatCard label="Events Today" value={summary?.eventsToday ?? '-'} />
        </div>
        <div className="grid2">
          <div className="card"><b>Events Over Time</b><TimelineChart data={timeline} /></div>
          <div className="card"><b>Attack Types</b><AttackChart data={attacks} /></div>
        </div>
        <div className="card" style={{ marginTop: 12 }}>
          <b>LIVE FEED ({live.length} events streamed)</b>
          {live.length === 0 && <div className="empty">Waiting for events… upload a log file or connect the honeypot.</div>}
          {live.length > 0 && <EventTable items={live.slice(0, 20)} />}
        </div>
        <div className="card" style={{ marginTop: 12 }}><b>LIVE ALERTS</b>
          {alerts.length === 0 && <div className="empty">No alerts yet.</div>}
          <EventTable items={alerts} /></div>
        <div className="card" style={{ marginTop: 12 }}><b>RECENT EVENTS</b><EventTable items={events} /></div>
      </div>
    </div></div>
  );
}
