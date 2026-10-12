import React, { useState, useCallback, useRef, useEffect } from 'react';
import api from '../services/api';
import { useRealtime } from '../hooks/useRealtime.js';
import StatCard from '../components/StatCard/StatCard.jsx';
import { EventTable, AlertTable } from '../components/AlertTable/AlertTable.jsx';
import { AttackChart, TimelineChart } from '../components/AttackChart/AttackChart.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import { fmt, riskLevel } from '../utils/helpers.js';

import UploadModal from '../components/UploadModal/UploadModal.jsx';

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [system, setSystem] = useState(null);
  const [lastUpdated, setLastUpdated] = useState('');
  const [live, setLive] = useState([]);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploadToast, setUploadToast] = useState(null);

  const load = useCallback(async () => {
    const results = await Promise.allSettled([
      api.get('/analytics/summary'), api.get('/alerts?limit=8'),
      api.get('/events?limit=8'), api.get('/analytics/attacks'),
      api.get('/analytics/timeline?days=1'), api.get('/system/status')
    ]);
    const [s, a, e, at, tl, sys] = results;
    const val = (r, fallback) => (r.status === 'fulfilled' ? r.value.data : fallback);
    const evs = (val(e, { items: [] }) || {}).items || [];
    setSummary(val(s, null));
    setAlerts((val(a, { items: [] }) || {}).items || []);
    setEvents(evs);
    // Populate the live feed with recent activity on load; the realtime
    // subscription below prepends newly streamed events.
    setLive((prev) => {
      const seen = new Set(prev.map(x => x._id || x.eventId));
      const merged = prev.concat(evs.filter(x => !seen.has(x._id || x.eventId)));
      return merged.slice(0, 30);
    });
    setAttacks(val(at, []));
    setTimeline(val(tl, []));
    setSystem(val(sys, null));
    setLastUpdated(new Date().toLocaleTimeString());
    const failed = results.filter(r => r.status === 'rejected').length;
    if (failed) console.warn(`${failed} dashboard request(s) failed`);
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

  const handleUploadSuccess = () => {
    load();
    setUploadToast('Log events imported successfully!');
    setTimeout(() => setUploadToast(null), 5000);
  };

  return (
    <div className="layout"><Sidebar /><div className="main"><Navbar system={system} lastUpdated={lastUpdated} onUploadSuccess={handleUploadSuccess} />
      <div className="content">
        <h2>HELLOHONEY SOC — LIVE</h2>
        {uploadToast && (
          <div className="upload-banner success" style={{ marginBottom: 12 }}>
            ✅ {uploadToast}
          </div>
        )}
        <div className="toolbar">
          <span style={{ fontSize: 12, color: 'var(--muted)' }}>UPLOAD LOGS (realtime):</span>
          <button className="btn" onClick={() => setShowUploadModal(true)}>
            📥 Upload Log File
          </button>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>Supports .log, .csv, .json, .txt, .pcap (Syslog, JSON, CSV, Web, PCAP)</span>
        </div>
        <UploadModal
          isOpen={showUploadModal}
          onClose={() => setShowUploadModal(false)}
          onUploadSuccess={handleUploadSuccess}
        />
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
          <b>LIVE FEED ({live.length} events)</b>
          {live.length === 0 && <div className="empty">Waiting for events… upload a log file or connect the honeypot.</div>}
          {live.length > 0 && <EventTable items={live.slice(0, 20)} />}
        </div>
        <div className="card" style={{ marginTop: 12 }}><b>LIVE ALERTS</b>
          <AlertTable items={alerts} /></div>
        <div className="card" style={{ marginTop: 12 }}><b>RECENT EVENTS</b><EventTable items={events} /></div>
      </div>
    </div></div>
  );
}
