import React from 'react';
import { useAuth } from '../../context/AuthContext.jsx';

export default function Navbar({ system, lastUpdated }) {
  const { user, logout } = useAuth();
  return (
    <div className="navbar">
      <div>
        <span className="statusdot" /> HONEYWATCH SOC &nbsp;|&nbsp; Honeypot {system?.honeypot || '...'} · Detection {system?.detectionEngine || '...'} · DB {system?.mongodb || '...'}
        {lastUpdated && <span style={{ marginLeft: 12, color: 'var(--muted)' }}>Last updated: {lastUpdated}</span>}
      </div>
      <div>{user?.name} ({user?.role}) <button className="btn ghost" onClick={logout}>Logout</button></div>
    </div>
  );
}
