import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.jsx';

const LINKS = [
  ['/', 'Dashboard', ['ADMIN', 'ANALYST', 'VIEWER']],
  ['/events', 'Events', ['ADMIN', 'ANALYST', 'VIEWER']],
  ['/alerts', 'Alerts', ['ADMIN', 'ANALYST', 'VIEWER']],
  ['/incidents', 'Incidents', ['ADMIN', 'ANALYST']],
  ['/attackers', 'Attackers', ['ADMIN', 'ANALYST', 'VIEWER']],
  ['/analytics', 'Analytics', ['ADMIN', 'ANALYST', 'VIEWER']],
  ['/rules', 'Rules', ['ADMIN', 'ANALYST']],
  ['/iocs', 'IOCs', ['ADMIN', 'ANALYST']],
  ['/reports', 'Reports', ['ADMIN', 'ANALYST']],
  ['/audit-logs', 'Audit Logs', ['ADMIN', 'ANALYST']],
  ['/settings', 'Settings', ['ADMIN', 'ANALYST', 'VIEWER']],
];

export default function Sidebar() {
  const { user } = useAuth();
  return (
    <div className="sidebar">
      <h2>🛡️ HONEYWATCH</h2>
      <span className="lab">LAB / SIMULATION</span>
      <nav>
        {LINKS.filter(([, , roles]) => roles.includes(user?.role)).map(([to, label]) => (
          <NavLink key={to} to={to} className={({ isActive }) => (isActive ? 'active' : '')}>{label}</NavLink>
        ))}
      </nav>
    </div>
  );
}
