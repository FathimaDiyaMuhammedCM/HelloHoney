import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Events from './pages/Events.jsx';
import EventDetails from './pages/EventDetails.jsx';
import Alerts from './pages/Alerts.jsx';
import AlertDetails from './pages/AlertDetails.jsx';
import Incidents from './pages/Incidents.jsx';
import IncidentDetails from './pages/IncidentDetails.jsx';
import Attackers from './pages/Attackers.jsx';
import AttackerDetails from './pages/AttackerDetails.jsx';
import Analytics from './pages/Analytics.jsx';
import Rules from './pages/Rules.jsx';
import Reports from './pages/Reports.jsx';
import IOCs from './pages/IOCs.jsx';
import AuditLogs from './pages/AuditLogs.jsx';
import Settings from './pages/Settings.jsx';
import Login, { NotFound } from './pages/Login.jsx';

function Guard({ children, roles }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" />;
  if (roles && !roles.includes(user.role)) return <div className="content">403 — Forbidden for role {user.role}</div>;
  return children;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Guard><Dashboard /></Guard>} />
        <Route path="/events" element={<Guard><Events /></Guard>} />
        <Route path="/events/:id" element={<Guard><EventDetails /></Guard>} />
        <Route path="/alerts" element={<Guard><Alerts /></Guard>} />
        <Route path="/alerts/:id" element={<Guard><AlertDetails /></Guard>} />
        <Route path="/incidents" element={<Guard roles={['ADMIN', 'ANALYST']}><Incidents /></Guard>} />
        <Route path="/incidents/:id" element={<Guard roles={['ADMIN', 'ANALYST']}><IncidentDetails /></Guard>} />
        <Route path="/attackers" element={<Guard><Attackers /></Guard>} />
        <Route path="/attackers/:ip" element={<Guard><AttackerDetails /></Guard>} />
        <Route path="/analytics" element={<Guard><Analytics /></Guard>} />
        <Route path="/rules" element={<Guard roles={['ADMIN', 'ANALYST']}><Rules /></Guard>} />
        <Route path="/iocs" element={<Guard roles={['ADMIN', 'ANALYST']}><IOCs /></Guard>} />
        <Route path="/reports" element={<Guard roles={['ADMIN', 'ANALYST']}><Reports /></Guard>} />
        <Route path="/audit-logs" element={<Guard roles={['ADMIN', 'ANALYST']}><AuditLogs /></Guard>} />
        <Route path="/settings" element={<Guard><Settings /></Guard>} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  );
}
