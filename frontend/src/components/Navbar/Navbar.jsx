import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import UploadModal from '../UploadModal/UploadModal.jsx';

export default function Navbar({ system, lastUpdated, onUploadSuccess }) {
  const { user, logout } = useAuth();
  const [showUpload, setShowUpload] = useState(false);

  return (
    <>
      <div className="navbar">
        <div>
          <span className="statusdot" /> HELLOHONEY SOC &nbsp;|&nbsp; Honeypot {system?.honeypot || '...'} · Detection {system?.detectionEngine || '...'} · DB {system?.mongodb || '...'}
          {lastUpdated && <span style={{ marginLeft: 12, color: 'var(--muted)' }}>Last updated: {lastUpdated}</span>}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            className="btn"
            style={{ fontSize: '0.8rem', padding: '5px 12px', background: 'var(--accent)', color: '#070c18' }}
            onClick={() => setShowUpload(true)}
          >
            📥 Upload Logs
          </button>
          <span>{user?.name} ({user?.role})</span>
          <button className="btn ghost" onClick={logout}>Logout</button>
        </div>
      </div>
      <UploadModal
        isOpen={showUpload}
        onClose={() => setShowUpload(false)}
        onUploadSuccess={() => {
          if (onUploadSuccess) onUploadSuccess();
        }}
      />
    </>
  );
}

