import React, { useState, useRef } from 'react';
import api from '../../services/api';

const SAMPLES = {
  syslog: {
    name: 'sample_auth.log',
    content: `Sep 28 10:15:32 honeypot sshd[1234]: Failed password for root from 192.168.1.50 port 44322 ssh2
Sep 28 10:15:34 honeypot sshd[1235]: Failed password for root from 192.168.1.50 port 44324 ssh2
Sep 28 10:15:36 honeypot sshd[1236]: Failed password for admin from 192.168.1.50 port 44326 ssh2
Sep 28 10:15:38 honeypot sshd[1237]: Failed password for test from 192.168.1.50 port 44328 ssh2
Sep 28 10:15:40 honeypot sshd[1238]: Failed password for user from 192.168.1.50 port 44330 ssh2
Sep 28 10:15:42 honeypot sshd[1239]: Failed password for guest from 192.168.1.50 port 44332 ssh2
Sep 28 10:16:00 honeypot sshd[1240]: Accepted password for admin from 10.0.0.5 port 22 ssh2`
  },
  csv: {
    name: 'sample_events.csv',
    content: `Timestamp,Source_IP,Source_Port,Destination_Port,Service,Protocol,Event_Type,Username,Status,Severity
2026-09-28T10:30:00Z,192.0.2.45,51230,22,SSH,TCP,FAILED_LOGIN,root,failed,MEDIUM
2026-09-28T10:30:02Z,192.0.2.45,51232,22,SSH,TCP,FAILED_LOGIN,admin,failed,MEDIUM
2026-09-28T10:30:04Z,192.0.2.45,51234,22,SSH,TCP,FAILED_LOGIN,ubuntu,failed,MEDIUM
2026-09-28T10:30:10Z,192.0.2.45,51240,80,HTTP,TCP,WEB_PROBE,,probed,HIGH
2026-09-28T10:30:15Z,192.0.2.70,55100,22,SSH,TCP,CONNECTION,,connected,INFO`
  },
  json: {
    name: 'sample_events.json',
    content: JSON.stringify([
      {
        timestamp: "2026-09-28T10:20:00.000Z",
        sourceIP: "198.51.100.99",
        sourcePort: 49120,
        destinationPort: 22,
        service: "SSH",
        protocol: "TCP",
        eventType: "FAILED_LOGIN",
        username: "root",
        status: "failed",
        severity: "MEDIUM"
      },
      {
        timestamp: "2026-09-28T10:20:05.000Z",
        sourceIP: "198.51.100.99",
        sourcePort: 49122,
        destinationPort: 22,
        service: "SSH",
        protocol: "TCP",
        eventType: "FAILED_LOGIN",
        username: "admin",
        status: "failed",
        severity: "MEDIUM"
      },
      {
        timestamp: "2026-09-28T10:21:00.000Z",
        sourceIP: "198.51.100.99",
        sourcePort: 50110,
        destinationPort: 80,
        service: "HTTP",
        protocol: "TCP",
        eventType: "WEB_PROBE",
        status: "probed",
        severity: "HIGH",
        metadata: { path: "/.env" }
      }
    ], null, 2)
  }
};

export default function UploadModal({ isOpen, onClose, onUploadSuccess }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [statusMsg, setStatusMsg] = useState(null);
  const [isError, setIsError] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef(null);

  if (!isOpen) return null;

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    else if (e.type === 'dragleave') setDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setStatusMsg(null);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setStatusMsg(null);
    }
  };

  const uploadBlob = async (blob, filename) => {
    setUploading(true);
    setStatusMsg(null);
    setIsError(false);
    try {
      const form = new FormData();
      form.append('file', blob, filename);

      const res = await api.post('/logs/upload', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 60000
      });

      const { eventsStored, eventsParsed, uploaded } = res.data;
      setIsError(false);
      setStatusMsg(`Successfully uploaded ${uploaded}! Stored ${eventsStored} events into the SOC database.`);
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      if (onUploadSuccess) onUploadSuccess();
    } catch (err) {
      setIsError(true);
      const msg = err.response?.data?.error || err.response?.data?.message || err.message;
      setStatusMsg('Upload failed: ' + msg);
    } finally {
      setUploading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!file) {
      setIsError(true);
      setStatusMsg('Please select or drop a log file first.');
      return;
    }
    uploadBlob(file, file.name);
  };

  const handleLoadSample = (sampleKey) => {
    const s = SAMPLES[sampleKey];
    if (!s) return;
    const blob = new Blob([s.content], { type: 'text/plain;charset=utf-8' });
    uploadBlob(blob, s.name);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-container" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <h3 style={{ margin: 0, fontSize: '1.25rem', color: 'var(--text)' }}>
              📥 Upload Security Logs
            </h3>
            <p style={{ margin: '4px 0 0 0', fontSize: '0.85rem', color: 'var(--muted)' }}>
              Supports Syslog (.log, .txt), CSV, JSON / NDJSON, Web access logs & PCAP.
            </p>
          </div>
          <button className="btn ghost" onClick={onClose} style={{ padding: '4px 10px' }}>✕</button>
        </div>

        <form onSubmit={handleSubmit} style={{ marginTop: '16px' }}>
          <div
            className={`dropzone ${dragActive ? 'active' : ''} ${file ? 'has-file' : ''}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.csv,.json,.txt,.pcap,.log.gz"
              style={{ display: 'none' }}
              onClick={(e) => { e.target.value = null; }}
              onChange={handleFileSelect}
            />
            <div style={{ fontSize: '2rem', marginBottom: '8px' }}>
              {file ? '📄' : '☁️'}
            </div>
            {file ? (
              <div>
                <b style={{ color: 'var(--accent)' }}>{file.name}</b>
                <div style={{ fontSize: '0.8rem', color: 'var(--muted)', marginTop: '4px' }}>
                  {(file.size / 1024).toFixed(1)} KB — Click or drop another to replace
                </div>
              </div>
            ) : (
              <div>
                <b>Drag & drop your log file here</b>
                <div style={{ fontSize: '0.82rem', color: 'var(--muted)', marginTop: '6px' }}>
                  or <span style={{ color: 'var(--accent)', textDecoration: 'underline' }}>browse from your computer</span>
                </div>
              </div>
            )}
          </div>

          {statusMsg && (
            <div
              className={`upload-banner ${isError ? 'error' : 'success'}`}
              style={{ marginTop: '14px' }}
            >
              <span>{isError ? '⚠️' : '✅'} {statusMsg}</span>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '18px' }}>
            <button type="button" className="btn ghost" onClick={onClose}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn"
              disabled={uploading || !file}
              style={{ minWidth: '130px' }}
            >
              {uploading ? 'Processing…' : 'Upload Log'}
            </button>
          </div>
        </form>

        <div style={{ marginTop: '22px', paddingTop: '16px', borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px' }}>
            ⚡ Quick Test with Built-in Sample Logs:
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn ghost"
              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
              onClick={() => handleLoadSample('syslog')}
              disabled={uploading}
            >
              📄 Syslog (Auth/SSH)
            </button>
            <button
              type="button"
              className="btn ghost"
              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
              onClick={() => handleLoadSample('csv')}
              disabled={uploading}
            >
              📊 CSV (Probes & Scans)
            </button>
            <button
              type="button"
              className="btn ghost"
              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
              onClick={() => handleLoadSample('json')}
              disabled={uploading}
            >
              📦 JSON (Security Events)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
