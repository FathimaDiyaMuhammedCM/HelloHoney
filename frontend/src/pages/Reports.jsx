import React, { useState, useEffect, useRef } from 'react';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import ReportPreview from '../components/ReportPreview/ReportPreview.jsx';

export default function Reports() {
  const defaultFrom = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
  const defaultTo = new Date().toISOString().slice(0, 10);

  const [f, setF] = useState({
    type: 'Security Summary',
    from: defaultFrom,
    to: defaultTo,
    severity: ''
  });

  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [pdfBlobUrl, setPdfBlobUrl] = useState(null);
  const [toast, setToast] = useState(null);

  const activePdfUrlRef = useRef(null);

  const showToast = (msg, isError = false) => {
    setToast({ msg, isError });
    setTimeout(() => setToast(null), 4000);
  };

  // Fetch report preview data
  const fetchPreview = async (filters = f) => {
    setLoading(true);
    try {
      const res = await api.post('/reports/preview', filters);
      setPreview(res.data);
      // Invalidate existing PDF blob url when filters change
      if (activePdfUrlRef.current) {
        URL.revokeObjectURL(activePdfUrlRef.current);
        activePdfUrlRef.current = null;
        setPdfBlobUrl(null);
      }
    } catch (err) {
      console.error('Failed to load report preview:', err);
      showToast('Failed to load report preview: ' + (err.response?.data?.message || err.message), true);
    } finally {
      setLoading(false);
    }
  };

  // Fetch live PDF document blob for inline document preview
  const loadPdfBlob = async () => {
    if (activePdfUrlRef.current) return activePdfUrlRef.current;
    setPdfLoading(true);
    try {
      const res = await api.post('/reports/pdf', f, { responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      activePdfUrlRef.current = url;
      setPdfBlobUrl(url);
      return url;
    } catch (err) {
      console.error('Failed to generate PDF for preview:', err);
      showToast('Failed to generate PDF document: ' + (err.response?.data?.message || err.message), true);
      return null;
    } finally {
      setPdfLoading(false);
    }
  };

  // Download PDF file
  const downloadPdf = async () => {
    setPdfLoading(true);
    try {
      let url = activePdfUrlRef.current;
      if (!url) {
        const res = await api.post('/reports/pdf', f, { responseType: 'blob' });
        url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
        activePdfUrlRef.current = url;
        setPdfBlobUrl(url);
      }
      const safeTypeName = (f.type || 'security-summary').toLowerCase().replace(/\s+/g, '-');
      const filename = `hellohoney-${safeTypeName}-${new Date().toISOString().slice(0, 10)}.pdf`;
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      showToast(`Downloaded ${filename}`);
    } catch (err) {
      console.error('Failed to download PDF:', err);
      showToast('Error downloading PDF: ' + (err.response?.data?.message || err.message), true);
    } finally {
      setPdfLoading(false);
    }
  };

  // CSV Export with filters
  const csv = (kind) => {
    const q = new URLSearchParams();
    if (f.from) q.set('from', f.from);
    if (f.to) q.set('to', f.to);
    if (f.severity) q.set('severity', f.severity);
    const queryString = q.toString() ? `?${q.toString()}` : '';
    window.open(`/api/reports/${kind}/csv${queryString}`, '_blank');
    showToast(`Exported ${kind}.csv`);
  };

  // Fetch initial preview on mount
  useEffect(() => {
    fetchPreview();
    return () => {
      if (activePdfUrlRef.current) {
        URL.revokeObjectURL(activePdfUrlRef.current);
      }
    };
  }, []);

  const handleFilterSubmit = (e) => {
    e.preventDefault();
    fetchPreview(f);
  };

  const handleQuickPreset = (days) => {
    const newFrom = days > 0 ? new Date(Date.now() - days * 86400000).toISOString().slice(0, 10) : '';
    const newTo = new Date().toISOString().slice(0, 10);
    const updated = { ...f, from: newFrom, to: newTo };
    setF(updated);
    fetchPreview(updated);
  };

  return (
    <div className="layout">
      <Sidebar />
      <div className="main">
        <Navbar />
        <div className="content">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h2 style={{ margin: 0 }}>SOC Security Reports & Analytics</h2>
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: 'var(--text-muted)' }}>
                Inspect, preview, and export high-assurance PDF and CSV security summaries generated from honeypot activity.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                className="btn"
                onClick={downloadPdf}
                disabled={pdfLoading}
                title="Download current report directly"
              >
                {pdfLoading ? '⏳ Generating…' : '📥 Download PDF'}
              </button>
            </div>
          </div>

          {toast && (
            <div className={`upload-banner ${toast.isError ? 'error' : 'success'}`} style={{ marginBottom: '16px' }}>
              {toast.isError ? '❌ ' : '✅ '} {toast.msg}
            </div>
          )}

          {/* Filter Configuration Card */}
          <div className="card no-print">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
              <b style={{ fontSize: '13.5px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text)' }}>
                🛠️ Report Parameters & Scope
              </b>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  type="button"
                  className="btn ghost"
                  style={{ padding: '4px 10px', fontSize: '11px' }}
                  onClick={() => handleQuickPreset(7)}
                >
                  Last 7 Days
                </button>
                <button
                  type="button"
                  className="btn ghost"
                  style={{ padding: '4px 10px', fontSize: '11px' }}
                  onClick={() => handleQuickPreset(30)}
                >
                  Last 30 Days
                </button>
                <button
                  type="button"
                  className="btn ghost"
                  style={{ padding: '4px 10px', fontSize: '11px' }}
                  onClick={() => handleQuickPreset(0)}
                >
                  All Time
                </button>
              </div>
            </div>

            <form onSubmit={handleFilterSubmit}>
              <div className="toolbar" style={{ flexWrap: 'wrap', gap: '10px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>REPORT TYPE</label>
                  <select
                    value={f.type}
                    onChange={e => setF({ ...f, type: e.target.value })}
                    style={{ minWidth: '180px' }}
                  >
                    <option>Security Summary</option>
                    <option>Event Report</option>
                    <option>Alert Report</option>
                    <option>Incident Report</option>
                    <option>Attack Activity Report</option>
                  </select>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>FROM DATE</label>
                  <input
                    type="date"
                    value={f.from}
                    onChange={e => setF({ ...f, from: e.target.value })}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>TO DATE</label>
                  <input
                    type="date"
                    value={f.to}
                    onChange={e => setF({ ...f, to: e.target.value })}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>SEVERITY</label>
                  <select
                    value={f.severity}
                    onChange={e => setF({ ...f, severity: e.target.value })}
                  >
                    <option value="">All Severities</option>
                    <option>HIGH</option>
                    <option>MEDIUM</option>
                    <option>LOW</option>
                  </select>
                </div>

                <div style={{ display: 'flex', alignItems: 'flex-end', gap: '8px', marginLeft: 'auto' }}>
                  <button type="submit" className="btn" disabled={loading}>
                    {loading ? 'Updating…' : '👁️ Preview Report'}
                  </button>
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={downloadPdf}
                    disabled={pdfLoading}
                  >
                    {pdfLoading ? 'Generating…' : '📥 Download PDF'}
                  </button>
                </div>
              </div>
            </form>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-light)', fontSize: '12px', color: 'var(--text-muted)', flexWrap: 'wrap', gap: '8px' }}>
              <span>🔒 Live MongoDB dataset. Credential strings and passwords are excluded.</span>
              <div style={{ display: 'flex', gap: '6px' }}>
                <span style={{ alignSelf: 'center', marginRight: '4px' }}>Quick Raw CSV:</span>
                <button className="btn ghost" style={{ padding: '3px 8px', fontSize: '11px' }} onClick={() => csv('events')}>Events</button>
                <button className="btn ghost" style={{ padding: '3px 8px', fontSize: '11px' }} onClick={() => csv('alerts')}>Alerts</button>
                <button className="btn ghost" style={{ padding: '3px 8px', fontSize: '11px' }} onClick={() => csv('incidents')}>Incidents</button>
              </div>
            </div>
          </div>

          {/* Interactive Report Preview Component */}
          <ReportPreview
            preview={preview}
            loading={loading}
            pdfLoading={pdfLoading}
            pdfBlobUrl={pdfBlobUrl}
            onDownloadPdf={downloadPdf}
            onLoadPdfPreview={loadPdfBlob}
            onExportCsv={csv}
            onRefresh={() => fetchPreview(f)}
          />
        </div>
      </div>
    </div>
  );
}
