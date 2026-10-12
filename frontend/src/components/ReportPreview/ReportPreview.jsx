import React, { useState } from 'react';
import SeverityBadge from '../SeverityBadge/SeverityBadge.jsx';
import StatusBadge from '../StatusBadge/StatusBadge.jsx';

export default function ReportPreview({
  preview,
  loading,
  pdfLoading,
  pdfBlobUrl,
  onDownloadPdf,
  onLoadPdfPreview,
  onExportCsv,
  onRefresh
}) {
  const [activeTab, setActiveTab] = useState('summary'); // 'summary' | 'pdf' | 'records'
  const [recordsSubTab, setRecordsSubTab] = useState('alerts'); // 'alerts' | 'events' | 'incidents'

  if (loading) {
    return (
      <div className="report-preview-container">
        <div style={{ padding: '60px 24px', textAlign: 'center', color: 'var(--text-muted)' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: '14px', animation: 'spin 1.5s linear infinite' }}>⚙️</div>
          <h3 style={{ margin: '0 0 8px', color: 'var(--text)' }}>Compiling Report Preview…</h3>
          <p style={{ margin: 0, fontSize: '0.9rem' }}>Analyzing live MongoDB events, correlated incidents, and risk telemetry.</p>
        </div>
      </div>
    );
  }

  if (!preview) {
    return null;
  }

  const { meta, summary, attacksByType, topAttackers, recentAlerts, recentIncidents, rules, sampleEvents, recommendations } = preview;

  const handlePdfTabClick = () => {
    setActiveTab('pdf');
    if (!pdfBlobUrl && onLoadPdfPreview) {
      onLoadPdfPreview();
    }
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="report-preview-container printable-report">
      {/* Top Header & Actions */}
      <div className="report-preview-header no-print">
        <div className="report-preview-title">
          <span style={{ fontSize: '1.6rem' }}>📑</span>
          <div>
            <h3>Report Preview: {meta?.type || 'Security Summary'}</h3>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '4px', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              <span>ID: <code style={{ color: 'var(--accent)', fontWeight: 600 }}>{meta?.reportId}</code></span>
              <span>•</span>
              <span className="badge b-INFO" style={{ fontSize: '10px', padding: '2px 8px' }}>LIVE PREVIEW</span>
              <span>•</span>
              <span>Generated: {new Date(meta?.generatedAt).toLocaleTimeString()}</span>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            className="btn"
            onClick={onDownloadPdf}
            disabled={pdfLoading}
            title="Download formatted PDF report document"
          >
            {pdfLoading ? '⏳ Generating PDF…' : '📥 Download PDF'}
          </button>
          <button className="btn ghost" onClick={() => onExportCsv('events')} title="Download filtered raw events as CSV">
            📊 Events CSV
          </button>
          <button className="btn ghost" onClick={() => onExportCsv('alerts')} title="Download alerts as CSV">
            ⚠️ Alerts CSV
          </button>
          <button className="btn ghost" onClick={() => onExportCsv('incidents')} title="Download incidents as CSV">
            🚨 Incidents CSV
          </button>
          <button className="btn ghost" onClick={handlePrint} title="Print report or save to system print dialog">
            🖨️ Print
          </button>
          <button className="btn ghost" onClick={onRefresh} title="Refresh live preview with updated database events">
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="report-preview-tabs no-print">
        <button
          className={`report-tab-btn ${activeTab === 'summary' ? 'active' : ''}`}
          onClick={() => setActiveTab('summary')}
        >
          📊 Executive Summary & Analysis
        </button>
        <button
          className={`report-tab-btn ${activeTab === 'pdf' ? 'active' : ''}`}
          onClick={handlePdfTabClick}
        >
          📄 PDF Document View {pdfLoading && '⏳'}
        </button>
        <button
          className={`report-tab-btn ${activeTab === 'records' ? 'active' : ''}`}
          onClick={() => setActiveTab('records')}
        >
          📋 Raw Data Records ({recentAlerts?.length || 0} Alerts, {sampleEvents?.length || 0} Events)
        </button>
      </div>

      {/* Tab 1: Executive Summary */}
      {activeTab === 'summary' && (
        <div className="report-preview-body">
          {/* Metadata Box */}
          <div className="report-meta-box">
            <div className="report-meta-item">
              <span className="report-meta-label">Report ID</span>
              <span className="report-meta-val" style={{ color: 'var(--accent)' }}>{meta?.reportId}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Observation Period</span>
              <span className="report-meta-val">{meta?.period?.from} → {meta?.period?.to}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Operator / Issuer</span>
              <span className="report-meta-val">{meta?.generatedBy}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Filter Severity</span>
              <span className="report-meta-val">{meta?.filters?.severity || 'ALL SEVERITIES'}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Classification</span>
              <span className="report-meta-val" style={{ color: 'var(--accent-pink)' }}>SOC DEFENSIVE LAB</span>
            </div>
          </div>

          {/* Metric Cards */}
          <div className="report-stat-grid">
            <div className="report-stat-card">
              <span className="r-label">Sampled Events</span>
              <span className="r-val">{summary?.totalEvents ?? 0}</span>
            </div>
            <div className="report-stat-card">
              <span className="r-label">Triggered Alerts</span>
              <span className="r-val" style={{ color: 'var(--accent-pink-bright)' }}>{summary?.totalAlerts ?? 0}</span>
            </div>
            <div className="report-stat-card">
              <span className="r-label">Correlated Incidents</span>
              <span className="r-val">{summary?.totalIncidents ?? 0}</span>
            </div>
            <div className="report-stat-card">
              <span className="r-label">Tracked Attackers</span>
              <span className="r-val">{summary?.trackedAttackers ?? 0}</span>
            </div>
            <div className="report-stat-card">
              <span className="r-label">HelloHoney Risk Score</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="r-val">{summary?.avgRisk ?? 0}</span>
                <span className={`badge b-${summary?.riskLevel || 'LOW'}`}>{summary?.riskLevel || 'LOW'}</span>
              </div>
            </div>
          </div>

          {/* Attack Types Distribution */}
          <div className="report-section">
            <div className="report-section-title">
              <span>🎯 Attack Vectors & Technique Distribution</span>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{attacksByType?.length || 0} Techniques Observed</span>
            </div>
            {(!attacksByType || attacksByType.length === 0) ? (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No alerts or attack vectors recorded within the selected filters.</p>
            ) : (
              <div className="attack-bar-list">
                {attacksByType.map(item => (
                  <div key={item.attackType} className="attack-bar-row">
                    <div className="attack-bar-meta">
                      <span><code>{item.attackType}</code></span>
                      <span>
                        <b style={{ color: 'var(--accent)' }}>{item.count}</b> alerts ({item.percentage}%)
                      </span>
                    </div>
                    <div className="attack-bar-track">
                      <div className="attack-bar-fill" style={{ width: `${Math.max(item.percentage, 4)}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Top Source IPs / Threat Actors */}
          <div className="report-section">
            <div className="report-section-title">
              <span>🏴‍☠️ Top Offending Source IPs & Risk Profiles</span>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Prioritized by HelloHoney Risk Score</span>
            </div>
            {(!topAttackers || topAttackers.length === 0) ? (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No attacker telemetry recorded.</p>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Source IP</th>
                      <th>Total Events</th>
                      <th>Risk Score</th>
                      <th>Threat Level</th>
                      <th>Observed Attack Vectors</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topAttackers.map(a => (
                      <tr key={a.sourceIP}>
                        <td><code style={{ color: 'var(--accent-green-bright)' }}>{a.sourceIP}</code></td>
                        <td>{a.totalEvents}</td>
                        <td><b>{a.riskScore}</b> / 100</td>
                        <td><span className={`badge b-${a.riskLevel}`}>{a.riskLevel}</span></td>
                        <td>
                          {a.attackTypes && a.attackTypes.length > 0
                            ? a.attackTypes.map(t => <span key={t} className="badge b-INFO" style={{ marginRight: 4, fontSize: '10px' }}>{t}</span>)
                            : <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Standard probe</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Alert Highlights */}
          <div className="report-section">
            <div className="report-section-title">
              <span>🚨 Alert Highlights Sample (Latest {recentAlerts?.length || 0})</span>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Included in PDF Export</span>
            </div>
            {(!recentAlerts || recentAlerts.length === 0) ? (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No alerts triggered in this time window.</p>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Attack Type</th>
                      <th>Source IP</th>
                      <th>Status</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentAlerts.slice(0, 10).map((alert, idx) => (
                      <tr key={alert.id || idx}>
                        <td><SeverityBadge value={alert.severity} /></td>
                        <td><b>{alert.attackType}</b></td>
                        <td><code>{alert.sourceIP}</code></td>
                        <td><StatusBadge value={alert.status} /></td>
                        <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {new Date(alert.timestamp).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Incident Highlights */}
          {recentIncidents && recentIncidents.length > 0 && (
            <div className="report-section">
              <div className="report-section-title">
                <span>🛡️ Correlated SOC Incidents</span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{recentIncidents.length} Registered</span>
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Incident ID</th>
                      <th>Title</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentIncidents.map(inc => (
                      <tr key={inc.incidentId}>
                        <td><code style={{ color: 'var(--accent)' }}>{inc.incidentId}</code></td>
                        <td><b>{inc.title}</b></td>
                        <td><SeverityBadge value={inc.severity} /></td>
                        <td><StatusBadge value={inc.status} /></td>
                        <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {new Date(inc.createdAt).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Active Detection Rules */}
          {rules && rules.length > 0 && (
            <div className="report-section">
              <div className="report-section-title">
                <span>⚙️ Active HelloHoney Detection Rules</span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{rules.length} Evaluated Rules</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '10px' }}>
                {rules.map(r => (
                  <div key={r.name} style={{ background: 'rgba(19, 34, 68, 0.4)', border: '1px solid var(--border)', borderRadius: '8px', padding: '10px 14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <b style={{ fontSize: '13px', color: 'var(--text)' }}>{r.name}</b>
                      <span className={`badge ${r.enabled ? 'b-LOW' : 'b-INFO'}`} style={{ fontSize: '10px' }}>
                        {r.enabled ? 'ACTIVE' : 'DISABLED'}
                      </span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Threshold: <b>{r.threshold}</b> events / <b>{r.timeWindow}s</b> window
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations & Risk Assessment */}
          <div className="report-section">
            <div className="report-section-title">
              <span>🛡️ HelloHoney Risk Assessment & Hardening Recommendations</span>
            </div>
            <div className="report-recommendations">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <span style={{ fontSize: '1.2rem' }}>💡</span>
                <b style={{ color: 'var(--accent-green-bright)', fontSize: '13.5px' }}>
                  Actionable SOC Advisory (HelloHoney Risk Baseline: {summary?.avgRisk ?? 0}/100 - {summary?.riskLevel || 'LOW'})
                </b>
              </div>
              <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-muted)' }}>
                Scale: 0-20 LOW, 21-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL. Based on real-time Honeypot correlation and repeat offender tracking:
              </p>
              <ul>
                {recommendations?.map((rec, i) => (
                  <li key={i}>{rec}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Privacy & Compliance Disclaimer */}
          <div style={{ padding: '12px 16px', background: 'rgba(13, 23, 46, 0.6)', border: '1px dashed var(--border)', borderRadius: '8px', fontSize: '12px', color: 'var(--text-muted)' }}>
            🔒 <b>Privacy & Lab Security Guarantee:</b> This report summarizes honeypot-observed defensive activity. Real credentials are never collected or stored. Passwords are permanently sanitized from all event stores and export files.
          </div>
        </div>
      )}

      {/* Tab 2: Rendered PDF Document Viewer */}
      {activeTab === 'pdf' && (
        <div className="report-preview-body">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
            <div>
              <b style={{ fontSize: '14px', color: 'var(--text)' }}>Exact PDF Document Layout</b>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Rendered using PDFKit backend generation engine. Zoom, inspect, or save directly.
              </div>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button className="btn" onClick={onDownloadPdf} disabled={pdfLoading}>
                {pdfLoading ? 'Generating…' : '📥 Download This PDF'}
              </button>
              {pdfBlobUrl && (
                <button
                  className="btn ghost"
                  onClick={() => window.open(pdfBlobUrl, '_blank')}
                  title="Open PDF viewer in new browser tab"
                >
                  ↗️ Open in New Tab
                </button>
              )}
            </div>
          </div>

          {pdfLoading ? (
            <div style={{ padding: '80px 24px', textAlign: 'center', background: 'rgba(13, 23, 46, 0.4)', borderRadius: '10px', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '2rem', marginBottom: '10px' }}>⏳</div>
              <h4>Rendering PDF Document Preview…</h4>
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Compiling PDFKit vector layout and typography.</p>
            </div>
          ) : pdfBlobUrl ? (
            <div style={{ borderRadius: '10px', overflow: 'hidden', border: '1px solid var(--border)', background: '#1e293b' }}>
              <iframe
                src={pdfBlobUrl}
                title="PDF Document Preview"
                style={{ width: '100%', height: '700px', border: 'none', display: 'block', background: '#ffffff' }}
              />
            </div>
          ) : (
            <div style={{ padding: '60px 24px', textAlign: 'center', background: 'rgba(13, 23, 46, 0.4)', borderRadius: '10px', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '12px' }}>📄</div>
              <h4>Ready to render PDF document preview</h4>
              <p style={{ color: 'var(--text-muted)', fontSize: '13px', maxWidth: '420px', margin: '0 auto 16px' }}>
                Click below to generate the exact binary PDF document and preview it directly inside the browser.
              </p>
              <button className="btn" onClick={onLoadPdfPreview}>
                ⚡ Load PDF Document Preview
              </button>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Raw Data Records Preview */}
      {activeTab === 'records' && (
        <div className="report-preview-body">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                className={`btn ${recordsSubTab === 'alerts' ? '' : 'ghost'}`}
                style={{ padding: '6px 12px', fontSize: '12px' }}
                onClick={() => setRecordsSubTab('alerts')}
              >
                Alerts ({recentAlerts?.length || 0})
              </button>
              <button
                className={`btn ${recordsSubTab === 'events' ? '' : 'ghost'}`}
                style={{ padding: '6px 12px', fontSize: '12px' }}
                onClick={() => setRecordsSubTab('events')}
              >
                Events ({sampleEvents?.length || 0})
              </button>
              <button
                className={`btn ${recordsSubTab === 'incidents' ? '' : 'ghost'}`}
                style={{ padding: '6px 12px', fontSize: '12px' }}
                onClick={() => setRecordsSubTab('incidents')}
              >
                Incidents ({recentIncidents?.length || 0})
              </button>
            </div>
            <div>
              <button className="btn ghost" onClick={() => onExportCsv(recordsSubTab)}>
                📥 Download {recordsSubTab.toUpperCase()} as CSV
              </button>
            </div>
          </div>

          {recordsSubTab === 'alerts' && (
            <div style={{ overflowX: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Alert ID</th>
                    <th>Severity</th>
                    <th>Attack Type</th>
                    <th>Source IP</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts?.map(a => (
                    <tr key={a.id}>
                      <td><code style={{ fontSize: '11px' }}>{a.id}</code></td>
                      <td><SeverityBadge value={a.severity} /></td>
                      <td><b>{a.attackType}</b></td>
                      <td><code>{a.sourceIP}</code></td>
                      <td><StatusBadge value={a.status} /></td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{new Date(a.timestamp).toLocaleString()}</td>
                    </tr>
                  ))}
                  {(!recentAlerts || recentAlerts.length === 0) && (
                    <tr><td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>No alert records found.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {recordsSubTab === 'events' && (
            <div style={{ overflowX: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Event ID</th>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Service</th>
                    <th>Event Type</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {sampleEvents?.map(e => (
                    <tr key={e._id}>
                      <td><code style={{ fontSize: '11px' }}>{e._id}</code></td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{new Date(e.timestamp).toLocaleString()}</td>
                      <td><code>{e.sourceIP}</code></td>
                      <td><b>{e.service}</b></td>
                      <td><code>{e.eventType}</code></td>
                      <td><SeverityBadge value={e.severity} /></td>
                    </tr>
                  ))}
                  {(!sampleEvents || sampleEvents.length === 0) && (
                    <tr><td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>No event records found.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {recordsSubTab === 'incidents' && (
            <div style={{ overflowX: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Incident ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Created At</th>
                  </tr>
                </thead>
                <tbody>
                  {recentIncidents?.map(i => (
                    <tr key={i.incidentId}>
                      <td><code style={{ color: 'var(--accent)' }}>{i.incidentId}</code></td>
                      <td><b>{i.title}</b></td>
                      <td><SeverityBadge value={i.severity} /></td>
                      <td><StatusBadge value={i.status} /></td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{new Date(i.createdAt).toLocaleString()}</td>
                    </tr>
                  ))}
                  {(!recentIncidents || recentIncidents.length === 0) && (
                    <tr><td colSpan="5" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>No incident records found.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Bottom Footer Action Bar */}
      <div className="report-preview-footer no-print">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-muted)' }}>
          <span>✅</span>
          <span><b>Preview verified.</b> Ready to export report in your preferred format.</span>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button className="btn" onClick={onDownloadPdf} disabled={pdfLoading}>
            {pdfLoading ? '⏳ Generating…' : '📥 Download PDF'}
          </button>
          <button className="btn ghost" onClick={() => onExportCsv('events')}>
            Events CSV
          </button>
          <button className="btn ghost" onClick={() => onExportCsv('alerts')}>
            Alerts CSV
          </button>
          <button className="btn ghost" onClick={() => onExportCsv('incidents')}>
            Incidents CSV
          </button>
        </div>
      </div>
    </div>
  );
}
