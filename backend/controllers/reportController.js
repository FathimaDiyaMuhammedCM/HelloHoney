const PDFDocument = require('pdfkit');
const { Parser } = require('json2csv');
const Event = require('../models/Event');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const Attacker = require('../models/Attacker');
const DetectionRule = require('../models/DetectionRule');
const Report = require('../models/Report');
const { uid } = require('../utils/ids');
const audit = require('../utils/audit');
const path = require('path');
const fs = require('fs');

function buildFilter(query) {
  const f = {};
  // Only accept primitive strings (blocks NoSQL operator objects in filters)
  if (typeof query.severity === 'string' && query.severity) f.severity = query.severity;
  if (typeof query.sourceIP === 'string' && query.sourceIP) f.sourceIP = query.sourceIP;
  if (typeof query.service === 'string' && query.service) f.service = query.service;
  if ((typeof query.from === 'string' && query.from) || (typeof query.to === 'string' && query.to)) {
    const ts = {};
    if (typeof query.from === 'string' && query.from) ts.$gte = new Date(query.from);
    if (typeof query.to === 'string' && query.to) ts.$lte = new Date(query.to);
    f.timestamp = ts;
  }
  return f;
}

async function previewReport(req, res, next) {
  try {
    const { type = 'Security Summary', from, to, severity, sourceIP, service } = req.body || req.query || {};
    const ef = buildFilter({ from, to, severity, sourceIP, service });
    const af = buildFilter({ from, to, severity, sourceIP });
    const [events, alerts, incidents, attackers, rules] = await Promise.all([
      Event.find(ef).sort('-timestamp').limit(200).lean(),
      Alert.find(af).sort('-timestamp').limit(200).lean(),
      Incident.find().sort('-createdAt').limit(50).lean(),
      Attacker.find().sort('-riskScore').limit(10).lean(),
      DetectionRule.find().lean()
    ]);

    const reportId = uid('RPT');
    const byType = {};
    alerts.forEach(a => { byType[a.attackType] = (byType[a.attackType] || 0) + 1; });
    const totalAlertsCount = alerts.length;
    const attacksByType = Object.entries(byType).map(([attackType, count]) => ({
      attackType,
      count,
      percentage: totalAlertsCount ? Math.round((count / totalAlertsCount) * 100) : 0
    }));

    const avgRisk = attackers.length ? Math.round(attackers.reduce((s, a) => s + a.riskScore, 0) / attackers.length) : 0;
    let riskLevel = 'LOW';
    if (avgRisk > 75) riskLevel = 'CRITICAL';
    else if (avgRisk > 50) riskLevel = 'HIGH';
    else if (avgRisk > 20) riskLevel = 'MEDIUM';

    const recommendations = [
      'Block repeat offender IPs at the lab firewall.',
      'Rotate exposed test credentials and enforce key-based SSH authentication.',
      'Review brute-force alerts promptly and calibrate rule rate thresholds.',
      'Keep honeypot sensors logically isolated on a dedicated subnet.'
    ];

    res.json({
      meta: {
        reportId,
        type,
        generatedAt: new Date().toISOString(),
        generatedBy: req.user?.name || 'SOC Operator',
        period: { from: from || 'Beginning of time', to: to || 'Present' },
        filters: { type, from, to, severity, sourceIP, service }
      },
      summary: {
        totalEvents: events.length,
        totalAlerts: alerts.length,
        totalIncidents: incidents.length,
        trackedAttackers: attackers.length,
        avgRisk,
        riskLevel
      },
      attacksByType,
      topAttackers: attackers.map(a => ({
        sourceIP: a.sourceIP,
        totalEvents: a.totalEvents,
        riskScore: a.riskScore,
        riskLevel: a.riskLevel || (a.riskScore > 75 ? 'CRITICAL' : a.riskScore > 50 ? 'HIGH' : a.riskScore > 20 ? 'MEDIUM' : 'LOW'),
        attackTypes: a.attackTypes || []
      })),
      recentAlerts: alerts.slice(0, 20).map(a => ({
        id: a._id,
        severity: a.severity,
        attackType: a.attackType,
        sourceIP: a.sourceIP,
        status: a.status,
        timestamp: a.timestamp
      })),
      recentIncidents: incidents.slice(0, 10).map(i => ({
        incidentId: i.incidentId,
        title: i.title,
        severity: i.severity,
        status: i.status,
        createdAt: i.createdAt
      })),
      rules: rules.map(r => ({
        name: r.name,
        category: r.category,
        threshold: r.threshold,
        timeWindow: r.timeWindow,
        enabled: r.enabled
      })),
      sampleEvents: events.slice(0, 20).map(e => ({
        _id: e._id,
        timestamp: e.timestamp,
        sourceIP: e.sourceIP,
        service: e.service,
        eventType: e.eventType,
        severity: e.severity
      })),
      recommendations
    });
  } catch (e) {
    next(e);
  }
}

async function pdfReport(req, res, next) {
  try {
    const { type = 'Security Summary', from, to, severity, sourceIP, service } = req.body || {};
    const ef = buildFilter({ from, to, severity, sourceIP, service });
    const af = buildFilter({ from, to, severity, sourceIP });
    const [events, alerts, incidents, attackers, rules] = await Promise.all([
      Event.find(ef).sort('-timestamp').limit(200).lean(),
      Alert.find(af).sort('-timestamp').limit(200).lean(),
      Incident.find().sort('-createdAt').limit(50).lean(),
      Attacker.find().sort('-riskScore').limit(10).lean(),
      DetectionRule.find().lean()
    ]);
    const reportId = uid('RPT');
    const dir = path.join(__dirname, '..', '..', 'reports');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const filePath = path.join(dir, `${reportId}.pdf`);
    const doc = new PDFDocument({ margin: 40 });
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);
    doc.fontSize(20).text('HELLOHONEY SECURITY REPORT', { align: 'center' });
    doc.moveDown();
    doc.fontSize(10).text(`Report ID: ${reportId}`);
    doc.text(`Generated: ${new Date().toISOString()}`);
    doc.text(`Period: ${from || 'beginning'} to ${to || 'now'}`);
    doc.text(`Type: ${type}`);
    doc.moveDown();
    doc.fontSize(14).text('EXECUTIVE SUMMARY');
    doc.fontSize(10).text(`Total Events: ${events.length} (sampled)`);
    doc.text(`Total Alerts: ${alerts.length} (sampled)`);
    doc.text(`Total Incidents: ${incidents.length}`);
    doc.text(`Top Attackers tracked: ${attackers.length}`);
    doc.moveDown();
    doc.fontSize(14).text('ATTACK SUMMARY');
    doc.fontSize(10);
    const byType = {};
    alerts.forEach(a => { byType[a.attackType] = (byType[a.attackType] || 0) + 1; });
    Object.entries(byType).forEach(([k, v]) => doc.text(`- ${k}: ${v}`));
    if (!Object.keys(byType).length) doc.text('No alerts in selected filters.');
    doc.moveDown();
    doc.fontSize(14).text('TOP SOURCE IPs');
    doc.fontSize(10);
    attackers.slice(0, 10).forEach(a => doc.text(`- ${a.sourceIP}: ${a.totalEvents} events, risk ${a.riskScore}`));
    doc.moveDown();
    doc.fontSize(14).text('ALERT SUMMARY (latest)');
    doc.fontSize(10);
    alerts.slice(0, 20).forEach(a => doc.text(`- [${a.severity}] ${a.attackType} from ${a.sourceIP} (${a.status})`));
    doc.moveDown();
    doc.fontSize(14).text('INCIDENT SUMMARY');
    doc.fontSize(10);
    incidents.slice(0, 10).forEach(i => doc.text(`- ${i.incidentId}: ${i.title} [${i.status}]`));
    doc.moveDown();
    doc.fontSize(14).text('DETECTION RULES');
    doc.fontSize(10);
    rules.forEach(r => doc.text(`- ${r.name}: threshold ${r.threshold}/${r.timeWindow}s [${r.enabled ? 'enabled' : 'disabled'}]`));
    doc.moveDown();
    doc.fontSize(14).text('RISK ANALYSIS (HelloHoney Risk Score, project-defined 0-100)');
    doc.fontSize(10).text('0-20 LOW, 21-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL.');
    const avg = attackers.length ? Math.round(attackers.reduce((s, a) => s + a.riskScore, 0) / attackers.length) : 0;
    doc.text(`Average attacker risk: ${avg}`);
    doc.moveDown();
    doc.fontSize(14).text('RECOMMENDATIONS');
    doc.fontSize(10).text('- Block repeat offender IPs at the lab firewall; rotate test credentials; review brute-force alerts promptly; keep honeypot isolated from production.');
    doc.moveDown();
    doc.fontSize(14).text('CONCLUSION');
    doc.fontSize(10).text('This lab report summarizes honeypot-observed activity. No real credentials were collected; passwords are never stored.');
    doc.end();
    await new Promise(r => stream.on('finish', r));
    await Report.create({ reportId, type, format: 'PDF', generatedBy: req.user?.name || 'system', filters: req.body, filePath });
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'REPORT_GENERATE', resource: 'Report', resourceId: reportId, sourceIP: req.ip });
    res.download(filePath);
  } catch (e) { next(e); }
}

function csvExport(kind) {
  return async (req, res, next) => {
    try {
      let rows = [];
      if (kind === 'events') rows = await Event.find(buildFilter(req.query)).limit(1000).lean();
      if (kind === 'alerts') rows = await Alert.find(buildFilter(req.query)).limit(1000).lean();
      if (kind === 'incidents') rows = await Incident.find().limit(1000).lean();
      // strip sensitive fields
      rows = rows.map(({ passwordEcho, __v, ...r }) => r);
      const parser = new Parser();
      const csv = rows.length ? parser.parse(rows) : 'no data';
      res.header('Content-Type', 'text/csv');
      res.attachment(`${kind}.csv`);
      res.send(csv);
    } catch (e) { next(e); }
  };
}

module.exports = { previewReport, pdfReport, csvExport };
