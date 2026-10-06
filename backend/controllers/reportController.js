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
  if (query.severity) f.severity = query.severity;
  if (query.sourceIP) f.sourceIP = query.sourceIP;
  if (query.service) f.service = query.service;
  if (query.from || query.to) f.timestamp = { ...(query.from ? { $gte: new Date(query.from) } : {}), ...(query.to ? { $lte: new Date(query.to) } : {}) };
  return f;
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
    doc.fontSize(14).text('RISK ANALYSIS (HoneyWatch Risk Score, project-defined 0-100)');
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

module.exports = { pdfReport, csvExport };
