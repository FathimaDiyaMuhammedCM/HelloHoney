const Event = require('../models/Event');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const DetectionRule = require('../models/DetectionRule');
const Attacker = require('../models/Attacker');
const { nextId } = require('../utils/ids');
const { computeAttackerRisk } = require('../utils/risk');

const SEV_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4, INFO: 0 };

let ioRef = null;
function setIO(io) { ioRef = io; }
function emit(evt, data) { try { if (ioRef) ioRef.emit(evt, data); } catch (e) {} }

async function ensureDefaultRules() {
  const count = await DetectionRule.countDocuments();
  if (count > 0) return;
  await DetectionRule.insertMany([
    { name: 'SSH Brute Force', description: 'More than 5 failed SSH logins from same IP within 60s', eventType: 'FAILED_LOGIN', threshold: 5, timeWindow: 60, severity: 'HIGH', enabled: true, ruleType: 'BRUTE_FORCE', attackType: 'SSH Brute Force', autoCreateIncident: true },
    { name: 'Port Scan', description: 'Connections/Port probes to 3+ distinct ports within 60s', eventType: 'PORT_PROBE', threshold: 3, timeWindow: 60, severity: 'MEDIUM', enabled: true, ruleType: 'PORT_SCAN', attackType: 'Port Scan', autoCreateIncident: false },
    { name: 'Web Reconnaissance', description: '3+ suspicious HTTP path probes within 120s', eventType: 'WEB_PROBE', threshold: 3, timeWindow: 120, severity: 'MEDIUM', enabled: true, ruleType: 'WEB_RECON', attackType: 'Web Reconnaissance', autoCreateIncident: false },
    { name: 'Rapid Connections', description: '10+ connections from same IP within 30s', eventType: 'CONNECTION', threshold: 10, timeWindow: 30, severity: 'MEDIUM', enabled: true, ruleType: 'RAPID_CONN', attackType: 'Repeated Connection Activity', autoCreateIncident: false },
    { name: 'Multi-Stage Attack', description: 'Port probe + SSH connection + failed logins from same IP within 10 min', eventType: 'FAILED_LOGIN', threshold: 3, timeWindow: 600, severity: 'HIGH', enabled: true, ruleType: 'MULTI_STAGE', attackType: 'Multi-Stage Attack', autoCreateIncident: true }
  ]);
  console.log('[DETECTION] Default rules seeded');
}

async function updateAttacker(ev) {
  const ip = ev.sourceIP;
  // Atomic upsert: avoids E11000 duplicate-key races when events arrive concurrently
  await Attacker.updateOne({ sourceIP: ip }, {
    $setOnInsert: { firstSeen: ev.timestamp || new Date() },
    $inc: { totalEvents: 1, failedLogins: ev.eventType === 'FAILED_LOGIN' ? 1 : 0 },
    $set: { lastSeen: ev.timestamp || new Date() },
    $addToSet: { services: ev.service }
  }, { upsert: true });
  const a = await Attacker.findOne({ sourceIP: ip });
  if ((SEV_RANK[ev.severity] || 0) > (SEV_RANK[a.highestSeverity] || 0)) a.highestSeverity = ev.severity;
  // recompute risk
  const portProbes = await Event.countDocuments({ sourceIP: ip, eventType: 'PORT_PROBE' });
  const webProbes = await Event.countDocuments({ sourceIP: ip, eventType: { $in: ['WEB_PROBE', 'SUSPICIOUS_REQUEST'] } });
  const attackTypes = await Alert.distinct('attackType', { sourceIP: ip }).then(r => r.length).catch(() => 0);
  const highAlerts = await Alert.countDocuments({ sourceIP: ip, severity: { $in: ['HIGH', 'CRITICAL'] } });
  a.riskScore = computeAttackerRisk({ failedLogins: a.failedLogins, portProbes, webProbes, attackTypes, highAlerts, repeated: a.totalEvents > 20 ? 1 : 0 });
  await a.save();
  return a;
}

async function recentEvents(ip, eventTypes, windowSec) {
  const since = new Date(Date.now() - windowSec * 1000);
  return Event.find({ sourceIP: ip, eventType: { $in: eventTypes }, timestamp: { $gte: since } }).sort({ timestamp: -1 }).lean();
}

async function maybeCreateAlert({ rule, sourceIP, events, description, severity, confidence = 85 }) {
  // dedupe: skip if an OPEN alert for same rule+IP created in last timeWindow
  const since = new Date(Date.now() - (rule.timeWindow || 60) * 1000);
  const dup = await Alert.findOne({ sourceIP, ruleName: rule.name, createdAt: { $gte: since } });
  if (dup) return dup;
  const alertId = await nextId(Alert, 'alertId', 'ALT');
  const alert = await Alert.create({
    alertId, timestamp: new Date(), sourceIP,
    attackType: rule.attackType || rule.name,
    severity: severity || rule.severity || 'MEDIUM',
    description, ruleId: rule._id, ruleName: rule.name,
    relatedEventIds: events.map(e => e.eventId || String(e._id)),
    confidence,
    status: 'OPEN',
    riskScore: Math.min(100, 30 + events.length * 5 + (severity === 'HIGH' || rule.severity === 'HIGH' ? 20 : 0))
  });
  await Attacker.updateOne({ sourceIP }, { $inc: { alerts: 1 } });
  emit('new_alert', alert);
  if (rule.autoCreateIncident) await correlateToIncident(alert, events);
  return alert;
}

async function correlateToIncident(alert, events) {
  // Find open incident for same IP updated recently, else create
  let inc = await Incident.findOne({ sourceIPs: alert.sourceIP, status: { $in: ['OPEN', 'INVESTIGATING'] } }).sort({ updatedAt: -1 });
  if (!inc) {
    const incidentId = await nextId(Incident, 'incidentId', 'INC');
    inc = await Incident.create({
      incidentId,
      title: `Possible ${alert.attackType} from ${alert.sourceIP}`,
      description: `Correlated campaign: ${alert.description}`,
      severity: alert.severity,
      status: 'OPEN',
      sourceIPs: [alert.sourceIP],
      relatedAlertIds: [alert.alertId],
      relatedEventIds: alert.relatedEventIds,
      riskScore: alert.riskScore,
      timeline: [{ message: `First suspicious activity from ${alert.sourceIP}`, }, { message: `${alert.attackType} alert (${alert.alertId})` }]
    });
    await Attacker.updateOne({ sourceIP: alert.sourceIP }, { $inc: { incidents: 1 } });
    emit('incident_update', inc);
  } else {
    if (!inc.relatedAlertIds.includes(alert.alertId)) inc.relatedAlertIds.push(alert.alertId);
    for (const eid of alert.relatedEventIds) if (!inc.relatedEventIds.includes(eid)) inc.relatedEventIds.push(eid);
    inc.riskScore = Math.min(100, inc.riskScore + 10);
    inc.timeline.push({ message: `${alert.attackType} alert (${alert.alertId}) linked` });
    await inc.save();
    emit('incident_update', inc);
  }
  return inc;
}

async function evaluateEvent(ev) {
  const rules = await DetectionRule.find({ enabled: true });
  const ip = ev.sourceIP;
  for (const rule of rules) {
    try {
      if (rule.ruleType === 'BRUTE_FORCE') {
        if (ev.eventType !== 'FAILED_LOGIN' && ev.eventType !== 'TEST_LOGIN') continue;
        const evs = await recentEvents(ip, ['FAILED_LOGIN', 'TEST_LOGIN'], rule.timeWindow);
        if (evs.length >= rule.threshold) {
          await maybeCreateAlert({ rule, sourceIP: ip, events: evs.slice(0, 20), description: `${evs.length} failed SSH logins from ${ip} within ${rule.timeWindow}s (possible SSH brute force)` });
        }
      } else if (rule.ruleType === 'PORT_SCAN') {
        if (!['PORT_PROBE', 'CONNECTION'].includes(ev.eventType)) continue;
        const since = new Date(Date.now() - rule.timeWindow * 1000);
        const evs = await Event.find({ sourceIP: ip, timestamp: { $gte: since }, eventType: { $in: ['PORT_PROBE', 'CONNECTION'] } }).lean();
        const ports = new Set(evs.map(e => e.destinationPort));
        if (ports.size >= rule.threshold || evs.length >= rule.threshold * 2) {
          await maybeCreateAlert({ rule, sourceIP: ip, events: evs.slice(0, 20), description: `Port scanning: ${ports.size} distinct ports touched by ${ip} within ${rule.timeWindow}s` });
        }
      } else if (rule.ruleType === 'WEB_RECON') {
        if (!['WEB_PROBE', 'SUSPICIOUS_REQUEST'].includes(ev.eventType)) continue;
        const evs = await recentEvents(ip, ['WEB_PROBE', 'SUSPICIOUS_REQUEST'], rule.timeWindow);
        if (evs.length >= rule.threshold) {
          await maybeCreateAlert({ rule, sourceIP: ip, events: evs.slice(0, 20), description: `${evs.length} suspicious HTTP probes from ${ip} within ${rule.timeWindow}s (web reconnaissance)` });
        }
      } else if (rule.ruleType === 'RAPID_CONN') {
        if (ev.eventType !== 'CONNECTION') continue;
        const evs = await recentEvents(ip, ['CONNECTION'], rule.timeWindow);
        if (evs.length >= rule.threshold) {
          await maybeCreateAlert({ rule, sourceIP: ip, events: evs.slice(0, 20), description: `Rapid connections: ${evs.length} connections from ${ip} within ${rule.timeWindow}s`, severity: 'MEDIUM', confidence: 70 });
        }
      } else if (rule.ruleType === 'MULTI_STAGE') {
        const evs = await Event.find({ sourceIP: ip, timestamp: { $gte: new Date(Date.now() - rule.timeWindow * 1000) } }).lean();
        const types = new Set(evs.map(e => e.eventType));
        const hasProbe = types.has('PORT_PROBE') || types.has('CONNECTION');
        const fails = evs.filter(e => e.eventType === 'FAILED_LOGIN' || e.eventType === 'TEST_LOGIN').length;
        if (hasProbe && fails >= rule.threshold) {
          await maybeCreateAlert({ rule, sourceIP: ip, events: evs.slice(0, 20), description: `Multi-stage activity from ${ip}: probe + SSH + ${fails} failed logins within ${rule.timeWindow}s`, confidence: 90 });
        }
      }
    } catch (e) {
      console.warn('[DETECTION] rule eval failed:', rule.name, e.message);
    }
  }
}

async function processEvent(ev) {
  await updateAttacker(ev);
  emit('new_event', ev);
  await evaluateEvent(ev);
}

module.exports = { ensureDefaultRules, processEvent, evaluateEvent, setIO, correlateToIncident };
