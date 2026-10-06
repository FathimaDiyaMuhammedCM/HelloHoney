const Event = require('../models/Event');
const { uid } = require('../utils/ids');
const { processEvent } = require('../services/detectionService');

const SEV_MAP = { CONNECTION: 'INFO', FAILED_LOGIN: 'MEDIUM', TEST_LOGIN: 'MEDIUM', DISCONNECT: 'LOW', PORT_PROBE: 'MEDIUM', WEB_PROBE: 'MEDIUM', SUSPICIOUS_REQUEST: 'HIGH' };

function normalize(body, req) {
  // Never store plaintext passwords: store only safe representation
  let passwordEcho = undefined;
  if (body.passwordAttempt) {
    const p = String(body.passwordAttempt);
    passwordEcho = `len=${p.length} sha-prefix=*** (redacted)`;
  }
  return {
    eventId: body.eventId || uid('EVT'),
    timestamp: body.timestamp ? new Date(body.timestamp) : new Date(),
    sourceIP: body.sourceIP || req.ip || '127.0.0.1',
    sourcePort: body.sourcePort,
    destinationIP: body.destinationIP || '127.0.0.1',
    destinationPort: body.destinationPort,
    service: body.service || 'SSH',
    protocol: body.protocol || 'TCP',
    eventType: body.eventType || 'CONNECTION',
    username: body.username,
    passwordEcho,
    status: body.status || 'failed',
    severity: body.severity || SEV_MAP[body.eventType] || 'LOW',
    sessionId: body.sessionId || uid('SES'),
    honeypotId: body.honeypotId || 'honeypot-01',
    simulated: !!body.simulated,
    metadata: body.metadata || {}
  };
}

async function ingest(req, res, next) {
  try {
    const data = normalize(req.body, req);
    const ev = await Event.create(data);
    processEvent(ev).catch(e => console.warn('[INGEST] detection failed', e.message));
    res.status(201).json(ev);
  } catch (e) { next(e); }
}

async function list(req, res, next) {
  try {
    const { q, service, severity, eventType, sourceIP, from, to, page = 1, limit = 20, sort = '-timestamp' } = req.query;
    const f = {};
    if (service) f.service = service;
    if (severity) f.severity = severity;
    if (eventType) f.eventType = eventType;
    if (sourceIP) f.sourceIP = sourceIP;
    if (from || to) f.timestamp = { ...(from ? { $gte: new Date(from) } : {}), ...(to ? { $lte: new Date(to) } : {}) };
    if (q) f.$or = [{ sourceIP: new RegExp(q, 'i') }, { eventId: new RegExp(q, 'i') }, { username: new RegExp(q, 'i') }, { sessionId: new RegExp(q, 'i') }];
    const p = Math.max(1, parseInt(page)), l = Math.min(100, parseInt(limit));
    const [items, total] = await Promise.all([
      Event.find(f).sort(sort).skip((p - 1) * l).limit(l).lean(),
      Event.countDocuments(f)
    ]);
    res.json({ items, total, page: p, pages: Math.ceil(total / l) });
  } catch (e) { next(e); }
}

async function getOne(req, res, next) {
  try {
    const ev = await Event.findOne({ $or: [{ eventId: req.params.id }, { _id: req.params.id.match(/^[0-9a-fA-F]{24}$/) ? req.params.id : undefined }] }).lean();
    if (!ev) return res.status(404).json({ error: 'Event not found' });
    const related = await Event.find({ sourceIP: ev.sourceIP }).sort('-timestamp').limit(20).lean();
    res.json({ event: ev, related });
  } catch (e) { next(e); }
}

module.exports = { ingest, list, getOne, normalize };
