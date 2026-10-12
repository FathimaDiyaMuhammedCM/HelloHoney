const Event = require('../models/Event');
const { uid } = require('../utils/ids');
const { authRequired } = require('../middleware/auth');
const { processEvent } = require('../services/detectionService');

const SEV_MAP = { CONNECTION: 'INFO', FAILED_LOGIN: 'MEDIUM', TEST_LOGIN: 'MEDIUM', DISCONNECT: 'LOW', PORT_PROBE: 'MEDIUM', WEB_PROBE: 'MEDIUM', SUSPICIOUS_REQUEST: 'HIGH' };

// Escape user input before building RegExp to prevent ReDoS / regex injection
function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Only accept primitive strings for filter values (blocks operator objects
// even if a future change reintroduces the extended query parser)
const str = (v) => (typeof v === 'string' ? v : undefined);

// Whitelisted sort fields — user input never reaches Mongo sort unvalidated
const SORT_WHITELIST = new Set(['-timestamp', 'timestamp', '-severity', 'severity', '-sourceIP', 'sourceIP', 'eventType', '-eventType', 'service', '_id']);

function normalize(body, req) {
  // Never store plaintext passwords: store only safe representation
  let passwordEcho = undefined;
  if (body.passwordAttempt) {
    const p = String(body.passwordAttempt);
    passwordEcho = `len=${p.length} sha-prefix=*** (redacted)`;
  }
  // Validate timestamp — reject invalid dates instead of letting Mongoose
  // throw a CastError (500). Falls back to current time for bad input.
  let timestamp = new Date();
  if (body.timestamp !== undefined) {
    const parsed = new Date(body.timestamp);
    if (!isNaN(parsed.getTime())) timestamp = parsed;
  }
  return {
    eventId: typeof body.eventId === 'string' ? body.eventId : uid('EVT'),
    timestamp,
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
    // Optional ingest key protection for honeypot sensors.
    // When INGEST_KEY env var is set, callers must supply it via x-ingest-key header.
    const ingestKey = process.env.INGEST_KEY;
    if (ingestKey) {
      const provided = req.headers['x-ingest-key'];
      if (provided !== ingestKey) {
        return res.status(401).json({ error: 'Invalid or missing ingest key' });
      }
    }
    const data = normalize(req.body, req);
    const ev = await Event.create(data);
    processEvent(ev).catch(e => console.warn('[INGEST] detection failed', e.message));
    res.status(201).json(ev);
  } catch (e) { next(e); }
}

async function list(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const { q, service, severity, eventType, sourceIP, from, to, page = 1, limit = 20, sort = '-timestamp' } = req.query;
    const f = {};
    if (str(service)) f.service = service;
    if (str(severity)) f.severity = severity;
    if (str(eventType)) f.eventType = eventType;
    if (str(sourceIP)) f.sourceIP = sourceIP;
    if ((typeof from === 'string' && from) || (typeof to === 'string' && to)) {
      const ts = {};
      if (typeof from === 'string' && from) ts.$gte = new Date(from);
      if (typeof to === 'string' && to) ts.$lte = new Date(to);
      f.timestamp = ts;
    }
    if (typeof q === 'string') f.$or = [{ sourceIP: new RegExp(escapeRegex(q), 'i') }, { eventId: new RegExp(escapeRegex(q), 'i') }, { username: new RegExp(escapeRegex(q), 'i') }];
    const sortKey = (typeof sort === 'string' && SORT_WHITELIST.has(sort)) ? sort : '-timestamp';
    const p = Math.max(1, parseInt(page, 10) || 1), l = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const [items, total] = await Promise.all([
      Event.find(f).select('-passwordEcho').sort(sortKey).skip((p - 1) * l).limit(l).lean(),
      Event.countDocuments(f)
    ]);
    res.json({ items, total, page: p, pages: Math.ceil(total / l) });
  } catch (e) { next(e); }
}

async function getOne(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const ev = await Event.findOne({ $or: [{ eventId: req.params.id }, { _id: req.params.id.match(/^[0-9a-fA-F]{24}$/) ? req.params.id : undefined }] }).select('-passwordEcho').lean();
    if (!ev) return res.status(404).json({ error: 'Event not found' });
    const related = await Event.find({ sourceIP: ev.sourceIP }).sort('-timestamp').limit(20).lean();
    res.json({ event: ev, related });
  } catch (e) { next(e); }
}

module.exports = { ingest, list, getOne, normalize };
