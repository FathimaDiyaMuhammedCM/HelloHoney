const { normalize } = require('./eventController');
const Event = require('../models/Event');
const { processEvent } = require('../services/detectionService');
const { uid } = require('../utils/ids');

async function emitSynthetic(req, res, next, events) {
  try {
    const created = [];
    for (const e of events) {
      const doc = await Event.create(normalize({ ...e, simulated: true }, req));
      created.push(doc);
      await processEvent(doc);
    }
    res.status(201).json({ created: created.length, events: created });
  } catch (e) { next(e); }
}

function synthIP(req) { return req.body.sourceIP || '192.168.56.20'; }

async function failedLogin(req, res, next) {
  const ip = synthIP(req);
  return emitSynthetic(req, res, next, [{ eventId: uid('EVT'), sourceIP: ip, service: 'SSH', eventType: 'FAILED_LOGIN', username: 'admin', status: 'failed', passwordAttempt: 'x', destinationPort: 2222, metadata: { lab: true } }]);
}

async function bruteForce(req, res, next) {
  const ip = synthIP(req);
  const evs = Array.from({ length: 10 }, (_, i) => ({ eventId: uid('EVT'), sourceIP: ip, sourcePort: 40000 + i, service: 'SSH', eventType: 'FAILED_LOGIN', username: ['admin', 'root', 'test'][i % 3], status: 'failed', passwordAttempt: 'guess' + i, destinationPort: 2222, metadata: { lab: true, bruteForce: true } }));
  return emitSynthetic(req, res, next, evs);
}

async function portScan(req, res, next) {
  const ip = req.body.sourceIP || '192.168.56.21';
  const ports = [22, 80, 2222, 8080, 3306, 443];
  const evs = ports.map((p, i) => ({ eventId: uid('EVT'), sourceIP: ip, service: 'TCP', eventType: 'PORT_PROBE', status: 'probed', destinationPort: p, metadata: { lab: true } }));
  return emitSynthetic(req, res, next, evs);
}

async function webProbe(req, res, next) {
  const ip = req.body.sourceIP || '10.0.2.20';
  const paths = ['/admin', '/wp-admin', '/.env', '/config', '/backup'];
  const evs = paths.map(p => ({ eventId: uid('EVT'), sourceIP: ip, service: 'HTTP', eventType: 'WEB_PROBE', status: 'probed', destinationPort: 8080, metadata: { lab: true, path: p } }));
  return emitSynthetic(req, res, next, evs);
}

async function multiStage(req, res, next) {
  const ip = req.body.sourceIP || '10.0.2.21';
  const evs = [
    { eventId: uid('EVT'), sourceIP: ip, service: 'TCP', eventType: 'PORT_PROBE', status: 'probed', destinationPort: 2222, metadata: { lab: true } },
    { eventId: uid('EVT'), sourceIP: ip, service: 'SSH', eventType: 'CONNECTION', status: 'connected', destinationPort: 2222, metadata: { lab: true } },
    ...Array.from({ length: 8 }, (_, i) => ({ eventId: uid('EVT'), sourceIP: ip, service: 'SSH', eventType: 'FAILED_LOGIN', username: 'root', status: 'failed', passwordAttempt: 'pw' + i, destinationPort: 2222, metadata: { lab: true } }))
  ];
  return emitSynthetic(req, res, next, evs);
}

module.exports = { failedLogin, bruteForce, portScan, webProbe, multiStage };
