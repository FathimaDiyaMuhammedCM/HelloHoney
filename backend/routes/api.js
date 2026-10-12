const express = require('express');
const { authRequired, requireRoles } = require('../middleware/auth');
const auth = require('../controllers/authController');
const ev = require('../controllers/eventController');
const al = require('../controllers/alertController');
const inc = require('../controllers/incidentController');
const atk = require('../controllers/attackerController');
const ana = require('../controllers/analyticsController');
const rules = require('../controllers/ruleController');
const iocs = require('../controllers/iocController');
const rep = require('../controllers/reportController');
const sim = require('../controllers/simulationController');
const sys = require('../controllers/systemController');
const aud = require('../controllers/auditController');
const logUp = require('../controllers/logUploadController');
const multer = require('multer');
const rateLimit = require('express-rate-limit');

const r = express.Router();

// Strict rate limit for authentication endpoints to prevent brute force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts, please try again later' }
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max upload
  fileFilter: (req, file, cb) => {
    const allowed = ['.log', '.txt', '.csv', '.tsv', '.json', '.ndjson', '.pcap', '.syslog', '.out'];
    const ext = require('path').extname(file.originalname || '').toLowerCase();
    if (allowed.includes(ext)) return cb(null, true);
    const err = new Error('Unsupported file type. Allowed: ' + allowed.join(', '));
    err.status = 400;
    cb(err);
  }
});

// auth (rate-limited to prevent credential brute force)
r.post('/auth/login', authLimiter, auth.login);
r.post('/auth/register', authLimiter, auth.register);
r.get('/auth/me', authRequired, auth.me);

// ingest (lab honeypot -> backend; protected by optional key, open on localhost lab)
r.post('/ingest/events', ev.ingest);

// events
r.get('/events', authRequired, ev.list);
r.get('/events/:id', authRequired, ev.getOne);

// alerts
r.get('/alerts', authRequired, al.list);
r.get('/alerts/:id', authRequired, al.getOne);
r.patch('/alerts/:id/status', authRequired, al.setStatus);

// incidents
r.get('/incidents', authRequired, inc.list);
r.post('/incidents', authRequired, inc.create);
r.get('/incidents/:id', authRequired, inc.getOne);
r.patch('/incidents/:id', authRequired, inc.update);
r.post('/incidents/:id/notes', authRequired, inc.addNote);

// attackers
r.get('/attackers', authRequired, atk.list);
r.get('/attackers/:ip', authRequired, atk.getOne);

// analytics
r.get('/analytics/summary', authRequired, ana.summary);
r.get('/analytics/timeline', authRequired, ana.timeline);
r.get('/analytics/attacks', authRequired, ana.attacks);
r.get('/analytics/severity', authRequired, ana.severityDist);
r.get('/analytics/top-ips', authRequired, ana.topIPs);
r.get('/analytics/services', authRequired, ana.services);

// rules (admin + analyst write, all auth read)
r.get('/rules', authRequired, rules.list);
r.post('/rules', authRequired, requireRoles('ADMIN', 'ANALYST'), rules.create);
r.patch('/rules/:id', authRequired, requireRoles('ADMIN', 'ANALYST'), rules.update);
r.delete('/rules/:id', authRequired, requireRoles('ADMIN'), rules.remove);

// iocs
r.get('/iocs', authRequired, iocs.list);
r.post('/iocs', authRequired, requireRoles('ADMIN', 'ANALYST'), iocs.create);
r.patch('/iocs/:id', authRequired, requireRoles('ADMIN', 'ANALYST'), iocs.update);
r.delete('/iocs/:id', authRequired, requireRoles('ADMIN'), iocs.remove);

// reports
r.post('/reports/preview', authRequired, rep.previewReport);
r.get('/reports/preview', authRequired, rep.previewReport);
r.post('/reports/pdf', authRequired, rep.pdfReport);
r.get('/reports/events/csv', authRequired, rep.csvExport('events'));
r.get('/reports/alerts/csv', authRequired, rep.csvExport('alerts'));
r.get('/reports/incidents/csv', authRequired, rep.csvExport('incidents'));

// log upload (all authenticated roles in lab mode)
r.post('/logs/upload', authRequired, requireRoles('ADMIN', 'ANALYST', 'VIEWER'), upload.single('file'), logUp.upload);

// simulation (lab only)
r.post('/simulation/failed-login', authRequired, sim.failedLogin);
r.post('/simulation/brute-force', authRequired, sim.bruteForce);
r.post('/simulation/port-scan', authRequired, sim.portScan);
r.post('/simulation/web-probe', authRequired, sim.webProbe);
r.post('/simulation/multi-stage', authRequired, sim.multiStage);

// system (health is public for probes; status exposes internal state -> auth required)
r.get('/health', sys.health);
r.get('/system/status', authRequired, sys.status);

// audit
r.get('/audit-logs', authRequired, requireRoles('ADMIN', 'ANALYST'), aud.list);

module.exports = r;
