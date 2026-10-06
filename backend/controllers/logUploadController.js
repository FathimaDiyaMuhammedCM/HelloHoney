const { parse } = require('../services/logParser');
const Event = require('../models/Event');
const audit = require('../utils/audit');
const { uid } = require('../utils/ids');
const { processEvent } = require('../services/detectionService');

async function upload(req, res) {
  try {
    // multer puts file in req.file
    if (!req.file) {
      return res.status(400).json({ error: 'No file received in request. Please select a file.' });
    }
    if (!req.file.originalname) {
      return res.status(400).json({ error: 'No filename received in upload.' });
    }

    const text = req.file.buffer ? req.file.buffer.toString('utf8') : '';
    if (!text.trim()) {
      return res.status(400).json({ error: 'Uploaded file is empty.' });
    }

    const events = parse(text);
    if (!events || !events.length) {
      return res.status(400).json({
        error: `Could not parse events from "${req.file.originalname}". Supported formats: Syslog, JSON, CSV, Web access logs.`,
        filename: req.file.originalname
      });
    }

    const saved = [];
    const BATCH_LIMIT = 500;
    const items = events.slice(0, BATCH_LIMIT);

    for (const e of items) {
      try {
        const evData = {
          eventId: e.eventId || uid('EVT'),
          timestamp: e.timestamp ? new Date(e.timestamp) : new Date(),
          sourceIP: e.sourceIP || '127.0.0.1',
          sourcePort: e.sourcePort ? Number(e.sourcePort) : undefined,
          destinationIP: e.destinationIP || '127.0.0.1',
          destinationPort: e.destinationPort ? Number(e.destinationPort) : (e.service === 'HTTP' ? 80 : 22),
          service: e.service || 'SSH',
          protocol: e.protocol || 'TCP',
          eventType: e.eventType || 'CONNECTION',
          username: e.username,
          passwordEcho: e.passwordEcho || (e.password ? `len=${String(e.password).length} sha-prefix=***` : undefined),
          status: e.status || (e.eventType === 'FAILED_LOGIN' ? 'failed' : 'connected'),
          severity: e.severity || (e.eventType === 'FAILED_LOGIN' ? 'MEDIUM' : 'LOW'),
          sessionId: e.sessionId || uid('SES'),
          honeypotId: e.honeypotId || 'honeypot-01',
          simulated: e.simulated !== false,
          metadata: { ...(e.metadata || {}), source: 'upload', filename: req.file.originalname }
        };

        const doc = await Event.create(evData);
        saved.push(doc.eventId);

        // Run through real-time detection & alert pipeline
        processEvent(doc).catch(err => console.warn('[LOGUPLOAD] detection warning:', err.message));
      } catch (err) {
        console.warn('[LOGUPLOAD] skip event error:', err.message);
      }
    }

    await audit({
      userName: req.user?.name || 'System',
      userId: req.user?.id || req.user?._id,
      action: 'LOG_UPLOAD',
      resource: 'LogFile',
      resourceId: req.file.originalname,
      details: `${events.length} parsed, ${saved.length} stored into database`,
      sourceIP: req.ip
    });

    res.status(201).json({
      message: `Successfully processed ${req.file.originalname}`,
      uploaded: req.file.originalname,
      eventsParsed: events.length,
      eventsStored: saved.length
    });
  } catch (err) {
    console.error('[LOGUPLOAD] error:', err.message, err.stack);
    res.status(500).json({ error: 'Upload failed: ' + err.message });
  }
}

module.exports = { upload };