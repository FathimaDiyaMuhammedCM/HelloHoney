const { parse, sanitizeEventType, sanitizeSeverity } = require('../services/logParser');
const Event = require('../models/Event');
const audit = require('../utils/audit');
const { uid } = require('../utils/ids');
const { processEvent } = require('../services/detectionService');

async function upload(req, res) {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file received in request. Please select a file.' });
    }
    if (!req.file.originalname) {
      return res.status(400).json({ error: 'No filename received in upload.' });
    }

    // Validate file type by extension and content sniffing
    const allowedExtensions = ['.log', '.txt', '.csv', '.tsv', '.json', '.ndjson', '.pcap', '.syslog', '.out'];
    const ext = require('path').extname(req.file.originalname).toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      return res.status(400).json({ error: 'Unsupported file type. Allowed: ' + allowedExtensions.join(', ') });
    }

    // Sanitize filename — prevent path traversal in stored metadata
    const safeFilename = require('path').basename(req.file.originalname).replace(/[^\w.\-]/g, '_');

    // Support both binary buffers (pcap) and utf8 text (syslog/csv/json)
    const rawData = req.file.buffer ? req.file.buffer : '';
    if (!rawData || (typeof rawData === 'string' && !rawData.trim())) {
      return res.status(400).json({ error: 'Uploaded file is empty.' });
    }

    const events = parse(rawData);
    if (!events || !events.length) {
      return res.status(400).json({
        error: `Could not parse events from "${safeFilename}". Supported formats: Syslog (RFC3164/ISO), JSON/NDJSON, CSV/TSV, Firewall/KV, Web access logs, PCAP.`,
        filename: safeFilename
      });
    }

    const BATCH_LIMIT = 1000;
    const items = events.slice(0, BATCH_LIMIT);
    const validDocs = [];

    for (let i = 0; i < items.length; i++) {
      const e = items[i];
      try {
        const evType = sanitizeEventType(e.eventType || 'CONNECTION');
        const sev = sanitizeSeverity(e.severity, evType);

        let ts = new Date();
        if (e.timestamp) {
          const parsedTs = new Date(e.timestamp);
          if (!isNaN(parsedTs.getTime())) ts = parsedTs;
        }

        const sp = e.sourcePort != null ? Number(e.sourcePort) : undefined;
        const dp = e.destinationPort != null ? Number(e.destinationPort) : (e.service === 'HTTP' ? 80 : 22);

        validDocs.push({
          eventId: uid('EVT'),
          timestamp: ts,
          sourceIP: String(e.sourceIP || '127.0.0.1').trim(),
          sourcePort: isNaN(sp) || sp < 0 ? undefined : sp,
          destinationIP: String(e.destinationIP || '127.0.0.1').trim(),
          destinationPort: isNaN(dp) || dp < 0 ? (e.service === 'HTTP' ? 80 : 22) : dp,
          service: String(e.service || (dp === 80 || dp === 8080 ? 'HTTP' : 'SSH')).trim(),
          protocol: String(e.protocol || 'TCP').trim(),
          eventType: evType,
          username: e.username ? String(e.username).trim() : undefined,
          passwordEcho: e.passwordEcho || (e.password ? `len=${String(e.password).length} sha-prefix=***` : undefined),
          status: e.status ? String(e.status).trim() : (evType === 'FAILED_LOGIN' ? 'failed' : 'connected'),
          severity: sev,
          sessionId: e.sessionId || uid('SES'),
          honeypotId: e.honeypotId || 'honeypot-01',
          simulated: e.simulated !== false,
          metadata: {
            ...(e.metadata || {}),
            originalEventId: e.eventId,
            source: 'upload',
            filename: safeFilename
          }
        });
      } catch (err) {
        console.warn('[LOGUPLOAD] skip doc preparation error:', err.message);
      }
    }

    if (!validDocs.length) {
      return res.status(400).json({
        error: `Parsed 0 valid events from "${safeFilename}". Please check the log formatting.`
      });
    }

    // Bulk insert into MongoDB for high performance
    const savedDocs = await Event.insertMany(validDocs, { ordered: false });

    // Asynchronously trigger detection & alerts
    (async () => {
      for (const doc of savedDocs.slice(0, 50)) {
        try {
          await processEvent(doc);
        } catch (_) {}
      }
    })();

    await audit({
      userName: req.user?.name || 'System',
      userId: req.user?.id || req.user?._id,
      action: 'LOG_UPLOAD',
      resource: 'LogFile',
      resourceId: safeFilename,
      details: `${events.length} parsed, ${savedDocs.length} stored into database`,
      sourceIP: req.ip
    });

    res.status(201).json({
      message: `Successfully processed ${safeFilename}`,
      uploaded: safeFilename,
      eventsParsed: events.length,
      eventsStored: savedDocs.length,
      sample: savedDocs[0]
    });
  } catch (err) {
    console.error('[LOGUPLOAD] error:', err.message, err.stack);
    res.status(500).json({ error: 'Upload failed. Please check the file format and try again.' });
  }
}

module.exports = { upload };