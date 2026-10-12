const Alert = require('../models/Alert');
const Event = require('../models/Event');
const audit = require('../utils/audit');

// Escape user input before building RegExp to prevent ReDoS / regex injection
function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Only accept primitive strings for filter values (blocks NoSQL operator objects)
const str = (v) => (typeof v === 'string' ? v : undefined);

async function list(req, res, next) {
  try {
    const { severity, status, attackType, sourceIP, from, to, q, page = 1, limit = 20 } = req.query;
    const f = {};
    if (str(severity)) f.severity = severity;
    if (str(status)) f.status = status;
    if (str(attackType)) f.attackType = new RegExp(escapeRegex(attackType), 'i');
    if (str(sourceIP)) f.sourceIP = sourceIP;
    if ((typeof from === 'string' && from) || (typeof to === 'string' && to)) {
      const ts = {};
      if (typeof from === 'string' && from) ts.$gte = new Date(from);
      if (typeof to === 'string' && to) ts.$lte = new Date(to);
      f.timestamp = ts;
    }
    if (typeof q === 'string') f.$or = [{ alertId: new RegExp(escapeRegex(q), 'i') }, { sourceIP: new RegExp(escapeRegex(q), 'i') }, { attackType: new RegExp(escapeRegex(q), 'i') }];
    const p = Math.max(1, parseInt(page, 10) || 1), l = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const [items, total] = await Promise.all([Alert.find(f).sort('-timestamp').skip((p - 1) * l).limit(l).lean(), Alert.countDocuments(f)]);
    res.json({ items, total, page: p, pages: Math.ceil(total / l) });
  } catch (e) { next(e); }
}

async function getOne(req, res, next) {
  try {
    const a = await Alert.findOne({ $or: [{ alertId: req.params.id }, { _id: req.params.id.match(/^[0-9a-fA-F]{24}$/) ? req.params.id : undefined }] }).lean();
    if (!a) return res.status(404).json({ error: 'Alert not found' });
    const events = await Event.find({ eventId: { $in: a.relatedEventIds || [] } }).select('-passwordEcho').lean();
    res.json({ alert: a, events });
  } catch (e) { next(e); }
}

async function setStatus(req, res, next) {
  try {
    const { status } = req.body;
    if (!['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
    const a = await Alert.findOneAndUpdate(
      { $or: [{ alertId: req.params.id }, { _id: req.params.id.match(/^[0-9a-fA-F]{24}$/) ? req.params.id : undefined }] },
      { status }, { new: true });
    if (!a) return res.status(404).json({ error: 'Alert not found' });
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'ALERT_STATUS_CHANGE', resource: 'Alert', resourceId: a.alertId, details: `-> ${status}`, sourceIP: req.ip });
    res.json(a);
  } catch (e) { next(e); }
}

module.exports = { list, getOne, setStatus };
