const Alert = require('../models/Alert');
const Event = require('../models/Event');
const audit = require('../utils/audit');

async function list(req, res, next) {
  try {
    const { severity, status, attackType, sourceIP, from, to, q, page = 1, limit = 20 } = req.query;
    const f = {};
    if (severity) f.severity = severity;
    if (status) f.status = status;
    if (attackType) f.attackType = new RegExp(attackType, 'i');
    if (sourceIP) f.sourceIP = sourceIP;
    if (from || to) f.timestamp = { ...(from ? { $gte: new Date(from) } : {}), ...(to ? { $lte: new Date(to) } : {}) };
    if (q) f.$or = [{ alertId: new RegExp(q, 'i') }, { sourceIP: new RegExp(q, 'i') }, { attackType: new RegExp(q, 'i') }];
    const p = Math.max(1, parseInt(page)), l = Math.min(100, parseInt(limit));
    const [items, total] = await Promise.all([Alert.find(f).sort('-timestamp').skip((p - 1) * l).limit(l).lean(), Alert.countDocuments(f)]);
    res.json({ items, total, page: p, pages: Math.ceil(total / l) });
  } catch (e) { next(e); }
}

async function getOne(req, res, next) {
  try {
    const a = await Alert.findOne({ $or: [{ alertId: req.params.id }, { _id: req.params.id.match(/^[0-9a-fA-F]{24}$/) ? req.params.id : undefined }] }).lean();
    if (!a) return res.status(404).json({ error: 'Alert not found' });
    const events = await Event.find({ eventId: { $in: a.relatedEventIds || [] } }).lean();
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
