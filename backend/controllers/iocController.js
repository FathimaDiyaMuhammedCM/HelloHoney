const IOC = require('../models/IOC');
const audit = require('../utils/audit');

// Escape user input before building RegExp to prevent ReDoS / regex injection
function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function list(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const { q, type } = req.query;
    const f = {};
    // Only accept primitive strings (blocks NoSQL operator objects)
    if (typeof type === 'string' && type) f.type = type;
    if (typeof q === 'string' && q) f.value = new RegExp(escapeRegex(q), 'i');
    res.json(await IOC.find(f).sort('-createdAt').limit(200).lean());
  } catch (e) { next(e); }
}

async function create(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const { value, type, description, severity, source, tags } = req.body || {};
    if (!value || !type) return res.status(400).json({ error: 'value and type are required' });
    // Whitelist allowed fields — prevent mass assignment of _id/__proto__ etc.
    const ioc = await IOC.create({ value, type, description, severity, source, tags });
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'IOC_CREATE', resource: 'IOC', resourceId: ioc.value, sourceIP: req.ip });
    res.status(201).json(ioc);
  } catch (e) { next(e); }
}

async function update(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    // Whitelist allowed fields — prevent mass assignment of _id/__proto__ etc.
    const allowed = {};
    const { value, type, description, severity, source, tags } = req.body || {};
    if (value !== undefined) allowed.value = value;
    if (type !== undefined) allowed.type = type;
    if (description !== undefined) allowed.description = description;
    if (severity !== undefined) allowed.severity = severity;
    if (source !== undefined) allowed.source = source;
    if (tags !== undefined) allowed.tags = tags;
    const ioc = await IOC.findByIdAndUpdate(req.params.id, allowed, { new: true, runValidators: true });
    if (!ioc) return res.status(404).json({ error: 'IOC not found' });
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'IOC_UPDATE', resource: 'IOC', resourceId: ioc.value, sourceIP: req.ip });
    res.json(ioc);
  } catch (e) { next(e); }
}

async function remove(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const ioc = await IOC.findByIdAndDelete(req.params.id);
    if (!ioc) return res.status(404).json({ error: 'IOC not found' });
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'IOC_DELETE', resource: 'IOC', resourceId: ioc.value, sourceIP: req.ip });
    res.json({ ok: true });
  } catch (e) { next(e); }
}

module.exports = { list, create, update, remove };
