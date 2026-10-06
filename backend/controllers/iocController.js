const IOC = require('../models/IOC');
const audit = require('../utils/audit');

async function list(req, res, next) {
  try {
    const { q, type } = req.query;
    const f = {};
    if (type) f.type = type;
    if (q) f.value = new RegExp(q, 'i');
    res.json(await IOC.find(f).sort('-createdAt').limit(200).lean());
  } catch (e) { next(e); }
}
async function create(req, res, next) {
  try {
    const ioc = await IOC.create(req.body);
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'IOC_CREATE', resource: 'IOC', resourceId: ioc.value, sourceIP: req.ip });
    res.status(201).json(ioc);
  } catch (e) { next(e); }
}
async function update(req, res, next) {
  try {
    const ioc = await IOC.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!ioc) return res.status(404).json({ error: 'IOC not found' });
    res.json(ioc);
  } catch (e) { next(e); }
}
async function remove(req, res, next) {
  try {
    await IOC.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (e) { next(e); }
}
module.exports = { list, create, update, remove };
