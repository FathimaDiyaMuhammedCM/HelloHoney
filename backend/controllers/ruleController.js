const DetectionRule = require('../models/DetectionRule');
const audit = require('../utils/audit');

async function list(req, res, next) {
  try { res.json(await DetectionRule.find().sort('name').lean()); }
  catch (e) { next(e); }
}
async function create(req, res, next) {
  try {
    const r = await DetectionRule.create(req.body);
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'RULE_CREATE', resource: 'Rule', resourceId: r.name, sourceIP: req.ip });
    res.status(201).json(r);
  } catch (e) { next(e); }
}
async function update(req, res, next) {
  try {
    const r = await DetectionRule.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
    if (!r) return res.status(404).json({ error: 'Rule not found' });
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'RULE_UPDATE', resource: 'Rule', resourceId: r.name, sourceIP: req.ip });
    res.json(r);
  } catch (e) { next(e); }
}
async function remove(req, res, next) {
  try {
    const r = await DetectionRule.findByIdAndDelete(req.params.id);
    if (!r) return res.status(404).json({ error: 'Rule not found' });
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'RULE_DELETE', resource: 'Rule', resourceId: r.name, sourceIP: req.ip });
    res.json({ ok: true });
  } catch (e) { next(e); }
}
module.exports = { list, create, update, remove };
