const AuditLog = require('../models/AuditLog');
async function list(req, res, next) {
  try {
    const logs = await AuditLog.find().sort('-timestamp').limit(200).lean();
    res.json(logs);
  } catch (e) { next(e); }
}
module.exports = { list };
