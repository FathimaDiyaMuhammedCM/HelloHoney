const AuditLog = require('../models/AuditLog');

async function audit({ userId, userName, action, resource, resourceId, details, sourceIP }) {
  try {
    await AuditLog.create({ userId, userName, action, resource, resourceId, details, sourceIP });
  } catch (e) {
    console.warn('[AUDIT] failed:', e.message);
  }
}

module.exports = audit;
