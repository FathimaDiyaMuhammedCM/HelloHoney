const mongoose = require('mongoose');

const auditSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  userId: { type: String },
  userName: { type: String },
  action: { type: String, required: true },
  resource: { type: String },
  resourceId: { type: String },
  details: { type: String },
  sourceIP: { type: String }
});

module.exports = mongoose.model('AuditLog', auditSchema);
