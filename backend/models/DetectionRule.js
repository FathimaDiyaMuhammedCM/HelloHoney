const mongoose = require('mongoose');

const ruleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String },
  eventType: { type: String, default: 'FAILED_LOGIN' },
  threshold: { type: Number, default: 5 },
  timeWindow: { type: Number, default: 60 },
  severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default: 'HIGH' },
  enabled: { type: Boolean, default: true },
  ruleType: { type: String, default: 'BRUTE_FORCE' },
  attackType: { type: String, default: 'SSH Brute Force' },
  autoCreateIncident: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('DetectionRule', ruleSchema);
