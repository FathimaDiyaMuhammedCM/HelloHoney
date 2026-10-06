const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  alertId: { type: String, unique: true, required: true },
  timestamp: { type: Date, default: Date.now, index: true },
  sourceIP: { type: String, required: true, index: true },
  attackType: { type: String, required: true, index: true },
  severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default: 'MEDIUM', index: true },
  description: { type: String },
  ruleId: { type: mongoose.Schema.Types.ObjectId, ref: 'DetectionRule' },
  ruleName: { type: String },
  relatedEventIds: [{ type: String }],
  confidence: { type: Number, default: 80 },
  status: { type: String, enum: ['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'], default: 'OPEN', index: true },
  riskScore: { type: Number, default: 0 }
}, { timestamps: true });

module.exports = mongoose.model('Alert', alertSchema);
