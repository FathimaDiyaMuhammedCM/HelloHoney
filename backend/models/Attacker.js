const mongoose = require('mongoose');

const attackerSchema = new mongoose.Schema({
  sourceIP: { type: String, unique: true, required: true },
  totalEvents: { type: Number, default: 0 },
  failedLogins: { type: Number, default: 0 },
  successfulTestLogins: { type: Number, default: 0 },
  alerts: { type: Number, default: 0 },
  incidents: { type: Number, default: 0 },
  firstSeen: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  highestSeverity: { type: String, default: 'LOW' },
  riskScore: { type: Number, default: 0 },
  services: [{ type: String }]
}, { timestamps: true });

module.exports = mongoose.model('Attacker', attackerSchema);
