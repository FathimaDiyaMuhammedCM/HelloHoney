const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
  eventId: { type: String, unique: true, required: true },
  timestamp: { type: Date, default: Date.now, index: true },
  sourceIP: { type: String, required: true, index: true },
  sourcePort: { type: Number },
  destinationIP: { type: String },
  destinationPort: { type: Number },
  service: { type: String, index: true, default: 'SSH' },
  protocol: { type: String, default: 'TCP' },
  eventType: { type: String, index: true, enum: ['CONNECTION', 'FAILED_LOGIN', 'TEST_LOGIN', 'DISCONNECT', 'PORT_PROBE', 'WEB_PROBE', 'SUSPICIOUS_REQUEST'], required: true },
  username: { type: String },
  passwordEcho: { type: String },
  status: { type: String, default: 'failed' },
  severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO'], default: 'LOW', index: true },
  sessionId: { type: String, index: true },
  honeypotId: { type: String, default: 'honeypot-01' },
  simulated: { type: Boolean, default: false },
  metadata: { type: Object, default: {} }
}, { timestamps: true });

eventSchema.index({ timestamp: -1 });
eventSchema.index({ sourceIP: 1, timestamp: -1 });

module.exports = mongoose.model('Event', eventSchema);
