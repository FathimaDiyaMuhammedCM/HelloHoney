const mongoose = require('mongoose');

const timelineSchema = new mongoose.Schema({
  at: { type: Date, default: Date.now },
  message: { type: String },
  by: { type: String }
}, { _id: false });

const incidentSchema = new mongoose.Schema({
  incidentId: { type: String, unique: true, required: true },
  title: { type: String, required: true },
  description: { type: String },
  severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default: 'MEDIUM' },
  status: { type: String, enum: ['OPEN', 'INVESTIGATING', 'RESOLVED'], default: 'OPEN', index: true },
  sourceIPs: [{ type: String }],
  relatedAlertIds: [{ type: String }],
  relatedEventIds: [{ type: String }],
  assignedTo: { type: String },
  riskScore: { type: Number, default: 0 },
  timeline: [timelineSchema],
  notes: [{ text: String, by: String, at: { type: Date, default: Date.now } }],
  resolvedAt: { type: Date }
}, { timestamps: true });

incidentSchema.index({ status: 1, severity: 1 });

module.exports = mongoose.model('Incident', incidentSchema);
