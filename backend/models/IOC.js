const mongoose = require('mongoose');

const iocSchema = new mongoose.Schema({
  type: { type: String, enum: ['IP', 'DOMAIN', 'URL', 'HASH', 'USERNAME'], required: true },
  value: { type: String, required: true },
  description: { type: String },
  severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default: 'MEDIUM' },
  source: { type: String, default: 'lab' },
  tags: [{ type: String }]
}, { timestamps: true });

iocSchema.index({ value: 1, type: 1 }, { unique: true });

module.exports = mongoose.model('IOC', iocSchema);
