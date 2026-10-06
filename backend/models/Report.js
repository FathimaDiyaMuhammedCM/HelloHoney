const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  reportId: { type: String, unique: true, required: true },
  type: { type: String, required: true },
  format: { type: String, enum: ['PDF', 'CSV'], default: 'PDF' },
  generatedBy: { type: String },
  filters: { type: Object },
  filePath: { type: String },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Report', reportSchema);
