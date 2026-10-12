const Incident = require('../models/Incident');
const { nextId } = require('../utils/ids');
const audit = require('../utils/audit');

// Escape user input before building RegExp to prevent ReDoS / regex injection
function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function list(req, res, next) {
  try {
    const { status, severity, q } = req.query;
    const f = {};
    // Only accept primitive strings (blocks NoSQL operator objects)
    if (typeof status === 'string' && status) f.status = status;
    if (typeof severity === 'string' && severity) f.severity = severity;
    if (typeof q === 'string' && q) f.$or = [{ incidentId: new RegExp(escapeRegex(q), 'i') }, { title: new RegExp(escapeRegex(q), 'i') }];
    const items = await Incident.find(f).sort('-createdAt').limit(100).lean();
    res.json({ items, total: items.length });
  } catch (e) { next(e); }
}

async function create(req, res, next) {
  try {
    const { title, description, severity, sourceIPs, relatedAlertIds, relatedEventIds, assignedTo } = req.body;
    if (!title) return res.status(400).json({ error: 'title required' });
    const incidentId = await nextId(Incident, 'incidentId', 'INC');
    const inc = await Incident.create({
      incidentId, title, description, severity: severity || 'MEDIUM',
      sourceIPs: sourceIPs || [], relatedAlertIds: relatedAlertIds || [],
      relatedEventIds: relatedEventIds || [], assignedTo,
      timeline: [{ message: 'Incident created by ' + (req.user?.name || 'system') }]
    });
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'INCIDENT_CREATE', resource: 'Incident', resourceId: incidentId, sourceIP: req.ip });
    res.status(201).json(inc);
  } catch (e) { next(e); }
}

async function getOne(req, res, next) {
  try {
    const inc = await Incident.findOne({ $or: [{ incidentId: req.params.id }, { _id: req.params.id.match(/^[0-9a-fA-F]{24}$/) ? req.params.id : undefined }] }).lean();
    if (!inc) return res.status(404).json({ error: 'Incident not found' });
    res.json(inc);
  } catch (e) { next(e); }
}

async function update(req, res, next) {
  try {
    const { status, assignedTo, severity, note, linkAlert } = req.body;
    const inc = await Incident.findOne({ $or: [{ incidentId: req.params.id }, { _id: req.params.id.match(/^[0-9a-fA-F]{24}$/) ? req.params.id : undefined }] });
    if (!inc) return res.status(404).json({ error: 'Incident not found' });
    if (status) {
      if (!['OPEN', 'INVESTIGATING', 'RESOLVED'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
      inc.status = status;
      inc.timeline.push({ message: `Status -> ${status} by ${req.user?.name || 'system'}` });
      if (status === 'RESOLVED') inc.resolvedAt = new Date();
    }
    if (assignedTo !== undefined) { inc.assignedTo = assignedTo; inc.timeline.push({ message: `Assigned to ${assignedTo}` }); }
    if (severity) inc.severity = severity;
    if (note) inc.notes.push({ text: note, by: req.user?.name || 'analyst' });
    if (linkAlert && !inc.relatedAlertIds.includes(linkAlert)) inc.relatedAlertIds.push(linkAlert);
    await inc.save();
    await audit({ userName: req.user?.name, userId: req.user?.id, action: 'INCIDENT_UPDATE', resource: 'Incident', resourceId: inc.incidentId, details: JSON.stringify(req.body).slice(0, 300), sourceIP: req.ip });
    res.json(inc);
  } catch (e) { next(e); }
}

async function addNote(req, res, next) {
  try {
    const inc = await Incident.findOne({ $or: [{ incidentId: req.params.id }, { _id: req.params.id.match(/^[0-9a-fA-F]{24}$/) ? req.params.id : undefined }] });
    if (!inc) return res.status(404).json({ error: 'Incident not found' });
    inc.notes.push({ text: req.body.text || '', by: req.user?.name || 'analyst' });
    inc.timeline.push({ message: `Note added by ${req.user?.name || 'analyst'}` });
    await inc.save();
    res.json(inc);
  } catch (e) { next(e); }
}

module.exports = { list, create, getOne, update, addNote };
