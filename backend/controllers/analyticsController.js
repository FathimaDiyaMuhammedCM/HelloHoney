const { authRequired } = require('../middleware/auth');
const Event = require('../models/Event');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const Attacker = require('../models/Attacker');

async function summary(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const dayAgo = new Date(Date.now() - 24 * 3600 * 1000);
    const [totalEvents, totalAlerts, openAlerts, highAlerts, openIncidents, totalAttackers, eventsToday] = await Promise.all([
      Event.countDocuments(), Alert.countDocuments(),
      Alert.countDocuments({ status: 'OPEN' }),
      Alert.countDocuments({ severity: { $in: ['HIGH', 'CRITICAL'] } }),
      Incident.countDocuments({ status: { $in: ['OPEN', 'INVESTIGATING'] } }),
      Attacker.countDocuments(),
      Event.countDocuments({ timestamp: { $gte: dayAgo } })
    ]);
    const lastEvent = await Event.findOne().sort('-timestamp').lean();
    res.json({ totalEvents, totalAlerts, activeAlerts: openAlerts, openAlerts, highSeverity: highAlerts, openIncidents, uniqueAttackers: totalAttackers, eventsToday, lastEventAt: lastEvent?.timestamp || null });
  } catch (e) { next(e); }
}

async function timeline(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const days = parseInt(req.query.days || '7');
    const since = new Date(Date.now() - days * 24 * 3600 * 1000);
    const rows = await Event.aggregate([
      { $match: { timestamp: { $gte: since } } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d %H:00', date: '$timestamp' } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } }, { $limit: 100 }
    ]);
    res.json(rows.map(r => ({ time: r._id, events: r.count })));
  } catch (e) { next(e); }
}

async function attacks(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const rows = await Alert.aggregate([{ $group: { _id: '$attackType', count: { $sum: 1 } } }, { $sort: { count: -1 } }]);
    res.json(rows.map(r => ({ attack: r._id, count: r.count })));
  } catch (e) { next(e); }
}

async function severityDist(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const rows = await Alert.aggregate([{ $group: { _id: '$severity', count: { $sum: 1 } } }]);
    const rows2 = await Event.aggregate([{ $group: { _id: '$severity', count: { $sum: 1 } } }]);
    res.json({ alerts: rows, events: rows2 });
  } catch (e) { next(e); }
}

async function topIPs(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const rows = await Event.aggregate([{ $group: { _id: '$sourceIP', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }]);
    res.json(rows.map(r => ({ ip: r._id, events: r.count })));
  } catch (e) { next(e); }
}

async function services(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const rows = await Event.aggregate([{ $group: { _id: '$service', count: { $sum: 1 } } }, { $sort: { count: -1 } }]);
    res.json(rows.map(r => ({ service: r._id, count: r.count })));
  } catch (e) { next(e); }
}

module.exports = { summary, timeline, attacks, severityDist, topIPs, services };
