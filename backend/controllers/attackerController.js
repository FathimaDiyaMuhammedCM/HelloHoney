const Attacker = require('../models/Attacker');
const Event = require('../models/Event');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');

async function list(req, res, next) {
  try {
    const items = await Attacker.find().sort('-riskScore').limit(200).lean();
    res.json({ items, total: items.length });
  } catch (e) { next(e); }
}

async function getOne(req, res, next) {
  try {
    const ip = req.params.ip;
    const attacker = await Attacker.findOne({ sourceIP: ip }).lean();
    if (!attacker) return res.status(404).json({ error: 'Attacker not found' });
    const [events, alerts, incidents] = await Promise.all([
      Event.find({ sourceIP: ip }).sort('-timestamp').limit(100).lean(),
      Alert.find({ sourceIP: ip }).sort('-timestamp').limit(50).lean(),
      Incident.find({ sourceIPs: ip }).sort('-createdAt').limit(20).lean()
    ]);
    res.json({ attacker, events, alerts, incidents });
  } catch (e) { next(e); }
}

module.exports = { list, getOne };
