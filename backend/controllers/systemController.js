const mongoose = require('mongoose');
const Event = require('../models/Event');
const Alert = require('../models/Alert');

async function health(req, res) {
  res.json({ status: 'ok', time: new Date().toISOString() });
}

async function status(req, res) {
  const [events, alerts] = await Promise.all([Event.countDocuments(), Alert.countDocuments()]);
  const lastEvent = await Event.findOne().sort('-timestamp').lean();
  res.json({
    api: 'HEALTHY',
    mongodb: mongoose.connection.readyState === 1 ? 'CONNECTED' : 'DISCONNECTED',
    honeypot: process.env.HONEYPOT_STATUS || 'RUNNING (lab)',
    detectionEngine: 'RUNNING',
    frontend: 'ONLINE',
    lastEventAt: lastEvent?.timestamp || null,
    eventsProcessed: events,
    alertsGenerated: alerts,
    simulationMode: (process.env.SIMULATION_MODE || 'true') === 'true',
    sshPort: process.env.SSH_HONEYPOT_PORT || 2222,
    httpPort: process.env.HTTP_HONEYPOT_PORT || 8080
  });
}

module.exports = { health, status };
