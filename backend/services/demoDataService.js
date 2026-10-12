// Auto-seed demo security data for lab/demo mode.
//
// The backend falls back to an in-memory MongoDB when no local/remote Mongo is
// configured, which means data is lost on every restart. Without sample data the
// SOC dashboard (Active Alerts, High Severity, Open Incidents, Attack Types,
// Events Over Time, ...) looks empty.
//
// This seeder runs only when SEED_DEMO_DATA=true AND the Event collection is
// empty, so it never overwrites real/uploaded data.
//
// All generated records are flagged DEMO / simulated and contain no secrets.

const Event = require('../models/Event');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const Attacker = require('../models/Attacker');
const IOC = require('../models/IOC');

async function seedDemoDataIfEmpty() {
  const existing = await Event.countDocuments();
  if (existing > 0) return { seeded: false, events: existing };

  const ips = ['192.168.56.20', '192.168.56.21', '10.0.2.20', '10.0.2.21'];
  const services = ['SSH', 'HTTP', 'TCP'];
  const types = ['CONNECTION', 'FAILED_LOGIN', 'PORT_PROBE', 'WEB_PROBE', 'DISCONNECT'];

  const events = [];
  for (let i = 0; i < 120; i++) {
    const t = types[i % types.length];
    events.push({
      eventId: `EVT-DEMO-${String(i + 1).padStart(4, '0')}`,
      timestamp: new Date(Date.now() - i * 9 * 60000),
      sourceIP: ips[i % ips.length],
      sourcePort: 40000 + (i % 5000),
      destinationIP: '127.0.0.1',
      destinationPort: t === 'WEB_PROBE' ? 8080 : 2222,
      service: t === 'WEB_PROBE' ? 'HTTP' : services[i % services.length],
      protocol: 'TCP',
      eventType: t,
      username: t === 'FAILED_LOGIN' ? ['admin', 'root', 'test'][i % 3] : undefined,
      status: t === 'FAILED_LOGIN' ? 'failed' : 'connected',
      severity: t === 'FAILED_LOGIN' ? 'MEDIUM' : t === 'CONNECTION' ? 'INFO' : 'MEDIUM',
      sessionId: `SES-DEMO-${i}`,
      honeypotId: 'honeypot-01',
      simulated: true,
      metadata: { demoData: true, path: t === 'WEB_PROBE' ? ['/admin', '/.env', '/wp-admin'][i % 3] : undefined }
    });
  }
  await Event.insertMany(events);

  const alerts = [
    { alertId: 'ALT-DEMO-0001', timestamp: new Date(), sourceIP: '192.168.56.20', attackType: 'SSH Brute Force', severity: 'HIGH', description: 'DEMO DATA: 8 failed SSH logins within 60s', ruleName: 'SSH Brute Force', relatedEventIds: ['EVT-DEMO-0002'], confidence: 90, status: 'OPEN', riskScore: 70 },
    { alertId: 'ALT-DEMO-0002', timestamp: new Date(), sourceIP: '192.168.56.21', attackType: 'Port Scan', severity: 'MEDIUM', description: 'DEMO DATA: 5 ports probed', ruleName: 'Port Scan', relatedEventIds: ['EVT-DEMO-0003'], confidence: 80, status: 'INVESTIGATING', riskScore: 45 },
    { alertId: 'ALT-DEMO-0003', timestamp: new Date(), sourceIP: '10.0.2.20', attackType: 'Web Reconnaissance', severity: 'MEDIUM', description: 'DEMO DATA: /.env, /admin probed', ruleName: 'Web Reconnaissance', relatedEventIds: ['EVT-DEMO-0004'], confidence: 75, status: 'OPEN', riskScore: 40 }
  ];
  for (let i = 4; i <= 22; i++) {
    alerts.push({
      alertId: `ALT-DEMO-${String(i).padStart(4, '0')}`,
      timestamp: new Date(Date.now() - (i - 3) * 11 * 60000),
      sourceIP: ips[i % 4],
      attackType: ['SSH Brute Force', 'Port Scan', 'Web Reconnaissance', 'Multi-Stage Attack'][i % 4],
      severity: ['LOW', 'MEDIUM', 'HIGH'][i % 3],
      description: 'DEMO DATA seeded alert',
      ruleName: 'SSH Brute Force',
      relatedEventIds: [],
      confidence: 80,
      status: i % 3 === 0 ? 'RESOLVED' : 'OPEN',
      riskScore: 30 + i
    });
  }
  await Alert.insertMany(alerts);

  await Incident.insertMany([
    { incidentId: 'INC-DEMO-0001', title: 'DEMO DATA: Possible SSH intrusion from 192.168.56.20', description: 'Correlated brute force campaign', severity: 'HIGH', status: 'INVESTIGATING', sourceIPs: ['192.168.56.20'], relatedAlertIds: ['ALT-DEMO-0001'], relatedEventIds: ['EVT-DEMO-0002'], riskScore: 65, timeline: [{ message: 'First suspicious connection' }, { message: 'SSH brute force alert' }, { message: 'Incident created' }] },
    { incidentId: 'INC-DEMO-0002', title: 'DEMO DATA: Web recon from 10.0.2.20', severity: 'MEDIUM', status: 'OPEN', sourceIPs: ['10.0.2.20'], relatedAlertIds: ['ALT-DEMO-0003'], relatedEventIds: ['EVT-DEMO-0004'], riskScore: 40, timeline: [{ message: 'Web probes detected' }] }
  ]);

  await Attacker.insertMany(ips.map((ip, i) => ({
    sourceIP: ip, totalEvents: 30, failedLogins: 8 + i,
    firstSeen: new Date(Date.now() - 86400000), lastSeen: new Date(),
    highestSeverity: i === 0 ? 'HIGH' : 'MEDIUM', riskScore: 40 + i * 8,
    services: ['SSH', 'HTTP']
  })));

  await IOC.create([
    { type: 'IP', value: '192.168.56.20', description: 'DEMO DATA: repeat brute forcer', severity: 'HIGH', tags: ['brute-force'] },
    { type: 'USERNAME', value: 'root', description: 'DEMO DATA: commonly probed account', severity: 'MEDIUM', tags: ['ssh'] }
  ]);

  return { seeded: true, events: events.length, alerts: alerts.length, incidents: 2, attackers: ips.length };
}

module.exports = { seedDemoDataIfEmpty };
