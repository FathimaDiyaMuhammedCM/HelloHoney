const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

async function run() {
  const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/hellohoney';
  try { await mongoose.connect(uri); console.log('[SEED] connected', uri); }
  catch (e) {
    console.log('[SEED] local mongo unavailable, using in-memory');
    const { MongoMemoryServer } = require('mongodb-memory-server');
    const mem = await MongoMemoryServer.create();
    await mongoose.connect(mem.getUri());
  }
  const User = require('../backend/models/User');
  const Event = require('../backend/models/Event');
  const Alert = require('../backend/models/Alert');
  const Incident = require('../backend/models/Incident');
  const Attacker = require('../backend/models/Attacker');
  const DetectionRule = require('../backend/models/DetectionRule');
  const IOC = require('../backend/models/IOC');

  await Promise.all([User.deleteMany({}), Event.deleteMany({}), Alert.deleteMany({}), Incident.deleteMany({}), Attacker.deleteMany({}), DetectionRule.deleteMany({}), IOC.deleteMany({})]);

  await User.create([
    { name: 'Admin', email: 'admin@hellohoney.local', passwordHash: await bcrypt.hash('Admin123!', 10), role: 'ADMIN' },
    { name: 'Analyst', email: 'analyst@hellohoney.local', passwordHash: await bcrypt.hash('Analyst123!', 10), role: 'ANALYST' },
    { name: 'Viewer', email: 'viewer@hellohoney.local', passwordHash: await bcrypt.hash('Viewer123!', 10), role: 'VIEWER' }
  ]);

  await DetectionRule.insertMany([
    { name: 'SSH Brute Force', description: 'More than 5 failed SSH logins from same IP within 60s', eventType: 'FAILED_LOGIN', threshold: 5, timeWindow: 60, severity: 'HIGH', enabled: true, ruleType: 'BRUTE_FORCE', attackType: 'SSH Brute Force', autoCreateIncident: true },
    { name: 'Port Scan', description: 'Connections to 3+ distinct ports within 60s', eventType: 'PORT_PROBE', threshold: 3, timeWindow: 60, severity: 'MEDIUM', enabled: true, ruleType: 'PORT_SCAN', attackType: 'Port Scan' },
    { name: 'Web Reconnaissance', description: '3+ suspicious HTTP probes within 120s', eventType: 'WEB_PROBE', threshold: 3, timeWindow: 120, severity: 'MEDIUM', enabled: true, ruleType: 'WEB_RECON', attackType: 'Web Reconnaissance' },
    { name: 'Rapid Connections', description: '10+ connections within 30s', eventType: 'CONNECTION', threshold: 10, timeWindow: 30, severity: 'MEDIUM', enabled: true, ruleType: 'RAPID_CONN', attackType: 'Repeated Connection Activity' },
    { name: 'Multi-Stage Attack', description: 'Probe + SSH + failed logins within 10 min', eventType: 'FAILED_LOGIN', threshold: 3, timeWindow: 600, severity: 'HIGH', enabled: true, ruleType: 'MULTI_STAGE', attackType: 'Multi-Stage Attack', autoCreateIncident: true }
  ]);

  const ips = ['192.168.56.20', '192.168.56.21', '10.0.2.20', '10.0.2.21'];
  const services = ['SSH', 'HTTP', 'TCP'];
  const types = ['CONNECTION', 'FAILED_LOGIN', 'PORT_PROBE', 'WEB_PROBE', 'DISCONNECT'];
  const evs = [];
  let n = 0;
  for (let i = 0; i < 120; i++) {
    const ip = ips[i % ips.length];
    const t = types[i % types.length];
    n++;
    evs.push({
      eventId: `EVT-DEMO-${String(n).padStart(4, '0')}`,
      timestamp: new Date(Date.now() - i * 9 * 60000),
      sourceIP: ip, sourcePort: 40000 + (i % 5000),
      destinationIP: '127.0.0.1', destinationPort: t === 'WEB_PROBE' ? 8080 : 2222,
      service: t === 'WEB_PROBE' ? 'HTTP' : services[i % services.length],
      protocol: 'TCP', eventType: t,
      username: t === 'FAILED_LOGIN' ? ['admin', 'root', 'test'][i % 3] : undefined,
      status: t === 'FAILED_LOGIN' ? 'failed' : 'connected',
      severity: t === 'FAILED_LOGIN' ? 'MEDIUM' : t === 'CONNECTION' ? 'INFO' : 'MEDIUM',
      sessionId: `SES-DEMO-${i}`, honeypotId: 'honeypot-01', simulated: true,
      metadata: { demoData: true, path: t === 'WEB_PROBE' ? ['/admin', '/.env', '/wp-admin'][i % 3] : undefined }
    });
  }
  await Event.insertMany(evs);

  await Alert.insertMany([
    { alertId: 'ALT-DEMO-0001', timestamp: new Date(), sourceIP: '192.168.56.20', attackType: 'SSH Brute Force', severity: 'HIGH', description: 'DEMO DATA: 8 failed SSH logins within 60s', ruleName: 'SSH Brute Force', relatedEventIds: ['EVT-DEMO-0001'], confidence: 90, status: 'OPEN', riskScore: 70 },
    { alertId: 'ALT-DEMO-0002', timestamp: new Date(), sourceIP: '192.168.56.21', attackType: 'Port Scan', severity: 'MEDIUM', description: 'DEMO DATA: 5 ports probed', ruleName: 'Port Scan', relatedEventIds: ['EVT-DEMO-0002'], confidence: 80, status: 'INVESTIGATING', riskScore: 45 },
    { alertId: 'ALT-DEMO-0003', timestamp: new Date(), sourceIP: '10.0.2.20', attackType: 'Web Reconnaissance', severity: 'MEDIUM', description: 'DEMO DATA: /.env, /admin probed', ruleName: 'Web Reconnaissance', relatedEventIds: [], confidence: 75, status: 'OPEN', riskScore: 40 }
  ]);
  for (let i = 4; i <= 22; i++) {
    await Alert.create({ alertId: `ALT-DEMO-${String(i).padStart(4, '0')}`, sourceIP: ips[i % 4], attackType: ['SSH Brute Force', 'Port Scan', 'Web Reconnaissance'][i % 3], severity: ['LOW', 'MEDIUM', 'HIGH'][i % 3], description: 'DEMO DATA seeded alert', ruleName: 'SSH Brute Force', relatedEventIds: [], status: i % 3 === 0 ? 'RESOLVED' : 'OPEN', riskScore: 30 + i });
  }
  await Incident.insertMany([
    { incidentId: 'INC-DEMO-0001', title: 'DEMO DATA: Possible SSH intrusion from 192.168.56.20', description: 'Correlated brute force campaign', severity: 'HIGH', status: 'INVESTIGATING', sourceIPs: ['192.168.56.20'], relatedAlertIds: ['ALT-DEMO-0001'], relatedEventIds: ['EVT-DEMO-0001'], riskScore: 65, timeline: [{ message: 'First suspicious connection' }, { message: 'SSH brute force alert' }, { message: 'Incident created' }] },
    { incidentId: 'INC-DEMO-0002', title: 'DEMO DATA: Web recon from 10.0.2.20', severity: 'MEDIUM', status: 'OPEN', sourceIPs: ['10.0.2.20'], relatedAlertIds: ['ALT-DEMO-0003'], relatedEventIds: [], riskScore: 40, timeline: [{ message: 'Web probes detected' }] }
  ]);
  await Attacker.insertMany(ips.map((ip, i) => ({ sourceIP: ip, totalEvents: 30, failedLogins: 8 + i, firstSeen: new Date(Date.now() - 86400000), lastSeen: new Date(), highestSeverity: i === 0 ? 'HIGH' : 'MEDIUM', riskScore: 40 + i * 8, services: ['SSH', 'HTTP'] })));
  await IOC.create([{ type: 'IP', value: '192.168.56.20', description: 'DEMO DATA: repeat brute forcer', severity: 'HIGH', tags: ['brute-force'] }, { type: 'USERNAME', value: 'root', description: 'DEMO DATA: commonly probed account', severity: 'MEDIUM', tags: ['ssh'] }]);
  console.log('[SEED] Demo data inserted (DEMO DATA).');
  await mongoose.disconnect();
}
run().catch(e => { console.error(e); process.exit(1); });
