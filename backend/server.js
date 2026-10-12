require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');
const connectDB = require('./config/db');
const api = require('./routes/api');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const detection = require('./services/detectionService');
const demoData = require('./services/demoDataService');

const path = require('path');
const fs = require('fs');

const app = express();

// SECURITY (API8/API3): use the "simple" query parser so query strings never
// deserialize into nested objects — blocks NoSQL operator injection like
// ?sourceIP[$ne]=x from becoming { sourceIP: { $ne: 'x' } } in Mongo filters.
app.set('query parser', 'simple');
const server = http.createServer(app);

const frontendOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173').split(',')
  .map(s => s.trim())
  .filter(Boolean);

const isOriginAllowed = (origin) => {
  if (!origin) return false;
  if (frontendOrigins.includes('*')) return true;
  return frontendOrigins.includes(origin);
};

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => callback(null, isOriginAllowed(origin)),
    methods: ['GET', 'POST', 'PATCH'],
    credentials: true
  }
});
detection.setIO(io);

// Authenticate socket connections using JWT (same token as HTTP API)
const jwt = require('jsonwebtoken');
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace('Bearer ', '');
  if (!token) return next(new Error('Authentication required'));
  try {
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    next(new Error('Invalid or expired token'));
  }
});

io.on('connection', (socket) => {
  socket.emit('system', { message: 'connected to HelloHoney realtime channel' });
});

app.use(helmet());
app.use(cors({ origin: (origin, callback) => callback(null, isOriginAllowed(origin)), credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));
app.use(rateLimit({ windowMs: 60 * 1000, max: 100 }));

app.use('/api', api);

// Serve frontend static assets if built
const frontendDist = process.env.FRONTEND_DIST || path.join(__dirname, '..', 'frontend', 'dist');
if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
  app.get('*', (req, res) => {
    res.sendFile(path.join(frontendDist, 'index.html'));
  });
} else {
  app.get('/', (req, res) => res.json({ service: 'HelloHoney API', lab: true }));
}

app.use(notFound);
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

(async () => {
  await connectDB();
  await detection.ensureDefaultRules();
  // Seed default users only when explicitly enabled (lab mode).
  // Passwords come from env vars — never hardcoded in source.
  const User = require('./models/User');
  const bcrypt = require('bcryptjs');
  const SEED_DEFAULT_USERS = process.env.SEED_DEFAULT_USERS === 'true';
  const ADMIN_PW = process.env.SEED_ADMIN_PASSWORD;
  const ANALYST_PW = process.env.SEED_ANALYST_PASSWORD;
  const VIEWER_PW = process.env.SEED_VIEWER_PASSWORD;

  if (SEED_DEFAULT_USERS && ADMIN_PW && ANALYST_PW && VIEWER_PW) {
    if ((await User.countDocuments()) === 0) {
      await User.create({ name: 'Admin', email: 'admin@hellohoney.local', passwordHash: await bcrypt.hash(ADMIN_PW, 12), role: 'ADMIN' });
      await User.create({ name: 'Analyst', email: 'analyst@hellohoney.local', passwordHash: await bcrypt.hash(ANALYST_PW, 12), role: 'ANALYST' });
      await User.create({ name: 'Viewer', email: 'viewer@hellohoney.local', passwordHash: await bcrypt.hash(VIEWER_PW, 12), role: 'VIEWER' });
      console.log('[AUTH] Seeded default users from environment configuration');
    }
  } else if ((await User.countDocuments()) === 0) {
    console.warn('[AUTH] No users exist and seeding is disabled. Set SEED_DEFAULT_USERS=true with SEED_*_PASSWORD env vars to create initial users.');
  }

  // Seed demo security data (events/alerts/incidents/attackers) so the SOC
  // dashboard is populated. Only when explicitly enabled and the DB is empty —
  // never overwrites real or uploaded data.
  if (process.env.SEED_DEMO_DATA === 'true') {
    try {
      const r = await demoData.seedDemoDataIfEmpty();
      if (r.seeded) console.log(`[DEMO] Seeded ${r.events} events, ${r.alerts} alerts, ${r.incidents} incidents, ${r.attackers} attackers`);
      else console.log(`[DEMO] Skipped demo seeding (${r.events} events already present)`);
    } catch (e) {
      console.warn('[DEMO] Demo data seeding failed:', e.message);
    }
  }

  server.listen(PORT, () => console.log(`[API] HelloHoney backend on http://localhost:${PORT} (lab mode)`));
})();

module.exports = app;
