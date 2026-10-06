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

const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

const frontendOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173,http://localhost:5000')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const isOriginAllowed = (origin) => {
  if (!origin || frontendOrigins.includes('*')) return true;
  return frontendOrigins.includes(origin) || true; // allow same origin & cloud origins
};

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => callback(null, isOriginAllowed(origin)),
    methods: ['GET', 'POST', 'PATCH'],
    credentials: true
  }
});
detection.setIO(io);

io.on('connection', (socket) => {
  socket.emit('system', { message: 'connected to HelloHoney realtime channel' });
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: (origin, callback) => callback(null, isOriginAllowed(origin)), credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));
app.use(rateLimit({ windowMs: 60 * 1000, max: 600 }));

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
  // ensure default admin user
  const User = require('./models/User');
  const bcrypt = require('bcryptjs');
  if ((await User.countDocuments()) === 0) {
    await User.create({ name: 'Admin', email: 'admin@hellohoney.local', passwordHash: await bcrypt.hash('Admin123!', 10), role: 'ADMIN' });
    await User.create({ name: 'Analyst', email: 'analyst@hellohoney.local', passwordHash: await bcrypt.hash('Analyst123!', 10), role: 'ANALYST' });
    await User.create({ name: 'Viewer', email: 'viewer@hellohoney.local', passwordHash: await bcrypt.hash('Viewer123!', 10), role: 'VIEWER' });
    console.log('[AUTH] Seeded default users: admin@hellohoney.local / analyst@hellohoney.local / viewer@hellohoney.local');
  }
  server.listen(PORT, () => console.log(`[API] HelloHoney backend on http://localhost:${PORT} (lab mode)`));
})();

module.exports = app;
