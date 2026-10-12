const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { signToken } = require('../middleware/auth');
const audit = require('../utils/audit');

async function register(req, res, next) {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'name, email, password required' });
    // Enforce password strength: minimum 8 characters with mixed complexity
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }
    if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
      return res.status(400).json({ error: 'Password must contain uppercase, lowercase, and a number' });
    }
    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Email already registered' });
    const passwordHash = await bcrypt.hash(password, 12);
    // SECURITY: Never accept role from client input — new users are always VIEWER.
    // Privileged roles must be promoted by an existing ADMIN.
    const user = await User.create({ name, email: email.toLowerCase(), passwordHash, role: 'VIEWER' });
    await audit({ userName: user.name, userId: String(user._id), action: 'REGISTER', resource: 'User', resourceId: String(user._id), sourceIP: req.ip });
    res.json({ token: signToken(user), user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (e) { next(e); }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body || {};
    // SECURITY: reject non-string credentials (blocks NoSQL operator objects
    // like { $ne: null } and prevents .toLowerCase() type-confusion 500s)
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'email and password must be strings' });
    }
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      await audit({ userName: email, action: 'FAILED_LOGIN', resource: 'Auth', details: 'unknown email', sourceIP: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      await audit({ userName: user.name, userId: String(user._id), action: 'FAILED_LOGIN', resource: 'Auth', sourceIP: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    user.lastLogin = new Date();
    await user.save();
    await audit({ userName: user.name, userId: String(user._id), action: 'LOGIN', resource: 'Auth', sourceIP: req.ip });
    res.json({ token: signToken(user), user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (e) { next(e); }
}

async function me(req, res) {
  res.json({ user: req.user });
}

module.exports = { register, login, me };
