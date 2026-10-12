const jwt = require('jsonwebtoken');

// Fail fast if JWT_SECRET is not configured — never fall back to a hardcoded secret.
function getSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret === 'hellohoney_lab_secret_change_me') {
    throw new Error('JWT_SECRET environment variable must be set to a strong random value');
  }
  return secret;
}

function signToken(user) {
  return jwt.sign(
    { id: user._id.toString(), email: user.email, role: user.role, name: user.name },
    getSecret(),
    { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
  );
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, getSecret());
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden: insufficient role' });
    next();
  };
}

module.exports = { signToken, authRequired, requireRoles };
