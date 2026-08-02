const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

function signToken(userDoc) {
  const jti = crypto.randomBytes(16).toString('hex');
  return jwt.sign(
    {
      sub: String(userDoc._id),
      email: userDoc.email,
      role: userDoc.role,
      name: userDoc.name || '',
      jti: jti
    },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

function verifyToken(token) {
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : req.cookies && req.cookies.token;
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // Normalize aliases used across older handlers
  payload._id = payload.sub;
  payload.id = payload.sub;
  req.user = payload;
  req.authToken = token;
  next();
}

function optionalAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  req.user = token ? verifyToken(token) : null;
  next();
}

module.exports = { signToken, verifyToken, authMiddleware, optionalAuth, JWT_SECRET };
