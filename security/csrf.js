'use strict';

const { doubleCsrf } = require('csrf-csrf');
const { isProduction } = require('../config/env');

const csrfSecret = process.env.CSRF_SECRET || process.env.JWT_SECRET || 'csrf-dev-secret-change-me';

const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => csrfSecret,
  cookieName: isProduction ? '__Host-ais.x-csrf-token' : 'ais.x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: isProduction ? 'strict' : 'lax',
    secure: isProduction,
    path: '/'
  },
  getTokenFromRequest: (req) =>
    req.headers['x-csrf-token'] || req.headers['xsrf-token'] || req.body?._csrf
});

function csrfProtection(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) return next();
  return doubleCsrfProtection(req, res, next);
}

module.exports = { generateToken, csrfProtection };
