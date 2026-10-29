'use strict';

const { doubleCsrf } = require('csrf-csrf');
const { isProduction } = require('../config/env');

const csrfSecret = process.env.CSRF_SECRET || process.env.JWT_SECRET || 'csrf-dev-secret-change-me';

let generateToken, doubleCsrfProtection;

try {
  const csrfConfig = doubleCsrf({
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
  generateToken = csrfConfig.generateToken;
  doubleCsrfProtection = csrfConfig.doubleCsrfProtection;
} catch (error) {
  console.error('CSRF initialization failed:', error.message);
  // Fallback: provide no-op functions if CSRF fails to initialize
  generateToken = () => 'fallback-csrf-token';
  doubleCsrfProtection = (req, res, next) => next();
}

function csrfProtection(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) return next();
  // Exempt login endpoint from CSRF protection
  if (req.path === '/api/auth/login') return next();
  // Exempt register endpoints from CSRF protection
  if (req.path === '/api/auth/register' || req.path === '/api/auth/register-employee') return next();
  return doubleCsrfProtection(req, res, next);
}

module.exports = { generateToken, csrfProtection };
