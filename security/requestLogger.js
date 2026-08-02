'use strict';

const { isProduction } = require('../config/env');
const logger = require('../logger');

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const entry = {
      ts: new Date().toISOString(),
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start,
      ip: req.ip,
      userAgent: req.headers['user-agent'] || ''
    };
    if (!isProduction || res.statusCode >= 400) {
      logger.info('HTTP request', entry);
    }
  });
  next();
}

module.exports = { requestLogger };
