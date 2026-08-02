'use strict';

const { isProduction } = require('../config/env');

function httpsRedirect(req, res, next) {
  if (!isProduction) return next();
  const proto = req.headers['x-forwarded-proto'];
  if (proto && proto !== 'https') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
}

module.exports = { httpsRedirect };
