'use strict';

const { isProduction, isDevelopment } = require('../config/env');

const LOCALHOST_ORIGINS = [
  'http://localhost:5502',
  'http://127.0.0.1:5502',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];

const DEFAULT_PRODUCTION_ORIGINS = [
  'https://aisconcepts.com',
  'https://www.aisconcepts.com',
  'https://ais-concepts.netlify.app',
  'https://ais-concepts-fronted.vercel.app'
];

function resolveCorsOrigin() {
  const raw = process.env.CLIENT_ORIGIN;
  let origins = [];

  if (raw && raw !== 'true') {
    origins = raw.split(',').map((s) => s.trim()).filter(Boolean);
  } else if (isProduction) {
    origins = [...DEFAULT_PRODUCTION_ORIGINS];
  }

  if (isDevelopment) {
    origins = [...new Set([...origins, ...LOCALHOST_ORIGINS])];
  }

  if (origins.length === 0) {
    origins = isProduction ? DEFAULT_PRODUCTION_ORIGINS : LOCALHOST_ORIGINS;
  }

  return [...new Set(origins)];
}

function corsOriginValidator(origin, callback) {
  const allowed = resolveCorsOrigin();
  if (!origin || allowed.includes(origin)) {
    callback(null, true);
  } else {
    callback(new Error('Not allowed by CORS'));
  }
}

module.exports = { resolveCorsOrigin, corsOriginValidator, LOCALHOST_ORIGINS };
