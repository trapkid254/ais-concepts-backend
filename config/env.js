'use strict';

const crypto = require('crypto');

const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';
const isDevelopment = NODE_ENV === 'development';

const WEAK_JWT_SECRETS = new Set([
  'dev-secret-change-me',
  'change-this-to-a-long-random-string-in-production',
  'your-secret-key',
  'secret'
]);

function validateJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    if (isProduction) {
      console.error('FATAL: JWT_SECRET is required in production.');
      process.exit(1);
    }
    console.warn('⚠️  JWT_SECRET not set — using ephemeral dev secret (tokens invalid after restart).');
    return crypto.randomBytes(64).toString('hex');
  }
  if (secret.length < 32) {
    if (isProduction) {
      console.error('FATAL: JWT_SECRET must be at least 32 characters in production.');
      process.exit(1);
    }
    console.warn('⚠️  JWT_SECRET is too short for production use.');
  }
  if (WEAK_JWT_SECRETS.has(secret)) {
    if (isProduction) {
      console.error('FATAL: JWT_SECRET is a known weak default. Generate a strong random secret.');
      process.exit(1);
    }
    console.warn('⚠️  JWT_SECRET is a known weak default.');
  }
  return secret;
}

function getMongoOptions() {
  const uri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';
  const opts = {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
  };
  
  // TLS configuration for production
  const forceTls = process.env.MONGODB_TLS === 'true';
  const isAtlas = uri.includes('mongodb+srv://') || uri.includes('mongodb.net');
  
  // Enable TLS in production or when explicitly requested
  if (isProduction && (forceTls || isAtlas)) {
    opts.tls = true;
    // Only allow invalid certificates in development or explicitly requested
    if (!isProduction || process.env.MONGODB_TLS_ALLOW_INVALID === 'true') {
      opts.tlsAllowInvalidCertificates = true;
    }
  }
  
  // Warn if using MongoDB without TLS in production
  if (isProduction && !opts.tls && !isAtlas) {
    console.warn('⚠️  MongoDB connection is not using TLS in production. Set MONGODB_TLS=true to enable encryption.');
  }
  
  return { uri, opts };
}

module.exports = {
  NODE_ENV,
  isProduction,
  isDevelopment,
  validateJwtSecret,
  getMongoOptions,
  APP_URL: process.env.APP_URL || (isProduction ? 'https://aisconcepts.com' : 'http://localhost:3000'),
  API_VERSION: 'v1'
};
