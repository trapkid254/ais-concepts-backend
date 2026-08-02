'use strict';

const models = require('../models');

async function revokeToken(jti, expiresAt) {
  if (!jti) return;
  await models.RevokedToken.findOneAndUpdate(
    { jti },
    { jti, expiresAt: expiresAt || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) },
    { upsert: true }
  );
}

async function isTokenRevoked(jti) {
  if (!jti) return false;
  const entry = await models.RevokedToken.findOne({ jti }).lean();
  return Boolean(entry);
}

async function cleanupExpiredTokens() {
  await models.RevokedToken.deleteMany({ expiresAt: { $lt: new Date() } });
}

module.exports = { revokeToken, isTokenRevoked, cleanupExpiredTokens };
