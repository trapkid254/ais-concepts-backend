'use strict';

const models = require('../models');
const logger = require('../logger');

async function logAudit({ actorId, actorEmail, action, targetType, targetId, details, ip, userAgent }) {
  try {
    await models.AuditLog.create({
      actorId: actorId || null,
      actorEmail: actorEmail || '',
      action,
      targetType: targetType || '',
      targetId: targetId ? String(targetId) : '',
      details: details || {},
      ip: ip || '',
      userAgent: userAgent || ''
    });
  } catch (err) {
    logger.error('Audit log write failed', { error: err.message, stack: err.stack });
  }
}

function auditMiddleware(action, targetType) {
  return (req, res, next) => {
    const originalJson = res.json.bind(res);
    res.json = function (body) {
      if (res.statusCode < 400 && req.user) {
        logAudit({
          actorId: req.user.sub,
          actorEmail: req.user.email,
          action,
          targetType,
          targetId: req.params.id || req.params.userId || '',
          details: { method: req.method, path: req.originalUrl },
          ip: req.ip,
          userAgent: req.headers['user-agent']
        });
      }
      return originalJson(body);
    };
    next();
  };
}

module.exports = { logAudit, auditMiddleware };
