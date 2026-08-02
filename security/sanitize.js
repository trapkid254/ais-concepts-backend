'use strict';

function stripHtml(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/<[^>]*>/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .trim();
}

function sanitizeObject(obj, depth = 0) {
  if (depth > 10) return obj;
  if (obj == null) return obj;
  if (typeof obj === 'string') return stripHtml(obj);
  if (Array.isArray(obj)) return obj.map((item) => sanitizeObject(item, depth + 1));
  if (typeof obj === 'object') {
    const out = {};
    for (const [key, val] of Object.entries(obj)) {
      if (key.startsWith('$') || key.includes('.')) continue;
      out[key] = sanitizeObject(val, depth + 1);
    }
    return out;
  }
  return obj;
}

function sanitizeInput(req, res, next) {
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeObject(req.body);
  }
  if (req.query && typeof req.query === 'object') {
    req.query = sanitizeObject(req.query);
  }
  next();
}

module.exports = { stripHtml, sanitizeObject, sanitizeInput };
