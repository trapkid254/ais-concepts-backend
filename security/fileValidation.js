'use strict';

const { fileTypeFromBuffer } = require('file-type');

const ALLOWED_IMAGE_MIMES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif'
]);

const ALLOWED_DOCUMENT_MIMES = new Set([
  'application/pdf',
  'image/jpeg',
  'image/png',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
]);

async function validateImageBuffer(buffer, maxBytes) {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    return { ok: false, error: 'No file data provided' };
  }
  if (maxBytes && buffer.length > maxBytes) {
    return { ok: false, error: `File exceeds maximum size of ${Math.round(maxBytes / 1024 / 1024)}MB` };
  }
  const detected = await fileTypeFromBuffer(buffer);
  if (!detected || !ALLOWED_IMAGE_MIMES.has(detected.mime)) {
    return { ok: false, error: 'Invalid image type. Allowed: JPEG, PNG, WebP, GIF' };
  }
  return { ok: true, mime: detected.mime };
}

async function validateDocumentBuffer(buffer, maxBytes) {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    return { ok: false, error: 'No file data provided' };
  }
  if (maxBytes && buffer.length > maxBytes) {
    return { ok: false, error: `File exceeds maximum size of ${Math.round(maxBytes / 1024 / 1024)}MB` };
  }
  const detected = await fileTypeFromBuffer(buffer);
  if (!detected || !ALLOWED_DOCUMENT_MIMES.has(detected.mime)) {
    return { ok: false, error: 'Invalid document type. Allowed: PDF, JPEG, PNG, DOC, DOCX' };
  }
  return { ok: true, mime: detected.mime };
}

function validateBase64DataUrl(dataUrl, allowedPrefixes) {
  if (!dataUrl || typeof dataUrl !== 'string') {
    return { ok: false, error: 'Invalid file data' };
  }
  const match = dataUrl.match(/^data:([^;]+);base64,/);
  if (!match) return { ok: false, error: 'Invalid data URL format' };
  const mime = match[1].toLowerCase();
  if (allowedPrefixes && !allowedPrefixes.includes(mime)) {
    return { ok: false, error: `File type ${mime} is not allowed` };
  }
  return { ok: true, mime };
}

module.exports = {
  validateImageBuffer,
  validateDocumentBuffer,
  validateBase64DataUrl,
  ALLOWED_IMAGE_MIMES,
  ALLOWED_DOCUMENT_MIMES
};
