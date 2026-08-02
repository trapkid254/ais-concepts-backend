'use strict';

const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

function generateTwoFactorSecret(email) {
  return speakeasy.generateSecret({
    name: `AIS Concepts (${email})`,
    length: 20
  });
}

async function generateQrCodeDataUrl(otpauthUrl) {
  return QRCode.toDataURL(otpauthUrl);
}

function verifyTotp(token, secret) {
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token: String(token).replace(/\s/g, ''),
    window: 1
  });
}

module.exports = { generateTwoFactorSecret, generateQrCodeDataUrl, verifyTotp };
