'use strict';

const nodemailer = require('nodemailer');
const { APP_URL } = require('../config/env');
const logger = require('../logger');

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return null;
  }
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
  return transporter;
}

async function sendEmail({ to, subject, text, html }) {
  const tx = getTransporter();
  if (!tx) {
    logger.warn('Email skipped - SMTP not configured', { to, subject });
    return false;
  }
  await tx.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    text,
    html
  });
  return true;
}

async function sendVerificationEmail(user, token) {
  const link = `${APP_URL}/verify-email.html?token=${encodeURIComponent(token)}&email=${encodeURIComponent(user.email)}`;
  return sendEmail({
    to: user.email,
    subject: 'Verify your AIS Concepts account',
    text: `Hello ${user.name || user.email},\n\nPlease verify your email by visiting:\n${link}\n\nThis link expires in 24 hours.`,
    html: `<p>Hello ${user.name || user.email},</p><p>Please <a href="${link}">verify your email address</a>.</p><p>This link expires in 24 hours.</p>`
  });
}

async function sendPasswordResetEmail(user, token) {
  const link = `${APP_URL}/reset-password.html?token=${encodeURIComponent(token)}&email=${encodeURIComponent(user.email)}`;
  return sendEmail({
    to: user.email,
    subject: 'Reset your AIS Concepts password',
    text: `Hello ${user.name || user.email},\n\nReset your password by visiting:\n${link}\n\nThis link expires in 1 hour. If you did not request this, ignore this email.`,
    html: `<p>Hello ${user.name || user.email},</p><p><a href="${link}">Reset your password</a>.</p><p>This link expires in 1 hour.</p>`
  });
}

module.exports = { sendEmail, sendVerificationEmail, sendPasswordResetEmail, getTransporter };
