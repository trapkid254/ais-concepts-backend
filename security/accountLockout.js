'use strict';

const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_DURATIONS_MS = [15 * 60 * 1000, 30 * 60 * 1000, 60 * 60 * 1000];

function isAccountLocked(user) {
  if (!user.lockUntil) return false;
  return new Date(user.lockUntil) > new Date();
}

function getLockoutRemainingMs(user) {
  if (!user.lockUntil) return 0;
  const remaining = new Date(user.lockUntil) - Date.now();
  return remaining > 0 ? remaining : 0;
}

async function recordFailedLogin(user) {
  user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
  if (user.failedLoginAttempts >= LOCKOUT_THRESHOLD) {
    const tier = Math.min(
      Math.floor((user.failedLoginAttempts - LOCKOUT_THRESHOLD) / LOCKOUT_THRESHOLD),
      LOCKOUT_DURATIONS_MS.length - 1
    );
    user.lockUntil = new Date(Date.now() + LOCKOUT_DURATIONS_MS[tier]);
  }
  await user.save();
}

async function resetLoginAttempts(user) {
  user.failedLoginAttempts = 0;
  user.lockUntil = null;
  await user.save();
}

module.exports = {
  LOCKOUT_THRESHOLD,
  isAccountLocked,
  getLockoutRemainingMs,
  recordFailedLogin,
  resetLoginAttempts
};
