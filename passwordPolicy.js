/** Password: 8–16 chars, upper, lower, digit, special */
function validatePasswordPolicy(password) {
  const p = password || '';
  if (p.length < 8 || p.length > 16) {
    return 'Password must be between 8 and 16 characters.';
  }
  if (!/[a-z]/.test(p)) return 'Password must include a lowercase letter.';
  if (!/[A-Z]/.test(p)) return 'Password must include an uppercase letter.';
  if (!/[0-9]/.test(p)) return 'Password must include a number.';
  if (!/[^A-Za-z0-9]/.test(p)) return 'Password must include a special character.';
  return null;
}

module.exports = { validatePasswordPolicy };
