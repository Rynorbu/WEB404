'use strict';

/**
 * A tiny in-memory user directory. Fictional accounts only; there is no real
 * database and no real people here.
 *
 * Passwords are stored as salted SHA-256 hashes rather than plaintext — not
 * because this demo is about password storage, but so the project never shows
 * a plaintext password sitting in source. (Hashing is covered properly in the
 * other assignments; here it is just good hygiene.)
 *
 * The important field for this assignment is `role`. The whole point of the
 * attacks is to get the server to treat an attacker as `role: "admin"` without
 * knowing an admin's password — purely by forging or tampering with a token.
 */
const crypto = require('crypto');

function hash(password, salt) {
  return crypto.createHash('sha256').update(`${salt}:${password}`).digest('hex');
}

// username -> { salt, hash, role, displayName }
const USERS = new Map();

function addUser(username, password, role, displayName) {
  const salt = crypto.randomBytes(8).toString('hex');
  USERS.set(username, { salt, hash: hash(password, salt), role, displayName });
}

// Seed the fictional directory. These credentials are printed on the login
// page on purpose — this is a lab, and the login step is not the subject.
addUser('alice', 'password123', 'user', 'Alice Dorji');
addUser('admin', 'S3cureAdminPass!', 'admin', 'Site Administrator');

/**
 * Check a username/password pair. Returns the public user profile (no secrets)
 * on success, or null on failure.
 */
function authenticate(username, password) {
  const record = USERS.get(username);
  if (!record) return null;
  if (hash(password, record.salt) !== record.hash) return null;
  return { username, role: record.role, displayName: record.displayName };
}

function getUser(username) {
  const record = USERS.get(username);
  if (!record) return null;
  return { username, role: record.role, displayName: record.displayName };
}

module.exports = { authenticate, getUser };
