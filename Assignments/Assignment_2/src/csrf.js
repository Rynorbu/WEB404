'use strict';

const crypto = require('crypto');

/**
 * CSRF defence: the Synchronizer Token Pattern.
 * =============================================
 *
 * The root cause of CSRF is that the browser automatically attaches the
 * victim's session cookie to EVERY request to the bank, including requests
 * triggered by a malicious third-party page. The cookie proves "this request
 * comes from a browser that is logged in", but it does NOT prove "the logged-in
 * user actually intended this request".
 *
 * The synchronizer token pattern adds that missing proof of intent:
 *
 *   1. When the session is created, the server generates a random secret token
 *      and stores it IN THE SESSION (server side). See src/session.js.
 *   2. The server embeds that token in every legitimate form it sends to the
 *      user (as a hidden field), so only pages served by the bank itself can
 *      know the token.
 *   3. On every state-changing request the server compares the token submitted
 *      in the request body against the token stored in the session.
 *
 * Why this defeats CSRF:
 *   - A cross-origin attacker page can make the browser SEND the cookie, but it
 *     cannot READ the token out of the bank's pages. The Same-Origin Policy
 *     stops the attacker's JavaScript from reading responses from another
 *     origin. Without the token, the forged request is rejected.
 */

/** Generate a fresh, unguessable CSRF token (256 bits of randomness). */
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Constant-time comparison of the expected and submitted tokens.
 *
 * We use crypto.timingSafeEqual rather than `===` so that the time taken to
 * compare does not leak how many leading characters were correct. A plain
 * string comparison can, in principle, be used as a timing oracle to recover
 * the token one character at a time.
 */
function isValidToken(expected, submitted) {
  // Reject anything missing or not a string before we touch the buffers.
  if (typeof expected !== 'string' || typeof submitted !== 'string') return false;
  if (expected.length === 0 || submitted.length === 0) return false;

  const a = Buffer.from(expected);
  const b = Buffer.from(submitted);

  // timingSafeEqual throws if the buffers differ in length, so guard first.
  if (a.length !== b.length) return false;

  return crypto.timingSafeEqual(a, b);
}

module.exports = { generateToken, isValidToken };
