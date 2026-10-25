'use strict';

/**
 * Central configuration for the JWT authentication demo.
 *
 * The single most important switch here is `secure`. It is driven by the
 * JWT_SECURE environment variable so that the EXACT SAME codebase can be
 * started in two modes:
 *
 *   JWT_SECURE=off  -> the vulnerable version. The token verifier trusts the
 *                      `alg` header the token itself carries, accepts the
 *                      `none` algorithm (unsigned tokens), compares signatures
 *                      with a non-constant-time string equality, and never
 *                      checks expiry. The signing secret is a tiny dictionary
 *                      word. This is deliberately broken so the attacks work.
 *
 *   JWT_SECURE=on   -> the hardened version. The verifier pins a single
 *                      expected algorithm (HS256), rejects `none` outright,
 *                      recomputes the HMAC and compares it in constant time,
 *                      and enforces exp / nbf / iss / aud. The secret is a long
 *                      random key read from the environment.
 *
 * Only `src/jwt.js` behaves differently between the two modes; everything else
 * in the application is shared, so the report can compare the two fairly.
 */
const crypto = require('crypto');
const path = require('path');

const secure = process.env.JWT_SECURE === 'on';

/**
 * The HMAC signing secret.
 *
 * Vulnerable mode uses the laughably weak secret `"secret"` — a word that sits
 * near the top of every JWT cracking wordlist (this is exactly how real weak
 * secrets get brute-forced). Secure mode uses a 32-byte random key supplied in
 * JWT_SECRET, or generates one on boot if the variable is absent, so it can
 * never be guessed or cracked offline.
 */
const secret = secure
  ? (process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'))
  : 'secret';

module.exports = {
  // Port the app runs on. Everything is local; nothing leaves the machine.
  port: Number(process.env.PORT) || 4000,

  // Flip the whole security posture of the app from one environment variable.
  // Anything other than the literal string "on" is treated as vulnerable, so a
  // forgotten/empty variable fails to the version the lab starts from.
  secure,

  // The shared HMAC secret described above.
  secret,

  // Standard registered claims the secure verifier checks. The vulnerable
  // verifier ignores these entirely.
  issuer: 'drukpass.local',
  audience: 'drukpass.webapp',

  // How long a freshly issued token stays valid (seconds). Short on purpose so
  // the expiry demo does not require a long wait.
  tokenTtlSeconds: 15 * 60,

  // Name of the cookie that carries the JWT.
  tokenCookieName: 'access_token',

  publicDir: path.join(__dirname, '..', 'public'),
};
