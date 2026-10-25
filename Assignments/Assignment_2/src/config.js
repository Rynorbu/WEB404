'use strict';

/**
 * Central configuration for the SecureBank demo application.
 *
 * The single most important switch here is `csrfProtection`. It is driven by
 * the CSRF_PROTECTION environment variable so that the EXACT SAME codebase can
 * be started in two modes:
 *
 *   CSRF_PROTECTION=off  -> the vulnerable version (no token is checked)
 *   CSRF_PROTECTION=on   -> the protected version (synchronizer token required)
 *
 * This lets the report compare the two versions fairly: the only thing that
 * changes between "vulnerable" and "protected" is whether the server demands a
 * valid CSRF token, not the rest of the application.
 */
const path = require('path');

module.exports = {
  // Port the legitimate bank runs on. The attacker page runs on a DIFFERENT
  // port (see attacker/server.js). Different ports = different ORIGIN, which is
  // what makes the request a genuine cross-origin (CSRF) request.
  port: Number(process.env.PORT) || 3000,

  // Flip the whole security posture of the app from one environment variable.
  csrfProtection: process.env.CSRF_PROTECTION === 'on',

  // Name of the cookie that carries the session id.
  sessionCookieName: 'sid',

  // Starting balance (in Ngultrum) for every freshly logged-in demo user.
  startingBalance: 10000,

  publicDir: path.join(__dirname, '..', 'public'),
};
