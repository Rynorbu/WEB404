'use strict';

/**
 * Central configuration for the DrukShelf demo application.
 *
 * The single most important switch here is `sqliProtection`. It is driven by
 * the SQLI_PROTECTION environment variable so that the EXACT SAME codebase can
 * be started in two modes:
 *
 *   SQLI_PROTECTION=off  -> the vulnerable version (queries are built by
 *                           concatenating raw user input into the SQL string)
 *   SQLI_PROTECTION=on   -> the protected version (parameterised / prepared
 *                           statements; user input is only ever bound as data)
 *
 * This lets the report compare the two versions fairly: the only thing that
 * changes between "vulnerable" and "protected" is HOW the query is built, not
 * the rest of the application.
 */
const path = require('path');

module.exports = {
  // Port the app runs on. Everything is local; nothing leaves the machine.
  port: Number(process.env.PORT) || 3000,

  // Flip the whole security posture of the app from one environment variable.
  // Anything other than the literal string "on" is treated as vulnerable, so a
  // forgotten/empty variable fails *safe for the demo* (i.e. stays vulnerable,
  // which is the default the lab starts from).
  sqliProtection: process.env.SQLI_PROTECTION === 'on',

  // Name of the cookie that carries the (very small) session id.
  sessionCookieName: 'sid',

  publicDir: path.join(__dirname, '..', 'public'),
};
