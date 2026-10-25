'use strict';

/**
 * ATTACK 3 — naive payload tampering, and why it fails (local lab tool).
 *
 * The instinctive attack is: take a real user token, flip `"role":"user"` to
 * `"role":"admin"`, and send it back. This script does exactly that — WITHOUT
 * touching the signature — to show the result:
 *
 *   - A correct verifier (and even our vulnerable one, for HS256 tokens)
 *     recomputes the signature over the NEW payload and finds it no longer
 *     matches, so the tampered token is REJECTED.
 *
 * That rejection is the whole reason the other two attacks exist: tampering
 * alone does not work against a signature check, so a real attacker must
 * either remove the signature (Attack 1, alg:none) or recover the key and
 * re-sign (Attack 2, weak-secret brute force). Running this script makes that
 * motivation concrete.
 *
 * Usage:
 *   node attacker/tamper.js [<real-token>]
 */
const jwt = require('../src/jwt');

let original = process.argv[2];
if (!original) {
  original = jwt.sign(
    { sub: 'alice', role: 'user' },
    'secret',
    { ttlSeconds: 900, issuer: 'drukpass.local', audience: 'drukpass.webapp' }
  );
}

const parts = original.split('.');
const payload = jwt.decode(original).payload;

console.log('=== Attack 3: payload tampering (role escalation) ===\n');
console.log('Original payload:');
console.log(JSON.stringify(payload, null, 2), '\n');

// Flip the role but keep the ORIGINAL signature untouched.
const tamperedPayload = { ...payload, role: 'admin' };
const tamperedToken = `${parts[0]}.${jwt.base64urlEncode(JSON.stringify(tamperedPayload))}.${parts[2]}`;

console.log('Tampered payload (role escalated to admin):');
console.log(JSON.stringify(tamperedPayload, null, 2), '\n');
console.log('Tampered token (original signature reused, now stale):');
console.log(tamperedToken + '\n');

console.log('Paste it into http://localhost:4000/inspect.');
console.log('  - The signature was computed over the OLD payload, so even the');
console.log('    vulnerable verifier recomputes it over the NEW payload and');
console.log('    REJECTS the token. Tampering alone is not enough — which is');
console.log('    exactly why attackers reach for alg:none or secret cracking.');
