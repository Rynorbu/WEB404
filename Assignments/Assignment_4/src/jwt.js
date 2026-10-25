'use strict';

/**
 * THE HEART OF THE DEMO.
 *
 * A hand-written JSON Web Token (JWT) implementation. Nothing here uses a JWT
 * library: the encoding, the HMAC signature, and BOTH verifier variants are
 * written out by hand so the report reader can see exactly where the vulnerable
 * version goes wrong and exactly what the secure version does instead.
 *
 * A JWT is three Base64URL segments joined by dots:
 *
 *     header.payload.signature
 *       |       |        |
 *       |       |        └─ HMAC-SHA256(header.payload, secret)   (for HS256)
 *       |       └────────── the claims  e.g. {"sub":"alice","role":"user"}
 *       └────────────────── {"alg":"HS256","typ":"JWT"}
 *
 * The signature is what binds the header and payload to someone who knows the
 * secret. If the signature is not checked — or is checked against an algorithm
 * the attacker gets to choose — the token can no longer be trusted.
 */
const crypto = require('crypto');

// --------------------------------------------------------------------------
// Base64URL helpers (RFC 7515 §2) — base64 with +/ replaced by -_ and no '='.
// --------------------------------------------------------------------------
function base64urlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(segment) {
  // Restore the standard base64 alphabet and padding, then decode.
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64');
}

function encodeJson(obj) {
  return base64urlEncode(JSON.stringify(obj));
}

function decodeJson(segment) {
  return JSON.parse(base64urlDecode(segment).toString('utf8'));
}

/**
 * Compute the HMAC-SHA256 signature of `${header}.${payload}` and return it as
 * a Base64URL string. This is the one and only legitimate signature for a
 * given signing input and secret.
 */
function hmacSign(signingInput, secret) {
  return base64urlEncode(crypto.createHmac('sha256', secret).update(signingInput).digest());
}

// --------------------------------------------------------------------------
// Signing — identical in both modes. The difference is never in how we ISSUE a
// token to our own users; it is always in how we VERIFY a token someone hands
// back to us.
// --------------------------------------------------------------------------

/**
 * Issue a signed HS256 token for the given claims.
 *
 * @param {object} claims     application claims, e.g. { sub, role }
 * @param {string} secret     the HMAC signing secret
 * @param {object} options    { ttlSeconds, issuer, audience }
 */
function sign(claims, secret, options = {}) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);

  const payload = { ...claims };
  payload.iat = now;
  if (options.issuer) payload.iss = options.issuer;
  if (options.audience) payload.aud = options.audience;
  if (options.ttlSeconds) payload.exp = now + options.ttlSeconds;

  const encodedHeader = encodeJson(header);
  const encodedPayload = encodeJson(payload);
  const signature = hmacSign(`${encodedHeader}.${encodedPayload}`, secret);
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * Split a token into its three parts and decode header + payload WITHOUT any
 * verification. Used both by the verifiers and by the UI's token inspector, so
 * a token can be shown even when it is invalid.
 */
function decode(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) {
    throw new Error('Not a JWT: expected at least two dot-separated segments.');
  }
  return {
    header: decodeJson(parts[0]),
    payload: decodeJson(parts[1]),
    signature: parts[2] || '',
    parts,
  };
}

// ==========================================================================
//  VULNERABLE VERIFIER
// ==========================================================================
/**
 * The broken verifier. It commits four classic JWT mistakes at once, so the
 * report can demonstrate several distinct attacks against the one function:
 *
 *   1. It trusts the `alg` value from the TOKEN'S OWN HEADER instead of pinning
 *      the algorithm the server expects.
 *   2. It honours `alg: "none"` — an unsigned token is accepted as valid, so
 *      anyone can forge any claims they like.
 *   3. When it does check an HMAC, it compares the signature with `===`, a
 *      non-constant-time comparison that also makes the whole check easy to
 *      reason about for the weak-secret brute force.
 *   4. It never looks at `exp`, so expired (or never-expiring) tokens live
 *      forever.
 *
 * It returns a result object rather than throwing, so the UI can render WHY a
 * token was accepted.
 */
function verifyVulnerable(token, secret) {
  const { header, payload, parts } = decode(token);
  const alg = header.alg;

  // MISTAKE #1 + #2: the algorithm is whatever the attacker put in the header.
  if (alg === 'none' || alg === 'None' || alg === 'NONE') {
    // "none" means "no signature". We accept the claims unconditionally.
    return {
      valid: true,
      payload,
      reason: `Accepted because the token's header said "alg":"${alg}" and this verifier honours the unsigned "none" algorithm — no signature was checked at all.`,
    };
  }

  // For everything else we "verify" an HMAC — but using the header's algorithm
  // and comparing with ===.
  const signingInput = `${parts[0]}.${parts[1]}`;
  const expected = hmacSign(signingInput, secret);

  // MISTAKE #3: non-constant-time comparison.
  if (parts[2] === expected) {
    return {
      valid: true,
      payload,
      // MISTAKE #4: we never check payload.exp.
      reason: `HMAC signature matched the weak secret, and this verifier does not check the "exp" claim, so the token is accepted regardless of age.`,
    };
  }

  return {
    valid: false,
    payload,
    reason: 'Signature did not match.',
  };
}

// ==========================================================================
//  SECURE VERIFIER
// ==========================================================================
/**
 * The hardened verifier. Each step below closes one of the holes above.
 *
 * @param {string} token
 * @param {string} secret
 * @param {object} options  { issuer, audience } to enforce
 */
function verifySecure(token, secret, options = {}) {
  let decoded;
  try {
    decoded = decode(token);
  } catch (err) {
    return { valid: false, reason: 'Malformed token.' };
  }
  const { header, payload, parts } = decoded;

  if (parts.length !== 3) {
    return { valid: false, reason: 'A valid signed JWT must have exactly three segments.' };
  }

  // FIX #1 + #2: PIN the algorithm. We decide what is acceptable, not the
  // token. "none" and any algorithm other than the one we issue are rejected
  // before a signature is even considered.
  if (header.alg !== 'HS256') {
    return {
      valid: false,
      reason: `Rejected: header algorithm "${header.alg}" is not the expected "HS256". The "none" algorithm and algorithm-switching are refused here.`,
    };
  }

  // FIX #3: recompute the HMAC ourselves and compare in CONSTANT TIME, so a
  // wrong signature cannot be confirmed byte-by-byte through timing.
  const expected = hmacSign(`${parts[0]}.${parts[1]}`, secret);
  const a = Buffer.from(parts[2]);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { valid: false, reason: 'Rejected: HMAC signature is invalid for this server’s secret.' };
  }

  // FIX #4: enforce the time-based and context claims now that the signature
  // is trusted.
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && now >= payload.exp) {
    return { valid: false, reason: 'Rejected: the token has expired (exp is in the past).' };
  }
  if (typeof payload.nbf === 'number' && now < payload.nbf) {
    return { valid: false, reason: 'Rejected: the token is not valid yet (nbf is in the future).' };
  }
  if (options.issuer && payload.iss !== options.issuer) {
    return { valid: false, reason: `Rejected: issuer "${payload.iss}" is not the expected "${options.issuer}".` };
  }
  if (options.audience && payload.aud !== options.audience) {
    return { valid: false, reason: `Rejected: audience "${payload.aud}" is not the expected "${options.audience}".` };
  }

  return {
    valid: true,
    payload,
    reason: 'Accepted: algorithm pinned to HS256, signature verified in constant time, and exp / iss / aud all checked.',
  };
}

/**
 * The single verify entry point the server calls. It dispatches to the right
 * implementation based on the security posture, so the rest of the app never
 * has to care which mode it is in.
 */
function verify(token, secret, options = {}) {
  return options.secure
    ? verifySecure(token, secret, { issuer: options.issuer, audience: options.audience })
    : verifyVulnerable(token, secret);
}

module.exports = {
  base64urlEncode,
  base64urlDecode,
  hmacSign,
  sign,
  decode,
  verify,
  verifyVulnerable,
  verifySecure,
};
