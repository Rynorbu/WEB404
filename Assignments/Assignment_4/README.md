<div align="center">

# DrukPass: JWT Authentication
### Building a JWT-Based Authentication System, Demonstrating Common JWT Attacks, and Implementing Secure JWT Handling

**WEB404: Secure Coding Practices · Assignment 4**

| | |
|---|---|
| **Name** | *[Your Name]* |
| **Student ID** | *[Your Student ID]* |
| **Programme** | *[Your Programme]* |
| **Institution** | *[Your College / University]* |
| **Submitted to** | *[Lecturer's Name]* |
| **Date of submission** | *[DD Month YYYY]* |

</div>

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Objectives](#2-objectives)
3. [Technologies Used](#3-technologies-used)
4. [Project Structure](#4-project-structure)
5. [JWT Background](#5-jwt-background)
6. [System Design](#6-system-design)
7. [Application Walkthrough](#7-application-walkthrough)
8. [The Authentication System](#8-the-authentication-system)
9. [The Vulnerable Verifier](#9-the-vulnerable-verifier)
10. [JWT Attacks Demonstrated](#10-jwt-attacks-demonstrated)
11. [Why the Attacks Work](#11-why-the-attacks-work)
12. [Secure JWT Implementation](#12-secure-jwt-implementation)
13. [How the Protection Works](#13-how-the-protection-works)
14. [Testing Methodology](#14-testing-methodology)
15. [Vulnerable vs Secure Comparison](#15-vulnerable-vs-secure-comparison)
16. [Results](#16-results)
17. [Security Lessons Learned](#17-security-lessons-learned)
18. [Limitations and Future Improvements](#18-limitations-and-future-improvements)
19. [Conclusion](#19-conclusion)
20. [References](#20-references)
21. [Appendix A: How to Run the Project](#appendix-a-how-to-run-the-project)

---

## 1. Introduction

Most modern web applications no longer keep a server-side session for every
logged-in user. Instead they hand the browser a **token** that the browser
sends back on each request, and the server reads the user's identity straight
out of that token. The dominant format for these tokens is the **JSON Web
Token (JWT)** — a compact, self-contained string that carries claims such as
*who you are* and *what role you have*, protected by a cryptographic signature.

A JWT's security rests entirely on one thing: the server **verifying the
signature correctly** before it trusts a single claim inside the token. The
claims themselves are not encrypted — anyone can read them — so the signature
is the only thing standing between "a token this server issued" and "a token an
attacker made up." When the verification step is weak, incomplete, or skips the
signature altogether, an attacker can mint a token that says *anything* —
including `"role": "admin"` — and the application will believe it. This family
of weaknesses is catalogued under **CWE-347 (Improper Verification of
Cryptographic Signature)** and appears throughout the OWASP guidance on broken
authentication and identification failures.

This assignment studies JWT security in two parts:

1. **The vulnerability.** A small but realistic login application, **DrukPass**,
   is built with a token verifier that makes the classic JWT mistakes: it trusts
   the algorithm named in the token, honours the unsigned `none` algorithm,
   signs with a trivially guessable secret, and never checks expiry. Three
   distinct attacks are then carried out against it, ending with an attacker
   reaching the admin-only area without ever knowing an admin's password
   (Sections 9–11).
2. **The defence.** The application is switched to a **hardened verifier**:
   it pins a single expected algorithm, rejects `none`, recomputes the HMAC and
   compares it in constant time, enforces the `exp` / `iss` / `aud` claims, and
   uses a long random secret. Every attack that worked before is replayed and
   now fails, while legitimate logins keep working unchanged (Sections 12–16).

> **Ethics and scope.** The entire exercise runs on `localhost` in a controlled
> lab. The user directory is fictional and held in memory. The included attack
> scripts build and inspect token strings for the demo application the student
> also runs; they contact no network service and provide no means of attacking
> any real or third-party system. JWT attacks are demonstrated here solely to
> understand and prevent them.

---

## 2. Objectives

1. **Explain** what a JWT is, how its three parts fit together, and why the
   signature — not the payload — is what makes a token trustworthy.
2. **Build** a functional JWT-based authentication system with login, a
   session carried in an `httpOnly` cookie, a user dashboard, and a role-gated
   admin area.
3. **Implement** the token verifier first *without* protection and demonstrate a
   range of working, controlled attacks: the `alg:none` signature bypass,
   offline brute force of a weak signing secret, and payload (role) tampering.
4. **Show** that these attacks lead to full privilege escalation — an attacker
   reaching the admin area with a token they forged themselves.
5. **Implement** the correct defences — algorithm pinning, constant-time
   signature verification, registered-claim enforcement, and a strong secret —
   across the exact same application.
6. **Demonstrate** that every attack that succeeded against the vulnerable
   version now fails against the secure version, without breaking normal use.
7. **Test** both versions and present the results as verifier verdicts, HTTP
   responses, and recovered/forged tokens.
8. **Reflect** on the lessons, the remaining limitations, and complementary
   defences (token storage, rotation, revocation, short lifetimes).

---

## 3. Technologies Used

| Technology | Role in the project |
|------------|---------------------|
| **Node.js (≥ 20)** | JavaScript runtime for the application and the attack scripts. |
| **Express 5** | Minimal web framework handling routes and form parsing. |
| **cookie-parser** | Reads the `httpOnly` cookie that carries the JWT. |
| **Node `crypto` (built-in)** | HMAC-SHA256 signing, the random secret, and `timingSafeEqual` for constant-time comparison. |
| **cross-env** | Sets the `JWT_SECURE` environment variable identically across Windows / macOS / Linux. |
| **HTML + CSS (server-rendered)** | Plain templates so the exact token sent to the browser, and the verifier's verdict, are printed on the page for inspection. |

**No JWT library is used.** Both the signing and *both* verifier variants are
written by hand in `src/jwt.js`, so every byte of the token and every step of
the check is inspectable — which is the whole point of the exercise.

---

## 4. Project Structure

```
Assignment_4/
├── package.json             # scripts: start:vulnerable / start:secure / attack:*
├── README.md                # this report
├── instruction.md           # how to run it and which screenshots to capture
├── src/
│   ├── config.js            # reads JWT_SECURE and flips the security posture + secret
│   ├── jwt.js               # THE HEART: hand-written sign + vulnerable vs secure verify
│   ├── users.js             # in-memory, salted-hash user directory (fictional)
│   ├── views.js             # server-rendered HTML, incl. the token inspector
│   └── server.js            # Express routes (login, dashboard, admin, inspect, logout)
├── attacker/
│   ├── alg-none.js          # Attack 1: forge an unsigned (alg:none) admin token
│   ├── brute-secret.js      # Attack 2: brute-force the weak secret, re-sign as admin
│   └── tamper.js            # Attack 3: naive role tampering (and why it fails)
├── public/
│   ├── style.css            # styling + light/dark theme; red = vulnerable, green = secure
│   ├── app.js               # progressive enhancement: light/dark theme toggle
│   ├── theme.js             # applies the saved theme before paint (no flash)
│   └── favicon.svg
└── screenshots/             # your captured evidence for this report
```

The only file that differs in behaviour between the two versions is
`src/jwt.js` (specifically which verifier `verify()` dispatches to); everything
else is shared.

---

## 5. JWT Background

### 5.1 Anatomy of a token

A JWT is three **Base64URL** segments joined by dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 . eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0 . oIxqglZazMwUoJ3W...
└──────────── header ───────────────┘   └──────────── payload ───────────────┘   └──── signature ────┘
```

- **Header** — JSON describing the token, e.g. `{"alg":"HS256","typ":"JWT"}`.
  The `alg` field names the algorithm used to produce the signature.
- **Payload** — JSON **claims**, e.g. `{"sub":"alice","role":"user","exp":...}`.
  These are the facts the application will act on.
- **Signature** — for `HS256`, this is
  `HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)`.

> **Base64URL is encoding, not encryption.** The header and payload are merely
> encoded, not hidden. Anyone holding the token can read every claim. Nothing
> secret should ever be placed in a JWT payload, and the *only* thing that stops
> an attacker from changing a claim is the signature check on the server.

### 5.2 The two algorithm families

- **HMAC (HS256/384/512)** — a **symmetric** scheme. The same secret both signs
  and verifies. This project uses `HS256`.
- **RSA/ECDSA (RS256, ES256, …)** — **asymmetric**. A private key signs; the
  matching public key verifies.

The distinction matters because several classic JWT attacks come from a verifier
being sloppy about *which* algorithm it is using (Section 11).

### 5.3 Registered claims that matter for security

| Claim | Meaning | Why it matters |
|-------|---------|----------------|
| `exp` | Expiry time | A token must stop being valid eventually. |
| `nbf` | Not-before time | A token should not be accepted before it is meant to be. |
| `iat` | Issued-at time | Supports age checks and auditing. |
| `iss` | Issuer | The server should only accept tokens *it* issued. |
| `aud` | Audience | A token for one service should not be replayable at another. |

A verifier that checks the signature but ignores these claims is still only half
done — an expired or foreign token with a valid signature would sail through.

---

## 6. System Design

DrukPass is a single Express application whose security posture is flipped by
one environment variable, `JWT_SECURE`, read in `src/config.js`:

```js
const secure = process.env.JWT_SECURE === 'on';

const secret = secure
  ? (process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex')) // strong
  : 'secret';                                                          // weak
```

- `JWT_SECURE=off` → vulnerable verifier + the weak secret `"secret"`.
- `JWT_SECURE=on` → hardened verifier + a 32-byte random secret.

A coloured banner (🔴 red / 🟢 green) sits at the top of every page so a
screenshot always shows which mode produced it.

The request lifecycle is identical in both modes:

```
         ┌──────────┐   POST /login    ┌───────────────┐
 browser │  /login  │ ───────────────► │  users.js      │  check salted hash
         └──────────┘                  └───────┬───────┘
                                                │ ok
                                                ▼
                                   jwt.sign({sub, role}, secret, {exp,iss,aud})
                                                │
                       Set-Cookie: access_token=<JWT>  (httpOnly)
                                                │
         ┌──────────┐  GET /dashboard  ┌────────▼────────┐
 browser │  cookie  │ ───────────────► │  jwt.verify()   │  ◄── THE ONLY
         └──────────┘                  │  vuln  OR  safe │      DIFFERENCE
                                        └────────┬────────┘
                                                 │ valid → session = {sub, role}
                                                 ▼
                                   role gate on /admin (role === 'admin')
```

Crucially, the **role the application acts on comes from the token's claim**,
not from a re-lookup in the user directory. This is deliberate and realistic:
it is exactly what makes a forged or tampered `role` claim have a visible,
demonstrable effect.

---

## 7. Application Walkthrough

| Page | Path | Purpose |
|------|------|---------|
| **Login** | `/login` | Authenticates against the fictional directory and issues a signed JWT into an `httpOnly` cookie. |
| **Dashboard** | `/dashboard` | Decodes the caller's own token and displays its coloured segments, header, payload, algorithm, and expiry. |
| **Admin** | `/admin` | Returns the admin area only when the verified token's `role` is `admin`; otherwise **403**. |
| **Token Inspector** | `/inspect` | Decodes any pasted token (without verifying) and then runs it through the **current mode's** verifier, printing ACCEPTED/REJECTED and the reason. |

The **Token Inspector** is the centre of the demonstration: it is where forged
tokens from the attack scripts are pasted to watch the verifier accept them in
red mode and reject them in green mode, with the reason shown each time.

---

## 8. The Authentication System

### 8.1 Issuing a token (identical in both modes)

Signing is never the vulnerable part — issuing a token to our own user is always
done correctly. From `src/jwt.js`:

```js
function sign(claims, secret, options = {}) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);

  const payload = { ...claims };
  payload.iat = now;
  if (options.issuer)   payload.iss = options.issuer;
  if (options.audience) payload.aud = options.audience;
  if (options.ttlSeconds) payload.exp = now + options.ttlSeconds;

  const encodedHeader  = encodeJson(header);
  const encodedPayload = encodeJson(payload);
  const signature = hmacSign(`${encodedHeader}.${encodedPayload}`, secret);
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}
```

On a successful login, `server.js` calls this and stores the result in a cookie
with the right flags:

```js
res.cookie(config.tokenCookieName, token, {
  httpOnly: true,   // JavaScript cannot read it → mitigates XSS token theft
  sameSite: 'lax',  // not sent on cross-site POSTs → mitigates CSRF
  path: '/',
});
```

### 8.2 Passwords

Although password storage is not the subject here, the fictional directory in
`src/users.js` still stores **salted SHA-256 hashes** rather than plaintext, so
the project never displays a plaintext password in source. The attacks in this
assignment never need a password at all — that is precisely the danger.

---

## 9. The Vulnerable Verifier

The vulnerable verifier (`verifyVulnerable` in `src/jwt.js`) commits four
classic mistakes at once, so several attacks can be shown against one function:

```js
function verifyVulnerable(token, secret) {
  const { header, payload, parts } = decode(token);
  const alg = header.alg;

  // MISTAKE #1 + #2: the algorithm is whatever the ATTACKER put in the header,
  // and the unsigned "none" algorithm is honoured.
  if (alg === 'none' || alg === 'None' || alg === 'NONE') {
    return { valid: true, payload, reason: '...accepted an unsigned token...' };
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const expected = hmacSign(signingInput, secret);

  // MISTAKE #3: non-constant-time comparison with ===.
  if (parts[2] === expected) {
    // MISTAKE #4: payload.exp is never checked.
    return { valid: true, payload, reason: '...signature matched the weak secret...' };
  }
  return { valid: false, payload, reason: 'Signature did not match.' };
}
```

| # | Mistake | Consequence | Attack it enables |
|---|---------|-------------|-------------------|
| 1 | Trusts the header's `alg` | Attacker chooses how their own token is checked | Algorithm confusion / `none` |
| 2 | Honours `alg: none` | Unsigned tokens accepted | **Attack 1** |
| 3 | Weak secret + `===` compare | Secret guessable offline; timing leak | **Attack 2** |
| 4 | Never checks `exp`/`iss`/`aud` | Expired / foreign tokens accepted | Replay of stale tokens |

---

## 10. JWT Attacks Demonstrated

All three scripts live in `attacker/` and only build or inspect token strings.
Full step-by-step capture instructions are in `instruction.md`.

### 10.1 Attack 1 — the `alg:none` signature bypass

The JWT spec defines an algorithm literally named `none`, meaning *"this token
is unsigned."* A verifier that honours it accepts **any** claims with **no
signature**. `attacker/alg-none.js` builds an admin token with an empty third
segment — note there is no secret anywhere in the script:

```js
const forgedPayload = { sub: 'attacker', role: 'admin', iss: 'drukpass.local', aud: 'drukpass.webapp' };
const header  = base64urlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
const payload = base64urlEncode(JSON.stringify(forgedPayload));
const token = `${header}.${payload}.`;   // ← empty signature
```

The script emits three case variants (`none`, `None`, `nONE`) because naive
blocklists often check only the lowercase spelling.

**Result (vulnerable mode):** pasting the token into `/inspect` returns
**ACCEPTED**, role **admin** — a full admin identity conjured out of nothing.
📷 *Screenshot 4.*

### 10.2 Attack 2 — offline brute force of a weak secret

An `HS256` signature is `HMAC-SHA256(header.payload, secret)`. If `secret` is a
short dictionary word, an attacker who captures **one** valid token can try
candidate secrets **offline** — no requests, no rate limit — until one
reproduces the token's signature. `attacker/brute-secret.js` does exactly this:

```js
for (const candidate of WORDLIST) {
  if (hmacSign(signingInput, candidate) === targetSig) { found = candidate; break; }
}
// then mint a brand-new, correctly signed admin token with the cracked secret:
const forged = jwt.sign({ sub: 'attacker', role: 'admin' }, found, { ... });
```

**Result (vulnerable mode):** the script prints `[FOUND] "secret"` and a fully
valid `HS256` admin token. Because the signature is genuine for the server's
secret, `/inspect` returns **ACCEPTED** and the token even opens `/admin` when
set as the cookie. 📷 *Screenshots 5–7.*

### 10.3 Attack 3 — naive payload tampering (and why it fails)

The instinctive attack is to take a real user token and flip `"role":"user"` to
`"role":"admin"` without touching the signature. `attacker/tamper.js` does this
to show the outcome:

```js
const tamperedPayload = { ...payload, role: 'admin' };
const tamperedToken = `${parts[0]}.${base64urlEncode(JSON.stringify(tamperedPayload))}.${parts[2]}`;
// ↑ original signature reused — now stale
```

**Result:** **REJECTED**, even in vulnerable mode, because the verifier
recomputes the HMAC over the *new* payload and it no longer matches the reused
signature. This negative result is pedagogically important: it is the reason
real attackers reach for `alg:none` (remove the signature) or secret cracking
(forge a new one) rather than editing a signed token in place. 📷 *Screenshot 8.*

---

## 11. Why the Attacks Work

Every attack above traces back to a single root cause: **the server let the
attacker influence how the attacker's own token was verified.**

- **`alg:none`** works because the verifier read the *algorithm* from
  attacker-controlled data (the header) and had a code path that accepted "no
  signature." The fix is not to patch `none` specifically but to stop trusting
  the header's `alg` at all — the server already knows which algorithm it uses.
- **Weak-secret brute force** works because HMAC verification is only as strong
  as the secret. A low-entropy secret turns a cryptographic check into a
  dictionary lookup that runs entirely on the attacker's machine.
- **Tampering fails** precisely because a *correct* signature check binds the
  payload to the secret — which is the property the other two attacks each find
  a way around.

A fourth, quieter problem underlies all of them: the vulnerable verifier never
checks `exp`, `iss`, or `aud`, so even a legitimately signed token can be
replayed long after it should have died, or used against the wrong service.

---

## 12. Secure JWT Implementation

The hardened verifier (`verifySecure` in `src/jwt.js`) closes every hole:

```js
function verifySecure(token, secret, options = {}) {
  const { header, payload, parts } = decode(token);
  if (parts.length !== 3) return reject('must have three segments');

  // FIX #1 + #2: PIN the algorithm. The server decides, not the token.
  if (header.alg !== 'HS256')
    return reject(`algorithm "${header.alg}" is not the expected HS256`);

  // FIX #3: recompute and compare in CONSTANT TIME.
  const expected = hmacSign(`${parts[0]}.${parts[1]}`, secret);
  const a = Buffer.from(parts[2]), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
    return reject('HMAC signature is invalid');

  // FIX #4: enforce the time-based and context claims.
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && now >= payload.exp) return reject('expired');
  if (typeof payload.nbf === 'number' && now <  payload.nbf) return reject('not yet valid');
  if (options.issuer   && payload.iss !== options.issuer)   return reject('wrong issuer');
  if (options.audience && payload.aud !== options.audience) return reject('wrong audience');

  return { valid: true, payload, reason: 'algorithm pinned, signature + exp/iss/aud all checked' };
}
```

Paired with a strong secret from `config.js`
(`crypto.randomBytes(32).toString('hex')`, or an injected `JWT_SECRET`), this is
a faithful miniature of what a production-grade JWT library does.

---

## 13. How the Protection Works

| Defence | Code | Attack it defeats |
|---------|------|-------------------|
| **Algorithm pinning** | `if (header.alg !== 'HS256') reject` | `alg:none` (Attack 1) and all algorithm-confusion variants |
| **Strong random secret** | `crypto.randomBytes(32)` | Weak-secret brute force (Attack 2) |
| **Constant-time compare** | `crypto.timingSafeEqual` | Timing side-channels on the signature |
| **Signature over current payload** | `hmacSign(parts[0]+'.'+parts[1])` | Payload tampering (Attack 3) |
| **`exp` / `nbf` enforcement** | time checks | Replay of expired tokens |
| **`iss` / `aud` enforcement** | claim checks | Cross-service token replay |
| **`httpOnly` + `sameSite` cookie** | `res.cookie(...)` | Token theft via XSS / CSRF |

The key conceptual shift is **control**: in the secure verifier the *server*
decides the algorithm and the validity window, and the token merely supplies
data to be checked against those server-side decisions.

---

## 14. Testing Methodology

Both versions were exercised the same way — through the browser, through the
Token Inspector, and from the command line with `curl.exe` — so the comparison
is like-for-like. Representative automated checks:

```bash
# A forged alg:none admin token
NONE="eyJhbGciOiJub25lIi...fQ."     # (full token from attacker/alg-none.js)

# Vulnerable mode → ACCEPTED
curl -s --data-urlencode "token=$NONE" http://localhost:4000/inspect | grep -o ACCEPTED

# Secure mode → REJECTED
curl -s --data-urlencode "token=$NONE" http://localhost:4000/inspect | grep -o REJECTED

# Role gate: alice (user) is refused the admin area
curl -s -i -b alice_cookie.txt http://localhost:4000/admin | grep "403"
```

Each attack was run in **both** modes and the verifier's verdict recorded. The
legitimate login flow (alice as `user`, admin as `admin`) was confirmed to keep
working in the secure build, so the hardening does not break normal use.

---

## 15. Vulnerable vs Secure Comparison

| Test | Vulnerable (🔴) | Secure (🟢) |
|------|----------------|-------------|
| Legitimate login (alice/admin) | ✅ Works | ✅ Works |
| **Attack 1** — `alg:none` admin token | ❌ **ACCEPTED** (admin) | ✅ Rejected — algorithm not `HS256` |
| **Attack 2** — cracked-secret admin token | ❌ **ACCEPTED** (admin) | ✅ Rejected — signature fails (random secret) |
| **Attack 3** — tampered role, reused signature | ✅ Rejected (stale signature) | ✅ Rejected (stale signature) |
| Expired token (valid signature) | ❌ **ACCEPTED** (no `exp` check) | ✅ Rejected — `exp` in the past |
| Token from a different issuer/audience | ❌ **ACCEPTED** (claims ignored) | ✅ Rejected — `iss`/`aud` mismatch |
| Admin area reached without admin password | ❌ **Yes** (via Attack 1 or 2) | ✅ No |

The only cells that change are the attacks: legitimate use is identical on both
sides, which is exactly the result a correct fix should produce.

---

## 16. Results

- The vulnerable verifier accepted **two independently forged admin tokens** —
  one unsigned (`alg:none`), one signed with a brute-forced secret — letting an
  attacker reach the admin area **without any admin credentials**.
- Naive tampering was rejected even by the vulnerable verifier, confirming that
  a signature check does bind the payload, and clarifying *why* the working
  attacks each sidestep that check rather than confront it.
- The secure verifier rejected **every** forged token while leaving legitimate
  logins and the role gate fully functional.
- The decisive fixes were **algorithm pinning** (kills `alg:none` and
  algorithm confusion) and a **strong random secret** (kills offline brute
  force); claim enforcement closed the quieter replay problems.

---

## 17. Security Lessons Learned

1. **The payload is public; only the signature protects it.** Never put secrets
   in a JWT, and never trust a claim before the signature is verified.
2. **Never trust the token's `alg` header.** Pin the algorithm server-side.
   This single rule eliminates the entire `none`/algorithm-confusion family.
3. **Secrets must have real entropy.** An HMAC is only as strong as its key; a
   dictionary word is no key at all. Use ≥ 32 random bytes, from the
   environment, never hard-coded.
4. **Verifying the signature is necessary but not sufficient.** Always enforce
   `exp` (and where relevant `nbf`, `iss`, `aud`) so a valid signature cannot be
   replayed forever or across services.
5. **Compare signatures in constant time** to avoid leaking information through
   timing.
6. **Store tokens carefully.** `httpOnly` keeps JavaScript (and thus XSS) away
   from the token; `sameSite` reduces CSRF exposure.
7. **Prefer a vetted library and secure defaults.** Hand-rolling here was for
   learning; in production, use a maintained library and still pass it an
   explicit `algorithms` allow-list.

---

## 18. Limitations and Future Improvements

- **No token revocation.** A stateless JWT is valid until it expires. Real
  systems add short lifetimes plus a **refresh-token** flow, or a server-side
  deny-list / token-version check for immediate logout.
- **Symmetric keys only.** This lab uses `HS256`. Asymmetric `RS256`/`ES256`
  separates signing (private key) from verifying (public key) and is worth
  demonstrating — along with the classic RS256→HS256 confusion attack.
- **In-memory users and sessions.** Everything resets on restart; a real system
  needs a database, password hashing with a slow KDF (bcrypt/argon2), and
  lockout/rate-limiting on login.
- **Transport.** Cookies here are not marked `Secure` because the lab is plain
  HTTP on localhost; over the internet, tokens must only travel over HTTPS with
  the `Secure` flag set.
- **No key rotation.** Production deployments rotate signing keys and advertise
  them (e.g. via a JWKS endpoint and a `kid` header).

---

## 19. Conclusion

A JWT moves trust from the server's memory into a string the client carries, and
that trade is safe only when the server verifies the string rigorously. This
assignment built one authentication system and showed both sides of that trade:
a verifier that trusted the token's own header, accepted unsigned tokens, and
used a guessable secret handed an attacker a full admin identity out of thin
air; a verifier that pinned its algorithm, demanded a genuine signature against
a strong secret, and enforced the registered claims rejected every one of those
forgeries while serving legitimate users unchanged. The lesson is compact: **a
JWT is only as trustworthy as the weakest line in the code that verifies it** —
so that code must decide the algorithm, insist on a real signature, and check
the claims every single time.

---

## 20. References

1. OWASP. *JSON Web Token for Java Cheat Sheet* and *Testing for JWT* (WSTG). <https://cheatsheetseries.owasp.org/>
2. OWASP Top 10 (2021): A07 *Identification and Authentication Failures*. <https://owasp.org/Top10/>
3. MITRE. *CWE-347: Improper Verification of Cryptographic Signature*. <https://cwe.mitre.org/data/definitions/347.html>
4. IETF. *RFC 7519 — JSON Web Token (JWT)*. <https://datatracker.ietf.org/doc/html/rfc7519>
5. IETF. *RFC 7515 — JSON Web Signature (JWS)*. <https://datatracker.ietf.org/doc/html/rfc7515>
6. IETF. *RFC 8725 — JSON Web Token Best Current Practices*. <https://datatracker.ietf.org/doc/html/rfc8725>
7. Auth0. *Critical vulnerabilities in JSON Web Token libraries* (the `alg:none` disclosure). <https://auth0.com/blog/>
8. PortSwigger Web Security Academy. *JWT attacks*. <https://portswigger.net/web-security/jwt>

---

## Appendix A: How to Run the Project

> Full step-by-step demo and screenshot guidance is in **`instruction.md`**.

### A.1 Prerequisites
- Node.js **20+** (`node --version`)
- A modern browser

### A.2 Install (once)
```powershell
npm install
```

### A.3 Run — vulnerable version (🔴)
```powershell
npm run start:vulnerable
```
Open <http://localhost:4000>. Console shows `VULNERABLE (broken verifier)` and
the weak secret.

### A.4 Run — secure version (🟢)
```powershell
# stop the other server first (Ctrl + C)
npm run start:secure
```
Console shows `SECURE (hardened verifier)`.

### A.5 Run the attacks (second terminal)
```powershell
npm run attack:alg-none   # or: node attacker/alg-none.js
npm run attack:brute      # or: node attacker/brute-secret.js
npm run attack:tamper     # or: node attacker/tamper.js
```
Paste the tokens they print into the **Token Inspector** at
<http://localhost:4000/inspect> and compare the verdict between the two modes.

> Only one server can use port 4000 at a time — always **Ctrl + C** the old one
> before starting the other. Everything is local and fictional; nothing here
> contacts or attacks any real or third-party system.
