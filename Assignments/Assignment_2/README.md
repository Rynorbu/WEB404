<div align="center">

# SecureBank: Cross-Site Request Forgery (CSRF)
### Building a CSRF-Vulnerable Form and Defending It with Synchronizer Tokens

**WEB404: Secure Coding Practices · Assignment 2**

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
5. [CSRF Background](#5-csrf-background)
6. [System Design](#6-system-design)
7. [Application Walkthrough](#7-application-walkthrough)
8. [Vulnerable Implementation](#8-vulnerable-implementation)
9. [Controlled CSRF Demonstration](#9-controlled-csrf-demonstration)
10. [Why the Vulnerability Works](#10-why-the-vulnerability-works)
11. [CSRF-Token Implementation](#11-csrf-token-implementation)
12. [How the Protection Works](#12-how-the-protection-works)
13. [Testing Methodology](#13-testing-methodology)
14. [Vulnerable vs Protected Comparison](#14-vulnerable-vs-protected-comparison)
15. [Results](#15-results)
16. [Security Lessons Learned](#16-security-lessons-learned)
17. [Limitations and Future Improvements](#17-limitations-and-future-improvements)
18. [Conclusion](#18-conclusion)
19. [References](#19-references)
20. [Appendix A: How to Run the Project](#appendix-a-how-to-run-the-project)

---

## 1. Introduction

When a user logs into a website, the server gives their browser a **session
cookie**. From that moment on, the browser **automatically attaches that cookie
to every request it sends to that site** — whether the request was triggered by
the user clicking a button on the site, or by some *completely unrelated page*
the user happens to have open in another tab.

That automatic, indiscriminate behaviour is convenient, but it is also the seed
of a serious vulnerability. If a malicious page can make the victim's browser
fire a request at a site where the victim is logged in, the browser will attach
the victim's cookie, and the site will treat the forged request as if the user
had made it on purpose. This attack is called **Cross-Site Request Forgery
(CSRF)**, catalogued by MITRE as **CWE-352** and listed by OWASP as a classic
web application risk.

The danger is that CSRF needs **no stolen password and no malware**. The victim
is already authenticated; the attacker merely *borrows* that authentication to
perform a **state-changing action** — transfer money, change an email address,
delete an account, or change a password — without the victim's knowledge or
consent.

This assignment studies CSRF in two parts:

1. **The vulnerability.** A small but realistic banking application,
   **SecureBank**, is built *without* CSRF protection. A separate, self-hosted
   "attacker" page then forges a money transfer out of the victim's account
   while the victim does nothing more than visit a page that looks like a prize
   giveaway (Sections 8–10).
2. **The defence.** The **synchronizer token pattern** is added to the exact
   same application. The identical attack is replayed and is now rejected before
   any money moves (Sections 11–15).

> **Ethics and scope.** The entire exercise runs on `localhost` in a controlled
> lab. The "attacker" page is hosted by the student on a different local port
> and targets only the demo bank the student also runs. It never contacts, and
> gives no means of attacking, any real or third-party website.

---

## 2. Objectives

1. **Explain** what CSRF is, why it is possible, and why the browser sends an
   authenticated request on an attacker's behalf.
2. **Build** a functional web application with a session login and a
   state-changing action (a money transfer).
3. **Implement** the application first *without* CSRF protection and demonstrate
   a working, controlled attack against it.
4. **Implement** a correct defence: a cryptographically strong CSRF token that is
   bound to the session, embedded in legitimate forms, and validated on the
   server before any state change.
5. **Demonstrate** that the same attack which succeeded against the vulnerable
   version now fails against the protected version.
6. **Test** both versions and present the results as HTTP status codes and
   account balances.
7. **Reflect** on the security lessons, the remaining limitations, and
   complementary defences.

---

## 3. Technologies Used

| Technology | Role in the project |
|------------|---------------------|
| **Node.js (≥ 20)** | JavaScript runtime for both the bank and the attacker server. |
| **Express 5** | Minimal web framework handling routes and form parsing. |
| **cookie-parser** | Reads the session cookie from incoming requests. |
| **Node `crypto` (built-in)** | Generates unguessable session ids and CSRF tokens, and compares tokens in constant time. |
| **cross-env** | Sets the `CSRF_PROTECTION` environment variable identically across Windows / macOS / Linux. |
| **HTML + CSS (server-rendered)** | Plain templates so the exact HTML sent to the browser — and the presence or absence of the token — is fully visible. |

No front-end framework and no CSRF library are used: the defence is implemented
by hand so that every step is inspectable.

---

## 4. Project Structure

```
Assignment_2/
├── package.json             # scripts: start:vulnerable / start:protected / start:attacker
├── instruction.md           # setup + the exact screenshot guide
├── README.md                # this report
│
├── src/                     # the SecureBank application (the victim)
│   ├── server.js            # routes; the ONE token check that flips vuln<->protected
│   ├── config.js            # reads CSRF_PROTECTION=on|off
│   ├── session.js           # in-memory session store (session id + per-session CSRF token)
│   ├── csrf.js              # token generation + constant-time validation
│   └── views.js             # server-side HTML (shows where the token is / isn't)
│
├── public/                  # static assets
│   ├── style.css
│   └── favicon.svg
│
├── attacker/                # the malicious site, hosted locally on port 4000
│   └── server.js            # serves the "you won a prize" auto-submitting page
│
└── screenshots/             # evidence for this report (you add the PNGs)
```

**Design choice — one codebase, two modes.** The vulnerable and protected
versions are *the same program*. A single environment variable, `CSRF_PROTECTION`,
decides whether the server demands a valid token. This makes the comparison fair:
nothing changes between the two demonstrations except the security control itself.

---

## 5. CSRF Background

### 5.1 What CSRF is

> **Cross-Site Request Forgery** forces an authenticated user's browser to send
> a request that performs an action the user did not intend, exploiting the fact
> that the browser automatically includes the user's credentials (the session
> cookie) with the request.

The attacker does **not** see the victim's cookie, session, or response. They do
not need to. They only need to cause the victim's browser to *emit a request*;
the browser supplies the credentials by itself.

### 5.2 The three preconditions

A CSRF attack is only possible when all three hold:

| # | Precondition | In this demo |
|---|--------------|--------------|
| 1 | **Cookie-based session.** The site authenticates requests using a cookie the browser sends automatically. | SecureBank uses a `sid` session cookie. |
| 2 | **A predictable state-changing request.** The attacker can construct the exact request that triggers the action. | `POST /transfer` with fields `to` and `amount`. |
| 3 | **No proof of intent.** The server cannot tell a user-initiated request from a forged one. | The vulnerable bank checks *nothing* beyond the cookie. |

The defence in this assignment removes precondition #3.

### 5.3 Why the browser sends the authenticated request

Cookies are **scoped to a site, not to a page**. Once SecureBank sets the `sid`
cookie, the browser's rule is simply: *"any request going to `localhost:3000`
gets the `localhost:3000` cookie attached."* The browser does **not** ask
"which page caused this request?" So a form on the attacker's page that posts to
`localhost:3000/transfer` gets the victim's SecureBank cookie attached
automatically — the victim is "logged in" as far as the bank can tell.

### 5.4 Impact

| Security goal | How CSRF breaks it |
|---------------|--------------------|
| **Integrity** | Attacker changes server state: money moved, email/password changed, account deleted. |
| **Confidentiality** | A changed email or password can lead to full account takeover, exposing all the victim's data. |
| **Availability** | Forged destructive actions (delete account, cancel service) can lock the victim out. |

---

## 6. System Design

### 6.1 Components and origins

```
   ┌────────────────────────────┐          ┌────────────────────────────┐
   │  SecureBank  (the victim)  │          │  Attacker page             │
   │  http://localhost:3000     │          │  http://localhost:4000     │
   │                            │          │                            │
   │  /login   → sets sid cookie│          │  serves a hidden auto-      │
   │  /dashboard → transfer form│          │  submitting <form> that     │
   │  /transfer → state change  │◄─────────│  POSTs to :3000/transfer   │
   └────────────────────────────┘  forged  └────────────────────────────┘
                 ▲                  request          (never sees the cookie)
                 │
        session cookie attached
        automatically by the
        victim's browser
```

The two servers run on **different ports**, so to the browser they are
**different origins** — a request from `:4000` to `:3000` is genuinely
*cross-origin*, which is the definition of the "cross-site" in CSRF. They remain
the same *site* (`localhost`), which is deliberately chosen so the modern default
`SameSite=Lax` cookie is still delivered and the classic attack is reproducible
over plain HTTP (see §10.2).

### 6.2 The security switch

`src/config.js` reads one environment variable:

```js
// CSRF_PROTECTION=off  -> vulnerable version (no token checked)
// CSRF_PROTECTION=on   -> protected version  (synchronizer token required)
csrfProtection: process.env.CSRF_PROTECTION === 'on',
```

`npm run start:vulnerable` and `npm run start:protected` set this variable for
you.

---

## 7. Application Walkthrough

SecureBank is a deliberately tiny banking app:

1. **Login** (`/login`) — any username is accepted (the assignment is about CSRF,
   not authentication). On login the server creates a session, stores a starting
   balance of **Nu. 10,000**, generates a per-session CSRF token, and sets the
   `sid` cookie.
2. **Dashboard** (`/dashboard`) — shows the balance, a **Transfer money** form
   (the state-changing action), and a transaction history that labels each row
   as *legitimate* or *CSRF / forged*.
3. **Transfer** (`POST /transfer`) — performs the transfer. This is the endpoint
   the attack targets and the defence protects.

A coloured banner at the top of every page states the current mode (**red** =
vulnerable, **green** = protected) so it is unambiguous in every screenshot.

---

## 8. Vulnerable Implementation

In vulnerable mode the transfer form is rendered with **no token at all**
(`src/views.js`):

```html
<form method="POST" action="/transfer">
  <!-- VULNERABLE: there is NO CSRF token here. The server will accept
       any POST that carries the session cookie, no matter who triggered it. -->
  <input name="to"     value="Norbu">
  <input name="amount" type="number" value="100">
  <button type="submit">Send transfer</button>
</form>
```

And the server performs the transfer after checking **only** that a session
cookie is present (`src/server.js`):

```js
app.post('/transfer', requireLogin, (req, res) => {
  const to = String(req.body.to || '').trim();
  const amount = Math.floor(Number(req.body.amount) || 0);

  if (config.csrfProtection) {
    /* ... token check (disabled in vulnerable mode) ... */
  }
  // Vulnerable mode falls straight through: ANY request with a valid
  // session cookie moves the money, regardless of where it came from.
  req.session.balance -= amount;
  req.session.history.unshift({ to, amount, /* ... */ });
  /* ... */
});
```

The flaw is precisely **precondition #3** from §5.2: the server has no way to
distinguish a request the user meant to make from one a foreign page forged.

![Screenshot 1 — The vulnerable SecureBank dashboard (red "VULNERABLE MODE" banner, Nu. 10,000 balance, transfer form).](screenshots/01-vulnerable-form.png)

*Figure 1 — The vulnerable application. The red banner confirms CSRF protection
is off and the account starts with Nu. 10,000.*

![Screenshot 2 — Page source of the transfer form showing no `_csrf` hidden field.](screenshots/02-vulnerable-page-source.png)

*Figure 2 — The form's HTML contains no CSRF token. There is nothing in a
submitted request that proves it came from a SecureBank page.*

---

## 9. Controlled CSRF Demonstration

The attacker site (`attacker/server.js`, served on `localhost:4000`) presents a
harmless-looking "you won a prize" page. Hidden inside it is this form, which
**auto-submits** as soon as the page loads:

```html
<!-- Served from localhost:4000. Note: no cookie and no token here —
     the browser will attach the victim's SecureBank cookie by itself. -->
<form id="attack" action="http://localhost:3000/transfer" method="POST">
  <input type="hidden" name="to"     value="attacker">
  <input type="hidden" name="amount" value="5000">
</form>
<script>document.getElementById('attack').submit();</script>
```

**The demonstration, step by step:**

1. The victim logs in to SecureBank (`localhost:3000`) — a normal session.
2. In the same browser, the victim opens the attacker page (`localhost:4000`),
   e.g. from a link in an email or chat.
3. The hidden form submits automatically to `localhost:3000/transfer`.
4. The browser, seeing a request bound for `localhost:3000`, **automatically
   attaches the victim's `sid` cookie**.
5. The vulnerable bank sees a valid session cookie, checks nothing else, and
   **transfers Nu. 5,000 to "attacker"**.

The victim clicked nothing on the bank and typed nothing — yet their money is
gone.

![Screenshot 3 — The attacker's "Congratulations / free prize" page at localhost:4000.](screenshots/03-attacker-page.png)

*Figure 3 — What the victim sees: a harmless-looking page on a different origin
(localhost:4000). The malicious form is hidden.*

![Screenshot 4 — Back on SecureBank: red CSRF warning, a Nu. 5,000 "CSRF / forged" transfer, balance reduced to Nu. 5,000.](screenshots/04-attack-success.png)

*Figure 4 — The attack succeeded. A transfer the user never authorised appears
in the history, tagged "CSRF / forged", and the balance has dropped to
Nu. 5,000.*

![Screenshot 5 — DevTools Network tab showing the cross-origin POST to /transfer with the Cookie header and Origin: localhost:4000, returning 200.](screenshots/05-attack-network.png)

*Figure 5 — Protocol-level evidence: the forged request carries the victim's
session Cookie even though its Origin is `localhost:4000`, and the server
answers `200 OK`.*

---

## 10. Why the Vulnerability Works

### 10.1 The root cause — ambient authority

The session cookie grants **ambient authority**: it is applied automatically to
every request to the site, regardless of who initiated that request. The bank
treats "the browser holds a valid session cookie" as equivalent to "the user
intends this action." Those two things are not the same, and CSRF is the gap
between them.

### 10.2 What about `SameSite` cookies?

Modern browsers default cookies to `SameSite=Lax`, which blocks cookies on many
*cross-site* requests and is a genuine partial defence. This demo is honest about
it: SecureBank and the attacker run on **different origins but the same site**
(`localhost`), so `Lax` still sends the cookie — reproducing the attack that
legacy or misconfigured apps remain exposed to (for example sites that set
`SameSite=None`, or sub-domains of the same site attacking each other).
`SameSite` is a valuable **complementary** control, but it is browser- and
configuration-dependent and does not cover same-site cross-origin cases, so it is
**not a substitute** for a server-side token. The token is the authoritative
defence this assignment implements.

### 10.3 Why the attacker can't just read the token

One might ask: could the attacker's JavaScript simply fetch the dashboard, read
the token, and include it? No — the **Same-Origin Policy** forbids script on
`localhost:4000` from reading responses from `localhost:3000`. The attacker can
cause a request to be *sent*, but cannot *read* what comes back. That asymmetry
is exactly what the token defence exploits.

---

## 11. CSRF-Token Implementation

The fix is the **synchronizer token pattern**. Three changes, all already in the
codebase and activated by `CSRF_PROTECTION=on`:

**1. Generate a secret token, bound to the session** (`src/session.js`):

```js
// Created once per session, stored server-side, separate from the session id.
csrfToken: crypto.randomBytes(32).toString('hex'),   // 256 bits of randomness
```

**2. Embed it in every legitimate form** (`src/views.js`, protected mode only):

```html
<!-- PROTECTED: a cross-origin attacker cannot read this value,
     so it cannot forge a request that passes validation. -->
<input type="hidden" name="_csrf" value="…per-session token…">
```

**3. Validate it on the server before any state change** (`src/server.js`):

```js
if (config.csrfProtection) {
  const submitted = req.body._csrf;
  if (!isValidToken(req.session.csrfToken, submitted)) {
    return res.status(403).send(/* "missing or invalid CSRF token" */);
  }
}
```

The comparison itself is **constant-time** to avoid leaking the token through
timing (`src/csrf.js`):

```js
function isValidToken(expected, submitted) {
  if (typeof submitted !== 'string' || submitted.length === 0) return false;
  const a = Buffer.from(expected), b = Buffer.from(submitted);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);   // not `===`, to resist timing attacks
}
```

![Screenshot 6 — Page source of the protected form showing the hidden `_csrf` token and the green "PROTECTED MODE" banner.](screenshots/06-protected-form-source.png)

*Figure 6 — In protected mode the legitimate form now carries a hidden `_csrf`
token that only the bank's own pages know.*

![Screenshot 7 — A normal transfer on the protected bank succeeding (green "legitimate" row).](screenshots/07-protected-legit-success.png)

*Figure 7 — The defence does not break normal use: a transfer submitted from the
bank's own form, carrying the valid token, succeeds and is tagged "legitimate".*

---

## 12. How the Protection Works

The token is a secret that is **shared only between the server and the pages the
server itself serves**:

| Party | Knows the session cookie? | Knows the CSRF token? | Result |
|-------|:-:|:-:|---|
| The real SecureBank page | yes (browser sends it) | **yes** (embedded by the server) | request accepted ✅ |
| The attacker's page | the browser sends it, but the attacker can't read it | **no** (Same-Origin Policy blocks reading it) | request rejected ❌ |

Because the attacker can make the browser *send* the cookie but cannot *read* the
token, a forged request arrives with the cookie but **without a valid token**, and
the server rejects it with **HTTP 403** before touching the balance. The defence
turns "do you hold a session cookie?" into "can you prove this request came from a
SecureBank page?" — which only a genuine SecureBank page can answer.

---

## 13. Testing Methodology

Both the browser demonstration and a reproducible terminal test were used. The
terminal test (using `curl.exe`) isolates the HTTP status codes so the result is
unambiguous. In each case the client first logs in to obtain a session cookie,
then sends a *forged* transfer that carries the cookie **but no token**, exactly
as the attacker page does.

```powershell
# Obtain a genuine session cookie
curl.exe -s -c cj.txt -d "username=Yeshi&password=password" http://localhost:3000/login -o $null

# Forged transfer: has the cookie, no token, Origin of the attacker site
curl.exe -s -b cj.txt -H "Origin: http://localhost:4000" `
     -d "to=attacker&amount=5000" http://localhost:3000/transfer -o $null -w "forged -> HTTP %{http_code}`n"
```

| Test | Mode | Request | Expected | Observed |
|------|------|---------|:--------:|:--------:|
| T1 | Vulnerable | Forged POST, cookie, **no token** | accepted | **HTTP 200**, balance 10,000 → 5,000 |
| T2 | Protected | Forged POST, cookie, **no token** | rejected | **HTTP 403**, balance unchanged (10,000) |
| T3 | Protected | Legitimate POST, cookie **+ valid token** | accepted | **HTTP 200**, balance reduced normally |
| T4 | Protected | Forged POST with a **wrong/guessed token** | rejected | **HTTP 403** (constant-time comparison fails) |

These four tests show the defence is both **effective** (T2, T4 block the attack)
and **non-disruptive** (T3 keeps legitimate use working).

![Screenshot 8 — Protected bank showing the forged transfer rejected with the red "missing or invalid CSRF token" message; balance unchanged at Nu. 10,000.](screenshots/08-protected-attack-blocked.png)

*Figure 8 — The identical attack against the protected bank: rejected, with the
balance left untouched.*

![Screenshot 9 — DevTools Network tab showing the forged POST to /transfer returning 403 Forbidden on the protected bank.](screenshots/09-protected-attack-403.png)

*Figure 9 — Protocol-level proof the server refused the forged request:
`403 Forbidden`.*

![Screenshot 10 — Terminal comparison: curl returns HTTP 200 against the vulnerable bank and HTTP 403 against the protected bank.](screenshots/10-curl-comparison.png)

*Figure 10 — The same forged request, side by side: 200 (vulnerable) versus 403
(protected).*

---

## 14. Vulnerable vs Protected Comparison

| Aspect | Vulnerable (`CSRF_PROTECTION=off`) | Protected (`CSRF_PROTECTION=on`) |
|--------|------------------------------------|----------------------------------|
| Token in the form | **None** | Hidden `_csrf` field, per session |
| Server-side check on `/transfer` | Session cookie only | Session cookie **+ valid token** |
| Proof of user intent | Absent | Present (only the bank's pages hold the token) |
| Forged transfer from `localhost:4000` | **Succeeds** (HTTP 200) | **Rejected** (HTTP 403) |
| Effect on the victim's balance | Nu. 10,000 → Nu. 5,000 | Unchanged (Nu. 10,000) |
| Legitimate transfers | Work | Still work |
| CWE status | Vulnerable to **CWE-352** | Mitigated |

---

## 15. Results

- The vulnerable version allowed a **cross-origin page to move money out of an
  authenticated account with zero interaction** beyond visiting a page: the
  balance fell from Nu. 10,000 to Nu. 5,000 (Figure 4, Test T1).
- Adding the synchronizer token caused the **identical** forged request to be
  **rejected with HTTP 403** before any state change, leaving the balance intact
  (Figures 8–9, Test T2).
- The defence did **not** interfere with legitimate use: transfers submitted from
  the bank's own form continued to succeed (Figure 7, Test T3).
- A forged request with a **guessed/incorrect token** was also rejected, and the
  constant-time comparison avoids leaking the token via response timing (Test T4).

The experiment confirms the hypothesis: CSRF succeeds precisely because the
server cannot distinguish intent, and a session-bound token restores that
distinction.

---

## 16. Security Lessons Learned

1. **A valid session is not consent.** Authentication answers "who are you?"; it
   does not answer "did you mean to do this?" State-changing actions need the
   second question answered too.
2. **Cookies carry ambient authority.** Because the browser attaches cookies
   automatically, any cookie-authenticated, state-changing endpoint is a CSRF
   candidate by default.
3. **Secrets must be unpredictable and bound to the session.** A token works only
   because it is cryptographically random (256 bits here) and tied to one
   session, so it cannot be guessed or reused across users.
4. **The Same-Origin Policy is what makes the token secret.** The defence relies
   on the attacker being able to *send* but not *read* cross-origin responses.
5. **Compare secrets in constant time.** `crypto.timingSafeEqual`, not `===`,
   prevents a timing side-channel from revealing the token.
6. **Defence in depth.** Tokens pair well with `SameSite` cookies, Origin/Referer
   checks, and re-authentication for sensitive actions — no single control should
   be trusted alone.

---

## 17. Limitations and Future Improvements

| Limitation of this demo | Suggested improvement for production |
|-------------------------|--------------------------------------|
| Sessions and balances are held **in memory** and reset on restart. | Use a persistent session store (e.g. Redis) and a database. |
| Login accepts any username with no real password check. | Implement proper authentication and password hashing. |
| Only the transfer endpoint is protected. | Apply the token check to **all** state-changing routes via shared middleware. |
| Token is generated once per session. | Consider per-request/rotating tokens, or the signed **double-submit cookie** pattern for stateless servers. |
| Relies on HTTP for the local lab. | Serve over HTTPS and set cookies `Secure` + `SameSite` in production. |
| Token defence only. | Add Origin/Referer validation and re-authentication for high-value actions as additional layers. |

---

## 18. Conclusion

This assignment built a realistic, self-contained banking application, showed a
**controlled CSRF attack** forging a money transfer out of an authenticated
account from a page on a different origin, and then **neutralised that exact
attack** by adding the synchronizer token pattern. The before/after evidence is
unambiguous: the same forged request returns **HTTP 200** and drains the account
against the vulnerable version, and **HTTP 403** with the balance untouched
against the protected version, while legitimate transfers keep working.

The core insight is that CSRF is a failure to verify **intent**: a session cookie
proves identity but not that the user meant to act. A cryptographically strong,
session-bound token — which only the server's own pages can know — supplies the
missing proof of intent and closes the gap, demonstrating the principle of
**defence in depth** in practice.

---

## 19. References

1. OWASP Foundation. *Cross-Site Request Forgery (CSRF)*. OWASP Community Pages. https://owasp.org/www-community/attacks/csrf
2. OWASP Foundation. *Cross-Site Request Forgery Prevention Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
3. MITRE. *CWE-352: Cross-Site Request Forgery (CSRF)*. https://cwe.mitre.org/data/definitions/352.html
4. MDN Web Docs. *SameSite cookies*. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
5. MDN Web Docs. *Same-origin policy*. https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
6. Node.js. *Crypto — `crypto.timingSafeEqual`*. https://nodejs.org/api/crypto.html
7. Express. *Express 5 documentation*. https://expressjs.com/

---

## Appendix A: How to Run the Project

> Full step-by-step instructions, including the exact screenshot guide, are in
> [`instruction.md`](instruction.md). A short version follows.

**Prerequisites:** Node.js ≥ 20, a modern browser.

```powershell
# 1. Install dependencies (once)
npm install

# 2. Terminal A — start the bank in VULNERABLE mode
npm run start:vulnerable        # http://localhost:3000  (red banner)

# 3. Terminal B — start the attacker page
npm run start:attacker          # http://localhost:4000

# 4. In the browser: log in at http://localhost:3000, then open
#    http://localhost:4000  -> watch Nu. 5,000 leave your account.

# 5. Stop Terminal A (Ctrl+C) and restart the bank in PROTECTED mode
npm run start:protected         # http://localhost:3000  (green banner)

# 6. Repeat step 4: the same attack is now rejected with HTTP 403.
```

All activity is confined to `localhost`; nothing contacts any external system.
