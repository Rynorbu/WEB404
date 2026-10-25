# Instructions — Running the Demo and Capturing the Screenshots

This file tells you **exactly** how to set up, run, and demonstrate the JWT
assignment, and **which screenshots to take** for the report (`README.md`).

Everything runs on your own machine (`localhost`). The user directory is
fictional and lives only in memory, so nothing you do causes lasting damage,
and nothing here touches any real or third-party system. JWTs are forged and
cracked here **only** to understand and prevent those attacks.

---

## 0. What you are about to build and show

You will run **one application** — **DrukPass**, a small login system — that can
start in either of two modes, chosen by an environment variable:

| Mode | Command | Banner | What happens to the attacks |
|------|---------|--------|-----------------------------|
| **Vulnerable** | `npm run start:vulnerable` | 🔴 red | They **work** |
| **Secure** | `npm run start:secure` | 🟢 green | They **fail** |

The same app runs at <http://localhost:4000> in both modes. The only thing that
changes is **how an incoming token is verified** — the single `jwt.verify(...)`
call in `src/jwt.js`.

> **Why one app, two modes?** It makes the comparison fair: the report shows the
> *same* forged token being accepted by the vulnerable build and rejected by the
> secure build, with nothing else changed.

---

## 1. Environment / setup requirements

- **Node.js 20 or newer** — check with `node --version`.
- **A modern browser** — Chrome or Edge (DevTools screenshots assume Chrome).
- **Windows PowerShell** (the commands below work the same in any terminal).
  `curl.exe` ships with Windows 10/11.

---

## 2. Installation

Open a terminal in the `Assignment_4` folder and install dependencies once:

```powershell
npm install
```

This installs `express`, `cookie-parser`, and `cross-env`. There is **no JWT
library** — the token code is written by hand in `src/jwt.js` so every step is
inspectable.

---

## 3. How to start the application

You need **one terminal** for the app. The attack scripts (Section 6) run in a
**second** terminal and do not need the server at all.

### The vulnerable version (Parts A and B)

```powershell
npm run start:vulnerable
```

You should see `DrukPass running at http://localhost:4000`,
`JWT handling: VULNERABLE (broken verifier)`, and the weak secret being printed.

### The secure version (Part C)

Stop the vulnerable server first (**Ctrl + C**), then:

```powershell
npm run start:secure
```

You should see `JWT handling: SECURE (hardened verifier)`.

> Only one server can use port 4000 at a time. Always **Ctrl + C** the old one
> before starting the other. To pin a known secret in secure mode (optional),
> set `JWT_SECRET` first: `$env:JWT_SECRET="<64 hex chars>"`.

---

## 4. The pages

| Page | Path | What it shows |
|------|------|---------------|
| **Login** | `/login` | Issues a signed JWT into an `httpOnly` cookie. Lab credentials are printed on the page. |
| **Dashboard** | `/dashboard` | Decodes *your* cookie token and shows its header, payload, algorithm, and expiry. |
| **Admin** | `/admin` | Reachable only when the verified token's `role` claim is `admin`. |
| **Token Inspector** | `/inspect` | Paste **any** token; it is decoded and then run through the current mode's verifier, which reports ACCEPTED or REJECTED and why. This is where you test the forged tokens. |

---

## 5. The demonstration, step by step

### Part A — Normal, legitimate use (vulnerable server running)

1. Go to <http://localhost:4000/login> and sign in as **alice / password123**.
   **📷 Screenshot 1** — the login page (red banner visible).
2. You land on the dashboard. Note the three coloured segments of the raw token
   and the decoded `header` / `payload`, with `role: user`.
   **📷 Screenshot 2** — the dashboard showing alice's decoded token.
3. Try to open <http://localhost:4000/admin>. You get **403 Forbidden** because
   alice's role is `user`.
   **📷 Screenshot 3** — the 403 page.

### Part B — The attacks (vulnerable server still running)

In a second terminal:

```powershell
node attacker/alg-none.js      # Attack 1
node attacker/brute-secret.js  # Attack 2
node attacker/tamper.js        # Attack 3
```

**Attack 1 — `alg:none` bypass**
- Copy the `alg="none"` token printed by `alg-none.js`.
- Paste it into `/inspect`. Verdict: **ACCEPTED**, role **admin** — with no
  signature at all.
  **📷 Screenshot 4** — inspector showing the `none` token ACCEPTED in red mode.

**Attack 2 — weak-secret brute force**
- Run `brute-secret.js`. Watch it try a wordlist and recover the secret
  `"secret"`, then print a correctly signed admin token.
  **📷 Screenshot 5** — the terminal showing `[FOUND] "secret"` and the forged token.
- Paste the forged admin token into `/inspect`. Verdict: **ACCEPTED**, role **admin**.
  **📷 Screenshot 6** — inspector showing the cracked-secret token ACCEPTED.
- *(Optional, to prove full takeover):* set the token as your cookie and reload
  `/admin`. In Chrome DevTools → Application → Cookies, edit `access_token` to
  the forged value, then visit `/admin` — you now see the Administrator area.
  **📷 Screenshot 7** — the admin area reached with a forged token.

**Attack 3 — why naive tampering fails**
- Run `tamper.js` and paste its token into `/inspect`. Verdict: **REJECTED** —
  even in vulnerable mode, because the reused signature no longer matches the
  edited payload. This is *why* Attacks 1 and 2 exist.
  **📷 Screenshot 8** — inspector showing the tampered token REJECTED.

### Part C — The defence (secure server)

Stop the server and restart with `npm run start:secure` (green banner).

- Repeat **Attack 1**: paste the `alg:none` token into `/inspect`. Verdict:
  **REJECTED** — algorithm is not the pinned `HS256`.
  **📷 Screenshot 9** — inspector REJECTING the `none` token in green mode.
- Repeat **Attack 2**: paste the cracked-secret admin token. Verdict:
  **REJECTED** — the server now uses a 32-byte random secret, so the signature
  fails.
  **📷 Screenshot 10** — inspector REJECTING the forged token in green mode.
- Confirm normal use still works: log in as **admin / S3cureAdminPass!** and
  open `/admin` successfully.
  **📷 Screenshot 11** — the admin area reached legitimately in green mode.

---

## 6. Summary of attack scripts

| Script | Attack | Needs server? | Output |
|--------|--------|---------------|--------|
| `attacker/alg-none.js` | Unsigned-token (`alg:none`) forgery | No | Admin tokens with an empty signature |
| `attacker/brute-secret.js` | Offline weak-secret brute force | No | The cracked secret + a valid forged admin token |
| `attacker/tamper.js` | Naive payload (role) tampering | No | A tampered token that gets rejected |

Each script only builds or inspects token strings; none of them attacks any
system other than the demo you are running.

---

## 7. Screenshot checklist

Save these into `screenshots/` and reference them in the report.

- [ ] **1** — Login page (red banner)
- [ ] **2** — Dashboard, alice's decoded token (`role: user`)
- [ ] **3** — 403 Forbidden on `/admin` as alice
- [ ] **4** — `/inspect`: `alg:none` token ACCEPTED (vulnerable)
- [ ] **5** — Terminal: `brute-secret.js` finds `"secret"`
- [ ] **6** — `/inspect`: cracked-secret admin token ACCEPTED (vulnerable)
- [ ] **7** — Admin area reached with a forged cookie *(optional)*
- [ ] **8** — `/inspect`: tampered token REJECTED (vulnerable)
- [ ] **9** — `/inspect`: `alg:none` token REJECTED (secure)
- [ ] **10** — `/inspect`: cracked-secret token REJECTED (secure)
- [ ] **11** — Admin area reached legitimately (secure)
