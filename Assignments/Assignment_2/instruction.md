# Instructions — Running the Demo and Capturing the Screenshots

This file tells you **exactly** how to set up, run, and demonstrate the CSRF
assignment, and **which screenshots to take** for the report (`README.md`).

Everything runs on your own machine (`localhost`). The "attacker" site is a
page you host yourself on a different port; it only ever targets the demo bank
you also run yourself. Nothing here touches any real or third-party website.

---

## 0. What you are about to build and show

You will run **two things at once**:

| Role | What it is | URL |
|------|------------|-----|
| **SecureBank** (victim) | A mini banking app with a money-transfer form | http://localhost:3000 |
| **Attacker page** | A "you won a prize" page that secretly forges a transfer | http://localhost:4000 |

The same bank code runs in one of two modes, chosen by an environment variable:

- **Vulnerable mode** (`CSRF_PROTECTION=off`) — no token is checked. The attack **works**.
- **Protected mode** (`CSRF_PROTECTION=on`) — a CSRF token is required. The attack **fails (HTTP 403)**.

Your report demonstrates the *same* attack succeeding against the vulnerable
mode and being blocked by the protected mode.

> **Why different ports matter.** `localhost:3000` and `localhost:4000` are
> *different origins*, so a request from one to the other is a genuine
> cross-origin (CSRF) request. They are still the same *site* (`localhost`), so
> the browser's default `SameSite=Lax` cookie is still sent — which is what lets
> the classic attack be reproduced over plain `http` without any HTTPS setup.

---

## 1. Environment / setup requirements

- **Node.js 20 or newer** — check with `node --version`.
- **A modern browser** — Google Chrome or Microsoft Edge (DevTools screenshots below assume Chrome).
- **Windows PowerShell** (this guide uses PowerShell commands; they work the same in any terminal).

---

## 2. Installation

Open a terminal in the `Assignment_2` folder and install dependencies once:

```powershell
npm install
```

This installs `express`, `cookie-parser`, and `cross-env` (used so the same
start command works on Windows, macOS and Linux).

---

## 3. How to start the application

You need **two terminals** open in the `Assignment_2` folder: one for the bank,
one for the attacker page. (Open a second terminal with the **+** button in the
VS Code terminal panel.)

### Terminal A — the bank

Start it in **vulnerable** mode for the first demo:

```powershell
npm run start:vulnerable
```

You should see `SecureBank running at http://localhost:3000` and
`CSRF protection: OFF (vulnerable)`.

Later, to run the **protected** version, stop this terminal (**Ctrl + C**) and run:

```powershell
npm run start:protected
```

### Terminal B — the attacker page

```powershell
npm run start:attacker
```

You should see `Attacker page running at http://localhost:4000`.
Leave both terminals running during the demo.

---

## 4. How to access the vulnerable version

1. Make sure Terminal A is running `npm run start:vulnerable`.
2. In the browser, open **http://localhost:3000**.
3. The top of the page shows a **red "VULNERABLE MODE"** banner.
4. Sign in (the username `Yeshi` and password `password` are pre-filled — any
   username works; there is no real authentication because this assignment is
   about CSRF, not passwords).
5. You land on the dashboard with a balance of **Nu. 10,000** and a
   **Transfer money** form.

---

## 5. How to perform the controlled CSRF demonstration

Keep the vulnerable bank running and stay **logged in** (this is the key point:
CSRF relies on you already having a live session).

1. In the **same browser**, open a new tab at **http://localhost:4000**.
2. You see an innocent-looking *"Congratulations, you won a prize"* page.
3. The page **auto-submits a hidden form** to `http://localhost:3000/transfer`.
   Your browser automatically attaches your SecureBank session cookie.
4. The browser lands back on the SecureBank dashboard showing a **red CSRF
   warning** and a **new transfer of Nu. 5,000 to "attacker"** that you never
   authorised. Your balance has dropped to **Nu. 5,000**.

> **Tip — see it without the redirect:** open http://localhost:4000/click
> instead. There you must click the button yourself, which is handy for a
> "before" screenshot of the attacker page. http://localhost:4000 (or `/auto`)
> fires automatically with no click at all.

To reset the balance for a clean screenshot, just **log out and log back in**
(each new session starts at Nu. 10,000).

---

## 6. How to enable / use the protected version

1. In Terminal A press **Ctrl + C** to stop the vulnerable bank.
2. Start the protected bank:
   ```powershell
   npm run start:protected
   ```
3. Reload **http://localhost:3000**. The banner is now **green "PROTECTED MODE"**.
4. Log in again. The transfer form now contains a hidden CSRF token (you can see
   it with **View Source** / DevTools).

---

## 7. How to verify that the CSRF token works

**A. The legitimate form still works.**
On http://localhost:3000, fill in the transfer form and click **Send transfer**.
It succeeds, because the bank's own page included the valid token.

**B. The same attack now fails.**
With the protected bank still running and you still logged in, open
**http://localhost:4000** again. This time the forged request is **rejected with
HTTP 403** and the dashboard shows *"Transfer rejected: missing or invalid CSRF
token."* Your balance is **unchanged**.

**C. (Optional) Prove it from the terminal.**
This shows the raw HTTP status codes for the report's testing section:

```powershell
# log in and save the cookie
curl.exe -s -c cj.txt -d "username=Yeshi&password=password" http://localhost:3000/login -o $null

# forged request with NO token  -> 403 Forbidden
curl.exe -s -b cj.txt -H "Origin: http://localhost:4000" -d "to=attacker&amount=5000" http://localhost:3000/transfer -o $null -w "forged  -> HTTP %{http_code}`n"
```

Expected output: `forged  -> HTTP 403`. (Against the vulnerable bank the same
command returns `HTTP 200`.)

---

## 8. Screenshots to take

Save every screenshot in the **`screenshots/`** folder using the **exact file
name** given. The README already links to these names, so each image appears in
the report as soon as you save it.

> **How to screenshot on Windows:** press **Win + Shift + S**, select the area,
> then paste into Paint (or the Snipping Tool) and save as PNG. Keep the browser
> at 100% zoom. For the DevTools Network screenshots, press **F12** first.

### Part A — The vulnerable application (bank in `start:vulnerable`)

| # | File name | What to have on screen & what to do | What the result should show | Why it matters |
|---|-----------|-------------------------------------|-----------------------------|----------------|
| 1 | `01-vulnerable-form.png` | SecureBank dashboard after logging in. | **Red** "VULNERABLE MODE" banner, balance **Nu. 10,000**, the Transfer money form, empty history. | Establishes the starting state and shows the form has no protection. |
| 2 | `02-vulnerable-page-source.png` | Right-click the transfer form → **View Page Source** (or F12 → Elements) and find the `<form action="/transfer">`. | The form's HTML with **no `_csrf` hidden field** and the code comment *"VULNERABLE: there is NO CSRF token here."* | Proves *why* it is vulnerable: nothing identifies a legitimate request. |

### Part B — The controlled CSRF attack (vulnerable bank + attacker page)

| # | File name | What to have on screen & what to do | What the result should show | Why it matters |
|---|-----------|-------------------------------------|-----------------------------|----------------|
| 3 | `03-attacker-page.png` | Open **http://localhost:4000/click** (the click version, so it doesn't redirect before you capture it). | The fake *"Congratulations / free prize"* page on **localhost:4000**. | Shows the attack from the victim's point of view: it looks harmless. |
| 4 | `04-attack-success.png` | Open **http://localhost:4000** (auto version) while logged in to the bank. You are redirected to the dashboard. | **Red CSRF warning** banner message, a new **Nu. 5,000 → "attacker"** row tagged **"CSRF / forged"**, balance now **Nu. 5,000**. | The core proof: a third-party page moved your money with no consent. |
| 5 | `05-attack-network.png` | Before step 4, press **F12 → Network** tab on the attacker tab; then let the attack fire. Click the `transfer` request → **Headers**. | The POST to `localhost:3000/transfer`, with the **Cookie** header present and **Origin: http://localhost:4000**, returning **200**. | Shows the browser silently attached the session cookie to a cross-origin request. |

### Part C — The protected application (bank in `start:protected`)

| # | File name | What to have on screen & what to do | What the result should show | Why it matters |
|---|-----------|-------------------------------------|-----------------------------|----------------|
| 6 | `06-protected-form-source.png` | Protected bank dashboard → **View Page Source**, find the `<form action="/transfer">`. | **Green** banner, and the form now containing `<input type="hidden" name="_csrf" value="…">` plus the *"PROTECTED"* comment. | Shows the fix: every legitimate form now carries a secret token. |
| 7 | `07-protected-legit-success.png` | On the protected bank, submit the transfer form normally (e.g. Nu. 100 to "Norbu"). | Green *"Transfer of Nu. 100 to 'Norbu' completed."* and a **"legitimate"**-tagged history row. | Proves the defence does **not** break normal use. |
| 8 | `08-protected-attack-blocked.png` | With the protected bank running and you logged in, open **http://localhost:4000** again. | **Red error** *"Transfer rejected: missing or invalid CSRF token."* and balance **unchanged at Nu. 10,000**. | The payoff: the identical attack is now blocked. |
| 9 | `09-protected-attack-403.png` | F12 → Network on the attacker tab during the blocked attack; click the `transfer` request. | The POST to `/transfer` returning **403 Forbidden**. | Hard, protocol-level evidence that the server refused the forged request. |

### Part D — Terminal evidence (optional but recommended)

| # | File name | What to have on screen & what to do | What the result should show | Why it matters |
|---|-----------|-------------------------------------|-----------------------------|----------------|
| 10 | `10-curl-comparison.png` | Run the `curl.exe` commands from Section 7C against **both** modes. | `forged -> HTTP 200` against vulnerable, `forged -> HTTP 403` against protected. | A concise, reproducible side-by-side result for the Testing section. |

---

## 9. Where each screenshot goes in README.md

Each file name above already appears as an `![...](screenshots/XX-....png)`
placeholder in the matching section of `README.md`:

| Screenshot | README section |
|------------|----------------|
| `01`, `02` | §8 Vulnerable implementation |
| `03`, `04`, `05` | §9 Controlled CSRF demonstration |
| `06`, `07` | §11 CSRF-token implementation |
| `08`, `09` | §13 Testing methodology / §15 Results |
| `10` | §13 Testing methodology |

Once you drop the PNGs into `screenshots/` with the exact names, the report is
complete.

---

## 10. Shutting down

Press **Ctrl + C** in both terminals. Because sessions are stored in memory,
everything resets the next time you start the bank.
