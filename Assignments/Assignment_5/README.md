<div align="center">

# DrukConsole: A Web Command-Line Interface
### Building a CLI Inside a Web Application, Demonstrating Command Injection, and Implementing Safeguards Against It

**WEB404: Secure Coding Practices · Assignment 5**

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
5. [Command Injection Background](#5-command-injection-background)
6. [System Design](#6-system-design)
7. [Application Walkthrough](#7-application-walkthrough)
8. [The Web Command-Line Interface](#8-the-web-command-line-interface)
9. [The Vulnerable Runner](#9-the-vulnerable-runner)
10. [Attacks Demonstrated](#10-attacks-demonstrated)
11. [Why the Attacks Work](#11-why-the-attacks-work)
12. [The Secure Implementation](#12-the-secure-implementation)
13. [How the Safeguards Work](#13-how-the-safeguards-work)
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

Many web applications need to reach beyond their own process and ask the
operating system to do something: ping a host, resolve a domain, convert an
image, run a backup, generate a PDF. The quickest way to do this is to build a
command string and hand it to a shell. It is also one of the most dangerous
things a web application can do, because the moment any part of that string
comes from the user, the user is no longer filling in a form — they are writing
part of a command that the server will run with the server's own privileges.

This family of weaknesses is **OS Command Injection**, catalogued as
**CWE-78 (Improper Neutralization of Special Elements used in an OS Command)**
and listed among the OWASP Top 10 under **A03:2021 – Injection**. Its cause is
always the same shape: *untrusted input is mixed into a command that an
interpreter then parses.* A shell treats characters such as `&`, `|`, `;`,
`$( )` and `` ` `` as syntax, not data, so a field meant to hold `127.0.0.1`
can instead carry `127.0.0.1 & whoami` — two commands where the developer
expected one.

This assignment studies command injection in two parts, around a single small
application called **DrukConsole** — a web page that exposes a command-line
interface for network diagnostics (ping and DNS lookup):

1. **The vulnerability.** The console is first built the naive way: it
   concatenates the user's host input into a shell command string and runs it
   with Node's `child_process.exec`. Three distinct attacks are then carried
   out against it — command chaining, sensitive-file disclosure, and a blind
   time-based injection — showing that an attacker can run arbitrary commands
   as the server, read files the feature was never meant to expose, and prove
   execution even when no output is returned (Sections 9–11).

2. **The defence.** The exact same console is switched to a **hardened runner**
   that never uses a shell at all. It allowlists the requested tool, validates
   the host against a strict pattern, and executes the program directly with
   `child_process.execFile` and an argument array. Every attack that worked
   before now fails, while legitimate diagnostics keep working unchanged
   (Sections 12–16).

> **Ethics and scope.** The entire exercise runs on `localhost` in a controlled
> lab. The only "target" is the student's own demo server. Every injected
> command is harmless and local: printing the current user name (`whoami`),
> reading a *fictional* secret file the app creates itself, and making the
> server pause for a few seconds. Nothing contacts a third-party system and
> nothing is destroyed. Command injection is demonstrated here solely to
> understand and prevent it.

---

## 2. Objectives

1. **Build** a command-line interface inside a web application — a browser
   front-end where a user selects a tool and a host, the server runs the
   corresponding system command, and the output is shown back on the page.
2. **Explain** what OS command injection (CWE-78) is, why mixing user input
   into a shell string causes it, and how shell metacharacters turn data into
   code.
3. **Implement** the command runner first *without* protection and demonstrate
   a range of working, controlled attacks: command chaining, sensitive-file
   disclosure, and blind time-based injection.
4. **Show** that these attacks lead to arbitrary command execution as the
   server account — far beyond the intended "ping a host" feature.
5. **Implement** the correct safeguards across the exact same application: an
   allowlist of permitted tools, strict input validation of the host, and
   argument-array execution with **no shell** (`execFile`, `shell: false`),
   backed by a timeout and an output cap.
6. **Demonstrate** that every attack that succeeded against the vulnerable
   version now fails against the secure version, without breaking normal use.
7. **Test** both versions and present the results as command strings, captured
   output, guard verdicts, and HTTP responses.
8. **Reflect** on the lessons, the remaining limitations, and complementary
   defences (least privilege, sandboxing, avoiding the shell entirely).

---

## 3. Technologies Used

| Technology | Role in the project |
|------------|---------------------|
| **Node.js (≥ 20)** | JavaScript runtime for the application and the attack scripts. |
| **Express 5** | Minimal web framework handling routes and form / JSON parsing. |
| **Node `child_process` (built-in)** | `exec` (vulnerable: runs a shell string) vs `execFile` (secure: runs a program directly with an argv array, no shell). |
| **System tools (`ping`, `nslookup`)** | The real commands the console drives — chosen because they are read-only and present on Windows, macOS and Linux. |
| **cross-env** | Sets the `CLI_SECURE` environment variable identically across Windows / macOS / Linux. |
| **HTML + CSS (server-rendered)** | Plain templates so the exact command the server ran, and its output, are printed on the page for inspection. |
| **Global `fetch` (built into Node ≥ 18)** | The three attacker scripts POST payloads to the local server and read the JSON response. |

**No third-party command-building or sanitising library is used.** Both the
vulnerable and the secure runners are written by hand in `src/runner.js`, so
every step — the dangerous concatenation and each of the safe layers — is
visible and inspectable, which is the whole point of the exercise.

---

## 4. Project Structure

```
Assignment_5/
├── package.json             # scripts: start:vulnerable / start:secure / attack:*
├── README.md                # this report
├── instruction.md           # how to run it and which screenshots to capture
├── .gitignore               # ignores node_modules + runtime lab artefacts
├── src/
│   ├── config.js            # reads CLI_SECURE and flips the security posture
│   ├── commands.js          # the tool ALLOWLIST + strict host validation
│   ├── runner.js            # THE HEART: vulnerable exec vs secure execFile
│   ├── views.js             # server-rendered HTML console + explainer page
│   └── server.js            # Express routes (console, /run, /about)
├── attacker/
│   ├── inject-chain.js      # Attack 1: command chaining (run a 2nd command)
│   ├── inject-exfil.js      # Attack 2: read a sensitive file via injection
│   └── inject-blind.js      # Attack 3: blind time-based injection
├── public/
│   ├── style.css            # styling + light/dark theme; red = vulnerable, green = secure
│   ├── app.js               # theme toggle + "fill payload" buttons
│   ├── theme.js             # applies saved theme before paint (no flash)
│   └── favicon.svg          # terminal-prompt icon
└── screenshots/
    └── README.md            # which screenshots to capture for the report
```

> `lab-secret.txt` (the fictional secret) and `pwned.txt` (a marker a blind
> attack can drop) are created at **runtime**, not committed — they are listed
> in `.gitignore`.

---

## 5. Command Injection Background

A **shell** (`cmd.exe` on Windows, `/bin/sh` on Linux/macOS) is a program whose
job is to read a line of text and interpret it as commands. To do that it gives
certain characters special meaning:

| Character | Meaning to the shell |
|-----------|----------------------|
| `&` / `&&` | Run another command after this one (Windows `&`; POSIX `&&` on success). |
| `;` | Separate and run several commands in sequence (POSIX). |
| `\|` | Pipe this command's output into the next command. |
| `$(...)` / `` `...` `` | Run the inner command and substitute its output. |
| `>` / `<` | Redirect output to / input from a file. |

When a developer writes:

```js
exec("ping -n 1 " + userHost);     // userHost comes straight from a form field
```

…they are *assuming* `userHost` is a hostname. But it is just text that will be
glued into a line the shell then parses. If the user sends
`127.0.0.1 & whoami`, the shell sees the `&` as syntax and runs **two**
commands. The user has crossed the line from supplying *data* to supplying
*code*. That is command injection, and it is devastating because the injected
command runs with all the privileges of the server process — it can read files,
open network connections, install software, or delete data.

The root cause, stated once: **an interpreter (the shell) was given a string
that mixed trusted command text with untrusted user input, and it cannot tell
the two apart.** Every safeguard in Section 12 is ultimately a way to stop that
mixing from happening.

---

## 6. System Design

The guiding idea, shared with the other assignments in this module, is
**one application, two modes**:

| Mode | Command | Banner | What happens to the attacks |
|------|---------|--------|-----------------------------|
| **Vulnerable** | `npm run start:vulnerable` | 🔴 red | They **work** |
| **Secure** | `npm run start:secure` | 🟢 green | They **fail** |

The same app runs at <http://localhost:5000> in both modes. The only thing that
changes is **how the server turns the request into a running command** — the
single `run(...)` call in `src/runner.js`. One environment variable,
`CLI_SECURE`, selects the runner:

```
CLI_SECURE=off  ->  runVulnerable()   exec(`${template} ${host}`)       shell string
CLI_SECURE=on   ->  runSecure()       execFile(bin, [args], shell:false) argv array
```

Keeping every route, view and tool definition identical between the two modes
makes the comparison fair: the report can show the *same* payload accepted and
run by the vulnerable build and rejected by the secure build, with nothing else
changed.

The data flow for a single request:

```
Browser form / attacker script
        │  POST /run  { tool, host }
        ▼
   server.js  ──►  runner.run(tool, host)
                        │
          CLI_SECURE ──►┤
            off │       │ on
                ▼       ▼
        runVulnerable  runSecure
          exec(string)   1. allowlist tool
                         2. validate host
                         3. execFile(bin,[host])
                        │
                        ▼
                result { commandShown, stdout, stderr, exitCode, guard }
                        │
                        ▼
             HTML result card  /  JSON (for attacker scripts)
```

---

## 7. Application Walkthrough

Opening <http://localhost:5000> shows the **console**: a coloured banner at the
top (red or green), a form with a **Tool** dropdown (Ping / DNS lookup) and a
**Host** field, and a **Run** button. Submitting the form sends `POST /run`;
the server runs the command and re-renders the page with a **Result** card that
shows three things:

1. a **verdict badge** — "Executed in a shell" (vulnerable) / "Executed
   directly (no shell)" (secure) / "Blocked before execution";
2. the **exact command** the server ran (a shell string, or an argv array); and
3. the **captured output** (stdout and stderr) and the exit code.

In vulnerable mode the right-hand panel offers **injection presets** — one
click fills the host field with a ready-made payload so a grader can reproduce
each attack instantly. In secure mode that panel is replaced with a short
explanation of why the console is now safe. The `/about` page explains both
runners side by side.

The console is driven both by the browser (which gets HTML back) and by the
three attacker scripts (which send `Accept: application/json` and get a JSON
result). Both go through the identical `run(...)` path, so an attack script and
the browser see exactly the same security behaviour.

---

## 8. The Web Command-Line Interface

The feature itself is deliberately ordinary — the kind of "run a quick
diagnostic" tool that appears on admin dashboards and status pages everywhere.
The tool catalog lives in `src/commands.js` and is shared by both modes:

```js
const TOOLS = {
  ping:    { label: 'Ping a host (ICMP echo)', bin: 'ping',
             buildArgs: (host) => [...pingArgs, host],   // secure: argv
             shellTemplate: `ping ${pingArgs.join(' ')}` // vulnerable: string
           },
  resolve: { label: 'DNS lookup (nslookup)',   bin: 'nslookup',
             buildArgs: (host) => [host],
             shellTemplate: 'nslookup' },
};
```

Each tool carries *both* representations on purpose: a `shellTemplate` (a string
the vulnerable runner concatenates onto) and a `buildArgs` function (an argv
array the secure runner passes to `execFile`). The flags are platform-aware
(`ping -n 1` on Windows, `ping -c 1` elsewhere) so the demo behaves the same on
any machine. Pinging `127.0.0.1` works with no network connection at all, which
keeps the "a legitimate request still works" test reliable offline.

---

## 9. The Vulnerable Runner

Here is the entire vulnerability, in `src/runner.js`:

```js
function runVulnerable(toolName, host) {
  const tool = TOOLS[toolName];
  const commandLine = `${tool.shellTemplate} ${host}`;   // <-- the flaw
  exec(commandLine, runOptions, (err, stdout, stderr) => { /* ... */ });
}
```

Two decisions make this exploitable:

1. **`host` is concatenated into a command string.** The developer validated
   the *tool* (it must be one of the dropdown values) but completely trusts the
   free-text *host* field. This is realistic: the part that "looks like a
   choice" gets checked; the part that "looks like typing" does not.
2. **`exec` runs that string in a shell.** `child_process.exec` always spawns a
   shell and asks it to parse the whole string. So every shell metacharacter in
   `host` is interpreted as syntax.

The only guards present are a 5-second **timeout** and a 64 KB **output cap**
(applied in *both* modes). These limit the blast radius — a runaway command
cannot hang the server forever — but they do **not** prevent injection: a short
command like `whoami` or `type secret.txt` finishes instantly and well within
the cap. Caps are not a substitute for not building the string in the first
place.

---

## 10. Attacks Demonstrated

All three attacks are run from a second terminal while the **vulnerable** server
is running. Each script POSTs a payload to `/run` and prints the result.

### Attack 1 — Command chaining (`attacker/inject-chain.js`)

**Payload** (`host` field): `127.0.0.1 & echo INJECTED-XXXX & whoami`
(POSIX uses `;` instead of `&`.)

The shell runs three commands: the intended ping, an `echo` of a unique marker,
and `whoami`. The server ran:

```
sh$ ping -n 1 127.0.0.1 & echo INJECTED-0JNZQM & whoami
```

and the output came back containing both the marker **and** the server's OS
account name:

```
...ping statistics...
INJECTED-0JNZQM
HP
```

The marker proves our injected commands executed; `whoami` proves we learned
something about the server a "ping" box should never reveal. **Arbitrary
command execution is confirmed.**

### Attack 2 — Sensitive-file disclosure (`attacker/inject-exfil.js`)

**Payload:** `127.0.0.1 & type lab-secret.txt` (POSIX: `; cat lab-secret.txt`).

Instead of a harmless command we chain one that reads a file the server process
can see but the feature was never meant to expose. The response contained the
file's contents, including the fictional key:

```
DRUKCONSOLE_API_KEY=sk_lab_0000_not_a_real_key_1234567890
```

A "ping a host" feature just handed an attacker a secret off the server's disk.
In the real world this is how credentials, config files and private keys leak.

### Attack 3 — Blind time-based injection (`attacker/inject-blind.js`)

Sometimes the injected command's output is **not** reflected back. Injection is
still exploitable: we make the server *wait* and measure the delay.

**Payload:** `127.0.0.1 & ping -n 4 127.0.0.1` (POSIX: `; sleep 3`). The extra
pings take about three seconds. The script times a normal request as a baseline,
then the injected one:

```
Baseline request : 151 ms
Injected request : 3171 ms
Added delay      : ~3020 ms   ->  blind injection CONFIRMED
```

The ~3-second gap only appears because our command ran. Even with no output to
read, timing alone proves code execution — which is exactly how blind injection
is detected against real systems.

---

## 11. Why the Attacks Work

Every one of the three attacks has the same root cause, viewed from a different
angle:

- **The shell was asked to parse attacker-influenced text.** `exec` hands the
  whole string to `cmd.exe` / `/bin/sh`. To the shell, `&`, `;`, `|`, `$()` are
  operators. The application *intended* `host` to be data, but the shell has no
  way to know that — it sees one line of shell syntax.
- **There was no boundary between command and argument.** Because everything is
  one string, there is nothing marking "the host stops here." A space followed
  by `&` is enough to start a new command.
- **No validation rejected the dangerous input.** Nothing checked that `host`
  looked like a host. Any string was accepted and executed.
- **The server runs with useful privileges.** The injected command inherits the
  server process's identity and file access, so reading `lab-secret.txt` or
  running `whoami` simply works.

Blind injection (Attack 3) underlines the key point: the vulnerability is in
the *execution*, not in whether the output happens to be shown. Hiding error
messages or output would not fix it.

---

## 12. The Secure Implementation

The secure runner (`runSecure` in `src/runner.js`) provides the identical
feature with three independent layers of defence. Any **one** of them already
stops all three attacks; together they are defence in depth.

```js
function runSecure(toolName, host) {
  // Layer 1 — ALLOWLIST the tool. Unknown tool => nothing runs.
  const tool = TOOLS[toolName];
  if (!tool) return reject(`Unknown tool "${toolName}" — not in the allowlist.`);

  // Layer 2 — VALIDATE the host against a strict known-good pattern.
  if (!isValidHost(host)) return reject('Host rejected: not a valid IP/hostname.');

  // Layer 3 — EXECUTE directly, NO shell, host as its own argv element.
  const argv = tool.buildArgs(host);               // e.g. ['-n','1','127.0.0.1']
  execFile(tool.bin, argv, { shell: false, timeout, maxBuffer }, cb);
}
```

The host validator (`isValidHost` in `src/commands.js`) is an **allowlist**, not
a blocklist. It accepts only two shapes and rejects everything else:

```js
const ipv4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const hostname =
  /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
return ipv4.test(host) || hostname.test(host);
```

Because a valid IPv4 address or hostname contains no spaces and none of the
characters `& | ; $ \` ( ) < > ' "` or newlines, every injection payload is
rejected here before anything runs.

---

## 13. How the Safeguards Work

**Layer 1 — Allowlist the tool.** The user can only ask for a tool that exists
in the `TOOLS` catalog. There is no code path that runs an arbitrary program the
user names; the "what to run" decision belongs entirely to the application.

**Layer 2 — Validate the input against a strict pattern.** Allowlisting the
*shape* of the input ("it must look exactly like an IP or a hostname") is far
safer than trying to blocklist bad characters. Blocklists are brittle — miss one
metacharacter, one encoding, one platform quirk, and the defence fails. An
allowlist states what is permitted and denies the infinite rest by default.

**Layer 3 — Execute with no shell.** This is the decisive layer. `execFile`
launches the named program **directly** via the operating system and passes the
argv array straight to it — no shell is involved, so there is nothing to parse
metacharacters. If an attacker somehow submitted `127.0.0.1 & whoami` and it
reached this layer, `execFile('ping', ['-n','1','127.0.0.1 & whoami'])` would
pass the entire string — spaces, ampersand and all — to `ping` as **one literal
hostname argument**. `ping` would simply fail to resolve it; `whoami` would
never run. The secure result card even prints the argv so this is visible:

```
exec ping "-n" "1" "127.0.0.1"
```

Each argument is quoted and separate — there is no command line for a shell to
re-interpret, because there is no shell.

**Supporting controls (both modes).** A 5-second timeout and a 64 KB output cap
bound the blast radius of any command, and `windowsHide: true` stops a console
window from flashing on Windows. These are hardening, not the primary defence —
the primary defence is never constructing a shell string from user input.

---

## 14. Testing Methodology

Testing uses the same three attacker scripts against **both** modes, plus a
legitimate request to confirm the feature still works when secured.

1. **Start the vulnerable server:** `npm run start:vulnerable`.
2. In a second terminal, run each attack and record the output:
   - `npm run attack:chain` — expect the marker **and** `whoami` output.
   - `npm run attack:exfil` — expect the secret file contents (API key) back.
   - `npm run attack:blind` — expect a ~3000 ms added delay.
3. **Stop** the vulnerable server (Ctrl + C) and **start the secure one:**
   `npm run start:secure`.
4. Re-run all three attacks — each must now report **BLOCKED / PREVENTED**.
5. Submit a legitimate request (`tool=ping`, `host=127.0.0.1`) and confirm it
   still returns `exit code 0` and real ping output, executed as an argv array.

Each script prints the target, the exact payload, the server mode, the command
the server ran, the captured output, and a plain-English verdict — so the
evidence is self-describing.

---

## 15. Vulnerable vs Secure Comparison

| Aspect | Vulnerable (`CLI_SECURE=off`) | Secure (`CLI_SECURE=on`) |
|--------|-------------------------------|--------------------------|
| How the command is run | `exec("ping -n 1 " + host)` — shell string | `execFile("ping", ["-n","1",host])` — argv, no shell |
| Shell involved? | **Yes** (`cmd.exe` / `/bin/sh`) | **No** (`shell: false`) |
| Host validation | None | Strict IPv4 / hostname allowlist |
| Tool restriction | Catalog lookup only (host trusted) | Enforced allowlist |
| `127.0.0.1 & whoami` | Runs `whoami` → **injection** | Rejected by validation → **blocked** |
| `127.0.0.1 & type secret` | Leaks the file → **disclosure** | Rejected → **blocked** |
| `127.0.0.1 & ping -n 4 ...` | ~3 s delay → **blind injection** | Rejected → **no delay** |
| Legitimate `127.0.0.1` | Works | Works (unchanged) |
| Blast-radius limits | Timeout + output cap | Timeout + output cap |

---

## 16. Results

| # | Attack | Vulnerable mode | Secure mode |
|---|--------|-----------------|-------------|
| 1 | Command chaining (`whoami`) | ✅ Succeeds — marker + account name returned | ❌ Blocked — host fails validation |
| 2 | Sensitive-file disclosure | ✅ Succeeds — API key returned | ❌ Blocked — host fails validation |
| 3 | Blind time-based injection | ✅ Succeeds — ~3000 ms added delay | ❌ Blocked — no delay, nothing ran |
| — | Legitimate ping of `127.0.0.1` | ✅ Works | ✅ Works (argv, exit 0) |

The one-line conclusion: **every attack that worked against the vulnerable
build fails against the secure build, and normal use is unaffected.** The only
code that changed between the two is the runner in `src/runner.js`.

---

## 17. Security Lessons Learned

1. **Don't build commands by string concatenation.** The vulnerability is born
   the instant user input is glued into a command string. If you must run an
   external program, pass arguments as a separate array and avoid a shell.
2. **Avoid the shell whenever you can.** `execFile`/`spawn` with
   `shell: false` removes the entire class of metacharacter attacks because
   there is no interpreter to trick. Reach for `exec` / `shell: true` only when
   you genuinely need shell features — and then treat every input as hostile.
3. **Prefer allowlists to blocklists.** Validating that input matches a
   known-good shape is robust; trying to strip or escape "bad" characters is a
   losing game across platforms and encodings.
4. **Validate, then still don't trust.** Validation and no-shell execution are
   complementary, not redundant. Defence in depth means an attack must defeat
   *every* layer, not just one.
5. **Apply least privilege and blast-radius limits.** Timeouts and output caps,
   and running the server with the fewest OS privileges necessary, reduce the
   damage if something else fails.
6. **Hidden output is not safety.** Blind injection shows the flaw is in
   execution, not in whether output is displayed.

---

## 18. Limitations and Future Improvements

- **Scope.** This lab covers OS command injection specifically. It is not a
  general treatment of injection (SQL, LDAP, template, etc.), though the root
  cause — mixing data into a command an interpreter parses — is shared.
- **No real multi-user model.** DrukConsole has no authentication; in a real
  app, a diagnostics console would sit behind login and authorization, and
  ideally behind an audit log of who ran what.
- **Process privileges.** The demo runs as the developer's own account. A
  production deployment should run the server as a dedicated low-privilege
  user, in a container or sandbox, so even a successful injection has little to
  reach. The fictional `lab-secret.txt` stands in for "something the process
  can read it shouldn't expose" precisely to make this point.
- **Richer validation.** A production tool might support IPv6, internationalised
  domain names, or port numbers — each would need its own carefully written
  allowlist pattern. Where a library exists for parsing the expected input type,
  prefer it to a hand-written regex.
- **Future work.** Structured logging of rejected inputs, rate limiting, and
  running the external tools inside a restricted sandbox (e.g. seccomp /
  AppContainer) would harden the console further.

---

## 19. Conclusion

OS command injection is one of the oldest and most damaging web vulnerabilities,
and this assignment reproduced it end to end in a realistic feature — a web
command-line console — and then removed it. The vulnerable build, which does
nothing more exotic than concatenate a form field into a shell command, allowed
an attacker to run arbitrary commands, read a secret off the server's disk, and
confirm execution purely through timing. The secure build, differing only in the
`src/runner.js` runner, defeated all three attacks by allowlisting the tool,
validating the host, and — most importantly — executing the program directly
with an argument array and **no shell at all**, while leaving legitimate use
untouched.

The lesson generalises far beyond this console: *never let untrusted input
become part of a command an interpreter will parse.* Pass data as data, keep it
out of the shell, and validate it against what you expect. Do that, and an
entire class of critical vulnerabilities simply has nowhere to live.

---

## 20. References

1. MITRE. *CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection').* <https://cwe.mitre.org/data/definitions/78.html>
2. OWASP. *A03:2021 – Injection.* <https://owasp.org/Top10/A03_2021-Injection/>
3. OWASP. *OS Command Injection Defense Cheat Sheet.* <https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html>
4. OWASP. *Command Injection.* <https://owasp.org/www-community/attacks/Command_Injection>
5. Node.js. *Child process — `exec`, `execFile`, `spawn`.* <https://nodejs.org/api/child_process.html>
6. OWASP. *Input Validation Cheat Sheet.* <https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html>

---

## Appendix A: How to Run the Project

> Full step-by-step instructions, including which screenshots to capture, are in
> [`instruction.md`](instruction.md).

```powershell
# 1. Install dependencies (once)
npm install

# 2a. Run the VULNERABLE version (red banner) — attacks work
npm run start:vulnerable      # http://localhost:5000

# 2b. …or the SECURE version (green banner) — attacks fail
npm run start:secure

# 3. In a SECOND terminal, run the attacks against whichever is running
npm run attack:chain          # command chaining (whoami)
npm run attack:exfil          # sensitive-file disclosure
npm run attack:blind          # blind time-based injection
```

Everything runs on `localhost`. The lab secret is fictional and created on the
fly; no external system is contacted and nothing is destroyed.

<div align="center">

---

*WEB404 · Assignment 5 · DrukConsole — a web command-line interface and its defence against command injection · local lab only.*

</div>
