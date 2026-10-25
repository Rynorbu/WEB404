# Instructions — Running the Demo and Capturing the Screenshots

This file tells you **exactly** how to set up, run, and demonstrate the
command-injection assignment, and **which screenshots to take** for the report
(`README.md`).

Everything runs on your own machine (`localhost`). The only "target" is the
demo server you start yourself. Every injected command is harmless and local —
printing the current user name, reading a *fictional* secret file the app
creates, and making the server pause a few seconds — and nothing here touches
any real or third-party system. Command injection is demonstrated **only** to
understand and prevent it.

---

## 0. What you are about to build and show

You will run **one application** — **DrukConsole**, a web page with a built-in
command-line console for network diagnostics — that can start in either of two
modes, chosen by an environment variable:

| Mode | Command | Banner | What happens to the attacks |
|------|---------|--------|-----------------------------|
| **Vulnerable** | `npm run start:vulnerable` | 🔴 red | They **work** |
| **Secure** | `npm run start:secure` | 🟢 green | They **fail** |

The same app runs at <http://localhost:5000> in both modes. The only thing that
changes is **how an incoming request becomes a running command** — the single
`run(...)` call in `src/runner.js`.

> **Why one app, two modes?** It makes the comparison fair: the report shows the
> *same* injection payload being executed by the vulnerable build and rejected
> by the secure build, with nothing else changed.

---

## 1. Environment / setup requirements

- **Node.js 20 or newer** — check with `node --version`.
- **A modern browser** — Chrome or Edge (DevTools screenshots assume Chrome).
- **Windows PowerShell** (the commands below work the same in any terminal).
  `curl.exe` ships with Windows 10/11. The attack scripts are cross-platform.

---

## 2. Installation

Open a terminal in the `Assignment_5` folder and install dependencies once:

```powershell
npm install
```

This installs `express` and `cross-env`. There is **no** command-building or
sanitising library — the vulnerable and secure runners are both written by hand
in `src/runner.js` so every step is inspectable.

---

## 3. How to start the application

You need **one terminal** for the app. The attack scripts (Section 6) run in a
**second** terminal.

### The vulnerable version (Parts A and B)

```powershell
npm run start:vulnerable
```

You should see `DrukConsole running at http://localhost:5000` and
`Command handling: VULNERABLE (shell string via exec)`.

### The secure version (Part C)

Stop the vulnerable server first (**Ctrl + C**), then:

```powershell
npm run start:secure
```

You should see `Command handling: SECURE (execFile, allowlist + validation)`.

> Only one server can use port 5000 at a time. Always **Ctrl + C** the old one
> before starting the other, or you will get an `EADDRINUSE` error (and the new
> server will quietly fail to take over the port).

---

## 4. Using the console in the browser

1. Open <http://localhost:5000>.
2. Leave the tool on **Ping a host** and type `127.0.0.1` in the Host field,
   then press **Run** — this is a normal, legitimate request.
3. In **vulnerable** mode, click one of the **injection presets** on the right
   to fill the Host field with a ready-made payload, then press **Run** and read
   the Result card.
4. Switch modes (restart the server) and try the same payload to see it blocked.

The **How it works** page (<http://localhost:5000/about>) explains both runners
side by side.

---

## 5. Screenshots to capture

Save screenshots into the `screenshots/` folder. Suggested shots:

| File | Mode | Shows |
|------|------|-------|
| `01-console-vuln.png` | 🔴 | The console with the red banner |
| `02-legit-ping.png` | 🔴 | A normal `127.0.0.1` ping returning output |
| `03-chain-browser.png` | 🔴 | Preset `127.0.0.1 & whoami` run in the browser — output shows the account name |
| `04-chain-terminal.png` | 🔴 | `npm run attack:chain` — marker + `whoami` in the terminal |
| `05-exfil.png` | 🔴 | `npm run attack:exfil` — the `DRUKCONSOLE_API_KEY` line returned |
| `06-blind.png` | 🔴 | `npm run attack:blind` — baseline vs injected timing, ~3000 ms delay |
| `07-console-secure.png` | 🟢 | The console with the green banner |
| `08-chain-blocked.png` | 🟢 | Same chaining payload → "Blocked before execution" card |
| `09-attacks-blocked-terminal.png` | 🟢 | The three `attack:*` scripts all reporting BLOCKED / PREVENTED |
| `10-legit-secure.png` | 🟢 | `127.0.0.1` still works in secure mode (argv shown, exit 0) |

---

## 6. Running the attacks (second terminal)

With a server running (see Section 3), open a **second** terminal in the
`Assignment_5` folder and run:

```powershell
npm run attack:chain     # Attack 1: command chaining — runs whoami
npm run attack:exfil     # Attack 2: reads the fictional lab-secret.txt
npm run attack:blind     # Attack 3: blind time-based injection (~3s delay)
```

Each script prints the payload, the server mode, the exact command the server
ran, the captured output, and a plain-English verdict.

- Against **`start:vulnerable`** you should see **SUCCEEDED / CONFIRMED**.
- Against **`start:secure`** you should see **BLOCKED / PREVENTED** every time.

> The scripts talk only to `http://localhost:5000`. To point them elsewhere in
> your own lab, set `TARGET`, e.g. `cross-env TARGET=http://localhost:5000 node attacker/inject-chain.js`.

---

## 7. Demonstration checklist

- [ ] `npm install` completed without errors.
- [ ] **Vulnerable** server starts (red banner, port 5000).
- [ ] Legitimate `127.0.0.1` ping returns output.
- [ ] `attack:chain` returns the marker **and** the `whoami` account name.
- [ ] `attack:exfil` returns the `DRUKCONSOLE_API_KEY` line.
- [ ] `attack:blind` reports a ~3000 ms added delay (injection CONFIRMED).
- [ ] **Secure** server starts (green banner) after Ctrl + C.
- [ ] All three attacks now report BLOCKED / PREVENTED.
- [ ] Legitimate `127.0.0.1` ping still works in secure mode.
- [ ] Screenshots saved in `screenshots/`.

---

## 8. Troubleshooting

- **`EADDRINUSE` on start** — another server is still on port 5000. Ctrl + C it,
  or close the other terminal, then start again.
- **Attack script says "Could not reach the server"** — start a server first
  (Section 3); make sure it is the vulnerable one if you expect the attacks to
  work.
- **`ping`/`nslookup` "could not be launched"** — rare, but if a tool is missing
  or named differently on your machine, the injection lesson still holds: in
  vulnerable mode the shell still parsed your input (you will see the marker /
  delay); only the specific tool output changes.
- **Secure mode seems to "work" for an attack** — you are almost certainly still
  running the vulnerable server. Confirm the green banner and the
  `Command handling: SECURE` line, and that no second node process is holding
  the port.
