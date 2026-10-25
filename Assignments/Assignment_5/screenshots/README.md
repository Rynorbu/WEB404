# Screenshots

Capture the evidence for the report here. The full capture guide — what each
shot should show and when to take it — is in `../instruction.md` (Section 5 and
the checklist in Section 7).

Suggested filenames:

| File | Shows |
|------|-------|
| `01-console-vuln.png` | Console with the red (vulnerable) banner |
| `02-legit-ping.png` | A normal `127.0.0.1` ping returning output |
| `03-chain-browser.png` | Preset `127.0.0.1 & whoami` run in the browser (vulnerable) |
| `04-chain-terminal.png` | `npm run attack:chain` — marker + `whoami` account name |
| `05-exfil.png` | `npm run attack:exfil` — the `DRUKCONSOLE_API_KEY` line leaked |
| `06-blind.png` | `npm run attack:blind` — ~3000 ms added delay confirmed |
| `07-console-secure.png` | Console with the green (secure) banner |
| `08-chain-blocked.png` | Same chaining payload → "Blocked before execution" |
| `09-attacks-blocked-terminal.png` | All three `attack:*` scripts reporting BLOCKED |
| `10-legit-secure.png` | `127.0.0.1` still works in secure mode (argv, exit 0) |
