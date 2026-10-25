# Screenshots

Capture the evidence for the report here. The full capture guide — what each
shot should show and when to take it — is in `../instruction.md` (Section 5 and
the checklist in Section 7).

Suggested filenames:

| File | Shows |
|------|-------|
| `01-login.png` | Login page (red banner) |
| `02-dashboard-user.png` | Dashboard — alice's decoded token (`role: user`) |
| `03-admin-403.png` | 403 Forbidden on `/admin` as alice |
| `04-inspect-none-accepted.png` | `/inspect`: `alg:none` token ACCEPTED (vulnerable) |
| `05-brute-found.png` | Terminal: `brute-secret.js` finds `"secret"` |
| `06-inspect-brute-accepted.png` | `/inspect`: cracked-secret admin token ACCEPTED (vulnerable) |
| `07-admin-forged.png` | Admin area reached with a forged cookie *(optional)* |
| `08-inspect-tamper-rejected.png` | `/inspect`: tampered token REJECTED (vulnerable) |
| `09-inspect-none-rejected.png` | `/inspect`: `alg:none` token REJECTED (secure) |
| `10-inspect-brute-rejected.png` | `/inspect`: cracked-secret token REJECTED (secure) |
| `11-admin-secure.png` | Admin area reached legitimately (secure) |
