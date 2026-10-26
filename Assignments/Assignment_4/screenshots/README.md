# Screenshots

These are the captured evidence files used in the report (`../README.md`). The
figure numbers below match the figures in the report.

| File | Report figure | Shows |
|------|---------------|-------|
| `1.png` | Figure 1 | Login page (vulnerable / red mode) |
| `2.png` | Figure 2 | Dashboard: alice's decoded token (`role: user`) |
| `3.png` | Figure 3 | 403 Forbidden on `/admin` as alice |
| `4.png` | Figure 4 | Inspector: `alg:none` token ACCEPTED (vulnerable) |
| `5.png` | Figure 5 | Terminal: brute force recovers the secret `"secret"` |
| `6.png` | Figure 6 | Inspector: cracked secret admin token ACCEPTED (vulnerable) |
| `8.png` | Figure 7 | Inspector: tampered token REJECTED (vulnerable) |
| `9.png` | Figure 8 | Inspector: `alg:none` token REJECTED (secure) |
| `10.png` | Figure 9 | Inspector: cracked secret token REJECTED (secure) |
| `11.png` | Figure 10 | Admin area reached legitimately (secure / green mode) |
