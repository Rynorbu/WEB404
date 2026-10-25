'use strict';

/**
 * Tiny server-side HTML views.
 *
 * These are plain template functions rather than a templating engine so that
 * the report reader can see exactly what HTML is sent to the browser, and in
 * particular can see WHERE the CSRF token is (or is not) placed in the form.
 *
 * `esc` HTML-escapes any value that originates from user input, so that the
 * demo cannot accidentally become an XSS demo as well.
 */
function esc(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function money(n) {
  return 'Nu. ' + Number(n).toLocaleString('en-IN');
}

/**
 * Inline icon set.
 *
 * These are the exact SVG paths shipped by `react-icons` in its Feather (`Fi*`)
 * collection. They are monochrome line icons drawn with `stroke="currentColor"`,
 * so they render BLACK (inheriting the text colour) — no coloured/emoji glyphs.
 * Inlining them avoids adding a React build step to this server-rendered app
 * while using precisely the same artwork react-icons would render.
 */
const ICONS = {
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  send: '<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  checkCircle: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
  alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  dollar: '<line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>',
  arrowRight: '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
};

function icon(name, size = 18) {
  return `<svg class="ico" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" ` +
    `stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ` +
    `aria-hidden="true">${ICONS[name] || ''}</svg>`;
}

function layout(title, body, banner) {
  const bannerIcon = banner.cssClass === 'green' ? icon('shield') : icon('alert');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)} · SecureBank</title>
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header class="topbar">
    <div class="brand">${icon('shield', 22)}<span>SecureBank</span></div>
    <div class="mode ${banner.cssClass}">${bannerIcon}<span>${esc(banner.label)}</span></div>
  </header>
  <main class="wrap">
    ${body}
  </main>
  <footer class="foot">WEB404 · Assignment 2 · CSRF demonstration — local lab use only</footer>
</body>
</html>`;
}

/** The login screen. No real authentication: this demo is about CSRF, not auth. */
function loginPage(banner, error) {
  const body = `
  <section class="card card-narrow">
    <div class="card-head">
      <div class="icon-badge">${icon('lock', 22)}</div>
      <div>
        <h1>Sign in to SecureBank</h1>
        <p class="muted">Demo login — any username works. This simulates an
        already authenticated banking session so we can study CSRF.</p>
      </div>
    </div>
    ${error ? `<p class="alert error">${icon('alert')}<span>${esc(error)}</span></p>` : ''}
    <form method="POST" action="/login" class="stack">
      <label>Username
        <span class="field">${icon('user')}<input name="username" value="Yeshi" autocomplete="off" required></span>
      </label>
      <label>Password
        <span class="field">${icon('lock')}<input name="password" type="password" value="password" autocomplete="off" required></span>
      </label>
      <button type="submit" class="btn primary">${icon('arrowRight')}<span>Sign in</span></button>
    </form>
  </section>`;
  return layout('Sign in', body, banner);
}

/**
 * The account dashboard, including the money-transfer form (the state-changing
 * action an attacker wants to forge).
 *
 * The crucial teaching detail: when `csrfToken` is provided (protected mode)
 * the form contains a hidden `_csrf` field. In vulnerable mode `csrfToken` is
 * null and NO such field is rendered — the form has no proof of intent.
 */
function dashboardPage(session, banner, csrfToken, notice) {
  const rows = session.history.length
    ? session.history.map((h) => `
        <tr>
          <td>${esc(h.to)}</td>
          <td class="num">${esc(money(h.amount))}</td>
          <td>${esc(h.when)}</td>
          <td><span class="tag ${h.forged ? 'bad' : 'ok'}">${h.forged ? icon('alert', 14) : icon('check', 14)}<span>${h.forged ? 'CSRF / forged' : 'legitimate'}</span></span></td>
        </tr>`).join('')
    : `<tr><td colspan="4" class="muted">No transfers yet.</td></tr>`;

  const tokenField = csrfToken
    ? `      <!-- PROTECTED: the synchronizer CSRF token is embedded in the form.
           A cross-origin attacker cannot read this value, so it cannot forge
           a request that passes validation. -->
      <input type="hidden" name="_csrf" value="${esc(csrfToken)}">\n`
    : `      <!-- VULNERABLE: there is NO CSRF token here. The server will accept
           any POST that carries the session cookie, no matter who triggered it. -->\n`;

  const noticeIcon = notice && notice.type === 'success' ? icon('checkCircle') : icon('alert');

  const body = `
  ${notice ? `<p class="alert ${notice.type}">${noticeIcon}<span>${esc(notice.text)}</span></p>` : ''}
  <section class="card">
    <div class="rowline">
      <div class="card-head">
        <div class="icon-badge">${icon('user', 22)}</div>
        <div>
          <h1>Welcome, ${esc(session.user)}</h1>
          <p class="muted">Your SecureBank account</p>
        </div>
      </div>
      <form method="POST" action="/logout"><button class="btn ghost">${icon('logout')}<span>Log out</span></button></form>
    </div>
    <div class="balance">
      <div class="balance-label">${icon('dollar', 16)}<span>Available balance</span></div>
      <strong>${esc(money(session.balance))}</strong>
    </div>
  </section>

  <section class="card">
    <h2>${icon('send', 20)}<span>Transfer money</span></h2>
    <p class="muted">Send funds to another account. This is the
    <strong>state-changing action</strong> that CSRF targets.</p>
    <form method="POST" action="/transfer" class="stack">
${tokenField}      <label>Recipient account
        <span class="field">${icon('user')}<input name="to" value="Norbu" required></span>
      </label>
      <label>Amount (Nu.)
        <span class="field">${icon('dollar')}<input name="amount" type="number" min="1" value="100" required></span>
      </label>
      <button type="submit" class="btn primary">${icon('send')}<span>Send transfer</span></button>
    </form>
  </section>

  <section class="card">
    <h2>${icon('clock', 20)}<span>Transaction history</span></h2>
    <table class="tbl">
      <thead><tr><th>To</th><th>Amount</th><th>When</th><th>Origin</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
  return layout('Dashboard', body, banner);
}

module.exports = { esc, money, icon, layout, loginPage, dashboardPage };
