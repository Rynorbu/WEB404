'use strict';

/**
 * Server-side HTML views, written as plain template functions (no templating
 * engine) so the report reader can see exactly what HTML is sent to the
 * browser. Every value that comes from user input or from a token is passed
 * through `esc()` before it lands in the page, so this JWT demo cannot turn
 * into a cross-site-scripting demo by accident.
 */

function esc(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* Inline Feather-style icon paths, drawn with stroke="currentColor" so they
 * inherit the text colour with no build step. */
const ICONS = {
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  key: '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  check: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
  alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  grid: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
  sun: '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
  moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
};

function icon(name, size = 18) {
  return `<svg class="ico" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" ` +
    `stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ` +
    `aria-hidden="true">${ICONS[name] || ''}</svg>`;
}

function themeToggle() {
  return `<button id="theme-toggle" class="icon-btn" type="button" aria-label="Toggle colour theme" title="Toggle light / dark">` +
    `<span class="only-light">${icon('moon')}</span><span class="only-dark">${icon('sun')}</span></button>`;
}

/* The three coloured segments of a raw JWT string, so the header / payload /
 * signature are visually distinct wherever a token is shown. */
function colourToken(token) {
  const parts = String(token).split('.');
  const names = ['tok-h', 'tok-p', 'tok-s'];
  return parts
    .map((p, i) => `<span class="${names[i] || 'tok-s'}">${esc(p)}</span>`)
    .join('<span class="tok-dot">.</span>');
}

function layout({ banner, session, active, title, body }) {
  const nav = session
    ? `<a class="nav-link${active === 'dashboard' ? ' on' : ''}" href="/dashboard">${icon('grid')} Dashboard</a>` +
      (session.role === 'admin'
        ? `<a class="nav-link${active === 'admin' ? ' on' : ''}" href="/admin">${icon('shield')} Admin</a>`
        : '') +
      `<a class="nav-link${active === 'inspect' ? ' on' : ''}" href="/inspect">${icon('search')} Token Inspector</a>`
    : `<a class="nav-link${active === 'inspect' ? ' on' : ''}" href="/inspect">${icon('search')} Token Inspector</a>`;

  const userArea = session
    ? `<span class="whoami">${icon('user')} ${esc(session.displayName || session.sub)} ` +
      `<span class="role-pill ${session.role === 'admin' ? 'role-admin' : 'role-user'}">${esc(session.role)}</span></span>` +
      `<form method="POST" action="/logout" class="inline">${themeToggle()}<button class="btn btn-ghost" type="submit">${icon('logout')} Log out</button></form>`
    : `${themeToggle()}<a class="btn btn-primary" href="/login">${icon('lock')} Log in</a>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · DrukPass</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script src="/theme.js"></script>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="banner ${banner.cssClass}">${icon(banner.cssClass === 'green' ? 'check' : 'alert')} ${esc(banner.label)}</div>
<header class="topbar">
  <a class="brand" href="/dashboard">${icon('shield', 22)} <span>DrukPass</span></a>
  <nav class="nav">${nav}</nav>
  <div class="user-area">${userArea}</div>
</header>
<main class="wrap">${body}</main>
<footer class="foot">WEB404 · Assignment 4 · JWT Authentication, Attacks &amp; Secure Handling · local lab only</footer>
<script src="/app.js"></script>
</body>
</html>`;
}

/* ---- login ---- */
function loginPage(banner, session, { error } = {}) {
  const body = `
  <section class="hero">
    <h1>${icon('lock', 26)} Sign in to DrukPass</h1>
    <p class="lead">On a successful login the server issues a signed <strong>JSON Web Token</strong> and stores it in an <code>httpOnly</code> cookie. Every protected page then trusts whatever that token says — which is exactly why how the token is <em>verified</em> matters so much.</p>
  </section>
  <div class="grid-2">
    <div class="card">
      <h2>${icon('user')} Credentials</h2>
      ${error ? `<div class="notice bad">${icon('alert')} ${esc(error)}</div>` : ''}
      <form method="POST" action="/login" class="form">
        <label>Username<input name="username" autocomplete="username" autofocus required></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
        <button class="btn btn-primary btn-block" type="submit">${icon('key')} Log in</button>
      </form>
    </div>
    <div class="card muted-card">
      <h2>${icon('alert')} Lab accounts</h2>
      <p class="hint">Fictional accounts seeded in memory. The login step is not the subject of this assignment — the attacks never need these passwords.</p>
      <table class="mini">
        <tr><th>Username</th><th>Password</th><th>Role</th></tr>
        <tr><td><code>alice</code></td><td><code>password123</code></td><td><span class="role-pill role-user">user</span></td></tr>
        <tr><td><code>admin</code></td><td><code>S3cureAdminPass!</code></td><td><span class="role-pill role-admin">admin</span></td></tr>
      </table>
    </div>
  </div>`;
  return layout({ banner, session, active: 'login', title: 'Log in', body });
}

/* Render the decoded header + payload of a token as pretty JSON panels. */
function tokenPanels(token, decoded) {
  return `
  <div class="token-raw">${colourToken(token)}</div>
  <div class="legend">
    <span><span class="swatch tok-h"></span> header</span>
    <span><span class="swatch tok-p"></span> payload</span>
    <span><span class="swatch tok-s"></span> signature</span>
  </div>
  <div class="grid-2">
    <div><div class="panel-label">Header</div><pre class="json">${esc(JSON.stringify(decoded.header, null, 2))}</pre></div>
    <div><div class="panel-label">Payload (claims)</div><pre class="json">${esc(JSON.stringify(decoded.payload, null, 2))}</pre></div>
  </div>`;
}

/* ---- dashboard ---- */
function dashboardPage(banner, session, { token, decoded }) {
  const exp = decoded.payload.exp
    ? new Date(decoded.payload.exp * 1000).toLocaleString()
    : '— (no expiry claim)';
  const body = `
  <section class="hero">
    <h1>${icon('grid', 24)} Your session</h1>
    <p class="lead">You are signed in as <strong>${esc(session.displayName || session.sub)}</strong>. The page below is drawn entirely from the JWT in your cookie — decoded here so you can see precisely what the server is trusting.</p>
  </section>
  <div class="card">
    <h2>${icon('key')} Access token</h2>
    ${tokenPanels(token, decoded)}
    <dl class="facts">
      <div><dt>Subject</dt><dd>${esc(decoded.payload.sub)}</dd></div>
      <div><dt>Role</dt><dd><span class="role-pill ${decoded.payload.role === 'admin' ? 'role-admin' : 'role-user'}">${esc(decoded.payload.role)}</span></dd></div>
      <div><dt>Algorithm (header)</dt><dd><code>${esc(decoded.header.alg)}</code></dd></div>
      <div><dt>Expires</dt><dd>${esc(exp)}</dd></div>
    </dl>
    <p class="hint">${icon('search')} Copy this token into the <a href="/inspect">Token Inspector</a> to see how the current verifier judges it — or tamper with it first.</p>
  </div>`;
  return layout({ banner, session, active: 'dashboard', title: 'Dashboard', body });
}

/* ---- admin (role-gated) ---- */
function adminPage(banner, session) {
  const body = `
  <section class="hero">
    <h1>${icon('shield', 24)} Administrator area</h1>
    <p class="lead">This page is reachable only when the verified token carries <code>"role":"admin"</code>. In the real world this is where user management, billing, and audit logs would live — the prize an attacker is after.</p>
  </section>
  <div class="card ok-card">
    <h2>${icon('check')} Access granted</h2>
    <p>The server accepted a token whose <code>role</code> claim is <strong>admin</strong>. Signed in as <strong>${esc(session.displayName || session.sub)}</strong>.</p>
    <ul class="admin-list">
      <li>${icon('user')} Manage user accounts</li>
      <li>${icon('key')} Rotate signing keys</li>
      <li>${icon('shield')} View the security audit log</li>
    </ul>
  </div>`;
  return layout({ banner, session, active: 'admin', title: 'Admin', body });
}

/* ---- 403 when a non-admin (or forged-but-rejected) token hits /admin ---- */
function forbiddenPage(banner, session, message) {
  const body = `
  <div class="card bad-card">
    <h2>${icon('alert')} 403 — Forbidden</h2>
    <p>${esc(message || 'You need an admin token to view this page.')}</p>
    <p class="hint"><a href="/dashboard">Back to dashboard</a></p>
  </div>`;
  return layout({ banner, session, active: 'admin', title: 'Forbidden', body });
}

/* ---- token inspector / playground ---- */
function inspectPage(banner, session, { input, result } = {}) {
  let output = '';
  if (result) {
    const verdictClass = result.verifyResult.valid ? 'ok' : 'bad';
    const verdictIcon = result.verifyResult.valid ? 'check' : 'alert';
    const verdictWord = result.verifyResult.valid ? 'ACCEPTED' : 'REJECTED';
    output = `
    <div class="card">
      <h2>${icon('search')} Decoded</h2>
      ${result.decodeError
        ? `<div class="notice bad">${icon('alert')} ${esc(result.decodeError)}</div>`
        : tokenPanels(input, result.decoded)}
    </div>
    <div class="card ${verdictClass}-card">
      <h2>${icon(verdictIcon)} Verifier verdict: ${verdictWord}</h2>
      <p>${esc(result.verifyResult.reason)}</p>
      ${result.verifyResult.valid
        ? `<p class="hint">In <strong>${banner.cssClass === 'green' ? 'secure' : 'vulnerable'}</strong> mode, the server would treat this request as <strong>${esc((result.verifyResult.payload && result.verifyResult.payload.sub) || 'unknown')}</strong> with role <strong>${esc((result.verifyResult.payload && result.verifyResult.payload.role) || 'none')}</strong>.</p>`
        : ''}
    </div>`;
  }
  const body = `
  <section class="hero">
    <h1>${icon('search', 24)} Token Inspector</h1>
    <p class="lead">Paste any JWT below. It is decoded without verification (so even a forged or broken token is shown), then run through the <strong>current mode's</strong> verifier so you can watch it be accepted or rejected. This is where the output of the attack scripts gets tested.</p>
  </section>
  <div class="card">
    <form method="POST" action="/inspect" class="form">
      <label>JWT<textarea name="token" rows="5" spellcheck="false" placeholder="header.payload.signature" required>${esc(input || '')}</textarea></label>
      <button class="btn btn-primary" type="submit">${icon('search')} Decode &amp; verify</button>
    </form>
  </div>
  ${output}`;
  return layout({ banner, session, active: 'inspect', title: 'Token Inspector', body });
}

module.exports = {
  esc,
  loginPage,
  dashboardPage,
  adminPage,
  forbiddenPage,
  inspectPage,
};
