'use strict';

/**
 * Tiny server-side HTML views.
 *
 * These are plain template functions rather than a templating engine so that
 * the report reader can see exactly what HTML is sent to the browser.
 *
 * `esc` HTML-escapes any value that originates from user input before it is
 * placed into the PAGE, so that this SQL-injection demo cannot accidentally
 * turn into a cross-site-scripting (XSS) demo as well. Note this is output
 * encoding for HTML — it is NOT what stops SQL injection. SQL injection is
 * stopped in queries.js by never concatenating input into SQL in the first
 * place. The two defences live at two different layers.
 */
function esc(value) {
  return String(value == null ? '' : value)
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
 * Inline icon set — the exact SVG paths from `react-icons` Feather (`Fi*`)
 * collection, drawn with `stroke="currentColor"` so they render monochrome
 * (inheriting the text colour) with no build step.
 */
const ICONS = {
  book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
  search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  key: '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  checkCircle: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
  alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  arrowRight: '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  tag: '<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/>',
  box: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>',
  sun: '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
  moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
};

function icon(name, size = 18) {
  return `<svg class="ico" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" ` +
    `stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ` +
    `aria-hidden="true">${ICONS[name] || ''}</svg>`;
}

function themeToggle() {
  return `<button id="theme-toggle" class="icon-btn" type="button" aria-label="Toggle colour theme" title="Toggle light / dark">
    <span class="icon-sun">${icon('sun', 18)}</span><span class="icon-moon">${icon('moon', 18)}</span>
  </button>`;
}

function layout(title, body, banner, session) {
  const bannerIcon = banner.cssClass === 'green' ? icon('lock') : icon('alert');
  const nav = session
    ? `<form method="POST" action="/logout" class="navform">
         <span class="who">${icon('user', 15)}<span>${esc(session.username)} · ${esc(session.role)}</span></span>
         <button class="btn ghost sm">${icon('logout', 15)}<span>Log out</span></button>
       </form>`
    : `<a class="btn ghost sm" href="/login">${icon('user', 15)}<span>Staff login</span></a>`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)} · DrukShelf</title>
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/style.css">
  <script src="/theme.js"></script>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/catalog">${icon('book', 22)}<span>DrukShelf</span></a>
    <div class="topbar-right">
      ${nav}
      ${themeToggle()}
      <div class="mode ${banner.cssClass}">${bannerIcon}<span>${esc(banner.label)}</span></div>
    </div>
  </header>
  <main class="wrap">
    ${body}
  </main>
  <footer class="foot">WEB404 · Assignment 3 · SQL-injection demonstration — local lab use only</footer>
  <script src="/app.js"></script>
</body>
</html>`;
}

/**
 * Render a SQL string, optionally highlighting the parts that came from user
 * input so the reader can SEE where data crossed into code.
 *
 * `inputs` is the list of raw user-supplied strings. We escape the whole SQL
 * first, then wrap each (escaped) input occurrence in a highlight span using
 * control-character placeholders so the wrapping cannot itself be re-matched.
 */
function renderSql(sql, inputs) {
  let out = esc(sql);
  for (const raw of inputs || []) {
    if (raw == null || raw === '') continue;
    const e = esc(String(raw));
    out = out.split(e).join('\u0000' + e + '\u0001');
  }
  return out.split('\u0000').join('<span class="inj">').split('\u0001').join('</span>');
}

/**
 * A reusable panel that prints the EXACT SQL the database engine received,
 * plus — in protected mode — the parameters that were bound separately.
 *
 * This panel is the single most useful thing in the demo: it shows, at a
 * glance, whether the user's input became part of the QUERY (vulnerable,
 * highlighted inside the query) or stayed a separate PARAMETER (protected).
 */
function sqlPanel(executedSql, params, inputs) {
  const safe = params !== null;
  const paramBlock = safe
    ? `<div class="sql-params">
         <span class="sql-label">${icon('key', 14)}<span>Bound parameters (sent separately, as data)</span></span>
         <pre class="sql">${(params || []).map((p, i) => `$${i + 1} = ${esc(JSON.stringify(p))}`).join('\n') || '(none)'}</pre>
       </div>`
    : '';
  const note = safe
    ? 'Input was bound as a parameter — the engine treats it as data, never as SQL.'
    : 'The highlighted text came from user input and is now part of the query — the engine parses it as SQL.';
  return `
  <div class="sqlbox ${safe ? 'safe' : 'danger'}">
    <span class="sql-label">${icon('database', 14)}<span>SQL sent to the database</span></span>
    <pre class="sql">${safe ? esc(executedSql) : renderSql(executedSql, inputs)}</pre>
    ${paramBlock}
    <p class="sql-note">${esc(note)}</p>
  </div>`;
}

/**
 * The "Attack Lab" — a demonstration aid, not part of a real bookshop.
 *
 * It offers one-click payloads so the assignment can be demonstrated without
 * hand-typing (and mistyping) long injection strings. In VULNERABLE mode the
 * buttons carry out the attack; in PROTECTED mode the identical buttons are
 * harmlessly neutralised, which is exactly the contrast the report shows.
 */
function attackLab(kind, protect) {
  const link = (q) => `/catalog?q=${encodeURIComponent(q)}`;

  const intro = `
    <p class="lab-note">${icon('zap', 14)}<span><strong>Attack Lab</strong> — a teaching aid for this assignment.
    ${protect
      ? 'The app is in <strong>PROTECTED</strong> mode, so these payloads are neutralised (treated as literal text).'
      : 'The app is in <strong>VULNERABLE</strong> mode, so these payloads work. Click one and read the SQL panel.'}
    </span></p>`;

  if (kind === 'catalog') {
    const buttons = [
      ['Normal search', 'clean', 'ok'],
      ['Auth-independent UNION dump (users table)', "zzz' UNION SELECT id, username, password, email, role FROM users-- ", 'bad'],
      ['Error-based (single quote)', "'", 'bad'],
      ['Boolean blind — first char = D? (true)', "zzzzz' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='D'-- ", 'bad'],
      ['Boolean blind — first char = Z? (false)', "zzzzz' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='Z'-- ", 'bad'],
    ]
      .map(([label, q, tone]) => `<a class="chip ${tone}" href="${link(q)}">${icon(tone === 'ok' ? 'search' : 'zap', 14)}<span>${esc(label)}</span></a>`)
      .join('');
    return `
    <details class="lab" ${protect ? '' : 'open'}>
      <summary>${icon('zap', 16)}<span>Attack Lab — one-click catalogue payloads</span></summary>
      ${intro}
      <div class="chips">${buttons}</div>
      <p class="lab-schema">Hidden table the UNION targets: <code>users(id, username, password, email, role)</code></p>
    </details>`;
  }

  // kind === 'login' : payloads that POST to /login
  const form = (label, username, password, tone) => `
    <form method="POST" action="/login" class="labform">
      <input type="hidden" name="username" value="${esc(username)}">
      <input type="hidden" name="password" value="${esc(password)}">
      <button class="chip ${tone}" type="submit">${icon(tone === 'ok' ? 'user' : 'zap', 14)}<span>${esc(label)}</span></button>
    </form>`;
  return `
    <details class="lab" ${protect ? '' : 'open'}>
      <summary>${icon('zap', 16)}<span>Attack Lab — one-click login payloads</span></summary>
      ${intro}
      <div class="chips">
        ${form('Legitimate login (yeshi)', 'yeshi', 'summer2023', 'ok')}
        ${form("Bypass: ' OR 1=1-- ", "' OR 1=1-- ", 'anything', 'bad')}
        ${form("Bypass target admin: admin'-- ", "admin'-- ", 'anything', 'bad')}
      </div>
    </details>`;
}

/* -------------------------------------------------------------------------- */

/** A single book rendered as a catalogue card. */
function bookCard(b) {
  return `
    <article class="bookcard">
      <div class="bookcard-top">${icon('book', 20)}<span class="cat">${esc(b.category)}</span></div>
      <h3>${esc(b.title)}</h3>
      <p class="byline">${esc(b.author)}</p>
      <div class="bookcard-foot">
        <span class="price">${esc(money(b.price))}</span>
        <span class="stock">${icon('box', 13)}<span>${esc(b.stock)} in stock</span></span>
      </div>
    </article>`;
}

/** The staff login screen (the target of the authentication-bypass attack). */
function loginPage(banner, session, { error, result } = {}) {
  const outcome = result
    ? (result.account
        ? `<p class="alert success">${icon('checkCircle')}<span>Authenticated as
             <strong>${esc(result.account.username)}</strong>
             (role: ${esc(result.account.role)}).
             ${result.rowCount > 1 ? `The query matched ${result.rowCount} rows — you were logged in as the first one.` : ''}</span></p>`
        : (result.error
            ? `<p class="alert error">${icon('alert')}<span>Database error: <code>${esc(result.error)}</code></span></p>`
            : `<p class="alert error">${icon('alert')}<span>Invalid username or password.</span></p>`))
    : '';

  const body = `
  <section class="card card-narrow">
    <div class="card-head">
      <div class="icon-badge">${icon('lock', 22)}</div>
      <div>
        <h1>Staff sign in</h1>
        <p class="muted">Sign in to manage the DrukShelf catalogue.</p>
      </div>
    </div>
    ${error ? `<p class="alert error">${icon('alert')}<span>${esc(error)}</span></p>` : ''}
    ${outcome}
    <form method="POST" action="/login" class="stack">
      <label>Username
        <span class="field">${icon('user')}<input name="username" value="${esc(result ? result.username : '')}" autocomplete="off" required></span>
      </label>
      <label>Password
        <span class="field">${icon('lock')}<input name="password" type="text" value="${esc(result ? result.password : '')}" autocomplete="off"></span>
      </label>
      <button type="submit" class="btn primary">${icon('arrowRight')}<span>Sign in</span></button>
    </form>
    ${result ? sqlPanel(result.executedSql, result.params, [result.username, result.password]) : ''}
    ${attackLab('login', banner.cssClass === 'green')}
  </section>`;
  return layout('Sign in', body, banner, session);
}

/**
 * The public catalogue + search box — the target of the UNION, error-based and
 * blind injections. `result` is null before any search (we then show the full
 * catalogue as cards), otherwise the object returned by searchBooks().
 */
function catalogPage(banner, session, term, result, books) {
  let resultsSection = '';
  if (result) {
    let panel;
    if (result.error) {
      panel = `
      <p class="alert error">${icon('alert')}
        <span>The search caused a database error, and the application leaked it
        to the page:<br><code>${esc(result.error)}</code></span></p>`;
    } else if (result.rows.length === 0) {
      panel = `<p class="alert">${icon('search')}<span>No books matched
        <strong>${esc(term)}</strong>.</span></p>`;
    } else {
      const cols = result.columns;
      const head = cols.map((c) => `<th>${esc(c)}</th>`).join('');
      const rows = result.rows
        .map(
          (r) =>
            `<tr>${cols
              .map((c) => `<td>${esc(c === 'price' && typeof r[c] === 'number' ? money(r[c]) : r[c])}</td>`)
              .join('')}</tr>`
        )
        .join('');
      panel = `
      <p class="muted">${result.rows.length} row(s) returned.</p>
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr>${head}</tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    }
    resultsSection = `
    <section class="card">
      <h2>${icon('search', 20)}<span>Search results</span></h2>
      ${panel}
      ${sqlPanel(result.executedSql, result.params, [term])}
    </section>`;
  }

  const browse = !result
    ? `<section class="card">
         <h2>${icon('book', 20)}<span>All books (${books.length})</span></h2>
         <div class="grid">${books.map(bookCard).join('')}</div>
       </section>`
    : '';

  const body = `
  <section class="card hero">
    <div class="card-head">
      <div class="icon-badge">${icon('book', 22)}</div>
      <div>
        <h1>DrukShelf catalogue</h1>
        <p class="muted">Search the bookshop by title. Every query is printed below so you can see exactly what reaches the database.</p>
      </div>
    </div>
    <form method="GET" action="/catalog" class="searchbar">
      <span class="field">${icon('search')}<input name="q" value="${esc(term || '')}" placeholder="Search by title, e.g. clean" autocomplete="off" autofocus></span>
      <button type="submit" class="btn primary">${icon('search')}<span>Search</span></button>
    </form>
    ${attackLab('catalog', banner.cssClass === 'green')}
  </section>
  ${resultsSection}
  ${browse}`;
  return layout('Catalogue', body, banner, session);
}

module.exports = { esc, money, icon, layout, sqlPanel, loginPage, catalogPage };
