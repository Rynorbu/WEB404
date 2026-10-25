'use strict';

/**
 * Server-side HTML views, written as plain template functions (no templating
 * engine) so the report reader can see exactly what HTML is sent to the
 * browser. Every value that comes from user input or from command output is
 * passed through `esc()` before it lands in the page, so this command-injection
 * demo cannot accidentally turn into a cross-site-scripting demo as well.
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
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  play: '<polygon points="5 3 19 12 5 21 5 3"/>',
  check: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
  alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
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

function layout({ banner, active, title, body }) {
  const nav =
    `<a class="nav-link${active === 'console' ? ' on' : ''}" href="/">${icon('terminal')} Console</a>` +
    `<a class="nav-link${active === 'about' ? ' on' : ''}" href="/about">${icon('book')} How it works</a>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · DrukConsole</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script src="/theme.js"></script>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="banner ${banner.cssClass}">${icon(banner.cssClass === 'green' ? 'check' : 'alert')} ${esc(banner.label)}</div>
<header class="topbar">
  <a class="brand" href="/">${icon('terminal', 22)} <span>DrukConsole</span></a>
  <nav class="nav">${nav}</nav>
  <div class="user-area">${themeToggle()}</div>
</header>
<main class="wrap">${body}</main>
<footer class="foot">WEB404 · Assignment 5 · Web Command-Line Interface &amp; Command-Injection Defence · local lab only</footer>
<script src="/app.js"></script>
</body>
</html>`;
}

/* The tool <select>, built from the shared catalog so the dropdown and the
 * runner can never drift apart. */
function toolOptions(tools, selected) {
  return Object.entries(tools)
    .map(
      ([name, t]) =>
        `<option value="${esc(name)}"${name === selected ? ' selected' : ''}>${esc(t.label)}</option>`
    )
    .join('');
}

/* Render one captured result (what the server ran and what came back). */
function resultBlock(result) {
  if (!result) return '';

  // Rejected before anything ran (secure mode's allowlist / validation).
  if (!result.ran) {
    return `
    <div class="card">
      <h2>${icon('shield')} Result</h2>
      <p><span class="verdict blocked">${icon('check')} Blocked before execution</span></p>
      <div class="notice ok">${icon('shield')} ${esc(result.guard.reason)}</div>
      <p class="hint">Nothing was handed to the operating system. The request never became a running command.</p>
    </div>`;
  }

  const verdictClass = result.mode === 'vulnerable' ? 'ran-shell' : 'ran-safe';
  const verdictText =
    result.mode === 'vulnerable'
      ? 'Executed in a shell'
      : 'Executed directly (no shell)';

  const prompt = result.mode === 'vulnerable' ? 'sh$' : 'exec';
  const launch = result.launchError
    ? `<div class="notice warn">${icon('alert')} The program could not be launched (<code>${esc(result.launchError)}</code>). On this machine the tool may be named differently or be unavailable — the injection lesson still holds, because the shell still parsed your input.</div>`
    : '';
  const timeout = result.timedOut
    ? `<div class="notice warn">${icon('alert')} The command hit the ${'5s'} time limit and was killed.</div>`
    : '';

  return `
  <div class="card">
    <h2>${icon('terminal')} Result</h2>
    <p>
      <span class="verdict ${verdictClass}">${icon(result.mode === 'vulnerable' ? 'alert' : 'check')} ${verdictText}</span>
    </p>
    <div class="notice ${result.mode === 'vulnerable' ? 'bad' : 'ok'}">${esc(result.guard.reason)}</div>

    <p class="hint" style="margin-top:14px">Command the server actually ran:</p>
    <code class="cmdline"><span class="prompt">${esc(prompt)}</span> ${esc(result.commandShown)}</code>
    ${launch}${timeout}

    ${result.stdout.trim()
      ? `<p class="hint" style="margin-top:12px">Standard output:</p><pre class="term stdout">${esc(result.stdout.trim())}</pre>`
      : ''}
    ${result.stderr.trim()
      ? `<p class="hint" style="margin-top:12px">Standard error:</p><pre class="term stderr">${esc(result.stderr.trim())}</pre>`
      : ''}
    ${!result.stdout.trim() && !result.stderr.trim()
      ? `<pre class="term"><span class="muted">(no output captured)</span></pre>`
      : ''}

    <div class="meta-row">
      <span>mode: <code>${esc(result.mode)}</code></span>
      <span>exit code: <code>${result.exitCode == null ? '—' : esc(result.exitCode)}</code></span>
    </div>
  </div>`;
}

/* Attack presets offered in the vulnerable UI so a grader can reproduce each
 * injection in one click. Hidden in secure mode (they all get blocked anyway,
 * but the console is not a toy there). */
function payloadPresets(isWindows) {
  const sep = isWindows ? '&' : ';';
  const readFile = isWindows ? 'type lab-secret.txt' : 'cat lab-secret.txt';
  const presets = [
    { lab: 'Command chaining — run a second command', value: `127.0.0.1 ${sep} whoami` },
    { lab: 'Sensitive file disclosure', value: `127.0.0.1 ${sep} ${readFile}` },
    { lab: 'Blind injection — drop a marker file', value: `127.0.0.1 ${sep} echo owned > pwned.txt` },
  ];
  return `
  <div class="card muted-card">
    <h2>${icon('alert')} Injection presets</h2>
    <p class="hint">Click one to fill the host field, then press <strong>Run</strong>. These are harmless (read-only / local), demonstrate the flaw, and only do anything in <strong>vulnerable</strong> mode.</p>
    <div class="payload-list">
      ${presets
        .map(
          (p) =>
            `<button type="button" class="payload-btn" data-fill="${esc(p.value)}"><span class="lab">${esc(p.lab)}</span>${esc(p.value)}</button>`
        )
        .join('')}
    </div>
  </div>`;
}

function consolePage(banner, tools, { toolName, host, result, isWindows, secure } = {}) {
  const body = `
  <section class="hero">
    <h1>${icon('terminal', 26)} Diagnostics console</h1>
    <p class="lead">A small web front-end over system network tools. Pick a tool, enter a host, and the server runs it and shows you the output — a <strong>command-line interface inside a web application</strong>. How the server turns your input into a command is the whole subject of this assignment.</p>
  </section>
  <div class="grid-2">
    <div class="card">
      <h2>${icon('play')} Run a diagnostic</h2>
      <form method="POST" action="/run" class="form">
        <label>Tool
          <select name="tool">${toolOptions(tools, toolName || 'ping')}</select>
        </label>
        <label>Host
          <input name="host" id="host" value="${esc(host || '')}" placeholder="${esc(tools.ping.placeholder)}" autocomplete="off" spellcheck="false" autofocus>
        </label>
        <button class="btn btn-primary btn-block" type="submit">${icon('play')} Run</button>
      </form>
      <p class="hint" style="margin-top:12px">${
        secure
          ? 'Secure mode: the host must be a valid IP or hostname, and it is executed directly with no shell.'
          : 'Vulnerable mode: whatever you type is concatenated into a shell command and executed.'
      }</p>
    </div>
    ${secure ? aboutCardShort() : payloadPresets(isWindows)}
  </div>
  ${resultBlock(result)}`;

  return layout({ banner, active: 'console', title: 'Console', body });
}

function aboutCardShort() {
  return `
  <div class="card muted-card">
    <h2>${icon('shield')} Why this is safe now</h2>
    <ul class="hint" style="line-height:1.7">
      <li><strong>Allowlist:</strong> only the tools in the dropdown can run.</li>
      <li><strong>Validation:</strong> the host must match a strict IP / hostname pattern.</li>
      <li><strong>No shell:</strong> the program runs via <code>execFile</code> with an argv array, so <code>&amp;</code>, <code>|</code>, <code>;</code>, <code>$()</code> are just literal text.</li>
    </ul>
    <p class="hint">Try any injection preset from the vulnerable mode here — each one is now rejected or runs harmlessly as a single literal argument.</p>
  </div>`;
}

function aboutPage(banner, { secure, isWindows } = {}) {
  const sep = isWindows ? '&' : ';';
  const body = `
  <section class="hero">
    <h1>${icon('book', 26)} How it works</h1>
    <p class="lead">The same console runs in two modes. Only <code>src/runner.js</code> changes between them.</p>
  </section>

  <div class="card">
    <h2>${icon('alert')} Vulnerable mode — a shell string</h2>
    <p>The host you type is concatenated onto a command template and the whole string is handed to a shell:</p>
    <code class="cmdline"><span class="prompt">sh$</span> ping -n 1 &lt;your host&gt;</code>
    <p class="hint" style="margin-top:10px">So typing <code>127.0.0.1 ${esc(sep)} whoami</code> makes the shell see <em>two</em> commands. This is <strong>CWE-78: OS Command Injection</strong>.</p>
  </div>

  <div class="card">
    <h2>${icon('check')} Secure mode — three layers</h2>
    <ol style="line-height:1.8">
      <li><strong>Allowlist the tool.</strong> A tool not in the catalog cannot run.</li>
      <li><strong>Validate the host.</strong> It must match a strict IPv4 / hostname pattern — no spaces, no <code>&amp; | ; $ \` ( )</code>.</li>
      <li><strong>No shell.</strong> The program is launched with <code>execFile(bin, [args], { shell: false })</code>, so the host is one literal argument and metacharacters mean nothing.</li>
    </ol>
    <p class="hint">Defence in depth: any one layer already stops the attacks; together they leave no room for injection.</p>
  </div>

  <p><a class="btn btn-primary" href="/">${icon('terminal')} Back to the console (${secure ? 'secure' : 'vulnerable'} mode)</a></p>`;

  return layout({ banner, active: 'about', title: 'How it works', body });
}

module.exports = { consolePage, aboutPage, esc };
