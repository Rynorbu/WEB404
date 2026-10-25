'use strict';

/**
 * The DrukConsole server.
 *
 * One application, two modes. The CLI_SECURE environment variable (read in
 * config.js) decides whether a submitted diagnostic is executed by the
 * vulnerable shell-string runner or the hardened execFile runner. Every route
 * below is identical in both modes; only the single `run(...)` call in
 * src/runner.js behaves differently.
 */
const fs = require('fs');
const express = require('express');

const config = require('./config');
const runner = require('./runner');
const views = require('./views');
const { TOOLS, isWindows } = require('./commands');

// A banner describing the current posture, shown at the top of every page and
// coloured so screenshots make the running mode obvious.
const banner = config.secure
  ? {
      label:
        'SECURE MODE — tool allowlisted, host validated, executed with no shell (execFile)',
      cssClass: 'green',
    }
  : {
      label:
        'VULNERABLE MODE — host text concatenated into a shell command and executed (exec)',
      cssClass: 'red',
    };

/**
 * Create the fictional "sensitive server file" the exfiltration attack targets,
 * if it is not already there. It is pure lab theatre — a stand-in for the kind
 * of secret a real server process can read (a config file, an API key, a
 * private key) — and it lives only on this machine. .gitignore keeps it out of
 * the repository.
 */
function ensureLabSecret() {
  try {
    if (!fs.existsSync(config.labSecretPath)) {
      fs.writeFileSync(
        config.labSecretPath,
        [
          '# DrukConsole lab secret (fictional)',
          'This file stands in for sensitive data the server process can read.',
          'If you can see these lines in the web console output, a command you',
          'injected was executed by the server and read a file it should never',
          'have exposed through a "ping a host" feature.',
          '',
          'DRUKCONSOLE_API_KEY=sk_lab_0000_not_a_real_key_1234567890',
          '',
        ].join('\n'),
        'utf8'
      );
    }
  } catch {
    /* non-fatal: the exfil demo just has nothing to read */
  }
}

function main() {
  ensureLabSecret();

  const app = express();
  app.disable('x-powered-by');
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json()); // the attacker scripts post JSON
  app.use(express.static(config.publicDir));

  // ---- console (home) ----
  app.get('/', (req, res) => {
    res.send(
      views.consolePage(banner, TOOLS, {
        toolName: 'ping',
        host: '',
        isWindows,
        secure: config.secure,
      })
    );
  });

  // ---- run a diagnostic ----
  // Shared by the browser form (returns HTML) and the attacker scripts (which
  // ask for JSON via the Accept header). The SAME runner handles both.
  app.post('/run', async (req, res) => {
    const toolName = String(req.body.tool || 'ping');
    const host = String(req.body.host == null ? '' : req.body.host);

    const result = await runner.run(toolName, host);

    const wantsJson =
      req.is('application/json') ||
      (req.get('accept') || '').includes('application/json');

    if (wantsJson) {
      return res.json({ secure: config.secure, toolName, host, result });
    }

    res.send(
      views.consolePage(banner, TOOLS, {
        toolName,
        host,
        result,
        isWindows,
        secure: config.secure,
      })
    );
  });

  // ---- explainer page ----
  app.get('/about', (req, res) => {
    res.send(views.aboutPage(banner, { secure: config.secure, isWindows }));
  });

  app.listen(config.port, () => {
    console.log(`DrukConsole running at http://localhost:${config.port}`);
    console.log(
      `Command handling: ${config.secure ? 'SECURE (execFile, allowlist + validation)' : 'VULNERABLE (shell string via exec)'}`
    );
    if (!config.secure) {
      console.log(
        'Reminder: this mode is intentionally injectable. Local lab only — do not expose this port.'
      );
    }
  });
}

main();
