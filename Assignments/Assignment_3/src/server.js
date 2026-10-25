'use strict';

const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');

const config = require('./config');
const { createDatabase } = require('./db');
const { authenticate, searchBooks, listBooks } = require('./queries');
const { loginPage, catalogPage } = require('./views');

// A single banner object describes the current security posture. It is shown at
// the top of every page and coloured red/green so screenshots make it obvious
// which version is running.
const banner = config.sqliProtection
  ? { label: 'PROTECTED MODE — parameterised queries', cssClass: 'green' }
  : { label: 'VULNERABLE MODE — string-concatenated SQL', cssClass: 'red' };

// In-memory session store: sid -> { username, role }. Sessions are lost on
// restart, which is fine for a local demo.
const sessions = new Map();

async function main() {
  // Build the fresh in-memory SQLite database before we start serving.
  const db = await createDatabase();

  const app = express();
  app.disable('x-powered-by');
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(express.static(config.publicDir));

  // Attach the current session (if any) to the request.
  app.use((req, res, next) => {
    const sid = req.cookies[config.sessionCookieName];
    req.sid = sid;
    req.session = sid ? sessions.get(sid) : undefined;
    next();
  });

  app.get('/', (req, res) => res.redirect('/catalog'));

  // ---- Catalogue search: UNION / error-based / blind injection target ------
  app.get('/catalog', (req, res) => {
    const q = req.query.q;
    // Only run a query when a search term was actually submitted, so the first
    // visit shows a clean, empty search box.
    const term = typeof q === 'string' ? q : null;
    const result = term !== null ? searchBooks(db, term, config.sqliProtection) : null;
    // When there is no search, show the whole catalogue as cards. This browse
    // query takes no user input, so it is the same in both modes.
    const books = result === null ? listBooks(db) : [];
    res.send(catalogPage(banner, req.session, term, result, books));
  });

  // ---- Login: authentication-bypass injection target -----------------------
  app.get('/login', (req, res) => {
    res.send(loginPage(banner, req.session, {}));
  });

  app.post('/login', (req, res) => {
    const username = String(req.body.username || '');
    const password = String(req.body.password || '');

    const r = authenticate(db, username, password, config.sqliProtection);

    // The visitor is considered authenticated if the query returned any row.
    const account = r.rows.length ? r.rows[0] : null;
    if (account) {
      const sid = crypto.randomBytes(16).toString('hex');
      sessions.set(sid, { username: account.username, role: account.role });
      res.cookie(config.sessionCookieName, sid, {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
      });
    }

    // Re-render the login page with the executed SQL and the outcome so the
    // injected payload stays visible for inspection and screenshots.
    res.send(
      loginPage(banner, account ? { username: account.username, role: account.role } : req.session, {
        result: {
          username,
          password,
          executedSql: r.executedSql,
          params: r.params,
          error: r.error,
          account,
          rowCount: r.rows.length,
        },
      })
    );
  });

  app.post('/logout', (req, res) => {
    if (req.sid) sessions.delete(req.sid);
    res.clearCookie(config.sessionCookieName);
    res.redirect('/catalog');
  });

  app.listen(config.port, () => {
    console.log(`DrukShelf running at http://localhost:${config.port}`);
    console.log(
      `SQL-injection protection: ${config.sqliProtection ? 'ON (protected)' : 'OFF (vulnerable)'}`
    );
  });
}

main().catch((err) => {
  console.error('Failed to start DrukShelf:', err);
  process.exit(1);
});
