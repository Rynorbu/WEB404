'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');

const config = require('./config');
const { SessionStore } = require('./session');
const { isValidToken } = require('./csrf');
const { loginPage, dashboardPage } = require('./views');

const sessions = new SessionStore();

// A single banner object describes the current security posture. It is shown at
// the top of every page and coloured red/green so screenshots make it obvious
// which version is running.
const banner = config.csrfProtection
  ? { label: 'PROTECTED MODE — CSRF token required', cssClass: 'green' }
  : { label: 'VULNERABLE MODE — no CSRF protection', cssClass: 'red' };

const app = express();
app.disable('x-powered-by');

// Parse form posts and cookies. `extended: false` is fine: our forms are simple
// key/value pairs.
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Static assets (stylesheet, favicon, theme toggle).
app.use(express.static(config.publicDir));

/**
 * Attach the current session (if any) to the request.
 *
 * IMPORTANT for the demo: the session cookie is set with SameSite=Lax (the
 * modern browser default). localhost:3000 and localhost:4000 are the SAME SITE
 * (host "localhost"), so the cookie is still sent between them, yet they are
 * DIFFERENT ORIGINS — which is exactly what makes the attacker request a real
 * cross-origin CSRF request. This lets the classic attack be reproduced over
 * plain http on localhost without any HTTPS gymnastics.
 */
function loadSession(req, res, next) {
  const sid = req.cookies[config.sessionCookieName];
  req.sid = sid;
  req.session = sid ? sessions.get(sid) : undefined;
  next();
}
app.use(loadSession);

function requireLogin(req, res, next) {
  if (!req.session) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => {
  res.redirect(req.session ? '/dashboard' : '/login');
});

app.get('/login', (req, res) => {
  res.send(loginPage(banner, null));
});

app.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  if (!username) return res.send(loginPage(banner, 'Please enter a username.'));

  const sid = sessions.create(username, config.startingBalance);

  // The session cookie. HttpOnly keeps it away from JavaScript; SameSite=Lax is
  // the realistic modern default (see note on loadSession above).
  res.cookie(config.sessionCookieName, sid, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
  });

  res.redirect('/dashboard');
});

app.post('/logout', (req, res) => {
  if (req.sid) sessions.destroy(req.sid);
  res.clearCookie(config.sessionCookieName);
  res.redirect('/login');
});

app.get('/dashboard', requireLogin, (req, res) => {
  // Only hand the CSRF token to the page in protected mode. In vulnerable mode
  // the form is rendered without it.
  const token = config.csrfProtection ? req.session.csrfToken : null;
  res.send(dashboardPage(req.session, banner, token, null));
});

/**
 * The state-changing endpoint CSRF targets.
 *
 * In BOTH modes the browser has already attached the session cookie, so the
 * user is "authenticated". The ONLY difference is the token check below.
 */
app.post('/transfer', requireLogin, (req, res) => {
  const to = String(req.body.to || '').trim() || 'unknown';
  const amount = Math.max(0, Math.floor(Number(req.body.amount) || 0));

  // ---- THE CSRF DEFENCE -------------------------------------------------
  // In protected mode we demand a valid synchronizer token. A forged request
  // from the attacker page cannot supply it, so it is rejected here with 403
  // BEFORE any money moves.
  if (config.csrfProtection) {
    const submitted = req.body._csrf;
    if (!isValidToken(req.session.csrfToken, submitted)) {
      return res.status(403).send(
        dashboardPage(req.session, banner, req.session.csrfToken, {
          type: 'error',
          text: 'Transfer rejected: missing or invalid CSRF token. ' +
                'This request did not originate from a SecureBank page.',
        })
      );
    }
  }
  // In vulnerable mode there is no check at all — we fall straight through and
  // perform the transfer for ANY request that carries the session cookie.
  // -----------------------------------------------------------------------

  if (amount <= 0) {
    return res.status(400).send(
      dashboardPage(req.session, banner, config.csrfProtection ? req.session.csrfToken : null, {
        type: 'error', text: 'Amount must be a positive number.',
      })
    );
  }

  // A request is flagged as "forged" when the browser tells us (via the Origin/
  // Referer header) that it was triggered by a page on a different origin. We
  // only use this to LABEL rows in the history table for the screenshots; it is
  // NOT the defence. (Origin checking can be a complementary defence, but the
  // token is the primary one this assignment implements.)
  const origin = req.get('origin') || req.get('referer') || '';
  const forged = origin !== '' && !origin.startsWith(`http://localhost:${config.port}`);

  req.session.balance -= amount;
  req.session.history.unshift({
    to,
    amount,
    when: new Date().toLocaleTimeString(),
    forged,
  });

  const token = config.csrfProtection ? req.session.csrfToken : null;
  res.send(dashboardPage(req.session, banner, token, {
    type: forged ? 'error' : 'success',
    text: forged
      ? `A transfer of Nu. ${amount} to "${to}" was just made by a request from ${origin}. ` +
        `You never clicked "Send" on SecureBank — this is CSRF.`
      : `Transfer of Nu. ${amount} to "${to}" completed.`,
  }));
});

app.listen(config.port, () => {
  console.log(`SecureBank running at http://localhost:${config.port}`);
  console.log(`CSRF protection: ${config.csrfProtection ? 'ON (protected)' : 'OFF (vulnerable)'}`);
});
