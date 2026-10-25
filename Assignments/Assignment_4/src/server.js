'use strict';

/**
 * The DrukPass JWT demo server.
 *
 * One application, two modes. The JWT_SECURE environment variable (read in
 * config.js) decides whether incoming tokens are checked by the vulnerable
 * verifier or the hardened one. Every route below is identical in both modes;
 * only the single `jwt.verify(...)` call behaves differently.
 */
const express = require('express');
const cookieParser = require('cookie-parser');

const config = require('./config');
const jwt = require('./jwt');
const { authenticate, getUser } = require('./users');
const views = require('./views');

// A banner describing the current posture, shown at the top of every page and
// coloured so screenshots make the running mode obvious.
const banner = config.secure
  ? { label: 'SECURE MODE — algorithm pinned, signature + exp/iss/aud enforced', cssClass: 'green' }
  : { label: 'VULNERABLE MODE — header-chosen algorithm, "none" allowed, no expiry check, weak secret', cssClass: 'red' };

/**
 * Read the token cookie, run it through the active verifier, and return a
 * session object ({ sub, role, displayName }) when it is accepted — or null.
 * This is the one place the whole app decides who the caller is.
 */
function sessionFromRequest(req) {
  const token = req.cookies[config.tokenCookieName];
  if (!token) return null;

  const result = jwt.verify(token, config.secret, {
    secure: config.secure,
    issuer: config.issuer,
    audience: config.audience,
  });
  if (!result.valid) return null;

  const profile = getUser(result.payload.sub);
  // The role we ACT on comes from the token's claim, not from the directory —
  // that is deliberate, so a forged/tampered role claim has a visible effect.
  return {
    sub: result.payload.sub,
    role: result.payload.role,
    displayName: profile ? profile.displayName : result.payload.sub,
  };
}

function main() {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(express.static(config.publicDir));

  app.use((req, res, next) => {
    req.session = sessionFromRequest(req);
    next();
  });

  app.get('/', (req, res) => res.redirect(req.session ? '/dashboard' : '/login'));

  // ---- login ----
  app.get('/login', (req, res) => {
    if (req.session) return res.redirect('/dashboard');
    res.send(views.loginPage(banner, req.session, {}));
  });

  app.post('/login', (req, res) => {
    const username = String(req.body.username || '');
    const password = String(req.body.password || '');
    const user = authenticate(username, password);

    if (!user) {
      return res.send(views.loginPage(banner, null, { error: 'Invalid username or password.' }));
    }

    // Issue a signed HS256 token carrying the subject and role.
    const token = jwt.sign(
      { sub: user.username, role: user.role },
      config.secret,
      { ttlSeconds: config.tokenTtlSeconds, issuer: config.issuer, audience: config.audience }
    );

    res.cookie(config.tokenCookieName, token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
    });
    res.redirect('/dashboard');
  });

  // ---- dashboard (any logged-in user) ----
  app.get('/dashboard', (req, res) => {
    if (!req.session) return res.redirect('/login');
    const token = req.cookies[config.tokenCookieName];
    let decoded;
    try {
      decoded = jwt.decode(token);
    } catch {
      return res.redirect('/login');
    }
    res.send(views.dashboardPage(banner, req.session, { token, decoded }));
  });

  // ---- admin (role must be admin) ----
  app.get('/admin', (req, res) => {
    if (!req.session) return res.redirect('/login');
    if (req.session.role !== 'admin') {
      return res
        .status(403)
        .send(views.forbiddenPage(banner, req.session, `Your token's role is "${req.session.role}", not "admin".`));
    }
    res.send(views.adminPage(banner, req.session));
  });

  // ---- token inspector / playground ----
  app.get('/inspect', (req, res) => {
    res.send(views.inspectPage(banner, req.session, {}));
  });

  app.post('/inspect', (req, res) => {
    const input = String(req.body.token || '').trim();
    let result;
    try {
      const decoded = jwt.decode(input);
      const verifyResult = jwt.verify(input, config.secret, {
        secure: config.secure,
        issuer: config.issuer,
        audience: config.audience,
      });
      result = { decoded, verifyResult };
    } catch (err) {
      result = {
        decodeError: err.message,
        verifyResult: { valid: false, reason: 'Could not be decoded, so it cannot be verified.' },
      };
    }
    res.send(views.inspectPage(banner, req.session, { input, result }));
  });

  app.post('/logout', (req, res) => {
    res.clearCookie(config.tokenCookieName);
    res.redirect('/login');
  });

  app.listen(config.port, () => {
    console.log(`DrukPass running at http://localhost:${config.port}`);
    console.log(`JWT handling: ${config.secure ? 'SECURE (hardened verifier)' : 'VULNERABLE (broken verifier)'}`);
    if (!config.secure) {
      console.log(`Weak signing secret in use: "${config.secret}"`);
    }
  });
}

main();
