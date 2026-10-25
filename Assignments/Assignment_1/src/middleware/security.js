/**
 * Security middleware: HTTP headers, rate limiting, CSRF origin check.
 * Written by hand (instead of helmet / express-rate-limit) to show what
 * each protection actually does.
 */

function securityHeaders(req, res, next) {
  // Only load scripts/styles/images from our own origin; no inline scripts,
  // no plugins, no framing.
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; " +
      "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );
  // Stop browsers from MIME-sniffing a response into an executable type
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.removeHeader('X-Powered-By');
  next();
}

/**
 * Simple fixed-window, in-memory rate limiter keyed by client IP.
 * Prevents upload flooding / disk exhaustion (denial of service).
 */
function rateLimiter({ windowMs, max }) {
  const hits = new Map();

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of hits) if (entry.resetAt <= now) hits.delete(ip);
  }, windowMs);
  timer.unref();

  return function rateLimit(req, res, next) {
    const now = Date.now();
    const key = req.ip;
    let entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      hits.set(key, entry);
    }
    entry.count += 1;

    res.setHeader('RateLimit-Limit', max);
    res.setHeader('RateLimit-Remaining', Math.max(0, max - entry.count));

    if (entry.count > max) {
      res.setHeader('Retry-After', Math.ceil((entry.resetAt - now) / 1000));
      return res.status(429).json({ error: 'Too many uploads. Please try again later.' });
    }
    next();
  };
}

/**
 * CSRF defence: state-changing requests must come from our own origin.
 * Browsers always send the Origin header on cross-site POSTs.
 */
function sameOriginOnly(req, res, next) {
  const origin = req.get('origin');
  if (origin) {
    const expected = `${req.protocol}://${req.get('host')}`;
    if (origin !== expected) {
      return res.status(403).json({ error: 'Cross-origin request rejected.' });
    }
  }
  next();
}

module.exports = { securityHeaders, rateLimiter, sameOriginOnly };
