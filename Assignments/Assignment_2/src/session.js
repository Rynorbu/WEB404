'use strict';

const crypto = require('crypto');

/**
 * A deliberately simple in-memory session store.
 *
 * In a real application you would use a database or a dedicated session store
 * (Redis, etc.) and a battle-tested library (express-session). For this
 * assignment an in-memory Map is enough, and keeping it small makes the
 * security logic easy to read: there is no framework "magic" hiding what the
 * CSRF defence actually does.
 *
 * Each session holds:
 *   - user:      the logged-in account name
 *   - balance:   the account balance (the state an attacker wants to change)
 *   - csrfToken: the per-session secret used by the synchronizer-token defence
 *   - history:   a log of transfers, so screenshots can show the damage/safety
 */
class SessionStore {
  constructor() {
    this.sessions = new Map();
  }

  /** Create a brand new session and return its id. */
  create(user, startingBalance) {
    // 128 bits of cryptographic randomness. The session id must be
    // unguessable; if an attacker could guess it they would not even need CSRF.
    const sid = crypto.randomBytes(16).toString('hex');

    this.sessions.set(sid, {
      user,
      balance: startingBalance,
      // The CSRF token is generated ONCE per session and tied to it. It is a
      // separate secret from the session id. See src/csrf.js for why this
      // "synchronizer token pattern" stops CSRF.
      csrfToken: crypto.randomBytes(32).toString('hex'),
      history: [],
    });

    return sid;
  }

  get(sid) {
    return this.sessions.get(sid);
  }

  destroy(sid) {
    this.sessions.delete(sid);
  }
}

module.exports = { SessionStore };
