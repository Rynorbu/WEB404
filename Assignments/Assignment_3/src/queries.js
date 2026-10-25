'use strict';

/**
 * ============================================================================
 *  THE HEART OF THE ASSIGNMENT
 * ============================================================================
 *
 * This module contains the ONLY code that differs between the vulnerable and
 * the protected version of the application. Everything else (routing, views,
 * the database, the seed data) is identical in both modes.
 *
 * Each function below has two clearly-labelled branches selected by `protect`:
 *
 *   protect === false  (VULNERABLE)
 *     The SQL string is built by CONCATENATING raw user input directly into
 *     the query text. The input is therefore treated as *code*: a quote typed
 *     by the user closes the string literal and everything after it is parsed
 *     as SQL. This is the root cause of every injection in the report.
 *
 *   protect === true   (PROTECTED)
 *     The SQL string is FIXED and contains `?` placeholders. User input is
 *     sent separately and BOUND as parameters, so the engine always treats it
 *     as *data*, never as SQL. The quote stays a quote; the attack collapses
 *     into a harmless (if odd-looking) search term or a failed login.
 *
 * Every function returns a small, uniform result object so the views can show
 * the reader EXACTLY what ran:
 *
 *   {
 *     rows:        [ {col: value, ...}, ... ],   // result set (may be empty)
 *     columns:     ['col', ...],                 // column names, in order
 *     executedSql: 'SELECT ... ',                // the literal SQL the engine saw
 *     params:      ['bound', 'values'] | null,   // bound params (protected only)
 *     error:       'message' | null,             // DB error text, if any
 *   }
 */

/**
 * Run a query against sql.js and normalise the result into row objects.
 *
 * When `params` is null we take the VULNERABLE path and hand the engine a
 * single finished SQL string (`db.exec`). When `params` is an array we take
 * the PROTECTED path: a prepared statement with the values bound separately.
 *
 * Any SQL error is caught and returned as text rather than thrown, because a
 * careless application leaking that text to the page is itself a classic
 * *error-based* SQL-injection vector — something this lab demonstrates.
 */
function execute(db, sql, params) {
  try {
    if (params === null) {
      // ---- VULNERABLE PATH: one pre-built string, no separation of data ----
      const result = db.exec(sql); // throws on malformed SQL
      if (result.length === 0) return { rows: [], columns: [], error: null };
      const { columns, values } = result[0];
      const rows = values.map((v) =>
        Object.fromEntries(columns.map((c, i) => [c, v[i]]))
      );
      return { rows, columns, error: null };
    }

    // ---- PROTECTED PATH: fixed SQL + separately bound parameters ----
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    const columns = stmt.getColumnNames();
    stmt.free();
    return { rows, columns, error: null };
  } catch (err) {
    return { rows: [], columns: [], error: err.message };
  }
}

/* -------------------------------------------------------------------------- */
/*  1. AUTHENTICATION  — targeted by the "authentication bypass" attack        */
/* -------------------------------------------------------------------------- */

/**
 * Look up the account whose username AND password match what was submitted.
 * A non-empty result set means "credentials accepted"; the first row is the
 * account the visitor is logged in as.
 */
function authenticate(db, username, password, protect) {
  let sql;
  let params;

  if (!protect) {
    // VULNERABLE: the username and password are pasted straight into the SQL.
    //
    //   Normal login:   username=yeshi  password=summer2023
    //     -> ... WHERE username = 'yeshi' AND password = 'summer2023'
    //
    //   Bypass:         username=admin'--
    //     -> ... WHERE username = 'admin'-- ' AND password = '...'
    //        the `--` comments out the password check entirely.
    //
    //   Bypass:         username=' OR 1=1--      (note the trailing space)
    //     -> ... WHERE username = '' OR 1=1-- ' AND password = '...'
    //        the `--` comments out the password check, 1=1 is always true,
    //        so every row matches and the first account (admin) is returned.
    //
    //   (Subtle: `' OR '1'='1` WITHOUT a comment does NOT bypass this query,
    //    because AND binds tighter than OR, so the password clause still has
    //    to hold. You must either comment the password out with `--` or make
    //    the whole AND-group true. The report discusses this.)
    sql =
      "SELECT id, username, role FROM users " +
      "WHERE username = '" + username + "' AND password = '" + password + "'";
    params = null;
  } else {
    // PROTECTED: the query shape is frozen; the two values are bound as data.
    // Whatever the user types in the username box can only ever be compared,
    // as a literal string, against the username column.
    sql =
      'SELECT id, username, role FROM users ' +
      'WHERE username = ? AND password = ?';
    params = [username, password];
  }

  const result = execute(db, sql, params);
  return { ...result, executedSql: sql, params };
}

/* -------------------------------------------------------------------------- */
/*  2. CATALOGUE SEARCH — targeted by UNION / error / blind injections         */
/* -------------------------------------------------------------------------- */

/**
 * Search the PUBLIC book catalogue by title.
 *
 * The result set has five columns (id, title, author, category, price). That
 * fixed column count is exactly what a UNION-based attack must match to splice
 * rows from another table into the output — see the report for the payload.
 */
function searchBooks(db, term, protect) {
  let sql;
  let params;

  if (!protect) {
    // VULNERABLE: the search term is concatenated inside the LIKE pattern.
    //
    //   Normal:  term = "clean"
    //     -> ... WHERE title LIKE '%clean%'
    //
    //   UNION:   term = "zzz' UNION SELECT id,username,password,email,role FROM users-- "
    //     -> ... WHERE title LIKE '%zzz' UNION SELECT ... FROM users-- %'
    //        the attacker's own SELECT is appended and its rows appear as
    //        "books", leaking the entire users table through the catalogue.
    sql =
      'SELECT id, title, author, category, price FROM books ' +
      "WHERE title LIKE '%" + term + "%' ORDER BY id";
    params = null;
  } else {
    // PROTECTED: the term is bound and concatenated into the LIKE pattern by
    // the DATABASE, not by us. A quote in the term is just a character to
    // search for; it can no longer terminate the string literal.
    sql =
      'SELECT id, title, author, category, price FROM books ' +
      "WHERE title LIKE '%' || ? || '%' ORDER BY id";
    params = [term];
  }

  const result = execute(db, sql, params);
  return { ...result, executedSql: sql, params };
}

/* -------------------------------------------------------------------------- */
/*  3. BROWSE — list the whole catalogue (NOT an injection target)             */
/* -------------------------------------------------------------------------- */

/**
 * Return every book, for the default "browse" view.
 *
 * This query takes NO user input, so it is identical and safe in both modes.
 * It is kept separate from searchBooks() precisely to make the point that the
 * injection risk comes from *user-controlled* input, not from running SQL.
 */
function listBooks(db) {
  const r = execute(
    db,
    'SELECT id, title, author, category, price, stock FROM books ORDER BY id',
    null
  );
  return r.rows;
}

module.exports = { execute, authenticate, searchBooks, listBooks };
