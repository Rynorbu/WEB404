'use strict';

/**
 * The demo database.
 *
 * We use **sql.js** — SQLite compiled to WebAssembly. This matters for the
 * assignment for two practical reasons:
 *
 *   1. It is a *real* SQL engine (real parser, real UNION, real error
 *      messages), so every injection technique behaves exactly as it would
 *      against a production SQLite/MySQL/PostgreSQL backend.
 *   2. It needs **no native build step and no separate database server** — it
 *      installs with a plain `npm install` and runs entirely in memory. The
 *      whole lab therefore stays self-contained on `localhost`.
 *
 * The database is rebuilt from scratch every time the server starts, so the
 * attacks never do lasting damage: a restart always returns a clean slate.
 */
const path = require('path');
const initSqlJs = require('sql.js');

/**
 * The seed data.
 *
 * Two tables, deliberately shaped like a real small shop:
 *
 *   books  — the PUBLIC catalogue. The search box queries this table, so it is
 *            the data the application is *supposed* to expose.
 *   users  — the PRIVATE accounts table. It holds usernames, plaintext
 *            passwords (bad practice on purpose — see the report), email
 *            addresses and roles. The application never intends to show this
 *            table to a visitor. It is the prize a SQL-injection attacker is
 *            after, and the UNION / blind demos extract it straight out of the
 *            search box even though the search box only ever "queries books".
 */
const SEED_BOOKS = [
  // id, title, author, category, price (Nu.), stock
  [1, 'The Hero with a Thousand Faces', 'Joseph Campbell', 'Mythology', 950, 12],
  [2, 'Clean Code', 'Robert C. Martin', 'Programming', 1200, 7],
  [3, 'The Pragmatic Programmer', 'Hunt & Thomas', 'Programming', 1350, 5],
  [4, 'Sapiens', 'Yuval Noah Harari', 'History', 890, 20],
  [5, 'The Circle of Karma', 'Kunzang Choden', 'Fiction', 640, 15],
  [6, 'Treasures of the Thunder Dragon', 'Ashi Dorji Wangmo Wangchuck', 'Memoir', 780, 9],
  [7, 'Beyond the Sky and the Earth', 'Jamie Zeppa', 'Travel', 720, 11],
  [8, 'The Web Application Hacker\'s Handbook', 'Stuttard & Pinto', 'Security', 1800, 4],
];

const SEED_USERS = [
  // id, username, password (plaintext ON PURPOSE for the demo), email, role
  [1, 'admin', 'Dr#k_R00t_2024!', 'admin@drukshelf.bt', 'administrator'],
  [2, 'yeshi', 'summer2023', 'yeshi@drukshelf.bt', 'staff'],
  [3, 'norbu', 'bhutan123', 'norbu@drukshelf.bt', 'customer'],
  [4, 'sonam', 'p@ssw0rd', 'sonam@drukshelf.bt', 'customer'],
];

/**
 * Build a fresh in-memory database and return the sql.js `Database` handle.
 * Awaited once at server start-up (see server.js).
 */
async function createDatabase() {
  const SQL = await initSqlJs({
    // Tell sql.js where its WebAssembly binary lives inside node_modules.
    locateFile: (file) =>
      path.join(__dirname, '..', 'node_modules', 'sql.js', 'dist', file),
  });

  const db = new SQL.Database();

  db.run(`
    CREATE TABLE books (
      id       INTEGER PRIMARY KEY,
      title    TEXT NOT NULL,
      author   TEXT NOT NULL,
      category TEXT NOT NULL,
      price    INTEGER NOT NULL,
      stock    INTEGER NOT NULL
    );
    CREATE TABLE users (
      id       INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      email    TEXT NOT NULL,
      role     TEXT NOT NULL
    );
  `);

  const insertBook = db.prepare(
    'INSERT INTO books (id, title, author, category, price, stock) VALUES (?,?,?,?,?,?)'
  );
  for (const row of SEED_BOOKS) insertBook.run(row);
  insertBook.free();

  const insertUser = db.prepare(
    'INSERT INTO users (id, username, password, email, role) VALUES (?,?,?,?,?)'
  );
  for (const row of SEED_USERS) insertUser.run(row);
  insertUser.free();

  return db;
}

module.exports = { createDatabase, SEED_BOOKS, SEED_USERS };
