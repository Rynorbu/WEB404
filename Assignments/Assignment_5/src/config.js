'use strict';

/**
 * Central configuration for the DrukConsole command-injection demo.
 *
 * The single most important switch here is `secure`. It is driven by the
 * CLI_SECURE environment variable so that the EXACT SAME codebase can be
 * started in two modes:
 *
 *   CLI_SECURE=off  -> the vulnerable version. The diagnostics console builds
 *                      a single shell command STRING by concatenating the
 *                      user's "host" input straight onto a tool template, then
 *                      hands that string to a system shell (child_process.exec).
 *                      Any shell metacharacter the user types (&, |, ;, $(), `)
 *                      is therefore interpreted by the shell, so the user can
 *                      run commands of their own. This is classic CWE-78 OS
 *                      Command Injection, and it is deliberately broken so the
 *                      attacks in /attacker work.
 *
 *   CLI_SECURE=on   -> the hardened version. The console never touches a shell.
 *                      It looks the requested tool up in a fixed ALLOWLIST,
 *                      validates the host against a strict pattern, and then
 *                      executes the program directly with child_process.execFile
 *                      passing the host as a single, separate argv element
 *                      (shell: false). Metacharacters lose all meaning because
 *                      no shell ever parses them, and anything that is not a
 *                      clean hostname / IP is rejected before execution.
 *
 * Only `src/runner.js` behaves differently between the two modes; every route,
 * view and tool definition is shared, so the report can compare the two fairly.
 */
const path = require('path');

const secure = process.env.CLI_SECURE === 'on';

module.exports = {
  // Port the app runs on. Everything is local; nothing leaves the machine.
  // (Assignment 4 used 4000; this one uses 5000 so both can run side by side.)
  port: Number(process.env.PORT) || 5000,

  // Flip the whole security posture of the app from one environment variable.
  // Anything other than the literal string "on" is treated as vulnerable, so a
  // forgotten/empty variable fails to the version the lab starts from.
  secure,

  // Hard caps applied to EVERY command run, in BOTH modes. These are not the
  // injection defence (a shell string can still do damage inside them) — they
  // are blast-radius limits: a runaway or hostile command cannot hang the
  // server forever or flood it with gigabytes of output.
  commandTimeoutMs: 5000,
  maxOutputBytes: 64 * 1024,

  publicDir: path.join(__dirname, '..', 'public'),

  // Where the fictional "sensitive server file" lives. The exfiltration attack
  // (attacker/inject-exfil.js) tries to read this through command injection;
  // in secure mode it cannot. It is created on boot if missing and is listed
  // in .gitignore, so it is never committed.
  labSecretPath: path.join(__dirname, '..', 'lab-secret.txt'),
};
