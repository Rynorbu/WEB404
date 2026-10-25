'use strict';

/**
 * THE HEART OF THE ASSIGNMENT.
 *
 * Two ways to run a diagnostics tool with a user-supplied host. They take the
 * same inputs and return the same shape of result, so the rest of the app can
 * not tell them apart — only the security outcome differs.
 *
 *   runVulnerable()  builds a SHELL STRING and runs it with child_process.exec.
 *                    exec() spawns a shell (cmd.exe on Windows, /bin/sh on
 *                    POSIX) and lets it parse the string. The user's host text
 *                    is concatenated in raw, so any shell metacharacter the
 *                    user types becomes shell syntax. => CWE-78.
 *
 *   runSecure()      allowlists the tool, validates the host, and runs the
 *                    program DIRECTLY with child_process.execFile and an argv
 *                    array (shell: false). No shell ever parses the input, so
 *                    metacharacters are just literal bytes in one argument.
 *
 * Both paths share the same timeout and output cap (see config) so that even
 * the vulnerable path cannot hang the machine or flood memory during the demo.
 */
const { exec, execFile } = require('child_process');

const config = require('./config');
const { TOOLS, isValidHost } = require('./commands');

const runOptions = {
  timeout: config.commandTimeoutMs,
  maxBuffer: config.maxOutputBytes,
  windowsHide: true,
};

/**
 * Normalise whatever a child-process callback hands back into the single
 * result shape the views understand. `err` is the Error exec/execFile passes on
 * a non-zero exit, a timeout, or a spawn failure; stdout/stderr come alongside.
 */
function toResult(base, err, stdout, stderr) {
  return {
    ...base,
    stdout: (stdout || '').toString(),
    stderr: (stderr || '').toString(),
    // exec/execFile put the process exit code on err.code (a number) when the
    // command ran but exited non-zero; a string code (e.g. 'ENOENT') means the
    // program could not be launched at all.
    exitCode: err && typeof err.code === 'number' ? err.code : err ? null : 0,
    launchError: err && typeof err.code === 'string' ? err.code : null,
    timedOut: Boolean(err && err.killed),
  };
}

/**
 * VULNERABLE runner — do not do this in real code.
 *
 * The one and only flaw is the next line: `${tool.shellTemplate} ${host}`.
 * The host is user input, and it is being baked into a string that is about to
 * be interpreted by a shell. `ping -n 1 127.0.0.1 & whoami` is, to the shell,
 * two commands. exec() runs both.
 */
function runVulnerable(toolName, host) {
  return new Promise((resolve) => {
    const tool = TOOLS[toolName];
    if (!tool) {
      // Even the "broken" version only knows the tools in the catalog — but the
      // host field is completely trusted, which is the realistic bug: the
      // dropdown is validated, the free-text field is not.
      return resolve({
        mode: 'vulnerable',
        guard: { allowed: false, reason: `Unknown tool "${toolName}".` },
        commandShown: null,
        ran: false,
      });
    }

    const commandLine = `${tool.shellTemplate} ${host}`;
    const base = {
      mode: 'vulnerable',
      guard: {
        allowed: true,
        reason:
          'No validation. The host text was concatenated into a shell command and executed.',
      },
      commandShown: commandLine,
      ran: true,
    };

    // exec = "run this STRING in a shell". That is the vulnerability.
    exec(commandLine, runOptions, (err, stdout, stderr) => {
      resolve(toResult(base, err, stdout, stderr));
    });
  });
}

/**
 * SECURE runner — the same feature, built the safe way.
 *
 * Three independent layers, any one of which already stops the attacks:
 *   1. Allowlist the tool: unknown tool name => rejected, nothing runs.
 *   2. Validate the host against a strict known-good pattern (commands.js).
 *      Spaces and every shell metacharacter are rejected here.
 *   3. execFile with an argv ARRAY and shell: false. The program is launched
 *      directly by the OS; there is no shell to interpret anything, so the host
 *      is handed to ping/nslookup as one literal argument.
 */
function runSecure(toolName, host) {
  return new Promise((resolve) => {
    // Layer 1 — allowlist.
    const tool = TOOLS[toolName];
    if (!tool) {
      return resolve({
        mode: 'secure',
        guard: { allowed: false, reason: `Unknown tool "${toolName}" — not in the allowlist.` },
        commandShown: null,
        ran: false,
      });
    }

    // Layer 2 — strict input validation.
    if (!isValidHost(host)) {
      return resolve({
        mode: 'secure',
        guard: {
          allowed: false,
          reason:
            'Host rejected: it is not a valid IPv4 address or hostname. ' +
            'Spaces and shell metacharacters (& | ; $ ` etc.) are not allowed.',
        },
        commandShown: null,
        ran: false,
      });
    }

    // Layer 3 — execute directly, no shell, host as its own argv element.
    const argv = tool.buildArgs(host);
    const base = {
      mode: 'secure',
      guard: {
        allowed: true,
        reason:
          'Host passed validation and was executed as a single argument with no shell (execFile, shell: false).',
      },
      // Shown for transparency only; this is NOT a shell string, it is argv.
      commandShown: `${tool.bin} ${argv.map((a) => JSON.stringify(a)).join(' ')}`,
      ran: true,
    };

    execFile(tool.bin, argv, { ...runOptions, shell: false }, (err, stdout, stderr) => {
      resolve(toResult(base, err, stdout, stderr));
    });
  });
}

/**
 * The one entry point the server calls. It picks the runner from config.secure,
 * so the route code never has to know which mode it is in.
 */
function run(toolName, host) {
  return config.secure ? runSecure(toolName, host) : runVulnerable(toolName, host);
}

module.exports = { run, runVulnerable, runSecure };
