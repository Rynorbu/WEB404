'use strict';

/**
 * The tool catalog — the ALLOWLIST at the centre of the secure design.
 *
 * DrukConsole is a tiny "network diagnostics" web console: the user picks a
 * tool from a dropdown and types a host. Both modes share this catalog, but
 * they USE it very differently:
 *
 *   - Vulnerable mode uses only `shellTemplate`: it glues the user's raw host
 *     string onto the end of the template and runs the whole thing in a shell.
 *     The catalog here is just a convenience; nothing stops the user's input
 *     from carrying extra commands.
 *
 *   - Secure mode uses `bin` + `buildArgs`: it runs the named program directly
 *     with an argv array and no shell, after the host has passed validation.
 *     The catalog is now a genuine security boundary — a tool that is not in
 *     this object simply cannot be run.
 *
 * The commands are chosen to be harmless and read-only (ping / DNS lookup) and
 * are platform-aware so the demo runs the same on Windows and POSIX.
 */
const isWindows = process.platform === 'win32';

/**
 * ping with a single echo request. Windows uses `-n`, everyone else `-c`.
 * `ping 127.0.0.1` works with no network at all, which keeps the "legitimate
 * request still works" demo reliable offline.
 */
const pingArgs = isWindows ? ['-n', '1'] : ['-c', '1'];

const TOOLS = {
  ping: {
    label: 'Ping a host (ICMP echo)',
    bin: 'ping',
    // Secure mode: fixed, trusted flags, then the host as its OWN argv element.
    buildArgs: (host) => [...pingArgs, host],
    // Vulnerable mode: a single shell string the host gets concatenated onto.
    shellTemplate: `ping ${pingArgs.join(' ')}`,
    placeholder: '127.0.0.1',
  },
  resolve: {
    label: 'DNS lookup (nslookup)',
    bin: 'nslookup',
    buildArgs: (host) => [host],
    shellTemplate: 'nslookup',
    placeholder: 'localhost',
  },
};

/**
 * Strict host validation used by the SECURE runner only.
 *
 * Accepts exactly two shapes and nothing else:
 *   - an IPv4 address (four 0-255 octets), or
 *   - a DNS hostname / label chain (letters, digits, hyphen, dot).
 *
 * Crucially it accepts no spaces and NONE of the shell metacharacters
 * (& | ; $ ` ( ) < > newline, quotes, ...). So even if secure mode ever did
 * reach a shell, there would be nothing dangerous left to interpret. This is
 * allowlist validation ("permit only this known-good shape"), which is far
 * safer than trying to blocklist bad characters one by one.
 */
function isValidHost(host) {
  if (typeof host !== 'string') return false;
  if (host.length === 0 || host.length > 253) return false;

  const ipv4 =
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const hostname =
    /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  return ipv4.test(host) || hostname.test(host);
}

module.exports = { TOOLS, isValidHost, isWindows };
