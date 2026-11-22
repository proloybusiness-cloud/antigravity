/**
 * OmniOS Headless, Interactive REPL & Remote CLI (`F-065`, Contract 8)
 * - Pure Node.js 24 ESM (`node:fs`, `node:path`, `node:readline`, `node:url`, built-in `fetch`)
 * - Supports local headless execution (boot + run + clean shutdown) and `--remote <url>` HTTP mode
 * - Supports `--json` machine output across every command and interactive/piped `shell` REPL
 */

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { createOmniOS } from '../os.mjs';
import { createHttpServer } from '../server/http-server.mjs';

const __filename = fileURLToPath(import.meta.url);

const BOOLEAN_FLAGS = new Map([
  ['--json', 'json'],
  ['--serve', 'serve'],
  ['--grant-all', 'grantAll'],
  ['--overwrite', 'overwrite'],
  ['--upgrade', 'upgrade'],
  ['--purge', 'purge'],
  ['--recursive', 'recursive'],
  ['-r', 'recursive'],
  ['--tree', 'tree'],
  ['--all', 'all'],
  ['--help', 'help'],
  ['-h', 'help'],
  ['--safe-mode', 'safeMode'],
  ['--include-dismissed', 'includeDismissed'],
  ['--clear-history', 'clearHistory'],
  ['--append', 'append'],
  ['--cancel', 'cancel'],
  ['--default', 'setAsDefault'],
  ['--lstat', 'lstat'],
]);

const VALUE_FLAGS = new Map([
  ['--data-dir', 'dataDir'],
  ['--remote', 'remote'],
  ['--port', 'port'],
  ['--host', 'host'],
  ['--signal', 'signal'],
  ['--platform', 'platform'],
  ['--limit', 'limit'],
  ['--type', 'type'],
  ['--action', 'action'],
  ['--uri', 'uri'],
  ['--mime', 'mime'],
  ['--ext', 'ext'],
  ['--scheme', 'scheme'],
  ['--app', 'app'],
  ['--title', 'title'],
  ['--body', 'body'],
  ['--priority', 'priority'],
  ['--category', 'category'],
  ['--out', 'out'],
  ['--output-dir', 'out'],
  ['-o', 'out'],
  ['--platforms', 'platforms'],
  ['--cwd', 'cwd'],
  ['--encoding', 'encoding'],
  ['--subsystem', 'subsystem'],
  ['--level', 'level'],
  ['--pref', 'pref'],
  ['--format', 'format'],
  ['--source', 'source'],
  ['--sha256', 'sha256'],
  ['--filename', 'filename'],
]);

const USAGE_TEXT = `OmniOS CLI — Unified Cross-Platform Operating System

Usage:
  node os/cli/omnios-cli.mjs [global flags] <command> [subcommand] [args...]

Global Flags:
  --json                Output machine-readable JSON
  --data-dir <dir>      Persistent SQLite data directory (default: in-memory)
  --remote <url>        Connect to a running OmniOS HTTP server (e.g. http://127.0.0.1:3777)
  --port <n>            HTTP/WS port for \`boot --serve\` (default: 3777)
  --host <addr>         HTTP/WS bind host for \`boot --serve\` (default: 127.0.0.1)
  -h, --help            Show this help message

Commands:
  boot [--serve] [--safe-mode]
  shell
  exec "<command>"
  status
  dmesg [--limit N] [--subsystem S] [--level L]
  services [start|stop|restart|health <name>]
  ps [--tree] [--all] [--platform P]
  kill <pid> [--signal SIGTERM]
  vfs ls|cat|write|mkdir|rm|symlink|resolve|stat|rename|mounts <args...> [--platform P] [-r]
  reg get|set|list|delete <hive> <keyPath> [valueName] [value] [--type REG_SZ]
  defaults read|write|delete|export|domains [domain] [key] [value]
  prefs get|set|delete <pkg> [prefName] [key] [value] [--pref NAME]
  ospm inspect|install|list|catalog|launch|stop|uninstall <arg> [--grant-all] [--overwrite] [--upgrade] [--purge]
  intent resolve|dispatch [--action A] [--uri U] [--mime M] [--ext E] [--scheme S] [--app ID]
  clipboard get|set|history|clear [text] [--limit N] [--mime M] [--clear-history]
  notify send|list|dismiss [id] [--app ID] [--title T] [--body B] [--priority P] [--category C]
  sdk build-samples [--out <dir>] [--platforms all|android,windows,ios,macos,universal]
`;

function toJsonSafe(value, seen = new Set(), depth = 0) {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === 'string' || t === 'boolean') return value;
  if (t === 'number') return Number.isFinite(value) ? value : null;
  if (t === 'bigint') return value.toString(10);
  if (t === 'function' || t === 'symbol') return undefined;
  if (depth >= 32) return '[MaxDepth]';
  if (Buffer.isBuffer(value)) return value.toString('base64');
  if (ArrayBuffer.isView(value)) {
    const view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString('base64');
  }
  if (value instanceof ArrayBuffer) return Buffer.from(value).toString('base64');
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.toISOString() : null;
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => {
        const s = toJsonSafe(item, seen, depth + 1);
        return s === undefined ? null : s;
      });
    }
    if (value instanceof Set) {
      return Array.from(value).map((item) => toJsonSafe(item, seen, depth + 1));
    }
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      const s = toJsonSafe(v, seen, depth + 1);
      if (s !== undefined) out[k] = s;
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

function safeJsonFormat(value) {
  return JSON.stringify(toJsonSafe(value), null, 2);
}

function parseScalarValue(raw) {
  if (typeof raw !== 'string') return raw;
  const trimmed = raw.trim();
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (trimmed === 'null') return null;
  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) {
    const num = Number(trimmed);
    if (Number.isFinite(num)) return num;
  }
  if (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  ) {
    try {
      return JSON.parse(trimmed);
    } catch (err) {
      // Keep as raw string when not valid JSON.
      void err;
    }
  }
  return raw;
}

function coerceRegistryData(type, rawValue) {
  const upper = String(type ?? 'REG_SZ').toUpperCase();
  if (upper === 'REG_DWORD') {
    const n = Number(rawValue);
    if (!Number.isFinite(n)) {
      throw new Error(`REG_DWORD requires a numeric value, got "${rawValue}"`);
    }
    return Math.trunc(n);
  }
  if (upper === 'REG_QWORD') {
    return BigInt(String(rawValue).trim());
  }
  if (upper === 'REG_MULTI_SZ') {
    if (Array.isArray(rawValue)) return rawValue.map(String);
    const s = String(rawValue);
    if (s.trim().startsWith('[')) {
      try {
        const parsed = JSON.parse(s);
        if (Array.isArray(parsed)) return parsed.map(String);
      } catch (err) {
        void err;
      }
    }
    return s.split(',').map((item) => item.trim());
  }
  if (upper === 'REG_BINARY') {
    const s = String(rawValue).trim();
    if (/^(?:[0-9a-fA-F]{2})+$/.test(s) && s.length % 2 === 0 && !s.endsWith('=')) {
      return new Uint8Array(Buffer.from(s, 'hex'));
    }
    return new Uint8Array(Buffer.from(s, 'base64'));
  }
  return String(rawValue ?? '');
}

/**
 * Parses CLI argv into structured command, subcommand, positional arguments, and flags.
 */
export function parseCliArgs(argv = []) {
  const args = Array.isArray(argv) ? argv.map(String) : [];
  const flags = {
    json: false,
    serve: false,
    grantAll: false,
    overwrite: false,
    upgrade: false,
    purge: false,
    recursive: false,
    tree: false,
    all: false,
    help: false,
    safeMode: false,
    includeDismissed: false,
    clearHistory: false,
    append: false,
    cancel: false,
    setAsDefault: false,
    lstat: false,
    dataDir: null,
    remote: null,
    port: null,
    host: null,
    signal: null,
    platform: null,
    limit: null,
    type: null,
    action: null,
    uri: null,
    mime: null,
    ext: null,
    scheme: null,
    app: null,
    title: null,
    body: null,
    priority: null,
    category: null,
    out: null,
    platforms: null,
    cwd: null,
    encoding: null,
    subsystem: null,
    level: null,
    pref: null,
    format: null,
    source: null,
    sha256: null,
    filename: null,
  };

  const positionals = [];
  let passthrough = false;

  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    if (passthrough) {
      positionals.push(token);
      continue;
    }
    if (token === '--') {
      passthrough = true;
      continue;
    }

    if (BOOLEAN_FLAGS.has(token)) {
      flags[BOOLEAN_FLAGS.get(token)] = true;
      continue;
    }

    if (VALUE_FLAGS.has(token)) {
      if (i + 1 >= args.length) {
        throw new Error(`Flag ${token} requires a value`);
      }
      flags[VALUE_FLAGS.get(token)] = args[++i];
      continue;
    }

    if (token.startsWith('--') && token.includes('=')) {
      const eqIdx = token.indexOf('=');
      const name = token.slice(0, eqIdx);
      const val = token.slice(eqIdx + 1);
      if (VALUE_FLAGS.has(name)) {
        flags[VALUE_FLAGS.get(name)] = val;
        continue;
      }
      if (BOOLEAN_FLAGS.has(name)) {
        const lower = val.trim().toLowerCase();
        flags[BOOLEAN_FLAGS.get(name)] = lower === 'true' || lower === '1' || lower === 'yes';
        continue;
      }
    }

    // For `exec`, forward unrecognized flags (like `-la` in `exec ls -la`) as command tokens.
    if (positionals[0] === 'exec') {
      positionals.push(token);
      continue;
    }

    if (token.startsWith('-') && token.length > 1 && !/^-\d/.test(token)) {
      throw new Error(`Unknown CLI flag: ${token}`);
    }

    positionals.push(token);
  }

  const command = positionals.length > 0 ? positionals[0].toLowerCase() : null;
  const rest = positionals.slice(1);
  const subcommand = rest.length > 0 ? rest[0].toLowerCase() : null;

  return {
    command,
    subcommand,
    positionals: rest,
    allPositionals: positionals,
    flags,
    rawArgv: args,
  };
}

function createRemoteClient(remoteUrl) {
  const baseUrl = String(remoteUrl).replace(/\/+$/, '');

  async function request(method, endpoint, { query = null, body = undefined, expectText = false } = {}) {
    let url = `${baseUrl}${endpoint}`;
    if (query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null && v !== '') {
          params.set(k, String(v));
        }
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    const headers = {};
    let fetchBody;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      fetchBody = JSON.stringify(toJsonSafe(body));
    }

    const res = await fetch(url, { method, headers, body: fetchBody });
    const contentType = String(res.headers.get('content-type') ?? '').toLowerCase();

    if (expectText && res.ok && !contentType.includes('application/json')) {
      return await res.text();
    }

    let payload;
    if (contentType.includes('application/json')) {
      payload = await res.json();
    } else {
      const text = await res.text();
      payload = { ok: res.ok, text };
    }

    if (!res.ok) {
      const msg =
        payload?.error?.message ??
        payload?.message ??
        `Remote HTTP ${res.status} ${res.statusText}`;
      const err = new Error(msg);
      if (payload?.error?.code) err.code = payload.error.code;
      err.status = res.status;
      throw err;
    }

    return payload;
  }

  return { request, baseUrl };
}

function formatTable(rows, columns) {
  if (!Array.isArray(rows) || rows.length === 0) return '(none)';
  const widths = columns.map((col) => {
    let maxW = col.label.length;
    for (const row of rows) {
      const cell = String(col.get(row) ?? '');
      if (cell.length > maxW) maxW = cell.length;
    }
    return Math.min(maxW, col.maxWidth ?? 48);
  });

  const pad = (val, w) => {
    const s = String(val ?? '');
    return s.length > w ? `${s.slice(0, Math.max(1, w - 1))}…` : s.padEnd(w);
  };

  const lines = [columns.map((c, idx) => pad(c.label, widths[idx])).join('  ')];
  for (const row of rows) {
    lines.push(columns.map((c, idx) => pad(c.get(row), widths[idx])).join('  '));
  }
  return lines.join('\n');
}

function formatProcessTree(nodes, indent = '') {
  const lines = [];
  for (const node of nodes ?? []) {
    lines.push(
      `${indent}${node.pid}  ${node.name}  [${node.state}] (${node.platform ?? 'system'}/${node.arch ?? 'native'})`
    );
    if (Array.isArray(node.children) && node.children.length > 0) {
      lines.push(...formatProcessTree(node.children, `${indent}  ├─ `));
    }
  }
  return lines;
}

async function resolvePackageSourceForCli(argPath, flags) {
  if (typeof argPath !== 'string' || argPath.length === 0) {
    throw new Error('Package path is required');
  }
  let isHostFile = false;
  try {
    const st = fs.statSync(argPath);
    isHostFile = st.isFile();
  } catch (err) {
    // Not a local host file; treat as VFS path below.
    void err;
    isHostFile = false;
  }

  if (isHostFile) {
    const bytes = await fsp.readFile(argPath);
    const filenameHint = flags.filename || path.basename(argPath);
    return {
      isHostFile: true,
      bytes: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
      base64: bytes.toString('base64'),
      filenameHint,
    };
  }

  return {
    isHostFile: false,
    vfsPath: argPath,
    filenameHint: flags.filename || path.posix.basename(argPath),
  };
}

function detectJsonFlagFromArgv(argv) {
  if (!Array.isArray(argv)) return false;
  let jsonMode = false;
  for (let i = 0; i < argv.length; i += 1) {
    const token = String(argv[i]);
    if (token === '--') break;
    if (VALUE_FLAGS.has(token)) {
      i += 1;
      continue;
    }
    if (token === '--json') {
      jsonMode = true;
    } else if (token.startsWith('--json=')) {
      const lower = token.slice('--json='.length).trim().toLowerCase();
      if (lower === 'true' || lower === '1' || lower === 'yes') {
        jsonMode = true;
      } else if (lower === 'false' || lower === '0' || lower === 'no') {
        jsonMode = false;
      }
    }
  }
  return jsonMode;
}

async function runRepl({ os, remote, flags, io, writeOut, writeErr }) {
  const inputStream = io.stdin ?? process.stdin;
  const isTty = Boolean(inputStream?.isTTY);
  const rl = readline.createInterface({
    input: inputStream,
    output: isTty ? (io.stdout ?? process.stdout) : undefined,
    terminal: isTty,
    prompt: 'omnios> ',
  });

  if (isTty) {
    writeOut('OmniOS Interactive Shell — type `help` for commands, `exit` to quit.\n');
    rl.prompt();
  }

  let lastExitCode = 0;
  let currentCwd = typeof flags.cwd === 'string' && flags.cwd.length > 0 ? flags.cwd : undefined;

  try {
    for await (const rawLine of rl) {
      const line = rawLine.trim();
      if (line.length === 0) {
        if (isTty) rl.prompt();
        continue;
      }
      if (line === 'exit' || line === 'quit') {
        break;
      }

      try {
        const res = remote
          ? await remote.request('POST', '/api/v1/shell/exec', {
              body: {
                command: line,
                ...(currentCwd ? { cwd: currentCwd } : {}),
                platform: flags.platform ?? undefined,
              },
            })
          : await os.shell.exec(line, {
              ...(currentCwd ? { cwd: currentCwd } : {}),
              ...(flags.platform ? { platform: flags.platform } : {}),
            });

        if (typeof res?.cwd === 'string' && res.cwd.length > 0) {
          currentCwd = res.cwd;
        }
        lastExitCode = Number.isInteger(res?.exitCode) ? res.exitCode : 0;
        if (flags.json) {
          writeOut(`${safeJsonFormat(res)}\n`);
        } else {
          if (res?.stdout) {
            writeOut(res.stdout.endsWith('\n') ? res.stdout : `${res.stdout}\n`);
          }
          if (res?.stderr) {
            writeErr(res.stderr.endsWith('\n') ? res.stderr : `${res.stderr}\n`);
          }
        }
      } catch (err) {
        lastExitCode = 1;
        const code = typeof err?.code === 'string' ? err.code : 'E_SHELL_REPL';
        const message = err?.message ?? String(err);
        if (flags.json) {
          const errObj = {
            ok: false,
            code,
            error: { code, message },
          };
          writeOut(`${safeJsonFormat(errObj)}\n`);
        }
        writeErr(`error: ${message}\n`);
      }

      if (isTty) rl.prompt();
    }
  } finally {
    rl.close();
  }

  return { exitCode: lastExitCode, data: { exited: true, lastExitCode } };
}

async function executeBootServe(os, flags, io, writeOut) {
  const port = flags.port !== null ? Number(flags.port) : Number(process.env.PORT ?? 3777);
  const host = flags.host ?? process.env.HOST ?? '127.0.0.1';
  if (os.scheduler && typeof os.scheduler.start === 'function' && !os.scheduler.isRunning?.()) {
    os.scheduler.start(os.kernel?.options?.tickMs ?? 16);
  }
  const server = createHttpServer(os, { port, host });
  const address = await server.start({ port, host });

  if (flags.json) {
    writeOut(`${safeJsonFormat({ ok: true, mode: 'serve', address, status: os.kernel.state })}\n`);
  } else {
    writeOut(`OmniOS server listening at ${address.url} (WebSocket: ${address.wsUrl})\n`);
  }

  await new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      process.off('SIGINT', onSig);
      process.off('SIGTERM', onSig);
      if (io.abortSignal) {
        io.abortSignal.removeEventListener('abort', onSig);
      }
      resolve();
    };
    const onSig = () => finish();

    if (io.abortSignal?.aborted) {
      finish();
      return;
    }
    process.once('SIGINT', onSig);
    process.once('SIGTERM', onSig);
    if (io.abortSignal) {
      io.abortSignal.addEventListener('abort', onSig, { once: true });
    }
  });

  await server.stop();
  return { exitCode: 0, data: { ok: true, mode: 'serve', address } };
}

async function runSdkCommand(positionals, flags) {
  const sub = positionals[0]?.toLowerCase();
  if (sub !== 'build-samples') {
    throw new Error(`Unknown sdk subcommand: ${sub ?? '(missing)'}. Expected: build-samples`);
  }
  const mod = await import('../../sdk/build-samples.mjs');
  const buildOpts = { quiet: true };
  if (flags.out) buildOpts.outputDir = flags.out;
  if (flags.platforms) buildOpts.platforms = flags.platforms;
  const manifest = await mod.buildAllSamples(buildOpts);
  const text = manifest.packages
    .map((p) => `${p.platform.padEnd(10)} ${p.filename.padEnd(28)} ${String(p.bytes).padStart(7)} bytes  ${p.sha256.slice(0, 16)}`)
    .join('\n');
  return {
    data: manifest,
    text: text || 'No sample packages built.',
  };
}

export async function runCli(argv = process.argv.slice(2), io = {}) {
  let outBuf = '';
  let errBuf = '';

  const writeOut = (str) => {
    const s = String(str);
    outBuf += s;
    if (typeof io.writeOut === 'function') {
      io.writeOut(s);
    } else if (io.stdout && typeof io.stdout.write === 'function') {
      io.stdout.write(s);
    }
  };

  const writeErr = (str) => {
    const s = String(str);
    errBuf += s;
    if (typeof io.writeErr === 'function') {
      io.writeErr(s);
    } else if (io.stderr && typeof io.stderr.write === 'function') {
      io.stderr.write(s);
    }
  };

  let parsed;
  try {
    parsed = parseCliArgs(argv);
  } catch (err) {
    const errObj = {
      ok: false,
      code: 'E_CLI_ARGS',
      error: { code: 'E_CLI_ARGS', message: err?.message ?? String(err) },
    };
    if (detectJsonFlagFromArgv(argv)) {
      writeOut(`${safeJsonFormat(errObj)}\n`);
    }
    writeErr(`${err?.message ?? err}\n`);
    return { exitCode: 1, stdout: outBuf, stderr: errBuf, data: errObj };
  }

  const { command, positionals, flags } = parsed;

  if (flags.help || !command || command === 'help') {
    if (flags.json) {
      const payload = { ok: true, usage: USAGE_TEXT };
      writeOut(`${safeJsonFormat(payload)}\n`);
      return { exitCode: 0, stdout: outBuf, stderr: errBuf, data: payload };
    }
    writeOut(USAGE_TEXT);
    return { exitCode: 0, stdout: outBuf, stderr: errBuf };
  }

  // `sdk build-samples` runs standalone without booting an OS instance.
  if (command === 'sdk') {
    try {
      const res = await runSdkCommand(positionals, flags);
      if (flags.json) {
        writeOut(`${safeJsonFormat(res.data)}\n`);
      } else {
        writeOut(`${res.text}\n`);
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf, data: res.data };
    } catch (err) {
      const code = typeof err?.code === 'string' ? err.code : 'E_SDK';
      const errObj = { ok: false, code, error: { code, message: err?.message ?? String(err) } };
      if (flags.json) writeOut(`${safeJsonFormat(errObj)}\n`);
      writeErr(`${err?.message ?? err}\n`);
      return { exitCode: 1, stdout: outBuf, stderr: errBuf, data: errObj };
    }
  }

  const remote = flags.remote ? createRemoteClient(flags.remote) : null;
  let localOs = null;
  let bootReport = null;

  try {
    if (!remote) {
      localOs = createOmniOS({
        dataDir: flags.dataDir ?? null,
        autoStartScheduler: false,
      });
      bootReport = await localOs.boot({ safeMode: Boolean(flags.safeMode) });
    }

    // ---- Special interactive/long-running commands ----
    if (command === 'boot') {
      if (flags.serve) {
        if (remote) {
          throw new Error('Cannot combine --serve with --remote');
        }
        const serveRes = await executeBootServe(localOs, flags, io, writeOut);
        return { exitCode: serveRes.exitCode, stdout: outBuf, stderr: errBuf, data: serveRes.data };
      }

      const data = remote
        ? await remote.request('GET', '/api/v1/kernel/status')
        : {
            ok: true,
            os: 'OmniOS',
            version: localOs.version ?? '1.0.0',
            status: localOs.kernel.state,
            bootReport,
            services: localOs.serviceManager.getStatus(),
          };

      if (flags.json) {
        writeOut(`${safeJsonFormat(data)}\n`);
      } else {
        const stages = (data.bootReport?.stages ?? [])
          .map((s) => `${s.name}(${s.durationMs ?? 0}ms)`)
          .join(' -> ');
        writeOut(
          `OmniOS booted [${data.status ?? data.state ?? 'RUNNING'}]${stages ? ` stages: ${stages}` : ''}\n`
        );
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf, data };
    }

    if (command === 'shell') {
      const replRes = await runRepl({ os: localOs, remote, flags, io, writeOut, writeErr });
      return { exitCode: replRes.exitCode, stdout: outBuf, stderr: errBuf, data: replRes.data };
    }

    if (command === 'exec') {
      const cmdStr = positionals.join(' ').trim();
      if (!cmdStr) {
        throw new Error('exec requires a command string');
      }
      const res = remote
        ? await remote.request('POST', '/api/v1/shell/exec', {
            body: {
              command: cmdStr,
              ...(flags.cwd ? { cwd: flags.cwd } : {}),
              ...(flags.platform ? { platform: flags.platform } : {}),
            },
          })
        : await localOs.shell.exec(cmdStr, {
            ...(flags.cwd ? { cwd: flags.cwd } : {}),
            ...(flags.platform ? { platform: flags.platform } : {}),
          });

      if (flags.json) {
        writeOut(`${safeJsonFormat(res)}\n`);
      } else {
        if (res.stdout) writeOut(res.stdout.endsWith('\n') ? res.stdout : `${res.stdout}\n`);
        if (res.stderr) writeErr(res.stderr.endsWith('\n') ? res.stderr : `${res.stderr}\n`);
      }
      return {
        exitCode: Number.isInteger(res.exitCode) ? res.exitCode : (res.ok ? 0 : 1),
        stdout: outBuf,
        stderr: errBuf,
        data: res,
      };
    }

    // ---- Standard single-shot commands ----
    let resultData;
    let formattedText = '';

    switch (command) {
      case 'status': {
        resultData = remote
          ? await remote.request('GET', '/api/v1/kernel/status')
          : localOs.getStatus();
        formattedText = [
          `OmniOS ${resultData.version ?? '1.0.0'} — State: ${resultData.state ?? resultData.status}`,
          `Uptime: ${resultData.uptimeMs ?? 0}ms | Processes: ${resultData.processCount ?? 0} (active: ${resultData.activeProcessCount ?? 0})`,
          `Services: ${Array.isArray(resultData.services) ? resultData.services.map((s) => `${s.name}=${s.state}`).join(', ') : ''}`,
        ].join('\n');
        break;
      }

      case 'dmesg': {
        const limit = flags.limit !== null ? Number(flags.limit) : 100;
        if (remote) {
          const res = await remote.request('GET', '/api/v1/kernel/dmesg', {
            query: { limit, subsystem: flags.subsystem, level: flags.level },
          });
          resultData = res.entries ?? res;
        } else {
          resultData = localOs.kernel.dmesg({
            limit,
            subsystem: flags.subsystem || undefined,
            level: flags.level || undefined,
          });
        }
        const entries = Array.isArray(resultData) ? resultData : [];
        formattedText = entries
          .map((e) => `[${String(e.seq).padStart(4)}] [${e.level}] [${e.subsystem}] ${e.message}`)
          .join('\n');
        break;
      }

      case 'services': {
        const action = positionals[0]?.toLowerCase();
        const name = positionals[1];
        if (!action || action === 'list' || action === 'status') {
          if (remote) {
            const res = await remote.request('GET', '/api/v1/kernel/services');
            resultData = res.services ?? res;
          } else {
            resultData = localOs.serviceManager.getStatus();
          }
          const rows = Array.isArray(resultData) ? resultData : Object.values(resultData ?? {});
          formattedText = formatTable(rows, [
            { label: 'NAME', get: (r) => r.name },
            { label: 'STATE', get: (r) => r.state },
            { label: 'RESTARTS', get: (r) => r.restarts ?? 0 },
            { label: 'DEPS', get: (r) => (r.deps ?? []).join(',') },
          ]);
        } else if (['start', 'stop', 'restart', 'health'].includes(action)) {
          if (!name) throw new Error(`services ${action} requires a service name`);
          if (remote) {
            resultData = await remote.request(
              'POST',
              `/api/v1/kernel/services/${encodeURIComponent(name)}/${encodeURIComponent(action)}`
            );
          } else if (action === 'health') {
            resultData = await localOs.serviceManager.checkHealth(name);
          } else {
            resultData = await localOs.serviceManager[action](name);
          }
          formattedText = `Service ${name} ${action}: ok`;
        } else {
          throw new Error(`Unknown services subcommand: ${action}`);
        }
        break;
      }

      case 'ps': {
        if (flags.tree) {
          if (remote) {
            const res = await remote.request('GET', '/api/v1/processes/tree', {
              query: { includeTerminated: flags.all ? 'true' : undefined },
            });
            resultData = res.tree ?? res;
          } else {
            resultData = localOs.processManager.getTree({ includeTerminated: Boolean(flags.all) });
          }
          formattedText = formatProcessTree(resultData).join('\n');
        } else {
          if (remote) {
            const res = await remote.request('GET', '/api/v1/processes', {
              query: {
                includeTerminated: flags.all ? 'true' : undefined,
                platform: flags.platform,
              },
            });
            resultData = res.processes ?? res;
          } else {
            resultData = localOs.processManager.list({
              includeTerminated: Boolean(flags.all),
              platform: flags.platform || undefined,
            });
          }
          formattedText = formatTable(resultData, [
            { label: 'PID', get: (p) => p.pid },
            { label: 'PPID', get: (p) => p.ppid },
            { label: 'STATE', get: (p) => p.state },
            { label: 'PLATFORM', get: (p) => p.platform ?? 'system' },
            { label: 'NAME', get: (p) => p.name },
          ]);
        }
        break;
      }

      case 'kill': {
        const pidRaw = positionals[0];
        if (!pidRaw || !/^\d+$/.test(pidRaw)) {
          throw new Error('kill requires a numeric <pid>');
        }
        const pid = Number(pidRaw);
        const signal = flags.signal ?? 'SIGTERM';
        resultData = remote
          ? await remote.request('POST', `/api/v1/processes/${pid}/signal`, { body: { signal } })
          : localOs.processManager.kill(pid, signal);
        formattedText = `Sent ${signal} to PID ${pid} (state=${resultData.state ?? 'updated'})`;
        break;
      }

      case 'vfs': {
        const sub = positionals[0]?.toLowerCase();
        const a1 = positionals[1];
        const a2 = positionals[2];
        const vfsCtx = {
          ...(flags.platform ? { platform: flags.platform } : {}),
          ...(flags.cwd ? { cwd: flags.cwd } : {}),
        };

        if (sub === 'ls') {
          const target = a1 ?? '/home/user';
          if (remote) {
            const res = await remote.request('GET', '/api/v1/vfs/ls', {
              query: { path: target, ...vfsCtx },
            });
            resultData = res.entries ?? res;
          } else {
            resultData = localOs.vfs.readdir(target, { ...vfsCtx, withFileTypes: true });
          }
          formattedText = formatTable(resultData, [
            { label: 'TYPE', get: (e) => e.type },
            { label: 'SIZE', get: (e) => e.size ?? 0 },
            { label: 'NAME', get: (e) => e.name },
          ]);
        } else if (sub === 'cat') {
          if (!a1) throw new Error('vfs cat requires <path>');
          const encoding = flags.encoding ?? 'utf8';
          if (remote) {
            const res = await remote.request('GET', '/api/v1/vfs/file', {
              query: { path: a1, encoding, ...vfsCtx },
            });
            resultData = res;
            formattedText = String(res.content ?? '');
          } else {
            if (encoding === 'base64') {
              const bytes = localOs.vfs.readFile(a1, vfsCtx);
              const content = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
              resultData = { path: a1, encoding: 'base64', content, size: bytes.byteLength };
              formattedText = content;
            } else {
              const content = localOs.vfs.readFile(a1, { ...vfsCtx, encoding: 'utf8' });
              resultData = { path: a1, encoding: 'utf8', content, size: Buffer.byteLength(content, 'utf8') };
              formattedText = content;
            }
          }
        } else if (sub === 'write') {
          if (!a1) throw new Error('vfs write requires <path> <content>');
          const content = positionals.slice(2).join(' ');
          const encoding = flags.encoding ?? 'utf8';
          if (remote) {
            resultData = await remote.request('PUT', '/api/v1/vfs/file', {
              body: { path: a1, content, encoding, append: Boolean(flags.append), ...vfsCtx },
            });
          } else {
            const data =
              encoding === 'base64'
                ? new Uint8Array(Buffer.from(content, 'base64'))
                : content;
            resultData = localOs.vfs.writeFile(a1, data, { ...vfsCtx, append: Boolean(flags.append) });
          }
          formattedText = `Wrote ${resultData.bytesWritten ?? resultData.size ?? 0} bytes to ${resultData.path ?? a1}`;
        } else if (sub === 'mkdir') {
          if (!a1) throw new Error('vfs mkdir requires <path>');
          resultData = remote
            ? await remote.request('POST', '/api/v1/vfs/mkdir', {
                body: { path: a1, recursive: Boolean(flags.recursive), ...vfsCtx },
              })
            : localOs.vfs.mkdir(a1, { ...vfsCtx, recursive: Boolean(flags.recursive) });
          formattedText = `Created directory ${resultData.path ?? a1}`;
        } else if (sub === 'rm') {
          if (!a1) throw new Error('vfs rm requires <path>');
          if (remote) {
            resultData = await remote.request('DELETE', '/api/v1/vfs/file', {
              query: { path: a1, recursive: flags.recursive ? 'true' : 'false', ...vfsCtx },
            });
          } else {
            const st = localOs.vfs.lstat(a1, vfsCtx);
            resultData =
              st.type === 'dir'
                ? localOs.vfs.rmdir(a1, { ...vfsCtx, recursive: Boolean(flags.recursive) })
                : localOs.vfs.unlink(a1, vfsCtx);
          }
          formattedText = `Removed ${a1}`;
        } else if (sub === 'symlink') {
          if (!a1 || !a2) throw new Error('vfs symlink requires <target> <linkPath>');
          resultData = remote
            ? await remote.request('POST', '/api/v1/vfs/symlink', {
                body: { target: a1, linkPath: a2, ...vfsCtx },
              })
            : localOs.vfs.symlink(a1, a2, vfsCtx);
          formattedText = `Linked ${a2} -> ${a1}`;
        } else if (sub === 'resolve') {
          if (!a1) throw new Error('vfs resolve requires <path>');
          if (remote) {
            resultData = await remote.request('GET', '/api/v1/vfs/resolve', {
              query: { path: a1, ...vfsCtx },
            });
          } else {
            const resolved = localOs.vfs.resolvePath(a1, vfsCtx);
            const platformPaths = {};
            for (const p of ['posix', 'windows', 'macos', 'android', 'ios']) {
              platformPaths[p] = localOs.pathTranslator.toPlatform(resolved.canonicalPath, p, vfsCtx);
            }
            resultData = { ...resolved, platformPaths };
          }
          formattedText = `${a1} => ${resultData.canonicalPath}`;
        } else if (sub === 'stat') {
          if (!a1) throw new Error('vfs stat requires <path>');
          if (remote) {
            const res = await remote.request('GET', '/api/v1/vfs/stat', {
              query: { path: a1, lstat: flags.lstat ? 'true' : undefined, ...vfsCtx },
            });
            resultData = res.stat ?? res;
          } else {
            resultData = flags.lstat ? localOs.vfs.lstat(a1, vfsCtx) : localOs.vfs.stat(a1, vfsCtx);
          }
          formattedText = `${a1}: type=${resultData.type} size=${resultData.size} mode=${resultData.mode?.toString(8) ?? ''}`;
        } else if (sub === 'rename') {
          if (!a1 || !a2) throw new Error('vfs rename requires <oldPath> <newPath>');
          resultData = remote
            ? await remote.request('POST', '/api/v1/vfs/rename', {
                body: { oldPath: a1, newPath: a2, ...vfsCtx },
              })
            : localOs.vfs.rename(a1, a2, vfsCtx);
          formattedText = `Renamed ${a1} -> ${a2}`;
        } else if (sub === 'mounts') {
          if (remote) {
            const res = await remote.request('GET', '/api/v1/vfs/mounts');
            resultData = res.mounts ?? res;
          } else {
            resultData = localOs.vfs.listMounts();
          }
          formattedText = safeJsonFormat(resultData);
        } else {
          throw new Error(`Unknown vfs subcommand: ${sub ?? '(missing)'}`);
        }
        break;
      }

      case 'reg': {
        const sub = positionals[0]?.toLowerCase();
        const hive = positionals[1];
        const keyPath = positionals[2] ?? '';
        const valueName = positionals[3];
        const valueRaw = positionals.slice(4).join(' ');

        if (!hive) throw new Error('reg requires <subcommand> <hive> [keyPath] ...');

        if (sub === 'get') {
          if (valueName === undefined) throw new Error('reg get requires <hive> <keyPath> <valueName>');
          if (remote) {
            const res = await remote.request('GET', '/api/v1/config/registry', {
              query: { hive, keyPath, valueName },
            });
            resultData = res.value ?? null;
          } else {
            resultData = localOs.configStore.registry.getValue(hive, keyPath, valueName);
          }
          formattedText = resultData ? `${valueName} (${resultData.type}) = ${String(resultData.data)}` : '(null)';
        } else if (sub === 'set') {
          if (valueName === undefined || positionals.length < 5) {
            throw new Error('reg set requires <hive> <keyPath> <valueName> <value> [--type REG_SZ]');
          }
          const regType = (flags.type ?? 'REG_SZ').toUpperCase();
          const data = coerceRegistryData(regType, valueRaw);
          if (remote) {
            resultData = await remote.request('PUT', '/api/v1/config/registry', {
              body: { hive, keyPath, valueName, type: regType, data },
            });
          } else {
            resultData = localOs.configStore.registry.setValue(hive, keyPath, valueName, regType, data);
          }
          formattedText = `Set ${hive}\\${keyPath}\\${valueName} (${regType})`;
        } else if (sub === 'list') {
          resultData = remote
            ? await remote.request('GET', '/api/v1/config/registry', { query: { hive, keyPath } })
            : localOs.configStore.registry.enumKey(hive, keyPath);
          const subkeys = (resultData.subkeys ?? []).map((s) => `  [key] ${s}`);
          const vals = Object.entries(resultData.values ?? {}).map(
            ([k, v]) => `  ${k} (${v.type}) = ${String(v.data)}`
          );
          formattedText = [...subkeys, ...vals].join('\n') || '(empty)';
        } else if (sub === 'delete') {
          if (remote) {
            resultData = await remote.request('DELETE', '/api/v1/config/registry', {
              query: { hive, keyPath, ...(valueName !== undefined ? { valueName } : {}) },
            });
          } else {
            resultData =
              valueName !== undefined
                ? localOs.configStore.registry.deleteValue(hive, keyPath, valueName)
                : localOs.configStore.registry.deleteKey(hive, keyPath);
          }
          formattedText = `Deleted registry entry under ${hive}\\${keyPath}`;
        } else {
          throw new Error(`Unknown reg subcommand: ${sub ?? '(missing)'}`);
        }
        break;
      }

      case 'defaults': {
        const sub = positionals[0]?.toLowerCase();
        const domain = positionals[1];
        const key = positionals[2];
        const valRaw = positionals.slice(3).join(' ');

        if (sub === 'domains') {
          if (remote) {
            const res = await remote.request('GET', '/api/v1/config/defaults');
            resultData = res.domains ?? res;
          } else {
            resultData = localOs.configStore.defaults.listDomains();
          }
          formattedText = Array.isArray(resultData) ? resultData.join('\n') : safeJsonFormat(resultData);
        } else if (sub === 'read') {
          if (!domain) {
            if (remote) {
              const res = await remote.request('GET', '/api/v1/config/defaults');
              resultData = res.domains ?? res;
            } else {
              resultData = localOs.configStore.defaults.listDomains();
            }
            formattedText = Array.isArray(resultData) ? resultData.join('\n') : safeJsonFormat(resultData);
          } else if (key) {
            if (remote) {
              const res = await remote.request('GET', '/api/v1/config/defaults', {
                query: { domain, key },
              });
              resultData = res.value;
            } else {
              resultData = localOs.configStore.defaults.get(domain, key);
            }
            formattedText = resultData === null || resultData === undefined ? '(null)' : String(resultData);
          } else {
            if (remote) {
              const res = await remote.request('GET', '/api/v1/config/defaults', {
                query: { domain },
              });
              resultData = res.values ?? res;
            } else {
              resultData = localOs.configStore.defaults.readDomain(domain);
            }
            formattedText = safeJsonFormat(resultData);
          }
        } else if (sub === 'write') {
          if (!domain || !key || positionals.length < 4) {
            throw new Error('defaults write requires <domain> <key> <value>');
          }
          const value = parseScalarValue(valRaw);
          resultData = remote
            ? await remote.request('PUT', '/api/v1/config/defaults', { body: { domain, key, value } })
            : localOs.configStore.defaults.set(domain, key, value);
          formattedText = `Set ${domain} ${key} = ${String(value)}`;
        } else if (sub === 'delete') {
          if (!domain || !key) throw new Error('defaults delete requires <domain> <key>');
          resultData = remote
            ? await remote.request('DELETE', '/api/v1/config/defaults', { query: { domain, key } })
            : localOs.configStore.defaults.remove(domain, key);
          formattedText = `Removed ${domain} ${key}`;
        } else if (sub === 'export') {
          if (!domain) throw new Error('defaults export requires <domain>');
          const xml = remote
            ? await remote.request('GET', '/api/v1/config/defaults', {
                query: { domain, format: 'plist' },
                expectText: true,
              })
            : localOs.configStore.defaults.exportPlistXml(domain);
          resultData = { domain, plist: xml };
          formattedText = xml;
        } else {
          throw new Error(`Unknown defaults subcommand: ${sub ?? '(missing)'}`);
        }
        break;
      }

      case 'prefs': {
        const sub = positionals[0]?.toLowerCase();
        const pkg = positionals[1];
        if (!pkg) throw new Error('prefs requires <subcommand> <packageName> ...');

        if (sub === 'get') {
          let prefName = flags.pref ?? 'default';
          let key = null;
          if (positionals.length >= 4) {
            prefName = positionals[2];
            key = positionals[3];
          } else if (positionals.length === 3) {
            if (flags.pref) {
              key = positionals[2];
            } else {
              // Support both `prefs get <pkg> <key>` and `prefs get <pkg> <prefName>`
              const probeKey = remote
                ? (await remote.request('GET', '/api/v1/config/prefs', {
                    query: { packageName: pkg, prefName: 'default', key: positionals[2] },
                  })).value
                : localOs.configStore.sharedPrefs.get(pkg, 'default', positionals[2]);
              if (probeKey !== null && probeKey !== undefined) {
                key = positionals[2];
              } else {
                const probeAll = remote
                  ? (await remote.request('GET', '/api/v1/config/prefs', {
                      query: { packageName: pkg, prefName: positionals[2] },
                    })).values
                  : localOs.configStore.sharedPrefs.getAll(pkg, positionals[2]);
                if (probeAll && Object.keys(probeAll).length > 0) {
                  prefName = positionals[2];
                } else {
                  key = positionals[2];
                }
              }
            }
          }

          if (key) {
            if (remote) {
              const res = await remote.request('GET', '/api/v1/config/prefs', {
                query: { packageName: pkg, prefName, key },
              });
              resultData = res.value;
            } else {
              resultData = localOs.configStore.sharedPrefs.get(pkg, prefName, key);
            }
            formattedText = resultData === null || resultData === undefined ? '(null)' : String(resultData);
          } else {
            if (remote) {
              const res = await remote.request('GET', '/api/v1/config/prefs', {
                query: { packageName: pkg, prefName },
              });
              resultData = res.values ?? res;
            } else {
              resultData = localOs.configStore.sharedPrefs.getAll(pkg, prefName);
            }
            formattedText = safeJsonFormat(resultData);
          }
        } else if (sub === 'set') {
          let prefName = flags.pref ?? 'default';
          let key;
          let rawVal;
          if (positionals.length >= 5) {
            prefName = positionals[2];
            key = positionals[3];
            rawVal = positionals.slice(4).join(' ');
          } else if (positionals.length === 4) {
            key = positionals[2];
            rawVal = positionals[3];
          } else {
            throw new Error('prefs set requires <pkg> [prefName] <key> <value>');
          }
          const value = parseScalarValue(rawVal);
          if (remote) {
            resultData = await remote.request('PUT', '/api/v1/config/prefs', {
              body: { packageName: pkg, prefName, key, value, ...(flags.type ? { type: flags.type } : {}) },
            });
          } else {
            resultData = localOs.configStore.sharedPrefs.edit(pkg, prefName, [
              { op: 'put', key, value, ...(flags.type ? { type: flags.type } : {}) },
            ]);
          }
          formattedText = `Set ${pkg}/${prefName}/${key} = ${String(value)}`;
        } else if (sub === 'delete') {
          let prefName = flags.pref ?? 'default';
          let key = null;
          if (positionals.length >= 4) {
            prefName = positionals[2];
            key = positionals[3];
          } else if (positionals.length === 3) {
            key = positionals[2];
          }
          if (remote) {
            resultData = await remote.request('DELETE', '/api/v1/config/prefs', {
              query: { packageName: pkg, prefName, ...(key ? { key } : { clear: 'true' }) },
            });
          } else {
            const ops = key ? [{ op: 'remove', key }] : [{ op: 'clear' }];
            resultData = localOs.configStore.sharedPrefs.edit(pkg, prefName, ops);
          }
          formattedText = key ? `Removed ${pkg}/${prefName}/${key}` : `Cleared ${pkg}/${prefName}`;
        } else {
          throw new Error(`Unknown prefs subcommand: ${sub ?? '(missing)'}`);
        }
        break;
      }

      case 'ospm': {
        const sub = positionals[0]?.toLowerCase();
        const arg = positionals[1];

        if (sub === 'list') {
          if (remote) {
            const res = await remote.request('GET', '/api/v1/packages', {
              query: { platform: flags.platform },
            });
            resultData = res.packages ?? res;
          } else {
            resultData = localOs.pkgManager.list(flags.platform ? { platform: flags.platform } : {});
          }
          formattedText = formatTable(resultData, [
            { label: 'APP_ID', get: (p) => p.appId },
            { label: 'PLATFORM', get: (p) => p.platform },
            { label: 'ARCH', get: (p) => p.arch },
            { label: 'VERSION', get: (p) => p.version },
            { label: 'NAME', get: (p) => p.name },
          ]);
        } else if (sub === 'catalog') {
          if (remote) {
            const res = await remote.request('GET', '/api/v1/packages/catalog', {
              query: { platform: flags.platform },
            });
            resultData = res.catalog ?? res;
          } else {
            resultData = localOs.pkgManager.getCatalog(flags.platform ? { platform: flags.platform } : {});
          }
          formattedText = formatTable(resultData, [
            { label: 'APP_ID', get: (p) => p.appId },
            { label: 'PLATFORM', get: (p) => p.platform },
            { label: 'FORMAT', get: (p) => p.format },
            { label: 'NAME', get: (p) => p.name },
          ]);
        } else if (sub === 'inspect') {
          if (!arg) throw new Error('ospm inspect requires <path>');
          const pkgSrc = await resolvePackageSourceForCli(arg, flags);
          if (remote) {
            const body = pkgSrc.isHostFile
              ? { base64: pkgSrc.base64, filenameHint: pkgSrc.filenameHint }
              : { path: pkgSrc.vfsPath, filenameHint: pkgSrc.filenameHint };
            const res = await remote.request('POST', '/api/v1/packages/inspect', { body });
            resultData = res.inspection ?? res;
          } else {
            resultData = pkgSrc.isHostFile
              ? await localOs.pkgManager.inspect(pkgSrc.bytes, pkgSrc.filenameHint)
              : await localOs.pkgManager.inspect(pkgSrc.vfsPath, pkgSrc.filenameHint);
          }
          formattedText = [
            `App ID:   ${resultData.appId}`,
            `Name:     ${resultData.name}`,
            `Platform: ${resultData.platform} (${resultData.format}, arch=${resultData.arch})`,
            `Version:  ${resultData.version}`,
            `SHA-256:  ${resultData.sha256}`,
            `Size:     ${resultData.sizeBytes} bytes`,
          ].join('\n');
        } else if (sub === 'install') {
          if (!arg) throw new Error('ospm install requires <path>');
          const pkgSrc = await resolvePackageSourceForCli(arg, flags);
          const installOpts = {
            filenameHint: pkgSrc.filenameHint,
            grantAll: Boolean(flags.grantAll),
            overwrite: Boolean(flags.overwrite),
            upgrade: Boolean(flags.upgrade),
            ...(flags.sha256 ? { expectedSha256: flags.sha256 } : {}),
            ...(flags.source ? { source: flags.source } : {}),
          };
          if (remote) {
            const body = pkgSrc.isHostFile
              ? { base64: pkgSrc.base64, ...installOpts }
              : { path: pkgSrc.vfsPath, ...installOpts };
            const res = await remote.request('POST', '/api/v1/packages/install', { body });
            resultData = res.package ?? res;
          } else {
            resultData = pkgSrc.isHostFile
              ? await localOs.pkgManager.install(pkgSrc.bytes, installOpts)
              : await localOs.pkgManager.install(pkgSrc.vfsPath, installOpts);
          }
          formattedText = `Installed ${resultData.appId} (${resultData.platform}/${resultData.arch}, uid=${resultData.uid})`;
        } else if (sub === 'launch') {
          if (!arg) throw new Error('ospm launch requires <appId>');
          const launchBody = {
            stepTicks: 10,
            ...(flags.platform ? { platform: flags.platform } : {}),
          };
          if (remote) {
            resultData = await remote.request(
              'POST',
              `/api/v1/packages/${encodeURIComponent(arg)}/launch`,
              { body: launchBody }
            );
          } else {
            resultData = await localOs.launchApp(arg, launchBody);
          }
          formattedText = `Launched ${resultData.appId} (PID ${resultData.pid}, windows=${(resultData.windowIds ?? []).length})`;
        } else if (sub === 'stop') {
          if (!arg) throw new Error('ospm stop requires <appId|pid>');
          const signal = flags.signal ?? 'SIGTERM';
          if (remote) {
            const isPid = /^\d+$/.test(arg);
            resultData = await remote.request(
              'POST',
              `/api/v1/packages/${encodeURIComponent(arg)}/stop`,
              { body: { ...(isPid ? { pid: Number(arg) } : {}), signal } }
            );
          } else {
            const target = /^\d+$/.test(arg) ? Number(arg) : arg;
            resultData = localOs.stopApp(target, { signal });
          }
          formattedText = `Stopped PIDs: ${(resultData.stoppedPids ?? []).join(', ') || '(none)'}`;
        } else if (sub === 'uninstall') {
          if (!arg) throw new Error('ospm uninstall requires <appId>');
          resultData = remote
            ? await remote.request('DELETE', `/api/v1/packages/${encodeURIComponent(arg)}`, {
                query: { purgeData: flags.purge ? 'true' : 'false' },
              })
            : await localOs.pkgManager.uninstall(arg, { purgeData: Boolean(flags.purge) });
          formattedText = resultData.removed
            ? `Uninstalled ${arg}${resultData.purgedData ? ' (purged data)' : ''}`
            : `Package not installed: ${arg}`;
        } else {
          throw new Error(`Unknown ospm subcommand: ${sub ?? '(missing)'}`);
        }
        break;
      }

      case 'intent': {
        const sub = positionals[0]?.toLowerCase();
        const intentPayload = {
          ...(flags.action ? { action: flags.action } : {}),
          ...(flags.uri ? { uri: flags.uri } : {}),
          ...(flags.mime ? { mimeType: flags.mime } : {}),
          ...(flags.ext ? { extension: flags.ext } : {}),
          ...(flags.scheme ? { scheme: flags.scheme } : {}),
          ...(flags.app ? { preferredAppId: flags.app } : {}),
        };

        if (sub === 'resolve') {
          if (remote) {
            const res = await remote.request('POST', '/api/v1/ipc/intents/resolve', {
              body: intentPayload,
            });
            resultData = res.candidates ?? res;
          } else {
            resultData = localOs.intentRouter.resolve(intentPayload);
          }
          formattedText = formatTable(resultData, [
            { label: 'APP_ID', get: (c) => c.appId },
            { label: 'SCORE', get: (c) => c.score },
            { label: 'DEFAULT', get: (c) => (c.isDefault ? 'yes' : 'no') },
          ]);
        } else if (sub === 'dispatch') {
          resultData = remote
            ? await remote.request('POST', '/api/v1/ipc/intents/dispatch', { body: intentPayload })
            : await localOs.intentRouter.dispatch(intentPayload);
          formattedText = `Intent status: ${resultData.status}${resultData.targetAppId ? ` -> ${resultData.targetAppId}` : ''}`;
        } else {
          throw new Error(`Unknown intent subcommand: ${sub ?? '(missing)'}`);
        }
        break;
      }

      case 'clipboard': {
        const sub = positionals[0]?.toLowerCase() ?? 'get';
        if (sub === 'get') {
          if (remote) {
            const res = await remote.request('GET', '/api/v1/ipc/clipboard', {
              query: { mime: flags.mime },
            });
            resultData = res.current ?? null;
          } else {
            resultData = flags.mime ? localOs.clipboard.get(flags.mime) : localOs.clipboard.get();
          }
          formattedText =
            typeof resultData === 'string'
              ? resultData
              : (resultData?.text ??
                resultData?.html ??
                (resultData ? safeJsonFormat(resultData) : '(empty)'));
        } else if (sub === 'set') {
          const text = positionals.slice(1).join(' ');
          const requestedMime = typeof flags.mime === 'string' ? flags.mime.trim() : '';
          const normalizedMime = requestedMime.toLowerCase();
          let clipBody;
          if (normalizedMime && normalizedMime !== 'text/plain') {
            let clipData = text;
            if (normalizedMime === 'application/json') {
              try {
                clipData = JSON.parse(text);
              } catch (parseErr) {
                const err = new Error(
                  `Invalid JSON for application/json clipboard payload: ${parseErr.message}`
                );
                err.code = 'EINVAL';
                throw err;
              }
            }
            clipBody = { mime: requestedMime, data: clipData, sourceAppId: 'com.omnios.cli' };
          } else {
            clipBody = { text, sourceAppId: 'com.omnios.cli' };
          }
          if (remote) {
            const res = await remote.request('POST', '/api/v1/ipc/clipboard', { body: clipBody });
            resultData = res.current ?? res;
          } else {
            resultData = localOs.clipboard.set(clipBody);
          }
          formattedText = `Clipboard updated (${text.length} chars)`;
        } else if (sub === 'history') {
          const limit = flags.limit !== null ? Number(flags.limit) : 20;
          if (remote) {
            const res = await remote.request('GET', '/api/v1/ipc/clipboard', { query: { limit } });
            resultData = res.history ?? [];
          } else {
            resultData = localOs.clipboard.history(limit);
          }
          formattedText = formatTable(resultData, [
            { label: 'ID', get: (c) => c.id },
            { label: 'MIME', get: (c) => c.mime ?? c.primaryMime ?? 'text/plain' },
            {
              label: 'TEXT',
              get: (c) =>
                c.text ??
                c.html ??
                (c.formats?.[c.mime] != null ? String(c.formats[c.mime]) : ''),
            },
          ]);
        } else if (sub === 'clear') {
          resultData = remote
            ? await remote.request('DELETE', '/api/v1/ipc/clipboard', {
                query: { clearHistory: flags.clearHistory ? 'true' : 'false' },
              })
            : localOs.clipboard.clear({ clearHistory: Boolean(flags.clearHistory) });
          formattedText = 'Clipboard cleared';
        } else {
          throw new Error(`Unknown clipboard subcommand: ${sub}`);
        }
        break;
      }

      case 'notify': {
        const sub = positionals[0]?.toLowerCase() ?? 'list';
        if (sub === 'send') {
          const title = flags.title ?? positionals[1] ?? 'OmniOS Notification';
          const bodyText = flags.body ?? positionals.slice(flags.title ? 1 : 2).join(' ') ?? '';
          const payload = {
            appId: flags.app ?? 'com.omnios.cli',
            platform: flags.platform ?? 'system',
            title,
            body: bodyText,
            priority: flags.priority ?? 'normal',
            category: flags.category ?? 'system',
          };
          if (remote) {
            const res = await remote.request('POST', '/api/v1/ipc/notifications', { body: payload });
            resultData = res.notification ?? res;
          } else {
            resultData = localOs.notifications.post(payload);
          }
          formattedText = `Posted notification ${resultData.id}: ${resultData.title}`;
        } else if (sub === 'list') {
          if (remote) {
            const res = await remote.request('GET', '/api/v1/ipc/notifications', {
              query: {
                includeDismissed: flags.includeDismissed ? 'true' : undefined,
                appId: flags.app,
                category: flags.category,
                priority: flags.priority,
              },
            });
            resultData = res.notifications ?? [];
          } else {
            resultData = localOs.notifications.list({
              includeDismissed: Boolean(flags.includeDismissed),
              appId: flags.app || undefined,
              category: flags.category || undefined,
              priority: flags.priority || undefined,
            });
          }
          formattedText = formatTable(resultData, [
            { label: 'ID', get: (n) => n.id },
            { label: 'APP', get: (n) => n.appId },
            { label: 'PRIORITY', get: (n) => n.priority },
            { label: 'TITLE', get: (n) => n.title },
          ]);
        } else if (sub === 'dismiss') {
          const id = positionals[1];
          if (!id) throw new Error('notify dismiss requires <notificationId>');
          if (remote) {
            const res = await remote.request(
              'POST',
              `/api/v1/ipc/notifications/${encodeURIComponent(id)}/dismiss`
            );
            resultData = res.notification ?? res;
          } else {
            resultData = localOs.notifications.dismiss(id);
          }
          formattedText = `Dismissed notification ${id}`;
        } else {
          throw new Error(`Unknown notify subcommand: ${sub}`);
        }
        break;
      }

      default:
        throw new Error(`Unknown command: ${command}. Run with --help for usage.`);
    }

    if (flags.json) {
      writeOut(`${safeJsonFormat(resultData)}\n`);
    } else if (formattedText.length > 0) {
      writeOut(formattedText.endsWith('\n') ? formattedText : `${formattedText}\n`);
    }

    return { exitCode: 0, stdout: outBuf, stderr: errBuf, data: resultData };
  } catch (err) {
    const code = typeof err?.code === 'string' ? err.code : 'E_CLI';
    const errObj = {
      ok: false,
      code,
      error: {
        code,
        message: err?.message ?? String(err),
      },
    };
    if (flags.json) {
      writeOut(`${safeJsonFormat(errObj)}\n`);
    }
    writeErr(`${err?.message ?? err}\n`);
    return { exitCode: 1, stdout: outBuf, stderr: errBuf, data: errObj };
  } finally {
    if (localOs && typeof localOs.shutdown === 'function') {
      try {
        await localOs.shutdown();
      } catch (shutdownErr) {
        writeErr(`Shutdown warning: ${shutdownErr?.message ?? shutdownErr}\n`);
      }
    }
  }
}

// Main-module entrypoint: `node os/cli/omnios-cli.mjs ...`
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const result = await runCli(process.argv.slice(2), {
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
  });
  process.exitCode = result.exitCode;
}
