/**
 * OmniOS E2E Test Harness — Opaque-Box Environment, HTTP/WS, CLI & Public Facade Helpers.
 *
 * STRICT INVARIANTS:
 * - Zero external dependencies (Node.js 24 built-in ESM modules + global fetch/WebSocket only).
 * - Strictly opaque-box: references ONLY the 3 documented public entrypoints:
 *   1. os/os.mjs (createOmniOS)
 *   2. os/server/http-server.mjs (HTTP REST + RFC 6455 WS)
 *   3. os/cli/omnios-cli.mjs (Headless & Remote CLI)
 * - Anti-skip: throws E_OMNIOS_NOT_IMPLEMENTED loudly whenever a required public entrypoint is missing.
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const REPO_ROOT = path.resolve(__dirname, '../../..');

export const PUBLIC_PATHS = Object.freeze({
  osEntry: path.join(REPO_ROOT, 'os', 'os.mjs'),
  httpServerEntry: path.join(REPO_ROOT, 'os', 'server', 'http-server.mjs'),
  cliEntry: path.join(REPO_ROOT, 'os', 'cli', 'omnios-cli.mjs'),
});

const MAX_LOG_BYTES = 256 * 1024;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function raceWithTimeout(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((resolve) => {
      timer = setTimeout(resolve, ms);
      timer.unref?.();
    }),
  ]).finally(() => clearTimeout(timer));
}

function appendCapped(existing, chunk) {
  const combined = existing + chunk;
  if (combined.length <= MAX_LOG_BYTES) return combined;
  return combined.slice(combined.length - MAX_LOG_BYTES);
}

async function removeDirWithRetry(dirPath) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await fs.rm(dirPath, { recursive: true, force: true });
      return;
    } catch (err) {
      if (attempt === 0 && (err?.code === 'EBUSY' || err?.code === 'ENOTEMPTY' || err?.code === 'EPERM')) {
        await sleep(100);
        continue;
      }
      throw err;
    }
  }
}

/**
 * Verifies that a public OmniOS entrypoint exists on disk.
 * Never skips; throws a structured E_OMNIOS_NOT_IMPLEMENTED error if absent.
 */
export async function assertPublicEntryExists(entryPath, label = entryPath) {
  try {
    await fs.access(entryPath);
  } catch (cause) {
    const err = new Error(
      `OmniOS public entrypoint missing: ${label} (${entryPath}). ` +
      `E2E tests must fail loudly when the target OS implementation is absent and must never skip.`
    );
    err.code = 'E_OMNIOS_NOT_IMPLEMENTED';
    err.entryPath = entryPath;
    err.cause = cause;
    throw err;
  }
}

/**
 * Allocates an isolated temporary directory for OmniOS SQLite data / scratch artifacts.
 */
export async function createTempDataDir(prefix = 'omnios-e2e-') {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  let cleanupPromise = null;

  function cleanup() {
    if (!cleanupPromise) {
      cleanupPromise = removeDirWithRetry(dir);
    }
    return cleanupPromise;
  }

  return { dir, cleanup };
}

/**
 * Reserves an unused local TCP port by briefly binding port 0 on host.
 */
export function allocateEphemeralPort(host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, host, () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      server.close((closeErr) => {
        if (closeErr) reject(closeErr);
        else resolve(port);
      });
    });
  });
}

/**
 * Polls an HTTP health endpoint until it responds 200 OK with valid JSON.
 */
export async function waitForHealth(healthUrl, { timeoutMs = 15000, intervalMs = 60, shouldAbort } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    const abortErr = shouldAbort?.();
    if (abortErr) throw abortErr;

    const remaining = Math.max(100, deadline - Date.now());
    try {
      const res = await fetch(healthUrl, {
        method: 'GET',
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(Math.min(2000, remaining)),
      });
      if (res.status === 200) {
        const text = await res.text();
        let parsed;
        let isJson = false;
        try {
          parsed = JSON.parse(text);
          isJson = true;
        } catch (parseErr) {
          lastError = new Error(
            `Health endpoint ${healthUrl} returned HTTP 200 with invalid JSON: ${parseErr.message} (body: ${text.slice(0, 120)})`
          );
        }
        if (isJson) {
          if (
            parsed !== null &&
            typeof parsed === 'object' &&
            !Array.isArray(parsed) &&
            parsed.ok !== false &&
            (parsed.ok === true || Boolean(parsed.status))
          ) {
            return { status: 200, body: parsed };
          }
          lastError = new Error(
            `Health endpoint ${healthUrl} returned HTTP 200 with unhealthy/unexpected payload: ${text.slice(0, 200)}`
          );
        }
      } else {
        lastError = new Error(`Health endpoint ${healthUrl} returned HTTP ${res.status}`);
      }
    } catch (err) {
      lastError = err;
    }

    const abortAfter = shouldAbort?.();
    if (abortAfter) throw abortAfter;

    const waitMs = Math.min(intervalMs, Math.max(0, deadline - Date.now()));
    if (waitMs > 0) await sleep(waitMs);
  }

  const err = new Error(
    `Timed out after ${timeoutMs}ms waiting for health endpoint ${healthUrl}` +
    (lastError ? ` (last error: ${lastError.message})` : '')
  );
  err.code = 'E_HEALTH_TIMEOUT';
  err.cause = lastError;
  throw err;
}

/**
 * Creates a zero-dependency HTTP REST API client wrapping Node 24 fetch.
 */
export function createApiClient(baseUrl, { defaultTimeoutMs = 15000 } = {}) {
  const normalizedBase = String(baseUrl).replace(/\/+$/, '');

  async function request(method, urlPath, {
    body,
    headers = {},
    query,
    timeoutMs = defaultTimeoutMs,
    expectOk = false,
  } = {}) {
    const cleanPath = urlPath.startsWith('http://') || urlPath.startsWith('https://')
      ? urlPath
      : `${normalizedBase}${urlPath.startsWith('/') ? urlPath : `/${urlPath}`}`;

    const urlObj = new URL(cleanPath);
    if (query && typeof query === 'object') {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null) {
          urlObj.searchParams.set(k, String(v));
        }
      }
    }

    const mergedHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      if (v !== undefined && v !== null) {
        mergedHeaders[k.toLowerCase()] = String(v);
      }
    }

    let encodedBody;
    if (body !== undefined && body !== null) {
      if (Buffer.isBuffer(body) || body instanceof Uint8Array) {
        encodedBody = body;
        if (!mergedHeaders['content-type']) {
          mergedHeaders['content-type'] = 'application/octet-stream';
        }
      } else if (typeof FormData !== 'undefined' && body instanceof FormData) {
        encodedBody = body;
      } else if (typeof body === 'string') {
        encodedBody = body;
        if (!mergedHeaders['content-type']) {
          mergedHeaders['content-type'] = 'text/plain; charset=utf-8';
        }
      } else {
        encodedBody = JSON.stringify(body);
        if (!mergedHeaders['content-type']) {
          mergedHeaders['content-type'] = 'application/json';
        }
      }
    }

    const res = await fetch(urlObj.toString(), {
      method: method.toUpperCase(),
      headers: mergedHeaders,
      body: encodedBody,
      signal: AbortSignal.timeout(timeoutMs),
    });

    const buffer = Buffer.from(await res.arrayBuffer());
    const text = buffer.toString('utf8');
    const respHeaders = Object.fromEntries(res.headers.entries());
    const ct = respHeaders['content-type'] || '';
    const trimmed = text.trim();

    let json = null;
    if (ct.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }

    const result = {
      status: res.status,
      ok: res.ok,
      headers: respHeaders,
      json,
      text,
      buffer,
    };

    if (expectOk && !res.ok) {
      const err = new Error(
        `HTTP ${method.toUpperCase()} ${urlObj.toString()} failed with ${res.status}: ${text.slice(0, 500)}`
      );
      err.status = res.status;
      err.response = result;
      throw err;
    }

    return result;
  }

  return {
    baseUrl: normalizedBase,
    request,
    get(urlPath, opts = {}) {
      return request('GET', urlPath, opts);
    },
    post(urlPath, body, opts = {}) {
      return request('POST', urlPath, { ...opts, body });
    },
    put(urlPath, body, opts = {}) {
      return request('PUT', urlPath, { ...opts, body });
    },
    patch(urlPath, body, opts = {}) {
      return request('PATCH', urlPath, { ...opts, body });
    },
    delete(urlPath, opts = {}) {
      return request('DELETE', urlPath, opts);
    },
    del(urlPath, opts = {}) {
      return request('DELETE', urlPath, opts);
    },
  };
}

/**
 * Connects to an RFC 6455 WebSocket endpoint using Node 24's built-in global WebSocket.
 * Buffers all received JSON envelopes and supports race-free mark()/since cursor waiting.
 */
export async function connectWs(wsUrl, { timeoutMs = 10000, protocols } = {}) {
  const ws = protocols !== undefined ? new WebSocket(wsUrl, protocols) : new WebSocket(wsUrl);

  const messages = [];
  const waiters = new Set();
  let closed = false;
  let closeInfo = null;
  let resolveClose;
  const closePromise = new Promise((resolve) => {
    resolveClose = resolve;
  });

  function decodeIncoming(rawData) {
    if (typeof rawData === 'string') return rawData;
    if (rawData instanceof ArrayBuffer) return Buffer.from(rawData).toString('utf8');
    if (ArrayBuffer.isView(rawData)) {
      return Buffer.from(rawData.buffer, rawData.byteOffset, rawData.byteLength).toString('utf8');
    }
    return String(rawData);
  }

  function pushMessage(text) {
    let parsed;
    try {
      parsed = JSON.parse(text);
      if (parsed === null || typeof parsed !== 'object') {
        parsed = { type: '__raw__', value: parsed, raw: text };
      }
    } catch {
      parsed = { type: '__raw__', raw: text };
    }
    const idx = messages.length;
    messages.push(parsed);

    for (const waiter of Array.from(waiters)) {
      if (idx < waiter.since) continue;
      let matched = false;
      try {
        matched = Boolean(waiter.predicate(parsed, idx));
      } catch (err) {
        clearTimeout(waiter.timer);
        waiters.delete(waiter);
        waiter.reject(err);
        continue;
      }
      if (matched) {
        clearTimeout(waiter.timer);
        waiters.delete(waiter);
        waiter.resolve(parsed);
      }
    }
  }

  ws.addEventListener('message', (ev) => {
    const data = ev.data;
    if (typeof Blob !== 'undefined' && data instanceof Blob) {
      data.text().then(pushMessage).catch(() => {});
    } else {
      pushMessage(decodeIncoming(data));
    }
  });

  ws.addEventListener('close', (ev) => {
    closed = true;
    closeInfo = { code: ev.code, reason: ev.reason || '' };
    resolveClose(closeInfo);
    for (const waiter of Array.from(waiters)) {
      clearTimeout(waiter.timer);
      waiters.delete(waiter);
      waiter.reject(
        new Error(`WebSocket ${wsUrl} closed (code=${ev.code}, reason=${ev.reason || ''}) while waiting for message`)
      );
    }
  });

  await new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { ws.close(); } catch { /* ignore */ }
      reject(new Error(`Timed out after ${timeoutMs}ms connecting to WebSocket ${wsUrl}`));
    }, timeoutMs);

    const onOpen = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.removeEventListener('error', onError);
      ws.removeEventListener('close', onPrematureClose);
      resolve();
    };

    const onError = (ev) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.removeEventListener('open', onOpen);
      ws.removeEventListener('close', onPrematureClose);
      const msg = ev?.message || ev?.error?.message || 'WebSocket connection error';
      reject(new Error(`Failed to connect to WebSocket ${wsUrl}: ${msg}`));
    };

    const onPrematureClose = (ev) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.removeEventListener('open', onOpen);
      ws.removeEventListener('error', onError);
      reject(new Error(`WebSocket ${wsUrl} closed before open (code=${ev.code})`));
    };

    ws.addEventListener('open', onOpen, { once: true });
    ws.addEventListener('error', onError, { once: true });
    ws.addEventListener('close', onPrematureClose, { once: true });
  });

  function normalizeMatcher(matcher) {
    if (typeof matcher === 'string') {
      return (m) => m && m.type === matcher;
    }
    if (matcher instanceof RegExp) {
      return (m) => matcher.test(String(m?.type ?? ''));
    }
    if (typeof matcher === 'function') {
      return matcher;
    }
    throw new TypeError(`Invalid WebSocket matcher: expected string, RegExp, or function`);
  }

  function waitForMessage(matcher, { timeoutMs: waitTimeoutMs = 5000, since = 0 } = {}) {
    let predicate;
    try {
      predicate = normalizeMatcher(matcher);
      for (let i = Math.max(0, since); i < messages.length; i++) {
        if (predicate(messages[i], i)) {
          return Promise.resolve(messages[i]);
        }
      }
    } catch (err) {
      return Promise.reject(err);
    }
    if (closed) {
      const seenTypes = messages.slice(since).map((m) => m?.type ?? '<unknown>');
      return Promise.reject(
        new Error(`WebSocket ${wsUrl} already closed before matching message arrived (seen since ${since}: [${seenTypes.join(', ')}])`)
      );
    }

    return new Promise((resolve, reject) => {
      const waiter = {
        since: Math.max(0, since),
        predicate,
        resolve,
        reject,
        timer: null,
      };
      waiter.timer = setTimeout(() => {
        waiters.delete(waiter);
        const seenTypes = messages.slice(waiter.since).map((m) => m?.type ?? '<unknown>');
        reject(
          new Error(
            `Timed out after ${waitTimeoutMs}ms waiting for WebSocket message on ${wsUrl} ` +
            `(seen since ${waiter.since}: [${seenTypes.join(', ')}])`
          )
        );
      }, waitTimeoutMs);
      waiters.add(waiter);
    });
  }

  function waitForType(type, opts = {}) {
    return waitForMessage(type, opts);
  }

  function waitForClose(waitTimeoutMs = 5000) {
    if (closed) return Promise.resolve(closeInfo);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Timed out after ${waitTimeoutMs}ms waiting for WebSocket ${wsUrl} to close`));
      }, waitTimeoutMs);
      closePromise.then((info) => {
        clearTimeout(timer);
        resolve(info);
      });
    });
  }

  function send(payload) {
    if (ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Cannot send on WebSocket ${wsUrl}: readyState=${ws.readyState}`);
    }
    if (typeof payload === 'string') {
      ws.send(payload);
    } else {
      ws.send(JSON.stringify(payload));
    }
  }

  let closeTask = null;
  function close(code = 1000, reason = 'test-complete') {
    if (!closeTask) {
      closeTask = (async () => {
        for (const waiter of Array.from(waiters)) {
          clearTimeout(waiter.timer);
          waiters.delete(waiter);
          waiter.reject(new Error(`WebSocket ${wsUrl} closed by test teardown`));
        }
        if (!closed && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
          try {
            ws.close(code, reason);
          } catch {
            // ignore close errors during teardown
          }
        }
        await raceWithTimeout(closePromise, 2000);
      })();
    }
    return closeTask;
  }

  return {
    ws,
    url: wsUrl,
    mark() {
      return messages.length;
    },
    getMessages(since = 0) {
      return messages.slice(since);
    },
    send,
    waitForMessage,
    waitForType,
    waitForClose,
    isOpen() {
      return ws.readyState === WebSocket.OPEN;
    },
    close,
  };
}

/**
 * Executes the public OmniOS CLI (os/cli/omnios-cli.mjs) as an isolated subprocess.
 */
export async function runCli(args = [], {
  dataDir,
  remote,
  json = false,
  input,
  env = {},
  cwd = REPO_ROOT,
  timeoutMs = 15000,
  expectZero = false,
} = {}) {
  await assertPublicEntryExists(PUBLIC_PATHS.cliEntry, 'os/cli/omnios-cli.mjs');

  const finalArgs = [PUBLIC_PATHS.cliEntry, ...args];
  if (dataDir && !args.includes('--data-dir')) {
    finalArgs.push('--data-dir', dataDir);
  }
  if (remote && !args.includes('--remote')) {
    finalArgs.push('--remote', remote);
  }
  if (json && !args.includes('--json')) {
    finalArgs.push('--json');
  }

  const childEnv = {
    ...process.env,
    ...(dataDir ? { OMNIOS_DATA_DIR: dataDir, DATA_DIR: dataDir } : {}),
    ...env,
  };

  return await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, finalArgs, {
      cwd,
      env: childEnv,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let killTimer = null;

    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGTERM'); } catch { /* ignore */ }
      killTimer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* ignore */ }
      }, 1000);
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });

    child.stdin.on('error', () => {});
    if (input !== undefined && input !== null) {
      child.stdin.write(input);
    }
    child.stdin.end();

    child.once('error', (err) => {
      clearTimeout(timeoutTimer);
      if (killTimer) clearTimeout(killTimer);
      reject(err);
    });

    child.once('close', (code, signal) => {
      clearTimeout(timeoutTimer);
      if (killTimer) clearTimeout(killTimer);

      if (timedOut) {
        const err = new Error(
          `OmniOS CLI timed out after ${timeoutMs}ms: node ${finalArgs.join(' ')}\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`
        );
        err.code = 'E_CLI_TIMEOUT';
        reject(err);
        return;
      }

      let parsedJson = null;
      const trimmed = stdout.trim();
      if (trimmed.length > 0 && (trimmed.startsWith('{') || trimmed.startsWith('[') || trimmed === 'null' || trimmed === 'true' || trimmed === 'false')) {
        try {
          parsedJson = JSON.parse(trimmed);
        } catch {
          parsedJson = null;
        }
      }

      const result = {
        code,
        signal,
        ok: code === 0,
        stdout,
        stderr,
        json: parsedJson,
      };

      if (expectZero && code !== 0) {
        const err = new Error(
          `OmniOS CLI exited with code ${code} (signal=${signal}): node ${finalArgs.join(' ')}\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`
        );
        err.code = 'E_CLI_NONZERO';
        err.result = result;
        reject(err);
        return;
      }

      resolve(result);
    });
  });
}

async function terminateChildProcess(child, sigtermWaitMs = 3000, sigkillWaitMs = 2000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;

  const waitExit = (ms) => new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve(true);
      return;
    }
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    const timer = setTimeout(() => {
      child.removeListener('exit', onExit);
      resolve(false);
    }, ms);
    child.once('exit', onExit);
  });

  try { child.kill('SIGTERM'); } catch { /* ignore */ }
  if (await waitExit(sigtermWaitMs)) return;

  try { child.kill('SIGKILL'); } catch { /* ignore */ }
  await waitExit(sigkillWaitMs);
}

/**
 * Starts an ephemeral OmniOS HTTP + WebSocket daemon on an isolated temp data directory and port.
 */
export async function startOmniServer({
  mode = 'server',
  host = '127.0.0.1',
  port,
  dataDir,
  keepDataDir = false,
  env = {},
  startupTimeoutMs = 15000,
} = {}) {
  const entryPath = mode === 'cli' ? PUBLIC_PATHS.cliEntry : PUBLIC_PATHS.httpServerEntry;
  const entryLabel = mode === 'cli' ? 'os/cli/omnios-cli.mjs' : 'os/server/http-server.mjs';
  await assertPublicEntryExists(entryPath, entryLabel);

  const ownsDataDir = !dataDir;
  const tempHolder = ownsDataDir ? await createTempDataDir('omnios-srv-') : null;
  const activeDataDir = dataDir ?? tempHolder.dir;
  const activePort = port ?? (await allocateEphemeralPort(host));

  const spawnArgs = mode === 'cli'
    ? [PUBLIC_PATHS.cliEntry, 'boot', '--port', String(activePort), '--host', host, '--data-dir', activeDataDir]
    : [PUBLIC_PATHS.httpServerEntry, '--port', String(activePort), '--host', host, '--data-dir', activeDataDir];

  const childEnv = {
    ...process.env,
    PORT: String(activePort),
    HOST: host,
    OMNIOS_PORT: String(activePort),
    OMNIOS_HOST: host,
    OMNIOS_DATA_DIR: activeDataDir,
    DATA_DIR: activeDataDir,
    ...env,
  };

  const child = spawn(process.execPath, spawnArgs, {
    cwd: REPO_ROOT,
    env: childEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdoutLog = '';
  let stderrLog = '';
  let earlyExitError = null;

  child.stdout.on('data', (chunk) => {
    stdoutLog = appendCapped(stdoutLog, chunk.toString('utf8'));
  });
  child.stderr.on('data', (chunk) => {
    stderrLog = appendCapped(stderrLog, chunk.toString('utf8'));
  });
  child.once('error', (err) => {
    earlyExitError = new Error(`OmniOS server process error: ${err.message}`);
  });
  child.once('exit', (code, signal) => {
    if (!earlyExitError) {
      earlyExitError = new Error(
        `OmniOS server exited prematurely (code=${code}, signal=${signal})\nSTDOUT:\n${stdoutLog}\nSTDERR:\n${stderrLog}`
      );
    }
  });

  const baseUrl = `http://${host}:${activePort}`;
  const wsUrl = `ws://${host}:${activePort}/ws`;
  const trackedWs = new Set();

  try {
    await waitForHealth(`${baseUrl}/api/health`, {
      timeoutMs: startupTimeoutMs,
      shouldAbort: () => earlyExitError,
    });
  } catch (err) {
    await terminateChildProcess(child);
    if (ownsDataDir && !keepDataDir && tempHolder) {
      await tempHolder.cleanup();
    }
    const wrapped = new Error(
      `Failed to start OmniOS server at ${baseUrl}: ${err.message}\nSTDOUT:\n${stdoutLog}\nSTDERR:\n${stderrLog}`
    );
    wrapped.cause = err;
    throw wrapped;
  }

  const api = createApiClient(baseUrl);
  let stopPromise = null;

  async function openTrackedWs(wsOpts = {}) {
    const handle = await connectWs(wsUrl, wsOpts);
    trackedWs.add(handle);
    const origClose = handle.close;
    handle.close = async (...closeArgs) => {
      trackedWs.delete(handle);
      return origClose(...closeArgs);
    };
    return handle;
  }

  function stop() {
    if (!stopPromise) {
      stopPromise = (async () => {
        await Promise.allSettled(Array.from(trackedWs).map((w) => w.close()));
        trackedWs.clear();
        await terminateChildProcess(child);
        if (ownsDataDir && !keepDataDir && tempHolder) {
          await tempHolder.cleanup();
        }
      })();
    }
    return stopPromise;
  }

  return {
    baseUrl,
    wsUrl,
    host,
    port: activePort,
    dataDir: activeDataDir,
    pid: child.pid,
    process: child,
    api,
    connectWs: openTrackedWs,
    runCli(cliArgs = [], cliOpts = {}) {
      return runCli(cliArgs, { remote: baseUrl, ...cliOpts });
    },
    getLogs() {
      return { stdout: stdoutLog, stderr: stderrLog };
    },
    stop,
    close: stop,
  };
}

/**
 * Loads the top-level public OmniOS runtime factory strictly via os/os.mjs (createOmniOS).
 * Zero private internal module imports are permitted.
 */
export async function loadPublicOmniOS(config = {}) {
  const { dataDir, keepDataDir = false, autoBoot = true, ...restConfig } = config;
  await assertPublicEntryExists(PUBLIC_PATHS.osEntry, 'os/os.mjs');

  const mod = await import(pathToFileURL(PUBLIC_PATHS.osEntry).href);
  const createOmniOS =
    mod.createOmniOS ??
    mod.default?.createOmniOS ??
    (typeof mod.default === 'function' ? mod.default : null);

  if (typeof createOmniOS !== 'function') {
    throw new Error(`Public entrypoint os/os.mjs does not export createOmniOS(config)`);
  }

  const ownsDataDir = !dataDir;
  const tempHolder = ownsDataDir ? await createTempDataDir('omnios-pub-') : null;
  const activeDataDir = dataDir ?? tempHolder.dir;

  let raw;
  try {
    raw = await createOmniOS({ dataDir: activeDataDir, ...restConfig });
    if (autoBoot) {
      const state = raw?.kernel?.getDiagnostics?.()?.state ?? raw?.getDiagnostics?.()?.state;
      if (state !== 'RUNNING') {
        if (typeof raw?.boot === 'function') {
          await raw.boot();
        } else if (typeof raw?.kernel?.boot === 'function') {
          await raw.kernel.boot();
        }
      }
    }
  } catch (err) {
    if (raw) {
      try {
        raw.scheduler?.stop?.();
        raw.kernel?.scheduler?.stop?.();
        if (typeof raw.shutdown === 'function') {
          await raw.shutdown();
        } else if (typeof raw.close === 'function') {
          await raw.close();
        } else if (typeof raw.kernel?.shutdown === 'function') {
          await raw.kernel.shutdown();
        }
      } catch {
        // best-effort teardown when boot fails after createOmniOS()
      }
    }
    if (ownsDataDir && !keepDataDir && tempHolder) {
      await tempHolder.cleanup();
    }
    throw err;
  }

  const kernel = raw.kernel ?? raw;
  let shutdownPromise = null;

  const handle = {
    raw,
    dataDir: activeDataDir,
    kernel,
    serviceManager: raw.serviceManager ?? raw.services ?? kernel?.serviceManager ?? kernel?.services ?? null,
    processManager: raw.processManager ?? raw.processes ?? kernel?.processManager ?? kernel?.processes ?? null,
    scheduler: raw.scheduler ?? kernel?.scheduler ?? null,
    vfs: raw.vfs ?? null,
    pathTranslator: raw.pathTranslator ?? raw.vfs?.pathTranslator ?? null,
    configStore: raw.configStore ?? raw.config ?? raw.store ?? null,
    ipc: raw.ipc ?? raw.ipcManager ?? null,
    intentRouter: raw.intentRouter ?? raw.router ?? null,
    clipboard: raw.clipboard ?? null,
    notifications: raw.notifications ?? raw.notificationCenter ?? null,
    security: raw.security ?? raw.securityManager ?? raw.permissions ?? null,
    users: raw.users ?? raw.userManager ?? raw.security?.users ?? null,
    compositor: raw.compositor ?? null,
    cpuRegistry: raw.cpuRegistry ?? kernel?.cpuRegistry ?? null,
    formatDetector: raw.formatDetector ?? raw.pkgManager?.formatDetector ?? raw.packageManager?.formatDetector ?? null,
    pkgManager: raw.pkgManager ?? raw.packageManager ?? raw.ospm ?? raw.packages ?? null,
    runtimes: raw.runtimes ?? null,
    search: raw.search ?? raw.spotlight ?? null,
    shell: raw.shell ?? raw.shellInterpreter ?? null,
    apps: raw.apps ?? raw.systemApps ?? null,
    require(name) {
      const value = handle[name];
      if (!value) {
        throw new Error(`OmniOS public runtime missing Contract subsystem "${name}"`);
      }
      return value;
    },
    shutdown() {
      if (!shutdownPromise) {
        shutdownPromise = (async () => {
          try {
            handle.scheduler?.stop?.();
            if (typeof raw.shutdown === 'function') {
              await raw.shutdown();
            } else if (typeof raw.close === 'function') {
              await raw.close();
            } else if (typeof kernel?.shutdown === 'function') {
              await kernel.shutdown();
            }
          } finally {
            if (ownsDataDir && !keepDataDir && tempHolder) {
              await tempHolder.cleanup();
            }
          }
        })();
      }
      return shutdownPromise;
    },
  };

  handle.close = handle.shutdown;
  return handle;
}
