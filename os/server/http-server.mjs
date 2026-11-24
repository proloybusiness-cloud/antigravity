/**
 * OmniOS HTTP REST API v1, Health Endpoints, Static `ui/` Server & `/ws` Host (`F-062`)
 * - Pure Node.js 24 ESM (`node:http`, `node:fs`, `node:path`, `node:url`)
 * - Serves ALL Contract 7 REST endpoints, static `ui/` with strict root-containment &
 *   symlink traversal defense, and RFC 6455 WebSocket upgrades at `/ws`
 * - Clean socket tracking & shutdown so `stop()` never hangs on HTTP keep-alive sockets
 */

import http from 'node:http';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createOmniOS } from '../os.mjs';
import { createWebSocketServer } from './websocket.mjs';
import { createSpotlightSearch } from './search.mjs';
import {
  OmniOSError,
  FormatError,
  QuotaExceededError,
  ERROR_CODES,
} from '../common/errors.mjs';
import {
  ALL_CAPABILITIES,
  DEFAULT_CAPABILITY_POLICIES,
} from '../security/permissions.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_UI_DIR = path.join(REPO_ROOT, 'ui');

const DEFAULT_MAX_JSON_BYTES = 1024 * 1024; // 1 MiB
const DEFAULT_MAX_BINARY_BYTES = 32 * 1024 * 1024; // 32 MiB
const MAX_DEV_READ_BYTES = 1024 * 1024; // 1 MiB
const MAX_STEP_TICKS = 50;

const MIME_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.wasm': 'application/wasm',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
});

class HttpRouteError extends Error {
  constructor(status, code, message, details = null, headers = null) {
    super(message);
    this.name = 'HttpRouteError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.headers = headers;
  }
}

function isExistingOmniOSInstance(val) {
  return Boolean(
    val &&
      typeof val === 'object' &&
      val.kernel &&
      val.processManager &&
      val.vfs &&
      val.compositor
  );
}

function formatHostForUrl(host) {
  if (!host || host === '0.0.0.0' || host === '::') return '127.0.0.1';
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

function parseBoolParam(val, fallback = false) {
  if (val === undefined || val === null || val === '') return fallback;
  if (typeof val === 'boolean') return val;
  const s = String(val).trim().toLowerCase();
  if (s === '1' || s === 'true' || s === 'yes' || s === 'on') return true;
  if (s === '0' || s === 'false' || s === 'no' || s === 'off') return false;
  return fallback;
}

function parseOptionalInt(val, fallback = undefined, { min = -Infinity, max = Infinity } = {}) {
  if (val === undefined || val === null || val === '') return fallback;
  const num = Number(val);
  if (!Number.isInteger(num)) return fallback;
  return Math.max(min, Math.min(max, num));
}

function parseStrictPid(raw) {
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) {
    throw new HttpRouteError(400, ERROR_CODES.EINVAL, `Invalid PID: ${raw}`);
  }
  const pid = Number(raw);
  if (!Number.isSafeInteger(pid) || pid < 0) {
    throw new HttpRouteError(400, ERROR_CODES.EINVAL, `Invalid PID: ${raw}`);
  }
  return pid;
}

function parseStrictNonNegInt(raw, label = 'integer') {
  if (typeof raw === 'number') {
    if (!Number.isSafeInteger(raw) || raw < 0) {
      throw new HttpRouteError(400, ERROR_CODES.EINVAL, `Invalid ${label}: ${raw}`);
    }
    return raw;
  }
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!/^\d+$/.test(trimmed)) {
      throw new HttpRouteError(400, ERROR_CODES.EINVAL, `Invalid ${label}: ${raw}`);
    }
    const num = Number(trimmed);
    if (!Number.isSafeInteger(num) || num < 0) {
      throw new HttpRouteError(400, ERROR_CODES.EINVAL, `Invalid ${label}: ${raw}`);
    }
    return num;
  }
  throw new HttpRouteError(400, ERROR_CODES.EINVAL, `Invalid ${label}: ${String(raw)}`);
}

function parseRegistryUidCtx(rawUid, isQueryString = false) {
  if (rawUid === null) {
    return { uid: null };
  }
  if (isQueryString && typeof rawUid === 'string' && rawUid.trim().toLowerCase() === 'null') {
    return { uid: null };
  }
  return { uid: parseStrictNonNegInt(rawUid, 'uid') };
}

const DANGEROUS_CONFIG_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function assertSafeConfigKey(key) {
  if (typeof key !== 'string' || DANGEROUS_CONFIG_KEYS.has(key)) {
    throw new HttpRouteError(
      400,
      ERROR_CODES.EINVAL,
      `Dangerous config key rejected: ${String(key)}`
    );
  }
}

function assertNoDangerousOwnKeys(obj) {
  if (!obj || typeof obj !== 'object') return;
  for (const key of Object.getOwnPropertyNames(obj)) {
    if (DANGEROUS_CONFIG_KEYS.has(key)) {
      throw new HttpRouteError(
        400,
        ERROR_CODES.EINVAL,
        `Dangerous config key rejected: ${key}`
      );
    }
  }
}

function safeDecodeParam(raw, label = 'parameter') {
  try {
    const decoded = decodeURIComponent(raw);
    if (decoded.includes('\0')) {
      throw new HttpRouteError(400, ERROR_CODES.EINVAL, `NUL byte forbidden in ${label}`);
    }
    return decoded;
  } catch (err) {
    if (err instanceof HttpRouteError) throw err;
    throw new HttpRouteError(400, ERROR_CODES.EINVAL, `Malformed URL encoding in ${label}`);
  }
}

function toJsonSafe(value, seen = new Set(), depth = 0) {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === 'string' || t === 'boolean') return value;
  if (t === 'number') return Number.isFinite(value) ? value : null;
  if (t === 'bigint') return value.toString(10);
  if (t === 'function' || t === 'symbol') return undefined;
  if (depth >= 32) return '[MaxDepth]';

  if (Buffer.isBuffer(value)) {
    return value.toString('base64');
  }
  if (ArrayBuffer.isView(value)) {
    const view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString('base64');
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(value).toString('base64');
  }
  if (value instanceof Date) {
    const ms = value.getTime();
    return Number.isFinite(ms) ? value.toISOString() : null;
  }
  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      ...(typeof value.code === 'string' ? { code: value.code } : {}),
    };
  }

  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const out = new Array(value.length);
      for (let i = 0; i < value.length; i += 1) {
        let item;
        try {
          item = value[i];
        } catch (err) {
          item = `[Unreadable: ${err?.message ?? 'error'}]`;
        }
        const safeItem = toJsonSafe(item, seen, depth + 1);
        out[i] = safeItem === undefined ? null : safeItem;
      }
      return out;
    }

    if (value instanceof Set) {
      const out = [];
      for (const item of value) {
        const safeItem = toJsonSafe(item, seen, depth + 1);
        out.push(safeItem === undefined ? null : safeItem);
      }
      return out;
    }

    if (value instanceof Map) {
      const out = {};
      for (const [k, v] of value.entries()) {
        const safeVal = toJsonSafe(v, seen, depth + 1);
        if (safeVal !== undefined) {
          Object.defineProperty(out, String(k), {
            value: safeVal,
            enumerable: true,
            configurable: true,
            writable: true,
          });
        }
      }
      return out;
    }

    const out = {};
    let keys;
    try {
      keys = Object.keys(value);
    } catch (err) {
      return `[Unreadable: ${err?.message ?? 'error'}]`;
    }
    for (let i = 0; i < keys.length; i += 1) {
      const key = keys[i];
      let prop;
      try {
        prop = value[key];
      } catch (err) {
        prop = `[Unreadable: ${err?.message ?? 'error'}]`;
      }
      const safeVal = toJsonSafe(prop, seen, depth + 1);
      if (safeVal !== undefined) {
        Object.defineProperty(out, key, {
          value: safeVal,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

function mapErrorToHttp(err) {
  if (err instanceof HttpRouteError) {
    return {
      status: err.status,
      code: err.code,
      name: err.name,
      message: err.message,
      details: err.details ?? undefined,
      headers: err.headers ?? null,
    };
  }

  const code = typeof err?.code === 'string' ? err.code : ERROR_CODES.E_OMNIOS;
  const name = typeof err?.name === 'string' ? err.name : 'Error';
  const message = typeof err?.message === 'string' ? err.message : String(err);
  const details = err?.details ?? undefined;

  if (code === 'ENOENT' || code === 'ESRCH' || code === 'E_SERVICE_NOT_FOUND') {
    return { status: 404, code, name, message, details, headers: null };
  }
  if (
    code === 'EACCES' ||
    code === 'EPERM' ||
    code === 'E_PERMISSION_DENIED' ||
    code === 'E_SANDBOX_VIOLATION' ||
    code === 'E_PATH_TRAVERSAL' ||
    code === 'ENOTCAPABLE'
  ) {
    return { status: 403, code, name, message, details, headers: null };
  }
  if (code === 'EEXIST' || code === 'E_SERVICE_EXISTS' || code === 'EBUSY' || code === 'EPIPE') {
    return { status: 409, code, name, message, details, headers: null };
  }
  if (code === 'E_PAYLOAD_TOO_LARGE' || code === 'EFBIG' || code === 'ENOSPC' || code === 'ENOMEM') {
    return { status: 413, code, name, message, details, headers: null };
  }
  if (
    code === 'EMFILE' ||
    code === 'ENFILE' ||
    code === 'E_FD_QUOTA' ||
    code === 'E_CPU_QUOTA' ||
    code === 'E_WINDOW_QUOTA'
  ) {
    return { status: 429, code, name, message, details, headers: null };
  }
  if (err instanceof QuotaExceededError || code === 'EQUOTA' || code === 'E_MEMORY_QUOTA') {
    return { status: 413, code, name, message, details, headers: null };
  }
  if (
    code === 'E_KERNEL_PANIC' ||
    code === 'E_KERNEL_NOT_RUNNING' ||
    code === 'E_STORAGE_CLOSED'
  ) {
    return { status: 503, code, name, message, details, headers: null };
  }
  if (
    code === 'ENOSYS' ||
    code === 'ENOTSUP' ||
    code === 'EOPNOTSUPP' ||
    code === 'E_UNIMPLEMENTED_API'
  ) {
    return { status: 501, code, name, message, details, headers: null };
  }
  if (
    err instanceof FormatError ||
    code === 'EINVAL' ||
    code === 'EISDIR' ||
    code === 'ENOTDIR' ||
    code === 'ENOTEMPTY' ||
    code === 'ELOOP' ||
    code === 'ENAMETOOLONG' ||
    code === 'ERANGE' ||
    code === 'EBADF' ||
    code === 'E_ARCHIVE_BOMB' ||
    code === 'E_ENCRYPTED_BINARY' ||
    code === 'E_UNKNOWN_FORMAT' ||
    code === 'E_BAD_CRC32' ||
    code === 'E_CYCLIC_PLIST' ||
    code === 'E_EOF' ||
    code === 'E_BUFFER_OVERFLOW' ||
    code === 'E_SERVICE_CYCLE' ||
    code === 'E_SERVICE_MISSING_DEP' ||
    code === 'E_SERVICE_INVALID' ||
    code === 'E_INVALID_TRANSITION' ||
    code.startsWith('E_MALFORMED_') ||
    code.startsWith('E_INVALID_')
  ) {
    return { status: 400, code, name, message, details, headers: null };
  }

  return {
    status: err instanceof OmniOSError ? 500 : 500,
    code,
    name,
    message,
    details,
    headers: null,
  };
}

function readRawBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const contentLengthHdr = req.headers['content-length'];
    if (contentLengthHdr !== undefined) {
      const declared = Number(contentLengthHdr);
      if (Number.isFinite(declared) && declared > maxBytes) {
        req.resume();
        reject(
          new HttpRouteError(
            413,
            'E_PAYLOAD_TOO_LARGE',
            `Request body exceeds maximum allowed size (${maxBytes} bytes)`
          )
        );
        return;
      }
    }

    const chunks = [];
    let total = 0;
    let settled = false;

    const cleanup = () => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('aborted', onAborted);
    };

    const onData = (chunk) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.byteLength;
      if (total > maxBytes) {
        settled = true;
        cleanup();
        req.resume();
        reject(
          new HttpRouteError(
            413,
            'E_PAYLOAD_TOO_LARGE',
            `Request body exceeds maximum allowed size (${maxBytes} bytes)`
          )
        );
        return;
      }
      chunks.push(buf);
    };

    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(chunks.length === 0 ? Buffer.alloc(0) : Buffer.concat(chunks, total));
    };

    const onError = (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };

    const onAborted = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new HttpRouteError(400, ERROR_CODES.EINVAL, 'Client aborted request body'));
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('aborted', onAborted);
  });
}

async function readJsonBody(req, maxBytes, { allowEmpty = true } = {}) {
  const raw = await readRawBody(req, maxBytes);
  if (raw.byteLength === 0) {
    if (allowEmpty) return {};
    throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Expected non-empty JSON request body');
  }
  let parsed;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch (err) {
    throw new HttpRouteError(
      400,
      ERROR_CODES.EINVAL,
      `Malformed JSON request body: ${err?.message ?? 'parse error'}`
    );
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'JSON request body must be a JSON object');
  }
  return parsed;
}

function extractVfsCtx(query, body = null) {
  const src = body && typeof body === 'object' ? body : {};
  const ctx = {};
  const platform = src.platform ?? query.get('platform');
  const cwd = src.cwd ?? query.get('cwd');
  const appId = src.appId ?? query.get('appId');
  const containerUuid = src.containerUuid ?? query.get('containerUuid');
  const rawUid = src.uid ?? query.get('uid');
  const rawGid = src.gid ?? query.get('gid');

  if (typeof platform === 'string' && platform.length > 0) ctx.platform = platform;
  if (typeof cwd === 'string' && cwd.length > 0) ctx.cwd = cwd;
  if (typeof appId === 'string' && appId.length > 0) ctx.appId = appId;
  if (typeof containerUuid === 'string' && containerUuid.length > 0) {
    ctx.containerUuid = containerUuid;
  }
  if (rawUid !== undefined && rawUid !== null && rawUid !== '') {
    ctx.uid = parseStrictNonNegInt(rawUid, 'uid');
  }
  if (rawGid !== undefined && rawGid !== null && rawGid !== '') {
    ctx.gid = parseStrictNonNegInt(rawGid, 'gid');
  }
  return ctx;
}

function buildFallbackStatusHtml(os) {
  const state = os?.kernel?.state ?? 'UNKNOWN';
  const version = os?.version ?? '1.0.0';
  const uptimeMs = os?.kernel?.getUptimeMs?.() ?? 0;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OmniOS ${version}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f141c; color: #e6edf3; margin: 0; padding: 2rem; }
    main { max-width: 720px; margin: 0 auto; background: #161d28; border: 1px solid #2a3444; border-radius: 12px; padding: 1.5rem 2rem; }
    h1 { margin-top: 0; font-size: 1.5rem; }
    code { background: #0b1017; padding: 0.15rem 0.4rem; border-radius: 4px; }
  </style>
</head>
<body>
  <main>
    <h1>OmniOS v${version}</h1>
    <p>Kernel State: <strong>${state}</strong> &middot; Uptime: ${uptimeMs} ms</p>
    <p>REST API: <code>/api/v1/health</code> &middot; WebSocket Bus: <code>/ws</code></p>
  </main>
</body>
</html>
`;
}

function hasRawTraversalAttempt(rawPathname) {
  if (rawPathname.includes('\0') || rawPathname.includes('\\')) return true;
  if (/(?:^|\/)\.\.(?:\/|$)/.test(rawPathname)) return true;
  const lower = rawPathname.toLowerCase();
  if (lower.includes('%2e%2e') || lower.includes('%5c') || lower.includes('%00')) return true;
  return false;
}

function methodNotAllowed(allowedMethods) {
  return new HttpRouteError(
    405,
    'E_METHOD_NOT_ALLOWED',
    `Method not allowed. Allowed: ${allowedMethods.join(', ')}`,
    { allowed: allowedMethods },
    { Allow: allowedMethods.join(', ') }
  );
}

export class OmniHttpServer {
  constructor(osOrOptions = {}, serverOptions = {}) {
    const existing = isExistingOmniOSInstance(osOrOptions);
    const mergedOpts = existing ? { ...(serverOptions ?? {}) } : { ...(osOrOptions ?? {}), ...(serverOptions ?? {}) };

    this._ownsOs = !existing;
    if (existing) {
      this.os = osOrOptions;
    } else {
      const osConfig = { ...(osOrOptions ?? {}) };
      if (osConfig.autoStartScheduler === undefined) {
        osConfig.autoStartScheduler = true;
      }
      this.os = createOmniOS(osConfig);
    }

    this._port =
      mergedOpts.port !== undefined && mergedOpts.port !== null
        ? Number(mergedOpts.port)
        : Number(process.env.PORT ?? 3777);
    this._host =
      typeof mergedOpts.host === 'string' && mergedOpts.host.length > 0
        ? mergedOpts.host
        : (process.env.HOST ?? '127.0.0.1');
    this._uiDir =
      typeof mergedOpts.uiDir === 'string' && mergedOpts.uiDir.length > 0
        ? path.resolve(mergedOpts.uiDir)
        : DEFAULT_UI_DIR;
    this._maxJsonBodyBytes =
      Number.isInteger(mergedOpts.maxJsonBodyBytes) && mergedOpts.maxJsonBodyBytes > 0
        ? mergedOpts.maxJsonBodyBytes
        : DEFAULT_MAX_JSON_BYTES;
    this._maxBinaryBodyBytes =
      Number.isInteger(mergedOpts.maxBinaryBodyBytes) && mergedOpts.maxBinaryBodyBytes > 0
        ? mergedOpts.maxBinaryBodyBytes
        : DEFAULT_MAX_BINARY_BYTES;

    this._ownsSearch = !this.os.search;
    this.search = this.os.search ?? createSpotlightSearch(this.os);
    this.wsServer = createWebSocketServer(this.os, mergedOpts.wsOptions ?? {});

    this._httpServer = null;
    this._sockets = new Set();
    this._address = null;
    this._started = false;
  }

  getAddress() {
    return this._address ? { ...this._address } : null;
  }

  async start({ port, host } = {}) {
    if (this._started && this._address) {
      return this.getAddress();
    }

    if (
      this._ownsOs &&
      this.os.kernel &&
      (this.os.kernel.state === 'UNINITIALIZED' || this.os.kernel.state === 'STOPPED')
    ) {
      await this.os.boot();
    }

    const listenPort = port !== undefined && port !== null ? Number(port) : this._port;
    const listenHost = typeof host === 'string' && host.length > 0 ? host : this._host;

    const server = http.createServer((req, res) => {
      this._handleRequest(req, res).catch((err) => {
        this._sendError(res, err);
      });
    });

    server.on('connection', (socket) => {
      this._sockets.add(socket);
      socket.on('close', () => {
        this._sockets.delete(socket);
      });
    });

    this.wsServer.attach(server);

    await new Promise((resolve, reject) => {
      const onError = (err) => {
        server.off('listening', onListening);
        reject(err);
      };
      const onListening = () => {
        server.off('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(listenPort, listenHost);
    });

    this._httpServer = server;
    const bound = server.address();
    const resolvedPort = typeof bound === 'object' && bound ? bound.port : listenPort;
    const resolvedHost = typeof bound === 'object' && bound && bound.address ? bound.address : listenHost;
    const urlHost = formatHostForUrl(resolvedHost);

    this._address = {
      port: resolvedPort,
      host: resolvedHost,
      url: `http://${urlHost}:${resolvedPort}`,
      wsUrl: `ws://${urlHost}:${resolvedPort}${this.wsServer.path}`,
    };
    this._started = true;
    return this.getAddress();
  }

  async stop() {
    if (!this._started && !this._httpServer) {
      if (this._ownsSearch) {
        this.search.dispose();
      }
      await this.wsServer.closeAll(1001, 'Server stopping');
      if (this._ownsOs && this.os?.kernel && this.os.kernel.state !== 'STOPPED') {
        await this.os.shutdown();
      }
      return;
    }

    this._started = false;
    await this.wsServer.closeAll(1001, 'Server stopping');

    if (this._ownsSearch) {
      this.search.dispose();
    }

    const server = this._httpServer;
    this._httpServer = null;
    this._address = null;

    if (server) {
      server.closeIdleConnections?.();
      for (const socket of Array.from(this._sockets)) {
        try {
          socket.destroy();
        } catch (err) {
          void err;
        }
      }
      this._sockets.clear();

      await new Promise((resolve) => {
        try {
          server.close(() => resolve());
        } catch (err) {
          void err;
          resolve();
        }
      });
    }

    if (this._ownsOs && this.os && typeof this.os.shutdown === 'function') {
      await this.os.shutdown();
    }
  }

  _sendJson(res, status, data, extraHeaders = null, headOnly = false) {
    if (res.writableEnded || res.destroyed) return;
    const bodyStr = JSON.stringify(toJsonSafe(data));
    const bodyBuf = Buffer.from(bodyStr, 'utf8');
    const headers = {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': bodyBuf.byteLength,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...(extraHeaders ?? {}),
    };
    res.writeHead(status, headers);
    if (headOnly) {
      res.end();
    } else {
      res.end(bodyBuf);
    }
  }

  _sendError(res, err) {
    const mapped = mapErrorToHttp(err);
    this._sendJson(
      res,
      mapped.status,
      {
        ok: false,
        code: mapped.code,
        error: {
          code: mapped.code,
          name: mapped.name,
          message: mapped.message,
          ...(mapped.details !== undefined ? { details: mapped.details } : {}),
        },
      },
      mapped.headers
    );
  }

  _pumpScheduler(ticks) {
    const clamped = Math.max(0, Math.min(MAX_STEP_TICKS, ticks));
    if (clamped <= 0) return;
    const scheduler = this.os?.scheduler;
    if (!scheduler || typeof scheduler.step !== 'function') return;
    try {
      scheduler.step(clamped);
    } catch (err) {
      // Scheduler step is best-effort if kernel is in panic/stopped state.
      void err;
    }
  }

  async _handleRequest(req, res) {
    const method = (req.method ?? 'GET').toUpperCase();
    const rawUrl = req.url ?? '/';
    const qIdx = rawUrl.indexOf('?');
    const rawPathPart = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);

    let parsedUrl;
    try {
      parsedUrl = new URL(rawUrl, 'http://omnios.local');
    } catch (err) {
      throw new HttpRouteError(400, ERROR_CODES.EINVAL, `Malformed request URL: ${err?.message ?? 'invalid'}`);
    }

    const pathname = parsedUrl.pathname;
    const query = parsedUrl.searchParams;

    if (pathname === this.wsServer.path) {
      const upgradeHeader = String(req.headers.upgrade ?? '').trim();
      const connectionHeader = String(req.headers.connection ?? '');
      const hasUpgradeToken = connectionHeader
        .split(',')
        .some((token) => token.trim().toLowerCase() === 'upgrade');
      if (upgradeHeader.length > 0 && !hasUpgradeToken) {
        this._sendJson(
          res,
          400,
          {
            ok: false,
            code: ERROR_CODES.EINVAL,
            error: {
              code: ERROR_CODES.EINVAL,
              message: 'Bad WebSocket upgrade request: missing Connection: upgrade header',
            },
          },
          null,
          method === 'HEAD'
        );
        return;
      }
      this._sendJson(
        res,
        426,
        {
          ok: false,
          code: ERROR_CODES.EINVAL,
          error: {
            code: ERROR_CODES.EINVAL,
            message: `WebSocket upgrade required on ${this.wsServer.path}`,
          },
        },
        {
          Upgrade: 'websocket',
          Connection: 'Upgrade',
        },
        method === 'HEAD'
      );
      return;
    }

    if (pathname === '/api/health' || pathname === '/api/v1/health' || pathname.startsWith('/api/')) {
      await this._handleApiRequest(req, res, method, pathname, query);
      return;
    }

    await this._handleStaticRequest(req, res, method, rawPathPart);
  }

  async _parsePackageUpload(req, query) {
    const contentType = String(req.headers['content-type'] ?? '').toLowerCase();
    const isBinary =
      contentType.includes('application/octet-stream') ||
      contentType.includes('application/zip') ||
      contentType.includes('application/wasm') ||
      contentType.includes('application/vnd.') ||
      contentType.startsWith('binary/');

    if (isBinary) {
      const bytes = await readRawBody(req, this._maxBinaryBodyBytes);
      if (bytes.byteLength === 0) {
        throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Binary package upload body is empty');
      }
      const headerFilename =
        typeof req.headers['x-filename'] === 'string' ? req.headers['x-filename'].trim() : '';
      const queryFilename =
        query.get('filenameHint') ?? query.get('filename') ?? '';
      const filenameHint = headerFilename || queryFilename || '';
      return {
        input: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
        filenameHint,
        opts: {
          filenameHint,
          grantAll: parseBoolParam(query.get('grantAll'), false),
          overwrite: parseBoolParam(query.get('overwrite'), false),
          upgrade: parseBoolParam(query.get('upgrade'), false),
          expectedSha256: query.get('expectedSha256') ?? query.get('sha256') ?? undefined,
          source: query.get('source') ?? 'upload',
        },
      };
    }

    const body = await readJsonBody(req, this._maxBinaryBodyBytes, { allowEmpty: false });
    const filenameHint = String(
      body.filenameHint ??
        body.filename ??
        query.get('filenameHint') ??
        query.get('filename') ??
        ''
    );

    let input;
    if (typeof body.base64 === 'string' && body.base64.length > 0) {
      const buf = Buffer.from(body.base64, 'base64');
      input = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } else if (typeof body.path === 'string' && body.path.length > 0) {
      input = body.path;
    } else {
      throw new HttpRouteError(
        400,
        ERROR_CODES.EINVAL,
        'Package request requires either "path" (VFS path) or "base64" payload, or application/octet-stream binary body'
      );
    }

    return {
      input,
      filenameHint,
      opts: {
        filenameHint,
        grantAll: body.grantAll !== undefined ? Boolean(body.grantAll) : parseBoolParam(query.get('grantAll'), false),
        grants: body.grants ?? undefined,
        overwrite: body.overwrite !== undefined ? Boolean(body.overwrite) : parseBoolParam(query.get('overwrite'), false),
        upgrade: body.upgrade !== undefined ? Boolean(body.upgrade) : parseBoolParam(query.get('upgrade'), false),
        expectedSha256: body.expectedSha256 ?? body.sha256 ?? undefined,
        source: body.source ?? 'api',
      },
    };
  }

  async _handleApiRequest(req, res, method, pathname, query) {
    const os = this.os;

    // ---- Health ----
    if (pathname === '/api/health') {
      if (method !== 'GET' && method !== 'HEAD') throw methodNotAllowed(['GET', 'HEAD']);
      this._sendJson(
        res,
        200,
        {
          ok: true,
          os: 'OmniOS',
          status: os.kernel.state,
          uptimeMs: os.kernel.getUptimeMs(),
          version: os.version ?? '1.0.0',
          liteMode: Boolean(os.kernel?.options?.liteMode),
        },
        null,
        method === 'HEAD'
      );
      return;
    }

    if (pathname === '/api/v1/health') {
      if (method !== 'GET' && method !== 'HEAD') throw methodNotAllowed(['GET', 'HEAD']);
      this._sendJson(
        res,
        200,
        {
          ok: true,
          os: 'OmniOS',
          status: os.kernel.state,
          uptimeMs: os.kernel.getUptimeMs(),
          version: os.version ?? '1.0.0',
          liteMode: Boolean(os.kernel?.options?.liteMode),
          services: os.serviceManager.getStatus(),
        },
        null,
        method === 'HEAD'
      );
      return;
    }

    // ---- Kernel ----
    if (pathname === '/api/v1/kernel/status') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const status =
        typeof os.getStatus === 'function'
          ? os.getStatus()
          : {
              ok: true,
              os: 'OmniOS',
              version: os.version ?? '1.0.0',
              status: os.kernel.state,
              ...os.kernel.getDiagnostics(),
            };
      this._sendJson(res, 200, { ok: true, ...status });
      return;
    }

    if (pathname === '/api/v1/kernel/dmesg') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const limit = parseOptionalInt(query.get('limit'), 200, { min: 0, max: 5000 });
      const sinceSeq = parseOptionalInt(query.get('sinceSeq'), undefined, { min: 0 });
      const subsystem = query.get('subsystem') || undefined;
      const level = query.get('level') || undefined;
      const entries = os.kernel.dmesg({ limit, subsystem, level, sinceSeq });
      this._sendJson(res, 200, { ok: true, count: entries.length, entries });
      return;
    }

    if (pathname === '/api/v1/kernel/services') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const services = os.serviceManager.getStatus();
      this._sendJson(res, 200, { ok: true, services });
      return;
    }

    const svcMatch = /^\/api\/v1\/kernel\/services\/([^/]+)\/([^/]+)$/.exec(pathname);
    if (svcMatch) {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      await readJsonBody(req, this._maxJsonBodyBytes, { allowEmpty: true });
      const name = safeDecodeParam(svcMatch[1], 'service name');
      const action = safeDecodeParam(svcMatch[2], 'service action').toLowerCase();
      let result;
      if (action === 'start') {
        result = await os.serviceManager.start(name);
      } else if (action === 'stop') {
        result = await os.serviceManager.stop(name);
      } else if (action === 'restart') {
        result = await os.serviceManager.restart(name);
      } else if (action === 'health') {
        result = await os.serviceManager.checkHealth(name);
      } else {
        throw new HttpRouteError(
          400,
          ERROR_CODES.EINVAL,
          `Invalid service action "${action}". Expected start, stop, restart, or health.`
        );
      }
      this._sendJson(res, 200, {
        ok: true,
        name,
        action,
        result,
        service: os.serviceManager.getStatus(name),
      });
      return;
    }

    if (pathname === '/api/v1/kernel/panic') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      const code = body.code ?? ERROR_CODES.E_KERNEL_PANIC;
      const reason = body.reason ?? 'Manual kernel panic triggered via API';
      const context = body.context ?? {};
      const panic = os.kernel.panic(code, reason, context);
      this._sendJson(res, 200, { ok: true, panic });
      return;
    }

    if (pathname === '/api/v1/kernel/recover') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      const safeMode = Boolean(body.safeMode);
      const bootReport =
        typeof os.recover === 'function'
          ? await os.recover({ safeMode })
          : await os.kernel.recover({ safeMode });
      this._sendJson(res, 200, { ok: true, bootReport });
      return;
    }

    // ---- Processes ----
    if (pathname === '/api/v1/processes') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const includeTerminated = parseBoolParam(query.get('includeTerminated'), false);
      const state = query.get('state') || undefined;
      const platform = query.get('platform') || undefined;
      const appId = query.get('appId') || undefined;
      const processes = os.processManager.list({ includeTerminated, state, platform, appId });
      this._sendJson(res, 200, { ok: true, count: processes.length, processes });
      return;
    }

    if (pathname === '/api/v1/processes/tree') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const includeTerminated = parseBoolParam(query.get('includeTerminated'), false);
      const tree = os.processManager.getTree({ includeTerminated });
      this._sendJson(res, 200, { ok: true, tree });
      return;
    }

    const procActionMatch = /^\/api\/v1\/processes\/([^/]+)\/(signal|stdin)$/.exec(pathname);
    if (procActionMatch) {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const pid = parseStrictPid(procActionMatch[1]);
      const action = procActionMatch[2];
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      if (action === 'signal') {
        const signal = body.signal ?? 'SIGTERM';
        const result = os.processManager.kill(pid, signal);
        this._sendJson(res, 200, { ok: true, ...result });
        return;
      }
      const data = body.data ?? '';
      if (typeof data !== 'string') {
        throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'stdin "data" must be a string');
      }
      const bytesWritten = os.processManager.writeStdin(pid, data);
      this._pumpScheduler(2);
      this._sendJson(res, 200, { ok: true, pid, bytesWritten });
      return;
    }

    const procDetailMatch = /^\/api\/v1\/processes\/([^/]+)$/.exec(pathname);
    if (procDetailMatch) {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const pid = parseStrictPid(procDetailMatch[1]);
      const pcb = os.processManager.get(pid);
      if (!pcb) {
        throw new HttpRouteError(404, ERROR_CODES.ESRCH, `Process not found: PID ${pid}`);
      }
      let debugState = null;
      if (pcb.executionContext && typeof pcb.executionContext.getDebugState === 'function') {
        try {
          debugState = pcb.executionContext.getDebugState();
        } catch (err) {
          debugState = { error: err?.message ?? 'Unable to read debug state' };
        }
      }
      const summary = os.processManager.toSummary(pcb);
      const detail = {
        ...summary,
        stdout: os.processManager.readStdout(pid, { consume: false }),
        stderr: os.processManager.readStderr(pid, { consume: false }),
        threads: os.processManager.listThreads(pid),
        fds: os.processManager.listFds(pid),
        windowIds: Array.from(pcb.windowIds ?? []),
        debugState,
      };
      this._sendJson(res, 200, { ok: true, process: detail });
      return;
    }

    // ---- VFS ----
    if (pathname === '/api/v1/vfs/ls') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const targetPath = query.get('path') ?? '/home/user';
      const ctx = extractVfsCtx(query);
      const namesOnly = parseBoolParam(query.get('namesOnly'), false);
      const withFileTypes = parseBoolParam(query.get('withFileTypes'), true);
      const entries = os.vfs.readdir(targetPath, { ...ctx, namesOnly, withFileTypes });
      const resolved = os.vfs.resolvePath(targetPath, ctx);
      this._sendJson(res, 200, { ok: true, path: targetPath, resolved, entries });
      return;
    }

    if (pathname === '/api/v1/vfs/stat') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const targetPath = query.get('path');
      if (!targetPath) throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required query param: path');
      const ctx = extractVfsCtx(query);
      const useLstat = parseBoolParam(query.get('lstat'), false);
      const stat = useLstat ? os.vfs.lstat(targetPath, ctx) : os.vfs.stat(targetPath, ctx);
      const resolved = os.vfs.resolvePath(targetPath, ctx);
      this._sendJson(res, 200, { ok: true, path: targetPath, resolved, stat });
      return;
    }

    if (pathname === '/api/v1/vfs/file') {
      if (method === 'GET') {
        const targetPath = query.get('path');
        if (!targetPath) throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required query param: path');
        const ctx = extractVfsCtx(query);
        const encoding = (query.get('encoding') ?? 'utf8').toLowerCase();
        const length = parseOptionalInt(query.get('length'), undefined, { min: 0, max: MAX_DEV_READ_BYTES });
        const readOpts = { ...ctx, ...(length !== undefined ? { length } : {}) };
        if (encoding === 'base64') {
          const bytes = os.vfs.readFile(targetPath, readOpts);
          const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
          this._sendJson(res, 200, {
            ok: true,
            path: targetPath,
            encoding: 'base64',
            content: buf.toString('base64'),
            size: bytes.byteLength,
          });
          return;
        }
        const content = os.vfs.readFile(targetPath, { ...readOpts, encoding: 'utf8' });
        this._sendJson(res, 200, {
          ok: true,
          path: targetPath,
          encoding: 'utf8',
          content,
          size: Buffer.byteLength(content, 'utf8'),
        });
        return;
      }

      if (method === 'PUT' || method === 'POST') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes);
        const targetPath = body.path ?? query.get('path');
        if (typeof targetPath !== 'string' || targetPath.length === 0) {
          throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required field: path');
        }
        const ctx = extractVfsCtx(query, body);
        const encoding = String(body.encoding ?? 'utf8').toLowerCase();
        const append = Boolean(body.append);
        const mode = body.mode !== undefined ? Number(body.mode) : undefined;
        const rawContent = body.content !== undefined ? body.content : (body.data ?? '');
        let payload;
        if (encoding === 'base64') {
          const buf = Buffer.from(String(rawContent), 'base64');
          payload = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        } else {
          payload = typeof rawContent === 'string' ? rawContent : String(rawContent);
        }
        const result = os.vfs.writeFile(targetPath, payload, {
          ...ctx,
          append,
          ...(mode !== undefined ? { mode } : {}),
        });
        this._sendJson(res, 200, { ok: true, ...result });
        return;
      }

      if (method === 'DELETE') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes, { allowEmpty: true });
        const targetPath = query.get('path') ?? body.path;
        if (typeof targetPath !== 'string' || targetPath.length === 0) {
          throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required parameter: path');
        }
        const ctx = extractVfsCtx(query, body);
        const recursive =
          body.recursive !== undefined
            ? Boolean(body.recursive)
            : parseBoolParam(query.get('recursive'), false);
        const st = os.vfs.lstat(targetPath, ctx);
        const result =
          st.type === 'dir'
            ? os.vfs.rmdir(targetPath, { ...ctx, recursive })
            : os.vfs.unlink(targetPath, ctx);
        this._sendJson(res, 200, { ok: true, removed: targetPath, type: st.type, ...result });
        return;
      }

      throw methodNotAllowed(['GET', 'PUT', 'POST', 'DELETE']);
    }

    if (pathname === '/api/v1/vfs/mkdir') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      if (typeof body.path !== 'string' || body.path.length === 0) {
        throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required field: path');
      }
      const ctx = extractVfsCtx(query, body);
      const mode = body.mode !== undefined ? Number(body.mode) : undefined;
      const result = os.vfs.mkdir(body.path, {
        ...ctx,
        recursive: Boolean(body.recursive),
        ...(mode !== undefined ? { mode } : {}),
      });
      this._sendJson(res, 201, { ok: true, ...result });
      return;
    }

    if (pathname === '/api/v1/vfs/rename') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      const oldPath = body.oldPath ?? body.from;
      const newPath = body.newPath ?? body.to;
      if (typeof oldPath !== 'string' || typeof newPath !== 'string') {
        throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'rename requires oldPath and newPath strings');
      }
      const ctx = extractVfsCtx(query, body);
      const result = os.vfs.rename(oldPath, newPath, ctx);
      this._sendJson(res, 200, { ok: true, ...result });
      return;
    }

    if (pathname === '/api/v1/vfs/symlink') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      const target = body.target;
      const linkPath = body.linkPath ?? body.path;
      if (typeof target !== 'string' || typeof linkPath !== 'string') {
        throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'symlink requires target and linkPath strings');
      }
      const ctx = extractVfsCtx(query, body);
      const result = os.vfs.symlink(target, linkPath, ctx);
      this._sendJson(res, 201, { ok: true, ...result });
      return;
    }

    if (pathname === '/api/v1/vfs/resolve') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const targetPath = query.get('path');
      if (!targetPath) throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required query param: path');
      const ctx = extractVfsCtx(query);
      const resolved = os.vfs.resolvePath(targetPath, ctx);
      const translator = os.pathTranslator ?? os.vfs.pathTranslator;
      const platformPaths = {};
      if (translator && typeof translator.toPlatform === 'function') {
        for (const p of ['posix', 'windows', 'macos', 'android', 'ios']) {
          try {
            platformPaths[p] = translator.toPlatform(resolved.canonicalPath, p, ctx);
          } catch (err) {
            void err;
          }
        }
      }
      const toPlatform = query.get('toPlatform');
      const targetPlatformPath =
        toPlatform && translator?.toPlatform
          ? translator.toPlatform(resolved.canonicalPath, toPlatform, ctx)
          : undefined;
      this._sendJson(res, 200, {
        ok: true,
        ...resolved,
        platformPaths,
        ...(targetPlatformPath !== undefined ? { targetPath: targetPlatformPath } : {}),
      });
      return;
    }

    if (pathname === '/api/v1/vfs/mounts') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      this._sendJson(res, 200, { ok: true, mounts: os.vfs.listMounts() });
      return;
    }

    // ---- Unified Config Store ----
    if (pathname === '/api/v1/config/system') {
      const normalizeSystemKey = (rawKey) => {
        if (typeof rawKey !== 'string') return rawKey;
        const shortAliases = new Set(['theme', 'volume', 'brightness', 'wifi', 'bluetooth', 'dnd', 'locale', 'shellMode']);
        return shortAliases.has(rawKey) ? `system.${rawKey}` : rawKey;
      };
      if (method === 'GET') {
        const rawKey = query.get('key');
        if (rawKey) {
          const key = normalizeSystemKey(rawKey);
          this._sendJson(res, 200, { ok: true, key, value: os.configStore.system.get(key) });
          return;
        }
        const all = os.configStore.system.getAll();
        this._sendJson(res, 200, { ok: true, values: all, system: all });
        return;
      }
      if (method === 'PUT' || method === 'PATCH' || method === 'POST') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes);
        assertNoDangerousOwnKeys(body);
        if (typeof body.key === 'string' && Object.prototype.hasOwnProperty.call(body, 'value')) {
          const key = normalizeSystemKey(body.key);
          assertSafeConfigKey(key);
          os.configStore.system.set(key, body.value);
        } else {
          let map;
          if (Object.prototype.hasOwnProperty.call(body, 'values')) {
            if (!body.values || typeof body.values !== 'object' || Array.isArray(body.values)) {
              throw new HttpRouteError(
                400,
                ERROR_CODES.EINVAL,
                'Field "values" must be a plain key/value object'
              );
            }
            map = body.values;
          } else if (Object.prototype.hasOwnProperty.call(body, 'updates')) {
            if (!body.updates || typeof body.updates !== 'object' || Array.isArray(body.updates)) {
              throw new HttpRouteError(
                400,
                ERROR_CODES.EINVAL,
                'Field "updates" must be a plain key/value object'
              );
            }
            map = body.updates;
          } else {
            map = body;
          }
          assertNoDangerousOwnKeys(map);
          const entries = Object.entries(map);
          if (entries.length === 0) {
            throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Expected { key, value } or key/value object');
          }
          for (const [rawK, v] of entries) {
            const k = normalizeSystemKey(rawK);
            assertSafeConfigKey(k);
            os.configStore.system.set(k, v);
          }
        }
        const all = os.configStore.system.getAll();
        this._sendJson(res, 200, { ok: true, values: all, system: all });
        return;
      }
      throw methodNotAllowed(['GET', 'PUT', 'PATCH', 'POST']);
    }

    if (pathname === '/api/v1/config/registry') {
      if (method === 'GET') {
        const hive = query.get('hive') ?? 'HKCU';
        const keyPath = query.get('keyPath') ?? '';
        const valueName = query.get('valueName');
        const ctx = query.has('uid') ? parseRegistryUidCtx(query.get('uid'), true) : null;
        if (valueName !== null) {
          const entry = os.configStore.registry.getValue(hive, keyPath, valueName, ctx);
          this._sendJson(res, 200, { ok: true, hive, keyPath, valueName, value: entry });
          return;
        }
        const enumerated = os.configStore.registry.enumKey(hive, keyPath, ctx);
        this._sendJson(res, 200, { ok: true, hive, keyPath, ...enumerated });
        return;
      }
      if (method === 'PUT' || method === 'POST') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes);
        const hive = body.hive ?? 'HKCU';
        const keyPath = body.keyPath ?? '';
        const hasBodyUid = Object.prototype.hasOwnProperty.call(body, 'uid') && body.uid !== undefined;
        const ctx = hasBodyUid ? parseRegistryUidCtx(body.uid, false) : null;
        if (body.createKeyOnly || (body.valueName === undefined && body.data === undefined && body.value === undefined)) {
          const created = os.configStore.registry.createKey(hive, keyPath, ctx);
          this._sendJson(res, 200, { ok: true, hive, keyPath, result: created });
          return;
        }
        const valueName = body.valueName ?? '';
        const type = body.type ?? 'REG_SZ';
        let data = body.data !== undefined ? body.data : body.value;
        if (type === 'REG_BINARY' && typeof data === 'string') {
          const buf = Buffer.from(data, 'base64');
          data = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        } else if (type === 'REG_QWORD' && typeof data === 'string' && /^-?\d+$/.test(data.trim())) {
          data = BigInt(data.trim());
        }
        const result = os.configStore.registry.setValue(hive, keyPath, valueName, type, data, ctx);
        this._sendJson(res, 200, { ok: true, hive, keyPath, valueName, type, result });
        return;
      }
      if (method === 'DELETE') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes, { allowEmpty: true });
        const hive = query.get('hive') ?? body.hive ?? 'HKCU';
        const keyPath = query.get('keyPath') ?? body.keyPath ?? '';
        const valueName = query.has('valueName') ? query.get('valueName') : body.valueName;
        let ctx = null;
        if (query.has('uid')) {
          ctx = parseRegistryUidCtx(query.get('uid'), true);
        } else if (Object.prototype.hasOwnProperty.call(body, 'uid') && body.uid !== undefined) {
          ctx = parseRegistryUidCtx(body.uid, false);
        }
        const deleted =
          valueName !== undefined && valueName !== null
            ? os.configStore.registry.deleteValue(hive, keyPath, valueName, ctx)
            : os.configStore.registry.deleteKey(hive, keyPath, ctx);
        this._sendJson(res, 200, { ok: true, hive, keyPath, deleted });
        return;
      }
      throw methodNotAllowed(['GET', 'PUT', 'POST', 'DELETE']);
    }

    if (pathname === '/api/v1/config/defaults') {
      if (method === 'GET') {
        const domain = query.get('domain');
        const key = query.get('key');
        const format = (query.get('format') ?? '').toLowerCase();
        if (!domain) {
          this._sendJson(res, 200, { ok: true, domains: os.configStore.defaults.listDomains() });
          return;
        }
        if (format === 'plist' || format === 'xml') {
          const xml = os.configStore.defaults.exportPlistXml(domain);
          const buf = Buffer.from(xml, 'utf8');
          res.writeHead(200, {
            'Content-Type': 'application/xml; charset=utf-8',
            'Content-Length': buf.byteLength,
            'Cache-Control': 'no-store',
          });
          res.end(buf);
          return;
        }
        if (key !== null && key !== '') {
          const value = os.configStore.defaults.get(domain, key);
          this._sendJson(res, 200, { ok: true, domain, key, value });
          return;
        }
        const values = os.configStore.defaults.readDomain(domain);
        this._sendJson(res, 200, { ok: true, domain, values });
        return;
      }
      if (method === 'PUT' || method === 'POST') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes);
        if (typeof body.domain !== 'string' || typeof body.key !== 'string') {
          throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'defaults write requires domain and key');
        }
        const value = os.configStore.defaults.set(body.domain, body.key, body.value);
        this._sendJson(res, 200, { ok: true, domain: body.domain, key: body.key, value });
        return;
      }
      if (method === 'DELETE') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes, { allowEmpty: true });
        const domain = query.get('domain') ?? body.domain;
        const key = query.get('key') ?? body.key;
        if (typeof domain !== 'string' || typeof key !== 'string') {
          throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'defaults delete requires domain and key');
        }
        const removed = os.configStore.defaults.remove(domain, key);
        this._sendJson(res, 200, { ok: true, domain, key, removed });
        return;
      }
      throw methodNotAllowed(['GET', 'PUT', 'POST', 'DELETE']);
    }

    if (pathname === '/api/v1/config/prefs') {
      if (method === 'GET') {
        const packageName = query.get('packageName') ?? query.get('package');
        if (!packageName) {
          const packages = os.configStore?.sharedPrefs?.listNamespaces?.() ?? [];
          this._sendJson(res, 200, { ok: true, packages });
          return;
        }
        const prefName = query.get('prefName') ?? 'default';
        const key = query.get('key');
        if (key !== null && key !== '') {
          const value = os.configStore.sharedPrefs.get(packageName, prefName, key);
          this._sendJson(res, 200, { ok: true, packageName, prefName, key, value });
          return;
        }
        const values = os.configStore.sharedPrefs.getAll(packageName, prefName);
        this._sendJson(res, 200, { ok: true, packageName, prefName, values });
        return;
      }
      if (method === 'PUT' || method === 'POST') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes);
        const packageName = body.packageName ?? body.package;
        if (typeof packageName !== 'string' || packageName.length === 0) {
          throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required field: packageName');
        }
        const prefName = body.prefName ?? 'default';
        let ops;
        if (Array.isArray(body.ops)) {
          ops = body.ops;
        } else if (typeof body.key === 'string' && body.key.length > 0) {
          ops = [
            {
              op: 'put',
              key: body.key,
              value: body.value,
              ...(body.type ? { type: body.type } : {}),
            },
          ];
        } else {
          throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Expected ops array or { key, value }');
        }
        const editRes = os.configStore.sharedPrefs.edit(packageName, prefName, ops);
        const values = os.configStore.sharedPrefs.getAll(packageName, prefName);
        this._sendJson(res, 200, { ok: true, packageName, prefName, ...editRes, values });
        return;
      }
      if (method === 'DELETE') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes, { allowEmpty: true });
        const packageName = query.get('packageName') ?? query.get('package') ?? body.packageName ?? body.package;
        if (typeof packageName !== 'string' || packageName.length === 0) {
          throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required parameter: packageName');
        }
        const prefName = query.get('prefName') ?? body.prefName ?? 'default';
        const key = query.get('key') ?? body.key;
        const clear = parseBoolParam(query.get('clear'), Boolean(body.clear));
        const ops = clear || !key ? [{ op: 'clear' }] : [{ op: 'remove', key }];
        const editRes = os.configStore.sharedPrefs.edit(packageName, prefName, ops);
        const values = os.configStore.sharedPrefs.getAll(packageName, prefName);
        this._sendJson(res, 200, { ok: true, packageName, prefName, ...editRes, values });
        return;
      }
      throw methodNotAllowed(['GET', 'PUT', 'POST', 'DELETE']);
    }

    // ---- IPC: Intents, Clipboard, Notifications ----
    if (pathname === '/api/v1/ipc/intents/resolve') {
      if (method !== 'GET' && method !== 'POST') throw methodNotAllowed(['GET', 'POST']);
      const src =
        method === 'POST'
          ? await readJsonBody(req, this._maxJsonBodyBytes)
          : {
              action: query.get('action') || undefined,
              uri: query.get('uri') || undefined,
              mimeType: query.get('mimeType') ?? query.get('mime') ?? undefined,
              extension: query.get('extension') ?? query.get('ext') ?? undefined,
              scheme: query.get('scheme') || undefined,
              host: query.get('host') || undefined,
            };
      const candidates = os.intentRouter.resolve({
        action: src.action ?? null,
        uri: src.uri ?? null,
        mimeType: src.mimeType ?? src.mime ?? null,
        extension: src.extension ?? src.ext ?? null,
        scheme: src.scheme ?? null,
        host: src.host ?? null,
      });
      this._sendJson(res, 200, { ok: true, candidates });
      return;
    }

    if (pathname === '/api/v1/ipc/intents/dispatch') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      const result = await os.intentRouter.dispatch({
        action: body.action ?? null,
        uri: body.uri ?? null,
        mimeType: body.mimeType ?? body.mime ?? null,
        extension: body.extension ?? body.ext ?? null,
        scheme: body.scheme ?? null,
        host: body.host ?? null,
        extras: body.extras ?? {},
        sourcePid: body.sourcePid ?? null,
        preferredAppId: body.preferredAppId ?? body.appId ?? null,
      });
      if (result?.status === 'DELIVERED') {
        this._pumpScheduler(5);
      }
      this._sendJson(res, 200, { ok: true, ...result });
      return;
    }

    if (pathname === '/api/v1/ipc/intents/choose') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      const requestId = body.requestId;
      if (typeof requestId !== 'string' || requestId.length === 0) {
        throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required field: requestId');
      }
      if (body.cancel) {
        const cancelled = os.intentRouter.cancelChooser(requestId);
        this._sendJson(res, 200, { ok: true, requestId, cancelled });
        return;
      }
      const chosenAppId = body.appId ?? body.chosenAppId;
      const result = await os.intentRouter.resolveChooser(requestId, chosenAppId, {
        setAsDefault: Boolean(body.setAsDefault),
      });
      this._pumpScheduler(5);
      this._sendJson(res, 200, { ok: true, ...result });
      return;
    }

    if (pathname === '/api/v1/ipc/clipboard') {
      if (method === 'GET') {
        const mime = query.get('mime') || undefined;
        const limit = parseOptionalInt(query.get('limit'), 20, { min: 0, max: 100 });
        const current = mime ? os.clipboard.get(mime) : os.clipboard.get();
        const history = os.clipboard.history(limit);
        this._sendJson(res, 200, { ok: true, current, history });
        return;
      }
      if (method === 'POST' || method === 'PUT') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes);
        const current = os.clipboard.set(body);
        this._sendJson(res, 200, { ok: true, current });
        return;
      }
      if (method === 'DELETE') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes, { allowEmpty: true });
        const clearHistory =
          body.clearHistory !== undefined
            ? Boolean(body.clearHistory)
            : parseBoolParam(query.get('clearHistory'), false);
        const sourceAppId = body.sourceAppId ?? query.get('sourceAppId') ?? undefined;
        const result = os.clipboard.clear({ clearHistory, sourceAppId });
        this._sendJson(res, 200, { ok: true, ...result });
        return;
      }
      throw methodNotAllowed(['GET', 'POST', 'PUT', 'DELETE']);
    }

    if (pathname === '/api/v1/ipc/notifications') {
      if (method === 'GET') {
        const includeDismissed = parseBoolParam(query.get('includeDismissed'), false);
        const unreadOnly = parseBoolParam(query.get('unreadOnly'), false);
        const appId = query.get('appId') || undefined;
        const category = query.get('category') || undefined;
        const priority = query.get('priority') || undefined;
        const notifications = os.notifications.list({
          includeDismissed,
          unreadOnly,
          appId,
          category,
          priority,
        });
        const liveActivities = os.notifications.getLiveActivities();
        this._sendJson(res, 200, { ok: true, notifications, liveActivities });
        return;
      }
      if (method === 'POST') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes);
        const notification = os.notifications.post(body);
        this._sendJson(res, 201, { ok: true, notification });
        return;
      }
      if (method === 'DELETE') {
        const appId = query.get('appId') || undefined;
        const result = os.notifications.clearAll(appId ? { appId } : {});
        this._sendJson(res, 200, { ok: true, ...result });
        return;
      }
      throw methodNotAllowed(['GET', 'POST', 'DELETE']);
    }

    const notifMatch = /^\/api\/v1\/ipc\/notifications\/([^/]+)\/(dismiss|action)$/.exec(pathname);
    if (notifMatch) {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const notifId = safeDecodeParam(notifMatch[1], 'notification id');
      const action = notifMatch[2];
      if (action === 'dismiss') {
        const notification = os.notifications.dismiss(notifId);
        this._sendJson(res, 200, { ok: true, notification });
        return;
      }
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      const actionId = body.actionId ?? body.action;
      if (typeof actionId !== 'string' || actionId.length === 0) {
        throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required field: actionId');
      }
      const result = os.notifications.invokeAction(notifId, actionId, { input: body.input ?? null });
      this._sendJson(res, 200, { ok: true, ...result });
      return;
    }

    // ---- Security ----
    if (pathname === '/api/v1/security/permissions') {
      if (method === 'GET') {
        const appId = query.get('appId') || undefined;
        this._sendJson(res, 200, {
          ok: true,
          capabilities: ALL_CAPABILITIES,
          defaults: DEFAULT_CAPABILITY_POLICIES,
          grants: os.permissions.listGrants(appId),
          pendingPrompts: os.permissions.getPendingPrompts(),
        });
        return;
      }
      if (method === 'PUT' || method === 'POST') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes);
        if (typeof body.promptId === 'string' && body.promptId.length > 0) {
          const decision = body.decision !== undefined ? body.decision : body.granted;
          const result = os.permissions.resolvePrompt(body.promptId, decision);
          if (!result || result.ok === false) {
            if (result?.reason === 'not_found') {
              throw new HttpRouteError(
                404,
                ERROR_CODES.ENOENT,
                `Permission prompt not found: ${body.promptId}`
              );
            }
            throw new HttpRouteError(
              400,
              ERROR_CODES.EINVAL,
              result?.reason
                ? `Failed to resolve permission prompt: ${result.reason}`
                : 'Invalid permission prompt decision'
            );
          }
          this._sendJson(res, 200, { ok: true, ...result });
          return;
        }
        if (typeof body.appId === 'string' && typeof body.capability === 'string' && typeof body.state === 'string') {
          const grant = os.permissions.setGrant(body.appId, body.capability, body.state, {
            source: body.source ?? 'api',
            audit: true,
          });
          this._sendJson(res, 200, { ok: true, grant });
          return;
        }
        throw new HttpRouteError(
          400,
          ERROR_CODES.EINVAL,
          'Expected either { promptId, decision } or { appId, capability, state }'
        );
      }
      throw methodNotAllowed(['GET', 'PUT', 'POST']);
    }

    if (pathname === '/api/v1/security/audit') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const appId = query.get('appId') || undefined;
      const capability = query.get('capability') || undefined;
      const limit = parseOptionalInt(query.get('limit'), 100, { min: 0, max: 1000 });
      const entries = os.permissions.getAuditLog({ appId, capability, limit });
      this._sendJson(res, 200, { ok: true, count: entries.length, entries });
      return;
    }

    if (pathname === '/api/v1/security/users') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      this._sendJson(res, 200, {
        ok: true,
        users: os.users.listUsers(),
        groups: os.users.listGroups(),
      });
      return;
    }

    // ---- Packages ----
    if (pathname === '/api/v1/packages') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const platform = query.get('platform') || undefined;
      const packages = os.pkgManager.list(platform ? { platform } : {});
      const systemApps = os.systemApps?.list ? os.systemApps.list() : [];
      this._sendJson(res, 200, { ok: true, packages, systemApps });
      return;
    }

    if (pathname === '/api/v1/packages/catalog') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const platform = query.get('platform') || undefined;
      const catalog = os.pkgManager.getCatalog(platform ? { platform } : {});
      const systemApps = os.systemApps?.list ? os.systemApps.list() : [];
      this._sendJson(res, 200, { ok: true, catalog, systemApps });
      return;
    }

    if (pathname === '/api/v1/packages/inspect') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const { input, filenameHint } = await this._parsePackageUpload(req, query);
      const inspection = await os.pkgManager.inspect(input, filenameHint);
      this._sendJson(res, 200, { ok: true, inspection });
      return;
    }

    if (pathname === '/api/v1/packages/install') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const { input, opts } = await this._parsePackageUpload(req, query);
      const pkg = await os.pkgManager.install(input, opts);
      this._sendJson(res, 201, { ok: true, package: pkg });
      return;
    }

    const pkgActionMatch = /^\/api\/v1\/packages\/([^/]+)\/(launch|stop)$/.exec(pathname);
    if (pkgActionMatch) {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const appId = safeDecodeParam(pkgActionMatch[1], 'appId');
      const action = pkgActionMatch[2];
      const body = await readJsonBody(req, this._maxJsonBodyBytes, { allowEmpty: true });

      if (action === 'launch') {
        const stepTicks = parseOptionalInt(body.stepTicks, 10, { min: 0, max: MAX_STEP_TICKS });
        let launchRes;
        if (typeof os.launchApp === 'function') {
          const launchOpts = {
            args: body.args,
            env: body.env,
            intent: body.intent,
            stepTicks,
          };
          if (body.preferSystem !== undefined) launchOpts.preferSystem = Boolean(body.preferSystem);
          if (typeof body.platform === 'string' && body.platform.length > 0) launchOpts.platform = body.platform;
          if (typeof body.cwd === 'string' && body.cwd.length > 0) launchOpts.cwd = body.cwd;
          if (typeof body.tab === 'string') launchOpts.tab = body.tab;
          if (typeof body.section === 'string') launchOpts.section = body.section;
          if (typeof body.viewMode === 'string') launchOpts.viewMode = body.viewMode;
          if (typeof body.path === 'string') launchOpts.path = body.path;
          if (body.pid !== undefined && body.pid !== null && body.pid !== '') {
            launchOpts.pid = parseStrictNonNegInt(body.pid, 'pid');
          }
          launchRes = await os.launchApp(appId, launchOpts);
        } else if (os.systemApps?.resolveId?.(appId)) {
          launchRes = await os.systemApps.launch(appId, body);
          this._pumpScheduler(stepTicks);
        } else {
          launchRes = await os.pkgManager.launch(appId, {
            args: body.args,
            env: body.env,
            intent: body.intent,
          });
          this._pumpScheduler(stepTicks);
        }
        // Ensure latest windowIds after bounded scheduler pump
        const freshWindows = os.compositor.listWindows({ pid: launchRes.pid }).map((w) => w.windowId);
        const pcbWindows = Array.from(os.processManager.get(launchRes.pid)?.windowIds ?? []);
        const windowIds = freshWindows.length > 0 ? freshWindows : (pcbWindows.length > 0 ? pcbWindows : (launchRes.windowIds ?? []));
        this._sendJson(res, 200, { ok: true, ...launchRes, windowIds });
        return;
      }

      const hasExplicitPid = body.pid !== undefined && body.pid !== null && body.pid !== '';
      const target = hasExplicitPid ? parseStrictNonNegInt(body.pid, 'pid') : appId;
      const signal = body.signal ?? 'SIGTERM';
      let stopRes;
      if (typeof os.stopApp === 'function') {
        stopRes = os.stopApp(target, { signal });
      } else if (typeof target === 'string' && os.systemApps?.resolveId?.(target)) {
        stopRes = os.systemApps.stop(target, { signal });
      } else {
        stopRes = os.pkgManager.stop(target, { signal });
      }
      this._sendJson(res, 200, { ok: true, ...stopRes });
      return;
    }

    const pkgSingleMatch = /^\/api\/v1\/packages\/([^/]+)$/.exec(pathname);
    if (pkgSingleMatch) {
      const appId = safeDecodeParam(pkgSingleMatch[1], 'appId');
      if (method === 'GET') {
        const rec = os.pkgManager.get(appId) ?? os.systemApps?.get?.(appId) ?? null;
        if (!rec) {
          throw new HttpRouteError(404, ERROR_CODES.ENOENT, `Package not found: ${appId}`);
        }
        this._sendJson(res, 200, { ok: true, package: rec });
        return;
      }
      if (method === 'DELETE') {
        const body = await readJsonBody(req, this._maxJsonBodyBytes, { allowEmpty: true });
        const purgeData =
          body.purgeData !== undefined
            ? Boolean(body.purgeData)
            : parseBoolParam(query.get('purgeData'), false);
        const result = await os.pkgManager.uninstall(appId, { purgeData });
        if (!result || result.removed === false) {
          throw new HttpRouteError(404, ERROR_CODES.ENOENT, `Package not found: ${appId}`);
        }
        this._sendJson(res, 200, { ok: true, ...result });
        return;
      }
      throw methodNotAllowed(['GET', 'DELETE']);
    }

    // ---- Compositor ----
    if (pathname === '/api/v1/compositor/snapshot') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const snapshot = os.compositor.getSnapshot();
      this._sendJson(res, 200, { ok: true, ...snapshot });
      return;
    }

    if (pathname === '/api/v1/compositor/shell-mode') {
      if (method !== 'PUT' && method !== 'POST') throw methodNotAllowed(['PUT', 'POST']);
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      const mode = body.mode ?? body.shellMode;
      const result = os.compositor.setShellMode(mode);
      this._sendJson(res, 200, { ok: true, ...result, snapshot: os.compositor.getSnapshot() });
      return;
    }

    const winActionMatch =
      /^\/api\/v1\/compositor\/windows\/([^/]+)\/(move|resize|focus|state|close|input)$/.exec(pathname);
    if (winActionMatch) {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const windowId = safeDecodeParam(winActionMatch[1], 'windowId');
      const action = winActionMatch[2];
      const body = await readJsonBody(req, this._maxJsonBodyBytes, { allowEmpty: true });

      if (action === 'move') {
        const win = os.compositor.moveWindow(windowId, Number(body.x), Number(body.y));
        this._sendJson(res, 200, { ok: true, window: win });
        return;
      }
      if (action === 'resize') {
        const win = os.compositor.resizeWindow(windowId, Number(body.width), Number(body.height));
        this._sendJson(res, 200, { ok: true, window: win });
        return;
      }
      if (action === 'focus') {
        const win = os.compositor.focusWindow(windowId);
        this._sendJson(res, 200, { ok: true, window: win });
        return;
      }
      if (action === 'state') {
        const win = os.compositor.setWindowState(windowId, body.state);
        this._sendJson(res, 200, { ok: true, window: win });
        return;
      }
      if (action === 'close') {
        const result = os.compositor.closeWindow(windowId);
        this._pumpScheduler(2);
        this._sendJson(res, 200, { ok: true, ...result });
        return;
      }
      // action === 'input'
      const rawEvent = body.event && typeof body.event === 'object' ? body.event : body;
      const event =
        rawEvent.type === undefined && (typeof rawEvent.action === 'string' || typeof rawEvent.targetId === 'string')
          ? { type: 'action', ...rawEvent }
          : rawEvent;
      const delivered = os.compositor.dispatchInput(windowId, event);
      this._pumpScheduler(5);
      const updatedWin = os.compositor.getWindow(windowId);
      this._sendJson(res, 200, { ok: true, delivered, window: updatedWin });
      return;
    }

    // ---- Shell & Search ----
    if (pathname === '/api/v1/shell/exec') {
      if (method !== 'POST') throw methodNotAllowed(['POST']);
      const body = await readJsonBody(req, this._maxJsonBodyBytes);
      const command = body.command ?? body.cmd;
      if (typeof command !== 'string') {
        throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Missing required string field: command');
      }
      const opts = {};
      if (body.cwd !== undefined) opts.cwd = body.cwd;
      if (body.env !== undefined) opts.env = body.env;
      if (body.platform !== undefined) opts.platform = body.platform;
      if (body.uid !== undefined) opts.uid = body.uid;
      if (body.gid !== undefined) opts.gid = body.gid;
      const result = await os.shell.exec(command, opts);
      this._sendJson(res, 200, result);
      return;
    }

    if (pathname === '/api/v1/search') {
      if (method !== 'GET') throw methodNotAllowed(['GET']);
      const q = query.get('q') ?? '';
      const limit = query.get('limit') ?? undefined;
      const types = query.get('types') ?? undefined;
      const result = this.search.query(q, { limit, types });
      this._sendJson(res, 200, { ok: true, ...result });
      return;
    }

    throw new HttpRouteError(404, ERROR_CODES.ENOENT, `Unknown API endpoint: ${pathname}`);
  }

  async _handleStaticRequest(req, res, method, rawPathPart) {
    if (method !== 'GET' && method !== 'HEAD') {
      throw methodNotAllowed(['GET', 'HEAD']);
    }

    if (hasRawTraversalAttempt(rawPathPart)) {
      throw new HttpRouteError(
        403,
        ERROR_CODES.E_PATH_TRAVERSAL,
        'Path traversal attempt blocked'
      );
    }

    let decodedPath;
    try {
      decodedPath = decodeURIComponent(rawPathPart);
    } catch (err) {
      void err;
      throw new HttpRouteError(400, ERROR_CODES.EINVAL, 'Malformed URL encoding in static path');
    }

    if (hasRawTraversalAttempt(decodedPath)) {
      throw new HttpRouteError(
        403,
        ERROR_CODES.E_PATH_TRAVERSAL,
        'Path traversal attempt blocked'
      );
    }

    const relPath = decodedPath === '/' ? '/index.html' : decodedPath;

    let realUiDir;
    try {
      realUiDir = await fsp.realpath(this._uiDir);
    } catch (err) {
      void err;
      if (relPath === '/index.html') {
        this._sendFallbackHtml(res, method);
        return;
      }
      throw new HttpRouteError(404, ERROR_CODES.ENOENT, `Static asset not found: ${decodedPath}`);
    }

    const candidate = path.resolve(realUiDir, `.${relPath}`);
    if (candidate !== realUiDir && !candidate.startsWith(realUiDir + path.sep)) {
      throw new HttpRouteError(
        403,
        ERROR_CODES.E_PATH_TRAVERSAL,
        'Static path escapes UI root directory'
      );
    }

    let targetFile = candidate;
    let stat;
    try {
      stat = await fsp.lstat(targetFile);
      if (stat.isDirectory()) {
        targetFile = path.join(targetFile, 'index.html');
        stat = await fsp.lstat(targetFile);
      }
    } catch (err) {
      void err;
      if (relPath === '/index.html') {
        this._sendFallbackHtml(res, method);
        return;
      }
      throw new HttpRouteError(404, ERROR_CODES.ENOENT, `Static asset not found: ${decodedPath}`);
    }

    let realTarget;
    try {
      realTarget = await fsp.realpath(targetFile);
    } catch (err) {
      void err;
      throw new HttpRouteError(404, ERROR_CODES.ENOENT, `Static asset not found: ${decodedPath}`);
    }

    if (realTarget !== realUiDir && !realTarget.startsWith(realUiDir + path.sep)) {
      throw new HttpRouteError(
        403,
        ERROR_CODES.E_PATH_TRAVERSAL,
        'Symlink target escapes UI root directory'
      );
    }

    let realStat;
    try {
      realStat = await fsp.stat(realTarget);
    } catch (err) {
      void err;
      throw new HttpRouteError(404, ERROR_CODES.ENOENT, `Static asset not found: ${decodedPath}`);
    }

    if (!realStat.isFile()) {
      if (relPath === '/index.html') {
        this._sendFallbackHtml(res, method);
        return;
      }
      throw new HttpRouteError(404, ERROR_CODES.ENOENT, `Static asset not found: ${decodedPath}`);
    }

    const ext = path.extname(realTarget).toLowerCase();
    const contentType = MIME_TYPES[ext] ?? 'application/octet-stream';
    const data = await fsp.readFile(realTarget);

    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': data.byteLength,
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
    });
    if (method === 'HEAD') {
      res.end();
    } else {
      res.end(data);
    }
  }

  _sendFallbackHtml(res, method) {
    const html = buildFallbackStatusHtml(this.os);
    const buf = Buffer.from(html, 'utf8');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Length': buf.byteLength,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    if (method === 'HEAD') {
      res.end();
    } else {
      res.end(buf);
    }
  }
}

export function createHttpServer(osOrOptions = {}, serverOptions = {}) {
  return new OmniHttpServer(osOrOptions, serverOptions);
}

export async function startOmniOSServer(options = {}) {
  const server = createHttpServer(options);
  const address = await server.start({
    port: options.port,
    host: options.host,
  });
  return { server, os: server.os, address };
}

// Main-module entrypoint: `node os/server/http-server.mjs`
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const argv = process.argv.slice(2);
  let liteMode;
  let cliPort;
  let cliHost;
  let cliDataDir;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--lite') {
      liteMode = true;
    } else if (arg.startsWith('--lite=')) {
      const val = arg.slice('--lite='.length).trim().toLowerCase();
      liteMode = val === 'true' || val === '1' || val === 'yes';
    } else if (arg === '--port' && i + 1 < argv.length) {
      cliPort = argv[++i];
    } else if (arg.startsWith('--port=')) {
      cliPort = arg.slice('--port='.length);
    } else if (arg === '--host' && i + 1 < argv.length) {
      cliHost = argv[++i];
    } else if (arg.startsWith('--host=')) {
      cliHost = arg.slice('--host='.length);
    } else if (arg === '--data-dir' && i + 1 < argv.length) {
      cliDataDir = argv[++i];
    } else if (arg.startsWith('--data-dir=')) {
      cliDataDir = arg.slice('--data-dir='.length);
    }
  }
  const port = Number(cliPort ?? process.env.PORT ?? 3777);
  const host = cliHost ?? process.env.HOST ?? '127.0.0.1';
  const dataDir = (cliDataDir ?? process.env.OMNIOS_DATA_DIR) || null;

  try {
    const { server, address } = await startOmniOSServer({
      port,
      host,
      dataDir,
      ...(liteMode !== undefined ? { liteMode } : {}),
    });
    console.log(`[OmniOS] HTTP/WS daemon listening at ${address.url} (ws: ${address.wsUrl})`);

    let shuttingDown = false;
    const shutdown = async (signal) => {
      if (shuttingDown) return;
      shuttingDown = true;
      console.log(`[OmniOS] Received ${signal}, shutting down cleanly...`);
      try {
        await server.stop();
      } catch (err) {
        console.error(`[OmniOS] Shutdown error: ${err?.message ?? err}`);
      }
      process.exitCode = 0;
    };

    process.once('SIGINT', () => {
      void shutdown('SIGINT');
    });
    process.once('SIGTERM', () => {
      void shutdown('SIGTERM');
    });
  } catch (err) {
    console.error(`[OmniOS] Failed to start server: ${err?.message ?? err}`);
    process.exitCode = 1;
  }
}
