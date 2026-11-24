/**
 * OmniOS Zero-Dependency RFC 6455 WebSocket Server (`F-063`)
 * - Pure Node.js 24 ESM over `http.Server` `'upgrade'`
 * - Full RFC 6455 handshake validation, frame state machine, fragmentation + interleaved
 *   control frames, strict UTF-8 validation, close code validation, and backpressure guard
 * - Bridges all Contract 7 Server->Client & Client->Server JSON envelopes `{ type, seq, ts, payload }`
 * - Zero static import of `os/os.mjs` (receives `os` instance in constructor)
 */

import crypto from 'node:crypto';
import { DEFAULT_MENU_BAR } from '../compositor/compositor.mjs';

export const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export const WS_OPCODES = Object.freeze({
  CONTINUATION: 0x0,
  TEXT: 0x1,
  BINARY: 0x2,
  CLOSE: 0x8,
  PING: 0x9,
  PONG: 0xa,
});

export const WS_CLOSE_CODES = Object.freeze({
  NORMAL: 1000,
  GOING_AWAY: 1001,
  PROTOCOL_ERROR: 1002,
  UNSUPPORTED_DATA: 1003,
  INVALID_PAYLOAD: 1007,
  POLICY_VIOLATION: 1008,
  MESSAGE_TOO_BIG: 1009,
  INTERNAL_ERROR: 1011,
});

const VALID_OPCODES = new Set([
  WS_OPCODES.CONTINUATION,
  WS_OPCODES.TEXT,
  WS_OPCODES.BINARY,
  WS_OPCODES.CLOSE,
  WS_OPCODES.PING,
  WS_OPCODES.PONG,
]);

const DEFAULT_MENU_ACTION_IDS = new Set();
for (const menu of DEFAULT_MENU_BAR) {
  for (const item of menu.items) {
    DEFAULT_MENU_ACTION_IDS.add(item.id);
  }
}

const SYSTEM_MENU_LAUNCH_MAP = Object.freeze({
  'omnios.settings': 'com.omnios.settings',
  'omnios.activity': 'com.omnios.monitor',
  'omnios.monitor': 'com.omnios.monitor',
  'omnios.terminal': 'com.omnios.terminal',
  'omnios.files': 'com.omnios.files',
  'omnios.apphub': 'com.omnios.apphub',
  'omnios.inspector': 'com.omnios.inspector',
  'omnios.notes': 'com.omnios.notes',
});

const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
const MAX_JSON_DEPTH = 32;

function isValidClientCloseCode(code) {
  if (!Number.isInteger(code)) return false;
  if (code >= 1000 && code <= 1003) return true;
  if (code >= 1007 && code <= 1011) return true;
  if (code >= 3000 && code <= 4999) return true;
  return false;
}

function isValidWebSocketKey(rawKey) {
  if (typeof rawKey !== 'string') return false;
  const trimmed = rawKey.trim();
  if (trimmed.length !== 24 || !/^[A-Za-z0-9+/]{22}==$/.test(trimmed)) {
    return false;
  }
  const decoded = Buffer.from(trimmed, 'base64');
  return decoded.byteLength === 16 && decoded.toString('base64') === trimmed;
}

function hasHeaderToken(headerValue, tokenLower) {
  if (typeof headerValue !== 'string' || headerValue.length === 0) return false;
  const parts = headerValue.split(',');
  for (let i = 0; i < parts.length; i += 1) {
    if (parts[i].trim().toLowerCase() === tokenLower) return true;
  }
  return false;
}

function extractRequestPathname(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) return '/';
  const qIdx = rawUrl.indexOf('?');
  return qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);
}

/**
 * Safely converts arbitrary kernel/app values (BigInt, Uint8Array/Buffer, Set, Map,
 * circular references, throwing getters) into a JSON-serializable structure.
 */
function toJsonSafe(value, seen = new Set(), depth = 0) {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === 'string' || t === 'boolean') return value;
  if (t === 'number') return Number.isFinite(value) ? value : null;
  if (t === 'bigint') return value.toString(10);
  if (t === 'function' || t === 'symbol') return undefined;
  if (depth >= MAX_JSON_DEPTH) return '[MaxDepth]';

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
        const safeKey = String(k);
        const safeVal = toJsonSafe(v, seen, depth + 1);
        if (safeVal !== undefined) {
          Object.defineProperty(out, safeKey, {
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

function safeJsonStringify(obj) {
  try {
    return JSON.stringify(toJsonSafe(obj));
  } catch (err) {
    return JSON.stringify({
      type: 'error',
      ts: new Date().toISOString(),
      payload: {
        code: 'E_SERIALIZE',
        message: `Failed to serialize WebSocket envelope: ${err?.message ?? 'unknown error'}`,
      },
    });
  }
}

function toPayloadBuffer(payload) {
  if (payload === null || payload === undefined) {
    return Buffer.alloc(0);
  }
  if (Buffer.isBuffer(payload)) {
    return payload;
  }
  if (typeof payload === 'string') {
    return Buffer.from(payload, 'utf8');
  }
  if (ArrayBuffer.isView(payload)) {
    return Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  }
  if (payload instanceof ArrayBuffer) {
    return Buffer.from(payload);
  }
  throw new TypeError('WebSocket frame payload must be a string, Buffer, Uint8Array, or ArrayBuffer');
}

/**
 * Encodes an RFC 6455 WebSocket frame.
 * Server->Client frames default to `mask: false` (unmasked per RFC 6455 §5.1).
 */
export function encodeWsFrame(opcode, payload = Buffer.alloc(0), options = {}) {
  if (!Number.isInteger(opcode) || opcode < 0 || opcode > 0x0f) {
    throw new RangeError(`Invalid WebSocket opcode: ${opcode}`);
  }
  const {
    fin = true,
    rsv1 = false,
    rsv2 = false,
    rsv3 = false,
    mask = false,
    maskingKey = null,
  } = options ?? {};

  const body = toPayloadBuffer(payload);
  const len = body.byteLength;

  let headerLen = 2;
  if (len >= 126 && len <= 0xffff) {
    headerLen += 2;
  } else if (len > 0xffff) {
    headerLen += 8;
  }
  if (mask) {
    headerLen += 4;
  }

  const frame = Buffer.allocUnsafe(headerLen + len);
  const b0 =
    (fin ? 0x80 : 0) |
    (rsv1 ? 0x40 : 0) |
    (rsv2 ? 0x20 : 0) |
    (rsv3 ? 0x10 : 0) |
    (opcode & 0x0f);
  frame[0] = b0;

  let offset = 2;
  const maskFlag = mask ? 0x80 : 0;
  if (len < 126) {
    frame[1] = maskFlag | len;
  } else if (len <= 0xffff) {
    frame[1] = maskFlag | 126;
    frame.writeUInt16BE(len, 2);
    offset = 4;
  } else {
    frame[1] = maskFlag | 127;
    frame.writeBigUInt64BE(BigInt(len), 2);
    offset = 10;
  }

  if (mask) {
    const keyBuf =
      maskingKey !== null && maskingKey !== undefined
        ? toPayloadBuffer(maskingKey)
        : crypto.randomBytes(4);
    if (keyBuf.byteLength !== 4) {
      throw new RangeError('WebSocket maskingKey must be exactly 4 bytes');
    }
    keyBuf.copy(frame, offset, 0, 4);
    offset += 4;
    for (let i = 0; i < len; i += 1) {
      frame[offset + i] = body[i] ^ keyBuf[i & 3];
    }
  } else if (len > 0) {
    body.copy(frame, offset);
  }

  return frame;
}

function encodeClosePayload(code, reason = '') {
  if (code === null || code === undefined) {
    return Buffer.alloc(0);
  }
  let reasonBuf = reason ? Buffer.from(String(reason), 'utf8') : Buffer.alloc(0);
  // RFC 6455 §5.5: control frame payload must not exceed 125 bytes (2B code + <=123B reason)
  if (reasonBuf.byteLength > 123) {
    reasonBuf = reasonBuf.subarray(0, 123);
  }
  const out = Buffer.allocUnsafe(2 + reasonBuf.byteLength);
  out.writeUInt16BE(code & 0xffff, 0);
  if (reasonBuf.byteLength > 0) {
    reasonBuf.copy(out, 2);
  }
  return out;
}

function writeHttpRejection(socket, statusCode, statusText, extraHeaders = {}, body = '') {
  if (!socket || socket.destroyed) return;
  const bodyBuf = Buffer.from(body || `${statusCode} ${statusText}\r\n`, 'utf8');
  const lines = [
    `HTTP/1.1 ${statusCode} ${statusText}`,
    'Connection: close',
    'Content-Type: text/plain; charset=utf-8',
    `Content-Length: ${bodyBuf.byteLength}`,
  ];
  for (const [k, v] of Object.entries(extraHeaders)) {
    lines.push(`${k}: ${v}`);
  }
  const raw = `${lines.join('\r\n')}\r\n\r\n`;
  try {
    socket.end(Buffer.concat([Buffer.from(raw, 'utf8'), bodyBuf]));
  } catch (err) {
    // Socket may already be closing; force destroy below.
    void err;
    try {
      socket.destroy();
    } catch (destroyErr) {
      void destroyErr;
    }
  }
}

export class OmniWebSocketServer {
  constructor(os, options = {}) {
    this._os = os ?? null;
    this.path = typeof options.path === 'string' && options.path.length > 0 ? options.path : '/ws';
    this._maxConnections =
      Number.isInteger(options.maxConnections) && options.maxConnections > 0
        ? options.maxConnections
        : 128;
    this._maxFrameBytes =
      Number.isInteger(options.maxFrameBytes) && options.maxFrameBytes > 0
        ? options.maxFrameBytes
        : 1024 * 1024;
    this._maxMessageBytes =
      Number.isInteger(options.maxMessageBytes) && options.maxMessageBytes > 0
        ? options.maxMessageBytes
        : 2 * 1024 * 1024;
    this._maxFragments =
      Number.isInteger(options.maxFragments) && options.maxFragments > 0
        ? options.maxFragments
        : 256;
    this._maxBackpressureBytes =
      Number.isInteger(options.maxBackpressureBytes) && options.maxBackpressureBytes > 0
        ? options.maxBackpressureBytes
        : 4 * 1024 * 1024;
    this._heartbeatMs =
      Number.isInteger(options.heartbeatMs) && options.heartbeatMs >= 0
        ? options.heartbeatMs
        : 30_000;
    this._rejectUnknownUpgrade = options.rejectUnknownUpgrade !== false;

    this._clients = new Set();
    this._clientSeq = 0;
    this._seq = 0;
    this._unsubs = [];
    this._subscribed = false;
    this._closed = false;
    this._httpServer = null;
    this._upgradeListener = null;
    this._heartbeatTimer = null;

    this._subscribeOsEvents();
  }

  _logError(context, err) {
    const msg = err?.message ?? String(err);
    try {
      this._os?.kernel?.log?.('warn', 'websocket', `${context}: ${msg}`);
    } catch (logErr) {
      // Kernel logger may be unavailable during shutdown.
      void logErr;
    }
  }

  _nextEnvelope(type, payload) {
    return {
      type,
      seq: ++this._seq,
      ts: new Date().toISOString(),
      payload,
    };
  }

  attach(httpServer) {
    if (!httpServer || typeof httpServer.on !== 'function') {
      throw new TypeError('OmniWebSocketServer.attach requires an http.Server instance');
    }
    this._closed = false;
    if (!this._subscribed) {
      this._subscribeOsEvents();
    }
    if (this._httpServer && this._upgradeListener) {
      this._httpServer.off('upgrade', this._upgradeListener);
    }
    this._httpServer = httpServer;
    this._upgradeListener = (req, socket, head) => {
      const pathname = extractRequestPathname(req?.url ?? '/');
      if (pathname !== this.path) {
        if (this._rejectUnknownUpgrade) {
          writeHttpRejection(socket, 404, 'Not Found', {}, 'WebSocket endpoint not found\n');
        }
        return;
      }
      this.handleUpgrade(req, socket, head);
    };
    httpServer.on('upgrade', this._upgradeListener);
    return this;
  }

  handleUpgrade(req, socket, head = Buffer.alloc(0)) {
    if (!socket) return null;

    if (this._closed) {
      writeHttpRejection(socket, 503, 'Service Unavailable', {}, 'WebSocket server closed\n');
      return null;
    }

    const method = typeof req?.method === 'string' ? req.method.toUpperCase() : '';
    if (method !== 'GET') {
      writeHttpRejection(socket, 400, 'Bad Request', {}, 'WebSocket upgrade requires GET\n');
      return null;
    }

    const pathname = extractRequestPathname(req?.url ?? '/');
    if (pathname !== this.path) {
      writeHttpRejection(socket, 404, 'Not Found', {}, 'WebSocket endpoint not found\n');
      return null;
    }

    const headers = req?.headers ?? {};
    const upgradeHdr = headers.upgrade;
    const connectionHdr = headers.connection;
    const versionHdr = headers['sec-websocket-version'];
    const keyHdr = headers['sec-websocket-key'];

    if (!hasHeaderToken(upgradeHdr, 'websocket') || !hasHeaderToken(connectionHdr, 'upgrade')) {
      writeHttpRejection(
        socket,
        400,
        'Bad Request',
        {},
        'Missing or invalid Upgrade/Connection headers\n'
      );
      return null;
    }

    if (typeof versionHdr !== 'string' || versionHdr.trim() !== '13') {
      writeHttpRejection(
        socket,
        426,
        'Upgrade Required',
        { 'Sec-WebSocket-Version': '13' },
        'Sec-WebSocket-Version: 13 is required\n'
      );
      return null;
    }

    if (!isValidWebSocketKey(keyHdr)) {
      writeHttpRejection(socket, 400, 'Bad Request', {}, 'Invalid Sec-WebSocket-Key\n');
      return null;
    }

    if (this._clients.size >= this._maxConnections) {
      writeHttpRejection(
        socket,
        503,
        'Service Unavailable',
        {},
        'Maximum WebSocket connections reached\n'
      );
      return null;
    }

    const acceptKey = crypto
      .createHash('sha1')
      .update(keyHdr.trim() + WS_GUID, 'utf8')
      .digest('base64');

    const responseLines = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${acceptKey}`,
      '\r\n',
    ];

    try {
      socket.setNoDelay?.(true);
      socket.write(responseLines.join('\r\n'));
    } catch (err) {
      this._logError('handshake write failed', err);
      try {
        socket.destroy();
      } catch (destroyErr) {
        void destroyErr;
      }
      return null;
    }

    const client = {
      id: ++this._clientSeq,
      socket,
      buffer: Buffer.alloc(0),
      fragOpcode: null,
      fragChunks: [],
      fragBytes: 0,
      fragCount: 0,
      closing: false,
      closed: false,
      alive: true,
    };

    this._clients.add(client);
    this._ensureHeartbeat();

    socket.on('data', (chunk) => {
      this._onSocketData(client, chunk);
    });
    socket.on('error', (err) => {
      this._logError(`client #${client.id} socket error`, err);
      this._cleanupClient(client, true);
    });
    socket.on('end', () => {
      this._cleanupClient(client, false);
    });
    socket.on('close', () => {
      this._cleanupClient(client, false);
    });

    // Immediately push initial compositor snapshot upon connect (Contract 7).
    if (this._os?.compositor?.getSnapshot) {
      try {
        const snapshot = this._os.compositor.getSnapshot();
        this.sendTo(client, 'compositor:snapshot', snapshot);
      } catch (err) {
        this._logError('initial snapshot push failed', err);
      }
    }

    // Process any trailing frame bytes that arrived with the HTTP upgrade packet.
    if (head && head.byteLength > 0) {
      this._onSocketData(client, Buffer.isBuffer(head) ? head : Buffer.from(head));
    }

    return client;
  }

  _ensureHeartbeat() {
    if (this._heartbeatMs <= 0 || this._heartbeatTimer || this._closed) return;
    this._heartbeatTimer = setInterval(() => {
      if (this._clients.size === 0) {
        this._clearHeartbeat();
        return;
      }
      const pingFrame = encodeWsFrame(WS_OPCODES.PING, Buffer.from('omnios-hb', 'utf8'), {
        mask: false,
      });
      for (const client of Array.from(this._clients)) {
        if (client.closed || client.closing) continue;
        if (!client.alive) {
          this._failClient(client, WS_CLOSE_CODES.GOING_AWAY, 'Heartbeat timeout');
          continue;
        }
        client.alive = false;
        this._sendRawFrame(client, pingFrame);
      }
    }, this._heartbeatMs);
    this._heartbeatTimer.unref?.();
  }

  _clearHeartbeat() {
    if (this._heartbeatTimer) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
  }

  _cleanupClient(client, destroySocket = false) {
    if (!client) return;
    const wasClosed = client.closed;
    client.closed = true;
    client.closing = true;
    client.buffer = Buffer.alloc(0);
    client.fragChunks = [];
    client.fragOpcode = null;
    client.fragBytes = 0;
    client.fragCount = 0;
    this._clients.delete(client);
    if (this._clients.size === 0) {
      this._clearHeartbeat();
    }
    if (destroySocket && !wasClosed && client.socket && !client.socket.destroyed) {
      try {
        client.socket.destroy();
      } catch (err) {
        void err;
      }
    }
  }

  _sendRawFrame(client, frameBuffer) {
    if (!client || client.closed || !client.socket || client.socket.destroyed || !client.socket.writable) {
      this._cleanupClient(client, false);
      return false;
    }
    if (client.socket.writableLength > this._maxBackpressureBytes) {
      this._logError(
        `client #${client.id} exceeded backpressure limit (${client.socket.writableLength}B)`,
        new Error('Backpressure drop')
      );
      this._failClient(client, WS_CLOSE_CODES.POLICY_VIOLATION, 'Slow consumer backpressure limit');
      return false;
    }
    try {
      client.socket.write(frameBuffer);
      return true;
    } catch (err) {
      this._logError(`client #${client.id} write failed`, err);
      this._cleanupClient(client, true);
      return false;
    }
  }

  _sendCloseAndEnd(client, code, reason = '') {
    if (!client || client.closed) return;
    if (!client.closing && client.socket && !client.socket.destroyed && client.socket.writable) {
      client.closing = true;
      const closePayload = encodeClosePayload(code, reason);
      const frame = encodeWsFrame(WS_OPCODES.CLOSE, closePayload, { mask: false });
      try {
        client.socket.write(frame);
        client.socket.end();
      } catch (err) {
        void err;
        try {
          client.socket.destroy();
        } catch (destroyErr) {
          void destroyErr;
        }
      }
    }
    this._cleanupClient(client, false);
  }

  _failClient(client, code, reason = '') {
    if (!client || client.closed) return;
    const sock = client.socket;
    if (!client.closing && sock && !sock.destroyed && sock.writable) {
      client.closing = true;
      const closePayload = encodeClosePayload(code, reason);
      const frame = encodeWsFrame(WS_OPCODES.CLOSE, closePayload, { mask: false });
      try {
        sock.write(frame, () => {
          try {
            sock.end();
          } catch (endErr) {
            void endErr;
          }
        });
      } catch (err) {
        void err;
        try {
          sock.destroy();
        } catch (destroyErr) {
          void destroyErr;
        }
      }
    } else if (sock && !sock.destroyed) {
      try {
        sock.destroy();
      } catch (destroyErr) {
        void destroyErr;
      }
    }
    this._cleanupClient(client, false);
  }

  _onSocketData(client, chunk) {
    if (!client || client.closed || !chunk || chunk.byteLength === 0) return;
    client.alive = true;

    const nextLen = client.buffer.byteLength + chunk.byteLength;
    const maxBufferedBytes = Math.max(this._maxMessageBytes, this._maxFrameBytes * 2) + 1024;
    // Cap buffered unread frame bytes to prevent unbounded memory growth.
    if (nextLen > maxBufferedBytes) {
      this._failClient(client, WS_CLOSE_CODES.MESSAGE_TOO_BIG, 'Frame buffer exceeds maximum size');
      return;
    }

    client.buffer =
      client.buffer.byteLength === 0 ? Buffer.from(chunk) : Buffer.concat([client.buffer, chunk]);

    this._drainFrames(client);
  }

  _drainFrames(client) {
    while (!client.closed && client.buffer.byteLength >= 2) {
      const buf = client.buffer;
      const b0 = buf[0];
      const b1 = buf[1];

      const fin = (b0 & 0x80) !== 0;
      const rsv = b0 & 0x70;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      const len7 = b1 & 0x7f;

      if (rsv !== 0) {
        this._failClient(client, WS_CLOSE_CODES.PROTOCOL_ERROR, 'Non-zero RSV bits are forbidden');
        return;
      }

      if (!VALID_OPCODES.has(opcode)) {
        this._failClient(client, WS_CLOSE_CODES.PROTOCOL_ERROR, `Reserved opcode 0x${opcode.toString(16)}`);
        return;
      }

      if (!masked) {
        this._failClient(client, WS_CLOSE_CODES.PROTOCOL_ERROR, 'Client frames must be masked');
        return;
      }

      const isControl = (opcode & 0x08) !== 0;
      if (isControl) {
        if (!fin) {
          this._failClient(client, WS_CLOSE_CODES.PROTOCOL_ERROR, 'Control frames must not be fragmented');
          return;
        }
        if (len7 > 125) {
          this._failClient(
            client,
            WS_CLOSE_CODES.PROTOCOL_ERROR,
            'Control frame payload exceeds 125 bytes'
          );
          return;
        }
      }

      let headerOffset = 2;
      let payloadLen = len7;

      if (len7 === 126) {
        if (buf.byteLength < 4) return;
        payloadLen = buf.readUInt16BE(2);
        if (payloadLen < 126) {
          this._failClient(
            client,
            WS_CLOSE_CODES.PROTOCOL_ERROR,
            'Non-minimal 16-bit payload length encoding'
          );
          return;
        }
        headerOffset = 4;
      } else if (len7 === 127) {
        if (buf.byteLength < 10) return;
        if ((buf[2] & 0x80) !== 0) {
          this._failClient(
            client,
            WS_CLOSE_CODES.PROTOCOL_ERROR,
            '64-bit payload length MSB must be 0'
          );
          return;
        }
        const bigLen = buf.readBigUInt64BE(2);
        if (bigLen <= 0xffffn) {
          this._failClient(
            client,
            WS_CLOSE_CODES.PROTOCOL_ERROR,
            'Non-minimal 64-bit payload length encoding'
          );
          return;
        }
        if (bigLen > BigInt(this._maxFrameBytes)) {
          this._failClient(client, WS_CLOSE_CODES.MESSAGE_TOO_BIG, 'Frame payload exceeds maxFrameBytes');
          return;
        }
        payloadLen = Number(bigLen);
        headerOffset = 10;
      }

      if (payloadLen > this._maxFrameBytes) {
        this._failClient(client, WS_CLOSE_CODES.MESSAGE_TOO_BIG, 'Frame payload exceeds maxFrameBytes');
        return;
      }

      const totalFrameBytes = headerOffset + 4 + payloadLen;
      if (buf.byteLength < totalFrameBytes) {
        return;
      }

      const mask0 = buf[headerOffset];
      const mask1 = buf[headerOffset + 1];
      const mask2 = buf[headerOffset + 2];
      const mask3 = buf[headerOffset + 3];
      const payloadStart = headerOffset + 4;

      const payload = Buffer.allocUnsafe(payloadLen);
      for (let i = 0; i < payloadLen; i += 1) {
        const m = i & 3;
        const keyByte = m === 0 ? mask0 : m === 1 ? mask1 : m === 2 ? mask2 : mask3;
        payload[i] = buf[payloadStart + i] ^ keyByte;
      }

      client.buffer =
        totalFrameBytes === buf.byteLength ? Buffer.alloc(0) : buf.subarray(totalFrameBytes);

      if (isControl) {
        this._handleControlFrame(client, opcode, payload);
        continue;
      }

      this._handleDataFrame(client, opcode, fin, payload);
    }
  }

  _handleControlFrame(client, opcode, payload) {
    if (opcode === WS_OPCODES.PING) {
      const pongFrame = encodeWsFrame(WS_OPCODES.PONG, payload, { mask: false });
      this._sendRawFrame(client, pongFrame);
      return;
    }

    if (opcode === WS_OPCODES.PONG) {
      client.alive = true;
      return;
    }

    if (opcode === WS_OPCODES.CLOSE) {
      if (payload.byteLength === 1) {
        this._failClient(
          client,
          WS_CLOSE_CODES.PROTOCOL_ERROR,
          'Close frame payload length of 1 is invalid'
        );
        return;
      }

      let echoCode = WS_CLOSE_CODES.NORMAL;
      if (payload.byteLength >= 2) {
        const code = payload.readUInt16BE(0);
        if (!isValidClientCloseCode(code)) {
          this._failClient(client, WS_CLOSE_CODES.PROTOCOL_ERROR, `Invalid close code: ${code}`);
          return;
        }
        if (payload.byteLength > 2) {
          try {
            STRICT_UTF8_DECODER.decode(payload.subarray(2));
          } catch (utfErr) {
            void utfErr;
            this._failClient(
              client,
              WS_CLOSE_CODES.INVALID_PAYLOAD,
              'Invalid UTF-8 in Close frame reason'
            );
            return;
          }
        }
        echoCode = code;
      }

      this._sendCloseAndEnd(client, echoCode, '');
    }
  }

  _handleDataFrame(client, opcode, fin, payload) {
    if (opcode === WS_OPCODES.CONTINUATION) {
      if (client.fragOpcode === null) {
        this._failClient(client, WS_CLOSE_CODES.PROTOCOL_ERROR, 'Unexpected continuation frame');
        return;
      }
      client.fragCount += 1;
      if (client.fragCount > this._maxFragments) {
        this._failClient(client, WS_CLOSE_CODES.MESSAGE_TOO_BIG, 'Fragment count exceeds maxFragments');
        return;
      }
      client.fragBytes += payload.byteLength;
      if (client.fragBytes > this._maxMessageBytes) {
        this._failClient(client, WS_CLOSE_CODES.MESSAGE_TOO_BIG, 'Message exceeds maxMessageBytes');
        return;
      }
      client.fragChunks.push(payload);

      if (fin) {
        const assembled = Buffer.concat(client.fragChunks, client.fragBytes);
        const msgOpcode = client.fragOpcode;
        client.fragOpcode = null;
        client.fragChunks = [];
        client.fragBytes = 0;
        client.fragCount = 0;
        this._onCompleteMessage(client, msgOpcode, assembled);
      }
      return;
    }

    // Starting a new TEXT or BINARY message.
    if (client.fragOpcode !== null) {
      this._failClient(
        client,
        WS_CLOSE_CODES.PROTOCOL_ERROR,
        'Received new data frame while fragmented message is active'
      );
      return;
    }

    if (payload.byteLength > this._maxMessageBytes) {
      this._failClient(client, WS_CLOSE_CODES.MESSAGE_TOO_BIG, 'Message exceeds maxMessageBytes');
      return;
    }

    if (!fin) {
      client.fragOpcode = opcode;
      client.fragChunks = [payload];
      client.fragBytes = payload.byteLength;
      client.fragCount = 1;
      return;
    }

    this._onCompleteMessage(client, opcode, payload);
  }

  _onCompleteMessage(client, opcode, payload) {
    if (opcode === WS_OPCODES.BINARY) {
      this.sendTo(client, 'error', {
        code: 'EINVAL',
        message: 'Binary WebSocket frames are not supported for JSON envelopes',
      });
      return;
    }

    let text;
    try {
      text = STRICT_UTF8_DECODER.decode(payload);
    } catch (utfErr) {
      void utfErr;
      this._failClient(client, WS_CLOSE_CODES.INVALID_PAYLOAD, 'Invalid UTF-8 in text frame');
      return;
    }

    let msg;
    try {
      msg = JSON.parse(text);
    } catch (parseErr) {
      this.sendTo(client, 'error', {
        code: 'EINVAL',
        message: `Invalid JSON message: ${parseErr?.message ?? 'parse error'}`,
      });
      return;
    }

    if (!msg || typeof msg !== 'object' || Array.isArray(msg) || typeof msg.type !== 'string') {
      this.sendTo(client, 'error', {
        code: 'EINVAL',
        message: 'WebSocket envelope must be a JSON object with a string "type" field',
      });
      return;
    }

    Promise.resolve()
      .then(() => this._handleClientMessage(client, msg))
      .catch((err) => {
        this.sendTo(client, 'error', {
          id: msg.id ?? msg.payload?.id ?? null,
          requestType: msg.type,
          code: typeof err?.code === 'string' ? err.code : 'E_OMNIOS',
          message: err?.message ?? String(err),
        });
      });
  }

  _pumpScheduler(ticks = 5) {
    const scheduler = this._os?.scheduler;
    if (!scheduler || typeof scheduler.step !== 'function') return;
    try {
      scheduler.step(ticks);
    } catch (err) {
      this._logError('scheduler step after WS input failed', err);
    }
  }

  async _handleMenuAction(payload) {
    const compositor = this._os?.compositor;
    const actionId = String(payload.actionId ?? payload.itemId ?? payload.action ?? '').trim();
    if (!actionId) {
      throw new Error('compositor:menu_action requires actionId or itemId');
    }

    const snap = compositor?.getSnapshot ? compositor.getSnapshot() : null;
    const targetWindowId = payload.windowId ?? snap?.focusedWindowId ?? null;

    if (actionId === 'window.minimize') {
      if (targetWindowId && compositor) {
        compositor.setWindowState(targetWindowId, 'minimized');
      }
      return;
    }
    if (actionId === 'window.maximize') {
      if (targetWindowId && compositor) {
        const win = compositor.getWindow?.(targetWindowId);
        const nextState = win?.state === 'maximized' ? 'normal' : 'maximized';
        compositor.setWindowState(targetWindowId, nextState);
      }
      return;
    }
    if (actionId === 'window.snap_left') {
      if (targetWindowId && compositor) {
        compositor.setWindowState(targetWindowId, 'snapped-left');
      }
      return;
    }
    if (actionId === 'window.snap_right') {
      if (targetWindowId && compositor) {
        compositor.setWindowState(targetWindowId, 'snapped-right');
      }
      return;
    }
    if (actionId === 'file.close') {
      if (targetWindowId && compositor) {
        compositor.closeWindow(targetWindowId);
        this._pumpScheduler(2);
      }
      return;
    }
    if (Object.prototype.hasOwnProperty.call(SYSTEM_MENU_LAUNCH_MAP, actionId)) {
      const targetAppId = SYSTEM_MENU_LAUNCH_MAP[actionId];
      if (typeof this._os?.launchApp === 'function') {
        await this._os.launchApp(targetAppId, { stepTicks: 5 });
      } else if (typeof this._os?.systemApps?.launch === 'function') {
        await this._os.systemApps.launch(targetAppId);
        this._pumpScheduler(5);
      }
      return;
    }
    if (actionId === 'omnios.about') {
      if (typeof this._os?.notifications?.post === 'function') {
        this._os.notifications.post({
          appId: 'com.omnios.system',
          platform: 'system',
          title: 'About OmniOS',
          body: `OmniOS v${this._os?.version ?? '1.0.0'} — Unified Android, Windows, iOS, macOS & WebAssembly OS`,
          priority: 'normal',
          category: 'system',
        });
      }
      return;
    }
    if (actionId === 'edit.copy' && typeof payload.text === 'string' && this._os?.clipboard?.set) {
      this._os.clipboard.set({ text: payload.text, sourceAppId: 'com.omnios.compositor' });
    }
    if (actionId === 'file.new' && !targetWindowId && typeof this._os?.launchApp === 'function') {
      await this._os.launchApp('com.omnios.notes', { preferSystem: true, stepTicks: 5 });
      return;
    }

    // Forward app-defined menu items (and edit.* / file.new on focused windows) to target app.
    if (targetWindowId && compositor?.dispatchInput) {
      compositor.dispatchInput(targetWindowId, {
        type: 'menu_action',
        actionId,
        itemId: actionId,
        menuId: payload.menuId ?? null,
        label: payload.label ?? null,
        isDefaultMenu: DEFAULT_MENU_ACTION_IDS.has(actionId),
        data: payload.data ?? null,
      });
      this._pumpScheduler(5);
    }
  }

  async _handleClientMessage(client, msg) {
    const type = msg.type;
    const payload =
      msg.payload && typeof msg.payload === 'object' && !Array.isArray(msg.payload)
        ? msg.payload
        : msg;
    const reqId = msg.id ?? payload.id ?? null;

    switch (type) {
      case 'ping': {
        this.sendTo(client, 'pong', {
          id: reqId,
          ts: new Date().toISOString(),
          echo: msg.payload ?? null,
        });
        return;
      }

      case 'compositor:input': {
        const windowId = payload.windowId;
        let event;
        if (payload.event && typeof payload.event === 'object') {
          event = payload.event;
        } else {
          const rest = { ...payload };
          delete rest.windowId;
          delete rest.type;
          delete rest.eventType;
          delete rest.actionType;
          delete rest.id;
          const inferredType =
            payload.eventType ??
            payload.actionType ??
            (payload !== msg && typeof payload.type === 'string' && payload.type !== 'compositor:input'
              ? payload.type
              : 'action');
          event = {
            ...rest,
            type: inferredType,
            targetId: payload.targetId ?? payload.controlId ?? null,
            action: payload.action ?? null,
          };
        }
        this._os.compositor.dispatchInput(windowId, event);
        this._pumpScheduler(5);
        return;
      }

      case 'compositor:move': {
        this._os.compositor.moveWindow(payload.windowId, Number(payload.x), Number(payload.y));
        return;
      }

      case 'compositor:resize': {
        this._os.compositor.resizeWindow(
          payload.windowId,
          Number(payload.width),
          Number(payload.height)
        );
        return;
      }

      case 'compositor:focus': {
        this._os.compositor.focusWindow(payload.windowId);
        return;
      }

      case 'compositor:state': {
        this._os.compositor.setWindowState(payload.windowId, payload.state);
        return;
      }

      case 'compositor:close': {
        this._os.compositor.closeWindow(payload.windowId);
        this._pumpScheduler(2);
        return;
      }

      case 'compositor:menu_action': {
        await this._handleMenuAction(payload);
        return;
      }

      case 'shell:mode': {
        const mode = payload.mode ?? payload.shellMode;
        this._os.compositor.setShellMode(mode);
        return;
      }

      case 'permission:decision': {
        const promptId = payload.promptId;
        const decision = payload.decision !== undefined ? payload.decision : payload.granted;
        this._os.permissions.resolvePrompt(promptId, decision);
        return;
      }

      case 'intent:choice': {
        const requestId = payload.requestId;
        const cancel = Boolean(payload.cancel);
        if (cancel) {
          this._os.intentRouter.cancelChooser(requestId);
          return;
        }
        const appId = payload.appId ?? payload.chosenAppId;
        const setAsDefault = Boolean(payload.setAsDefault);
        try {
          await this._os.intentRouter.resolveChooser(requestId, appId, { setAsDefault });
          this._pumpScheduler(5);
        } catch (err) {
          if (err?.code === 'ENOENT') {
            this.sendTo(client, 'error', {
              id: reqId,
              requestType: type,
              code: 'ENOENT',
              message: err.message,
            });
            return;
          }
          throw err;
        }
        return;
      }

      case 'terminal:exec': {
        const command = String(payload.command ?? payload.cmd ?? '');
        const opts =
          payload.options && typeof payload.options === 'object'
            ? { ...payload.options }
            : payload.opts && typeof payload.opts === 'object'
              ? { ...payload.opts }
              : {};
        if (payload.cwd !== undefined && opts.cwd === undefined) opts.cwd = payload.cwd;
        if (payload.platform !== undefined && opts.platform === undefined) {
          opts.platform = payload.platform;
        }
        const result = await this._os.shell.exec(command, opts);
        this.sendTo(client, 'terminal:result', {
          id: reqId,
          ...result,
        });
        return;
      }

      default: {
        this.sendTo(client, 'error', {
          id: reqId,
          requestType: type,
          code: 'EINVAL',
          message: `Unsupported WebSocket message type: ${type}`,
        });
      }
    }
  }

  _subscribeOsEvents() {
    const bus = this._os?.eventBus ?? this._os?.kernel?.eventBus;
    if (!bus || typeof bus.on !== 'function' || this._subscribed) return;
    this._subscribed = true;

    const perms = this._os?.permissions;
    if (typeof perms?.registerInteractiveSource === 'function') {
      this._unsubs.push(
        perms.registerInteractiveSource(() => !this._closed && this._clients.size > 0)
      );
    }

    const add = (pattern, handler) => {
      const unsub = bus.on(pattern, handler);
      if (typeof unsub === 'function') {
        this._unsubs.push(unsub);
      } else {
        this._unsubs.push(() => {
          bus.off?.(pattern, handler);
        });
      }
    };

    // Direct Contract 7 pass-through events
    const passthrough = [
      'compositor:snapshot',
      'compositor:window_created',
      'compositor:window_updated',
      'compositor:surface_patch',
      'compositor:window_closed',
      'notification:posted',
      'notification:updated',
      'config:changed',
      'permission:prompt',
      'intent:chooser',
    ];
    for (const evtName of passthrough) {
      add(evtName, (payload) => {
        if (this._clients.size === 0) return;
        this.broadcast(evtName, payload);
      });
    }

    // Bridged process lifecycle events -> process:update
    const processEvents = [
      'process:created',
      'process:state_changed',
      'process:exited',
      'process:reaped',
      'process:signal',
    ];
    for (const evtName of processEvents) {
      add(evtName, (payload) => {
        if (this._clients.size === 0) return;
        let processSummary = null;
        const pid = payload?.pid;
        if (typeof pid === 'number' && this._os?.processManager?.get) {
          try {
            const pcb = this._os.processManager.get(pid);
            if (pcb && typeof this._os.processManager.toSummary === 'function') {
              processSummary = this._os.processManager.toSummary(pcb);
            }
          } catch (err) {
            this._logError(`process summary lookup for pid ${pid} failed`, err);
          }
        }
        this.broadcast('process:update', {
          event: evtName,
          ...(payload && typeof payload === 'object' ? payload : { data: payload }),
          process: processSummary,
        });
      });
    }

    // Bridged process stdout & stderr -> process:stdout (preserving stream field)
    add('process:stdout', (payload) => {
      if (this._clients.size === 0) return;
      this.broadcast('process:stdout', {
        ...(payload && typeof payload === 'object' ? payload : { data: payload }),
        stream: payload?.stream ?? 'stdout',
      });
    });
    add('process:stderr', (payload) => {
      if (this._clients.size === 0) return;
      this.broadcast('process:stdout', {
        ...(payload && typeof payload === 'object' ? payload : { data: payload }),
        stream: 'stderr',
      });
    });

    // Bridged kernel & service events -> kernel:event
    const kernelEvents = [
      'kernel:booted',
      'kernel:panic',
      'kernel:recovered',
      'kernel:shutdown',
      'kernel:dmesg',
      'service:started',
      'service:stopped',
      'service:failed',
      'service:restarted',
      'service:unhealthy',
    ];
    for (const evtName of kernelEvents) {
      add(evtName, (payload) => {
        if (this._clients.size === 0) return;
        this.broadcast('kernel:event', {
          event: evtName,
          ...(payload && typeof payload === 'object' ? payload : {}),
          data: payload,
        });
      });
    }
  }

  _unsubscribeOsEvents() {
    for (const unsub of this._unsubs) {
      try {
        unsub();
      } catch (err) {
        this._logError('eventBus unsubscribe failed', err);
      }
    }
    this._unsubs = [];
    this._subscribed = false;
  }

  sendTo(client, type, payload = null) {
    if (!client || client.closed) return false;
    const envelope = this._nextEnvelope(type, payload);
    const json = safeJsonStringify(envelope);
    const frame = encodeWsFrame(WS_OPCODES.TEXT, Buffer.from(json, 'utf8'), { mask: false });
    return this._sendRawFrame(client, frame);
  }

  broadcast(type, payload = null) {
    if (this._clients.size === 0) return 0;
    const envelope = this._nextEnvelope(type, payload);
    const json = safeJsonStringify(envelope);
    const frame = encodeWsFrame(WS_OPCODES.TEXT, Buffer.from(json, 'utf8'), { mask: false });
    let sent = 0;
    for (const client of Array.from(this._clients)) {
      if (this._sendRawFrame(client, frame)) {
        sent += 1;
      }
    }
    return sent;
  }

  getClientCount() {
    return this._clients.size;
  }

  async closeAll(code = WS_CLOSE_CODES.GOING_AWAY, reason = 'Server shutting down') {
    this._closed = true;
    this._clearHeartbeat();
    this._unsubscribeOsEvents();

    if (this._httpServer && this._upgradeListener) {
      this._httpServer.off('upgrade', this._upgradeListener);
      this._upgradeListener = null;
      this._httpServer = null;
    }

    const clients = Array.from(this._clients);
    if (clients.length === 0) return;

    const closeFrame = encodeWsFrame(
      WS_OPCODES.CLOSE,
      encodeClosePayload(code, reason),
      { mask: false }
    );

    for (const client of clients) {
      const sock = client.socket;
      client.closing = true;
      client.closed = true;
      this._clients.delete(client);
      if (sock && !sock.destroyed) {
        try {
          if (sock.writable) {
            sock.write(closeFrame);
          }
          sock.end();
        } catch (err) {
          void err;
        }
        try {
          sock.destroy();
        } catch (destroyErr) {
          void destroyErr;
        }
      }
    }
  }
}

export function createWebSocketServer(os, options = {}) {
  return new OmniWebSocketServer(os, options);
}
