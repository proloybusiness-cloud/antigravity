/**
 * OmniOS Inter-Process Communication Manager (`IPCManager`)
 * - Prototype-safe named channels / pipes (`createChannel`, `closeChannel`, `send`, `recv`, `subscribe`, `listChannels`)
 * - Request/Reply RPC (`registerRpc`, `unregisterRpc`, `callRpc`, plus channel `request`/`reply`)
 *   with `.unref()` timeout timers and zero unhandled promise rejections
 * - Shared Memory (`shmCreate`, `shmAttach`, `shmDetach`, `shmRead`, `shmWrite`, `shmDestroy`, `shmStat`, `listShm`)
 *   with overflow-safe bounds checks (`ERANGE`), `byteOffset`-safe views, `.slice()` defensive reads,
 *   read-only `EACCES` enforcement, and zero-fill destroy
 * - Dual-hook automatic process resource cleanup (`eventBus.on('process:exited')` + `processManager.addCleanupHook`)
 */

import { types } from 'node:util';
import {
  OmniOSError,
  QuotaExceededError,
  SecurityError,
  ERROR_CODES,
} from '../common/errors.mjs';

export const DEFAULT_MAX_QUEUE_SIZE = 1024;
export const DEFAULT_RPC_TIMEOUT_MS = 5000;
export const DEFAULT_MAX_SHM_SIZE = 16 * 1024 * 1024; // 16 MiB
export const DEFAULT_MAX_TOTAL_SHM_BYTES = 64 * 1024 * 1024; // 64 MiB

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8');

const AB_BYTE_LENGTH = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const AB_DETACHED = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'detached')?.get ?? null;
const TYPED_ARRAY_CTOR = Object.getPrototypeOf(Uint8Array);
const TYPED_ARRAY_PROTO = TYPED_ARRAY_CTOR.prototype;
const TA_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'buffer').get;
const TA_BYTE_OFFSET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteOffset').get;
const TA_BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteLength').get;
const DV_BUFFER = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
const DV_BYTE_OFFSET = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get;
const DV_BYTE_LENGTH = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;
const SET_SIZE_GET = Object.getOwnPropertyDescriptor(Set.prototype, 'size').get;
const SYMBOL_DESCRIPTION_GET = Object.getOwnPropertyDescriptor(Symbol.prototype, 'description')?.get ?? null;

function extractGenuineBytes(val) {
  if (val === null || val === undefined || typeof val !== 'object') {
    return { ok: false, detached: false };
  }
  try {
    if (types.isTypedArray(val) && !types.isProxy(val)) {
      const buf = TA_BUFFER.call(val);
      if (types.isArrayBuffer(buf) && AB_DETACHED && AB_DETACHED.call(buf)) {
        return { ok: false, detached: true };
      }
      const byteOffset = TA_BYTE_OFFSET.call(val);
      const byteLength = TA_BYTE_LENGTH.call(val);
      return { ok: true, bytes: new Uint8Array(buf, byteOffset, byteLength) };
    }
    if (types.isDataView(val) && !types.isProxy(val)) {
      const buf = DV_BUFFER.call(val);
      if (types.isArrayBuffer(buf) && AB_DETACHED && AB_DETACHED.call(buf)) {
        return { ok: false, detached: true };
      }
      const byteOffset = DV_BYTE_OFFSET.call(val);
      const byteLength = DV_BYTE_LENGTH.call(val);
      return { ok: true, bytes: new Uint8Array(buf, byteOffset, byteLength) };
    }
    if (types.isArrayBuffer(val) && !types.isProxy(val)) {
      if (AB_DETACHED && AB_DETACHED.call(val)) {
        return { ok: false, detached: true };
      }
      const byteLength = AB_BYTE_LENGTH.call(val);
      return { ok: true, bytes: new Uint8Array(val, 0, byteLength) };
    }
  } catch {
    return { ok: false, detached: false };
  }
  return { ok: false, detached: false };
}

function defineSafeProp(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

function validateNonEmptyName(value, label, maxLen = 256) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLen || value.includes('\0')) {
    throw new OmniOSError(`Invalid ${label}: must be a non-empty string (<= ${maxLen} chars, no NUL)`, {
      code: ERROR_CODES.EINVAL,
      details: { label },
    });
  }
  return value;
}

function validatePid(pid, label = 'pid') {
  if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 0) {
    throw new OmniOSError(`Invalid ${label}: must be a non-negative safe integer`, {
      code: ERROR_CODES.EINVAL,
      details: { label, value: pid },
    });
  }
  return pid;
}

const MAX_TIMEOUT_MS = 2_147_483_647;

function validateTimeoutMs(timeoutMs) {
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new OmniOSError(`Invalid timeoutMs: must be a positive finite number`, {
      code: ERROR_CODES.EINVAL,
      details: { timeoutMs },
    });
  }
  return Math.min(timeoutMs, MAX_TIMEOUT_MS);
}

const MAX_CLONE_ARRAY_LEN = 100_000;
const MAX_CLONE_NODES = 250_000;
export const MAX_IPC_PAYLOAD_BYTES = 4 * 1024 * 1024; // 4 MiB
const MAX_CLONE_BIGINT_ABS = 1n << 4096n;
const MAX_DISPLAY_LENGTH = 256;

function capDisplayString(str) {
  if (str.length > 65_536) return `[String(${str.length})]`;
  return str.length > MAX_DISPLAY_LENGTH ? `${str.slice(0, MAX_DISPLAY_LENGTH)}...` : str;
}

function safeDisplayValue(val) {
  if (val === null) return 'null';
  if (val === undefined) return 'undefined';
  const t = typeof val;
  if (t === 'string') return capDisplayString(val);
  if (t === 'number' || t === 'boolean') return String(val);
  if (t === 'bigint') {
    if (val > MAX_CLONE_BIGINT_ABS || val < -MAX_CLONE_BIGINT_ABS) {
      return '[BigInt(out-of-range)]';
    }
    return capDisplayString(val.toString(10));
  }
  if (t === 'symbol') {
    try {
      const desc = SYMBOL_DESCRIPTION_GET ? SYMBOL_DESCRIPTION_GET.call(val) : val.description;
      return desc === undefined ? 'Symbol()' : `Symbol(${capDisplayString(desc)})`;
    } catch {
      return 'Symbol()';
    }
  }
  if (t === 'function') return '[Function]';
  try {
    return Array.isArray(val) ? '[Array]' : '[Object]';
  } catch {
    return '[Unreadable]';
  }
}

function safeErrorMessage(err) {
  if (err === null || err === undefined) return 'Unknown error';
  if (typeof err === 'string') return capDisplayString(err);
  if (typeof err === 'object') {
    try {
      const msg = err.message;
      if (typeof msg === 'string' && msg.length > 0) return capDisplayString(msg);
      if (msg !== undefined && msg !== '') return safeDisplayValue(msg);
    } catch {
      // Hostile getter on err.message
    }
    try {
      const name = err.name;
      if (typeof name === 'string' && name.length > 0) return capDisplayString(name);
    } catch {
      // Hostile getter on err.name
    }
    return safeDisplayValue(err);
  }
  return safeDisplayValue(err);
}

function safeErrorCode(err, fallback = ERROR_CODES.E_OMNIOS) {
  if (err === null || err === undefined) return fallback;
  try {
    const code = err.code;
    if (typeof code === 'string' && code.length > 0) return code;
  } catch {
    // Hostile getter on err.code
  }
  return fallback;
}

function consumeIpcBytes(budget, delta) {
  if (delta > budget.remainingBytes) {
    const limit = budget.limitBytes ?? MAX_IPC_PAYLOAD_BYTES;
    throw new QuotaExceededError(`IPC payload exceeds maximum byte budget (${limit} bytes)`, {
      code: ERROR_CODES.EFBIG,
      quotaType: 'ipcPayloadBytes',
      limit,
      actual: limit - budget.remainingBytes + delta,
    });
  }
  budget.remainingBytes -= delta;
}

function safeGetProp(obj, key, label) {
  try {
    return obj[key];
  } catch (err) {
    throw new OmniOSError(`Unreadable ${label} property "${key}"`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
}

function normalizeReadableOptions(opts, label) {
  if (opts === undefined || opts === null) return {};
  let isArr = false;
  try {
    isArr = Array.isArray(opts);
  } catch (err) {
    throw new OmniOSError(`${label} must be a readable plain object`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (typeof opts !== 'object' || isArr) {
    throw new OmniOSError(`${label} must be a plain object`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  return opts;
}

function isOmniOSError(err) {
  try {
    return err instanceof OmniOSError;
  } catch {
    return false;
  }
}

function isErrorInstance(err) {
  try {
    return err instanceof Error;
  } catch {
    return false;
  }
}

function hasProxyInPrototypeChain(obj) {
  let cur = obj;
  let hops = 0;
  while (cur !== null && cur !== undefined) {
    if (++hops > 64) return true;
    if (types.isProxy(cur)) return true;
    try {
      cur = Object.getPrototypeOf(cur);
    } catch {
      return true;
    }
  }
  return false;
}

function hasAccessorProperty(obj, prop) {
  let cur = obj;
  let hops = 0;
  while (cur !== null && cur !== undefined) {
    if (++hops > 64) return true;
    if (types.isProxy(cur)) return true;
    let desc;
    try {
      desc = Object.getOwnPropertyDescriptor(cur, prop);
    } catch {
      return true;
    }
    if (desc !== undefined) {
      return Boolean(desc.get || desc.set);
    }
    try {
      cur = Object.getPrototypeOf(cur);
    } catch {
      return true;
    }
  }
  return false;
}

function isSafeOmniOSError(err) {
  if (!isOmniOSError(err)) return false;
  try {
    if (types.isProxy(err) || hasProxyInPrototypeChain(err)) return false;
    if (
      hasAccessorProperty(err, 'message') ||
      hasAccessorProperty(err, 'code') ||
      hasAccessorProperty(err, 'name')
    ) {
      return false;
    }
    const msg = err.message;
    const code = err.code;
    const name = err.name;
    return typeof msg === 'string' && typeof code === 'string' && typeof name === 'string';
  } catch {
    return false;
  }
}

function normalizeIpcError(err, fallbackMessage = 'IPC error') {
  if (isSafeOmniOSError(err)) {
    return err;
  }
  try {
    const msg = safeErrorMessage(err);
    const code = safeErrorCode(err, ERROR_CODES.E_OMNIOS);
    let safeCause;
    if (isErrorInstance(err)) {
      try {
        if (
          !types.isProxy(err) &&
          !hasProxyInPrototypeChain(err) &&
          !hasAccessorProperty(err, 'message') &&
          !hasAccessorProperty(err, 'code') &&
          !hasAccessorProperty(err, 'name')
        ) {
          safeCause = err;
        }
      } catch {
        safeCause = undefined;
      }
    }
    return new OmniOSError(msg || fallbackMessage, {
      code,
      cause: safeCause,
    });
  } catch {
    return new OmniOSError(fallbackMessage, {
      code: ERROR_CODES.E_OMNIOS,
    });
  }
}

function suppressAsyncRejection(value, onError = null) {
  if (value === null || value === undefined) return;
  if (typeof value !== 'object' && typeof value !== 'function') return;
  const handler = (err) => {
    if (typeof onError === 'function') {
      try {
        onError(err);
      } catch {
        // Never allow error reporter to throw unhandled.
      }
    }
  };
  try {
    if (types.isPromise(value)) {
      Promise.prototype.then.call(value, undefined, handler);
      return;
    }
  } catch {
    // Fall through to guarded thenable check.
  }
  try {
    const thenFn = value.then;
    if (typeof thenFn === 'function') {
      thenFn.call(value, undefined, handler);
    }
  } catch {
    // Ignore hostile thenable getters/methods.
  }
}

function isThenableValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value !== 'object' && typeof value !== 'function') return false;
  try {
    if (types.isPromise(value)) return true;
  } catch {
    // Fall through.
  }
  try {
    return typeof value.then === 'function';
  } catch {
    return false;
  }
}

function safeCloneIpcPayload(
  value,
  ancestors = new Set(),
  depth = 0,
  budget = { remaining: MAX_CLONE_NODES, remainingBytes: MAX_IPC_PAYLOAD_BYTES, limitBytes: MAX_IPC_PAYLOAD_BYTES }
) {
  if (depth > 64) {
    throw new OmniOSError('IPC payload exceeds maximum nesting depth', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (value === null || value === undefined) {
    consumeIpcBytes(budget, 2);
    return value;
  }
  const t = typeof value;
  if (t === 'boolean' || t === 'number') {
    consumeIpcBytes(budget, 4);
    return value;
  }
  if (t === 'string') {
    consumeIpcBytes(budget, value.length + 2);
    return value;
  }
  if (t === 'bigint') {
    if (value > MAX_CLONE_BIGINT_ABS || value < -MAX_CLONE_BIGINT_ABS) {
      throw new QuotaExceededError('IPC payload BigInt exceeds maximum magnitude', {
        code: ERROR_CODES.EFBIG,
        quotaType: 'ipcPayloadBytes',
        limit: budget.limitBytes ?? MAX_IPC_PAYLOAD_BYTES,
      });
    }
    const approxBytes =
      value > 0xffffffffffffffffn || value < -0xffffffffffffffffn
        ? Math.ceil(value.toString(16).length / 2) + 8
        : 16;
    consumeIpcBytes(budget, approxBytes);
    return value;
  }
  if (t === 'function' || t === 'symbol') {
    throw new OmniOSError(`Unsupported IPC payload type: ${t}`, {
      code: ERROR_CODES.EINVAL,
    });
  }

  // Check Array.isArray FIRST (in its own try/catch) BEFORE any instanceof or Proxy check so
  // Proxy-wrapped Arrays with throwing getPrototypeOf traps are preserved as Arrays.
  let isArr = false;
  try {
    isArr = Array.isArray(value);
  } catch (err) {
    throw new OmniOSError('Unreadable IPC payload object', {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }

  if (isArr) {
    if (ancestors.has(value)) {
      throw new OmniOSError('Cyclic reference in IPC payload', {
        code: ERROR_CODES.EINVAL,
      });
    }
    ancestors.add(value);
    try {
      let len;
      try {
        len = value.length;
      } catch (err) {
        throw new OmniOSError('Unreadable IPC payload array length', {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
      if (
        typeof len !== 'number' ||
        !Number.isSafeInteger(len) ||
        len < 0 ||
        len > 0xffffffff ||
        len > MAX_CLONE_ARRAY_LEN ||
        len > budget.remaining
      ) {
        throw new OmniOSError('Invalid IPC payload array length', {
          code: ERROR_CODES.EINVAL,
        });
      }
      consumeIpcBytes(budget, 16);
      if (len * 2 > budget.remainingBytes) {
        consumeIpcBytes(budget, len * 2);
      }
      const arr = [];
      for (let i = 0; i < len; i++) {
        if (budget.remaining <= 0) {
          throw new OmniOSError('IPC payload exceeds maximum element count', {
            code: ERROR_CODES.EINVAL,
          });
        }
        budget.remaining -= 1;
        let elem;
        try {
          elem = value[i];
        } catch (err) {
          throw new OmniOSError(`Unreadable IPC payload array index ${i}`, {
            code: ERROR_CODES.EINVAL,
            cause: isErrorInstance(err) ? err : undefined,
          });
        }
        arr.push(safeCloneIpcPayload(elem, ancestors, depth + 1, budget));
      }
      return arr;
    } finally {
      ancestors.delete(value);
    }
  }

  if (types.isDate(value) && !types.isProxy(value)) {
    consumeIpcBytes(budget, 24);
    try {
      return new Date(Date.prototype.getTime.call(value));
    } catch (err) {
      throw new OmniOSError('Unreadable Date IPC payload', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
  }

  const bin = extractGenuineBytes(value);
  if (bin.detached) {
    throw new OmniOSError('Unreadable detached binary IPC payload', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (bin.ok) {
    consumeIpcBytes(budget, Math.max(128, bin.bytes.byteLength));
    try {
      return bin.bytes.slice();
    } catch (err) {
      throw new OmniOSError('Unreadable binary IPC payload', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
  }

  if (
    types.isProxy(value) ||
    types.isBoxedPrimitive(value) ||
    types.isSharedArrayBuffer?.(value)
  ) {
    throw new OmniOSError('Proxied, boxed primitive, or SharedArrayBuffer IPC payload is not allowed', {
      code: ERROR_CODES.EINVAL,
    });
  }

  let isSpoofedSpecial = false;
  try {
    isSpoofedSpecial =
      value instanceof ArrayBuffer ||
      value instanceof Date ||
      value instanceof TYPED_ARRAY_CTOR ||
      value instanceof DataView ||
      (typeof SharedArrayBuffer === 'function' && value instanceof SharedArrayBuffer) ||
      ArrayBuffer.isView(value);
  } catch (err) {
    throw new OmniOSError('Unreadable IPC payload object', {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (isSpoofedSpecial) {
    throw new OmniOSError('Spoofed or proxied binary/Date IPC payload is not allowed', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (ancestors.has(value)) {
    throw new OmniOSError('Cyclic reference in IPC payload', {
      code: ERROR_CODES.EINVAL,
    });
  }
  ancestors.add(value);
  try {
    const out = {};
    let keys;
    try {
      keys = Object.keys(value);
    } catch (err) {
      throw new OmniOSError('Unreadable IPC payload object keys', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (keys.length > MAX_CLONE_ARRAY_LEN || keys.length > budget.remaining) {
      throw new OmniOSError('IPC payload object exceeds maximum key count', {
        code: ERROR_CODES.EINVAL,
      });
    }
    consumeIpcBytes(budget, 16);
    if (keys.length * 2 > budget.remainingBytes) {
      consumeIpcBytes(budget, keys.length * 2);
    }
    for (const key of keys) {
      if (budget.remaining <= 0) {
        throw new OmniOSError('IPC payload exceeds maximum element count', {
          code: ERROR_CODES.EINVAL,
        });
      }
      budget.remaining -= 1;
      consumeIpcBytes(budget, key.length + 4);
      let propVal;
      try {
        propVal = value[key];
      } catch (err) {
        throw new OmniOSError(`Unreadable IPC payload property "${safeDisplayValue(key)}"`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
      defineSafeProp(out, key, safeCloneIpcPayload(propVal, ancestors, depth + 1, budget));
    }
    return out;
  } finally {
    ancestors.delete(value);
  }
}

function toShmBytes(input) {
  if (typeof input === 'string') {
    return TEXT_ENCODER.encode(input);
  }
  const bin = extractGenuineBytes(input);
  if (bin.detached) {
    throw new OmniOSError('Unreadable detached SHM write data', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (bin.ok) {
    return bin.bytes;
  }
  throw new OmniOSError('SHM write data must be Uint8Array, ArrayBuffer, ArrayBufferView, or string', {
    code: ERROR_CODES.EINVAL,
  });
}

export class IPCManager {
  constructor(opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'IPCManager options');
    const kernel = safeGetProp(optsObj, 'kernel', 'IPCManager options') ?? null;
    const rawEventBus = safeGetProp(optsObj, 'eventBus', 'IPCManager options');
    const rawProcessManager = safeGetProp(optsObj, 'processManager', 'IPCManager options');
    const log = safeGetProp(optsObj, 'log', 'IPCManager options');
    const rawMaxQueueSize = safeGetProp(optsObj, 'maxQueueSize', 'IPCManager options');
    const rawDefaultRpcTimeoutMs = safeGetProp(optsObj, 'defaultRpcTimeoutMs', 'IPCManager options');
    const rawMaxShmSize = safeGetProp(optsObj, 'maxShmSize', 'IPCManager options');
    const rawMaxTotalShmBytes = safeGetProp(optsObj, 'maxTotalShmBytes', 'IPCManager options');

    if (kernel !== null && typeof kernel !== 'object') {
      throw new OmniOSError('IPCManager kernel must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const kernelBus = kernel ? (safeGetProp(kernel, 'eventBus', 'IPCManager kernel') ?? null) : null;
    const kernelPm = kernel ? (safeGetProp(kernel, 'processManager', 'IPCManager kernel') ?? null) : null;
    const eventBus = rawEventBus !== undefined ? rawEventBus : kernelBus;
    const processManager = rawProcessManager !== undefined ? rawProcessManager : kernelPm;

    if (eventBus !== null) {
      if (typeof eventBus !== 'object') {
        throw new OmniOSError('IPCManager eventBus must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(eventBus, 'on', 'IPCManager eventBus');
      safeGetProp(eventBus, 'emit', 'IPCManager eventBus');
    }
    if (processManager !== null) {
      if (typeof processManager !== 'object') {
        throw new OmniOSError('IPCManager processManager must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(processManager, 'has', 'IPCManager processManager');
      safeGetProp(processManager, 'addCleanupHook', 'IPCManager processManager');
    }

    const maxQueueSize = rawMaxQueueSize !== undefined ? rawMaxQueueSize : DEFAULT_MAX_QUEUE_SIZE;
    const defaultRpcTimeoutMs =
      rawDefaultRpcTimeoutMs !== undefined ? rawDefaultRpcTimeoutMs : DEFAULT_RPC_TIMEOUT_MS;
    const maxShmSize = rawMaxShmSize !== undefined ? rawMaxShmSize : DEFAULT_MAX_SHM_SIZE;
    const maxTotalShmBytes =
      rawMaxTotalShmBytes !== undefined ? rawMaxTotalShmBytes : DEFAULT_MAX_TOTAL_SHM_BYTES;

    this._eventBus = eventBus;
    this._processManager = processManager;
    this._log = typeof log === 'function' ? log : () => {};
    this._maxQueueSize = Number.isSafeInteger(maxQueueSize) && maxQueueSize >= 1 ? maxQueueSize : DEFAULT_MAX_QUEUE_SIZE;
    this._defaultRpcTimeoutMs =
      typeof defaultRpcTimeoutMs === 'number' && Number.isFinite(defaultRpcTimeoutMs) && defaultRpcTimeoutMs > 0
        ? Math.min(defaultRpcTimeoutMs, MAX_TIMEOUT_MS)
        : DEFAULT_RPC_TIMEOUT_MS;
    this._maxShmSize = Number.isSafeInteger(maxShmSize) && maxShmSize > 0 ? maxShmSize : DEFAULT_MAX_SHM_SIZE;
    this._maxTotalShmBytes =
      Number.isSafeInteger(maxTotalShmBytes) && maxTotalShmBytes > 0 ? maxTotalShmBytes : DEFAULT_MAX_TOTAL_SHM_BYTES;

    // Prototype-safe internal registries
    this._channels = new Map();
    this._rpcs = new Map();
    this._pendingRequests = new Map();
    this._shmById = new Map();
    this._shmByName = new Map();
    this._hookedPids = new Set();

    this._totalShmBytes = 0;
    this._msgSeq = 0;
    this._rpcSeq = 0;
    this._shmSeq = 0;
    this._unsubProcessExit = null;
    this._started = false;

    this.start();
  }

  start() {
    if (this._started) return;
    if (this._eventBus && !this._unsubProcessExit) {
      const onFn = safeGetProp(this._eventBus, 'on', 'IPCManager eventBus');
      if (typeof onFn === 'function') {
        try {
          this._unsubProcessExit = onFn.call(this._eventBus, 'process:exited', (evt) => {
            if (evt && typeof evt.pid === 'number') {
              this.cleanupProcess(evt.pid);
            }
          });
        } catch (err) {
          if (isSafeOmniOSError(err)) throw err;
          throw new OmniOSError(`IPCManager failed to subscribe to eventBus: ${safeErrorMessage(err)}`, {
            code: ERROR_CODES.EINVAL,
            cause: isErrorInstance(err) ? err : undefined,
          });
        }
      }
    }
    this._started = true;
  }

  stop() {
    this._started = false;
    if (this._unsubProcessExit) {
      try {
        this._unsubProcessExit();
      } catch {
        // Ignore unsubscribe failure.
      }
      this._unsubProcessExit = null;
    }

    const stopErr = new OmniOSError('IPCManager stopped', { code: ERROR_CODES.EPIPE });
    for (const [corrId, pending] of Array.from(this._pendingRequests.entries())) {
      this._rejectPending(corrId, pending, stopErr);
    }

    for (const seg of this._shmById.values()) {
      seg.buffer.fill(0);
    }
    this._shmById.clear();
    this._shmByName.clear();
    this._totalShmBytes = 0;
    this._channels.clear();
    this._rpcs.clear();
    this._hookedPids.clear();
  }

  dispose() {
    this.stop();
  }

  isRunning() {
    return this._started;
  }

  _emit(event, payload) {
    if (!this._eventBus) return;
    try {
      this._eventBus.emit(event, payload);
    } catch {
      // Never allow event listeners to break IPC operations.
    }
  }

  _hookProcessCleanup(pid) {
    if (!this._processManager || typeof pid !== 'number' || pid <= 0) return;
    if (this._hookedPids.has(pid)) return;
    let added = false;
    try {
      const hasFn = this._processManager.has;
      if (typeof hasFn === 'function' && !hasFn.call(this._processManager, pid)) return;
      const addHookFn = this._processManager.addCleanupHook;
      if (typeof addHookFn !== 'function') return;
      this._hookedPids.add(pid);
      added = true;
      addHookFn.call(this._processManager, pid, () => {
        this.cleanupProcess(pid);
      });
    } catch {
      // Isolate revoked or unavailable ProcessManager during optional cleanup-hook registration.
      if (added) {
        this._hookedPids.delete(pid);
      }
    }
  }

  _channelSummary(ch) {
    return {
      name: ch.name,
      ownerPid: ch.ownerPid,
      queueSize: ch.queue.length,
      maxQueueSize: ch.maxQueueSize,
      subscriberCount: ch.subscribers.size,
      persistent: ch.persistent,
      createdAt: ch.createdAt,
    };
  }

  _checkChannelAccess(ch, pid) {
    if (!ch.allowedPids) return;
    if (pid === null || pid === undefined || pid === 0 || pid === ch.ownerPid) return;
    if (!ch.allowedPids.has(pid)) {
      throw new SecurityError(`PID ${pid} is not permitted to access IPC channel "${ch.name}"`, {
        code: ERROR_CODES.EACCES,
        pid,
        details: { channel: ch.name },
      });
    }
  }

  _rejectPending(correlationId, pending, error) {
    if (!pending || pending.settled) return;
    pending.settled = true;
    this._pendingRequests.delete(correlationId);
    if (pending.timer) {
      clearTimeout(pending.timer);
      pending.timer = null;
    }
    pending.reject(error);
  }

  _resolvePending(correlationId, pending, value) {
    if (!pending || pending.settled) return;
    pending.settled = true;
    this._pendingRequests.delete(correlationId);
    if (pending.timer) {
      clearTimeout(pending.timer);
      pending.timer = null;
    }
    pending.resolve(value);
  }

  // -------------------------------------------------------------------------
  // Named Channels / Pipes
  // -------------------------------------------------------------------------

  createChannel(name, ownerPid = 0, opts = {}) {
    validateNonEmptyName(name, 'channel name');
    validatePid(ownerPid, 'ownerPid');

    const optsObj = normalizeReadableOptions(opts, 'createChannel options');
    const rawMaxQueueSize = safeGetProp(optsObj, 'maxQueueSize', 'createChannel options');
    const rawPersistent = safeGetProp(optsObj, 'persistent', 'createChannel options');
    const rawAllowedPids = safeGetProp(optsObj, 'allowedPids', 'createChannel options');
    const maxQueueSize = rawMaxQueueSize !== undefined ? rawMaxQueueSize : this._maxQueueSize;
    const persistent = rawPersistent !== undefined ? rawPersistent : false;
    const allowedPids = rawAllowedPids !== undefined ? rawAllowedPids : null;

    if (!Number.isSafeInteger(maxQueueSize) || maxQueueSize < 1) {
      throw new OmniOSError('Channel maxQueueSize must be a positive safe integer', {
        code: ERROR_CODES.EINVAL,
        details: { maxQueueSize },
      });
    }
    if (this._channels.has(name)) {
      throw new OmniOSError(`IPC channel already exists: ${name}`, {
        code: ERROR_CODES.EEXIST,
        details: { name },
      });
    }

    let allowedSet = null;
    if (allowedPids !== null && allowedPids !== undefined) {
      let isArr = false;
      let isSet = false;
      try {
        isArr = Array.isArray(allowedPids);
      } catch {
        throw new OmniOSError('allowedPids must be a readable Array, Set, or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (!isArr) {
        isSet = types.isSet(allowedPids) && !types.isProxy(allowedPids);
      }
      if (!isArr && !isSet) {
        throw new OmniOSError('allowedPids must be an Array, Set, or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      allowedSet = new Set();
      if (isArr) {
        let len;
        try {
          len = allowedPids.length;
        } catch (err) {
          throw new OmniOSError('Unreadable allowedPids array length', {
            code: ERROR_CODES.EINVAL,
            cause: isErrorInstance(err) ? err : undefined,
          });
        }
        if (
          typeof len !== 'number' ||
          !Number.isSafeInteger(len) ||
          len < 0 ||
          len > 0xffffffff ||
          len > MAX_CLONE_ARRAY_LEN
        ) {
          throw new OmniOSError('Invalid allowedPids array length', {
            code: ERROR_CODES.EINVAL,
          });
        }
        for (let i = 0; i < len; i++) {
          let p;
          try {
            p = allowedPids[i];
          } catch (err) {
            throw new OmniOSError(`Unreadable allowedPids entry at index ${i}`, {
              code: ERROR_CODES.EINVAL,
              cause: isErrorInstance(err) ? err : undefined,
            });
          }
          allowedSet.add(validatePid(p, 'allowedPid'));
        }
      } else {
        try {
          const setSize = SET_SIZE_GET.call(allowedPids);
          if (setSize > MAX_CLONE_ARRAY_LEN) {
            throw new OmniOSError('allowedPids Set exceeds maximum length', {
              code: ERROR_CODES.EINVAL,
            });
          }
          for (const p of Set.prototype.values.call(allowedPids)) {
            allowedSet.add(validatePid(p, 'allowedPid'));
          }
        } catch (err) {
          if (isSafeOmniOSError(err)) throw err;
          throw new OmniOSError('Unreadable allowedPids collection', {
            code: ERROR_CODES.EINVAL,
            cause: isErrorInstance(err) ? err : undefined,
          });
        }
      }
    }

    const ch = {
      name,
      ownerPid,
      maxQueueSize,
      persistent: Boolean(persistent),
      allowedPids: allowedSet,
      queue: [],
      subscribers: new Set(),
      createdAt: new Date().toISOString(),
    };

    this._channels.set(name, ch);
    this._hookProcessCleanup(ownerPid);
    this._emit('ipc:channel_created', { name, ownerPid });
    return this._channelSummary(ch);
  }

  closeChannel(name, requesterPid = null) {
    const ch = this._channels.get(name);
    if (!ch) return false;

    if (requesterPid !== null && requesterPid !== undefined) {
      validatePid(requesterPid, 'requesterPid');
      if (requesterPid !== 0 && ch.ownerPid !== 0 && requesterPid !== ch.ownerPid) {
        throw new SecurityError(`PID ${requesterPid} cannot close channel "${name}" owned by PID ${ch.ownerPid}`, {
          code: ERROR_CODES.EPERM,
          pid: requesterPid,
          details: { channel: name, ownerPid: ch.ownerPid },
        });
      }
    }

    this._channels.delete(name);
    const closedErr = new OmniOSError(`IPC channel closed: ${name}`, {
      code: ERROR_CODES.EPIPE,
      details: { channel: name },
    });
    for (const [corrId, pending] of Array.from(this._pendingRequests.entries())) {
      if (pending.channelName === name) {
        this._rejectPending(corrId, pending, closedErr);
      }
    }

    this._emit('ipc:channel_closed', { name, ownerPid: ch.ownerPid });
    return true;
  }

  send(channelName, fromPid = 0, payload = null, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'send options');
    const rawType = safeGetProp(optsObj, 'type', 'send options');
    const correlationId = safeGetProp(optsObj, 'correlationId', 'send options') ?? null;
    const replyTo = safeGetProp(optsObj, 'replyTo', 'send options') ?? null;
    const meta = safeGetProp(optsObj, 'meta', 'send options') ?? null;
    const type = rawType !== undefined ? rawType : 'message';

    const ch = this._channels.get(channelName);
    if (!ch) {
      throw new OmniOSError(`IPC channel not found: ${safeDisplayValue(channelName)}`, {
        code: ERROR_CODES.ENOENT,
        details: { channel: safeDisplayValue(channelName) },
      });
    }
    validatePid(fromPid, 'fromPid');
    this._checkChannelAccess(ch, fromPid);

    // Validate & deep-clone ALL envelope fields under a shared budget at depth=1 strictly
    // BEFORE checking queue quota, incrementing _msgSeq, mutating ch.queue, notifying
    // subscribers, or emitting ipc:message (guarantees zero queue poisoning & zero mutability leaks).
    const safeType = typeof type === 'string' && type.length > 0 ? type : 'message';
    if (safeType.length > 4096) {
      throw new OmniOSError('IPC message type exceeds maximum length (4096 chars)', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const envelopeOverhead = channelName.length + safeType.length + 1024;
    const cloneBudget = {
      remaining: MAX_CLONE_NODES - 32,
      remainingBytes: Math.max(0, MAX_IPC_PAYLOAD_BYTES - envelopeOverhead),
      limitBytes: MAX_IPC_PAYLOAD_BYTES,
    };
    const clonedPayload = safeCloneIpcPayload(payload, new Set(), 1, cloneBudget);
    const clonedMeta =
      meta !== null && meta !== undefined
        ? safeCloneIpcPayload(meta, new Set(), 1, cloneBudget)
        : null;
    const clonedCorrelationId =
      correlationId !== null && correlationId !== undefined
        ? safeCloneIpcPayload(correlationId, new Set(), 1, cloneBudget)
        : null;
    const clonedReplyTo =
      replyTo !== null && replyTo !== undefined
        ? safeCloneIpcPayload(replyTo, new Set(), 1, cloneBudget)
        : null;

    if (ch.subscribers.size === 0 && ch.queue.length >= ch.maxQueueSize) {
      throw new QuotaExceededError(`IPC channel "${channelName}" queue full (${ch.maxQueueSize})`, {
        code: ERROR_CODES.EQUOTA,
        quotaType: 'ipcQueue',
        limit: ch.maxQueueSize,
        actual: ch.queue.length,
        pid: fromPid,
        details: { channel: channelName },
      });
    }

    const envelope = {
      id: ++this._msgSeq,
      channel: channelName,
      fromPid,
      type: safeType,
      correlationId: clonedCorrelationId,
      replyTo: clonedReplyTo,
      payload: clonedPayload,
      meta: clonedMeta,
      ts: new Date().toISOString(),
    };

    if (ch.subscribers.size === 0) {
      ch.queue.push(envelope);
    } else {
      if (ch.queue.length >= ch.maxQueueSize) {
        ch.queue.shift();
      }
      ch.queue.push(envelope);

      const subs = Array.from(ch.subscribers);
      for (const sub of subs) {
        try {
          const ret = sub.fn(safeCloneIpcPayload(envelope));
          suppressAsyncRejection(ret, (err) => {
            try {
              this._log(
                'warn',
                'ipc',
                `Async channel subscriber error on "${channelName}": ${safeErrorMessage(err)}`
              );
            } catch {
              // Isolate logger failures.
            }
          });
        } catch (err) {
          try {
            this._log(
              'warn',
              'ipc',
              `Channel subscriber error on "${channelName}": ${safeErrorMessage(err)}`
            );
          } catch {
            // Isolate logger failures.
          }
        }
      }
    }

    this._emit('ipc:message', {
      id: envelope.id,
      channel: channelName,
      fromPid,
      type: envelope.type,
    });

    return safeCloneIpcPayload(envelope);
  }

  recv(channelName, pid = null, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'recv options');
    const peek = Boolean(safeGetProp(optsObj, 'peek', 'recv options'));
    const ch = this._channels.get(channelName);
    if (!ch) {
      throw new OmniOSError(`IPC channel not found: ${safeDisplayValue(channelName)}`, {
        code: ERROR_CODES.ENOENT,
        details: { channel: safeDisplayValue(channelName) },
      });
    }
    if (pid !== null && pid !== undefined) {
      validatePid(pid, 'pid');
      this._checkChannelAccess(ch, pid);
    }
    if (ch.queue.length === 0) return null;
    const envelope = peek ? ch.queue[0] : ch.queue.shift();
    return safeCloneIpcPayload(envelope);
  }

  subscribe(channelName, fn, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'subscribe options');
    const pid = safeGetProp(optsObj, 'pid', 'subscribe options') ?? null;
    const ch = this._channels.get(channelName);
    if (!ch) {
      throw new OmniOSError(`IPC channel not found: ${safeDisplayValue(channelName)}`, {
        code: ERROR_CODES.ENOENT,
        details: { channel: safeDisplayValue(channelName) },
      });
    }
    if (typeof fn !== 'function') {
      throw new OmniOSError('Channel subscriber must be a function', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (pid !== null && pid !== undefined) {
      validatePid(pid, 'pid');
      this._checkChannelAccess(ch, pid);
      this._hookProcessCleanup(pid);
    }

    const entry = { fn, pid: pid ?? null };
    ch.subscribers.add(entry);

    let active = true;
    return () => {
      if (!active) return;
      active = false;
      ch.subscribers.delete(entry);
    };
  }

  listChannels(opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'listChannels options');
    const ownerPid = safeGetProp(optsObj, 'ownerPid', 'listChannels options');
    const result = [];
    for (const ch of this._channels.values()) {
      if (ownerPid !== undefined && ch.ownerPid !== ownerPid) continue;
      result.push(this._channelSummary(ch));
    }
    return result;
  }

  // -------------------------------------------------------------------------
  // Request / Reply RPC (Direct Endpoints & Channel Request/Reply)
  // -------------------------------------------------------------------------

  registerRpc(endpoint, handler, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'registerRpc options');
    const rawOwnerPid = safeGetProp(optsObj, 'ownerPid', 'registerRpc options');
    const rawOverwrite = safeGetProp(optsObj, 'overwrite', 'registerRpc options');
    const ownerPid = rawOwnerPid !== undefined ? rawOwnerPid : 0;
    const overwrite = Boolean(rawOverwrite);

    validateNonEmptyName(endpoint, 'RPC endpoint');
    if (typeof handler !== 'function') {
      throw new OmniOSError('RPC handler must be a function', {
        code: ERROR_CODES.EINVAL,
      });
    }
    validatePid(ownerPid, 'ownerPid');

    if (this._rpcs.has(endpoint) && !overwrite) {
      throw new OmniOSError(`RPC endpoint already registered: ${endpoint}`, {
        code: ERROR_CODES.EEXIST,
        details: { endpoint },
      });
    }

    const record = { endpoint, handler, ownerPid };
    this._rpcs.set(endpoint, record);
    this._hookProcessCleanup(ownerPid);

    return () => this.unregisterRpc(endpoint);
  }

  unregisterRpc(endpoint) {
    const existing = this._rpcs.get(endpoint);
    if (!existing) return false;
    this._rpcs.delete(endpoint);

    const pipeErr = new OmniOSError(`RPC endpoint unregistered: ${endpoint}`, {
      code: ERROR_CODES.EPIPE,
      details: { endpoint },
    });
    for (const [corrId, pending] of Array.from(this._pendingRequests.entries())) {
      if (pending.endpoint === endpoint) {
        this._rejectPending(corrId, pending, pipeErr);
      }
    }
    return true;
  }

  callRpc(endpoint, payload = null, opts = {}) {
    return new Promise((resolve, reject) => {
      let fromPid;
      let timeoutMs;
      try {
        const optsObj = normalizeReadableOptions(opts, 'callRpc options');
        const rawFromPid = safeGetProp(optsObj, 'fromPid', 'callRpc options');
        const rawTimeoutMs = safeGetProp(optsObj, 'timeoutMs', 'callRpc options');
        fromPid = rawFromPid !== undefined ? rawFromPid : 0;
        timeoutMs = rawTimeoutMs !== undefined ? rawTimeoutMs : this._defaultRpcTimeoutMs;
        validateNonEmptyName(endpoint, 'RPC endpoint');
        validatePid(fromPid, 'fromPid');
        timeoutMs = validateTimeoutMs(timeoutMs);
      } catch (err) {
        reject(err);
        return;
      }

      const rpc = this._rpcs.get(endpoint);
      if (!rpc) {
        reject(
          new OmniOSError(`RPC endpoint not found: ${endpoint}`, {
            code: ERROR_CODES.ENOENT,
            details: { endpoint },
          })
        );
        return;
      }

      let clonedPayload;
      try {
        clonedPayload = safeCloneIpcPayload(payload);
      } catch (err) {
        reject(err);
        return;
      }

      const correlationId = `rpc-${++this._rpcSeq}`;
      const pending = {
        resolve,
        reject,
        timer: null,
        endpoint,
        channelName: null,
        fromPid,
        targetOwnerPid: rpc.ownerPid,
        settled: false,
      };

      const timer = setTimeout(() => {
        this._rejectPending(
          correlationId,
          pending,
          new OmniOSError(`RPC "${endpoint}" timed out after ${timeoutMs}ms`, {
            code: ERROR_CODES.ETIMEDOUT,
            details: { endpoint, timeoutMs, correlationId },
          })
        );
      }, timeoutMs);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
      pending.timer = timer;
      this._pendingRequests.set(correlationId, pending);
      this._hookProcessCleanup(fromPid);

      const context = {
        endpoint,
        fromPid,
        ownerPid: rpc.ownerPid,
        correlationId,
      };

      const handleSuccess = (res) => {
        if (pending.settled) return;
        try {
          const clonedRes = res === undefined ? undefined : safeCloneIpcPayload(res);
          this._resolvePending(correlationId, pending, clonedRes);
        } catch (cloneErr) {
          this._rejectPending(correlationId, pending, cloneErr);
        }
      };

      const handleFailure = (err) => {
        if (pending.settled) return;
        const wrapped = normalizeIpcError(err, 'RPC handler failed');
        this._rejectPending(correlationId, pending, wrapped);
      };

      let result;
      try {
        result = rpc.handler(clonedPayload, context);
      } catch (err) {
        handleFailure(err);
        return;
      }

      if (isThenableValue(result)) {
        try {
          if (types.isPromise(result)) {
            Promise.prototype.then.call(result, handleSuccess, handleFailure);
          } else {
            result.then(handleSuccess, handleFailure);
          }
        } catch (err) {
          suppressAsyncRejection(result);
          handleFailure(err);
        }
      } else {
        handleSuccess(result);
      }
    });
  }

  request(channelName, fromPid, payload = null, opts = {}) {
    return new Promise((resolve, reject) => {
      let timeoutMs;
      try {
        const optsObj = normalizeReadableOptions(opts, 'request options');
        const rawTimeoutMs = safeGetProp(optsObj, 'timeoutMs', 'request options');
        timeoutMs = rawTimeoutMs !== undefined ? rawTimeoutMs : this._defaultRpcTimeoutMs;
        validateNonEmptyName(channelName, 'channel name');
        validatePid(fromPid, 'fromPid');
        timeoutMs = validateTimeoutMs(timeoutMs);
      } catch (err) {
        reject(err);
        return;
      }

      const ch = this._channels.get(channelName);
      if (!ch) {
        reject(
          new OmniOSError(`IPC channel not found: ${channelName}`, {
            code: ERROR_CODES.ENOENT,
            details: { channel: channelName },
          })
        );
        return;
      }

      try {
        this._checkChannelAccess(ch, fromPid);
      } catch (err) {
        reject(err);
        return;
      }

      const correlationId = `req-${++this._rpcSeq}`;
      const pending = {
        resolve,
        reject,
        timer: null,
        endpoint: null,
        channelName,
        fromPid,
        targetOwnerPid: ch.ownerPid,
        settled: false,
      };

      const timer = setTimeout(() => {
        this._rejectPending(
          correlationId,
          pending,
          new OmniOSError(`IPC request on "${channelName}" timed out after ${timeoutMs}ms`, {
            code: ERROR_CODES.ETIMEDOUT,
            details: { channel: channelName, timeoutMs, correlationId },
          })
        );
      }, timeoutMs);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
      pending.timer = timer;
      this._pendingRequests.set(correlationId, pending);
      this._hookProcessCleanup(fromPid);

      try {
        this.send(channelName, fromPid, payload, { type: 'request', correlationId });
      } catch (err) {
        this._rejectPending(correlationId, pending, err);
      }
    });
  }

  reply(correlationId, payload = null, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'reply options');
    const rawFromPid = safeGetProp(optsObj, 'fromPid', 'reply options');
    const error = safeGetProp(optsObj, 'error', 'reply options') ?? null;
    const fromPid = rawFromPid !== undefined ? rawFromPid : 0;

    if (typeof correlationId !== 'string' || correlationId.length === 0) return false;
    const pending = this._pendingRequests.get(correlationId);
    if (!pending || pending.settled) return false;

    if (fromPid !== null && fromPid !== undefined) {
      validatePid(fromPid, 'fromPid');
    }

    if (error !== null && error !== undefined) {
      const errObj = normalizeIpcError(error, 'IPC reply error');
      this._rejectPending(correlationId, pending, errObj);
      return true;
    }

    const cloned = payload === undefined ? undefined : safeCloneIpcPayload(payload);
    this._resolvePending(correlationId, pending, cloned);
    return true;
  }

  // -------------------------------------------------------------------------
  // Shared Memory (SHM)
  // -------------------------------------------------------------------------

  _resolveShm(idOrName) {
    if (typeof idOrName !== 'string' || idOrName.length === 0) return null;
    return this._shmById.get(idOrName) ?? this._shmByName.get(idOrName) ?? null;
  }

  _shmSummary(seg) {
    return {
      id: seg.id,
      name: seg.name,
      size: seg.size,
      ownerPid: seg.ownerPid,
      mode: seg.mode,
      attachedPids: Array.from(seg.attached.keys()),
      createdAt: seg.createdAt,
    };
  }

  shmCreate(name, size, ownerPid = 0, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'shmCreate options');
    const rawMode = safeGetProp(optsObj, 'mode', 'shmCreate options');
    const mode = rawMode !== undefined ? rawMode : 'rw';
    validateNonEmptyName(name, 'SHM segment name');
    validatePid(ownerPid, 'ownerPid');

    if (typeof size !== 'number' || !Number.isSafeInteger(size) || size <= 0) {
      throw new OmniOSError('SHM size must be a positive safe integer', {
        code: ERROR_CODES.EINVAL,
        details: { size },
      });
    }
    if (mode !== 'r' && mode !== 'rw') {
      throw new OmniOSError(`Invalid SHM mode "${safeDisplayValue(mode)}": expected "r" or "rw"`, {
        code: ERROR_CODES.EINVAL,
        details: { mode: safeDisplayValue(mode) },
      });
    }
    if (this._shmByName.has(name)) {
      throw new OmniOSError(`SHM segment already exists: ${name}`, {
        code: ERROR_CODES.EEXIST,
        details: { name },
      });
    }
    if (size > this._maxShmSize) {
      throw new QuotaExceededError(`SHM segment size ${size} exceeds limit ${this._maxShmSize}`, {
        code: ERROR_CODES.ENOMEM,
        quotaType: 'shmSegment',
        limit: this._maxShmSize,
        actual: size,
        pid: ownerPid,
      });
    }
    if (this._totalShmBytes + size > this._maxTotalShmBytes) {
      throw new QuotaExceededError(
        `Total SHM allocation (${this._totalShmBytes + size}) exceeds limit ${this._maxTotalShmBytes}`,
        {
          code: ERROR_CODES.ENOMEM,
          quotaType: 'shmTotal',
          limit: this._maxTotalShmBytes,
          actual: this._totalShmBytes + size,
          pid: ownerPid,
        }
      );
    }

    const id = `shm-${++this._shmSeq}`;
    const attached = new Map();
    attached.set(ownerPid, { mode: 'rw', attachedAt: new Date().toISOString() });

    const seg = {
      id,
      name,
      size,
      ownerPid,
      mode,
      buffer: new Uint8Array(size),
      attached,
      createdAt: new Date().toISOString(),
    };

    this._shmById.set(id, seg);
    this._shmByName.set(name, seg);
    this._totalShmBytes += size;
    this._hookProcessCleanup(ownerPid);

    this._emit('ipc:shm_created', { id, name, size, ownerPid });
    return this._shmSummary(seg);
  }

  shmAttach(idOrName, pid, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'shmAttach options');
    const rawMode = safeGetProp(optsObj, 'mode', 'shmAttach options');
    const mode = rawMode !== undefined ? rawMode : 'rw';
    const seg = this._resolveShm(idOrName);
    if (!seg) {
      throw new OmniOSError(`SHM segment not found: ${safeDisplayValue(idOrName)}`, {
        code: ERROR_CODES.ENOENT,
        details: { idOrName: safeDisplayValue(idOrName) },
      });
    }
    validatePid(pid, 'pid');
    if (mode !== 'r' && mode !== 'rw') {
      throw new OmniOSError(`Invalid SHM attach mode "${safeDisplayValue(mode)}": expected "r" or "rw"`, {
        code: ERROR_CODES.EINVAL,
        details: { mode: safeDisplayValue(mode) },
      });
    }
    if (seg.mode === 'r' && mode === 'rw' && pid !== 0 && pid !== seg.ownerPid) {
      throw new SecurityError(`SHM segment "${seg.name}" is read-only; PID ${pid} cannot attach read-write`, {
        code: ERROR_CODES.EACCES,
        pid,
        details: { id: seg.id, name: seg.name },
      });
    }

    seg.attached.set(pid, { mode, attachedAt: new Date().toISOString() });
    this._hookProcessCleanup(pid);
    return {
      id: seg.id,
      name: seg.name,
      size: seg.size,
      pid,
      mode,
    };
  }

  shmDetach(idOrName, pid) {
    const seg = this._resolveShm(idOrName);
    if (!seg) {
      throw new OmniOSError(`SHM segment not found: ${safeDisplayValue(idOrName)}`, {
        code: ERROR_CODES.ENOENT,
        details: { idOrName: safeDisplayValue(idOrName) },
      });
    }
    validatePid(pid, 'pid');
    return seg.attached.delete(pid);
  }

  shmWrite(idOrName, offset, bytes, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'shmWrite options');
    const pid = safeGetProp(optsObj, 'pid', 'shmWrite options') ?? null;
    const seg = this._resolveShm(idOrName);
    if (!seg) {
      throw new OmniOSError(`SHM segment not found: ${safeDisplayValue(idOrName)}`, {
        code: ERROR_CODES.ENOENT,
        details: { idOrName: safeDisplayValue(idOrName) },
      });
    }
    if (pid !== null && pid !== undefined) {
      validatePid(pid, 'pid');
      if (pid !== 0 && pid !== seg.ownerPid) {
        const attachment = seg.attached.get(pid);
        if (!attachment || attachment.mode !== 'rw') {
          throw new SecurityError(`PID ${pid} does not have write access to SHM segment "${seg.name}"`, {
            code: ERROR_CODES.EACCES,
            pid,
            details: { id: seg.id, name: seg.name },
          });
        }
      }
    }
    if (typeof offset !== 'number' || !Number.isSafeInteger(offset) || offset < 0) {
      throw new OmniOSError(`Invalid SHM write offset: ${safeDisplayValue(offset)}`, {
        code: ERROR_CODES.EINVAL,
        details: { offset: safeDisplayValue(offset) },
      });
    }

    if (typeof bytes === 'string' && (offset > seg.size || bytes.length > seg.size - offset)) {
      throw new OmniOSError(
        `SHM write out of bounds: offset=${offset}, length=${bytes.length}, size=${seg.size}`,
        {
          code: ERROR_CODES.ERANGE,
          details: { id: seg.id, offset, length: bytes.length, size: seg.size },
        }
      );
    }
    const src = toShmBytes(bytes);
    if (offset > seg.size || src.byteLength > seg.size - offset) {
      throw new OmniOSError(
        `SHM write out of bounds: offset=${offset}, length=${src.byteLength}, size=${seg.size}`,
        {
          code: ERROR_CODES.ERANGE,
          details: { id: seg.id, offset, length: src.byteLength, size: seg.size },
        }
      );
    }

    seg.buffer.set(src, offset);
    return {
      id: seg.id,
      name: seg.name,
      offset,
      bytesWritten: src.byteLength,
    };
  }

  shmRead(idOrName, offset = 0, length = undefined, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'shmRead options');
    const pid = safeGetProp(optsObj, 'pid', 'shmRead options') ?? null;
    const encoding = safeGetProp(optsObj, 'encoding', 'shmRead options') ?? null;
    const seg = this._resolveShm(idOrName);
    if (!seg) {
      throw new OmniOSError(`SHM segment not found: ${safeDisplayValue(idOrName)}`, {
        code: ERROR_CODES.ENOENT,
        details: { idOrName: safeDisplayValue(idOrName) },
      });
    }
    if (pid !== null && pid !== undefined) {
      validatePid(pid, 'pid');
      if (pid !== 0 && pid !== seg.ownerPid && !seg.attached.has(pid)) {
        throw new SecurityError(`PID ${pid} is not attached to SHM segment "${seg.name}"`, {
          code: ERROR_CODES.EACCES,
          pid,
          details: { id: seg.id, name: seg.name },
        });
      }
    }
    if (typeof offset !== 'number' || !Number.isSafeInteger(offset) || offset < 0) {
      throw new OmniOSError(`Invalid SHM read offset: ${safeDisplayValue(offset)}`, {
        code: ERROR_CODES.EINVAL,
        details: { offset: safeDisplayValue(offset) },
      });
    }
    if (offset > seg.size) {
      throw new OmniOSError(`SHM read offset out of bounds: offset=${offset}, size=${seg.size}`, {
        code: ERROR_CODES.ERANGE,
        details: { id: seg.id, offset, size: seg.size },
      });
    }

    const len = length === undefined ? seg.size - offset : length;
    if (typeof len !== 'number' || !Number.isSafeInteger(len) || len < 0) {
      throw new OmniOSError(`Invalid SHM read length: ${safeDisplayValue(len)}`, {
        code: ERROR_CODES.EINVAL,
        details: { length: safeDisplayValue(len) },
      });
    }
    if (len > seg.size - offset) {
      throw new OmniOSError(`SHM read out of bounds: offset=${offset}, length=${len}, size=${seg.size}`, {
        code: ERROR_CODES.ERANGE,
        details: { id: seg.id, offset, length: len, size: seg.size },
      });
    }

    // Always return an isolated copy (never expose internal SHM buffer view directly).
    const out = seg.buffer.slice(offset, offset + len);
    if (encoding === 'utf8' || encoding === 'utf-8') {
      return TEXT_DECODER.decode(out);
    }
    return out;
  }

  shmDestroy(idOrName, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'shmDestroy options');
    const pid = safeGetProp(optsObj, 'pid', 'shmDestroy options') ?? null;
    const seg = this._resolveShm(idOrName);
    if (!seg) return false;

    if (pid !== null && pid !== undefined) {
      validatePid(pid, 'pid');
      if (pid !== 0 && seg.ownerPid !== 0 && pid !== seg.ownerPid) {
        throw new SecurityError(`PID ${pid} cannot destroy SHM "${seg.name}" owned by PID ${seg.ownerPid}`, {
          code: ERROR_CODES.EPERM,
          pid,
          details: { id: seg.id, ownerPid: seg.ownerPid },
        });
      }
    }

    seg.buffer.fill(0);
    this._totalShmBytes = Math.max(0, this._totalShmBytes - seg.size);
    this._shmById.delete(seg.id);
    this._shmByName.delete(seg.name);
    this._emit('ipc:shm_destroyed', { id: seg.id, name: seg.name, ownerPid: seg.ownerPid });
    return true;
  }

  shmStat(idOrName) {
    const seg = this._resolveShm(idOrName);
    return seg ? this._shmSummary(seg) : null;
  }

  listShm() {
    const out = [];
    for (const seg of this._shmById.values()) {
      out.push(this._shmSummary(seg));
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Process Teardown Cleanup
  // -------------------------------------------------------------------------

  cleanupProcess(pid) {
    if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid <= 0) {
      return { channelsClosed: 0, subscriptionsRemoved: 0, rpcsRemoved: 0, pendingRejected: 0, shmDestroyed: 0 };
    }

    let channelsClosed = 0;
    let subscriptionsRemoved = 0;
    let rpcsRemoved = 0;
    let pendingRejected = 0;
    let shmDestroyed = 0;

    for (const [name, ch] of Array.from(this._channels.entries())) {
      for (const sub of Array.from(ch.subscribers)) {
        if (sub.pid === pid) {
          ch.subscribers.delete(sub);
          subscriptionsRemoved += 1;
        }
      }
      if (ch.ownerPid === pid && !ch.persistent) {
        this.closeChannel(name);
        channelsClosed += 1;
      }
    }

    for (const [endpoint, rpc] of Array.from(this._rpcs.entries())) {
      if (rpc.ownerPid === pid) {
        this.unregisterRpc(endpoint);
        rpcsRemoved += 1;
      }
    }

    const exitErr = new OmniOSError(`IPC peer process PID ${pid} exited`, {
      code: ERROR_CODES.EPIPE,
      details: { pid },
    });
    for (const [corrId, pending] of Array.from(this._pendingRequests.entries())) {
      if (pending.fromPid === pid || pending.targetOwnerPid === pid) {
        this._rejectPending(corrId, pending, exitErr);
        pendingRejected += 1;
      }
    }

    for (const seg of Array.from(this._shmById.values())) {
      if (seg.ownerPid === pid) {
        this.shmDestroy(seg.id);
        shmDestroyed += 1;
      } else {
        seg.attached.delete(pid);
      }
    }

    this._hookedPids.delete(pid);
    return { channelsClosed, subscriptionsRemoved, rpcsRemoved, pendingRejected, shmDestroyed };
  }
}

export function createIPCManager(options = {}) {
  return new IPCManager(options);
}
