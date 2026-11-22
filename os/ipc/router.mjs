/**
 * OmniOS Universal Intent, URL-Scheme & File-Association Router (`IntentRouter`)
 * Normalizes Android `<intent-filter>`, Apple `CFBundleURLTypes`/`CFBundleDocumentTypes` (with UTI mapping),
 * Windows `HKCR` associations, and Universal manifests into a single ranked cross-platform dispatcher
 * with Share Sheet chooser flow (`DELIVERED` | `CHOOSER_REQUIRED` | `NO_HANDLER`).
 */

import { types } from 'node:util';
import { OmniOSError, QuotaExceededError, ERROR_CODES } from '../common/errors.mjs';

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

function freezeLookup(obj) {
  return Object.freeze(Object.assign(Object.create(null), obj));
}

export const CANONICAL_ACTION_ALIASES = freezeLookup({
  view: 'view',
  open: 'view',
  'android.intent.action.view': 'view',
  send: 'send',
  share: 'send',
  'android.intent.action.send': 'send',
  send_multiple: 'send_multiple',
  'android.intent.action.send_multiple': 'send_multiple',
  edit: 'edit',
  'android.intent.action.edit': 'edit',
  main: 'main',
  launch: 'main',
  'android.intent.action.main': 'main',
  dial: 'dial',
  'android.intent.action.dial': 'dial',
  pick: 'pick',
  'android.intent.action.pick': 'pick',
  search: 'search',
  'android.intent.action.search': 'search',
});

export const UTI_TYPE_MAP = freezeLookup({
  'public.plain-text': Object.freeze({ extensions: Object.freeze(['.txt']), mimeTypes: Object.freeze(['text/plain']) }),
  'public.text': Object.freeze({ extensions: Object.freeze(['.txt']), mimeTypes: Object.freeze(['text/plain']) }),
  'public.utf8-plain-text': Object.freeze({ extensions: Object.freeze(['.txt']), mimeTypes: Object.freeze(['text/plain']) }),
  'public.html': Object.freeze({ extensions: Object.freeze(['.html', '.htm']), mimeTypes: Object.freeze(['text/html']) }),
  'public.json': Object.freeze({ extensions: Object.freeze(['.json']), mimeTypes: Object.freeze(['application/json']) }),
  'public.xml': Object.freeze({ extensions: Object.freeze(['.xml']), mimeTypes: Object.freeze(['application/xml']) }),
  'public.png': Object.freeze({ extensions: Object.freeze(['.png']), mimeTypes: Object.freeze(['image/png']) }),
  'public.jpeg': Object.freeze({ extensions: Object.freeze(['.jpg', '.jpeg']), mimeTypes: Object.freeze(['image/jpeg']) }),
  'public.svg-image': Object.freeze({ extensions: Object.freeze(['.svg']), mimeTypes: Object.freeze(['image/svg+xml']) }),
  'com.adobe.pdf': Object.freeze({ extensions: Object.freeze(['.pdf']), mimeTypes: Object.freeze(['application/pdf']) }),
  'net.daringfireball.markdown': Object.freeze({
    extensions: Object.freeze(['.md', '.markdown']),
    mimeTypes: Object.freeze(['text/markdown']),
  }),
  'public.comma-separated-values-text': Object.freeze({
    extensions: Object.freeze(['.csv']),
    mimeTypes: Object.freeze(['text/csv']),
  }),
  'public.zip-archive': Object.freeze({ extensions: Object.freeze(['.zip']), mimeTypes: Object.freeze(['application/zip']) }),
  'public.mp3': Object.freeze({ extensions: Object.freeze(['.mp3']), mimeTypes: Object.freeze(['audio/mpeg']) }),
  'public.mpeg-4': Object.freeze({ extensions: Object.freeze(['.mp4']), mimeTypes: Object.freeze(['video/mp4']) }),
});

const EXT_TO_MIME = freezeLookup({
  '.txt': 'text/plain',
  '.log': 'text/plain',
  '.md': 'text/markdown',
  '.markdown': 'text/markdown',
  '.html': 'text/html',
  '.htm': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.csv': 'text/csv',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip',
  '.mp3': 'audio/mpeg',
  '.mp4': 'video/mp4',
  '.wasm': 'application/wasm',
});

function defineSafeProp(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

const MAX_CLONE_ARRAY_LEN = 100_000;
const MAX_CLONE_NODES = 250_000;
const MAX_CLONE_BYTES = 2 * 1024 * 1024; // 2 MiB
const MAX_CLONE_BIGINT_ABS = 1n << 4096n;
const MAX_DISPLAY_LENGTH = 256;
const MAX_MANIFEST_DESCRIPTORS = 1024;
const MAX_MANIFEST_ENTRIES = 16_384;
const MAX_MANIFEST_BYTES = 1 * 1024 * 1024; // 1 MiB
const MAX_ROUTER_FIELD_CHARS = 4096;
const DESCRIPTOR_SIG_CACHE = new WeakMap();

function capDisplayString(str) {
  if (str.length > 65_536) return `[String(${str.length})]`;
  return str.length > MAX_DISPLAY_LENGTH ? `${str.slice(0, MAX_DISPLAY_LENGTH)}...` : str;
}

function createManifestBudget() {
  return { descriptors: 0, entries: 0, bytes: 0 };
}

function chargeManifestDescriptors(budget, count = 1, label = 'intent manifest') {
  if (!budget) return;
  budget.descriptors += count;
  if (budget.descriptors > MAX_MANIFEST_DESCRIPTORS) {
    throw new QuotaExceededError(
      `${label} exceeds maximum descriptor limit (${MAX_MANIFEST_DESCRIPTORS})`,
      {
        code: ERROR_CODES.EQUOTA,
        quotaType: 'manifestDescriptors',
        limit: MAX_MANIFEST_DESCRIPTORS,
        actual: budget.descriptors,
      }
    );
  }
}

function chargeManifestEntries(budget, count = 1, bytes = 0, label = 'intent manifest') {
  if (!budget) return;
  budget.entries += count;
  if (budget.entries > MAX_MANIFEST_ENTRIES) {
    throw new QuotaExceededError(
      `${label} exceeds maximum matcher entry limit (${MAX_MANIFEST_ENTRIES})`,
      {
        code: ERROR_CODES.EQUOTA,
        quotaType: 'manifestEntries',
        limit: MAX_MANIFEST_ENTRIES,
        actual: budget.entries,
      }
    );
  }
  budget.bytes += bytes;
  if (budget.bytes > MAX_MANIFEST_BYTES) {
    throw new QuotaExceededError(
      `${label} exceeds maximum byte limit (${MAX_MANIFEST_BYTES} bytes)`,
      {
        code: ERROR_CODES.EQUOTA,
        quotaType: 'manifestBytes',
        limit: MAX_MANIFEST_BYTES,
        actual: budget.bytes,
      }
    );
  }
}

function measureDescriptors(list) {
  let entries = 0;
  let bytes = 0;
  for (const h of list) {
    for (const set of [h.actions, h.schemes, h.extensions, h.mimeTypes, h.hosts, h.categories]) {
      entries += set.size;
      for (const s of set) {
        bytes += typeof s === 'string' ? s.length + 2 : 8;
      }
    }
    if (typeof h.platform === 'string') bytes += h.platform.length;
    if (typeof h.label === 'string') bytes += h.label.length;
  }
  return { entries, bytes };
}

function consumeCloneBytes(budget, delta) {
  if (budget.exceeded || delta > budget.remainingBytes) {
    budget.exceeded = true;
    budget.bytesExceeded = true;
    return false;
  }
  budget.remainingBytes -= delta;
  return true;
}

function isErrorInstance(err) {
  try {
    return err instanceof Error;
  } catch {
    return false;
  }
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

function forEachSafeArrayItem(arr, label, fn, maxLen = 10_000) {
  let isArr = false;
  try {
    isArr = Array.isArray(arr);
  } catch (err) {
    throw new OmniOSError(`${label} must be a readable Array`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (!isArr) {
    throw new OmniOSError(`${label} must be an Array`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  let len;
  try {
    len = arr.length;
  } catch (err) {
    throw new OmniOSError(`Unreadable ${label} array length`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (
    typeof len !== 'number' ||
    !Number.isSafeInteger(len) ||
    len < 0 ||
    len > 0xffffffff ||
    len > maxLen
  ) {
    throw new OmniOSError(`Invalid ${label} array length`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  for (let i = 0; i < len; i++) {
    let item;
    try {
      item = arr[i];
    } catch (err) {
      throw new OmniOSError(`Unreadable ${label} item at index ${i}`, {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    fn(item, i);
  }
  return len;
}

function cloneJsonSafe(
  val,
  seen = new Set(),
  depth = 0,
  budget = { remaining: MAX_CLONE_NODES, remainingBytes: MAX_CLONE_BYTES, exceeded: false, bytesExceeded: false }
) {
  if (depth > 32) {
    if (!consumeCloneBytes(budget, 2)) return '[Unreadable]';
    return null;
  }
  if (val === null || val === undefined) {
    if (!consumeCloneBytes(budget, 2)) return '[Unreadable]';
    return val;
  }
  const t = typeof val;
  if (t === 'boolean') {
    if (!consumeCloneBytes(budget, 2)) return '[Unreadable]';
    return val;
  }
  if (t === 'string') {
    if (!consumeCloneBytes(budget, val.length + 2)) return '[Unreadable]';
    return val;
  }
  if (t === 'number') {
    if (!consumeCloneBytes(budget, 2)) return '[Unreadable]';
    return Number.isFinite(val) ? val : null;
  }
  if (t === 'bigint') {
    if (val > MAX_CLONE_BIGINT_ABS || val < -MAX_CLONE_BIGINT_ABS) {
      budget.exceeded = true;
      budget.bytesExceeded = true;
      return '[Unreadable]';
    }
    const str = val.toString(10);
    if (!consumeCloneBytes(budget, str.length + 2)) return '[Unreadable]';
    return str;
  }
  if (t !== 'object') {
    if (!consumeCloneBytes(budget, 2)) return '[Unreadable]';
    return null;
  }

  // Check Array.isArray FIRST (in its own try/catch) BEFORE any instanceof or Proxy check so
  // Proxy-wrapped Arrays with throwing getPrototypeOf traps are preserved as Arrays.
  let isArr = false;
  try {
    isArr = Array.isArray(val);
  } catch {
    consumeCloneBytes(budget, 2);
    return '[Unreadable]';
  }

  if (isArr) {
    if (seen.has(val)) {
      if (!consumeCloneBytes(budget, 2)) return '[Unreadable]';
      return '[Circular]';
    }
    seen.add(val);
    try {
      let len;
      try {
        len = val.length;
      } catch {
        consumeCloneBytes(budget, 2);
        return '[Unreadable]';
      }
      if (
        typeof len !== 'number' ||
        !Number.isSafeInteger(len) ||
        len < 0 ||
        len > 0xffffffff ||
        len > MAX_CLONE_ARRAY_LEN
      ) {
        consumeCloneBytes(budget, 2);
        return '[Unreadable]';
      }
      if (len > budget.remaining) {
        budget.exceeded = true;
        return '[Unreadable]';
      }
      if (!consumeCloneBytes(budget, 16) || len * 2 > budget.remainingBytes) {
        budget.exceeded = true;
        budget.bytesExceeded = true;
        return '[Unreadable]';
      }
      const arr = [];
      for (let i = 0; i < len; i++) {
        if (budget.exceeded || budget.remaining <= 0) {
          budget.exceeded = true;
          return '[Unreadable]';
        }
        budget.remaining -= 1;
        let item;
        try {
          item = val[i];
        } catch {
          item = '[Unreadable]';
        }
        arr.push(cloneJsonSafe(item, seen, depth + 1, budget));
        if (budget.exceeded) return '[Unreadable]';
      }
      return arr;
    } finally {
      seen.delete(val);
    }
  }

  if (types.isDate(val) && !types.isProxy(val)) {
    if (!consumeCloneBytes(budget, 24)) return '[Unreadable]';
    try {
      const ms = Date.prototype.getTime.call(val);
      return Number.isFinite(ms) ? Date.prototype.toISOString.call(val) : 'Invalid Date';
    } catch {
      return '[Unreadable]';
    }
  }

  const bin = extractGenuineBytes(val);
  if (bin.detached) {
    consumeCloneBytes(budget, 2);
    return '[Unreadable]';
  }
  if (bin.ok) {
    try {
      if (bin.bytes.byteLength > MAX_CLONE_ARRAY_LEN) {
        consumeCloneBytes(budget, 2);
        return '[Unreadable]';
      }
      if (bin.bytes.byteLength > budget.remaining) {
        budget.exceeded = true;
        return '[Unreadable]';
      }
      if (!consumeCloneBytes(budget, Math.max(16, bin.bytes.byteLength * 2))) return '[Unreadable]';
      budget.remaining -= bin.bytes.byteLength;
      return Array.from(bin.bytes);
    } catch {
      consumeCloneBytes(budget, 2);
      return '[Unreadable]';
    }
  }

  if (
    types.isProxy(val) ||
    types.isBoxedPrimitive(val) ||
    types.isSharedArrayBuffer?.(val)
  ) {
    consumeCloneBytes(budget, 2);
    return '[Unreadable]';
  }

  let isSpoofedSpecial = false;
  try {
    isSpoofedSpecial =
      val instanceof Date ||
      val instanceof ArrayBuffer ||
      val instanceof TYPED_ARRAY_CTOR ||
      val instanceof DataView ||
      (typeof SharedArrayBuffer === 'function' && val instanceof SharedArrayBuffer) ||
      ArrayBuffer.isView(val);
  } catch {
    consumeCloneBytes(budget, 2);
    return '[Unreadable]';
  }
  if (isSpoofedSpecial) {
    consumeCloneBytes(budget, 2);
    return '[Unreadable]';
  }

  if (seen.has(val)) {
    if (!consumeCloneBytes(budget, 2)) return '[Unreadable]';
    return '[Circular]';
  }
  seen.add(val);
  try {
    let keys;
    try {
      keys = Object.keys(val);
    } catch {
      consumeCloneBytes(budget, 2);
      return '[Unreadable]';
    }
    if (keys.length > MAX_CLONE_ARRAY_LEN) {
      consumeCloneBytes(budget, 2);
      return '[Unreadable]';
    }
    if (keys.length > budget.remaining) {
      budget.exceeded = true;
      return '[Unreadable]';
    }
    if (!consumeCloneBytes(budget, 16) || keys.length * 2 > budget.remainingBytes) {
      budget.exceeded = true;
      budget.bytesExceeded = true;
      return '[Unreadable]';
    }
    const out = {};
    for (const key of keys) {
      if (budget.exceeded || budget.remaining <= 0) {
        budget.exceeded = true;
        return '[Unreadable]';
      }
      budget.remaining -= 1;
      if (!consumeCloneBytes(budget, key.length + 2)) return '[Unreadable]';
      let prop;
      try {
        prop = val[key];
      } catch {
        prop = '[Unreadable]';
      }
      defineSafeProp(out, key, cloneJsonSafe(prop, seen, depth + 1, budget));
      if (budget.exceeded) return '[Unreadable]';
    }
    return out;
  } finally {
    seen.delete(val);
  }
}

function cloneJsonSafeWithCount(val, maxNodes = MAX_CLONE_NODES, maxBytes = MAX_CLONE_BYTES) {
  const cap = Number.isSafeInteger(maxNodes) && maxNodes >= 0 ? maxNodes : 0;
  const byteCap = Number.isSafeInteger(maxBytes) && maxBytes >= 0 ? maxBytes : 0;
  const budget = { remaining: cap, remainingBytes: byteCap, exceeded: false, bytesExceeded: false };
  const value = cloneJsonSafe(val, new Set(), 0, budget);
  const nodes = Math.max(0, cap - budget.remaining);
  const bytes = Math.max(0, byteCap - budget.remainingBytes);
  return { value, nodes, bytes, exceeded: budget.exceeded, bytesExceeded: budget.bytesExceeded };
}

function cloneFieldOrThrow(val, fieldName, maxNodes = MAX_CLONE_NODES, maxBytes = MAX_CLONE_BYTES) {
  const res = cloneJsonSafeWithCount(val, maxNodes, maxBytes);
  if (res.exceeded) {
    throw new QuotaExceededError(
      res.bytesExceeded
        ? `${fieldName} exceeds maximum byte budget (${maxBytes} bytes)`
        : `${fieldName} exceeds maximum node budget (${maxNodes})`,
      {
        code: ERROR_CODES.EQUOTA,
        quotaType: res.bytesExceeded ? 'intentBytes' : 'intentNodes',
        limit: res.bytesExceeded ? maxBytes : maxNodes,
        actual: res.bytesExceeded ? res.bytes : res.nodes,
      }
    );
  }
  return res.value;
}

function cloneCandidate(c) {
  return {
    appId: c.appId,
    platform: c.platform,
    label: c.label,
    score: c.score,
    priority: c.priority,
    isDefault: Boolean(c.isDefault),
    matchedOn: Array.isArray(c.matchedOn) ? [...c.matchedOn] : [],
  };
}

function cloneIntentRecord(intent) {
  if (!intent) return null;
  return {
    action: intent.action,
    uri: intent.uri,
    mimeType: intent.mimeType,
    extension: intent.extension,
    scheme: intent.scheme,
    host: intent.host,
    extras: intent.extras !== undefined ? cloneJsonSafe(intent.extras) : {},
    sourcePid: intent.sourcePid,
    ts: intent.ts,
  };
}

function clonePendingChooser(pending) {
  if (!pending) return null;
  return {
    requestId: pending.requestId,
    intent: cloneIntentRecord(pending.intent),
    candidates: Array.isArray(pending.candidates) ? pending.candidates.map(cloneCandidate) : [],
    createdAt: pending.createdAt,
  };
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
    // Ignore.
  }
  try {
    const thenFn = value.then;
    if (typeof thenFn === 'function') {
      thenFn.call(value, undefined, handler);
    }
  } catch {
    // Ignore.
  }
}

function isThenable(value) {
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

function validateAppId(appId) {
  if (typeof appId !== 'string' || appId.length === 0 || appId.length > MAX_ROUTER_FIELD_CHARS || appId.includes('\0')) {
    throw new OmniOSError('appId must be a non-empty string without NUL bytes', {
      code: ERROR_CODES.EINVAL,
      details: { appId: safeDisplayValue(appId) },
    });
  }
  const trimmed = appId.trim();
  if (trimmed.length === 0) {
    throw new OmniOSError('appId must be a non-empty string without NUL bytes', {
      code: ERROR_CODES.EINVAL,
      details: { appId: safeDisplayValue(appId) },
    });
  }
  return trimmed;
}

function normalizeAction(action) {
  if (typeof action !== 'string' || action.length === 0 || action.length > MAX_ROUTER_FIELD_CHARS) return null;
  const trimmed = action.trim().toLowerCase();
  if (!trimmed) return null;
  if (Object.prototype.hasOwnProperty.call(CANONICAL_ACTION_ALIASES, trimmed)) {
    return CANONICAL_ACTION_ALIASES[trimmed];
  }
  return trimmed;
}

function normalizeScheme(scheme) {
  if (typeof scheme !== 'string' || scheme.length === 0 || scheme.length > MAX_ROUTER_FIELD_CHARS) return null;
  const trimmed = scheme.trim().toLowerCase();
  let end = trimmed.length;
  while (end > 0 && trimmed.charCodeAt(end - 1) === 0x3a) {
    end -= 1;
  }
  const cleaned = end === trimmed.length ? trimmed : trimmed.slice(0, end);
  if (!cleaned || !/^[a-z][a-z0-9+.-]*$/.test(cleaned)) return null;
  return cleaned;
}

function normalizeExtension(ext) {
  if (typeof ext !== 'string' || ext.length === 0 || ext.length > MAX_ROUTER_FIELD_CHARS) return null;
  let cleaned = ext.trim().toLowerCase();
  if (!cleaned) return null;
  if (cleaned.startsWith('*.')) cleaned = cleaned.slice(1);
  if (!cleaned.startsWith('.')) cleaned = `.${cleaned}`;
  if (cleaned.length < 2 || cleaned.includes('/') || cleaned.includes('\\') || cleaned.includes('\0')) return null;
  return cleaned;
}

function normalizeMimeType(mime) {
  if (typeof mime !== 'string' || mime.length === 0 || mime.length > MAX_ROUTER_FIELD_CHARS) return null;
  const semi = mime.indexOf(';');
  const head = semi === -1 ? mime : mime.slice(0, semi);
  const base = head.trim().toLowerCase();
  if (!base || !base.includes('/')) return null;
  return base;
}

function normalizeHost(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > MAX_ROUTER_FIELD_CHARS) return null;
  const cleaned = host.trim().toLowerCase();
  return cleaned.length > 0 ? cleaned : null;
}

function normalizePriority(priority) {
  if (typeof priority !== 'number' || !Number.isFinite(priority)) return 0;
  return Math.max(-1000, Math.min(1000, Math.trunc(priority)));
}

function appendReadableList(out, value, label, budget = null) {
  if (value === undefined || value === null) return;
  let isArr = false;
  try {
    isArr = Array.isArray(value);
  } catch (err) {
    throw new OmniOSError(`Unreadable ${label} value`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (isArr) {
    forEachSafeArrayItem(
      value,
      label,
      (item) => {
        const byteCost = typeof item === 'string' ? item.length + 2 : 8;
        chargeManifestEntries(budget, 1, byteCost, label);
        out.push(item);
      },
      10_000
    );
  } else {
    const byteCost = typeof value === 'string' ? value.length + 2 : 8;
    chargeManifestEntries(budget, 1, byteCost, label);
    out.push(value);
  }
}

function toStringList(single, plural, label = 'descriptor field', budget = null) {
  const out = [];
  appendReadableList(out, single, label, budget);
  appendReadableList(out, plural, label, budget);
  return out;
}

function parseUriSafely(uri) {
  const result = { scheme: null, host: null, extension: null };
  if (typeof uri !== 'string' || uri.length === 0 || uri.length > 8192) return result;
  const trimmed = uri.trim();
  if (!trimmed || trimmed.length > 4096) return result;

  // Guarded scheme extraction (RFC 3986)
  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(trimmed);
  let rest = trimmed;
  if (schemeMatch) {
    // Avoid treating Windows drive letters like C:\file.txt as a URL scheme
    const candidate = schemeMatch[1].toLowerCase();
    if (!(candidate.length === 1 && (trimmed[2] === '\\' || trimmed[2] === '/'))) {
      result.scheme = candidate;
      rest = trimmed.slice(schemeMatch[0].length);
    }
  }

  // Strip fragment & query before extracting host & pathname
  let pathPart = rest;
  const hashIdx = pathPart.indexOf('#');
  if (hashIdx !== -1) pathPart = pathPart.slice(0, hashIdx);
  const queryIdx = pathPart.indexOf('?');
  if (queryIdx !== -1) pathPart = pathPart.slice(0, queryIdx);

  let isHierarchical = false;
  if (result.scheme && pathPart.startsWith('//')) {
    isHierarchical = true;
    const afterSlashes = pathPart.slice(2);
    const slashIdx = afterSlashes.indexOf('/');
    const authority = slashIdx === -1 ? afterSlashes : afterSlashes.slice(0, slashIdx);
    const hostPort = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
    const colonIdx = hostPort.startsWith('[') ? hostPort.indexOf(']') + 1 : hostPort.indexOf(':');
    const hostCandidate = colonIdx > 0 ? hostPort.slice(0, colonIdx) : hostPort;
    if (hostCandidate && result.scheme !== 'file') {
      result.host = hostCandidate.toLowerCase();
    }
    pathPart = slashIdx === -1 ? '' : afterSlashes.slice(slashIdx);
  }

  // Extract file extension ONLY for scheme-less paths, `file:` URIs, or hierarchical URIs with a path segment.
  // Never extract spurious extensions (e.g. `.com`) from opaque non-hierarchical URIs like `mailto:user@example.com`.
  const canExtractExtension =
    !result.scheme || result.scheme === 'file' || (isHierarchical && pathPart.length > 0);
  if (canExtractExtension) {
    const normalizedPath = pathPart.replace(/\\/g, '/');
    const lastSlash = normalizedPath.lastIndexOf('/');
    const basename = lastSlash === -1 ? normalizedPath : normalizedPath.slice(lastSlash + 1);
    if (basename && !basename.startsWith('.') && basename.includes('.')) {
      const lastDot = basename.lastIndexOf('.');
      const ext = normalizeExtension(basename.slice(lastDot));
      if (ext) result.extension = ext;
    } else if (basename && basename.startsWith('.') && basename.indexOf('.', 1) !== -1) {
      const lastDot = basename.lastIndexOf('.');
      const ext = normalizeExtension(basename.slice(lastDot));
      if (ext) result.extension = ext;
    }
  }

  return result;
}

function matchMime(queryMime, handlerMimes) {
  if (!queryMime || handlerMimes.size === 0) return 0;
  if (handlerMimes.has(queryMime)) return 30;
  const slashIdx = queryMime.indexOf('/');
  if (slashIdx > 0) {
    const wildcard = `${queryMime.slice(0, slashIdx)}/*`;
    if (handlerMimes.has(wildcard)) return 20;
  }
  if (handlerMimes.has('*/*')) return 10;
  return 0;
}

function buildCriteriaKeyFromObject(criteria) {
  if (!criteria || typeof criteria !== 'object') return null;
  let isArr = false;
  try {
    isArr = Array.isArray(criteria);
  } catch (err) {
    throw new OmniOSError('Unreadable criteria object', {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (isArr) return null;

  const rawUri = safeGetProp(criteria, 'uri', 'criteria');
  const rawAction = safeGetProp(criteria, 'action', 'criteria');
  const rawScheme = safeGetProp(criteria, 'scheme', 'criteria');
  const rawExtension = safeGetProp(criteria, 'extension', 'criteria');
  const rawMimeType = safeGetProp(criteria, 'mimeType', 'criteria');

  const parsedUri = rawUri ? parseUriSafely(rawUri) : { scheme: null, extension: null };
  const action = normalizeAction(rawAction);
  const scheme = normalizeScheme(rawScheme ?? parsedUri.scheme);
  const extension = normalizeExtension(rawExtension ?? parsedUri.extension);
  const mimeType = normalizeMimeType(rawMimeType);

  const parts = [];
  if (action) parts.push(`action:${action}`);
  if (scheme && scheme !== 'file') parts.push(`scheme:${scheme}`);
  if (extension) parts.push(`ext:${extension}`);
  if (mimeType) parts.push(`mime:${mimeType}`);
  return parts.length > 0 ? parts.join('|') : null;
}

function normalizeCriteriaKey(criteria) {
  if (typeof criteria === 'string') {
    if (criteria.length > MAX_ROUTER_FIELD_CHARS) {
      throw new OmniOSError(`Default handler criteria exceeds maximum length (${MAX_ROUTER_FIELD_CHARS})`, {
        code: ERROR_CODES.EINVAL,
      });
    }
    const trimmed = criteria.trim();
    if (!trimmed) {
      throw new OmniOSError('Default handler criteria cannot be empty', { code: ERROR_CODES.EINVAL });
    }
    const lower = trimmed.toLowerCase();
    if (lower.startsWith('ext:')) {
      const ext = normalizeExtension(trimmed.slice(4));
      if (!ext) throw new OmniOSError(`Invalid extension criteria: ${safeDisplayValue(criteria)}`, { code: ERROR_CODES.EINVAL });
      return `ext:${ext}`;
    }
    if (lower.startsWith('scheme:')) {
      const sc = normalizeScheme(trimmed.slice(7));
      if (!sc) throw new OmniOSError(`Invalid scheme criteria: ${safeDisplayValue(criteria)}`, { code: ERROR_CODES.EINVAL });
      return `scheme:${sc}`;
    }
    if (lower.startsWith('mime:')) {
      const mt = normalizeMimeType(trimmed.slice(5));
      if (!mt) throw new OmniOSError(`Invalid MIME criteria: ${safeDisplayValue(criteria)}`, { code: ERROR_CODES.EINVAL });
      return `mime:${mt}`;
    }
    if (lower.startsWith('action:')) {
      const act = normalizeAction(trimmed.slice(7));
      if (!act) throw new OmniOSError(`Invalid action criteria: ${safeDisplayValue(criteria)}`, { code: ERROR_CODES.EINVAL });
      return `action:${act}`;
    }
    if (lower.includes('|')) {
      return lower;
    }
    if (lower.startsWith('.')) {
      const ext = normalizeExtension(lower);
      if (ext) return `ext:${ext}`;
    }
    if (lower.includes('/')) {
      const mt = normalizeMimeType(lower);
      if (mt) return `mime:${mt}`;
    }
    return lower;
  }
  if (criteria && typeof criteria === 'object') {
    const key = buildCriteriaKeyFromObject(criteria);
    if (!key) {
      throw new OmniOSError('Default handler criteria object must specify at least one matcher field', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return key;
  }
  throw new OmniOSError('Invalid default handler criteria', { code: ERROR_CODES.EINVAL });
}

function isReadableObject(val, label) {
  if (!val || typeof val !== 'object') return false;
  let isArr = false;
  try {
    isArr = Array.isArray(val);
  } catch (err) {
    throw new OmniOSError(`Unreadable ${label}`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  return !isArr;
}

function normalizeFlatDescriptor(desc, { platform = null, label = null } = {}, budget = null) {
  if (!isReadableObject(desc, 'intent handler descriptor')) return null;

  chargeManifestDescriptors(budget, 1, 'intent manifest');

  const actions = new Set();
  for (const a of toStringList(
    safeGetProp(desc, 'action', 'handler descriptor'),
    safeGetProp(desc, 'actions', 'handler descriptor'),
    'descriptor actions',
    budget
  )) {
    const norm = normalizeAction(a);
    if (norm) actions.add(norm);
  }

  const schemes = new Set();
  for (const s of toStringList(
    safeGetProp(desc, 'scheme', 'handler descriptor'),
    safeGetProp(desc, 'schemes', 'handler descriptor'),
    'descriptor schemes',
    budget
  )) {
    const norm = normalizeScheme(s);
    if (norm) schemes.add(norm);
  }

  const extensions = new Set();
  for (const e of toStringList(
    safeGetProp(desc, 'extension', 'handler descriptor'),
    safeGetProp(desc, 'extensions', 'handler descriptor'),
    'descriptor extensions',
    budget
  )) {
    const norm = normalizeExtension(e);
    if (norm) extensions.add(norm);
  }

  const mimeTypes = new Set();
  for (const m of toStringList(
    safeGetProp(desc, 'mimeType', 'handler descriptor'),
    safeGetProp(desc, 'mimeTypes', 'handler descriptor'),
    'descriptor mimeTypes',
    budget
  )) {
    const norm = normalizeMimeType(m);
    if (norm) mimeTypes.add(norm);
  }

  const hosts = new Set();
  for (const h of toStringList(
    safeGetProp(desc, 'host', 'handler descriptor'),
    safeGetProp(desc, 'hosts', 'handler descriptor'),
    'descriptor hosts',
    budget
  )) {
    const norm = normalizeHost(h);
    if (norm) hosts.add(norm);
  }

  const categories = new Set();
  for (const c of toStringList(
    safeGetProp(desc, 'category', 'handler descriptor'),
    safeGetProp(desc, 'categories', 'handler descriptor'),
    'descriptor categories',
    budget
  )) {
    if (typeof c === 'string') {
      const trimmedCat = c.trim();
      if (trimmedCat.length > 0) categories.add(trimmedCat.toLowerCase());
    }
  }

  if (
    actions.size === 0 &&
    schemes.size === 0 &&
    extensions.size === 0 &&
    mimeTypes.size === 0 &&
    hosts.size === 0
  ) {
    return null;
  }

  const rawPriority = safeGetProp(desc, 'priority', 'handler descriptor');
  const rawPlatform = safeGetProp(desc, 'platform', 'handler descriptor');
  const rawLabel = safeGetProp(desc, 'label', 'handler descriptor');

  // Charge raw pre-trim lengths strictly BEFORE calling .trim() to block whitespace CPU DoS
  const rawPlatformBytes = typeof rawPlatform === 'string' ? rawPlatform.length : 0;
  const fallbackPlatformBytes =
    rawPlatformBytes === 0 && typeof platform === 'string' ? platform.length : 0;
  const rawLabelBytes = typeof rawLabel === 'string' ? rawLabel.length : 0;
  const fallbackLabelBytes =
    rawLabelBytes === 0 && typeof label === 'string' ? label.length : 0;
  chargeManifestEntries(
    budget,
    0,
    rawPlatformBytes + fallbackPlatformBytes + rawLabelBytes + fallbackLabelBytes,
    'handler descriptor'
  );

  let resolvedPlatform = null;
  if (typeof rawPlatform === 'string') {
    const trimmedRawPlatform = rawPlatform.trim();
    if (trimmedRawPlatform.length > 0) {
      resolvedPlatform = trimmedRawPlatform;
    }
  }
  if (resolvedPlatform === null && typeof platform === 'string') {
    if (fallbackPlatformBytes === 0 && platform.length > 0) {
      chargeManifestEntries(budget, 0, platform.length, 'handler descriptor');
    }
    const trimmedFallbackPlatform = platform.trim();
    if (trimmedFallbackPlatform.length > 0) {
      resolvedPlatform = trimmedFallbackPlatform;
    }
  }
  const resolvedLabel =
    typeof rawLabel === 'string'
      ? rawLabel
      : typeof label === 'string'
        ? label
        : null;

  return {
    actions,
    schemes,
    extensions,
    mimeTypes,
    hosts,
    categories,
    priority: normalizePriority(rawPriority),
    platform: resolvedPlatform,
    label: resolvedLabel,
  };
}

function isReadableArrayProp(val, label) {
  if (val === undefined || val === null) return false;
  try {
    return Array.isArray(val);
  } catch (err) {
    throw new OmniOSError(`Unreadable ${label}`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
}

function normalizeManifestInput(handlers, defaults) {
  const budget = createManifestBudget();
  let isArr = false;
  try {
    isArr = Array.isArray(handlers);
  } catch (err) {
    throw new OmniOSError('handlers must be a readable Array or platform manifest object', {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (isArr) {
    const out = [];
    forEachSafeArrayItem(handlers, 'handlers', (item) => {
      const normalized = normalizeFlatDescriptor(item, defaults, budget);
      if (normalized) {
        out.push(normalized);
      } else {
        chargeManifestEntries(budget, 1, 8, 'handlers');
      }
    });
    return out;
  }

  if (!handlers || typeof handlers !== 'object') {
    throw new OmniOSError('handlers must be an Array or platform manifest object', {
      code: ERROR_CODES.EINVAL,
    });
  }

  const out = [];
  let recognizedManifest = false;

  // Android <intent-filter>
  const rawIntentFilters = safeGetProp(handlers, 'intentFilters', 'manifest');
  if (isReadableArrayProp(rawIntentFilters, 'manifest.intentFilters')) {
    recognizedManifest = true;
    forEachSafeArrayItem(rawIntentFilters, 'manifest.intentFilters', (filter) => {
      if (!isReadableObject(filter, 'intentFilter')) {
        chargeManifestEntries(budget, 1, 8, 'manifest.intentFilters');
        return;
      }
      const baseActions = toStringList(
        safeGetProp(filter, 'action', 'intentFilter'),
        safeGetProp(filter, 'actions', 'intentFilter'),
        'intentFilter actions',
        budget
      );
      const baseCats = toStringList(
        safeGetProp(filter, 'category', 'intentFilter'),
        safeGetProp(filter, 'categories', 'intentFilter'),
        'intentFilter categories',
        budget
      );
      const rawFilterData = safeGetProp(filter, 'data', 'intentFilter');

      const fScheme = safeGetProp(filter, 'scheme', 'intentFilter');
      const fSchemes = safeGetProp(filter, 'schemes', 'intentFilter');
      const fHost = safeGetProp(filter, 'host', 'intentFilter');
      const fHosts = safeGetProp(filter, 'hosts', 'intentFilter');
      const fMimeType = safeGetProp(filter, 'mimeType', 'intentFilter');
      const fMimeTypes = safeGetProp(filter, 'mimeTypes', 'intentFilter');
      const fExtension = safeGetProp(filter, 'extension', 'intentFilter');
      const fExtensions = safeGetProp(filter, 'extensions', 'intentFilter');
      const fPriority = safeGetProp(filter, 'priority', 'intentFilter');
      const fPlatform = safeGetProp(filter, 'platform', 'intentFilter');
      const fLabel = safeGetProp(filter, 'label', 'intentFilter');

      const processDataItem = (d) => {
        let dObj = null;
        if (d !== null && d !== undefined) {
          if (isReadableObject(d, 'intentFilter.data')) {
            dObj = d;
          }
        }
        const desc = {
          actions: baseActions,
          categories: baseCats,
          scheme: (dObj ? safeGetProp(dObj, 'scheme', 'intentFilter.data') : undefined) ?? fScheme,
          schemes: (dObj ? safeGetProp(dObj, 'schemes', 'intentFilter.data') : undefined) ?? fSchemes,
          host: (dObj ? safeGetProp(dObj, 'host', 'intentFilter.data') : undefined) ?? fHost,
          hosts: (dObj ? safeGetProp(dObj, 'hosts', 'intentFilter.data') : undefined) ?? fHosts,
          mimeType: (dObj ? safeGetProp(dObj, 'mimeType', 'intentFilter.data') : undefined) ?? fMimeType,
          mimeTypes: (dObj ? safeGetProp(dObj, 'mimeTypes', 'intentFilter.data') : undefined) ?? fMimeTypes,
          extension:
            (dObj
              ? (safeGetProp(dObj, 'pathExtension', 'intentFilter.data') ??
                safeGetProp(dObj, 'extension', 'intentFilter.data'))
              : undefined) ?? fExtension,
          extensions: (dObj ? safeGetProp(dObj, 'extensions', 'intentFilter.data') : undefined) ?? fExtensions,
          priority: fPriority,
          platform: fPlatform ?? defaults.platform ?? 'android',
          label: fLabel ?? defaults.label,
        };
        const norm = normalizeFlatDescriptor(desc, defaults, budget);
        if (norm) out.push(norm);
      };

      if (isReadableArrayProp(rawFilterData, 'intentFilter.data')) {
        let hadData = false;
        forEachSafeArrayItem(rawFilterData, 'intentFilter.data', (d) => {
          hadData = true;
          processDataItem(d);
        });
        if (!hadData) {
          processDataItem(null);
        }
      } else {
        processDataItem(null);
      }
    });
  }

  // Apple CFBundleURLTypes
  const rawUrlTypes = safeGetProp(handlers, 'CFBundleURLTypes', 'manifest');
  if (isReadableArrayProp(rawUrlTypes, 'manifest.CFBundleURLTypes')) {
    recognizedManifest = true;
    forEachSafeArrayItem(rawUrlTypes, 'manifest.CFBundleURLTypes', (urlType) => {
      if (!isReadableObject(urlType, 'CFBundleURLType')) {
        chargeManifestEntries(budget, 1, 8, 'manifest.CFBundleURLTypes');
        return;
      }
      const norm = normalizeFlatDescriptor(
        {
          schemes:
            safeGetProp(urlType, 'CFBundleURLSchemes', 'CFBundleURLType') ??
            safeGetProp(urlType, 'schemes', 'CFBundleURLType') ??
            [],
          label: safeGetProp(urlType, 'CFBundleURLName', 'CFBundleURLType') ?? defaults.label,
          platform: defaults.platform ?? 'ios',
          priority: safeGetProp(urlType, 'priority', 'CFBundleURLType'),
        },
        defaults,
        budget
      );
      if (norm) out.push(norm);
    });
  }

  // Apple CFBundleDocumentTypes
  const rawDocTypes = safeGetProp(handlers, 'CFBundleDocumentTypes', 'manifest');
  if (isReadableArrayProp(rawDocTypes, 'manifest.CFBundleDocumentTypes')) {
    recognizedManifest = true;
    forEachSafeArrayItem(rawDocTypes, 'manifest.CFBundleDocumentTypes', (docType) => {
      if (!isReadableObject(docType, 'CFBundleDocumentType')) {
        chargeManifestEntries(budget, 1, 8, 'manifest.CFBundleDocumentTypes');
        return;
      }
      const exts = toStringList(
        null,
        safeGetProp(docType, 'CFBundleTypeExtensions', 'CFBundleDocumentType'),
        'CFBundleTypeExtensions',
        budget
      );
      const mimes = toStringList(
        null,
        safeGetProp(docType, 'CFBundleTypeMIMETypes', 'CFBundleDocumentType'),
        'CFBundleTypeMIMETypes',
        budget
      );
      const utis = toStringList(
        null,
        safeGetProp(docType, 'LSItemContentTypes', 'CFBundleDocumentType'),
        'LSItemContentTypes',
        budget
      );
      for (const uti of utis) {
        if (typeof uti !== 'string') continue;
        const mapped = UTI_TYPE_MAP[uti.trim().toLowerCase()];
        if (mapped) {
          for (const ext of mapped.extensions) {
            chargeManifestEntries(budget, 1, ext.length + 2, 'LSItemContentTypes');
            exts.push(ext);
          }
          for (const mime of mapped.mimeTypes) {
            chargeManifestEntries(budget, 1, mime.length + 2, 'LSItemContentTypes');
            mimes.push(mime);
          }
        }
      }
      const norm = normalizeFlatDescriptor(
        {
          actions: ['view', 'edit'],
          extensions: exts,
          mimeTypes: mimes,
          label: safeGetProp(docType, 'CFBundleTypeName', 'CFBundleDocumentType') ?? defaults.label,
          platform: defaults.platform ?? 'macos',
          priority: safeGetProp(docType, 'priority', 'CFBundleDocumentType'),
        },
        defaults,
        budget
      );
      if (norm) out.push(norm);
    });
  }

  // Windows HKCR fileAssociations / urlSchemes
  const rawFileAssocs = safeGetProp(handlers, 'fileAssociations', 'manifest');
  if (isReadableArrayProp(rawFileAssocs, 'manifest.fileAssociations')) {
    recognizedManifest = true;
    forEachSafeArrayItem(rawFileAssocs, 'manifest.fileAssociations', (assoc) => {
      if (typeof assoc === 'string') {
        const norm = normalizeFlatDescriptor(
          { actions: ['view'], extension: assoc, platform: defaults.platform ?? 'windows' },
          defaults,
          budget
        );
        if (norm) out.push(norm);
      } else if (isReadableObject(assoc, 'fileAssociation')) {
        const norm = normalizeFlatDescriptor(
          {
            actions: safeGetProp(assoc, 'actions', 'fileAssociation') ?? ['view'],
            extension: safeGetProp(assoc, 'extension', 'fileAssociation'),
            extensions: safeGetProp(assoc, 'extensions', 'fileAssociation'),
            mimeType: safeGetProp(assoc, 'mimeType', 'fileAssociation'),
            mimeTypes: safeGetProp(assoc, 'mimeTypes', 'fileAssociation'),
            label:
              safeGetProp(assoc, 'progId', 'fileAssociation') ??
              safeGetProp(assoc, 'label', 'fileAssociation') ??
              defaults.label,
            platform: defaults.platform ?? 'windows',
            priority: safeGetProp(assoc, 'priority', 'fileAssociation'),
          },
          defaults,
          budget
        );
        if (norm) out.push(norm);
      } else {
        chargeManifestEntries(budget, 1, 8, 'manifest.fileAssociations');
      }
    });
  }

  const rawUrlSchemes = safeGetProp(handlers, 'urlSchemes', 'manifest');
  if (isReadableArrayProp(rawUrlSchemes, 'manifest.urlSchemes')) {
    recognizedManifest = true;
    forEachSafeArrayItem(rawUrlSchemes, 'manifest.urlSchemes', (sc) => {
      if (typeof sc === 'string') {
        const norm = normalizeFlatDescriptor(
          { scheme: sc, platform: defaults.platform ?? 'windows' },
          defaults,
          budget
        );
        if (norm) out.push(norm);
      } else if (isReadableObject(sc, 'urlScheme')) {
        const norm = normalizeFlatDescriptor(
          sc,
          {
            platform: safeGetProp(sc, 'platform', 'urlScheme') ?? defaults.platform ?? 'windows',
            label: defaults.label,
          },
          budget
        );
        if (norm) out.push(norm);
      } else {
        chargeManifestEntries(budget, 1, 8, 'manifest.urlSchemes');
      }
    });
  }

  // Universal wrapper `{ handlers: [...] }`
  const rawNestedHandlers = safeGetProp(handlers, 'handlers', 'manifest');
  if (isReadableArrayProp(rawNestedHandlers, 'manifest.handlers')) {
    recognizedManifest = true;
    forEachSafeArrayItem(rawNestedHandlers, 'manifest.handlers', (item) => {
      const norm = normalizeFlatDescriptor(item, defaults, budget);
      if (norm) {
        out.push(norm);
      } else {
        chargeManifestEntries(budget, 1, 8, 'manifest.handlers');
      }
    });
  }

  // Single flat descriptor object fallback
  if (!recognizedManifest) {
    const single = normalizeFlatDescriptor(handlers, defaults, budget);
    if (single) out.push(single);
  }

  return out;
}

export class IntentRouter {
  constructor(opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'IntentRouter options');
    const kernel = safeGetProp(optsObj, 'kernel', 'IntentRouter options') ?? null;
    const rawEventBus = safeGetProp(optsObj, 'eventBus', 'IntentRouter options');
    const rawProcessManager = safeGetProp(optsObj, 'processManager', 'IntentRouter options');
    const configStore = safeGetProp(optsObj, 'configStore', 'IntentRouter options') ?? null;
    const launcher = safeGetProp(optsObj, 'launcher', 'IntentRouter options') ?? null;
    const log = safeGetProp(optsObj, 'log', 'IntentRouter options');
    const rawMaxPendingChoosers = safeGetProp(optsObj, 'maxPendingChoosers', 'IntentRouter options');

    if (kernel !== null && typeof kernel !== 'object') {
      throw new OmniOSError('IntentRouter kernel must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const kernelBus = kernel ? (safeGetProp(kernel, 'eventBus', 'IntentRouter kernel') ?? null) : null;
    const kernelPm = kernel ? (safeGetProp(kernel, 'processManager', 'IntentRouter kernel') ?? null) : null;
    const eventBus = rawEventBus !== undefined ? rawEventBus : kernelBus;
    const processManager = rawProcessManager !== undefined ? rawProcessManager : kernelPm;

    if (eventBus !== null) {
      if (typeof eventBus !== 'object') {
        throw new OmniOSError('IntentRouter eventBus must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(eventBus, 'emit', 'IntentRouter eventBus');
    }
    if (processManager !== null) {
      if (typeof processManager !== 'object') {
        throw new OmniOSError('IntentRouter processManager must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(processManager, 'getAll', 'IntentRouter processManager');
    }
    if (configStore !== null) {
      if (typeof configStore !== 'object') {
        throw new OmniOSError('IntentRouter configStore must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(configStore, 'system', 'IntentRouter configStore');
    }

    const maxPendingChoosers = rawMaxPendingChoosers !== undefined ? rawMaxPendingChoosers : 256;

    this._eventBus = eventBus;
    this._processManager = processManager;
    this._configStore = configStore;
    this._launcher = typeof launcher === 'function' ? launcher : null;
    this._log = typeof log === 'function' ? log : () => {};
    this._maxPendingChoosers =
      Number.isSafeInteger(maxPendingChoosers) && maxPendingChoosers >= 1 ? maxPendingChoosers : 256;

    this._handlersByApp = new Map();
    this._defaults = new Map();
    this._pendingChoosers = new Map();
    this._chooserSeq = 0;
  }

  setLauncher(launcher) {
    this._launcher = typeof launcher === 'function' ? launcher : null;
  }

  _emit(event, payload) {
    if (!this._eventBus) return;
    try {
      this._eventBus.emit(event, payload);
    } catch {
      // Fault-isolated emit.
    }
  }

  _dedupeDescriptors(list) {
    const seen = new Set();
    const out = [];
    const sortSet = (s) => Array.from(s).sort().join('\0');
    for (const h of list) {
      let sig = DESCRIPTOR_SIG_CACHE.get(h);
      if (sig === undefined) {
        try {
          sig = JSON.stringify([
            sortSet(h.actions),
            sortSet(h.schemes),
            sortSet(h.extensions),
            sortSet(h.mimeTypes),
            sortSet(h.hosts),
            sortSet(h.categories),
            h.priority,
            typeof h.platform === 'string' ? h.platform : null,
            typeof h.label === 'string' ? h.label : null,
          ]);
        } catch (err) {
          throw new OmniOSError('Intent handler descriptor exceeds serializable signature size', {
            code: ERROR_CODES.EINVAL,
            cause: isErrorInstance(err) ? err : undefined,
          });
        }
        DESCRIPTOR_SIG_CACHE.set(h, sig);
      }
      if (seen.has(sig)) continue;
      seen.add(sig);
      out.push(h);
    }
    return out;
  }

  registerHandlers(appId, handlers, opts = {}) {
    const cleanAppId = validateAppId(appId);
    const optsObj = normalizeReadableOptions(opts, 'registerHandlers options');
    const rawPlatformOpt = safeGetProp(optsObj, 'platform', 'registerHandlers options') ?? null;
    const rawLabelOpt = safeGetProp(optsObj, 'label', 'registerHandlers options') ?? null;
    let platform = null;
    if (typeof rawPlatformOpt === 'string') {
      if (rawPlatformOpt.length > MAX_ROUTER_FIELD_CHARS) {
        throw new QuotaExceededError(
          `registerHandlers options.platform exceeds maximum length (${MAX_ROUTER_FIELD_CHARS} bytes)`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: 'manifestBytes',
            limit: MAX_ROUTER_FIELD_CHARS,
            actual: rawPlatformOpt.length,
          }
        );
      }
      const trimmedPlatformOpt = rawPlatformOpt.trim();
      platform = trimmedPlatformOpt.length > 0 ? trimmedPlatformOpt : null;
    }
    let label = null;
    if (typeof rawLabelOpt === 'string') {
      if (rawLabelOpt.length > MAX_ROUTER_FIELD_CHARS) {
        throw new QuotaExceededError(
          `registerHandlers options.label exceeds maximum length (${MAX_ROUTER_FIELD_CHARS} bytes)`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: 'manifestBytes',
            limit: MAX_ROUTER_FIELD_CHARS,
            actual: rawLabelOpt.length,
          }
        );
      }
      label = rawLabelOpt;
    }
    const rawReplace = safeGetProp(optsObj, 'replace', 'registerHandlers options');
    const replace = rawReplace !== undefined ? Boolean(rawReplace) : true;
    const normalized = this._dedupeDescriptors(normalizeManifestInput(handlers, { platform, label }));

    if (replace) {
      if (normalized.length === 0) {
        this._handlersByApp.delete(cleanAppId);
      } else {
        this._handlersByApp.set(cleanAppId, normalized);
      }
    } else {
      const existing = this._handlersByApp.get(cleanAppId) ?? [];
      if (existing.length + normalized.length > MAX_MANIFEST_DESCRIPTORS) {
        throw new QuotaExceededError(
          `App "${cleanAppId}" handlers exceed maximum descriptor limit (${MAX_MANIFEST_DESCRIPTORS})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: 'manifestDescriptors',
            limit: MAX_MANIFEST_DESCRIPTORS,
            actual: existing.length + normalized.length,
          }
        );
      }
      const existingStats = measureDescriptors(existing);
      const newStats = measureDescriptors(normalized);
      if (existingStats.entries + newStats.entries > MAX_MANIFEST_ENTRIES) {
        throw new QuotaExceededError(
          `App "${cleanAppId}" handlers exceed maximum matcher entry limit (${MAX_MANIFEST_ENTRIES})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: 'manifestEntries',
            limit: MAX_MANIFEST_ENTRIES,
            actual: existingStats.entries + newStats.entries,
          }
        );
      }
      if (existingStats.bytes + newStats.bytes > MAX_MANIFEST_BYTES) {
        throw new QuotaExceededError(
          `App "${cleanAppId}" handlers exceed maximum byte limit (${MAX_MANIFEST_BYTES} bytes)`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: 'manifestBytes',
            limit: MAX_MANIFEST_BYTES,
            actual: existingStats.bytes + newStats.bytes,
          }
        );
      }
      const merged = this._dedupeDescriptors([...existing, ...normalized]);
      if (merged.length > 0) {
        this._handlersByApp.set(cleanAppId, merged);
      }
    }

    return {
      appId: cleanAppId,
      count: (this._handlersByApp.get(cleanAppId) ?? []).length,
    };
  }

  unregisterApp(appId) {
    if (typeof appId !== 'string' || appId.length === 0 || appId.length > MAX_ROUTER_FIELD_CHARS) return false;
    const cleanAppId = appId.trim();
    if (cleanAppId.length === 0) return false;
    const hadHandlers = this._handlersByApp.delete(cleanAppId);

    let removedDefaults = false;
    for (const [key, boundApp] of Array.from(this._defaults.entries())) {
      if (boundApp === cleanAppId) {
        this._defaults.delete(key);
        removedDefaults = true;
      }
    }

    for (const [reqId, pending] of Array.from(this._pendingChoosers.entries())) {
      const filtered = pending.candidates.filter((c) => c.appId !== cleanAppId);
      if (filtered.length === 0) {
        this._pendingChoosers.delete(reqId);
      } else if (filtered.length !== pending.candidates.length) {
        pending.candidates = filtered;
      }
    }

    return hadHandlers || removedDefaults;
  }

  unregisterHandlers(appId) {
    return this.unregisterApp(appId);
  }

  indexRegistryAssociations(configStore = this._configStore) {
    let indexed = 0;
    try {
      if (!configStore || !configStore.registry || typeof configStore.registry.enumKey !== 'function') {
        return { indexed: 0 };
      }
      const root = configStore.registry.enumKey('HKCR', '');
      if (!root || !Array.isArray(root.subkeys) || typeof configStore.registry.getValue !== 'function') {
        return { indexed: 0 };
      }

      const subkeys = root.subkeys;
      for (let i = 0; i < subkeys.length; i++) {
        let subkey;
        try {
          subkey = subkeys[i];
        } catch (_elemErr) {
          // Isolate unreadable subkey entry so remaining associations continue indexing.
          continue;
        }
        if (
          typeof subkey !== 'string' ||
          subkey.length === 0 ||
          subkey.length > MAX_ROUTER_FIELD_CHARS ||
          subkey.includes('\0')
        ) {
          continue;
        }

        let rawAppId = null;
        let rawMime = null;
        let isUrlProtocol = false;
        try {
          const appIdVal = configStore.registry.getValue('HKCR', subkey, 'OmniOSAppId');
          const mimeVal = configStore.registry.getValue('HKCR', subkey, 'Content Type');
          const urlProtoVal = configStore.registry.getValue('HKCR', subkey, 'URL Protocol');
          rawAppId = appIdVal?.data;
          rawMime = mimeVal?.data;
          isUrlProtocol = urlProtoVal !== null && urlProtoVal !== undefined;
        } catch (_readErr) {
          // Isolate Registry read errors for a single HKCR subkey.
          continue;
        }

        let targetAppId =
          typeof rawAppId === 'string' &&
          rawAppId.length > 0 &&
          rawAppId.length <= MAX_ROUTER_FIELD_CHARS &&
          !rawAppId.includes('\0')
            ? rawAppId.trim() || null
            : null;
        if (!targetAppId) {
          // Follow ProgID default value (`HKCR\.ext` `(Default)` -> `HKCR\<ProgID>\OmniOSAppId`)
          try {
            const defVal = configStore.registry.getValue('HKCR', subkey, '');
            const rawDef = defVal?.data;
            const defTrimmed =
              typeof rawDef === 'string' &&
              rawDef.length > 0 &&
              rawDef.length <= MAX_ROUTER_FIELD_CHARS &&
              !rawDef.includes('\0')
                ? rawDef.trim()
                : '';
            if (defTrimmed) {
              const progApp = configStore.registry.getValue('HKCR', defTrimmed, 'OmniOSAppId');
              const rawProgApp = progApp?.data;
              const progTrimmed =
                typeof rawProgApp === 'string' &&
                rawProgApp.length > 0 &&
                rawProgApp.length <= MAX_ROUTER_FIELD_CHARS &&
                !rawProgApp.includes('\0')
                  ? rawProgApp.trim()
                  : '';
              if (progTrimmed) {
                targetAppId = progTrimmed;
              }
            }
          } catch (_progErr) {
            // Ignore missing or unreadable ProgID target for this subkey.
          }
        }
        if (!targetAppId) continue;

        const mimeType =
          typeof rawMime === 'string' &&
          rawMime.length > 0 &&
          rawMime.length <= MAX_ROUTER_FIELD_CHARS &&
          !rawMime.includes('\0') &&
          rawMime.trim().length > 0
            ? rawMime.trim()
            : undefined;

        try {
          if (subkey.startsWith('.')) {
            const cleanExt = normalizeExtension(subkey);
            if (!cleanExt) continue;
            this.registerHandlers(
              targetAppId,
              [
                {
                  actions: ['view'],
                  extension: cleanExt,
                  mimeType,
                  platform: 'windows',
                },
              ],
              { platform: 'windows', replace: false }
            );
            indexed += 1;
          } else if (isUrlProtocol) {
            const cleanScheme = normalizeScheme(subkey);
            if (!cleanScheme) continue;
            this.registerHandlers(
              targetAppId,
              [{ scheme: cleanScheme, platform: 'windows' }],
              { platform: 'windows', replace: false }
            );
            indexed += 1;
          }
        } catch (subErr) {
          // Isolate single malformed or over-quota HKCR subkey so remaining system associations continue indexing.
          try {
            this._log(
              'warn',
              'router',
              `Skipped HKCR association "${capDisplayString(subkey)}": ${safeErrorMessage(subErr)}`
            );
          } catch {
            // Isolate logger failures.
          }
          continue;
        }
      }
    } catch (err) {
      try {
        this._log('warn', 'router', `Failed to index HKCR associations: ${safeErrorMessage(err)}`);
      } catch {
        // Isolate logger failures.
      }
    }
    return { indexed };
  }

  setDefaultHandler(criteria, appId) {
    const key = normalizeCriteriaKey(criteria);
    if (appId === null || appId === undefined) {
      return this._defaults.delete(key);
    }
    const cleanAppId = validateAppId(appId);
    this._defaults.set(key, cleanAppId);
    return true;
  }

  getDefaultHandler(criteria) {
    const key = normalizeCriteriaKey(criteria);
    return this._defaults.get(key) ?? null;
  }

  listHandlers(appId = undefined) {
    const serialize = (id, list) => ({
      appId: id,
      handlers: list.map((h) => ({
        actions: Array.from(h.actions),
        schemes: Array.from(h.schemes),
        extensions: Array.from(h.extensions),
        mimeTypes: Array.from(h.mimeTypes),
        hosts: Array.from(h.hosts),
        categories: Array.from(h.categories),
        priority: h.priority,
        platform: h.platform,
        label: h.label,
      })),
    });

    if (appId !== undefined) {
      const list = this._handlersByApp.get(appId);
      return list ? [serialize(appId, list)] : [];
    }
    const out = [];
    for (const [id, list] of this._handlersByApp.entries()) {
      out.push(serialize(id, list));
    }
    return out;
  }

  resolve(query = {}) {
    const qObj = normalizeReadableOptions(query, 'resolve query');
    const action = safeGetProp(qObj, 'action', 'resolve query') ?? null;
    const uri = safeGetProp(qObj, 'uri', 'resolve query') ?? null;
    const mimeType = safeGetProp(qObj, 'mimeType', 'resolve query') ?? null;
    const extension = safeGetProp(qObj, 'extension', 'resolve query') ?? null;
    const scheme = safeGetProp(qObj, 'scheme', 'resolve query') ?? null;
    const host = safeGetProp(qObj, 'host', 'resolve query') ?? null;

    const parsedUri = parseUriSafely(uri);
    const qAction = normalizeAction(action);
    const qScheme = normalizeScheme(scheme ?? parsedUri.scheme);
    const qHost = normalizeHost(host ?? parsedUri.host);
    const qExtension = normalizeExtension(extension ?? parsedUri.extension);
    const qExplicitMime = normalizeMimeType(mimeType);
    const qInferredMime = !qExplicitMime && qExtension ? (EXT_TO_MIME[qExtension] ?? null) : null;

    if (!qAction && !qScheme && !qExtension && !qExplicitMime && !qHost) {
      return [];
    }

    const bestByApp = new Map();

    for (const [appId, handlers] of this._handlersByApp.entries()) {
      for (const h of handlers) {
        // 1. Disqualification guards
        if (qAction && h.actions.size > 0 && !h.actions.has(qAction)) continue;

        // Custom / non-file URL schemes MUST only match handlers explicitly declaring that scheme
        // (never allow pure local file-association handlers with `h.schemes.size === 0` to hijack custom schemes).
        if (qScheme && qScheme !== 'file') {
          if (!h.schemes.has(qScheme)) continue;
        } else if (qScheme === 'file') {
          if (h.schemes.size > 0 && !h.schemes.has('file')) continue;
        }

        const explicitMimeScore = qExplicitMime ? matchMime(qExplicitMime, h.mimeTypes) : 0;
        if (qExplicitMime && h.mimeTypes.size > 0 && explicitMimeScore === 0) continue;

        const inferredMimeScore = qInferredMime ? matchMime(qInferredMime, h.mimeTypes) : 0;
        const effectiveMimeScore = explicitMimeScore > 0 ? explicitMimeScore : inferredMimeScore > 0 ? Math.min(25, inferredMimeScore) : 0;

        if (qExtension && h.extensions.size > 0 && !h.extensions.has(qExtension)) {
          if (explicitMimeScore === 0) continue;
        }

        if (qHost && h.hosts.size > 0 && !h.hosts.has(qHost)) continue;

        // Scheme-only handlers require a matching scheme in the query
        if (
          h.schemes.size > 0 &&
          h.actions.size === 0 &&
          h.extensions.size === 0 &&
          h.mimeTypes.size === 0 &&
          (!qScheme || !h.schemes.has(qScheme))
        ) {
          continue;
        }

        // If a handler declares data constraints (schemes, extensions, mimeTypes, or hosts)
        // and the query targets specific data (non-file URL scheme, extension, MIME type, or host),
        // require at least one data constraint to match so unrelated file/mime handlers
        // never hijack custom URL schemes or mismatched content types on generic actions like 'view'.
        const handlerHasDataConstraint =
          h.schemes.size > 0 || h.extensions.size > 0 || h.mimeTypes.size > 0 || h.hosts.size > 0;
        const queryHasData = Boolean(
          (qScheme && qScheme !== 'file') || qExtension || qExplicitMime || qHost
        );
        if (handlerHasDataConstraint && queryHasData) {
          const schemeMatched = Boolean(qScheme && qScheme !== 'file' && h.schemes.has(qScheme));
          const extMatched = Boolean(qExtension && h.extensions.has(qExtension));
          const hostMatched = Boolean(qHost && h.hosts.has(qHost));
          if (!schemeMatched && !extMatched && effectiveMimeScore === 0 && !hostMatched) {
            continue;
          }
        }

        // 2. Additive Match Score
        let matchScore = 0;
        const matchedOn = [];

        if (qScheme && h.schemes.has(qScheme)) {
          matchScore += qScheme === 'file' ? 10 : 40;
          matchedOn.push(`scheme:${qScheme}`);
        }
        if (qExtension && h.extensions.has(qExtension)) {
          matchScore += 35;
          matchedOn.push(`ext:${qExtension}`);
        }
        if (effectiveMimeScore > 0) {
          matchScore += effectiveMimeScore;
          matchedOn.push(`mime:${qExplicitMime ?? qInferredMime}`);
        }
        if (qAction && h.actions.has(qAction)) {
          matchScore += 25;
          matchedOn.push(`action:${qAction}`);
        }
        if (qHost && h.hosts.has(qHost)) {
          matchScore += 10;
          matchedOn.push(`host:${qHost}`);
        }

        if (matchScore <= 0) continue;

        // If query explicitly specified a MIME type or extension AND handler had no match on either
        // (e.g. only matched generic `action: 'view'` while a custom URL scheme or file type was requested),
        // still allow generic action match only if no required domain mismatch happened above.
        const score = matchScore + h.priority;
        const existing = bestByApp.get(appId);
        if (!existing || score > existing.score || (score === existing.score && h.priority > existing.priority)) {
          bestByApp.set(appId, {
            appId,
            platform: h.platform,
            label: h.label,
            score,
            priority: h.priority,
            isDefault: false,
            matchedOn,
          });
        }
      }
    }

    if (bestByApp.size === 0) return [];

    // Resolve default binding in specificity order
    const defaultKeysToCheck = [];
    const compoundKey = buildCriteriaKeyFromObject({
      action: qAction,
      scheme: qScheme,
      extension: qExtension,
      mimeType: qExplicitMime,
    });
    if (compoundKey) defaultKeysToCheck.push(compoundKey);
    if (qScheme && qScheme !== 'file') defaultKeysToCheck.push(`scheme:${qScheme}`);
    if (qExtension) defaultKeysToCheck.push(`ext:${qExtension}`);
    if (qExplicitMime) defaultKeysToCheck.push(`mime:${qExplicitMime}`);
    if (qInferredMime) defaultKeysToCheck.push(`mime:${qInferredMime}`);
    if (qAction) defaultKeysToCheck.push(`action:${qAction}`);

    for (const key of defaultKeysToCheck) {
      const boundApp = this._defaults.get(key);
      if (boundApp && bestByApp.has(boundApp)) {
        bestByApp.get(boundApp).isDefault = true;
        break;
      }
    }

    const candidates = Array.from(bestByApp.values());
    candidates.sort((a, b) => {
      if (a.isDefault !== b.isDefault) return a.isDefault ? -1 : 1;
      if (b.score !== a.score) return b.score - a.score;
      if (b.priority !== a.priority) return b.priority - a.priority;
      return a.appId < b.appId ? -1 : a.appId > b.appId ? 1 : 0;
    });

    return candidates;
  }

  _deliver(targetAppId, intent, extraFields = {}) {
    const clonedIntent = cloneIntentRecord(intent);

    // 1. Deliver directly to an active process for targetAppId if running
    if (this._processManager) {
      let activePcb = null;
      try {
        const getAllFn = this._processManager.getAll;
        if (typeof getAllFn === 'function') {
          const pcbs = getAllFn.call(this._processManager);
          if (Array.isArray(pcbs)) {
            activePcb = pcbs.find(
              (pcb) => pcb && pcb.appId === targetAppId && pcb.state !== 'ZOMBIE' && pcb.state !== 'TERMINATED'
            ) ?? null;
          }
        }
      } catch (err) {
        try {
          this._log(
            'warn',
            'router',
            `ProcessManager lookup failed during intent delivery: ${safeErrorMessage(err)}`
          );
        } catch {
          // Isolate logger failures.
        }
      }
      if (activePcb) {
        try {
          const execCtx = activePcb.executionContext;
          const deliverFn = execCtx?.deliverEvent;
          if (typeof deliverFn === 'function') {
            const ret = deliverFn.call(execCtx, { type: 'intent', intent: clonedIntent });
            suppressAsyncRejection(ret, (err) => {
              try {
                this._log(
                  'warn',
                  'router',
                  `Async error delivering intent to PID ${activePcb.pid} (${safeErrorCode(err)}): ${safeErrorMessage(err)}`
                );
              } catch {
                // Isolate logger failures.
              }
            });
          }
        } catch (err) {
          try {
            this._log(
              'warn',
              'router',
              `Failed delivering intent to PID ${activePcb.pid} (${safeErrorCode(err)}): ${safeErrorMessage(err)}`
            );
          } catch {
            // Isolate logger failures.
          }
        }
        try {
          if (activePcb.state === 'BLOCKED' && typeof this._processManager.wake === 'function') {
            this._processManager.wake(activePcb.pid);
          }
        } catch {
          // Ignore wake errors.
        }
        this._emit('intent:delivered', {
          targetAppId,
          pid: activePcb.pid,
          launched: false,
          intent: cloneIntentRecord(intent),
        });
        return {
          status: 'DELIVERED',
          targetAppId,
          pid: activePcb.pid,
          launched: false,
          ...extraFields,
        };
      }
    }

    // 2. Otherwise launch via injected launcher hook if configured
    if (this._launcher) {
      const launchRes = this._launcher(targetAppId, { intent: clonedIntent });
      if (isThenable(launchRes)) {
        return launchRes.then((r) => {
          const pid = r?.pid ?? null;
          this._emit('intent:delivered', {
            targetAppId,
            pid,
            launched: true,
            intent: cloneIntentRecord(intent),
          });
          return {
            status: 'DELIVERED',
            targetAppId,
            pid,
            launched: true,
            ...extraFields,
          };
        });
      }
      const pid = launchRes?.pid ?? null;
      this._emit('intent:delivered', {
        targetAppId,
        pid,
        launched: true,
        intent: cloneIntentRecord(intent),
      });
      return {
        status: 'DELIVERED',
        targetAppId,
        pid,
        launched: true,
        ...extraFields,
      };
    }

    // 3. Standalone router (no process manager or launcher)
    this._emit('intent:delivered', {
      targetAppId,
      pid: null,
      launched: false,
      intent: cloneIntentRecord(intent),
    });
    return {
      status: 'DELIVERED',
      targetAppId,
      pid: null,
      launched: false,
      ...extraFields,
    };
  }

  dispatch(intentOpts = {}) {
    const optsObj = normalizeReadableOptions(intentOpts, 'dispatch intent');
    const action = safeGetProp(optsObj, 'action', 'dispatch intent') ?? null;
    const uri = safeGetProp(optsObj, 'uri', 'dispatch intent') ?? null;
    const mimeType = safeGetProp(optsObj, 'mimeType', 'dispatch intent') ?? null;
    const extension = safeGetProp(optsObj, 'extension', 'dispatch intent') ?? null;
    const scheme = safeGetProp(optsObj, 'scheme', 'dispatch intent') ?? null;
    const host = safeGetProp(optsObj, 'host', 'dispatch intent') ?? null;
    const rawExtras = safeGetProp(optsObj, 'extras', 'dispatch intent');
    const extras = rawExtras !== undefined ? rawExtras : {};
    const sourcePid = safeGetProp(optsObj, 'sourcePid', 'dispatch intent') ?? null;
    const preferredAppId = safeGetProp(optsObj, 'preferredAppId', 'dispatch intent') ?? null;

    if (preferredAppId !== null && preferredAppId !== undefined) {
      if (
        typeof preferredAppId !== 'string' ||
        preferredAppId.length === 0 ||
        preferredAppId.length > MAX_ROUTER_FIELD_CHARS ||
        preferredAppId.trim().length === 0
      ) {
        throw new OmniOSError(`Invalid preferredAppId: ${safeDisplayValue(preferredAppId)}`, {
          code: ERROR_CODES.EINVAL,
          details: { preferredAppId: safeDisplayValue(preferredAppId) },
        });
      }
    }

    const candidates = this.resolve({ action, uri, mimeType, extension, scheme, host });
    const clonedExtras = cloneFieldOrThrow(extras ?? {}, 'intent.extras');
    const intentRecord = {
      action: normalizeAction(action),
      uri: typeof uri === 'string' ? uri : null,
      mimeType: normalizeMimeType(mimeType),
      extension: normalizeExtension(extension),
      scheme: normalizeScheme(scheme),
      host: normalizeHost(host),
      extras: clonedExtras,
      sourcePid: typeof sourcePid === 'number' ? sourcePid : null,
      ts: new Date().toISOString(),
    };

    if (candidates.length === 0) {
      return { status: 'NO_HANDLER', candidates: [] };
    }

    if (preferredAppId !== null && preferredAppId !== undefined) {
      const match = candidates.find((c) => c.appId === preferredAppId);
      if (!match) {
        return {
          status: 'NO_HANDLER',
          reason: `Preferred handler "${safeDisplayValue(preferredAppId)}" does not match intent`,
          candidates: candidates.map(cloneCandidate),
        };
      }
      return this._deliver(match.appId, intentRecord);
    }

    if (candidates.length === 1 || candidates[0].isDefault === true) {
      return this._deliver(candidates[0].appId, intentRecord);
    }

    // Multiple matching handlers without a default -> Share Sheet chooser
    const requestId = `intent-${++this._chooserSeq}`;
    if (this._pendingChoosers.size >= this._maxPendingChoosers) {
      const oldestKey = this._pendingChoosers.keys().next().value;
      if (oldestKey !== undefined) {
        this._pendingChoosers.delete(oldestKey);
      }
    }

    const pending = {
      requestId,
      intent: intentRecord,
      candidates: candidates.map(cloneCandidate),
      createdAt: new Date().toISOString(),
    };
    this._pendingChoosers.set(requestId, pending);

    this._emit('intent:chooser', clonePendingChooser(pending));

    return {
      status: 'CHOOSER_REQUIRED',
      requestId,
      candidates: candidates.map(cloneCandidate),
    };
  }

  resolveChooser(requestId, chosenAppId, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'resolveChooser options');
    const setAsDefault = Boolean(safeGetProp(optsObj, 'setAsDefault', 'resolveChooser options'));
    const pending = this._pendingChoosers.get(requestId);
    if (!pending) {
      throw new OmniOSError(`Pending intent chooser not found: ${safeDisplayValue(requestId)}`, {
        code: ERROR_CODES.ENOENT,
        details: { requestId: safeDisplayValue(requestId) },
      });
    }

    const cleanAppId = validateAppId(chosenAppId);
    if (!pending.candidates.some((c) => c.appId === cleanAppId)) {
      throw new OmniOSError(`App "${cleanAppId}" is not a valid candidate for chooser "${safeDisplayValue(requestId)}"`, {
        code: ERROR_CODES.EINVAL,
        details: { requestId: safeDisplayValue(requestId), chosenAppId: cleanAppId },
      });
    }

    // Strictly one-shot: delete before delivery
    this._pendingChoosers.delete(requestId);

    if (setAsDefault) {
      const key = buildCriteriaKeyFromObject(pending.intent);
      if (key) {
        this._defaults.set(key, cleanAppId);
      }
    }

    return this._deliver(cleanAppId, pending.intent, { requestId });
  }

  cancelChooser(requestId) {
    const pending = this._pendingChoosers.get(requestId);
    if (!pending) return false;
    this._pendingChoosers.delete(requestId);
    this._emit('intent:chooser_cancelled', { requestId, intent: cloneIntentRecord(pending.intent) });
    return true;
  }

  listPendingChoosers() {
    const out = [];
    for (const pending of this._pendingChoosers.values()) {
      out.push(clonePendingChooser(pending));
    }
    return out;
  }
}

export function createIntentRouter(options = {}) {
  return new IntentRouter(options);
}
