/**
 * OmniOS Multi-MIME Shared Clipboard (`SharedClipboard`)
 * Supports `text/plain`, `text/html`, `application/json`, `image/png` (and extensible MIME formats)
 * with a bounded 20-entry history, entry size cap, prototype-safe JSON-safe deep cloning,
 * and live `clipboard:changed` KernelEventBus notifications.
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

export const SUPPORTED_CLIPBOARD_MIMES = Object.freeze([
  'text/plain',
  'text/html',
  'application/json',
  'image/png',
]);

export const DEFAULT_HISTORY_LIMIT = 20;
export const DEFAULT_MAX_ENTRY_BYTES = 4 * 1024 * 1024; // 4 MiB

const TEXT_ENCODER = new TextEncoder();
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

function defineSafeProp(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

const MAX_MIME_LENGTH = 4096;
const MAX_MIME_BASE_LENGTH = 256;
const MAX_META_STRING_LENGTH = 4096;

function normalizeMime(mime) {
  if (typeof mime !== 'string' || mime.length === 0 || mime.length > MAX_MIME_LENGTH) return null;
  const semi = mime.indexOf(';');
  const head = semi === -1 ? mime : mime.slice(0, semi);
  const cleaned = head.trim().toLowerCase();
  if (!cleaned || cleaned.length > MAX_MIME_BASE_LENGTH || !cleaned.includes('/') || cleaned.includes('\0')) {
    return null;
  }
  return cleaned;
}

function isErrorInstance(err) {
  try {
    return err instanceof Error;
  } catch {
    return false;
  }
}

const MAX_CLONE_ARRAY_LEN = 100_000;
const MAX_CLONE_NODES = 250_000;
const MAX_JSON_NESTING_DEPTH = 64;
const JSON_CONTAINER_BYTE_COST = 64;
const MAX_CLIPBOARD_FORMATS = 128;
const MAX_CLONE_BIGINT_ABS = 1n << 4096n;
const MAX_DISPLAY_LENGTH = 256;

function capDisplayString(str) {
  if (str.length > 65_536) return `[String(${str.length})]`;
  return str.length > MAX_DISPLAY_LENGTH ? `${str.slice(0, MAX_DISPLAY_LENGTH)}...` : str;
}

function consumeClipboardBytes(budget, delta) {
  if (delta > budget.remainingBytes) {
    const limit = budget.limitBytes ?? DEFAULT_MAX_ENTRY_BYTES;
    throw new QuotaExceededError(
      `Clipboard entry size exceeds limit (${limit} bytes)`,
      {
        code: ERROR_CODES.EFBIG,
        quotaType: 'clipboard',
        limit,
        actual: limit - budget.remainingBytes + delta,
      }
    );
  }
  budget.remainingBytes -= delta;
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
    throw new OmniOSError(`Unreadable clipboard property "${label}"`, {
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

function deepCloneJson(
  value,
  ancestors = new Set(),
  depth = 0,
  budget = {
    remaining: MAX_CLONE_NODES,
    remainingBytes: DEFAULT_MAX_ENTRY_BYTES,
    limitBytes: DEFAULT_MAX_ENTRY_BYTES,
  }
) {
  if (depth > 64) {
    throw new OmniOSError('JSON clipboard payload exceeds maximum nesting depth', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (value === null) {
    consumeClipboardBytes(budget, 4);
    return null;
  }
  const t = typeof value;
  if (t === 'boolean') {
    consumeClipboardBytes(budget, value ? 4 : 5);
    return value;
  }
  if (t === 'string') {
    consumeClipboardBytes(budget, value.length + 2);
    return value;
  }
  if (t === 'number') {
    if (!Number.isFinite(value)) {
      throw new OmniOSError('JSON clipboard payload cannot contain NaN or Infinity', {
        code: ERROR_CODES.EINVAL,
      });
    }
    consumeClipboardBytes(budget, 2);
    return value;
  }
  if (t !== 'object') {
    throw new OmniOSError(`Unsupported JSON clipboard value type: ${t}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (ancestors.has(value)) {
    throw new OmniOSError('Cyclic reference in JSON clipboard payload', {
      code: ERROR_CODES.EINVAL,
    });
  }
  let isArr = false;
  try {
    isArr = Array.isArray(value);
  } catch (err) {
    throw new OmniOSError('Unreadable JSON clipboard payload', {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  ancestors.add(value);
  try {
    if (isArr) {
      let len;
      try {
        len = value.length;
      } catch (err) {
        throw new OmniOSError('Unreadable JSON clipboard array length', {
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
        throw new OmniOSError('Invalid JSON clipboard array length', {
          code: ERROR_CODES.EINVAL,
        });
      }
      consumeClipboardBytes(budget, 64);
      if (len * 2 > budget.remainingBytes) {
        consumeClipboardBytes(budget, len * 2);
      }
      const arr = new Array(len);
      const canInlinePrim = depth < MAX_JSON_NESTING_DEPTH;
      for (let i = 0; i < len; i++) {
        if (budget.remaining <= 0) {
          throw new OmniOSError('JSON clipboard payload exceeds maximum element count', {
            code: ERROR_CODES.EINVAL,
          });
        }
        budget.remaining -= 1;
        let elem;
        try {
          elem = value[i];
        } catch (err) {
          throw new OmniOSError(`Unreadable JSON clipboard array index ${i}`, {
            code: ERROR_CODES.EINVAL,
            cause: isErrorInstance(err) ? err : undefined,
          });
        }
        if (elem === undefined) {
          consumeClipboardBytes(budget, 4);
          arr[i] = null;
        } else if (canInlinePrim && typeof elem === 'number') {
          if (!Number.isFinite(elem)) {
            throw new OmniOSError('JSON clipboard payload cannot contain NaN or Infinity', {
              code: ERROR_CODES.EINVAL,
            });
          }
          consumeClipboardBytes(budget, 2);
          arr[i] = elem;
        } else if (canInlinePrim && elem === null) {
          consumeClipboardBytes(budget, 4);
          arr[i] = null;
        } else if (canInlinePrim && typeof elem === 'boolean') {
          consumeClipboardBytes(budget, elem ? 4 : 5);
          arr[i] = elem;
        } else if (canInlinePrim && typeof elem === 'string') {
          consumeClipboardBytes(budget, elem.length + 2);
          arr[i] = elem;
        } else {
          arr[i] = deepCloneJson(elem, ancestors, depth + 1, budget);
        }
      }
      return arr;
    }
    if (types.isDate(value) && !types.isProxy(value)) {
      try {
        const ms = Date.prototype.getTime.call(value);
        if (Number.isFinite(ms)) {
          const iso = Date.prototype.toISOString.call(value);
          consumeClipboardBytes(budget, iso.length + 2);
          return iso;
        }
        consumeClipboardBytes(budget, 4);
        return null;
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError('Unreadable Date in JSON clipboard payload', {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
    }
    if (
      types.isProxy(value) ||
      types.isBoxedPrimitive(value) ||
      types.isArrayBuffer(value) ||
      types.isTypedArray(value) ||
      types.isDataView(value) ||
      types.isSharedArrayBuffer?.(value)
    ) {
      throw new OmniOSError('Proxied, boxed primitive, or binary object is not a valid JSON clipboard value', {
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
      throw new OmniOSError('Unreadable JSON clipboard payload', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (isSpoofedSpecial) {
      throw new OmniOSError('Spoofed or proxied binary/Date is not allowed in JSON clipboard payload', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const out = {};
    let keys;
    try {
      keys = Object.keys(value);
    } catch (err) {
      throw new OmniOSError('Unreadable JSON clipboard object keys', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (keys.length > MAX_CLONE_ARRAY_LEN || keys.length > budget.remaining) {
      throw new OmniOSError('JSON clipboard object exceeds maximum key count', {
        code: ERROR_CODES.EINVAL,
      });
    }
    consumeClipboardBytes(budget, 64);
    if (keys.length * 4 > budget.remainingBytes) {
      consumeClipboardBytes(budget, keys.length * 4);
    }
    let emittedKeys = 0;
    for (const key of keys) {
      if (budget.remaining <= 0) {
        throw new OmniOSError('JSON clipboard payload exceeds maximum element count', {
          code: ERROR_CODES.EINVAL,
        });
      }
      budget.remaining -= 1;
      let prop;
      try {
        prop = value[key];
      } catch (err) {
        throw new OmniOSError(`Unreadable JSON clipboard property "${safeDisplayValue(key)}"`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
      if (prop === undefined) continue;
      consumeClipboardBytes(budget, key.length + 3 + (emittedKeys > 0 ? 1 : 0));
      emittedKeys += 1;
      defineSafeProp(out, key, deepCloneJson(prop, ancestors, depth + 1, budget));
    }
    return out;
  } finally {
    ancestors.delete(value);
  }
}

function normalizeBase64Png(input, maxBytes = DEFAULT_MAX_ENTRY_BYTES, totalLimit = maxBytes) {
  const reportedLimit = Number.isSafeInteger(totalLimit) && totalLimit >= 0 ? totalLimit : maxBytes;
  const alreadyUsed = Math.max(0, reportedLimit - maxBytes);
  if (typeof input === 'string') {
    if (input.length > maxBytes * 2 + 64) {
      throw new QuotaExceededError(
        `Clipboard entry size exceeds limit (${reportedLimit} bytes)`,
        {
          code: ERROR_CODES.EFBIG,
          quotaType: 'clipboard',
          limit: reportedLimit,
          actual: alreadyUsed + input.length,
        }
      );
    }
    let trimmed = input.trim();
    const prefixMatch = /^data:image\/png;base64,/i.exec(trimmed);
    if (prefixMatch) {
      trimmed = trimmed.slice(prefixMatch[0].length);
    }
    const compact = trimmed.replace(/\s+/g, '');
    if (compact.length > maxBytes) {
      throw new QuotaExceededError(
        `Clipboard entry size (${alreadyUsed + compact.length} bytes) exceeds limit (${reportedLimit} bytes)`,
        {
          code: ERROR_CODES.EFBIG,
          quotaType: 'clipboard',
          limit: reportedLimit,
          actual: alreadyUsed + compact.length,
        }
      );
    }
    if (compact.length > 0 && ((compact.length & 3) !== 0 || !BASE64_PATTERN.test(compact))) {
      throw new OmniOSError('Invalid Base64 image/png clipboard payload', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return compact;
  }
  const bin = extractGenuineBytes(input);
  if (bin.detached) {
    throw new OmniOSError('Unreadable detached image/png clipboard payload', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (bin.ok) {
    const b64Len = Math.ceil(bin.bytes.byteLength / 3) * 4;
    if (b64Len > maxBytes) {
      throw new QuotaExceededError(
        `Clipboard entry size (${alreadyUsed + b64Len} bytes) exceeds limit (${reportedLimit} bytes)`,
        {
          code: ERROR_CODES.EFBIG,
          quotaType: 'clipboard',
          limit: reportedLimit,
          actual: alreadyUsed + b64Len,
        }
      );
    }
    try {
      return Buffer.from(bin.bytes.buffer, bin.bytes.byteOffset, bin.bytes.byteLength).toString('base64');
    } catch (err) {
      throw new OmniOSError('Unreadable image/png clipboard payload', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
  }
  throw new OmniOSError('image/png clipboard payload must be Uint8Array, ArrayBuffer, or Base64 string', {
    code: ERROR_CODES.EINVAL,
  });
}

function validateParsedJson(value, depth, budget) {
  if (depth > MAX_JSON_NESTING_DEPTH) {
    throw new OmniOSError('JSON clipboard payload exceeds maximum nesting depth', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (value === null) {
    consumeClipboardBytes(budget, 4);
    return;
  }
  const t = typeof value;
  if (t === 'number') {
    consumeClipboardBytes(budget, 2);
    return;
  }
  if (t === 'string') {
    consumeClipboardBytes(budget, value.length + 2);
    return;
  }
  if (t === 'boolean') {
    consumeClipboardBytes(budget, value ? 4 : 5);
    return;
  }
  if (Array.isArray(value)) {
    const len = value.length;
    if (len > MAX_CLONE_ARRAY_LEN || len > budget.remaining) {
      throw new OmniOSError('Invalid JSON clipboard array length', {
        code: ERROR_CODES.EINVAL,
      });
    }
    consumeClipboardBytes(budget, JSON_CONTAINER_BYTE_COST);
    if (len * 2 > budget.remainingBytes) {
      consumeClipboardBytes(budget, len * 2);
    }
    const nextDepth = depth + 1;
    const canInlinePrim = depth < MAX_JSON_NESTING_DEPTH;
    budget.remaining -= len;
    for (let i = 0; i < len; i += 1) {
      const elem = value[i];
      if (canInlinePrim && typeof elem === 'number') {
        consumeClipboardBytes(budget, 2);
      } else if (canInlinePrim && elem === null) {
        consumeClipboardBytes(budget, 4);
      } else if (canInlinePrim && typeof elem === 'boolean') {
        consumeClipboardBytes(budget, elem ? 4 : 5);
      } else if (canInlinePrim && typeof elem === 'string') {
        consumeClipboardBytes(budget, elem.length + 2);
      } else {
        validateParsedJson(elem, nextDepth, budget);
      }
    }
    return;
  }
  const keys = Object.keys(value);
  const klen = keys.length;
  if (klen > MAX_CLONE_ARRAY_LEN || klen > budget.remaining) {
    throw new OmniOSError('JSON clipboard object exceeds maximum key count', {
      code: ERROR_CODES.EINVAL,
    });
  }
  consumeClipboardBytes(budget, JSON_CONTAINER_BYTE_COST);
  if (klen * 4 > budget.remainingBytes) {
    consumeClipboardBytes(budget, klen * 4);
  }
  budget.remaining -= klen;
  const nextDepth = depth + 1;
  for (let i = 0; i < klen; i += 1) {
    const key = keys[i];
    consumeClipboardBytes(budget, key.length + 3 + (i > 0 ? 1 : 0));
    validateParsedJson(value[key], nextDepth, budget);
  }
}

function preScanJsonString(input, maxBytes, reportedLimit, alreadyUsed) {
  const len = input.length;
  let depth = 0;
  let containers = 0;
  let estimatedNodes = 0;
  let compactChars = 0;
  const maxContainers = Math.min(MAX_CLONE_NODES, Math.floor(maxBytes / JSON_CONTAINER_BYTE_COST));

  for (let i = 0; i < len; i += 1) {
    const ch = input.charCodeAt(i);
    // Fast path for digits, '.', '-', ':', uppercase letters (none of whitespace/quote/comma/braces/brackets)
    if (ch >= 0x2d && ch < 0x5b) {
      compactChars += 1;
      continue;
    }
    // Outside strings, JSON whitespace (space, tab, LF, CR) does not count toward compact byte size
    if (ch <= 0x20 && (ch === 0x20 || ch === 0x09 || ch === 0x0a || ch === 0x0d)) {
      continue;
    }

    compactChars += 1;
    if (ch === 0x22) {
      // Scan string literal in tight inner loop handling '\"' and '\\' escapes
      const strStart = i;
      i += 1;
      while (i < len) {
        const sc = input.charCodeAt(i);
        if (sc === 0x22) {
          break;
        }
        if (sc === 0x5c) {
          i += 2;
          continue;
        }
        i += 1;
      }
      compactChars += Math.min(i, len - 1) - strStart;
      if (compactChars > maxBytes) {
        throw new QuotaExceededError(
          `Clipboard entry size (${alreadyUsed + compactChars} bytes) exceeds limit (${reportedLimit} bytes)`,
          {
            code: ERROR_CODES.EFBIG,
            quotaType: 'clipboard',
            limit: reportedLimit,
            actual: alreadyUsed + compactChars,
          }
        );
      }
    } else if (ch === 0x7b || ch === 0x5b) {
      depth += 1;
      if (depth > MAX_JSON_NESTING_DEPTH) {
        throw new OmniOSError('JSON clipboard payload exceeds maximum nesting depth', {
          code: ERROR_CODES.EINVAL,
        });
      }
      containers += 1;
      estimatedNodes += 1;
      if (containers > maxContainers) {
        const containerBytes = containers * JSON_CONTAINER_BYTE_COST;
        throw new QuotaExceededError(
          `Clipboard entry size (${alreadyUsed + containerBytes} bytes) exceeds limit (${reportedLimit} bytes)`,
          {
            code: ERROR_CODES.EFBIG,
            quotaType: 'clipboard',
            limit: reportedLimit,
            actual: alreadyUsed + containerBytes,
          }
        );
      }
      if (estimatedNodes > MAX_CLONE_NODES) {
        throw new QuotaExceededError(
          `Clipboard JSON payload exceeds maximum node count (${MAX_CLONE_NODES})`,
          {
            code: ERROR_CODES.EFBIG,
            quotaType: 'clipboard',
            limit: reportedLimit,
            actual: alreadyUsed + compactChars,
          }
        );
      }
    } else if (ch === 0x7d || ch === 0x5d) {
      if (depth > 0) depth -= 1;
    } else if (ch === 0x2c) {
      estimatedNodes += 1;
      if (estimatedNodes > MAX_CLONE_NODES) {
        throw new QuotaExceededError(
          `Clipboard JSON payload exceeds maximum node count (${MAX_CLONE_NODES})`,
          {
            code: ERROR_CODES.EFBIG,
            quotaType: 'clipboard',
            limit: reportedLimit,
            actual: alreadyUsed + compactChars,
          }
        );
      }
    }
  }

  if (compactChars > maxBytes) {
    throw new QuotaExceededError(
      `Clipboard entry size (${alreadyUsed + compactChars} bytes) exceeds limit (${reportedLimit} bytes)`,
      {
        code: ERROR_CODES.EFBIG,
        quotaType: 'clipboard',
        limit: reportedLimit,
        actual: alreadyUsed + compactChars,
      }
    );
  }
}

function normalizeJsonPayload(input, maxBytes = DEFAULT_MAX_ENTRY_BYTES, totalLimit = maxBytes) {
  const reportedLimit = Number.isSafeInteger(totalLimit) && totalLimit >= 0 ? totalLimit : maxBytes;
  const alreadyUsed = Math.max(0, reportedLimit - maxBytes);
  const budget = {
    remaining: MAX_CLONE_NODES,
    remainingBytes: maxBytes,
    limitBytes: reportedLimit,
  };
  let safe;
  if (typeof input === 'string') {
    if (input.length > Math.max(maxBytes * 2 + 1024, 65536)) {
      throw new QuotaExceededError(
        `Clipboard entry size exceeds limit (${reportedLimit} bytes)`,
        {
          code: ERROR_CODES.EFBIG,
          quotaType: 'clipboard',
          limit: reportedLimit,
          actual: alreadyUsed + input.length,
        }
      );
    }
    preScanJsonString(input, maxBytes, reportedLimit, alreadyUsed);
    try {
      safe = JSON.parse(input);
    } catch (err) {
      throw new OmniOSError('Invalid JSON string for application/json clipboard payload', {
        code: ERROR_CODES.EINVAL,
        cause: err,
      });
    }
    validateParsedJson(safe, 0, budget);
  } else {
    safe = deepCloneJson(input, new Set(), 0, budget);
  }
  let serialized;
  try {
    serialized = JSON.stringify(safe);
  } catch (err) {
    if (err instanceof RangeError) {
      throw new QuotaExceededError(`Clipboard entry size exceeds limit (${reportedLimit} bytes)`, {
        code: ERROR_CODES.EFBIG,
        quotaType: 'clipboard',
        limit: reportedLimit,
        cause: err,
      });
    }
    throw new OmniOSError('Unable to serialize application/json clipboard payload', {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (typeof serialized !== 'string') {
    throw new OmniOSError('Invalid application/json clipboard payload', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const budgetBytes = Math.max(0, maxBytes - budget.remainingBytes);
  return { serialized, parsed: safe, budgetBytes };
}

function parseStoredJson(rec) {
  if (!rec || !Object.prototype.hasOwnProperty.call(rec.formats, 'application/json')) {
    return null;
  }
  return JSON.parse(rec.formats['application/json']);
}

function cloneRecord(rec, preParsedJson = undefined) {
  if (!rec) return null;
  const formatsCopy = {};
  for (const key of Object.keys(rec.formats)) {
    defineSafeProp(formatsCopy, key, rec.formats[key]);
  }
  return {
    id: rec.id,
    mime: rec.mime,
    mimes: [...rec.mimes],
    text: rec.text,
    html: rec.html,
    json: preParsedJson !== undefined ? preParsedJson : parseStoredJson(rec),
    formats: formatsCopy,
    sourceAppId: rec.sourceAppId,
    sourcePlatform: rec.sourcePlatform,
    ts: rec.ts,
  };
}

export class SharedClipboard {
  constructor(opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'SharedClipboard options');
    const kernel = safeGetProp(optsObj, 'kernel', 'kernel') ?? null;
    const rawEventBus = safeGetProp(optsObj, 'eventBus', 'eventBus');
    const rawMaxHistory = safeGetProp(optsObj, 'maxHistory', 'maxHistory');
    const rawMaxEntryBytes = safeGetProp(optsObj, 'maxEntryBytes', 'maxEntryBytes');

    if (kernel !== null && typeof kernel !== 'object') {
      throw new OmniOSError('SharedClipboard kernel must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const kernelBus = kernel ? (safeGetProp(kernel, 'eventBus', 'kernel.eventBus') ?? null) : null;
    const eventBus = rawEventBus !== undefined ? rawEventBus : kernelBus;
    if (eventBus !== null) {
      if (typeof eventBus !== 'object') {
        throw new OmniOSError('SharedClipboard eventBus must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(eventBus, 'emit', 'eventBus.emit');
    }

    const maxHistory = rawMaxHistory !== undefined ? rawMaxHistory : DEFAULT_HISTORY_LIMIT;
    const maxEntryBytes = rawMaxEntryBytes !== undefined ? rawMaxEntryBytes : DEFAULT_MAX_ENTRY_BYTES;
    this._eventBus = eventBus;
    this._maxHistory = Number.isSafeInteger(maxHistory) && maxHistory >= 1 ? maxHistory : DEFAULT_HISTORY_LIMIT;
    this._maxEntryBytes =
      Number.isSafeInteger(maxEntryBytes) && maxEntryBytes >= 1 ? maxEntryBytes : DEFAULT_MAX_ENTRY_BYTES;
    this._maxHistoryBytes = Math.max(this._maxEntryBytes * 2, 8 * 1024 * 1024);
    this._historyBytes = 0;
    this._current = null;
    this._history = [];
    this._seq = 0;
  }

  _emit(event, payload) {
    if (!this._eventBus) return;
    try {
      this._eventBus.emit(event, payload);
    } catch {
      // Fault-isolated emit.
    }
  }

  set(input) {
    let inputIsArr = false;
    try {
      inputIsArr = Array.isArray(input);
    } catch (err) {
      throw new OmniOSError('Clipboard set() requires a readable non-null payload object', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (!input || typeof input !== 'object' || inputIsArr) {
      throw new OmniOSError('Clipboard set() requires a non-null payload object', {
        code: ERROR_CODES.EINVAL,
      });
    }

    const formats = {};
    let returnParsedJson = null;
    let jsonBudgetBytes = 0;
    let accumulatedBytes = 0;
    const formatByteSizes = new Map();
    const stagedFormats = new Map();

    const stageFormat = (rawMime, rawVal) => {
      const mime = normalizeMime(rawMime);
      if (!mime) {
        throw new OmniOSError(`Invalid clipboard MIME type: ${safeDisplayValue(rawMime)}`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      stagedFormats.set(mime, rawVal);
    };

    const addFormat = (mime, rawVal) => {
      const prevBytes = formatByteSizes.get(mime) ?? 0;
      const baseBytes = accumulatedBytes - prevBytes;
      const remainingForKey = this._maxEntryBytes - baseBytes;
      if (remainingForKey < 0) {
        throw new QuotaExceededError(
          `Clipboard entry size (${baseBytes} bytes) exceeds limit (${this._maxEntryBytes} bytes)`,
          {
            code: ERROR_CODES.EFBIG,
            quotaType: 'clipboard',
            limit: this._maxEntryBytes,
            actual: baseBytes,
          }
        );
      }

      let storedVal;
      let nextParsedJson = null;
      let nextJsonBudget = 0;
      let hasNextJsonBudget = false;
      if (mime === 'text/plain' || mime === 'text/html') {
        if (typeof rawVal !== 'string') {
          throw new OmniOSError(`Clipboard format "${mime}" requires a string value`, {
            code: ERROR_CODES.EINVAL,
          });
        }
        if (rawVal.length > remainingForKey) {
          throw new QuotaExceededError(
            `Clipboard entry size (${baseBytes + rawVal.length} bytes) exceeds limit (${this._maxEntryBytes} bytes)`,
            {
              code: ERROR_CODES.EFBIG,
              quotaType: 'clipboard',
              limit: this._maxEntryBytes,
              actual: baseBytes + rawVal.length,
            }
          );
        }
        storedVal = rawVal;
      } else if (mime === 'application/json') {
        const { serialized, parsed, budgetBytes } = normalizeJsonPayload(rawVal, remainingForKey, this._maxEntryBytes);
        storedVal = serialized;
        nextParsedJson = parsed;
        nextJsonBudget = budgetBytes;
        hasNextJsonBudget = true;
      } else if (mime === 'image/png') {
        storedVal = normalizeBase64Png(rawVal, remainingForKey, this._maxEntryBytes);
      } else if (typeof rawVal === 'string') {
        if (rawVal.length > remainingForKey) {
          throw new QuotaExceededError(
            `Clipboard entry size (${baseBytes + rawVal.length} bytes) exceeds limit (${this._maxEntryBytes} bytes)`,
            {
              code: ERROR_CODES.EFBIG,
              quotaType: 'clipboard',
              limit: this._maxEntryBytes,
              actual: baseBytes + rawVal.length,
            }
          );
        }
        storedVal = rawVal;
      } else {
        const bin = extractGenuineBytes(rawVal);
        if (bin.detached) {
          throw new OmniOSError(`Unreadable detached binary value for clipboard MIME "${mime}"`, {
            code: ERROR_CODES.EINVAL,
          });
        }
        if (bin.ok) {
          const b64Len = Math.ceil(bin.bytes.byteLength / 3) * 4;
          if (b64Len > remainingForKey) {
            throw new QuotaExceededError(
              `Clipboard entry size (${baseBytes + b64Len} bytes) exceeds limit (${this._maxEntryBytes} bytes)`,
              {
                code: ERROR_CODES.EFBIG,
                quotaType: 'clipboard',
                limit: this._maxEntryBytes,
                actual: baseBytes + b64Len,
              }
            );
          }
          try {
            storedVal = Buffer.from(bin.bytes.buffer, bin.bytes.byteOffset, bin.bytes.byteLength).toString('base64');
          } catch (err) {
            throw new OmniOSError(`Unreadable binary value for clipboard MIME "${mime}"`, {
              code: ERROR_CODES.EINVAL,
              cause: isErrorInstance(err) ? err : undefined,
            });
          }
        } else {
          throw new OmniOSError(`Unsupported value for clipboard MIME "${mime}"`, {
            code: ERROR_CODES.EINVAL,
          });
        }
      }

      const storedBytes = Buffer.byteLength(storedVal, 'utf8');
      if (storedBytes > remainingForKey) {
        throw new QuotaExceededError(
          `Clipboard entry size (${baseBytes + storedBytes} bytes) exceeds limit (${this._maxEntryBytes} bytes)`,
          {
            code: ERROR_CODES.EFBIG,
            quotaType: 'clipboard',
            limit: this._maxEntryBytes,
            actual: baseBytes + storedBytes,
          }
        );
      }
      defineSafeProp(formats, mime, storedVal);
      if (hasNextJsonBudget) {
        returnParsedJson = nextParsedJson;
        jsonBudgetBytes = nextJsonBudget;
      }
      accumulatedBytes = baseBytes + storedBytes;
      formatByteSizes.set(mime, storedBytes);
    };

    // 1. Explicit formats map (guard all top-level reads against hostile getters / revoked Proxies)
    const inputFormats = safeGetProp(input, 'formats', 'formats');
    if (inputFormats !== undefined && inputFormats !== null) {
      let formatsIsArr = false;
      try {
        formatsIsArr = Array.isArray(inputFormats);
      } catch (err) {
        throw new OmniOSError('Unreadable clipboard input.formats', {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
      if (
        typeof inputFormats !== 'object' ||
        formatsIsArr ||
        types.isProxy(inputFormats) ||
        types.isBoxedPrimitive(inputFormats) ||
        types.isTypedArray(inputFormats) ||
        types.isArrayBuffer(inputFormats) ||
        types.isDataView(inputFormats) ||
        types.isSharedArrayBuffer?.(inputFormats) ||
        types.isDate(inputFormats)
      ) {
        throw new OmniOSError('Clipboard input.formats must be a plain object', {
          code: ERROR_CODES.EINVAL,
        });
      }
      let formatKeysIn;
      try {
        formatKeysIn = Object.keys(inputFormats);
      } catch (err) {
        throw new OmniOSError('Unreadable clipboard input.formats keys', {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
      if (formatKeysIn.length > MAX_CLIPBOARD_FORMATS) {
        throw new OmniOSError(`Clipboard input.formats exceeds maximum format count (${MAX_CLIPBOARD_FORMATS})`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      for (const key of formatKeysIn) {
        let rawVal;
        try {
          rawVal = inputFormats[key];
        } catch (err) {
          throw new OmniOSError(`Unreadable clipboard format "${safeDisplayValue(key)}"`, {
            code: ERROR_CODES.EINVAL,
            cause: isErrorInstance(err) ? err : undefined,
          });
        }
        stageFormat(key, rawVal);
      }
    }

    // 2. Shorthand properties (last-write-wins over explicit formats map)
    const inputText = safeGetProp(input, 'text', 'text');
    if (inputText !== undefined && inputText !== null) {
      stageFormat('text/plain', inputText);
    }
    const inputHtml = safeGetProp(input, 'html', 'html');
    if (inputHtml !== undefined && inputHtml !== null) {
      stageFormat('text/html', inputHtml);
    }
    const inputJson = safeGetProp(input, 'json', 'json');
    if (inputJson !== undefined && inputJson !== null) {
      stageFormat('application/json', inputJson);
    }
    const inputImagePng = safeGetProp(input, 'imagePng', 'imagePng');
    if (inputImagePng !== undefined && inputImagePng !== null) {
      stageFormat('image/png', inputImagePng);
    } else {
      const inputImage = safeGetProp(input, 'image', 'image');
      if (inputImage !== undefined && inputImage !== null) {
        stageFormat('image/png', inputImage);
      }
    }

    // 3. Generic { mime, data } (last-write-wins over formats & shorthands)
    const inputMime = safeGetProp(input, 'mime', 'mime');
    const inputData = safeGetProp(input, 'data', 'data');
    if (inputMime !== undefined && inputMime !== null && inputData !== undefined && inputData !== null) {
      stageFormat(inputMime, inputData);
    }

    const inputSourceAppId = safeGetProp(input, 'sourceAppId', 'sourceAppId');
    const inputSourcePlatform = safeGetProp(input, 'sourcePlatform', 'sourcePlatform');
    if (typeof inputSourceAppId === 'string' && inputSourceAppId.length > MAX_META_STRING_LENGTH) {
      throw new OmniOSError(`Clipboard sourceAppId exceeds maximum length (${MAX_META_STRING_LENGTH})`, {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (typeof inputSourcePlatform === 'string' && inputSourcePlatform.length > MAX_META_STRING_LENGTH) {
      throw new OmniOSError(`Clipboard sourcePlatform exceeds maximum length (${MAX_META_STRING_LENGTH})`, {
        code: ERROR_CODES.EINVAL,
      });
    }

    if (stagedFormats.size === 0) {
      throw new OmniOSError('Clipboard set() requires at least one MIME payload', {
        code: ERROR_CODES.EINVAL,
      });
    }

    // Process each unique normalized MIME at most once per set() call
    for (const [mime, rawVal] of stagedFormats) {
      addFormat(mime, rawVal);
    }

    const formatKeys = Object.keys(formats);

    // Enforce total serialized byte cap
    let totalBytes = 0;
    for (const k of formatKeys) {
      totalBytes += Buffer.byteLength(formats[k], 'utf8');
    }
    if (totalBytes > this._maxEntryBytes) {
      throw new QuotaExceededError(
        `Clipboard entry size (${totalBytes} bytes) exceeds limit (${this._maxEntryBytes} bytes)`,
        {
          code: ERROR_CODES.EFBIG,
          quotaType: 'clipboard',
          limit: this._maxEntryBytes,
          actual: totalBytes,
        }
      );
    }

    let primaryMime = null;
    if (inputMime !== undefined && inputMime !== null) {
      const requested = normalizeMime(inputMime);
      if (requested && Object.prototype.hasOwnProperty.call(formats, requested)) {
        primaryMime = requested;
      }
    }
    if (!primaryMime) {
      for (const candidate of SUPPORTED_CLIPBOARD_MIMES) {
        if (Object.prototype.hasOwnProperty.call(formats, candidate)) {
          primaryMime = candidate;
          break;
        }
      }
    }
    if (!primaryMime) {
      primaryMime = formatKeys[0];
    }

    const recordByteSize = Math.max(1, totalBytes, jsonBudgetBytes);
    const record = {
      id: ++this._seq,
      mime: primaryMime,
      mimes: formatKeys,
      text: Object.prototype.hasOwnProperty.call(formats, 'text/plain') ? formats['text/plain'] : null,
      html: Object.prototype.hasOwnProperty.call(formats, 'text/html') ? formats['text/html'] : null,
      formats,
      sourceAppId: typeof inputSourceAppId === 'string' ? inputSourceAppId : null,
      sourcePlatform: typeof inputSourcePlatform === 'string' ? inputSourcePlatform : null,
      ts: new Date().toISOString(),
      _byteSize: recordByteSize,
    };

    this._current = record;
    this._history.unshift(record);
    this._historyBytes += recordByteSize;
    while (
      this._history.length > this._maxHistory ||
      (this._history.length > 1 && this._historyBytes > this._maxHistoryBytes)
    ) {
      const evicted = this._history.pop();
      this._historyBytes = Math.max(0, this._historyBytes - (evicted?._byteSize ?? 0));
    }

    // Transfer freshly cloned JSON AST exclusively to caller return value; record retains only serialized string
    const cloned = cloneRecord(record, returnParsedJson);
    if (this._eventBus) {
      this._emit('clipboard:changed', cloneRecord(record));
    }
    return cloned;
  }

  get(mime = undefined) {
    if (!this._current) return null;
    if (mime === undefined) {
      return cloneRecord(this._current);
    }
    const norm = normalizeMime(mime);
    if (!norm || !Object.prototype.hasOwnProperty.call(this._current.formats, norm)) {
      return null;
    }
    if (norm === 'application/json') {
      return parseStoredJson(this._current);
    }
    return this._current.formats[norm];
  }

  getBytes(mime = 'image/png') {
    if (!this._current) return null;
    const norm = normalizeMime(mime);
    if (!norm || !Object.prototype.hasOwnProperty.call(this._current.formats, norm)) {
      return null;
    }
    const raw = this._current.formats[norm];
    if (norm === 'image/png' || norm.startsWith('image/') || norm === 'application/octet-stream') {
      const buf = Buffer.from(raw, 'base64');
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).slice();
    }
    return TEXT_ENCODER.encode(raw);
  }

  clear(opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'clear options');
    const clearHistory = Boolean(safeGetProp(optsObj, 'clearHistory', 'clearHistory'));
    const sourceAppId = safeGetProp(optsObj, 'sourceAppId', 'sourceAppId') ?? null;
    this._current = null;
    if (clearHistory) {
      this._history = [];
      this._historyBytes = 0;
    }
    this._emit('clipboard:changed', {
      cleared: true,
      clearHistory,
      current: null,
      sourceAppId: typeof sourceAppId === 'string' ? sourceAppId : null,
      ts: new Date().toISOString(),
    });
    return { cleared: true };
  }

  history(limit = DEFAULT_HISTORY_LIMIT) {
    if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 0) {
      throw new OmniOSError('Clipboard history limit must be a non-negative safe integer', {
        code: ERROR_CODES.EINVAL,
        details: { limit },
      });
    }
    const capped = Math.min(limit, this._maxHistory, this._history.length);
    const out = new Array(capped);
    for (let i = 0; i < capped; i++) {
      out[i] = cloneRecord(this._history[i]);
    }
    return out;
  }
}

export function createSharedClipboard(options = {}) {
  return new SharedClipboard(options);
}
