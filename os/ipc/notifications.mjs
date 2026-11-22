/**
 * OmniOS Unified Notification Center, Dynamic Island Live Activities & `ipc-brokerd` Service
 * - Priority/category notification queue with interactive actions (`post`, `list`, `get`, `markRead`, `dismiss`, `clearAll`, `invokeAction`)
 * - Live Do Not Disturb (DND) filtering reading `configStore.system.get('system.dnd')`:
 *   normal/low/high are queued with `suppressed: true, deliveredBanner: false`, while `urgent`/`critical` bypass DND
 * - iOS Dynamic Island Live Activities (`getLiveActivities`, `updateLiveActivity`, `endLiveActivity`)
 * - Systemd-like `ipc-brokerd` service registration (`createIpcBrokerService`, `registerIpcBrokerService`)
 */

import { types } from 'node:util';
import { OmniOSError, QuotaExceededError, ERROR_CODES } from '../common/errors.mjs';

export const NOTIFICATION_PRIORITIES = Object.freeze(['low', 'normal', 'high', 'urgent', 'critical']);
export const DND_BYPASS_PRIORITIES = Object.freeze(new Set(['urgent', 'critical']));

const PRIORITY_SET = new Set(NOTIFICATION_PRIORITIES);

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
const MAX_POST_TOTAL_NODES = 500_000;
const MAX_CLONE_BYTES = 2 * 1024 * 1024; // 2 MiB
const MAX_INVOKED_ACTIONS = 64;
const MAX_INVOKED_ACTIONS_BYTES = MAX_CLONE_BYTES; // 2 MiB
const MAX_CLONE_BIGINT_ABS = 1n << 4096n;
const MAX_DISPLAY_LENGTH = 256;

function consumeCloneBytes(budget, delta) {
  if (budget.exceeded || delta > budget.remainingBytes) {
    budget.exceeded = true;
    budget.bytesExceeded = true;
    return false;
  }
  budget.remainingBytes -= delta;
  return true;
}

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

function createCloneBudget(maxNodes = MAX_CLONE_NODES, maxBytes = MAX_CLONE_BYTES, limitBytes = maxBytes) {
  const cap = Number.isSafeInteger(maxNodes) && maxNodes >= 0 ? maxNodes : 0;
  const byteCap = Number.isSafeInteger(maxBytes) && maxBytes >= 0 ? maxBytes : 0;
  const reportedLimit = Number.isSafeInteger(limitBytes) && limitBytes >= 0 ? limitBytes : byteCap;
  return {
    maxNodes: cap,
    maxBytes: reportedLimit,
    remaining: cap,
    remainingBytes: byteCap,
    exceeded: false,
    bytesExceeded: false,
  };
}

function throwBudgetExceeded(fieldName, budget) {
  const maxNodes = budget.maxNodes ?? MAX_CLONE_NODES;
  const maxBytes = budget.maxBytes ?? MAX_CLONE_BYTES;
  const nodesUsed = Math.max(0, maxNodes - budget.remaining);
  const bytesUsed = Math.max(0, maxBytes - budget.remainingBytes);
  throw new QuotaExceededError(
    budget.bytesExceeded
      ? `${fieldName} exceeds maximum byte budget (${maxBytes} bytes)`
      : `${fieldName} exceeds maximum node budget (${maxNodes})`,
    {
      code: ERROR_CODES.EQUOTA,
      quotaType: budget.bytesExceeded ? 'notificationBytes' : 'notificationNodes',
      limit: budget.bytesExceeded ? maxBytes : maxNodes,
      actual: budget.bytesExceeded ? bytesUsed : nodesUsed,
    }
  );
}

function cloneFieldWithBudget(val, fieldName, sharedBudget, perFieldMaxNodes = MAX_CLONE_NODES) {
  if (sharedBudget.exceeded) {
    throwBudgetExceeded(fieldName, sharedBudget);
  }
  const allowedNodes = Math.min(perFieldMaxNodes, Math.max(0, sharedBudget.remaining));
  const bytesBefore = sharedBudget.remainingBytes;
  const fieldBudget = {
    maxNodes: allowedNodes,
    maxBytes: sharedBudget.maxBytes ?? MAX_CLONE_BYTES,
    remaining: allowedNodes,
    remainingBytes: bytesBefore,
    exceeded: false,
    bytesExceeded: false,
  };
  const cloned = cloneJsonSafe(val, new Set(), 0, fieldBudget);
  const nodesSpent = Math.max(0, allowedNodes - fieldBudget.remaining);
  const bytesSpent = Math.max(0, bytesBefore - fieldBudget.remainingBytes);
  sharedBudget.remaining = Math.max(0, sharedBudget.remaining - nodesSpent);
  sharedBudget.remainingBytes = fieldBudget.remainingBytes;
  if (fieldBudget.exceeded) {
    sharedBudget.exceeded = true;
    sharedBudget.bytesExceeded = sharedBudget.bytesExceeded || fieldBudget.bytesExceeded;
    throwBudgetExceeded(fieldName, fieldBudget.bytesExceeded ? sharedBudget : fieldBudget);
  }
  return { value: cloned, bytes: bytesSpent, nodes: nodesSpent };
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
        quotaType: res.bytesExceeded ? 'notificationBytes' : 'notificationNodes',
        limit: res.bytesExceeded ? maxBytes : maxNodes,
        actual: res.bytesExceeded ? res.bytes : res.nodes,
      }
    );
  }
  return res.value;
}

function cloneActionRecord(act) {
  return {
    id: act.id,
    label: act.label,
    destructive: Boolean(act.destructive),
    payload: act.payload !== undefined ? cloneJsonSafe(act.payload) : null,
  };
}

function cloneInvokedActionRecord(entry) {
  return {
    actionId: entry.actionId,
    label: entry.label,
    input: entry.input !== undefined ? cloneJsonSafe(entry.input) : null,
    ts: entry.ts,
  };
}

function cloneLiveActivityRecord(la) {
  if (!la) return null;
  const out = {
    id: la.id,
    notificationId: la.notificationId,
    appId: la.appId,
    platform: la.platform,
    title: la.title,
    subtitle: la.subtitle,
    compactLeading: la.compactLeading !== undefined ? cloneJsonSafe(la.compactLeading) : null,
    compactTrailing: la.compactTrailing !== undefined ? cloneJsonSafe(la.compactTrailing) : null,
    expandedBody: la.expandedBody !== undefined ? cloneJsonSafe(la.expandedBody) : null,
    progress: la.progress,
    icon: la.icon !== undefined ? cloneJsonSafe(la.icon) : null,
    payload: la.payload !== undefined ? cloneJsonSafe(la.payload) : null,
    state: la.state,
    dismissalPolicy: la.dismissalPolicy,
    createdAt: la.createdAt,
    updatedAt: la.updatedAt,
    endedAt: la.endedAt,
  };
  if (Object.prototype.hasOwnProperty.call(la, 'data')) {
    out.data = cloneJsonSafe(la.data);
  }
  return out;
}

function cloneNotificationRecord(rec) {
  if (!rec) return null;
  return {
    id: rec.id,
    appId: rec.appId,
    platform: rec.platform,
    title: rec.title,
    body: rec.body,
    priority: rec.priority,
    category: rec.category,
    actions: Array.isArray(rec.actions) ? rec.actions.map(cloneActionRecord) : [],
    invokedActions: Array.isArray(rec.invokedActions) ? rec.invokedActions.map(cloneInvokedActionRecord) : [],
    liveActivity: rec.liveActivity ? cloneLiveActivityRecord(rec.liveActivity) : null,
    data: rec.data !== undefined ? cloneJsonSafe(rec.data) : null,
    silent: Boolean(rec.silent),
    suppressed: Boolean(rec.suppressed),
    deliveredBanner: Boolean(rec.deliveredBanner),
    read: Boolean(rec.read),
    dismissed: Boolean(rec.dismissed),
    dismissedAt: rec.dismissedAt,
    createdAt: rec.createdAt,
    updatedAt: rec.updatedAt,
  };
}

function isErrorInstance(err) {
  try {
    return err instanceof Error;
  } catch {
    return false;
  }
}

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

function safeCoerceString(value, fieldName, { nullAsEmpty = false } = {}) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return nullAsEmpty ? '' : String(value);
  const t = typeof value;
  if (t === 'number' || t === 'boolean') return String(value);
  if (t === 'bigint') {
    if (value > MAX_CLONE_BIGINT_ABS || value < -MAX_CLONE_BIGINT_ABS) {
      throw new OmniOSError(`Invalid ${fieldName}: BigInt out of range`, {
        code: ERROR_CODES.EINVAL,
      });
    }
    return value.toString(10);
  }
  if (t === 'symbol') {
    throw new OmniOSError(`${fieldName} cannot be a Symbol`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  throw new OmniOSError(`Invalid ${fieldName}: must be a string or primitive`, {
    code: ERROR_CODES.EINVAL,
  });
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

function assertPlainObject(obj, label) {
  let isArr = false;
  try {
    isArr = Array.isArray(obj);
  } catch (err) {
    throw new OmniOSError(`${label} must be a readable plain object`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (!obj || typeof obj !== 'object' || isArr) {
    throw new OmniOSError(`${label} must be a plain object`, {
      code: ERROR_CODES.EINVAL,
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

function normalizeProgress(progress) {
  if (progress === null || progress === undefined) return null;
  if (typeof progress !== 'number' || !Number.isFinite(progress)) {
    throw new OmniOSError('liveActivity.progress must be a finite number in [0, 1] or null', {
      code: ERROR_CODES.EINVAL,
      details: { progress: safeDisplayValue(progress) },
    });
  }
  return Math.max(0, Math.min(1, progress));
}

function normalizeActions(actions, budget = createCloneBudget(MAX_CLONE_NODES, MAX_CLONE_BYTES)) {
  if (actions === null || actions === undefined) return [];
  let isArr = false;
  try {
    isArr = Array.isArray(actions);
  } catch (err) {
    throw new OmniOSError('Notification actions must be a readable Array', {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (!isArr) {
    throw new OmniOSError('Notification actions must be an Array', {
      code: ERROR_CODES.EINVAL,
    });
  }
  let len;
  try {
    len = actions.length;
  } catch (err) {
    throw new OmniOSError('Unreadable notification actions length', {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (
    typeof len !== 'number' ||
    !Number.isSafeInteger(len) ||
    len < 0 ||
    len > 0xffffffff ||
    len > 1000
  ) {
    throw new OmniOSError('Invalid notification actions length', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const seenIds = new Set();
  const out = [];
  for (let i = 0; i < len; i++) {
    let act;
    try {
      act = actions[i];
    } catch (err) {
      throw new OmniOSError(`Unreadable notification action at index ${i}`, {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    assertPlainObject(act, 'Notification action');
    const rawId = safeGetProp(act, 'id', 'notification action');
    const rawLabel = safeGetProp(act, 'label', 'notification action');
    const rawDestructive = safeGetProp(act, 'destructive', 'notification action');
    const rawPayload = safeGetProp(act, 'payload', 'notification action');
    if (typeof rawId !== 'string') {
      throw new OmniOSError('Notification action requires a non-empty string id', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (typeof rawLabel !== 'string') {
      throw new OmniOSError('Notification action requires a non-empty string label', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (budget.remaining <= 0) {
      budget.exceeded = true;
      throwBudgetExceeded('notification actions', budget);
    }
    budget.remaining -= 1;
    // Charge raw pre-trim lengths strictly BEFORE calling .trim() to block whitespace CPU DoS
    if (!consumeCloneBytes(budget, rawId.length + rawLabel.length + 32)) {
      throwBudgetExceeded('notification actions', budget);
    }
    const id = rawId.trim();
    if (id.length === 0) {
      throw new OmniOSError('Notification action requires a non-empty string id', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const label = rawLabel.trim();
    if (label.length === 0) {
      throw new OmniOSError('Notification action requires a non-empty string label', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (seenIds.has(id)) {
      throw new OmniOSError(`Duplicate notification action id: ${safeDisplayValue(id)}`, {
        code: ERROR_CODES.EINVAL,
        details: { actionId: safeDisplayValue(id) },
      });
    }
    seenIds.add(id);
    const payload =
      rawPayload !== undefined
        ? cloneFieldWithBudget(rawPayload, 'notification action.payload', budget, budget.remaining).value
        : null;
    out.push({
      id,
      label,
      destructive: Boolean(rawDestructive),
      payload,
    });
  }
  return out;
}

export class NotificationCenter {
  constructor(opts = {}) {
    if (opts !== undefined && opts !== null) {
      assertPlainObject(opts, 'NotificationCenter options');
    }
    const optsObj = opts ?? {};
    const kernel = safeGetProp(optsObj, 'kernel', 'NotificationCenter options') ?? null;
    const rawEventBus = safeGetProp(optsObj, 'eventBus', 'NotificationCenter options');
    const configStore = safeGetProp(optsObj, 'configStore', 'NotificationCenter options') ?? null;
    const isDndEnabled = safeGetProp(optsObj, 'isDndEnabled', 'NotificationCenter options') ?? null;
    const rawProcessManager = safeGetProp(optsObj, 'processManager', 'NotificationCenter options');
    const onAction = safeGetProp(optsObj, 'onAction', 'NotificationCenter options') ?? null;
    const rawMaxNotifications = safeGetProp(optsObj, 'maxNotifications', 'NotificationCenter options');
    const log = safeGetProp(optsObj, 'log', 'NotificationCenter options');

    if (kernel !== null && typeof kernel !== 'object') {
      throw new OmniOSError('NotificationCenter kernel must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const kernelBus = kernel ? (safeGetProp(kernel, 'eventBus', 'NotificationCenter kernel') ?? null) : null;
    const kernelPm = kernel ? (safeGetProp(kernel, 'processManager', 'NotificationCenter kernel') ?? null) : null;
    const eventBus = rawEventBus !== undefined ? rawEventBus : kernelBus;
    const processManager = rawProcessManager !== undefined ? rawProcessManager : kernelPm;

    if (eventBus !== null) {
      if (typeof eventBus !== 'object') {
        throw new OmniOSError('NotificationCenter eventBus must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(eventBus, 'emit', 'NotificationCenter eventBus');
    }
    if (configStore !== null) {
      if (typeof configStore !== 'object') {
        throw new OmniOSError('NotificationCenter configStore must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(configStore, 'system', 'NotificationCenter configStore');
    }
    if (processManager !== null) {
      if (typeof processManager !== 'object') {
        throw new OmniOSError('NotificationCenter processManager must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(processManager, 'get', 'NotificationCenter processManager');
    }

    const maxNotifications = rawMaxNotifications !== undefined ? rawMaxNotifications : 500;

    this._eventBus = eventBus;
    this._configStore = configStore;
    this._isDndEnabled = typeof isDndEnabled === 'function' ? isDndEnabled : null;
    this._processManager = processManager;
    this._onAction = typeof onAction === 'function' ? onAction : null;
    this._maxNotifications =
      Number.isSafeInteger(maxNotifications) && maxNotifications >= 1 ? maxNotifications : 500;
    this._log = typeof log === 'function' ? log : () => {};

    this._notifications = new Map();
    this._liveActivities = new Map();
    this._notifSeq = 0;
    this._liveActivitySeq = 0;
  }

  _emit(event, payload) {
    if (!this._eventBus) return;
    try {
      this._eventBus.emit(event, payload);
    } catch {
      // Fault-isolated emit.
    }
  }

  _isDndActive() {
    if (this._isDndEnabled) {
      try {
        return Boolean(this._isDndEnabled());
      } catch {
        return false;
      }
    }
    if (this._configStore) {
      try {
        if (!this._configStore.system?.get) return false;
        if (typeof this._configStore.isReady === 'function' && !this._configStore.isReady()) {
          return false;
        }
        return Boolean(this._configStore.system.get('system.dnd'));
      } catch {
        return false;
      }
    }
    return false;
  }

  _evictIfFull() {
    if (this._notifications.size < this._maxNotifications) return;

    // Evict oldest dismissed -> oldest read -> oldest overall
    let victimId = null;
    for (const [id, rec] of this._notifications.entries()) {
      if (rec.dismissed) {
        victimId = id;
        break;
      }
    }
    if (!victimId) {
      for (const [id, rec] of this._notifications.entries()) {
        if (rec.read) {
          victimId = id;
          break;
        }
      }
    }
    if (!victimId) {
      victimId = this._notifications.keys().next().value;
    }
    if (victimId !== undefined) {
      this._notifications.delete(victimId);
    }
  }

  post(options = {}) {
    assertPlainObject(options, 'Notification options');

    const appId = safeGetProp(options, 'appId', 'notification');
    const platformRaw = safeGetProp(options, 'platform', 'notification');
    const titleRaw = safeGetProp(options, 'title', 'notification');
    const bodyRaw = safeGetProp(options, 'body', 'notification');
    const priorityRaw = safeGetProp(options, 'priority', 'notification');
    const categoryRaw = safeGetProp(options, 'category', 'notification');
    const actionsRaw = safeGetProp(options, 'actions', 'notification');
    const liveActivity = safeGetProp(options, 'liveActivity', 'notification');
    const dataRaw = safeGetProp(options, 'data', 'notification');
    const silentRaw = safeGetProp(options, 'silent', 'notification');

    const platform = platformRaw === undefined ? 'universal' : platformRaw;
    const title = titleRaw === undefined ? '' : titleRaw;
    const body = bodyRaw === undefined ? '' : bodyRaw;
    const priority = priorityRaw === undefined ? 'normal' : priorityRaw;
    const category = categoryRaw === undefined ? 'general' : categoryRaw;
    const actions = actionsRaw === undefined ? [] : actionsRaw;
    const data = dataRaw === undefined ? null : dataRaw;
    const silent = silentRaw === undefined ? false : silentRaw;

    // Validate, coerce, and clone ALL fields under ONE shared cumulative byte budget
    // strictly BEFORE calling .trim(), mutating _liveActivities/_notifications, or calling _evictIfFull()
    const postBudget = createCloneBudget(MAX_POST_TOTAL_NODES, MAX_CLONE_BYTES);

    if (typeof appId !== 'string' || appId.includes('\0')) {
      throw new OmniOSError('Notification requires a non-empty string appId', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (!consumeCloneBytes(postBudget, appId.length)) {
      throwBudgetExceeded('notification appId', postBudget);
    }
    const cleanAppId = appId.trim();
    if (cleanAppId.length === 0) {
      throw new OmniOSError('Notification requires a non-empty string appId', {
        code: ERROR_CODES.EINVAL,
      });
    }

    let resolvedPlatform = 'universal';
    if (typeof platform === 'string') {
      if (!consumeCloneBytes(postBudget, platform.length)) {
        throwBudgetExceeded('notification platform', postBudget);
      }
      const trimmedPlatform = platform.trim();
      if (trimmedPlatform.length > 0) {
        resolvedPlatform = trimmedPlatform.toLowerCase();
      }
    }

    let resolvedCategory = 'general';
    if (typeof category === 'string') {
      if (!consumeCloneBytes(postBudget, category.length)) {
        throwBudgetExceeded('notification category', postBudget);
      }
      const trimmedCategory = category.trim();
      if (trimmedCategory.length > 0) {
        resolvedCategory = trimmedCategory;
      }
    }

    // Validate & read liveActivity fields upfront BEFORE any sequence or Map mutation
    let parsedLa = null;
    if (liveActivity !== null && liveActivity !== undefined) {
      assertPlainObject(liveActivity, 'liveActivity');
      parsedLa = {
        id: safeGetProp(liveActivity, 'id', 'liveActivity'),
        title: safeGetProp(liveActivity, 'title', 'liveActivity'),
        subtitle: safeGetProp(liveActivity, 'subtitle', 'liveActivity'),
        compactLeading: safeGetProp(liveActivity, 'compactLeading', 'liveActivity'),
        compactTrailing: safeGetProp(liveActivity, 'compactTrailing', 'liveActivity'),
        expandedBody: safeGetProp(liveActivity, 'expandedBody', 'liveActivity'),
        progress: safeGetProp(liveActivity, 'progress', 'liveActivity'),
        icon: safeGetProp(liveActivity, 'icon', 'liveActivity'),
        payload: safeGetProp(liveActivity, 'payload', 'liveActivity'),
        data: safeGetProp(liveActivity, 'data', 'liveActivity'),
      };
    }

    let trimmedTitle = '';
    if (typeof title === 'string') {
      if (!consumeCloneBytes(postBudget, title.length)) {
        throwBudgetExceeded('notification text', postBudget);
      }
      trimmedTitle = title.trim();
    }
    let trimmedLaTitle = '';
    if (parsedLa !== null && typeof parsedLa.title === 'string') {
      if (!consumeCloneBytes(postBudget, parsedLa.title.length)) {
        throwBudgetExceeded('liveActivity text', postBudget);
      }
      trimmedLaTitle = parsedLa.title.trim();
    }
    const resolvedTitle = trimmedTitle.length > 0 ? trimmedTitle : trimmedLaTitle;
    if (!resolvedTitle) {
      throw new OmniOSError('Notification requires a non-empty string title', {
        code: ERROR_CODES.EINVAL,
      });
    }

    let normPriority = '';
    if (typeof priority === 'string') {
      if (!consumeCloneBytes(postBudget, priority.length)) {
        throwBudgetExceeded('notification priority', postBudget);
      }
      normPriority = priority.trim().toLowerCase();
    }
    if (!PRIORITY_SET.has(normPriority)) {
      throw new OmniOSError(`Invalid notification priority: ${safeDisplayValue(priority)}`, {
        code: ERROR_CODES.EINVAL,
        details: { priority: safeDisplayValue(priority), allowed: NOTIFICATION_PRIORITIES },
      });
    }

    const resolvedBody = safeCoerceString(body, 'Notification body', { nullAsEmpty: true });
    if (!consumeCloneBytes(postBudget, resolvedBody.length)) {
      throwBudgetExceeded('notification text', postBudget);
    }
    const actionsNodeCap = Math.min(MAX_CLONE_NODES, postBudget.remaining);
    const actionsBudget = createCloneBudget(actionsNodeCap, postBudget.remainingBytes, MAX_CLONE_BYTES);
    const normalizedActions = normalizeActions(actions, actionsBudget);
    postBudget.remaining = Math.max(0, postBudget.remaining - (actionsNodeCap - actionsBudget.remaining));
    postBudget.remainingBytes = actionsBudget.remainingBytes;

    const clonedData =
      data !== null && data !== undefined
        ? cloneFieldWithBudget(data, 'notification.data', postBudget, MAX_CLONE_NODES).value
        : null;

    const now = new Date().toISOString();
    const nextNotifSeq = this._notifSeq + 1;
    const id = `notif-${nextNotifSeq}`;

    const dndActive = this._isDndActive();
    const suppressed = dndActive && !DND_BYPASS_PRIORITIES.has(normPriority);
    const deliveredBanner = !suppressed && !silent;

    let nextLaSeq = this._liveActivitySeq;
    let liveActivityRecord = null;
    if (parsedLa !== null) {
      let trimmedLaId = '';
      if (typeof parsedLa.id === 'string') {
        if (!consumeCloneBytes(postBudget, parsedLa.id.length)) {
          throwBudgetExceeded('liveActivity id', postBudget);
        }
        trimmedLaId = parsedLa.id.trim();
      }
      const laId = trimmedLaId.length > 0 ? trimmedLaId : `la-${++nextLaSeq}`;
      const existingLa = this._liveActivities.get(laId);
      const validatedProgress = normalizeProgress(parsedLa.progress);
      const laSubtitle =
        parsedLa.subtitle === undefined || parsedLa.subtitle === null
          ? ''
          : typeof parsedLa.subtitle === 'string'
            ? parsedLa.subtitle
            : safeCoerceString(parsedLa.subtitle, 'liveActivity.subtitle');
      const laTitle = trimmedLaTitle.length > 0 ? trimmedLaTitle : resolvedTitle;
      if (!consumeCloneBytes(postBudget, laSubtitle.length)) {
        throwBudgetExceeded('liveActivity text', postBudget);
      }
      const laLeadingRes =
        parsedLa.compactLeading !== undefined
          ? cloneFieldWithBudget(parsedLa.compactLeading, 'liveActivity.compactLeading', postBudget, MAX_CLONE_NODES)
          : { value: null, bytes: 0 };
      const laTrailingRes =
        parsedLa.compactTrailing !== undefined
          ? cloneFieldWithBudget(parsedLa.compactTrailing, 'liveActivity.compactTrailing', postBudget, MAX_CLONE_NODES)
          : { value: null, bytes: 0 };
      const laExpandedRes =
        parsedLa.expandedBody !== undefined
          ? cloneFieldWithBudget(parsedLa.expandedBody, 'liveActivity.expandedBody', postBudget, MAX_CLONE_NODES)
          : { value: typeof body === 'string' ? body : resolvedBody, bytes: resolvedBody.length };
      const laIconRes =
        parsedLa.icon !== undefined
          ? cloneFieldWithBudget(parsedLa.icon, 'liveActivity.icon', postBudget, MAX_CLONE_NODES)
          : { value: null, bytes: 0 };
      const laPayloadRes =
        parsedLa.payload !== undefined
          ? cloneFieldWithBudget(parsedLa.payload, 'liveActivity.payload', postBudget, MAX_CLONE_NODES)
          : { value: null, bytes: 0 };
      const laDataRes =
        parsedLa.data !== undefined
          ? cloneFieldWithBudget(parsedLa.data, 'liveActivity.data', postBudget, MAX_CLONE_NODES)
          : null;

      liveActivityRecord = {
        id: laId,
        notificationId: id,
        appId: cleanAppId,
        platform: resolvedPlatform,
        title: laTitle,
        subtitle: laSubtitle,
        compactLeading: laLeadingRes.value,
        compactTrailing: laTrailingRes.value,
        expandedBody: laExpandedRes.value,
        progress: validatedProgress,
        icon: laIconRes.value,
        payload: laPayloadRes.value,
        state: 'active',
        dismissalPolicy: null,
        createdAt: existingLa ? existingLa.createdAt : now,
        updatedAt: now,
        endedAt: null,
        _fieldBytes: {
          title: laTitle.length,
          subtitle: laSubtitle.length,
          compactLeading: laLeadingRes.bytes,
          compactTrailing: laTrailingRes.bytes,
          expandedBody: laExpandedRes.bytes,
          icon: laIconRes.bytes,
          payload: laPayloadRes.bytes,
          data: laDataRes ? laDataRes.bytes : 0,
        },
      };
      if (laDataRes !== null) {
        liveActivityRecord.data = laDataRes.value;
      }
    }

    const record = {
      id,
      appId: cleanAppId,
      platform: resolvedPlatform,
      title: resolvedTitle,
      body: resolvedBody,
      priority: normPriority,
      category: resolvedCategory,
      actions: normalizedActions,
      invokedActions: [],
      _invokedActionsBytes: 0,
      liveActivity: liveActivityRecord ? cloneLiveActivityRecord(liveActivityRecord) : null,
      data: clonedData,
      silent: Boolean(silent),
      suppressed,
      deliveredBanner,
      read: false,
      dismissed: false,
      dismissedAt: null,
      createdAt: now,
      updatedAt: now,
    };

    // Atomic commit phase: zero validation/coercion/cloning errors possible below
    this._notifSeq = nextNotifSeq;
    if (liveActivityRecord) {
      this._liveActivitySeq = nextLaSeq;
      this._liveActivities.set(liveActivityRecord.id, liveActivityRecord);
    }
    this._evictIfFull();
    this._notifications.set(id, record);
    if (this._eventBus) {
      this._emit('notification:posted', cloneNotificationRecord(record));
    }
    return cloneNotificationRecord(record);
  }

  list(opts = {}) {
    if (opts !== undefined && opts !== null) {
      assertPlainObject(opts, 'Notification list options');
    }
    const optsObj = opts ?? {};
    const includeDismissed = Boolean(safeGetProp(optsObj, 'includeDismissed', 'list options'));
    const appId = safeGetProp(optsObj, 'appId', 'list options');
    const category = safeGetProp(optsObj, 'category', 'list options');
    const priority = safeGetProp(optsObj, 'priority', 'list options');
    const unreadOnly = Boolean(safeGetProp(optsObj, 'unreadOnly', 'list options'));
    const rawIncludeSuppressed = safeGetProp(optsObj, 'includeSuppressed', 'list options');
    const includeSuppressed = rawIncludeSuppressed !== undefined ? Boolean(rawIncludeSuppressed) : true;

    const out = [];
    const targetPriority = priority !== undefined ? safeDisplayValue(priority).toLowerCase() : undefined;
    const values = Array.from(this._notifications.values());
    for (let i = values.length - 1; i >= 0; i--) {
      const n = values[i];
      if (!includeDismissed && n.dismissed) continue;
      if (appId !== undefined && n.appId !== appId) continue;
      if (category !== undefined && n.category !== category) continue;
      if (targetPriority !== undefined && n.priority !== targetPriority) continue;
      if (unreadOnly && n.read) continue;
      if (!includeSuppressed && n.suppressed) continue;
      out.push(cloneNotificationRecord(n));
    }
    return out;
  }

  get(id) {
    const rec = this._notifications.get(id);
    return rec ? cloneNotificationRecord(rec) : null;
  }

  markRead(id) {
    const rec = this._notifications.get(id);
    if (!rec) {
      throw new OmniOSError(`Notification not found: ${safeDisplayValue(id)}`, {
        code: ERROR_CODES.ENOENT,
        details: { id: safeDisplayValue(id) },
      });
    }
    rec.read = true;
    rec.updatedAt = new Date().toISOString();
    const cloned = cloneNotificationRecord(rec);
    this._emit('notification:updated', { type: 'read', notification: cloneNotificationRecord(rec) });
    return cloned;
  }

  dismiss(id) {
    const rec = this._notifications.get(id);
    if (!rec) {
      throw new OmniOSError(`Notification not found: ${safeDisplayValue(id)}`, {
        code: ERROR_CODES.ENOENT,
        details: { id: safeDisplayValue(id) },
      });
    }
    const now = new Date().toISOString();
    rec.dismissed = true;
    rec.dismissedAt = now;
    rec.updatedAt = now;
    const cloned = cloneNotificationRecord(rec);
    this._emit('notification:updated', { type: 'dismissed', notification: cloneNotificationRecord(rec) });
    return cloned;
  }

  clearAll(opts = {}) {
    if (opts !== undefined && opts !== null) {
      assertPlainObject(opts, 'clearAll options');
    }
    const optsObj = opts ?? {};
    const appId = safeGetProp(optsObj, 'appId', 'clearAll options');
    const now = new Date().toISOString();
    let count = 0;
    for (const rec of this._notifications.values()) {
      if (rec.dismissed) continue;
      if (appId !== undefined && rec.appId !== appId) continue;
      rec.dismissed = true;
      rec.dismissedAt = now;
      rec.updatedAt = now;
      count += 1;
    }
    this._emit('notification:updated', { type: 'cleared', appId: appId ?? null, count });
    return { cleared: count };
  }

  invokeAction(id, actionId, opts = {}) {
    if (opts !== undefined && opts !== null) {
      assertPlainObject(opts, 'invokeAction options');
    }
    const optsObj = opts ?? {};
    const input = safeGetProp(optsObj, 'input', 'invokeAction options') ?? null;
    const rec = this._notifications.get(id);
    if (!rec) {
      throw new OmniOSError(`Notification not found: ${safeDisplayValue(id)}`, {
        code: ERROR_CODES.ENOENT,
        details: { id: safeDisplayValue(id) },
      });
    }
    const action = rec.actions.find((a) => a.id === actionId);
    if (!action) {
      throw new OmniOSError(
        `Notification action "${safeDisplayValue(actionId)}" not found on notification "${safeDisplayValue(id)}"`,
        {
          code: ERROR_CODES.ENOENT,
          details: { id: safeDisplayValue(id), actionId: safeDisplayValue(actionId) },
        }
      );
    }

    if (rec.invokedActions.length >= MAX_INVOKED_ACTIONS) {
      throw new QuotaExceededError(
        `Notification "${safeDisplayValue(id)}" invokedActions exceeds maximum count (${MAX_INVOKED_ACTIONS})`,
        {
          code: ERROR_CODES.EQUOTA,
          quotaType: 'invokedActionsCount',
          limit: MAX_INVOKED_ACTIONS,
          actual: rec.invokedActions.length + 1,
        }
      );
    }

    const usedInvokedBytes = rec._invokedActionsBytes ?? 0;
    const entryOverhead = action.id.length + action.label.length + 64;
    const remainingInvokedBytes = MAX_INVOKED_ACTIONS_BYTES - usedInvokedBytes;
    if (entryOverhead > remainingInvokedBytes) {
      throw new QuotaExceededError(
        `Notification "${safeDisplayValue(id)}" invokedActions exceeds maximum byte budget (${MAX_INVOKED_ACTIONS_BYTES} bytes)`,
        {
          code: ERROR_CODES.EQUOTA,
          quotaType: 'invokedActionsBytes',
          limit: MAX_INVOKED_ACTIONS_BYTES,
          actual: usedInvokedBytes + entryOverhead,
        }
      );
    }

    let safeInput = null;
    let inputBytes = 0;
    if (input !== null && input !== undefined) {
      const inputBudget = createCloneBudget(
        MAX_CLONE_NODES,
        remainingInvokedBytes - entryOverhead,
        MAX_INVOKED_ACTIONS_BYTES
      );
      const clonedRes = cloneFieldWithBudget(input, 'invokeAction.input', inputBudget, MAX_CLONE_NODES);
      safeInput = clonedRes.value;
      inputBytes = clonedRes.bytes;
    }

    const now = new Date().toISOString();
    rec._invokedActionsBytes = usedInvokedBytes + entryOverhead + inputBytes;
    rec.invokedActions.push({
      actionId: action.id,
      label: action.label,
      input: safeInput,
      ts: now,
    });
    rec.read = true;
    rec.updatedAt = now;

    let deliveredPid = null;
    if (this._processManager) {
      let targetPcb = null;
      try {
        const getAllFn = this._processManager.getAll;
        if (typeof getAllFn === 'function') {
          const pcbs = getAllFn.call(this._processManager);
          if (Array.isArray(pcbs)) {
            targetPcb = pcbs.find(
              (pcb) => pcb && pcb.appId === rec.appId && pcb.state !== 'ZOMBIE' && pcb.state !== 'TERMINATED'
            ) ?? null;
          }
        }
      } catch (err) {
        try {
          this._log(
            'warn',
            'notifications',
            `ProcessManager lookup failed during invokeAction: ${safeErrorMessage(err)}`
          );
        } catch {
          // Isolate logger failures.
        }
      }
      if (targetPcb) {
        deliveredPid = targetPcb.pid;
        try {
          const execCtx = targetPcb.executionContext;
          const deliverFn = execCtx?.deliverEvent;
          if (typeof deliverFn === 'function') {
            const ret = deliverFn.call(execCtx, {
              type: 'notification_action',
              notificationId: id,
              actionId: action.id,
              action: cloneActionRecord(action),
              input: safeInput !== null ? cloneJsonSafe(safeInput) : null,
            });
            suppressAsyncRejection(ret, (err) => {
              try {
                this._log(
                  'warn',
                  'notifications',
                  `Async error delivering action to PID ${targetPcb.pid} (${safeErrorCode(err)}): ${safeErrorMessage(err)}`
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
              'notifications',
              `Failed delivering action to PID ${targetPcb.pid} (${safeErrorCode(err)}): ${safeErrorMessage(err)}`
            );
          } catch {
            // Isolate logger failures.
          }
        }
        try {
          if (targetPcb.state === 'BLOCKED' && typeof this._processManager.wake === 'function') {
            this._processManager.wake(targetPcb.pid);
          }
        } catch {
          // Ignore wake errors.
        }
      }
    }

    if (this._onAction) {
      try {
        const ret = this._onAction({
          notification: cloneNotificationRecord(rec),
          action: cloneActionRecord(action),
          input: safeInput !== null ? cloneJsonSafe(safeInput) : null,
        });
        suppressAsyncRejection(ret, (err) => {
          try {
            this._log(
              'warn',
              'notifications',
              `Async onAction callback rejected (${safeErrorCode(err)}): ${safeErrorMessage(err)}`
            );
          } catch {
            // Isolate logger failures.
          }
        });
      } catch (err) {
        try {
          this._log(
            'warn',
            'notifications',
            `onAction callback threw (${safeErrorCode(err)}): ${safeErrorMessage(err)}`
          );
        } catch {
          // Isolate logger failures.
        }
      }
    }

    if (this._eventBus) {
      const eventPayload = {
        type: 'action_invoked',
        notification: cloneNotificationRecord(rec),
        actionId: action.id,
        input: safeInput !== null ? cloneJsonSafe(safeInput) : null,
        deliveredPid,
      };
      this._emit('notification:action', eventPayload);
      this._emit('notification:updated', {
        type: 'action_invoked',
        notification: cloneNotificationRecord(rec),
        actionId: action.id,
        input: safeInput !== null ? cloneJsonSafe(safeInput) : null,
        deliveredPid,
      });
    }

    return {
      ok: true,
      notificationId: id,
      appId: rec.appId,
      actionId: action.id,
      action: cloneActionRecord(action),
      deliveredPid,
    };
  }

  _findLiveActivity(activityId) {
    if (this._liveActivities.has(activityId)) {
      return this._liveActivities.get(activityId);
    }
    for (const la of this._liveActivities.values()) {
      if (la.notificationId === activityId) return la;
    }
    return null;
  }

  getLiveActivities(opts = {}) {
    if (opts !== undefined && opts !== null) {
      assertPlainObject(opts, 'getLiveActivities options');
    }
    const optsObj = opts ?? {};
    const includeEnded = Boolean(safeGetProp(optsObj, 'includeEnded', 'getLiveActivities options'));
    const out = [];
    for (const la of this._liveActivities.values()) {
      if (!includeEnded && la.state !== 'active') continue;
      out.push(cloneLiveActivityRecord(la));
    }
    out.sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : 0));
    return out;
  }

  updateLiveActivity(activityId, patch = {}) {
    const la = this._findLiveActivity(activityId);
    if (!la) {
      throw new OmniOSError(`Live Activity not found: ${safeDisplayValue(activityId)}`, {
        code: ERROR_CODES.ENOENT,
        details: { activityId: safeDisplayValue(activityId) },
      });
    }
    if (la.state === 'ended') {
      throw new OmniOSError(`Cannot update ended Live Activity: ${la.id}`, {
        code: ERROR_CODES.EINVAL,
        details: { activityId: la.id },
      });
    }
    assertPlainObject(patch, 'Live Activity patch');

    // Read, validate, coerce, and clone ALL patch fields into locals BEFORE mutating la or linkedNotif!
    const rawTitle = safeGetProp(patch, 'title', 'Live Activity patch');
    const rawSubtitle = safeGetProp(patch, 'subtitle', 'Live Activity patch');
    const rawCompactLeading = safeGetProp(patch, 'compactLeading', 'Live Activity patch');
    const rawCompactTrailing = safeGetProp(patch, 'compactTrailing', 'Live Activity patch');
    const rawExpandedBody = safeGetProp(patch, 'expandedBody', 'Live Activity patch');
    const rawProgress = safeGetProp(patch, 'progress', 'Live Activity patch');
    const rawIcon = safeGetProp(patch, 'icon', 'Live Activity patch');
    const rawPayload = safeGetProp(patch, 'payload', 'Live Activity patch');
    const rawData = safeGetProp(patch, 'data', 'Live Activity patch');

    const hasTitle = rawTitle !== undefined;
    const nextTitle = hasTitle ? safeCoerceString(rawTitle, 'liveActivity.title') : undefined;
    const hasSubtitle = rawSubtitle !== undefined;
    const nextSubtitle = hasSubtitle ? safeCoerceString(rawSubtitle, 'liveActivity.subtitle') : undefined;
    const hasCompactLeading = rawCompactLeading !== undefined;
    const hasCompactTrailing = rawCompactTrailing !== undefined;
    const hasExpandedBody = rawExpandedBody !== undefined;
    const hasProgress = rawProgress !== undefined;
    const nextProgress = hasProgress ? normalizeProgress(rawProgress) : undefined;
    const hasIcon = rawIcon !== undefined;
    const hasPayload = rawPayload !== undefined;
    const hasData = rawData !== undefined;

    const prevBytes = la._fieldBytes ?? {};
    const untouchedBytes =
      (hasTitle ? 0 : (prevBytes.title ?? 0)) +
      (hasSubtitle ? 0 : (prevBytes.subtitle ?? 0)) +
      (hasCompactLeading ? 0 : (prevBytes.compactLeading ?? 0)) +
      (hasCompactTrailing ? 0 : (prevBytes.compactTrailing ?? 0)) +
      (hasExpandedBody ? 0 : (prevBytes.expandedBody ?? 0)) +
      (hasIcon ? 0 : (prevBytes.icon ?? 0)) +
      (hasPayload ? 0 : (prevBytes.payload ?? 0)) +
      (hasData ? 0 : (prevBytes.data ?? 0));
    const patchBudget = createCloneBudget(
      MAX_POST_TOTAL_NODES,
      Math.max(0, MAX_CLONE_BYTES - untouchedBytes),
      MAX_CLONE_BYTES
    );
    if (!consumeCloneBytes(patchBudget, (hasTitle ? nextTitle.length : 0) + (hasSubtitle ? nextSubtitle.length : 0))) {
      throwBudgetExceeded('liveActivity patch', patchBudget);
    }
    const nextCompactLeadingRes = hasCompactLeading
      ? cloneFieldWithBudget(rawCompactLeading, 'liveActivity.compactLeading', patchBudget, MAX_CLONE_NODES)
      : null;
    const nextCompactTrailingRes = hasCompactTrailing
      ? cloneFieldWithBudget(rawCompactTrailing, 'liveActivity.compactTrailing', patchBudget, MAX_CLONE_NODES)
      : null;
    const nextExpandedBodyRes = hasExpandedBody
      ? cloneFieldWithBudget(rawExpandedBody, 'liveActivity.expandedBody', patchBudget, MAX_CLONE_NODES)
      : null;
    const nextIconRes = hasIcon
      ? cloneFieldWithBudget(rawIcon, 'liveActivity.icon', patchBudget, MAX_CLONE_NODES)
      : null;
    const nextPayloadRes = hasPayload
      ? cloneFieldWithBudget(rawPayload, 'liveActivity.payload', patchBudget, MAX_CLONE_NODES)
      : null;
    const nextDataRes = hasData
      ? cloneFieldWithBudget(rawData, 'liveActivity.data', patchBudget, MAX_CLONE_NODES)
      : null;

    // Atomic commit phase: apply all validated updates together
    if (!la._fieldBytes) {
      la._fieldBytes = {
        title: 0,
        subtitle: 0,
        compactLeading: 0,
        compactTrailing: 0,
        expandedBody: 0,
        icon: 0,
        payload: 0,
        data: 0,
      };
    }
    if (hasTitle) {
      la.title = nextTitle;
      la._fieldBytes.title = nextTitle.length;
    }
    if (hasSubtitle) {
      la.subtitle = nextSubtitle;
      la._fieldBytes.subtitle = nextSubtitle.length;
    }
    if (hasCompactLeading) {
      la.compactLeading = nextCompactLeadingRes.value;
      la._fieldBytes.compactLeading = nextCompactLeadingRes.bytes;
    }
    if (hasCompactTrailing) {
      la.compactTrailing = nextCompactTrailingRes.value;
      la._fieldBytes.compactTrailing = nextCompactTrailingRes.bytes;
    }
    if (hasExpandedBody) {
      la.expandedBody = nextExpandedBodyRes.value;
      la._fieldBytes.expandedBody = nextExpandedBodyRes.bytes;
    }
    if (hasProgress) la.progress = nextProgress;
    if (hasIcon) {
      la.icon = nextIconRes.value;
      la._fieldBytes.icon = nextIconRes.bytes;
    }
    if (hasPayload) {
      la.payload = nextPayloadRes.value;
      la._fieldBytes.payload = nextPayloadRes.bytes;
    }
    if (hasData) {
      la.data = nextDataRes.value;
      la._fieldBytes.data = nextDataRes.bytes;
    }
    la.updatedAt = new Date().toISOString();

    const linkedNotif = this._notifications.get(la.notificationId);
    if (linkedNotif) {
      linkedNotif.liveActivity = cloneLiveActivityRecord(la);
      linkedNotif.updatedAt = la.updatedAt;
    }

    const cloned = cloneLiveActivityRecord(la);
    this._emit('notification:updated', {
      type: 'live_activity_updated',
      liveActivity: cloneLiveActivityRecord(la),
      notificationId: la.notificationId,
    });
    return cloned;
  }

  endLiveActivity(activityId, opts = {}) {
    if (opts !== undefined && opts !== null) {
      assertPlainObject(opts, 'endLiveActivity options');
    }
    const optsObj = opts ?? {};
    const rawPolicy = safeGetProp(optsObj, 'dismissalPolicy', 'endLiveActivity options');
    const dismissalPolicy = rawPolicy !== undefined ? rawPolicy : 'immediate';
    const la = this._findLiveActivity(activityId);
    if (!la) {
      throw new OmniOSError(`Live Activity not found: ${safeDisplayValue(activityId)}`, {
        code: ERROR_CODES.ENOENT,
        details: { activityId: safeDisplayValue(activityId) },
      });
    }
    const now = new Date().toISOString();
    la.state = 'ended';
    la.endedAt = now;
    la.updatedAt = now;
    la.dismissalPolicy = typeof dismissalPolicy === 'string' ? dismissalPolicy : 'immediate';

    const linkedNotif = this._notifications.get(la.notificationId);
    if (linkedNotif) {
      linkedNotif.liveActivity = cloneLiveActivityRecord(la);
      linkedNotif.updatedAt = now;
    }

    const cloned = cloneLiveActivityRecord(la);
    this._emit('notification:updated', {
      type: 'live_activity_ended',
      liveActivity: cloneLiveActivityRecord(la),
      notificationId: la.notificationId,
    });
    return cloned;
  }
}

export function createNotificationCenter(options = {}) {
  return new NotificationCenter(options);
}

function validateServiceDep(obj, label, probeProp) {
  if (obj === null || obj === undefined) return null;
  if (typeof obj !== 'object') {
    throw new OmniOSError(`createIpcBrokerService ${label} must be an object or null`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (probeProp) {
    safeGetProp(obj, probeProp, `createIpcBrokerService ${label}`);
  }
  return obj;
}

export function createIpcBrokerService(options = {}) {
  if (options !== undefined && options !== null) {
    assertPlainObject(options, 'createIpcBrokerService options');
  }
  const optsObj = options ?? {};
  const ipc = validateServiceDep(safeGetProp(optsObj, 'ipc', 'createIpcBrokerService options'), 'ipc', 'start');
  const router = validateServiceDep(
    safeGetProp(optsObj, 'router', 'createIpcBrokerService options'),
    'router',
    'listPendingChoosers'
  );
  const clipboard = validateServiceDep(
    safeGetProp(optsObj, 'clipboard', 'createIpcBrokerService options'),
    'clipboard',
    'get'
  );
  const notifications = validateServiceDep(
    safeGetProp(optsObj, 'notifications', 'createIpcBrokerService options'),
    'notifications',
    'list'
  );
  const kernel = validateServiceDep(
    safeGetProp(optsObj, 'kernel', 'createIpcBrokerService options'),
    'kernel',
    'storage'
  );
  const rawDeps = safeGetProp(optsObj, 'deps', 'createIpcBrokerService options');
  const rawEssential = safeGetProp(optsObj, 'essential', 'createIpcBrokerService options');

  let deps = [];
  if (rawDeps !== undefined && rawDeps !== null) {
    let isArr = false;
    try {
      isArr = Array.isArray(rawDeps);
    } catch (err) {
      throw new OmniOSError('createIpcBrokerService deps must be a readable Array', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (!isArr) {
      throw new OmniOSError('createIpcBrokerService deps must be an Array', {
        code: ERROR_CODES.EINVAL,
      });
    }
    let depsLen;
    try {
      depsLen = rawDeps.length;
    } catch (err) {
      throw new OmniOSError('Unreadable createIpcBrokerService deps', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (typeof depsLen !== 'number' || !Number.isSafeInteger(depsLen) || depsLen < 0 || depsLen > 1024) {
      throw new OmniOSError('Invalid createIpcBrokerService deps length', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      deps = [];
      for (let i = 0; i < depsLen; i++) {
        deps.push(rawDeps[i]);
      }
    } catch (err) {
      throw new OmniOSError('Unreadable createIpcBrokerService deps', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
  }
  const essential = rawEssential !== undefined ? Boolean(rawEssential) : true;
  // Retain validated references (clipboard/kernel validated at creation for I4/J4 parity)
  void clipboard;

  let running = false;
  return {
    name: 'ipc-brokerd',
    deps,
    essential,
    description: 'OmniOS IPC Broker, Universal Intent Router, Shared Clipboard & Notification Daemon',
    start() {
      try {
        if (kernel !== null) {
          void kernel.storage;
        }
        if (ipc !== null && typeof ipc.start === 'function') {
          ipc.start();
        }
        running = true;
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError(`ipc-brokerd failed to start: ${safeErrorMessage(err)}`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
    },
    stop() {
      running = false;
      try {
        if (ipc !== null && typeof ipc.stop === 'function') {
          ipc.stop();
        }
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError(`ipc-brokerd failed to stop: ${safeErrorMessage(err)}`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
    },
    healthCheck() {
      if (!running) {
        return { ok: false, reason: 'ipc-brokerd is not running' };
      }
      try {
        return {
          ok: true,
          channels: ipc ? ipc.listChannels().length : 0,
          shmSegments: ipc ? ipc.listShm().length : 0,
          pendingChoosers: router ? router.listPendingChoosers().length : 0,
          notifications: notifications ? notifications.list().length : 0,
          liveActivities: notifications ? notifications.getLiveActivities().length : 0,
        };
      } catch (err) {
        return { ok: false, reason: safeErrorMessage(err) };
      }
    },
  };
}

export function registerIpcBrokerService(serviceManager, options = {}) {
  if (!serviceManager || typeof serviceManager !== 'object') {
    throw new OmniOSError('registerIpcBrokerService requires a ServiceManager object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const registerFn = safeGetProp(serviceManager, 'register', 'registerIpcBrokerService serviceManager');
  if (typeof registerFn !== 'function') {
    throw new OmniOSError('registerIpcBrokerService serviceManager must implement register()', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const svc = createIpcBrokerService(options);
  registerFn.call(serviceManager, svc);
  return svc;
}
