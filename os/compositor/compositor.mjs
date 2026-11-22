/**
 * OmniOS Headless Window Compositor Server (`Compositor` / `compositord`)
 * - Kernel-space display server managing window lifecycle, bounds, z-order, focus,
 *   Snap Layouts (all 10 states with chained `restoreBounds` preservation), and active Global Menu Bar
 * - Dual-mode surface engine: Retained Semantic UI Scene Graph (`uiTree`) + 2D Drawlist (`drawOps`/`appendDrawOps`)
 *   with strictly monotonic `surfaceRevision`
 * - Direct fault-isolated input router delivering events to owning process `ExecutionContext.deliverEvent()`
 *   (zero uncaught throws or unhandled promise rejections)
 * - Strict M1 ProcessManager integration: live PCB validation before `registerWindow`, internal `_windowsByPid`
 *   tracking (surviving M1's pre-event `pcb.windowIds.clear()`), and `maxWindows` quota enforcement
 * - Optional bidirectional `configStore` sync for `system.shellMode` (`'hybrid'` alias -> `'unified'`)
 */

import { types } from 'node:util';
import {
  OmniOSError,
  ProcessError,
  QuotaExceededError,
  ERROR_CODES,
} from '../common/errors.mjs';

export const SHELL_MODES = Object.freeze(['unified', 'windows', 'macos', 'ios', 'android']);

export const WINDOW_STATES = Object.freeze([
  'normal',
  'minimized',
  'maximized',
  'snapped-left',
  'snapped-right',
  'snapped-tl',
  'snapped-tr',
  'snapped-bl',
  'snapped-br',
  'fullscreen',
]);

export const CHROME_STYLES = Object.freeze([
  'unified',
  'macos',
  'windows',
  'ios',
  'android',
  'frameless',
]);

export const DEFAULT_VIEWPORT = Object.freeze({
  width: 1440,
  height: 900,
  insets: Object.freeze({ top: 0, bottom: 0, left: 0, right: 0 }),
});

export const DEFAULT_MENU_BAR = Object.freeze([
  Object.freeze({
    id: 'omnios',
    label: 'OmniOS',
    items: Object.freeze([
      Object.freeze({ id: 'omnios.about', label: 'About OmniOS' }),
      Object.freeze({ id: 'omnios.settings', label: 'System Settings...' }),
      Object.freeze({ id: 'omnios.activity', label: 'Activity Monitor' }),
    ]),
  }),
  Object.freeze({
    id: 'file',
    label: 'File',
    items: Object.freeze([
      Object.freeze({ id: 'file.new', label: 'New Window' }),
      Object.freeze({ id: 'file.close', label: 'Close Window' }),
    ]),
  }),
  Object.freeze({
    id: 'edit',
    label: 'Edit',
    items: Object.freeze([
      Object.freeze({ id: 'edit.copy', label: 'Copy' }),
      Object.freeze({ id: 'edit.paste', label: 'Paste' }),
    ]),
  }),
  Object.freeze({
    id: 'window',
    label: 'Window',
    items: Object.freeze([
      Object.freeze({ id: 'window.minimize', label: 'Minimize' }),
      Object.freeze({ id: 'window.maximize', label: 'Zoom / Maximize' }),
      Object.freeze({ id: 'window.snap_left', label: 'Snap Left' }),
      Object.freeze({ id: 'window.snap_right', label: 'Snap Right' }),
    ]),
  }),
]);

const SHELL_MODE_SET = new Set(SHELL_MODES);
const WINDOW_STATE_SET = new Set(WINDOW_STATES);
const CHROME_STYLE_SET = new Set(CHROME_STYLES);
const UI_WAIT_REASONS = new Set(['ui', 'event', 'ui_event', 'message']);
const REFLOW_STATES = new Set([
  'maximized',
  'fullscreen',
  'snapped-left',
  'snapped-right',
  'snapped-tl',
  'snapped-tr',
  'snapped-bl',
  'snapped-br',
]);

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
const MAX_SURFACE_DRAW_OPS_NODES = 200_000;
const MAX_CLONE_BYTES = 4 * 1024 * 1024; // 4 MiB
const MAX_SURFACE_BYTES = 2 * 1024 * 1024; // 2 MiB
const MAX_ICON_NODES = 4096;
const MAX_ICON_BYTES = 65_536;
const MAX_CLONE_BIGINT_ABS = 1n << 4096n;
const MAX_DISPLAY_LENGTH = 256;

function capDisplayString(str) {
  if (str.length > 65_536) return `[String(${str.length})]`;
  return str.length > MAX_DISPLAY_LENGTH ? `${str.slice(0, MAX_DISPLAY_LENGTH)}...` : str;
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

function safeIsArray(val) {
  try {
    return Array.isArray(val);
  } catch {
    return false;
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

function assertReadablePlainObject(obj, label) {
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

function cloneJsonSafe(
  val,
  seen = new Set(),
  depth = 0,
  budget = { remaining: MAX_CLONE_NODES, remainingBytes: MAX_CLONE_BYTES, exceeded: false, bytesExceeded: false }
) {
  if (depth > 48) {
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

function coerceWindowTitle(value, fallback = 'Untitled') {
  if (value === undefined || value === null) return fallback;
  const t = typeof value;
  if (t === 'string') return value;
  if (t === 'number' || t === 'boolean') return String(value);
  if (t === 'bigint') {
    if (value > MAX_CLONE_BIGINT_ABS || value < -MAX_CLONE_BIGINT_ABS) {
      throw new OmniOSError('Invalid window title: BigInt out of range', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return value.toString(10);
  }
  if (t === 'symbol') {
    throw new OmniOSError('Window title cannot be a Symbol', {
      code: ERROR_CODES.EINVAL,
    });
  }
  throw new OmniOSError('Invalid window title: must be a string or primitive', {
    code: ERROR_CODES.EINVAL,
  });
}

export function normalizeShellMode(mode) {
  if (typeof mode !== 'string') {
    throw new OmniOSError(`Invalid shell mode: ${safeDisplayValue(mode)}`, {
      code: ERROR_CODES.EINVAL,
      details: { mode: safeDisplayValue(mode), allowed: SHELL_MODES },
    });
  }
  if (mode.length > 64) {
    throw new OmniOSError(`Unsupported shell mode: ${safeDisplayValue(mode)}`, {
      code: ERROR_CODES.EINVAL,
      details: { mode: safeDisplayValue(mode), allowed: SHELL_MODES },
    });
  }
  const lower = mode.trim().toLowerCase();
  const mapped = lower === 'hybrid' ? 'unified' : lower;
  if (!SHELL_MODE_SET.has(mapped)) {
    throw new OmniOSError(`Unsupported shell mode: ${safeDisplayValue(mode)}`, {
      code: ERROR_CODES.EINVAL,
      details: { mode: safeDisplayValue(mode), allowed: SHELL_MODES },
    });
  }
  return mapped;
}

function normalizeInsets(insets = {}) {
  if (insets === undefined || insets === null) {
    return { top: 0, bottom: 0, left: 0, right: 0 };
  }
  assertReadablePlainObject(insets, 'Viewport insets');
  const check = (v, name) => {
    const num = v === undefined ? 0 : v;
    if (typeof num !== 'number' || !Number.isFinite(num) || num < 0) {
      throw new OmniOSError(`Viewport inset "${name}" must be a non-negative finite number`, {
        code: ERROR_CODES.EINVAL,
        details: { name, value: safeDisplayValue(v) },
      });
    }
    return Math.round(num);
  };
  return {
    top: check(safeGetProp(insets, 'top', 'viewport.insets'), 'top'),
    bottom: check(safeGetProp(insets, 'bottom', 'viewport.insets'), 'bottom'),
    left: check(safeGetProp(insets, 'left', 'viewport.insets'), 'left'),
    right: check(safeGetProp(insets, 'right', 'viewport.insets'), 'right'),
  };
}

function normalizeViewport(viewport = DEFAULT_VIEWPORT) {
  assertReadablePlainObject(viewport, 'Viewport');
  const rawWidth = safeGetProp(viewport, 'width', 'viewport');
  const rawHeight = safeGetProp(viewport, 'height', 'viewport');
  const rawInsets = safeGetProp(viewport, 'insets', 'viewport');
  const width = rawWidth ?? DEFAULT_VIEWPORT.width;
  const height = rawHeight ?? DEFAULT_VIEWPORT.height;
  if (typeof width !== 'number' || !Number.isFinite(width) || width < 1) {
    throw new OmniOSError(`Invalid viewport width: ${safeDisplayValue(width)}`, { code: ERROR_CODES.EINVAL });
  }
  if (typeof height !== 'number' || !Number.isFinite(height) || height < 1) {
    throw new OmniOSError(`Invalid viewport height: ${safeDisplayValue(height)}`, { code: ERROR_CODES.EINVAL });
  }
  const insets = normalizeInsets(rawInsets);
  if (insets.left + insets.right >= Math.round(width) || insets.top + insets.bottom >= Math.round(height)) {
    throw new OmniOSError('Viewport insets exceed viewport dimensions', {
      code: ERROR_CODES.EINVAL,
      details: { width, height, insets },
    });
  }
  return {
    width: Math.round(width),
    height: Math.round(height),
    insets,
  };
}

function defaultChromeForPlatform(platform) {
  if (typeof platform === 'string' && platform.length <= 64) {
    const p = platform.trim().toLowerCase();
    if (CHROME_STYLE_SET.has(p)) return p;
  }
  return 'unified';
}

function computeStateBounds(state, viewport, restoreBounds) {
  const { width: vpW, height: vpH, insets } = viewport;
  const workX = insets.left;
  const workY = insets.top;
  const workW = Math.max(1, vpW - insets.left - insets.right);
  const workH = Math.max(1, vpH - insets.top - insets.bottom);
  const leftW = Math.max(1, Math.floor(workW / 2));
  const rightW = Math.max(1, workW - leftW);
  const topH = Math.max(1, Math.floor(workH / 2));
  const bottomH = Math.max(1, workH - topH);

  switch (state) {
    case 'normal':
      return { ...restoreBounds };
    case 'fullscreen':
      return { x: 0, y: 0, width: vpW, height: vpH };
    case 'maximized':
      return { x: workX, y: workY, width: workW, height: workH };
    case 'snapped-left':
      return { x: workX, y: workY, width: leftW, height: workH };
    case 'snapped-right':
      return { x: workX + leftW, y: workY, width: rightW, height: workH };
    case 'snapped-tl':
      return { x: workX, y: workY, width: leftW, height: topH };
    case 'snapped-tr':
      return { x: workX + leftW, y: workY, width: rightW, height: topH };
    case 'snapped-bl':
      return { x: workX, y: workY + topH, width: leftW, height: bottomH };
    case 'snapped-br':
      return { x: workX + leftW, y: workY + topH, width: rightW, height: bottomH };
    case 'minimized':
    default:
      return null;
  }
}

export class Compositor {
  constructor(options = {}) {
    if (options !== undefined && options !== null) {
      assertReadablePlainObject(options, 'Compositor options');
    }
    const optsObj = options ?? {};
    const kernel = safeGetProp(optsObj, 'kernel', 'Compositor options') ?? null;
    const rawProcessManager = safeGetProp(optsObj, 'processManager', 'Compositor options');
    const rawEventBus = safeGetProp(optsObj, 'eventBus', 'Compositor options');
    const configStore = safeGetProp(optsObj, 'configStore', 'Compositor options') ?? null;
    const rawViewport = safeGetProp(optsObj, 'viewport', 'Compositor options');
    const shellMode = safeGetProp(optsObj, 'shellMode', 'Compositor options');
    const rawDefaultMenuBar = safeGetProp(optsObj, 'defaultMenuBar', 'Compositor options');
    const rawMaxDrawOps = safeGetProp(optsObj, 'maxDrawOps', 'Compositor options');
    const log = safeGetProp(optsObj, 'log', 'Compositor options');

    if (kernel !== null && typeof kernel !== 'object') {
      throw new OmniOSError('Compositor kernel must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const kernelPm = kernel ? (safeGetProp(kernel, 'processManager', 'Compositor kernel') ?? null) : null;
    const kernelBus = kernel ? (safeGetProp(kernel, 'eventBus', 'Compositor kernel') ?? null) : null;

    const processManager = rawProcessManager !== undefined ? rawProcessManager : kernelPm;
    const eventBus = rawEventBus !== undefined ? rawEventBus : kernelBus;
    const viewport = rawViewport !== undefined ? rawViewport : DEFAULT_VIEWPORT;
    const maxDrawOps = rawMaxDrawOps !== undefined ? rawMaxDrawOps : 10_000;

    if (!processManager || typeof processManager !== 'object') {
      throw new OmniOSError('Compositor requires a ProcessManager instance', {
        code: ERROR_CODES.EINVAL,
      });
    }
    safeGetProp(processManager, 'get', 'Compositor processManager');
    if (eventBus !== null) {
      if (typeof eventBus !== 'object') {
        throw new OmniOSError('Compositor eventBus must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(eventBus, 'on', 'Compositor eventBus');
      safeGetProp(eventBus, 'emit', 'Compositor eventBus');
    }
    if (configStore !== null) {
      if (typeof configStore !== 'object') {
        throw new OmniOSError('Compositor configStore must be an object or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeGetProp(configStore, 'system', 'Compositor configStore');
    }

    const normalizedViewport = normalizeViewport(viewport);
    let clonedDefaultMenuBar;
    if (rawDefaultMenuBar === undefined || rawDefaultMenuBar === null) {
      clonedDefaultMenuBar = cloneJsonSafe(DEFAULT_MENU_BAR);
    } else {
      let isMenuArr = false;
      try {
        isMenuArr = Array.isArray(rawDefaultMenuBar);
      } catch (err) {
        throw new OmniOSError('Compositor defaultMenuBar must be a readable Array', {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
      if (!isMenuArr) {
        throw new OmniOSError('Compositor defaultMenuBar must be an Array', {
          code: ERROR_CODES.EINVAL,
        });
      }
      const menuRes = cloneJsonSafeWithCount(rawDefaultMenuBar, MAX_SURFACE_DRAW_OPS_NODES, MAX_SURFACE_BYTES);
      if (menuRes.exceeded) {
        throw new QuotaExceededError(
          menuRes.bytesExceeded
            ? `Compositor defaultMenuBar exceeds maximum byte budget (${MAX_SURFACE_BYTES} bytes)`
            : `Compositor defaultMenuBar exceeds maximum node budget (${MAX_SURFACE_DRAW_OPS_NODES})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: menuRes.bytesExceeded ? 'menuBarBytes' : 'menuBarNodes',
            limit: menuRes.bytesExceeded ? MAX_SURFACE_BYTES : MAX_SURFACE_DRAW_OPS_NODES,
            actual: menuRes.bytesExceeded ? menuRes.bytes : menuRes.nodes,
          }
        );
      }
      clonedDefaultMenuBar = menuRes.value;
      if (!Array.isArray(clonedDefaultMenuBar)) {
        throw new OmniOSError('Compositor defaultMenuBar must be a readable Array', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }

    this._kernel = kernel;
    this._processManager = processManager;
    this._eventBus = eventBus;
    this._configStore = configStore;
    this._viewport = normalizedViewport;
    this._defaultMenuBar = clonedDefaultMenuBar;
    this._maxDrawOps = Number.isSafeInteger(maxDrawOps) && maxDrawOps >= 1 ? maxDrawOps : 10_000;
    this._log = typeof log === 'function' ? log : () => {};

    let initialMode = 'unified';
    if (shellMode !== undefined) {
      initialMode = normalizeShellMode(shellMode);
    } else if (this._configStore) {
      try {
        if (this._configStore.system?.get) {
          if (typeof this._configStore.isReady !== 'function' || this._configStore.isReady()) {
            const stored = this._configStore.system.get('system.shellMode');
            if (typeof stored === 'string') {
              initialMode = normalizeShellMode(stored);
            }
          }
        }
      } catch {
        // Defer sync until configStore is initialized.
      }
    }
    this._shellMode = initialMode;
    this._syncingShellMode = false;

    // Prototype-safe internal maps
    this._windows = new Map();
    this._windowsByPid = new Map();
    this._hookedPids = new Set();

    this._nextWindowSeq = 1;
    this._zCounter = 0;
    this._focusedWindowId = null;
    this._started = false;
    this._unsubProcessExit = null;
    this._unsubConfigChanged = null;

    // Auto-subscribe so standalone instances clean up windows on process exit
    this._attachListeners();
  }

  _attachListeners() {
    if (this._eventBus) {
      const onFn = safeGetProp(this._eventBus, 'on', 'Compositor eventBus');
      if (typeof onFn !== 'function') return;
      try {
        if (!this._unsubProcessExit) {
          this._unsubProcessExit = onFn.call(this._eventBus, 'process:exited', (evt) => {
            if (evt && typeof evt.pid === 'number') {
              this.destroyWindowsForPid(evt.pid, { reason: 'process_exited' });
            }
          });
        }
        if (!this._unsubConfigChanged) {
          this._unsubConfigChanged = onFn.call(this._eventBus, 'config:changed', (evt) => {
            if (!evt || evt.canonicalKey !== 'system.shellMode') return;
            if (this._syncingShellMode) return;
            try {
              const nextMode = normalizeShellMode(evt.value);
              if (nextMode !== this._shellMode) {
                this._syncingShellMode = true;
                try {
                  this._shellMode = nextMode;
                  this._emit('compositor:snapshot', this.getSnapshot());
                } finally {
                  this._syncingShellMode = false;
                }
              }
            } catch {
              // Ignore invalid mode value from external event.
            }
          });
        }
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError(`Compositor failed to subscribe to eventBus: ${safeErrorMessage(err)}`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
    }
  }

  start() {
    this._attachListeners();
    if (this._configStore) {
      try {
        const getFn = this._configStore.system?.get;
        if (
          typeof getFn === 'function' &&
          (typeof this._configStore.isReady !== 'function' || this._configStore.isReady())
        ) {
          const stored = getFn.call(this._configStore.system, 'system.shellMode');
          if (typeof stored === 'string') {
            this._shellMode = normalizeShellMode(stored);
          }
        }
      } catch {
        // Keep current shellMode if configStore is not open, unavailable, or revoked.
      }
    }
    this._started = true;
    return { running: true, shellMode: this._shellMode };
  }

  stop() {
    this._started = false;
    if (this._unsubProcessExit) {
      try {
        this._unsubProcessExit();
      } catch {
        // Ignore.
      }
      this._unsubProcessExit = null;
    }
    if (this._unsubConfigChanged) {
      try {
        this._unsubConfigChanged();
      } catch {
        // Ignore.
      }
      this._unsubConfigChanged = null;
    }
  }

  isRunning() {
    return this._started;
  }

  _emit(event, payload) {
    if (!this._eventBus) return;
    try {
      this._eventBus.emit(event, payload);
    } catch {
      // Never allow listener errors to disrupt compositor operations.
    }
  }

  _safeLog(level, subsystem, message) {
    try {
      this._log(level, subsystem, message);
    } catch {
      // Isolate logger failures (prevent unhandled rejections inside async error handlers).
    }
  }

  _hookProcessCleanup(pid) {
    if (this._hookedPids.has(pid)) return;
    let added = false;
    try {
      const addHookFn = this._processManager.addCleanupHook;
      if (typeof addHookFn !== 'function') return;
      this._hookedPids.add(pid);
      added = true;
      addHookFn.call(this._processManager, pid, () => {
        this.destroyWindowsForPid(pid, { reason: 'process_exited' });
      });
    } catch {
      // Isolate revoked or unavailable ProcessManager during optional cleanup-hook registration.
      if (added) {
        this._hookedPids.delete(pid);
      }
    }
  }

  _requireWindow(windowId) {
    const win = this._windows.get(windowId);
    if (!win) {
      throw new OmniOSError(`Compositor window not found: ${safeDisplayValue(windowId)}`, {
        code: ERROR_CODES.ENOENT,
        details: { windowId: safeDisplayValue(windowId) },
      });
    }
    return win;
  }

  _cloneWindow(win) {
    return {
      windowId: win.windowId,
      pid: win.pid,
      appId: win.appId,
      platform: win.platform,
      title: win.title,
      icon: cloneJsonSafe(win.icon),
      chromeStyle: win.chromeStyle,
      menuBar: win.menuBar === null ? null : cloneJsonSafe(win.menuBar),
      bounds: { ...win.bounds },
      restoreBounds: { ...win.restoreBounds },
      state: win.state,
      zIndex: win.zIndex,
      focused: win.focused,
      surface: {
        uiTree: win.surface.uiTree === null ? null : cloneJsonSafe(win.surface.uiTree),
        drawOps: cloneJsonSafe(win.surface.drawOps),
      },
      surfaceRevision: win.surfaceRevision,
      createdAt: win.createdAt,
      updatedAt: win.updatedAt,
    };
  }

  _selectNextFocusWindow(excludeWindowId = null) {
    let best = null;
    for (const win of this._windows.values()) {
      if (win.windowId === excludeWindowId) continue;
      if (win.state === 'minimized') continue;
      if (!best || win.zIndex > best.zIndex) {
        best = win;
      }
    }
    if (this._focusedWindowId && this._focusedWindowId !== excludeWindowId) {
      const prev = this._windows.get(this._focusedWindowId);
      if (prev) prev.focused = false;
    }
    if (best) {
      best.focused = true;
      this._focusedWindowId = best.windowId;
    } else {
      this._focusedWindowId = null;
    }
    return this._focusedWindowId;
  }

  _deliverToProcess(pid, windowId, rawEvent) {
    let pcb;
    try {
      pcb = this._processManager.get(pid);
    } catch (err) {
      const msg = safeErrorMessage(err);
      this._safeLog('warn', 'compositor', `ProcessManager.get(${pid}) failed: ${msg}`);
      return { delivered: false, windowId, pid, error: msg };
    }
    if (!pcb || pcb.state === 'ZOMBIE' || pcb.state === 'TERMINATED') {
      return { delivered: false, windowId, pid, reason: 'process_not_alive' };
    }

    const safeEvent = cloneJsonSafe(rawEvent);
    const payload = {
      ...(safeEvent && typeof safeEvent === 'object' && !Array.isArray(safeEvent) ? safeEvent : {}),
      windowId,
      pid,
      ts: new Date().toISOString(),
    };

    let execCtx;
    let deliverFn;
    try {
      execCtx = pcb.executionContext;
      deliverFn = execCtx?.deliverEvent;
    } catch (err) {
      const msg = safeErrorMessage(err);
      this._safeLog('warn', 'compositor', `Unreadable executionContext for PID ${pid}: ${msg}`);
      this._emit('compositor:input_error', { windowId, pid, error: msg, eventType: payload.type });
      return { delivered: false, windowId, pid, error: msg };
    }

    if (typeof deliverFn !== 'function') {
      this._emit('compositor:input', { windowId, pid, event: payload, delivered: false, reason: 'no_handler' });
      return { delivered: false, windowId, pid, reason: 'no_handler' };
    }

    let ret;
    try {
      ret = deliverFn.call(execCtx, payload);
    } catch (err) {
      const msg = safeErrorMessage(err);
      this._safeLog('warn', 'compositor', `Sync deliverEvent error in PID ${pid}: ${msg}`);
      this._emit('compositor:input_error', { windowId, pid, error: msg, eventType: payload.type });
      return { delivered: false, windowId, pid, error: msg };
    }

    // Fault-isolate native Promises, cross-realm Promises, and hostile thenables
    if (ret !== null && ret !== undefined && (typeof ret === 'object' || typeof ret === 'function')) {
      const onAsyncErr = (err) => {
        const msg = safeErrorMessage(err);
        this._safeLog('warn', 'compositor', `Async deliverEvent error in PID ${pid}: ${msg}`);
        this._emit('compositor:input_error', { windowId, pid, error: msg, eventType: payload.type });
      };
      let handledNative = false;
      try {
        if (types.isPromise(ret)) {
          Promise.prototype.then.call(ret, undefined, onAsyncErr);
          handledNative = true;
        }
      } catch {
        // Fall through to guarded thenable check.
      }
      if (!handledNative) {
        try {
          const thenFn = ret.then;
          if (typeof thenFn === 'function') {
            thenFn.call(ret, undefined, onAsyncErr);
          }
        } catch (err) {
          onAsyncErr(err);
        }
      }
    }

    // Wake UI-blocked threads on the owning process
    try {
      if (pcb.state === 'BLOCKED' && typeof this._processManager.wake === 'function') {
        let wokeAny = false;
        if (pcb.threads instanceof Map) {
          for (const tcb of pcb.threads.values()) {
            if (
              tcb.state === 'BLOCKED' &&
              (!tcb.waitReason || (typeof tcb.waitReason === 'string' && UI_WAIT_REASONS.has(tcb.waitReason)))
            ) {
              this._processManager.wake(pid, tcb.tid);
              wokeAny = true;
            }
          }
        }
        if (!wokeAny) {
          this._processManager.wake(pid);
        }
      }
    } catch {
      // Ignore wake errors (including post-construction revoked ProcessManager).
    }

    this._emit('compositor:input', { windowId, pid, event: payload, delivered: true });
    return { delivered: true, windowId, pid };
  }

  // -------------------------------------------------------------------------
  // Public Contract 6 API
  // -------------------------------------------------------------------------

  createWindow(pid, opts = {}) {
    if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 0) {
      throw new ProcessError(`Invalid PID: ${safeDisplayValue(pid)}`, { code: ERROR_CODES.EINVAL, pid: null });
    }
    let pcb;
    try {
      pcb = this._processManager.get(pid);
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError(`Compositor processManager is unreadable: ${safeErrorMessage(err)}`, {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (!pcb) {
      throw new ProcessError(`Process not found: PID ${pid}`, { code: ERROR_CODES.ESRCH, pid });
    }
    // CRITICAL M1 INVARIANT: reject ZOMBIE/TERMINATED BEFORE calling registerWindow!
    if (pcb.state === 'ZOMBIE' || pcb.state === 'TERMINATED') {
      throw new ProcessError(`Cannot create window for exited PID ${pid} (state=${pcb.state})`, {
        code: ERROR_CODES.EINVAL,
        pid,
        state: pcb.state,
      });
    }

    assertReadablePlainObject(opts, 'createWindow options');

    const rawWidth = safeGetProp(opts, 'width', 'createWindow options');
    const rawHeight = safeGetProp(opts, 'height', 'createWindow options');
    const rawX = safeGetProp(opts, 'x', 'createWindow options');
    const rawY = safeGetProp(opts, 'y', 'createWindow options');
    const rawState = safeGetProp(opts, 'state', 'createWindow options');
    const rawPlatform = safeGetProp(opts, 'platform', 'createWindow options');
    const rawChromeStyle = safeGetProp(opts, 'chromeStyle', 'createWindow options');
    const rawMenuBar = safeGetProp(opts, 'menuBar', 'createWindow options');
    const rawDrawOps = safeGetProp(opts, 'drawOps', 'createWindow options');
    const rawTitle = safeGetProp(opts, 'title', 'createWindow options');
    const rawAppId = safeGetProp(opts, 'appId', 'createWindow options');
    const rawIcon = safeGetProp(opts, 'icon', 'createWindow options');
    const rawUiTree = safeGetProp(opts, 'uiTree', 'createWindow options');
    const rawFocus = safeGetProp(opts, 'focus', 'createWindow options');
    const rawWindowId = safeGetProp(opts, 'windowId', 'createWindow options');

    const width = rawWidth ?? 640;
    const height = rawHeight ?? 480;
    if (typeof width !== 'number' || !Number.isFinite(width) || width < 1) {
      throw new OmniOSError(`Invalid window width: ${safeDisplayValue(width)}`, { code: ERROR_CODES.EINVAL });
    }
    if (typeof height !== 'number' || !Number.isFinite(height) || height < 1) {
      throw new OmniOSError(`Invalid window height: ${safeDisplayValue(height)}`, { code: ERROR_CODES.EINVAL });
    }

    const cascadeIndex = (this._nextWindowSeq - 1) % 10;
    const x = rawX ?? 60 + cascadeIndex * 28;
    const y = rawY ?? 48 + cascadeIndex * 24;
    if (typeof x !== 'number' || !Number.isFinite(x)) {
      throw new OmniOSError(`Invalid window x: ${safeDisplayValue(x)}`, { code: ERROR_CODES.EINVAL });
    }
    if (typeof y !== 'number' || !Number.isFinite(y)) {
      throw new OmniOSError(`Invalid window y: ${safeDisplayValue(y)}`, { code: ERROR_CODES.EINVAL });
    }

    const state = rawState ?? 'normal';
    if (typeof state !== 'string' || !WINDOW_STATE_SET.has(state)) {
      throw new OmniOSError(`Invalid window state: ${safeDisplayValue(state)}`, {
        code: ERROR_CODES.EINVAL,
        details: { state: safeDisplayValue(state), allowed: WINDOW_STATES },
      });
    }

    const trimmedRawPlatform =
      typeof rawPlatform === 'string' && rawPlatform.length <= 256 ? rawPlatform.trim() : '';
    const platform = trimmedRawPlatform
      ? trimmedRawPlatform.toLowerCase()
      : (pcb.platform ?? 'universal');

    const chromeStyle = rawChromeStyle ?? defaultChromeForPlatform(platform);
    if (typeof chromeStyle !== 'string' || !CHROME_STYLE_SET.has(chromeStyle)) {
      throw new OmniOSError(`Invalid chromeStyle: ${safeDisplayValue(chromeStyle)}`, {
        code: ERROR_CODES.EINVAL,
        details: { chromeStyle: safeDisplayValue(chromeStyle), allowed: CHROME_STYLES },
      });
    }

    let remainingWindowBytes = MAX_SURFACE_BYTES;
    let menuBar = null;
    let menuBarBytes = 0;
    if (rawMenuBar !== undefined && rawMenuBar !== null) {
      if (!safeIsArray(rawMenuBar)) {
        throw new OmniOSError('Window menuBar must be an Array or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
      const menuRes = cloneJsonSafeWithCount(rawMenuBar, MAX_SURFACE_DRAW_OPS_NODES, remainingWindowBytes);
      if (menuRes.exceeded) {
        throw new QuotaExceededError(
          menuRes.bytesExceeded
            ? `Window menuBar exceeds maximum byte budget (${MAX_SURFACE_BYTES} bytes)`
            : `Window menuBar exceeds maximum node budget (${MAX_SURFACE_DRAW_OPS_NODES})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: menuRes.bytesExceeded ? 'menuBarBytes' : 'menuBarNodes',
            limit: menuRes.bytesExceeded ? MAX_SURFACE_BYTES : MAX_SURFACE_DRAW_OPS_NODES,
            actual: menuRes.bytesExceeded ? MAX_SURFACE_BYTES - remainingWindowBytes + menuRes.bytes : menuRes.nodes,
            pid,
          }
        );
      }
      menuBar = menuRes.value;
      menuBarBytes = menuRes.bytes;
      remainingWindowBytes = Math.max(0, remainingWindowBytes - menuBarBytes);
      if (!Array.isArray(menuBar)) {
        throw new OmniOSError('Window menuBar must be a readable Array or null', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }

    let drawOps = [];
    let drawOpsNodeCount = 0;
    let drawOpsBytes = 0;
    if (rawDrawOps !== undefined && rawDrawOps !== null) {
      if (!safeIsArray(rawDrawOps)) {
        throw new OmniOSError('Window drawOps must be an Array', {
          code: ERROR_CODES.EINVAL,
        });
      }
      let drawOpsLen;
      try {
        drawOpsLen = rawDrawOps.length;
      } catch {
        throw new OmniOSError('Unreadable window drawOps length', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (
        typeof drawOpsLen !== 'number' ||
        !Number.isSafeInteger(drawOpsLen) ||
        drawOpsLen < 0 ||
        drawOpsLen > 0xffffffff
      ) {
        throw new OmniOSError('Invalid window drawOps length', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (drawOpsLen > this._maxDrawOps) {
        throw new QuotaExceededError(`drawOps count (${drawOpsLen}) exceeds limit (${this._maxDrawOps})`, {
          code: ERROR_CODES.EQUOTA,
          quotaType: 'drawOps',
          limit: this._maxDrawOps,
          actual: drawOpsLen,
          pid,
        });
      }
      const drawOpsRes = cloneJsonSafeWithCount(rawDrawOps, MAX_SURFACE_DRAW_OPS_NODES, remainingWindowBytes);
      if (drawOpsRes.exceeded) {
        throw new QuotaExceededError(
          drawOpsRes.bytesExceeded
            ? `drawOps exceeds maximum surface byte budget (${MAX_SURFACE_BYTES} bytes)`
            : `drawOps exceeds maximum surface node budget (${MAX_SURFACE_DRAW_OPS_NODES})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: drawOpsRes.bytesExceeded ? 'drawOpsBytes' : 'drawOpsNodes',
            limit: drawOpsRes.bytesExceeded ? MAX_SURFACE_BYTES : MAX_SURFACE_DRAW_OPS_NODES,
            actual: drawOpsRes.bytesExceeded ? MAX_SURFACE_BYTES - remainingWindowBytes + drawOpsRes.bytes : drawOpsRes.nodes,
            pid,
          }
        );
      }
      drawOps = drawOpsRes.value;
      drawOpsNodeCount = drawOpsRes.nodes;
      drawOpsBytes = drawOpsRes.bytes;
      remainingWindowBytes = Math.max(0, remainingWindowBytes - drawOpsBytes);
      if (!Array.isArray(drawOps)) {
        throw new OmniOSError('Window drawOps must be a readable Array', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (drawOps.length > this._maxDrawOps) {
        throw new QuotaExceededError(`drawOps count (${drawOps.length}) exceeds limit (${this._maxDrawOps})`, {
          code: ERROR_CODES.EQUOTA,
          quotaType: 'drawOps',
          limit: this._maxDrawOps,
          actual: drawOps.length,
          pid,
        });
      }
    }

    // Coerce & clone all window options BEFORE allocating windowId or registering with ProcessManager
    const title = coerceWindowTitle(rawTitle, 'Untitled');
    const trimmedRawAppId =
      typeof rawAppId === 'string' && rawAppId.length <= 4096 ? rawAppId.trim() : '';
    const appId = trimmedRawAppId || (pcb.appId ?? pcb.name ?? `pid-${pid}`);
    let icon = null;
    let iconBytes = 0;
    if (rawIcon !== undefined && rawIcon !== null) {
      const iconByteLimit = Math.min(MAX_ICON_BYTES, remainingWindowBytes);
      const iconRes = cloneJsonSafeWithCount(rawIcon, MAX_ICON_NODES, iconByteLimit);
      if (iconRes.exceeded) {
        throw new QuotaExceededError(
          iconRes.bytesExceeded
            ? `Window icon exceeds maximum byte budget (${iconByteLimit} bytes)`
            : `Window icon exceeds maximum node budget (${MAX_ICON_NODES})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: iconRes.bytesExceeded ? 'iconBytes' : 'iconNodes',
            limit: iconRes.bytesExceeded ? iconByteLimit : MAX_ICON_NODES,
            actual: iconRes.bytesExceeded ? iconRes.bytes : iconRes.nodes,
            pid,
          }
        );
      }
      icon = iconRes.value;
      iconBytes = iconRes.bytes;
      remainingWindowBytes = Math.max(0, remainingWindowBytes - iconBytes);
    }
    let uiTree = null;
    let uiTreeBytes = 0;
    if (rawUiTree !== undefined && rawUiTree !== null) {
      const uiTreeRes = cloneJsonSafeWithCount(rawUiTree, MAX_SURFACE_DRAW_OPS_NODES, remainingWindowBytes);
      if (uiTreeRes.exceeded) {
        throw new QuotaExceededError(
          uiTreeRes.bytesExceeded
            ? `Window uiTree exceeds maximum surface byte budget (${MAX_SURFACE_BYTES} bytes)`
            : `Window uiTree exceeds maximum surface node budget (${MAX_SURFACE_DRAW_OPS_NODES})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: uiTreeRes.bytesExceeded ? 'uiTreeBytes' : 'uiTreeNodes',
            limit: uiTreeRes.bytesExceeded ? MAX_SURFACE_BYTES : MAX_SURFACE_DRAW_OPS_NODES,
            actual: uiTreeRes.bytesExceeded ? MAX_SURFACE_BYTES - remainingWindowBytes + uiTreeRes.bytes : uiTreeRes.nodes,
            pid,
          }
        );
      }
      uiTree = uiTreeRes.value;
      uiTreeBytes = uiTreeRes.bytes;
      remainingWindowBytes = Math.max(0, remainingWindowBytes - uiTreeBytes);
    }
    const shouldFocus = rawFocus !== false && state !== 'minimized';

    let windowId;
    let nextSeqCandidate = this._nextWindowSeq;
    if (rawWindowId !== undefined && rawWindowId !== null) {
      if (typeof rawWindowId !== 'string' || rawWindowId.length === 0 || rawWindowId.length > 4096) {
        throw new OmniOSError('Custom windowId must be a non-empty string', {
          code: ERROR_CODES.EINVAL,
        });
      }
      windowId = rawWindowId.trim();
      if (windowId.length === 0) {
        throw new OmniOSError('Custom windowId must be a non-empty string', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (this._windows.has(windowId)) {
        throw new OmniOSError(`Window ID already exists: ${safeDisplayValue(windowId)}`, {
          code: ERROR_CODES.EEXIST,
          details: { windowId: safeDisplayValue(windowId) },
        });
      }
    } else {
      windowId = `win-${nextSeqCandidate++}`;
      while (this._windows.has(windowId)) {
        windowId = `win-${nextSeqCandidate++}`;
      }
    }

    const normalBounds = {
      x: Math.round(x),
      y: Math.round(y),
      width: Math.round(width),
      height: Math.round(height),
    };
    const initialBounds =
      state !== 'normal' && state !== 'minimized'
        ? computeStateBounds(state, this._viewport, normalBounds)
        : { ...normalBounds };

    const now = new Date().toISOString();
    const nextZIndex = this._zCounter + 1;
    const win = {
      windowId,
      pid,
      appId,
      platform,
      title,
      icon,
      chromeStyle,
      menuBar,
      bounds: initialBounds,
      restoreBounds: { ...normalBounds },
      state,
      zIndex: nextZIndex,
      focused: shouldFocus,
      surface: {
        uiTree,
        drawOps,
      },
      _drawOpsNodeCount: drawOpsNodeCount,
      _drawOpsBytes: drawOpsBytes,
      _menuBarBytes: menuBarBytes,
      _uiTreeBytes: uiTreeBytes,
      _iconBytes: iconBytes,
      surfaceRevision: 1,
      createdAt: now,
      updatedAt: now,
    };

    // Enforce M1 maxWindows quota (`QuotaExceededError(E_WINDOW_QUOTA)`) AFTER all validation & object creation
    try {
      this._processManager.registerWindow(pid, windowId);
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError(`Compositor processManager is unreadable: ${safeErrorMessage(err)}`, {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    try {
      this._nextWindowSeq = nextSeqCandidate;
      this._zCounter = nextZIndex;
      this._hookProcessCleanup(pid);

      if (shouldFocus && this._focusedWindowId) {
        const prev = this._windows.get(this._focusedWindowId);
        if (prev) prev.focused = false;
      }

      this._windows.set(windowId, win);
      let pidSet = this._windowsByPid.get(pid);
      if (!pidSet) {
        pidSet = new Set();
        this._windowsByPid.set(pid, pidSet);
      }
      pidSet.add(windowId);

      if (shouldFocus) {
        this._focusedWindowId = windowId;
      }
    } catch (err) {
      // Roll back PCB window slot if anything fails after registerWindow
      try {
        this._windows.delete(windowId);
        const pidSet = this._windowsByPid.get(pid);
        if (pidSet) {
          pidSet.delete(windowId);
          if (pidSet.size === 0) this._windowsByPid.delete(pid);
        }
        this._processManager.unregisterWindow(pid, windowId);
      } catch {
        // Ignore secondary rollback failure.
      }
      throw err;
    }

    const cloned = this._cloneWindow(win);
    this._emit('compositor:window_created', {
      window: this._cloneWindow(win),
      focusedWindowId: this._focusedWindowId,
      activeMenuBar: this.getActiveMenuBar(),
    });
    return cloned;
  }

  updateSurface(windowId, patch = {}) {
    const win = this._requireWindow(windowId);
    assertReadablePlainObject(patch, 'updateSurface patch');

    const rawMenuBar = safeGetProp(patch, 'menuBar', 'updateSurface patch');
    const rawDrawOps = safeGetProp(patch, 'drawOps', 'updateSurface patch');
    const rawAppendDrawOps = safeGetProp(patch, 'appendDrawOps', 'updateSurface patch');
    const rawTitle = safeGetProp(patch, 'title', 'updateSurface patch');
    const rawIcon = safeGetProp(patch, 'icon', 'updateSurface patch');
    const rawUiTree = safeGetProp(patch, 'uiTree', 'updateSurface patch');

    if (rawMenuBar !== undefined && rawMenuBar !== null && !safeIsArray(rawMenuBar)) {
      throw new OmniOSError('menuBar must be an Array or null', { code: ERROR_CODES.EINVAL });
    }
    if (rawDrawOps !== undefined && !safeIsArray(rawDrawOps)) {
      throw new OmniOSError('drawOps must be an Array', { code: ERROR_CODES.EINVAL });
    }
    if (rawAppendDrawOps !== undefined && !safeIsArray(rawAppendDrawOps)) {
      throw new OmniOSError('appendDrawOps must be an Array', { code: ERROR_CODES.EINVAL });
    }

    // Validate drawOps length & quota strictly BEFORE cloning or mutating state
    let baseLen;
    let appendLen;
    try {
      baseLen = rawDrawOps !== undefined ? rawDrawOps.length : win.surface.drawOps.length;
      appendLen = rawAppendDrawOps !== undefined ? rawAppendDrawOps.length : 0;
    } catch {
      throw new OmniOSError('Unreadable drawOps length', { code: ERROR_CODES.EINVAL });
    }
    if (
      typeof baseLen !== 'number' ||
      !Number.isSafeInteger(baseLen) ||
      baseLen < 0 ||
      baseLen > 0xffffffff
    ) {
      throw new OmniOSError('Invalid drawOps length', { code: ERROR_CODES.EINVAL });
    }
    if (
      typeof appendLen !== 'number' ||
      !Number.isSafeInteger(appendLen) ||
      appendLen < 0 ||
      appendLen > 0xffffffff
    ) {
      throw new OmniOSError('Invalid appendDrawOps length', { code: ERROR_CODES.EINVAL });
    }
    if (baseLen + appendLen > this._maxDrawOps) {
      throw new QuotaExceededError(
        `drawOps count (${baseLen + appendLen}) exceeds limit (${this._maxDrawOps})`,
        {
          code: ERROR_CODES.EQUOTA,
          quotaType: 'drawOps',
          limit: this._maxDrawOps,
          actual: baseLen + appendLen,
          pid: win.pid,
        }
      );
    }

    // Coerce & clone ALL fields into local variables under ONE window-level shared MAX_SURFACE_BYTES
    // budget BEFORE mutating any window state!
    const nextTitle = rawTitle !== undefined ? coerceWindowTitle(rawTitle, '') : undefined;
    let nextIconBytes = rawIcon !== undefined ? 0 : (win._iconBytes ?? 0);
    let nextMenuBarBytes = rawMenuBar !== undefined ? 0 : (win._menuBarBytes ?? 0);
    let nextUiTreeBytes = rawUiTree !== undefined ? 0 : (win._uiTreeBytes ?? 0);
    let nextDrawOpsBytes = rawDrawOps !== undefined ? 0 : (win._drawOpsBytes ?? 0);
    const getRemainingWindowBytes = () =>
      Math.max(0, MAX_SURFACE_BYTES - (nextIconBytes + nextMenuBarBytes + nextUiTreeBytes + nextDrawOpsBytes));

    let nextIcon;
    if (rawIcon !== undefined) {
      if (rawIcon === null) {
        nextIcon = null;
        nextIconBytes = 0;
      } else {
        const iconByteLimit = Math.min(MAX_ICON_BYTES, getRemainingWindowBytes());
        const iconRes = cloneJsonSafeWithCount(rawIcon, MAX_ICON_NODES, iconByteLimit);
        if (iconRes.exceeded) {
          throw new QuotaExceededError(
            iconRes.bytesExceeded
              ? `icon exceeds maximum byte budget (${iconByteLimit} bytes)`
              : `icon exceeds maximum node budget (${MAX_ICON_NODES})`,
            {
              code: ERROR_CODES.EQUOTA,
              quotaType: iconRes.bytesExceeded ? 'iconBytes' : 'iconNodes',
              limit: iconRes.bytesExceeded ? iconByteLimit : MAX_ICON_NODES,
              actual: iconRes.bytesExceeded ? iconRes.bytes : iconRes.nodes,
              pid: win.pid,
            }
          );
        }
        nextIcon = iconRes.value;
        nextIconBytes = iconRes.bytes;
      }
    }
    let nextMenuBar;
    if (rawMenuBar !== undefined) {
      if (rawMenuBar === null) {
        nextMenuBar = null;
        nextMenuBarBytes = 0;
      } else {
        const remBytes = getRemainingWindowBytes();
        const menuRes = cloneJsonSafeWithCount(rawMenuBar, MAX_SURFACE_DRAW_OPS_NODES, remBytes);
        if (menuRes.exceeded) {
          throw new QuotaExceededError(
            menuRes.bytesExceeded
              ? `menuBar exceeds maximum byte budget (${MAX_SURFACE_BYTES} bytes)`
              : `menuBar exceeds maximum node budget (${MAX_SURFACE_DRAW_OPS_NODES})`,
            {
              code: ERROR_CODES.EQUOTA,
              quotaType: menuRes.bytesExceeded ? 'menuBarBytes' : 'menuBarNodes',
              limit: menuRes.bytesExceeded ? MAX_SURFACE_BYTES : MAX_SURFACE_DRAW_OPS_NODES,
              actual: menuRes.bytesExceeded ? MAX_SURFACE_BYTES - remBytes + menuRes.bytes : menuRes.nodes,
              pid: win.pid,
            }
          );
        }
        nextMenuBar = menuRes.value;
        nextMenuBarBytes = menuRes.bytes;
      }
    }
    let nextUiTree;
    if (rawUiTree !== undefined) {
      if (rawUiTree === null) {
        nextUiTree = null;
        nextUiTreeBytes = 0;
      } else {
        const remBytes = getRemainingWindowBytes();
        const uiTreeRes = cloneJsonSafeWithCount(rawUiTree, MAX_SURFACE_DRAW_OPS_NODES, remBytes);
        if (uiTreeRes.exceeded) {
          throw new QuotaExceededError(
            uiTreeRes.bytesExceeded
              ? `uiTree exceeds maximum surface byte budget (${MAX_SURFACE_BYTES} bytes)`
              : `uiTree exceeds maximum surface node budget (${MAX_SURFACE_DRAW_OPS_NODES})`,
            {
              code: ERROR_CODES.EQUOTA,
              quotaType: uiTreeRes.bytesExceeded ? 'uiTreeBytes' : 'uiTreeNodes',
              limit: uiTreeRes.bytesExceeded ? MAX_SURFACE_BYTES : MAX_SURFACE_DRAW_OPS_NODES,
              actual: uiTreeRes.bytesExceeded ? MAX_SURFACE_BYTES - remBytes + uiTreeRes.bytes : uiTreeRes.nodes,
              pid: win.pid,
            }
          );
        }
        nextUiTree = uiTreeRes.value;
        nextUiTreeBytes = uiTreeRes.bytes;
      }
    }

    let nextDrawOps;
    let nextDrawOpsNodeCount = rawDrawOps !== undefined ? 0 : (win._drawOpsNodeCount ?? 0);
    if (rawDrawOps !== undefined) {
      const remBytes = getRemainingWindowBytes();
      const drawOpsRes = cloneJsonSafeWithCount(rawDrawOps, MAX_SURFACE_DRAW_OPS_NODES, remBytes);
      if (drawOpsRes.exceeded) {
        throw new QuotaExceededError(
          drawOpsRes.bytesExceeded
            ? `drawOps exceeds maximum surface byte budget (${MAX_SURFACE_BYTES} bytes)`
            : `drawOps exceeds maximum surface node budget (${MAX_SURFACE_DRAW_OPS_NODES})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: drawOpsRes.bytesExceeded ? 'drawOpsBytes' : 'drawOpsNodes',
            limit: drawOpsRes.bytesExceeded ? MAX_SURFACE_BYTES : MAX_SURFACE_DRAW_OPS_NODES,
            actual: drawOpsRes.bytesExceeded ? MAX_SURFACE_BYTES - remBytes + drawOpsRes.bytes : drawOpsRes.nodes,
            pid: win.pid,
          }
        );
      }
      nextDrawOps = drawOpsRes.value;
      nextDrawOpsNodeCount = drawOpsRes.nodes;
      nextDrawOpsBytes = drawOpsRes.bytes;
    }

    let nextAppended = null;
    if (rawAppendDrawOps !== undefined && appendLen > 0) {
      const remainingNodeBudget = Math.max(0, MAX_SURFACE_DRAW_OPS_NODES - nextDrawOpsNodeCount);
      const remainingByteBudget = getRemainingWindowBytes();
      const appendRes = cloneJsonSafeWithCount(rawAppendDrawOps, remainingNodeBudget, remainingByteBudget);
      const projectedTotalBytes =
        nextIconBytes + nextMenuBarBytes + nextUiTreeBytes + nextDrawOpsBytes + appendRes.bytes;
      if (
        appendRes.exceeded ||
        nextDrawOpsNodeCount + appendRes.nodes > MAX_SURFACE_DRAW_OPS_NODES ||
        projectedTotalBytes > MAX_SURFACE_BYTES
      ) {
        const isBytes = appendRes.bytesExceeded || projectedTotalBytes > MAX_SURFACE_BYTES;
        throw new QuotaExceededError(
          isBytes
            ? `Cumulative drawOps exceeds maximum surface byte budget (${MAX_SURFACE_BYTES} bytes)`
            : `Cumulative drawOps exceeds maximum surface node budget (${MAX_SURFACE_DRAW_OPS_NODES})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: isBytes ? 'drawOpsBytes' : 'drawOpsNodes',
            limit: isBytes ? MAX_SURFACE_BYTES : MAX_SURFACE_DRAW_OPS_NODES,
            actual: isBytes ? projectedTotalBytes : nextDrawOpsNodeCount + appendRes.nodes,
            pid: win.pid,
          }
        );
      }
      nextAppended = appendRes.value;
      nextDrawOpsNodeCount += appendRes.nodes;
      nextDrawOpsBytes += appendRes.bytes;
    }

    // Enforce Array invariants on cloned fields BEFORE mutating ANY state
    if (rawMenuBar !== undefined && rawMenuBar !== null && !Array.isArray(nextMenuBar)) {
      throw new OmniOSError('menuBar must be a readable Array or null', { code: ERROR_CODES.EINVAL });
    }
    if (rawDrawOps !== undefined && !Array.isArray(nextDrawOps)) {
      throw new OmniOSError('drawOps must be a readable Array', { code: ERROR_CODES.EINVAL });
    }
    if (nextAppended !== null && !Array.isArray(nextAppended)) {
      throw new OmniOSError('appendDrawOps must be a readable Array', { code: ERROR_CODES.EINVAL });
    }

    // Re-verify drawOps quota on actual cloned arrays (TOCTOU defense in depth)
    const effectiveBaseLen = nextDrawOps !== undefined ? nextDrawOps.length : win.surface.drawOps.length;
    const effectiveAppendLen = nextAppended !== null ? nextAppended.length : 0;
    if (effectiveBaseLen + effectiveAppendLen > this._maxDrawOps) {
      throw new QuotaExceededError(
        `drawOps count (${effectiveBaseLen + effectiveAppendLen}) exceeds limit (${this._maxDrawOps})`,
        {
          code: ERROR_CODES.EQUOTA,
          quotaType: 'drawOps',
          limit: this._maxDrawOps,
          actual: effectiveBaseLen + effectiveAppendLen,
          pid: win.pid,
        }
      );
    }

    // Atomic commit phase: zero validation or cloning throws possible below
    let metaChanged = false;
    if (nextTitle !== undefined) {
      win.title = nextTitle;
      metaChanged = true;
    }
    if (nextIcon !== undefined) {
      win.icon = nextIcon;
      win._iconBytes = nextIconBytes;
      metaChanged = true;
    }
    if (nextMenuBar !== undefined) {
      win.menuBar = nextMenuBar;
      win._menuBarBytes = nextMenuBarBytes;
      metaChanged = true;
    }
    if (nextUiTree !== undefined) {
      win.surface.uiTree = nextUiTree;
      win._uiTreeBytes = nextUiTreeBytes;
    }
    if (nextDrawOps !== undefined) {
      win.surface.drawOps = nextDrawOps;
    }
    if (nextAppended !== null) {
      for (let i = 0; i < nextAppended.length; i++) {
        win.surface.drawOps.push(nextAppended[i]);
      }
    }
    if (nextDrawOps !== undefined || nextAppended !== null) {
      win._drawOpsNodeCount = nextDrawOpsNodeCount;
      win._drawOpsBytes = nextDrawOpsBytes;
    }

    win.surfaceRevision += 1;
    win.updatedAt = new Date().toISOString();

    const activeMenuBar = this.getActiveMenuBar();
    this._emit('compositor:surface_patch', {
      windowId: win.windowId,
      pid: win.pid,
      surfaceRevision: win.surfaceRevision,
      title: win.title,
      menuBar: win.menuBar === null ? null : cloneJsonSafe(win.menuBar),
      activeMenuBar,
      surface: {
        uiTree: win.surface.uiTree === null ? null : cloneJsonSafe(win.surface.uiTree),
        drawOps: cloneJsonSafe(win.surface.drawOps),
      },
    });

    if (metaChanged) {
      this._emit('compositor:window_updated', {
        window: this._cloneWindow(win),
        reason: 'surface_meta',
        focusedWindowId: this._focusedWindowId,
        activeMenuBar,
      });
    }

    return { windowId: win.windowId, surfaceRevision: win.surfaceRevision };
  }

  moveWindow(windowId, x, y) {
    const win = this._requireWindow(windowId);
    if (typeof x !== 'number' || !Number.isFinite(x) || typeof y !== 'number' || !Number.isFinite(y)) {
      throw new OmniOSError('moveWindow requires finite numeric x and y coordinates', {
        code: ERROR_CODES.EINVAL,
        details: { x, y },
      });
    }
    win.bounds.x = Math.round(x);
    win.bounds.y = Math.round(y);
    if (win.state === 'normal') {
      win.restoreBounds.x = win.bounds.x;
      win.restoreBounds.y = win.bounds.y;
    }
    win.updatedAt = new Date().toISOString();

    const cloned = this._cloneWindow(win);
    this._emit('compositor:window_updated', {
      window: this._cloneWindow(win),
      reason: 'move',
      focusedWindowId: this._focusedWindowId,
      activeMenuBar: this.getActiveMenuBar(),
    });
    return cloned;
  }

  resizeWindow(windowId, width, height) {
    const win = this._requireWindow(windowId);
    if (
      typeof width !== 'number' ||
      !Number.isFinite(width) ||
      width < 1 ||
      typeof height !== 'number' ||
      !Number.isFinite(height) ||
      height < 1
    ) {
      throw new OmniOSError('resizeWindow requires finite width >= 1 and height >= 1', {
        code: ERROR_CODES.EINVAL,
        details: { width, height },
      });
    }
    win.bounds.width = Math.round(width);
    win.bounds.height = Math.round(height);
    if (win.state === 'normal') {
      win.restoreBounds.width = win.bounds.width;
      win.restoreBounds.height = win.bounds.height;
    }
    win.updatedAt = new Date().toISOString();

    const cloned = this._cloneWindow(win);
    this._emit('compositor:window_updated', {
      window: this._cloneWindow(win),
      reason: 'resize',
      focusedWindowId: this._focusedWindowId,
      activeMenuBar: this.getActiveMenuBar(),
    });
    return cloned;
  }

  focusWindow(windowId) {
    const win = this._requireWindow(windowId);
    if (win.state === 'minimized') {
      win.state = 'normal';
      win.bounds = { ...win.restoreBounds };
    }
    if (this._focusedWindowId && this._focusedWindowId !== windowId) {
      const prev = this._windows.get(this._focusedWindowId);
      if (prev) prev.focused = false;
    }
    win.focused = true;
    win.zIndex = ++this._zCounter;
    win.updatedAt = new Date().toISOString();
    this._focusedWindowId = windowId;

    const cloned = this._cloneWindow(win);
    this._emit('compositor:window_updated', {
      window: this._cloneWindow(win),
      reason: 'focus',
      focusedWindowId: this._focusedWindowId,
      activeMenuBar: this.getActiveMenuBar(),
    });
    return cloned;
  }

  setWindowState(windowId, state) {
    const win = this._requireWindow(windowId);
    if (typeof state !== 'string' || !WINDOW_STATE_SET.has(state)) {
      throw new OmniOSError(`Invalid window state: ${safeDisplayValue(state)}`, {
        code: ERROR_CODES.EINVAL,
        details: { state: safeDisplayValue(state), allowed: WINDOW_STATES },
      });
    }

    // Preserve original normal bounds across chained non-normal state transitions
    if (win.state === 'normal' && state !== 'normal') {
      win.restoreBounds = { ...win.bounds };
    }

    win.state = state;
    if (state === 'minimized') {
      if (win.focused || this._focusedWindowId === windowId) {
        win.focused = false;
        this._selectNextFocusWindow(windowId);
      }
    } else {
      const nextBounds = computeStateBounds(state, this._viewport, win.restoreBounds);
      if (nextBounds) {
        win.bounds = nextBounds;
      }
    }
    win.updatedAt = new Date().toISOString();

    const cloned = this._cloneWindow(win);
    this._emit('compositor:window_updated', {
      window: this._cloneWindow(win),
      reason: 'state',
      focusedWindowId: this._focusedWindowId,
      activeMenuBar: this.getActiveMenuBar(),
    });
    return cloned;
  }

  closeWindow(windowId, opts = {}) {
    const win = this._requireWindow(windowId);
    if (opts !== undefined && opts !== null) {
      assertReadablePlainObject(opts, 'closeWindow options');
    }
    const optsObj = opts ?? {};
    const rawNotify = safeGetProp(optsObj, 'notifyProcess', 'closeWindow options');
    const rawReason = safeGetProp(optsObj, 'reason', 'closeWindow options');
    const notifyProcess = rawNotify !== undefined ? Boolean(rawNotify) : true;
    const reason = rawReason !== undefined ? safeDisplayValue(rawReason) : 'closed';

    // Re-entrancy safe: detach from internal maps & PCB BEFORE any callback/event
    this._windows.delete(windowId);
    const pidSet = this._windowsByPid.get(win.pid);
    if (pidSet) {
      pidSet.delete(windowId);
      if (pidSet.size === 0) {
        this._windowsByPid.delete(win.pid);
      }
    }

    try {
      this._processManager.unregisterWindow(win.pid, windowId);
    } catch {
      // Safe no-op if PID already gone.
    }

    if (this._focusedWindowId === windowId) {
      this._focusedWindowId = null;
      this._selectNextFocusWindow();
    }

    if (notifyProcess) {
      this._deliverToProcess(win.pid, windowId, { type: 'window_close', windowId, reason });
    }

    this._emit('compositor:window_closed', {
      windowId,
      pid: win.pid,
      appId: win.appId,
      reason,
      focusedWindowId: this._focusedWindowId,
      activeMenuBar: this.getActiveMenuBar(),
    });

    return { closed: true, windowId, pid: win.pid };
  }

  destroyWindowsForPid(pid, opts = {}) {
    if (opts !== undefined && opts !== null) {
      assertReadablePlainObject(opts, 'destroyWindowsForPid options');
    }
    const optsObj = opts ?? {};
    const rawReason = safeGetProp(optsObj, 'reason', 'destroyWindowsForPid options');
    const reason = rawReason !== undefined ? safeDisplayValue(rawReason) : 'process_exited';

    const pidSet = this._windowsByPid.get(pid);
    if (!pidSet || pidSet.size === 0) {
      this._windowsByPid.delete(pid);
      this._hookedPids.delete(pid);
      return { pid, closedWindowIds: [] };
    }

    const windowIds = Array.from(pidSet);
    const closedWindowIds = [];
    for (const wid of windowIds) {
      if (this._windows.has(wid)) {
        this.closeWindow(wid, { notifyProcess: false, reason });
        closedWindowIds.push(wid);
      }
    }
    this._windowsByPid.delete(pid);
    this._hookedPids.delete(pid);
    return { pid, closedWindowIds };
  }

  dispatchInput(windowId, event) {
    const win = this._requireWindow(windowId);
    assertReadablePlainObject(event, 'dispatchInput event');
    const eventType = safeGetProp(event, 'type', 'dispatchInput event');
    if (
      typeof eventType !== 'string' ||
      eventType.length === 0 ||
      eventType.length > 4096 ||
      eventType.trim().length === 0
    ) {
      throw new OmniOSError('dispatchInput event requires a non-empty string type', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return this._deliverToProcess(win.pid, windowId, event);
  }

  getWindow(windowId) {
    const win = this._windows.get(windowId);
    return win ? this._cloneWindow(win) : null;
  }

  listWindows(opts = {}) {
    if (opts !== undefined && opts !== null) {
      assertReadablePlainObject(opts, 'listWindows options');
    }
    const optsObj = opts ?? {};
    const pid = safeGetProp(optsObj, 'pid', 'listWindows options');
    const appId = safeGetProp(optsObj, 'appId', 'listWindows options');
    const platform = safeGetProp(optsObj, 'platform', 'listWindows options');
    const list = [];
    const targetPlatform = platform !== undefined ? safeDisplayValue(platform).toLowerCase() : undefined;
    for (const win of this._windows.values()) {
      if (pid !== undefined && win.pid !== pid) continue;
      if (appId !== undefined && win.appId !== appId) continue;
      if (targetPlatform !== undefined && win.platform !== targetPlatform) continue;
      list.push(this._cloneWindow(win));
    }
    list.sort((a, b) => a.zIndex - b.zIndex);
    return list;
  }

  getActiveMenuBar() {
    if (this._focusedWindowId) {
      const focused = this._windows.get(this._focusedWindowId);
      if (focused && Array.isArray(focused.menuBar) && focused.menuBar.length > 0) {
        return cloneJsonSafe(focused.menuBar);
      }
    }
    return cloneJsonSafe(this._defaultMenuBar);
  }

  setShellMode(mode) {
    const normalized = normalizeShellMode(mode);
    const changed = normalized !== this._shellMode;
    this._shellMode = normalized;

    if (changed && this._configStore && !this._syncingShellMode) {
      this._syncingShellMode = true;
      try {
        const setFn = this._configStore.system?.set;
        if (
          typeof setFn === 'function' &&
          (typeof this._configStore.isReady !== 'function' || this._configStore.isReady())
        ) {
          setFn.call(this._configStore.system, 'system.shellMode', normalized);
        }
      } catch {
        // Ignore if configStore is not open yet, unavailable, or revoked.
      } finally {
        this._syncingShellMode = false;
      }
    }

    this._emit('compositor:snapshot', this.getSnapshot());
    return { shellMode: this._shellMode };
  }

  setViewport(width, height, insets = {}) {
    this._viewport = normalizeViewport({ width, height, insets });
    for (const win of this._windows.values()) {
      if (REFLOW_STATES.has(win.state)) {
        const nextBounds = computeStateBounds(win.state, this._viewport, win.restoreBounds);
        if (nextBounds) {
          win.bounds = nextBounds;
          win.updatedAt = new Date().toISOString();
        }
      }
    }
    this._emit('compositor:snapshot', this.getSnapshot());
    return cloneJsonSafe(this._viewport);
  }

  getSnapshot() {
    return {
      shellMode: this._shellMode,
      viewport: cloneJsonSafe(this._viewport),
      focusedWindowId: this._focusedWindowId,
      activeMenuBar: this.getActiveMenuBar(),
      windows: this.listWindows(),
    };
  }
}

export function createCompositor(options = {}) {
  return new Compositor(options);
}

export function registerCompositorService(serviceManager, compositor, opts = {}) {
  if (!serviceManager || typeof serviceManager !== 'object') {
    throw new OmniOSError('registerCompositorService requires a ServiceManager object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const registerFn = safeGetProp(serviceManager, 'register', 'registerCompositorService serviceManager');
  if (typeof registerFn !== 'function') {
    throw new OmniOSError('registerCompositorService serviceManager must implement register()', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (!compositor || typeof compositor !== 'object') {
    throw new OmniOSError('registerCompositorService requires a Compositor object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (typeof safeGetProp(compositor, 'start', 'registerCompositorService compositor') !== 'function') {
    throw new OmniOSError('registerCompositorService compositor must implement start()', {
      code: ERROR_CODES.EINVAL,
    });
  }
  safeGetProp(compositor, 'stop', 'registerCompositorService compositor');
  safeGetProp(compositor, 'isRunning', 'registerCompositorService compositor');
  safeGetProp(compositor, 'getSnapshot', 'registerCompositorService compositor');

  if (opts !== undefined && opts !== null) {
    assertReadablePlainObject(opts, 'registerCompositorService options');
  }
  const optsObj = opts ?? {};
  const rawDeps = safeGetProp(optsObj, 'deps', 'registerCompositorService options');
  const rawEssential = safeGetProp(optsObj, 'essential', 'registerCompositorService options');
  const kernel = safeGetProp(optsObj, 'kernel', 'registerCompositorService options') ?? null;

  let deps = [];
  if (rawDeps !== undefined && rawDeps !== null) {
    let isArr = false;
    try {
      isArr = Array.isArray(rawDeps);
    } catch (err) {
      throw new OmniOSError('registerCompositorService deps must be a readable Array', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (!isArr) {
      throw new OmniOSError('registerCompositorService deps must be an Array', {
        code: ERROR_CODES.EINVAL,
      });
    }
    let depsLen;
    try {
      depsLen = rawDeps.length;
    } catch (err) {
      throw new OmniOSError('Unreadable registerCompositorService deps', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (typeof depsLen !== 'number' || !Number.isSafeInteger(depsLen) || depsLen < 0 || depsLen > 1024) {
      throw new OmniOSError('Invalid registerCompositorService deps length', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      deps = [];
      for (let i = 0; i < depsLen; i++) {
        deps.push(rawDeps[i]);
      }
    } catch (err) {
      throw new OmniOSError('Unreadable registerCompositorService deps', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
  }
  const essential = rawEssential !== undefined ? Boolean(rawEssential) : true;
  if (kernel !== null) {
    if (typeof kernel !== 'object') {
      throw new OmniOSError('registerCompositorService kernel must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    safeGetProp(kernel, 'storage', 'registerCompositorService kernel');
  }

  const svc = {
    name: 'compositord',
    deps,
    essential,
    description: 'OmniOS Headless Window Compositor & Input Router Daemon',
    async start() {
      try {
        if (kernel !== null) {
          void kernel.storage;
        }
        compositor.start();
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError(`compositord failed to start: ${safeErrorMessage(err)}`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
    },
    async stop() {
      try {
        compositor.stop();
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError(`compositord failed to stop: ${safeErrorMessage(err)}`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
    },
    async healthCheck() {
      try {
        if (!compositor.isRunning()) {
          return { ok: false, reason: 'compositord is not running' };
        }
        const snap = compositor.getSnapshot();
        return {
          ok: true,
          shellMode: snap.shellMode,
          windowCount: snap.windows.length,
          focusedWindowId: snap.focusedWindowId,
        };
      } catch (err) {
        return { ok: false, reason: safeErrorMessage(err) };
      }
    },
  };
  registerFn.call(serviceManager, svc);
  return svc;
}
