/**
 * OmniOS Package Manager Core (`PackageManager` / `ospm` / `pkgd`)
 * - Runtime registry (`registerRuntime`, `getRuntime`, `listRuntimes`)
 * - Package inspection (`inspect`) with SHA-256 hashing & strict ZIP-slip/bomb defense
 * - Transactional installation (`install`) with SHA-256 verification, sandbox UID allocation,
 *   VFS extraction + rollback on error, permission & intent registration, and SQLite persistence (`pkg` namespace)
 * - Safe process launch (`launch`) with `autoReady: false` + orphan-PCB teardown on runtime failure
 * - Lifecycle control (`list`, `get`, `stop`, `uninstall` with `purgeData`) & App Hub catalog (`registerCatalogEntry`, `getCatalog`)
 * - Lazy `kernel.storage` resolution & idempotent `init()` across `kernel.boot()` / `kernel.recover()`
 */

import crypto from 'node:crypto';
import { types } from 'node:util';
import {
  OmniOSError,
  FormatError,
  SecurityError,
  ProcessError,
  QuotaExceededError,
  ERROR_CODES,
} from '../common/errors.mjs';
import { SqliteStorage } from '../common/storage-sqlite.mjs';
import { PROCESS_STATES } from '../kernel/process.mjs';
import { FormatDetector, PACKAGE_FORMATS } from './format-detector.mjs';
import { readZip } from './zip.mjs';
import { mapNativePermissions } from '../security/permissions.mjs';

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

export const PKG_MIGRATIONS = Object.freeze([
  Object.freeze({
    version: 1,
    name: 'init_pkg_tables',
    sql: `
      CREATE TABLE IF NOT EXISTS installed_packages (
        app_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        platform TEXT NOT NULL,
        format TEXT NOT NULL,
        arch TEXT NOT NULL DEFAULT 'native',
        version TEXT NOT NULL DEFAULT '1.0.0',
        sha256 TEXT NOT NULL,
        size_bytes INTEGER NOT NULL DEFAULT 0,
        uid INTEGER NOT NULL,
        gid INTEGER NOT NULL,
        install_dir TEXT NOT NULL,
        data_dir TEXT NOT NULL,
        entry_point TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'local',
        permissions_json TEXT NOT NULL DEFAULT '[]',
        intents_json TEXT NOT NULL DEFAULT '[]',
        metadata_json TEXT NOT NULL DEFAULT '{}',
        installed_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_installed_packages_platform
        ON installed_packages(platform);

      CREATE TABLE IF NOT EXISTS app_catalog (
        catalog_id TEXT PRIMARY KEY,
        app_id TEXT NOT NULL,
        name TEXT NOT NULL,
        platform TEXT NOT NULL,
        format TEXT NOT NULL DEFAULT 'unknown',
        version TEXT NOT NULL DEFAULT '1.0.0',
        description TEXT NOT NULL DEFAULT '',
        icon TEXT,
        package_path TEXT,
        sha256 TEXT,
        size_bytes INTEGER NOT NULL DEFAULT 0,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_app_catalog_platform
        ON app_catalog(platform);
    `,
  }),
]);

const ZIP_FORMATS = new Set([
  PACKAGE_FORMATS.ANDROID_APK,
  PACKAGE_FORMATS.WINDOWS_MSIX,
  PACKAGE_FORMATS.IOS_IPA,
  PACKAGE_FORMATS.MACOS_APP,
  PACKAGE_FORMATS.UNIVERSAL_UAPP,
]);

const APP_ID_PATTERN = /^[A-Za-z0-9._-]+$/;
const FORBIDDEN_APP_IDS = new Set(['__proto__', 'constructor', 'prototype']);
const ROOT_VFS_CTX = Object.freeze({ uid: 0, gid: 0 });

function safeErrorName(err, fallback = 'LaunchError') {
  if (err === null || err === undefined) return fallback;
  try {
    const name = err.name;
    if (typeof name === 'string' && name.length > 0) return capDisplayString(name);
  } catch {
    // Hostile getter on err.name
  }
  return fallback;
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

function isSecurityError(err) {
  try {
    return err instanceof SecurityError;
  } catch {
    return false;
  }
}

const MAX_CLONE_ARRAY_LEN = 100_000;
const MAX_CLONE_NODES = 250_000;
const MAX_METADATA_NODES = 200_000;
const MAX_CLONE_BYTES = 2 * 1024 * 1024; // 2 MiB
const MAX_METADATA_BYTES = 2 * 1024 * 1024 - 65_536;
const MAX_CLONE_BIGINT_ABS = 1n << 4096n;
const MAX_DISPLAY_LENGTH = 256;
const MAX_INSTALL_GRANTS = 1024;
const MAX_PACKAGE_PATH_CHARS = 4096;
const MAX_APP_ID_LEN = 128;
const PLATFORM_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;

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

function safeJsonStringify(value, label) {
  try {
    const out = JSON.stringify(value);
    if (typeof out !== 'string') {
      throw new OmniOSError(`Unable to serialize ${label}`, {
        code: ERROR_CODES.EINVAL,
      });
    }
    return out;
  } catch (err) {
    if (err instanceof OmniOSError) throw err;
    if (err instanceof RangeError) {
      throw new QuotaExceededError(`${label} exceeds serializable byte limit`, {
        code: ERROR_CODES.EQUOTA,
        quotaType: 'metadataBytes',
        limit: MAX_CLONE_BYTES,
        cause: err,
      });
    }
    throw new OmniOSError(`Unable to serialize ${label}`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
}

function isErrorInstance(err) {
  try {
    return err instanceof Error;
  } catch {
    return false;
  }
}

function isOmniOSError(err) {
  try {
    return err instanceof OmniOSError;
  } catch {
    return false;
  }
}

function wrapDependencyError(err, label) {
  if (isOmniOSError(err)) return err;
  return new OmniOSError(`PackageManager ${label} is unreadable: ${safeErrorMessage(err)}`, {
    code: ERROR_CODES.EINVAL,
    cause: isErrorInstance(err) ? err : undefined,
  });
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

function safeCoerceString(value, fieldName) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return String(value);
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

function safeIsArray(val, label) {
  try {
    return Array.isArray(val);
  } catch (err) {
    throw new OmniOSError(`Unreadable ${label}`, {
      code: ERROR_CODES.EINVAL,
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
}

function defineSafeProp(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
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
        quotaType: res.bytesExceeded ? 'metadataBytes' : 'metadataNodes',
        limit: res.bytesExceeded ? maxBytes : maxNodes,
        actual: res.bytesExceeded ? res.bytes : res.nodes,
      }
    );
  }
  return res.value;
}

function cloneAppRecord(rec) {
  if (!rec) return null;
  return {
    appId: rec.appId,
    name: rec.name,
    platform: rec.platform,
    format: rec.format,
    arch: rec.arch,
    version: rec.version,
    sha256: rec.sha256,
    sizeBytes: rec.sizeBytes,
    uid: rec.uid,
    gid: rec.gid,
    installDir: rec.installDir,
    dataDir: rec.dataDir,
    entryPoint: rec.entryPoint,
    source: rec.source,
    permissions: cloneJsonSafe(rec.permissions ?? []),
    intents: cloneJsonSafe(rec.intents ?? []),
    metadata: cloneJsonSafe(rec.metadata ?? {}),
    installedAt: rec.installedAt,
    updatedAt: rec.updatedAt,
  };
}

function cloneCatalogRecord(entry) {
  if (!entry) return null;
  return {
    catalogId: entry.catalogId,
    appId: entry.appId,
    name: entry.name,
    platform: entry.platform,
    format: entry.format,
    version: entry.version,
    description: entry.description,
    icon: entry.icon ?? null,
    packagePath: entry.packagePath ?? null,
    sha256: entry.sha256 ?? null,
    sizeBytes: entry.sizeBytes,
    metadata: cloneJsonSafe(entry.metadata ?? {}),
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
  };
}

function cloneInspection(insp) {
  if (!insp) return null;
  return {
    format: insp.format,
    platform: insp.platform,
    arch: insp.arch,
    appId: insp.appId,
    name: insp.name,
    version: insp.version,
    entryPoint: insp.entryPoint,
    permissions: cloneJsonSafe(insp.permissions ?? []),
    intents: cloneJsonSafe(insp.intents ?? []),
    sectionsOrClasses: cloneJsonSafe(insp.sectionsOrClasses ?? []),
    importsOrMethods: cloneJsonSafe(insp.importsOrMethods ?? []),
    sha256: insp.sha256,
    sizeBytes: insp.sizeBytes,
    rawMetadata: cloneJsonSafe(insp.rawMetadata ?? {}),
    detection: cloneJsonSafe(insp.detection ?? null),
    runtimeAvailable: Boolean(insp.runtimeAvailable),
  };
}

function cloneLaunchIntent(rawIntent) {
  if (rawIntent === null || rawIntent === undefined) return null;
  if (typeof rawIntent !== 'object') {
    return cloneFieldOrThrow(rawIntent, 'launch intent', MAX_CLONE_NODES, MAX_CLONE_BYTES);
  }
  let isArr = false;
  try {
    isArr = Array.isArray(rawIntent);
  } catch {
    return '[Unreadable]';
  }
  if (isArr || (types.isDate(rawIntent) && !types.isProxy(rawIntent)) || extractGenuineBytes(rawIntent).ok) {
    return cloneFieldOrThrow(rawIntent, 'launch intent', MAX_CLONE_NODES, MAX_CLONE_BYTES);
  }
  if (
    types.isProxy(rawIntent) ||
    types.isBoxedPrimitive(rawIntent) ||
    types.isSharedArrayBuffer?.(rawIntent)
  ) {
    return '[Unreadable]';
  }
  let isSpoofedSpecial = false;
  try {
    isSpoofedSpecial =
      rawIntent instanceof Date ||
      rawIntent instanceof ArrayBuffer ||
      rawIntent instanceof TYPED_ARRAY_CTOR ||
      rawIntent instanceof DataView ||
      (typeof SharedArrayBuffer === 'function' && rawIntent instanceof SharedArrayBuffer) ||
      ArrayBuffer.isView(rawIntent);
  } catch {
    return '[Unreadable]';
  }
  if (isSpoofedSpecial) {
    return '[Unreadable]';
  }
  let keys;
  try {
    keys = Object.keys(rawIntent);
  } catch {
    return '[Unreadable]';
  }
  // Structural top-level clone for intent records (preserves a valid 249,995-node extras field
  // while enforcing shared cumulative node AND byte caps across all top-level keys).
  if (keys.length <= 32 && keys.includes('extras')) {
    const maxTotalNodes = MAX_CLONE_NODES + 256;
    const out = {};
    let remainingNodes = maxTotalNodes;
    let remainingBytes = Math.max(0, MAX_CLONE_BYTES - 16);
    for (const key of keys) {
      if (remainingNodes <= 0) {
        throw new QuotaExceededError(`launch intent exceeds maximum node budget (${maxTotalNodes})`, {
          code: ERROR_CODES.EQUOTA,
          quotaType: 'metadataNodes',
          limit: maxTotalNodes,
          actual: maxTotalNodes,
        });
      }
      remainingNodes -= 1;
      if (key.length + 2 > remainingBytes) {
        throw new QuotaExceededError(`launch intent exceeds maximum byte budget (${MAX_CLONE_BYTES} bytes)`, {
          code: ERROR_CODES.EQUOTA,
          quotaType: 'metadataBytes',
          limit: MAX_CLONE_BYTES,
          actual: MAX_CLONE_BYTES - remainingBytes + key.length + 2,
        });
      }
      remainingBytes -= key.length + 2;
      let prop;
      try {
        prop = rawIntent[key];
      } catch {
        prop = '[Unreadable]';
      }
      const keyNodeCap = Math.min(MAX_CLONE_NODES, remainingNodes);
      const res = cloneJsonSafeWithCount(prop, keyNodeCap, remainingBytes);
      if (res.exceeded) {
        throw new QuotaExceededError(
          res.bytesExceeded
            ? `launch intent.${key} exceeds maximum byte budget (${MAX_CLONE_BYTES} bytes)`
            : `launch intent.${key} exceeds maximum node budget (${maxTotalNodes})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: res.bytesExceeded ? 'metadataBytes' : 'metadataNodes',
            limit: res.bytesExceeded ? MAX_CLONE_BYTES : maxTotalNodes,
            actual: res.bytesExceeded
              ? MAX_CLONE_BYTES - remainingBytes + res.bytes
              : maxTotalNodes - remainingNodes + res.nodes,
          }
        );
      }
      remainingNodes = Math.max(0, remainingNodes - res.nodes);
      remainingBytes = Math.max(0, remainingBytes - res.bytes);
      defineSafeProp(out, key, res.value);
    }
    return out;
  }
  return cloneFieldOrThrow(rawIntent, 'launch intent', MAX_CLONE_NODES, MAX_CLONE_BYTES);
}

function validateSafePlatform(platform, label = 'package platform') {
  if (typeof platform !== 'string') {
    throw new SecurityError(`Invalid or unsafe ${label}: ${safeDisplayValue(platform)}`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      details: { label, platformType: typeof platform },
    });
  }
  if (platform.length > 256) {
    throw new SecurityError(`Invalid or unsafe ${label}: "${safeDisplayValue(platform)}"`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      details: { label, platform: safeDisplayValue(platform) },
    });
  }
  const normalized = platform.trim().toLowerCase();
  if (
    normalized.length === 0 ||
    FORBIDDEN_APP_IDS.has(normalized) ||
    !PLATFORM_PATTERN.test(normalized)
  ) {
    throw new SecurityError(`Invalid or unsafe ${label}: "${safeDisplayValue(platform)}"`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      details: { label, platform: safeDisplayValue(platform) },
    });
  }
  return normalized;
}

function validatePackageDirPath(rawPath, expectedPrefix, label) {
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    throw new SecurityError(`${label} must be a non-empty canonical path under "${expectedPrefix}"`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      details: { label, expectedPrefix, path: safeDisplayValue(rawPath) },
    });
  }
  if (rawPath.length > MAX_PACKAGE_PATH_CHARS) {
    throw new SecurityError(
      `${label} "${safeDisplayValue(rawPath)}" exceeds maximum path length (${MAX_PACKAGE_PATH_CHARS})`,
      {
        code: ERROR_CODES.E_PATH_TRAVERSAL,
        details: { label, expectedPrefix, path: safeDisplayValue(rawPath), length: rawPath.length },
      }
    );
  }
  if (/[\x00-\x1f\x7f\\]/.test(rawPath) || rawPath.trim() !== rawPath || !rawPath.startsWith('/')) {
    throw new SecurityError(`${label} "${safeDisplayValue(rawPath)}" escapes allowed prefix "${expectedPrefix}"`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      details: { label, expectedPrefix, path: safeDisplayValue(rawPath) },
    });
  }
  const withoutTrailing = rawPath.length > 1 && rawPath.endsWith('/') ? rawPath.slice(0, -1) : rawPath;
  if (withoutTrailing === '/' || withoutTrailing.includes('//')) {
    throw new SecurityError(`${label} "${safeDisplayValue(rawPath)}" escapes allowed prefix "${expectedPrefix}"`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      details: { label, expectedPrefix, path: safeDisplayValue(rawPath) },
    });
  }
  const segments = withoutTrailing.slice(1).split('/');
  for (let i = 0; i < segments.length; i += 1) {
    const seg = segments[i];
    if (seg.length === 0 || seg === '.' || seg === '..') {
      throw new SecurityError(
        `${label} "${safeDisplayValue(rawPath)}" escapes allowed prefix "${expectedPrefix}"`,
        {
          code: ERROR_CODES.E_PATH_TRAVERSAL,
          details: { label, expectedPrefix, path: safeDisplayValue(rawPath) },
        }
      );
    }
  }
  const normalized = `/${segments.join('/')}`;
  const requiredPrefix = `${expectedPrefix}/`;
  if (!normalized.startsWith(requiredPrefix) || normalized.length <= requiredPrefix.length) {
    throw new SecurityError(
      `${label} "${safeDisplayValue(rawPath)}" escapes allowed prefix "${expectedPrefix}"`,
      {
        code: ERROR_CODES.E_PATH_TRAVERSAL,
        details: { label, expectedPrefix, path: safeDisplayValue(rawPath) },
      }
    );
  }
  return normalized;
}

function validateOptionalDep(obj, label, probeProps = []) {
  if (obj === null || obj === undefined) return null;
  if (typeof obj !== 'object') {
    throw new OmniOSError(`PackageManager ${label} must be an object or null`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  for (const prop of probeProps) {
    safeGetProp(obj, prop, `PackageManager ${label}`);
  }
  return obj;
}

function safeParseJson(str, fallback) {
  if (typeof str !== 'string' || str.length === 0) return fallback;
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}

function validateSafeAppId(appId) {
  if (typeof appId !== 'string') {
    throw new SecurityError(`Invalid or unsafe appId: ${typeof appId}`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      appId: null,
      details: { appIdType: typeof appId },
    });
  }
  if (FORBIDDEN_APP_IDS.has(appId)) {
    throw new SecurityError(`Forbidden prototype appId: ${appId}`, {
      code: ERROR_CODES.EINVAL,
      appId,
      details: { appId },
    });
  }
  if (
    appId.length === 0 ||
    appId.length > 128 ||
    appId === '.' ||
    appId === '..' ||
    appId.includes('..') ||
    !APP_ID_PATTERN.test(appId)
  ) {
    const safeId = safeDisplayValue(appId);
    throw new SecurityError(`Invalid or unsafe appId: ${safeId}`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      appId: safeId,
      details: { appId: safeId },
    });
  }
  return appId;
}

function stripTrailingSlashes(str) {
  let end = str.length;
  while (end > 0 && str.charCodeAt(end - 1) === 0x2f) {
    end -= 1;
  }
  return end === str.length ? str : str.slice(0, end);
}

function stripEdgeDots(str) {
  let start = 0;
  let end = str.length;
  while (start < end && str.charCodeAt(start) === 0x2e) {
    start += 1;
  }
  while (end > start && str.charCodeAt(end - 1) === 0x2e) {
    end -= 1;
  }
  return start === 0 && end === str.length ? str : str.slice(start, end);
}

function basenamePosix(p) {
  if (typeof p !== 'string') return '';
  let end = p.length;
  while (end > 0) {
    const ch = p.charCodeAt(end - 1);
    if (ch !== 0x2f && ch !== 0x5c) break;
    end -= 1;
  }
  let start = end;
  while (start > 0) {
    const ch = p.charCodeAt(start - 1);
    if (ch === 0x2f || ch === 0x5c) break;
    start -= 1;
  }
  return p.slice(start, end);
}

function dirnamePosix(p) {
  const cleaned = stripTrailingSlashes(p);
  const idx = cleaned.lastIndexOf('/');
  if (idx <= 0) return '/';
  return cleaned.slice(0, idx);
}

function sanitizeFilename(name, fallback = 'package.bin') {
  const base = basenamePosix(name);
  if (!base || base === '.' || base === '..' || !/^[A-Za-z0-9._-]+$/.test(base)) {
    return fallback;
  }
  return base;
}

function deriveDefaultAppId(platform, filenameHint, sha256) {
  const cleanedBase = stripEdgeDots(
    basenamePosix(filenameHint)
      .replace(/\.(apk|exe|dll|msix|appx|msi|bat|cmd|ipa|app\.zip|dmg|pkg|uapp|wasm|zip)$/i, '')
      .replace(/[^A-Za-z0-9._-]+/g, '-')
  ).toLowerCase();
  if (cleanedBase && cleanedBase !== '.' && cleanedBase !== '..' && !cleanedBase.includes('..')) {
    const maxBaseLen = Math.max(0, MAX_APP_ID_LEN - platform.length - 1);
    const base =
      cleanedBase.length > maxBaseLen ? stripEdgeDots(cleanedBase.slice(0, maxBaseLen)) : cleanedBase;
    if (base && base !== '.' && base !== '..' && !base.includes('..')) {
      return `${platform}.${base}`;
    }
  }
  return `${platform}.pkg-${sha256.slice(0, 12)}`;
}

function rowToAppRecord(row) {
  return {
    appId: row.app_id,
    name: row.name,
    platform: row.platform,
    format: row.format,
    arch: row.arch,
    version: row.version,
    sha256: row.sha256,
    sizeBytes: row.size_bytes,
    uid: row.uid,
    gid: row.gid,
    installDir: row.install_dir,
    dataDir: row.data_dir,
    entryPoint: row.entry_point,
    source: row.source,
    permissions: safeParseJson(row.permissions_json, []),
    intents: safeParseJson(row.intents_json, []),
    metadata: safeParseJson(row.metadata_json, {}),
    installedAt: row.installed_at,
    updatedAt: row.updated_at,
  };
}

function rowToCatalogEntry(row) {
  return {
    catalogId: row.catalog_id,
    appId: row.app_id,
    name: row.name,
    platform: row.platform,
    format: row.format,
    version: row.version,
    description: row.description,
    icon: row.icon ?? null,
    packagePath: row.package_path ?? null,
    sha256: row.sha256 ?? null,
    sizeBytes: row.size_bytes,
    metadata: safeParseJson(row.metadata_json, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class PackageManager {
  constructor(opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'PackageManager options');
    const kernel = safeGetProp(optsObj, 'kernel', 'PackageManager options') ?? null;
    const storage = safeGetProp(optsObj, 'storage', 'PackageManager options') ?? null;
    const rawProcessManager = safeGetProp(optsObj, 'processManager', 'PackageManager options');
    const rawScheduler = safeGetProp(optsObj, 'scheduler', 'PackageManager options');
    const rawEventBus = safeGetProp(optsObj, 'eventBus', 'PackageManager options');
    const rawCpuRegistry = safeGetProp(optsObj, 'cpuRegistry', 'PackageManager options');
    const vfs = safeGetProp(optsObj, 'vfs', 'PackageManager options') ?? null;
    const configStore = safeGetProp(optsObj, 'configStore', 'PackageManager options') ?? null;
    const ipc = safeGetProp(optsObj, 'ipc', 'PackageManager options') ?? null;
    const intentRouter = safeGetProp(optsObj, 'intentRouter', 'PackageManager options') ?? null;
    const clipboard = safeGetProp(optsObj, 'clipboard', 'PackageManager options') ?? null;
    const notifications = safeGetProp(optsObj, 'notifications', 'PackageManager options') ?? null;
    const users = safeGetProp(optsObj, 'users', 'PackageManager options') ?? null;
    const permissions = safeGetProp(optsObj, 'permissions', 'PackageManager options') ?? null;
    const compositor = safeGetProp(optsObj, 'compositor', 'PackageManager options') ?? null;
    const rawDetector = safeGetProp(optsObj, 'detector', 'PackageManager options');
    const log = safeGetProp(optsObj, 'log', 'PackageManager options');

    if (kernel !== null && typeof kernel !== 'object') {
      throw new OmniOSError('PackageManager kernel must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    validateOptionalDep(storage, 'storage', ['isOpen']);

    const kernelPm = kernel ? (safeGetProp(kernel, 'processManager', 'PackageManager kernel') ?? null) : null;
    const kernelSched = kernel ? (safeGetProp(kernel, 'scheduler', 'PackageManager kernel') ?? null) : null;
    const kernelBus = kernel ? (safeGetProp(kernel, 'eventBus', 'PackageManager kernel') ?? null) : null;
    const kernelCpu = kernel ? (safeGetProp(kernel, 'cpuRegistry', 'PackageManager kernel') ?? null) : null;
    const kernelStorage = kernel ? (safeGetProp(kernel, 'storage', 'PackageManager kernel') ?? null) : null;

    const processManager = validateOptionalDep(
      rawProcessManager !== undefined ? rawProcessManager : kernelPm,
      'processManager',
      ['spawn', 'get']
    );
    const scheduler = validateOptionalDep(
      rawScheduler !== undefined ? rawScheduler : kernelSched,
      'scheduler',
      ['tick']
    );
    const eventBus = validateOptionalDep(
      rawEventBus !== undefined ? rawEventBus : kernelBus,
      'eventBus',
      ['on', 'emit']
    );
    const cpuRegistry = validateOptionalDep(
      rawCpuRegistry !== undefined ? rawCpuRegistry : kernelCpu,
      'cpuRegistry',
      ['list']
    );
    validateOptionalDep(vfs, 'vfs', ['stat', 'mkdir']);
    validateOptionalDep(configStore, 'configStore', ['system']);
    validateOptionalDep(ipc, 'ipc', ['createChannel']);
    validateOptionalDep(intentRouter, 'intentRouter', ['registerHandlers']);
    validateOptionalDep(clipboard, 'clipboard', ['get']);
    validateOptionalDep(notifications, 'notifications', ['post']);
    validateOptionalDep(users, 'users', ['getUserByAppId', 'allocateAppUid']);
    validateOptionalDep(permissions, 'permissions', ['listGrants', 'setGrant']);
    validateOptionalDep(compositor, 'compositor', ['getSnapshot']);
    const detector =
      rawDetector !== undefined && rawDetector !== null
        ? validateOptionalDep(rawDetector, 'detector', ['detect'])
        : new FormatDetector();

    this._kernel = kernel;
    this._storage = storage;
    this._ownsStorage = false;
    this._processManager = processManager;
    this._scheduler = scheduler;
    this._eventBus = eventBus;
    this._cpuRegistry = cpuRegistry;
    this._vfs = vfs;
    this._configStore = configStore;
    this._ipc = ipc;
    this._intentRouter = intentRouter;
    this._clipboard = clipboard;
    this._notifications = notifications;
    this._users = users;
    this._permissions = permissions;
    this._compositor = compositor;
    this._detector = detector;
    this.formatDetector = detector;
    this._log = typeof log === 'function' ? log : () => {};

    // Prototype-safe maps
    this._runtimes = new Map();
    this._installedCache = new Map();
    this._catalogCache = new Map();
    this._runningPidsByAppId = new Map();

    this._fallbackUidSeq = 10000;
    this._initializedStorage = null;
    this._running = false;
    this._unsubProcessExit = null;

    this._attachListeners();

    const initialStorage = this._storage ?? kernelStorage ?? null;
    if (initialStorage !== null) {
      const initialOpen = Boolean(safeGetProp(initialStorage, 'isOpen', 'PackageManager storage'));
      if (initialOpen) {
        this.init(initialStorage);
      }
    } else if (!this._storage && !this._kernel) {
      this._storage = new SqliteStorage(':memory:');
      this._ownsStorage = true;
      this.init();
    }
  }

  _attachListeners() {
    if (this._eventBus && !this._unsubProcessExit) {
      const onFn = safeGetProp(this._eventBus, 'on', 'PackageManager eventBus');
      if (typeof onFn === 'function') {
        try {
          this._unsubProcessExit = onFn.call(this._eventBus, 'process:exited', (evt) => {
            if (!evt || typeof evt.pid !== 'number') return;
            for (const [appId, pidSet] of this._runningPidsByAppId.entries()) {
              if (pidSet.delete(evt.pid) && pidSet.size === 0) {
                this._runningPidsByAppId.delete(appId);
              }
            }
          });
        } catch (err) {
          throw wrapDependencyError(err, 'eventBus');
        }
      }
    }
  }

  _emit(event, payload) {
    if (!this._eventBus) return;
    try {
      this._eventBus.emit(event, payload);
    } catch {
      // Fault-isolated emit.
    }
  }

  _resolveStorage({ allowMemoryFallback = true } = {}) {
    try {
      if (this._storage && this._storage.isOpen) return this._storage;
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError(`PackageManager storage is unreadable: ${safeErrorMessage(err)}`, {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    try {
      if (this._kernel) {
        const ks = this._kernel.storage;
        if (ks && ks.isOpen) return ks;
      }
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError(`PackageManager kernel storage is unreadable: ${safeErrorMessage(err)}`, {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (allowMemoryFallback && !this._kernel && !this._storage) {
      this._storage = new SqliteStorage(':memory:');
      this._ownsStorage = true;
      return this._storage;
    }
    return null;
  }

  init(storage = null) {
    if (storage !== null && storage !== undefined && typeof storage !== 'object') {
      throw new OmniOSError('PackageManager storage must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const db = storage ?? this._resolveStorage({ allowMemoryFallback: true });
    let dbOpen = false;
    if (db && typeof db === 'object') {
      dbOpen = Boolean(safeGetProp(db, 'isOpen', 'PackageManager storage'));
    }
    if (!db || !dbOpen) {
      throw new OmniOSError('PackageManager requires an open SqliteStorage instance', {
        code: ERROR_CODES.E_STORAGE_CLOSED,
      });
    }
    if (storage && storage !== this._storage) {
      if (this._ownsStorage && this._storage) {
        try {
          if (this._storage.isOpen) {
            this._storage.close();
          }
        } catch {
          // Ignore prior private storage close error.
        }
      }
      this._storage = storage;
      this._ownsStorage = false;
    }

    try {
      db.migrate('pkg', PKG_MIGRATIONS);
    } catch (err) {
      throw wrapDependencyError(err, 'storage');
    }

    // Hydrate caches from SQLite (idempotent across kernel.recover() / DB reopen)
    this._installedCache.clear();
    let pkgRows;
    try {
      pkgRows = db.all('SELECT * FROM installed_packages ORDER BY app_id ASC');
    } catch (err) {
      throw wrapDependencyError(err, 'storage');
    }
    let maxUid = this._fallbackUidSeq - 1;
    for (const row of pkgRows) {
      const rec = rowToAppRecord(row);
      this._installedCache.set(rec.appId, rec);
      if (typeof rec.uid === 'number' && rec.uid > maxUid) {
        maxUid = rec.uid;
      }
      if (this._intentRouter && Array.isArray(rec.intents) && rec.intents.length > 0) {
        try {
          if (typeof this._intentRouter.registerHandlers === 'function') {
            this._intentRouter.registerHandlers(rec.appId, rec.intents, {
              platform: rec.platform,
              label: rec.name,
              replace: true,
            });
          }
        } catch (err) {
          try {
            this._log(
              'warn',
              'pkg',
              `Failed to re-register persisted intents for ${rec.appId}: ${safeErrorMessage(err)}`
            );
          } catch {
            // Isolate logger failures.
          }
        }
      }
    }
    this._fallbackUidSeq = Math.max(10000, maxUid + 1);

    this._catalogCache.clear();
    let catRows;
    try {
      catRows = db.all('SELECT * FROM app_catalog ORDER BY catalog_id ASC');
    } catch (err) {
      throw wrapDependencyError(err, 'storage');
    }
    for (const row of catRows) {
      const entry = rowToCatalogEntry(row);
      this._catalogCache.set(entry.catalogId, entry);
    }

    this._initializedStorage = db;
    this._attachListeners();
    this._running = true;
    return { installedCount: this._installedCache.size, catalogCount: this._catalogCache.size };
  }

  _ensureReady() {
    const db = this._resolveStorage({ allowMemoryFallback: true });
    let isOpen = false;
    try {
      isOpen = Boolean(db && db.isOpen);
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError(`PackageManager storage is unreadable: ${safeErrorMessage(err)}`, {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (!db || !isOpen) {
      throw new OmniOSError('PackageManager storage is not open', {
        code: ERROR_CODES.E_STORAGE_CLOSED,
      });
    }
    if (this._initializedStorage !== db) {
      this.init(db === this._storage ? null : db);
    }
    return db;
  }

  isReady() {
    try {
      const db = this._resolveStorage({ allowMemoryFallback: false });
      return Boolean(db && db.isOpen && this._initializedStorage === db);
    } catch {
      return false;
    }
  }

  isRunning() {
    return this._running && this.isReady();
  }

  stopDaemon() {
    this._running = false;
    // NEVER close shared kernel.storage!
  }

  close() {
    this.dispose();
  }

  dispose() {
    this.stopDaemon();
    if (this._unsubProcessExit) {
      try {
        this._unsubProcessExit();
      } catch {
        // Ignore.
      }
      this._unsubProcessExit = null;
    }
    if (this._ownsStorage && this._storage) {
      try {
        if (this._storage.isOpen) {
          this._storage.close();
        }
      } catch {
        // Ignore storage close error during dispose.
      }
      this._ownsStorage = false;
      this._initializedStorage = null;
    }
  }

  _buildServicesBundle() {
    return {
      kernel: this._kernel,
      processManager: this._processManager,
      scheduler: this._scheduler,
      eventBus: this._eventBus,
      cpuRegistry: this._cpuRegistry,
      vfs: this._vfs,
      configStore: this._configStore,
      ipc: this._ipc,
      intentRouter: this._intentRouter,
      clipboard: this._clipboard,
      notifications: this._notifications,
      users: this._users,
      permissions: this._permissions,
      compositor: this._compositor,
      pkgManager: this,
    };
  }

  // -------------------------------------------------------------------------
  // Runtime Registry
  // -------------------------------------------------------------------------

  registerRuntime(platform, runtime) {
    if (typeof platform !== 'string' || platform.length === 0 || platform.length > 256) {
      throw new OmniOSError('Runtime platform must be a non-empty string', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const key = platform.trim().toLowerCase();
    if (key.length === 0) {
      throw new OmniOSError('Runtime platform must be a non-empty string', {
        code: ERROR_CODES.EINVAL,
      });
    }
    let hasInspect = false;
    let hasCreateCtx = false;
    if (runtime && typeof runtime === 'object') {
      try {
        hasInspect = typeof runtime.inspectPackage === 'function';
        hasCreateCtx = typeof runtime.createExecutionContext === 'function';
      } catch (err) {
        throw new OmniOSError(`Runtime for "${safeDisplayValue(platform)}" is unreadable`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
    }
    if (!hasInspect || !hasCreateCtx) {
      throw new OmniOSError(
        `Runtime for "${safeDisplayValue(platform)}" must implement inspectPackage() and createExecutionContext()`,
        { code: ERROR_CODES.EINVAL }
      );
    }
    this._runtimes.set(key, runtime);
    return { platform: key, registered: true };
  }

  getRuntime(platform) {
    if (typeof platform !== 'string' || platform.length === 0 || platform.length > 256) return null;
    return this._runtimes.get(platform.trim().toLowerCase()) ?? null;
  }

  listRuntimes() {
    return Array.from(this._runtimes.keys());
  }

  // -------------------------------------------------------------------------
  // Byte & VFS Helpers
  // -------------------------------------------------------------------------

  async _resolvePackageBytes(bufferOrVfsPath, filenameHint = '') {
    if (typeof filenameHint === 'string' && filenameHint.length > MAX_PACKAGE_PATH_CHARS) {
      throw new OmniOSError(`Package filenameHint exceeds maximum length (${MAX_PACKAGE_PATH_CHARS})`, {
        code: ERROR_CODES.EINVAL,
        details: { filenameHint: safeDisplayValue(filenameHint), maxLength: MAX_PACKAGE_PATH_CHARS },
      });
    }
    if (typeof bufferOrVfsPath === 'string') {
      if (bufferOrVfsPath.length > MAX_PACKAGE_PATH_CHARS) {
        throw new OmniOSError(`Package path exceeds maximum length (${MAX_PACKAGE_PATH_CHARS})`, {
          code: ERROR_CODES.EINVAL,
          details: { path: safeDisplayValue(bufferOrVfsPath), maxLength: MAX_PACKAGE_PATH_CHARS },
        });
      }
      if (!this._vfs) {
        throw new OmniOSError('Cannot read package from VFS path: VFS is not configured', {
          code: ERROR_CODES.EINVAL,
          details: { path: safeDisplayValue(bufferOrVfsPath) },
        });
      }
      let readFileFn;
      try {
        readFileFn = this._vfs.readFile;
      } catch (err) {
        throw wrapDependencyError(err, 'vfs');
      }
      if (typeof readFileFn !== 'function') {
        throw new OmniOSError('Cannot read package from VFS path: VFS is not configured', {
          code: ERROR_CODES.EINVAL,
          details: { path: bufferOrVfsPath },
        });
      }
      let raw;
      try {
        raw = await readFileFn.call(this._vfs, bufferOrVfsPath, { ...ROOT_VFS_CTX });
      } catch (err) {
        throw wrapDependencyError(err, 'vfs');
      }
      const rawBin = extractGenuineBytes(raw);
      if (rawBin.ok) {
        return {
          bytes: rawBin.bytes.slice(),
          filenameHint: filenameHint || basenamePosix(bufferOrVfsPath),
        };
      }
      if (typeof raw === 'string') {
        const bytes = Buffer.from(raw, 'utf8');
        return {
          bytes: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength).slice(),
          filenameHint: filenameHint || basenamePosix(bufferOrVfsPath),
        };
      }
      throw new FormatError('Unreadable package bytes returned by VFS', {
        code: ERROR_CODES.EINVAL,
      });
    }

    const bin = extractGenuineBytes(bufferOrVfsPath);
    if (bin.detached) {
      throw new FormatError('Unreadable detached package buffer input', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (bin.ok) {
      return { bytes: bin.bytes.slice(), filenameHint };
    }

    throw new FormatError('Package input must be a Uint8Array, Buffer, ArrayBuffer, or VFS path string', {
      code: ERROR_CODES.EINVAL,
    });
  }

  async _vfsExists(targetPath) {
    if (!this._vfs) return false;
    try {
      const fn = this._vfs.lstat ?? this._vfs.stat;
      if (typeof fn !== 'function') {
        throw new OmniOSError('PackageManager vfs must implement lstat() or stat()', {
          code: ERROR_CODES.EINVAL,
        });
      }
      await fn.call(this._vfs, targetPath, { ...ROOT_VFS_CTX });
      return true;
    } catch (err) {
      if (safeErrorCode(err, '') === ERROR_CODES.ENOENT) return false;
      throw wrapDependencyError(err, 'vfs');
    }
  }

  async _assertNoSymlinkInPath(targetPath, label) {
    if (!this._vfs) return;
    let lstatFn;
    try {
      lstatFn = this._vfs.lstat;
    } catch (err) {
      throw wrapDependencyError(err, 'vfs');
    }
    if (typeof lstatFn !== 'function') return;
    if (typeof targetPath !== 'string' || targetPath.length === 0 || targetPath.length > MAX_PACKAGE_PATH_CHARS) {
      throw new SecurityError(`${label} "${safeDisplayValue(targetPath)}" is invalid or exceeds maximum path length`, {
        code: ERROR_CODES.E_PATH_TRAVERSAL,
        details: { label, path: safeDisplayValue(targetPath) },
      });
    }
    const parts = targetPath.slice(1).split('/');
    let cur = '';
    for (let i = 0; i < parts.length; i += 1) {
      cur += `/${parts[i]}`;
      try {
        const st = await lstatFn.call(this._vfs, cur, { ...ROOT_VFS_CTX });
        if (st && st.type === 'symlink') {
          throw new SecurityError(`${label} "${safeDisplayValue(targetPath)}" traverses symlink component "${safeDisplayValue(cur)}"`, {
            code: ERROR_CODES.E_PATH_TRAVERSAL,
            details: { label, path: safeDisplayValue(targetPath), symlink: safeDisplayValue(cur) },
          });
        }
      } catch (err) {
        if (isSecurityError(err)) throw err;
        if (safeErrorCode(err, '') === ERROR_CODES.ENOENT) break;
        throw wrapDependencyError(err, 'vfs');
      }
    }
  }

  async _vfsRemoveRecursive(targetPath) {
    if (!this._vfs) return;
    let st;
    try {
      const statFn = this._vfs.lstat ?? this._vfs.stat;
      if (typeof statFn !== 'function') {
        throw new OmniOSError('PackageManager vfs must implement lstat() or stat()', {
          code: ERROR_CODES.EINVAL,
        });
      }
      st = await statFn.call(this._vfs, targetPath, { ...ROOT_VFS_CTX });
    } catch (err) {
      if (safeErrorCode(err, '') === ERROR_CODES.ENOENT) return;
      throw wrapDependencyError(err, 'vfs');
    }

    try {
      if (st && st.type === 'dir') {
        await this._vfs.rmdir(targetPath, { recursive: true, ...ROOT_VFS_CTX });
      } else {
        await this._vfs.unlink(targetPath, { ...ROOT_VFS_CTX });
      }
    } catch (err) {
      throw wrapDependencyError(err, 'vfs');
    }
  }

  async _vfsExtractPackage({ installDir, dataDir, bytes, format, filenameHint, uid, gid }) {
    if (!this._vfs) {
      return { createdInstallDir: false, createdDataDir: false, backupInstallDir: null };
    }

    // Defense-in-depth symlink verification strictly BEFORE any rename, mkdir, chown, or writeFile
    await this._assertNoSymlinkInPath(installDir, 'package installDir');
    await this._assertNoSymlinkInPath(dataDir, 'package dataDir');

    // Validate and parse ZIP archive BEFORE mutating or touching any existing VFS directory
    const archive = ZIP_FORMATS.has(format) ? readZip(bytes) : null;

    const existedInstall = await this._vfsExists(installDir);
    const existedData = await this._vfsExists(dataDir);
    let backupInstallDir = null;
    let createdFreshInstallDir = false;
    let createdFreshDataDir = false;

    try {
      if (existedInstall) {
        if (typeof this._vfs.rename === 'function') {
          const candidateBackup = `${installDir}.__omnios_bak_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
          await this._vfs.rename(installDir, candidateBackup, { ...ROOT_VFS_CTX });
          backupInstallDir = candidateBackup;
        } else {
          await this._vfsRemoveRecursive(installDir);
        }
      }
      createdFreshInstallDir = true;
      await this._vfs.mkdir(installDir, { recursive: true, mode: 0o755, ...ROOT_VFS_CTX });

      if (!existedData) {
        createdFreshDataDir = true;
        // Ensure parent directory (e.g. /var/appdata/<platform>) is traversable (0o755)
        // before creating the private app sandbox directory (0o700) owned by (uid, gid).
        const dataParent = dirnamePosix(dataDir);
        if (dataParent && dataParent !== '/') {
          await this._vfs.mkdir(dataParent, { recursive: true, mode: 0o755, ...ROOT_VFS_CTX });
        }
        await this._vfs.mkdir(dataDir, { recursive: true, mode: 0o700, ...ROOT_VFS_CTX });
        if (typeof this._vfs.chown === 'function') {
          await this._vfs.chown(dataDir, uid, gid, { ...ROOT_VFS_CTX });
        }
      } else if (typeof this._vfs.chown === 'function') {
        await this._vfs.chown(dataDir, uid, gid, { ...ROOT_VFS_CTX });
      }

      if (archive) {
        for (const meta of archive.entryList) {
          const destPath = `${installDir}/${stripTrailingSlashes(meta.name)}`;
          if (meta.isDirectory) {
            await this._vfs.mkdir(destPath, { recursive: true, mode: 0o755, ...ROOT_VFS_CTX });
          } else {
            const parent = dirnamePosix(destPath);
            if (parent !== installDir) {
              await this._vfs.mkdir(parent, { recursive: true, mode: 0o755, ...ROOT_VFS_CTX });
            }
            const fileBytes = archive.readBytes(meta.name);
            await this._vfs.writeFile(destPath, fileBytes, { mode: 0o644, ...ROOT_VFS_CTX });
          }
        }
      } else {
        const binName = sanitizeFilename(filenameHint, 'binary.bin');
        await this._vfs.writeFile(`${installDir}/${binName}`, bytes, { mode: 0o755, ...ROOT_VFS_CTX });
      }

      await this._vfs.writeFile(`${installDir}/.package.bin`, bytes, { mode: 0o644, ...ROOT_VFS_CTX });
      return { createdInstallDir: true, createdDataDir: createdFreshDataDir, backupInstallDir };
    } catch (err) {
      // Only remove installDir if we actually moved/cleared the prior install and began creating the fresh dir!
      if (createdFreshInstallDir) {
        try {
          await this._vfsRemoveRecursive(installDir);
        } catch {
          // Ignore rollback failure.
        }
      }
      if (backupInstallDir && this._vfs) {
        try {
          if (typeof this._vfs.rename === 'function') {
            await this._vfs.rename(backupInstallDir, installDir, { ...ROOT_VFS_CTX });
          }
        } catch {
          // Ignore backup restore failure.
        }
      }
      if (createdFreshDataDir) {
        try {
          await this._vfsRemoveRecursive(dataDir);
        } catch {
          // Ignore rollback failure.
        }
      }
      throw wrapDependencyError(err, 'vfs');
    }
  }

  _getExistingAppUser(appId) {
    if (!this._users) return null;
    try {
      const getter =
        typeof this._users.getUserByAppId === 'function'
          ? this._users.getUserByAppId
          : typeof this._users.getAppUser === 'function'
            ? this._users.getAppUser
            : null;
      if (!getter) return null;
      return getter.call(this._users, appId) ?? null;
    } catch {
      // Ignore unreadable or unavailable UserManager lookup.
      return null;
    }
  }

  _allocateSandboxUid(appId, platform, dataDir) {
    if (this._users) {
      let allocator;
      try {
        allocator = this._users.allocateAppUid ?? this._users.allocateSandboxUid;
      } catch (err) {
        throw wrapDependencyError(err, 'users');
      }
      if (typeof allocator === 'function') {
        let rec;
        try {
          rec = allocator.call(this._users, appId, {
            platform,
            sandboxRoot: dataDir,
            strictSandbox: platform === 'ios' || platform === 'android',
          });
        } catch (err) {
          throw wrapDependencyError(err, 'users');
        }
        if (rec && typeof rec.uid === 'number') {
          return {
            uid: rec.uid,
            gid: typeof rec.gid === 'number' ? rec.gid : rec.uid,
            allocatedByUsers: true,
            user: rec,
          };
        }
      }
    }
    const uid = this._fallbackUidSeq++;
    return { uid, gid: uid, allocatedByUsers: false, user: null };
  }

  _releaseSandboxUid(appId) {
    if (!this._users) return;
    try {
      const releaser = this._users.releaseAppUid ?? this._users.removeAppUser;
      if (typeof releaser === 'function') {
        releaser.call(this._users, appId);
      }
    } catch {
      // Ignore user cleanup errors.
    }
  }

  // -------------------------------------------------------------------------
  // Public Contract 5 API
  // -------------------------------------------------------------------------

  async inspect(bufferOrVfsPath, filenameHint = '') {
    const { bytes, filenameHint: resolvedHint } = await this._resolvePackageBytes(bufferOrVfsPath, filenameHint);
    const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');

    // strictZip: true ensures ZIP-slip (E_PATH_TRAVERSAL) & ZIP-bomb (E_ARCHIVE_BOMB) throw FormatError!
    let detection;
    try {
      const detectFn = this._detector?.detect;
      if (typeof detectFn !== 'function') {
        throw new OmniOSError('PackageManager detector must implement detect()', {
          code: ERROR_CODES.EINVAL,
        });
      }
      detection = detectFn.call(this._detector, bytes, resolvedHint, { strictZip: true });
    } catch (err) {
      throw wrapDependencyError(err, 'detector');
    }
    if (!detection || typeof detection !== 'object') {
      throw new OmniOSError('PackageManager detector returned an invalid result', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (detection.format === PACKAGE_FORMATS.UNKNOWN) {
      if (bytes.byteLength >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
        throw new FormatError('Invalid or malformed PE executable header', {
          code: ERROR_CODES.E_INVALID_PE,
          format: PACKAGE_FORMATS.WINDOWS_PE,
          details: {
            magicHex: detection.magicHex,
            filenameHint: resolvedHint,
            ...detection.details,
          },
        });
      }
      throw new FormatError('Unrecognized package or binary format', {
        code: 'E_UNKNOWN_FORMAT',
        format: 'unknown',
        details: {
          magicHex: detection.magicHex,
          filenameHint: resolvedHint,
          ...detection.details,
        },
      });
    }

    const runtime = this.getRuntime(detection.platform);
    if (runtime) {
      const rtInspect = await runtime.inspectPackage(bytes, resolvedHint, detection);
      const rtObj = rtInspect && typeof rtInspect === 'object' ? rtInspect : {};
      const rtAppId = safeGetProp(rtObj, 'appId', 'runtime inspectPackage');
      const rtFormat = safeGetProp(rtObj, 'format', 'runtime inspectPackage');
      const rtPlatform = safeGetProp(rtObj, 'platform', 'runtime inspectPackage');
      const rtArch = safeGetProp(rtObj, 'arch', 'runtime inspectPackage');
      const rtName = safeGetProp(rtObj, 'name', 'runtime inspectPackage');
      const rtVersion = safeGetProp(rtObj, 'version', 'runtime inspectPackage');
      const rtEntryPoint = safeGetProp(rtObj, 'entryPoint', 'runtime inspectPackage');
      const rtPermsRaw = safeGetProp(rtObj, 'permissions', 'runtime inspectPackage');
      const rtIntentsRaw = safeGetProp(rtObj, 'intents', 'runtime inspectPackage');
      const rtSections = safeGetProp(rtObj, 'sectionsOrClasses', 'runtime inspectPackage');
      const rtImports = safeGetProp(rtObj, 'importsOrMethods', 'runtime inspectPackage');
      const rtRawMetadata = safeGetProp(rtObj, 'rawMetadata', 'runtime inspectPackage');
      const rtMetadata = safeGetProp(rtObj, 'metadata', 'runtime inspectPackage');

      const appId = rtAppId ?? deriveDefaultAppId(detection.platform, resolvedHint, sha256);
      const maxInspectNodes = MAX_CLONE_NODES + 1024;
      let inspectRemNodes = maxInspectNodes;
      let inspectRemBytes = MAX_CLONE_BYTES;
      const cloneInspectField = (val, fieldName) => {
        const nodeCap = Math.min(MAX_CLONE_NODES, inspectRemNodes);
        const res = cloneJsonSafeWithCount(val, nodeCap, inspectRemBytes);
        if (res.exceeded) {
          throw new QuotaExceededError(
            res.bytesExceeded
              ? `${fieldName} exceeds maximum byte budget (${MAX_CLONE_BYTES} bytes)`
              : `${fieldName} exceeds maximum node budget (${maxInspectNodes})`,
            {
              code: ERROR_CODES.EQUOTA,
              quotaType: res.bytesExceeded ? 'metadataBytes' : 'metadataNodes',
              limit: res.bytesExceeded ? MAX_CLONE_BYTES : maxInspectNodes,
              actual: res.bytesExceeded
                ? MAX_CLONE_BYTES - inspectRemBytes + res.bytes
                : maxInspectNodes - inspectRemNodes + res.nodes,
            }
          );
        }
        inspectRemNodes = Math.max(0, inspectRemNodes - res.nodes);
        inspectRemBytes = Math.max(0, inspectRemBytes - res.bytes);
        return res.value;
      };
      const clonedPerms =
        rtPermsRaw !== undefined && rtPermsRaw !== null && safeIsArray(rtPermsRaw, 'runtime inspectPackage.permissions')
          ? cloneInspectField(rtPermsRaw, 'runtime inspectPackage.permissions')
          : [];
      if (!Array.isArray(clonedPerms)) {
        throw new OmniOSError('Runtime inspectPackage permissions must be a readable Array', {
          code: ERROR_CODES.EINVAL,
        });
      }
      const clonedIntents =
        rtIntentsRaw !== undefined && rtIntentsRaw !== null && safeIsArray(rtIntentsRaw, 'runtime inspectPackage.intents')
          ? cloneInspectField(rtIntentsRaw, 'runtime inspectPackage.intents')
          : [];
      if (!Array.isArray(clonedIntents)) {
        throw new OmniOSError('Runtime inspectPackage intents must be a readable Array', {
          code: ERROR_CODES.EINVAL,
        });
      }
      const clonedSections = cloneInspectField(rtSections ?? [], 'runtime inspectPackage.sectionsOrClasses');
      const clonedImports = cloneInspectField(rtImports ?? [], 'runtime inspectPackage.importsOrMethods');
      const clonedRawMeta = cloneInspectField(rtRawMetadata ?? rtMetadata ?? {}, 'runtime inspectPackage.rawMetadata');

      return cloneInspection({
        format: rtFormat ?? detection.format,
        platform: rtPlatform ?? detection.platform,
        arch: rtArch ?? detection.details?.arch ?? 'native',
        appId,
        name: rtName ?? appId,
        version: rtVersion ?? '1.0.0',
        entryPoint: rtEntryPoint ?? '',
        permissions: clonedPerms,
        intents: clonedIntents,
        sectionsOrClasses: clonedSections,
        importsOrMethods: clonedImports,
        sha256,
        sizeBytes: bytes.byteLength,
        rawMetadata: clonedRawMeta,
        detection,
        runtimeAvailable: true,
      });
    }

    const fallbackAppId = deriveDefaultAppId(detection.platform, resolvedHint, sha256);
    return cloneInspection({
      format: detection.format,
      platform: detection.platform,
      arch: detection.details?.arch ?? 'native',
      appId: fallbackAppId,
      name: fallbackAppId,
      version: '1.0.0',
      entryPoint: '',
      permissions: [],
      intents: [],
      sectionsOrClasses: [],
      importsOrMethods: [],
      sha256,
      sizeBytes: bytes.byteLength,
      rawMetadata: {},
      detection,
      runtimeAvailable: false,
    });
  }

  async install(bufferOrVfsPath, opts = {}) {
    const db = this._ensureReady();
    const optsObj = normalizeReadableOptions(opts, 'install options');
    const rawFilenameHint = safeGetProp(optsObj, 'filenameHint', 'install options');
    const rawGrantAll = safeGetProp(optsObj, 'grantAll', 'install options');
    const grants = safeGetProp(optsObj, 'grants', 'install options') ?? null;
    const rawSource = safeGetProp(optsObj, 'source', 'install options');
    const expectedSha256 = safeGetProp(optsObj, 'expectedSha256', 'install options') ?? null;
    const overwrite = Boolean(safeGetProp(optsObj, 'overwrite', 'install options'));
    const upgrade = Boolean(safeGetProp(optsObj, 'upgrade', 'install options'));

    const filenameHint = rawFilenameHint !== undefined && rawFilenameHint !== null ? rawFilenameHint : '';
    const grantAll = Boolean(rawGrantAll);
    const source = rawSource !== undefined && rawSource !== null ? rawSource : 'local';

    // Validate & snapshot install grants in O(1) strictly BEFORE package inspection, UID allocation, or VFS/DB mutations.
    const explicitGrants = new Set();
    const safeGrantsMap = new Map();
    if (grants !== null && grants !== undefined) {
      const grantsObj = normalizeReadableOptions(grants, 'install grants');
      if (
        types.isProxy(grantsObj) ||
        types.isBoxedPrimitive(grantsObj) ||
        types.isTypedArray(grantsObj) ||
        types.isArrayBuffer(grantsObj) ||
        types.isDataView(grantsObj) ||
        types.isSharedArrayBuffer?.(grantsObj) ||
        types.isDate(grantsObj)
      ) {
        throw new OmniOSError('install grants must be a plain object', {
          code: ERROR_CODES.EINVAL,
        });
      }
      let grantKeys;
      try {
        grantKeys = Object.keys(grantsObj);
      } catch (gErr) {
        throw new OmniOSError('Unreadable install grants object', {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(gErr) ? gErr : undefined,
        });
      }
      if (grantKeys.length > MAX_INSTALL_GRANTS) {
        throw new OmniOSError(`install grants exceeds maximum capability count (${MAX_INSTALL_GRANTS})`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      for (const cap of grantKeys) {
        const stateVal = safeGetProp(grantsObj, cap, 'install grants');
        explicitGrants.add(cap);
        safeGrantsMap.set(cap, stateVal);
      }
    }

    const { bytes, filenameHint: resolvedHint } = await this._resolvePackageBytes(bufferOrVfsPath, filenameHint);
    const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');

    if (expectedSha256 !== null && expectedSha256 !== undefined) {
      if (typeof expectedSha256 !== 'string' || expectedSha256.length === 0 || expectedSha256.length > 256) {
        throw new OmniOSError('expectedSha256 must be a non-empty hex string', {
          code: ERROR_CODES.EINVAL,
          details: { expectedType: typeof expectedSha256 },
        });
      }
      const normalizedExpected = expectedSha256.trim().toLowerCase();
      if (normalizedExpected.length === 0) {
        throw new OmniOSError('expectedSha256 must be a non-empty hex string', {
          code: ERROR_CODES.EINVAL,
          details: { expectedType: typeof expectedSha256 },
        });
      }
      if (normalizedExpected !== sha256) {
        const safeExpected = safeDisplayValue(normalizedExpected);
        throw new SecurityError(
          `Package SHA-256 verification failed: expected ${safeExpected}, actual ${sha256}`,
          {
            code: 'E_HASH_MISMATCH',
            details: { expected: safeExpected, actual: sha256 },
          }
        );
      }
    }

    const inspection = await this.inspect(bytes, resolvedHint);
    const runtime = this.getRuntime(inspection.platform);
    if (!runtime) {
      const safePlatform = safeDisplayValue(inspection.platform);
      const safeFormat = safeDisplayValue(inspection.format);
      throw new FormatError(`No runtime registered for platform "${safePlatform}"`, {
        code: ERROR_CODES.ENOTSUP,
        format: typeof inspection.format === 'string' ? capDisplayString(inspection.format) : safeFormat,
        details: { platform: safePlatform, format: safeFormat },
      });
    }

    const appId = validateSafeAppId(inspection.appId);
    const inspectedPlatform = validateSafePlatform(inspection.platform, 'package platform');
    const existing = this._installedCache.get(appId) ?? null;
    if (existing && !overwrite && !upgrade) {
      throw new OmniOSError(`Package already installed: ${appId}`, {
        code: ERROR_CODES.EEXIST,
        details: { appId },
      });
    }

    const defaultInstallDir = validatePackageDirPath(
      `/apps/${inspectedPlatform}/${appId}`,
      `/apps/${inspectedPlatform}`,
      'package installDir'
    );
    const defaultDataDir = validatePackageDirPath(
      `/var/appdata/${inspectedPlatform}/${appId}`,
      `/var/appdata/${inspectedPlatform}`,
      'package dataDir'
    );
    // Validate canonical containment & reject symlinks strictly BEFORE UID allocation and VFS extraction!
    await this._assertNoSymlinkInPath(defaultInstallDir, 'package installDir');
    await this._assertNoSymlinkInPath(defaultDataDir, 'package dataDir');

    // Always check UserManager for a pre-existing user BEFORE UID allocation (covers both
    // direct overwrite AND reinstall after uninstall({ purgeData: false })).
    const existingUser = this._getExistingAppUser(appId);
    let prevUserSandbox = null;
    if (existingUser) {
      prevUserSandbox = {
        platform: existingUser.platform ?? existing?.platform ?? inspectedPlatform,
        sandboxRoot: existingUser.sandboxRoot ?? existing?.dataDir ?? defaultDataDir,
        strictSandbox: Boolean(existingUser.strictSandbox),
      };
    } else if (existing && this._users) {
      prevUserSandbox = {
        platform: existing.platform,
        sandboxRoot: existing.dataDir,
        strictSandbox: existing.platform === 'android' || existing.platform === 'ios',
      };
    }

    let uid;
    let gid;
    let allocatedFreshUid = false;
    let allocatedUser = null;
    if (existing) {
      uid = existing.uid;
      gid = existing.gid;
    } else if (existingUser && typeof existingUser.uid === 'number') {
      uid = existingUser.uid;
      gid = typeof existingUser.gid === 'number' ? existingUser.gid : existingUser.uid;
      allocatedFreshUid = false;
    } else {
      const alloc = this._allocateSandboxUid(appId, inspectedPlatform, defaultDataDir);
      uid = alloc.uid;
      gid = alloc.gid;
      allocatedUser = alloc.user ?? null;
      allocatedFreshUid = !existingUser && alloc.allocatedByUsers;
    }

    const prevDbRow = existing
      ? db.get('SELECT * FROM installed_packages WHERE app_id = ?', appId)
      : null;
    // Always snapshot prior grants regardless of whether `existing` is null (preserves
    // grants retained across `uninstall({ purgeData: false })` on failed reinstall).
    let prevGrants = null;
    if (this._permissions) {
      try {
        const listFn = this._permissions.listGrants;
        if (typeof listFn === 'function') {
          const listed = listFn.call(this._permissions, appId);
          if (Array.isArray(listed)) {
            prevGrants = listed.map((g) => ({
              capability: g.capability,
              state: g.state,
              source: g.source ?? 'user',
            }));
          }
        }
      } catch {
        // Ignore inability to snapshot prior grants when permissions broker is unavailable.
        prevGrants = null;
      }
    }

    let extracted = { createdInstallDir: false, createdDataDir: false, backupInstallDir: null };
    let createdCustomDataDir = null;
    let sandboxUpdated = false;
    let dbCommitted = false;
    let cacheUpdated = false;
    let permissionsUpdated = false;
    let intentsUpdated = false;
    try {
      extracted = await this._vfsExtractPackage({
        installDir: defaultInstallDir,
        dataDir: defaultDataDir,
        bytes,
        format: inspection.format,
        filenameHint: resolvedHint,
        uid,
        gid,
      });

      let rtRecord = null;
      if (typeof runtime.installPackage === 'function') {
        rtRecord = await runtime.installPackage(
          { ...inspection, appId, uid, gid, installDir: defaultInstallDir, dataDir: defaultDataDir },
          bytes,
          this._buildServicesBundle()
        );
      }

      const rtObj = rtRecord && typeof rtRecord === 'object' ? rtRecord : {};
      const rtPermsRaw = safeGetProp(rtObj, 'permissions', 'runtime installPackage');
      const rtIntentsRaw = safeGetProp(rtObj, 'intents', 'runtime installPackage');
      const rtMetaRaw = safeGetProp(rtObj, 'metadata', 'runtime installPackage');

      const now = new Date().toISOString();
      const permissionsList =
        rtPermsRaw !== undefined && rtPermsRaw !== null
          ? (safeIsArray(rtPermsRaw, 'package permissions') ? rtPermsRaw : null)
          : (inspection.permissions ?? []);
      if (permissionsList === null) {
        throw new OmniOSError('Package permissions must be a readable Array', {
          code: ERROR_CODES.EINVAL,
          details: { appId },
        });
      }
      const intentsList =
        rtIntentsRaw !== undefined && rtIntentsRaw !== null
          ? (safeIsArray(rtIntentsRaw, 'package intents') ? rtIntentsRaw : null)
          : (inspection.intents ?? []);
      if (intentsList === null) {
        throw new OmniOSError('Package intents must be a readable Array', {
          code: ERROR_CODES.EINVAL,
          details: { appId },
        });
      }

      const clonedPermissions = cloneFieldOrThrow(permissionsList, 'package permissions', MAX_CLONE_NODES);
      if (!Array.isArray(clonedPermissions)) {
        throw new OmniOSError('Package permissions must be a readable Array', {
          code: ERROR_CODES.EINVAL,
          details: { appId },
        });
      }
      const clonedIntents = cloneFieldOrThrow(intentsList, 'package intents', MAX_CLONE_NODES);
      if (!Array.isArray(clonedIntents)) {
        throw new OmniOSError('Package intents must be a readable Array', {
          code: ERROR_CODES.EINVAL,
          details: { appId },
        });
      }

      // Enforce a combined node + byte budget (MAX_METADATA_NODES = 200,000, MAX_METADATA_BYTES)
      // across rawMetadata + runtime installPackage metadata so persisted metadata can NEVER
      // exhaust cloneJsonSafe on read or break launch().
      const metaBudget = {
        remaining: MAX_METADATA_NODES,
        remainingBytes: MAX_METADATA_BYTES,
        exceeded: false,
        bytesExceeded: false,
      };
      const clonedBaseMeta = cloneJsonSafe(inspection.rawMetadata ?? {}, new Set(), 0, metaBudget);
      const clonedRtMeta =
        !metaBudget.exceeded && rtMetaRaw !== undefined && rtMetaRaw !== null
          ? cloneJsonSafe(rtMetaRaw, new Set(), 0, metaBudget)
          : {};
      if (metaBudget.exceeded) {
        throw new QuotaExceededError(
          metaBudget.bytesExceeded
            ? `Package metadata exceeds maximum combined byte budget (${MAX_METADATA_BYTES} bytes)`
            : `Package metadata exceeds maximum combined node budget (${MAX_METADATA_NODES})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: metaBudget.bytesExceeded ? 'metadataBytes' : 'metadataNodes',
            limit: metaBudget.bytesExceeded ? MAX_METADATA_BYTES : MAX_METADATA_NODES,
            actual: metaBudget.bytesExceeded
              ? MAX_METADATA_BYTES - metaBudget.remainingBytes
              : MAX_METADATA_NODES - metaBudget.remaining,
            details: { appId },
          }
        );
      }
      const mergedMeta = {};
      if (clonedBaseMeta && typeof clonedBaseMeta === 'object' && !Array.isArray(clonedBaseMeta)) {
        for (const k of Object.keys(clonedBaseMeta)) {
          defineSafeProp(mergedMeta, k, clonedBaseMeta[k]);
        }
      }
      if (clonedRtMeta && typeof clonedRtMeta === 'object' && !Array.isArray(clonedRtMeta)) {
        for (const k of Object.keys(clonedRtMeta)) {
          defineSafeProp(mergedMeta, k, clonedRtMeta[k]);
        }
      }
      const mergedKeyCount = Object.keys(mergedMeta).length;
      if (mergedKeyCount > MAX_CLONE_ARRAY_LEN) {
        throw new QuotaExceededError(
          `Package metadata exceeds maximum top-level key count (${MAX_CLONE_ARRAY_LEN})`,
          {
            code: ERROR_CODES.EQUOTA,
            quotaType: 'metadataKeys',
            limit: MAX_CLONE_ARRAY_LEN,
            actual: mergedKeyCount,
            details: { appId },
          }
        );
      }

      const resolvedPlatform = validateSafePlatform(
        safeCoerceString(safeGetProp(rtObj, 'platform', 'runtime installPackage') ?? inspectedPlatform, 'package platform'),
        'package platform'
      );
      const rawInstallDir = safeCoerceString(
        safeGetProp(rtObj, 'installDir', 'runtime installPackage') ?? defaultInstallDir,
        'package installDir'
      );
      const rawDataDir = safeCoerceString(
        safeGetProp(rtObj, 'dataDir', 'runtime installPackage') ?? defaultDataDir,
        'package dataDir'
      );
      // Enforce strict canonical containment strictly BEFORE any mkdir, chown(ROOT_VFS_CTX),
      // updateAppSandbox, or SQLite persistence!
      const safeInstallDir = validatePackageDirPath(
        rawInstallDir,
        `/apps/${resolvedPlatform}`,
        'package installDir'
      );
      const safeDataDir = validatePackageDirPath(
        rawDataDir,
        `/var/appdata/${resolvedPlatform}`,
        'package dataDir'
      );
      await this._assertNoSymlinkInPath(safeInstallDir, 'package installDir');
      await this._assertNoSymlinkInPath(safeDataDir, 'package dataDir');

      const record = {
        appId,
        name: safeCoerceString(safeGetProp(rtObj, 'name', 'runtime installPackage') ?? inspection.name ?? appId, 'package name'),
        platform: resolvedPlatform,
        format: safeCoerceString(safeGetProp(rtObj, 'format', 'runtime installPackage') ?? inspection.format, 'package format'),
        arch: safeCoerceString(safeGetProp(rtObj, 'arch', 'runtime installPackage') ?? inspection.arch ?? 'native', 'package arch'),
        version: safeCoerceString(safeGetProp(rtObj, 'version', 'runtime installPackage') ?? inspection.version ?? '1.0.0', 'package version'),
        sha256,
        sizeBytes: bytes.byteLength,
        uid,
        gid,
        installDir: safeInstallDir,
        dataDir: safeDataDir,
        entryPoint: safeCoerceString(safeGetProp(rtObj, 'entryPoint', 'runtime installPackage') ?? inspection.entryPoint ?? '', 'package entryPoint'),
        source: safeCoerceString(source ?? 'local', 'package source'),
        permissions: clonedPermissions,
        intents: clonedIntents,
        metadata: mergedMeta,
        installedAt: existing ? existing.installedAt : now,
        updatedAt: now,
      };

      // If runtime returned a custom dataDir, ensure it exists with traversable parents & app ownership
      if (this._vfs && record.dataDir && record.dataDir !== defaultDataDir) {
        try {
          const customExists = await this._vfsExists(record.dataDir);
          if (!customExists) {
            createdCustomDataDir = record.dataDir;
            const parent = dirnamePosix(record.dataDir);
            if (parent && parent !== '/') {
              await this._vfs.mkdir(parent, { recursive: true, mode: 0o755, ...ROOT_VFS_CTX });
            }
            await this._vfs.mkdir(record.dataDir, { recursive: true, mode: 0o700, ...ROOT_VFS_CTX });
          }
          if (typeof this._vfs.chown === 'function') {
            await this._vfs.chown(record.dataDir, uid, gid, { ...ROOT_VFS_CTX });
          }
        } catch (vfsErr) {
          throw wrapDependencyError(vfsErr, 'vfs');
        }
      }

      // Sync UserManager sandboxRoot, platform & strictSandbox whenever they differ from the
      // resolved package record (covers fresh custom UUID dataDir, direct overwrite, and
      // cross-platform reinstall after uninstall({ purgeData: false })).
      const targetStrictSandbox = record.platform === 'android' || record.platform === 'ios';
      const currentUser = this._getExistingAppUser(appId) ?? allocatedUser ?? prevUserSandbox;
      if (
        this._users &&
        currentUser &&
        (currentUser.platform !== record.platform ||
          currentUser.sandboxRoot !== record.dataDir ||
          Boolean(currentUser.strictSandbox) !== targetStrictSandbox)
      ) {
        try {
          const updateFn = this._users.updateAppSandbox;
          if (typeof updateFn === 'function') {
            updateFn.call(this._users, appId, {
              platform: record.platform,
              sandboxRoot: record.dataDir,
              strictSandbox: targetStrictSandbox,
            });
            sandboxUpdated = true;
          }
        } catch (userErr) {
          throw wrapDependencyError(userErr, 'users');
        }
      }

      const permissionsJson = safeJsonStringify(record.permissions, 'package permissions');
      const intentsJson = safeJsonStringify(record.intents, 'package intents');
      const metadataJson = safeJsonStringify(record.metadata, 'package metadata');

      // Persist atomically in SQLite (strictly synchronous callback!)
      try {
        db.transaction(() => {
          db.run(
            `INSERT INTO installed_packages (
              app_id, name, platform, format, arch, version, sha256, size_bytes,
              uid, gid, install_dir, data_dir, entry_point, source,
              permissions_json, intents_json, metadata_json, installed_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(app_id) DO UPDATE SET
              name = excluded.name,
              platform = excluded.platform,
              format = excluded.format,
              arch = excluded.arch,
              version = excluded.version,
              sha256 = excluded.sha256,
              size_bytes = excluded.size_bytes,
              uid = excluded.uid,
              gid = excluded.gid,
              install_dir = excluded.install_dir,
              data_dir = excluded.data_dir,
              entry_point = excluded.entry_point,
              source = excluded.source,
              permissions_json = excluded.permissions_json,
              intents_json = excluded.intents_json,
              metadata_json = excluded.metadata_json,
              updated_at = excluded.updated_at`,
            record.appId,
            record.name,
            record.platform,
            record.format,
            record.arch,
            record.version,
            record.sha256,
            record.sizeBytes,
            record.uid,
            record.gid,
            record.installDir,
            record.dataDir,
            record.entryPoint,
            record.source,
            permissionsJson,
            intentsJson,
            metadataJson,
            record.installedAt,
            record.updatedAt
          );
        });
      } catch (dbErr) {
        throw wrapDependencyError(dbErr, 'storage');
      }
      dbCommitted = true;

      this._installedCache.set(appId, record);
      cacheUpdated = true;

      // Register permissions on PermissionBroker if injected
      if (this._permissions) {
        let setGrantFn;
        let mapPermsFn;
        let mapPermFn;
        try {
          setGrantFn = this._permissions.setGrant;
          mapPermsFn = this._permissions.mapNativePermissions;
          mapPermFn = this._permissions.mapNativePermission;
        } catch (permErr) {
          throw wrapDependencyError(permErr, 'permissions');
        }
        if (typeof setGrantFn === 'function') {
          const capabilities = new Set();
          const unmappedCandidates = new Set();
          const rawPerms = [];
          for (const p of record.permissions) {
            if (typeof p === 'string') {
              const trimmed = p.trim();
              if (trimmed.length > 0) rawPerms.push(trimmed);
            }
          }

          if (rawPerms.length > 0) {
            if (typeof mapPermsFn === 'function') {
              let res;
              try {
                res = mapPermsFn.call(this._permissions, rawPerms, record.platform);
              } catch (permErr) {
                throw wrapDependencyError(permErr, 'permissions');
              }
              if (Array.isArray(res?.capabilities)) {
                for (const cap of res.capabilities) capabilities.add(cap);
              }
              if (Array.isArray(res?.unmapped)) {
                for (const unmapped of res.unmapped) {
                  capabilities.add(unmapped);
                  unmappedCandidates.add(unmapped);
                }
              }
            } else if (typeof mapPermFn === 'function') {
              for (const rawPerm of rawPerms) {
                let mapped;
                try {
                  mapped = mapPermFn.call(this._permissions, rawPerm, record.platform);
                } catch (permErr) {
                  throw wrapDependencyError(permErr, 'permissions');
                }
                if (typeof mapped === 'string' && mapped) {
                  capabilities.add(mapped);
                } else if (Array.isArray(mapped)) {
                  for (const cap of mapped) if (typeof cap === 'string' && cap) capabilities.add(cap);
                } else if (mapped && typeof mapped.capability === 'string') {
                  capabilities.add(mapped.capability);
                } else {
                  capabilities.add(rawPerm);
                  unmappedCandidates.add(rawPerm);
                }
              }
            } else {
              const res = mapNativePermissions(rawPerms, record.platform);
              for (const cap of res.capabilities) capabilities.add(cap);
              for (const unmapped of res.unmapped) {
                capabilities.add(unmapped);
                unmappedCandidates.add(unmapped);
              }
            }
          }
          for (const cap of explicitGrants) {
            capabilities.add(cap);
          }
          if (grantAll) {
            for (const cap of [
              'fs.read.user',
              'fs.write.user',
              'clipboard.read',
              'clipboard.write',
              'notifications.post',
              'ui.window',
            ]) {
              capabilities.add(cap);
            }
          }
          for (const cap of capabilities) {
            let state = 'prompt';
            if (grantAll) {
              state = 'allow';
            } else if (safeGrantsMap.has(cap)) {
              state = safeGrantsMap.get(cap);
            }
            try {
              setGrantFn.call(this._permissions, appId, cap, state);
              permissionsUpdated = true;
            } catch (permErr) {
              // Skip unknown unmapped vendor permissions, but propagate real broker/storage errors for rollback!
              const isUnknownUnmapped =
                unmappedCandidates.has(cap) &&
                !explicitGrants.has(cap) &&
                isSecurityError(permErr) &&
                safeErrorCode(permErr, '') === ERROR_CODES.EINVAL &&
                /unknown capability/i.test(safeErrorMessage(permErr));
              if (isUnknownUnmapped) {
                try {
                  this._log(
                    'warn',
                    'pkg',
                    `Skipping unmapped permission "${cap}" for ${appId}: ${safeErrorMessage(permErr)}`
                  );
                } catch {
                  // Isolate logger failures.
                }
              } else {
                throw wrapDependencyError(permErr, 'permissions');
              }
            }
          }
        }
      }

      // Register intents on IntentRouter if injected (and clear stale intents on upgrade when empty)
      if (this._intentRouter) {
        try {
          const regFn = this._intentRouter.registerHandlers;
          if (record.intents.length > 0 && typeof regFn === 'function') {
            intentsUpdated = true;
            regFn.call(this._intentRouter, appId, record.intents, {
              platform: record.platform,
              label: record.name,
              replace: true,
            });
          } else if (existing && record.intents.length === 0) {
            const unreg = this._intentRouter.unregisterApp ?? this._intentRouter.unregisterHandlers;
            if (typeof unreg === 'function') {
              intentsUpdated = true;
              unreg.call(this._intentRouter, appId);
            } else if (typeof regFn === 'function') {
              intentsUpdated = true;
              regFn.call(this._intentRouter, appId, [], {
                platform: record.platform,
                label: record.name,
                replace: true,
              });
            }
          }
        } catch (irErr) {
          throw wrapDependencyError(irErr, 'intentRouter');
        }
      }

      // Install succeeded completely: delete any overwrite backup directory and obsolete cross-platform installDir
      if (extracted.backupInstallDir) {
        try {
          await this._assertNoSymlinkInPath(extracted.backupInstallDir, 'package backup installDir');
          await this._vfsRemoveRecursive(extracted.backupInstallDir);
        } catch {
          // Ignore best-effort cleanup of obsolete backup after committed install.
        }
      }
      if (
        existing &&
        typeof existing.installDir === 'string' &&
        existing.installDir.length > 0 &&
        existing.installDir !== '/' &&
        existing.installDir !== defaultInstallDir &&
        existing.installDir !== record.installDir
      ) {
        try {
          const prevPlatform = validateSafePlatform(existing.platform, 'previous package platform');
          const safePrevInstallDir = validatePackageDirPath(
            existing.installDir,
            `/apps/${prevPlatform}`,
            'previous package installDir'
          );
          await this._assertNoSymlinkInPath(safePrevInstallDir, 'previous package installDir');
          await this._vfsRemoveRecursive(safePrevInstallDir);
        } catch {
          // Ignore best-effort cleanup of obsolete cross-platform installDir after committed install.
        }
      }
      // If a custom dataDir was used (e.g. iOS UUID container) and extraction created an empty
      // defaultDataDir, best-effort remove that unused empty directory (non-recursive rmdir only).
      if (
        this._vfs &&
        extracted.createdDataDir &&
        record.dataDir &&
        record.dataDir !== defaultDataDir
      ) {
        try {
          if (typeof this._vfs.rmdir === 'function') {
            await this._assertNoSymlinkInPath(defaultDataDir, 'package dataDir');
            await this._vfs.rmdir(defaultDataDir, { ...ROOT_VFS_CTX });
          }
        } catch {
          // Ignore if non-empty, symlinked, revoked, or already absent.
        }
      }

      this._emit('pkg:installed', cloneAppRecord(record));
      return cloneAppRecord(record);
    } catch (err) {
      // Atomic rollback across intents, permissions, SQLite, cache, user sandbox, VFS, and sandbox UID
      if (intentsUpdated && this._intentRouter) {
        try {
          if (
            existing &&
            Array.isArray(existing.intents) &&
            existing.intents.length > 0 &&
            typeof this._intentRouter.registerHandlers === 'function'
          ) {
            this._intentRouter.registerHandlers(appId, existing.intents, {
              platform: existing.platform,
              label: existing.name,
              replace: true,
            });
          } else {
            const unreg = this._intentRouter.unregisterApp ?? this._intentRouter.unregisterHandlers;
            if (typeof unreg === 'function') {
              unreg.call(this._intentRouter, appId);
            }
          }
        } catch {
          // Ignore secondary rollback failure.
        }
      }

      if (permissionsUpdated && this._permissions) {
        try {
          const revokeFn = this._permissions.revokeAllGrants ?? this._permissions.clearAppGrants;
          if (typeof revokeFn === 'function') {
            revokeFn.call(this._permissions, appId);
          }
          if (
            Array.isArray(prevGrants) &&
            prevGrants.length > 0 &&
            typeof this._permissions.setGrant === 'function'
          ) {
            for (const g of prevGrants) {
              try {
                this._permissions.setGrant(appId, g.capability, g.state, {
                  source: g.source ?? 'user',
                });
              } catch {
                // Ignore individual grant restore error.
              }
            }
          }
        } catch {
          // Ignore secondary rollback failure.
        }
      }

      if (dbCommitted) {
        try {
          db.transaction(() => {
            if (existing && prevDbRow) {
              db.run(
                `INSERT OR REPLACE INTO installed_packages (
                  app_id, name, platform, format, arch, version, sha256, size_bytes,
                  uid, gid, install_dir, data_dir, entry_point, source,
                  permissions_json, intents_json, metadata_json, installed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                prevDbRow.app_id,
                prevDbRow.name,
                prevDbRow.platform,
                prevDbRow.format,
                prevDbRow.arch,
                prevDbRow.version,
                prevDbRow.sha256,
                prevDbRow.size_bytes,
                prevDbRow.uid,
                prevDbRow.gid,
                prevDbRow.install_dir,
                prevDbRow.data_dir,
                prevDbRow.entry_point,
                prevDbRow.source,
                prevDbRow.permissions_json,
                prevDbRow.intents_json,
                prevDbRow.metadata_json,
                prevDbRow.installed_at,
                prevDbRow.updated_at
              );
            } else {
              db.run('DELETE FROM installed_packages WHERE app_id = ?', appId);
            }
          });
        } catch {
          // Ignore secondary rollback failure.
        }
      }

      if (cacheUpdated) {
        if (existing) {
          this._installedCache.set(appId, existing);
        } else {
          this._installedCache.delete(appId);
        }
      }

      if (createdCustomDataDir) {
        try {
          await this._assertNoSymlinkInPath(createdCustomDataDir, 'package dataDir');
          await this._vfsRemoveRecursive(createdCustomDataDir);
        } catch {
          // Ignore rollback failure.
        }
      }
      if (extracted.createdInstallDir) {
        try {
          await this._assertNoSymlinkInPath(defaultInstallDir, 'package installDir');
          await this._vfsRemoveRecursive(defaultInstallDir);
        } catch {
          // Ignore rollback failure.
        }
        if (extracted.backupInstallDir && this._vfs) {
          try {
            if (typeof this._vfs.rename === 'function') {
              await this._assertNoSymlinkInPath(extracted.backupInstallDir, 'package backup installDir');
              await this._assertNoSymlinkInPath(defaultInstallDir, 'package installDir');
              await this._vfs.rename(extracted.backupInstallDir, defaultInstallDir, { ...ROOT_VFS_CTX });
            }
          } catch {
            // Ignore backup restore failure.
          }
        }
      }
      if (extracted.createdDataDir) {
        try {
          await this._assertNoSymlinkInPath(defaultDataDir, 'package dataDir');
          await this._vfsRemoveRecursive(defaultDataDir);
        } catch {
          // Ignore rollback failure.
        }
      }
      if (allocatedFreshUid) {
        this._releaseSandboxUid(appId);
      } else if (sandboxUpdated && prevUserSandbox && this._users) {
        try {
          if (typeof this._users.updateAppSandbox === 'function') {
            this._users.updateAppSandbox(appId, prevUserSandbox);
          }
        } catch {
          // Ignore secondary sandbox rollback failure.
        }
      }
      throw err;
    }
  }

  list(opts = {}) {
    this._ensureReady();
    const optsObj = normalizeReadableOptions(opts, 'list options');
    const platform = safeGetProp(optsObj, 'platform', 'list options');
    const trimmedFilter = typeof platform === 'string' && platform.length <= 256 ? platform.trim() : '';
    const filterPlatform = trimmedFilter ? trimmedFilter.toLowerCase() : null;
    const out = [];
    for (const rec of this._installedCache.values()) {
      if (filterPlatform && rec.platform.toLowerCase() !== filterPlatform) continue;
      out.push(cloneAppRecord(rec));
    }
    return out;
  }

  get(appId) {
    this._ensureReady();
    if (typeof appId !== 'string') return null;
    const rec = this._installedCache.get(appId);
    return rec ? cloneAppRecord(rec) : null;
  }

  async launch(appId, opts = {}) {
    this._ensureReady();
    const appRecord = this.get(appId);
    if (!appRecord) {
      throw new OmniOSError(`Package not installed: ${safeDisplayValue(appId)}`, {
        code: ERROR_CODES.ENOENT,
        details: { appId: safeDisplayValue(appId) },
      });
    }

    const runtime = this.getRuntime(appRecord.platform);
    if (!runtime) {
      const safePlatform = safeDisplayValue(appRecord.platform);
      const safeFormat = safeDisplayValue(appRecord.format);
      throw new FormatError(`No runtime registered for platform "${safePlatform}"`, {
        code: ERROR_CODES.ENOTSUP,
        format: typeof appRecord.format === 'string' ? capDisplayString(appRecord.format) : safeFormat,
        details: { appId: safeDisplayValue(appId), platform: safePlatform },
      });
    }

    if (!this._processManager) {
      throw new OmniOSError('PackageManager requires ProcessManager to launch apps', {
        code: ERROR_CODES.EINVAL,
      });
    }

    // Validate & sanitize ALL launch options strictly BEFORE spawning the PCB (zero orphan PCBs!)
    const optsObj = normalizeReadableOptions(opts, 'launch options');
    const rawArgs = safeGetProp(optsObj, 'args', 'launch options');
    const rawEnv = safeGetProp(optsObj, 'env', 'launch options');
    const rawIntent = safeGetProp(optsObj, 'intent', 'launch options');
    const rawPriority = safeGetProp(optsObj, 'priority', 'launch options');
    const rawQuotas = safeGetProp(optsObj, 'quotas', 'launch options');
    const rawCwd = safeGetProp(optsObj, 'cwd', 'launch options');

    const safeArgs = [];
    if (rawArgs !== undefined && rawArgs !== null) {
      if (!safeIsArray(rawArgs, 'launch args')) {
        throw new OmniOSError('launch args must be an Array', {
          code: ERROR_CODES.EINVAL,
        });
      }
      let argsLen;
      try {
        argsLen = rawArgs.length;
      } catch (err) {
        throw new OmniOSError('Unreadable launch args length', {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
      if (
        typeof argsLen !== 'number' ||
        !Number.isSafeInteger(argsLen) ||
        argsLen < 0 ||
        argsLen > 0xffffffff ||
        argsLen > 10_000
      ) {
        throw new OmniOSError('Invalid launch args array length', {
          code: ERROR_CODES.EINVAL,
        });
      }
      let totalArgsBytes = 0;
      for (let i = 0; i < argsLen; i++) {
        let elem;
        try {
          elem = rawArgs[i];
        } catch (err) {
          throw new OmniOSError(`Unreadable launch arg at index ${i}`, {
            code: ERROR_CODES.EINVAL,
            cause: isErrorInstance(err) ? err : undefined,
          });
        }
        const argStr = safeCoerceString(elem, `launch args[${i}]`);
        totalArgsBytes += argStr.length + 2;
        if (totalArgsBytes > MAX_CLONE_BYTES) {
          throw new QuotaExceededError(`launch args exceeds maximum byte budget (${MAX_CLONE_BYTES} bytes)`, {
            code: ERROR_CODES.EQUOTA,
            quotaType: 'launchArgsBytes',
            limit: MAX_CLONE_BYTES,
            actual: totalArgsBytes,
          });
        }
        safeArgs.push(argStr);
      }
    }

    let safeEnv = {};
    if (rawEnv !== undefined && rawEnv !== null) {
      const envObj = normalizeReadableOptions(rawEnv, 'launch env');
      const clonedEnv = cloneFieldOrThrow(envObj, 'launch env', MAX_CLONE_NODES);
      if (!clonedEnv || typeof clonedEnv !== 'object' || Array.isArray(clonedEnv)) {
        throw new OmniOSError('launch env must be a readable plain object', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeEnv = clonedEnv;
    }

    let safeCwd = appRecord.dataDir;
    if (rawCwd !== undefined && rawCwd !== null) {
      if (
        typeof rawCwd !== 'string' ||
        rawCwd.length === 0 ||
        rawCwd.length > MAX_PACKAGE_PATH_CHARS ||
        rawCwd.includes('\0') ||
        rawCwd.trim().length === 0
      ) {
        throw new OmniOSError('launch cwd must be a non-empty string without NUL bytes', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeCwd = rawCwd;
    }

    let priority = 0;
    if (rawPriority !== undefined && rawPriority !== null) {
      if (typeof rawPriority !== 'number' || !Number.isFinite(rawPriority)) {
        throw new OmniOSError('launch priority must be a finite number', {
          code: ERROR_CODES.EINVAL,
        });
      }
      priority = rawPriority;
    }

    let safeQuotas = {};
    if (rawQuotas !== undefined && rawQuotas !== null) {
      const quotasObj = normalizeReadableOptions(rawQuotas, 'launch quotas');
      const clonedQuotas = cloneFieldOrThrow(quotasObj, 'launch quotas', MAX_CLONE_NODES);
      if (!clonedQuotas || typeof clonedQuotas !== 'object' || Array.isArray(clonedQuotas)) {
        throw new OmniOSError('launch quotas must be a readable plain object', {
          code: ERROR_CODES.EINVAL,
        });
      }
      safeQuotas = clonedQuotas;
    }

    const safeIntent = rawIntent !== null && rawIntent !== undefined ? cloneLaunchIntent(rawIntent) : null;

    // Spawn in CREATED state (`autoReady: false`) before creating executionContext
    let pcb;
    try {
      const spawnFn = this._processManager.spawn;
      if (typeof spawnFn !== 'function') {
        throw new OmniOSError('PackageManager processManager must implement spawn()', {
          code: ERROR_CODES.EINVAL,
        });
      }
      pcb = spawnFn.call(this._processManager, {
        name: appRecord.name,
        appId: appRecord.appId,
        platform: appRecord.platform,
        arch: appRecord.arch,
        uid: appRecord.uid,
        gid: appRecord.gid,
        cwd: safeCwd,
        env: cloneJsonSafe(safeEnv),
        args: [...safeArgs],
        priority,
        quotas: safeQuotas,
        autoReady: false,
        executionContext: null,
      });
    } catch (err) {
      throw wrapDependencyError(err, 'processManager');
    }
    if (!pcb || typeof pcb !== 'object') {
      throw new OmniOSError('PackageManager processManager.spawn() returned an invalid PCB', {
        code: ERROR_CODES.EINVAL,
      });
    }

    let execCtx;
    try {
      execCtx = await runtime.createExecutionContext(
        pcb,
        cloneAppRecord(appRecord),
        this._buildServicesBundle(),
        {
          args: [...safeArgs],
          env: cloneJsonSafe(safeEnv),
          intent: safeIntent,
        }
      );

      if (!execCtx || typeof execCtx !== 'object' || typeof execCtx.step !== 'function') {
        const safePlatform = safeDisplayValue(appRecord.platform);
        throw new OmniOSError(
          `Runtime "${safePlatform}" returned an invalid IExecutionContext (missing step())`,
          { code: ERROR_CODES.EINVAL, details: { appId: safeDisplayValue(appId), platform: safePlatform } }
        );
      }

      pcb.executionContext = execCtx;
      if (pcb.state === PROCESS_STATES.CREATED) {
        try {
          this._processManager.transitionState(pcb.pid, PROCESS_STATES.READY, {
            reason: 'ospm_launch',
          });
        } catch (pmErr) {
          throw wrapDependencyError(pmErr, 'processManager');
        }
      }
    } catch (err) {
      // Orphan-PCB guard: safely extract fault strings BEFORE exit() so hostile error getters never bypass teardown
      const faultReason = {
        name: safeErrorName(err, 'LaunchError'),
        message: safeErrorMessage(err),
        code: safeErrorCode(err, ERROR_CODES.E_OMNIOS),
      };
      try {
        if (pcb.state !== PROCESS_STATES.ZOMBIE && pcb.state !== PROCESS_STATES.TERMINATED) {
          this._processManager.exit(pcb.pid, 1, { faultReason });
        }
      } catch {
        // Ignore secondary cleanup failure.
      }
      throw err;
    }

    let pidSet = this._runningPidsByAppId.get(appRecord.appId);
    if (!pidSet) {
      pidSet = new Set();
      this._runningPidsByAppId.set(appRecord.appId, pidSet);
    }
    pidSet.add(pcb.pid);

    const launchInfo = {
      pid: pcb.pid,
      appId: appRecord.appId,
      platform: appRecord.platform,
      windowIds: Array.from(pcb.windowIds ?? []),
    };
    this._emit('pkg:launched', launchInfo);
    return launchInfo;
  }

  stop(pidOrAppId, opts = {}) {
    const optsObj = normalizeReadableOptions(opts, 'stop options');
    const rawSignal = safeGetProp(optsObj, 'signal', 'stop options');
    const signal = rawSignal !== undefined ? rawSignal : 'SIGTERM';
    if (typeof signal !== 'string' && !(typeof signal === 'number' && Number.isInteger(signal))) {
      throw new OmniOSError(`Invalid stop signal: ${safeDisplayValue(signal)}`, {
        code: ERROR_CODES.EINVAL,
        details: { signal: safeDisplayValue(signal) },
      });
    }
    if (!this._processManager) {
      throw new OmniOSError('PackageManager requires ProcessManager to stop apps', {
        code: ERROR_CODES.EINVAL,
      });
    }

    const stoppedPids = [];
    if (typeof pidOrAppId === 'number') {
      let pcb;
      try {
        pcb = this._processManager.get(pidOrAppId);
      } catch (err) {
        throw wrapDependencyError(err, 'processManager');
      }
      if (!pcb) {
        throw new ProcessError(`Process not found: PID ${pidOrAppId}`, {
          code: ERROR_CODES.ESRCH,
          pid: pidOrAppId,
        });
      }
      try {
        this._processManager.kill(pidOrAppId, signal);
      } catch (err) {
        throw wrapDependencyError(err, 'processManager');
      }
      stoppedPids.push(pidOrAppId);
      return { stoppedPids };
    }

    if (typeof pidOrAppId === 'string' && pidOrAppId.length > 0 && pidOrAppId.length <= 256) {
      const targetAppId = pidOrAppId.trim();
      if (targetAppId.length > 0) {
        let allPcbs;
        try {
          allPcbs = this._processManager.getAll();
        } catch (err) {
          throw wrapDependencyError(err, 'processManager');
        }
        if (Array.isArray(allPcbs)) {
          for (const pcb of allPcbs) {
            if (
              pcb &&
              pcb.appId === targetAppId &&
              pcb.state !== PROCESS_STATES.ZOMBIE &&
              pcb.state !== PROCESS_STATES.TERMINATED
            ) {
              try {
                this._processManager.kill(pcb.pid, signal);
              } catch (err) {
                throw wrapDependencyError(err, 'processManager');
              }
              stoppedPids.push(pcb.pid);
            }
          }
        }
        if (stoppedPids.length === 0 && !this._installedCache.has(targetAppId)) {
          throw new OmniOSError(`Package not installed: ${targetAppId}`, {
            code: ERROR_CODES.ENOENT,
          });
        }
        return { stoppedPids };
      }
    }

    throw new OmniOSError('stop() requires a PID number or appId string', {
      code: ERROR_CODES.EINVAL,
    });
  }

  async uninstall(appId, opts = {}) {
    const db = this._ensureReady();
    const optsObj = normalizeReadableOptions(opts, 'uninstall options');
    const purgeData = Boolean(safeGetProp(optsObj, 'purgeData', 'uninstall options'));
    const record = this._installedCache.get(appId);
    if (!record) {
      throw new OmniOSError(`Package not installed: ${appId}`, {
        code: ERROR_CODES.ENOENT,
      });
    }

    const shouldPurge = Boolean(purgeData);

    // Defense-in-depth containment checks strictly BEFORE any root VFS recursive deletion
    let safeInstallDir = null;
    let safeDataDir = null;
    if (this._vfs && (record.installDir || (shouldPurge && record.dataDir))) {
      const safePlatform = validateSafePlatform(record.platform, 'package platform');
      if (record.installDir) {
        safeInstallDir = validatePackageDirPath(
          record.installDir,
          `/apps/${safePlatform}`,
          'package installDir'
        );
        await this._assertNoSymlinkInPath(safeInstallDir, 'package installDir');
      }
      if (shouldPurge && record.dataDir) {
        safeDataDir = validatePackageDirPath(
          record.dataDir,
          `/var/appdata/${safePlatform}`,
          'package dataDir'
        );
        await this._assertNoSymlinkInPath(safeDataDir, 'package dataDir');
      }
    }

    let stoppedPids = [];
    if (this._processManager) {
      try {
        const res = this.stop(appId, { signal: 'SIGKILL' });
        stoppedPids = res.stoppedPids;
      } catch (err) {
        try {
          this._log(
            'warn',
            'pkg',
            `Best-effort process stop failed during uninstall of ${appId}: ${safeErrorMessage(err)}`
          );
        } catch {
          // Isolate logger failures.
        }
      }
    }

    // Unregister intents (best-effort so revoked/unavailable intentRouter never leaves ghost state)
    if (this._intentRouter) {
      try {
        const unreg = this._intentRouter.unregisterApp ?? this._intentRouter.unregisterHandlers;
        if (typeof unreg === 'function') {
          unreg.call(this._intentRouter, appId);
        } else if (typeof this._intentRouter.registerHandlers === 'function') {
          this._intentRouter.registerHandlers(appId, []);
        }
      } catch (err) {
        try {
          this._log(
            'warn',
            'pkg',
            `Best-effort intent unregister failed during uninstall of ${appId}: ${safeErrorMessage(err)}`
          );
        } catch {
          // Isolate logger failures.
        }
      }
    }

    // Remove installed files from VFS
    if (this._vfs && safeInstallDir) {
      await this._vfsRemoveRecursive(safeInstallDir);
    }

    if (shouldPurge) {
      if (this._vfs && safeDataDir) {
        await this._vfsRemoveRecursive(safeDataDir);
      }
      if (this._permissions) {
        try {
          const revokeFn = this._permissions.revokeAllGrants ?? this._permissions.clearAppGrants;
          if (typeof revokeFn === 'function') {
            revokeFn.call(this._permissions, appId);
          }
        } catch (err) {
          try {
            this._log(
              'warn',
              'pkg',
              `Best-effort permission revoke failed during uninstall of ${appId}: ${safeErrorMessage(err)}`
            );
          } catch {
            // Isolate logger failures.
          }
        }
      }
      this._releaseSandboxUid(appId);
    }

    db.transaction(() => {
      db.run('DELETE FROM installed_packages WHERE app_id = ?', appId);
    });
    this._installedCache.delete(appId);
    this._runningPidsByAppId.delete(appId);

    const summary = {
      removed: true,
      appId,
      stoppedPids,
      purgedData: shouldPurge,
    };
    this._emit('pkg:uninstalled', summary);
    return summary;
  }

  // -------------------------------------------------------------------------
  // App Hub Catalog
  // -------------------------------------------------------------------------

  registerCatalogEntry(entry) {
    const db = this._ensureReady();
    let isEntryArr = false;
    try {
      isEntryArr = Array.isArray(entry);
    } catch (err) {
      throw new OmniOSError('Catalog entry must be a readable plain object', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (!entry || typeof entry !== 'object' || isEntryArr) {
      throw new OmniOSError('Catalog entry must be a plain object', { code: ERROR_CODES.EINVAL });
    }

    const rawAppId = safeGetProp(entry, 'appId', 'catalog entry');
    const rawName = safeGetProp(entry, 'name', 'catalog entry');
    const rawPlatform = safeGetProp(entry, 'platform', 'catalog entry');
    const rawCatalogId = safeGetProp(entry, 'catalogId', 'catalog entry');
    const rawFormat = safeGetProp(entry, 'format', 'catalog entry');
    const rawVersion = safeGetProp(entry, 'version', 'catalog entry');
    const rawDescription = safeGetProp(entry, 'description', 'catalog entry');
    const rawCategory = safeGetProp(entry, 'category', 'catalog entry');
    const rawIcon = safeGetProp(entry, 'icon', 'catalog entry');
    const rawPackagePath = safeGetProp(entry, 'packagePath', 'catalog entry');
    const rawSha256 = safeGetProp(entry, 'sha256', 'catalog entry');
    const rawSizeBytes = safeGetProp(entry, 'sizeBytes', 'catalog entry');
    const rawMetadata = safeGetProp(entry, 'metadata', 'catalog entry');

    const appId = validateSafeAppId(rawAppId);
    if (typeof rawName !== 'string' || rawName.length === 0 || rawName.length > 4096) {
      throw new OmniOSError('Catalog entry requires a non-empty name', { code: ERROR_CODES.EINVAL });
    }
    const trimmedName = rawName.trim();
    if (trimmedName.length === 0) {
      throw new OmniOSError('Catalog entry requires a non-empty name', { code: ERROR_CODES.EINVAL });
    }
    if (typeof rawPlatform !== 'string' || rawPlatform.length === 0 || rawPlatform.length > 256) {
      throw new OmniOSError('Catalog entry requires a non-empty platform', { code: ERROR_CODES.EINVAL });
    }
    const trimmedPlatform = rawPlatform.trim().toLowerCase();
    if (trimmedPlatform.length === 0) {
      throw new OmniOSError('Catalog entry requires a non-empty platform', { code: ERROR_CODES.EINVAL });
    }

    let catalogId = appId;
    if (rawCatalogId !== undefined && rawCatalogId !== null) {
      const rawCatStr = safeCoerceString(rawCatalogId, 'catalog entry catalogId');
      if (rawCatStr.length > 4096) {
        throw new OmniOSError('Catalog entry catalogId exceeds maximum length (4096)', { code: ERROR_CODES.EINVAL });
      }
      const coercedCatalogId = rawCatStr.trim();
      if (coercedCatalogId.length > 0) catalogId = coercedCatalogId;
    }

    let format = 'unknown';
    if (rawFormat !== undefined && rawFormat !== null) {
      const rawFmtStr = safeCoerceString(rawFormat, 'catalog entry format');
      if (rawFmtStr.length > 256) {
        throw new OmniOSError('Catalog entry format exceeds maximum length (256)', { code: ERROR_CODES.EINVAL });
      }
      const coercedFormat = rawFmtStr.trim();
      if (coercedFormat.length > 0) format = coercedFormat;
    }

    let version = '1.0.0';
    if (rawVersion !== undefined && rawVersion !== null) {
      const rawVerStr = safeCoerceString(rawVersion, 'catalog entry version');
      if (rawVerStr.length > 256) {
        throw new OmniOSError('Catalog entry version exceeds maximum length (256)', { code: ERROR_CODES.EINVAL });
      }
      const coercedVersion = rawVerStr.trim();
      if (coercedVersion.length > 0) version = coercedVersion;
    }

    const description =
      rawDescription !== undefined && rawDescription !== null
        ? safeCoerceString(rawDescription, 'catalog entry description')
        : '';

    // Validate optional category string if supplied (reject Symbol / throwing toString / revoked Proxy)
    if (rawCategory !== undefined && rawCategory !== null) {
      safeCoerceString(rawCategory, 'catalog entry category');
    }

    const icon =
      rawIcon !== undefined && rawIcon !== null ? safeCoerceString(rawIcon, 'catalog entry icon') : null;
    const packagePath =
      rawPackagePath !== undefined && rawPackagePath !== null
        ? safeCoerceString(rawPackagePath, 'catalog entry packagePath')
        : null;
    const sha256 =
      rawSha256 !== undefined && rawSha256 !== null
        ? safeCoerceString(rawSha256, 'catalog entry sha256')
        : null;

    const existing = this._catalogCache.get(catalogId);
    const now = new Date().toISOString();

    const clonedMetadata = cloneFieldOrThrow(rawMetadata ?? {}, 'catalog entry metadata', MAX_CLONE_NODES);

    const record = {
      catalogId,
      appId,
      name: trimmedName,
      platform: trimmedPlatform,
      format,
      version,
      description,
      icon,
      packagePath,
      sha256,
      sizeBytes: Number.isSafeInteger(rawSizeBytes) && rawSizeBytes >= 0 ? rawSizeBytes : 0,
      metadata: clonedMetadata,
      createdAt: existing ? existing.createdAt : now,
      updatedAt: now,
    };

    const catalogMetadataJson = safeJsonStringify(record.metadata, 'catalog entry metadata');
    db.transaction(() => {
      db.run(
        `INSERT INTO app_catalog (
          catalog_id, app_id, name, platform, format, version, description,
          icon, package_path, sha256, size_bytes, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(catalog_id) DO UPDATE SET
          app_id = excluded.app_id,
          name = excluded.name,
          platform = excluded.platform,
          format = excluded.format,
          version = excluded.version,
          description = excluded.description,
          icon = excluded.icon,
          package_path = excluded.package_path,
          sha256 = excluded.sha256,
          size_bytes = excluded.size_bytes,
          metadata_json = excluded.metadata_json,
          updated_at = excluded.updated_at`,
        record.catalogId,
        record.appId,
        record.name,
        record.platform,
        record.format,
        record.version,
        record.description,
        record.icon,
        record.packagePath,
        record.sha256,
        record.sizeBytes,
        catalogMetadataJson,
        record.createdAt,
        record.updatedAt
      );
    });

    this._catalogCache.set(catalogId, record);
    return {
      ...cloneCatalogRecord(record),
      installed: this._installedCache.has(record.appId),
    };
  }

  getCatalog(opts = {}) {
    this._ensureReady();
    const optsObj = normalizeReadableOptions(opts, 'getCatalog options');
    const platform = safeGetProp(optsObj, 'platform', 'getCatalog options');
    const trimmedFilter = typeof platform === 'string' && platform.length <= 256 ? platform.trim() : '';
    const filterPlatform = trimmedFilter ? trimmedFilter.toLowerCase() : null;
    const out = [];
    for (const entry of this._catalogCache.values()) {
      if (filterPlatform && entry.platform !== filterPlatform) continue;
      out.push({
        ...cloneCatalogRecord(entry),
        installed: this._installedCache.has(entry.appId),
      });
    }
    return out;
  }
}

export function createPackageManager(options = {}) {
  return new PackageManager(options);
}

export function registerPackageService(serviceManager, pkgManager, opts = {}) {
  if (!serviceManager || typeof serviceManager !== 'object') {
    throw new OmniOSError('registerPackageService requires a ServiceManager object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const registerFn = safeGetProp(serviceManager, 'register', 'registerPackageService serviceManager');
  if (typeof registerFn !== 'function') {
    throw new OmniOSError('registerPackageService serviceManager must implement register()', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (!pkgManager || typeof pkgManager !== 'object') {
    throw new OmniOSError('registerPackageService requires a PackageManager object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (typeof safeGetProp(pkgManager, 'init', 'registerPackageService pkgManager') !== 'function') {
    throw new OmniOSError('registerPackageService pkgManager must implement init()', {
      code: ERROR_CODES.EINVAL,
    });
  }
  safeGetProp(pkgManager, 'stopDaemon', 'registerPackageService pkgManager');
  safeGetProp(pkgManager, 'isRunning', 'registerPackageService pkgManager');

  const optsObj = normalizeReadableOptions(opts, 'registerPackageService options');
  const rawDeps = safeGetProp(optsObj, 'deps', 'registerPackageService options');
  const rawEssential = safeGetProp(optsObj, 'essential', 'registerPackageService options');
  const kernel = safeGetProp(optsObj, 'kernel', 'registerPackageService options') ?? null;
  const storage = safeGetProp(optsObj, 'storage', 'registerPackageService options') ?? null;

  let deps = [];
  if (rawDeps !== undefined && rawDeps !== null) {
    if (!safeIsArray(rawDeps, 'registerPackageService deps')) {
      throw new OmniOSError('registerPackageService deps must be an Array', {
        code: ERROR_CODES.EINVAL,
      });
    }
    let depsLen;
    try {
      depsLen = rawDeps.length;
    } catch (err) {
      throw new OmniOSError('Unreadable registerPackageService deps', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (typeof depsLen !== 'number' || !Number.isSafeInteger(depsLen) || depsLen < 0 || depsLen > 1024) {
      throw new OmniOSError('Invalid registerPackageService deps length', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      deps = [];
      for (let i = 0; i < depsLen; i++) {
        deps.push(rawDeps[i]);
      }
    } catch (err) {
      throw new OmniOSError('Unreadable registerPackageService deps', {
        code: ERROR_CODES.EINVAL,
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
  }
  const essential = Boolean(rawEssential);
  if (kernel !== null) {
    if (typeof kernel !== 'object') {
      throw new OmniOSError('registerPackageService kernel must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    safeGetProp(kernel, 'storage', 'registerPackageService kernel');
  }
  if (storage !== null) {
    if (typeof storage !== 'object') {
      throw new OmniOSError('registerPackageService storage must be an object or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    safeGetProp(storage, 'isOpen', 'registerPackageService storage');
  }

  const svc = {
    name: 'pkgd',
    deps,
    essential,
    description: 'OmniOS Package Manager (`ospm`) & App Hub Catalog Daemon',
    async start() {
      let resolvedStorage = null;
      try {
        if (storage !== null) {
          resolvedStorage = storage;
        } else if (kernel !== null) {
          resolvedStorage = kernel.storage ?? null;
        }
        pkgManager.init(resolvedStorage);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError(`pkgd failed to start: ${safeErrorMessage(err)}`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
    },
    async stop() {
      try {
        pkgManager.stopDaemon();
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError(`pkgd failed to stop: ${safeErrorMessage(err)}`, {
          code: ERROR_CODES.EINVAL,
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
    },
    async healthCheck() {
      try {
        if (!pkgManager.isRunning()) {
          return { ok: false, reason: 'pkgd is not running or storage closed' };
        }
        return {
          ok: true,
          installedCount: pkgManager.list().length,
          catalogCount: pkgManager.getCatalog().length,
          runtimes: pkgManager.listRuntimes(),
        };
      } catch (err) {
        return { ok: false, reason: safeErrorMessage(err) };
      }
    },
  };
  registerFn.call(serviceManager, svc);
  return svc;
}
