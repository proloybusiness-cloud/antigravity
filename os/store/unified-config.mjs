/**
 * OmniOS Unified Config Store — Windows Registry, Apple Defaults/XML Plist,
 * Android SharedPreferences & Live Atomic 8-Key Cross-Platform Sync (F-021, F-022, F-035)
 * Zero-dependency Node.js 24 ESM module backed by WAL SQLite (`config` namespace).
 */

import { types } from 'node:util';
import { SqliteStorage } from '../common/storage-sqlite.mjs';
import { OmniOSError, FormatError, SecurityError, ERROR_CODES } from '../common/errors.mjs';

function freezeLookup(obj) {
  return Object.freeze(Object.assign(Object.create(null), obj));
}

function defineSafeProp(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

export const REGISTRY_HIVES = freezeLookup({
  HKCR: 'HKCR',
  HKCU: 'HKCU',
  HKLM: 'HKLM',
  HKU: 'HKU',
  HKCC: 'HKCC',
});

export const REGISTRY_HIVE_ALIASES = freezeLookup({
  HKCR: 'HKCR',
  HKEY_CLASSES_ROOT: 'HKCR',
  HKCU: 'HKCU',
  HKEY_CURRENT_USER: 'HKCU',
  HKLM: 'HKLM',
  HKEY_LOCAL_MACHINE: 'HKLM',
  HKU: 'HKU',
  HKEY_USERS: 'HKU',
  HKCC: 'HKCC',
  HKEY_CURRENT_CONFIG: 'HKCC',
});

export const REGISTRY_TYPES = freezeLookup({
  REG_SZ: 'REG_SZ',
  REG_EXPAND_SZ: 'REG_EXPAND_SZ',
  REG_BINARY: 'REG_BINARY',
  REG_DWORD: 'REG_DWORD',
  REG_MULTI_SZ: 'REG_MULTI_SZ',
  REG_QWORD: 'REG_QWORD',
});

const VALID_REG_TYPES = new Set(Object.values(REGISTRY_TYPES));

export const CANONICAL_SHELL_MODES = Object.freeze([
  'unified',
  'windows',
  'macos',
  'ios',
  'android',
]);

const VALID_SHELL_MODES = new Set(CANONICAL_SHELL_MODES);
const VALID_THEMES = new Set(['dark', 'light', 'auto']);

const SYSTEM_REG_KEY_PATH = 'Software\\OmniOS\\System';
const SYSTEM_REG_KEY_NORM = 'software\\omnios\\system';
const SYSTEM_DEFAULTS_DOMAIN = 'NSGlobalDomain';
const SYSTEM_SP_PACKAGE = 'com.omnios.system';
const SYSTEM_SP_PREF = 'system_settings';

const SYMBOL_DESCRIPTION_GET =
  Object.getOwnPropertyDescriptor(Symbol.prototype, 'description')?.get ?? null;
const MAX_DISPLAY_BIGINT_ABS = 1n << 4096n;
const MIN_DISPLAY_BIGINT_NEG = -MAX_DISPLAY_BIGINT_ABS;

function safeDisplay(value, maxLen = 256) {
  if (typeof value === 'string') {
    if (value.length > 65536) return `[String(${value.length} chars)]`;
    return value.length > maxLen ? `${value.slice(0, maxLen)}...` : value;
  }
  if (value === null || value === undefined) return String(value);
  const t = typeof value;
  if (t === 'number' || t === 'boolean') return String(value);
  if (t === 'bigint') {
    if (value > MAX_DISPLAY_BIGINT_ABS || value < MIN_DISPLAY_BIGINT_NEG) {
      return '[BigInt(Truncated)]';
    }
    const str = value.toString(10);
    return str.length > maxLen ? `${str.slice(0, maxLen)}...` : str;
  }
  if (t === 'symbol') {
    try {
      const desc = SYMBOL_DESCRIPTION_GET ? SYMBOL_DESCRIPTION_GET.call(value) : undefined;
      if (typeof desc === 'string') {
        if (desc.length > 65536) return `Symbol([String(${desc.length} chars)])`;
        const innerMax = Math.max(0, maxLen - 8);
        const capped = desc.length > innerMax ? `${desc.slice(0, innerMax)}...` : desc;
        return `Symbol(${capped})`;
      }
      return 'Symbol()';
    } catch (_err) {
      return '[Symbol]';
    }
  }
  if (t === 'function') return '[Function]';
  if (t === 'object') {
    try {
      if (Array.isArray(value)) return '[Array]';
    } catch (_err) {
      return '[Unreadable]';
    }
    return '[Object]';
  }
  return '[Unreadable]';
}

function validateTheme(raw) {
  if (typeof raw !== 'string') {
    throw new OmniOSError('system.theme must be a string ("dark" | "light" | "auto")', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (raw.length > 64) {
    throw new OmniOSError(`Invalid system.theme: "${safeDisplay(raw, 128)}" (expected dark|light|auto)`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  const norm = raw.trim().toLowerCase();
  if (!VALID_THEMES.has(norm)) {
    throw new OmniOSError(`Invalid system.theme: "${safeDisplay(raw, 128)}" (expected dark|light|auto)`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  return norm;
}

function validateShellMode(raw) {
  if (typeof raw !== 'string') {
    throw new OmniOSError(
      'system.shellMode must be a string ("unified" | "windows" | "macos" | "ios" | "android")',
      { code: ERROR_CODES.EINVAL }
    );
  }
  if (raw.length > 64) {
    throw new OmniOSError(
      `Invalid system.shellMode: "${safeDisplay(raw, 128)}" (expected unified|windows|macos|ios|android)`,
      { code: ERROR_CODES.EINVAL }
    );
  }
  const lowered = raw.trim().toLowerCase();
  const normalized = lowered === 'hybrid' ? 'unified' : lowered;
  if (!VALID_SHELL_MODES.has(normalized)) {
    throw new OmniOSError(
      `Invalid system.shellMode: "${safeDisplay(raw, 128)}" (expected unified|windows|macos|ios|android)`,
      { code: ERROR_CODES.EINVAL }
    );
  }
  return normalized;
}

function validatePercentInt(raw, keyName) {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw)) {
    throw new OmniOSError(`${keyName} must be an integer between 0 and 100`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (raw < 0 || raw > 100) {
    throw new OmniOSError(`${keyName} out of range [0..100]: ${raw}`, {
      code: ERROR_CODES.ERANGE,
    });
  }
  return raw;
}

function validateBooleanOrDword(raw, keyName) {
  if (typeof raw === 'boolean') return raw;
  if (raw === 0 || raw === 1) return raw === 1;
  throw new OmniOSError(`${keyName} must be a boolean (or 0/1 DWORD)`, {
    code: ERROR_CODES.EINVAL,
  });
}

function validateLocale(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 64 || /[\x00-\x1f\x7f]/.test(raw)) {
    throw new OmniOSError('system.locale must be a non-empty string (<= 64 chars, no control chars)', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new OmniOSError('system.locale must be a non-empty string (<= 64 chars, no control chars)', {
      code: ERROR_CODES.EINVAL,
    });
  }
  return trimmed;
}

export const CANONICAL_SYSTEM_KEYS = Object.freeze([
  'system.theme',
  'system.shellMode',
  'system.volume',
  'system.brightness',
  'system.wifi',
  'system.bluetooth',
  'system.dnd',
  'system.locale',
]);

export const SYSTEM_SYNC_MAP = freezeLookup({
  'system.theme': Object.freeze({
    canonicalKey: 'system.theme',
    defaultValue: 'dark',
    validate: validateTheme,
    regHive: REGISTRY_HIVES.HKCU,
    regKeyPath: SYSTEM_REG_KEY_PATH,
    regValueName: 'Theme',
    regType: REGISTRY_TYPES.REG_SZ,
    toReg: (v) => v,
    defaultsDomain: SYSTEM_DEFAULTS_DOMAIN,
    defaultsKey: 'AppleInterfaceStyle',
    toDefaults: (v) => v,
    spPackage: SYSTEM_SP_PACKAGE,
    spPref: SYSTEM_SP_PREF,
    spKey: 'system.theme',
    spType: 'string',
    toSp: (v) => v,
  }),
  'system.shellMode': Object.freeze({
    canonicalKey: 'system.shellMode',
    defaultValue: 'unified',
    validate: validateShellMode,
    regHive: REGISTRY_HIVES.HKCU,
    regKeyPath: SYSTEM_REG_KEY_PATH,
    regValueName: 'ShellMode',
    regType: REGISTRY_TYPES.REG_SZ,
    toReg: (v) => v,
    defaultsDomain: SYSTEM_DEFAULTS_DOMAIN,
    defaultsKey: 'OmniOSShellMode',
    toDefaults: (v) => v,
    spPackage: SYSTEM_SP_PACKAGE,
    spPref: SYSTEM_SP_PREF,
    spKey: 'system.shellMode',
    spType: 'string',
    toSp: (v) => v,
  }),
  'system.volume': Object.freeze({
    canonicalKey: 'system.volume',
    defaultValue: 75,
    validate: (v) => validatePercentInt(v, 'system.volume'),
    regHive: REGISTRY_HIVES.HKCU,
    regKeyPath: SYSTEM_REG_KEY_PATH,
    regValueName: 'Volume',
    regType: REGISTRY_TYPES.REG_DWORD,
    toReg: (v) => v,
    defaultsDomain: SYSTEM_DEFAULTS_DOMAIN,
    defaultsKey: 'OmniOSVolume',
    toDefaults: (v) => v,
    spPackage: SYSTEM_SP_PACKAGE,
    spPref: SYSTEM_SP_PREF,
    spKey: 'system.volume',
    spType: 'int',
    toSp: (v) => v,
  }),
  'system.brightness': Object.freeze({
    canonicalKey: 'system.brightness',
    defaultValue: 80,
    validate: (v) => validatePercentInt(v, 'system.brightness'),
    regHive: REGISTRY_HIVES.HKCU,
    regKeyPath: SYSTEM_REG_KEY_PATH,
    regValueName: 'Brightness',
    regType: REGISTRY_TYPES.REG_DWORD,
    toReg: (v) => v,
    defaultsDomain: SYSTEM_DEFAULTS_DOMAIN,
    defaultsKey: 'OmniOSBrightness',
    toDefaults: (v) => v,
    spPackage: SYSTEM_SP_PACKAGE,
    spPref: SYSTEM_SP_PREF,
    spKey: 'system.brightness',
    spType: 'int',
    toSp: (v) => v,
  }),
  'system.wifi': Object.freeze({
    canonicalKey: 'system.wifi',
    defaultValue: true,
    validate: (v) => validateBooleanOrDword(v, 'system.wifi'),
    regHive: REGISTRY_HIVES.HKCU,
    regKeyPath: SYSTEM_REG_KEY_PATH,
    regValueName: 'WifiEnabled',
    regType: REGISTRY_TYPES.REG_DWORD,
    toReg: (v) => (v ? 1 : 0),
    defaultsDomain: SYSTEM_DEFAULTS_DOMAIN,
    defaultsKey: 'OmniOSWifiEnabled',
    toDefaults: (v) => v,
    spPackage: SYSTEM_SP_PACKAGE,
    spPref: SYSTEM_SP_PREF,
    spKey: 'system.wifi',
    spType: 'boolean',
    toSp: (v) => v,
  }),
  'system.bluetooth': Object.freeze({
    canonicalKey: 'system.bluetooth',
    defaultValue: true,
    validate: (v) => validateBooleanOrDword(v, 'system.bluetooth'),
    regHive: REGISTRY_HIVES.HKCU,
    regKeyPath: SYSTEM_REG_KEY_PATH,
    regValueName: 'BluetoothEnabled',
    regType: REGISTRY_TYPES.REG_DWORD,
    toReg: (v) => (v ? 1 : 0),
    defaultsDomain: SYSTEM_DEFAULTS_DOMAIN,
    defaultsKey: 'OmniOSBluetoothEnabled',
    toDefaults: (v) => v,
    spPackage: SYSTEM_SP_PACKAGE,
    spPref: SYSTEM_SP_PREF,
    spKey: 'system.bluetooth',
    spType: 'boolean',
    toSp: (v) => v,
  }),
  'system.dnd': Object.freeze({
    canonicalKey: 'system.dnd',
    defaultValue: false,
    validate: (v) => validateBooleanOrDword(v, 'system.dnd'),
    regHive: REGISTRY_HIVES.HKCU,
    regKeyPath: SYSTEM_REG_KEY_PATH,
    regValueName: 'DoNotDisturb',
    regType: REGISTRY_TYPES.REG_DWORD,
    toReg: (v) => (v ? 1 : 0),
    defaultsDomain: SYSTEM_DEFAULTS_DOMAIN,
    defaultsKey: 'OmniOSDoNotDisturb',
    toDefaults: (v) => v,
    spPackage: SYSTEM_SP_PACKAGE,
    spPref: SYSTEM_SP_PREF,
    spKey: 'system.dnd',
    spType: 'boolean',
    toSp: (v) => v,
  }),
  'system.locale': Object.freeze({
    canonicalKey: 'system.locale',
    defaultValue: 'en-US',
    validate: validateLocale,
    regHive: REGISTRY_HIVES.HKCU,
    regKeyPath: SYSTEM_REG_KEY_PATH,
    regValueName: 'Locale',
    regType: REGISTRY_TYPES.REG_SZ,
    toReg: (v) => v,
    defaultsDomain: SYSTEM_DEFAULTS_DOMAIN,
    defaultsKey: 'AppleLocale',
    toDefaults: (v) => v,
    spPackage: SYSTEM_SP_PACKAGE,
    spPref: SYSTEM_SP_PREF,
    spKey: 'system.locale',
    spType: 'string',
    toSp: (v) => v,
  }),
});

// Reverse lookup tables (null-prototype)
const REG_VALUE_TO_CANONICAL = Object.create(null);
const DEFAULTS_KEY_TO_CANONICAL = Object.create(null);
const SP_KEY_TO_CANONICAL = Object.create(null);
for (const canonicalKey of CANONICAL_SYSTEM_KEYS) {
  const spec = SYSTEM_SYNC_MAP[canonicalKey];
  REG_VALUE_TO_CANONICAL[spec.regValueName.toLowerCase()] = canonicalKey;
  DEFAULTS_KEY_TO_CANONICAL[spec.defaultsKey] = canonicalKey;
  SP_KEY_TO_CANONICAL[spec.spKey] = canonicalKey;
}

const GLOBAL_DOMAIN_ALIASES = freezeLookup({
  NSGlobalDomain: 'NSGlobalDomain',
  '.GlobalPreferences': 'NSGlobalDomain',
  '-g': 'NSGlobalDomain',
  'Apple Global Domain': 'NSGlobalDomain',
});

export const CONFIG_MIGRATIONS = Object.freeze([
  Object.freeze({
    version: 1,
    name: 'unified_config_initial',
    sql: `
      CREATE TABLE IF NOT EXISTS registry_keys (
        hive TEXT NOT NULL,
        key_path_norm TEXT NOT NULL,
        key_path_orig TEXT NOT NULL,
        parent_path_norm TEXT NOT NULL,
        name_orig TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (hive, key_path_norm)
      );
      CREATE INDEX IF NOT EXISTS idx_reg_keys_parent
        ON registry_keys(hive, parent_path_norm);

      CREATE TABLE IF NOT EXISTS registry_values (
        hive TEXT NOT NULL,
        key_path_norm TEXT NOT NULL,
        value_name_norm TEXT NOT NULL,
        value_name_orig TEXT NOT NULL,
        value_type TEXT NOT NULL,
        data_text TEXT,
        data_blob BLOB,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (hive, key_path_norm, value_name_norm)
      );
      CREATE INDEX IF NOT EXISTS idx_reg_values_key
        ON registry_values(hive, key_path_norm);

      CREATE TABLE IF NOT EXISTS defaults_entries (
        domain TEXT NOT NULL,
        key_name TEXT NOT NULL,
        value_ast_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (domain, key_name)
      );

      CREATE TABLE IF NOT EXISTS shared_prefs_entries (
        package_name TEXT NOT NULL,
        pref_name TEXT NOT NULL,
        key_name TEXT NOT NULL,
        value_type TEXT NOT NULL,
        value_ast_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (package_name, pref_name, key_name)
      );
      CREATE INDEX IF NOT EXISTS idx_shared_prefs_scope
        ON shared_prefs_entries(package_name, pref_name);

      CREATE TABLE IF NOT EXISTS system_config (
        key_name TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `,
  }),
]);

// ============================================================================
// Registry Helpers
// ============================================================================

export const MAX_REG_KEY_PATH_CHARS = 4096;
export const MAX_REG_KEY_DEPTH = 64;
export const MAX_REG_SEGMENT_CHARS = 255;
export const MAX_REG_VALUE_NAME_CHARS = 4096;
const MAX_CONFIG_IDENTIFIER_CHARS = 1024;
const MAX_CONFIG_KEY_CHARS = 4096;
const MAX_CONFIG_ARRAY_LENGTH = 1_000_000;
const MAX_CONFIG_DEPTH = 128;
const MAX_CONFIG_NODES = 65536;
const MAX_CONFIG_PAYLOAD_BYTES = 4 * 1024 * 1024;
const MAX_SP_EDIT_OPS = 16384;
const MAX_EVENT_NODES = 4096;
const MAX_EVENT_BINARY_BYTES = 65536;
const MAX_EVENT_BYTES = 262144;
const MAX_EVENT_STRING_CHARS = 16384;
const MAX_BIGINT_ABS = 1n << 65536n;
const MIN_BIGINT_NEG = -MAX_BIGINT_ABS;

function safeBigIntDisplay(big) {
  if (big > MAX_BIGINT_ABS || big < MIN_BIGINT_NEG) {
    return '[BigInt(out-of-range)]';
  }
  const str = big.toString(10);
  return str.length > 64 ? `${str.slice(0, 64)}...` : str;
}

function consumeConfigBytes(budget, delta) {
  if (typeof delta !== 'number' || !Number.isFinite(delta) || delta < 0) {
    throw new OmniOSError('Config value exceeds maximum serialized payload size', {
      code: ERROR_CODES.EINVAL,
    });
  }
  budget.bytes = (budget.bytes ?? 0) + delta;
  if (budget.bytes > MAX_CONFIG_PAYLOAD_BYTES) {
    throw new OmniOSError(
      `Config value exceeds maximum serialized payload size (${MAX_CONFIG_PAYLOAD_BYTES} bytes)`,
      { code: ERROR_CODES.EINVAL }
    );
  }
}

function safeStringifyConfigJson(value) {
  try {
    const out = JSON.stringify(value);
    if (out === undefined) {
      throw new OmniOSError('Config value is not JSON-serializable', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return out;
  } catch (err) {
    if (err instanceof OmniOSError) throw err;
    throw new OmniOSError('Config value exceeds maximum serialized payload size', {
      code: ERROR_CODES.EINVAL,
    });
  }
}


const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_CTOR = TYPED_ARRAY_PROTO.constructor;
const TYPED_ARRAY_BUFFER_GET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'buffer').get;
const TYPED_ARRAY_OFFSET_GET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteOffset').get;
const TYPED_ARRAY_LENGTH_GET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteLength').get;
const DATA_VIEW_BUFFER_GET = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
const DATA_VIEW_OFFSET_GET = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get;
const DATA_VIEW_LENGTH_GET = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;
const AB_BYTE_LENGTH_GET = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const AB_DETACHED_GET = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'detached')?.get ?? null;
const SET_SIZE_GET = Object.getOwnPropertyDescriptor(Set.prototype, 'size').get;
const DATE_GET_TIME = Date.prototype.getTime;
const DATE_TO_ISO_STRING = Date.prototype.toISOString;
const DATE_GET_UTC_FULL_YEAR = Date.prototype.getUTCFullYear;
const DATE_GET_UTC_MONTH = Date.prototype.getUTCMonth;
const DATE_GET_UTC_DATE = Date.prototype.getUTCDate;
const DATE_GET_UTC_HOURS = Date.prototype.getUTCHours;
const DATE_GET_UTC_MINUTES = Date.prototype.getUTCMinutes;
const DATE_GET_UTC_SECONDS = Date.prototype.getUTCSeconds;

function safeIsArray(value) {
  try {
    return Array.isArray(value);
  } catch {
    return null;
  }
}

function safeInstanceOf(value, Ctor) {
  try {
    return value instanceof Ctor;
  } catch {
    return null;
  }
}

function safeIsArrayBufferView(value) {
  try {
    return ArrayBuffer.isView(value);
  } catch {
    return null;
  }
}

function isGenuineArrayBuffer(value) {
  return types.isArrayBuffer(value) && !types.isProxy(value);
}

function isGenuineBinaryView(value) {
  return (types.isTypedArray(value) || types.isDataView(value)) && !types.isProxy(value);
}

function isGenuineDate(value) {
  return types.isDate(value) && !types.isProxy(value);
}

function isGenuineSet(value) {
  return types.isSet(value) && !types.isProxy(value);
}

function isBufferDetached(buf) {
  if (AB_DETACHED_GET && types.isArrayBuffer(buf)) {
    return Boolean(AB_DETACHED_GET.call(buf));
  }
  return false;
}

function copyGenuineArrayBuffer(ab) {
  if (isBufferDetached(ab)) {
    throw new TypeError('ArrayBuffer is detached');
  }
  return new Uint8Array(ab).slice();
}

function copyGenuineBinaryView(view) {
  const isDv = types.isDataView(view);
  const buf = isDv ? DATA_VIEW_BUFFER_GET.call(view) : TYPED_ARRAY_BUFFER_GET.call(view);
  if (isBufferDetached(buf)) {
    throw new TypeError('Underlying ArrayBuffer is detached');
  }
  const offset = isDv ? DATA_VIEW_OFFSET_GET.call(view) : TYPED_ARRAY_OFFSET_GET.call(view);
  const byteLength = isDv ? DATA_VIEW_LENGTH_GET.call(view) : TYPED_ARRAY_LENGTH_GET.call(view);
  return new Uint8Array(buf, offset, byteLength).slice();
}

function detectSpoofedOrUnreadableBuiltin(value) {
  if (types.isProxy(value)) {
    return 'Unsupported Proxy object in config value';
  }
  if (types.isSharedArrayBuffer(value)) {
    return 'Unsupported or spoofed SharedArrayBuffer in config value';
  }
  if (types.isBoxedPrimitive(value)) {
    return 'Unsupported boxed primitive object in config value';
  }
  const proto = Object.getPrototypeOf(value);
  if (proto === Object.prototype || proto === null) {
    return null;
  }
  const pAb = safeInstanceOf(value, ArrayBuffer);
  if (pAb === null) return 'Invalid or unreadable config value';
  if (pAb === true) return 'Invalid or spoofed ArrayBuffer in config value';
  const pDate = safeInstanceOf(value, Date);
  if (pDate === null) return 'Invalid or unreadable config value';
  if (pDate === true) return 'Invalid or spoofed Date in config value';
  const pTa = safeInstanceOf(value, TYPED_ARRAY_CTOR);
  if (pTa === null) return 'Invalid or unreadable config value';
  if (pTa === true) return 'Invalid or spoofed TypedArray in config value';
  const pDv = safeInstanceOf(value, DataView);
  if (pDv === null) return 'Invalid or unreadable config value';
  if (pDv === true) return 'Invalid or spoofed DataView in config value';
  const pView = safeIsArrayBufferView(value);
  if (pView === null) return 'Invalid or unreadable config value';
  if (pView === true) return 'Invalid or spoofed binary view in config value';
  if (typeof SharedArrayBuffer === 'function') {
    const pSab = safeInstanceOf(value, SharedArrayBuffer);
    if (pSab === null) return 'Invalid or unreadable config value';
    if (pSab === true) return 'Unsupported or spoofed SharedArrayBuffer in config value';
  }
  return null;
}

function readSafeArrayLength(arr, label = 'array', maxLen = MAX_CONFIG_ARRAY_LENGTH) {
  let len;
  try {
    len = arr.length;
  } catch {
    throw new OmniOSError(`Unreadable ${label} length`, { code: ERROR_CODES.EINVAL });
  }
  if (
    typeof len !== 'number' ||
    !Number.isSafeInteger(len) ||
    len < 0 ||
    len > maxLen
  ) {
    throw new OmniOSError(`Invalid ${label} length`, { code: ERROR_CODES.EINVAL });
  }
  return len;
}

function normalizeHive(hive) {
  if (typeof hive !== 'string' || hive.length === 0) {
    throw new OmniOSError(`Invalid registry hive: ${safeDisplay(hive)}`, { code: ERROR_CODES.EINVAL });
  }
  if (hive.length > 64) {
    throw new OmniOSError(`Unknown registry hive: ${safeDisplay(hive)}`, { code: ERROR_CODES.EINVAL });
  }
  const upper = hive.trim().toUpperCase();
  if (upper.length === 0) {
    throw new OmniOSError(`Invalid registry hive: ${safeDisplay(hive)}`, { code: ERROR_CODES.EINVAL });
  }
  if (!Object.prototype.hasOwnProperty.call(REGISTRY_HIVE_ALIASES, upper)) {
    throw new OmniOSError(`Unknown registry hive: ${safeDisplay(hive)}`, { code: ERROR_CODES.EINVAL });
  }
  return REGISTRY_HIVE_ALIASES[upper];
}

function normalizeKeyPath(keyPath, { allowEmpty = false, rejectTraversal = false } = {}) {
  if ((keyPath === null || keyPath === undefined || keyPath === '') && allowEmpty) {
    return { orig: '', norm: '', segments: [] };
  }
  if (typeof keyPath !== 'string') {
    throw new OmniOSError('Registry keyPath must be a string without NUL bytes', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (keyPath.length > MAX_REG_KEY_PATH_CHARS) {
    throw new OmniOSError(
      `Registry keyPath exceeds maximum length (${MAX_REG_KEY_PATH_CHARS}): ${safeDisplay(keyPath, 128)}`,
      { code: ERROR_CODES.EINVAL }
    );
  }
  if (keyPath.includes('\0')) {
    throw new OmniOSError('Registry keyPath must be a string without NUL bytes', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const withBackslashes = keyPath.replace(/\//g, '\\');
  let start = 0;
  let end = withBackslashes.length;
  while (start < end && withBackslashes.charCodeAt(start) === 0x5c) start += 1;
  while (end > start && withBackslashes.charCodeAt(end - 1) === 0x5c) end -= 1;
  const cleaned = withBackslashes.slice(start, end).replace(/\\+/g, '\\');
  if (cleaned.length === 0) {
    if (allowEmpty) return { orig: '', norm: '', segments: [] };
    throw new OmniOSError('Registry keyPath must not be empty', { code: ERROR_CODES.EINVAL });
  }
  const segments = cleaned.split('\\').filter(Boolean);
  if (segments.length > MAX_REG_KEY_DEPTH) {
    throw new OmniOSError(
      `Registry keyPath exceeds maximum depth (${MAX_REG_KEY_DEPTH}): ${safeDisplay(keyPath, 128)}`,
      { code: ERROR_CODES.EINVAL }
    );
  }
  for (const seg of segments) {
    if (seg.length > MAX_REG_SEGMENT_CHARS) {
      throw new OmniOSError(
        `Registry key segment exceeds maximum length (${MAX_REG_SEGMENT_CHARS}): ${safeDisplay(seg, 128)}`,
        { code: ERROR_CODES.EINVAL }
      );
    }
    if (rejectTraversal && (seg === '..' || seg === '.')) {
      throw new SecurityError(`Registry path traversal rejected: ${safeDisplay(keyPath, 128)}`, {
        code: ERROR_CODES.E_PATH_TRAVERSAL,
      });
    }
  }
  const orig = segments.join('\\');
  return { orig, norm: orig.toLowerCase(), segments };
}

function normalizeValueName(valueName) {
  if (valueName === null || valueName === undefined) {
    return { orig: '', norm: '' };
  }
  if (typeof valueName !== 'string') {
    throw new OmniOSError('Registry valueName must be a string without NUL bytes', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (valueName.length > MAX_REG_VALUE_NAME_CHARS) {
    throw new OmniOSError(
      `Registry valueName exceeds maximum length (${MAX_REG_VALUE_NAME_CHARS}): ${safeDisplay(valueName, 128)}`,
      { code: ERROR_CODES.EINVAL }
    );
  }
  if (valueName.includes('\0')) {
    throw new OmniOSError('Registry valueName must be a string without NUL bytes', {
      code: ERROR_CODES.EINVAL,
    });
  }
  return { orig: valueName, norm: valueName.toLowerCase() };
}

function sanitizeVirtualAppScope(scope) {
  if (
    typeof scope !== 'string' ||
    scope.length === 0 ||
    scope.length > 256 ||
    scope.includes('\\') ||
    scope.includes('/') ||
    scope.includes('\0') ||
    scope.includes('..') ||
    scope === '.'
  ) {
    throw new SecurityError(`Invalid appId for Registry VirtualStore: ${safeDisplay(scope)}`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
    });
  }
  return scope;
}

// Internal reserved hive unreachable via normalizeHive() (not in REGISTRY_HIVE_ALIASES),
// isolating per-app VirtualStore completely from HKCU & HKCR reads/writes/enumerations.
const INTERNAL_VIRTUALSTORE_HIVE = '__VIRTUALSTORE__';

function encodeVirtualScope(kind, scope) {
  return `${kind}_${Buffer.from(scope, 'utf8').toString('hex')}`;
}

function resolveRegContext(ctx) {
  if (ctx === null || ctx === undefined) {
    return { privileged: true, uid: 0, appId: null, virtualPrefix: null };
  }
  if (typeof ctx !== 'object') {
    throw new SecurityError('Invalid Registry context: expected object, null, or undefined', {
      code: ERROR_CODES.EINVAL,
    });
  }

  let pcb;
  let ctxUid;
  let pcbUid;
  let uid;
  let rawAppId;
  let pid;
  let elevated;
  let isAdmin;
  let ctxPrivileged;
  try {
    pcb = ctx.pcb;
    if (pcb !== null && pcb !== undefined && typeof pcb !== 'object') {
      throw new SecurityError('Invalid pcb for Registry context', {
        code: ERROR_CODES.EINVAL,
      });
    }
    ctxUid = ctx.uid;
    pcbUid = pcb ? pcb.uid : undefined;
    uid = ctxUid ?? pcbUid;

    const ctxAppId = ctx.appId;
    const pcbAppId = pcb ? pcb.appId : undefined;
    rawAppId = ctxAppId ?? pcbAppId ?? null;

    const ctxPid = ctx.pid;
    const pcbPid = pcb ? pcb.pid : undefined;
    pid = ctxPid ?? pcbPid ?? null;

    elevated = ctx.elevated;
    isAdmin = ctx.isAdmin;
    ctxPrivileged = ctx.privileged;
  } catch (err) {
    if (err instanceof SecurityError) throw err;
    throw new SecurityError('Invalid or unreadable Registry context', {
      code: ERROR_CODES.EINVAL,
    });
  }

  // Validate uid STRICTLY BEFORE computing privilege so non-number / invalid uid
  // NEVER fails open to privileged ROOT.
  if (uid !== undefined && uid !== null) {
    if (typeof uid !== 'number' || !Number.isSafeInteger(uid) || uid < 0) {
      throw new SecurityError('Invalid uid for Registry context: must be a non-negative integer', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  if (pid !== undefined && pid !== null) {
    if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 0) {
      throw new SecurityError('Invalid pid for Registry context: must be a non-negative integer', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  const hasExplicitNullUid = (ctxUid === null || pcbUid === null) && (uid === undefined || uid === null);

  let privileged;
  if (elevated === true || isAdmin === true) {
    privileged = true;
  } else if (elevated === false || isAdmin === false || ctxPrivileged === false) {
    privileged = false;
  } else if (typeof uid === 'number') {
    privileged = uid === 0;
  } else if (rawAppId !== null || pid !== null || hasExplicitNullUid) {
    privileged = false;
  } else {
    privileged = true;
  }

  if (privileged) {
    if (rawAppId !== null && typeof rawAppId !== 'string') {
      throw new SecurityError('Invalid appId for Registry context: must be a string', {
        code: ERROR_CODES.E_PATH_TRAVERSAL,
      });
    }
    return {
      privileged: true,
      uid: typeof uid === 'number' ? uid : 0,
      appId: rawAppId,
      virtualPrefix: null,
    };
  }

  let scopeKind;
  let scopeInput;
  if (rawAppId !== null && rawAppId !== undefined) {
    scopeKind = 'app';
    if (typeof rawAppId !== 'string') {
      throw new SecurityError('Invalid appId for Registry VirtualStore: must be a string', {
        code: ERROR_CODES.E_PATH_TRAVERSAL,
      });
    }
    scopeInput = rawAppId;
  } else if (pid !== null && pid !== undefined) {
    scopeKind = 'pid';
    scopeInput = String(pid);
  } else if (typeof uid === 'number') {
    scopeKind = 'uid';
    scopeInput = String(uid);
  } else {
    scopeKind = 'anon';
    scopeInput = 'unprivileged';
  }
  const appScope = sanitizeVirtualAppScope(scopeInput);
  const encodedScope = encodeVirtualScope(scopeKind, appScope);
  return {
    privileged: false,
    uid: typeof uid === 'number' ? uid : null,
    appId: scopeKind === 'app' ? appScope : `${scopeKind}-${appScope}`,
    virtualPrefix: `MACHINE\\${encodedScope}`,
  };
}

const MAX_UINT32 = 0xffffffff;
const MAX_UINT64 = 0xffffffffffffffffn;
const MIN_INT32 = -2147483648;
const MAX_INT32 = 2147483647;
const MIN_INT64 = -9223372036854775808n;
const MAX_INT64 = 9223372036854775807n;

function serializeRegistryValue(type, data) {
  if (typeof type !== 'string' || type.length > 32 || !VALID_REG_TYPES.has(type)) {
    throw new OmniOSError(`Invalid registry value type: ${safeDisplay(type)}`, {
      code: ERROR_CODES.EINVAL,
    });
  }

  if (type === REGISTRY_TYPES.REG_SZ || type === REGISTRY_TYPES.REG_EXPAND_SZ) {
    if (typeof data !== 'string') {
      throw new OmniOSError(`${type} requires string data`, { code: ERROR_CODES.EINVAL });
    }
    if (data.length > MAX_CONFIG_PAYLOAD_BYTES) {
      throw new OmniOSError(
        `${type} value exceeds maximum serialized payload size (${MAX_CONFIG_PAYLOAD_BYTES} bytes)`,
        { code: ERROR_CODES.EINVAL }
      );
    }
    return { dataText: data, dataBlob: null, liveData: data };
  }

  if (type === REGISTRY_TYPES.REG_BINARY) {
    if (data === null || data === undefined || typeof data !== 'object') {
      throw new OmniOSError('REG_BINARY requires Uint8Array, ArrayBuffer, TypedArray, or byte array', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const isArr = safeIsArray(data);
    if (isArr === null) {
      throw new OmniOSError('REG_BINARY value is unreadable', {
        code: ERROR_CODES.EINVAL,
      });
    }
    let bytes;
    if (isArr) {
      const len = readSafeArrayLength(data, 'REG_BINARY array', MAX_CONFIG_NODES);
      if (len > MAX_CONFIG_PAYLOAD_BYTES) {
        throw new OmniOSError(
          `REG_BINARY value exceeds maximum serialized payload size (${MAX_CONFIG_PAYLOAD_BYTES} bytes)`,
          { code: ERROR_CODES.EINVAL }
        );
      }
      const tmp = [];
      for (let i = 0; i < len; i += 1) {
        let b;
        try {
          b = data[i];
        } catch {
          throw new OmniOSError(`Unreadable REG_BINARY array element at index ${i}`, {
            code: ERROR_CODES.EINVAL,
          });
        }
        if (typeof b !== 'number' || !Number.isInteger(b) || b < 0 || b > 255) {
          throw new OmniOSError('REG_BINARY array elements must be integers in 0..255', {
            code: ERROR_CODES.EINVAL,
          });
        }
        tmp.push(b);
      }
      bytes = new Uint8Array(tmp);
    } else if (isGenuineBinaryView(data)) {
      let byteLength;
      try {
        const isDv = types.isDataView(data);
        const buf = isDv ? DATA_VIEW_BUFFER_GET.call(data) : TYPED_ARRAY_BUFFER_GET.call(data);
        if (isBufferDetached(buf)) {
          throw new TypeError('Underlying ArrayBuffer is detached');
        }
        byteLength = isDv ? DATA_VIEW_LENGTH_GET.call(data) : TYPED_ARRAY_LENGTH_GET.call(data);
      } catch {
        throw new OmniOSError('Unreadable TypedArray view for REG_BINARY', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (byteLength > MAX_CONFIG_PAYLOAD_BYTES) {
        throw new OmniOSError(
          `REG_BINARY value exceeds maximum serialized payload size (${MAX_CONFIG_PAYLOAD_BYTES} bytes)`,
          { code: ERROR_CODES.EINVAL }
        );
      }
      try {
        bytes = copyGenuineBinaryView(data);
      } catch {
        throw new OmniOSError('Unreadable TypedArray view for REG_BINARY', {
          code: ERROR_CODES.EINVAL,
        });
      }
    } else if (isGenuineArrayBuffer(data)) {
      let byteLength;
      try {
        if (isBufferDetached(data)) {
          throw new TypeError('ArrayBuffer is detached');
        }
        byteLength = AB_BYTE_LENGTH_GET.call(data);
      } catch {
        throw new OmniOSError('Unreadable ArrayBuffer for REG_BINARY', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (byteLength > MAX_CONFIG_PAYLOAD_BYTES) {
        throw new OmniOSError(
          `REG_BINARY value exceeds maximum serialized payload size (${MAX_CONFIG_PAYLOAD_BYTES} bytes)`,
          { code: ERROR_CODES.EINVAL }
        );
      }
      try {
        bytes = copyGenuineArrayBuffer(data);
      } catch {
        throw new OmniOSError('Unreadable ArrayBuffer for REG_BINARY', {
          code: ERROR_CODES.EINVAL,
        });
      }
    } else {
      throw new OmniOSError(
        'REG_BINARY requires Uint8Array, ArrayBuffer, TypedArray, or byte array',
        { code: ERROR_CODES.EINVAL }
      );
    }
    return { dataText: null, dataBlob: bytes, liveData: bytes.slice() };
  }

  if (type === REGISTRY_TYPES.REG_DWORD) {
    let num;
    if (typeof data === 'number') {
      if (!Number.isSafeInteger(data) || data < 0 || data > MAX_UINT32) {
        throw new OmniOSError(`REG_DWORD out of range [0..0xFFFFFFFF]: ${data}`, {
          code: ERROR_CODES.ERANGE,
        });
      }
      num = data;
    } else if (typeof data === 'bigint') {
      if (data < 0n || data > BigInt(MAX_UINT32)) {
        throw new OmniOSError(`REG_DWORD out of range [0..0xFFFFFFFF]: ${safeBigIntDisplay(data)}`, {
          code: ERROR_CODES.ERANGE,
        });
      }
      num = Number(data);
    } else {
      throw new OmniOSError('REG_DWORD requires unsigned 32-bit integer or bigint', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return { dataText: String(num), dataBlob: null, liveData: num };
  }

  if (type === REGISTRY_TYPES.REG_MULTI_SZ) {
    const isArr = safeIsArray(data);
    if (isArr !== true) {
      throw new OmniOSError('REG_MULTI_SZ requires string[]', { code: ERROR_CODES.EINVAL });
    }
    const len = readSafeArrayLength(data, 'REG_MULTI_SZ array', MAX_CONFIG_NODES);
    const budget = { count: 1, bytes: 4 };
    const cloned = [];
    for (let i = 0; i < len; i += 1) {
      let item;
      try {
        item = data[i];
      } catch {
        throw new OmniOSError(`Unreadable REG_MULTI_SZ element at index ${i}`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (typeof item !== 'string') {
        throw new OmniOSError('REG_MULTI_SZ requires string[]', { code: ERROR_CODES.EINVAL });
      }
      consumeConfigBytes(budget, item.length + 4);
      cloned.push(item);
    }
    return { dataText: safeStringifyConfigJson(cloned), dataBlob: null, liveData: cloned };
  }

  if (type === REGISTRY_TYPES.REG_QWORD) {
    let big;
    if (typeof data === 'bigint') {
      big = data;
    } else if (typeof data === 'number') {
      if (!Number.isSafeInteger(data) || data < 0) {
        throw new OmniOSError(`REG_QWORD requires non-negative integer/bigint: ${data}`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      big = BigInt(data);
    } else if (typeof data === 'string' && data.length <= 1024) {
      const trimmed = data.trim();
      if (!/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(trimmed)) {
        throw new OmniOSError('REG_QWORD requires unsigned 64-bit bigint, safe integer, or decimal/hex string', {
          code: ERROR_CODES.EINVAL,
        });
      }
      big = BigInt(trimmed);
    } else {
      throw new OmniOSError('REG_QWORD requires unsigned 64-bit bigint, safe integer, or decimal/hex string', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (big < 0n || big > MAX_UINT64) {
      throw new OmniOSError(`REG_QWORD out of range [0..2^64-1]: ${safeBigIntDisplay(big)}`, {
        code: ERROR_CODES.ERANGE,
      });
    }
    return { dataText: big.toString(10), dataBlob: null, liveData: big };
  }

  throw new OmniOSError(`Unsupported registry type: ${safeDisplay(type)}`, { code: ERROR_CODES.EINVAL });
}

function deserializeRegistryRow(row) {
  const type = row.value_type;
  if (type === REGISTRY_TYPES.REG_SZ || type === REGISTRY_TYPES.REG_EXPAND_SZ) {
    return row.data_text ?? '';
  }
  if (type === REGISTRY_TYPES.REG_BINARY) {
    if (row.data_blob === null || row.data_blob === undefined) {
      return new Uint8Array(0);
    }
    if (!isGenuineBinaryView(row.data_blob)) {
      throw new OmniOSError('Corrupt REG_BINARY value', { code: ERROR_CODES.EINVAL });
    }
    try {
      return copyGenuineBinaryView(row.data_blob);
    } catch {
      throw new OmniOSError('Corrupt REG_BINARY value', { code: ERROR_CODES.EINVAL });
    }
  }
  if (type === REGISTRY_TYPES.REG_DWORD) {
    if (
      typeof row.data_text !== 'string' ||
      row.data_text.length === 0 ||
      row.data_text.length > 32 ||
      !/^\d+$/.test(row.data_text)
    ) {
      throw new OmniOSError('Corrupt REG_DWORD value', { code: ERROR_CODES.EINVAL });
    }
    const n = Number(row.data_text);
    if (!Number.isSafeInteger(n) || n < 0 || n > MAX_UINT32) {
      throw new OmniOSError('Corrupt REG_DWORD value out of 32-bit unsigned range', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return n;
  }
  if (type === REGISTRY_TYPES.REG_MULTI_SZ) {
    let parsed;
    try {
      parsed = JSON.parse(row.data_text || '[]');
    } catch {
      throw new OmniOSError('Corrupt REG_MULTI_SZ JSON value', { code: ERROR_CODES.EINVAL });
    }
    if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === 'string')) {
      throw new OmniOSError('Corrupt REG_MULTI_SZ array value', { code: ERROR_CODES.EINVAL });
    }
    return parsed.slice();
  }
  if (type === REGISTRY_TYPES.REG_QWORD) {
    if (typeof row.data_text !== 'string' || row.data_text.length === 0 || row.data_text.length > 128) {
      throw new OmniOSError('Corrupt REG_QWORD value', { code: ERROR_CODES.EINVAL });
    }
    const trimmed = row.data_text.trim();
    if (trimmed.length === 0 || trimmed.length > 64) {
      throw new OmniOSError('Corrupt REG_QWORD value', { code: ERROR_CODES.EINVAL });
    }
    let q;
    try {
      q = BigInt(trimmed);
    } catch {
      throw new OmniOSError('Corrupt REG_QWORD value', { code: ERROR_CODES.EINVAL });
    }
    if (q < 0n || q > MAX_UINT64) {
      throw new OmniOSError('Corrupt REG_QWORD value out of 64-bit unsigned range', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return q;
  }
  return row.data_text;
}

function makeRegistryValueRecord({ type, data, name, hive, keyPath, virtualized = false }) {
  const rec = {
    type,
    data,
    name,
    hive,
    keyPath,
    virtualized: Boolean(virtualized),
  };
  Object.defineProperty(rec, 'toJSON', {
    enumerable: false,
    configurable: true,
    value() {
      return {
        type: this.type,
        data:
          this.type === REGISTRY_TYPES.REG_QWORD && typeof this.data === 'bigint'
            ? this.data.toString(10)
            : this.type === REGISTRY_TYPES.REG_BINARY && isGenuineBinaryView(this.data)
              ? (() => {
                  try {
                    const b = copyGenuineBinaryView(this.data);
                    return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('base64');
                  } catch {
                    return '[UnreadableObject]';
                  }
                })()
              : this.data,
        name: this.name,
        hive: this.hive,
        keyPath: this.keyPath,
        virtualized: this.virtualized,
      };
    },
  });
  return rec;
}

// ============================================================================
// Collision-Free Typed Value AST Codec (Defaults & SharedPreferences)
// ============================================================================

function encodeValueAst(value, ancestors = new Set(), depth = 0, budget = { count: 0, bytes: 0 }, options = null) {
  if (depth > MAX_CONFIG_DEPTH) {
    throw new OmniOSError(`Config value exceeds maximum nesting depth (${MAX_CONFIG_DEPTH})`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (value !== null && typeof value === 'object' && ancestors.has(value)) {
    throw new FormatError('Cyclic object reference in plist/config value', {
      code: ERROR_CODES.E_CYCLIC_PLIST,
      format: 'plist',
    });
  }
  budget.count += 1;
  if (budget.count > MAX_CONFIG_NODES) {
    throw new OmniOSError(`Config value exceeds maximum node count (${MAX_CONFIG_NODES})`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  consumeConfigBytes(budget, 4);

  if (value === undefined) {
    throw new OmniOSError('Config value cannot be undefined', { code: ERROR_CODES.EINVAL });
  }
  if (value === null) {
    return ['n'];
  }
  const t = typeof value;
  if (t === 'string') {
    consumeConfigBytes(budget, value.length);
    return ['s', value];
  }
  if (t === 'boolean') return ['b', value];
  if (t === 'bigint') {
    if (options?.jsonOnly) {
      throw new OmniOSError(
        'System config value must be JSON-serializable (BigInt and binary buffers are not supported)',
        { code: ERROR_CODES.EINVAL }
      );
    }
    if (value > MAX_BIGINT_ABS || value < MIN_BIGINT_NEG) {
      throw new OmniOSError('Config BigInt value exceeds maximum supported bit width', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const dec = value.toString(10);
    consumeConfigBytes(budget, dec.length);
    return ['I', dec];
  }
  if (t === 'number') {
    if (Number.isNaN(value)) return ['r', 'NaN'];
    if (value === Infinity) return ['r', 'Infinity'];
    if (value === -Infinity) return ['r', '-Infinity'];
    if (Object.is(value, -0)) return ['r', '-0'];
    if (Number.isSafeInteger(value)) return ['i', value];
    return ['r', value];
  }
  if (t === 'function' || t === 'symbol') {
    throw new OmniOSError(`Unsupported config value type: ${t}`, { code: ERROR_CODES.EINVAL });
  }

  // Check Array.isArray FIRST (isolated try/catch) BEFORE any instanceof checks so
  // Proxy-wrapped Arrays with throwing getPrototypeOf traps remain Arrays and
  // revoked Proxies throw typed OmniOSError(EINVAL).
  const isArr = safeIsArray(value);
  if (isArr === null) {
    throw new OmniOSError('Invalid or unreadable config value', { code: ERROR_CODES.EINVAL });
  }

  if (!isArr) {
    if (isGenuineDate(value)) {
      let ms;
      let iso;
      try {
        ms = DATE_GET_TIME.call(value);
        if (Number.isFinite(ms)) {
          iso = DATE_TO_ISO_STRING.call(value);
        }
      } catch {
        throw new OmniOSError('Unreadable Date in config value', { code: ERROR_CODES.EINVAL });
      }
      if (!Number.isFinite(ms)) {
        throw new OmniOSError('Invalid Date (NaN) in config value', { code: ERROR_CODES.EINVAL });
      }
      if (typeof iso !== 'string') {
        throw new OmniOSError('Unreadable Date in config value', { code: ERROR_CODES.EINVAL });
      }
      consumeConfigBytes(budget, iso.length);
      return ['d', iso];
    }

    if (isGenuineBinaryView(value)) {
      if (options?.jsonOnly) {
        throw new OmniOSError(
          'System config value must be JSON-serializable (BigInt and binary buffers are not supported)',
          { code: ERROR_CODES.EINVAL }
        );
      }
      let byteLength;
      try {
        const isDv = types.isDataView(value);
        const buf = isDv ? DATA_VIEW_BUFFER_GET.call(value) : TYPED_ARRAY_BUFFER_GET.call(value);
        if (isBufferDetached(buf)) {
          throw new TypeError('Underlying ArrayBuffer is detached');
        }
        byteLength = isDv ? DATA_VIEW_LENGTH_GET.call(value) : TYPED_ARRAY_LENGTH_GET.call(value);
      } catch {
        throw new OmniOSError('Unreadable binary view in config value', { code: ERROR_CODES.EINVAL });
      }
      consumeConfigBytes(budget, Math.ceil(byteLength / 3) * 4);
      try {
        const bytes = copyGenuineBinaryView(value);
        const b64 = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
        return ['x', b64];
      } catch {
        throw new OmniOSError('Unreadable binary view in config value', { code: ERROR_CODES.EINVAL });
      }
    }

    if (isGenuineArrayBuffer(value)) {
      if (options?.jsonOnly) {
        throw new OmniOSError(
          'System config value must be JSON-serializable (BigInt and binary buffers are not supported)',
          { code: ERROR_CODES.EINVAL }
        );
      }
      let byteLength;
      try {
        if (isBufferDetached(value)) {
          throw new TypeError('ArrayBuffer is detached');
        }
        byteLength = AB_BYTE_LENGTH_GET.call(value);
      } catch {
        throw new OmniOSError('Unreadable ArrayBuffer in config value', { code: ERROR_CODES.EINVAL });
      }
      consumeConfigBytes(budget, Math.ceil(byteLength / 3) * 4);
      try {
        const bytes = copyGenuineArrayBuffer(value);
        const b64 = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
        return ['x', b64];
      } catch {
        throw new OmniOSError('Unreadable ArrayBuffer in config value', { code: ERROR_CODES.EINVAL });
      }
    }

    const spoofErr = detectSpoofedOrUnreadableBuiltin(value);
    if (spoofErr !== null) {
      throw new OmniOSError(spoofErr, { code: ERROR_CODES.EINVAL });
    }
  }

  ancestors.add(value);
  try {
    if (isArr) {
      let len;
      try {
        len = value.length;
      } catch {
        throw new OmniOSError('Unreadable config array length', { code: ERROR_CODES.EINVAL });
      }
      if (
        typeof len !== 'number' ||
        !Number.isInteger(len) ||
        len < 0 ||
        len > MAX_CONFIG_NODES ||
        budget.count + len > MAX_CONFIG_NODES
      ) {
        throw new OmniOSError(
          `Config array length invalid or exceeds maximum node count (${MAX_CONFIG_NODES})`,
          { code: ERROR_CODES.EINVAL }
        );
      }
      const items = [];
      for (let i = 0; i < len; i += 1) {
        let elem;
        try {
          elem = value[i];
        } catch {
          throw new OmniOSError(`Unreadable config array element at index ${i}`, {
            code: ERROR_CODES.EINVAL,
          });
        }
        items.push(encodeValueAst(elem, ancestors, depth + 1, budget, options));
      }
      return ['a', items];
    }

    let keys;
    try {
      keys = Object.keys(value);
    } catch {
      throw new OmniOSError('Unreadable config object keys', { code: ERROR_CODES.EINVAL });
    }
    if (keys.length > MAX_CONFIG_NODES) {
      throw new OmniOSError(`Config object exceeds maximum key count (${MAX_CONFIG_NODES})`, {
        code: ERROR_CODES.EINVAL,
      });
    }
    const entries = [];
    for (let i = 0; i < keys.length; i += 1) {
      const k = keys[i];
      consumeConfigBytes(budget, k.length + 4);
      let v;
      try {
        v = value[k];
      } catch {
        throw new OmniOSError(`Unreadable config object property "${safeDisplay(k)}"`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (v === undefined) continue;
      entries.push([k, encodeValueAst(v, ancestors, depth + 1, budget, options)]);
    }
    return ['o', entries];
  } finally {
    ancestors.delete(value);
  }
}

function decodeValueAst(node, depth = 0, budget = { count: 0, bytes: 0 }) {
  if (depth > MAX_CONFIG_DEPTH) {
    throw new OmniOSError(`Config value exceeds maximum nesting depth (${MAX_CONFIG_DEPTH})`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  budget.count += 1;
  if (budget.count > MAX_CONFIG_NODES) {
    throw new OmniOSError(`Config value exceeds maximum node count (${MAX_CONFIG_NODES})`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  consumeConfigBytes(budget, 4);
  if (!Array.isArray(node) || node.length === 0) {
    throw new OmniOSError('Corrupt config value AST', { code: ERROR_CODES.EINVAL });
  }
  const tag = node[0];
  switch (tag) {
    case 'n':
      return null;
    case 's':
      if (typeof node[1] !== 'string') {
        throw new OmniOSError('Corrupt config string AST', { code: ERROR_CODES.EINVAL });
      }
      consumeConfigBytes(budget, node[1].length);
      return node[1];
    case 'b':
      if (typeof node[1] !== 'boolean') {
        throw new OmniOSError('Corrupt config boolean AST', { code: ERROR_CODES.EINVAL });
      }
      return node[1];
    case 'i':
      if (typeof node[1] !== 'number' || !Number.isFinite(node[1])) {
        throw new OmniOSError('Corrupt config integer AST', { code: ERROR_CODES.EINVAL });
      }
      return node[1];
    case 'I': {
      if (typeof node[1] !== 'string' || node[1].length === 0 || node[1].length > 20480) {
        throw new OmniOSError('Corrupt config bigint AST', { code: ERROR_CODES.EINVAL });
      }
      const trimmed = node[1].trim();
      if (trimmed.length === 0 || trimmed.length > 20000) {
        throw new OmniOSError('Corrupt config bigint AST', { code: ERROR_CODES.EINVAL });
      }
      consumeConfigBytes(budget, node[1].length);
      let big;
      try {
        big = BigInt(trimmed);
      } catch {
        throw new OmniOSError('Corrupt config bigint AST', { code: ERROR_CODES.EINVAL });
      }
      if (big > MAX_BIGINT_ABS || big < MIN_BIGINT_NEG) {
        throw new OmniOSError('Corrupt config bigint AST', { code: ERROR_CODES.EINVAL });
      }
      return big;
    }
    case 'r': {
      const v = node[1];
      if (v === 'NaN') return NaN;
      if (v === 'Infinity') return Infinity;
      if (v === '-Infinity') return -Infinity;
      if (v === '-0') return -0;
      if (typeof v !== 'number' || !Number.isFinite(v)) {
        throw new OmniOSError('Corrupt config number AST', { code: ERROR_CODES.EINVAL });
      }
      return v;
    }
    case 'd': {
      if (typeof node[1] !== 'string') {
        throw new OmniOSError('Corrupt config date AST', { code: ERROR_CODES.EINVAL });
      }
      consumeConfigBytes(budget, node[1].length);
      const dt = new Date(node[1]);
      if (!Number.isFinite(DATE_GET_TIME.call(dt))) {
        throw new OmniOSError('Corrupt config date AST', { code: ERROR_CODES.EINVAL });
      }
      return dt;
    }
    case 'x': {
      if (typeof node[1] !== 'string') {
        throw new OmniOSError('Corrupt config binary AST', { code: ERROR_CODES.EINVAL });
      }
      consumeConfigBytes(budget, node[1].length);
      try {
        const buf = Buffer.from(node[1], 'base64');
        return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).slice();
      } catch {
        throw new OmniOSError('Corrupt config binary AST', { code: ERROR_CODES.EINVAL });
      }
    }
    case 'a': {
      if (!Array.isArray(node[1])) {
        throw new OmniOSError('Corrupt config array AST', { code: ERROR_CODES.EINVAL });
      }
      const items = node[1];
      if (items.length > MAX_CONFIG_NODES || budget.count + items.length > MAX_CONFIG_NODES) {
        throw new OmniOSError(`Config value exceeds maximum node count (${MAX_CONFIG_NODES})`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      const out = new Array(items.length);
      for (let i = 0; i < items.length; i += 1) {
        out[i] = decodeValueAst(items[i], depth + 1, budget);
      }
      return out;
    }
    case 'o': {
      if (!Array.isArray(node[1])) {
        throw new OmniOSError('Corrupt config object AST', { code: ERROR_CODES.EINVAL });
      }
      if (node[1].length > MAX_CONFIG_NODES) {
        throw new OmniOSError(`Config value exceeds maximum node count (${MAX_CONFIG_NODES})`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      const out = {};
      for (const entry of node[1]) {
        if (!Array.isArray(entry) || entry.length < 2 || typeof entry[0] !== 'string') {
          throw new OmniOSError('Corrupt config object entry AST', { code: ERROR_CODES.EINVAL });
        }
        consumeConfigBytes(budget, entry[0].length + 4);
        defineSafeProp(out, entry[0], decodeValueAst(entry[1], depth + 1, budget));
      }
      return out;
    }
    default:
      throw new OmniOSError('Corrupt config value AST: unknown tag', {
        code: ERROR_CODES.EINVAL,
      });
  }
}

/**
 * Materializes a pure, prototype-free, getter-free, toJSON-free JSON-safe value strictly
 * from a validated AST produced by encodeValueAst(). Rejects BigInt ('I') and binary ('x') tags.
 */
function astToSystemJsonValue(node, depth = 0, budget = { count: 0, bytes: 0 }) {
  if (depth > MAX_CONFIG_DEPTH) {
    throw new OmniOSError(`Config value exceeds maximum nesting depth (${MAX_CONFIG_DEPTH})`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  budget.count += 1;
  if (budget.count > MAX_CONFIG_NODES) {
    throw new OmniOSError(`Config value exceeds maximum node count (${MAX_CONFIG_NODES})`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  consumeConfigBytes(budget, 4);
  if (!Array.isArray(node) || node.length === 0) {
    throw new OmniOSError('System config value must be JSON-serializable', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const tag = node[0];
  switch (tag) {
    case 'n':
      return null;
    case 's':
      if (typeof node[1] !== 'string') {
        throw new OmniOSError('System config value must be JSON-serializable', {
          code: ERROR_CODES.EINVAL,
        });
      }
      consumeConfigBytes(budget, node[1].length);
      return node[1];
    case 'b':
      if (typeof node[1] !== 'boolean') {
        throw new OmniOSError('System config value must be JSON-serializable', {
          code: ERROR_CODES.EINVAL,
        });
      }
      return node[1];
    case 'i':
      if (typeof node[1] !== 'number' || !Number.isFinite(node[1])) {
        throw new OmniOSError('System config value must be JSON-serializable', {
          code: ERROR_CODES.EINVAL,
        });
      }
      return node[1];
    case 'r': {
      const v = node[1];
      if (v === 'NaN' || v === 'Infinity' || v === '-Infinity') {
        return null;
      }
      if (v === '-0') {
        return 0;
      }
      return typeof v === 'number' && Number.isFinite(v) ? v : null;
    }
    case 'd':
      if (typeof node[1] !== 'string') {
        throw new OmniOSError('System config value must be JSON-serializable', {
          code: ERROR_CODES.EINVAL,
        });
      }
      consumeConfigBytes(budget, node[1].length);
      return node[1];
    case 'I':
    case 'x':
      throw new OmniOSError(
        'System config value must be JSON-serializable (BigInt and binary buffers are not supported)',
        { code: ERROR_CODES.EINVAL }
      );
    case 'a': {
      if (!Array.isArray(node[1])) {
        throw new OmniOSError('System config value must be JSON-serializable', {
          code: ERROR_CODES.EINVAL,
        });
      }
      const items = node[1];
      if (items.length > MAX_CONFIG_NODES || budget.count + items.length > MAX_CONFIG_NODES) {
        throw new OmniOSError(`Config value exceeds maximum node count (${MAX_CONFIG_NODES})`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      const out = new Array(items.length);
      for (let i = 0; i < items.length; i += 1) {
        out[i] = astToSystemJsonValue(items[i], depth + 1, budget);
      }
      return out;
    }
    case 'o': {
      if (!Array.isArray(node[1])) {
        throw new OmniOSError('System config value must be JSON-serializable', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (node[1].length > MAX_CONFIG_NODES) {
        throw new OmniOSError(`Config value exceeds maximum node count (${MAX_CONFIG_NODES})`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      const out = Object.create(null);
      for (const entry of node[1]) {
        if (!Array.isArray(entry) || entry.length < 2 || typeof entry[0] !== 'string') {
          throw new OmniOSError('System config value must be JSON-serializable', {
            code: ERROR_CODES.EINVAL,
          });
        }
        consumeConfigBytes(budget, entry[0].length + 4);
        defineSafeProp(out, entry[0], astToSystemJsonValue(entry[1], depth + 1, budget));
      }
      return out;
    }
    default:
      throw new OmniOSError('System config value must be JSON-serializable', {
        code: ERROR_CODES.EINVAL,
      });
  }
}

function parseAndDecodeValueAst(jsonText) {
  if (typeof jsonText !== 'string') {
    throw new OmniOSError('Corrupt or unreadable config AST JSON', {
      code: ERROR_CODES.EINVAL,
    });
  }
  let ast;
  try {
    ast = JSON.parse(jsonText);
  } catch (err) {
    if (err instanceof OmniOSError) throw err;
    throw new OmniOSError('Corrupt or unreadable config AST JSON', {
      code: ERROR_CODES.EINVAL,
    });
  }
  return decodeValueAst(ast, 0, { count: 0, bytes: 0 });
}

function parseSystemConfigJson(jsonText) {
  if (typeof jsonText !== 'string') {
    throw new OmniOSError('Corrupt system_config JSON value', {
      code: ERROR_CODES.EINVAL,
    });
  }
  try {
    return JSON.parse(jsonText);
  } catch (err) {
    if (err instanceof OmniOSError) throw err;
    throw new OmniOSError('Corrupt system_config JSON value', {
      code: ERROR_CODES.EINVAL,
    });
  }
}

function toJsonSafeEventValue(value, depth = 0, seen = new Set(), budget = { count: 0, bytes: 0 }) {
  if (value !== null && typeof value === 'object' && seen.has(value)) {
    return '[Circular]';
  }
  if (budget.count >= MAX_EVENT_NODES || budget.bytes >= MAX_EVENT_BYTES) {
    return '[Truncated]';
  }
  budget.count += 1;
  budget.bytes += 4;

  if (value === null || value === undefined) return null;
  const t = typeof value;
  if (t === 'boolean') return value;
  if (t === 'string') {
    const remaining = Math.max(0, MAX_EVENT_BYTES - budget.bytes);
    const allowed = Math.min(MAX_EVENT_STRING_CHARS, remaining);
    if (value.length > allowed) {
      budget.bytes = Math.min(MAX_EVENT_BYTES, budget.bytes + allowed + 14);
      return `${value.slice(0, allowed)}...[Truncated]`;
    }
    budget.bytes += value.length;
    return value;
  }
  if (t === 'number') {
    if (Number.isFinite(value)) {
      budget.bytes += 8;
      return value;
    }
    const s = String(value);
    budget.bytes += s.length;
    return s;
  }
  if (t === 'bigint') {
    if (value > MAX_BIGINT_ABS || value < MIN_BIGINT_NEG) {
      budget.bytes += 24;
      return '[BigInt(Truncated)]';
    }
    const str = value.toString(10);
    const remaining = Math.max(0, MAX_EVENT_BYTES - budget.bytes);
    const allowed = Math.min(MAX_EVENT_STRING_CHARS, remaining);
    if (str.length > allowed) {
      budget.bytes = Math.min(MAX_EVENT_BYTES, budget.bytes + allowed + 14);
      return `${str.slice(0, allowed)}...[Truncated]`;
    }
    budget.bytes += str.length;
    return str;
  }
  if (t === 'function' || t === 'symbol') {
    budget.bytes += 12;
    return `[${t}]`;
  }
  if (depth >= 8) return '[MaxDepth]';

  const isArr = safeIsArray(value);
  if (isArr === null) return '[Unreadable]';

  if (!isArr) {
    if (isGenuineDate(value)) {
      try {
        const ms = DATE_GET_TIME.call(value);
        if (!Number.isFinite(ms)) return null;
        const iso = DATE_TO_ISO_STRING.call(value);
        if (typeof iso === 'string') {
          budget.bytes += iso.length;
          return iso;
        }
        return null;
      } catch {
        return null;
      }
    }
    if (isGenuineBinaryView(value)) {
      try {
        const isDv = types.isDataView(value);
        const buf = isDv ? DATA_VIEW_BUFFER_GET.call(value) : TYPED_ARRAY_BUFFER_GET.call(value);
        if (isBufferDetached(buf)) {
          return '[UnreadableObject]';
        }
        const byteLength = isDv ? DATA_VIEW_LENGTH_GET.call(value) : TYPED_ARRAY_LENGTH_GET.call(value);
        const b64Len = Math.ceil(byteLength / 3) * 4;
        if (byteLength > MAX_EVENT_BINARY_BYTES || budget.bytes + b64Len > MAX_EVENT_BYTES) {
          budget.bytes += 32;
          return `[Binary(${byteLength} bytes)]`;
        }
        const offset = isDv ? DATA_VIEW_OFFSET_GET.call(value) : TYPED_ARRAY_OFFSET_GET.call(value);
        const bytes = new Uint8Array(buf, offset, byteLength).slice();
        const b64 = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
        budget.bytes += b64.length;
        return b64;
      } catch {
        return '[UnreadableObject]';
      }
    }
    if (isGenuineArrayBuffer(value)) {
      try {
        if (isBufferDetached(value)) {
          return '[UnreadableObject]';
        }
        const byteLength = AB_BYTE_LENGTH_GET.call(value);
        const b64Len = Math.ceil(byteLength / 3) * 4;
        if (byteLength > MAX_EVENT_BINARY_BYTES || budget.bytes + b64Len > MAX_EVENT_BYTES) {
          budget.bytes += 32;
          return `[Binary(${byteLength} bytes)]`;
        }
        const bytes = new Uint8Array(value).slice();
        const b64 = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
        budget.bytes += b64.length;
        return b64;
      } catch {
        return '[UnreadableObject]';
      }
    }
    if (detectSpoofedOrUnreadableBuiltin(value) !== null) {
      return '[UnreadableObject]';
    }
  }

  seen.add(value);
  try {
    if (isArr) {
      let rawLen;
      try {
        rawLen = value.length;
      } catch {
        return '[Unreadable]';
      }
      if (typeof rawLen !== 'number' || !Number.isSafeInteger(rawLen) || rawLen < 0 || rawLen > 0xffffffff) {
        return '[Unreadable]';
      }
      const len = Math.min(rawLen, 1024);
      const out = [];
      let truncatedPushed = false;
      for (let i = 0; i < len; i += 1) {
        let elem;
        try {
          elem = value[i];
        } catch {
          elem = '[Unreadable]';
        }
        if (elem !== null && typeof elem === 'object' && seen.has(elem)) {
          out.push('[Circular]');
          continue;
        }
        if (budget.count >= MAX_EVENT_NODES || budget.bytes >= MAX_EVENT_BYTES) {
          if (!truncatedPushed) {
            out.push('[Truncated]');
            truncatedPushed = true;
          }
          continue;
        }
        out.push(toJsonSafeEventValue(elem, depth + 1, seen, budget));
      }
      return out;
    }
    let keys;
    try {
      keys = Object.keys(value);
    } catch {
      return '[Unreadable]';
    }
    const out = {};
    const maxKeys = Math.min(keys.length, 1024);
    let truncatedAdded = false;
    for (let i = 0; i < maxKeys; i += 1) {
      const k = keys[i];
      let v;
      try {
        v = value[k];
      } catch {
        v = '[Unreadable]';
      }
      if (v !== null && typeof v === 'object' && seen.has(v)) {
        const safeKey = k.length > 256 ? `${k.slice(0, 256)}...[Truncated]` : k;
        defineSafeProp(out, safeKey, '[Circular]');
        continue;
      }
      if (budget.count >= MAX_EVENT_NODES || budget.bytes >= MAX_EVENT_BYTES) {
        if (!truncatedAdded) {
          truncatedAdded = true;
          if (!Object.prototype.hasOwnProperty.call(out, '__truncated__')) {
            defineSafeProp(out, '__truncated__', '[Truncated]');
          }
        }
        continue;
      }
      const remaining = Math.max(0, MAX_EVENT_BYTES - budget.bytes);
      const allowedKeyLen = Math.min(MAX_EVENT_STRING_CHARS, remaining);
      const safeKey = k.length > allowedKeyLen ? `${k.slice(0, allowedKeyLen)}...[Truncated]` : k;
      budget.bytes += safeKey.length + 4;
      defineSafeProp(out, safeKey, toJsonSafeEventValue(v, depth + 1, seen, budget));
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

// ============================================================================
// XML 1.0 Plist Serializer (Verified Compatible with Python 3 plistlib.loads)
// ============================================================================

/**
 * Strips illegal XML 1.0 control characters (`\x00-\x08`, `\x0B`, `\x0C`, `\x0E-\x1F`, `\uFFFE`, `\uFFFF`),
 * replaces unpaired UTF-16 surrogates with `\uFFFD`, and escapes XML special chars + `\r -> &#xD;`.
 */
function escapeXml10Text(str, maxOutputLen = Infinity) {
  let clean = '';
  for (let i = 0; i < str.length; i += 1) {
    const code = str.charCodeAt(i);
    // High surrogate (0xD800..0xDBFF)
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 < str.length) {
        const next = str.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          clean += str[i] + str[i + 1];
          i += 1;
        } else {
          clean += '\uFFFD';
        }
      } else {
        clean += '\uFFFD';
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      // Lone low surrogate (0xDC00..0xDFFF)
      clean += '\uFFFD';
    } else if (
      // Illegal XML 1.0 control characters and non-characters
      (code <= 0x08) ||
      code === 0x0b ||
      code === 0x0c ||
      (code >= 0x0e && code <= 0x1f) ||
      code === 0xfffe ||
      code === 0xffff
    ) {
      continue;
    } else if (code === 0x26) {
      clean += '&amp;';
    } else if (code === 0x3c) {
      clean += '&lt;';
    } else if (code === 0x3e) {
      clean += '&gt;';
    } else if (code === 0x22) {
      clean += '&quot;';
    } else if (code === 0x27) {
      clean += '&apos;';
    } else if (code === 0x0d) {
      clean += '&#xD;';
    } else {
      clean += str[i];
    }
    if (clean.length > maxOutputLen) {
      throw new OmniOSError(
        `Config value exceeds maximum serialized payload size (${MAX_CONFIG_PAYLOAD_BYTES} bytes)`,
        { code: ERROR_CODES.EINVAL }
      );
    }
  }
  return clean;
}

/**
 * Formats a Date strictly as UTC `YYYY-MM-DDTHH:MM:SSZ` WITHOUT fractional milliseconds
 * (required by Python 3 `plistlib.loads`!).
 */
function formatPlistUtcDate(date) {
  if (!isGenuineDate(date) || Number.isNaN(DATE_GET_TIME.call(date))) {
    return '1970-01-01T00:00:00Z';
  }
  const year = DATE_GET_UTC_FULL_YEAR.call(date);
  if (year < 1) return '0001-01-01T00:00:00Z';
  if (year > 9999) return '9999-12-31T23:59:59Z';
  const yyyy = String(year).padStart(4, '0');
  const mm = String(DATE_GET_UTC_MONTH.call(date) + 1).padStart(2, '0');
  const dd = String(DATE_GET_UTC_DATE.call(date)).padStart(2, '0');
  const hh = String(DATE_GET_UTC_HOURS.call(date)).padStart(2, '0');
  const mi = String(DATE_GET_UTC_MINUTES.call(date)).padStart(2, '0');
  const ss = String(DATE_GET_UTC_SECONDS.call(date)).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}T${hh}:${mi}:${ss}Z`;
}

function wrapBase64(b64, indent) {
  if (b64.length === 0) return '';
  const lines = [];
  for (let i = 0; i < b64.length; i += 68) {
    lines.push(`${indent}${b64.slice(i, i + 68)}`);
  }
  return lines.join('\n');
}

function serializePlistValueXml(value, indentLevel = 0, depth = 0, budget = { count: 0, bytes: 0 }) {
  if (depth > MAX_CONFIG_DEPTH + 1) {
    throw new OmniOSError(`Plist value exceeds maximum nesting depth (${MAX_CONFIG_DEPTH})`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  budget.count += 1;
  if (budget.count > MAX_CONFIG_NODES) {
    throw new OmniOSError(`Config value exceeds maximum node count (${MAX_CONFIG_NODES})`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  consumeConfigBytes(budget, 4 + indentLevel);
  const indent = '\t'.repeat(indentLevel);

  if (typeof value === 'string') {
    const maxRemaining = Math.max(0, MAX_CONFIG_PAYLOAD_BYTES - budget.bytes);
    const escaped = escapeXml10Text(value, maxRemaining);
    consumeConfigBytes(budget, escaped.length + 17);
    return `${indent}<string>${escaped}</string>`;
  }
  if (typeof value === 'boolean') {
    consumeConfigBytes(budget, 8);
    return value ? `${indent}<true/>` : `${indent}<false/>`;
  }
  if (typeof value === 'bigint') {
    if (value > MAX_BIGINT_ABS || value < MIN_BIGINT_NEG) {
      throw new OmniOSError('Config BigInt value exceeds maximum supported bit width', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const dec = value.toString(10);
    consumeConfigBytes(budget, dec.length + 19);
    return `${indent}<integer>${dec}</integer>`;
  }
  if (typeof value === 'number') {
    let tagStr;
    if (Number.isNaN(value)) tagStr = '<real>nan</real>';
    else if (value === Infinity) tagStr = '<real>inf</real>';
    else if (value === -Infinity) tagStr = '<real>-inf</real>';
    else if (Object.is(value, -0)) tagStr = '<real>-0.0</real>';
    else if (Number.isSafeInteger(value)) tagStr = `<integer>${value}</integer>`;
    else tagStr = `<real>${String(value)}</real>`;
    consumeConfigBytes(budget, tagStr.length);
    return `${indent}${tagStr}`;
  }
  if (isGenuineDate(value)) {
    const formatted = formatPlistUtcDate(value);
    consumeConfigBytes(budget, formatted.length + 13);
    return `${indent}<date>${formatted}</date>`;
  }
  if (isGenuineBinaryView(value)) {
    let byteLength;
    try {
      const isDv = types.isDataView(value);
      const buf = isDv ? DATA_VIEW_BUFFER_GET.call(value) : TYPED_ARRAY_BUFFER_GET.call(value);
      if (isBufferDetached(buf)) {
        throw new TypeError('Underlying ArrayBuffer is detached');
      }
      byteLength = isDv ? DATA_VIEW_LENGTH_GET.call(value) : TYPED_ARRAY_LENGTH_GET.call(value);
    } catch {
      throw new OmniOSError('Unreadable binary view in plist value', { code: ERROR_CODES.EINVAL });
    }
    const b64Len = Math.ceil(byteLength / 3) * 4;
    const lineCount = b64Len > 0 ? Math.ceil(b64Len / 68) : 0;
    consumeConfigBytes(budget, b64Len + lineCount * (indentLevel + 1) + 15 + indentLevel);
    const bytes = copyGenuineBinaryView(value);
    const b64 = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
    if (b64.length === 0) {
      return `${indent}<data></data>`;
    }
    return `${indent}<data>\n${wrapBase64(b64, indent)}\n${indent}</data>`;
  }
  if (Array.isArray(value)) {
    const filtered = value.filter((item) => item !== null && item !== undefined);
    if (filtered.length === 0) {
      consumeConfigBytes(budget, 8);
      return `${indent}<array/>`;
    }
    consumeConfigBytes(budget, 18 + indentLevel);
    const innerParts = [];
    for (let i = 0; i < filtered.length; i += 1) {
      innerParts.push(serializePlistValueXml(filtered[i], indentLevel + 1, depth + 1, budget));
    }
    return `${indent}<array>\n${innerParts.join('\n')}\n${indent}</array>`;
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== null && value[k] !== undefined)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    if (keys.length === 0) {
      consumeConfigBytes(budget, 7);
      return `${indent}<dict/>`;
    }
    consumeConfigBytes(budget, 16 + indentLevel);
    const parts = [];
    const childIndent = '\t'.repeat(indentLevel + 1);
    for (const k of keys) {
      const maxRemaining = Math.max(0, MAX_CONFIG_PAYLOAD_BYTES - budget.bytes);
      const escapedKey = escapeXml10Text(k, maxRemaining);
      consumeConfigBytes(budget, escapedKey.length + childIndent.length + 12);
      parts.push(`${childIndent}<key>${escapedKey}</key>`);
      parts.push(serializePlistValueXml(value[k], indentLevel + 1, depth + 1, budget));
    }
    return `${indent}<dict>\n${parts.join('\n')}\n${indent}</dict>`;
  }
  consumeConfigBytes(budget, 17);
  return `${indent}<string></string>`;
}

// ============================================================================
// SharedPreferences Validation Helpers
// ============================================================================

const VALID_SP_TYPES = new Set(['string', 'int', 'long', 'float', 'boolean', 'stringSet', 'json']);

function extractStringArraySafe(value, label, budget = null) {
  const isArr = safeIsArray(value);
  const scanBudget = { count: 0, bytes: budget ? (budget.bytes ?? 0) : 0 };
  if (isArr === true) {
    const len = readSafeArrayLength(value, label, MAX_CONFIG_NODES);
    const out = [];
    for (let i = 0; i < len; i += 1) {
      let elem;
      try {
        elem = value[i];
      } catch {
        throw new OmniOSError(`Unreadable ${label} element at index ${i}`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (typeof elem !== 'string') {
        return null;
      }
      consumeConfigBytes(scanBudget, elem.length + 4);
      out.push(elem);
    }
    return out;
  }
  if (isArr === null) {
    throw new OmniOSError(`Unreadable ${label} value`, { code: ERROR_CODES.EINVAL });
  }
  if (isGenuineSet(value)) {
    let setSize;
    try {
      setSize = SET_SIZE_GET.call(value);
    } catch {
      throw new OmniOSError(`Unreadable Set in ${label}`, { code: ERROR_CODES.EINVAL });
    }
    if (setSize > MAX_CONFIG_NODES) {
      throw new OmniOSError(`${label} exceeds maximum length`, { code: ERROR_CODES.EINVAL });
    }
    const out = [];
    try {
      for (const item of Set.prototype.values.call(value)) {
        if (out.length >= MAX_CONFIG_NODES) {
          throw new OmniOSError(`${label} exceeds maximum length`, { code: ERROR_CODES.EINVAL });
        }
        if (typeof item !== 'string') {
          return null;
        }
        consumeConfigBytes(scanBudget, item.length + 4);
        out.push(item);
      }
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError(`Unreadable Set in ${label}`, { code: ERROR_CODES.EINVAL });
    }
    return out;
  }
  const spoofSet = safeInstanceOf(value, Set);
  if (spoofSet === null || spoofSet === true) {
    throw new OmniOSError(`Unreadable or spoofed Set in ${label}`, { code: ERROR_CODES.EINVAL });
  }
  return null;
}

function normalizeSharedPrefValue(value, explicitType = undefined, budget = null) {
  const activeBudget = budget ?? { count: 0, bytes: 0 };
  let type = explicitType;
  let preExtractedStrings = null;

  if (type === undefined || type === null) {
    if (typeof value === 'string') type = 'string';
    else if (typeof value === 'boolean') type = 'boolean';
    else if (typeof value === 'bigint') type = 'long';
    else if (typeof value === 'number') {
      type = Number.isInteger(value) && value >= MIN_INT32 && value <= MAX_INT32 ? 'int' : 'float';
    } else if (value !== null && value !== undefined && typeof value === 'object') {
      const isArr = safeIsArray(value);
      if (isArr === null) {
        throw new OmniOSError('Unreadable SharedPreferences value', { code: ERROR_CODES.EINVAL });
      }
      if (isArr) {
        const extracted = extractStringArraySafe(value, 'SharedPreferences array', activeBudget);
        if (extracted !== null) {
          type = 'stringSet';
          preExtractedStrings = extracted;
        } else {
          type = 'json';
        }
      } else if (isGenuineSet(value)) {
        type = 'stringSet';
      } else {
        const spoofSet = safeInstanceOf(value, Set);
        if (spoofSet === null || spoofSet === true) {
          throw new OmniOSError('Unreadable or spoofed Set in SharedPreferences value', {
            code: ERROR_CODES.EINVAL,
          });
        }
        type = 'json';
      }
    } else {
      throw new OmniOSError('Cannot infer SharedPreferences type for value', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  if (typeof type !== 'string' || type.length > 32 || !VALID_SP_TYPES.has(type)) {
    throw new OmniOSError(`Invalid SharedPreferences type: ${safeDisplay(type)}`, {
      code: ERROR_CODES.EINVAL,
    });
  }

  if (type === 'string') {
    if (typeof value !== 'string') {
      throw new OmniOSError('SharedPreferences "string" requires a string value', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return { type, normalized: value, ast: encodeValueAst(value, new Set(), 0, activeBudget) };
  }

  if (type === 'boolean') {
    if (typeof value !== 'boolean') {
      throw new OmniOSError('SharedPreferences "boolean" requires a boolean value', {
        code: ERROR_CODES.EINVAL,
      });
    }
    return { type, normalized: value, ast: encodeValueAst(value, new Set(), 0, activeBudget) };
  }

  if (type === 'int') {
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
      throw new OmniOSError('SharedPreferences "int" requires a 32-bit integer', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (value < MIN_INT32 || value > MAX_INT32) {
      throw new OmniOSError(`SharedPreferences "int" out of signed 32-bit range: ${value}`, {
        code: ERROR_CODES.ERANGE,
      });
    }
    return { type, normalized: value, ast: encodeValueAst(value, new Set(), 0, activeBudget) };
  }

  if (type === 'long') {
    let big;
    if (typeof value === 'bigint') {
      big = value;
    } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
      big = BigInt(value);
    } else {
      throw new OmniOSError('SharedPreferences "long" requires a signed 64-bit integer or bigint', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (big < MIN_INT64 || big > MAX_INT64) {
      throw new OmniOSError(`SharedPreferences "long" out of signed 64-bit range: ${safeBigIntDisplay(big)}`, {
        code: ERROR_CODES.ERANGE,
      });
    }
    const normalized =
      typeof value === 'number' && Number.isSafeInteger(value) ? value : big;
    const dec = big.toString(10);
    consumeConfigBytes(activeBudget, 4 + dec.length);
    return {
      type,
      normalized,
      ast: typeof normalized === 'bigint' ? ['I', dec] : ['i', normalized],
    };
  }

  if (type === 'float') {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new OmniOSError('SharedPreferences "float" requires a finite number', {
        code: ERROR_CODES.EINVAL,
      });
    }
    consumeConfigBytes(activeBudget, 12);
    return { type, normalized: value, ast: ['r', Object.is(value, -0) ? '-0' : value] };
  }

  if (type === 'stringSet') {
    const arr =
      preExtractedStrings ??
      (value !== null && value !== undefined && typeof value === 'object'
        ? extractStringArraySafe(value, 'SharedPreferences stringSet', activeBudget)
        : null);
    if (arr === null) {
      throw new OmniOSError('SharedPreferences "stringSet" requires Set<string> or string[]', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const deduped = Array.from(new Set(arr)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return { type, normalized: deduped, ast: encodeValueAst(deduped, new Set(), 0, activeBudget) };
  }

  // 'json'
  if (value === undefined) {
    throw new OmniOSError('SharedPreferences "json" cannot be undefined', {
      code: ERROR_CODES.EINVAL,
    });
  }
  const ast = encodeValueAst(value, new Set(), 0, activeBudget);
  return { type: 'json', normalized: decodeValueAst(ast, 0, { count: 0, bytes: 0 }), ast };
}

function assertNonEmptyNoNul(val, label, maxLen = MAX_CONFIG_KEY_CHARS) {
  if (typeof val !== 'string' || val.length === 0 || val.length > maxLen || val.includes('\0')) {
    throw new OmniOSError(`${label} must be a non-empty string (<= ${maxLen} chars, no NUL bytes)`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  return val;
}

// ============================================================================
// UnifiedConfigStore
// ============================================================================

export class UnifiedConfigStore {
  constructor(opts = {}) {
    let storage = null;
    let getStorage = null;
    let kernel = null;
    let eventBus = null;
    let log = () => {};

    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new OmniOSError('Invalid UnifiedConfigStore constructor options: expected object', {
          code: ERROR_CODES.EINVAL,
        });
      }
      try {
        if (opts.storage !== undefined) storage = opts.storage;
        if (opts.getStorage !== undefined) getStorage = opts.getStorage;
        if (opts.kernel !== undefined) kernel = opts.kernel;
        if (opts.eventBus !== undefined) eventBus = opts.eventBus;
        if (opts.log !== undefined) log = opts.log;
      } catch {
        throw new OmniOSError('Unreadable UnifiedConfigStore constructor options', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }

    if (kernel !== null && kernel !== undefined && typeof kernel !== 'object') {
      throw new OmniOSError('Invalid UnifiedConfigStore kernel dependency', { code: ERROR_CODES.EINVAL });
    }
    if (storage !== null && storage !== undefined && typeof storage !== 'object') {
      throw new OmniOSError('Invalid UnifiedConfigStore storage dependency', { code: ERROR_CODES.EINVAL });
    }
    if (eventBus !== null && eventBus !== undefined && typeof eventBus !== 'object') {
      throw new OmniOSError('Invalid UnifiedConfigStore eventBus dependency', { code: ERROR_CODES.EINVAL });
    }

    let kernelEventBus = null;
    let kernelStorage = null;
    let kernelStorageOpen = false;
    let storageOpen = false;
    try {
      if (kernel !== null && kernel !== undefined) {
        kernelEventBus = kernel.eventBus ?? null;
        kernelStorage = kernel.storage ?? null;
        kernelStorageOpen = Boolean(kernelStorage?.isOpen);
      }
      if (storage !== null && storage !== undefined) {
        storageOpen = Boolean(storage.isOpen);
      }
      const resolvedEventBus = eventBus ?? kernelEventBus ?? null;
      if (resolvedEventBus !== null && resolvedEventBus !== undefined) {
        if (typeof resolvedEventBus !== 'object' || typeof resolvedEventBus.emit !== 'function') {
          throw new OmniOSError('Invalid UnifiedConfigStore eventBus dependency: missing emit()', {
            code: ERROR_CODES.EINVAL,
          });
        }
      }
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError('Unreadable UnifiedConfigStore dependency option', {
        code: ERROR_CODES.EINVAL,
      });
    }

    this._kernel = kernel;
    this._getStorage = typeof getStorage === 'function' ? getStorage : null;
    this._eventBus = eventBus ?? kernelEventBus ?? null;
    this._log = typeof log === 'function' ? log : () => {};
    this._storage = storage;
    this._ownsStorage = false;
    this._initialized = false;
    this._emittingSyncKeys = new Set();

    // Facades matching Contract 3
    this.registry = {
      createKey: (hive, keyPath, ctx = null) => this._regCreateKey(hive, keyPath, ctx),
      setValue: (hive, keyPath, valueName, type, data, ctx = null) =>
        this._regSetValue(hive, keyPath, valueName, type, data, ctx),
      getValue: (hive, keyPath, valueName, ctx = null) =>
        this._regGetValue(hive, keyPath, valueName, ctx),
      enumKey: (hive, keyPath = '', ctx = null) => this._regEnumKey(hive, keyPath, ctx),
      deleteValue: (hive, keyPath, valueName, ctx = null) =>
        this._regDeleteValue(hive, keyPath, valueName, ctx),
      deleteKey: (hive, keyPath, ctx = null) => this._regDeleteKey(hive, keyPath, ctx),
    };

    this.defaults = {
      set: (domain, key, value, ctx = null) => this._defaultsSet(domain, key, value, ctx),
      get: (domain, key, ctx = null) => this._defaultsGet(domain, key, ctx),
      remove: (domain, key, ctx = null) => this._defaultsRemove(domain, key, ctx),
      readDomain: (domain, ctx = null) => this._defaultsReadDomain(domain, ctx),
      listDomains: () => this._defaultsListDomains(),
      exportPlistXml: (domain) => this._defaultsExportPlistXml(domain),
    };

    this.sharedPrefs = {
      edit: (packageName, prefName, ops, ctx = null) =>
        this._spEdit(packageName, prefName, ops, ctx),
      getAll: (packageName, prefName, ctx = null) => this._spGetAll(packageName, prefName, ctx),
      get: (packageName, prefName, key, defaultValue = null, ctx = null) =>
        this._spGet(packageName, prefName, key, defaultValue, ctx),
    };

    this.system = {
      get: (key) => this._systemGet(key),
      set: (key, value) => this._systemSet(key, value),
      getAll: () => this._systemGetAll(),
    };

    if (storageOpen) {
      this.init(storage);
    } else if (!storage && kernelStorageOpen) {
      this.init(kernelStorage);
    } else if (!storage && this._getStorage) {
      let candidate;
      let candidateOpen = false;
      try {
        candidate = this._getStorage();
        candidateOpen = Boolean(candidate?.isOpen);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError('Unreadable UnifiedConfigStore getStorage() dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (candidateOpen) {
        this.init(candidate);
      }
    } else if (!storage && !kernel && !this._getStorage) {
      this.init();
    }
  }

  isReady() {
    try {
      return Boolean(this._initialized && this._storage?.isOpen);
    } catch {
      return false;
    }
  }

  init(storage = null) {
    let db;
    let isOpen = false;
    try {
      db =
        storage ??
        this._kernel?.storage ??
        (this._getStorage ? this._getStorage() : null) ??
        this._storage ??
        null;
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError('Unreadable storage dependency in UnifiedConfigStore.init()', {
        code: ERROR_CODES.EINVAL,
      });
    }

    let createdPrivate = false;
    if (!db && !this._kernel && !this._getStorage) {
      db = new SqliteStorage(':memory:');
      createdPrivate = true;
    }

    try {
      isOpen = Boolean(db && db.isOpen);
    } catch {
      throw new OmniOSError('Unreadable storage in UnifiedConfigStore.init()', {
        code: ERROR_CODES.EINVAL,
      });
    }

    if (!isOpen) {
      throw new OmniOSError('UnifiedConfigStore requires an open SqliteStorage', {
        code: ERROR_CODES.E_STORAGE_CLOSED,
      });
    }

    if (createdPrivate) {
      this._ownsStorage = true;
    } else if (db !== this._storage) {
      if (this._ownsStorage && this._storage?.isOpen) {
        this._storage.close();
      }
      this._ownsStorage = false;
    }

    this._storage = db;
    if (!this._eventBus && this._kernel) {
      try {
        if (this._kernel.eventBus) {
          this._eventBus = this._kernel.eventBus;
        }
      } catch {
        // Ignore unreadable kernel.eventBus
      }
    }

    db.migrate('config', CONFIG_MIGRATIONS);
    this._seedCanonicalDefaults(db);
    this._initialized = true;
    return this;
  }

  close() {
    if (this._ownsStorage && this._storage?.isOpen) {
      this._storage.close();
    }
    this._initialized = false;
  }

  dispose() {
    this.close();
  }

  _requireStorage() {
    let currentOpen = false;
    if (this._initialized && this._storage) {
      try {
        currentOpen = Boolean(this._storage.isOpen);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError('Unreadable UnifiedConfigStore storage', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (currentOpen) {
        return this._storage;
      }
    }
    let lazy = null;
    let lazyOpen = false;
    try {
      lazy = this._kernel?.storage ?? (this._getStorage ? this._getStorage() : null);
      lazyOpen = Boolean(lazy?.isOpen);
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError('Unreadable UnifiedConfigStore storage dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (lazyOpen) {
      this.init(lazy);
      return this._storage;
    }
    throw new OmniOSError('UnifiedConfigStore storage is not open or initialized', {
      code: ERROR_CODES.E_STORAGE_CLOSED,
    });
  }

  _seedCanonicalDefaults(db) {
    const now = new Date().toISOString();
    db.transaction((tx) => {
      for (const canonicalKey of CANONICAL_SYSTEM_KEYS) {
        const spec = SYSTEM_SYNC_MAP[canonicalKey];
        const existing = tx.get(
          'SELECT value_json FROM system_config WHERE key_name = ?',
          canonicalKey
        );
        let value = spec.defaultValue;
        if (existing) {
          try {
            const parsed = JSON.parse(existing.value_json);
            value = spec.validate(parsed);
          } catch {
            value = spec.defaultValue;
          }
          // Ensure canonical persisted value (e.g. migrating legacy 'hybrid' -> 'unified')
          tx.run(
            'UPDATE system_config SET value_json = ? WHERE key_name = ?',
            JSON.stringify(value),
            canonicalKey
          );
        } else {
          tx.run(
            'INSERT INTO system_config (key_name, value_json, updated_at) VALUES (?, ?, ?)',
            canonicalKey,
            JSON.stringify(value),
            now
          );
        }

        // Seed missing platform mirror entries without overwriting existing persisted values
        const regExists = tx.get(
          'SELECT 1 AS ok FROM registry_values WHERE hive = ? AND key_path_norm = ? AND value_name_norm = ?',
          spec.regHive,
          SYSTEM_REG_KEY_NORM,
          spec.regValueName.toLowerCase()
        );
        if (!regExists) {
          this._writeRegistryRow(
            tx,
            spec.regHive,
            spec.regKeyPath,
            spec.regValueName,
            spec.regType,
            spec.toReg(value),
            now
          );
        }

        const defExists = tx.get(
          'SELECT 1 AS ok FROM defaults_entries WHERE domain = ? AND key_name = ?',
          spec.defaultsDomain,
          spec.defaultsKey
        );
        if (!defExists) {
          this._writeDefaultsRow(tx, spec.defaultsDomain, spec.defaultsKey, spec.toDefaults(value), now);
        }

        const spExists = tx.get(
          'SELECT 1 AS ok FROM shared_prefs_entries WHERE package_name = ? AND pref_name = ? AND key_name = ?',
          spec.spPackage,
          spec.spPref,
          spec.spKey
        );
        if (!spExists) {
          this._writeSharedPrefRow(tx, spec.spPackage, spec.spPref, spec.spKey, spec.spType, spec.toSp(value), now);
        }
      }
    });
  }

  // ---- Structural Non-Recursive Low-Level SQL Writers ----

  _ensureKeyChain(tx, hive, segments, nowIso) {
    if (!Array.isArray(segments) || segments.length > MAX_REG_KEY_DEPTH + 4) {
      throw new OmniOSError(`Registry keyPath exceeds maximum depth (${MAX_REG_KEY_DEPTH})`, {
        code: ERROR_CODES.EINVAL,
      });
    }
    let parentNorm = '';
    const builtOrig = [];
    for (let i = 0; i < segments.length; i += 1) {
      const seg = segments[i];
      builtOrig.push(seg);
      const pathOrig = builtOrig.join('\\');
      const pathNorm = pathOrig.toLowerCase();
      tx.run(
        `INSERT INTO registry_keys (hive, key_path_norm, key_path_orig, parent_path_norm, name_orig, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(hive, key_path_norm) DO NOTHING`,
        hive,
        pathNorm,
        pathOrig,
        parentNorm,
        seg,
        nowIso
      );
      parentNorm = pathNorm;
    }
  }

  _writeSystemRow(tx, key, value, nowIso) {
    tx.run(
      `INSERT INTO system_config (key_name, value_json, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(key_name) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
      key,
      JSON.stringify(value),
      nowIso
    );
  }

  _writeRegistryRow(
    tx,
    hive,
    keyPathOrig,
    valueNameOrig,
    type,
    data,
    nowIso,
    preSerialized = null,
    preNormalizedKey = null
  ) {
    const kp = preNormalizedKey ?? normalizeKeyPath(keyPathOrig, { allowEmpty: false });
    const vn = normalizeValueName(valueNameOrig);
    const ser = preSerialized ?? serializeRegistryValue(type, data);
    this._ensureKeyChain(tx, hive, kp.segments, nowIso);
    tx.run(
      `INSERT INTO registry_values
        (hive, key_path_norm, value_name_norm, value_name_orig, value_type, data_text, data_blob, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(hive, key_path_norm, value_name_norm)
       DO UPDATE SET
         value_type = excluded.value_type,
         data_text = excluded.data_text,
         data_blob = excluded.data_blob,
         updated_at = excluded.updated_at`,
      hive,
      kp.norm,
      vn.norm,
      vn.orig,
      type,
      ser.dataText,
      ser.dataBlob,
      nowIso
    );
    return ser.liveData;
  }

  _writeDefaultsRow(tx, domain, keyName, value, nowIso) {
    const ast = encodeValueAst(value, new Set(), 0, { count: 0, bytes: 0 });
    const astJson = safeStringifyConfigJson(ast);
    tx.run(
      `INSERT INTO defaults_entries (domain, key_name, value_ast_json, updated_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(domain, key_name)
       DO UPDATE SET value_ast_json = excluded.value_ast_json, updated_at = excluded.updated_at`,
      domain,
      keyName,
      astJson,
      nowIso
    );
    return decodeValueAst(ast, 0, { count: 0, bytes: 0 });
  }

  _writeSharedPrefRow(tx, packageName, prefName, keyName, type, value, nowIso, budget = null) {
    const norm = normalizeSharedPrefValue(value, type, budget);
    const astJson = safeStringifyConfigJson(norm.ast);
    tx.run(
      `INSERT INTO shared_prefs_entries
        (package_name, pref_name, key_name, value_type, value_ast_json, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(package_name, pref_name, key_name)
       DO UPDATE SET
         value_type = excluded.value_type,
         value_ast_json = excluded.value_ast_json,
         updated_at = excluded.updated_at`,
      packageName,
      prefName,
      keyName,
      norm.type,
      astJson,
      nowIso
    );
    return norm.normalized;
  }

  // ---- Atomic 4-View Canonical Sync ----

  _syncCanonicalSystemKey(tx, canonicalKey, rawValue, { source, origin }) {
    const spec = SYSTEM_SYNC_MAP[canonicalKey];
    const validated = spec.validate(rawValue);
    const oldRow = tx.get('SELECT value_json FROM system_config WHERE key_name = ?', canonicalKey);
    const oldValue = oldRow ? parseSystemConfigJson(oldRow.value_json) : spec.defaultValue;
    const nowIso = new Date().toISOString();

    this._writeSystemRow(tx, canonicalKey, validated, nowIso);
    this._writeRegistryRow(
      tx,
      spec.regHive,
      spec.regKeyPath,
      spec.regValueName,
      spec.regType,
      spec.toReg(validated),
      nowIso
    );
    this._writeDefaultsRow(
      tx,
      spec.defaultsDomain,
      spec.defaultsKey,
      spec.toDefaults(validated),
      nowIso
    );
    this._writeSharedPrefRow(
      tx,
      spec.spPackage,
      spec.spPref,
      spec.spKey,
      spec.spType,
      spec.toSp(validated),
      nowIso
    );

    return {
      source,
      canonicalKey,
      key: canonicalKey,
      oldValue,
      value: validated,
      synced: true,
      origin,
      ts: nowIso,
    };
  }

  _emitConfigChanged(eventPayload) {
    if (!this._eventBus) return;
    const syncKey = eventPayload.canonicalKey ?? null;
    const rawKey = safeDisplay(eventPayload.key ?? '');
    const guardKey = syncKey
      ? `sync:${syncKey}`
      : `${eventPayload.source ?? 'config'}:${eventPayload.source === 'registry' ? rawKey.toLowerCase() : rawKey}`;
    if (this._emittingSyncKeys.has(guardKey)) {
      return;
    }
    this._emittingSyncKeys.add(guardKey);
    try {
      if (typeof this._eventBus.emit === 'function') {
        this._eventBus.emit('config:changed', {
          source: eventPayload.source,
          canonicalKey: syncKey,
          key: eventPayload.key,
          oldValue: toJsonSafeEventValue(eventPayload.oldValue),
          value: toJsonSafeEventValue(eventPayload.value),
          synced: Boolean(syncKey && eventPayload.synced),
          origin: eventPayload.origin,
          ts: eventPayload.ts ?? new Date().toISOString(),
        });
      }
    } catch {
      // Ignore revoked or throwing eventBus after SQLite commit so config writes stay consistent
    } finally {
      this._emittingSyncKeys.delete(guardKey);
    }
  }

  // ==========================================================================
  // Facade 1: Windows Registry
  // ==========================================================================

  _resolveWriteTarget(hive, keyPath, ctx) {
    const canonHive = normalizeHive(hive);
    const regCtx = resolveRegContext(ctx);
    const kp = normalizeKeyPath(keyPath, {
      allowEmpty: false,
      rejectTraversal: !regCtx.privileged,
    });

    if (canonHive === REGISTRY_HIVES.HKLM && !regCtx.privileged) {
      const actualPath = `${regCtx.virtualPrefix}\\${kp.orig}`;
      return {
        hive: canonHive,
        keyPath: kp.orig,
        actualHive: INTERNAL_VIRTUALSTORE_HIVE,
        actualKeyPath: actualPath,
        actualKeyNorm: actualPath.toLowerCase(),
        actualSegments: actualPath.split('\\'),
        virtualized: true,
        regCtx,
      };
    }

    if (canonHive === REGISTRY_HIVES.HKCR) {
      const targetHive = regCtx.privileged ? REGISTRY_HIVES.HKLM : REGISTRY_HIVES.HKCU;
      const actualPath = `Software\\Classes\\${kp.orig}`;
      return {
        hive: canonHive,
        keyPath: kp.orig,
        actualHive: targetHive,
        actualKeyPath: actualPath,
        actualKeyNorm: actualPath.toLowerCase(),
        actualSegments: actualPath.split('\\'),
        virtualized: false,
        regCtx,
      };
    }

    return {
      hive: canonHive,
      keyPath: kp.orig,
      actualHive: canonHive,
      actualKeyPath: kp.orig,
      actualKeyNorm: kp.norm,
      actualSegments: kp.segments,
      virtualized: false,
      regCtx,
    };
  }

  _getReadLayers(hive, keyPath, ctx, { allowEmpty = false } = {}) {
    const canonHive = normalizeHive(hive);
    const regCtx = resolveRegContext(ctx);
    const kp = normalizeKeyPath(keyPath, {
      allowEmpty,
      rejectTraversal: !regCtx.privileged,
    });

    if (canonHive === REGISTRY_HIVES.HKCR) {
      const suffix = kp.orig ? `\\${kp.orig}` : '';
      const layers = [
        {
          hive: REGISTRY_HIVES.HKCU,
          keyPath: `Software\\Classes${suffix}`,
          keyNorm: `software\\classes${suffix.toLowerCase()}`,
          virtualized: false,
        },
      ];
      if (!regCtx.privileged) {
        const vp = `${regCtx.virtualPrefix}\\Software\\Classes${suffix}`;
        layers.push({
          hive: INTERNAL_VIRTUALSTORE_HIVE,
          keyPath: vp,
          keyNorm: vp.toLowerCase(),
          virtualized: true,
        });
      }
      layers.push({
        hive: REGISTRY_HIVES.HKLM,
        keyPath: `Software\\Classes${suffix}`,
        keyNorm: `software\\classes${suffix.toLowerCase()}`,
        virtualized: false,
      });
      return { canonHive, kp, layers, regCtx };
    }

    if (canonHive === REGISTRY_HIVES.HKLM && !regCtx.privileged) {
      const vp = kp.orig ? `${regCtx.virtualPrefix}\\${kp.orig}` : regCtx.virtualPrefix;
      return {
        canonHive,
        kp,
        regCtx,
        layers: [
          {
            hive: INTERNAL_VIRTUALSTORE_HIVE,
            keyPath: vp,
            keyNorm: vp.toLowerCase(),
            virtualized: true,
          },
          {
            hive: REGISTRY_HIVES.HKLM,
            keyPath: kp.orig,
            keyNorm: kp.norm,
            virtualized: false,
          },
        ],
      };
    }

    return {
      canonHive,
      kp,
      regCtx,
      layers: [
        {
          hive: canonHive,
          keyPath: kp.orig,
          keyNorm: kp.norm,
          virtualized: false,
        },
      ],
    };
  }

  _regCreateKey(hive, keyPath, ctx = null) {
    const db = this._requireStorage();
    const target = this._resolveWriteTarget(hive, keyPath, ctx);
    const nowIso = new Date().toISOString();
    let existed = false;

    db.transaction((tx) => {
      const row = tx.get(
        'SELECT 1 AS ok FROM registry_keys WHERE hive = ? AND key_path_norm = ?',
        target.actualHive,
        target.actualKeyNorm
      );
      existed = Boolean(row);
      this._ensureKeyChain(tx, target.actualHive, target.actualSegments, nowIso);
    });

    return {
      hive: target.hive,
      keyPath: target.keyPath,
      created: !existed,
      virtualized: target.virtualized,
      actualHive: target.actualHive,
      actualKeyPath: target.actualKeyPath,
    };
  }

  _regSetValue(hive, keyPath, valueName, type, data, ctx = null) {
    const db = this._requireStorage();
    const target = this._resolveWriteTarget(hive, keyPath, ctx);
    const vn = normalizeValueName(valueName);
    const ser = serializeRegistryValue(type, data);
    const nowIso = new Date().toISOString();

    let changeEvent = null;
    db.transaction((tx) => {
      // Check for live 8-key canonical sync on non-virtualized HKCU\Software\OmniOS\System
      const isSystemSyncTarget =
        !target.virtualized &&
        target.actualHive === REGISTRY_HIVES.HKCU &&
        target.actualKeyNorm === SYSTEM_REG_KEY_NORM &&
        Object.prototype.hasOwnProperty.call(REG_VALUE_TO_CANONICAL, vn.norm);

      if (isSystemSyncTarget) {
        const canonicalKey = REG_VALUE_TO_CANONICAL[vn.norm];
        changeEvent = this._syncCanonicalSystemKey(tx, canonicalKey, ser.liveData, {
          source: 'registry',
          origin: {
            hive: target.hive,
            keyPath: target.keyPath,
            valueName: vn.orig,
          },
        });
        return;
      }

      const prevRow = tx.get(
        'SELECT value_type, data_text, data_blob FROM registry_values WHERE hive = ? AND key_path_norm = ? AND value_name_norm = ?',
        target.actualHive,
        target.actualKeyNorm,
        vn.norm
      );
      const oldValue = prevRow ? deserializeRegistryRow(prevRow) : null;

      this._writeRegistryRow(tx, target.actualHive, target.actualKeyPath, vn.orig, type, data, nowIso, ser, {
        orig: target.actualKeyPath,
        norm: target.actualKeyNorm,
        segments: target.actualSegments,
      });
      changeEvent = {
        source: 'registry',
        canonicalKey: null,
        key: `${target.hive}\\${target.keyPath}\\${vn.orig}`,
        oldValue,
        value: ser.liveData,
        synced: false,
        origin: {
          hive: target.hive,
          keyPath: target.keyPath,
          valueName: vn.orig,
          virtualized: target.virtualized,
        },
        ts: nowIso,
      };
    });

    if (changeEvent) {
      this._emitConfigChanged(changeEvent);
    }

    return {
      hive: target.hive,
      keyPath: target.keyPath,
      valueName: vn.orig,
      type,
      virtualized: target.virtualized,
      actualHive: target.actualHive,
      actualKeyPath: target.actualKeyPath,
    };
  }

  _regGetValue(hive, keyPath, valueName, ctx = null) {
    const db = this._requireStorage();
    const { canonHive, kp, layers } = this._getReadLayers(hive, keyPath, ctx, { allowEmpty: false });
    const vn = normalizeValueName(valueName);

    for (const layer of layers) {
      const row = db.get(
        `SELECT value_name_orig, value_type, data_text, data_blob
         FROM registry_values
         WHERE hive = ? AND key_path_norm = ? AND value_name_norm = ?`,
        layer.hive,
        layer.keyNorm,
        vn.norm
      );
      if (row) {
        return makeRegistryValueRecord({
          type: row.value_type,
          data: deserializeRegistryRow(row),
          name: row.value_name_orig,
          hive: canonHive,
          keyPath: kp.orig,
          virtualized: layer.virtualized,
        });
      }
    }
    return null;
  }

  _regEnumKey(hive, keyPath = '', ctx = null) {
    const db = this._requireStorage();
    const { canonHive, kp, layers } = this._getReadLayers(hive, keyPath, ctx, { allowEmpty: true });

    let exists = kp.norm === '';
    const subkeyMap = new Map(); // nameLower -> origName
    const valueMap = new Map(); // valueNameNorm -> record

    // Process from lowest priority to highest so higher layers override on collision
    for (let i = layers.length - 1; i >= 0; i -= 1) {
      const layer = layers[i];
      if (layer.keyNorm !== '') {
        const keyRow = db.get(
          'SELECT 1 AS ok FROM registry_keys WHERE hive = ? AND key_path_norm = ?',
          layer.hive,
          layer.keyNorm
        );
        if (keyRow) exists = true;
      }

      const subRows = db.all(
        'SELECT name_orig FROM registry_keys WHERE hive = ? AND parent_path_norm = ? ORDER BY name_orig ASC',
        layer.hive,
        layer.keyNorm
      );
      for (const s of subRows) {
        subkeyMap.set(s.name_orig.toLowerCase(), s.name_orig);
      }

      if (layer.keyNorm !== '') {
        const valRows = db.all(
          `SELECT value_name_norm, value_name_orig, value_type, data_text, data_blob
           FROM registry_values
           WHERE hive = ? AND key_path_norm = ?`,
          layer.hive,
          layer.keyNorm
        );
        for (const v of valRows) {
          valueMap.set(
            v.value_name_norm,
            makeRegistryValueRecord({
              type: v.value_type,
              data: deserializeRegistryRow(v),
              name: v.value_name_orig,
              hive: canonHive,
              keyPath: kp.orig,
              virtualized: layer.virtualized,
            })
          );
        }
      }
    }

    const subkeys = Array.from(subkeyMap.values()).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const values = {};
    const sortedVals = Array.from(valueMap.values()).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b ? 1 : 0
    );
    for (const rec of sortedVals) {
      defineSafeProp(values, rec.name, rec);
    }

    return {
      hive: canonHive,
      keyPath: kp.orig,
      exists,
      subkeys,
      values,
    };
  }

  _regDeleteValue(hive, keyPath, valueName, ctx = null) {
    const db = this._requireStorage();
    const target = this._resolveWriteTarget(hive, keyPath, ctx);
    const vn = normalizeValueName(valueName);

    let deleted = false;
    let oldValue = null;

    db.transaction((tx) => {
      const existing = tx.get(
        'SELECT value_type, data_text, data_blob FROM registry_values WHERE hive = ? AND key_path_norm = ? AND value_name_norm = ?',
        target.actualHive,
        target.actualKeyNorm,
        vn.norm
      );
      if (existing) {
        oldValue = deserializeRegistryRow(existing);
        tx.run(
          'DELETE FROM registry_values WHERE hive = ? AND key_path_norm = ? AND value_name_norm = ?',
          target.actualHive,
          target.actualKeyNorm,
          vn.norm
        );
        deleted = true;
        return;
      }

      if (target.hive === REGISTRY_HIVES.HKLM && !target.regCtx.privileged) {
        const globalExists = tx.get(
          'SELECT 1 AS ok FROM registry_values WHERE hive = ? AND key_path_norm = ? AND value_name_norm = ?',
          REGISTRY_HIVES.HKLM,
          target.keyPath.toLowerCase(),
          vn.norm
        );
        if (globalExists) {
          throw new SecurityError('Unprivileged deletion of global HKLM registry value denied', {
            code: ERROR_CODES.EACCES,
            appId: target.regCtx.appId,
          });
        }
      }
    });

    if (deleted) {
      this._emitConfigChanged({
        source: 'registry',
        canonicalKey: null,
        key: `${target.hive}\\${target.keyPath}\\${vn.orig}`,
        oldValue,
        value: null,
        synced: false,
        origin: {
          hive: target.hive,
          keyPath: target.keyPath,
          valueName: vn.orig,
          deleted: true,
        },
        ts: new Date().toISOString(),
      });
    }

    return deleted;
  }

  /**
   * Recursive B-tree range delete using exact BINARY bounds (`\` = 0x5C to `]` = 0x5D).
   * Zero SQL `LIKE` wildcards -> 100% immune to `%`/`_` wildcard injection!
   */
  _regDeleteKey(hive, keyPath, ctx = null) {
    const db = this._requireStorage();
    const target = this._resolveWriteTarget(hive, keyPath, ctx);
    const norm = target.actualKeyNorm;
    const prefixLow = `${norm}\\`;
    const prefixHigh = `${norm}]`;

    let deleted = false;
    db.transaction((tx) => {
      const kDel = tx.run(
        `DELETE FROM registry_keys
         WHERE hive = ? AND (key_path_norm = ? OR (key_path_norm >= ? AND key_path_norm < ?))`,
        target.actualHive,
        norm,
        prefixLow,
        prefixHigh
      );
      const vDel = tx.run(
        `DELETE FROM registry_values
         WHERE hive = ? AND (key_path_norm = ? OR (key_path_norm >= ? AND key_path_norm < ?))`,
        target.actualHive,
        norm,
        prefixLow,
        prefixHigh
      );

      if (kDel.changes > 0 || vDel.changes > 0) {
        deleted = true;
        return;
      }

      if (target.hive === REGISTRY_HIVES.HKLM && !target.regCtx.privileged) {
        const gNorm = target.keyPath.toLowerCase();
        const globalExists = tx.get(
          `SELECT 1 AS ok FROM registry_keys
           WHERE hive = ? AND (key_path_norm = ? OR (key_path_norm >= ? AND key_path_norm < ?))
           LIMIT 1`,
          REGISTRY_HIVES.HKLM,
          gNorm,
          `${gNorm}\\`,
          `${gNorm}]`
        );
        if (globalExists) {
          throw new SecurityError('Unprivileged deletion of global HKLM registry key denied', {
            code: ERROR_CODES.EACCES,
            appId: target.regCtx.appId,
          });
        }
      }
    });

    if (deleted) {
      this._emitConfigChanged({
        source: 'registry',
        canonicalKey: null,
        key: `${target.hive}\\${target.keyPath}`,
        oldValue: null,
        value: null,
        synced: false,
        origin: {
          hive: target.hive,
          keyPath: target.keyPath,
          deletedKey: true,
        },
        ts: new Date().toISOString(),
      });
    }

    return deleted;
  }

  // ==========================================================================
  // Facade 2: Apple NSUserDefaults & XML 1.0 Plist
  // ==========================================================================

  _normalizeDomain(domain) {
    assertNonEmptyNoNul(domain, 'domain', MAX_CONFIG_IDENTIFIER_CHARS);
    if (Object.prototype.hasOwnProperty.call(GLOBAL_DOMAIN_ALIASES, domain)) {
      return GLOBAL_DOMAIN_ALIASES[domain];
    }
    return domain;
  }

  _defaultsSet(domain, key, value, ctx = null) {
    void ctx;
    const db = this._requireStorage();
    const cleanDomain = this._normalizeDomain(domain);
    assertNonEmptyNoNul(key, 'key');

    if (value === null) {
      const removed = this._defaultsRemove(cleanDomain, key, ctx);
      return { domain: cleanDomain, key, removed };
    }

    const nowIso = new Date().toISOString();
    let changeEvent = null;

    db.transaction((tx) => {
      if (
        cleanDomain === SYSTEM_DEFAULTS_DOMAIN &&
        Object.prototype.hasOwnProperty.call(DEFAULTS_KEY_TO_CANONICAL, key)
      ) {
        const canonicalKey = DEFAULTS_KEY_TO_CANONICAL[key];
        changeEvent = this._syncCanonicalSystemKey(tx, canonicalKey, value, {
          source: 'defaults',
          origin: { domain: cleanDomain, key },
        });
        return;
      }

      const prevRow = tx.get(
        'SELECT value_ast_json FROM defaults_entries WHERE domain = ? AND key_name = ?',
        cleanDomain,
        key
      );
      const oldValue = prevRow ? parseAndDecodeValueAst(prevRow.value_ast_json) : null;

      const savedValue = this._writeDefaultsRow(tx, cleanDomain, key, value, nowIso);
      changeEvent = {
        source: 'defaults',
        canonicalKey: null,
        key: `${cleanDomain}.${key}`,
        oldValue,
        value: savedValue,
        synced: false,
        origin: { domain: cleanDomain, key },
        ts: nowIso,
      };
    });

    if (changeEvent) {
      this._emitConfigChanged(changeEvent);
    }

    return { domain: cleanDomain, key, value: changeEvent?.value ?? value };
  }

  _defaultsGet(domain, key, ctx = null) {
    void ctx;
    const db = this._requireStorage();
    const cleanDomain = this._normalizeDomain(domain);
    assertNonEmptyNoNul(key, 'key');
    const row = db.get(
      'SELECT value_ast_json FROM defaults_entries WHERE domain = ? AND key_name = ?',
      cleanDomain,
      key
    );
    if (!row) return null;
    return parseAndDecodeValueAst(row.value_ast_json);
  }

  _defaultsRemove(domain, key, ctx = null) {
    void ctx;
    const db = this._requireStorage();
    const cleanDomain = this._normalizeDomain(domain);
    assertNonEmptyNoNul(key, 'key');

    let oldValue = null;
    let deleted = false;
    db.transaction((tx) => {
      const prevRow = tx.get(
        'SELECT value_ast_json FROM defaults_entries WHERE domain = ? AND key_name = ?',
        cleanDomain,
        key
      );
      if (!prevRow) return;
      oldValue = parseAndDecodeValueAst(prevRow.value_ast_json);
      const res = tx.run(
        'DELETE FROM defaults_entries WHERE domain = ? AND key_name = ?',
        cleanDomain,
        key
      );
      deleted = res.changes > 0;
    });

    if (deleted) {
      this._emitConfigChanged({
        source: 'defaults',
        canonicalKey: null,
        key: `${cleanDomain}.${key}`,
        oldValue,
        value: null,
        synced: false,
        origin: { domain: cleanDomain, key, removed: true },
        ts: new Date().toISOString(),
      });
    }
    return deleted;
  }

  _defaultsReadDomain(domain, ctx = null) {
    void ctx;
    const db = this._requireStorage();
    const cleanDomain = this._normalizeDomain(domain);
    const rows = db.all(
      'SELECT key_name, value_ast_json FROM defaults_entries WHERE domain = ? ORDER BY key_name ASC',
      cleanDomain
    );
    const out = {};
    for (const row of rows) {
      defineSafeProp(out, row.key_name, parseAndDecodeValueAst(row.value_ast_json));
    }
    return out;
  }

  _defaultsListDomains() {
    const db = this._requireStorage();
    const rows = db.all('SELECT DISTINCT domain FROM defaults_entries ORDER BY domain ASC');
    return rows.map((r) => r.domain);
  }

  _defaultsExportPlistXml(domain) {
    const dict = this._defaultsReadDomain(domain);
    const body = serializePlistValueXml(dict, 0, 0, { count: 0, bytes: 0 });
    return [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
      '<plist version="1.0">',
      body,
      '</plist>',
      '',
    ].join('\n');
  }

  // ==========================================================================
  // Facade 3: Android SharedPreferences (Atomic Batch Transactions)
  // ==========================================================================

  _spEdit(packageName, prefName, ops, ctx = null) {
    void ctx;
    const db = this._requireStorage();
    assertNonEmptyNoNul(packageName, 'packageName', MAX_CONFIG_IDENTIFIER_CHARS);
    assertNonEmptyNoNul(prefName, 'prefName', MAX_CONFIG_IDENTIFIER_CHARS);
    const isOpsArr = safeIsArray(ops);
    if (isOpsArr !== true) {
      throw new OmniOSError('sharedPrefs.edit() ops must be an array', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const opsLen = readSafeArrayLength(ops, 'sharedPrefs.edit() ops', MAX_SP_EDIT_OPS);

    // Snapshot operation descriptors defensively before opening SQLite transaction
    const snapshotOps = [];
    for (let i = 0; i < opsLen; i += 1) {
      let entry;
      let opName;
      let entryKey;
      let entryType;
      let entryValue;
      try {
        entry = ops[i];
        if (!entry || typeof entry !== 'object') {
          throw new OmniOSError(`Invalid SharedPreferences operation at index ${i}`, {
            code: ERROR_CODES.EINVAL,
          });
        }
        opName = entry.op;
        if (typeof opName !== 'string') {
          throw new OmniOSError(`Invalid SharedPreferences operation at index ${i}`, {
            code: ERROR_CODES.EINVAL,
          });
        }
        if (opName.length > 64) {
          throw new OmniOSError(`Unknown SharedPreferences op: ${safeDisplay(opName, 128)}`, {
            code: ERROR_CODES.EINVAL,
          });
        }
        if (opName === 'put') {
          entryKey = entry.key;
          entryType = entry.type;
          entryValue = entry.value;
        } else if (opName === 'remove') {
          entryKey = entry.key;
        }
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError(`Unreadable SharedPreferences operation at index ${i}`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      snapshotOps.push({ op: opName, key: entryKey, type: entryType, value: entryValue });
    }

    const nowIso = new Date().toISOString();
    const changedKeys = [];
    const pendingEvents = [];
    const batchBudget = { count: 0, bytes: 0 };

    db.transaction((tx) => {
      for (let i = 0; i < snapshotOps.length; i += 1) {
        const entry = snapshotOps[i];

        if (entry.op === 'clear') {
          consumeConfigBytes(batchBudget, 4);
          const existing = tx.all(
            'SELECT key_name FROM shared_prefs_entries WHERE package_name = ? AND pref_name = ?',
            packageName,
            prefName
          );
          tx.run(
            'DELETE FROM shared_prefs_entries WHERE package_name = ? AND pref_name = ?',
            packageName,
            prefName
          );
          for (const row of existing) {
            changedKeys.push(row.key_name);
          }
          if (existing.length > 0) {
            pendingEvents.push({
              source: 'sharedPrefs',
              canonicalKey: null,
              key: `${packageName}/${prefName}`,
              oldValue: null,
              value: null,
              synced: false,
              origin: { packageName, prefName, cleared: true },
              ts: nowIso,
            });
          }
        } else if (entry.op === 'put') {
          const key = assertNonEmptyNoNul(entry.key, 'key');
          consumeConfigBytes(batchBudget, key.length + 4);
          const isSystemSp =
            packageName === SYSTEM_SP_PACKAGE &&
            prefName === SYSTEM_SP_PREF &&
            Object.prototype.hasOwnProperty.call(SP_KEY_TO_CANONICAL, key);

          if (isSystemSp) {
            consumeConfigBytes(batchBudget, 32);
            const canonicalKey = SP_KEY_TO_CANONICAL[key];
            const ev = this._syncCanonicalSystemKey(tx, canonicalKey, entry.value, {
              source: 'sharedPrefs',
              origin: { packageName, prefName, key },
            });
            pendingEvents.push(ev);
            changedKeys.push(key);
          } else {
            const prevRow = tx.get(
              'SELECT value_ast_json FROM shared_prefs_entries WHERE package_name = ? AND pref_name = ? AND key_name = ?',
              packageName,
              prefName,
              key
            );
            const oldValue = prevRow ? parseAndDecodeValueAst(prevRow.value_ast_json) : null;
            const opBudget = { count: 0, bytes: batchBudget.bytes };
            const normalized = this._writeSharedPrefRow(
              tx,
              packageName,
              prefName,
              key,
              entry.type,
              entry.value,
              nowIso,
              opBudget
            );
            batchBudget.bytes = opBudget.bytes;
            changedKeys.push(key);
            pendingEvents.push({
              source: 'sharedPrefs',
              canonicalKey: null,
              key: `${packageName}/${prefName}/${key}`,
              oldValue,
              value: normalized,
              synced: false,
              origin: { packageName, prefName, key },
              ts: nowIso,
            });
          }
        } else if (entry.op === 'remove') {
          const key = assertNonEmptyNoNul(entry.key, 'key');
          consumeConfigBytes(batchBudget, key.length + 4);
          const prevRow = tx.get(
            'SELECT value_ast_json FROM shared_prefs_entries WHERE package_name = ? AND pref_name = ? AND key_name = ?',
            packageName,
            prefName,
            key
          );
          if (prevRow) {
            const oldValue = parseAndDecodeValueAst(prevRow.value_ast_json);
            tx.run(
              'DELETE FROM shared_prefs_entries WHERE package_name = ? AND pref_name = ? AND key_name = ?',
              packageName,
              prefName,
              key
            );
            changedKeys.push(key);
            pendingEvents.push({
              source: 'sharedPrefs',
              canonicalKey: null,
              key: `${packageName}/${prefName}/${key}`,
              oldValue,
              value: null,
              synced: false,
              origin: { packageName, prefName, key, removed: true },
              ts: nowIso,
            });
          }
        } else {
          throw new OmniOSError(`Unknown SharedPreferences op: ${safeDisplay(entry.op, 128)}`, {
            code: ERROR_CODES.EINVAL,
          });
        }
      }
    });

    for (const ev of pendingEvents) {
      this._emitConfigChanged(ev);
    }

    return {
      packageName,
      prefName,
      appliedOps: opsLen,
      changedKeys: Array.from(new Set(changedKeys)),
    };
  }

  _spGetAll(packageName, prefName, ctx = null) {
    void ctx;
    const db = this._requireStorage();
    assertNonEmptyNoNul(packageName, 'packageName', MAX_CONFIG_IDENTIFIER_CHARS);
    assertNonEmptyNoNul(prefName, 'prefName', MAX_CONFIG_IDENTIFIER_CHARS);
    const rows = db.all(
      'SELECT key_name, value_ast_json FROM shared_prefs_entries WHERE package_name = ? AND pref_name = ? ORDER BY key_name ASC',
      packageName,
      prefName
    );
    const out = {};
    for (const row of rows) {
      defineSafeProp(out, row.key_name, parseAndDecodeValueAst(row.value_ast_json));
    }
    return out;
  }

  _spGet(packageName, prefName, key, defaultValue = null, ctx = null) {
    void ctx;
    const db = this._requireStorage();
    assertNonEmptyNoNul(packageName, 'packageName', MAX_CONFIG_IDENTIFIER_CHARS);
    assertNonEmptyNoNul(prefName, 'prefName', MAX_CONFIG_IDENTIFIER_CHARS);
    assertNonEmptyNoNul(key, 'key');
    const row = db.get(
      'SELECT value_ast_json FROM shared_prefs_entries WHERE package_name = ? AND pref_name = ? AND key_name = ?',
      packageName,
      prefName,
      key
    );
    if (!row) return defaultValue;
    return parseAndDecodeValueAst(row.value_ast_json);
  }

  // ==========================================================================
  // Facade 4: System Config
  // ==========================================================================

  _systemGet(key) {
    const db = this._requireStorage();
    assertNonEmptyNoNul(key, 'key');
    const row = db.get('SELECT value_json FROM system_config WHERE key_name = ?', key);
    if (row) {
      return parseSystemConfigJson(row.value_json);
    }
    if (Object.prototype.hasOwnProperty.call(SYSTEM_SYNC_MAP, key)) {
      return SYSTEM_SYNC_MAP[key].defaultValue;
    }
    return null;
  }

  _systemSet(key, value) {
    const db = this._requireStorage();
    assertNonEmptyNoNul(key, 'key');
    let changeEvent = null;

    db.transaction((tx) => {
      if (Object.prototype.hasOwnProperty.call(SYSTEM_SYNC_MAP, key)) {
        changeEvent = this._syncCanonicalSystemKey(tx, key, value, {
          source: 'system',
          origin: { key },
        });
        return;
      }

      if (value === undefined) {
        throw new OmniOSError('system.set() value cannot be undefined', {
          code: ERROR_CODES.EINVAL,
        });
      }
      // Single-pass AST validation + pure JSON materialization (blocks toJSON/getter TOCTOU,
      // BigInt, binary buffer JSON explosion, DAG OOM, and depth bypass).
      let serialized;
      try {
        const ast = encodeValueAst(value, new Set(), 0, { count: 0, bytes: 0 }, { jsonOnly: true });
        const materialized = astToSystemJsonValue(ast, 0, { count: 0, bytes: 0 });
        serialized = JSON.stringify(materialized);
      } catch (err) {
        if (err instanceof OmniOSError) {
          throw err;
        }
        let reason = 'value is not JSON-serializable';
        try {
          if (err && typeof err.message === 'string' && err.message.length > 0) {
            reason = err.message;
          }
        } catch {
          // Ignore hostile error getters
        }
        throw new OmniOSError(`system.set() value must be JSON-serializable: ${safeDisplay(reason)}`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (serialized === undefined) {
        throw new OmniOSError('system.set() value must be JSON-serializable', {
          code: ERROR_CODES.EINVAL,
        });
      }
      const prevRow = tx.get('SELECT value_json FROM system_config WHERE key_name = ?', key);
      const oldValue = prevRow ? parseSystemConfigJson(prevRow.value_json) : null;
      const nowIso = new Date().toISOString();
      tx.run(
        `INSERT INTO system_config (key_name, value_json, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(key_name) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
        key,
        serialized,
        nowIso
      );
      changeEvent = {
        source: 'system',
        canonicalKey: null,
        key,
        oldValue,
        value: parseSystemConfigJson(serialized),
        synced: false,
        origin: { key },
        ts: nowIso,
      };
    });

    if (changeEvent) {
      this._emitConfigChanged(changeEvent);
    }

    return changeEvent.value;
  }

  _systemGetAll() {
    const db = this._requireStorage();
    const rows = db.all('SELECT key_name, value_json FROM system_config ORDER BY key_name ASC');
    const out = {};
    for (const k of CANONICAL_SYSTEM_KEYS) {
      defineSafeProp(out, k, SYSTEM_SYNC_MAP[k].defaultValue);
    }
    for (const row of rows) {
      defineSafeProp(out, row.key_name, parseSystemConfigJson(row.value_json));
    }
    return out;
  }
}

export function createUnifiedConfigStore(options = {}) {
  return new UnifiedConfigStore(options);
}

export function createConfigService(configStore, opts = {}) {
  if (!configStore || typeof configStore !== 'object') {
    throw new OmniOSError('Invalid createConfigService configStore dependency: expected object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  try {
    if (typeof configStore.init !== 'function') {
      throw new OmniOSError('Invalid createConfigService configStore dependency: missing init()', {
        code: ERROR_CODES.EINVAL,
      });
    }
  } catch (err) {
    if (err instanceof OmniOSError) throw err;
    throw new OmniOSError('Unreadable createConfigService configStore dependency', {
      code: ERROR_CODES.EINVAL,
    });
  }

  let kernel = null;
  let getStorage = null;
  let deps = [];
  let essential = true;
  let description =
    'Unified Config Store, Windows Registry, Apple Defaults & Android SharedPreferences Daemon';
  if (opts !== null && opts !== undefined) {
    if (typeof opts !== 'object') {
      throw new OmniOSError('Invalid createConfigService options: expected object', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      if (opts.kernel !== undefined) kernel = opts.kernel;
      if (opts.getStorage !== undefined) getStorage = opts.getStorage;
      if (opts.deps !== undefined) deps = opts.deps;
      if (opts.essential !== undefined) essential = opts.essential;
      if (opts.description !== undefined) description = opts.description;
    } catch {
      throw new OmniOSError('Unreadable createConfigService options', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  if (kernel !== null && kernel !== undefined) {
    if (typeof kernel !== 'object') {
      throw new OmniOSError('Invalid createConfigService kernel dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      void kernel.storage;
    } catch {
      throw new OmniOSError('Unreadable createConfigService kernel dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  if (getStorage !== null && getStorage !== undefined) {
    if (typeof getStorage !== 'function') {
      throw new OmniOSError('Invalid createConfigService getStorage dependency: expected function', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      void getStorage.length;
    } catch {
      throw new OmniOSError('Unreadable createConfigService getStorage dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  let running = false;
  return {
    name: 'configd',
    deps,
    essential,
    description,
    start() {
      let storage = null;
      try {
        storage = getStorage ? getStorage() : (kernel?.storage ?? null);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError('Unreadable storage dependency in configd.start()', {
          code: ERROR_CODES.EINVAL,
        });
      }
      try {
        configStore.init(storage);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new OmniOSError('Failed to start configd: unreadable configStore dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
      running = true;
    },
    stop() {
      running = false;
      // NEVER close shared kernel.storage!
    },
    healthCheck() {
      try {
        if (!running || !configStore.isReady()) {
          return { ok: false, reason: 'configd not running or SQLite storage closed' };
        }
        configStore.system.get('system.theme');
        return { ok: true };
      } catch {
        return { ok: false, reason: 'configd health check failed' };
      }
    },
  };
}

export function registerConfigService(serviceManager, configStore, options = {}) {
  if (!serviceManager || typeof serviceManager !== 'object') {
    throw new OmniOSError('Invalid registerConfigService serviceManager: expected object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  let registerFn;
  try {
    registerFn = serviceManager.register;
  } catch {
    throw new OmniOSError('Unreadable registerConfigService serviceManager', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (typeof registerFn !== 'function') {
    throw new OmniOSError('Invalid registerConfigService serviceManager: missing register()', {
      code: ERROR_CODES.EINVAL,
    });
  }
  return registerFn.call(serviceManager, createConfigService(configStore, options));
}

export function registerConfigSyscalls(syscalls, configStore) {
  if (!syscalls || typeof syscalls !== 'object') {
    throw new OmniOSError('Invalid registerConfigSyscalls syscalls: expected object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  let registerFn;
  try {
    registerFn = syscalls.register;
  } catch {
    throw new OmniOSError('Unreadable registerConfigSyscalls syscalls', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (typeof registerFn !== 'function') {
    throw new OmniOSError('Invalid registerConfigSyscalls syscalls: missing register()', {
      code: ERROR_CODES.EINVAL,
    });
  }

  if (!configStore || typeof configStore !== 'object') {
    throw new OmniOSError('Invalid registerConfigSyscalls configStore: expected object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  try {
    if (
      !configStore.system ||
      typeof configStore.system !== 'object' ||
      typeof configStore.system.get !== 'function' ||
      typeof configStore.system.set !== 'function' ||
      !configStore.registry ||
      typeof configStore.registry !== 'object' ||
      typeof configStore.registry.getValue !== 'function' ||
      typeof configStore.registry.setValue !== 'function' ||
      !configStore.defaults ||
      typeof configStore.defaults !== 'object' ||
      typeof configStore.defaults.get !== 'function' ||
      typeof configStore.defaults.set !== 'function' ||
      !configStore.sharedPrefs ||
      typeof configStore.sharedPrefs !== 'object' ||
      typeof configStore.sharedPrefs.get !== 'function' ||
      typeof configStore.sharedPrefs.edit !== 'function'
    ) {
      throw new OmniOSError(
        'Invalid registerConfigSyscalls configStore: missing system/registry/defaults/sharedPrefs facades',
        { code: ERROR_CODES.EINVAL }
      );
    }
  } catch (err) {
    if (err instanceof OmniOSError) throw err;
    throw new OmniOSError('Unreadable registerConfigSyscalls configStore', {
      code: ERROR_CODES.EINVAL,
    });
  }

  const invokeConfig = (fn) => {
    try {
      return fn();
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new OmniOSError('Unreadable configStore dependency in config syscall handler', {
        code: ERROR_CODES.EINVAL,
      });
    }
  };

  try {
    registerFn.call(syscalls, 'config.get', (_ctx, key) =>
      invokeConfig(() => configStore.system.get(key))
    );
    registerFn.call(syscalls, 'config.set', (_ctx, key, value) =>
      invokeConfig(() => configStore.system.set(key, value))
    );
    registerFn.call(syscalls, 'reg.get', (ctx, hive, keyPath, valueName) =>
      invokeConfig(() => configStore.registry.getValue(hive, keyPath, valueName, ctx))
    );
    registerFn.call(syscalls, 'reg.set', (ctx, hive, keyPath, valueName, type, data) =>
      invokeConfig(() => configStore.registry.setValue(hive, keyPath, valueName, type, data, ctx))
    );
    registerFn.call(syscalls, 'defaults.get', (ctx, domain, key) =>
      invokeConfig(() => configStore.defaults.get(domain, key, ctx))
    );
    registerFn.call(syscalls, 'defaults.set', (ctx, domain, key, value) =>
      invokeConfig(() => configStore.defaults.set(domain, key, value, ctx))
    );
    registerFn.call(syscalls, 'prefs.get', (ctx, pkg, pref, key, defVal = null) =>
      invokeConfig(() => configStore.sharedPrefs.get(pkg, pref, key, defVal, ctx))
    );
    registerFn.call(syscalls, 'prefs.edit', (ctx, pkg, pref, ops) =>
      invokeConfig(() => configStore.sharedPrefs.edit(pkg, pref, ops, ctx))
    );
  } catch (err) {
    if (err instanceof OmniOSError) throw err;
    throw new OmniOSError('Failed to register config syscalls: unreadable syscalls dispatcher', {
      code: ERROR_CODES.EINVAL,
    });
  }
}
