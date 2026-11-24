/**
 * OmniOS Security — Unified Permission Broker & Persistent SQLite Audit Log (F-028)
 * Maps Android runtime permissions, iOS TCC, macOS Gatekeeper/entitlements, Windows UAC/MSIX,
 * and WASI/OmniOS rights into 14 canonical capabilities with fail-closed policy enforcement.
 */

import crypto from 'node:crypto';
import { types } from 'node:util';
import { SqliteStorage } from '../common/storage-sqlite.mjs';
import { OmniOSError, SecurityError, ERROR_CODES } from '../common/errors.mjs';

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
const DATE_GET_TIME = Date.prototype.getTime;
const DATE_TO_ISO_STRING = Date.prototype.toISOString;

function isGenuineArrayBuffer(value) {
  return types.isArrayBuffer(value) && !types.isProxy(value);
}

function isGenuineBinaryView(value) {
  return (types.isTypedArray(value) || types.isDataView(value)) && !types.isProxy(value);
}

function isGenuineDate(value) {
  return types.isDate(value) && !types.isProxy(value);
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

function isSpoofedOrUnreadableBuiltin(value) {
  if (types.isProxy(value)) return true;
  if (types.isSharedArrayBuffer(value)) return true;
  if (types.isBoxedPrimitive(value)) return true;
  const proto = Object.getPrototypeOf(value);
  if (proto === Object.prototype || proto === null) {
    return false;
  }
  try {
    if (value instanceof ArrayBuffer) return true;
  } catch {
    return true;
  }
  try {
    if (value instanceof Date) return true;
  } catch {
    return true;
  }
  try {
    if (value instanceof TYPED_ARRAY_CTOR || value instanceof DataView || ArrayBuffer.isView(value)) {
      return true;
    }
  } catch {
    return true;
  }
  if (typeof SharedArrayBuffer === 'function') {
    try {
      if (value instanceof SharedArrayBuffer) return true;
    } catch {
      return true;
    }
  }
  return false;
}

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

export const CAPABILITIES = freezeLookup({
  FS_READ_USER: 'fs.read.user',
  FS_WRITE_USER: 'fs.write.user',
  FS_READ_SYSTEM: 'fs.read.system',
  FS_WRITE_SYSTEM: 'fs.write.system',
  NETWORK_OUTBOUND: 'network.outbound',
  CLIPBOARD_READ: 'clipboard.read',
  CLIPBOARD_WRITE: 'clipboard.write',
  NOTIFICATIONS_POST: 'notifications.post',
  IPC_BROADCAST: 'ipc.broadcast',
  PROCESS_SPAWN: 'process.spawn',
  REGISTRY_SYSTEM_WRITE: 'registry.system.write',
  CAMERA_DEVICE: 'camera.device',
  LOCATION_DEVICE: 'location.device',
  UI_WINDOW: 'ui.window',
});

export const ALL_CAPABILITIES = Object.freeze([
  CAPABILITIES.FS_READ_USER,
  CAPABILITIES.FS_WRITE_USER,
  CAPABILITIES.FS_READ_SYSTEM,
  CAPABILITIES.FS_WRITE_SYSTEM,
  CAPABILITIES.NETWORK_OUTBOUND,
  CAPABILITIES.CLIPBOARD_READ,
  CAPABILITIES.CLIPBOARD_WRITE,
  CAPABILITIES.NOTIFICATIONS_POST,
  CAPABILITIES.IPC_BROADCAST,
  CAPABILITIES.PROCESS_SPAWN,
  CAPABILITIES.REGISTRY_SYSTEM_WRITE,
  CAPABILITIES.CAMERA_DEVICE,
  CAPABILITIES.LOCATION_DEVICE,
  CAPABILITIES.UI_WINDOW,
]);

const CAPABILITY_SET = new Set(ALL_CAPABILITIES);

export const PERMISSION_STATES = freezeLookup({
  ALLOW: 'allow',
  DENY: 'deny',
  PROMPT: 'prompt',
});

const VALID_STATES = new Set([
  PERMISSION_STATES.ALLOW,
  PERMISSION_STATES.DENY,
  PERMISSION_STATES.PROMPT,
]);

export const DEFAULT_CAPABILITY_POLICIES = freezeLookup({
  [CAPABILITIES.UI_WINDOW]: PERMISSION_STATES.ALLOW,
  [CAPABILITIES.FS_READ_SYSTEM]: PERMISSION_STATES.ALLOW,
  [CAPABILITIES.CLIPBOARD_WRITE]: PERMISSION_STATES.ALLOW,
  [CAPABILITIES.IPC_BROADCAST]: PERMISSION_STATES.ALLOW,
  [CAPABILITIES.NETWORK_OUTBOUND]: PERMISSION_STATES.ALLOW,

  [CAPABILITIES.FS_READ_USER]: PERMISSION_STATES.PROMPT,
  [CAPABILITIES.FS_WRITE_USER]: PERMISSION_STATES.PROMPT,
  [CAPABILITIES.CLIPBOARD_READ]: PERMISSION_STATES.PROMPT,
  [CAPABILITIES.NOTIFICATIONS_POST]: PERMISSION_STATES.PROMPT,
  [CAPABILITIES.CAMERA_DEVICE]: PERMISSION_STATES.PROMPT,
  [CAPABILITIES.LOCATION_DEVICE]: PERMISSION_STATES.PROMPT,
  [CAPABILITIES.PROCESS_SPAWN]: PERMISSION_STATES.PROMPT,

  [CAPABILITIES.FS_WRITE_SYSTEM]: PERMISSION_STATES.DENY,
  [CAPABILITIES.REGISTRY_SYSTEM_WRITE]: PERMISSION_STATES.DENY,
});

export const ANDROID_PERMISSION_MAP = freezeLookup({
  'android.permission.READ_EXTERNAL_STORAGE': CAPABILITIES.FS_READ_USER,
  'android.permission.READ_MEDIA_IMAGES': CAPABILITIES.FS_READ_USER,
  'android.permission.READ_MEDIA_VIDEO': CAPABILITIES.FS_READ_USER,
  'android.permission.READ_MEDIA_AUDIO': CAPABILITIES.FS_READ_USER,
  'android.permission.WRITE_EXTERNAL_STORAGE': CAPABILITIES.FS_WRITE_USER,
  'android.permission.MANAGE_EXTERNAL_STORAGE': CAPABILITIES.FS_WRITE_USER,
  'android.permission.READ_SYSTEM_FILES': CAPABILITIES.FS_READ_SYSTEM,
  'android.permission.MOUNT_UNMOUNT_FILESYSTEMS': CAPABILITIES.FS_WRITE_SYSTEM,
  'android.permission.WRITE_SYSTEM_FILES': CAPABILITIES.FS_WRITE_SYSTEM,
  'android.permission.INTERNET': CAPABILITIES.NETWORK_OUTBOUND,
  'android.permission.ACCESS_NETWORK_STATE': CAPABILITIES.NETWORK_OUTBOUND,
  'android.permission.CHANGE_NETWORK_STATE': CAPABILITIES.NETWORK_OUTBOUND,
  'android.permission.READ_CLIPBOARD': CAPABILITIES.CLIPBOARD_READ,
  'android.permission.WRITE_CLIPBOARD': CAPABILITIES.CLIPBOARD_WRITE,
  'android.permission.POST_NOTIFICATIONS': CAPABILITIES.NOTIFICATIONS_POST,
  'android.permission.BROADCAST_STICKY': CAPABILITIES.IPC_BROADCAST,
  'android.permission.SEND_BROADCAST': CAPABILITIES.IPC_BROADCAST,
  'android.permission.EXEC_PROCESS': CAPABILITIES.PROCESS_SPAWN,
  'android.permission.RUN_USER_INITIATED_JOBS': CAPABILITIES.PROCESS_SPAWN,
  'android.permission.WRITE_SETTINGS': CAPABILITIES.REGISTRY_SYSTEM_WRITE,
  'android.permission.WRITE_SECURE_SETTINGS': CAPABILITIES.REGISTRY_SYSTEM_WRITE,
  'android.permission.CAMERA': CAPABILITIES.CAMERA_DEVICE,
  'android.permission.ACCESS_FINE_LOCATION': CAPABILITIES.LOCATION_DEVICE,
  'android.permission.ACCESS_COARSE_LOCATION': CAPABILITIES.LOCATION_DEVICE,
  'android.permission.ACCESS_BACKGROUND_LOCATION': CAPABILITIES.LOCATION_DEVICE,
  'android.permission.SYSTEM_ALERT_WINDOW': CAPABILITIES.UI_WINDOW,
});

export const IOS_TCC_PERMISSION_MAP = freezeLookup({
  kTCCServiceCamera: CAPABILITIES.CAMERA_DEVICE,
  NSCameraUsageDescription: CAPABILITIES.CAMERA_DEVICE,
  kTCCServiceLocation: CAPABILITIES.LOCATION_DEVICE,
  NSLocationWhenInUseUsageDescription: CAPABILITIES.LOCATION_DEVICE,
  NSLocationAlwaysUsageDescription: CAPABILITIES.LOCATION_DEVICE,
  NSLocationAlwaysAndWhenInUseUsageDescription: CAPABILITIES.LOCATION_DEVICE,
  kTCCServicePhotos: CAPABILITIES.FS_READ_USER,
  NSPhotoLibraryUsageDescription: CAPABILITIES.FS_READ_USER,
  kTCCServiceSystemPolicyDocumentsFolder: CAPABILITIES.FS_READ_USER,
  NSDocumentsFolderUsageDescription: CAPABILITIES.FS_READ_USER,
  kTCCServiceSystemPolicyDownloadsFolder: CAPABILITIES.FS_READ_USER,
  NSDownloadsFolderUsageDescription: CAPABILITIES.FS_READ_USER,
  kTCCServiceSystemPolicyDesktopFolder: CAPABILITIES.FS_READ_USER,
  NSDesktopFolderUsageDescription: CAPABILITIES.FS_READ_USER,
  kTCCServicePhotosAdd: CAPABILITIES.FS_WRITE_USER,
  NSPhotoLibraryAddUsageDescription: CAPABILITIES.FS_WRITE_USER,
  kTCCServiceSystemPolicyDocumentsFolderWrite: CAPABILITIES.FS_WRITE_USER,
  kTCCServiceSystemPolicyAllFiles: CAPABILITIES.FS_READ_SYSTEM,
  kTCCServiceSystemPolicySysAdminFiles: CAPABILITIES.FS_WRITE_SYSTEM,
  kTCCServicePasteboard: CAPABILITIES.CLIPBOARD_READ,
  UIPasteboard: CAPABILITIES.CLIPBOARD_READ,
  kTCCServicePasteboardWrite: CAPABILITIES.CLIPBOARD_WRITE,
  kTCCServiceUserNotifications: CAPABILITIES.NOTIFICATIONS_POST,
  UNUserNotificationCenter: CAPABILITIES.NOTIFICATIONS_POST,
  kTCCServiceNetwork: CAPABILITIES.NETWORK_OUTBOUND,
  NSLocalNetworkUsageDescription: CAPABILITIES.NETWORK_OUTBOUND,
  kTCCServiceAppleEvents: CAPABILITIES.IPC_BROADCAST,
  UIWindow: CAPABILITIES.UI_WINDOW,
});

export const MACOS_ENTITLEMENT_MAP = freezeLookup({
  'com.apple.security.files.user-selected.read-only': CAPABILITIES.FS_READ_USER,
  'com.apple.security.files.downloads.read-only': CAPABILITIES.FS_READ_USER,
  'com.apple.security.assets.pictures.read-only': CAPABILITIES.FS_READ_USER,
  'com.apple.security.files.user-selected.read-write': CAPABILITIES.FS_WRITE_USER,
  'com.apple.security.files.downloads.read-write': CAPABILITIES.FS_WRITE_USER,
  'com.apple.security.assets.pictures.read-write': CAPABILITIES.FS_WRITE_USER,
  'com.apple.security.temporary-exception.files.absolute-path.read-only': CAPABILITIES.FS_READ_SYSTEM,
  'com.apple.security.temporary-exception.files.absolute-path.read-write': CAPABILITIES.FS_WRITE_SYSTEM,
  'com.apple.security.network.client': CAPABILITIES.NETWORK_OUTBOUND,
  'com.apple.security.network.server': CAPABILITIES.NETWORK_OUTBOUND,
  'com.apple.security.device.camera': CAPABILITIES.CAMERA_DEVICE,
  'com.apple.security.personal-information.location': CAPABILITIES.LOCATION_DEVICE,
  'com.apple.security.automation.apple-events': CAPABILITIES.IPC_BROADCAST,
  'com.apple.security.cs.allow-unsigned-executable-memory': CAPABILITIES.PROCESS_SPAWN,
  'com.apple.security.inherit': CAPABILITIES.PROCESS_SPAWN,
  'com.apple.security.gatekeeper.unidentified-developer': CAPABILITIES.PROCESS_SPAWN,
  'com.apple.security.gatekeeper.quarantine': CAPABILITIES.PROCESS_SPAWN,
  'com.apple.developer.usernotifications': CAPABILITIES.NOTIFICATIONS_POST,
  'com.apple.security.system-configuration': CAPABILITIES.REGISTRY_SYSTEM_WRITE,
  'com.apple.security.clipboard.read': CAPABILITIES.CLIPBOARD_READ,
  'com.apple.security.clipboard.write': CAPABILITIES.CLIPBOARD_WRITE,
  'com.apple.security.ui.window': CAPABILITIES.UI_WINDOW,
});

export const WINDOWS_UAC_PERMISSION_MAP = freezeLookup({
  asInvoker: CAPABILITIES.UI_WINDOW,
  highestAvailable: CAPABILITIES.FS_WRITE_SYSTEM,
  requireAdministrator: CAPABILITIES.REGISTRY_SYSTEM_WRITE,
  internetClient: CAPABILITIES.NETWORK_OUTBOUND,
  internetClientServer: CAPABILITIES.NETWORK_OUTBOUND,
  privateNetworkClientServer: CAPABILITIES.NETWORK_OUTBOUND,
  documentsLibrary: CAPABILITIES.FS_READ_USER,
  picturesLibrary: CAPABILITIES.FS_READ_USER,
  broadFileSystemAccess: CAPABILITIES.FS_READ_USER,
  documentsLibraryWrite: CAPABILITIES.FS_WRITE_USER,
  removableStorage: CAPABILITIES.FS_WRITE_USER,
  systemFilesRead: CAPABILITIES.FS_READ_SYSTEM,
  webcam: CAPABILITIES.CAMERA_DEVICE,
  location: CAPABILITIES.LOCATION_DEVICE,
  runFullTrust: CAPABILITIES.PROCESS_SPAWN,
  toastNotifications: CAPABILITIES.NOTIFICATIONS_POST,
  clipboardRead: CAPABILITIES.CLIPBOARD_READ,
  clipboardWrite: CAPABILITIES.CLIPBOARD_WRITE,
  appBroadcast: CAPABILITIES.IPC_BROADCAST,
});

const WINDOWS_MULTI_CAPS = freezeLookup({
  requireAdministrator: Object.freeze([
    CAPABILITIES.REGISTRY_SYSTEM_WRITE,
    CAPABILITIES.FS_WRITE_SYSTEM,
  ]),
});

export const WASI_RIGHTS_PERMISSION_MAP = freezeLookup({
  RIGHT_FD_READ: CAPABILITIES.FS_READ_USER,
  'wasi:fd_read': CAPABILITIES.FS_READ_USER,
  'wasi:path_open_read': CAPABILITIES.FS_READ_USER,
  RIGHT_FD_WRITE: CAPABILITIES.FS_WRITE_USER,
  'wasi:fd_write': CAPABILITIES.FS_WRITE_USER,
  'wasi:path_create_file': CAPABILITIES.FS_WRITE_USER,
  'wasi:system_read': CAPABILITIES.FS_READ_SYSTEM,
  'wasi:system_write': CAPABILITIES.FS_WRITE_SYSTEM,
  RIGHT_SOCK_SHUTDOWN: CAPABILITIES.NETWORK_OUTBOUND,
  'wasi:sock_connect': CAPABILITIES.NETWORK_OUTBOUND,
  'wasi:network': CAPABILITIES.NETWORK_OUTBOUND,
  'wasi:proc_spawn': CAPABILITIES.PROCESS_SPAWN,
  'omni:ui.window': CAPABILITIES.UI_WINDOW,
  'omni:clipboard.read': CAPABILITIES.CLIPBOARD_READ,
  'omni:clipboard.write': CAPABILITIES.CLIPBOARD_WRITE,
  'omni:notifications.post': CAPABILITIES.NOTIFICATIONS_POST,
  'omni:ipc.broadcast': CAPABILITIES.IPC_BROADCAST,
  'omni:camera.device': CAPABILITIES.CAMERA_DEVICE,
  'omni:location.device': CAPABILITIES.LOCATION_DEVICE,
  'omni:registry.system.write': CAPABILITIES.REGISTRY_SYSTEM_WRITE,
});

export const NATIVE_PERMISSION_MAPS = freezeLookup({
  android: ANDROID_PERMISSION_MAP,
  ios: IOS_TCC_PERMISSION_MAP,
  macos: MACOS_ENTITLEMENT_MAP,
  windows: WINDOWS_UAC_PERMISSION_MAP,
  wasi: WASI_RIGHTS_PERMISSION_MAP,
  universal: WASI_RIGHTS_PERMISSION_MAP,
});

const ALL_NATIVE_MAP_LIST = Object.freeze([
  ANDROID_PERMISSION_MAP,
  IOS_TCC_PERMISSION_MAP,
  MACOS_ENTITLEMENT_MAP,
  WINDOWS_UAC_PERMISSION_MAP,
  WASI_RIGHTS_PERMISSION_MAP,
]);

export const PERMISSION_MIGRATIONS = Object.freeze([
  Object.freeze({
    version: 1,
    name: 'security_permissions_initial',
    sql: `
      CREATE TABLE IF NOT EXISTS permission_grants (
        app_id TEXT NOT NULL,
        capability TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('allow', 'deny', 'prompt')),
        source TEXT NOT NULL DEFAULT 'user',
        updated_at TEXT NOT NULL,
        PRIMARY KEY (app_id, capability)
      );

      CREATE TABLE IF NOT EXISTS security_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        app_id TEXT NOT NULL,
        pid INTEGER,
        platform TEXT NOT NULL,
        capability TEXT,
        native_permission TEXT,
        policy TEXT NOT NULL,
        granted INTEGER NOT NULL,
        reason TEXT NOT NULL,
        context_json TEXT NOT NULL DEFAULT '{}'
      );

      CREATE INDEX IF NOT EXISTS idx_security_audit_app_id ON security_audit(app_id, id DESC);
      CREATE INDEX IF NOT EXISTS idx_security_audit_id ON security_audit(id DESC);
    `,
  }),
]);

const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;
const MAX_NATIVE_PERMISSION_LIST = 65536;
const MAX_NATIVE_PERMISSION_BYTES = 1 * 1024 * 1024;
const MAX_NATIVE_PERMISSION_ENTRY_CHARS = 512;

const MAX_AUDIT_CONTEXT_NODES = 2048;
const MAX_AUDIT_BINARY_BYTES = 16384;
const MAX_AUDIT_CONTEXT_BYTES = 65536;
const MAX_AUDIT_STRING_CHARS = 4096;
const MAX_SAFE_STRING_CHARS = 512;
const MAX_AUDIT_BIGINT_ABS = 1n << 65536n;
const MIN_AUDIT_BIGINT_NEG = -MAX_AUDIT_BIGINT_ABS;
const MAX_DISPLAY_BIGINT_ABS = 1n << 4096n;
const MIN_DISPLAY_BIGINT_NEG = -MAX_DISPLAY_BIGINT_ABS;
const MAX_TIMEOUT_MS = 2_147_483_647;
const DEFAULT_HEADLESS_PROMPT_TIMEOUT_MS = 2500;
const DEFAULT_INTERACTIVE_PROMPT_TIMEOUT_MS = 15000;
const SYMBOL_DESCRIPTION_GET =
  Object.getOwnPropertyDescriptor(Symbol.prototype, 'description')?.get ?? null;

function safeString(value, fallback = '[Unreadable]', maxLen = MAX_SAFE_STRING_CHARS) {
  if (typeof value === 'string') {
    return value.length > maxLen ? `${value.slice(0, maxLen)}...[Truncated]` : value;
  }
  if (value === null || value === undefined) return '';
  const t = typeof value;
  if (t === 'number' || t === 'boolean') return String(value);
  if (t === 'bigint') {
    if (value > MAX_DISPLAY_BIGINT_ABS || value < MIN_DISPLAY_BIGINT_NEG) {
      return '[BigInt(Truncated)]';
    }
    const str = value.toString(10);
    return str.length > maxLen ? `${str.slice(0, maxLen)}...[Truncated]` : str;
  }
  if (t === 'symbol') {
    try {
      const desc = SYMBOL_DESCRIPTION_GET ? SYMBOL_DESCRIPTION_GET.call(value) : undefined;
      if (typeof desc === 'string') {
        const innerMax = Math.max(0, maxLen - 8);
        const capped = desc.length > innerMax ? `${desc.slice(0, innerMax)}...[Truncated]` : desc;
        return `Symbol(${capped})`;
      }
      return 'Symbol()';
    } catch (_err) {
      return fallback;
    }
  }
  if (t === 'function') return '[Function]';
  if (t === 'object') {
    try {
      if (Array.isArray(value)) return '[Array]';
    } catch (_err) {
      return fallback;
    }
    return '[Object]';
  }
  return fallback;
}

function safeNullableString(value, fallback = '[Unreadable]') {
  if (value === null || value === undefined) return null;
  return safeString(value, fallback);
}

function sanitizeReason(reason, defaultReason = 'unknown') {
  if (reason === null || reason === undefined) return defaultReason;
  const str = safeString(reason, '[Unreadable]');
  return str.length > 0 ? str : defaultReason;
}

function assertValidAppId(appId) {
  if (typeof appId !== 'string' || appId.length === 0 || appId.length > 256 || CONTROL_CHAR_RE.test(appId)) {
    throw new SecurityError('Invalid appId: must be a non-empty string without control characters', {
      code: ERROR_CODES.EINVAL,
    });
  }
  return appId;
}

function assertValidCapability(capability) {
  if (typeof capability !== 'string' || capability.length > 64 || !CAPABILITY_SET.has(capability)) {
    throw new SecurityError(`Unknown capability: ${safeString(capability)}`, {
      code: ERROR_CODES.EINVAL,
      capability: typeof capability === 'string' ? safeString(capability) : null,
    });
  }
  return capability;
}

function assertValidState(state) {
  if (typeof state !== 'string' || state.length > 16 || !VALID_STATES.has(state)) {
    throw new SecurityError(`Invalid permission state: ${safeString(state)}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  return state;
}

/**
 * Safely converts arbitrary/hostile objects (BigInt, circular refs, DAGs, throwing getters,
 * Proxies, Date(NaN), Uint8Array, boxed primitives, prototype keys) into a bounded JSON-safe structure.
 */
function safeJsonClone(value, depth = 0, seen = new Set(), budget = { count: 0, bytes: 0 }) {
  if (value !== null && typeof value === 'object' && seen.has(value)) {
    return '[Circular]';
  }
  if (budget.count >= MAX_AUDIT_CONTEXT_NODES || budget.bytes >= MAX_AUDIT_CONTEXT_BYTES) {
    return '[Truncated]';
  }
  budget.count += 1;
  budget.bytes += 4;

  if (value === null || value === undefined) return null;
  const t = typeof value;
  if (t === 'boolean') return value;
  if (t === 'string') {
    const remaining = Math.max(0, MAX_AUDIT_CONTEXT_BYTES - budget.bytes);
    const allowed = Math.min(MAX_AUDIT_STRING_CHARS, remaining);
    if (value.length > allowed) {
      budget.bytes = Math.min(MAX_AUDIT_CONTEXT_BYTES, budget.bytes + allowed + 14);
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
    if (value > MAX_AUDIT_BIGINT_ABS || value < MIN_AUDIT_BIGINT_NEG) {
      budget.bytes += 24;
      return '[BigInt(Truncated)]';
    }
    const str = value.toString(10);
    const remaining = Math.max(0, MAX_AUDIT_CONTEXT_BYTES - budget.bytes);
    const allowed = Math.min(MAX_AUDIT_STRING_CHARS, remaining);
    if (str.length > allowed) {
      budget.bytes = Math.min(MAX_AUDIT_CONTEXT_BYTES, budget.bytes + allowed + 14);
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

  let isArr = false;
  try {
    isArr = Array.isArray(value);
  } catch {
    return '[UnreadableObject]';
  }

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
        if (byteLength > MAX_AUDIT_BINARY_BYTES || budget.bytes + b64Len > MAX_AUDIT_CONTEXT_BYTES) {
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
        if (byteLength > MAX_AUDIT_BINARY_BYTES || budget.bytes + b64Len > MAX_AUDIT_CONTEXT_BYTES) {
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

    if (isSpoofedOrUnreadableBuiltin(value)) {
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
        return '[UnreadableArray]';
      }
      if (typeof rawLen !== 'number' || !Number.isSafeInteger(rawLen) || rawLen < 0 || rawLen > 0xffffffff) {
        return '[UnreadableArray]';
      }
      const len = Math.min(rawLen, 256);
      const out = [];
      let truncatedPushed = false;
      for (let i = 0; i < len; i += 1) {
        let item;
        try {
          item = value[i];
        } catch {
          item = '[Unreadable]';
        }
        if (item !== null && typeof item === 'object' && seen.has(item)) {
          out.push('[Circular]');
          continue;
        }
        if (budget.count >= MAX_AUDIT_CONTEXT_NODES || budget.bytes >= MAX_AUDIT_CONTEXT_BYTES) {
          if (!truncatedPushed) {
            out.push('[Truncated]');
            truncatedPushed = true;
          }
          continue;
        }
        out.push(safeJsonClone(item, depth + 1, seen, budget));
      }
      return out;
    }

    const out = {};
    let keys;
    try {
      keys = Object.keys(value);
    } catch {
      return '[UnreadableObject]';
    }
    const maxKeys = Math.min(keys.length, 256);
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
      if (budget.count >= MAX_AUDIT_CONTEXT_NODES || budget.bytes >= MAX_AUDIT_CONTEXT_BYTES) {
        if (!truncatedAdded) {
          truncatedAdded = true;
          if (!Object.prototype.hasOwnProperty.call(out, '__truncated__')) {
            defineSafeProp(out, '__truncated__', '[Truncated]');
          }
        }
        continue;
      }
      const remaining = Math.max(0, MAX_AUDIT_CONTEXT_BYTES - budget.bytes);
      const allowedKeyLen = Math.min(MAX_AUDIT_STRING_CHARS, remaining);
      const safeKey = k.length > allowedKeyLen ? `${k.slice(0, allowedKeyLen)}...[Truncated]` : k;
      budget.bytes += safeKey.length + 4;
      defineSafeProp(out, safeKey, safeJsonClone(v, depth + 1, seen, budget));
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

function safeJsonStringify(value) {
  try {
    const cleaned = value === null || value === undefined ? {} : safeJsonClone(value);
    const out = JSON.stringify(cleaned);
    return typeof out === 'string' ? out : '"[Unserializable]"';
  } catch (_err) {
    return '"[Unserializable]"';
  }
}

function parseSanitizedContextJson(contextJson) {
  if (typeof contextJson !== 'string' || contextJson.length === 0) {
    return {};
  }
  try {
    return JSON.parse(contextJson);
  } catch (_err) {
    return {};
  }
}

function clonePromptPayload(entry) {
  return {
    promptId: entry.promptId,
    appId: entry.appId,
    pid: entry.pid,
    platform: entry.platform,
    capability: entry.capability,
    nativePermission: entry.nativePermission,
    context: parseSanitizedContextJson(entry.contextJson),
    createdAt: entry.createdAt,
  };
}

/**
 * Maps a single native platform permission / entitlement / TCC service / UAC level / WASI right
 * to its canonical OmniOS capability string, or `null` if unmapped.
 */
export function mapNativePermission(nativePermission, platform = null) {
  if (
    typeof nativePermission !== 'string' ||
    nativePermission.length === 0 ||
    nativePermission.length > MAX_NATIVE_PERMISSION_ENTRY_CHARS
  ) {
    return null;
  }
  const trimmed = nativePermission.trim();
  if (trimmed.length === 0) return null;

  if (platform !== null && platform !== undefined && platform !== '') {
    const plat = safeString(platform, '', 64).trim().toLowerCase();
    const map = NATIVE_PERMISSION_MAPS[plat];
    if (map) {
      if (Object.prototype.hasOwnProperty.call(map, trimmed)) {
        return map[trimmed];
      }
      if (plat === 'android' && !trimmed.startsWith('android.permission.')) {
        const prefixed = `android.permission.${trimmed}`;
        if (Object.prototype.hasOwnProperty.call(ANDROID_PERMISSION_MAP, prefixed)) {
          return ANDROID_PERMISSION_MAP[prefixed];
        }
      }
      return null;
    }
    return null;
  }

  for (const map of ALL_NATIVE_MAP_LIST) {
    if (Object.prototype.hasOwnProperty.call(map, trimmed)) {
      return map[trimmed];
    }
  }
  const androidPrefixed = `android.permission.${trimmed}`;
  if (Object.prototype.hasOwnProperty.call(ANDROID_PERMISSION_MAP, androidPrefixed)) {
    return ANDROID_PERMISSION_MAP[androidPrefixed];
  }
  return null;
}

/**
 * Maps a list of native permissions into deduplicated canonical capabilities + unmapped list + details.
 */
export function mapNativePermissions(nativeList, platform = null) {
  let isArr = false;
  try {
    isArr = Array.isArray(nativeList);
  } catch (_err) {
    throw new SecurityError('nativeList must be a readable array', { code: ERROR_CODES.EINVAL });
  }
  if (!isArr) {
    throw new SecurityError('nativeList must be an array', { code: ERROR_CODES.EINVAL });
  }

  let len;
  try {
    len = nativeList.length;
  } catch (_err) {
    throw new SecurityError('nativeList.length is unreadable', { code: ERROR_CODES.EINVAL });
  }
  if (
    typeof len !== 'number' ||
    !Number.isSafeInteger(len) ||
    len < 0 ||
    len > MAX_NATIVE_PERMISSION_LIST
  ) {
    throw new SecurityError('Invalid nativeList length', { code: ERROR_CODES.EINVAL });
  }

  const capSet = new Set();
  const unmapped = [];
  const mappings = [];
  const plat =
    platform !== null && platform !== undefined && platform !== ''
      ? safeString(platform, '', 64).trim().toLowerCase()
      : null;

  let cumulativeBytes = 0;

  for (let i = 0; i < len; i += 1) {
    let raw;
    let unreadableElement = false;
    try {
      raw = nativeList[i];
    } catch (_err) {
      unreadableElement = true;
      raw = null;
    }

    let native;
    let mapped = null;
    if (unreadableElement) {
      native = '[Unreadable]';
    } else if (typeof raw === 'string') {
      if (raw.length > MAX_NATIVE_PERMISSION_ENTRY_CHARS) {
        native = `${raw.slice(0, MAX_NATIVE_PERMISSION_ENTRY_CHARS)}...[Truncated]`;
        mapped = null;
      } else {
        native = raw.trim();
        mapped = mapNativePermission(native, plat);
      }
    } else {
      native = safeString(raw, '[Unreadable]', MAX_NATIVE_PERMISSION_ENTRY_CHARS);
    }

    cumulativeBytes += native.length + 64;
    if (cumulativeBytes > MAX_NATIVE_PERMISSION_BYTES) {
      throw new SecurityError(
        `nativeList exceeds maximum cumulative size (${MAX_NATIVE_PERMISSION_BYTES} bytes)`,
        { code: ERROR_CODES.EINVAL }
      );
    }

    mappings.push({ native, capability: mapped });
    if (mapped) {
      capSet.add(mapped);
      if (
        (plat === null || plat === 'windows') &&
        Object.prototype.hasOwnProperty.call(WINDOWS_MULTI_CAPS, native)
      ) {
        for (const extra of WINDOWS_MULTI_CAPS[native]) {
          capSet.add(extra);
        }
      }
    } else {
      unmapped.push(native);
    }
  }

  return {
    capabilities: Array.from(capSet),
    unmapped,
    mappings,
  };
}

function normalizePromptDecision(decision) {
  if (decision === true || decision === 'allow') return 'allow';
  if (decision === 'allow_once') return 'allow_once';
  if (decision === false || decision === 'deny') return 'deny';
  if (decision === 'deny_once') return 'deny_once';
  return null;
}

export class PermissionBroker {
  constructor(opts = {}) {
    let storage = null;
    let getStorage = null;
    let kernel = null;
    let eventBus = null;
    let userManager = null;
    let defaultPolicies = {};
    let policyOverride = null;
    let promptHandler = null;
    let promptTimeoutMs = DEFAULT_HEADLESS_PROMPT_TIMEOUT_MS;
    let hasExplicitPromptTimeout = false;
    let interactivePromptTimeoutMs = DEFAULT_INTERACTIVE_PROMPT_TIMEOUT_MS;

    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new SecurityError('Invalid PermissionBroker constructor options: expected object', {
          code: ERROR_CODES.EINVAL,
        });
      }
      try {
        if (opts.storage !== undefined) storage = opts.storage;
        if (opts.getStorage !== undefined) getStorage = opts.getStorage;
        if (opts.kernel !== undefined) kernel = opts.kernel;
        if (opts.eventBus !== undefined) eventBus = opts.eventBus;
        if (opts.userManager !== undefined) userManager = opts.userManager;
        if (opts.defaultPolicies !== undefined) defaultPolicies = opts.defaultPolicies;
        if (opts.policyOverride !== undefined) policyOverride = opts.policyOverride;
        if (opts.promptHandler !== undefined) promptHandler = opts.promptHandler;
        if (opts.promptTimeoutMs !== undefined) {
          promptTimeoutMs = opts.promptTimeoutMs;
          hasExplicitPromptTimeout = true;
        }
        if (opts.interactivePromptTimeoutMs !== undefined) {
          interactivePromptTimeoutMs = opts.interactivePromptTimeoutMs;
        }
      } catch {
        throw new SecurityError('Unreadable PermissionBroker constructor options', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }

    if (kernel !== null && kernel !== undefined && typeof kernel !== 'object') {
      throw new SecurityError('Invalid PermissionBroker kernel dependency', { code: ERROR_CODES.EINVAL });
    }
    if (storage !== null && storage !== undefined && typeof storage !== 'object') {
      throw new SecurityError('Invalid PermissionBroker storage dependency', { code: ERROR_CODES.EINVAL });
    }
    if (eventBus !== null && eventBus !== undefined && typeof eventBus !== 'object') {
      throw new SecurityError('Invalid PermissionBroker eventBus dependency', { code: ERROR_CODES.EINVAL });
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
          throw new SecurityError('Invalid PermissionBroker eventBus dependency: missing emit()', {
            code: ERROR_CODES.EINVAL,
          });
        }
      }
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new SecurityError('Unreadable PermissionBroker dependency option', {
        code: ERROR_CODES.EINVAL,
      });
    }

    this._kernel = kernel;
    this._getStorage = typeof getStorage === 'function' ? getStorage : null;
    this._eventBus = eventBus ?? kernelEventBus ?? null;
    this._userManager = userManager;
    this._storage = storage;
    this._ownsStorage = false;
    this._initialized = false;

    this._defaultPolicies = Object.create(null);
    for (const cap of ALL_CAPABILITIES) {
      this._defaultPolicies[cap] = DEFAULT_CAPABILITY_POLICIES[cap];
    }
    if (defaultPolicies && typeof defaultPolicies === 'object') {
      if (
        isSpoofedOrUnreadableBuiltin(defaultPolicies) ||
        isGenuineBinaryView(defaultPolicies) ||
        isGenuineArrayBuffer(defaultPolicies) ||
        isGenuineDate(defaultPolicies)
      ) {
        throw new SecurityError('Invalid defaultPolicies option', { code: ERROR_CODES.EINVAL });
      }
      for (const cap of ALL_CAPABILITIES) {
        let hasCap;
        let stateVal;
        try {
          hasCap = Object.prototype.hasOwnProperty.call(defaultPolicies, cap);
          if (hasCap) {
            stateVal = defaultPolicies[cap];
          }
        } catch {
          throw new SecurityError('Unreadable defaultPolicies entry', { code: ERROR_CODES.EINVAL });
        }
        if (hasCap && VALID_STATES.has(stateVal)) {
          this._defaultPolicies[cap] = stateVal;
        }
      }
    }

    this._policyOverride = null;
    if (policyOverride !== null && policyOverride !== undefined) {
      this.setPolicyOverride(policyOverride);
    }

    this._promptHandler = null;
    if (promptHandler !== null && promptHandler !== undefined) {
      this.setPromptHandler(promptHandler);
    }

    if (typeof promptTimeoutMs !== 'number' || !Number.isFinite(promptTimeoutMs) || promptTimeoutMs < 0) {
      throw new SecurityError('promptTimeoutMs must be a non-negative finite number', {
        code: ERROR_CODES.EINVAL,
      });
    }
    this._hasExplicitPromptTimeout = hasExplicitPromptTimeout;
    this._promptTimeoutMs = Math.min(promptTimeoutMs, MAX_TIMEOUT_MS);
    if (
      typeof interactivePromptTimeoutMs !== 'number' ||
      !Number.isFinite(interactivePromptTimeoutMs) ||
      interactivePromptTimeoutMs < 0
    ) {
      throw new SecurityError('interactivePromptTimeoutMs must be a non-negative finite number', {
        code: ERROR_CODES.EINVAL,
      });
    }
    this._interactivePromptTimeoutMs = Math.min(interactivePromptTimeoutMs, MAX_TIMEOUT_MS);
    this._interactiveSources = new Set();

    this._pendingPrompts = new Map();
    this._promptSeq = 0;

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
        throw new SecurityError('Unreadable PermissionBroker getStorage() dependency', {
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

  get isReady() {
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
      throw new SecurityError('Unreadable storage dependency in PermissionBroker.init()', {
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
      throw new SecurityError('Unreadable storage in PermissionBroker.init()', {
        code: ERROR_CODES.EINVAL,
      });
    }

    if (!isOpen) {
      throw new OmniOSError('PermissionBroker requires an open SqliteStorage', {
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

    db.migrate('security_permissions', PERMISSION_MIGRATIONS);
    this._initialized = true;
    return this;
  }

  close() {
    this.cancelAllPendingPrompts('broker_closed');
    if (this._ownsStorage && this._storage?.isOpen) {
      this._storage.close();
    }
    this._initialized = false;
  }

  _requireStorage() {
    let currentOpen = false;
    if (this._initialized && this._storage) {
      try {
        currentOpen = Boolean(this._storage.isOpen);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new SecurityError('Unreadable PermissionBroker storage', {
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
      throw new SecurityError('Unreadable PermissionBroker storage dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (lazyOpen) {
      this.init(lazy);
      return this._storage;
    }
    throw new OmniOSError('PermissionBroker storage is not open or initialized', {
      code: ERROR_CODES.E_STORAGE_CLOSED,
    });
  }

  _emit(event, payload) {
    if (!this._eventBus) return;
    try {
      if (typeof this._eventBus.emit === 'function') {
        this._eventBus.emit(event, payload);
      }
    } catch {
      // Ignore revoked or throwing eventBus after state commit so mutations stay consistent
    }
  }

  // ---- Grants & Policies ----

  setGrant(appId, capability, state, opts = {}) {
    const db = this._requireStorage();
    assertValidAppId(appId);
    assertValidCapability(capability);
    assertValidState(state);
    let source = 'user';
    let auditGrant = false;
    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new SecurityError('Invalid setGrant options', { code: ERROR_CODES.EINVAL });
      }
      try {
        if (opts.source !== undefined) {
          source = opts.source;
        }
        if (opts.audit !== undefined) {
          auditGrant = Boolean(opts.audit);
        }
      } catch {
        throw new SecurityError('Unreadable setGrant options', { code: ERROR_CODES.EINVAL });
      }
    }
    const cleanSource =
      typeof source === 'string' &&
      source.length > 0 &&
      source.length <= 128 &&
      !CONTROL_CHAR_RE.test(source)
        ? source
        : 'user';
    const updatedAt = new Date().toISOString();

    db.transaction((tx) => {
      tx.run(
        `INSERT INTO permission_grants (app_id, capability, state, source, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(app_id, capability)
         DO UPDATE SET state = excluded.state, source = excluded.source, updated_at = excluded.updated_at`,
        appId,
        capability,
        state,
        cleanSource,
        updatedAt
      );
    });

    const record = { appId, capability, state, source: cleanSource, updatedAt };
    if (auditGrant) {
      this._writeAudit({
        appId,
        pid: null,
        platform: 'system',
        capability,
        nativePermission: null,
        policy: state,
        granted: state === PERMISSION_STATES.ALLOW,
        reason: `grant_updated:${cleanSource}`,
        context: { source: cleanSource, state },
      });
    }
    this._emit('security:grant_changed', { ...record });
    return record;
  }

  getGrant(appId, capability) {
    const db = this._requireStorage();
    if (typeof appId !== 'string' || typeof capability !== 'string') return null;
    const row = db.get(
      'SELECT app_id, capability, state, source, updated_at FROM permission_grants WHERE app_id = ? AND capability = ?',
      appId,
      capability
    );
    if (!row) return null;
    return {
      appId: row.app_id,
      capability: row.capability,
      state: row.state,
      source: row.source,
      updatedAt: row.updated_at,
    };
  }

  listGrants(appId = undefined) {
    const db = this._requireStorage();
    const rows =
      appId !== undefined && appId !== null
        ? db.all(
            'SELECT app_id, capability, state, source, updated_at FROM permission_grants WHERE app_id = ? ORDER BY capability ASC',
            safeString(appId)
          )
        : db.all(
            'SELECT app_id, capability, state, source, updated_at FROM permission_grants ORDER BY app_id ASC, capability ASC'
          );
    return rows.map((row) => ({
      appId: row.app_id,
      capability: row.capability,
      state: row.state,
      source: row.source,
      updatedAt: row.updated_at,
    }));
  }

  revokeAllGrants(appId) {
    const db = this._requireStorage();
    assertValidAppId(appId);
    const res = db.transaction((tx) =>
      tx.run('DELETE FROM permission_grants WHERE app_id = ?', appId)
    );
    if (res.changes > 0) {
      this._emit('security:grants_revoked', { appId, count: res.changes });
    }
    return res.changes;
  }

  clearAppGrants(appId) {
    return this.revokeAllGrants(appId);
  }

  setDefaultPolicy(capability, state) {
    assertValidCapability(capability);
    assertValidState(state);
    this._defaultPolicies[capability] = state;
  }

  getDefaultPolicy(capability) {
    assertValidCapability(capability);
    return this._defaultPolicies[capability];
  }

  setPolicyOverride(override) {
    if (override === null || override === undefined) {
      this._policyOverride = null;
      return;
    }
    if (typeof override === 'function') {
      this._policyOverride = override;
      return;
    }
    if (typeof override === 'string' && override.length <= 16 && VALID_STATES.has(override)) {
      this._policyOverride = override;
      return;
    }
    throw new SecurityError(
      "policyOverride must be 'allow', 'deny', 'prompt', a function, or null",
      { code: ERROR_CODES.EINVAL }
    );
  }

  setPromptHandler(fn) {
    if (fn === null || fn === undefined) {
      this._promptHandler = null;
      return;
    }
    if (typeof fn !== 'function') {
      throw new SecurityError('promptHandler must be a function or null', {
        code: ERROR_CODES.EINVAL,
      });
    }
    this._promptHandler = fn;
  }

  registerInteractiveSource(predicate) {
    if (typeof predicate !== 'function') {
      throw new SecurityError('Interactive source predicate must be a function', {
        code: ERROR_CODES.EINVAL,
      });
    }
    this._interactiveSources.add(predicate);
    return () => {
      this._interactiveSources.delete(predicate);
    };
  }

  hasInteractivePromptConsumer() {
    if (typeof this._promptHandler === 'function') return true;
    for (const pred of this._interactiveSources) {
      try {
        if (pred()) return true;
      } catch {
        // Ignore predicate errors; fail closed as non-interactive.
      }
    }
    return false;
  }

  // ---- Audit Logging ----

  _writeAudit({
    appId,
    pid,
    platform,
    capability,
    nativePermission,
    policy,
    granted,
    reason,
    context,
    preSerializedContextJson = null,
  }) {
    const db = this._requireStorage();
    const ts = new Date().toISOString();
    const contextJson =
      typeof preSerializedContextJson === 'string'
        ? preSerializedContextJson
        : safeJsonStringify(context);
    const safeAppId = safeString(appId, '[Unreadable]');
    const safePid = typeof pid === 'number' && Number.isSafeInteger(pid) ? pid : null;
    const safePlat = safeString(platform ?? 'posix');
    const safeCap = safeNullableString(capability);
    const safeNative = safeNullableString(nativePermission);
    const safePolicy =
      typeof policy === 'string' && VALID_STATES.has(policy) ? policy : PERMISSION_STATES.DENY;
    const safeReason = sanitizeReason(reason, 'unknown');
    const res = db.run(
      `INSERT INTO security_audit
        (ts, app_id, pid, platform, capability, native_permission, policy, granted, reason, context_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ts,
      safeAppId,
      safePid,
      safePlat,
      safeCap,
      safeNative,
      safePolicy,
      granted ? 1 : 0,
      safeReason,
      contextJson
    );
    const entry = {
      id: res.lastInsertRowid,
      ts,
      appId: safeAppId,
      pid: safePid,
      platform: safePlat,
      capability: safeCap,
      nativePermission: safeNative,
      policy: safePolicy,
      granted: Boolean(granted),
      reason: safeReason,
      context: parseSanitizedContextJson(contextJson),
    };
    this._emit('security:audit', { ...entry });
    return entry;
  }

  getAuditLog(opts = {}) {
    const db = this._requireStorage();
    let appId;
    let capability;
    let platform;
    let granted;
    let limit = 100;
    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new SecurityError('Invalid getAuditLog options', { code: ERROR_CODES.EINVAL });
      }
      try {
        appId = opts.appId;
        capability = opts.capability;
        platform = opts.platform;
        granted = opts.granted;
        if (opts.limit !== undefined) {
          limit = opts.limit;
        }
      } catch {
        throw new SecurityError('Unreadable getAuditLog options', { code: ERROR_CODES.EINVAL });
      }
    }
    if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 0) {
      throw new SecurityError('limit must be a non-negative safe integer', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (limit === 0) return [];

    const clauses = [];
    const params = [];
    if (appId !== undefined && appId !== null) {
      clauses.push('app_id = ?');
      params.push(safeString(appId));
    }
    if (capability !== undefined && capability !== null) {
      clauses.push('capability = ?');
      params.push(safeString(capability));
    }
    if (platform !== undefined && platform !== null) {
      clauses.push('platform = ?');
      params.push(safeString(platform));
    }
    if (granted !== undefined && granted !== null) {
      clauses.push('granted = ?');
      params.push(granted ? 1 : 0);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    params.push(Math.min(limit, 10000));
    const rows = db.all(
      `SELECT id, ts, app_id, pid, platform, capability, native_permission,
              policy, granted, reason, context_json
       FROM security_audit
       ${whereSql}
       ORDER BY id DESC
       LIMIT ?`,
      ...params
    );

    return rows.map((row) => {
      let parsedCtx = {};
      try {
        parsedCtx = JSON.parse(row.context_json || '{}');
      } catch {
        parsedCtx = {};
      }
      return {
        id: Number(row.id),
        ts: row.ts,
        appId: row.app_id,
        pid: row.pid === null ? null : Number(row.pid),
        platform: row.platform,
        capability: row.capability ?? null,
        nativePermission: row.native_permission ?? null,
        policy: row.policy,
        granted: Boolean(row.granted),
        reason: row.reason,
        context: parsedCtx,
      };
    });
  }

  // ---- Prompt Resolution ----

  _settlePrompt(entry, decision, reasonOverride = null) {
    if (entry.settled) return false;
    entry.settled = true;
    if (entry.timer !== null) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }
    this._pendingPrompts.delete(entry.promptId);

    const granted = decision === 'allow' || decision === 'allow_once';
    const persistState = decision === 'allow' ? 'allow' : decision === 'deny' ? 'deny' : null;

    if (persistState && this.isReady) {
      try {
        this.setGrant(entry.appId, entry.capability, persistState, { source: 'prompt' });
      } catch {
        // Storage may have closed during teardown; keep decision fail-safe.
      }
    }

    const defaultReason =
      decision === 'allow'
        ? 'prompt_allowed'
        : decision === 'allow_once'
          ? 'prompt_allowed_once'
          : decision === 'deny'
            ? 'prompt_denied'
            : 'prompt_denied_once';
    const reason =
      reasonOverride !== null && reasonOverride !== undefined
        ? sanitizeReason(reasonOverride, defaultReason)
        : defaultReason;

    entry.outcome = { granted, decision, reason };
    this._emit('permission:resolved', {
      promptId: entry.promptId,
      appId: entry.appId,
      capability: entry.capability,
      decision,
      granted,
      reason,
      ts: new Date().toISOString(),
    });

    if (typeof entry.resolve === 'function') {
      entry.resolve(entry.outcome);
    }
    return true;
  }

  resolvePrompt(promptId, decision) {
    if (typeof promptId !== 'string' || promptId.length === 0) {
      throw new SecurityError('promptId must be a non-empty string', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const normalized = normalizePromptDecision(decision);
    if (!normalized) {
      throw new SecurityError(
        "Invalid prompt decision: expected 'allow', 'allow_once', 'deny', 'deny_once', or boolean",
        { code: ERROR_CODES.EINVAL }
      );
    }

    const entry = this._pendingPrompts.get(promptId);
    if (!entry || entry.settled) {
      return { ok: false, promptId, reason: 'not_found' };
    }

    this._settlePrompt(entry, normalized);
    return {
      ok: true,
      promptId,
      decision: normalized,
      granted: entry.outcome.granted,
      reason: entry.outcome.reason,
    };
  }

  getPendingPrompts() {
    const out = [];
    for (const entry of this._pendingPrompts.values()) {
      if (!entry.settled) {
        out.push(clonePromptPayload(entry));
      }
    }
    return out;
  }

  cancelAllPendingPrompts(reason = 'cancelled') {
    const safeReason = sanitizeReason(reason, 'cancelled');
    const entries = Array.from(this._pendingPrompts.values());
    let count = 0;
    for (const entry of entries) {
      if (this._settlePrompt(entry, 'deny_once', safeReason)) {
        count += 1;
      }
    }
    return count;
  }

  // ---- Core Permission Check ----

  async checkPermission(req = {}) {
    this._requireStorage();
    if (req === null || req === undefined || typeof req !== 'object') {
      throw new SecurityError('Invalid permission request: expected object', {
        code: ERROR_CODES.EINVAL,
      });
    }
    let appId;
    let pid = null;
    let platform = 'posix';
    let capability = null;
    let nativePermission = null;
    let context = null;
    let timeoutMs;
    try {
      appId = req.appId;
      if (req.pid !== undefined) pid = req.pid;
      if (req.platform !== undefined) platform = req.platform;
      if (req.capability !== undefined) capability = req.capability;
      if (req.nativePermission !== undefined) nativePermission = req.nativePermission;
      if (req.context !== undefined) context = req.context;
      timeoutMs = req.timeoutMs;
    } catch {
      throw new SecurityError('Unreadable permission request object', {
        code: ERROR_CODES.EINVAL,
      });
    }
    assertValidAppId(appId);

    if (pid !== null && pid !== undefined) {
      if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 0) {
        throw new SecurityError('pid must be a non-negative safe integer or null', {
          code: ERROR_CODES.EINVAL,
          appId,
        });
      }
    }

    let rawTimeoutMs;
    if (timeoutMs !== undefined) {
      rawTimeoutMs = timeoutMs;
    } else if (!this._hasExplicitPromptTimeout && this.hasInteractivePromptConsumer()) {
      rawTimeoutMs = this._interactivePromptTimeoutMs;
    } else {
      rawTimeoutMs = this._promptTimeoutMs;
    }
    if (
      typeof rawTimeoutMs !== 'number' ||
      !Number.isFinite(rawTimeoutMs) ||
      rawTimeoutMs < 0
    ) {
      throw new SecurityError('timeoutMs must be a non-negative finite number', {
        code: ERROR_CODES.EINVAL,
        appId,
      });
    }
    const effectiveTimeoutMs = Math.min(rawTimeoutMs, MAX_TIMEOUT_MS);

    let cleanPlatform = 'posix';
    if (typeof platform === 'string' && platform.length > 0) {
      const boundedPlatform =
        platform.length > 128 ? `${platform.slice(0, 128)}...[Truncated]` : platform;
      const trimmedPlatform = boundedPlatform.trim().toLowerCase();
      if (trimmedPlatform.length > 0) {
        cleanPlatform = trimmedPlatform;
      }
    }

    const safeNativePerm = safeNullableString(nativePermission);

    let canonicalCap = null;
    if (capability !== null && capability !== undefined) {
      if (typeof capability !== 'string' || capability.length > 64 || !CAPABILITY_SET.has(capability)) {
        const safeCap = safeString(capability);
        const audit = this._writeAudit({
          appId,
          pid,
          platform: cleanPlatform,
          capability: safeCap,
          nativePermission: safeNativePerm,
          policy: PERMISSION_STATES.DENY,
          granted: false,
          reason: 'unknown_capability',
          context,
        });
        return {
          granted: false,
          policy: PERMISSION_STATES.DENY,
          capability: safeCap,
          nativePermission: safeNativePerm,
          reason: 'unknown_capability',
          auditId: audit.id,
        };
      }
      canonicalCap = capability;
    } else if (nativePermission !== null && nativePermission !== undefined) {
      const mapped = mapNativePermission(nativePermission, cleanPlatform === 'posix' ? null : cleanPlatform);
      if (!mapped) {
        const audit = this._writeAudit({
          appId,
          pid,
          platform: cleanPlatform,
          capability: null,
          nativePermission: safeNativePerm,
          policy: PERMISSION_STATES.DENY,
          granted: false,
          reason: 'unmapped_native_permission',
          context,
        });
        return {
          granted: false,
          policy: PERMISSION_STATES.DENY,
          capability: null,
          nativePermission: safeNativePerm,
          reason: 'unmapped_native_permission',
          auditId: audit.id,
        };
      }
      canonicalCap = mapped;
    } else {
      throw new SecurityError('Either capability or nativePermission must be provided', {
        code: ERROR_CODES.EINVAL,
        appId,
      });
    }

    // Snapshot context ONCE before policy resolution / prompt delivery / audit write
    // so all consumers observe an identical bounded JSON representation with zero double-cloning or TOCTOU drift.
    const contextJson = safeJsonStringify(context);

    // Policy resolution order:
    // 1. policyOverride -> 2. persisted grant -> 3. default capability policy -> fail-closed 'deny'
    let resolvedPolicy = null;
    let policyReason = null;

    if (this._policyOverride !== null) {
      if (typeof this._policyOverride === 'string') {
        resolvedPolicy = this._policyOverride;
        policyReason = 'policy_override';
      } else if (typeof this._policyOverride === 'function') {
        try {
          const overrideResult = this._policyOverride({
            appId,
            pid,
            platform: cleanPlatform,
            capability: canonicalCap,
            nativePermission: safeNativePerm,
            context: parseSanitizedContextJson(contextJson),
          });
          if (typeof overrideResult === 'string' && VALID_STATES.has(overrideResult)) {
            resolvedPolicy = overrideResult;
            policyReason = 'policy_override';
          }
        } catch (_err) {
          resolvedPolicy = PERMISSION_STATES.DENY;
          policyReason = 'policy_override_error';
        }
      }
    }

    if (resolvedPolicy === null) {
      const grant = this.getGrant(appId, canonicalCap);
      if (grant && VALID_STATES.has(grant.state)) {
        resolvedPolicy = grant.state;
        policyReason = grant.state === PERMISSION_STATES.ALLOW
          ? 'persisted_grant_allow'
          : grant.state === PERMISSION_STATES.DENY
            ? 'persisted_grant_deny'
            : 'persisted_grant_prompt';
      }
    }

    if (resolvedPolicy === null) {
      resolvedPolicy = this._defaultPolicies[canonicalCap] ?? PERMISSION_STATES.DENY;
      policyReason = `default_${resolvedPolicy}`;
    }

    if (resolvedPolicy === PERMISSION_STATES.ALLOW) {
      const audit = this._writeAudit({
        appId,
        pid,
        platform: cleanPlatform,
        capability: canonicalCap,
        nativePermission: safeNativePerm,
        policy: PERMISSION_STATES.ALLOW,
        granted: true,
        reason: policyReason,
        preSerializedContextJson: contextJson,
      });
      return {
        granted: true,
        policy: PERMISSION_STATES.ALLOW,
        capability: canonicalCap,
        nativePermission: safeNativePerm,
        reason: policyReason,
        auditId: audit.id,
      };
    }

    if (resolvedPolicy === PERMISSION_STATES.DENY) {
      const audit = this._writeAudit({
        appId,
        pid,
        platform: cleanPlatform,
        capability: canonicalCap,
        nativePermission: safeNativePerm,
        policy: PERMISSION_STATES.DENY,
        granted: false,
        reason: policyReason,
        preSerializedContextJson: contextJson,
      });
      return {
        granted: false,
        policy: PERMISSION_STATES.DENY,
        capability: canonicalCap,
        nativePermission: safeNativePerm,
        reason: policyReason,
        auditId: audit.id,
      };
    }

    // Prompt flow (resolvedPolicy === 'prompt')
    const promptId = `perm_${++this._promptSeq}_${crypto.randomBytes(4).toString('hex')}`;
    const createdAt = new Date().toISOString();

    const entry = {
      promptId,
      appId,
      pid,
      platform: cleanPlatform,
      capability: canonicalCap,
      nativePermission: safeNativePerm,
      contextJson,
      createdAt,
      settled: false,
      outcome: null,
      resolve: null,
      timer: null,
    };

    const waitPromise = new Promise((resolve) => {
      entry.resolve = resolve;
    });

    this._pendingPrompts.set(promptId, entry);
    this._emit('permission:prompt', clonePromptPayload(entry));

    let outcome;
    if (entry.settled) {
      outcome = entry.outcome;
    } else {
      // Arm .unref() timeout so unresolved prompts always fail closed without hanging Node
      const timer = setTimeout(() => {
        this._settlePrompt(entry, 'deny_once', 'prompt_timeout');
      }, effectiveTimeoutMs);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
      entry.timer = timer;

      if (typeof this._promptHandler === 'function') {
        Promise.resolve()
          .then(() => this._promptHandler(clonePromptPayload(entry)))
          .then((handlerResult) => {
            if (entry.settled) return;
            if (handlerResult === 'pending' || handlerResult === undefined) {
              return;
            }
            const norm = normalizePromptDecision(handlerResult);
            if (norm) {
              this._settlePrompt(entry, norm);
            } else {
              this._settlePrompt(entry, 'deny_once', 'prompt_invalid_response');
            }
          })
          .catch((_err) => {
            if (!entry.settled) {
              this._settlePrompt(entry, 'deny_once', 'prompt_handler_error');
            }
          });
      }

      outcome = await waitPromise;
    }

    let auditId = null;
    if (this.isReady) {
      try {
        const audit = this._writeAudit({
          appId,
          pid,
          platform: cleanPlatform,
          capability: canonicalCap,
          nativePermission: safeNativePerm,
          policy: PERMISSION_STATES.PROMPT,
          granted: outcome.granted,
          reason: outcome.reason,
          preSerializedContextJson: contextJson,
        });
        auditId = audit.id;
      } catch (_err) {
        // Storage may have closed or broker shut down concurrently during teardown; keep fail-closed outcome.
        auditId = null;
      }
    }

    return {
      granted: outcome.granted,
      policy: PERMISSION_STATES.PROMPT,
      capability: canonicalCap,
      nativePermission: safeNativePerm,
      reason: outcome.reason,
      promptId,
      auditId,
    };
  }

  mapNativePermission(nativePermission, platform = null) {
    return mapNativePermission(nativePermission, platform);
  }

  mapNativePermissions(nativeList, platform = null) {
    return mapNativePermissions(nativeList, platform);
  }

  async assertPermission(req) {
    const result = await this.checkPermission(req);
    if (!result.granted) {
      let reqAppId = null;
      let reqPid = null;
      let reqNative = null;
      try {
        if (req && typeof req === 'object') {
          if (typeof req.appId === 'string') reqAppId = req.appId;
          if (typeof req.pid === 'number' && Number.isSafeInteger(req.pid)) reqPid = req.pid;
          reqNative = req.nativePermission;
        }
      } catch {
        // Ignore hostile second-read traps on req
      }
      throw new SecurityError(
        `Permission denied for app "${safeString(reqAppId)}" capability "${safeString(result.capability ?? reqNative)}": ${safeString(result.reason, 'denied')}`,
        {
          code: ERROR_CODES.E_PERMISSION_DENIED,
          capability: result.capability,
          appId: reqAppId,
          pid: reqPid,
          details: result,
        }
      );
    }
    return result;
  }
}

export function createPermissionBroker(options = {}) {
  return new PermissionBroker(options);
}

export function registerSecurityService(serviceManager, opts = {}) {
  if (!serviceManager || typeof serviceManager !== 'object') {
    throw new SecurityError('Invalid registerSecurityService serviceManager: expected object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  let registerFn;
  try {
    registerFn = serviceManager.register;
  } catch {
    throw new SecurityError('Unreadable registerSecurityService serviceManager', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (typeof registerFn !== 'function') {
    throw new SecurityError('Invalid registerSecurityService serviceManager: missing register()', {
      code: ERROR_CODES.EINVAL,
    });
  }

  let userManager = null;
  let permissionBroker = null;
  let kernel = null;
  let getStorage = null;
  let deps = [];
  let essential = true;
  let description = 'OmniOS Security & Permission Broker Daemon';
  if (opts !== null && opts !== undefined) {
    if (typeof opts !== 'object') {
      throw new SecurityError('Invalid registerSecurityService options: expected object', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      if (opts.userManager !== undefined) userManager = opts.userManager;
      if (opts.permissionBroker !== undefined) permissionBroker = opts.permissionBroker;
      if (opts.kernel !== undefined) kernel = opts.kernel;
      if (opts.getStorage !== undefined) getStorage = opts.getStorage;
      if (opts.deps !== undefined) deps = opts.deps;
      if (opts.essential !== undefined) essential = opts.essential;
      if (opts.description !== undefined) description = opts.description;
    } catch {
      throw new SecurityError('Unreadable registerSecurityService options', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  if (kernel !== null && kernel !== undefined) {
    if (typeof kernel !== 'object') {
      throw new SecurityError('Invalid registerSecurityService kernel dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      void kernel.storage;
    } catch {
      throw new SecurityError('Unreadable registerSecurityService kernel dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  if (getStorage !== null && getStorage !== undefined) {
    if (typeof getStorage !== 'function') {
      throw new SecurityError('Invalid registerSecurityService getStorage dependency: expected function', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      void getStorage.length;
    } catch {
      throw new SecurityError('Unreadable registerSecurityService getStorage dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  if (userManager !== null && userManager !== undefined) {
    if (typeof userManager !== 'object') {
      throw new SecurityError('Invalid registerSecurityService userManager dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      if (typeof userManager.init !== 'function') {
        throw new SecurityError('Invalid registerSecurityService userManager dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new SecurityError('Unreadable registerSecurityService userManager dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  if (permissionBroker !== null && permissionBroker !== undefined) {
    if (typeof permissionBroker !== 'object') {
      throw new SecurityError('Invalid registerSecurityService permissionBroker dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      if (typeof permissionBroker.init !== 'function') {
        throw new SecurityError('Invalid registerSecurityService permissionBroker dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new SecurityError('Unreadable registerSecurityService permissionBroker dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  let running = false;
  return registerFn.call(serviceManager, {
    name: 'securityd',
    deps,
    essential,
    description,
    start() {
      let storage = null;
      try {
        storage = getStorage ? getStorage() : (kernel?.storage ?? null);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new SecurityError('Unreadable storage dependency in securityd.start()', {
          code: ERROR_CODES.EINVAL,
        });
      }
      try {
        if (userManager) {
          userManager.init(storage);
        }
        if (permissionBroker) {
          permissionBroker.init(storage);
        }
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new SecurityError('Failed to start securityd: unreadable dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
      running = true;
    },
    stop() {
      running = false;
      if (permissionBroker) {
        try {
          permissionBroker.cancelAllPendingPrompts('service_stopped');
        } catch (err) {
          if (err instanceof OmniOSError) throw err;
          throw new SecurityError('Failed to stop securityd: unreadable permissionBroker', {
            code: ERROR_CODES.EINVAL,
          });
        }
      }
    },
    healthCheck() {
      try {
        if (!running) {
          return { ok: false, reason: 'securityd stopped' };
        }
        if (userManager) {
          if (!userManager.isReady) {
            return { ok: false, reason: 'userManager storage not ready' };
          }
          if (userManager.getUserByUid(0) === null || userManager.getUserByUid(1000) === null) {
            return { ok: false, reason: 'built-in users missing' };
          }
        }
        if (permissionBroker && !permissionBroker.isReady) {
          return { ok: false, reason: 'permissionBroker storage not ready' };
        }
        return { ok: true };
      } catch {
        return { ok: false, reason: 'securityd health check failed' };
      }
    },
  });
}
