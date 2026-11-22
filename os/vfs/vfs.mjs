/**
 * OmniOS Unified Persistent SQLite POSIX Virtual File System (F-016, F-018, F-019, F-035)
 * Zero-dependency Node.js 24 ESM VFS backed by WAL SQLite (`vfs` namespace),
 * unified with 4-platform PathTranslator, dynamic /proc + /dev + in-memory /tmp mounts,
 * UserManager POSIX ACLs & sandboxing, ProcessManager FDs, and live `vfs:changed` events.
 */

import { types } from 'node:util';
import { SqliteStorage } from '../common/storage-sqlite.mjs';
import {
  OmniOSError,
  VfsError,
  ProcessError,
  QuotaExceededError,
  ERROR_CODES,
} from '../common/errors.mjs';
import { UserManager, DEFAULT_USER_UID, DEFAULT_USER_GID, ROOT_UID } from '../security/users.mjs';
import {
  PathTranslator,
  MAX_PATH_LENGTH,
  normalizePosixPath,
  isPathWithinRoot,
} from './path-translator.mjs';
import {
  VirtualMountManager,
  DEFAULT_MAX_TMP_BYTES,
  makeStatObject,
  makeDirentObject,
} from './virtual-mounts.mjs';

function freezeLookup(obj) {
  return Object.freeze(Object.assign(Object.create(null), obj));
}

export const MAX_SYMLINK_DEPTH = 16;
export const DEFAULT_MAX_STORAGE_BYTES = 256 * 1024 * 1024; // 256 MiB

export const OPEN_FLAGS = freezeLookup({
  O_RDONLY: 0,
  O_WRONLY: 1,
  O_RDWR: 2,
  O_CREAT: 0o100,
  O_EXCL: 0o200,
  O_TRUNC: 0o1000,
  O_APPEND: 0o2000,
  O_DIRECTORY: 0o200000,
});

export const SEEK_WHENCE = freezeLookup({
  SEEK_SET: 0,
  SEEK_CUR: 1,
  SEEK_END: 2,
});

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: false });
const VALID_ENCODINGS = new Set(['utf8', 'utf-8', 'base64', 'hex', 'latin1', 'ascii']);
const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;
const MAX_XATTR_NAME_BYTES = 255;
const PROTECTED_MOUNT_PATHS = new Set(['/', '/proc', '/dev', '/tmp']);

export const STANDARD_BOOT_DIRS = Object.freeze([
  Object.freeze({ path: '/', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/home', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/home/user', mode: 0o755, uid: 1000, gid: 1000 }),
  Object.freeze({ path: '/home/user/Documents', mode: 0o755, uid: 1000, gid: 1000 }),
  Object.freeze({ path: '/home/user/Downloads', mode: 0o755, uid: 1000, gid: 1000 }),
  Object.freeze({ path: '/home/user/Desktop', mode: 0o755, uid: 1000, gid: 1000 }),
  Object.freeze({ path: '/home/user/Pictures', mode: 0o755, uid: 1000, gid: 1000 }),
  Object.freeze({ path: '/root', mode: 0o700, uid: 0, gid: 0 }),
  Object.freeze({ path: '/etc', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/bin', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/usr', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/usr/bin', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/usr/lib', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/system', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/system/windows', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/system/windows/System32', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/system/windows/drive_c', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/system/android', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/system/macos', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/system/ios', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/apps', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/apps/android', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/apps/windows', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/apps/macos', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/apps/ios', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/apps/universal', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/var', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/var/log', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/var/appdata', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/var/appdata/android', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/var/appdata/windows', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/var/appdata/macos', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/var/appdata/macos/Library', mode: 0o755, uid: 1000, gid: 1000 }),
  Object.freeze({ path: '/var/appdata/ios', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/var/appdata/universal', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/proc', mode: 0o555, uid: 0, gid: 0 }),
  Object.freeze({ path: '/dev', mode: 0o755, uid: 0, gid: 0 }),
  Object.freeze({ path: '/tmp', mode: 0o1777, uid: 0, gid: 0 }),
]);

export const VFS_MIGRATIONS = Object.freeze([
  Object.freeze({
    version: 1,
    name: 'vfs_initial',
    sql: `
      CREATE TABLE IF NOT EXISTS vfs_inodes (
        ino INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL CHECK (type IN ('file', 'dir', 'symlink')),
        mode INTEGER NOT NULL,
        uid INTEGER NOT NULL DEFAULT 0,
        gid INTEGER NOT NULL DEFAULT 0,
        size INTEGER NOT NULL DEFAULT 0,
        nlink INTEGER NOT NULL DEFAULT 1,
        target TEXT,
        atime_ms INTEGER NOT NULL,
        mtime_ms INTEGER NOT NULL,
        ctime_ms INTEGER NOT NULL,
        birthtime_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS vfs_dirents (
        parent_ino INTEGER NOT NULL,
        name TEXT NOT NULL,
        name_lower TEXT NOT NULL,
        child_ino INTEGER NOT NULL,
        PRIMARY KEY (parent_ino, name),
        FOREIGN KEY (parent_ino) REFERENCES vfs_inodes(ino) ON DELETE CASCADE,
        FOREIGN KEY (child_ino) REFERENCES vfs_inodes(ino) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_vfs_dirents_parent_lower ON vfs_dirents(parent_ino, name_lower);
      CREATE INDEX IF NOT EXISTS idx_vfs_dirents_child ON vfs_dirents(child_ino);

      CREATE TABLE IF NOT EXISTS vfs_blobs (
        ino INTEGER PRIMARY KEY,
        data BLOB NOT NULL,
        FOREIGN KEY (ino) REFERENCES vfs_inodes(ino) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS vfs_xattrs (
        ino INTEGER NOT NULL,
        name TEXT NOT NULL,
        value BLOB NOT NULL,
        PRIMARY KEY (ino, name),
        FOREIGN KEY (ino) REFERENCES vfs_inodes(ino) ON DELETE CASCADE
      );
    `,
  }),
]);

function splitSegments(canonicalPath) {
  if (canonicalPath === '/') return [];
  return canonicalPath.split('/').filter(Boolean);
}

function joinCanonical(parentPath, childName) {
  return parentPath === '/' ? `/${childName}` : `${parentPath}/${childName}`;
}

const SYMBOL_DESCRIPTION_GET =
  Object.getOwnPropertyDescriptor(Symbol.prototype, 'description')?.get ?? null;
const MAX_DISPLAY_BIGINT_ABS = 1n << 4096n;
const MIN_DISPLAY_BIGINT_NEG = -MAX_DISPLAY_BIGINT_ABS;

function safeDisplay(value, maxLen = 256) {
  if (typeof value === 'string') {
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

function safePath(path) {
  if (path === null || path === undefined) return null;
  if (typeof path === 'string') {
    return path.length > MAX_PATH_LENGTH ? path.slice(0, 128) : path;
  }
  return safeDisplay(path);
}

function readSafeOpt(opts, key, fallback = undefined) {
  if (opts === null || opts === undefined) return fallback;
  if (typeof opts !== 'object') {
    throw new VfsError(`Invalid VFS options object`, { code: ERROR_CODES.EINVAL });
  }
  try {
    const v = opts[key];
    return v === undefined ? fallback : v;
  } catch {
    throw new VfsError(`Unreadable VFS option: ${key}`, { code: ERROR_CODES.EINVAL });
  }
}

function assertValidFilename(name, fullPath) {
  if (
    typeof name !== 'string' ||
    name.length === 0 ||
    name.length > 255 ||
    name === '.' ||
    name === '..' ||
    name.includes('/') ||
    CONTROL_CHAR_RE.test(name) ||
    TEXT_ENCODER.encode(name).byteLength > 255
  ) {
    throw new VfsError(`Invalid filename: ${safeDisplay(name)}`, {
      code: ERROR_CODES.EINVAL,
      path: safePath(fullPath),
    });
  }
}

function assertValidXattrName(name, path) {
  const sp = safePath(path);
  if (typeof name !== 'string' || name.length === 0) {
    throw new VfsError('Invalid xattr name', { code: ERROR_CODES.EINVAL, path: sp });
  }
  if (name.length > MAX_XATTR_NAME_BYTES) {
    throw new VfsError(`Invalid xattr name: exceeds maximum length (${MAX_XATTR_NAME_BYTES})`, {
      code: ERROR_CODES.EINVAL,
      path: sp,
    });
  }
  if (CONTROL_CHAR_RE.test(name)) {
    throw new VfsError('Invalid xattr name', { code: ERROR_CODES.EINVAL, path: sp });
  }
  const nameBytes = TEXT_ENCODER.encode(name).byteLength;
  if (nameBytes > MAX_XATTR_NAME_BYTES) {
    throw new VfsError(`Invalid xattr name: exceeds maximum length (${MAX_XATTR_NAME_BYTES})`, {
      code: ERROR_CODES.EINVAL,
      path: sp,
    });
  }
  return nameBytes;
}

function assertValidMode(mode, path) {
  if (typeof mode !== 'number' || !Number.isSafeInteger(mode) || mode < 0 || mode > 0o7777) {
    throw new VfsError(`Invalid file mode: ${safeDisplay(mode)}`, {
      code: ERROR_CODES.EINVAL,
      path: safePath(path),
    });
  }
  return mode & 0o7777;
}

function assertNonNegativeInt(val, label, path = null) {
  if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < 0) {
    throw new VfsError(`Invalid ${label}: expected non-negative safe integer`, {
      code: ERROR_CODES.EINVAL,
      path: safePath(path),
    });
  }
  return val;
}

const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER_GET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'buffer').get;
const TYPED_ARRAY_OFFSET_GET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteOffset').get;
const TYPED_ARRAY_LENGTH_GET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteLength').get;
const DATA_VIEW_BUFFER_GET = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
const DATA_VIEW_OFFSET_GET = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get;
const DATA_VIEW_LENGTH_GET = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;
const AB_DETACHED_GET = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'detached')?.get ?? null;

function isGenuineArrayBuffer(value) {
  return types.isArrayBuffer(value) && !types.isProxy(value);
}

function isGenuineBinaryView(value) {
  return (types.isTypedArray(value) || types.isDataView(value)) && !types.isProxy(value);
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

/**
 * Normalizes any binary/string input into an owned compact Uint8Array (`byteOffset === 0`).
 */
function normalizeBytes(data, path = null) {
  const sp = safePath(path);
  if (typeof data === 'string') {
    return TEXT_ENCODER.encode(data);
  }
  if (data !== null && data !== undefined && typeof data === 'object') {
    if (isGenuineBinaryView(data)) {
      try {
        return copyGenuineBinaryView(data);
      } catch {
        throw new VfsError('Unreadable binary data input', {
          code: ERROR_CODES.EINVAL,
          path: sp,
        });
      }
    }
    if (isGenuineArrayBuffer(data)) {
      try {
        return copyGenuineArrayBuffer(data);
      } catch {
        throw new VfsError('Unreadable binary data input', {
          code: ERROR_CODES.EINVAL,
          path: sp,
        });
      }
    }
  }
  throw new VfsError('Data must be a string, Uint8Array, ArrayBuffer, or TypedArray', {
    code: ERROR_CODES.EINVAL,
    path: sp,
  });
}

function decodeBytes(bytes, encoding, path = null) {
  const sp = safePath(path);
  if (encoding === null || encoding === undefined) {
    return bytes.slice();
  }
  if (typeof encoding !== 'string') {
    throw new VfsError(`Invalid encoding: ${safeDisplay(encoding)}`, {
      code: ERROR_CODES.EINVAL,
      path: sp,
    });
  }
  if (encoding.length > 64) {
    throw new VfsError(`Unsupported encoding: ${safeDisplay(encoding)}`, {
      code: ERROR_CODES.EINVAL,
      path: sp,
    });
  }
  const enc = encoding.trim().toLowerCase();
  if (!VALID_ENCODINGS.has(enc)) {
    throw new VfsError(`Unsupported encoding: ${safeDisplay(encoding)}`, {
      code: ERROR_CODES.EINVAL,
      path: sp,
    });
  }
  if (enc === 'utf8' || enc === 'utf-8') {
    return TEXT_DECODER.decode(bytes);
  }
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString(enc);
}

function parseOpenFlags(flags, path) {
  const sp = safePath(path);
  if (typeof flags === 'number') {
    if (!Number.isSafeInteger(flags) || flags < 0) {
      throw new VfsError(`Invalid open flags: ${flags}`, {
        code: ERROR_CODES.EINVAL,
        path: sp,
      });
    }
    const access = flags & 3;
    if (access > 2) {
      throw new VfsError(`Invalid open access mode: ${flags}`, {
        code: ERROR_CODES.EINVAL,
        path: sp,
      });
    }
    return flags;
  }

  if (typeof flags === 'string') {
    const map = {
      r: OPEN_FLAGS.O_RDONLY,
      rs: OPEN_FLAGS.O_RDONLY,
      'r+': OPEN_FLAGS.O_RDWR,
      'rs+': OPEN_FLAGS.O_RDWR,
      w: OPEN_FLAGS.O_WRONLY | OPEN_FLAGS.O_CREAT | OPEN_FLAGS.O_TRUNC,
      wx: OPEN_FLAGS.O_WRONLY | OPEN_FLAGS.O_CREAT | OPEN_FLAGS.O_EXCL | OPEN_FLAGS.O_TRUNC,
      'w+': OPEN_FLAGS.O_RDWR | OPEN_FLAGS.O_CREAT | OPEN_FLAGS.O_TRUNC,
      'wx+': OPEN_FLAGS.O_RDWR | OPEN_FLAGS.O_CREAT | OPEN_FLAGS.O_EXCL | OPEN_FLAGS.O_TRUNC,
      a: OPEN_FLAGS.O_WRONLY | OPEN_FLAGS.O_CREAT | OPEN_FLAGS.O_APPEND,
      ax: OPEN_FLAGS.O_WRONLY | OPEN_FLAGS.O_CREAT | OPEN_FLAGS.O_EXCL | OPEN_FLAGS.O_APPEND,
      'a+': OPEN_FLAGS.O_RDWR | OPEN_FLAGS.O_CREAT | OPEN_FLAGS.O_APPEND,
      'ax+': OPEN_FLAGS.O_RDWR | OPEN_FLAGS.O_CREAT | OPEN_FLAGS.O_EXCL | OPEN_FLAGS.O_APPEND,
    };
    if (Object.prototype.hasOwnProperty.call(map, flags)) {
      return map[flags];
    }
  }

  throw new VfsError(`Invalid open flags: ${safeDisplay(flags)}`, {
    code: ERROR_CODES.EINVAL,
    path: sp,
  });
}

function rowToInode(row) {
  return {
    mount: 'root',
    ino: Number(row.ino),
    type: row.type,
    mode: Number(row.mode),
    uid: Number(row.uid),
    gid: Number(row.gid),
    size: Number(row.size),
    nlink: Number(row.nlink),
    target: row.target ?? null,
    atimeMs: Number(row.atime_ms),
    mtimeMs: Number(row.mtime_ms),
    ctimeMs: Number(row.ctime_ms),
    birthtimeMs: Number(row.birthtime_ms),
  };
}

// ============================================================================
// VfsFileHandle
// ============================================================================

export class VfsFileHandle {
  constructor({ vfs, fd, path, ino, mount, flags, pos, pid, actor, deviceName = null, procNode = null }) {
    this._vfs = vfs;
    this.fd = fd;
    this.path = path;
    this.ino = ino;
    this.mount = mount;
    this.flags = flags;
    this.pos = pos;
    this.closed = false;
    this.pid = pid;
    this._actor = actor;
    this._deviceName = deviceName;
    this._procNode = procNode;
    this._closingFromKernel = false;
  }

  _assertOpen() {
    if (this.closed) {
      throw new VfsError(`Bad file descriptor (${this.fd}): handle is closed`, {
        code: ERROR_CODES.EBADF,
        path: this.path,
      });
    }
  }

  _markClosedFromKernel() {
    this.closed = true;
    this._vfs._removeHandleRef(this);
  }

  read(length = 4096, offset = undefined) {
    return this._vfs._readHandle(this, length, offset);
  }

  write(data, offset = undefined) {
    return this._vfs._writeHandle(this, data, offset);
  }

  seek(offset, whence = SEEK_WHENCE.SEEK_SET) {
    return this._vfs._seekHandle(this, offset, whence);
  }

  stat() {
    return this._vfs._statHandle(this);
  }

  close() {
    return this._vfs._closeHandle(this);
  }
}

// ============================================================================
// Unified Persistent SQLite POSIX VFS
// ============================================================================

export class VFS {
  constructor(opts = {}) {
    let storage = null;
    let getStorage = null;
    let kernel = null;
    let eventBus = null;
    let processManager = null;
    let userManager = null;
    let pathTranslator = null;
    let virtualMounts = null;
    let maxStorageBytes = DEFAULT_MAX_STORAGE_BYTES;
    let maxTmpBytes = DEFAULT_MAX_TMP_BYTES;

    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new VfsError('Invalid VFS constructor options: expected object', {
          code: ERROR_CODES.EINVAL,
        });
      }
      try {
        if (opts.storage !== undefined) storage = opts.storage;
        if (opts.getStorage !== undefined) getStorage = opts.getStorage;
        if (opts.kernel !== undefined) kernel = opts.kernel;
        if (opts.eventBus !== undefined) eventBus = opts.eventBus;
        if (opts.processManager !== undefined) processManager = opts.processManager;
        if (opts.userManager !== undefined) userManager = opts.userManager;
        if (opts.pathTranslator !== undefined) pathTranslator = opts.pathTranslator;
        if (opts.virtualMounts !== undefined) virtualMounts = opts.virtualMounts;
        if (opts.maxStorageBytes !== undefined) maxStorageBytes = opts.maxStorageBytes;
        if (opts.maxTmpBytes !== undefined) maxTmpBytes = opts.maxTmpBytes;
      } catch {
        throw new VfsError('Unreadable VFS constructor options', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }

    if (typeof maxStorageBytes !== 'number' || !Number.isFinite(maxStorageBytes) || maxStorageBytes < 0) {
      throw new VfsError('maxStorageBytes must be a non-negative finite number', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (kernel !== null && kernel !== undefined && typeof kernel !== 'object') {
      throw new VfsError('Invalid VFS kernel dependency', { code: ERROR_CODES.EINVAL });
    }
    if (storage !== null && storage !== undefined && typeof storage !== 'object') {
      throw new VfsError('Invalid VFS storage dependency', { code: ERROR_CODES.EINVAL });
    }
    if (eventBus !== null && eventBus !== undefined && typeof eventBus !== 'object') {
      throw new VfsError('Invalid VFS eventBus dependency', { code: ERROR_CODES.EINVAL });
    }
    if (processManager !== null && processManager !== undefined && typeof processManager !== 'object') {
      throw new VfsError('Invalid VFS processManager dependency', { code: ERROR_CODES.EINVAL });
    }
    if (userManager !== null && userManager !== undefined && typeof userManager !== 'object') {
      throw new VfsError('Invalid VFS userManager dependency', { code: ERROR_CODES.EINVAL });
    }
    if (pathTranslator !== null && pathTranslator !== undefined && typeof pathTranslator !== 'object') {
      throw new VfsError('Invalid VFS pathTranslator dependency', { code: ERROR_CODES.EINVAL });
    }
    if (virtualMounts !== null && virtualMounts !== undefined && typeof virtualMounts !== 'object') {
      throw new VfsError('Invalid VFS virtualMounts dependency', { code: ERROR_CODES.EINVAL });
    }

    let kernelEventBus = null;
    let kernelProcessManager = null;
    let kernelStorage = null;
    let kernelStorageOpen = false;
    let storageOpen = false;
    try {
      if (kernel !== null && kernel !== undefined) {
        kernelEventBus = kernel.eventBus ?? null;
        kernelProcessManager = kernel.processManager ?? null;
        kernelStorage = kernel.storage ?? null;
        kernelStorageOpen = Boolean(kernelStorage?.isOpen);
      }
      if (storage !== null && storage !== undefined) {
        storageOpen = Boolean(storage.isOpen);
      }
      const resolvedEventBus = eventBus ?? kernelEventBus ?? null;
      if (resolvedEventBus !== null && resolvedEventBus !== undefined) {
        if (typeof resolvedEventBus !== 'object' || typeof resolvedEventBus.emit !== 'function') {
          throw new VfsError('Invalid VFS eventBus dependency: missing emit()', {
            code: ERROR_CODES.EINVAL,
          });
        }
      }
      const resolvedProcessManager = processManager ?? kernelProcessManager ?? null;
      if (resolvedProcessManager !== null && resolvedProcessManager !== undefined) {
        if (typeof resolvedProcessManager !== 'object') {
          throw new VfsError('Invalid VFS processManager dependency', { code: ERROR_CODES.EINVAL });
        }
        void resolvedProcessManager.get;
      }
      if (userManager !== null && userManager !== undefined) {
        if (
          typeof userManager.canRead !== 'function' ||
          typeof userManager.canWrite !== 'function' ||
          typeof userManager.canExec !== 'function' ||
          typeof userManager.checkSandboxAccess !== 'function'
        ) {
          throw new VfsError('Invalid VFS userManager dependency: missing permission methods', {
            code: ERROR_CODES.EINVAL,
          });
        }
      }
      if (pathTranslator !== null && pathTranslator !== undefined) {
        if (
          typeof pathTranslator.toCanonical !== 'function' ||
          typeof pathTranslator.toPlatform !== 'function'
        ) {
          throw new VfsError('Invalid VFS pathTranslator dependency: missing translation methods', {
            code: ERROR_CODES.EINVAL,
          });
        }
      }
      if (virtualMounts !== null && virtualMounts !== undefined) {
        if (
          typeof virtualMounts.getMountRoot !== 'function' ||
          typeof virtualMounts.lookupStep !== 'function' ||
          typeof virtualMounts.listChildren !== 'function' ||
          typeof virtualMounts.clearTmp !== 'function' ||
          !virtualMounts.tmpFs ||
          typeof virtualMounts.tmpFs !== 'object' ||
          typeof virtualMounts.tmpFs.readFileData !== 'function' ||
          !virtualMounts.procFs ||
          typeof virtualMounts.procFs !== 'object' ||
          typeof virtualMounts.procFs.readNode !== 'function' ||
          !virtualMounts.devFs ||
          typeof virtualMounts.devFs !== 'object' ||
          typeof virtualMounts.devFs.readDevice !== 'function'
        ) {
          throw new VfsError('Invalid VFS virtualMounts dependency: missing mount methods', {
            code: ERROR_CODES.EINVAL,
          });
        }
      }
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new VfsError('Unreadable VFS dependency option', {
        code: ERROR_CODES.EINVAL,
      });
    }

    this._kernel = kernel;
    this._getStorage = typeof getStorage === 'function' ? getStorage : null;
    this._eventBus = eventBus ?? kernelEventBus ?? null;
    this._processManager = processManager ?? kernelProcessManager ?? null;
    this._storage = storage;
    this._ownsStorage = false;
    this._initialized = false;
    this.maxStorageBytes = Math.floor(maxStorageBytes);

    const isStandalonePrivate = !storage && !kernel && !this._getStorage;
    let standalonePrivateStorage = null;
    if (isStandalonePrivate) {
      standalonePrivateStorage = new SqliteStorage(':memory:');
      this._storage = standalonePrivateStorage;
      this._ownsStorage = true;
    }

    this._ownsUserManager = !userManager;
    this.userManager =
      userManager ??
      new UserManager({
        storage: standalonePrivateStorage ?? (storageOpen ? storage : null),
        getStorage: standalonePrivateStorage ? null : this._getStorage,
        kernel: standalonePrivateStorage ? null : this._kernel,
        eventBus: this._eventBus,
      });

    this.pathTranslator = pathTranslator ?? new PathTranslator();
    this.virtualMounts =
      virtualMounts ??
      new VirtualMountManager({
        kernel: this._kernel,
        processManager: this._processManager,
        maxTmpBytes,
      });

    this._openHandles = new Map(); // handleKey -> VfsFileHandle
    this._genuineHandles = new WeakSet();
    this._openInodeRefs = new Map(); // `${mount}:${ino}` -> open refcount
    this._nextStandaloneFd = 3;

    if (standalonePrivateStorage) {
      this.init();
    } else if (storageOpen) {
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
        throw new VfsError('Unreadable VFS getStorage() dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (candidateOpen) {
        this.init(candidate);
      }
    }
  }

  get isReady() {
    try {
      return Boolean(this._initialized && this._storage?.isOpen);
    } catch {
      return false;
    }
  }

  get processManager() {
    if (this._processManager) return this._processManager;
    try {
      return this._kernel?.processManager ?? null;
    } catch {
      return null;
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
      throw new VfsError('Unreadable storage dependency in VFS.init()', {
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
      throw new VfsError('Unreadable storage in VFS.init()', {
        code: ERROR_CODES.EINVAL,
      });
    }

    if (!isOpen) {
      throw new OmniOSError('VFS requires an open SqliteStorage', {
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
    if (this._kernel) {
      try {
        if (!this._eventBus && this._kernel.eventBus) {
          this._eventBus = this._kernel.eventBus;
        }
        if (!this._processManager && this._kernel.processManager) {
          this._processManager = this._kernel.processManager;
        }
      } catch {
        // Ignore unreadable kernel properties
      }
    }

    if (this._ownsUserManager && (!this.userManager.isReady || this.userManager._storage !== db)) {
      this.userManager.init(db);
    }

    db.migrate('vfs', VFS_MIGRATIONS);

    const now = Date.now();
    db.transaction((tx) => {
      // Seed canonical root `/` with guaranteed ino = 1
      tx.run(
        `INSERT OR IGNORE INTO vfs_inodes
          (ino, type, mode, uid, gid, size, nlink, target, atime_ms, mtime_ms, ctime_ms, birthtime_ms)
         VALUES (1, 'dir', ?, 0, 0, 0, 2, NULL, ?, ?, ?, ?)`,
        0o755,
        now,
        now,
        now,
        now
      );

      for (const spec of STANDARD_BOOT_DIRS) {
        if (spec.path === '/') continue;
        const segs = splitSegments(spec.path);
        let parentIno = 1;
        for (let i = 0; i < segs.length; i += 1) {
          const seg = segs[i];
          const isLeaf = i === segs.length - 1;
          const existing = tx.get(
            'SELECT child_ino FROM vfs_dirents WHERE parent_ino = ? AND name = ?',
            parentIno,
            seg
          );
          if (existing) {
            parentIno = Number(existing.child_ino);
            continue;
          }
          const dirMode = isLeaf ? spec.mode : 0o755;
          const dirUid = isLeaf ? spec.uid : 0;
          const dirGid = isLeaf ? spec.gid : 0;
          const res = tx.run(
            `INSERT INTO vfs_inodes
              (type, mode, uid, gid, size, nlink, target, atime_ms, mtime_ms, ctime_ms, birthtime_ms)
             VALUES ('dir', ?, ?, ?, 0, 2, NULL, ?, ?, ?, ?)`,
            dirMode,
            dirUid,
            dirGid,
            now,
            now,
            now,
            now
          );
          const childIno = res.lastInsertRowid;
          tx.run(
            'INSERT INTO vfs_dirents (parent_ino, name, name_lower, child_ino) VALUES (?, ?, ?, ?)',
            parentIno,
            seg,
            seg.toLowerCase(),
            childIno
          );
          tx.run(
            'UPDATE vfs_inodes SET nlink = nlink + 1 WHERE ino = ?',
            parentIno
          );
          parentIno = childIno;
        }
      }

      // Startup GC for any leftover unlinked orphan inodes (nlink <= 0) from prior sessions
      const orphans = tx.all('SELECT ino FROM vfs_inodes WHERE nlink <= 0 AND ino != 1');
      for (const row of orphans) {
        if (!this._hasOpenInodeRef('root', Number(row.ino))) {
          tx.run('DELETE FROM vfs_inodes WHERE ino = ?', row.ino);
        }
      }
    });

    this._initialized = true;
    return this;
  }

  close(fdOrHandle = undefined, opts = {}) {
    if (fdOrHandle !== undefined) {
      return this.closeHandle(fdOrHandle, opts);
    }
    return this.dispose();
  }

  dispose() {
    this.closeAllHandles();
    this.virtualMounts.clearTmp();
    if (this._ownsUserManager) {
      this.userManager.close();
    }
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
        throw new VfsError('Unreadable VFS storage', {
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
      throw new VfsError('Unreadable VFS storage dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (lazyOpen) {
      this.init(lazy);
      return this._storage;
    }
    throw new OmniOSError('VFS storage is not open or initialized', {
      code: ERROR_CODES.E_STORAGE_CLOSED,
    });
  }

  _emitChanged({ op, path, oldPath = null, ino, mount, size = null, actor, pid = null }) {
    if (!this._eventBus) return;
    try {
      if (typeof this._eventBus.emit === 'function') {
        this._eventBus.emit('vfs:changed', {
          op,
          path,
          oldPath,
          ino: Number(ino),
          mount,
          size: size === null || size === undefined ? null : Number(size),
          uid: actor.uid,
          pid: pid ?? null,
          ts: new Date().toISOString(),
        });
      }
    } catch {
      // Ignore revoked or throwing eventBus after VFS state commit so mutations stay consistent
    }
  }

  // ---- Context & Path Normalization ----

  _normalizeCtx(ctx = {}) {
    if (ctx !== null && ctx !== undefined && typeof ctx !== 'object') {
      throw new VfsError('Invalid VFS context', { code: ERROR_CODES.EINVAL });
    }
    const safeCtx = ctx && typeof ctx === 'object' ? ctx : {};
    const pm = this.processManager;

    let rawPid;
    let rawUid;
    let rawGid;
    let rawCwd;
    let rawPlatform;
    let rawAppId;
    let rawContainerUuid;
    let rawSandboxRoot;
    let rawStrictSandbox;
    let rawGids;
    let rawCaseInsensitive;
    try {
      rawPid = safeCtx.pid;
      rawUid = safeCtx.uid;
      rawGid = safeCtx.gid;
      rawCwd = safeCtx.cwd;
      rawPlatform = safeCtx.platform;
      rawAppId = safeCtx.appId;
      rawContainerUuid = safeCtx.containerUuid;
      rawSandboxRoot = safeCtx.sandboxRoot;
      rawStrictSandbox = safeCtx.strictSandbox;
      rawGids = safeCtx.gids;
      rawCaseInsensitive = safeCtx.caseInsensitive;
    } catch {
      throw new VfsError('Unreadable VFS context object', { code: ERROR_CODES.EINVAL });
    }

    const pid = rawPid !== undefined && rawPid !== null ? rawPid : null;
    if (pid !== null && (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 0)) {
      throw new VfsError(`Invalid pid: ${safeDisplay(pid)}`, { code: ERROR_CODES.EINVAL });
    }
    let pcb = null;
    let pcbUid;
    let pcbGid;
    let pcbCwd;
    let pcbPlatform;
    let pcbAppId;
    if (pid !== null && pm) {
      try {
        if (typeof pm.get === 'function') {
          pcb = pm.get(pid);
        }
        if (pcb) {
          pcbUid = pcb.uid;
          pcbGid = pcb.gid;
          pcbCwd = pcb.cwd;
          pcbPlatform = pcb.platform;
          pcbAppId = pcb.appId;
        }
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new VfsError('ProcessManager is unavailable or revoked', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }

    const uid =
      rawUid !== undefined && rawUid !== null
        ? rawUid
        : pcb
          ? pcbUid
          : DEFAULT_USER_UID;
    assertNonNegativeInt(uid, 'uid');

    const gid =
      rawGid !== undefined && rawGid !== null
        ? rawGid
        : pcb
          ? pcbGid
          : rawUid !== undefined
            ? undefined
            : DEFAULT_USER_GID;
    if (gid !== undefined) {
      assertNonNegativeInt(gid, 'gid');
    }

    const cwd = rawCwd !== undefined && rawCwd !== null ? rawCwd : (pcbCwd ?? '/home/user');
    const platform =
      rawPlatform !== undefined && rawPlatform !== null
        ? rawPlatform
        : (pcbPlatform ?? 'posix');
    const appId =
      rawAppId !== undefined && rawAppId !== null ? rawAppId : (pcbAppId ?? '');
    const containerUuid = rawContainerUuid ?? '';
    const sandboxRoot = rawSandboxRoot ?? null;
    const strictSandbox = rawStrictSandbox;

    let clonedGids;
    if (rawGids !== undefined && rawGids !== null) {
      let isArr = false;
      try {
        isArr = Array.isArray(rawGids);
        if (isArr) {
          const gLen = rawGids.length;
          if (typeof gLen !== 'number' || !Number.isSafeInteger(gLen) || gLen < 0 || gLen > 4096) {
            throw new VfsError('Invalid ctx.gids length', { code: ERROR_CODES.EINVAL });
          }
          clonedGids = [];
          for (let i = 0; i < gLen; i += 1) {
            clonedGids.push(rawGids[i]);
          }
        }
      } catch (err) {
        if (err instanceof VfsError) throw err;
        throw new VfsError('Unreadable ctx.gids array', { code: ERROR_CODES.EINVAL });
      }
    }

    const actor = {
      uid,
      ...(gid !== undefined ? { gid } : {}),
      ...(clonedGids !== undefined ? { gids: clonedGids } : {}),
      ...(appId ? { appId } : {}),
      ...(typeof strictSandbox === 'boolean' ? { strictSandbox } : {}),
    };

    return {
      actor,
      pid,
      cwd,
      platform,
      appId,
      containerUuid,
      sandboxRoot,
      explicitCaseInsensitive:
        typeof rawCaseInsensitive === 'boolean' ? rawCaseInsensitive : null,
    };
  }

  resolvePath(rawPath, ctx = {}) {
    const norm = this._normalizeCtx(ctx);
    return this.pathTranslator.toCanonical(rawPath, {
      platform: norm.platform,
      cwd: norm.cwd,
      appId: norm.appId,
      containerUuid: norm.containerUuid,
      sandboxRoot: norm.sandboxRoot,
    });
  }

  _assertSandbox(
    actor,
    canonicalPath,
    sandboxRoot,
    originalPath,
    mode = 'read',
    { caseInsensitive = false, platform = 'posix' } = {}
  ) {
    let explicitRoot = sandboxRoot;
    if (typeof explicitRoot === 'string' && explicitRoot.length > 0) {
      explicitRoot = this.pathTranslator._canonicalizeSandboxRoot(explicitRoot, platform);
    }
    const check = this.userManager.checkSandboxAccess(actor, canonicalPath, {
      mode,
      explicitSandboxRoot: explicitRoot,
      caseInsensitive,
    });
    if (!check.allowed) {
      throw new VfsError(`Sandbox access denied to ${canonicalPath}: ${check.reason}`, {
        code: ERROR_CODES.EACCES,
        path: originalPath,
        details: {
          violation: ERROR_CODES.E_PATH_TRAVERSAL,
          canonicalPath,
          reason: check.reason,
        },
      });
    }
  }

  // ---- SQLite Low-Level Helpers ----

  _getSqliteInode(db, ino) {
    const row = db.get(
      `SELECT ino, type, mode, uid, gid, size, nlink, target, atime_ms, mtime_ms, ctime_ms, birthtime_ms
       FROM vfs_inodes WHERE ino = ?`,
      ino
    );
    return row ? rowToInode(row) : null;
  }

  _lookupSqliteChild(db, parentIno, seg, { caseInsensitive = false } = {}) {
    let row = db.get(
      'SELECT name, child_ino FROM vfs_dirents WHERE parent_ino = ? AND name = ?',
      parentIno,
      seg
    );
    if (!row && caseInsensitive) {
      row = db.get(
        'SELECT name, child_ino FROM vfs_dirents WHERE parent_ino = ? AND name_lower = ? ORDER BY name ASC LIMIT 1',
        parentIno,
        seg.toLowerCase()
      );
    }
    if (!row) return null;
    const node = this._getSqliteInode(db, Number(row.child_ino));
    if (!node) return null;
    return { name: row.name, node };
  }

  _getSqliteUsedBytes(db) {
    const row = db.get(
      `SELECT
         COALESCE((SELECT SUM(size) FROM vfs_inodes WHERE type = 'file'), 0) +
         COALESCE((SELECT SUM(COALESCE(LENGTH(CAST(target AS BLOB)), 0)) FROM vfs_inodes WHERE type = 'symlink'), 0) +
         COALESCE((SELECT SUM(LENGTH(CAST(name AS BLOB)) + LENGTH(value)) FROM vfs_xattrs), 0)
       AS total`
    );
    return Number(row?.total ?? 0);
  }

  _getNodeQuotaBytes(db, mount, node) {
    if (!node) return 0;
    if (mount === 'tmp') {
      const base =
        node.type === 'file'
          ? (node.data?.byteLength ?? 0)
          : node.type === 'symlink'
            ? (typeof node.size === 'number' ? node.size : TEXT_ENCODER.encode(node.target ?? '').byteLength)
            : 0;
      return base + this.virtualMounts.tmpFs.getNodeXattrBytes(node);
    }
    const base =
      node.type === 'file'
        ? Number(node.size ?? 0)
        : node.type === 'symlink'
          ? TEXT_ENCODER.encode(node.target ?? '').byteLength
          : 0;
    const xRow = db.get(
      'SELECT COALESCE(SUM(LENGTH(CAST(name AS BLOB)) + LENGTH(value)), 0) AS total FROM vfs_xattrs WHERE ino = ?',
      node.ino
    );
    return base + Number(xRow?.total ?? 0);
  }

  _assertSqliteQuota(db, deltaBytes, path) {
    if (deltaBytes <= 0) return;
    const used = this._getSqliteUsedBytes(db);
    if (
      !Number.isSafeInteger(deltaBytes) ||
      !Number.isSafeInteger(used + deltaBytes) ||
      used + deltaBytes > this.maxStorageBytes
    ) {
      throw new VfsError(
        `No space left on device (${used + deltaBytes} > ${this.maxStorageBytes})`,
        {
          code: ERROR_CODES.ENOSPC,
          path,
        }
      );
    }
  }

  _isSqliteAncestor(db, ancestorIno, startIno) {
    let curIno = startIno;
    const visited = new Set();
    while (curIno && !visited.has(curIno)) {
      if (curIno === ancestorIno) return true;
      if (curIno === 1) break;
      visited.add(curIno);
      const row = db.get('SELECT parent_ino FROM vfs_dirents WHERE child_ino = ? LIMIT 1', curIno);
      if (!row) break;
      curIno = Number(row.parent_ino);
    }
    return false;
  }

  // ---- Unified Cross-Mount Path & Symlink Resolver ----

  _resolvePath(rawPath, normCtx, { followFinal = true, allowMissingLeaf = false, mode = 'read' } = {}) {
    const db = this._requireStorage();
    const translated = this.pathTranslator.toCanonical(rawPath, {
      platform: normCtx.platform,
      cwd: normCtx.cwd,
      appId: normCtx.appId,
      containerUuid: normCtx.containerUuid,
      sandboxRoot: normCtx.sandboxRoot,
    });
    const caseInsensitive =
      normCtx.explicitCaseInsensitive !== null
        ? normCtx.explicitCaseInsensitive
        : translated.caseInsensitive;

    this._assertSandbox(normCtx.actor, translated.canonicalPath, normCtx.sandboxRoot, rawPath, mode, {
      caseInsensitive,
      platform: normCtx.platform,
    });

    const rootInode = this._getSqliteInode(db, 1);
    if (!rootInode) {
      throw new VfsError('VFS root inode missing', {
        code: ERROR_CODES.EIO,
        path: '/',
      });
    }

    let queue = splitSegments(translated.canonicalPath);
    if (queue.length === 0) {
      return {
        exists: true,
        mount: 'root',
        node: rootInode,
        parentMount: 'root',
        parentNode: rootInode,
        parentPath: '/',
        leafName: '',
        requestedLeafName: '',
        canonicalPath: '/',
        caseInsensitive,
      };
    }

    let symlinkDepth = 0;
    let currentMount = 'root';
    let currentNode = rootInode;
    let currentPath = '/';

    while (queue.length > 0) {
      const seg = queue.shift();
      const isFinal = queue.length === 0;

      if (currentNode.type !== 'dir') {
        throw new VfsError(`Not a directory: ${currentPath}`, {
          code: ERROR_CODES.ENOTDIR,
          path: rawPath,
        });
      }

      if (!this.userManager.canExec(normCtx.actor, currentNode)) {
        throw new VfsError(`Permission denied traversing ${currentPath}`, {
          code: ERROR_CODES.EACCES,
          path: rawPath,
        });
      }

      // Handle virtual mount transitions from `/`
      let childMount = currentMount;
      let lookup = null;
      if (currentMount === 'root' && currentPath === '/') {
        const lower = caseInsensitive ? seg.toLowerCase() : seg;
        if (lower === 'proc' || lower === 'dev' || lower === 'tmp') {
          childMount = lower;
          lookup = { name: lower, node: this.virtualMounts.getMountRoot(lower) };
        }
      }

      if (lookup === null) {
        if (currentMount === 'root') {
          lookup = this._lookupSqliteChild(db, currentNode.ino, seg, { caseInsensitive });
        } else {
          lookup = this.virtualMounts.lookupStep(currentMount, currentNode, seg, { caseInsensitive });
        }
      }

      if (!lookup) {
        if (isFinal && allowMissingLeaf) {
          return {
            exists: false,
            mount: currentMount,
            node: null,
            parentMount: currentMount,
            parentNode: currentNode,
            parentPath: currentPath,
            leafName: seg,
            requestedLeafName: seg,
            canonicalPath: joinCanonical(currentPath, seg),
            caseInsensitive,
          };
        }
        throw new VfsError(`No such file or directory: ${rawPath}`, {
          code: ERROR_CODES.ENOENT,
          path: rawPath,
        });
      }

      const actualName = lookup.name;
      const childNode = lookup.node;
      const nextPath = joinCanonical(currentPath, actualName);

      if (childNode.type === 'symlink' && (!isFinal || followFinal)) {
        symlinkDepth += 1;
        if (symlinkDepth > MAX_SYMLINK_DEPTH) {
          throw new VfsError(`Too many levels of symbolic links: ${rawPath}`, {
            code: ERROR_CODES.ELOOP,
            path: rawPath,
          });
        }

        const target = childNode.target;
        const expandedBase = target.startsWith('/')
          ? normalizePosixPath(target)
          : normalizePosixPath(joinCanonical(currentPath, target));
        const fullExpanded =
          queue.length > 0
            ? normalizePosixPath(joinCanonical(expandedBase, queue.join('/')))
            : expandedBase;

        // Post-expansion sandbox check blocks symlink escapes out of sandboxes
        let explicitRoot = normCtx.sandboxRoot;
        if (typeof explicitRoot === 'string' && explicitRoot.length > 0) {
          explicitRoot = this.pathTranslator._canonicalizeSandboxRoot(explicitRoot, normCtx.platform);
        }
        const sbCheck = this.userManager.checkSandboxAccess(normCtx.actor, fullExpanded, {
          mode,
          explicitSandboxRoot: explicitRoot,
          caseInsensitive,
        });
        if (!sbCheck.allowed) {
          throw new VfsError(`Symlink target escapes sandbox: ${target}`, {
            code: ERROR_CODES.EACCES,
            path: rawPath,
            details: {
              violation: ERROR_CODES.E_PATH_TRAVERSAL,
              target,
              expandedPath: fullExpanded,
              reason: sbCheck.reason,
            },
          });
        }

        if (fullExpanded === '/') {
          return {
            exists: true,
            mount: 'root',
            node: rootInode,
            parentMount: 'root',
            parentNode: rootInode,
            parentPath: '/',
            leafName: '',
            requestedLeafName: '',
            canonicalPath: '/',
            caseInsensitive,
          };
        }

        queue = splitSegments(fullExpanded);
        currentMount = 'root';
        currentNode = rootInode;
        currentPath = '/';
        continue;
      }

      if (isFinal) {
        return {
          exists: true,
          mount: childMount,
          node: childNode,
          parentMount: currentMount,
          parentNode: currentNode,
          parentPath: currentPath,
          leafName: actualName,
          requestedLeafName: seg,
          canonicalPath: nextPath,
          caseInsensitive,
        };
      }

      currentMount = childMount;
      currentNode = childNode;
      currentPath = nextPath;
    }

    throw new VfsError(`No such file or directory: ${rawPath}`, {
      code: ERROR_CODES.ENOENT,
      path: rawPath,
    });
  }

  // ---- Core Contract 2 VFS Operations ----

  stat(path, ctx = {}) {
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, { followFinal: true, allowMissingLeaf: false });
    return makeStatObject(res.node);
  }

  lstat(path, ctx = {}) {
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, { followFinal: false, allowMissingLeaf: false });
    return makeStatObject(res.node);
  }

  readdir(path, ctx = {}) {
    const db = this._requireStorage();
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, { followFinal: true, allowMissingLeaf: false });

    if (res.node.type !== 'dir') {
      throw new VfsError(`Not a directory: ${path}`, {
        code: ERROR_CODES.ENOTDIR,
        path,
      });
    }
    if (!this.userManager.canRead(norm.actor, res.node)) {
      throw new VfsError(`Permission denied reading directory: ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }

    let dirents;
    if (res.mount === 'root') {
      const rows = db.all(
        `SELECT d.name, i.ino, i.type, i.mode, i.uid, i.gid, i.size, i.nlink, i.target,
                i.atime_ms, i.mtime_ms, i.ctime_ms, i.birthtime_ms
         FROM vfs_dirents d
         JOIN vfs_inodes i ON i.ino = d.child_ino
         WHERE d.parent_ino = ?
         ORDER BY d.name ASC`,
        res.node.ino
      );
      dirents = rows.map((r) => {
        if (res.canonicalPath === '/' && (r.name === 'proc' || r.name === 'dev' || r.name === 'tmp')) {
          return makeDirentObject(r.name, this.virtualMounts.getMountRoot(r.name));
        }
        return makeDirentObject(r.name, rowToInode(r));
      });
      dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    } else {
      dirents = this.virtualMounts.listChildren(res.mount, res.node);
    }

    const namesOnly = readSafeOpt(ctx, 'namesOnly', false) === true;
    const withFileTypes = readSafeOpt(ctx, 'withFileTypes', true);
    if (namesOnly || withFileTypes === false) {
      return dirents.map((d) => d.name);
    }
    return dirents;
  }

  readFile(path, opts = {}) {
    const db = this._requireStorage();
    const norm = this._normalizeCtx(opts);
    const readLength = readSafeOpt(opts, 'length', undefined);
    const readEncoding = readSafeOpt(opts, 'encoding', undefined);
    const res = this._resolvePath(path, norm, { followFinal: true, allowMissingLeaf: false });

    if (res.node.type === 'dir') {
      throw new VfsError(`Illegal operation on a directory: ${path}`, {
        code: ERROR_CODES.EISDIR,
        path,
      });
    }
    if (!this.userManager.canRead(norm.actor, res.node)) {
      throw new VfsError(`Permission denied reading file: ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }

    let rawBytes;
    if (res.mount === 'dev') {
      rawBytes = this.virtualMounts.devFs.readDevice(res.node.name, readLength);
    } else if (res.mount === 'proc') {
      rawBytes = this.virtualMounts.procFs.readNode(res.node);
    } else if (res.mount === 'tmp') {
      rawBytes = this.virtualMounts.tmpFs.readFileData(res.node);
    } else {
      const blobRow = db.get('SELECT data FROM vfs_blobs WHERE ino = ?', res.node.ino);
      rawBytes = blobRow?.data ? new Uint8Array(blobRow.data).slice() : new Uint8Array(0);
    }

    return decodeBytes(rawBytes, readEncoding, path);
  }

  writeFile(path, data, opts = {}) {
    const db = this._requireStorage();
    const norm = this._normalizeCtx(opts);
    const bytes = normalizeBytes(data, path);
    const mode = assertValidMode(readSafeOpt(opts, 'mode', 0o644) ?? 0o644, path);
    const append = Boolean(readSafeOpt(opts, 'append', false));

    const res = this._resolvePath(path, norm, {
      followFinal: true,
      allowMissingLeaf: true,
      mode: 'write',
    });

    if (res.mount === 'proc') {
      throw new VfsError(`Read-only virtual mount /proc: ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }

    if (res.mount === 'dev') {
      if (!res.exists) {
        throw new VfsError(`Cannot create entries in /dev: ${path}`, {
          code: ERROR_CODES.EACCES,
          path,
        });
      }
      if (res.node.type === 'dir') {
        throw new VfsError(`Is a directory: ${path}`, { code: ERROR_CODES.EISDIR, path });
      }
      if (!this.userManager.canWrite(norm.actor, res.node)) {
        throw new VfsError(`Permission denied writing device: ${path}`, {
          code: ERROR_CODES.EACCES,
          path,
        });
      }
      const wRes = this.virtualMounts.devFs.writeDevice(res.node.name, bytes);
      return {
        path: res.canonicalPath,
        ino: res.node.ino,
        size: 0,
        bytesWritten: wRes.bytesWritten,
      };
    }

    const resolvedActor = this.userManager._resolveActor(norm.actor);
    let finalIno;
    let finalSize;

    if (res.exists) {
      if (res.node.type === 'dir') {
        throw new VfsError(`Is a directory: ${path}`, {
          code: ERROR_CODES.EISDIR,
          path,
        });
      }
      if (!this.userManager.canWrite(norm.actor, res.node)) {
        throw new VfsError(`Permission denied writing file: ${path}`, {
          code: ERROR_CODES.EACCES,
          path,
        });
      }

      if (res.mount === 'tmp') {
        let payload = bytes;
        if (append && res.node.data && res.node.data.byteLength > 0) {
          this.virtualMounts.tmpFs.assertQuota(bytes.byteLength, res.canonicalPath);
          payload = new Uint8Array(res.node.data.byteLength + bytes.byteLength);
          payload.set(res.node.data, 0);
          payload.set(bytes, res.node.data.byteLength);
        }
        this.virtualMounts.tmpFs.updateFileData(res.node, payload, { path: res.canonicalPath });
        finalIno = res.node.ino;
        finalSize = res.node.size;
      } else {
        const now = Date.now();
        db.transaction((tx) => {
          let payload = bytes;
          let oldSize = res.node.size;
          if (append) {
            this._assertSqliteQuota(tx, bytes.byteLength, res.canonicalPath);
            const existingRow = tx.get('SELECT data FROM vfs_blobs WHERE ino = ?', res.node.ino);
            const prev = existingRow?.data ? new Uint8Array(existingRow.data) : new Uint8Array(0);
            oldSize = prev.byteLength;
            payload = new Uint8Array(prev.byteLength + bytes.byteLength);
            payload.set(prev, 0);
            payload.set(bytes, prev.byteLength);
          }
          this._assertSqliteQuota(tx, payload.byteLength - oldSize, res.canonicalPath);
          tx.run(
            `INSERT INTO vfs_blobs (ino, data) VALUES (?, ?)
             ON CONFLICT(ino) DO UPDATE SET data = excluded.data`,
            res.node.ino,
            payload
          );
          tx.run(
            'UPDATE vfs_inodes SET size = ?, mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
            payload.byteLength,
            now,
            now,
            res.node.ino
          );
          finalIno = res.node.ino;
          finalSize = payload.byteLength;
        });
      }
    } else {
      assertValidFilename(res.leafName, path);
      if (
        !this.userManager.canWrite(norm.actor, res.parentNode) ||
        !this.userManager.canExec(norm.actor, res.parentNode)
      ) {
        throw new VfsError(`Permission denied creating file in ${res.parentPath}`, {
          code: ERROR_CODES.EACCES,
          path,
        });
      }

      if (res.mount === 'tmp') {
        const created = this.virtualMounts.tmpFs.createFile(res.parentNode, res.leafName, bytes, {
          mode,
          uid: resolvedActor.uid,
          gid: resolvedActor.gid,
          path: res.canonicalPath,
        });
        finalIno = created.ino;
        finalSize = created.size;
      } else {
        const now = Date.now();
        db.transaction((tx) => {
          this._assertSqliteQuota(tx, bytes.byteLength, res.canonicalPath);
          const ins = tx.run(
            `INSERT INTO vfs_inodes
              (type, mode, uid, gid, size, nlink, target, atime_ms, mtime_ms, ctime_ms, birthtime_ms)
             VALUES ('file', ?, ?, ?, ?, 1, NULL, ?, ?, ?, ?)`,
            mode,
            resolvedActor.uid,
            resolvedActor.gid,
            bytes.byteLength,
            now,
            now,
            now,
            now
          );
          finalIno = ins.lastInsertRowid;
          tx.run(
            'INSERT INTO vfs_dirents (parent_ino, name, name_lower, child_ino) VALUES (?, ?, ?, ?)',
            res.parentNode.ino,
            res.leafName,
            res.leafName.toLowerCase(),
            finalIno
          );
          tx.run('INSERT INTO vfs_blobs (ino, data) VALUES (?, ?)', finalIno, bytes);
          tx.run(
            'UPDATE vfs_inodes SET mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
            now,
            now,
            res.parentNode.ino
          );
          finalSize = bytes.byteLength;
        });
      }
    }

    this._emitChanged({
      op: 'write',
      path: res.canonicalPath,
      ino: finalIno,
      mount: res.mount,
      size: finalSize,
      actor: resolvedActor,
      pid: norm.pid,
    });

    return {
      path: res.canonicalPath,
      ino: finalIno,
      size: finalSize,
      bytesWritten: bytes.byteLength,
    };
  }

  mkdir(path, opts = {}) {
    const db = this._requireStorage();
    const norm = this._normalizeCtx(opts);
    const recursive = Boolean(readSafeOpt(opts, 'recursive', false));
    const mode = assertValidMode(readSafeOpt(opts, 'mode', 0o755) ?? 0o755, path);
    const resolvedActor = this.userManager._resolveActor(norm.actor);

    if (recursive) {
      const translated = this.pathTranslator.toCanonical(path, {
        platform: norm.platform,
        cwd: norm.cwd,
        appId: norm.appId,
        containerUuid: norm.containerUuid,
        sandboxRoot: norm.sandboxRoot,
      });
      const caseInsensitive =
        norm.explicitCaseInsensitive !== null
          ? norm.explicitCaseInsensitive
          : translated.caseInsensitive;

      this._assertSandbox(norm.actor, translated.canonicalPath, norm.sandboxRoot, path, 'write', {
        caseInsensitive,
        platform: norm.platform,
      });

      const rootInode = this._getSqliteInode(db, 1);
      if (!rootInode) {
        throw new VfsError('VFS root inode missing', {
          code: ERROR_CODES.EIO,
          path: '/',
        });
      }

      let queue = splitSegments(translated.canonicalPath);
      if (queue.length === 0) {
        return { path: '/', ino: 1, created: false };
      }

      let symlinkDepth = 0;
      let currentMount = 'root';
      let currentNode = rootInode;
      let currentPath = '/';
      let lastResult = { path: '/', ino: 1, created: false };
      let anyCreated = false;

      while (queue.length > 0) {
        const seg = queue.shift();

        if (currentNode.type !== 'dir') {
          throw new VfsError(`Not a directory: ${currentPath}`, {
            code: ERROR_CODES.ENOTDIR,
            path,
          });
        }
        if (!this.userManager.canExec(norm.actor, currentNode)) {
          throw new VfsError(`Permission denied traversing ${currentPath}`, {
            code: ERROR_CODES.EACCES,
            path,
          });
        }

        let childMount = currentMount;
        let lookup = null;
        if (currentMount === 'root' && currentPath === '/') {
          const lower = caseInsensitive ? seg.toLowerCase() : seg;
          if (lower === 'proc' || lower === 'dev' || lower === 'tmp') {
            childMount = lower;
            lookup = { name: lower, node: this.virtualMounts.getMountRoot(lower) };
          }
        }

        if (lookup === null) {
          if (currentMount === 'root') {
            lookup = this._lookupSqliteChild(db, currentNode.ino, seg, { caseInsensitive });
          } else {
            lookup = this.virtualMounts.lookupStep(currentMount, currentNode, seg, { caseInsensitive });
          }
        }

        if (lookup) {
          const actualName = lookup.name;
          const childNode = lookup.node;
          const nextPath = joinCanonical(currentPath, actualName);

          if (childNode.type === 'symlink') {
            symlinkDepth += 1;
            if (symlinkDepth > MAX_SYMLINK_DEPTH) {
              throw new VfsError(`Too many levels of symbolic links: ${path}`, {
                code: ERROR_CODES.ELOOP,
                path,
              });
            }
            const target = childNode.target;
            const expandedBase = target.startsWith('/')
              ? normalizePosixPath(target)
              : normalizePosixPath(joinCanonical(currentPath, target));
            const fullExpanded =
              queue.length > 0
                ? normalizePosixPath(joinCanonical(expandedBase, queue.join('/')))
                : expandedBase;

            this._assertSandbox(norm.actor, fullExpanded, norm.sandboxRoot, path, 'write', {
              caseInsensitive,
              platform: norm.platform,
            });

            if (fullExpanded === '/') {
              currentMount = 'root';
              currentNode = rootInode;
              currentPath = '/';
              lastResult = { path: '/', ino: 1, created: false };
              queue = [];
              break;
            }
            queue = splitSegments(fullExpanded);
            currentMount = 'root';
            currentNode = rootInode;
            currentPath = '/';
            continue;
          }

          if (childNode.type !== 'dir') {
            throw new VfsError(`Not a directory: ${nextPath}`, {
              code: ERROR_CODES.ENOTDIR,
              path,
            });
          }

          currentMount = childMount;
          currentNode = childNode;
          currentPath = nextPath;
          lastResult = { path: nextPath, ino: childNode.ino, created: false };
          continue;
        }

        const targetPath = joinCanonical(currentPath, seg);
        // Enforce sandbox before creating any missing directory segment
        this._assertSandbox(norm.actor, targetPath, norm.sandboxRoot, path, 'write', {
          caseInsensitive,
          platform: norm.platform,
        });

        const step = {
          exists: false,
          mount: currentMount,
          node: null,
          parentMount: currentMount,
          parentNode: currentNode,
          parentPath: currentPath,
          leafName: seg,
          requestedLeafName: seg,
          canonicalPath: targetPath,
          caseInsensitive,
        };
        const made = this._createSingleDir(db, step, mode, resolvedActor, norm, path);
        lastResult = made;
        anyCreated = true;

        currentNode =
          currentMount === 'tmp'
            ? this.virtualMounts.tmpFs.getNodeByIno(made.ino)
            : this._getSqliteInode(db, made.ino);
        currentPath = targetPath;
      }

      return {
        path: lastResult.path,
        ino: lastResult.ino,
        created: anyCreated,
      };
    }

    const res = this._resolvePath(path, norm, {
      followFinal: false,
      allowMissingLeaf: true,
      mode: 'write',
    });

    if (res.exists) {
      throw new VfsError(`File or directory already exists: ${path}`, {
        code: ERROR_CODES.EEXIST,
        path,
      });
    }

    return this._createSingleDir(db, res, mode, resolvedActor, norm, path);
  }

  _createSingleDir(db, res, mode, resolvedActor, norm, originalPath) {
    if (res.mount === 'proc' || res.mount === 'dev') {
      throw new VfsError(`Cannot create directory on virtual mount /${res.mount}`, {
        code: ERROR_CODES.EACCES,
        path: originalPath,
      });
    }
    assertValidFilename(res.leafName, originalPath);
    if (
      !this.userManager.canWrite(norm.actor, res.parentNode) ||
      !this.userManager.canExec(norm.actor, res.parentNode)
    ) {
      throw new VfsError(`Permission denied creating directory in ${res.parentPath}`, {
        code: ERROR_CODES.EACCES,
        path: originalPath,
      });
    }

    let createdIno;
    if (res.mount === 'tmp') {
      const node = this.virtualMounts.tmpFs.createDir(res.parentNode, res.leafName, {
        mode,
        uid: resolvedActor.uid,
        gid: resolvedActor.gid,
      });
      createdIno = node.ino;
    } else {
      const now = Date.now();
      db.transaction((tx) => {
        const ins = tx.run(
          `INSERT INTO vfs_inodes
            (type, mode, uid, gid, size, nlink, target, atime_ms, mtime_ms, ctime_ms, birthtime_ms)
           VALUES ('dir', ?, ?, ?, 0, 2, NULL, ?, ?, ?, ?)`,
          mode,
          resolvedActor.uid,
          resolvedActor.gid,
          now,
          now,
          now,
          now
        );
        createdIno = ins.lastInsertRowid;
        tx.run(
          'INSERT INTO vfs_dirents (parent_ino, name, name_lower, child_ino) VALUES (?, ?, ?, ?)',
          res.parentNode.ino,
          res.leafName,
          res.leafName.toLowerCase(),
          createdIno
        );
        tx.run(
          'UPDATE vfs_inodes SET nlink = nlink + 1, mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
          now,
          now,
          res.parentNode.ino
        );
      });
    }

    this._emitChanged({
      op: 'mkdir',
      path: res.canonicalPath,
      ino: createdIno,
      mount: res.mount,
      size: 0,
      actor: resolvedActor,
      pid: norm.pid,
    });

    return { path: res.canonicalPath, ino: createdIno, created: true };
  }

  unlink(path, ctx = {}) {
    const db = this._requireStorage();
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, {
      followFinal: false,
      allowMissingLeaf: false,
      mode: 'write',
    });

    if (PROTECTED_MOUNT_PATHS.has(res.canonicalPath) || res.mount === 'proc' || res.mount === 'dev') {
      throw new VfsError(`Cannot unlink protected or virtual path: ${path}`, {
        code: res.node.type === 'dir' ? ERROR_CODES.EISDIR : ERROR_CODES.EACCES,
        path,
      });
    }
    if (res.node.type === 'dir') {
      throw new VfsError(`Cannot unlink directory (use rmdir): ${path}`, {
        code: ERROR_CODES.EISDIR,
        path,
      });
    }
    if (!this.userManager.canDeleteInDir(norm.actor, res.parentNode, res.node)) {
      throw new VfsError(`Permission denied unlinking: ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }

    const removedIno = res.node.ino;
    if (res.mount === 'tmp') {
      this.virtualMounts.tmpFs.removeEntry(res.parentNode, res.leafName, {
        deferReclaim: this._hasOpenInodeRef('tmp', removedIno),
      });
    } else {
      const now = Date.now();
      db.transaction((tx) => {
        tx.run(
          'DELETE FROM vfs_dirents WHERE parent_ino = ? AND name = ?',
          res.parentNode.ino,
          res.leafName
        );
        tx.run(
          'UPDATE vfs_inodes SET nlink = MAX(0, nlink - 1), ctime_ms = ? WHERE ino = ?',
          now,
          removedIno
        );
        const updated = tx.get('SELECT nlink FROM vfs_inodes WHERE ino = ?', removedIno);
        if ((!updated || Number(updated.nlink) <= 0) && !this._hasOpenInodeRef('root', removedIno)) {
          tx.run('DELETE FROM vfs_inodes WHERE ino = ?', removedIno);
        }
        tx.run(
          'UPDATE vfs_inodes SET mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
          now,
          now,
          res.parentNode.ino
        );
      });
    }

    const resolvedActor = this.userManager._resolveActor(norm.actor);
    this._emitChanged({
      op: 'unlink',
      path: res.canonicalPath,
      ino: removedIno,
      mount: res.mount,
      size: null,
      actor: resolvedActor,
      pid: norm.pid,
    });

    return { path: res.canonicalPath, ino: removedIno };
  }

  rmdir(path, opts = {}) {
    const db = this._requireStorage();
    const norm = this._normalizeCtx(opts);
    const recursive = Boolean(readSafeOpt(opts, 'recursive', false));
    const res = this._resolvePath(path, norm, {
      followFinal: false,
      allowMissingLeaf: false,
      mode: 'write',
    });

    if (PROTECTED_MOUNT_PATHS.has(res.canonicalPath)) {
      throw new VfsError(`Cannot remove mountpoint or root directory: ${path}`, {
        code: ERROR_CODES.EINVAL,
        path,
      });
    }
    if (res.mount === 'proc' || res.mount === 'dev') {
      throw new VfsError(`Cannot remove directory on virtual mount /${res.mount}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }
    if (res.node.type !== 'dir') {
      throw new VfsError(`Not a directory: ${path}`, {
        code: ERROR_CODES.ENOTDIR,
        path,
      });
    }
    if (!this.userManager.canDeleteInDir(norm.actor, res.parentNode, res.node)) {
      throw new VfsError(`Permission denied removing directory: ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }

    const removedIno = res.node.ino;
    if (res.mount === 'tmp') {
      if (!recursive && res.node.children.size > 0) {
        throw new VfsError(`Directory not empty: ${path}`, {
          code: ERROR_CODES.ENOTEMPTY,
          path,
        });
      }
      if (recursive) {
        this._assertCanDeleteTmpSubtree(norm.actor, res.node, path);
      }
      this.virtualMounts.tmpFs.removeEntry(res.parentNode, res.leafName, {
        shouldDefer: (n) => this._hasOpenInodeRef('tmp', n.ino),
      });
    } else {
      const childCountRow = db.get(
        'SELECT COUNT(*) AS cnt FROM vfs_dirents WHERE parent_ino = ?',
        removedIno
      );
      const childCount = Number(childCountRow?.cnt ?? 0);
      if (!recursive && childCount > 0) {
        throw new VfsError(`Directory not empty: ${path}`, {
          code: ERROR_CODES.ENOTEMPTY,
          path,
        });
      }

      const now = Date.now();
      db.transaction((tx) => {
        if (recursive && childCount > 0) {
          this._deleteSqliteSubtree(tx, norm.actor, res.node, path);
        }
        tx.run(
          'DELETE FROM vfs_dirents WHERE parent_ino = ? AND name = ?',
          res.parentNode.ino,
          res.leafName
        );
        if (this._hasOpenInodeRef('root', removedIno)) {
          tx.run('UPDATE vfs_inodes SET nlink = 0, ctime_ms = ? WHERE ino = ?', now, removedIno);
        } else {
          tx.run('DELETE FROM vfs_inodes WHERE ino = ?', removedIno);
        }
        tx.run(
          'UPDATE vfs_inodes SET nlink = MAX(2, nlink - 1), mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
          now,
          now,
          res.parentNode.ino
        );
      });
    }

    const resolvedActor = this.userManager._resolveActor(norm.actor);
    this._emitChanged({
      op: 'rmdir',
      path: res.canonicalPath,
      ino: removedIno,
      mount: res.mount,
      size: null,
      actor: resolvedActor,
      pid: norm.pid,
    });

    return { path: res.canonicalPath, ino: removedIno };
  }

  _assertCanDeleteTmpSubtree(actor, rootDirNode, path) {
    if (!rootDirNode) return;
    const resolvedActor = this.userManager._resolveActor(actor);
    const stack = [rootDirNode];
    const visited = new Set([rootDirNode.ino]);
    while (stack.length > 0) {
      const dirNode = stack.pop();
      if (!dirNode || !dirNode.children) continue;
      for (const entry of dirNode.children.values()) {
        if (!this.userManager.canDeleteInDir(resolvedActor, dirNode, entry.node)) {
          throw new VfsError(`Permission denied removing subtree entry: ${entry.name}`, {
            code: ERROR_CODES.EACCES,
            path,
          });
        }
        if (entry.node.type === 'dir' && !visited.has(entry.node.ino)) {
          visited.add(entry.node.ino);
          stack.push(entry.node);
        }
      }
    }
  }

  _deleteSqliteSubtree(tx, actor, rootDirNode, path) {
    if (!rootDirNode) return;
    const now = Date.now();
    const resolvedActor = this.userManager._resolveActor(actor);
    const stack = [{ dirNode: rootDirNode, parentIno: null, entryName: null, visited: false }];
    const seenDirs = new Set([rootDirNode.ino]);

    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      if (!frame.visited) {
        frame.visited = true;
        const { dirNode } = frame;
        const children = tx.all(
          `SELECT d.name, i.ino, i.type, i.mode, i.uid, i.gid, i.size, i.nlink, i.target,
                  i.atime_ms, i.mtime_ms, i.ctime_ms, i.birthtime_ms
           FROM vfs_dirents d
           JOIN vfs_inodes i ON i.ino = d.child_ino
           WHERE d.parent_ino = ?`,
          dirNode.ino
        );
        for (const row of children) {
          const childInode = rowToInode(row);
          if (!this.userManager.canDeleteInDir(resolvedActor, dirNode, childInode)) {
            throw new VfsError(`Permission denied removing subtree entry: ${row.name}`, {
              code: ERROR_CODES.EACCES,
              path,
            });
          }
          if (childInode.type === 'dir') {
            if (seenDirs.has(childInode.ino)) {
              tx.run('DELETE FROM vfs_dirents WHERE parent_ino = ? AND name = ?', dirNode.ino, row.name);
            } else {
              seenDirs.add(childInode.ino);
              stack.push({
                dirNode: childInode,
                parentIno: dirNode.ino,
                entryName: row.name,
                visited: false,
              });
            }
          } else {
            tx.run('DELETE FROM vfs_dirents WHERE parent_ino = ? AND name = ?', dirNode.ino, row.name);
            tx.run(
              'UPDATE vfs_inodes SET nlink = MAX(0, nlink - 1), ctime_ms = ? WHERE ino = ?',
              now,
              childInode.ino
            );
            const rem = tx.get('SELECT nlink FROM vfs_inodes WHERE ino = ?', childInode.ino);
            if ((!rem || Number(rem.nlink) <= 0) && !this._hasOpenInodeRef('root', childInode.ino)) {
              tx.run('DELETE FROM vfs_inodes WHERE ino = ?', childInode.ino);
            }
          }
        }
        continue;
      }

      stack.pop();
      if (frame.parentIno !== null) {
        tx.run(
          'DELETE FROM vfs_dirents WHERE parent_ino = ? AND name = ?',
          frame.parentIno,
          frame.entryName
        );
        if (this._hasOpenInodeRef('root', frame.dirNode.ino)) {
          tx.run('UPDATE vfs_inodes SET nlink = 0, ctime_ms = ? WHERE ino = ?', now, frame.dirNode.ino);
        } else {
          tx.run('DELETE FROM vfs_inodes WHERE ino = ?', frame.dirNode.ino);
        }
      }
    }
  }

  rename(oldPath, newPath, ctx = {}) {
    const db = this._requireStorage();
    const norm = this._normalizeCtx(ctx);
    const src = this._resolvePath(oldPath, norm, {
      followFinal: false,
      allowMissingLeaf: false,
      mode: 'write',
    });
    const dst = this._resolvePath(newPath, norm, {
      followFinal: false,
      allowMissingLeaf: true,
      mode: 'write',
    });

    if (
      PROTECTED_MOUNT_PATHS.has(src.canonicalPath) ||
      PROTECTED_MOUNT_PATHS.has(dst.canonicalPath) ||
      src.mount === 'proc' ||
      src.mount === 'dev' ||
      dst.mount === 'proc' ||
      dst.mount === 'dev'
    ) {
      throw new VfsError(`Cannot rename protected or virtual mount path`, {
        code: ERROR_CODES.EACCES,
        path: oldPath,
      });
    }

    const requestedNewLeaf = dst.requestedLeafName || dst.leafName;
    assertValidFilename(requestedNewLeaf, newPath);
    const targetCanonicalPath = joinCanonical(dst.parentPath, requestedNewLeaf);

    if (!this.userManager.canDeleteInDir(norm.actor, src.parentNode, src.node)) {
      throw new VfsError(`Permission denied renaming source: ${oldPath}`, {
        code: ERROR_CODES.EACCES,
        path: oldPath,
      });
    }
    if (
      !this.userManager.canWrite(norm.actor, dst.parentNode) ||
      !this.userManager.canExec(norm.actor, dst.parentNode)
    ) {
      throw new VfsError(`Permission denied writing destination parent: ${dst.parentPath}`, {
        code: ERROR_CODES.EACCES,
        path: newPath,
      });
    }

    // Cross-mount rename between SQLite 'root' and in-memory 'tmp'
    if (src.mount !== dst.mount) {
      return this._crossMountRename(src, dst, targetCanonicalPath, norm, oldPath, newPath);
    }

    // Case-only rename or no-op rename to same inode in same parent directory
    if (dst.exists && dst.node.ino === src.node.ino && dst.parentNode.ino === src.parentNode.ino) {
      if (src.leafName !== requestedNewLeaf) {
        if (src.mount === 'tmp') {
          this.virtualMounts.tmpFs.moveEntry(
            src.parentNode,
            src.leafName,
            dst.parentNode,
            requestedNewLeaf,
            dst.leafName
          );
        } else {
          const now = Date.now();
          db.transaction((tx) => {
            tx.run(
              'UPDATE vfs_dirents SET name = ?, name_lower = ? WHERE parent_ino = ? AND name = ?',
              requestedNewLeaf,
              requestedNewLeaf.toLowerCase(),
              src.parentNode.ino,
              src.leafName
            );
            tx.run('UPDATE vfs_inodes SET ctime_ms = ? WHERE ino = ?', now, src.node.ino);
            tx.run(
              'UPDATE vfs_inodes SET mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
              now,
              now,
              src.parentNode.ino
            );
          });
        }
      }

      const resolvedActor = this.userManager._resolveActor(norm.actor);
      this._emitChanged({
        op: 'rename',
        path: targetCanonicalPath,
        oldPath: src.canonicalPath,
        ino: src.node.ino,
        mount: src.mount,
        size: src.node.size,
        actor: resolvedActor,
        pid: norm.pid,
      });
      return { oldPath: src.canonicalPath, newPath: targetCanonicalPath, ino: src.node.ino };
    }

    // Directory subtree cycle guard (both canonical prefix and inode ancestry chain)
    if (src.node.type === 'dir') {
      const isPrefixCycle = isPathWithinRoot(targetCanonicalPath, src.canonicalPath);
      const isInoCycle =
        src.mount === 'tmp'
          ? this.virtualMounts.tmpFs.isAncestor(src.node.ino, dst.parentNode)
          : this._isSqliteAncestor(db, src.node.ino, dst.parentNode.ino);
      if (isPrefixCycle || isInoCycle) {
        throw new VfsError(`Cannot rename directory into its own subtree: ${oldPath} -> ${newPath}`, {
          code: ERROR_CODES.EINVAL,
          path: newPath,
        });
      }
    }

    // POSIX destination replacement checks
    if (dst.exists) {
      if (!this.userManager.canDeleteInDir(norm.actor, dst.parentNode, dst.node)) {
        throw new VfsError(`Permission denied replacing destination: ${newPath}`, {
          code: ERROR_CODES.EACCES,
          path: newPath,
        });
      }
      if (src.node.type === 'dir' && dst.node.type !== 'dir') {
        throw new VfsError(`Cannot overwrite non-directory with directory: ${newPath}`, {
          code: ERROR_CODES.ENOTDIR,
          path: newPath,
        });
      }
      if (src.node.type !== 'dir' && dst.node.type === 'dir') {
        throw new VfsError(`Cannot overwrite directory with non-directory: ${newPath}`, {
          code: ERROR_CODES.EISDIR,
          path: newPath,
        });
      }
      if (src.node.type === 'dir' && dst.node.type === 'dir') {
        const dstEmpty =
          dst.mount === 'tmp'
            ? dst.node.children.size === 0
            : Number(
                db.get('SELECT COUNT(*) AS cnt FROM vfs_dirents WHERE parent_ino = ?', dst.node.ino)
                  ?.cnt ?? 0
              ) === 0;
        if (!dstEmpty) {
          throw new VfsError(`Target directory not empty: ${newPath}`, {
            code: ERROR_CODES.ENOTEMPTY,
            path: newPath,
          });
        }
      }
    }

    if (src.mount === 'tmp') {
      this.virtualMounts.tmpFs.moveEntry(
        src.parentNode,
        src.leafName,
        dst.parentNode,
        requestedNewLeaf,
        dst.exists ? dst.leafName : null,
        { shouldDefer: (n) => this._hasOpenInodeRef('tmp', n.ino) }
      );
    } else {
      const now = Date.now();
      db.transaction((tx) => {
        if (dst.exists) {
          tx.run(
            'DELETE FROM vfs_dirents WHERE parent_ino = ? AND name = ?',
            dst.parentNode.ino,
            dst.leafName
          );
          if (dst.node.type === 'dir') {
            if (this._hasOpenInodeRef('root', dst.node.ino)) {
              tx.run('UPDATE vfs_inodes SET nlink = 0, ctime_ms = ? WHERE ino = ?', now, dst.node.ino);
            } else {
              tx.run('DELETE FROM vfs_inodes WHERE ino = ?', dst.node.ino);
            }
            tx.run(
              'UPDATE vfs_inodes SET nlink = MAX(2, nlink - 1) WHERE ino = ?',
              dst.parentNode.ino
            );
          } else {
            tx.run(
              'UPDATE vfs_inodes SET nlink = MAX(0, nlink - 1), ctime_ms = ? WHERE ino = ?',
              now,
              dst.node.ino
            );
            const rem = tx.get('SELECT nlink FROM vfs_inodes WHERE ino = ?', dst.node.ino);
            if ((!rem || Number(rem.nlink) <= 0) && !this._hasOpenInodeRef('root', dst.node.ino)) {
              tx.run('DELETE FROM vfs_inodes WHERE ino = ?', dst.node.ino);
            }
          }
        }

        tx.run(
          'DELETE FROM vfs_dirents WHERE parent_ino = ? AND name = ?',
          src.parentNode.ino,
          src.leafName
        );
        tx.run(
          'INSERT INTO vfs_dirents (parent_ino, name, name_lower, child_ino) VALUES (?, ?, ?, ?)',
          dst.parentNode.ino,
          requestedNewLeaf,
          requestedNewLeaf.toLowerCase(),
          src.node.ino
        );

        if (src.node.type === 'dir' && src.parentNode.ino !== dst.parentNode.ino) {
          tx.run(
            'UPDATE vfs_inodes SET nlink = MAX(2, nlink - 1) WHERE ino = ?',
            src.parentNode.ino
          );
          tx.run('UPDATE vfs_inodes SET nlink = nlink + 1 WHERE ino = ?', dst.parentNode.ino);
        }

        tx.run('UPDATE vfs_inodes SET ctime_ms = ? WHERE ino = ?', now, src.node.ino);
        tx.run(
          'UPDATE vfs_inodes SET mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
          now,
          now,
          src.parentNode.ino
        );
        if (dst.parentNode.ino !== src.parentNode.ino) {
          tx.run(
            'UPDATE vfs_inodes SET mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
            now,
            now,
            dst.parentNode.ino
          );
        }
      });
    }

    const resolvedActor = this.userManager._resolveActor(norm.actor);
    this._emitChanged({
      op: 'rename',
      path: targetCanonicalPath,
      oldPath: src.canonicalPath,
      ino: src.node.ino,
      mount: dst.mount,
      size: src.node.size,
      actor: resolvedActor,
      pid: norm.pid,
    });
    return { oldPath: src.canonicalPath, newPath: targetCanonicalPath, ino: src.node.ino };
  }

  _crossMountRename(src, dst, targetCanonicalPath, norm, oldPath, newPath) {
    const db = this._requireStorage();
    if (src.node.type === 'dir') {
      throw new VfsError(`Cross-mount directory rename not supported: ${oldPath} -> ${newPath}`, {
        code: ERROR_CODES.EINVAL,
        path: newPath,
      });
    }
    if (dst.exists) {
      if (dst.node.type === 'dir') {
        throw new VfsError(`Cannot overwrite directory with file: ${newPath}`, {
          code: ERROR_CODES.EISDIR,
          path: newPath,
        });
      }
      if (!this.userManager.canDeleteInDir(norm.actor, dst.parentNode, dst.node)) {
        throw new VfsError(`Permission denied replacing destination: ${newPath}`, {
          code: ERROR_CODES.EACCES,
          path: newPath,
        });
      }
    }

    let createdIno;
    const dstFreedBytes =
      dst.exists && !this._hasOpenInodeRef(dst.mount, dst.node.ino)
        ? this._getNodeQuotaBytes(db, dst.mount, dst.node)
        : 0;

    if (src.node.type === 'symlink') {
      const targetBytes = TEXT_ENCODER.encode(src.node.target).byteLength;
      const netDelta = targetBytes - dstFreedBytes;
      if (dst.mount === 'tmp') {
        this.virtualMounts.tmpFs.assertQuota(netDelta, targetCanonicalPath);
      } else {
        this._assertSqliteQuota(db, netDelta, targetCanonicalPath);
      }
      if (dst.exists) {
        this.unlink(dst.canonicalPath, { uid: ROOT_UID, gid: 0 });
      }
      const sym = this.symlink(src.node.target, targetCanonicalPath, {
        uid: ROOT_UID,
        gid: 0,
      });
      // Preserve symlink owner/group directly (lchown semantics — safe for dangling & live links)
      if (dst.mount === 'tmp') {
        const symNode = this.virtualMounts.tmpFs.getNodeByIno(sym.ino);
        if (symNode) {
          symNode.uid = src.node.uid;
          symNode.gid = src.node.gid;
        }
      } else {
        db.transaction((tx) => {
          tx.run(
            'UPDATE vfs_inodes SET uid = ?, gid = ? WHERE ino = ?',
            src.node.uid,
            src.node.gid,
            sym.ino
          );
        });
      }
      createdIno = sym.ino;
    } else {
      const data = this.readFile(src.canonicalPath, { uid: ROOT_UID, gid: 0 });
      // Pre-validate destination quota BEFORE unlinking dst so ENOSPC never destroys dst!
      const netDelta = data.byteLength - dstFreedBytes;
      if (dst.mount === 'tmp') {
        this.virtualMounts.tmpFs.assertQuota(netDelta, targetCanonicalPath);
      } else {
        this._assertSqliteQuota(db, netDelta, targetCanonicalPath);
      }

      if (dst.exists) {
        this.unlink(dst.canonicalPath, { uid: ROOT_UID, gid: 0 });
      }
      const written = this.writeFile(targetCanonicalPath, data, {
        uid: ROOT_UID,
        gid: 0,
        mode: src.node.mode,
      });
      this.chown(targetCanonicalPath, src.node.uid, src.node.gid, { uid: ROOT_UID, gid: 0 });
      createdIno = written.ino;
    }

    this.unlink(src.canonicalPath, { uid: ROOT_UID, gid: 0 });
    return { oldPath: src.canonicalPath, newPath: targetCanonicalPath, ino: createdIno };
  }

  symlink(target, linkPath, ctx = {}) {
    const db = this._requireStorage();
    if (typeof target !== 'string' || target.length === 0) {
      throw new VfsError('Symlink target must be a non-empty string without control characters', {
        code: ERROR_CODES.EINVAL,
        path: safePath(linkPath),
      });
    }
    if (target.length > MAX_PATH_LENGTH) {
      throw new VfsError(`Symlink target exceeds maximum length (${MAX_PATH_LENGTH})`, {
        code: ERROR_CODES.EINVAL,
        path: safePath(linkPath),
      });
    }
    if (CONTROL_CHAR_RE.test(target)) {
      throw new VfsError('Symlink target must be a non-empty string without control characters', {
        code: ERROR_CODES.EINVAL,
        path: safePath(linkPath),
      });
    }
    const size = TEXT_ENCODER.encode(target).byteLength;
    if (size > MAX_PATH_LENGTH) {
      throw new VfsError(`Symlink target exceeds maximum length (${MAX_PATH_LENGTH})`, {
        code: ERROR_CODES.EINVAL,
        path: safePath(linkPath),
      });
    }
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(linkPath, norm, {
      followFinal: false,
      allowMissingLeaf: true,
      mode: 'write',
    });

    if (res.exists) {
      throw new VfsError(`File already exists: ${linkPath}`, {
        code: ERROR_CODES.EEXIST,
        path: linkPath,
      });
    }
    if (res.mount === 'proc' || res.mount === 'dev') {
      throw new VfsError(`Cannot create symlink on virtual mount /${res.mount}`, {
        code: ERROR_CODES.EACCES,
        path: linkPath,
      });
    }
    assertValidFilename(res.leafName, linkPath);
    if (
      !this.userManager.canWrite(norm.actor, res.parentNode) ||
      !this.userManager.canExec(norm.actor, res.parentNode)
    ) {
      throw new VfsError(`Permission denied creating symlink in ${res.parentPath}`, {
        code: ERROR_CODES.EACCES,
        path: linkPath,
      });
    }

    const resolvedActor = this.userManager._resolveActor(norm.actor);
    let createdIno;

    if (res.mount === 'tmp') {
      const node = this.virtualMounts.tmpFs.createSymlink(res.parentNode, res.leafName, target, {
        uid: resolvedActor.uid,
        gid: resolvedActor.gid,
        path: res.canonicalPath,
      });
      createdIno = node.ino;
    } else {
      const now = Date.now();
      db.transaction((tx) => {
        this._assertSqliteQuota(tx, size, res.canonicalPath);
        const ins = tx.run(
          `INSERT INTO vfs_inodes
            (type, mode, uid, gid, size, nlink, target, atime_ms, mtime_ms, ctime_ms, birthtime_ms)
           VALUES ('symlink', ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
          0o777,
          resolvedActor.uid,
          resolvedActor.gid,
          size,
          target,
          now,
          now,
          now,
          now
        );
        createdIno = ins.lastInsertRowid;
        tx.run(
          'INSERT INTO vfs_dirents (parent_ino, name, name_lower, child_ino) VALUES (?, ?, ?, ?)',
          res.parentNode.ino,
          res.leafName,
          res.leafName.toLowerCase(),
          createdIno
        );
        tx.run(
          'UPDATE vfs_inodes SET mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
          now,
          now,
          res.parentNode.ino
        );
      });
    }

    this._emitChanged({
      op: 'symlink',
      path: res.canonicalPath,
      ino: createdIno,
      mount: res.mount,
      size,
      actor: resolvedActor,
      pid: norm.pid,
    });

    return { path: res.canonicalPath, target, ino: createdIno };
  }

  readlink(path, ctx = {}) {
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, { followFinal: false, allowMissingLeaf: false });
    if (res.node.type !== 'symlink') {
      throw new VfsError(`Not a symbolic link: ${path}`, {
        code: ERROR_CODES.EINVAL,
        path,
      });
    }
    return res.node.target;
  }

  chmod(path, mode, ctx = {}) {
    const db = this._requireStorage();
    const cleanMode = assertValidMode(mode, path);
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, {
      followFinal: true,
      allowMissingLeaf: false,
      mode: 'write',
    });

    if (res.mount === 'proc' || res.mount === 'dev') {
      throw new VfsError(`Cannot chmod on virtual mount /${res.mount}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }
    if (!this.userManager.canChmod(norm.actor, res.node)) {
      throw new VfsError(`Permission denied changing mode of ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }

    const now = Date.now();
    if (res.mount === 'tmp') {
      res.node.mode = cleanMode;
      res.node.ctimeMs = now;
    } else {
      db.transaction((tx) => {
        tx.run(
          'UPDATE vfs_inodes SET mode = ?, ctime_ms = ? WHERE ino = ?',
          cleanMode,
          now,
          res.node.ino
        );
      });
    }

    const resolvedActor = this.userManager._resolveActor(norm.actor);
    this._emitChanged({
      op: 'chmod',
      path: res.canonicalPath,
      ino: res.node.ino,
      mount: res.mount,
      size: res.node.size,
      actor: resolvedActor,
      pid: norm.pid,
    });

    return { path: res.canonicalPath, ino: res.node.ino, mode: cleanMode };
  }

  chown(path, uid, gid, ctx = {}) {
    const db = this._requireStorage();
    assertNonNegativeInt(uid, 'uid', path);
    assertNonNegativeInt(gid, 'gid', path);
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, {
      followFinal: true,
      allowMissingLeaf: false,
      mode: 'write',
    });

    if (res.mount === 'proc' || res.mount === 'dev') {
      throw new VfsError(`Cannot chown on virtual mount /${res.mount}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }
    if (!this.userManager.canChown(norm.actor, res.node, uid, gid)) {
      throw new VfsError(`Permission denied changing ownership of ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }

    const now = Date.now();
    if (res.mount === 'tmp') {
      res.node.uid = uid;
      res.node.gid = gid;
      res.node.ctimeMs = now;
    } else {
      db.transaction((tx) => {
        tx.run(
          'UPDATE vfs_inodes SET uid = ?, gid = ?, ctime_ms = ? WHERE ino = ?',
          uid,
          gid,
          now,
          res.node.ino
        );
      });
    }

    const resolvedActor = this.userManager._resolveActor(norm.actor);
    this._emitChanged({
      op: 'chown',
      path: res.canonicalPath,
      ino: res.node.ino,
      mount: res.mount,
      size: res.node.size,
      actor: resolvedActor,
      pid: norm.pid,
    });

    return { path: res.canonicalPath, ino: res.node.ino, uid, gid };
  }

  // ---- Extended Attributes (xattrs) ----

  setXattr(path, name, value, ctx = {}) {
    const db = this._requireStorage();
    const nameBytes = assertValidXattrName(name, path);
    const bytes = normalizeBytes(value, path);
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, {
      followFinal: true,
      allowMissingLeaf: false,
      mode: 'write',
    });

    if (res.mount === 'proc' || res.mount === 'dev') {
      throw new VfsError(`Cannot set xattr on virtual mount /${res.mount}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }
    if (!this.userManager.canWrite(norm.actor, res.node) && !this.userManager.canChmod(norm.actor, res.node)) {
      throw new VfsError(`Permission denied setting xattr on ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }

    if (res.mount === 'tmp') {
      this.virtualMounts.tmpFs.setXattr(res.node, name, bytes, { path: res.canonicalPath });
    } else {
      db.transaction((tx) => {
        const existing = tx.get(
          'SELECT LENGTH(value) AS val_len FROM vfs_xattrs WHERE ino = ? AND name = ?',
          res.node.ino,
          name
        );
        const delta = existing
          ? bytes.byteLength - Number(existing.val_len ?? 0)
          : nameBytes + bytes.byteLength;
        this._assertSqliteQuota(tx, delta, res.canonicalPath);
        tx.run(
          `INSERT INTO vfs_xattrs (ino, name, value) VALUES (?, ?, ?)
           ON CONFLICT(ino, name) DO UPDATE SET value = excluded.value`,
          res.node.ino,
          name,
          bytes
        );
      });
    }

    const resolvedActor = this.userManager._resolveActor(norm.actor);
    this._emitChanged({
      op: 'xattr',
      path: res.canonicalPath,
      ino: res.node.ino,
      mount: res.mount,
      size: res.node.size,
      actor: resolvedActor,
      pid: norm.pid,
    });
    return { path: res.canonicalPath, name, size: bytes.byteLength };
  }

  getXattr(path, name, ctx = {}) {
    const db = this._requireStorage();
    assertValidXattrName(name, path);
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, { followFinal: true, allowMissingLeaf: false });
    if (!this.userManager.canRead(norm.actor, res.node)) {
      throw new VfsError(`Permission denied reading xattr on ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }
    if (res.mount === 'proc' || res.mount === 'dev') return null;
    if (res.mount === 'tmp') {
      const val = res.node.xattrs.get(name);
      return val ? val.slice() : null;
    }
    const row = db.get('SELECT value FROM vfs_xattrs WHERE ino = ? AND name = ?', res.node.ino, name);
    return row?.value ? new Uint8Array(row.value).slice() : null;
  }

  listXattrs(path, ctx = {}) {
    const db = this._requireStorage();
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, { followFinal: true, allowMissingLeaf: false });
    if (!this.userManager.canRead(norm.actor, res.node)) {
      throw new VfsError(`Permission denied listing xattrs on ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }
    if (res.mount === 'proc' || res.mount === 'dev') return [];
    if (res.mount === 'tmp') {
      return Array.from(res.node.xattrs.keys()).sort();
    }
    const rows = db.all('SELECT name FROM vfs_xattrs WHERE ino = ? ORDER BY name ASC', res.node.ino);
    return rows.map((r) => r.name);
  }

  removeXattr(path, name, ctx = {}) {
    const db = this._requireStorage();
    assertValidXattrName(name, path);
    const norm = this._normalizeCtx(ctx);
    const res = this._resolvePath(path, norm, {
      followFinal: true,
      allowMissingLeaf: false,
      mode: 'write',
    });
    if (res.mount === 'proc' || res.mount === 'dev') {
      throw new VfsError(`Cannot remove xattr on virtual mount /${res.mount}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }
    if (!this.userManager.canWrite(norm.actor, res.node) && !this.userManager.canChmod(norm.actor, res.node)) {
      throw new VfsError(`Permission denied removing xattr on ${path}`, {
        code: ERROR_CODES.EACCES,
        path,
      });
    }
    if (res.mount === 'tmp') {
      return this.virtualMounts.tmpFs.removeXattr(res.node, name);
    }
    const r = db.transaction((tx) =>
      tx.run('DELETE FROM vfs_xattrs WHERE ino = ? AND name = ?', res.node.ino, name)
    );
    return r.changes > 0;
  }

  // ---- File Descriptors & Handle API (Wired to ProcessManager FDs & EMFILE) ----

  _assertPidCanOpenFd(pid) {
    const pm = this.processManager;
    if (pid === null || !pm) {
      return;
    }
    let pcb = null;
    let state;
    let fdSize;
    let maxOpenFds;
    try {
      if (typeof pm.has !== 'function' || !pm.has(pid)) {
        return;
      }
      pcb = typeof pm.get === 'function' ? pm.get(pid) : null;
      if (!pcb) return;
      state = pcb.state;
      if (pcb.fdTable && pcb.quotas) {
        fdSize = pcb.fdTable.size;
        maxOpenFds = pcb.quotas.maxOpenFds;
      }
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new VfsError('ProcessManager is unavailable or revoked', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (state === 'ZOMBIE' || state === 'TERMINATED') {
      throw new ProcessError(`Cannot open FD on ${state} PID ${pid}`, {
        code: ERROR_CODES.EINVAL,
        pid,
      });
    }
    if (fdSize !== undefined && maxOpenFds !== undefined && fdSize >= maxOpenFds) {
      throw new QuotaExceededError(
        `PID ${pid} exceeded maxOpenFds limit (${maxOpenFds})`,
        {
          code: ERROR_CODES.EMFILE,
          quotaType: 'openFds',
          limit: maxOpenFds,
          actual: fdSize,
          pid,
        }
      );
    }
  }

  open(path, flags = 'r', ctx = {}) {
    const db = this._requireStorage();
    const mask = parseOpenFlags(flags, path);
    const access = mask & 3;
    const wantRead = access === OPEN_FLAGS.O_RDONLY || access === OPEN_FLAGS.O_RDWR;
    const wantWrite = access === OPEN_FLAGS.O_WRONLY || access === OPEN_FLAGS.O_RDWR;
    const isCreate = (mask & OPEN_FLAGS.O_CREAT) !== 0;
    const isExcl = (mask & OPEN_FLAGS.O_EXCL) !== 0;
    const isTrunc = (mask & OPEN_FLAGS.O_TRUNC) !== 0;
    const isAppend = (mask & OPEN_FLAGS.O_APPEND) !== 0;
    const isDirectory = (mask & OPEN_FLAGS.O_DIRECTORY) !== 0;

    const norm = this._normalizeCtx(ctx);
    const resolvedActor = this.userManager._resolveActor(norm.actor);
    const res = this._resolvePath(path, norm, {
      followFinal: !(isCreate && isExcl),
      allowMissingLeaf: isCreate,
      mode: wantWrite ? 'write' : 'read',
    });

    if (res.exists && isCreate && isExcl) {
      throw new VfsError(`File already exists (O_EXCL): ${path}`, {
        code: ERROR_CODES.EEXIST,
        path,
      });
    }

    let node = res.node;
    const mount = res.mount;
    const canonicalPath = res.canonicalPath;

    if (!res.exists) {
      if (!isCreate) {
        throw new VfsError(`No such file or directory: ${path}`, {
          code: ERROR_CODES.ENOENT,
          path,
        });
      }
      if (mount === 'proc' || mount === 'dev') {
        throw new VfsError(`Cannot create file on virtual mount /${mount}`, {
          code: ERROR_CODES.EACCES,
          path,
        });
      }
      assertValidFilename(res.leafName, path);
      if (
        !this.userManager.canWrite(norm.actor, res.parentNode) ||
        !this.userManager.canExec(norm.actor, res.parentNode)
      ) {
        throw new VfsError(`Permission denied creating file in ${res.parentPath}`, {
          code: ERROR_CODES.EACCES,
          path,
        });
      }
      const createMode = assertValidMode(readSafeOpt(ctx, 'mode', 0o644) ?? 0o644, path);
      // Pre-validate PID liveness & maxOpenFds BEFORE any O_CREAT filesystem mutation!
      this._assertPidCanOpenFd(norm.pid);

      const empty = new Uint8Array(0);
      if (mount === 'tmp') {
        node = this.virtualMounts.tmpFs.createFile(res.parentNode, res.leafName, empty, {
          mode: createMode,
          uid: resolvedActor.uid,
          gid: resolvedActor.gid,
          path: canonicalPath,
        });
      } else {
        const now = Date.now();
        let newIno;
        db.transaction((tx) => {
          const ins = tx.run(
            `INSERT INTO vfs_inodes
              (type, mode, uid, gid, size, nlink, target, atime_ms, mtime_ms, ctime_ms, birthtime_ms)
             VALUES ('file', ?, ?, ?, 0, 1, NULL, ?, ?, ?, ?)`,
            createMode,
            resolvedActor.uid,
            resolvedActor.gid,
            now,
            now,
            now,
            now
          );
          newIno = ins.lastInsertRowid;
          tx.run(
            'INSERT INTO vfs_dirents (parent_ino, name, name_lower, child_ino) VALUES (?, ?, ?, ?)',
            res.parentNode.ino,
            res.leafName,
            res.leafName.toLowerCase(),
            newIno
          );
          tx.run('INSERT INTO vfs_blobs (ino, data) VALUES (?, ?)', newIno, empty);
          tx.run(
            'UPDATE vfs_inodes SET mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
            now,
            now,
            res.parentNode.ino
          );
        });
        node = this._getSqliteInode(db, newIno);
      }
      this._emitChanged({
        op: 'write',
        path: canonicalPath,
        ino: node.ino,
        mount,
        size: 0,
        actor: resolvedActor,
        pid: norm.pid,
      });
    } else {
      if (isDirectory && node.type !== 'dir') {
        throw new VfsError(`Not a directory: ${path}`, { code: ERROR_CODES.ENOTDIR, path });
      }
      if (wantWrite && node.type === 'dir') {
        throw new VfsError(`Is a directory: ${path}`, { code: ERROR_CODES.EISDIR, path });
      }
      if (wantWrite && mount === 'proc') {
        throw new VfsError(`Read-only virtual mount /proc: ${path}`, {
          code: ERROR_CODES.EACCES,
          path,
        });
      }
      if (wantRead && !this.userManager.canRead(norm.actor, node)) {
        throw new VfsError(`Permission denied opening for read: ${path}`, {
          code: ERROR_CODES.EACCES,
          path,
        });
      }
      if (wantWrite && !this.userManager.canWrite(norm.actor, node)) {
        throw new VfsError(`Permission denied opening for write: ${path}`, {
          code: ERROR_CODES.EACCES,
          path,
        });
      }
      // Pre-validate PID liveness & maxOpenFds BEFORE any O_TRUNC mutation!
      this._assertPidCanOpenFd(norm.pid);

      if (isTrunc && wantWrite && node.type === 'file') {
        if (mount === 'tmp') {
          this.virtualMounts.tmpFs.updateFileData(node, new Uint8Array(0), { path: canonicalPath });
        } else if (mount === 'root') {
          const now = Date.now();
          db.transaction((tx) => {
            tx.run(
              `INSERT INTO vfs_blobs (ino, data) VALUES (?, ?)
               ON CONFLICT(ino) DO UPDATE SET data = excluded.data`,
              node.ino,
              new Uint8Array(0)
            );
            tx.run(
              'UPDATE vfs_inodes SET size = 0, mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
              now,
              now,
              node.ino
            );
          });
          node.size = 0;
        }
        if (mount === 'tmp' || mount === 'root') {
          this._emitChanged({
            op: 'write',
            path: canonicalPath,
            ino: node.ino,
            mount,
            size: 0,
            actor: resolvedActor,
            pid: norm.pid,
          });
        }
      }
    }

    const initialPos = isAppend && node.type === 'file' ? node.size : 0;
    const handle = new VfsFileHandle({
      vfs: this,
      fd: -1,
      path: canonicalPath,
      ino: node.ino,
      mount,
      flags: mask,
      pos: initialPos,
      pid: norm.pid,
      actor: resolvedActor,
      deviceName: mount === 'dev' ? node.name : null,
      procNode: mount === 'proc' ? node : null,
    });

    const pm = this.processManager;
    let hasPidInPm = false;
    if (norm.pid !== null && pm) {
      try {
        hasPidInPm = typeof pm.has === 'function' && Boolean(pm.has(norm.pid));
        if (hasPidInPm) {
          const fd = pm.openFd(norm.pid, {
            type: node.type === 'device' ? 'device' : 'file',
            path: canonicalPath,
            flags: mask,
            pos: initialPos,
            handle,
            onClose: () => {
              if (!handle._closingFromKernel) {
                handle._markClosedFromKernel();
              }
            },
          });
          handle.fd = fd;
        }
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new VfsError('ProcessManager is unavailable or revoked', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }
    if (!hasPidInPm) {
      handle.fd = this._nextStandaloneFd++;
    }

    this._genuineHandles.add(handle);
    this._openHandles.set(this._handleKey(handle.pid, handle.fd), handle);
    this._incInodeRef(handle.mount, handle.ino);
    return handle;
  }

  _handleKey(pid, fd) {
    if (pid !== null && (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 0)) {
      throw new VfsError(`Invalid pid: ${safeDisplay(pid)}`, { code: ERROR_CODES.EINVAL });
    }
    if (typeof fd !== 'number' || !Number.isSafeInteger(fd) || fd < 0) {
      throw new VfsError(`Invalid fd: ${safeDisplay(fd)}`, { code: ERROR_CODES.EINVAL });
    }
    return `${pid === null ? 'standalone' : pid}:${fd}`;
  }

  _inodeRefKey(mount, ino) {
    return `${mount}:${ino}`;
  }

  _incInodeRef(mount, ino) {
    if (mount !== 'root' && mount !== 'tmp') return;
    const key = this._inodeRefKey(mount, ino);
    this._openInodeRefs.set(key, (this._openInodeRefs.get(key) ?? 0) + 1);
  }

  _hasOpenInodeRef(mount, ino) {
    if (mount !== 'root' && mount !== 'tmp') return false;
    return (this._openInodeRefs.get(this._inodeRefKey(mount, ino)) ?? 0) > 0;
  }

  _decInodeRef(mount, ino) {
    if (mount !== 'root' && mount !== 'tmp') return;
    const key = this._inodeRefKey(mount, ino);
    const cur = this._openInodeRefs.get(key) ?? 0;
    if (cur <= 1) {
      this._openInodeRefs.delete(key);
      this._reclaimIfUnlinked(mount, ino);
    } else {
      this._openInodeRefs.set(key, cur - 1);
    }
  }

  _reclaimIfUnlinked(mount, ino) {
    if (mount === 'tmp') {
      this.virtualMounts.tmpFs.reclaimIfUnlinked(ino);
      return;
    }
    if (mount === 'root') {
      try {
        if (this._storage?.isOpen) {
          this._storage.transaction((tx) => {
            const row = tx.get('SELECT nlink FROM vfs_inodes WHERE ino = ?', ino);
            if (row && Number(row.nlink) <= 0) {
              tx.run('DELETE FROM vfs_inodes WHERE ino = ?', ino);
            }
          });
        }
      } catch {
        // Storage may already be closing or unreadable during teardown
      }
    }
  }

  _removeHandleRef(handle) {
    const key = this._handleKey(handle.pid, handle.fd);
    const existed = this._openHandles.delete(key);
    if (existed) {
      this._decInodeRef(handle.mount, handle.ino);
    }
  }

  _resolveHandleArg(fdOrHandle, opts = {}) {
    const rawPid = readSafeOpt(opts, 'pid', null);
    const pid = rawPid !== undefined && rawPid !== null ? rawPid : null;
    if (pid !== null && (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 0)) {
      throw new VfsError(`Invalid pid: ${safeDisplay(pid)}`, {
        code: ERROR_CODES.EINVAL,
      });
    }

    if (fdOrHandle !== null && fdOrHandle !== undefined && typeof fdOrHandle === 'object') {
      if (this._genuineHandles.has(fdOrHandle)) {
        let hFd;
        let hPid;
        try {
          hFd = fdOrHandle.fd;
          hPid = fdOrHandle.pid;
        } catch {
          throw new VfsError('Unreadable file handle', { code: ERROR_CODES.EINVAL });
        }
        if (
          typeof hFd !== 'number' ||
          !Number.isSafeInteger(hFd) ||
          hFd < 0 ||
          (hPid !== null && (typeof hPid !== 'number' || !Number.isSafeInteger(hPid) || hPid < 0))
        ) {
          throw new VfsError(`Bad file descriptor: ${safeDisplay(hFd)}`, {
            code: ERROR_CODES.EBADF,
          });
        }
        return fdOrHandle;
      }
      throw new VfsError(`Bad file descriptor: ${safeDisplay(fdOrHandle)}`, {
        code: ERROR_CODES.EBADF,
      });
    }

    if (typeof fdOrHandle === 'number' && Number.isSafeInteger(fdOrHandle) && fdOrHandle >= 0) {
      const direct = this._openHandles.get(this._handleKey(pid, fdOrHandle));
      if (direct) return direct;
      if (pid !== null && this.processManager) {
        let entry = null;
        try {
          const pm = this.processManager;
          entry = typeof pm.getFd === 'function' ? pm.getFd(pid, fdOrHandle) : null;
        } catch (err) {
          if (err instanceof OmniOSError) throw err;
          throw new VfsError('ProcessManager is unavailable or revoked', {
            code: ERROR_CODES.EINVAL,
          });
        }
        if (entry?.handle && this._genuineHandles.has(entry.handle)) {
          return entry.handle;
        }
      }
    }
    throw new VfsError(`Bad file descriptor: ${safeDisplay(fdOrHandle)}`, {
      code: ERROR_CODES.EBADF,
    });
  }

  _syncKernelFdPos(handle) {
    if (handle.pid !== null && this.processManager) {
      try {
        const pm = this.processManager;
        if (typeof pm.getFd === 'function') {
          const entry = pm.getFd(handle.pid, handle.fd);
          if (entry) {
            entry.pos = handle.pos;
          }
        }
      } catch {
        // ProcessManager may be unavailable or revoked; local handle.pos remains authoritative
      }
    }
  }

  _readHandle(handle, length = 4096, offset = undefined) {
    handle._assertOpen();
    const access = handle.flags & 3;
    if (access === OPEN_FLAGS.O_WRONLY) {
      throw new VfsError(`File descriptor ${handle.fd} is not open for reading`, {
        code: ERROR_CODES.EBADF,
        path: handle.path,
      });
    }
    assertNonNegativeInt(length, 'length', handle.path);
    if (offset !== undefined) {
      assertNonNegativeInt(offset, 'offset', handle.path);
    }

    if (handle.mount === 'dev') {
      if (!handle._deviceName) {
        throw new VfsError(`Is a directory: ${handle.path}`, {
          code: ERROR_CODES.EISDIR,
          path: handle.path,
        });
      }
      return this.virtualMounts.devFs.readDevice(handle._deviceName, length);
    }

    if (handle.mount === 'proc') {
      if (!handle._procNode || handle._procNode.type === 'dir') {
        throw new VfsError(`Is a directory: ${handle.path}`, {
          code: ERROR_CODES.EISDIR,
          path: handle.path,
        });
      }
      const full = this.virtualMounts.procFs.readNode(handle._procNode);
      const readPos = offset !== undefined ? offset : handle.pos;
      const slice = readPos >= full.byteLength
        ? new Uint8Array(0)
        : full.slice(readPos, Math.min(full.byteLength, readPos + length));
      if (offset === undefined) {
        handle.pos = readPos + slice.byteLength;
        this._syncKernelFdPos(handle);
      }
      return slice;
    }

    const readPos = offset !== undefined ? offset : handle.pos;
    let data;
    if (handle.mount === 'tmp') {
      const node = this.virtualMounts.tmpFs.getNodeByIno(handle.ino);
      if (!node) return new Uint8Array(0);
      if (node.type === 'dir') {
        throw new VfsError(`Is a directory: ${handle.path}`, {
          code: ERROR_CODES.EISDIR,
          path: handle.path,
        });
      }
      data = node.data ?? new Uint8Array(0);
    } else {
      const db = this._requireStorage();
      const node = this._getSqliteInode(db, handle.ino);
      if (!node) return new Uint8Array(0);
      if (node.type === 'dir') {
        throw new VfsError(`Is a directory: ${handle.path}`, {
          code: ERROR_CODES.EISDIR,
          path: handle.path,
        });
      }
      const blobRow = db.get('SELECT data FROM vfs_blobs WHERE ino = ?', handle.ino);
      data = blobRow?.data ? new Uint8Array(blobRow.data) : new Uint8Array(0);
    }

    const out =
      readPos >= data.byteLength
        ? new Uint8Array(0)
        : data.slice(readPos, Math.min(data.byteLength, readPos + length));
    if (offset === undefined) {
      handle.pos = readPos + out.byteLength;
      this._syncKernelFdPos(handle);
    }
    return out;
  }

  _writeHandle(handle, data, offset = undefined) {
    handle._assertOpen();
    const access = handle.flags & 3;
    if (access === OPEN_FLAGS.O_RDONLY) {
      throw new VfsError(`File descriptor ${handle.fd} is not open for writing`, {
        code: ERROR_CODES.EBADF,
        path: handle.path,
      });
    }
    if (handle.mount === 'proc') {
      throw new VfsError(`Read-only virtual mount /proc: ${handle.path}`, {
        code: ERROR_CODES.EACCES,
        path: handle.path,
      });
    }

    const bytes = normalizeBytes(data, handle.path);
    if (offset !== undefined) {
      assertNonNegativeInt(offset, 'offset', handle.path);
    }

    if (handle.mount === 'dev') {
      if (!handle._deviceName) {
        throw new VfsError(`Is a directory: ${handle.path}`, {
          code: ERROR_CODES.EISDIR,
          path: handle.path,
        });
      }
      const wRes = this.virtualMounts.devFs.writeDevice(handle._deviceName, bytes);
      return { bytesWritten: wRes.bytesWritten, pos: handle.pos, size: 0 };
    }

    const isAppend = (handle.flags & OPEN_FLAGS.O_APPEND) !== 0;
    let newSize = 0;

    if (handle.mount === 'tmp') {
      const node = this.virtualMounts.tmpFs.getNodeByIno(handle.ino);
      if (!node) {
        throw new VfsError(`Open file target no longer exists: ${handle.path}`, {
          code: ERROR_CODES.EBADF,
          path: handle.path,
        });
      }
      if (node.type === 'dir') {
        throw new VfsError(`Is a directory: ${handle.path}`, {
          code: ERROR_CODES.EISDIR,
          path: handle.path,
        });
      }
      const existing = node.data ?? new Uint8Array(0);
      const writePos = isAppend ? existing.byteLength : (offset !== undefined ? offset : handle.pos);
      const targetLen = Math.max(existing.byteLength, writePos + bytes.byteLength);
      this.virtualMounts.tmpFs.assertQuota(targetLen - existing.byteLength, handle.path);
      const merged = new Uint8Array(targetLen);
      merged.set(existing, 0);
      merged.set(bytes, writePos);
      this.virtualMounts.tmpFs.updateFileData(node, merged, { path: handle.path });
      newSize = node.size;
      if (offset === undefined || isAppend) {
        handle.pos = writePos + bytes.byteLength;
        this._syncKernelFdPos(handle);
      }
    } else {
      const db = this._requireStorage();
      const now = Date.now();
      let newPos = handle.pos;
      db.transaction((tx) => {
        const node = this._getSqliteInode(tx, handle.ino);
        if (!node) {
          throw new VfsError(`Open file target no longer exists: ${handle.path}`, {
            code: ERROR_CODES.EBADF,
            path: handle.path,
          });
        }
        if (node.type === 'dir') {
          throw new VfsError(`Is a directory: ${handle.path}`, {
            code: ERROR_CODES.EISDIR,
            path: handle.path,
          });
        }
        const blobRow = tx.get('SELECT data FROM vfs_blobs WHERE ino = ?', handle.ino);
        const existing = blobRow?.data ? new Uint8Array(blobRow.data) : new Uint8Array(0);
        const writePos = isAppend ? existing.byteLength : (offset !== undefined ? offset : handle.pos);
        const targetLen = Math.max(existing.byteLength, writePos + bytes.byteLength);
        this._assertSqliteQuota(tx, targetLen - existing.byteLength, handle.path);
        const merged = new Uint8Array(targetLen);
        merged.set(existing, 0);
        merged.set(bytes, writePos);
        tx.run(
          `INSERT INTO vfs_blobs (ino, data) VALUES (?, ?)
           ON CONFLICT(ino) DO UPDATE SET data = excluded.data`,
          handle.ino,
          merged
        );
        tx.run(
          'UPDATE vfs_inodes SET size = ?, mtime_ms = ?, ctime_ms = ? WHERE ino = ?',
          targetLen,
          now,
          now,
          handle.ino
        );
        newSize = targetLen;
        if (offset === undefined || isAppend) {
          newPos = writePos + bytes.byteLength;
        }
      });
      handle.pos = newPos;
      this._syncKernelFdPos(handle);
    }

    this._emitChanged({
      op: 'write',
      path: handle.path,
      ino: handle.ino,
      mount: handle.mount,
      size: newSize,
      actor: handle._actor,
      pid: handle.pid,
    });

    return { bytesWritten: bytes.byteLength, pos: handle.pos, size: newSize };
  }

  _seekHandle(handle, offset, whence = SEEK_WHENCE.SEEK_SET) {
    handle._assertOpen();
    if (typeof offset !== 'number' || !Number.isSafeInteger(offset)) {
      throw new VfsError(`Invalid seek offset: ${safeDisplay(offset)}`, {
        code: ERROR_CODES.EINVAL,
        path: handle.path,
      });
    }

    let w;
    if (whence === 0 || whence === 'SET' || whence === 'SEEK_SET') w = SEEK_WHENCE.SEEK_SET;
    else if (whence === 1 || whence === 'CUR' || whence === 'SEEK_CUR') w = SEEK_WHENCE.SEEK_CUR;
    else if (whence === 2 || whence === 'END' || whence === 'SEEK_END') w = SEEK_WHENCE.SEEK_END;
    else {
      throw new VfsError(`Invalid seek whence: ${safeDisplay(whence)}`, {
        code: ERROR_CODES.EINVAL,
        path: handle.path,
      });
    }

    let base = 0;
    if (w === SEEK_WHENCE.SEEK_CUR) {
      base = handle.pos;
    } else if (w === SEEK_WHENCE.SEEK_END) {
      if (handle.mount === 'tmp') {
        const node = this.virtualMounts.tmpFs.getNodeByIno(handle.ino);
        base = node ? node.size : 0;
      } else if (handle.mount === 'root') {
        const db = this._requireStorage();
        const node = this._getSqliteInode(db, handle.ino);
        base = node ? node.size : 0;
      } else if (handle.mount === 'proc' && handle._procNode) {
        base = this.virtualMounts.procFs.readNode(handle._procNode).byteLength;
      } else {
        base = 0;
      }
    }

    const nextPos = base + offset;
    if (!Number.isSafeInteger(nextPos) || nextPos < 0) {
      throw new VfsError(`Invalid resulting seek position: ${nextPos}`, {
        code: ERROR_CODES.EINVAL,
        path: handle.path,
      });
    }
    handle.pos = nextPos;
    this._syncKernelFdPos(handle);
    return handle.pos;
  }

  _statHandle(handle) {
    handle._assertOpen();
    if (handle.mount === 'dev') {
      const dev = handle._deviceName
        ? this.virtualMounts.devFs.lookupChild(this.virtualMounts.devFs.getRootNode(), handle._deviceName)?.node
        : this.virtualMounts.devFs.getRootNode();
      if (!dev) {
        throw new VfsError(`Device missing: ${handle.path}`, { code: ERROR_CODES.ENOENT, path: handle.path });
      }
      return makeStatObject(dev);
    }
    if (handle.mount === 'proc') {
      const node = handle._procNode ?? this.virtualMounts.procFs.getRootNode();
      if (node.type === 'file') {
        const bytes = this.virtualMounts.procFs.readNode(node);
        return makeStatObject({ ...node, size: bytes.byteLength });
      }
      return makeStatObject(node);
    }
    if (handle.mount === 'tmp') {
      const node = this.virtualMounts.tmpFs.getNodeByIno(handle.ino);
      if (!node) {
        throw new VfsError(`Handle inode no longer exists: ${handle.path}`, {
          code: ERROR_CODES.EBADF,
          path: handle.path,
        });
      }
      return makeStatObject(node);
    }
    const db = this._requireStorage();
    const node = this._getSqliteInode(db, handle.ino);
    if (!node) {
      throw new VfsError(`Handle inode no longer exists: ${handle.path}`, {
        code: ERROR_CODES.EBADF,
        path: handle.path,
      });
    }
    return makeStatObject(node);
  }

  _closeHandle(handle) {
    handle._assertOpen();
    handle.closed = true;
    this._removeHandleRef(handle);

    const pm = this.processManager;
    if (handle.pid !== null && pm) {
      handle._closingFromKernel = true;
      try {
        if (typeof pm.getFd === 'function' && pm.getFd(handle.pid, handle.fd)) {
          pm.closeFd(handle.pid, handle.fd);
        }
      } catch {
        // Process may already have exited or processManager may be revoked during teardown
      } finally {
        handle._closingFromKernel = false;
      }
    }
    return true;
  }

  read(fdOrHandle, length = 4096, opts = {}) {
    const handle = this._resolveHandleArg(fdOrHandle, opts);
    return this._readHandle(handle, length, readSafeOpt(opts, 'offset', undefined));
  }

  write(fdOrHandle, data, opts = {}) {
    const handle = this._resolveHandleArg(fdOrHandle, opts);
    return this._writeHandle(handle, data, readSafeOpt(opts, 'offset', undefined));
  }

  seek(fdOrHandle, offset, whence = SEEK_WHENCE.SEEK_SET, opts = {}) {
    const handle = this._resolveHandleArg(fdOrHandle, opts);
    return this._seekHandle(handle, offset, whence);
  }

  closeHandle(fdOrHandle, opts = {}) {
    const handle = this._resolveHandleArg(fdOrHandle, opts);
    return this._closeHandle(handle);
  }

  closeAllHandles() {
    const handles = Array.from(this._openHandles.values());
    let closedCount = 0;
    for (const h of handles) {
      if (!h.closed) {
        try {
          this._closeHandle(h);
          closedCount += 1;
        } catch {
          h.closed = true;
          this._removeHandleRef(h);
        }
      }
    }
    this._openHandles.clear();
    this._openInodeRefs.clear();
    return closedCount;
  }

  // ---- Mounts & Telemetry ----

  listMounts() {
    return this.virtualMounts.listMounts();
  }

  getStorageStats() {
    const db = this._requireStorage();
    const usedBytes = this._getSqliteUsedBytes(db);
    const countRow = db.get('SELECT COUNT(*) AS cnt FROM vfs_inodes');
    return {
      usedBytes,
      maxStorageBytes: this.maxStorageBytes,
      inodeCount: Number(countRow?.cnt ?? 0),
      tmpUsedBytes: this.virtualMounts.tmpFs.usedBytes,
      maxTmpBytes: this.virtualMounts.tmpFs.maxBytes,
      openHandles: this._openHandles.size,
    };
  }
}

export function createVFS(options = {}) {
  return new VFS(options);
}

export function registerVfsService(serviceManager, vfs, opts = {}) {
  if (!serviceManager || typeof serviceManager !== 'object') {
    throw new VfsError('Invalid registerVfsService serviceManager: expected object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  let registerFn;
  try {
    registerFn = serviceManager.register;
  } catch {
    throw new VfsError('Unreadable registerVfsService serviceManager', {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (typeof registerFn !== 'function') {
    throw new VfsError('Invalid registerVfsService serviceManager: missing register()', {
      code: ERROR_CODES.EINVAL,
    });
  }

  if (!vfs || typeof vfs !== 'object') {
    throw new VfsError('Invalid registerVfsService vfs dependency: expected object', {
      code: ERROR_CODES.EINVAL,
    });
  }
  try {
    if (typeof vfs.init !== 'function') {
      throw new VfsError('Invalid registerVfsService vfs dependency: missing init()', {
        code: ERROR_CODES.EINVAL,
      });
    }
  } catch (err) {
    if (err instanceof OmniOSError) throw err;
    throw new VfsError('Unreadable registerVfsService vfs dependency', {
      code: ERROR_CODES.EINVAL,
    });
  }

  const kernel = readSafeOpt(opts, 'kernel', null);
  const getStorage = readSafeOpt(opts, 'getStorage', null);
  const deps = readSafeOpt(opts, 'deps', []);
  const essential = readSafeOpt(opts, 'essential', true);
  const description = readSafeOpt(opts, 'description', 'OmniOS Unified POSIX VFS Daemon');

  if (kernel !== null && kernel !== undefined) {
    if (typeof kernel !== 'object') {
      throw new VfsError('Invalid registerVfsService kernel dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      void kernel.storage;
    } catch {
      throw new VfsError('Unreadable registerVfsService kernel dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  if (getStorage !== null && getStorage !== undefined) {
    if (typeof getStorage !== 'function') {
      throw new VfsError('Invalid registerVfsService getStorage dependency: expected function', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      void getStorage.length;
    } catch {
      throw new VfsError('Unreadable registerVfsService getStorage dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }

  let running = false;
  return registerFn.call(serviceManager, {
    name: 'vfsd',
    deps,
    essential,
    description,
    start() {
      let storage = null;
      try {
        storage = getStorage ? getStorage() : (kernel?.storage ?? null);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new VfsError('Unreadable storage dependency in vfsd.start()', {
          code: ERROR_CODES.EINVAL,
        });
      }
      try {
        vfs.init(storage);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new VfsError('Failed to start vfsd: unreadable VFS dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
      running = true;
    },
    stop() {
      running = false;
      try {
        vfs.closeAllHandles();
        vfs.virtualMounts.clearTmp();
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new VfsError('Failed to stop vfsd: unreadable VFS dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
      // NEVER close shared kernel.storage!
    },
    healthCheck() {
      try {
        if (!running || !vfs.isReady) {
          return { ok: false, reason: 'vfsd stopped or storage closed' };
        }
        const rootStat = vfs.stat('/', { uid: ROOT_UID, gid: 0 });
        return rootStat.type === 'dir'
          ? { ok: true }
          : { ok: false, reason: 'root inode is not a directory' };
      } catch {
        return { ok: false, reason: 'vfsd health check failed' };
      }
    },
  });
}
