/**
 * OmniOS Universal WebAssembly / WASI Preview 1 & `omni_os_v1` Host Bridge (`F-056`, Edge Case `#29`)
 * Zero external dependencies, zero `node:fs` imports.
 *
 * Security invariants enforced on every call:
 *  - `MAX_IOVS = 1024`: any `iovs_len >>> 0 > 1024` returns `WASI_EINVAL (28)` immediately.
 *  - Non-overflowing linear-memory bounds check `checkMem(ptr, len)`: validates unsigned 32-bit
 *    `p <= mem.byteLength && n <= mem.byteLength - p`, returning `WASI_EFAULT (21)` (or `-21` for
 *    handle/byte-count `omni_os_v1` functions) on OOB. Never lets JS `RangeError` escape.
 *  - Preopen capability & path-jail enforcement: FD 0/1/2 stdio, FD 3 preopened `appRecord.dataDir`
 *    (virtual name `'.'`), optional additional preopens only when explicitly granted. Rejects
 *    leading `/`, NUL bytes, and `..` escaping preopen root with `WASI_ENOTCAPABLE (76)`;
 *    enforces per-FD `rightsBase`/`rightsInheriting` bitmasks; maps VFS errors via `posixCodeToWasi`.
 */

import crypto from 'node:crypto';
import { WASI_ERRNO, ERROR_CODES, posixCodeToWasi } from '../../common/errors.mjs';
import { OPEN_FLAGS, SEEK_WHENCE } from '../../vfs/vfs.mjs';

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: false });

function freezeLookup(obj) {
  return Object.freeze(Object.assign(Object.create(null), obj));
}

const WASI_RIGHTS = freezeLookup({
  FD_DATASYNC: 1n << 0n,
  FD_READ: 1n << 1n,
  FD_SEEK: 1n << 2n,
  FD_FDSTAT_SET_FLAGS: 1n << 3n,
  FD_SYNC: 1n << 4n,
  FD_TELL: 1n << 5n,
  FD_WRITE: 1n << 6n,
  FD_ADVISE: 1n << 7n,
  FD_ALLOCATE: 1n << 8n,
  PATH_CREATE_DIRECTORY: 1n << 9n,
  PATH_CREATE_FILE: 1n << 10n,
  PATH_LINK_SOURCE: 1n << 11n,
  PATH_LINK_TARGET: 1n << 12n,
  PATH_OPEN: 1n << 13n,
  FD_READDIR: 1n << 14n,
  PATH_READLINK: 1n << 15n,
  PATH_RENAME_SOURCE: 1n << 16n,
  PATH_RENAME_TARGET: 1n << 17n,
  PATH_FILESTAT_GET: 1n << 18n,
  PATH_FILESTAT_SET_SIZE: 1n << 19n,
  PATH_FILESTAT_SET_TIMES: 1n << 20n,
  FD_FILESTAT_GET: 1n << 21n,
  FD_FILESTAT_SET_SIZE: 1n << 22n,
  FD_FILESTAT_SET_TIMES: 1n << 23n,
  PATH_SYMLINK: 1n << 24n,
  PATH_REMOVE_DIRECTORY: 1n << 25n,
  PATH_UNLINK_FILE: 1n << 26n,
  POLL_FD_READWRITE: 1n << 27n,
  SOCK_SHUTDOWN: 1n << 28n,
  SOCK_ACCEPT: 1n << 29n,
});

const RIGHTS_FILE_READ =
  WASI_RIGHTS.FD_READ |
  WASI_RIGHTS.FD_SEEK |
  WASI_RIGHTS.FD_TELL |
  WASI_RIGHTS.FD_ADVISE |
  WASI_RIGHTS.FD_FILESTAT_GET |
  WASI_RIGHTS.POLL_FD_READWRITE;

const RIGHTS_FILE_WRITE =
  WASI_RIGHTS.FD_DATASYNC |
  WASI_RIGHTS.FD_WRITE |
  WASI_RIGHTS.FD_SEEK |
  WASI_RIGHTS.FD_FDSTAT_SET_FLAGS |
  WASI_RIGHTS.FD_SYNC |
  WASI_RIGHTS.FD_TELL |
  WASI_RIGHTS.FD_ADVISE |
  WASI_RIGHTS.FD_ALLOCATE |
  WASI_RIGHTS.FD_FILESTAT_GET |
  WASI_RIGHTS.FD_FILESTAT_SET_SIZE |
  WASI_RIGHTS.FD_FILESTAT_SET_TIMES |
  WASI_RIGHTS.POLL_FD_READWRITE;

const RIGHTS_DIR_READ =
  WASI_RIGHTS.PATH_OPEN |
  WASI_RIGHTS.FD_READDIR |
  WASI_RIGHTS.PATH_READLINK |
  WASI_RIGHTS.PATH_FILESTAT_GET |
  WASI_RIGHTS.FD_FILESTAT_GET |
  WASI_RIGHTS.FD_SYNC |
  WASI_RIGHTS.FD_DATASYNC |
  WASI_RIGHTS.POLL_FD_READWRITE;

const RIGHTS_DIR_WRITE =
  WASI_RIGHTS.PATH_CREATE_DIRECTORY |
  WASI_RIGHTS.PATH_CREATE_FILE |
  WASI_RIGHTS.PATH_LINK_SOURCE |
  WASI_RIGHTS.PATH_LINK_TARGET |
  WASI_RIGHTS.PATH_RENAME_SOURCE |
  WASI_RIGHTS.PATH_RENAME_TARGET |
  WASI_RIGHTS.PATH_FILESTAT_SET_SIZE |
  WASI_RIGHTS.PATH_FILESTAT_SET_TIMES |
  WASI_RIGHTS.FD_FILESTAT_SET_TIMES |
  WASI_RIGHTS.PATH_SYMLINK |
  WASI_RIGHTS.PATH_REMOVE_DIRECTORY |
  WASI_RIGHTS.PATH_UNLINK_FILE;

const RIGHTS_DIR_ALL = RIGHTS_DIR_READ | RIGHTS_DIR_WRITE;
const RIGHTS_ALL = RIGHTS_DIR_ALL | RIGHTS_FILE_READ | RIGHTS_FILE_WRITE;

const RIGHTS_STDIN =
  WASI_RIGHTS.FD_READ | WASI_RIGHTS.FD_FILESTAT_GET | WASI_RIGHTS.POLL_FD_READWRITE;

const RIGHTS_STDOUT =
  WASI_RIGHTS.FD_WRITE | WASI_RIGHTS.FD_FILESTAT_GET | WASI_RIGHTS.POLL_FD_READWRITE;

export const WASI_CONSTANTS = Object.freeze({
  MAX_IOVS: 1024,
  ERRNO: WASI_ERRNO,
  CLOCKID: freezeLookup({
    REALTIME: 0,
    MONOTONIC: 1,
    PROCESS_CPUTIME_ID: 2,
    THREAD_CPUTIME_ID: 3,
  }),
  FILETYPE: freezeLookup({
    UNKNOWN: 0,
    BLOCK_DEVICE: 1,
    CHARACTER_DEVICE: 2,
    DIRECTORY: 3,
    REGULAR_FILE: 4,
    SOCKET_DGRAM: 5,
    SOCKET_STREAM: 6,
    SYMBOLIC_LINK: 7,
  }),
  FDFLAGS: freezeLookup({
    APPEND: 1,
    DSYNC: 2,
    NONBLOCK: 4,
    RSYNC: 8,
    SYNC: 16,
  }),
  OFLAGS: freezeLookup({
    CREAT: 1,
    DIRECTORY: 2,
    EXCL: 4,
    TRUNC: 8,
  }),
  LOOKUPFLAGS: freezeLookup({
    SYMLINK_FOLLOW: 1,
  }),
  WHENCE: freezeLookup({
    SET: 0,
    CUR: 1,
    END: 2,
  }),
  PREOPENTYPE: freezeLookup({
    DIR: 0,
  }),
  FSTFLAGS: freezeLookup({
    ATIM: 1,
    ATIM_NOW: 2,
    MTIM: 4,
    MTIM_NOW: 8,
  }),
  EVENTTYPE: freezeLookup({
    CLOCK: 0,
    FD_READ: 1,
    FD_WRITE: 2,
  }),
  SUBCLOCKFLAGS: freezeLookup({
    SUBSCRIPTION_CLOCK_ABSTIME: 1,
  }),
  RIGHTS: WASI_RIGHTS,
  RIGHTS_SETS: freezeLookup({
    STDIN: RIGHTS_STDIN,
    STDOUT: RIGHTS_STDOUT,
    FILE_READ: RIGHTS_FILE_READ,
    FILE_WRITE: RIGHTS_FILE_WRITE,
    FILE_ALL: RIGHTS_FILE_READ | RIGHTS_FILE_WRITE,
    DIR_READ: RIGHTS_DIR_READ,
    DIR_ALL: RIGHTS_DIR_ALL,
    ALL: RIGHTS_ALL,
  }),
  OMNI_EVENT: freezeLookup({
    CLICK: 1,
    ACTION: 2,
    KEYDOWN: 3,
    INPUT: 4,
    POINTER_DOWN: 5,
    POINTER_MOVE: 6,
    POINTER_UP: 7,
    MENU_ACTION: 8,
    INTENT: 9,
    WINDOW_CLOSE: 10,
    NOTIFICATION_ACTION: 11,
  }),
});

/**
 * Thrown by `wasi_snapshot_preview1.proc_exit(code)` to unwind WebAssembly cleanly.
 */
export class WasiExitSignal extends Error {
  constructor(exitCode = 0) {
    const code = typeof exitCode === 'number' && Number.isFinite(exitCode) ? (exitCode >>> 0) : 0;
    super(`WASI process exited with code ${code}`);
    this.name = 'WasiExitSignal';
    this.exitCode = code;
  }
}

function toU64(val) {
  if (typeof val === 'bigint') return BigInt.asUintN(64, val);
  if (typeof val === 'number' && Number.isFinite(val)) {
    return BigInt.asUintN(64, BigInt(Math.trunc(val)));
  }
  return 0n;
}

function toI64(val) {
  if (typeof val === 'bigint') return BigInt.asIntN(64, val);
  if (typeof val === 'number' && Number.isFinite(val)) {
    return BigInt.asIntN(64, BigInt(Math.trunc(val)));
  }
  return 0n;
}

function vfsTypeToWasiFiletype(type) {
  switch (type) {
    case 'file':
      return WASI_CONSTANTS.FILETYPE.REGULAR_FILE;
    case 'dir':
      return WASI_CONSTANTS.FILETYPE.DIRECTORY;
    case 'symlink':
      return WASI_CONSTANTS.FILETYPE.SYMBOLIC_LINK;
    case 'device':
      return WASI_CONSTANTS.FILETYPE.CHARACTER_DEVICE;
    default:
      return WASI_CONSTANTS.FILETYPE.UNKNOWN;
  }
}

function mapVfsErrorToWasi(err) {
  if (!err || typeof err !== 'object') return WASI_ERRNO.WASI_EIO;
  if (
    err.code === ERROR_CODES.E_PATH_TRAVERSAL ||
    err.code === ERROR_CODES.E_SANDBOX_VIOLATION ||
    err.code === ERROR_CODES.ENOTCAPABLE ||
    err.details?.violation === ERROR_CODES.E_PATH_TRAVERSAL
  ) {
    return WASI_ERRNO.WASI_ENOTCAPABLE;
  }
  return posixCodeToWasi(err.code);
}

function normalizeRootPath(rawPath) {
  if (typeof rawPath !== 'string' || rawPath.length === 0 || rawPath.length > 4096) {
    return null;
  }
  if (!rawPath.startsWith('/')) {
    return null;
  }
  if (rawPath.includes('\\')) {
    return null;
  }
  for (let i = 0; i < rawPath.length; i++) {
    const code = rawPath.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return null;
    }
  }
  const parts = rawPath.split('/');
  const cleanParts = [];
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i];
    if (seg === '') continue;
    if (seg === '.' || seg === '..') {
      return null;
    }
    cleanParts.push(seg);
  }
  return cleanParts.length === 0 ? '/' : `/${cleanParts.join('/')}`;
}

function writeFilestatToView(view, offset, st) {
  // WASI filestat (64 bytes, 8-byte aligned)
  for (let i = 0; i < 64; i += 8) {
    view.setBigUint64(offset + i, 0n, true);
  }
  const mtimeMs = typeof st.mtimeMs === 'number' && Number.isFinite(st.mtimeMs) ? st.mtimeMs : 0;
  const ctimeMs = typeof st.ctimeMs === 'number' && Number.isFinite(st.ctimeMs) ? st.ctimeMs : mtimeMs;
  const parsedAtime = typeof st.atime === 'string' ? Date.parse(st.atime) : mtimeMs;
  const atimeMs = Number.isFinite(parsedAtime) ? parsedAtime : mtimeMs;

  const atimNs = BigInt(Math.max(0, Math.trunc(atimeMs))) * 1_000_000n;
  const mtimNs = BigInt(Math.max(0, Math.trunc(mtimeMs))) * 1_000_000n;
  const ctimNs = BigInt(Math.max(0, Math.trunc(ctimeMs))) * 1_000_000n;

  view.setBigUint64(offset + 0, 1n, true); // dev
  view.setBigUint64(offset + 8, BigInt(Math.max(0, Math.trunc(st.ino ?? 0))), true); // ino
  view.setUint8(offset + 16, vfsTypeToWasiFiletype(st.type)); // filetype
  view.setBigUint64(offset + 24, BigInt(Math.max(1, Math.trunc(st.nlink ?? 1))), true); // nlink
  view.setBigUint64(offset + 32, BigInt(Math.max(0, Math.trunc(st.size ?? 0))), true); // size
  view.setBigUint64(offset + 40, atimNs, true); // atim
  view.setBigUint64(offset + 48, mtimNs, true); // mtim
  view.setBigUint64(offset + 56, ctimNs, true); // ctim
}

export class WasiBridge {
  constructor({
    pcb = null,
    appRecord = null,
    services = {},
    args = [],
    env = {},
    preopens = null,
    memory = null,
  } = {}) {
    this._pcb = pcb;
    this._appRecord = appRecord;
    this._services = services ?? {};
    this._vfs = this._services.vfs ?? null;
    this._processManager = this._services.processManager ?? this._services.kernel?.processManager ?? null;
    this._compositor = this._services.compositor ?? null;
    this._clipboard = this._services.clipboard ?? null;
    this._notifications = this._services.notifications ?? null;
    this._ipc = this._services.ipc ?? null;
    this._intentRouter = this._services.intentRouter ?? null;
    this._permissions = this._services.permissions ?? null;
    this._kernel = this._services.kernel ?? null;

    this._pid = pcb?.pid ?? 0;
    this._uid = pcb?.uid ?? appRecord?.uid ?? 1000;
    this._gid = pcb?.gid ?? appRecord?.gid ?? 1000;
    this._appId = appRecord?.appId ?? pcb?.appId ?? 'universal.wasm';

    this._args = Array.isArray(args) ? args.map((a) => String(a)) : [];
    this._envEntries = Object.entries(env ?? {}).map(([k, v]) => `${k}=${v ?? ''}`);

    this._memory = null;
    this._cachedBuf = null;
    this._cachedOffset = 0;
    this._cachedLen = 0;
    this._cachedU8 = null;
    this._cachedView = null;
    if (memory) {
      this.setMemory(memory);
    }

    this._startHrTime = process.hrtime.bigint();
    this._fds = new Map();
    this._nextFd = 3;
    this._windows = new Map();
    this._nextWindowHandle = 1;
    this._disposed = false;

    this.exited = false;
    this.exitCode = 0;
    this.lastSyscall = null;
    this.syscallCount = 0;
    this.logs = [];

    // Fallback buffers when running standalone without ProcessManager
    this._fallbackStdin = new Uint8Array(0);
    this._fallbackStdoutChunks = [];
    this._fallbackStderrChunks = [];

    this._initStandardFds(preopens);
  }

  _initStandardFds(extraPreopens) {
    // FD 0: stdin
    this._fds.set(0, {
      fd: 0,
      type: 'stream',
      filetype: WASI_CONSTANTS.FILETYPE.CHARACTER_DEVICE,
      hostPath: '/dev/stdin',
      preopenRoot: null,
      relSegments: [],
      virtualName: null,
      vfsHandle: null,
      rightsBase: RIGHTS_STDIN,
      rightsInheriting: 0n,
      fdFlags: 0,
      actorUid: this._uid,
      actorGid: this._gid,
    });
    // FD 1: stdout
    this._fds.set(1, {
      fd: 1,
      type: 'stream',
      filetype: WASI_CONSTANTS.FILETYPE.CHARACTER_DEVICE,
      hostPath: '/dev/stdout',
      preopenRoot: null,
      relSegments: [],
      virtualName: null,
      vfsHandle: null,
      rightsBase: RIGHTS_STDOUT,
      rightsInheriting: 0n,
      fdFlags: 0,
      actorUid: this._uid,
      actorGid: this._gid,
    });
    // FD 2: stderr
    this._fds.set(2, {
      fd: 2,
      type: 'stream',
      filetype: WASI_CONSTANTS.FILETYPE.CHARACTER_DEVICE,
      hostPath: '/dev/stderr',
      preopenRoot: null,
      relSegments: [],
      virtualName: null,
      vfsHandle: null,
      rightsBase: RIGHTS_STDOUT,
      rightsInheriting: 0n,
      fdFlags: 0,
      actorUid: this._uid,
      actorGid: this._gid,
    });

    // FD 3: preopened appRecord.dataDir (virtual dir name '.')
    const primaryDataDir =
      normalizeRootPath(this._appRecord?.dataDir ?? this._pcb?.cwd ?? '/tmp') ?? '/tmp';
    this._fds.set(3, {
      fd: 3,
      type: 'preopen',
      filetype: WASI_CONSTANTS.FILETYPE.DIRECTORY,
      hostPath: primaryDataDir,
      preopenRoot: primaryDataDir,
      relSegments: [],
      virtualName: '.',
      vfsHandle: null,
      rightsBase: RIGHTS_DIR_ALL,
      rightsInheriting: RIGHTS_ALL,
      fdFlags: 0,
      actorUid: this._uid,
      actorGid: this._gid,
    });
    this._nextFd = 4;

    // Optional additional preopens from untrusted manifest:
    // NEVER read/trust `spec.capability`! Derive required capabilities strictly from validated `hPath` & `wantWrite`.
    const manifestPreopens = this._appRecord?.metadata?.manifest?.preopens;
    if (Array.isArray(manifestPreopens)) {
      for (const spec of manifestPreopens) {
        if (!spec || typeof spec !== 'object') continue;
        const vName = typeof spec.virtualName === 'string' && spec.virtualName.length > 0 ? spec.virtualName : null;
        const hPath = typeof spec.hostPath === 'string' && spec.hostPath.length > 0 ? normalizeRootPath(spec.hostPath) : null;
        if (!vName || !hPath) continue;
        if (vName.includes('\0') || vName.includes('\\')) continue;

        // Strictly forbid root, container, and sensitive parent directories
        // ('/', '/home', '/var' are parents of '/root', '/home/user', '/var/appdata')
        if (
          hPath === '/' ||
          hPath === '/home' ||
          hPath === '/var' ||
          hPath === '/root' ||
          hPath.startsWith('/root/') ||
          hPath === '/var/appdata' ||
          hPath.startsWith('/var/appdata/')
        ) {
          continue;
        }

        const wantWrite = Boolean(spec.writable);
        const isUserPath = hPath === '/home/user' || hPath.startsWith('/home/user/');

        let actorUid = this._uid;
        let actorGid = this._gid;

        if (isUserPath) {
          if (!this._isCapabilityExplicitlyAllowed('fs.read.user')) continue;
          if (wantWrite && !this._isCapabilityExplicitlyAllowed('fs.write.user')) continue;
          actorUid = 1000;
          actorGid = 1000;
        } else {
          if (!this._isCapabilityExplicitlyAllowed('fs.read.system')) continue;
          if (wantWrite && !this._isCapabilityExplicitlyAllowed('fs.write.system')) continue;
          // Keep app's own actorUid/actorGid (no UID 1000 escalation outside /home/user)
        }

        const fd = this._allocFd();
        this._fds.set(fd, {
          fd,
          type: 'preopen',
          filetype: WASI_CONSTANTS.FILETYPE.DIRECTORY,
          hostPath: hPath,
          preopenRoot: hPath,
          relSegments: [],
          virtualName: vName,
          vfsHandle: null,
          rightsBase: wantWrite ? RIGHTS_DIR_ALL : RIGHTS_DIR_READ,
          rightsInheriting: wantWrite ? RIGHTS_ALL : (RIGHTS_DIR_READ | RIGHTS_FILE_READ),
          fdFlags: 0,
          actorUid,
          actorGid,
        });
      }
    }

    // Optional explicit constructor preopens (for direct runtime / unit configuration)
    if (Array.isArray(extraPreopens)) {
      for (const spec of extraPreopens) {
        if (!spec || typeof spec !== 'object') continue;
        const vName = typeof spec.virtualName === 'string' && spec.virtualName.length > 0 ? spec.virtualName : null;
        const hPath = typeof spec.hostPath === 'string' && spec.hostPath.length > 0 ? normalizeRootPath(spec.hostPath) : null;
        if (!vName || !hPath) continue;
        if (spec.capability && !this._isCapabilityExplicitlyAllowed(spec.capability)) continue;
        const isUserPath = hPath === '/home/user' || hPath.startsWith('/home/user/');
        const fd = this._allocFd();
        const writable = spec.writable !== false;
        this._fds.set(fd, {
          fd,
          type: 'preopen',
          filetype: WASI_CONSTANTS.FILETYPE.DIRECTORY,
          hostPath: hPath,
          preopenRoot: hPath,
          relSegments: [],
          virtualName: vName,
          vfsHandle: null,
          rightsBase: spec.rightsBase !== undefined ? toU64(spec.rightsBase) : (writable ? RIGHTS_DIR_ALL : RIGHTS_DIR_READ),
          rightsInheriting: spec.rightsInheriting !== undefined ? toU64(spec.rightsInheriting) : (writable ? RIGHTS_ALL : (RIGHTS_DIR_READ | RIGHTS_FILE_READ)),
          fdFlags: 0,
          actorUid: spec.uid ?? (isUserPath ? 1000 : this._uid),
          actorGid: spec.gid ?? (isUserPath ? 1000 : this._gid),
        });
      }
    }
  }

  _isCapabilityExplicitlyAllowed(capability) {
    if (!this._permissions || typeof this._permissions.getGrant !== 'function') {
      return false;
    }
    try {
      const grant = this._permissions.getGrant(this._appId, capability);
      return Boolean(grant && grant.state === 'allow');
    } catch {
      return false;
    }
  }

  _isCapabilityExplicitlyDenied(capability) {
    if (!this._permissions || typeof this._permissions.getGrant !== 'function') {
      return false;
    }
    try {
      const grant = this._permissions.getGrant(this._appId, capability);
      return Boolean(grant && grant.state === 'deny');
    } catch {
      return false;
    }
  }

  _recordSyscall(name) {
    this.lastSyscall = name;
    this.syscallCount += 1;
    if (this._pcb?.stats) {
      this._pcb.stats.syscallsCount += 1;
    }
  }

  _allocFd() {
    while (this._fds.has(this._nextFd)) {
      this._nextFd += 1;
    }
    const fd = this._nextFd;
    this._nextFd += 1;
    return fd;
  }

  setMemory(memory) {
    this._memory = memory;
    this._cachedBuf = null;
    this._cachedOffset = 0;
    this._cachedLen = 0;
    this._cachedU8 = null;
    this._cachedView = null;
  }

  bindMemory(memory) {
    this.setMemory(memory);
  }

  setFallbackStdin(data) {
    this._fallbackStdin = typeof data === 'string' ? TEXT_ENCODER.encode(data) : new Uint8Array(data);
  }

  getFallbackStdout() {
    const total = this._fallbackStdoutChunks.reduce((acc, c) => acc + c.byteLength, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of this._fallbackStdoutChunks) {
      out.set(c, off);
      off += c.byteLength;
    }
    return TEXT_DECODER.decode(out);
  }

  getFallbackStderr() {
    const total = this._fallbackStderrChunks.reduce((acc, c) => acc + c.byteLength, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of this._fallbackStderrChunks) {
      out.set(c, off);
      off += c.byteLength;
    }
    return TEXT_DECODER.decode(out);
  }

  _getMem() {
    const mem = this._memory;
    if (!mem) return null;
    let buf;
    let byteOffset = 0;
    let byteLength = 0;
    try {
      if (mem instanceof WebAssembly.Memory) {
        buf = mem.buffer;
        byteLength = buf.byteLength;
      } else if (mem instanceof ArrayBuffer) {
        buf = mem;
        byteLength = buf.byteLength;
      } else if (ArrayBuffer.isView(mem)) {
        buf = mem.buffer;
        byteOffset = mem.byteOffset;
        byteLength = mem.byteLength;
      } else {
        return null;
      }
    } catch {
      return null;
    }
    if (
      this._cachedBuf !== buf ||
      this._cachedOffset !== byteOffset ||
      this._cachedLen !== byteLength
    ) {
      this._cachedBuf = buf;
      this._cachedOffset = byteOffset;
      this._cachedLen = byteLength;
      this._cachedU8 = new Uint8Array(buf, byteOffset, byteLength);
      this._cachedView = new DataView(buf, byteOffset, byteLength);
    }
    return { u8: this._cachedU8, view: this._cachedView, byteLength };
  }

  /**
   * Non-overflowing linear-memory bounds check (Edge Case #29).
   * Returns `{ p, n, u8, view }` on success, or `null` if OOB / overflow / detached.
   */
  checkMem(ptr, len) {
    const mem = this._getMem();
    if (!mem) return null;
    if (
      typeof ptr !== 'number' ||
      typeof len !== 'number' ||
      !Number.isFinite(ptr) ||
      !Number.isFinite(len) ||
      ptr < -0x80000000 ||
      len < -0x80000000 ||
      ptr > 0xffffffff ||
      len > 0xffffffff
    ) {
      return null;
    }
    const p = ptr >>> 0;
    const n = len >>> 0;
    if (p > mem.byteLength || n > mem.byteLength - p) {
      return null;
    }
    return { p, n, u8: mem.u8, view: mem.view };
  }

  _readUtf8(ptr, len) {
    const m = this.checkMem(ptr, len);
    if (!m) return null;
    return TEXT_DECODER.decode(m.u8.subarray(m.p, m.p + m.n));
  }

  /**
   * Validates iovecs descriptor table & every individual `{ bufPtr, bufLen }` slice (Edge Case #29).
   * Returns `{ errno: 0, slices }` or `{ errno: WASI_EINVAL | WASI_EFAULT }`.
   */
  _readIovs(iovsPtr, iovsLen) {
    if (
      typeof iovsLen !== 'number' ||
      !Number.isFinite(iovsLen) ||
      iovsLen < -0x80000000 ||
      iovsLen > 0xffffffff
    ) {
      return { errno: WASI_ERRNO.WASI_EINVAL };
    }
    const count = iovsLen >>> 0;
    if (count > WASI_CONSTANTS.MAX_IOVS) {
      return { errno: WASI_ERRNO.WASI_EINVAL };
    }
    // count <= 1024, so tableBytes <= 8192 (overflow-free)
    const tableBytes = count * 8;
    const tbl = this.checkMem(iovsPtr, tableBytes);
    if (!tbl) {
      return { errno: WASI_ERRNO.WASI_EFAULT };
    }
    const slices = new Array(count);
    for (let i = 0; i < count; i++) {
      const bufPtr = tbl.view.getUint32(tbl.p + i * 8, true);
      const bufLen = tbl.view.getUint32(tbl.p + i * 8 + 4, true);
      const slice = this.checkMem(bufPtr, bufLen);
      if (!slice) {
        return { errno: WASI_ERRNO.WASI_EFAULT };
      }
      slices[i] = slice;
    }
    return { errno: WASI_ERRNO.WASI_ESUCCESS, slices };
  }

  _requireFd(fd, requiredRight = 0n) {
    if (typeof fd !== 'number' || !Number.isFinite(fd) || fd < 0 || fd > 0xffffffff) {
      return { errno: WASI_ERRNO.WASI_EBADF };
    }
    const entry = this._fds.get(fd >>> 0);
    if (!entry) {
      return { errno: WASI_ERRNO.WASI_EBADF };
    }
    if (entry.vfsHandle && entry.vfsHandle.closed) {
      this._fds.delete(fd >>> 0);
      return { errno: WASI_ERRNO.WASI_EBADF };
    }
    if (requiredRight !== 0n && (entry.rightsBase & requiredRight) !== requiredRight) {
      return { errno: WASI_ERRNO.WASI_ENOTCAPABLE };
    }
    return { errno: WASI_ERRNO.WASI_ESUCCESS, entry };
  }

  _vfsCtxForEntry(entry) {
    return {
      pid: this._processManager && this._pid > 0 ? this._pid : null,
      uid: entry.actorUid,
      gid: entry.actorGid,
      cwd: entry.hostPath,
      platform: 'posix',
      appId: this._appId,
      sandboxRoot: entry.preopenRoot,
    };
  }

  /**
   * Resolves a WASI relative path strictly inside `dirEntry.preopenRoot`.
   * Rejects leading `/`, NUL bytes, and `..` escaping the preopen root with `WASI_ENOTCAPABLE (76)`.
   */
  _resolveWithinDirFd(dirEntry, relPath) {
    if (dirEntry.filetype !== WASI_CONSTANTS.FILETYPE.DIRECTORY || !dirEntry.preopenRoot) {
      return { errno: WASI_ERRNO.WASI_ENOTDIR };
    }
    if (typeof relPath !== 'string' || relPath.length === 0) {
      return { errno: WASI_ERRNO.WASI_ENOENT };
    }
    if (relPath.includes('\0')) {
      return { errno: WASI_ERRNO.WASI_ENOTCAPABLE };
    }
    if (relPath.startsWith('/')) {
      return { errno: WASI_ERRNO.WASI_ENOTCAPABLE };
    }

    const stack = Array.isArray(dirEntry.relSegments) ? [...dirEntry.relSegments] : [];
    const parts = relPath.split('/');
    for (let i = 0; i < parts.length; i++) {
      const seg = parts[i];
      if (seg === '' || seg === '.') continue;
      if (seg === '..') {
        if (stack.length === 0) {
          return { errno: WASI_ERRNO.WASI_ENOTCAPABLE };
        }
        stack.pop();
        continue;
      }
      stack.push(seg);
    }

    const root = dirEntry.preopenRoot;
    const fullPath =
      stack.length === 0
        ? root
        : root === '/'
          ? `/${stack.join('/')}`
          : `${root}/${stack.join('/')}`;

    if (fullPath !== root && !(root === '/' ? fullPath.startsWith('/') : fullPath.startsWith(`${root}/`))) {
      return { errno: WASI_ERRNO.WASI_ENOTCAPABLE };
    }

    return {
      errno: WASI_ERRNO.WASI_ESUCCESS,
      fullPath,
      relSegments: stack,
    };
  }

  // -------------------------------------------------------------------------
  // WASI Preview 1 (`wasi_snapshot_preview1`)
  // -------------------------------------------------------------------------

  _buildWasiImports() {
    const E = WASI_ERRNO;
    const R = WASI_CONSTANTS.RIGHTS;

    return {
      args_sizes_get: (argcPtr, argvBufSizePtr) => {
        this._recordSyscall('wasi:args_sizes_get');
        const cMem = this.checkMem(argcPtr, 4);
        const sMem = this.checkMem(argvBufSizePtr, 4);
        if (!cMem || !sMem) return E.WASI_EFAULT;
        let total = 0;
        for (const a of this._args) {
          total += TEXT_ENCODER.encode(a).byteLength + 1;
        }
        cMem.view.setUint32(cMem.p, this._args.length >>> 0, true);
        sMem.view.setUint32(sMem.p, total >>> 0, true);
        return E.WASI_ESUCCESS;
      },

      args_get: (argvPtr, argvBufPtr) => {
        this._recordSyscall('wasi:args_get');
        const encoded = this._args.map((a) => TEXT_ENCODER.encode(a));
        let total = 0;
        for (const b of encoded) total += b.byteLength + 1;

        const ptrsMem = this.checkMem(argvPtr, encoded.length * 4);
        const bufMem = this.checkMem(argvBufPtr, total);
        if (!ptrsMem || !bufMem) return E.WASI_EFAULT;

        let cursor = 0;
        for (let i = 0; i < encoded.length; i++) {
          ptrsMem.view.setUint32(ptrsMem.p + i * 4, (bufMem.p + cursor) >>> 0, true);
          bufMem.u8.set(encoded[i], bufMem.p + cursor);
          cursor += encoded[i].byteLength;
          bufMem.u8[bufMem.p + cursor] = 0;
          cursor += 1;
        }
        return E.WASI_ESUCCESS;
      },

      environ_sizes_get: (countPtr, bufSizePtr) => {
        this._recordSyscall('wasi:environ_sizes_get');
        const cMem = this.checkMem(countPtr, 4);
        const sMem = this.checkMem(bufSizePtr, 4);
        if (!cMem || !sMem) return E.WASI_EFAULT;
        let total = 0;
        for (const entry of this._envEntries) {
          total += TEXT_ENCODER.encode(entry).byteLength + 1;
        }
        cMem.view.setUint32(cMem.p, this._envEntries.length >>> 0, true);
        sMem.view.setUint32(sMem.p, total >>> 0, true);
        return E.WASI_ESUCCESS;
      },

      environ_get: (environPtr, environBufPtr) => {
        this._recordSyscall('wasi:environ_get');
        const encoded = this._envEntries.map((e) => TEXT_ENCODER.encode(e));
        let total = 0;
        for (const b of encoded) total += b.byteLength + 1;

        const ptrsMem = this.checkMem(environPtr, encoded.length * 4);
        const bufMem = this.checkMem(environBufPtr, total);
        if (!ptrsMem || !bufMem) return E.WASI_EFAULT;

        let cursor = 0;
        for (let i = 0; i < encoded.length; i++) {
          ptrsMem.view.setUint32(ptrsMem.p + i * 4, (bufMem.p + cursor) >>> 0, true);
          bufMem.u8.set(encoded[i], bufMem.p + cursor);
          cursor += encoded[i].byteLength;
          bufMem.u8[bufMem.p + cursor] = 0;
          cursor += 1;
        }
        return E.WASI_ESUCCESS;
      },

      clock_res_get: (clockId, resPtr) => {
        this._recordSyscall('wasi:clock_res_get');
        const cid = clockId >>> 0;
        if (cid > 3) return E.WASI_EINVAL;
        const out = this.checkMem(resPtr, 8);
        if (!out) return E.WASI_EFAULT;
        const res = cid === 0 ? 1_000_000n : 1000n;
        out.view.setBigUint64(out.p, res, true);
        return E.WASI_ESUCCESS;
      },

      clock_time_get: (clockId, _precision, timePtr) => {
        this._recordSyscall('wasi:clock_time_get');
        const cid = clockId >>> 0;
        if (cid > 3) return E.WASI_EINVAL;
        const out = this.checkMem(timePtr, 8);
        if (!out) return E.WASI_EFAULT;
        let ns;
        if (cid === 0) {
          ns = BigInt(Date.now()) * 1_000_000n;
        } else if (cid === 1) {
          ns = process.hrtime.bigint();
        } else {
          ns = process.hrtime.bigint() - this._startHrTime;
          if (ns < 0n) ns = 0n;
        }
        out.view.setBigUint64(out.p, ns, true);
        return E.WASI_ESUCCESS;
      },

      random_get: (bufPtr, bufLen) => {
        this._recordSyscall('wasi:random_get');
        const m = this.checkMem(bufPtr, bufLen);
        if (!m) return E.WASI_EFAULT;
        if (m.n > 0) {
          crypto.randomFillSync(m.u8.subarray(m.p, m.p + m.n));
        }
        return E.WASI_ESUCCESS;
      },

      fd_write: (fd, iovsPtr, iovsLen, nwrittenPtr) => {
        this._recordSyscall('wasi:fd_write');
        const iovRes = this._readIovs(iovsPtr, iovsLen);
        if (iovRes.errno !== E.WASI_ESUCCESS) return iovRes.errno;
        const out = this.checkMem(nwrittenPtr, 4);
        if (!out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(fd, R.FD_WRITE);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;

        let totalWritten = 0;
        try {
          for (const slice of iovRes.slices) {
            if (slice.n === 0) continue;
            const chunk = slice.u8.slice(slice.p, slice.p + slice.n);
            if (entry.type === 'stream') {
              if (entry.fd === 1) {
                if (this._processManager && this._pid > 0) {
                  this._processManager.writeStdout(this._pid, chunk);
                } else {
                  this._fallbackStdoutChunks.push(chunk);
                }
                totalWritten += chunk.byteLength;
              } else if (entry.fd === 2) {
                if (this._processManager && this._pid > 0) {
                  this._processManager.writeStderr(this._pid, chunk);
                } else {
                  this._fallbackStderrChunks.push(chunk);
                }
                totalWritten += chunk.byteLength;
              } else {
                return E.WASI_EBADF;
              }
            } else {
              if (!this._vfs || !entry.vfsHandle) return E.WASI_EBADF;
              const w = this._vfs.write(entry.vfsHandle, chunk);
              totalWritten += w.bytesWritten;
            }
          }
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }

        out.view.setUint32(out.p, totalWritten >>> 0, true);
        return E.WASI_ESUCCESS;
      },

      fd_read: (fd, iovsPtr, iovsLen, nreadPtr) => {
        this._recordSyscall('wasi:fd_read');
        const iovRes = this._readIovs(iovsPtr, iovsLen);
        if (iovRes.errno !== E.WASI_ESUCCESS) return iovRes.errno;
        const out = this.checkMem(nreadPtr, 4);
        if (!out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(fd, R.FD_READ);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;

        let totalRead = 0;
        try {
          for (const slice of iovRes.slices) {
            if (slice.n === 0) continue;
            let data;
            if (entry.type === 'stream') {
              if (entry.fd !== 0) return E.WASI_EBADF;
              if (this._processManager && this._pid > 0) {
                data = this._processManager.readStdin(this._pid, slice.n, {
                  encoding: 'binary',
                  consume: true,
                });
              } else {
                const take = Math.min(slice.n, this._fallbackStdin.byteLength);
                data = this._fallbackStdin.slice(0, take);
                this._fallbackStdin = this._fallbackStdin.slice(take);
              }
            } else {
              if (!this._vfs || !entry.vfsHandle) return E.WASI_EBADF;
              data = this._vfs.read(entry.vfsHandle, slice.n);
            }
            if (data.byteLength > 0) {
              slice.u8.set(data, slice.p);
              totalRead += data.byteLength;
            }
            if (data.byteLength < slice.n) break;
          }
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }

        out.view.setUint32(out.p, totalRead >>> 0, true);
        return E.WASI_ESUCCESS;
      },

      fd_pwrite: (fd, iovsPtr, iovsLen, offset, nwrittenPtr) => {
        this._recordSyscall('wasi:fd_pwrite');
        const iovRes = this._readIovs(iovsPtr, iovsLen);
        if (iovRes.errno !== E.WASI_ESUCCESS) return iovRes.errno;
        const out = this.checkMem(nwrittenPtr, 4);
        if (!out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(fd, R.FD_WRITE | R.FD_SEEK);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        if (entry.type === 'stream') return E.WASI_ESPIPE;
        if (!this._vfs || !entry.vfsHandle) return E.WASI_EBADF;

        const offBig = toU64(offset);
        if (offBig > BigInt(Number.MAX_SAFE_INTEGER)) return E.WASI_EINVAL;
        let curOff = Number(offBig);
        let totalWritten = 0;

        try {
          for (const slice of iovRes.slices) {
            if (slice.n === 0) continue;
            const chunk = slice.u8.slice(slice.p, slice.p + slice.n);
            const w = this._vfs.write(entry.vfsHandle, chunk, { offset: curOff });
            totalWritten += w.bytesWritten;
            curOff += w.bytesWritten;
          }
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }

        out.view.setUint32(out.p, totalWritten >>> 0, true);
        return E.WASI_ESUCCESS;
      },

      fd_pread: (fd, iovsPtr, iovsLen, offset, nreadPtr) => {
        this._recordSyscall('wasi:fd_pread');
        const iovRes = this._readIovs(iovsPtr, iovsLen);
        if (iovRes.errno !== E.WASI_ESUCCESS) return iovRes.errno;
        const out = this.checkMem(nreadPtr, 4);
        if (!out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(fd, R.FD_READ | R.FD_SEEK);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        if (entry.type === 'stream') return E.WASI_ESPIPE;
        if (!this._vfs || !entry.vfsHandle) return E.WASI_EBADF;

        const offBig = toU64(offset);
        if (offBig > BigInt(Number.MAX_SAFE_INTEGER)) return E.WASI_EINVAL;
        let curOff = Number(offBig);
        let totalRead = 0;

        try {
          for (const slice of iovRes.slices) {
            if (slice.n === 0) continue;
            const data = this._vfs.read(entry.vfsHandle, slice.n, { offset: curOff });
            if (data.byteLength > 0) {
              slice.u8.set(data, slice.p);
              totalRead += data.byteLength;
              curOff += data.byteLength;
            }
            if (data.byteLength < slice.n) break;
          }
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }

        out.view.setUint32(out.p, totalRead >>> 0, true);
        return E.WASI_ESUCCESS;
      },

      fd_seek: (fd, offset, whence, newOffsetPtr) => {
        this._recordSyscall('wasi:fd_seek');
        const out = this.checkMem(newOffsetPtr, 8);
        if (!out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(fd, R.FD_SEEK);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        if (entry.type === 'stream') return E.WASI_ESPIPE;
        if (!this._vfs || !entry.vfsHandle) return E.WASI_EBADF;

        const w = whence >>> 0;
        if (w !== SEEK_WHENCE.SEEK_SET && w !== SEEK_WHENCE.SEEK_CUR && w !== SEEK_WHENCE.SEEK_END) {
          return E.WASI_EINVAL;
        }
        const deltaBig = toI64(offset);
        if (
          deltaBig < BigInt(-Number.MAX_SAFE_INTEGER) ||
          deltaBig > BigInt(Number.MAX_SAFE_INTEGER)
        ) {
          return E.WASI_EINVAL;
        }

        try {
          const nextPos = this._vfs.seek(entry.vfsHandle, Number(deltaBig), w);
          out.view.setBigUint64(out.p, BigInt(nextPos), true);
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      fd_tell: (fd, offsetPtr) => {
        this._recordSyscall('wasi:fd_tell');
        const out = this.checkMem(offsetPtr, 8);
        if (!out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(fd, R.FD_TELL);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        if (entry.type === 'stream') return E.WASI_ESPIPE;
        if (!entry.vfsHandle) return E.WASI_EBADF;

        out.view.setBigUint64(out.p, BigInt(entry.vfsHandle.pos ?? 0), true);
        return E.WASI_ESUCCESS;
      },

      fd_close: (fd) => {
        this._recordSyscall('wasi:fd_close');
        const fdRes = this._requireFd(fd, 0n);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        this._fds.delete(entry.fd);
        if (entry.vfsHandle && !entry.vfsHandle.closed && this._vfs) {
          try {
            this._vfs.closeHandle(entry.vfsHandle);
          } catch {
            // Ignore already-closed handle errors
          }
        }
        return E.WASI_ESUCCESS;
      },

      fd_fdstat_get: (fd, statPtr) => {
        this._recordSyscall('wasi:fd_fdstat_get');
        const out = this.checkMem(statPtr, 24);
        if (!out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(fd, 0n);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;

        out.u8.fill(0, out.p, out.p + 24);
        out.view.setUint8(out.p + 0, entry.filetype);
        out.view.setUint16(out.p + 2, entry.fdFlags & 0xffff, true);
        out.view.setBigUint64(out.p + 8, entry.rightsBase, true);
        out.view.setBigUint64(out.p + 16, entry.rightsInheriting, true);
        return E.WASI_ESUCCESS;
      },

      fd_fdstat_set_flags: (fd, flags) => {
        this._recordSyscall('wasi:fd_fdstat_set_flags');
        const fdRes = this._requireFd(fd, R.FD_FDSTAT_SET_FLAGS);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        entry.fdFlags = flags & 0xffff;
        if (entry.vfsHandle) {
          if ((entry.fdFlags & WASI_CONSTANTS.FDFLAGS.APPEND) !== 0) {
            entry.vfsHandle.flags |= OPEN_FLAGS.O_APPEND;
          } else {
            entry.vfsHandle.flags &= ~OPEN_FLAGS.O_APPEND;
          }
        }
        return E.WASI_ESUCCESS;
      },

      fd_fdstat_set_rights: (fd, fsRightsBase, fsRightsInheriting) => {
        this._recordSyscall('wasi:fd_fdstat_set_rights');
        const fdRes = this._requireFd(fd, 0n);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        const reqBase = toU64(fsRightsBase);
        const reqInh = toU64(fsRightsInheriting);
        // Rights can only be attenuated (never elevated)
        if ((reqBase & ~entry.rightsBase) !== 0n || (reqInh & ~entry.rightsInheriting) !== 0n) {
          return E.WASI_ENOTCAPABLE;
        }
        entry.rightsBase = reqBase;
        entry.rightsInheriting = reqInh;
        return E.WASI_ESUCCESS;
      },

      fd_renumber: (fromFd, toFd) => {
        this._recordSyscall('wasi:fd_renumber');
        const fromRes = this._requireFd(fromFd, 0n);
        if (fromRes.errno !== E.WASI_ESUCCESS) return E.WASI_EBADF;
        const toRes = this._requireFd(toFd, 0n);
        if (toRes.errno !== E.WASI_ESUCCESS) return E.WASI_EBADF;
        if (fromRes.entry.fd === toRes.entry.fd) return E.WASI_ESUCCESS;
        const target = toRes.entry;
        if (target.vfsHandle && !target.vfsHandle.closed && this._vfs) {
          try {
            this._vfs.closeHandle(target.vfsHandle);
          } catch {
            // Ignore close errors
          }
        }
        const source = fromRes.entry;
        this._fds.delete(source.fd);
        source.fd = target.fd;
        this._fds.set(target.fd, source);
        return E.WASI_ESUCCESS;
      },

      fd_filestat_get: (fd, bufPtr) => {
        this._recordSyscall('wasi:fd_filestat_get');
        const out = this.checkMem(bufPtr, 64);
        if (!out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(fd, R.FD_FILESTAT_GET);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;

        if (entry.type === 'stream') {
          writeFilestatToView(out.view, out.p, {
            ino: entry.fd,
            type: 'device',
            nlink: 1,
            size: 0,
            mtimeMs: 0,
            ctimeMs: 0,
          });
          return E.WASI_ESUCCESS;
        }
        if (!this._vfs) return E.WASI_ENOSYS;
        try {
          const st = entry.vfsHandle
            ? entry.vfsHandle.stat()
            : this._vfs.stat(entry.hostPath, this._vfsCtxForEntry(entry));
          writeFilestatToView(out.view, out.p, st);
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      fd_filestat_set_size: (fd, size) => {
        this._recordSyscall('wasi:fd_filestat_set_size');
        const fdRes = this._requireFd(fd, R.FD_FILESTAT_SET_SIZE);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        if (entry.type === 'stream') return E.WASI_EINVAL;
        if (entry.filetype === WASI_CONSTANTS.FILETYPE.DIRECTORY) return E.WASI_EISDIR;
        if (!this._vfs || !entry.vfsHandle) return E.WASI_EBADF;

        const targetBig = toU64(size);
        if (targetBig > BigInt(64 * 1024 * 1024)) return E.WASI_EFBIG;
        const targetSize = Number(targetBig);

        try {
          const ctx = this._vfsCtxForEntry(entry);
          const existing = this._vfs.readFile(entry.hostPath, ctx);
          const resized = new Uint8Array(targetSize);
          resized.set(existing.subarray(0, Math.min(existing.byteLength, targetSize)), 0);
          this._vfs.writeFile(entry.hostPath, resized, ctx);
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      fd_filestat_set_times: (fd, _atim, _mtim, fstFlags) => {
        this._recordSyscall('wasi:fd_filestat_set_times');
        const fdRes = this._requireFd(fd, R.FD_FILESTAT_SET_TIMES);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const f = fstFlags & 0xffff;
        if (
          ((f & WASI_CONSTANTS.FSTFLAGS.ATIM) !== 0 && (f & WASI_CONSTANTS.FSTFLAGS.ATIM_NOW) !== 0) ||
          ((f & WASI_CONSTANTS.FSTFLAGS.MTIM) !== 0 && (f & WASI_CONSTANTS.FSTFLAGS.MTIM_NOW) !== 0)
        ) {
          return E.WASI_EINVAL;
        }
        return E.WASI_ESUCCESS;
      },

      fd_prestat_get: (fd, bufPtr) => {
        this._recordSyscall('wasi:fd_prestat_get');
        const out = this.checkMem(bufPtr, 8);
        if (!out) return E.WASI_EFAULT;
        const fdRes = this._requireFd(fd, 0n);
        if (fdRes.errno !== E.WASI_ESUCCESS) return E.WASI_EBADF;
        const entry = fdRes.entry;
        if (entry.type !== 'preopen' || typeof entry.virtualName !== 'string') {
          return E.WASI_EBADF;
        }
        const nameBytes = TEXT_ENCODER.encode(entry.virtualName);
        out.u8.fill(0, out.p, out.p + 8);
        out.view.setUint8(out.p + 0, WASI_CONSTANTS.PREOPENTYPE.DIR);
        out.view.setUint32(out.p + 4, nameBytes.byteLength >>> 0, true);
        return E.WASI_ESUCCESS;
      },

      fd_prestat_dir_name: (fd, pathPtr, pathLen) => {
        this._recordSyscall('wasi:fd_prestat_dir_name');
        const fdRes = this._requireFd(fd, 0n);
        if (fdRes.errno !== E.WASI_ESUCCESS) return E.WASI_EBADF;
        const entry = fdRes.entry;
        if (entry.type !== 'preopen' || typeof entry.virtualName !== 'string') {
          return E.WASI_EBADF;
        }
        const out = this.checkMem(pathPtr, pathLen);
        if (!out) return E.WASI_EFAULT;
        const nameBytes = TEXT_ENCODER.encode(entry.virtualName);
        if (out.n < nameBytes.byteLength) {
          return E.WASI_ENAMETOOLONG;
        }
        out.u8.set(nameBytes, out.p);
        return E.WASI_ESUCCESS;
      },

      fd_readdir: (fd, bufPtr, bufLen, cookie, bufusedPtr) => {
        this._recordSyscall('wasi:fd_readdir');
        const bufMem = this.checkMem(bufPtr, bufLen);
        const usedMem = this.checkMem(bufusedPtr, 4);
        if (!bufMem || !usedMem) return E.WASI_EFAULT;

        const fdRes = this._requireFd(fd, R.FD_READDIR);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        if (entry.filetype !== WASI_CONSTANTS.FILETYPE.DIRECTORY) {
          return E.WASI_ENOTDIR;
        }
        if (!this._vfs) return E.WASI_ENOSYS;

        try {
          const ctx = this._vfsCtxForEntry(entry);
          const dirStat = this._vfs.stat(entry.hostPath, ctx);
          const children = this._vfs.readdir(entry.hostPath, ctx);
          const allEntries = [
            { name: '.', ino: dirStat.ino, type: 'dir' },
            { name: '..', ino: dirStat.ino, type: 'dir' },
            ...children,
          ];

          const startCookie = toU64(cookie);
          const startIdx = startCookie > BigInt(allEntries.length) ? allEntries.length : Number(startCookie);

          let written = 0;
          for (let i = startIdx; i < allEntries.length && written < bufMem.n; i++) {
            const item = allEntries[i];
            const nameBytes = TEXT_ENCODER.encode(item.name);
            const recLen = 24 + nameBytes.byteLength;
            const rec = new Uint8Array(recLen);
            const rv = new DataView(rec.buffer);
            rv.setBigUint64(0, BigInt(i + 1), true); // d_next
            rv.setBigUint64(8, BigInt(Math.max(0, Math.trunc(item.ino ?? 0))), true); // d_ino
            rv.setUint32(16, nameBytes.byteLength >>> 0, true); // d_namlen
            rv.setUint8(20, vfsTypeToWasiFiletype(item.type)); // d_type
            rec.set(nameBytes, 24);

            const copyLen = Math.min(recLen, bufMem.n - written);
            bufMem.u8.set(rec.subarray(0, copyLen), bufMem.p + written);
            written += copyLen;
          }

          usedMem.view.setUint32(usedMem.p, written >>> 0, true);
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      fd_sync: (fd) => {
        this._recordSyscall('wasi:fd_sync');
        const fdRes = this._requireFd(fd, R.FD_SYNC);
        return fdRes.errno;
      },

      fd_datasync: (fd) => {
        this._recordSyscall('wasi:fd_datasync');
        const fdRes = this._requireFd(fd, R.FD_DATASYNC);
        return fdRes.errno;
      },

      fd_advise: (fd, _offset, _len, _advice) => {
        this._recordSyscall('wasi:fd_advise');
        const fdRes = this._requireFd(fd, R.FD_ADVISE);
        return fdRes.errno;
      },

      fd_allocate: (fd, offset, len) => {
        this._recordSyscall('wasi:fd_allocate');
        const fdRes = this._requireFd(fd, R.FD_ALLOCATE);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const entry = fdRes.entry;
        if (entry.type === 'stream') return E.WASI_EINVAL;
        if (entry.filetype === WASI_CONSTANTS.FILETYPE.DIRECTORY) return E.WASI_EISDIR;
        if (!this._vfs || !entry.vfsHandle) return E.WASI_EBADF;

        const targetBig = toU64(offset) + toU64(len);
        if (targetBig > BigInt(64 * 1024 * 1024)) return E.WASI_EFBIG;
        const targetSize = Number(targetBig);

        try {
          const ctx = this._vfsCtxForEntry(entry);
          const existing = this._vfs.readFile(entry.hostPath, ctx);
          if (targetSize > existing.byteLength) {
            const grown = new Uint8Array(targetSize);
            grown.set(existing, 0);
            this._vfs.writeFile(entry.hostPath, grown, ctx);
          }
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_open: (
        dirFd,
        dirFlags,
        pathPtr,
        pathLen,
        oFlags,
        fsRightsBase,
        fsRightsInheriting,
        fdFlags,
        openedFdPtr
      ) => {
        this._recordSyscall('wasi:path_open');
        const relPath = this._readUtf8(pathPtr, pathLen);
        const out = this.checkMem(openedFdPtr, 4);
        if (relPath === null || !out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(dirFd, R.PATH_OPEN);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const dirEntry = fdRes.entry;

        const resolved = this._resolveWithinDirFd(dirEntry, relPath);
        if (resolved.errno !== E.WASI_ESUCCESS) return resolved.errno;
        if (!this._vfs) return E.WASI_ENOSYS;

        const of = oFlags & 0xffff;
        const ff = fdFlags & 0xffff;
        const followSymlinks = (dirFlags & WASI_CONSTANTS.LOOKUPFLAGS.SYMLINK_FOLLOW) !== 0;

        const reqBase = toU64(fsRightsBase);
        const reqInheriting = toU64(fsRightsInheriting);

        // Enforce directory capability rights for creation/truncation/write/read
        if ((of & WASI_CONSTANTS.OFLAGS.CREAT) !== 0 && (dirEntry.rightsBase & R.PATH_CREATE_FILE) === 0n) {
          return E.WASI_ENOTCAPABLE;
        }
        if ((of & WASI_CONSTANTS.OFLAGS.TRUNC) !== 0 && (dirEntry.rightsInheriting & R.FD_FILESTAT_SET_SIZE) === 0n) {
          return E.WASI_ENOTCAPABLE;
        }
        if ((reqBase & R.FD_WRITE) !== 0n && (dirEntry.rightsInheriting & R.FD_WRITE) === 0n) {
          return E.WASI_ENOTCAPABLE;
        }
        if ((reqBase & R.FD_READ) !== 0n && (dirEntry.rightsInheriting & R.FD_READ) === 0n) {
          return E.WASI_ENOTCAPABLE;
        }

        const effectiveBase = reqBase & dirEntry.rightsInheriting;
        const effectiveInheriting = reqInheriting & dirEntry.rightsInheriting;

        const ctx = this._vfsCtxForEntry(dirEntry);

        try {
          if (!followSymlinks) {
            try {
              const lst = this._vfs.lstat(resolved.fullPath, ctx);
              if (lst.type === 'symlink') {
                return E.WASI_ELOOP;
              }
            } catch (lstatErr) {
              if (lstatErr?.code !== ERROR_CODES.ENOENT) {
                return mapVfsErrorToWasi(lstatErr);
              }
            }
          }

          let existingStat = null;
          try {
            existingStat = this._vfs.stat(resolved.fullPath, ctx);
          } catch (statErr) {
            if (statErr?.code !== ERROR_CODES.ENOENT) {
              return mapVfsErrorToWasi(statErr);
            }
          }

          const wantDir = (of & WASI_CONSTANTS.OFLAGS.DIRECTORY) !== 0;
          const isDirTarget = existingStat?.type === 'dir';
          const wantRead = (effectiveBase & R.FD_READ) !== 0n;
          const wantWrite =
            (effectiveBase & R.FD_WRITE) !== 0n ||
            (of & (WASI_CONSTANTS.OFLAGS.CREAT | WASI_CONSTANTS.OFLAGS.TRUNC)) !== 0;

          let vfsFlags = OPEN_FLAGS.O_RDONLY;
          if (isDirTarget || wantDir) {
            if (wantWrite && !wantDir) return E.WASI_EISDIR;
            vfsFlags = OPEN_FLAGS.O_RDONLY | OPEN_FLAGS.O_DIRECTORY;
          } else if (wantRead && wantWrite) {
            vfsFlags = OPEN_FLAGS.O_RDWR;
          } else if (wantWrite) {
            vfsFlags = OPEN_FLAGS.O_WRONLY;
          }

          if ((of & WASI_CONSTANTS.OFLAGS.CREAT) !== 0) vfsFlags |= OPEN_FLAGS.O_CREAT;
          if ((of & WASI_CONSTANTS.OFLAGS.EXCL) !== 0) vfsFlags |= OPEN_FLAGS.O_EXCL;
          if ((of & WASI_CONSTANTS.OFLAGS.TRUNC) !== 0) vfsFlags |= OPEN_FLAGS.O_TRUNC;
          if ((ff & WASI_CONSTANTS.FDFLAGS.APPEND) !== 0) vfsFlags |= OPEN_FLAGS.O_APPEND;

          const handle = this._vfs.open(resolved.fullPath, vfsFlags, ctx);
          const openedStat = handle.stat();
          const newFd = this._allocFd();
          this._fds.set(newFd, {
            fd: newFd,
            type: openedStat.type === 'dir' ? 'dir' : 'file',
            filetype: vfsTypeToWasiFiletype(openedStat.type),
            hostPath: handle.path,
            preopenRoot: dirEntry.preopenRoot,
            relSegments: resolved.relSegments,
            virtualName: null,
            vfsHandle: handle,
            rightsBase: effectiveBase,
            rightsInheriting: effectiveInheriting,
            fdFlags: ff,
            actorUid: dirEntry.actorUid,
            actorGid: dirEntry.actorGid,
          });
          out.view.setUint32(out.p, newFd >>> 0, true);
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_filestat_get: (dirFd, flags, pathPtr, pathLen, bufPtr) => {
        this._recordSyscall('wasi:path_filestat_get');
        const relPath = this._readUtf8(pathPtr, pathLen);
        const out = this.checkMem(bufPtr, 64);
        if (relPath === null || !out) return E.WASI_EFAULT;

        const fdRes = this._requireFd(dirFd, R.PATH_FILESTAT_GET);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const dirEntry = fdRes.entry;

        const resolved = this._resolveWithinDirFd(dirEntry, relPath);
        if (resolved.errno !== E.WASI_ESUCCESS) return resolved.errno;
        if (!this._vfs) return E.WASI_ENOSYS;

        try {
          const ctx = this._vfsCtxForEntry(dirEntry);
          const follow = (flags & WASI_CONSTANTS.LOOKUPFLAGS.SYMLINK_FOLLOW) !== 0;
          const st = follow
            ? this._vfs.stat(resolved.fullPath, ctx)
            : this._vfs.lstat(resolved.fullPath, ctx);
          writeFilestatToView(out.view, out.p, st);
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_create_directory: (dirFd, pathPtr, pathLen) => {
        this._recordSyscall('wasi:path_create_directory');
        const relPath = this._readUtf8(pathPtr, pathLen);
        if (relPath === null) return E.WASI_EFAULT;

        const fdRes = this._requireFd(dirFd, R.PATH_CREATE_DIRECTORY);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const dirEntry = fdRes.entry;

        const resolved = this._resolveWithinDirFd(dirEntry, relPath);
        if (resolved.errno !== E.WASI_ESUCCESS) return resolved.errno;
        if (!this._vfs) return E.WASI_ENOSYS;

        try {
          this._vfs.mkdir(resolved.fullPath, {
            recursive: false,
            mode: 0o755,
            ...this._vfsCtxForEntry(dirEntry),
          });
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_remove_directory: (dirFd, pathPtr, pathLen) => {
        this._recordSyscall('wasi:path_remove_directory');
        const relPath = this._readUtf8(pathPtr, pathLen);
        if (relPath === null) return E.WASI_EFAULT;

        const fdRes = this._requireFd(dirFd, R.PATH_REMOVE_DIRECTORY);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const dirEntry = fdRes.entry;

        const resolved = this._resolveWithinDirFd(dirEntry, relPath);
        if (resolved.errno !== E.WASI_ESUCCESS) return resolved.errno;
        if (resolved.fullPath === dirEntry.preopenRoot) return E.WASI_EBUSY;
        if (!this._vfs) return E.WASI_ENOSYS;

        try {
          this._vfs.rmdir(resolved.fullPath, {
            recursive: false,
            ...this._vfsCtxForEntry(dirEntry),
          });
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_unlink_file: (dirFd, pathPtr, pathLen) => {
        this._recordSyscall('wasi:path_unlink_file');
        const relPath = this._readUtf8(pathPtr, pathLen);
        if (relPath === null) return E.WASI_EFAULT;

        const fdRes = this._requireFd(dirFd, R.PATH_UNLINK_FILE);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const dirEntry = fdRes.entry;

        const resolved = this._resolveWithinDirFd(dirEntry, relPath);
        if (resolved.errno !== E.WASI_ESUCCESS) return resolved.errno;
        if (!this._vfs) return E.WASI_ENOSYS;

        try {
          this._vfs.unlink(resolved.fullPath, this._vfsCtxForEntry(dirEntry));
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_rename: (oldFd, oldPathPtr, oldPathLen, newFd, newPathPtr, newPathLen) => {
        this._recordSyscall('wasi:path_rename');
        const oldPath = this._readUtf8(oldPathPtr, oldPathLen);
        const newPath = this._readUtf8(newPathPtr, newPathLen);
        if (oldPath === null || newPath === null) return E.WASI_EFAULT;

        const oldRes = this._requireFd(oldFd, R.PATH_RENAME_SOURCE);
        if (oldRes.errno !== E.WASI_ESUCCESS) return oldRes.errno;
        const newRes = this._requireFd(newFd, R.PATH_RENAME_TARGET);
        if (newRes.errno !== E.WASI_ESUCCESS) return newRes.errno;

        const oldResolved = this._resolveWithinDirFd(oldRes.entry, oldPath);
        if (oldResolved.errno !== E.WASI_ESUCCESS) return oldResolved.errno;
        const newResolved = this._resolveWithinDirFd(newRes.entry, newPath);
        if (newResolved.errno !== E.WASI_ESUCCESS) return newResolved.errno;
        if (!this._vfs) return E.WASI_ENOSYS;

        if (oldRes.entry.preopenRoot !== newRes.entry.preopenRoot) {
          return E.WASI_EXDEV;
        }
        try {
          this._vfs.rename(oldResolved.fullPath, newResolved.fullPath, this._vfsCtxForEntry(oldRes.entry));
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_readlink: (dirFd, pathPtr, pathLen, bufPtr, bufLen, bufusedPtr) => {
        this._recordSyscall('wasi:path_readlink');
        const relPath = this._readUtf8(pathPtr, pathLen);
        const outBuf = this.checkMem(bufPtr, bufLen);
        const outUsed = this.checkMem(bufusedPtr, 4);
        if (relPath === null || !outBuf || !outUsed) return E.WASI_EFAULT;

        const fdRes = this._requireFd(dirFd, R.PATH_READLINK);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const dirEntry = fdRes.entry;

        const resolved = this._resolveWithinDirFd(dirEntry, relPath);
        if (resolved.errno !== E.WASI_ESUCCESS) return resolved.errno;
        if (!this._vfs) return E.WASI_ENOSYS;

        try {
          const target = this._vfs.readlink(resolved.fullPath, this._vfsCtxForEntry(dirEntry));
          const targetBytes = TEXT_ENCODER.encode(target);
          const n = Math.min(outBuf.n, targetBytes.byteLength);
          outBuf.u8.set(targetBytes.subarray(0, n), outBuf.p);
          outUsed.view.setUint32(outUsed.p, n >>> 0, true);
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_symlink: (oldPathPtr, oldPathLen, dirFd, newPathPtr, newPathLen) => {
        this._recordSyscall('wasi:path_symlink');
        const target = this._readUtf8(oldPathPtr, oldPathLen);
        const newPath = this._readUtf8(newPathPtr, newPathLen);
        if (target === null || newPath === null) return E.WASI_EFAULT;

        const fdRes = this._requireFd(dirFd, R.PATH_SYMLINK);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const dirEntry = fdRes.entry;

        // Disallow absolute or NUL symlink targets escaping capability root
        if (target.length === 0 || target.includes('\0') || target.startsWith('/')) {
          return E.WASI_ENOTCAPABLE;
        }
        const resolved = this._resolveWithinDirFd(dirEntry, newPath);
        if (resolved.errno !== E.WASI_ESUCCESS) return resolved.errno;
        if (!this._vfs) return E.WASI_ENOSYS;

        try {
          this._vfs.symlink(target, resolved.fullPath, this._vfsCtxForEntry(dirEntry));
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_filestat_set_times: (dirFd, flags, pathPtr, pathLen, _atim, _mtim, fstFlags) => {
        this._recordSyscall('wasi:path_filestat_set_times');
        const relPath = this._readUtf8(pathPtr, pathLen);
        if (relPath === null) return E.WASI_EFAULT;

        const fdRes = this._requireFd(dirFd, R.PATH_FILESTAT_SET_TIMES);
        if (fdRes.errno !== E.WASI_ESUCCESS) return fdRes.errno;
        const dirEntry = fdRes.entry;

        const resolved = this._resolveWithinDirFd(dirEntry, relPath);
        if (resolved.errno !== E.WASI_ESUCCESS) return resolved.errno;

        const f = fstFlags & 0xffff;
        if (
          ((f & WASI_CONSTANTS.FSTFLAGS.ATIM) !== 0 && (f & WASI_CONSTANTS.FSTFLAGS.ATIM_NOW) !== 0) ||
          ((f & WASI_CONSTANTS.FSTFLAGS.MTIM) !== 0 && (f & WASI_CONSTANTS.FSTFLAGS.MTIM_NOW) !== 0)
        ) {
          return E.WASI_EINVAL;
        }
        if (!this._vfs) return E.WASI_ENOSYS;

        try {
          const ctx = this._vfsCtxForEntry(dirEntry);
          const follow = (flags & WASI_CONSTANTS.LOOKUPFLAGS.SYMLINK_FOLLOW) !== 0;
          if (follow) {
            this._vfs.stat(resolved.fullPath, ctx);
          } else {
            this._vfs.lstat(resolved.fullPath, ctx);
          }
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      path_link: (oldFd, _oldFlags, oldPathPtr, oldPathLen, newFd, newPathPtr, newPathLen) => {
        this._recordSyscall('wasi:path_link');
        const oldPath = this._readUtf8(oldPathPtr, oldPathLen);
        const newPath = this._readUtf8(newPathPtr, newPathLen);
        if (oldPath === null || newPath === null) return E.WASI_EFAULT;

        const oldRes = this._requireFd(oldFd, R.PATH_LINK_SOURCE);
        if (oldRes.errno !== E.WASI_ESUCCESS) return oldRes.errno;
        const newRes = this._requireFd(newFd, R.PATH_LINK_TARGET);
        if (newRes.errno !== E.WASI_ESUCCESS) return newRes.errno;

        const oResolved = this._resolveWithinDirFd(oldRes.entry, oldPath);
        if (oResolved.errno !== E.WASI_ESUCCESS) return oResolved.errno;
        const nResolved = this._resolveWithinDirFd(newRes.entry, newPath);
        if (nResolved.errno !== E.WASI_ESUCCESS) return nResolved.errno;
        return E.WASI_ENOTSUP;
      },

      poll_oneoff: (inPtr, outPtr, nsubscriptions, neventsPtr) => {
        this._recordSyscall('wasi:poll_oneoff');
        const nsubs = nsubscriptions >>> 0;
        if (nsubs === 0 || nsubs > WASI_CONSTANTS.MAX_IOVS) {
          return E.WASI_EINVAL;
        }
        const inMem = this.checkMem(inPtr, nsubs * 48);
        const outMem = this.checkMem(outPtr, nsubs * 32);
        const cntMem = this.checkMem(neventsPtr, 4);
        if (!inMem || !outMem || !cntMem) return E.WASI_EFAULT;

        let emitted = 0;
        for (let i = 0; i < nsubs; i++) {
          const sOff = inMem.p + i * 48;
          const eOff = outMem.p + emitted * 32;
          const userdata = inMem.view.getBigUint64(sOff, true);
          const tag = inMem.view.getUint8(sOff + 8);

          outMem.u8.fill(0, eOff, eOff + 32);
          outMem.view.setBigUint64(eOff + 0, userdata, true);
          outMem.view.setUint8(eOff + 10, tag);

          if (tag === WASI_CONSTANTS.EVENTTYPE.CLOCK) {
            const clockId = inMem.view.getUint32(sOff + 16, true);
            outMem.view.setUint16(eOff + 8, clockId > 3 ? E.WASI_EINVAL : E.WASI_ESUCCESS, true);
            emitted += 1;
          } else if (
            tag === WASI_CONSTANTS.EVENTTYPE.FD_READ ||
            tag === WASI_CONSTANTS.EVENTTYPE.FD_WRITE
          ) {
            const subFd = inMem.view.getUint32(sOff + 16, true);
            const fdRes = this._requireFd(subFd, R.POLL_FD_READWRITE);
            outMem.view.setUint16(eOff + 8, fdRes.errno, true);
            if (fdRes.errno === E.WASI_ESUCCESS) {
              let avail = 4096n;
              if (tag === WASI_CONSTANTS.EVENTTYPE.FD_READ) {
                if (fdRes.entry.fd === 0) {
                  avail = BigInt(
                    this._pcb?.streams?.stdin?.size ?? this._fallbackStdin.byteLength
                  );
                } else if (fdRes.entry.vfsHandle) {
                  try {
                    const st = fdRes.entry.vfsHandle.stat();
                    const rem = Math.max(0, st.size - fdRes.entry.vfsHandle.pos);
                    avail = BigInt(rem);
                  } catch {
                    avail = 0n;
                  }
                }
              }
              outMem.view.setBigUint64(eOff + 16, avail, true);
            }
            emitted += 1;
          } else {
            outMem.view.setUint16(eOff + 8, E.WASI_EINVAL, true);
            emitted += 1;
          }
        }

        cntMem.view.setUint32(cntMem.p, emitted >>> 0, true);
        return E.WASI_ESUCCESS;
      },

      sched_yield: () => {
        this._recordSyscall('wasi:sched_yield');
        return E.WASI_ESUCCESS;
      },

      proc_exit: (rval) => {
        this._recordSyscall('wasi:proc_exit');
        const code = rval >>> 0;
        this.exited = true;
        this.exitCode = code;
        throw new WasiExitSignal(code);
      },

      proc_raise: (_sig) => {
        this._recordSyscall('wasi:proc_raise');
        return E.WASI_ENOSYS;
      },

      sock_accept: (fd, _flags, roFdPtr) => {
        this._recordSyscall('wasi:sock_accept');
        if (!this.checkMem(roFdPtr, 4)) return E.WASI_EFAULT;
        const fdRes = this._requireFd(fd, R.SOCK_ACCEPT);
        return fdRes.errno !== E.WASI_ESUCCESS ? fdRes.errno : E.WASI_ENOSYS;
      },

      sock_recv: (fd, riDataPtr, riDataLen, _riFlags, roDataLenPtr, roFlagsPtr) => {
        this._recordSyscall('wasi:sock_recv');
        const iovRes = this._readIovs(riDataPtr, riDataLen);
        if (iovRes.errno !== E.WASI_ESUCCESS) return iovRes.errno;
        if (!this.checkMem(roDataLenPtr, 4) || !this.checkMem(roFlagsPtr, 2)) return E.WASI_EFAULT;
        const fdRes = this._requireFd(fd, R.FD_READ);
        return fdRes.errno !== E.WASI_ESUCCESS ? fdRes.errno : E.WASI_ENOSYS;
      },

      sock_send: (fd, siDataPtr, siDataLen, _siFlags, soDataLenPtr) => {
        this._recordSyscall('wasi:sock_send');
        const iovRes = this._readIovs(siDataPtr, siDataLen);
        if (iovRes.errno !== E.WASI_ESUCCESS) return iovRes.errno;
        if (!this.checkMem(soDataLenPtr, 4)) return E.WASI_EFAULT;
        const fdRes = this._requireFd(fd, R.FD_WRITE);
        return fdRes.errno !== E.WASI_ESUCCESS ? fdRes.errno : E.WASI_ENOSYS;
      },

      sock_shutdown: (fd, _how) => {
        this._recordSyscall('wasi:sock_shutdown');
        const fdRes = this._requireFd(fd, R.SOCK_SHUTDOWN);
        return fdRes.errno !== E.WASI_ESUCCESS ? fdRes.errno : E.WASI_ENOSYS;
      },
    };
  }

  // -------------------------------------------------------------------------
  // OmniOS Universal Compositor / UI / Canvas / IPC / Clipboard / Notification ABI (`omni_os_v1`)
  // -------------------------------------------------------------------------

  _buildOmniOsImports() {
    const E = WASI_ERRNO;

    const getWindowRec = (winH) => {
      if (typeof winH !== 'number' || !Number.isFinite(winH)) return null;
      return this._windows.get(winH | 0) ?? null;
    };

    return {
      window_create: (titlePtr, titleLen, width, height) => {
        this._recordSyscall('omni:window_create');
        const title = this._readUtf8(titlePtr, titleLen);
        if (title === null) return -E.WASI_EFAULT;
        if (this._isCapabilityExplicitlyDenied('ui.window')) return -E.WASI_EACCES;

        const w = typeof width === 'number' && Number.isFinite(width) ? Math.trunc(width) : 0;
        const h = typeof height === 'number' && Number.isFinite(height) ? Math.trunc(height) : 0;
        if (w < 1 || h < 1 || w > 16384 || h > 16384) {
          return -E.WASI_EINVAL;
        }

        const handle = this._nextWindowHandle++;
        let windowId = `wasm-win-${this._pid}-${handle}`;

        if (this._compositor && this._pid > 0) {
          try {
            const created = this._compositor.createWindow(this._pid, {
              appId: this._appId,
              platform: 'universal',
              title: title || this._appRecord?.name || 'Universal App',
              width: w,
              height: h,
              uiTree: null,
              drawOps: [],
            });
            windowId = created.windowId;
          } catch (err) {
            return err?.code === ERROR_CODES.E_WINDOW_QUOTA ? -E.WASI_ENOMEM : -E.WASI_EIO;
          }
        }

        this._windows.set(handle, {
          handle,
          windowId,
          title,
          width: w,
          height: h,
          pendingDrawOps: [],
          replaceOnCommit: false,
          pendingUiTree: null,
          hasPendingUiTree: false,
          committedDrawOps: [],
          committedUiTree: null,
        });
        return handle;
      },

      surface_clear: (winH, colorPtr, colorLen) => {
        this._recordSyscall('omni:surface_clear');
        const color = this._readUtf8(colorPtr, colorLen);
        if (color === null) return E.WASI_EFAULT;
        const win = getWindowRec(winH);
        if (!win) return E.WASI_EBADF;

        win.pendingDrawOps = [{ op: 'clear', color: color || '#0f172a' }];
        win.replaceOnCommit = true;
        return E.WASI_ESUCCESS;
      },

      canvas_rect: (winH, x, y, w, h, colorPtr, colorLen) => {
        this._recordSyscall('omni:canvas_rect');
        const color = this._readUtf8(colorPtr, colorLen);
        if (color === null) return E.WASI_EFAULT;
        const win = getWindowRec(winH);
        if (!win) return E.WASI_EBADF;

        win.pendingDrawOps.push({
          op: 'rect',
          x: Number.isFinite(x) ? x : 0,
          y: Number.isFinite(y) ? y : 0,
          w: Number.isFinite(w) ? w : 0,
          h: Number.isFinite(h) ? h : 0,
          color: color || '#38bdf8',
        });
        return E.WASI_ESUCCESS;
      },

      canvas_circle: (winH, cx, cy, r, colorPtr, colorLen) => {
        this._recordSyscall('omni:canvas_circle');
        const color = this._readUtf8(colorPtr, colorLen);
        if (color === null) return E.WASI_EFAULT;
        const win = getWindowRec(winH);
        if (!win) return E.WASI_EBADF;

        const x = Number.isFinite(cx) ? cx : 0;
        const y = Number.isFinite(cy) ? cy : 0;
        const radius = Number.isFinite(r) ? r : 0;
        win.pendingDrawOps.push({
          op: 'circle',
          cx: x,
          cy: y,
          x,
          y,
          r: radius,
          color: color || '#f472b6',
        });
        return E.WASI_ESUCCESS;
      },

      canvas_line: (winH, x1, y1, x2, y2, strokeWidth, colorPtr, colorLen) => {
        this._recordSyscall('omni:canvas_line');
        const color = this._readUtf8(colorPtr, colorLen);
        if (color === null) return E.WASI_EFAULT;
        const win = getWindowRec(winH);
        if (!win) return E.WASI_EBADF;

        const sw = Number.isFinite(strokeWidth) && strokeWidth > 0 ? strokeWidth : 1;
        win.pendingDrawOps.push({
          op: 'line',
          x1: Number.isFinite(x1) ? x1 : 0,
          y1: Number.isFinite(y1) ? y1 : 0,
          x2: Number.isFinite(x2) ? x2 : 0,
          y2: Number.isFinite(y2) ? y2 : 0,
          strokeWidth: sw,
          lineWidth: sw,
          color: color || '#94a3b8',
        });
        return E.WASI_ESUCCESS;
      },

      canvas_text: (winH, x, y, textPtr, textLen, colorPtr, colorLen, fontSize) => {
        this._recordSyscall('omni:canvas_text');
        const text = this._readUtf8(textPtr, textLen);
        const color = this._readUtf8(colorPtr, colorLen);
        if (text === null || color === null) return E.WASI_EFAULT;
        const win = getWindowRec(winH);
        if (!win) return E.WASI_EBADF;

        win.pendingDrawOps.push({
          op: 'text',
          x: Number.isFinite(x) ? x : 0,
          y: Number.isFinite(y) ? y : 0,
          text,
          color: color || '#f8fafc',
          fontSize: Number.isFinite(fontSize) && fontSize > 0 ? fontSize : 14,
        });
        return E.WASI_ESUCCESS;
      },

      ui_set_tree: (winH, jsonPtr, jsonLen) => {
        this._recordSyscall('omni:ui_set_tree');
        const jsonStr = this._readUtf8(jsonPtr, jsonLen);
        if (jsonStr === null) return E.WASI_EFAULT;
        const win = getWindowRec(winH);
        if (!win) return E.WASI_EBADF;

        let parsed;
        try {
          parsed = JSON.parse(jsonStr);
        } catch {
          return E.WASI_EINVAL;
        }
        win.pendingUiTree = parsed;
        win.hasPendingUiTree = true;
        return E.WASI_ESUCCESS;
      },

      surface_commit: (winH) => {
        this._recordSyscall('omni:surface_commit');
        const win = getWindowRec(winH);
        if (!win) return E.WASI_EBADF;

        const patch = {};
        if (win.replaceOnCommit) {
          patch.drawOps = [...win.pendingDrawOps];
          win.committedDrawOps = [...win.pendingDrawOps];
        } else if (win.pendingDrawOps.length > 0) {
          patch.appendDrawOps = [...win.pendingDrawOps];
          win.committedDrawOps.push(...win.pendingDrawOps);
        }
        if (win.hasPendingUiTree) {
          patch.uiTree = win.pendingUiTree;
          win.committedUiTree = win.pendingUiTree;
        }

        win.pendingDrawOps = [];
        win.replaceOnCommit = false;
        win.hasPendingUiTree = false;

        if (this._compositor && Object.keys(patch).length > 0) {
          try {
            this._compositor.updateSurface(win.windowId, patch);
          } catch (err) {
            return err?.code === ERROR_CODES.ENOENT ? E.WASI_EBADF : E.WASI_EIO;
          }
        }
        return E.WASI_ESUCCESS;
      },

      clipboard_set: (ptr, len) => {
        this._recordSyscall('omni:clipboard_set');
        const text = this._readUtf8(ptr, len);
        if (text === null) return E.WASI_EFAULT;
        if (this._isCapabilityExplicitlyDenied('clipboard.write')) return E.WASI_EACCES;
        if (!this._clipboard) return E.WASI_ENOSYS;
        try {
          this._clipboard.set({
            text,
            sourceAppId: this._appId,
            sourcePlatform: 'universal',
          });
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      clipboard_get: (bufPtr, bufLen) => {
        this._recordSyscall('omni:clipboard_get');
        const out = this.checkMem(bufPtr, bufLen);
        if (!out) return -E.WASI_EFAULT;
        if (this._isCapabilityExplicitlyDenied('clipboard.read')) return -E.WASI_EACCES;
        if (!this._clipboard) return -E.WASI_ENOSYS;
        try {
          const rec = this._clipboard.get();
          const text = typeof rec?.text === 'string' ? rec.text : '';
          const bytes = TEXT_ENCODER.encode(text);
          const n = Math.min(out.n, bytes.byteLength);
          if (n > 0) {
            out.u8.set(bytes.subarray(0, n), out.p);
          }
          return n;
        } catch (err) {
          return -mapVfsErrorToWasi(err);
        }
      },

      notify_post: (titlePtr, titleLen, bodyPtr, bodyLen) => {
        this._recordSyscall('omni:notify_post');
        const title = this._readUtf8(titlePtr, titleLen);
        const body = this._readUtf8(bodyPtr, bodyLen);
        if (title === null || body === null) return E.WASI_EFAULT;
        if (this._isCapabilityExplicitlyDenied('notifications.post')) return E.WASI_EACCES;
        if (!this._notifications) return E.WASI_ENOSYS;
        if (title.trim().length === 0) return E.WASI_EINVAL;
        try {
          this._notifications.post({
            appId: this._appId,
            platform: 'universal',
            title,
            body,
          });
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      ipc_send: (chanPtr, chanLen, msgPtr, msgLen) => {
        this._recordSyscall('omni:ipc_send');
        const channel = this._readUtf8(chanPtr, chanLen);
        const message = this._readUtf8(msgPtr, msgLen);
        if (channel === null || message === null) return E.WASI_EFAULT;
        if (this._isCapabilityExplicitlyDenied('ipc.broadcast')) return E.WASI_EACCES;
        if (!this._ipc) return E.WASI_ENOSYS;
        if (channel.length === 0 || channel.includes('\0')) return E.WASI_EINVAL;
        try {
          this._ipc.send(channel, this._pid, message);
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      intent_dispatch: (actionPtr, actionLen, uriPtr, uriLen, mimePtr, mimeLen) => {
        this._recordSyscall('omni:intent_dispatch');
        const action = this._readUtf8(actionPtr, actionLen);
        const uri = this._readUtf8(uriPtr, uriLen);
        const mimeType = this._readUtf8(mimePtr, mimeLen);
        if (action === null || uri === null || mimeType === null) return E.WASI_EFAULT;
        if (!this._intentRouter) return E.WASI_ENOSYS;
        try {
          const res = this._intentRouter.dispatch({
            action: action || null,
            uri: uri || null,
            mimeType: mimeType || null,
            sourcePid: this._pid,
          });
          if (res && typeof res.then === 'function') {
            res.catch(() => {});
          }
          return E.WASI_ESUCCESS;
        } catch (err) {
          return mapVfsErrorToWasi(err);
        }
      },

      log: (ptr, len) => {
        this._recordSyscall('omni:log');
        const text = this._readUtf8(ptr, len);
        if (text === null) return;
        this.logs.push(text);
        if (this.logs.length > 512) {
          this.logs.shift();
        }
        const line = text.endsWith('\n') ? text : `${text}\n`;
        if (this._processManager && this._pid > 0) {
          try {
            this._processManager.writeStdout(this._pid, line);
          } catch {
            // Isolate stream write errors
          }
        } else {
          this._fallbackStdoutChunks.push(TEXT_ENCODER.encode(line));
        }
      },
    };
  }

  getImportObject() {
    if (!this._importObject) {
      this._importObject = {
        wasi_snapshot_preview1: this._buildWasiImports(),
        omni_os_v1: this._buildOmniOsImports(),
      };
    }
    return this._importObject;
  }

  getWindows() {
    return Array.from(this._windows.values()).map((w) => ({
      handle: w.handle,
      windowId: w.windowId,
      title: w.title,
      width: w.width,
      height: w.height,
      drawOpsCount: w.committedDrawOps.length,
    }));
  }

  getWindowIds() {
    return Array.from(this._windows.values()).map((w) => w.windowId);
  }

  getOpenFdCount() {
    return this._fds.size;
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    for (const entry of this._fds.values()) {
      if (entry.vfsHandle && !entry.vfsHandle.closed && this._vfs) {
        try {
          this._vfs.closeHandle(entry.vfsHandle);
        } catch {
          // Ignore close errors during teardown
        }
      }
    }
    this._fds.clear();
    this._windows.clear();
    this._memory = null;
    this._cachedBuf = null;
    this._cachedU8 = null;
    this._cachedView = null;
  }
}

export function createWasiBridge(opts = {}) {
  return new WasiBridge(opts);
}
