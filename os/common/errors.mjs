/**
 * OmniOS Structured Error Hierarchy, Cross-Platform Error Codes & POSIX Signals
 * Zero-dependency Node.js 24 ESM foundation shared across M1-M7.
 */

function freezeLookup(obj) {
  return Object.freeze(Object.assign(Object.create(null), obj));
}

export const ERROR_CODES = freezeLookup({
  // POSIX error codes
  EPERM: 'EPERM',
  ENOENT: 'ENOENT',
  ESRCH: 'ESRCH',
  EINTR: 'EINTR',
  EIO: 'EIO',
  ENXIO: 'ENXIO',
  E2BIG: 'E2BIG',
  ENOEXEC: 'ENOEXEC',
  EBADF: 'EBADF',
  ECHILD: 'ECHILD',
  EAGAIN: 'EAGAIN',
  ENOMEM: 'ENOMEM',
  EACCES: 'EACCES',
  EFAULT: 'EFAULT',
  EBUSY: 'EBUSY',
  EEXIST: 'EEXIST',
  EXDEV: 'EXDEV',
  ENODEV: 'ENODEV',
  ENOTDIR: 'ENOTDIR',
  EISDIR: 'EISDIR',
  EINVAL: 'EINVAL',
  ENFILE: 'ENFILE',
  EMFILE: 'EMFILE',
  ENOTTY: 'ENOTTY',
  EFBIG: 'EFBIG',
  ENOSPC: 'ENOSPC',
  ESPIPE: 'ESPIPE',
  EROFS: 'EROFS',
  EPIPE: 'EPIPE',
  ERANGE: 'ERANGE',
  ENOSYS: 'ENOSYS',
  ENOTEMPTY: 'ENOTEMPTY',
  ELOOP: 'ELOOP',
  ENAMETOOLONG: 'ENAMETOOLONG',
  ENOTSUP: 'ENOTSUP',
  EOPNOTSUPP: 'EOPNOTSUPP',
  ETIMEDOUT: 'ETIMEDOUT',
  ECANCELED: 'ECANCELED',
  ENOTCAPABLE: 'ENOTCAPABLE',
  EQUOTA: 'EQUOTA',

  // OmniOS Binary / Container / Format codes
  E_OMNIOS: 'E_OMNIOS',
  E_PATH_TRAVERSAL: 'E_PATH_TRAVERSAL',
  E_ARCHIVE_BOMB: 'E_ARCHIVE_BOMB',
  E_MALFORMED_ZIP: 'E_MALFORMED_ZIP',
  E_BAD_CRC32: 'E_BAD_CRC32',
  E_MALFORMED_AXML: 'E_MALFORMED_AXML',
  E_MALFORMED_ARSC: 'E_MALFORMED_ARSC',
  E_MALFORMED_DEX: 'E_MALFORMED_DEX',
  E_INVALID_DEX_MAGIC: 'E_INVALID_DEX_MAGIC',
  E_INVALID_DEX_CHECKSUM: 'E_INVALID_DEX_CHECKSUM',
  E_INVALID_DEX_HEADER: 'E_INVALID_DEX_HEADER',
  E_INVALID_DEX_BOUNDS: 'E_INVALID_DEX_BOUNDS',
  E_INVALID_LEB128: 'E_INVALID_LEB128',
  E_INVALID_MUTF8: 'E_INVALID_MUTF8',
  E_INVALID_PE: 'E_INVALID_PE',
  E_INVALID_MSIX: 'E_INVALID_MSIX',
  E_INVALID_MSI: 'E_INVALID_MSI',
  E_INVALID_MACHO: 'E_INVALID_MACHO',
  E_INVALID_FAT: 'E_INVALID_FAT',
  E_ENCRYPTED_BINARY: 'E_ENCRYPTED_BINARY',
  E_MALFORMED_PLIST: 'E_MALFORMED_PLIST',
  E_CYCLIC_PLIST: 'E_CYCLIC_PLIST',
  E_INVALID_WASM: 'E_INVALID_WASM',
  E_MALFORMED_BINARY: 'E_MALFORMED_BINARY',
  E_BUFFER_OVERFLOW: 'E_BUFFER_OVERFLOW',
  E_EOF: 'E_EOF',

  // VMM / CPU / Quota / Runtime codes
  E_CPU_QUOTA: 'E_CPU_QUOTA',
  E_MEMORY_QUOTA: 'E_MEMORY_QUOTA',
  E_FD_QUOTA: 'E_FD_QUOTA',
  E_WINDOW_QUOTA: 'E_WINDOW_QUOTA',
  E_UNMAPPED_PAGE: 'E_UNMAPPED_PAGE',
  E_GUARD_VIOLATION: 'E_GUARD_VIOLATION',
  E_READ_VIOLATION: 'E_READ_VIOLATION',
  E_WRITE_VIOLATION: 'E_WRITE_VIOLATION',
  E_NX_EXEC_VIOLATION: 'E_NX_EXEC_VIOLATION',
  E_MISALIGNED_ACCESS: 'E_MISALIGNED_ACCESS',
  E_ILLEGAL_INSTRUCTION: 'E_ILLEGAL_INSTRUCTION',
  E_UNSUPPORTED_OPCODE: 'E_UNSUPPORTED_OPCODE',
  E_UNRESOLVED_IMPORT: 'E_UNRESOLVED_IMPORT',
  E_UNIMPLEMENTED_API: 'E_UNIMPLEMENTED_API',

  // Process / Service / Kernel / Storage / Security codes
  E_INVALID_TRANSITION: 'E_INVALID_TRANSITION',
  E_PROCESS_PROTECTED: 'E_PROCESS_PROTECTED',
  E_SERVICE_ERROR: 'E_SERVICE_ERROR',
  E_SERVICE_CYCLE: 'E_SERVICE_CYCLE',
  E_SERVICE_MISSING_DEP: 'E_SERVICE_MISSING_DEP',
  E_SERVICE_DEPENDENCY: 'E_SERVICE_DEPENDENCY',
  E_SERVICE_EXISTS: 'E_SERVICE_EXISTS',
  E_SERVICE_NOT_FOUND: 'E_SERVICE_NOT_FOUND',
  E_SERVICE_INVALID: 'E_SERVICE_INVALID',
  E_SERVICE_START_FAILED: 'E_SERVICE_START_FAILED',
  E_KERNEL_PANIC: 'E_KERNEL_PANIC',
  E_KERNEL_NOT_RUNNING: 'E_KERNEL_NOT_RUNNING',
  E_STORAGE_ERROR: 'E_STORAGE_ERROR',
  E_STORAGE_CLOSED: 'E_STORAGE_CLOSED',
  E_MIGRATION_FAILED: 'E_MIGRATION_FAILED',
  E_ASYNC_TRANSACTION: 'E_ASYNC_TRANSACTION',
  E_PERMISSION_DENIED: 'E_PERMISSION_DENIED',
  E_SANDBOX_VIOLATION: 'E_SANDBOX_VIOLATION',
});

export const POSIX_ERRNO = freezeLookup({
  EPERM: 1,
  ENOENT: 2,
  ESRCH: 3,
  EINTR: 4,
  EIO: 5,
  ENXIO: 6,
  E2BIG: 7,
  ENOEXEC: 8,
  EBADF: 9,
  ECHILD: 10,
  EAGAIN: 11,
  ENOMEM: 12,
  EACCES: 13,
  EFAULT: 14,
  EBUSY: 16,
  EEXIST: 17,
  EXDEV: 18,
  ENODEV: 19,
  ENOTDIR: 20,
  EISDIR: 21,
  EINVAL: 22,
  ENFILE: 23,
  EMFILE: 24,
  ENOTTY: 25,
  EFBIG: 27,
  ENOSPC: 28,
  ESPIPE: 29,
  EROFS: 30,
  EPIPE: 32,
  ERANGE: 34,
  ENAMETOOLONG: 36,
  ENOSYS: 38,
  ENOTEMPTY: 39,
  ELOOP: 40,
  ENOTSUP: 95,
  EOPNOTSUPP: 95,
  ETIMEDOUT: 110,
  ECANCELED: 125,
});

export const DARWIN_ERRNO = freezeLookup({
  ...POSIX_ERRNO,
  EAGAIN: 35,
  EOPNOTSUPP: 45,
  ENOTSUP: 45,
  ETIMEDOUT: 60,
  ELOOP: 62,
  ENAMETOOLONG: 63,
  ENOTEMPTY: 66,
  ENOSYS: 78,
  ECANCELED: 89,
});

export const WIN32_ERROR = freezeLookup({
  ERROR_SUCCESS: 0,
  ERROR_INVALID_FUNCTION: 1,
  ERROR_FILE_NOT_FOUND: 2,
  ERROR_PATH_NOT_FOUND: 3,
  ERROR_TOO_MANY_OPEN_FILES: 4,
  ERROR_ACCESS_DENIED: 5,
  ERROR_INVALID_HANDLE: 6,
  ERROR_NOT_ENOUGH_MEMORY: 8,
  ERROR_OUTOFMEMORY: 14,
  ERROR_WRITE_PROTECT: 19,
  ERROR_SHARING_VIOLATION: 32,
  ERROR_FILE_EXISTS: 80,
  ERROR_INVALID_PARAMETER: 87,
  ERROR_BROKEN_PIPE: 109,
  ERROR_DISK_FULL: 112,
  ERROR_CALL_NOT_IMPLEMENTED: 120,
  ERROR_INSUFFICIENT_BUFFER: 122,
  ERROR_INVALID_NAME: 123,
  ERROR_MOD_NOT_FOUND: 126,
  ERROR_PROC_NOT_FOUND: 127,
  ERROR_DIR_NOT_EMPTY: 145,
  ERROR_ALREADY_EXISTS: 183,
  ERROR_MORE_DATA: 234,
  ERROR_NO_MORE_ITEMS: 259,
  ERROR_DIRECTORY: 267,
  ERROR_INVALID_ADDRESS: 487,
  STATUS_ACCESS_VIOLATION: 0xc0000005,
  STATUS_ILLEGAL_INSTRUCTION: 0xc000001d,
  STATUS_INTEGER_DIVIDE_BY_ZERO: 0xc0000094,
  STATUS_STACK_OVERFLOW: 0xc00000fd,
});

export const WASI_ERRNO = freezeLookup({
  WASI_ESUCCESS: 0,
  WASI_E2BIG: 1,
  WASI_EACCES: 2,
  WASI_EAGAIN: 6,
  WASI_EBADF: 8,
  WASI_EBUSY: 10,
  WASI_EEXIST: 20,
  WASI_EFAULT: 21,
  WASI_EFBIG: 22,
  WASI_EINTR: 27,
  WASI_EINVAL: 28,
  WASI_EIO: 29,
  WASI_EISDIR: 31,
  WASI_ELOOP: 32,
  WASI_EMFILE: 33,
  WASI_ENAMETOOLONG: 37,
  WASI_ENOENT: 44,
  WASI_ENOMEM: 48,
  WASI_ENOSPC: 51,
  WASI_ENOSYS: 52,
  WASI_ENOTDIR: 54,
  WASI_ENOTEMPTY: 55,
  WASI_ENOTSUP: 58,
  WASI_EPERM: 63,
  WASI_EPIPE: 64,
  WASI_EROFS: 69,
  WASI_ESPIPE: 70,
  WASI_EXDEV: 75,
  WASI_ENOTCAPABLE: 76,
});

export const SIGNALS = freezeLookup({
  SIGHUP: 1,
  SIGINT: 2,
  SIGQUIT: 3,
  SIGILL: 4,
  SIGTRAP: 5,
  SIGABRT: 6,
  SIGBUS: 7,
  SIGFPE: 8,
  SIGKILL: 9,
  SIGUSR1: 10,
  SIGSEGV: 11,
  SIGUSR2: 12,
  SIGPIPE: 13,
  SIGALRM: 14,
  SIGTERM: 15,
  SIGCHLD: 17,
  SIGCONT: 18,
  SIGSTOP: 19,
  SIGTSTP: 20,
  SIGXCPU: 24,
});

export const SIGNAL_NAMES = freezeLookup(
  Object.fromEntries(Object.entries(SIGNALS).map(([name, num]) => [num, name]))
);

function toJsonSafeScalar(val) {
  if (val === null || val === undefined) return val;
  if (typeof val === 'bigint') {
    return val < 0n ? `-0x${(-val).toString(16)}` : `0x${val.toString(16)}`;
  }
  if (typeof val === 'number') return Number.isFinite(val) ? val : null;
  if (typeof val === 'string' || typeof val === 'boolean') return val;
  if (typeof val === 'object') return toJsonSafeDetails(val);
  try {
    return String(val);
  } catch {
    return '[Unreadable]';
  }
}

function toJsonSafeDetails(val, seen = new Set(), depth = 0) {
  if (val === null || val === undefined) return val;
  const t = typeof val;
  if (t === 'bigint') return toJsonSafeScalar(val);
  if (t === 'number') return Number.isFinite(val) ? val : null;
  if (t === 'string' || t === 'boolean') return val;
  if (t !== 'object') {
    try {
      return String(val);
    } catch {
      return '[Unreadable]';
    }
  }
  if (depth > 8) return '[MaxDepth]';
  if (seen.has(val)) return '[Circular]';
  seen.add(val);
  try {
    if (val instanceof Date) {
      const ms = val.getTime();
      return Number.isNaN(ms) ? 'Invalid Date' : val.toISOString();
    }
    if (Array.isArray(val)) return val.map((item) => toJsonSafeDetails(item, seen, depth + 1));
    const out = {};
    for (const k of Object.keys(val)) {
      let propVal;
      try {
        propVal = val[k];
      } catch {
        propVal = '[Unreadable]';
      }
      Object.defineProperty(out, k, {
        value: toJsonSafeDetails(propVal, seen, depth + 1),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return out;
  } catch {
    return '[Unreadable]';
  } finally {
    seen.delete(val);
  }
}

export class OmniOSError extends Error {
  constructor(
    message,
    {
      code = ERROR_CODES.E_OMNIOS,
      errno = undefined,
      signal = null,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = new.target.name;
    this.code = code;
    this.errno =
      errno !== undefined
        ? errno
        : typeof code === 'string' && Object.prototype.hasOwnProperty.call(POSIX_ERRNO, code)
          ? POSIX_ERRNO[code]
          : null;
    this.signal = signal;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: toJsonSafeScalar(this.code),
      errno: toJsonSafeScalar(this.errno),
      signal: toJsonSafeScalar(this.signal),
      details: toJsonSafeDetails(this.details),
      timestamp: this.timestamp,
    };
  }
}

export class MemoryFaultError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.E_UNMAPPED_PAGE,
      faultType = null,
      address = undefined,
      addr = undefined,
      access = null,
      pagePerms = null,
      pid = null,
      signal = undefined,
      errno = undefined,
      details = null,
      cause = undefined,
    } = {}
  ) {
    const resolvedSignal =
      signal !== undefined ? signal : code === ERROR_CODES.ENOMEM ? null : 'SIGSEGV';
    super(message, { code, errno, signal: resolvedSignal, details, cause });
    const resolvedAddr = address !== undefined ? address : addr !== undefined ? addr : null;
    this.faultType = faultType ?? code;
    this.address = resolvedAddr;
    this.addr = resolvedAddr;
    this.access = access;
    this.pagePerms = pagePerms;
    this.pid = pid;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      faultType: toJsonSafeScalar(this.faultType),
      address: toJsonSafeScalar(this.address),
      addr: toJsonSafeScalar(this.addr),
      access: toJsonSafeScalar(this.access),
      pagePerms: toJsonSafeScalar(this.pagePerms),
      pid: toJsonSafeScalar(this.pid),
    };
  }
}

export class IllegalInstructionError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.E_ILLEGAL_INSTRUCTION,
      pc = null,
      opcode = null,
      arch = null,
      pid = null,
      signal = 'SIGILL',
      errno = undefined,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, errno, signal, details, cause });
    this.pc = pc;
    this.opcode = opcode;
    this.arch = arch;
    this.pid = pid;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      pc: toJsonSafeScalar(this.pc),
      opcode: toJsonSafeScalar(this.opcode),
      arch: toJsonSafeScalar(this.arch),
      pid: toJsonSafeScalar(this.pid),
    };
  }
}

export class UnsupportedOpcodeError extends IllegalInstructionError {
  constructor(
    message,
    {
      code = ERROR_CODES.E_UNSUPPORTED_OPCODE,
      pc = null,
      opcode = null,
      arch = null,
      pid = null,
      signal = 'SIGILL',
      errno = undefined,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, pc, opcode, arch, pid, signal, errno, details, cause });
  }
}

export class QuotaExceededError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.E_CPU_QUOTA,
      quotaType = undefined,
      quota = undefined,
      limit = null,
      actual = undefined,
      current = undefined,
      pid = null,
      signal = undefined,
      errno = undefined,
      details = null,
      cause = undefined,
    } = {}
  ) {
    const resolvedSignal =
      signal !== undefined ? signal : code === ERROR_CODES.E_CPU_QUOTA ? 'SIGXCPU' : null;
    super(message, { code, errno, signal: resolvedSignal, details, cause });
    const normalizedQuota = quotaType ?? quota ?? 'cpu';
    const normalizedActual = actual ?? current ?? null;
    this.quotaType = normalizedQuota;
    this.quota = normalizedQuota;
    this.limit = limit;
    this.actual = normalizedActual;
    this.current = normalizedActual;
    this.pid = pid;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      quotaType: toJsonSafeScalar(this.quotaType),
      limit: toJsonSafeScalar(this.limit),
      actual: toJsonSafeScalar(this.actual),
      pid: toJsonSafeScalar(this.pid),
    };
  }
}

export class SyscallError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.ENOSYS,
      syscall = null,
      pid = null,
      errno = undefined,
      signal = null,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, errno, signal, details, cause });
    this.syscall = syscall;
    this.pid = pid;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      syscall: toJsonSafeScalar(this.syscall),
      pid: toJsonSafeScalar(this.pid),
    };
  }
}

export class VfsError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.EIO,
      path = null,
      syscall = null,
      errno = undefined,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, errno, details, cause });
    this.path = path;
    this.syscall = syscall;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      path: toJsonSafeScalar(this.path),
      syscall: toJsonSafeScalar(this.syscall),
    };
  }
}

export class FormatError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.E_MALFORMED_BINARY,
      format = null,
      offset = null,
      errno = undefined,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, errno, details, cause });
    this.format = format;
    this.offset = offset;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      format: toJsonSafeScalar(this.format),
      offset: toJsonSafeScalar(this.offset),
    };
  }
}

export class SecurityError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.EACCES,
      capability = null,
      appId = null,
      pid = null,
      errno = undefined,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, errno, details, cause });
    this.capability = capability;
    this.appId = appId;
    this.pid = pid;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      capability: toJsonSafeScalar(this.capability),
      appId: toJsonSafeScalar(this.appId),
      pid: toJsonSafeScalar(this.pid),
    };
  }
}

export class KernelPanicError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.E_KERNEL_PANIC,
      panicDump = null,
      context = null,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, details, cause });
    this.panicDump = panicDump;
    this.context = context;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      panicDump: toJsonSafeDetails(this.panicDump),
      context: toJsonSafeDetails(this.context),
    };
  }
}

export class UnresolvedImportError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.E_UNRESOLVED_IMPORT,
      library = null,
      symbol = null,
      ordinal = null,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, details, cause });
    this.library = library;
    this.symbol = symbol;
    this.ordinal = ordinal;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      library: toJsonSafeScalar(this.library),
      symbol: toJsonSafeScalar(this.symbol),
      ordinal: toJsonSafeScalar(this.ordinal),
    };
  }
}

export class ProcessError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.ESRCH,
      pid = null,
      state = null,
      targetState = null,
      errno = undefined,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, errno, details, cause });
    this.pid = pid;
    this.state = state;
    this.targetState = targetState;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      pid: toJsonSafeScalar(this.pid),
      state: toJsonSafeScalar(this.state),
      targetState: toJsonSafeScalar(this.targetState),
    };
  }
}

export class ServiceError extends OmniOSError {
  constructor(
    message,
    {
      code = ERROR_CODES.E_SERVICE_ERROR,
      serviceName = null,
      cycle = null,
      missingDep = null,
      details = null,
      cause = undefined,
    } = {}
  ) {
    super(message, { code, details, cause });
    this.serviceName = serviceName;
    this.cycle = cycle;
    this.missingDep = missingDep;
  }

  toJSON() {
    return {
      ...super.toJSON(),
      serviceName: toJsonSafeScalar(this.serviceName),
      cycle: toJsonSafeDetails(this.cycle),
      missingDep: toJsonSafeScalar(this.missingDep),
    };
  }
}

export function isOmniOSError(err) {
  return err instanceof OmniOSError;
}

export function resolveSignal(sig) {
  if (typeof sig === 'number' && Number.isInteger(sig)) {
    if (Object.prototype.hasOwnProperty.call(SIGNAL_NAMES, sig)) {
      return { name: SIGNAL_NAMES[sig], number: sig };
    }
    throw new OmniOSError(`Unknown signal: ${sig}`, { code: ERROR_CODES.EINVAL });
  }
  if (typeof sig === 'string') {
    const trimmed = sig.trim().toUpperCase();
    if (trimmed.length > 0) {
      const fullName = trimmed.startsWith('SIG') ? trimmed : `SIG${trimmed}`;
      if (Object.prototype.hasOwnProperty.call(SIGNALS, fullName)) {
        return { name: fullName, number: SIGNALS[fullName] };
      }
    }
  }
  throw new OmniOSError(`Unknown signal: ${sig}`, { code: ERROR_CODES.EINVAL });
}

export function posixCodeToDarwinErrno(code) {
  if (typeof code === 'string' && Object.prototype.hasOwnProperty.call(DARWIN_ERRNO, code)) {
    return DARWIN_ERRNO[code];
  }
  return DARWIN_ERRNO.EIO;
}

const POSIX_TO_WIN32_MAP = freezeLookup({
  ENOENT: WIN32_ERROR.ERROR_FILE_NOT_FOUND,
  EACCES: WIN32_ERROR.ERROR_ACCESS_DENIED,
  EPERM: WIN32_ERROR.ERROR_ACCESS_DENIED,
  EBADF: WIN32_ERROR.ERROR_INVALID_HANDLE,
  ENOMEM: WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY,
  EEXIST: WIN32_ERROR.ERROR_ALREADY_EXISTS,
  EINVAL: WIN32_ERROR.ERROR_INVALID_PARAMETER,
  ENOSPC: WIN32_ERROR.ERROR_DISK_FULL,
  EMFILE: WIN32_ERROR.ERROR_TOO_MANY_OPEN_FILES,
  ENOTDIR: WIN32_ERROR.ERROR_DIRECTORY,
  EISDIR: WIN32_ERROR.ERROR_DIRECTORY,
  ENOTEMPTY: WIN32_ERROR.ERROR_DIR_NOT_EMPTY,
  ENOSYS: WIN32_ERROR.ERROR_CALL_NOT_IMPLEMENTED,
  EFAULT: WIN32_ERROR.ERROR_INVALID_ADDRESS,
  EPIPE: WIN32_ERROR.ERROR_BROKEN_PIPE,
  EROFS: WIN32_ERROR.ERROR_WRITE_PROTECT,
  EBUSY: WIN32_ERROR.ERROR_SHARING_VIOLATION,
  ENAMETOOLONG: WIN32_ERROR.ERROR_INVALID_NAME,
});

export function posixCodeToWin32(code) {
  if (typeof code === 'string' && Object.prototype.hasOwnProperty.call(POSIX_TO_WIN32_MAP, code)) {
    return POSIX_TO_WIN32_MAP[code];
  }
  return WIN32_ERROR.ERROR_INVALID_FUNCTION;
}

export function posixCodeToWasi(code) {
  if (code === ERROR_CODES.E_PATH_TRAVERSAL || code === ERROR_CODES.ENOTCAPABLE) {
    return WASI_ERRNO.WASI_ENOTCAPABLE;
  }
  if (typeof code === 'string') {
    const key = `WASI_${code}`;
    if (Object.prototype.hasOwnProperty.call(WASI_ERRNO, key)) {
      return WASI_ERRNO[key];
    }
  }
  return WASI_ERRNO.WASI_EIO;
}
