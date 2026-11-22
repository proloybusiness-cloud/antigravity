/**
 * OmniOS Darwin / XNU BSD Syscall & Mach Trap Layer (`F-051`, Edge Case `#25`)
 * Shared across iOS & macOS runtimes (both ARM64 `SVC #0x80` and x86-64 `SYSCALL`).
 * Zero external dependencies, zero `node:fs` imports.
 *
 * Key Guarantees:
 * - Edge Case #25: BSD errors set Carry flag (`PSTATE.C = 1` ARM64 / `RFLAGS.CF = 1` x86-64)
 *   with POSITIVE Darwin `errno` in `X0`/`RAX`; success clears Carry flag (`C = 0`).
 * - Translates Darwin `O_*` flags to VFS Linux `OPEN_FLAGS`.
 * - ORs `S_IFREG`/`S_IFDIR`/`S_IFLNK`/`S_IFCHR` into `struct stat64.st_mode`.
 * - Maps `E_PATH_TRAVERSAL` -> `DARWIN_ERRNO.EACCES (13)` and `MemoryFaultError` -> `ENOMEM`/`EFAULT`.
 * - Supports optional `permissionBroker` for authorized shared user-space path brokering without
 *   weakening strict app container sandbox isolation.
 */

import { randomBytes } from 'node:crypto';
import {
  MemoryFaultError,
  DARWIN_ERRNO,
  ERROR_CODES,
  posixCodeToDarwinErrno,
} from '../../common/errors.mjs';
import { OPEN_FLAGS, SEEK_WHENCE } from '../../vfs/vfs.mjs';
import { PROT_READ, PROT_WRITE, PROT_EXEC } from '../../kernel/vmm.mjs';

export { DARWIN_ERRNO };

export const DARWIN_SYSCALLS = Object.freeze({
  SYS_syscall: 0,
  SYS_exit: 1,
  SYS_read: 3,
  SYS_write: 4,
  SYS_open: 5,
  SYS_close: 6,
  SYS_unlink: 10,
  SYS_chdir: 12,
  SYS_chmod: 15,
  SYS_getpid: 20,
  SYS_getuid: 24,
  SYS_geteuid: 25,
  SYS_access: 33,
  SYS_getppid: 39,
  SYS_dup: 41,
  SYS_getegid: 43,
  SYS_sigaction: 46,
  SYS_getgid: 47,
  SYS_sigprocmask: 48,
  SYS_symlink: 57,
  SYS_readlink: 58,
  SYS_munmap: 73,
  SYS_mprotect: 74,
  SYS_dup2: 90,
  SYS_fcntl: 92,
  SYS_gettimeofday: 116,
  SYS_rename: 128,
  SYS_mkdir: 136,
  SYS_rmdir: 137,
  SYS_csops: 169,
  SYS_stat: 188,
  SYS_fstat: 189,
  SYS_lstat: 190,
  SYS_mmap: 197,
  SYS_lseek: 199,
  SYS_ftruncate: 201,
  SYS_sysctl: 202,
  SYS_sysctlbyname: 274,
  SYS_issetugid: 327,
  SYS_stat64: 338,
  SYS_fstat64: 339,
  SYS_lstat64: 340,
  SYS_getdirentries64: 344,
  SYS_fstatfs64: 346,
  SYS_bsdthread_register: 366,
  SYS_read_nocancel: 396,
  SYS_write_nocancel: 397,
  SYS_open_nocancel: 398,
  SYS_close_nocancel: 399,
  SYS_fcntl_nocancel: 406,
  SYS_getentropy: 500,
});

export const MACH_TRAPS = Object.freeze({
  mach_absolute_time: -3,
  mach_reply_port: -26,
  thread_self_trap: -27,
  task_self_trap: -28,
  host_self_trap: -29,
  mach_msg_trap: -31,
  mach_timebase_info_trap: -89,
});

export const DARWIN_O_FLAGS = Object.freeze({
  O_RDONLY: 0x0000,
  O_WRONLY: 0x0001,
  O_RDWR: 0x0002,
  O_ACCMODE: 0x0003,
  O_NONBLOCK: 0x0004,
  O_APPEND: 0x0008,
  O_SHLOCK: 0x0010,
  O_EXLOCK: 0x0020,
  O_NOFOLLOW: 0x0100,
  O_CREAT: 0x0200,
  O_TRUNC: 0x0400,
  O_EXCL: 0x0800,
  O_DIRECTORY: 0x100000,
  O_SYMLINK: 0x200000,
  O_CLOEXEC: 0x1000000,
});

const DARWIN_MAP_ANON = 0x1000;
const DARWIN_MAP_FIXED = 0x0010;

const S_IFMT_BY_TYPE = Object.freeze({
  file: 0o100000, // S_IFREG
  dir: 0o040000, // S_IFDIR
  symlink: 0o120000, // S_IFLNK
  device: 0o020000, // S_IFCHR
});

const DT_BY_TYPE = Object.freeze({
  file: 8, // DT_REG
  dir: 4, // DT_DIR
  symlink: 10, // DT_LNK
  device: 2, // DT_CHR
});

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: false });

/**
 * Translate Darwin XNU `O_*` flags to OmniOS VFS Linux `OPEN_FLAGS`.
 */
export function translateDarwinOpenFlags(darwinFlags) {
  const f = Number(typeof darwinFlags === 'bigint' ? darwinFlags & 0xffffffffn : darwinFlags) >>> 0;
  let out = f & DARWIN_O_FLAGS.O_ACCMODE;
  if ((f & DARWIN_O_FLAGS.O_CREAT) !== 0) out |= OPEN_FLAGS.O_CREAT;
  if ((f & DARWIN_O_FLAGS.O_EXCL) !== 0) out |= OPEN_FLAGS.O_EXCL;
  if ((f & DARWIN_O_FLAGS.O_TRUNC) !== 0) out |= OPEN_FLAGS.O_TRUNC;
  if ((f & DARWIN_O_FLAGS.O_APPEND) !== 0) out |= OPEN_FLAGS.O_APPEND;
  // Support both canonical XNU O_DIRECTORY (0x100000) and compact 0x10000
  if ((f & DARWIN_O_FLAGS.O_DIRECTORY) !== 0 || (f & 0x10000) !== 0) {
    out |= OPEN_FLAGS.O_DIRECTORY;
  }
  return out;
}

function mapErrorToDarwinErrno(err) {
  if (!err) return DARWIN_ERRNO.EIO;
  if (err instanceof MemoryFaultError) {
    return err.code === ERROR_CODES.ENOMEM ? DARWIN_ERRNO.ENOMEM : DARWIN_ERRNO.EFAULT;
  }
  const code = err.code;
  if (
    code === ERROR_CODES.E_PATH_TRAVERSAL ||
    code === ERROR_CODES.E_SANDBOX_VIOLATION ||
    code === ERROR_CODES.E_PERMISSION_DENIED
  ) {
    return DARWIN_ERRNO.EACCES;
  }
  if (code === ERROR_CODES.E_FD_QUOTA) {
    return DARWIN_ERRNO.EMFILE;
  }
  if (code === ERROR_CODES.E_MEMORY_QUOTA) {
    return DARWIN_ERRNO.ENOMEM;
  }
  return posixCodeToDarwinErrno(code);
}

/**
 * Serialize VFS stat object into 144-byte Darwin XNU `struct stat64`.
 */
function encodeDarwinStat64(stat) {
  const buf = new Uint8Array(144);
  const dv = new DataView(buf.buffer);

  const typeBits = S_IFMT_BY_TYPE[stat.type] ?? S_IFMT_BY_TYPE.file;
  const mode = (typeBits | ((stat.mode ?? 0o644) & 0o7777)) & 0xffff;

  dv.setInt32(0x00, 1, true); // st_dev
  dv.setUint16(0x04, mode, true); // st_mode (with S_IF* bits!)
  dv.setUint16(0x06, Math.max(1, stat.nlink ?? 1) & 0xffff, true); // st_nlink
  dv.setBigUint64(0x08, BigInt(stat.ino ?? 1), true); // st_ino
  dv.setUint32(0x10, (stat.uid ?? 0) >>> 0, true); // st_uid
  dv.setUint32(0x14, (stat.gid ?? 0) >>> 0, true); // st_gid
  dv.setInt32(0x18, 0, true); // st_rdev

  const writeTimespec = (off, msVal) => {
    const ms = Number.isFinite(msVal) ? msVal : Date.now();
    const sec = BigInt(Math.floor(ms / 1000));
    const nsec = BigInt(Math.floor((ms % 1000) * 1_000_000));
    dv.setBigInt64(off, sec, true);
    dv.setBigInt64(off + 8, nsec < 0n ? nsec + 1_000_000_000n : nsec, true);
  };

  const mtimeMs = stat.mtimeMs ?? Date.parse(stat.mtime ?? '') ?? Date.now();
  const ctimeMs = stat.ctimeMs ?? mtimeMs;
  const atimeMs = stat.atime ? Date.parse(stat.atime) : mtimeMs;
  const birthMs = stat.birthtime ? Date.parse(stat.birthtime) : ctimeMs;

  writeTimespec(0x20, atimeMs); // st_atimespec
  writeTimespec(0x30, mtimeMs); // st_mtimespec
  writeTimespec(0x40, ctimeMs); // st_ctimespec
  writeTimespec(0x50, birthMs); // st_birthtimespec

  const size = BigInt(Math.max(0, stat.size ?? 0));
  dv.setBigInt64(0x60, size, true); // st_size
  dv.setBigInt64(0x68, (size + 511n) / 512n, true); // st_blocks
  dv.setInt32(0x70, 4096, true); // st_blksize
  dv.setUint32(0x74, 0, true); // st_flags
  dv.setUint32(0x78, 0, true); // st_gen
  return buf;
}

// Helpers for x86-64 CPU adapters (compatible with M3 X86_64Cpu directly, adapters, and lightweight mocks)
function getX64Reg(cpu, name) {
  if (typeof cpu.getReg64 === 'function') {
    return BigInt.asUintN(64, BigInt(cpu.getReg64(name)));
  }
  if (typeof cpu.getReg === 'function') {
    return BigInt.asUintN(64, BigInt(cpu.getReg(name)));
  }
  if (cpu.regs && name in cpu.regs) {
    return BigInt.asUintN(64, BigInt(cpu.regs[name]));
  }
  if (name in cpu) {
    return BigInt.asUintN(64, BigInt(cpu[name]));
  }
  return 0n;
}

function setX64Reg(cpu, name, val) {
  const v = BigInt.asUintN(64, typeof val === 'bigint' ? val : BigInt(val));
  if (typeof cpu.setReg64 === 'function') {
    cpu.setReg64(name, v);
  } else if (typeof cpu.setReg === 'function') {
    cpu.setReg(name, v);
  } else if (cpu.regs && name in cpu.regs) {
    cpu.regs[name] = v;
  } else {
    cpu[name] = v;
  }
}

function setX64Carry(cpu, bit) {
  const b = bit ? 1 : 0;
  if (typeof cpu.rflags === 'bigint') {
    cpu.rflags = b ? cpu.rflags | 1n : cpu.rflags & ~1n;
    return;
  }
  if (typeof cpu.setFlag === 'function') {
    cpu.setFlag('CF', Boolean(b));
    return;
  }
  if (cpu.flags && typeof cpu.flags === 'object') {
    cpu.flags.CF = b;
    return;
  }
  if (typeof cpu.rflags === 'number') {
    cpu.rflags = b ? (cpu.rflags | 1) >>> 0 : (cpu.rflags & ~1) >>> 0;
  }
}

export class DarwinSyscallLayer {
  constructor({
    pcb = null,
    addressSpace = null,
    vfs = null,
    processManager = null,
    platform = 'macos',
    arch = 'arm64',
    appId = '',
    containerUuid = '',
    sandboxRoot = null,
    cwd = '/home/user',
    pid = null,
    ppid = 1,
    uid = null,
    gid = null,
    entitlementsXml = null,
    permissionBroker = null,
    onStdout = null,
    onStderr = null,
  } = {}) {
    this.pcb = pcb;
    this.addressSpace = addressSpace ?? pcb?.addressSpace ?? null;
    this.vfs = vfs;
    this.processManager = processManager;
    this.platform = platform;
    this.arch = arch;
    this.appId = appId || pcb?.appId || '';
    this.containerUuid = containerUuid || '';
    this.sandboxRoot = sandboxRoot;
    this.cwd = cwd || pcb?.cwd || '/home/user';
    this.pid = pid ?? pcb?.pid ?? 1;
    this.ppid = ppid ?? pcb?.ppid ?? 1;
    this.uid = uid ?? pcb?.uid ?? 1000;
    this.gid = gid ?? pcb?.gid ?? 1000;
    this.entitlementsXml = entitlementsXml;
    this.permissionBroker = typeof permissionBroker === 'function' ? permissionBroker : null;
    this.onStdout = typeof onStdout === 'function' ? onStdout : null;
    this.onStderr = typeof onStderr === 'function' ? onStderr : null;

    this.hasExited = false;
    this.exitCode = 0;
    this.syscallCount = 0;
    this.lastSyscall = null;
    this._nextMachPort = 0x1003;
    this._fdHandles = new Map(); // fd -> VfsFileHandle (for standalone & fast lookup)
    this._fdFlags = new Map(); // fd -> cloexec / fcntl flags
    this._dirCursors = new Map(); // fd -> dirent index cursor
  }

  _baseVfsCtx() {
    const ctx = {
      pid: this.pcb ? this.pcb.pid : null,
      uid: this.pcb?.uid ?? this.uid,
      gid: this.pcb?.gid ?? this.gid,
      cwd: this.pcb?.cwd ?? this.cwd,
      platform: this.platform,
      appId: this.appId,
      containerUuid: this.containerUuid,
    };
    if (this.sandboxRoot !== null && this.sandboxRoot !== undefined) {
      ctx.sandboxRoot = this.sandboxRoot;
    }
    return ctx;
  }

  _resolveEffectiveCtx(rawPath, wantWrite = false) {
    const baseCtx = this._baseVfsCtx();
    if (!this.permissionBroker || !this.vfs?.pathTranslator) {
      return baseCtx;
    }
    try {
      const translated = this.vfs.pathTranslator.toCanonical(rawPath, {
        platform: baseCtx.platform,
        cwd: baseCtx.cwd,
        appId: baseCtx.appId,
        containerUuid: baseCtx.containerUuid,
      });
      const canonical = translated.canonicalPath;
      const inSharedUser =
        canonical === '/home/user' || canonical.startsWith('/home/user/');
      if (!inSharedUser) {
        return baseCtx;
      }
      // If already within sandboxRoot, no brokering needed
      if (
        baseCtx.sandboxRoot &&
        (canonical === baseCtx.sandboxRoot || canonical.startsWith(`${baseCtx.sandboxRoot}/`))
      ) {
        return baseCtx;
      }

      const decision = this.permissionBroker({
        action: wantWrite ? 'write' : 'read',
        capability: wantWrite ? 'fs.write.user' : 'fs.read.user',
        rawPath,
        canonicalPath: canonical,
        appId: baseCtx.appId,
        pid: this.pid,
        platform: baseCtx.platform,
      });

      if (decision && decision.allowed === true) {
        const defaultSharedRoot =
          this.platform === 'ios' ? '/home/user/Documents' : '/home/user';
        return {
          ...baseCtx,
          uid: 1000,
          gid: 1000,
          sandboxRoot: defaultSharedRoot,
          ...(decision.effectiveCtx ?? {}),
        };
      }
    } catch {
      // Fall back strictly to baseCtx (which enforces sandbox jail!)
    }
    return baseCtx;
  }

  _pathWithinRoot(canonicalPath, root) {
    if (!root || root === '/') return true;
    const cleanRoot = root.length > 1 && root.endsWith('/') ? root.slice(0, -1) : root;
    return canonicalPath === cleanRoot || canonicalPath.startsWith(`${cleanRoot}/`);
  }

  _resolveRenameCtx(oldPath, newPath) {
    const srcCtx = this._resolveEffectiveCtx(oldPath, true);
    const dstCtx = this._resolveEffectiveCtx(newPath, true);
    if (srcCtx.uid !== dstCtx.uid || srcCtx.gid !== dstCtx.gid) {
      return null;
    }
    const srcRoot = srcCtx.sandboxRoot ?? null;
    const dstRoot = dstCtx.sandboxRoot ?? null;
    if (srcRoot !== dstRoot) {
      return null;
    }
    if (srcRoot !== null && this.vfs?.pathTranslator) {
      try {
        const oldCan = this.vfs.pathTranslator.toCanonical(oldPath, {
          platform: srcCtx.platform,
          cwd: srcCtx.cwd,
          appId: srcCtx.appId,
          containerUuid: srcCtx.containerUuid,
        }).canonicalPath;
        const newCan = this.vfs.pathTranslator.toCanonical(newPath, {
          platform: dstCtx.platform,
          cwd: dstCtx.cwd,
          appId: dstCtx.appId,
          containerUuid: dstCtx.containerUuid,
        }).canonicalPath;
        if (!this._pathWithinRoot(oldCan, srcRoot) || !this._pathWithinRoot(newCan, dstRoot)) {
          return null;
        }
      } catch {
        return null;
      }
    }
    return srcCtx;
  }

  _getHandle(fd) {
    if (this._fdHandles.has(fd)) {
      return this._fdHandles.get(fd);
    }
    if (this.pcb?.fdTable?.has(fd)) {
      const entry = this.pcb.fdTable.get(fd);
      if (entry?.handle) return entry.handle;
    }
    return null;
  }

  /**
   * Dispatch ARM64 `SVC #imm16` (typically `SVC #0x80`).
   * Edge Case #25: Carry flag `PSTATE.C = 1` + positive Darwin `errno` in `X0` on BSD error.
   */
  handleArm64Svc(cpu, _imm16 = 0x80) {
    let rawNum = BigInt.asIntN(64, cpu.getReg(16));
    let args;
    if (rawNum === 0n) {
      // Indirect SYS_syscall: real syscall number in X0, args in X1..X6
      rawNum = BigInt.asIntN(64, cpu.getReg(0));
      args = [
        cpu.getReg(1),
        cpu.getReg(2),
        cpu.getReg(3),
        cpu.getReg(4),
        cpu.getReg(5),
        cpu.getReg(6),
      ];
    } else {
      args = [
        cpu.getReg(0),
        cpu.getReg(1),
        cpu.getReg(2),
        cpu.getReg(3),
        cpu.getReg(4),
        cpu.getReg(5),
      ];
    }

    const num = Number(rawNum);
    this.syscallCount += 1;
    this.lastSyscall = { arch: 'arm64', num, args: args.map((a) => `0x${a.toString(16)}`) };

    if (num < 0) {
      const machRes = this._dispatchMachTrap(num, args, cpu.addressSpace ?? this.addressSpace);
      cpu.setReg(0, BigInt.asUintN(64, machRes));
      return null;
    }

    const outcome = this._dispatchBsdSyscall(num, args, cpu.addressSpace ?? this.addressSpace);
    if (outcome.exited) {
      cpu.halted = true;
      cpu.exitCode = outcome.exitCode;
      return { status: 'EXITED', exitCode: outcome.exitCode };
    }
    if (outcome.error !== undefined) {
      // Edge Case #25: Set Carry flag C = 1 and place POSITIVE Darwin errno in X0
      cpu.pstate.C = 1;
      cpu.setReg(0, BigInt(outcome.error >>> 0));
    } else {
      // Success: Clear Carry flag C = 0
      cpu.pstate.C = 0;
      cpu.setReg(0, BigInt.asUintN(64, outcome.value ?? 0n));
      if (outcome.value2 !== undefined) {
        cpu.setReg(1, BigInt.asUintN(64, outcome.value2));
      }
    }
    return null;
  }

  /**
   * Dispatch x86-64 `SYSCALL` (Darwin class `0x02` = Unix BSD, `0x01` = Mach).
   * Edge Case #25: Carry flag `RFLAGS.CF = 1` + positive Darwin `errno` in `RAX` on BSD error.
   */
  handleX86_64Syscall(cpu) {
    const rax = getX64Reg(cpu, 'rax');
    const sysClass = Number((rax >> 24n) & 0xffn);
    const lowNum = Number(rax & 0xffffffn);
    const args = [
      getX64Reg(cpu, 'rdi'),
      getX64Reg(cpu, 'rsi'),
      getX64Reg(cpu, 'rdx'),
      getX64Reg(cpu, 'r10'),
      getX64Reg(cpu, 'r8'),
      getX64Reg(cpu, 'r9'),
    ];

    this.syscallCount += 1;

    // Class 1 (0x01xxxxxx) -> Mach trap (negative trap number)
    if (sysClass === 1) {
      const trapNum = -lowNum;
      this.lastSyscall = { arch: 'x86_64', num: trapNum };
      const machRes = this._dispatchMachTrap(trapNum, args, cpu.addressSpace ?? this.addressSpace);
      setX64Reg(cpu, 'rax', machRes);
      return null;
    }

    // Class 2 (0x02xxxxxx) or raw BSD syscall number
    let bsdNum = sysClass === 2 ? lowNum : Number(BigInt.asIntN(32, rax));
    if (bsdNum < 0) {
      this.lastSyscall = { arch: 'x86_64', num: bsdNum };
      const machRes = this._dispatchMachTrap(bsdNum, args, cpu.addressSpace ?? this.addressSpace);
      setX64Reg(cpu, 'rax', machRes);
      return null;
    }

    if (bsdNum === 0) {
      bsdNum = Number(args[0] & 0xffffffn);
      args.shift();
      args.push(0n);
    }

    this.lastSyscall = { arch: 'x86_64', num: bsdNum };
    const outcome = this._dispatchBsdSyscall(bsdNum, args, cpu.addressSpace ?? this.addressSpace);
    if (outcome.exited) {
      cpu.halted = true;
      if ('exited' in cpu) cpu.exited = true;
      cpu.exitCode = outcome.exitCode;
      return { status: 'EXITED', exitCode: outcome.exitCode };
    }
    if (outcome.error !== undefined) {
      // Edge Case #25: Set RFLAGS.CF = 1 and positive Darwin errno in RAX
      setX64Carry(cpu, 1);
      setX64Reg(cpu, 'rax', BigInt(outcome.error >>> 0));
    } else {
      setX64Carry(cpu, 0);
      setX64Reg(cpu, 'rax', outcome.value ?? 0n);
      if (outcome.value2 !== undefined) {
        setX64Reg(cpu, 'rdx', outcome.value2);
      }
    }
    return null;
  }

  // =========================================================================
  // Mach Traps
  // =========================================================================

  _dispatchMachTrap(trapNum, args, addrSpace) {
    switch (trapNum) {
      case MACH_TRAPS.mach_absolute_time:
        return process.hrtime.bigint();
      case MACH_TRAPS.mach_reply_port: {
        const port = BigInt(this._nextMachPort);
        this._nextMachPort += 0x100;
        return port;
      }
      case MACH_TRAPS.thread_self_trap:
        return 0x203n;
      case MACH_TRAPS.task_self_trap:
        return 0x103n;
      case MACH_TRAPS.host_self_trap:
        return 0x303n;
      case MACH_TRAPS.mach_msg_trap:
        return 0n; // MACH_MSG_SUCCESS
      case MACH_TRAPS.mach_timebase_info_trap: {
        const infoPtr = args[0];
        if (infoPtr !== 0n && addrSpace) {
          try {
            addrSpace.writeU32(infoPtr, 1, true); // numer = 1
            addrSpace.writeU32(infoPtr + 4n, 1, true); // denom = 1
          } catch (err) {
            if (err instanceof MemoryFaultError || err?.name === 'MemoryFaultError') {
              return 1n; // KERN_INVALID_ADDRESS
            }
            return 1n; // KERN_INVALID_ADDRESS
          }
        }
        return 0n;
      }
      default:
        return 0n;
    }
  }

  // =========================================================================
  // BSD Syscalls
  // =========================================================================

  _dispatchBsdSyscall(num, args, addrSpace) {
    try {
      switch (num) {
        case DARWIN_SYSCALLS.SYS_exit: {
          const code = Number(BigInt.asIntN(32, args[0])) & 0xff;
          this.hasExited = true;
          this.exitCode = code;
          return { exited: true, exitCode: code };
        }

        case DARWIN_SYSCALLS.SYS_read:
        case DARWIN_SYSCALLS.SYS_read_nocancel: {
          const fd = Number(BigInt.asIntN(32, args[0]));
          const bufPtr = args[1];
          const count = Number(args[2]);
          if (count < 0 || !Number.isSafeInteger(count)) {
            return { error: DARWIN_ERRNO.EINVAL };
          }
          if (count === 0) return { value: 0n };
          if (!addrSpace) return { error: DARWIN_ERRNO.EFAULT };

          if (fd === 0) {
            if (this.pcb?.streams?.stdin) {
              const raw = this.pcb.streams.stdin.read(count, { encoding: 'buffer', consume: true });
              const bytes = raw instanceof Uint8Array ? raw : TEXT_ENCODER.encode(String(raw ?? ''));
              if (bytes.byteLength > 0) {
                addrSpace.write(bufPtr, bytes);
              }
              return { value: BigInt(bytes.byteLength) };
            }
            return { value: 0n };
          }

          if (fd < 0 || !this.vfs) return { error: DARWIN_ERRNO.EBADF };
          const handle = this._getHandle(fd);
          const data = handle
            ? handle.read(count)
            : this.vfs.read(fd, count, { pid: this.pcb ? this.pcb.pid : null });
          if (data.byteLength > 0) {
            addrSpace.write(bufPtr, data);
          }
          return { value: BigInt(data.byteLength) };
        }

        case DARWIN_SYSCALLS.SYS_write:
        case DARWIN_SYSCALLS.SYS_write_nocancel: {
          const fd = Number(BigInt.asIntN(32, args[0]));
          const bufPtr = args[1];
          const count = Number(args[2]);
          if (count < 0 || !Number.isSafeInteger(count)) {
            return { error: DARWIN_ERRNO.EINVAL };
          }
          if (!addrSpace) return { error: DARWIN_ERRNO.EFAULT };
          const data = count === 0 ? new Uint8Array(0) : addrSpace.read(bufPtr, count);

          if (fd === 1) {
            if (this.onStdout) this.onStdout(data);
            if (this.processManager && this.pcb) {
              this.processManager.writeStdout(this.pcb.pid, data);
            } else if (this.pcb?.streams?.stdout) {
              this.pcb.streams.stdout.write(data);
            }
            return { value: BigInt(data.byteLength) };
          }
          if (fd === 2) {
            if (this.onStderr) this.onStderr(data);
            if (this.processManager && this.pcb) {
              this.processManager.writeStderr(this.pcb.pid, data);
            } else if (this.pcb?.streams?.stderr) {
              this.pcb.streams.stderr.write(data);
            }
            return { value: BigInt(data.byteLength) };
          }

          if (fd < 0 || !this.vfs) return { error: DARWIN_ERRNO.EBADF };
          const handle = this._getHandle(fd);
          const res = handle
            ? handle.write(data)
            : this.vfs.write(fd, data, { pid: this.pcb ? this.pcb.pid : null });
          return { value: BigInt(res?.bytesWritten ?? data.byteLength) };
        }

        case DARWIN_SYSCALLS.SYS_open:
        case DARWIN_SYSCALLS.SYS_open_nocancel: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const darwinFlags = Number(args[1] & 0xffffffffn) >>> 0;
          const mode = Number(args[2] & 0o7777n) || 0o644;
          const vfsFlags = translateDarwinOpenFlags(darwinFlags);
          const access = darwinFlags & DARWIN_O_FLAGS.O_ACCMODE;
          const wantWrite =
            access === DARWIN_O_FLAGS.O_WRONLY ||
            access === DARWIN_O_FLAGS.O_RDWR ||
            (darwinFlags & (DARWIN_O_FLAGS.O_CREAT | DARWIN_O_FLAGS.O_TRUNC)) !== 0;

          const ctx = this._resolveEffectiveCtx(path, wantWrite);
          const handle = this.vfs.open(path, vfsFlags, { ...ctx, mode });
          this._fdHandles.set(handle.fd, handle);
          this._fdFlags.set(handle.fd, (darwinFlags & DARWIN_O_FLAGS.O_CLOEXEC) !== 0 ? 1 : 0);
          return { value: BigInt(handle.fd) };
        }

        case DARWIN_SYSCALLS.SYS_close:
        case DARWIN_SYSCALLS.SYS_close_nocancel: {
          const fd = Number(BigInt.asIntN(32, args[0]));
          if (fd < 0) return { error: DARWIN_ERRNO.EBADF };
          if (fd <= 2) return { value: 0n };
          const handle = this._getHandle(fd);
          this._fdHandles.delete(fd);
          this._fdFlags.delete(fd);
          this._dirCursors.delete(fd);
          if (handle) {
            handle.close();
            return { value: 0n };
          }
          if (this.vfs) {
            this.vfs.closeHandle(fd, { pid: this.pcb ? this.pcb.pid : null });
            return { value: 0n };
          }
          return { error: DARWIN_ERRNO.EBADF };
        }

        case DARWIN_SYSCALLS.SYS_unlink: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const ctx = this._resolveEffectiveCtx(path, true);
          this.vfs.unlink(path, ctx);
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_chdir: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const ctx = this._resolveEffectiveCtx(path, false);
          const st = this.vfs.stat(path, ctx);
          if (st.type !== 'dir') return { error: DARWIN_ERRNO.ENOTDIR };
          const translated = this.vfs.pathTranslator.toCanonical(path, {
            platform: ctx.platform,
            cwd: ctx.cwd,
            appId: ctx.appId,
            containerUuid: ctx.containerUuid,
          });
          this.cwd = translated.canonicalPath;
          if (this.pcb) this.pcb.cwd = this.cwd;
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_chmod: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const mode = Number(args[1] & 0o7777n);
          const ctx = this._resolveEffectiveCtx(path, true);
          this.vfs.chmod(path, mode, ctx);
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_getpid:
          return { value: BigInt(this.pcb?.pid ?? this.pid) };

        case DARWIN_SYSCALLS.SYS_getppid:
          return { value: BigInt(this.pcb?.ppid ?? this.ppid) };

        case DARWIN_SYSCALLS.SYS_getuid:
        case DARWIN_SYSCALLS.SYS_geteuid:
          return { value: BigInt(this.pcb?.uid ?? this.uid) };

        case DARWIN_SYSCALLS.SYS_getgid:
        case DARWIN_SYSCALLS.SYS_getegid:
          return { value: BigInt(this.pcb?.gid ?? this.gid) };

        case DARWIN_SYSCALLS.SYS_issetugid:
          return { value: 0n };

        case DARWIN_SYSCALLS.SYS_access: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const amode = Number(args[1] & 0x7n);
          const ctx = this._resolveEffectiveCtx(path, (amode & 2) !== 0);
          this.vfs.stat(path, ctx);
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_mkdir: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const mode = Number(args[1] & 0o7777n) || 0o755;
          const ctx = this._resolveEffectiveCtx(path, true);
          this.vfs.mkdir(path, { ...ctx, mode });
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_rmdir: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const ctx = this._resolveEffectiveCtx(path, true);
          this.vfs.rmdir(path, ctx);
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_rename: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const oldPath = addrSpace.readCString(args[0], 4096);
          const newPath = addrSpace.readCString(args[1], 4096);
          const ctx = this._resolveRenameCtx(oldPath, newPath);
          if (!ctx) return { error: DARWIN_ERRNO.EACCES };
          this.vfs.rename(oldPath, newPath, ctx);
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_symlink: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const target = addrSpace.readCString(args[0], 4096);
          const linkPath = addrSpace.readCString(args[1], 4096);
          const ctx = this._resolveEffectiveCtx(linkPath, true);
          this.vfs.symlink(target, linkPath, ctx);
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_readlink: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const bufPtr = args[1];
          const bufSize = Number(args[2]);
          const ctx = this._resolveEffectiveCtx(path, false);
          const target = this.vfs.readlink(path, ctx);
          const encoded = TEXT_ENCODER.encode(target);
          const n = Math.min(encoded.byteLength, Math.max(0, bufSize));
          if (n > 0) addrSpace.write(bufPtr, encoded.subarray(0, n));
          return { value: BigInt(n) };
        }

        case DARWIN_SYSCALLS.SYS_stat:
        case DARWIN_SYSCALLS.SYS_stat64: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const statPtr = args[1];
          const ctx = this._resolveEffectiveCtx(path, false);
          const st = this.vfs.stat(path, ctx);
          addrSpace.write(statPtr, encodeDarwinStat64(st));
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_lstat:
        case DARWIN_SYSCALLS.SYS_lstat64: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const path = addrSpace.readCString(args[0], 4096);
          const statPtr = args[1];
          const ctx = this._resolveEffectiveCtx(path, false);
          const st = this.vfs.lstat(path, ctx);
          addrSpace.write(statPtr, encodeDarwinStat64(st));
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_fstat:
        case DARWIN_SYSCALLS.SYS_fstat64: {
          if (!addrSpace) return { error: DARWIN_ERRNO.EFAULT };
          const fd = Number(BigInt.asIntN(32, args[0]));
          const statPtr = args[1];
          if (fd >= 0 && fd <= 2) {
            const devStat = {
              ino: fd + 1,
              type: 'device',
              mode: 0o620,
              uid: this.uid,
              gid: this.gid,
              size: 0,
              nlink: 1,
              mtimeMs: Date.now(),
              ctimeMs: Date.now(),
            };
            addrSpace.write(statPtr, encodeDarwinStat64(devStat));
            return { value: 0n };
          }
          const handle = this._getHandle(fd);
          if (!handle) return { error: DARWIN_ERRNO.EBADF };
          const st = handle.stat();
          addrSpace.write(statPtr, encodeDarwinStat64(st));
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_lseek: {
          if (!this.vfs) return { error: DARWIN_ERRNO.ENOSYS };
          const fd = Number(BigInt.asIntN(32, args[0]));
          const offset = Number(BigInt.asIntN(64, args[1]));
          const whence = Number(BigInt.asIntN(32, args[2]));
          if (fd < 3) return { error: DARWIN_ERRNO.ESPIPE };
          const handle = this._getHandle(fd);
          const nextPos = handle
            ? handle.seek(offset, whence)
            : this.vfs.seek(fd, offset, whence, { pid: this.pcb ? this.pcb.pid : null });
          return { value: BigInt(nextPos) };
        }

        case DARWIN_SYSCALLS.SYS_getdirentries64: {
          if (!this.vfs || !addrSpace) return { error: DARWIN_ERRNO.ENOSYS };
          const fd = Number(BigInt.asIntN(32, args[0]));
          const bufPtr = args[1];
          const bufSize = Number(args[2]);
          const basepPtr = args[3];
          const handle = this._getHandle(fd);
          if (!handle) return { error: DARWIN_ERRNO.EBADF };

          const ctx = this._resolveEffectiveCtx(handle.path, false);
          const entries = this.vfs.readdir(handle.path, ctx);
          let cursor = this._dirCursors.get(fd) ?? 0;
          if (cursor >= entries.length) {
            return { value: 0n };
          }

          const outChunks = [];
          let totalBytes = 0;
          while (cursor < entries.length) {
            const ent = entries[cursor];
            const nameBytes = TEXT_ENCODER.encode(ent.name);
            const rawLen = 21 + nameBytes.byteLength + 1;
            const recLen = (rawLen + 7) & ~7;
            if (totalBytes + recLen > bufSize) {
              if (totalBytes === 0) return { error: DARWIN_ERRNO.EINVAL };
              break;
            }
            const rec = new Uint8Array(recLen);
            const dv = new DataView(rec.buffer);
            dv.setBigUint64(0x00, BigInt(ent.ino ?? cursor + 1), true); // d_ino
            dv.setBigUint64(0x08, BigInt(cursor + 1), true); // d_seekoff
            dv.setUint16(0x10, recLen, true); // d_reclen
            dv.setUint16(0x12, nameBytes.byteLength, true); // d_namlen
            rec[0x14] = DT_BY_TYPE[ent.type] ?? 8; // d_type
            rec.set(nameBytes, 0x15);
            rec[0x15 + nameBytes.byteLength] = 0;
            outChunks.push(rec);
            totalBytes += recLen;
            cursor += 1;
          }

          this._dirCursors.set(fd, cursor);
          if (totalBytes > 0) {
            const combined = new Uint8Array(totalBytes);
            let off = 0;
            for (const c of outChunks) {
              combined.set(c, off);
              off += c.byteLength;
            }
            addrSpace.write(bufPtr, combined);
          }
          if (basepPtr !== 0n) {
            addrSpace.writeU64(basepPtr, BigInt(cursor), true);
          }
          return { value: BigInt(totalBytes) };
        }

        case DARWIN_SYSCALLS.SYS_fcntl:
        case DARWIN_SYSCALLS.SYS_fcntl_nocancel: {
          const fd = Number(BigInt.asIntN(32, args[0]));
          const cmd = Number(BigInt.asIntN(32, args[1]));
          const arg = args[2];
          if (fd < 0) return { error: DARWIN_ERRNO.EBADF };
          if (cmd === 1) {
            // F_GETFD
            return { value: BigInt(this._fdFlags.get(fd) ?? 0) };
          }
          if (cmd === 2) {
            // F_SETFD
            this._fdFlags.set(fd, Number(arg & 1n));
            return { value: 0n };
          }
          if (cmd === 3) {
            // F_GETFL
            const handle = this._getHandle(fd);
            return { value: BigInt(handle ? handle.flags & 3 : 2) };
          }
          if (cmd === 4) {
            // F_SETFL
            return { value: 0n };
          }
          if (cmd === 50 && addrSpace) {
            // F_GETPATH (Darwin specific!)
            const handle = this._getHandle(fd);
            if (!handle) return { error: DARWIN_ERRNO.EBADF };
            addrSpace.writeCString(arg, handle.path);
            return { value: 0n };
          }
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_mmap: {
          if (!addrSpace) return { error: DARWIN_ERRNO.ENOMEM };
          const addrHint = args[0];
          const len = Number(args[1]);
          const prot = Number(args[2] & 7n);
          const flags = Number(args[3] & 0xffffffffn) >>> 0;
          const fd = Number(BigInt.asIntN(32, args[4]));
          const offset = Number(BigInt.asIntN(64, args[5]));

          if (!Number.isSafeInteger(len) || len <= 0) {
            return { error: DARWIN_ERRNO.EINVAL };
          }

          const hint = (flags & DARWIN_MAP_FIXED) !== 0 ? addrHint : (addrHint === 0n ? 0 : addrHint);
          const isAnon = (flags & DARWIN_MAP_ANON) !== 0 || fd < 0;

          let mappedBase;
          if (!isAnon && fd >= 3) {
            const handle = this._getHandle(fd);
            if (!handle) return { error: DARWIN_ERRNO.EBADF };
            mappedBase = addrSpace.mmap(hint, len, PROT_READ | PROT_WRITE, 'darwin-mmap-file');
            const fileBytes = handle.read(len, Math.max(0, offset));
            if (fileBytes.byteLength > 0) {
              addrSpace.write(mappedBase, fileBytes);
            }
            if (prot !== (PROT_READ | PROT_WRITE)) {
              addrSpace.mprotect(mappedBase, len, prot);
            }
          } else {
            mappedBase = addrSpace.mmap(hint, len, prot, 'darwin-mmap');
          }
          return { value: BigInt(mappedBase) };
        }

        case DARWIN_SYSCALLS.SYS_munmap: {
          if (!addrSpace) return { error: DARWIN_ERRNO.EINVAL };
          const addr = args[0];
          const len = Number(args[1]);
          if (!Number.isSafeInteger(len) || len <= 0) {
            return { error: DARWIN_ERRNO.EINVAL };
          }
          addrSpace.munmap(addr, len);
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_mprotect: {
          if (!addrSpace) return { error: DARWIN_ERRNO.EINVAL };
          const addr = args[0];
          const len = Number(args[1]);
          const prot = Number(args[2] & 7n);
          addrSpace.mprotect(addr, len, prot);
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_gettimeofday: {
          if (!addrSpace) return { error: DARWIN_ERRNO.EFAULT };
          const tvPtr = args[0];
          const tzPtr = args[1];
          const nowMs = Date.now();
          const sec = BigInt(Math.floor(nowMs / 1000));
          const usec = Math.floor((nowMs % 1000) * 1000);
          if (tvPtr !== 0n) {
            const buf = new Uint8Array(16);
            const dv = new DataView(buf.buffer);
            dv.setBigInt64(0, sec, true);
            dv.setInt32(8, usec, true);
            dv.setInt32(12, 0, true);
            addrSpace.write(tvPtr, buf);
          }
          if (tzPtr !== 0n) {
            const buf = new Uint8Array(8);
            addrSpace.write(tzPtr, buf);
          }
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_sysctl: {
          if (!addrSpace) return { error: DARWIN_ERRNO.EFAULT };
          const namePtr = args[0];
          const nameLen = Number(args[1] & 0xffffffffn);
          const oldp = args[2];
          const oldlenp = args[3];
          if (nameLen < 2 || nameLen > 16) return { error: DARWIN_ERRNO.EINVAL };
          const mib = [];
          for (let i = 0; i < nameLen; i++) {
            mib.push(addrSpace.readU32(namePtr + BigInt(i * 4), true));
          }
          const key = this._mibToSysctlName(mib);
          if (!key) return { error: DARWIN_ERRNO.ENOENT };
          return this._writeSysctlValue(key, oldp, oldlenp, addrSpace);
        }

        case DARWIN_SYSCALLS.SYS_sysctlbyname: {
          if (!addrSpace) return { error: DARWIN_ERRNO.EFAULT };
          const namePtr = args[0];
          const nameLen = Number(args[1]);
          const oldp = args[2];
          const oldlenp = args[3];
          let key;
          if (nameLen > 0 && nameLen < 256) {
            const raw = addrSpace.read(namePtr, nameLen);
            key = TEXT_DECODER.decode(raw).replace(/\0+$/, '');
          } else {
            key = addrSpace.readCString(namePtr, 256);
          }
          return this._writeSysctlValue(key, oldp, oldlenp, addrSpace);
        }

        case DARWIN_SYSCALLS.SYS_getentropy: {
          if (!addrSpace) return { error: DARWIN_ERRNO.EFAULT };
          const bufPtr = args[0];
          const bufLen = Number(args[1]);
          if (bufLen < 0 || bufLen > 256) {
            return { error: DARWIN_ERRNO.EIO };
          }
          const rnd = randomBytes(bufLen);
          if (bufLen > 0) {
            addrSpace.write(bufPtr, new Uint8Array(rnd.buffer, rnd.byteOffset, rnd.byteLength));
          }
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_csops: {
          if (!addrSpace) return { error: DARWIN_ERRNO.EFAULT };
          const ops = Number(args[1] & 0xffffffffn) >>> 0;
          const useraddr = args[2];
          const usersize = Number(args[3]);
          if (ops === 0 && useraddr !== 0n && usersize >= 4) {
            // CS_OPS_STATUS -> CS_VALID (0x1) | CS_ADHOC (0x2)
            addrSpace.writeU32(useraddr, 0x00000001, true);
            return { value: 0n };
          }
          if (ops === 7 && this.entitlementsXml && useraddr !== 0n) {
            const xmlBytes = TEXT_ENCODER.encode(this.entitlementsXml);
            const total = 8 + xmlBytes.byteLength;
            if (usersize < total) return { error: DARWIN_ERRNO.ERANGE };
            const blob = new Uint8Array(total);
            const dv = new DataView(blob.buffer);
            dv.setUint32(0, 0xfade7171, false);
            dv.setUint32(4, total, false);
            blob.set(xmlBytes, 8);
            addrSpace.write(useraddr, blob);
            return { value: 0n };
          }
          return { value: 0n };
        }

        case DARWIN_SYSCALLS.SYS_bsdthread_register:
          return { value: 0x1000n };

        case DARWIN_SYSCALLS.SYS_sigaction:
        case DARWIN_SYSCALLS.SYS_sigprocmask:
        case DARWIN_SYSCALLS.SYS_fstatfs64:
          return { value: 0n };

        default:
          return { error: DARWIN_ERRNO.ENOSYS };
      }
    } catch (err) {
      return { error: mapErrorToDarwinErrno(err) };
    }
  }

  _mibToSysctlName(mib) {
    const [ctl, sub] = mib;
    if (ctl === 1) {
      // CTL_KERN
      if (sub === 1) return 'kern.ostype';
      if (sub === 2) return 'kern.osrelease';
      if (sub === 4) return 'kern.version';
      if (sub === 10) return 'kern.hostname';
      if (sub === 65) return 'kern.osversion';
    }
    if (ctl === 6) {
      // CTL_HW
      if (sub === 1) return 'hw.machine';
      if (sub === 2) return 'hw.model';
      if (sub === 3) return 'hw.ncpu';
      if (sub === 4) return 'hw.byteorder';
      if (sub === 7) return 'hw.pagesize';
      if (sub === 24) return 'hw.memsize';
      if (sub === 25) return 'hw.activecpu';
    }
    return null;
  }

  _getSysctlPayload(key) {
    const isIos = this.platform === 'ios';
    const u32 = (n) => {
      const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, n >>> 0, true);
      return b;
    };
    const u64 = (n) => {
      const b = new Uint8Array(8);
      new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
      return b;
    };
    const cstr = (s) => {
      const enc = TEXT_ENCODER.encode(s);
      const b = new Uint8Array(enc.byteLength + 1);
      b.set(enc, 0);
      b[enc.byteLength] = 0;
      return b;
    };

    switch (key) {
      case 'kern.ostype': return cstr('Darwin');
      case 'kern.osrelease': return cstr('23.0.0');
      case 'kern.osversion': return cstr('23A344');
      case 'kern.hostname': return cstr('omnios.local');
      case 'kern.version': return cstr('Darwin Kernel Version 23.0.0: OmniOS XNU Compat');
      case 'hw.machine': return cstr(this.arch === 'x86_64' ? 'x86_64' : 'arm64');
      case 'hw.model': return cstr(isIos ? 'iPhone16,1' : 'Mac15,3');
      case 'hw.ncpu':
      case 'hw.activecpu':
      case 'hw.physicalcpu':
      case 'hw.logicalcpu':
        return u32(4);
      case 'hw.byteorder': return u32(1234);
      case 'hw.pagesize': return u32(4096);
      case 'hw.memsize': return u64(8_589_934_592n);
      case 'hw.optional.arm64': return u32(this.arch === 'arm64' ? 1 : 0);
      default:
        return null;
    }
  }

  _writeSysctlValue(key, oldp, oldlenp, addrSpace) {
    const payload = this._getSysctlPayload(key);
    if (!payload) return { error: DARWIN_ERRNO.ENOENT };

    if (oldp === 0n) {
      if (oldlenp !== 0n) {
        addrSpace.writeU64(oldlenp, BigInt(payload.byteLength), true);
      }
      return { value: 0n };
    }

    const avail = oldlenp !== 0n ? Number(addrSpace.readU64(oldlenp, true)) : payload.byteLength;
    if (oldlenp !== 0n) {
      addrSpace.writeU64(oldlenp, BigInt(payload.byteLength), true);
    }
    if (avail < payload.byteLength) {
      if (avail > 0) {
        addrSpace.write(oldp, payload.subarray(0, avail));
      }
      return { error: DARWIN_ERRNO.ENOMEM };
    }
    addrSpace.write(oldp, payload);
    return { value: 0n };
  }

  dispose() {
    for (const handle of this._fdHandles.values()) {
      try {
        if (!handle.closed) handle.close();
      } catch {
        // Ignore teardown errors
      }
    }
    this._fdHandles.clear();
    this._fdFlags.clear();
    this._dirCursors.clear();
  }
}

export function createDarwinSyscalls(opts = {}) {
  return new DarwinSyscallLayer(opts);
}
