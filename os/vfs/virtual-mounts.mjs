/**
 * OmniOS Dynamic Virtual Mounts — /proc, /dev, and In-Memory /tmp (F-020)
 * STRICT ISOLATION: Zero `node:fs` imports! VFS `/tmp` is 100% in-memory and never touches host `/tmp`.
 */

import { randomBytes } from 'node:crypto';
import { types } from 'node:util';
import { VfsError, ERROR_CODES } from '../common/errors.mjs';

const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_CTOR = TYPED_ARRAY_PROTO.constructor;
const TYPED_ARRAY_BUFFER_GET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'buffer').get;
const TYPED_ARRAY_OFFSET_GET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteOffset').get;
const TYPED_ARRAY_LENGTH_GET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteLength').get;
const DATA_VIEW_BUFFER_GET = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
const DATA_VIEW_LENGTH_GET = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;
const AB_LENGTH_GET = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const AB_DETACHED_GET = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'detached')?.get ?? null;

function isGenuineUint8Array(value) {
  return types.isUint8Array(value) && !types.isProxy(value);
}

function isGenuineBinaryView(value) {
  return (types.isTypedArray(value) || types.isDataView(value)) && !types.isProxy(value);
}

function isGenuineArrayBuffer(value) {
  return types.isArrayBuffer(value) && !types.isProxy(value);
}

function isBufferDetached(buf) {
  if (AB_DETACHED_GET && types.isArrayBuffer(buf)) {
    return Boolean(AB_DETACHED_GET.call(buf));
  }
  return false;
}

function inspectGenuineUint8Array(bytes, path = '/tmp', label = 'TmpFsMount') {
  if (!isGenuineUint8Array(bytes)) {
    throw new VfsError(`${label} requires a genuine Uint8Array`, {
      code: ERROR_CODES.EINVAL,
      path,
    });
  }
  let buf;
  let offset;
  let byteLength;
  try {
    buf = TYPED_ARRAY_BUFFER_GET.call(bytes);
    if (isBufferDetached(buf)) {
      throw new TypeError('Underlying ArrayBuffer is detached');
    }
    offset = TYPED_ARRAY_OFFSET_GET.call(bytes);
    byteLength = TYPED_ARRAY_LENGTH_GET.call(bytes);
  } catch {
    throw new VfsError(`Unreadable or detached Uint8Array in ${label}`, {
      code: ERROR_CODES.EINVAL,
      path,
    });
  }
  return { buf, offset, byteLength };
}

function copyGenuineUint8Array(bytes, path = '/tmp', label = 'TmpFsMount', preInspected = null) {
  const { buf, offset, byteLength } = preInspected ?? inspectGenuineUint8Array(bytes, path, label);
  try {
    if (isBufferDetached(buf)) {
      throw new TypeError('Underlying ArrayBuffer is detached');
    }
    const out = new Uint8Array(byteLength);
    if (byteLength > 0) {
      out.set(new Uint8Array(buf, offset, byteLength));
    }
    return out;
  } catch {
    throw new VfsError(`Unreadable or detached Uint8Array in ${label}`, {
      code: ERROR_CODES.EINVAL,
      path,
    });
  }
}

function readSafeOpt(opts, key, fallback = undefined, label = 'virtual-mount') {
  if (opts === null || opts === undefined) return fallback;
  if (typeof opts !== 'object') {
    throw new VfsError(`Invalid ${label} options: expected object`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  try {
    const v = opts[key];
    return v === undefined ? fallback : v;
  } catch {
    throw new VfsError(`Unreadable ${label} option: ${key}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
}

function validateProcessManagerDep(pm, label) {
  if (pm === null || pm === undefined) return null;
  if (typeof pm !== 'object') {
    throw new VfsError(`Invalid ${label} processManager dependency`, { code: ERROR_CODES.EINVAL });
  }
  try {
    void pm.get;
  } catch {
    throw new VfsError(`Unreadable ${label} processManager dependency`, { code: ERROR_CODES.EINVAL });
  }
  return pm;
}

function validateKernelDep(kernel, label) {
  if (kernel === null || kernel === undefined) return null;
  if (typeof kernel !== 'object') {
    throw new VfsError(`Invalid ${label} kernel dependency`, { code: ERROR_CODES.EINVAL });
  }
  let kernelPm = null;
  try {
    kernelPm = kernel.processManager ?? null;
  } catch {
    throw new VfsError(`Unreadable ${label} kernel dependency`, { code: ERROR_CODES.EINVAL });
  }
  if (kernelPm !== null && kernelPm !== undefined) {
    validateProcessManagerDep(kernelPm, label);
  }
  return kernel;
}

export const DEFAULT_MAX_TMP_BYTES = 32 * 1024 * 1024; // 32 MiB
export const DEFAULT_ZERO_READ_BYTES = 4096;
export const DEFAULT_URANDOM_READ_BYTES = 32;
export const MAX_DEVICE_READ_BYTES = 16 * 1024 * 1024; // 16 MiB

const TEXT_ENCODER = new TextEncoder();

const PROC_ROOT_INO = 0x10000001;
const PROC_UPTIME_INO = 0x10000002;
const PROC_VERSION_INO = 0x10000003;
const PROC_MEMINFO_INO = 0x10000004;
const PROC_PID_BASE_INO = 0x10100000;

const DEV_ROOT_INO = 0x18000001;
const DEV_NULL_INO = 0x18000002;
const DEV_ZERO_INO = 0x18000003;
const DEV_URANDOM_INO = 0x18000004;

const TMP_ROOT_INO = 0x20000001;

const SYMBOL_DESCRIPTION_GET =
  Object.getOwnPropertyDescriptor(Symbol.prototype, 'description')?.get ?? null;
const MAX_DISPLAY_BIGINT_ABS = 1n << 4096n;
const MIN_DISPLAY_BIGINT_NEG = -MAX_DISPLAY_BIGINT_ABS;
const MAX_DATE_MS = 8.64e15;

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

function toSafeFiniteNumber(value, fallback = 0) {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : fallback;
  }
  if (typeof value === 'string') {
    if (value.length === 0 || value.length > 64) return fallback;
    const trimmed = value.trim();
    if (trimmed.length === 0) return fallback;
    const n = Number(trimmed);
    return Number.isFinite(n) ? n : fallback;
  }
  return fallback;
}

function toSafeTimestampMs(value, fallbackMs = 0) {
  if (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= -MAX_DATE_MS &&
    value <= MAX_DATE_MS
  ) {
    return value;
  }
  if (typeof value === 'string' && value.length > 0 && value.length <= 64) {
    const trimmed = value.trim();
    if (trimmed.length > 0) {
      const n = Number(trimmed);
      if (Number.isFinite(n) && n >= -MAX_DATE_MS && n <= MAX_DATE_MS) {
        return n;
      }
    }
  }
  if (
    typeof fallbackMs === 'number' &&
    Number.isFinite(fallbackMs) &&
    fallbackMs >= -MAX_DATE_MS &&
    fallbackMs <= MAX_DATE_MS
  ) {
    return fallbackMs;
  }
  return 0;
}

export function makeStatObject(node) {
  const mtimeMs = toSafeTimestampMs(node.mtimeMs, 0);
  const ctimeMs = toSafeTimestampMs(node.ctimeMs, mtimeMs);
  const atimeMs = toSafeTimestampMs(node.atimeMs ?? mtimeMs, mtimeMs);
  const birthtimeMs = toSafeTimestampMs(node.birthtimeMs ?? ctimeMs, ctimeMs);
  const out = {
    ino: toSafeFiniteNumber(node.ino, 0),
    type: node.type,
    size: toSafeFiniteNumber(node.size, 0),
    mode: toSafeFiniteNumber(node.mode, 0),
    uid: toSafeFiniteNumber(node.uid, 0),
    gid: toSafeFiniteNumber(node.gid, 0),
    nlink: toSafeFiniteNumber(node.nlink, 1),
    mtime: new Date(mtimeMs).toISOString(),
    ctime: new Date(ctimeMs).toISOString(),
    atime: new Date(atimeMs).toISOString(),
    birthtime: new Date(birthtimeMs).toISOString(),
    mtimeMs,
    ctimeMs,
  };
  if (node.type === 'symlink') {
    out.target = node.target ?? '';
  }
  return out;
}

export function makeDirentObject(name, node) {
  const mtimeMs = toSafeTimestampMs(node.mtimeMs, 0);
  const ctimeMs = toSafeTimestampMs(node.ctimeMs, mtimeMs);
  const out = {
    name,
    type: node.type,
    ino: toSafeFiniteNumber(node.ino, 0),
    size: toSafeFiniteNumber(node.size, 0),
    mode: toSafeFiniteNumber(node.mode, 0),
    uid: toSafeFiniteNumber(node.uid, 0),
    gid: toSafeFiniteNumber(node.gid, 0),
    mtime: new Date(mtimeMs).toISOString(),
    ctime: new Date(ctimeMs).toISOString(),
  };
  if (node.type === 'symlink') {
    out.target = node.target ?? '';
  }
  return out;
}

function lexSortDirents(list) {
  list.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return list;
}

// ============================================================================
// 1. ProcFsMount (/proc)
// ============================================================================

export class ProcFsMount {
  constructor(opts = {}) {
    const kernel = validateKernelDep(readSafeOpt(opts, 'kernel', null, 'ProcFsMount'), 'ProcFsMount');
    const processManager = validateProcessManagerDep(
      readSafeOpt(opts, 'processManager', null, 'ProcFsMount'),
      'ProcFsMount'
    );
    this._kernel = kernel;
    this._processManager = processManager;
    this._createdPerf = performance.now();
    this._createdMs = Date.now();
  }

  get processManager() {
    if (this._processManager) return this._processManager;
    try {
      return this._kernel?.processManager ?? null;
    } catch {
      return null;
    }
  }

  getRootNode() {
    const now = Date.now();
    return {
      mount: 'proc',
      kind: 'root',
      ino: PROC_ROOT_INO,
      type: 'dir',
      mode: 0o555,
      uid: 0,
      gid: 0,
      size: 0,
      nlink: 2,
      atimeMs: now,
      mtimeMs: now,
      ctimeMs: now,
      birthtimeMs: this._createdMs,
    };
  }

  _getUptimeBytes() {
    const fallbackMs = Number((performance.now() - this._createdPerf).toFixed(3));
    let uptimeMs = fallbackMs;
    try {
      if (this._kernel && typeof this._kernel.getUptimeMs === 'function') {
        const raw = this._kernel.getUptimeMs();
        uptimeMs = toSafeFiniteNumber(raw, fallbackMs);
      }
    } catch {
      // Fallback to local monotonic clock if kernel reference is unreadable or revoked
      uptimeMs = fallbackMs;
    }
    const secs = Math.max(0, uptimeMs / 1000);
    const idleSecs = secs / 2;
    return TEXT_ENCODER.encode(`${secs.toFixed(3)} ${idleSecs.toFixed(3)}\n`);
  }

  _getVersionBytes() {
    return TEXT_ENCODER.encode(`OmniOS 1.0.0 (Node.js ${process.version})\n`);
  }

  _getMeminfoBytes() {
    const pm = this.processManager;
    let mappedPages = 0;
    let usedBytes = 0;
    let peakBytes = 0;
    let activeProcesses = 0;
    let totalProcesses = 0;

    if (pm) {
      try {
        if (typeof pm.getAggregateMemoryStats === 'function') {
          const stats = pm.getAggregateMemoryStats();
          mappedPages = toSafeFiniteNumber(stats?.totalMappedPages ?? stats?.mappedPages, 0);
          usedBytes = toSafeFiniteNumber(stats?.totalUsedBytes ?? stats?.usedBytes, 0);
          peakBytes = toSafeFiniteNumber(stats?.totalPeakBytes ?? stats?.peakBytes, 0);
        }
        if (typeof pm.getAll === 'function') {
          const all = pm.getAll();
          if (Array.isArray(all)) {
            totalProcesses = all.length;
            activeProcesses = all.filter((p) => p && p.state !== 'TERMINATED').length;
          }
        }
      } catch {
        // Fallback to zeroed process telemetry if processManager is unreadable or revoked
        mappedPages = 0;
        usedBytes = 0;
        peakBytes = 0;
        activeProcesses = 0;
        totalProcesses = 0;
      }
    }

    const text = [
      `MappedPages:\t${mappedPages}`,
      `UsedBytes:\t${usedBytes}`,
      `PeakBytes:\t${peakBytes}`,
      `UsedKB:\t${Math.ceil(usedBytes / 1024)} kB`,
      `PeakKB:\t${Math.ceil(peakBytes / 1024)} kB`,
      `ActiveProcesses:\t${activeProcesses}`,
      `TotalProcesses:\t${totalProcesses}`,
      '',
    ].join('\n');
    return TEXT_ENCODER.encode(text);
  }

  _getPcb(pid) {
    const pm = this.processManager;
    if (!pm) return null;
    try {
      if (typeof pm.get !== 'function') return null;
      const pcb = pm.get(pid);
      if (!pcb || pcb.state === 'TERMINATED') return null;
      return pcb;
    } catch {
      // Fallback cleanly if processManager or PCB is unreadable or revoked
      return null;
    }
  }

  _getPidStatusBytes(pcb) {
    let mem = { usedBytes: 0, peakBytes: 0, mappedPages: 0 };
    try {
      if (pcb.addressSpace && typeof pcb.addressSpace.getStats === 'function') {
        mem = pcb.addressSpace.getStats() ?? mem;
      }
    } catch {
      mem = { usedBytes: 0, peakBytes: 0, mappedPages: 0 };
    }

    const readSafe = (fn, fallback) => {
      try {
        const val = fn();
        return val ?? fallback;
      } catch {
        return fallback;
      }
    };

    const lines = [
      `Name:\t${readSafe(() => safeDisplay(pcb.name ?? '', 4096), '')}`,
      `State:\t${readSafe(() => safeDisplay(pcb.state ?? 'UNKNOWN', 256), 'UNKNOWN')}`,
      `Pid:\t${readSafe(() => safeDisplay(pcb.pid ?? 0, 64), '0')}`,
      `PPid:\t${readSafe(() => safeDisplay(pcb.ppid ?? 0, 64), '0')}`,
      `Uid:\t${readSafe(() => safeDisplay(pcb.uid ?? 0, 64), '0')}`,
      `Gid:\t${readSafe(() => safeDisplay(pcb.gid ?? 0, 64), '0')}`,
      `Platform:\t${readSafe(() => safeDisplay(pcb.platform ?? 'posix', 256), 'posix')}`,
      `Arch:\t${readSafe(() => safeDisplay(pcb.arch ?? 'none', 256), 'none')}`,
      `AppId:\t${readSafe(() => safeDisplay(pcb.appId ?? '', 512), '')}`,
      `Priority:\t${readSafe(() => safeDisplay(pcb.priority ?? 0, 64), '0')}`,
      `Threads:\t${readSafe(() => safeDisplay(pcb.threads?.size ?? 0, 64), '0')}`,
      `VmSize:\t${readSafe(() => Math.ceil(toSafeFiniteNumber(mem.usedBytes, 0) / 1024), 0)} kB`,
      `VmPeak:\t${readSafe(() => Math.ceil(toSafeFiniteNumber(mem.peakBytes, 0) / 1024), 0)} kB`,
      `MappedPages:\t${readSafe(() => toSafeFiniteNumber(mem.mappedPages, 0), 0)}`,
      `OpenFds:\t${readSafe(() => safeDisplay(pcb.fdTable?.size ?? 0, 64), '0')}`,
      `Windows:\t${readSafe(() => safeDisplay(pcb.windowIds?.size ?? 0, 64), '0')}`,
      `Instructions:\t${readSafe(() => safeDisplay(pcb.stats?.instructionsExecuted ?? 0, 64), '0')}`,
      `Syscalls:\t${readSafe(() => safeDisplay(pcb.stats?.syscallsCount ?? 0, 64), '0')}`,
      '',
    ];
    return TEXT_ENCODER.encode(lines.join('\n'));
  }

  _getPidCmdlineBytes(pcb) {
    let cmd = '';
    try {
      const rawArgs = pcb.args;
      const args = Array.isArray(rawArgs) ? rawArgs : [];
      if (args.length > 0) {
        const parts = [];
        const maxArgs = Math.min(args.length, 4096);
        for (let i = 0; i < maxArgs; i += 1) {
          try {
            parts.push(safeDisplay(args[i] ?? '', 4096));
          } catch (_err) {
            parts.push('');
          }
        }
        cmd = parts.join('\0');
      } else {
        cmd = safeDisplay(pcb.name ?? '', 4096);
      }
    } catch (_err) {
      try {
        cmd = safeDisplay(pcb.name ?? '', 4096);
      } catch (_innerErr) {
        cmd = '';
      }
    }
    return TEXT_ENCODER.encode(`${cmd}\n`);
  }

  _getPidCwdBytes(pcb) {
    let cwd = '/';
    try {
      cwd = safeDisplay(pcb.cwd ?? '/', 4096);
    } catch (_err) {
      cwd = '/';
    }
    return TEXT_ENCODER.encode(`${cwd}\n`);
  }

  _getPidMapsBytes(pcb) {
    let regions = [];
    try {
      if (pcb.addressSpace && typeof pcb.addressSpace.getStats === 'function') {
        const stats = pcb.addressSpace.getStats();
        if (Array.isArray(stats?.guardRegions)) {
          const maxGuard = Math.min(stats.guardRegions.length, 65536);
          for (let i = 0; i < maxGuard; i += 1) {
            const g = stats.guardRegions[i];
            if (g && typeof g === 'object') {
              regions.push({ ...g, perms: 0, guard: true });
            }
          }
        }
        if (Array.isArray(stats?.regions)) {
          const maxRegions = Math.min(stats.regions.length, 65536);
          for (let i = 0; i < maxRegions; i += 1) {
            const r = stats.regions[i];
            if (r && typeof r === 'object') {
              regions.push(r);
            }
          }
        }
        regions.sort(
          (a, b) =>
            toSafeFiniteNumber(a?.base ?? a?.start, 0) - toSafeFiniteNumber(b?.base ?? b?.start, 0)
        );
      }
      if (regions.length === 0) {
        return TEXT_ENCODER.encode('');
      }
      const lines = regions.map((r) => {
        const start = Math.max(0, Math.trunc(toSafeFiniteNumber(r?.base ?? r?.start, 0)));
        const size = Math.max(0, Math.trunc(toSafeFiniteNumber(r?.size, 0)));
        const end = Math.max(0, Math.trunc(toSafeFiniteNumber(r?.end, start + size)));
        const perms = Math.trunc(toSafeFiniteNumber(r?.perms, 0));
        const pStr =
          `${(perms & 1) ? 'r' : '-'}${(perms & 2) ? 'w' : '-'}${(perms & 4) ? 'x' : '-'}${r?.guard ? 'g' : 'p'}`;
        const label = r?.label ? ` ${safeDisplay(r.label, 256)}` : '';
        return `0x${start.toString(16).padStart(8, '0')}-0x${end.toString(16).padStart(8, '0')} ${pStr}${label}`;
      });
      return TEXT_ENCODER.encode(`${lines.join('\n')}\n`);
    } catch {
      return TEXT_ENCODER.encode('');
    }
  }

  _makeFileNode({ kind, ino, uid = 0, gid = 0, pid = null, bytes }) {
    const now = Date.now();
    return {
      mount: 'proc',
      kind,
      pid,
      ino,
      type: 'file',
      mode: 0o444,
      uid,
      gid,
      size: bytes.byteLength,
      nlink: 1,
      atimeMs: now,
      mtimeMs: now,
      ctimeMs: now,
      birthtimeMs: this._createdMs,
      _cachedBytes: bytes,
    };
  }

  lookupChild(parentNode, seg, opts = {}) {
    const caseInsensitive = Boolean(readSafeOpt(opts, 'caseInsensitive', false, 'ProcFsMount.lookupChild'));
    if (typeof seg !== 'string') return null;
    const target = caseInsensitive ? seg.toLowerCase() : seg;

    if (parentNode.kind === 'root') {
      if (target === 'uptime') {
        return {
          name: 'uptime',
          node: this._makeFileNode({
            kind: 'uptime',
            ino: PROC_UPTIME_INO,
            bytes: this._getUptimeBytes(),
          }),
        };
      }
      if (target === 'version') {
        return {
          name: 'version',
          node: this._makeFileNode({
            kind: 'version',
            ino: PROC_VERSION_INO,
            bytes: this._getVersionBytes(),
          }),
        };
      }
      if (target === 'meminfo') {
        return {
          name: 'meminfo',
          node: this._makeFileNode({
            kind: 'meminfo',
            ino: PROC_MEMINFO_INO,
            bytes: this._getMeminfoBytes(),
          }),
        };
      }
      if (seg.length <= 16 && /^(0|[1-9]\d*)$/.test(seg)) {
        const pid = Number(seg);
        if (!Number.isSafeInteger(pid)) return null;
        const pcb = this._getPcb(pid);
        if (!pcb) return null;
        const now = Date.now();
        let pcbUid = 0;
        let pcbGid = 0;
        let pcbStartedAt = this._createdMs;
        try {
          const rawUid = pcb.uid ?? 0;
          const rawGid = pcb.gid ?? 0;
          const rawStartedAt = pcb.stats?.startedAt;
          pcbUid = typeof rawUid === 'number' && Number.isFinite(rawUid) ? rawUid : 0;
          pcbGid = typeof rawGid === 'number' && Number.isFinite(rawGid) ? rawGid : 0;
          pcbStartedAt = toSafeTimestampMs(rawStartedAt, this._createdMs);
        } catch (_err) {
          pcbUid = 0;
          pcbGid = 0;
          pcbStartedAt = this._createdMs;
        }
        return {
          name: String(pid),
          node: {
            mount: 'proc',
            kind: 'pid_dir',
            pid,
            ino: PROC_PID_BASE_INO + pid * 16,
            type: 'dir',
            mode: 0o555,
            uid: pcbUid,
            gid: pcbGid,
            size: 0,
            nlink: 2,
            atimeMs: now,
            mtimeMs: now,
            ctimeMs: now,
            birthtimeMs: pcbStartedAt,
          },
        };
      }
      return null;
    }

    if (parentNode.kind === 'pid_dir') {
      const pcb = this._getPcb(parentNode.pid);
      if (!pcb) return null;
      const pid = parentNode.pid;
      const baseIno = PROC_PID_BASE_INO + pid * 16;
      let pcbUid = 0;
      let pcbGid = 0;
      try {
        const rawUid = pcb.uid ?? 0;
        const rawGid = pcb.gid ?? 0;
        pcbUid = typeof rawUid === 'number' && Number.isFinite(rawUid) ? rawUid : 0;
        pcbGid = typeof rawGid === 'number' && Number.isFinite(rawGid) ? rawGid : 0;
      } catch (_err) {
        pcbUid = 0;
        pcbGid = 0;
      }

      if (target === 'status') {
        return {
          name: 'status',
          node: this._makeFileNode({
            kind: 'pid_status',
            pid,
            ino: baseIno + 1,
            uid: pcbUid,
            gid: pcbGid,
            bytes: this._getPidStatusBytes(pcb),
          }),
        };
      }
      if (target === 'cmdline') {
        return {
          name: 'cmdline',
          node: this._makeFileNode({
            kind: 'pid_cmdline',
            pid,
            ino: baseIno + 2,
            uid: pcbUid,
            gid: pcbGid,
            bytes: this._getPidCmdlineBytes(pcb),
          }),
        };
      }
      if (target === 'cwd') {
        return {
          name: 'cwd',
          node: this._makeFileNode({
            kind: 'pid_cwd',
            pid,
            ino: baseIno + 3,
            uid: pcbUid,
            gid: pcbGid,
            bytes: this._getPidCwdBytes(pcb),
          }),
        };
      }
      if (target === 'maps') {
        return {
          name: 'maps',
          node: this._makeFileNode({
            kind: 'pid_maps',
            pid,
            ino: baseIno + 4,
            uid: pcbUid,
            gid: pcbGid,
            bytes: this._getPidMapsBytes(pcb),
          }),
        };
      }
    }

    return null;
  }

  readNode(node) {
    if (node.kind === 'uptime') return this._getUptimeBytes();
    if (node.kind === 'version') return this._getVersionBytes();
    if (node.kind === 'meminfo') return this._getMeminfoBytes();

    if (node.pid !== null && node.pid !== undefined) {
      const pcb = this._getPcb(node.pid);
      if (!pcb) {
        const displayPid = safeDisplay(node.pid, 64);
        throw new VfsError(`Process ${displayPid} no longer exists`, {
          code: ERROR_CODES.ENOENT,
          path: `/proc/${displayPid}`,
        });
      }
      if (node.kind === 'pid_status') return this._getPidStatusBytes(pcb);
      if (node.kind === 'pid_cmdline') return this._getPidCmdlineBytes(pcb);
      if (node.kind === 'pid_cwd') return this._getPidCwdBytes(pcb);
      if (node.kind === 'pid_maps') return this._getPidMapsBytes(pcb);
    }

    return node._cachedBytes
      ? copyGenuineUint8Array(node._cachedBytes, '/proc', 'ProcFsMount.readNode')
      : new Uint8Array(0);
  }

  listChildren(dirNode) {
    const entries = [];
    if (dirNode.kind === 'root') {
      for (const fixed of ['meminfo', 'uptime', 'version']) {
        const res = this.lookupChild(dirNode, fixed);
        if (res) entries.push(makeDirentObject(res.name, res.node));
      }
      const pm = this.processManager;
      if (pm) {
        try {
          if (typeof pm.getAll === 'function') {
            const all = pm.getAll();
            if (Array.isArray(all)) {
              for (const pcb of all) {
                try {
                  if (!pcb || typeof pcb !== 'object' || pcb.state === 'TERMINATED') continue;
                  const pid = pcb.pid;
                  if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 0) continue;
                  const res = this.lookupChild(dirNode, String(pid));
                  if (res) entries.push(makeDirentObject(res.name, res.node));
                } catch {
                  // Skip unreadable or revoked PCB entries safely
                }
              }
            }
          }
        } catch {
          // Fallback to static /proc entries if processManager is unreadable or revoked
        }
      }
      return lexSortDirents(entries);
    }

    if (dirNode.kind === 'pid_dir') {
      for (const name of ['cmdline', 'cwd', 'maps', 'status']) {
        const res = this.lookupChild(dirNode, name);
        if (res) entries.push(makeDirentObject(res.name, res.node));
      }
      return lexSortDirents(entries);
    }

    return entries;
  }
}

// ============================================================================
// 2. DevFsMount (/dev)
// ============================================================================

export class DevFsMount {
  constructor() {
    this._createdMs = Date.now();
    this._root = {
      mount: 'dev',
      name: 'dev',
      ino: DEV_ROOT_INO,
      type: 'dir',
      mode: 0o755,
      uid: 0,
      gid: 0,
      size: 0,
      nlink: 2,
      atimeMs: this._createdMs,
      mtimeMs: this._createdMs,
      ctimeMs: this._createdMs,
      birthtimeMs: this._createdMs,
    };

    this._devices = new Map([
      [
        'null',
        {
          mount: 'dev',
          name: 'null',
          ino: DEV_NULL_INO,
          type: 'device',
          mode: 0o666,
          uid: 0,
          gid: 0,
          size: 0,
          nlink: 1,
          atimeMs: this._createdMs,
          mtimeMs: this._createdMs,
          ctimeMs: this._createdMs,
          birthtimeMs: this._createdMs,
        },
      ],
      [
        'zero',
        {
          mount: 'dev',
          name: 'zero',
          ino: DEV_ZERO_INO,
          type: 'device',
          mode: 0o666,
          uid: 0,
          gid: 0,
          size: 0,
          nlink: 1,
          atimeMs: this._createdMs,
          mtimeMs: this._createdMs,
          ctimeMs: this._createdMs,
          birthtimeMs: this._createdMs,
        },
      ],
      [
        'urandom',
        {
          mount: 'dev',
          name: 'urandom',
          ino: DEV_URANDOM_INO,
          type: 'device',
          mode: 0o666,
          uid: 0,
          gid: 0,
          size: 0,
          nlink: 1,
          atimeMs: this._createdMs,
          mtimeMs: this._createdMs,
          ctimeMs: this._createdMs,
          birthtimeMs: this._createdMs,
        },
      ],
    ]);
  }

  getRootNode() {
    return this._root;
  }

  lookupChild(parentNode, seg, opts = {}) {
    const caseInsensitive = Boolean(readSafeOpt(opts, 'caseInsensitive', false, 'DevFsMount.lookupChild'));
    if (parentNode.ino !== DEV_ROOT_INO || typeof seg !== 'string') return null;
    const key = caseInsensitive ? seg.toLowerCase() : seg;
    const dev = this._devices.get(key);
    if (!dev) return null;
    return { name: dev.name, node: dev };
  }

  listChildren(dirNode) {
    if (dirNode.ino !== DEV_ROOT_INO) return [];
    const entries = [];
    for (const [name, dev] of this._devices.entries()) {
      entries.push(makeDirentObject(name, dev));
    }
    return lexSortDirents(entries);
  }

  readDevice(deviceName, length = undefined) {
    if (typeof deviceName !== 'string' || !this._devices.has(deviceName)) {
      const displayName = safeDisplay(deviceName);
      throw new VfsError(`No such device: /dev/${displayName}`, {
        code: ERROR_CODES.ENOENT,
        path: `/dev/${displayName}`,
      });
    }

    if (deviceName === 'null') {
      if (length !== undefined) {
        if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) {
          throw new VfsError('Invalid device read length', {
            code: ERROR_CODES.EINVAL,
            path: '/dev/null',
          });
        }
      }
      return new Uint8Array(0);
    }

    const defaultLen =
      deviceName === 'zero' ? DEFAULT_ZERO_READ_BYTES : DEFAULT_URANDOM_READ_BYTES;
    const reqLen = length === undefined ? defaultLen : length;
    if (
      typeof reqLen !== 'number' ||
      !Number.isSafeInteger(reqLen) ||
      reqLen < 0 ||
      reqLen > MAX_DEVICE_READ_BYTES
    ) {
      const displayLen = safeDisplay(reqLen);
      throw new VfsError(
        `Invalid read length ${displayLen} for /dev/${deviceName} (0..${MAX_DEVICE_READ_BYTES})`,
        {
          code: ERROR_CODES.EINVAL,
          path: `/dev/${deviceName}`,
        }
      );
    }

    if (reqLen === 0) return new Uint8Array(0);
    if (deviceName === 'zero') {
      return new Uint8Array(reqLen);
    }
    const rnd = randomBytes(reqLen);
    const out = new Uint8Array(rnd.byteLength);
    out.set(new Uint8Array(rnd.buffer, rnd.byteOffset, rnd.byteLength));
    return out;
  }

  writeDevice(deviceName, bytes) {
    if (typeof deviceName !== 'string' || !this._devices.has(deviceName)) {
      const displayName = safeDisplay(deviceName);
      throw new VfsError(`No such device: /dev/${displayName}`, {
        code: ERROR_CODES.ENOENT,
        path: `/dev/${displayName}`,
      });
    }
    let byteLength = 0;
    if (bytes !== null && bytes !== undefined) {
      if (isGenuineBinaryView(bytes)) {
        try {
          const isDv = types.isDataView(bytes);
          const buf = isDv ? DATA_VIEW_BUFFER_GET.call(bytes) : TYPED_ARRAY_BUFFER_GET.call(bytes);
          if (isBufferDetached(buf)) {
            throw new TypeError('detached');
          }
          byteLength = isDv ? DATA_VIEW_LENGTH_GET.call(bytes) : TYPED_ARRAY_LENGTH_GET.call(bytes);
        } catch {
          throw new VfsError('Unreadable device write buffer', {
            code: ERROR_CODES.EINVAL,
            path: `/dev/${deviceName}`,
          });
        }
      } else if (isGenuineArrayBuffer(bytes)) {
        try {
          if (isBufferDetached(bytes)) {
            throw new TypeError('detached');
          }
          byteLength = AB_LENGTH_GET.call(bytes);
        } catch {
          throw new VfsError('Unreadable device write buffer', {
            code: ERROR_CODES.EINVAL,
            path: `/dev/${deviceName}`,
          });
        }
      } else if (typeof bytes === 'object') {
        let spoofedOrUnreadable = types.isProxy(bytes);
        if (!spoofedOrUnreadable) {
          try {
            if (
              bytes instanceof ArrayBuffer ||
              bytes instanceof TYPED_ARRAY_CTOR ||
              bytes instanceof DataView ||
              ArrayBuffer.isView(bytes)
            ) {
              spoofedOrUnreadable = true;
            }
          } catch {
            spoofedOrUnreadable = true;
          }
        }
        if (spoofedOrUnreadable) {
          throw new VfsError('Unreadable device write buffer', {
            code: ERROR_CODES.EINVAL,
            path: `/dev/${deviceName}`,
          });
        }
      }
    }
    return { bytesWritten: byteLength };
  }
}

// ============================================================================
// 3. TmpFsMount (100% In-Memory POSIX /tmp with sticky bit 0o1777 & ENOSPC cap)
// ============================================================================

export class TmpFsMount {
  constructor(opts = {}) {
    const maxBytes = readSafeOpt(opts, 'maxBytes', DEFAULT_MAX_TMP_BYTES, 'TmpFsMount');
    if (typeof maxBytes !== 'number' || !Number.isFinite(maxBytes) || maxBytes < 0) {
      throw new VfsError('TmpFsMount maxBytes must be a non-negative finite number', {
        code: ERROR_CODES.EINVAL,
      });
    }
    this.maxBytes = Math.floor(maxBytes);
    this._nodesByIno = new Map();
    this._nextIno = TMP_ROOT_INO + 1;
    this.usedBytes = 0;
    this._root = null;
    this.clear();
  }

  clear() {
    const now = Date.now();
    this._nodesByIno.clear();
    this._nextIno = TMP_ROOT_INO + 1;
    this.usedBytes = 0;
    this._root = {
      mount: 'tmp',
      ino: TMP_ROOT_INO,
      parentIno: TMP_ROOT_INO,
      type: 'dir',
      mode: 0o1777,
      uid: 0,
      gid: 0,
      size: 0,
      nlink: 2,
      target: null,
      data: null,
      children: new Map(), // exactName -> { name, nameLower, node }
      xattrs: new Map(),
      atimeMs: now,
      mtimeMs: now,
      ctimeMs: now,
      birthtimeMs: now,
    };
    this._nodesByIno.set(this._root.ino, this._root);
  }

  getRootNode() {
    return this._root;
  }

  getNodeByIno(ino) {
    return this._nodesByIno.get(ino) ?? null;
  }

  lookupChild(dirNode, seg, opts = {}) {
    const caseInsensitive = Boolean(readSafeOpt(opts, 'caseInsensitive', false, 'TmpFsMount.lookupChild'));
    if (!dirNode || dirNode.type !== 'dir' || typeof seg !== 'string') return null;
    const exact = dirNode.children.get(seg);
    if (exact) {
      return { name: exact.name, node: exact.node };
    }
    if (caseInsensitive) {
      const targetLower = seg.toLowerCase();
      for (const entry of dirNode.children.values()) {
        if (entry.nameLower === targetLower) {
          return { name: entry.name, node: entry.node };
        }
      }
    }
    return null;
  }

  listChildren(dirNode) {
    if (!dirNode || dirNode.type !== 'dir') return [];
    const out = [];
    for (const entry of dirNode.children.values()) {
      out.push(makeDirentObject(entry.name, entry.node));
    }
    return lexSortDirents(out);
  }

  assertQuota(deltaBytes, path = '/tmp') {
    if (typeof deltaBytes !== 'number' || Number.isNaN(deltaBytes)) {
      throw new VfsError('Invalid quota delta on /tmp', {
        code: ERROR_CODES.EINVAL,
        path,
      });
    }
    if (deltaBytes > 0) {
      if (
        !Number.isSafeInteger(deltaBytes) ||
        !Number.isSafeInteger(this.usedBytes + deltaBytes) ||
        this.usedBytes + deltaBytes > this.maxBytes
      ) {
        throw new VfsError(
          `No space left on /tmp (${this.usedBytes + deltaBytes} > ${this.maxBytes})`,
          {
            code: ERROR_CODES.ENOSPC,
            path,
          }
        );
      }
    }
  }

  _assertQuota(deltaBytes, path) {
    this.assertQuota(deltaBytes, path);
  }

  _normalizeTmpPath(rawPath) {
    return typeof rawPath === 'string' && rawPath.length > 0 && rawPath.length <= 4096
      ? rawPath
      : '/tmp';
  }

  _assertTmpMode(mode, path, label) {
    if (typeof mode !== 'number' || !Number.isSafeInteger(mode) || mode < 0) {
      throw new VfsError(`Invalid mode in ${label}: ${safeDisplay(mode)}`, {
        code: ERROR_CODES.EINVAL,
        path,
      });
    }
    return mode & 0o7777;
  }

  _assertTmpId(val, field, path, label) {
    if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < 0) {
      throw new VfsError(`Invalid ${field} in ${label}: ${safeDisplay(val)}`, {
        code: ERROR_CODES.EINVAL,
        path,
      });
    }
    return val;
  }

  _assertTmpName(name, path, label) {
    if (typeof name !== 'string' || name.length === 0 || name.length > 255) {
      throw new VfsError(`Invalid entry name in ${label}: ${safeDisplay(name)}`, {
        code: ERROR_CODES.EINVAL,
        path,
      });
    }
    return name;
  }

  createFile(parentDir, name, bytes, opts = {}) {
    const rawPath = readSafeOpt(opts, 'path', '/tmp', 'TmpFsMount.createFile');
    const path = this._normalizeTmpPath(rawPath);
    const safeName = this._assertTmpName(name, path, 'TmpFsMount.createFile');
    const safeMode = this._assertTmpMode(
      readSafeOpt(opts, 'mode', 0o644, 'TmpFsMount.createFile'),
      path,
      'TmpFsMount.createFile'
    );
    const safeUid = this._assertTmpId(
      readSafeOpt(opts, 'uid', 1000, 'TmpFsMount.createFile'),
      'uid',
      path,
      'TmpFsMount.createFile'
    );
    const safeGid = this._assertTmpId(
      readSafeOpt(opts, 'gid', 1000, 'TmpFsMount.createFile'),
      'gid',
      path,
      'TmpFsMount.createFile'
    );
    const info = inspectGenuineUint8Array(bytes, path, 'TmpFsMount.createFile');
    this.assertQuota(info.byteLength, path);
    const owned = copyGenuineUint8Array(bytes, path, 'TmpFsMount.createFile', info);
    const now = Date.now();
    const node = {
      mount: 'tmp',
      ino: this._nextIno++,
      parentIno: parentDir.ino,
      type: 'file',
      mode: safeMode,
      uid: safeUid,
      gid: safeGid,
      size: owned.byteLength,
      nlink: 1,
      target: null,
      data: owned,
      children: null,
      xattrs: new Map(),
      atimeMs: now,
      mtimeMs: now,
      ctimeMs: now,
      birthtimeMs: now,
    };
    this._nodesByIno.set(node.ino, node);
    parentDir.children.set(safeName, { name: safeName, nameLower: safeName.toLowerCase(), node });
    parentDir.mtimeMs = now;
    parentDir.ctimeMs = now;
    this.usedBytes += owned.byteLength;
    return node;
  }

  updateFileData(fileNode, newBytes, opts = {}) {
    const path = this._normalizeTmpPath(readSafeOpt(opts, 'path', '/tmp', 'TmpFsMount.updateFileData'));
    const info = inspectGenuineUint8Array(newBytes, path, 'TmpFsMount.updateFileData');
    const oldSize = isGenuineUint8Array(fileNode.data) ? TYPED_ARRAY_LENGTH_GET.call(fileNode.data) : 0;
    const delta = info.byteLength - oldSize;
    this.assertQuota(delta, path);
    const owned = copyGenuineUint8Array(newBytes, path, 'TmpFsMount.updateFileData', info);
    const now = Date.now();
    fileNode.data = owned;
    fileNode.size = owned.byteLength;
    fileNode.mtimeMs = now;
    fileNode.ctimeMs = now;
    this.usedBytes = Math.max(0, this.usedBytes + delta);
    return fileNode;
  }

  readFileData(fileNode) {
    fileNode.atimeMs = Date.now();
    return fileNode.data
      ? copyGenuineUint8Array(fileNode.data, '/tmp', 'TmpFsMount.readFileData')
      : new Uint8Array(0);
  }

  createDir(parentDir, name, opts = {}) {
    const path = this._normalizeTmpPath(readSafeOpt(opts, 'path', '/tmp', 'TmpFsMount.createDir'));
    const safeName = this._assertTmpName(name, path, 'TmpFsMount.createDir');
    const safeMode = this._assertTmpMode(
      readSafeOpt(opts, 'mode', 0o755, 'TmpFsMount.createDir'),
      path,
      'TmpFsMount.createDir'
    );
    const safeUid = this._assertTmpId(
      readSafeOpt(opts, 'uid', 1000, 'TmpFsMount.createDir'),
      'uid',
      path,
      'TmpFsMount.createDir'
    );
    const safeGid = this._assertTmpId(
      readSafeOpt(opts, 'gid', 1000, 'TmpFsMount.createDir'),
      'gid',
      path,
      'TmpFsMount.createDir'
    );
    const now = Date.now();
    const node = {
      mount: 'tmp',
      ino: this._nextIno++,
      parentIno: parentDir.ino,
      type: 'dir',
      mode: safeMode,
      uid: safeUid,
      gid: safeGid,
      size: 0,
      nlink: 2,
      target: null,
      data: null,
      children: new Map(),
      xattrs: new Map(),
      atimeMs: now,
      mtimeMs: now,
      ctimeMs: now,
      birthtimeMs: now,
    };
    this._nodesByIno.set(node.ino, node);
    parentDir.children.set(safeName, { name: safeName, nameLower: safeName.toLowerCase(), node });
    parentDir.nlink += 1;
    parentDir.mtimeMs = now;
    parentDir.ctimeMs = now;
    return node;
  }

  createSymlink(parentDir, name, target, opts = {}) {
    const path = this._normalizeTmpPath(readSafeOpt(opts, 'path', '/tmp', 'TmpFsMount.createSymlink'));
    const safeName = this._assertTmpName(name, path, 'TmpFsMount.createSymlink');
    const safeUid = this._assertTmpId(
      readSafeOpt(opts, 'uid', 1000, 'TmpFsMount.createSymlink'),
      'uid',
      path,
      'TmpFsMount.createSymlink'
    );
    const safeGid = this._assertTmpId(
      readSafeOpt(opts, 'gid', 1000, 'TmpFsMount.createSymlink'),
      'gid',
      path,
      'TmpFsMount.createSymlink'
    );
    if (typeof target !== 'string' || target.length === 0 || target.length > 4096) {
      throw new VfsError('Invalid symlink target in TmpFsMount.createSymlink', {
        code: ERROR_CODES.EINVAL,
        path,
      });
    }
    const byteLen = TEXT_ENCODER.encode(target).byteLength;
    this.assertQuota(byteLen, path);
    const now = Date.now();
    const node = {
      mount: 'tmp',
      ino: this._nextIno++,
      parentIno: parentDir.ino,
      type: 'symlink',
      mode: 0o777,
      uid: safeUid,
      gid: safeGid,
      size: byteLen,
      nlink: 1,
      target,
      data: null,
      children: null,
      xattrs: new Map(),
      atimeMs: now,
      mtimeMs: now,
      ctimeMs: now,
      birthtimeMs: now,
    };
    this._nodesByIno.set(node.ino, node);
    parentDir.children.set(safeName, { name: safeName, nameLower: safeName.toLowerCase(), node });
    parentDir.mtimeMs = now;
    parentDir.ctimeMs = now;
    this.usedBytes += byteLen;
    return node;
  }

  getNodeXattrBytes(node) {
    if (!node || !node.xattrs || node.xattrs.size === 0) return 0;
    let total = 0;
    for (const [k, v] of node.xattrs.entries()) {
      total += TEXT_ENCODER.encode(k).byteLength + (isGenuineUint8Array(v) ? TYPED_ARRAY_LENGTH_GET.call(v) : 0);
    }
    return total;
  }

  setXattr(node, name, bytes, opts = {}) {
    const path = this._normalizeTmpPath(readSafeOpt(opts, 'path', '/tmp', 'TmpFsMount.setXattr'));
    const safeName = this._assertTmpName(name, path, 'TmpFsMount.setXattr');
    const info = inspectGenuineUint8Array(bytes, path, 'TmpFsMount.setXattr');
    const prev = node.xattrs.get(safeName);
    const nameBytes = TEXT_ENCODER.encode(safeName).byteLength;
    const delta = isGenuineUint8Array(prev)
      ? info.byteLength - TYPED_ARRAY_LENGTH_GET.call(prev)
      : nameBytes + info.byteLength;
    this.assertQuota(delta, path);
    const owned = copyGenuineUint8Array(bytes, path, 'TmpFsMount.setXattr', info);
    node.xattrs.set(safeName, owned);
    this.usedBytes = Math.max(0, this.usedBytes + delta);
    node.ctimeMs = Date.now();
    return copyGenuineUint8Array(owned, path, 'TmpFsMount.setXattr');
  }

  removeXattr(node, name) {
    const prev = node.xattrs.get(name);
    if (!prev) return false;
    const reclaimed =
      TEXT_ENCODER.encode(name).byteLength + (isGenuineUint8Array(prev) ? TYPED_ARRAY_LENGTH_GET.call(prev) : 0);
    node.xattrs.delete(name);
    this.usedBytes = Math.max(0, this.usedBytes - reclaimed);
    node.ctimeMs = Date.now();
    return true;
  }

  removeEntry(parentDir, actualName, opts = {}) {
    const deferReclaim = Boolean(readSafeOpt(opts, 'deferReclaim', false, 'TmpFsMount.removeEntry'));
    const shouldDefer = readSafeOpt(opts, 'shouldDefer', null, 'TmpFsMount.removeEntry');
    const entry = parentDir.children.get(actualName);
    if (!entry) return null;
    const node = entry.node;
    parentDir.children.delete(actualName);
    const now = Date.now();
    parentDir.mtimeMs = now;
    parentDir.ctimeMs = now;
    if (node.type === 'dir') {
      parentDir.nlink = Math.max(2, parentDir.nlink - 1);
      this._destroySubtree(node, shouldDefer);
      return node;
    }
    node.nlink = Math.max(0, node.nlink - 1);
    node.ctimeMs = now;
    const defer = Boolean(deferReclaim || (typeof shouldDefer === 'function' && shouldDefer(node)));
    if (node.nlink === 0) {
      node.parentIno = null;
      if (!defer) {
        this._destroySubtree(node);
      }
    }
    return node;
  }

  reclaimIfUnlinked(ino) {
    const node = this._nodesByIno.get(ino);
    if (!node || node.nlink > 0) return false;
    this._destroySubtree(node);
    return true;
  }

  _destroySubtree(rootNode, shouldDefer = null) {
    if (!rootNode) return;
    const deferFn = typeof shouldDefer === 'function' ? shouldDefer : null;
    const stack = [rootNode];
    while (stack.length > 0) {
      const node = stack.pop();
      if (!node) continue;
      if (node.type === 'dir' && node.children) {
        for (const child of node.children.values()) {
          stack.push(child.node);
        }
        node.children.clear();
      }
      node.nlink = 0;
      node.parentIno = null;
      if (deferFn && deferFn(node)) {
        continue;
      }
      if (node.type === 'file' && node.data) {
        const dataLen = isGenuineUint8Array(node.data) ? TYPED_ARRAY_LENGTH_GET.call(node.data) : 0;
        this.usedBytes = Math.max(0, this.usedBytes - dataLen);
        node.data = null;
      } else if (node.type === 'symlink' && node.target !== null) {
        const symBytes =
          typeof node.size === 'number' ? node.size : TEXT_ENCODER.encode(node.target).byteLength;
        this.usedBytes = Math.max(0, this.usedBytes - symBytes);
        node.target = null;
      }
      if (node.xattrs && node.xattrs.size > 0) {
        const xattrBytes = this.getNodeXattrBytes(node);
        this.usedBytes = Math.max(0, this.usedBytes - xattrBytes);
        node.xattrs.clear();
      }
      this._nodesByIno.delete(node.ino);
    }
  }

  isAncestor(ancestorIno, descendantNode) {
    let cur = descendantNode;
    const visited = new Set();
    while (cur) {
      if (cur.ino === ancestorIno) return true;
      if (cur.ino === TMP_ROOT_INO || visited.has(cur.ino)) break;
      visited.add(cur.ino);
      cur = this._nodesByIno.get(cur.parentIno) ?? null;
    }
    return false;
  }

  moveEntry(
    srcParent,
    srcActualName,
    dstParent,
    dstNewName,
    existingDstActualName = null,
    opts = {}
  ) {
    const shouldDefer = readSafeOpt(opts, 'shouldDefer', null, 'TmpFsMount.moveEntry');
    const srcEntry = srcParent.children.get(srcActualName);
    if (!srcEntry) return null;
    const srcNode = srcEntry.node;
    const now = Date.now();

    // Case-only rename in same directory
    if (
      srcParent.ino === dstParent.ino &&
      existingDstActualName !== null &&
      dstParent.children.get(existingDstActualName)?.node.ino === srcNode.ino
    ) {
      srcParent.children.delete(srcActualName);
      srcParent.children.set(dstNewName, {
        name: dstNewName,
        nameLower: dstNewName.toLowerCase(),
        node: srcNode,
      });
      srcNode.ctimeMs = now;
      srcParent.mtimeMs = now;
      srcParent.ctimeMs = now;
      return srcNode;
    }

    if (existingDstActualName !== null) {
      this.removeEntry(dstParent, existingDstActualName, { shouldDefer });
    }

    srcParent.children.delete(srcActualName);
    if (srcNode.type === 'dir' && srcParent.ino !== dstParent.ino) {
      srcParent.nlink = Math.max(2, srcParent.nlink - 1);
      dstParent.nlink += 1;
    }

    srcNode.parentIno = dstParent.ino;
    srcNode.ctimeMs = now;
    dstParent.children.set(dstNewName, {
      name: dstNewName,
      nameLower: dstNewName.toLowerCase(),
      node: srcNode,
    });
    srcParent.mtimeMs = now;
    srcParent.ctimeMs = now;
    dstParent.mtimeMs = now;
    dstParent.ctimeMs = now;
    return srcNode;
  }
}

// ============================================================================
// 4. VirtualMountManager
// ============================================================================

export class VirtualMountManager {
  constructor(opts = {}) {
    const kernel = validateKernelDep(
      readSafeOpt(opts, 'kernel', null, 'VirtualMountManager'),
      'VirtualMountManager'
    );
    const processManager = validateProcessManagerDep(
      readSafeOpt(opts, 'processManager', null, 'VirtualMountManager'),
      'VirtualMountManager'
    );
    const maxTmpBytes = readSafeOpt(opts, 'maxTmpBytes', DEFAULT_MAX_TMP_BYTES, 'VirtualMountManager');
    this.procFs = new ProcFsMount({ kernel, processManager });
    this.devFs = new DevFsMount();
    this.tmpFs = new TmpFsMount({ maxBytes: maxTmpBytes });
  }

  getMountRoot(mountName) {
    if (mountName === 'proc') return this.procFs.getRootNode();
    if (mountName === 'dev') return this.devFs.getRootNode();
    if (mountName === 'tmp') return this.tmpFs.getRootNode();
    return null;
  }

  lookupStep(mountName, parentNode, seg, opts = {}) {
    if (mountName === 'proc') return this.procFs.lookupChild(parentNode, seg, opts);
    if (mountName === 'dev') return this.devFs.lookupChild(parentNode, seg, opts);
    if (mountName === 'tmp') return this.tmpFs.lookupChild(parentNode, seg, opts);
    return null;
  }

  listChildren(mountName, dirNode) {
    if (mountName === 'proc') return this.procFs.listChildren(dirNode);
    if (mountName === 'dev') return this.devFs.listChildren(dirNode);
    if (mountName === 'tmp') return this.tmpFs.listChildren(dirNode);
    return [];
  }

  clearTmp() {
    this.tmpFs.clear();
  }

  listMounts() {
    return [
      { path: '/', type: 'sqlite', readOnly: false },
      { path: '/proc', type: 'procfs', readOnly: true },
      { path: '/dev', type: 'devfs', readOnly: false },
      { path: '/tmp', type: 'tmpfs', readOnly: false, maxBytes: this.tmpFs.maxBytes, usedBytes: this.tmpFs.usedBytes },
    ];
  }
}

export function createVirtualMounts(options = {}) {
  return new VirtualMountManager(options);
}
