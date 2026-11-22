/**
 * OmniOS Process & Thread Manager (`ProcessManager`)
 * Features:
 *  - Strict PCB FSM (CREATED -> READY <-> RUNNING <-> BLOCKED | STOPPED -> ZOMBIE -> TERMINATED)
 *  - Multi-thread TCB support (Map<tid, TCB>) with independent registers & ExecutionContexts
 *  - Full POSIX signal handling with custom catchers, uncatchable SIGKILL/SIGSTOP, protected PID 0/1
 *  - Bounded ring-buffer stdin/stdout/stderr streams with live KernelEventBus events
 *  - Per-PID FD table (0, 1, 2, 3+) with maxOpenFds (EMFILE) quota & guaranteed close-on-exit
 *  - Orphan reparenting to PID 1 (omnid), process tree construction, VMM teardown & quotas
 */

import {
  OmniOSError,
  ProcessError,
  QuotaExceededError,
  SecurityError,
  ERROR_CODES,
  SIGNALS,
  SIGNAL_NAMES,
  resolveSignal,
} from '../common/errors.mjs';
import { AddressSpace, DEFAULT_MAX_MEMORY_BYTES } from './vmm.mjs';

export { SIGNALS, SIGNAL_NAMES };
export const SIGNAL_BY_NUMBER = SIGNAL_NAMES;

export const PROCESS_STATES = Object.freeze({
  CREATED: 'CREATED',
  READY: 'READY',
  RUNNING: 'RUNNING',
  BLOCKED: 'BLOCKED',
  STOPPED: 'STOPPED',
  ZOMBIE: 'ZOMBIE',
  TERMINATED: 'TERMINATED',
});

export const THREAD_STATES = Object.freeze({
  CREATED: 'CREATED',
  READY: 'READY',
  RUNNING: 'RUNNING',
  BLOCKED: 'BLOCKED',
  STOPPED: 'STOPPED',
  EXITED: 'EXITED',
});

export const VALID_PROCESS_TRANSITIONS = Object.freeze({
  CREATED: Object.freeze(new Set(['READY', 'STOPPED', 'ZOMBIE'])),
  READY: Object.freeze(new Set(['RUNNING', 'BLOCKED', 'STOPPED', 'ZOMBIE'])),
  RUNNING: Object.freeze(new Set(['READY', 'BLOCKED', 'STOPPED', 'ZOMBIE'])),
  BLOCKED: Object.freeze(new Set(['READY', 'STOPPED', 'ZOMBIE'])),
  STOPPED: Object.freeze(new Set(['READY', 'BLOCKED', 'ZOMBIE'])),
  ZOMBIE: Object.freeze(new Set(['TERMINATED'])),
  TERMINATED: Object.freeze(new Set()),
});

export const UNCATCHABLE_SIGNALS = Object.freeze(new Set([SIGNALS.SIGKILL, SIGNALS.SIGSTOP]));

export const DEFAULT_QUOTAS = Object.freeze({
  maxMemoryBytes: DEFAULT_MAX_MEMORY_BYTES, // 64 MiB
  maxInstructionsPerTick: 16384,
  maxTotalInstructions: 10_000_000,
  maxOpenFds: 64,
  maxWindows: 8,
});

export const DEFAULT_STREAM_CAPACITY = 65536; // 64 KiB

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8');

function decodeStreamPayload(data) {
  if (typeof data === 'string') return data;
  if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
    return TEXT_DECODER.decode(data);
  }
  return String(data ?? '');
}

const FAULT_STANDARD_KEYS = Object.freeze([
  'name',
  'message',
  'code',
  'signal',
  'faultType',
  'address',
  'addr',
  'ts',
]);

function toJsonSafeFaultValue(val, seen = new Set(), depth = 0) {
  if (val === null || val === undefined) return val;
  const t = typeof val;
  if (t === 'bigint') {
    return val < 0n ? `-0x${(-val).toString(16)}` : `0x${val.toString(16)}`;
  }
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
    if (Array.isArray(val)) {
      return val.map((item) => toJsonSafeFaultValue(item, seen, depth + 1));
    }
    const out = {};
    for (const k of Object.keys(val)) {
      let propVal;
      try {
        propVal = val[k];
      } catch {
        propVal = '[Unreadable]';
      }
      Object.defineProperty(out, k, {
        value: toJsonSafeFaultValue(propVal, seen, depth + 1),
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

function normalizeFaultReason(val) {
  if (val === null || val === undefined) return null;
  if (typeof val === 'string') return val;
  const safe = toJsonSafeFaultValue(val);
  if (safe === null || safe === undefined) return null;
  if (typeof safe === 'string') return safe;
  if (typeof safe === 'number' || typeof safe === 'boolean') return String(safe);
  try {
    return JSON.stringify(safe);
  } catch {
    return '[Unreadable]';
  }
}

function extractFaultMessage(fault) {
  if (fault === null || fault === undefined || typeof fault !== 'object') return null;
  try {
    const msg = fault.message;
    return msg === null || msg === undefined ? null : normalizeFaultReason(msg);
  } catch {
    return null;
  }
}

function normalizeFaultForSummary(fault) {
  if (fault === null || fault === undefined) return null;
  if (typeof fault !== 'object') {
    return { message: String(toJsonSafeFaultValue(fault)) };
  }

  let source = fault;
  let usedToJson = false;
  try {
    const toJsonFn = fault.toJSON;
    if (typeof toJsonFn === 'function') {
      const serialized = toJsonFn.call(fault);
      if (serialized !== null && typeof serialized === 'object' && !Array.isArray(serialized)) {
        source = serialized;
        usedToJson = true;
      }
    }
  } catch {
    // Fall back to guarded property extraction from fault directly.
  }

  const out = {};
  const setProp = (key, val) => {
    Object.defineProperty(out, key, {
      value: val,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  };

  const seen = new Set();
  seen.add(fault);
  if (source !== fault) seen.add(source);

  try {
    for (const k of Object.keys(source)) {
      let propVal;
      try {
        propVal = source[k];
      } catch {
        propVal = '[Unreadable]';
      }
      if (propVal !== undefined) {
        setProp(k, toJsonSafeFaultValue(propVal, seen, 1));
      }
    }
  } catch {
    // Hostile Proxy whose ownKeys trap throws; continue to standard fields below.
  }

  for (const key of FAULT_STANDARD_KEYS) {
    if (Object.prototype.hasOwnProperty.call(out, key)) continue;
    let propVal;
    let readable = true;
    try {
      propVal = source[key];
      if (propVal === undefined && usedToJson) {
        propVal = fault[key];
      }
    } catch {
      propVal = '[Unreadable]';
      readable = false;
    }
    if (!readable) {
      setProp(key, '[Unreadable]');
    } else if (propVal !== undefined) {
      setProp(key, toJsonSafeFaultValue(propVal, seen, 1));
    }
  }

  return out;
}

/**
 * Bounded circular byte ring buffer for per-process stdin/stdout/stderr.
 */
export class ProcessStreamBuffer {
  constructor(maxBytes = DEFAULT_STREAM_CAPACITY) {
    if (!Number.isInteger(maxBytes) || maxBytes < 1) {
      throw new OmniOSError(`Invalid stream capacity: ${maxBytes}`, { code: ERROR_CODES.EINVAL });
    }
    this.maxBytes = maxBytes;
    this._buf = new Uint8Array(maxBytes);
    this._head = 0;
    this._size = 0;
    this._totalWritten = 0;
    this._droppedBytes = 0;
  }

  get size() {
    return this._size;
  }

  get capacity() {
    return this.maxBytes;
  }

  get totalWritten() {
    return this._totalWritten;
  }

  get droppedBytes() {
    return this._droppedBytes;
  }

  write(data) {
    let chunk;
    if (typeof data === 'string') {
      chunk = TEXT_ENCODER.encode(data);
    } else if (data instanceof Uint8Array) {
      chunk = data;
    } else if (data instanceof ArrayBuffer) {
      chunk = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
      chunk = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else {
      chunk = TEXT_ENCODER.encode(String(data ?? ''));
    }

    const len = chunk.byteLength;
    if (len === 0) return 0;

    this._totalWritten += len;

    if (len >= this.maxBytes) {
      this._droppedBytes += this._size + (len - this.maxBytes);
      this._buf.set(chunk.subarray(len - this.maxBytes), 0);
      this._head = 0;
      this._size = this.maxBytes;
      return len;
    }

    const overflow = this._size + len - this.maxBytes;
    if (overflow > 0) {
      this._head = (this._head + overflow) % this.maxBytes;
      this._size -= overflow;
      this._droppedBytes += overflow;
    }

    const tail = (this._head + this._size) % this.maxBytes;
    const firstPart = Math.min(len, this.maxBytes - tail);
    this._buf.set(chunk.subarray(0, firstPart), tail);
    if (firstPart < len) {
      this._buf.set(chunk.subarray(firstPart), 0);
    }
    this._size += len;
    return len;
  }

  read(maxBytes = Infinity, { encoding = 'utf8', consume = true } = {}) {
    const requested = maxBytes === Infinity ? this._size : Math.max(0, Math.floor(maxBytes));
    const count = Math.min(this._size, requested);
    const out = new Uint8Array(count);

    if (count > 0) {
      const firstPart = Math.min(count, this.maxBytes - this._head);
      out.set(this._buf.subarray(this._head, this._head + firstPart), 0);
      if (firstPart < count) {
        out.set(this._buf.subarray(0, count - firstPart), firstPart);
      }
      if (consume) {
        this._head = (this._head + count) % this.maxBytes;
        this._size -= count;
      }
    }

    if (encoding === null || encoding === 'binary') {
      return out;
    }
    return TEXT_DECODER.decode(out);
  }

  peek(encoding = 'utf8', maxBytes = Infinity) {
    return this.read(maxBytes, { encoding, consume: false });
  }

  clear() {
    this._head = 0;
    this._size = 0;
  }
}

function validatePriority(priority) {
  if (typeof priority !== 'number' || !Number.isInteger(priority) || priority < -20 || priority > 19) {
    throw new ProcessError(`Priority must be an integer in [-20, 19]: ${priority}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  return priority;
}

function mergeQuotas(base, overrides = {}) {
  const merged = { ...base, ...(overrides ?? {}) };
  if (typeof merged.maxMemoryBytes !== 'number' || merged.maxMemoryBytes < 0 || Number.isNaN(merged.maxMemoryBytes)) {
    throw new ProcessError(`Invalid maxMemoryBytes quota: ${merged.maxMemoryBytes}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (
    typeof merged.maxInstructionsPerTick !== 'number' ||
    merged.maxInstructionsPerTick <= 0 ||
    Number.isNaN(merged.maxInstructionsPerTick)
  ) {
    throw new ProcessError(`Invalid maxInstructionsPerTick quota: ${merged.maxInstructionsPerTick}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (
    typeof merged.maxTotalInstructions !== 'number' ||
    merged.maxTotalInstructions <= 0 ||
    Number.isNaN(merged.maxTotalInstructions)
  ) {
    throw new ProcessError(`Invalid maxTotalInstructions quota: ${merged.maxTotalInstructions}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (!Number.isInteger(merged.maxOpenFds) || merged.maxOpenFds < 3) {
    throw new ProcessError(`Invalid maxOpenFds quota (must be integer >= 3): ${merged.maxOpenFds}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (!Number.isInteger(merged.maxWindows) || merged.maxWindows < 0) {
    throw new ProcessError(`Invalid maxWindows quota: ${merged.maxWindows}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  return merged;
}

function createThreadRecord({
  tid,
  pid,
  name,
  state,
  priority,
  executionContext = null,
  registers = {},
  stackBase = null,
  stackSize = 0,
}) {
  return {
    tid,
    pid,
    name: String(name ?? `thread-${tid}`),
    state,
    priority,
    executionContext,
    registers: { ...(registers ?? {}) },
    stackBase,
    stackSize,
    waitReason: null,
    exitCode: null,
    _stateBeforeStop: null,
    _disposed: false,
    stats: {
      createdAt: Date.now(),
      cpuTicks: 0,
      instructionsExecuted: 0,
      syscallsCount: 0,
    },
  };
}

function disposeThreadContextOnce(tcb) {
  if (!tcb || tcb._disposed) return;
  tcb._disposed = true;
  try {
    const ctx = tcb.executionContext;
    if (ctx && typeof ctx.dispose === 'function') {
      ctx.dispose();
    }
  } catch {
    // Isolate executionContext.dispose getter and method failures during teardown.
  }
}

export class ProcessManager {
  constructor({
    eventBus = null,
    dmesg = null,
    defaultQuotas = {},
    streamCapacity = DEFAULT_STREAM_CAPACITY,
  } = {}) {
    this._eventBus = eventBus;
    this._dmesg = typeof dmesg === 'function' ? dmesg : null;
    this._defaultQuotas = mergeQuotas(DEFAULT_QUOTAS, defaultQuotas);
    this._streamCapacity = streamCapacity;
    this._processes = new Map();
    this._nextPid = 2;
  }

  _requirePcb(pid) {
    const pcb = this._processes.get(pid);
    if (!pcb) {
      throw new ProcessError(`Process not found: PID ${pid}`, {
        code: ERROR_CODES.ESRCH,
        pid,
      });
    }
    return pcb;
  }

  _createPcb({
    pid,
    ppid,
    name,
    appId = null,
    platform = 'posix',
    arch = 'native',
    uid = 1000,
    gid = 1000,
    cwd = '/home/user',
    env = {},
    args = [],
    priority = 0,
    quotas = {},
    executionContext = null,
    addressSpace = null,
    autoReady = true,
    registers = {},
    system = false,
  }) {
    if (typeof name !== 'string' || name.trim().length === 0) {
      throw new ProcessError('Process name must be a non-empty string', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const validPriority = validatePriority(priority);
    const mergedQuotas = mergeQuotas(
      system ? { ...this._defaultQuotas, maxTotalInstructions: Infinity } : this._defaultQuotas,
      quotas
    );

    const addrSpace =
      addressSpace ??
      new AddressSpace({
        pid,
        maxMemoryBytes: mergedQuotas.maxMemoryBytes,
      });

    const streams = {
      stdin: new ProcessStreamBuffer(this._streamCapacity),
      stdout: new ProcessStreamBuffer(this._streamCapacity),
      stderr: new ProcessStreamBuffer(this._streamCapacity),
    };

    const now = Date.now();
    const fdTable = new Map([
      [0, { fd: 0, type: 'stream', path: '/dev/stdin', flags: 'r', pos: 0, handle: streams.stdin, onClose: null, openedAt: now, meta: {} }],
      [1, { fd: 1, type: 'stream', path: '/dev/stdout', flags: 'w', pos: 0, handle: streams.stdout, onClose: null, openedAt: now, meta: {} }],
      [2, { fd: 2, type: 'stream', path: '/dev/stderr', flags: 'w', pos: 0, handle: streams.stderr, onClose: null, openedAt: now, meta: {} }],
    ]);

    const mainTcb = createThreadRecord({
      tid: 1,
      pid,
      name: `${name}:main`,
      state: THREAD_STATES.CREATED,
      priority: validPriority,
      executionContext,
      registers,
    });

    const threads = new Map([[1, mainTcb]]);

    const pcb = {
      pid,
      ppid,
      name,
      appId: appId ?? null,
      platform: String(platform),
      arch: String(arch),
      uid,
      gid,
      cwd: String(cwd),
      env: { ...(env ?? {}) },
      args: Array.isArray(args) ? [...args] : [],
      priority: validPriority,
      state: PROCESS_STATES.CREATED,
      system: Boolean(system),
      threads,
      mainTid: 1,
      _nextTid: 2,
      fdTable,
      streams,
      addressSpace: addrSpace,
      quotas: mergedQuotas,
      windowIds: new Set(),
      signalHandlers: new Map(),
      cleanupHooks: [],
      stats: {
        startedAt: now,
        exitedAt: null,
        cpuTicks: 0,
        instructionsExecuted: 0,
        syscallsCount: 0,
        exitCode: null,
        exitSignal: null,
        exitSignalNumber: null,
        faultReason: null,
        lastFault: null,
      },
      get executionContext() {
        return this.threads.get(this.mainTid)?.executionContext ?? null;
      },
      set executionContext(ctx) {
        const main = this.threads.get(this.mainTid);
        if (main) main.executionContext = ctx;
      },
    };

    this._processes.set(pid, pcb);

    this._eventBus?.emit('process:created', {
      pid: pcb.pid,
      ppid: pcb.ppid,
      name: pcb.name,
      appId: pcb.appId,
      platform: pcb.platform,
      arch: pcb.arch,
    });

    if (autoReady) {
      mainTcb.state = THREAD_STATES.READY;
      this.transitionState(pid, PROCESS_STATES.READY, { reason: 'spawn' });
    }

    return pcb;
  }

  spawnSystemProcess({
    pid,
    ppid = 0,
    name,
    appId = null,
    platform = 'kernel',
    arch = 'native',
    cwd = '/',
    env = {},
    args = [],
    priority = 0,
    quotas = {},
    executionContext = null,
    autoReady = true,
  } = {}) {
    if (pid !== 0 && pid !== 1) {
      throw new ProcessError(`spawnSystemProcess only permits PID 0 or 1, got ${pid}`, {
        code: ERROR_CODES.EINVAL,
        pid,
      });
    }
    if (this._processes.has(pid)) {
      throw new ProcessError(`System process PID ${pid} already exists`, {
        code: ERROR_CODES.EEXIST,
        pid,
      });
    }
    this._nextPid = Math.max(this._nextPid, 2);
    return this._createPcb({
      pid,
      ppid,
      name,
      appId,
      platform,
      arch,
      uid: 0,
      gid: 0,
      cwd,
      env,
      args,
      priority,
      quotas,
      executionContext,
      autoReady,
      system: true,
    });
  }

  spawn({
    name,
    appId = null,
    ppid = undefined,
    platform = 'posix',
    arch = 'native',
    uid = 1000,
    gid = 1000,
    cwd = '/home/user',
    env = {},
    args = [],
    priority = 0,
    quotas = {},
    executionContext = null,
    addressSpace = null,
    autoReady = true,
    registers = {},
  } = {}) {
    while (this._processes.has(this._nextPid)) {
      this._nextPid += 1;
    }
    const candidatePid = this._nextPid;
    let resolvedPpid;
    if (ppid !== undefined && ppid !== null) {
      if (typeof ppid !== 'number' || !Number.isSafeInteger(ppid) || ppid < 0) {
        throw new ProcessError(`Invalid parent PID (ppid): ${ppid}`, {
          code: ERROR_CODES.ESRCH,
          pid: typeof ppid === 'number' ? ppid : null,
        });
      }
      if (ppid === candidatePid) {
        throw new ProcessError(`Process PID ${candidatePid} cannot be its own parent`, {
          code: ERROR_CODES.ESRCH,
          pid: ppid,
        });
      }
      if (this._processes.size > 0) {
        const parent = this._processes.get(ppid);
        if (
          !parent ||
          parent.state === PROCESS_STATES.ZOMBIE ||
          parent.state === PROCESS_STATES.TERMINATED
        ) {
          throw new ProcessError(
            parent
              ? `Parent process PID ${ppid} is ${parent.state}`
              : `Parent process not found: PID ${ppid}`,
            {
              code: ERROR_CODES.ESRCH,
              pid: ppid,
            }
          );
        }
      } else if (ppid !== 0) {
        throw new ProcessError(`Parent process not found: PID ${ppid}`, {
          code: ERROR_CODES.ESRCH,
          pid: ppid,
        });
      }
      resolvedPpid = ppid;
    } else {
      const init = this._processes.get(1);
      resolvedPpid =
        init && init.state !== PROCESS_STATES.ZOMBIE && init.state !== PROCESS_STATES.TERMINATED
          ? 1
          : 0;
    }

    const pcb = this._createPcb({
      pid: candidatePid,
      ppid: resolvedPpid,
      name,
      appId,
      platform,
      arch,
      uid,
      gid,
      cwd,
      env,
      args,
      priority,
      quotas,
      executionContext,
      addressSpace,
      autoReady,
      registers,
      system: false,
    });
    this._nextPid = Math.max(this._nextPid, candidatePid + 1);
    return pcb;
  }

  get(pid) {
    return this._processes.get(pid) ?? null;
  }

  has(pid) {
    return this._processes.has(pid);
  }

  getAll() {
    return Array.from(this._processes.values());
  }

  toSummary(pcb) {
    if (!pcb) return null;
    let activeThreadCount = 0;
    for (const tcb of pcb.threads.values()) {
      if (tcb.state !== THREAD_STATES.EXITED) activeThreadCount += 1;
    }
    const safeFaultReason = normalizeFaultReason(pcb.stats.faultReason);
    const normalizedLastFault =
      pcb.stats.lastFault !== null && pcb.stats.lastFault !== undefined
        ? normalizeFaultForSummary(pcb.stats.lastFault)
        : null;
    return {
      pid: pcb.pid,
      ppid: pcb.ppid,
      name: pcb.name,
      appId: pcb.appId,
      platform: pcb.platform,
      arch: pcb.arch,
      uid: pcb.uid,
      gid: pcb.gid,
      cwd: pcb.cwd,
      priority: pcb.priority,
      state: pcb.state,
      system: pcb.system,
      threadCount: pcb.threads.size,
      activeThreadCount,
      fdCount: pcb.fdTable.size,
      windowCount: pcb.windowIds.size,
      exitCode: pcb.stats.exitCode,
      exitSignal: pcb.stats.exitSignal,
      exitSignalNumber: pcb.stats.exitSignalNumber,
      faultReason: safeFaultReason,
      lastFault: normalizedLastFault,
      stats: {
        ...pcb.stats,
        faultReason: safeFaultReason,
        lastFault: normalizedLastFault ? normalizeFaultForSummary(normalizedLastFault) : null,
      },
      memory: pcb.addressSpace.getStats(),
      quotas: { ...pcb.quotas },
    };
  }

  list({ includeTerminated = false, state = undefined, platform = undefined, appId = undefined } = {}) {
    const out = [];
    for (const pcb of this._processes.values()) {
      if (!includeTerminated && pcb.state === PROCESS_STATES.TERMINATED) continue;
      if (state !== undefined && pcb.state !== state) continue;
      if (platform !== undefined && pcb.platform !== platform) continue;
      if (appId !== undefined && pcb.appId !== appId) continue;
      out.push(this.toSummary(pcb));
    }
    return out;
  }

  getTree({ includeTerminated = false } = {}) {
    const nodeMap = new Map();
    const nodes = [];

    for (const pcb of this._processes.values()) {
      if (!includeTerminated && pcb.state === PROCESS_STATES.TERMINATED) continue;
      const node = { ...this.toSummary(pcb), children: [] };
      nodeMap.set(pcb.pid, node);
      nodes.push(node);
    }

    const attachedParent = new Map();
    const roots = [];
    for (const node of nodes) {
      const parent = node.ppid !== node.pid ? nodeMap.get(node.ppid) : null;
      if (!parent) {
        roots.push(node);
        continue;
      }

      let createsCycle = false;
      const visited = new Set([node.pid]);
      let curPid = parent.pid;
      while (curPid !== undefined) {
        if (visited.has(curPid)) {
          createsCycle = true;
          break;
        }
        visited.add(curPid);
        curPid = attachedParent.get(curPid);
      }

      if (createsCycle) {
        roots.push(node);
      } else {
        parent.children.push(node);
        attachedParent.set(node.pid, parent.pid);
      }
    }
    return roots;
  }

  getAggregateMemoryStats() {
    let totalMappedPages = 0;
    let totalUsedBytes = 0;
    let totalPeakBytes = 0;
    let activeProcesses = 0;

    for (const pcb of this._processes.values()) {
      const mem = pcb.addressSpace.getStats();
      totalMappedPages += mem.mappedPages;
      totalUsedBytes += mem.usedBytes;
      totalPeakBytes += mem.peakBytes;
      if (pcb.state !== PROCESS_STATES.ZOMBIE && pcb.state !== PROCESS_STATES.TERMINATED) {
        activeProcesses += 1;
      }
    }

    return {
      totalMappedPages,
      totalUsedBytes,
      totalPeakBytes,
      activeProcesses,
      totalProcesses: this._processes.size,
    };
  }

  // ---- Strict PCB FSM Transitions ----

  transitionState(pid, nextState, { reason = null } = {}) {
    const pcb = this._requirePcb(pid);
    const allowed = VALID_PROCESS_TRANSITIONS[pcb.state];
    if (!allowed || !allowed.has(nextState)) {
      throw new ProcessError(`Illegal process state transition: ${pcb.state} -> ${nextState}`, {
        code: ERROR_CODES.EINVAL,
        pid,
        state: pcb.state,
        targetState: nextState,
      });
    }
    const prevState = pcb.state;
    pcb.state = nextState;

    // When moving CREATED -> READY manually, ensure CREATED main thread becomes READY
    if (prevState === PROCESS_STATES.CREATED && nextState === PROCESS_STATES.READY) {
      for (const tcb of pcb.threads.values()) {
        if (tcb.state === THREAD_STATES.CREATED) {
          tcb.state = THREAD_STATES.READY;
        }
      }
    }

    this._eventBus?.emit('process:state_changed', {
      pid: pcb.pid,
      prevState,
      state: nextState,
      reason,
      exitCode: pcb.stats.exitCode,
      exitSignal: pcb.stats.exitSignal,
    });
    return pcb;
  }

  setState(pid, nextState, opts = {}) {
    return this.transitionState(pid, nextState, opts);
  }

  getRunnableThreads() {
    const runnable = [];
    for (const pcb of this._processes.values()) {
      if (pcb.state !== PROCESS_STATES.READY && pcb.state !== PROCESS_STATES.RUNNING) continue;
      for (const tcb of pcb.threads.values()) {
        if (tcb.state !== THREAD_STATES.READY) continue;
        try {
          const execCtx = tcb.executionContext;
          if (execCtx && typeof execCtx.step === 'function') {
            runnable.push({ pcb, tcb, execCtx });
          }
        } catch {
          // Isolate throwing executionContext or step getters.
          continue;
        }
      }
    }
    return runnable;
  }

  markRunning(pid, tid = 1) {
    const pcb = this._requirePcb(pid);
    const tcb = pcb.threads.get(tid);
    if (!tcb) {
      throw new ProcessError(`Thread ${tid} not found in PID ${pid}`, { code: ERROR_CODES.ESRCH, pid });
    }
    if (pcb.state !== PROCESS_STATES.READY && pcb.state !== PROCESS_STATES.RUNNING) {
      throw new ProcessError(`Cannot mark PID ${pid} RUNNING from state ${pcb.state}`, {
        code: ERROR_CODES.EINVAL,
        pid,
        state: pcb.state,
        targetState: PROCESS_STATES.RUNNING,
      });
    }
    if (tcb.state !== THREAD_STATES.READY && tcb.state !== THREAD_STATES.RUNNING) {
      throw new ProcessError(
        `Cannot mark thread ${tid} of PID ${pid} RUNNING from thread state ${tcb.state}`,
        {
          code: ERROR_CODES.EINVAL,
          pid,
          state: pcb.state,
          targetState: PROCESS_STATES.RUNNING,
        }
      );
    }
    if (pcb.state === PROCESS_STATES.READY) {
      this.transitionState(pid, PROCESS_STATES.RUNNING, { reason: 'dispatch' });
    }
    tcb.state = THREAD_STATES.RUNNING;
    return tcb;
  }

  markReady(pid, tid = 1) {
    const pcb = this._requirePcb(pid);
    const tcb = pcb.threads.get(tid);
    if (!tcb) {
      throw new ProcessError(`Thread ${tid} not found in PID ${pid}`, { code: ERROR_CODES.ESRCH, pid });
    }
    const validPcbState =
      pcb.state === PROCESS_STATES.READY ||
      pcb.state === PROCESS_STATES.RUNNING ||
      pcb.state === PROCESS_STATES.BLOCKED;
    const validTcbState =
      tcb.state === THREAD_STATES.READY ||
      tcb.state === THREAD_STATES.RUNNING ||
      tcb.state === THREAD_STATES.BLOCKED;
    if (!validPcbState || !validTcbState) {
      throw new ProcessError(
        `Cannot mark thread ${tid} READY in process ${pid} (pcb=${pcb.state}, tcb=${tcb.state})`,
        {
          code: ERROR_CODES.EINVAL,
          pid,
          state: pcb.state,
          targetState: PROCESS_STATES.READY,
        }
      );
    }
    tcb.state = THREAD_STATES.READY;
    tcb.waitReason = null;

    let anyRunning = false;
    for (const t of pcb.threads.values()) {
      if (t.state === THREAD_STATES.EXITED) continue;
      if (t.state === THREAD_STATES.RUNNING) {
        anyRunning = true;
        break;
      }
    }
    if (!anyRunning && (pcb.state === PROCESS_STATES.RUNNING || pcb.state === PROCESS_STATES.BLOCKED)) {
      this.transitionState(pid, PROCESS_STATES.READY, { reason: 'ready' });
    }
    return tcb;
  }

  markBlocked(pid, tid = 1, waitReason = 'io') {
    const pcb = this._requirePcb(pid);
    const tcb = pcb.threads.get(tid);
    if (!tcb) {
      throw new ProcessError(`Thread ${tid} not found in PID ${pid}`, { code: ERROR_CODES.ESRCH, pid });
    }
    const validPcbState =
      pcb.state === PROCESS_STATES.READY ||
      pcb.state === PROCESS_STATES.RUNNING ||
      pcb.state === PROCESS_STATES.BLOCKED;
    const validTcbState =
      tcb.state === THREAD_STATES.READY ||
      tcb.state === THREAD_STATES.RUNNING ||
      tcb.state === THREAD_STATES.BLOCKED;
    if (!validPcbState || !validTcbState) {
      throw new ProcessError(
        `Cannot block thread ${tid} in process ${pid} (pcb=${pcb.state}, tcb=${tcb.state})`,
        {
          code: ERROR_CODES.EINVAL,
          pid,
          state: pcb.state,
          targetState: PROCESS_STATES.BLOCKED,
        }
      );
    }
    tcb.state = THREAD_STATES.BLOCKED;
    tcb.waitReason = waitReason;

    let anyRunning = false;
    let anyReadyOrRunning = false;
    for (const t of pcb.threads.values()) {
      if (t.state === THREAD_STATES.EXITED) continue;
      if (t.state === THREAD_STATES.RUNNING) {
        anyRunning = true;
        anyReadyOrRunning = true;
      } else if (t.state === THREAD_STATES.READY) {
        anyReadyOrRunning = true;
      }
    }

    if (!anyReadyOrRunning) {
      if (pcb.state === PROCESS_STATES.RUNNING || pcb.state === PROCESS_STATES.READY) {
        this.transitionState(pid, PROCESS_STATES.BLOCKED, { reason: waitReason });
      }
    } else if (pcb.state === PROCESS_STATES.RUNNING && !anyRunning) {
      this.transitionState(pid, PROCESS_STATES.READY, { reason: 'thread_blocked' });
    }

    return tcb;
  }

  wake(pid, tid = null) {
    const pcb = this._requirePcb(pid);
    if (
      pcb.state === PROCESS_STATES.ZOMBIE ||
      pcb.state === PROCESS_STATES.TERMINATED ||
      pcb.state === PROCESS_STATES.STOPPED
    ) {
      return false;
    }

    let woke = false;
    if (tid !== null && tid !== undefined) {
      const tcb = pcb.threads.get(tid);
      if (!tcb) return false;
      if (tcb.state === THREAD_STATES.BLOCKED) {
        tcb.state = THREAD_STATES.READY;
        tcb.waitReason = null;
        woke = true;
      }
    } else {
      for (const tcb of pcb.threads.values()) {
        if (tcb.state === THREAD_STATES.BLOCKED) {
          tcb.state = THREAD_STATES.READY;
          tcb.waitReason = null;
          woke = true;
        }
      }
    }

    if (woke && pcb.state === PROCESS_STATES.BLOCKED) {
      this.transitionState(pid, PROCESS_STATES.READY, { reason: 'wake' });
    }
    return woke;
  }

  // ---- Multi-Thread Management ----

  createThread(
    pid,
    {
      name = undefined,
      executionContext = null,
      registers = {},
      priority = undefined,
      stackBase = null,
      stackSize = 0,
    } = {}
  ) {
    const pcb = this._requirePcb(pid);
    if (pcb.state === PROCESS_STATES.ZOMBIE || pcb.state === PROCESS_STATES.TERMINATED) {
      throw new ProcessError(`Cannot create thread in ${pcb.state} process PID ${pid}`, {
        code: ERROR_CODES.EINVAL,
        pid,
        state: pcb.state,
      });
    }
    const threadPriority = priority !== undefined ? validatePriority(priority) : pcb.priority;
    let initState = THREAD_STATES.READY;
    if (pcb.state === PROCESS_STATES.CREATED) initState = THREAD_STATES.CREATED;
    else if (pcb.state === PROCESS_STATES.STOPPED) initState = THREAD_STATES.STOPPED;

    const tid = pcb._nextTid;
    const tcb = createThreadRecord({
      tid,
      pid,
      name: name ?? `${pcb.name}:t${tid}`,
      state: initState,
      priority: threadPriority,
      executionContext,
      registers,
      stackBase,
      stackSize,
    });
    pcb._nextTid = tid + 1;
    pcb.threads.set(tid, tcb);

    // If process was BLOCKED and new thread is READY, unblock PCB
    if (pcb.state === PROCESS_STATES.BLOCKED && initState === THREAD_STATES.READY) {
      this.transitionState(pid, PROCESS_STATES.READY, { reason: 'thread_created' });
    }

    this._eventBus?.emit('thread:created', { pid, tid, name: tcb.name });
    return tcb;
  }

  getThread(pid, tid) {
    const pcb = this._processes.get(pid);
    if (!pcb) return null;
    return pcb.threads.get(tid) ?? null;
  }

  listThreads(pid) {
    const pcb = this._requirePcb(pid);
    return Array.from(pcb.threads.values()).map((t) => ({
      tid: t.tid,
      pid: t.pid,
      name: t.name,
      state: t.state,
      priority: t.priority,
      waitReason: t.waitReason,
      exitCode: t.exitCode,
      stackBase: t.stackBase,
      stackSize: t.stackSize,
      stats: { ...t.stats },
    }));
  }

  exitThread(pid, tid, exitCode = 0) {
    const pcb = this._requirePcb(pid);
    const tcb = pcb.threads.get(tid);
    if (!tcb) {
      throw new ProcessError(`Thread ${tid} not found in PID ${pid}`, {
        code: ERROR_CODES.ESRCH,
        pid,
      });
    }
    if (tcb.state === THREAD_STATES.EXITED) return;

    const code = Number.isInteger(exitCode) ? exitCode : 0;
    tcb.state = THREAD_STATES.EXITED;
    tcb.exitCode = code;
    tcb.waitReason = null;
    disposeThreadContextOnce(tcb);

    this._eventBus?.emit('thread:exited', { pid, tid, exitCode: code });

    if (pcb.state === PROCESS_STATES.ZOMBIE || pcb.state === PROCESS_STATES.TERMINATED) {
      return;
    }

    let anyLive = false;
    let anyRunning = false;
    let anyReadyOrRunning = false;
    for (const t of pcb.threads.values()) {
      if (t.state !== THREAD_STATES.EXITED) {
        anyLive = true;
        if (t.state === THREAD_STATES.RUNNING) {
          anyRunning = true;
          anyReadyOrRunning = true;
        } else if (t.state === THREAD_STATES.READY) {
          anyReadyOrRunning = true;
        }
      }
    }

    if (tid === pcb.mainTid || !anyLive) {
      this.exit(pid, code);
      return;
    }

    if (pcb.state === PROCESS_STATES.RUNNING || pcb.state === PROCESS_STATES.READY) {
      if (!anyReadyOrRunning) {
        this.transitionState(pid, PROCESS_STATES.BLOCKED, { reason: 'thread_exited' });
      } else if (pcb.state === PROCESS_STATES.RUNNING && !anyRunning) {
        this.transitionState(pid, PROCESS_STATES.READY, { reason: 'thread_exited' });
      }
    }
  }

  // ---- POSIX Signals ----

  normalizeSignal(signal) {
    return resolveSignal(signal);
  }

  onSignal(pid, signal, handler) {
    const pcb = this._requirePcb(pid);
    if (pcb.state === PROCESS_STATES.ZOMBIE || pcb.state === PROCESS_STATES.TERMINATED) {
      throw new ProcessError(`Cannot register signal handler on ${pcb.state} PID ${pid}`, {
        code: ERROR_CODES.EINVAL,
        pid,
        state: pcb.state,
      });
    }
    const { name, number } = resolveSignal(signal);
    if (UNCATCHABLE_SIGNALS.has(number)) {
      throw new ProcessError(`Cannot catch uncatchable signal ${name} (${number})`, {
        code: ERROR_CODES.EINVAL,
        pid,
      });
    }
    if (handler === null) {
      pcb.signalHandlers.delete(number);
      return;
    }
    if (typeof handler !== 'function') {
      throw new ProcessError('Signal handler must be a function or null', {
        code: ERROR_CODES.EINVAL,
        pid,
      });
    }
    pcb.signalHandlers.set(number, handler);
  }

  kill(
    pid,
    signal = 'SIGTERM',
    { allowSystem = false, forceDefault = false, reason = null, fault = null } = {}
  ) {
    const pcb = this._requirePcb(pid);
    const { name, number } = resolveSignal(signal);

    if (pcb.system && !allowSystem && number !== SIGNALS.SIGCONT) {
      throw new SecurityError(`Cannot send ${name} to protected system process PID ${pid} (${pcb.name})`, {
        code: ERROR_CODES.EPERM,
        pid,
      });
    }

    if (pcb.state === PROCESS_STATES.ZOMBIE || pcb.state === PROCESS_STATES.TERMINATED) {
      return { ok: false, pid, signal: name, signalNumber: number, state: pcb.state };
    }

    this._eventBus?.emit('process:signal', { pid, signal: name, signalNumber: number });

    if (number === SIGNALS.SIGSTOP) {
      if (pcb.state !== PROCESS_STATES.STOPPED) {
        this.transitionState(pid, PROCESS_STATES.STOPPED, { reason: name });
        for (const tcb of pcb.threads.values()) {
          if (tcb.state !== THREAD_STATES.EXITED) {
            tcb._stateBeforeStop = tcb.state;
            tcb.state = THREAD_STATES.STOPPED;
          }
        }
      }
      return { ok: true, pid, signal: name, signalNumber: number, state: pcb.state };
    }

    if (number === SIGNALS.SIGCONT) {
      if (pcb.state === PROCESS_STATES.STOPPED) {
        let anyReady = false;
        let anyBlocked = false;
        for (const tcb of pcb.threads.values()) {
          if (tcb.state === THREAD_STATES.STOPPED) {
            if (tcb._stateBeforeStop === THREAD_STATES.BLOCKED) {
              tcb.state = THREAD_STATES.BLOCKED;
              anyBlocked = true;
            } else {
              tcb.state = THREAD_STATES.READY;
              tcb.waitReason = null;
              anyReady = true;
            }
            tcb._stateBeforeStop = null;
          } else if (tcb.state === THREAD_STATES.READY || tcb.state === THREAD_STATES.RUNNING) {
            anyReady = true;
          } else if (tcb.state === THREAD_STATES.BLOCKED) {
            anyBlocked = true;
          }
        }
        const nextPcbState = !anyReady && anyBlocked ? PROCESS_STATES.BLOCKED : PROCESS_STATES.READY;
        this.transitionState(pid, nextPcbState, { reason: name });
      }
      const handler = pcb.signalHandlers.get(number);
      if (!forceDefault && handler) {
        try {
          handler(name, number, pcb);
        } catch {
          // Isolate SIGCONT handler error.
        }
      }
      return { ok: true, pid, signal: name, signalNumber: number, state: pcb.state };
    }

    if (number === SIGNALS.SIGKILL) {
      this._terminateProcess(pcb, {
        exitCode: 128 + SIGNALS.SIGKILL,
        exitSignal: 'SIGKILL',
        exitSignalNumber: SIGNALS.SIGKILL,
        faultReason: normalizeFaultReason(reason) ?? 'Killed by SIGKILL',
        fault,
      });
      return { ok: true, pid, signal: name, signalNumber: number, state: pcb.state };
    }

    // Catchable signals
    if (!forceDefault && pcb.signalHandlers.has(number)) {
      const handler = pcb.signalHandlers.get(number);
      try {
        const res = handler(name, number, pcb);
        if (res !== false) {
          return {
            ok: true,
            pid,
            signal: name,
            signalNumber: number,
            state: pcb.state,
            handled: true,
          };
        }
      } catch {
        // Handler threw -> fall through to default termination
      }
    }

    this._terminateProcess(pcb, {
      exitCode: 128 + number,
      exitSignal: name,
      exitSignalNumber: number,
      faultReason: normalizeFaultReason(reason) ?? extractFaultMessage(fault) ?? `Terminated by ${name}`,
      fault,
    });
    return { ok: true, pid, signal: name, signalNumber: number, state: pcb.state };
  }

  // ---- Streams, FD Table & Quotas ----

  writeStdin(pid, data) {
    const pcb = this._requirePcb(pid);
    const byteLength = pcb.streams.stdin.write(data);
    this._eventBus?.emit('process:stdin', {
      pid,
      data: decodeStreamPayload(data),
      byteLength,
    });
    // Wake threads waiting on stdin
    for (const tcb of pcb.threads.values()) {
      if (tcb.state === THREAD_STATES.BLOCKED && tcb.waitReason === 'stdin') {
        this.wake(pid, tcb.tid);
      }
    }
    return byteLength;
  }

  readStdin(pid, maxBytes = Infinity, { encoding = 'utf8', consume = true } = {}) {
    const pcb = this._requirePcb(pid);
    return pcb.streams.stdin.read(maxBytes, { encoding, consume });
  }

  writeStdout(pid, data) {
    const pcb = this._requirePcb(pid);
    const byteLength = pcb.streams.stdout.write(data);
    this._eventBus?.emit('process:stdout', {
      pid,
      stream: 'stdout',
      data: decodeStreamPayload(data),
      byteLength,
    });
    return byteLength;
  }

  writeStderr(pid, data) {
    const pcb = this._requirePcb(pid);
    const byteLength = pcb.streams.stderr.write(data);
    this._eventBus?.emit('process:stderr', {
      pid,
      stream: 'stderr',
      data: decodeStreamPayload(data),
      byteLength,
    });
    return byteLength;
  }

  readStdout(pid, { encoding = 'utf8', consume = false, maxBytes = Infinity } = {}) {
    const pcb = this._requirePcb(pid);
    return pcb.streams.stdout.read(maxBytes, { encoding, consume });
  }

  readStderr(pid, { encoding = 'utf8', consume = false, maxBytes = Infinity } = {}) {
    const pcb = this._requirePcb(pid);
    return pcb.streams.stderr.read(maxBytes, { encoding, consume });
  }

  openFd(pid, descriptor = {}) {
    const pcb = this._requirePcb(pid);
    if (pcb.state === PROCESS_STATES.ZOMBIE || pcb.state === PROCESS_STATES.TERMINATED) {
      throw new ProcessError(`Cannot open FD on ${pcb.state} PID ${pid}`, {
        code: ERROR_CODES.EINVAL,
        pid,
      });
    }
    if (pcb.fdTable.size >= pcb.quotas.maxOpenFds) {
      throw new QuotaExceededError(
        `PID ${pid} exceeded maxOpenFds limit (${pcb.quotas.maxOpenFds})`,
        {
          code: ERROR_CODES.EMFILE,
          quotaType: 'openFds',
          limit: pcb.quotas.maxOpenFds,
          actual: pcb.fdTable.size,
          pid,
        }
      );
    }

    let fd = 3;
    while (pcb.fdTable.has(fd)) {
      fd += 1;
    }

    const closeFn =
      typeof descriptor.onClose === 'function'
        ? descriptor.onClose
        : typeof descriptor.close === 'function'
          ? descriptor.close
          : null;

    const entry = {
      fd,
      type: String(descriptor.type ?? 'file'),
      path: descriptor.path ?? null,
      flags: descriptor.flags ?? 'r',
      pos: Number.isInteger(descriptor.pos) ? descriptor.pos : 0,
      handle: descriptor.handle ?? null,
      onClose: closeFn,
      openedAt: Date.now(),
      meta: descriptor.meta ? { ...descriptor.meta } : {},
    };
    pcb.fdTable.set(fd, entry);
    return fd;
  }

  getFd(pid, fd) {
    const pcb = this._processes.get(pid);
    if (!pcb) return null;
    return pcb.fdTable.get(fd) ?? null;
  }

  listFds(pid) {
    const pcb = this._requirePcb(pid);
    return Array.from(pcb.fdTable.values()).map((e) => ({
      fd: e.fd,
      type: e.type,
      path: e.path,
      flags: e.flags,
      pos: e.pos,
      openedAt: e.openedAt,
    }));
  }

  closeFd(pid, fd) {
    const pcb = this._requirePcb(pid);
    const entry = pcb.fdTable.get(fd);
    if (!entry) {
      throw new ProcessError(`Bad file descriptor ${fd} on PID ${pid}`, {
        code: ERROR_CODES.EBADF,
        pid,
      });
    }
    pcb.fdTable.delete(fd);
    try {
      if (typeof entry.onClose === 'function') {
        entry.onClose(entry);
      }
    } catch {
      // Isolate FD close callback error.
    }
    return true;
  }

  registerWindow(pid, windowId) {
    const pcb = this._requirePcb(pid);
    const id = String(windowId);
    if (!pcb.windowIds.has(id) && pcb.windowIds.size >= pcb.quotas.maxWindows) {
      throw new QuotaExceededError(
        `PID ${pid} exceeded maxWindows quota (${pcb.quotas.maxWindows})`,
        {
          code: ERROR_CODES.E_WINDOW_QUOTA,
          quotaType: 'windows',
          limit: pcb.quotas.maxWindows,
          actual: pcb.windowIds.size,
          pid,
        }
      );
    }
    pcb.windowIds.add(id);
    return true;
  }

  unregisterWindow(pid, windowId) {
    const pcb = this._processes.get(pid);
    if (!pcb) return false;
    return pcb.windowIds.delete(String(windowId));
  }

  addCleanupHook(pid, fn) {
    const pcb = this._requirePcb(pid);
    if (typeof fn !== 'function') {
      throw new ProcessError('Cleanup hook must be a function', { code: ERROR_CODES.EINVAL, pid });
    }
    pcb.cleanupHooks.push(fn);
    return () => {
      const idx = pcb.cleanupHooks.indexOf(fn);
      if (idx !== -1) pcb.cleanupHooks.splice(idx, 1);
    };
  }

  // ---- Exit, Resource Teardown, Orphan Reparenting & Reaping ----

  exit(pid, exitCode = 0, { faultReason = null, fault = null } = {}) {
    const pcb = this._requirePcb(pid);
    const code = Number.isInteger(exitCode) ? exitCode : 0;
    return this._terminateProcess(pcb, {
      exitCode: code,
      exitSignal: null,
      exitSignalNumber: null,
      faultReason,
      fault,
    });
  }

  _terminateProcess(pcb, { exitCode = 0, exitSignal = null, exitSignalNumber = null, faultReason = null, fault = null }) {
    if (pcb.state === PROCESS_STATES.ZOMBIE || pcb.state === PROCESS_STATES.TERMINATED) {
      return this.toSummary(pcb);
    }

    const prevState = pcb.state;
    pcb.stats.exitCode = exitCode;
    pcb.stats.exitSignal = exitSignal;
    pcb.stats.exitSignalNumber = exitSignalNumber;
    pcb.stats.faultReason = normalizeFaultReason(faultReason);
    if (fault !== null && fault !== undefined) {
      pcb.stats.lastFault = normalizeFaultForSummary(fault);
    }
    pcb.stats.exitedAt = Date.now();
    pcb.state = PROCESS_STATES.ZOMBIE;

    // 1. Mark all threads EXITED and dispose execution contexts once
    for (const tcb of pcb.threads.values()) {
      tcb.state = THREAD_STATES.EXITED;
      if (tcb.exitCode === null) tcb.exitCode = exitCode;
      tcb.waitReason = null;
      tcb._stateBeforeStop = null;
      disposeThreadContextOnce(tcb);
    }

    // 2. Close all open FDs
    const openFds = Array.from(pcb.fdTable.values());
    pcb.fdTable.clear();
    for (const entry of openFds) {
      try {
        if (typeof entry.onClose === 'function') {
          entry.onClose(entry);
        }
      } catch {
        // Isolate FD teardown errors.
      }
    }

    // 3. Execute all registered cleanup hooks & clear windows
    const hooks = pcb.cleanupHooks.splice(0);
    for (const hook of hooks) {
      try {
        if (typeof hook === 'function') {
          hook(pcb);
        }
      } catch {
        // Isolate cleanup hook errors.
      }
    }
    pcb.windowIds.clear();

    // 4. Destroy isolated VMM AddressSpace
    try {
      pcb.addressSpace.destroy();
    } catch {
      // Isolate VMM destroy errors.
    }

    // 5. Reparent orphaned live children to PID 1 (omnid)
    if (pcb.pid !== 1) {
      for (const child of this._processes.values()) {
        if (
          child.ppid === pcb.pid &&
          child.pid !== pcb.pid &&
          child.state !== PROCESS_STATES.TERMINATED
        ) {
          const oldPpid = child.ppid;
          child.ppid = 1;
          this._eventBus?.emit('process:reparented', {
            pid: child.pid,
            oldPpid,
            newPpid: 1,
          });
        }
      }
    }

    this._eventBus?.emit('process:state_changed', {
      pid: pcb.pid,
      prevState,
      state: PROCESS_STATES.ZOMBIE,
      reason: exitSignal ?? 'exit',
      exitCode: pcb.stats.exitCode,
      exitSignal: pcb.stats.exitSignal,
    });

    this._eventBus?.emit('process:exited', {
      pid: pcb.pid,
      ppid: pcb.ppid,
      name: pcb.name,
      appId: pcb.appId,
      exitCode: pcb.stats.exitCode,
      exitSignal: pcb.stats.exitSignal,
      exitSignalNumber: pcb.stats.exitSignalNumber,
      faultReason: pcb.stats.faultReason,
    });

    return this.toSummary(pcb);
  }

  reap(pid) {
    const pcb = this._requirePcb(pid);
    if (pcb.state !== PROCESS_STATES.ZOMBIE) {
      throw new ProcessError(`Cannot reap process PID ${pid} in state ${pcb.state} (expected ZOMBIE)`, {
        code: ERROR_CODES.EINVAL,
        pid,
        state: pcb.state,
      });
    }
    this.transitionState(pid, PROCESS_STATES.TERMINATED, { reason: 'reap' });
    this._eventBus?.emit('process:reaped', {
      pid: pcb.pid,
      exitCode: pcb.stats.exitCode,
      exitSignal: pcb.stats.exitSignal,
    });
    return this.toSummary(pcb);
  }

  shutdownAll() {
    // Terminate user processes first
    for (const pcb of Array.from(this._processes.values())) {
      if (!pcb.system && pcb.state !== PROCESS_STATES.ZOMBIE && pcb.state !== PROCESS_STATES.TERMINATED) {
        try {
          this.kill(pcb.pid, 'SIGKILL', { allowSystem: false, forceDefault: true, reason: 'shutdown' });
        } catch {
          this._terminateProcess(pcb, { exitCode: 137, exitSignal: 'SIGKILL', exitSignalNumber: 9, faultReason: 'shutdown' });
        }
      }
    }
    // Terminate system processes (PID 1, PID 0)
    for (const pcb of Array.from(this._processes.values())) {
      if (pcb.system && pcb.state !== PROCESS_STATES.ZOMBIE && pcb.state !== PROCESS_STATES.TERMINATED) {
        this._terminateProcess(pcb, { exitCode: 0, exitSignal: null, exitSignalNumber: null, faultReason: 'shutdown' });
      }
    }
    // Reap all zombies to TERMINATED
    for (const pcb of Array.from(this._processes.values())) {
      if (pcb.state === PROCESS_STATES.ZOMBIE) {
        this.reap(pcb.pid);
      }
    }
  }

  reset() {
    for (const pcb of Array.from(this._processes.values())) {
      if (pcb.state !== PROCESS_STATES.ZOMBIE && pcb.state !== PROCESS_STATES.TERMINATED) {
        for (const tcb of pcb.threads.values()) {
          tcb.state = THREAD_STATES.EXITED;
          disposeThreadContextOnce(tcb);
        }
        const openFds = Array.from(pcb.fdTable.values());
        pcb.fdTable.clear();
        for (const entry of openFds) {
          try {
            if (typeof entry.onClose === 'function') {
              entry.onClose(entry);
            }
          } catch {
            // Isolate FD teardown errors.
          }
        }
        const hooks = pcb.cleanupHooks.splice(0);
        for (const hook of hooks) {
          try {
            if (typeof hook === 'function') {
              hook(pcb);
            }
          } catch {
            // Isolate cleanup hook errors.
          }
        }
        pcb.windowIds.clear();
        try { pcb.addressSpace.destroy(); } catch { /* ignore */ }
      }
    }
    this._processes.clear();
    this._nextPid = 2;
  }
}
