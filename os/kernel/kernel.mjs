/**
 * OmniOS Microkernel Coordinator (`OmniKernel`)
 * Features:
 *  - Coordinates EventBus, CpuRegistry, SyscallDispatcher, ProcessManager, Scheduler, ServiceManager, SqliteStorage
 *  - Bounded circular `dmesg` ring buffer (`F-003`) with limit/subsystem/level/sinceSeq filtering
 *  - Synchronous `panic()` persisting JSON-safe dumps to SQLite `panic_dumps` + safe `recover({ safeMode })` (`F-004`)
 *  - Live runtime diagnostics snapshot `getDiagnostics()` (`F-005`)
 */

import path from 'node:path';
import { KernelEventBus } from './event-bus.mjs';
import { CpuRegistry } from '../cpu/registry.mjs';
import { SyscallDispatcher } from './syscalls.mjs';
import { ProcessManager, PROCESS_STATES } from './process.mjs';
import { Scheduler, DEFAULT_BASE_QUANTUM, DEFAULT_TICK_MS } from './scheduler.mjs';
import { ServiceManager } from './services.mjs';
import { runBootSequence } from './boot.mjs';
import { OmniOSError, ERROR_CODES } from '../common/errors.mjs';

export const KERNEL_STATES = Object.freeze({
  UNINITIALIZED: 'UNINITIALIZED',
  BOOTING: 'BOOTING',
  RUNNING: 'RUNNING',
  SAFE_MODE: 'SAFE_MODE',
  PANIC: 'PANIC',
  STOPPED: 'STOPPED',
  BOOT_FAILED: 'BOOT_FAILED',
});

function safeStringifyKey(value) {
  try {
    return String(value);
  } catch {
    return '[UnstringifiableKey]';
  }
}

function safeCloneValue(value, ancestors = new Set(), depth = 0, maxDepth = 32) {
  try {
    if (value === null || value === undefined) return value;
    const t = typeof value;
    if (t === 'boolean' || t === 'string') return value;
    if (t === 'number') return Number.isFinite(value) ? value : String(value);
    if (t === 'bigint') return value.toString();
    if (t === 'symbol') return value.toString();
    if (t === 'function') return `[Function: ${value.name || 'anonymous'}]`;

    if (depth >= maxDepth) {
      return '[MaxDepth]';
    }

    if (ancestors.has(value)) {
      return '[Circular]';
    }

    if (value instanceof Date) {
      const ms = value.getTime();
      return Number.isNaN(ms) ? 'Invalid Date' : value.toISOString();
    }
    if (value instanceof Error) {
      ancestors.add(value);
      try {
        let safeName;
        try {
          safeName = safeStringifyKey(value.name);
        } catch {
          safeName = '[Unreadable]';
        }
        let safeMessage;
        try {
          safeMessage = safeStringifyKey(value.message);
        } catch {
          safeMessage = '[Unreadable]';
        }
        let safeCode = null;
        try {
          const rawCode = value.code;
          safeCode =
            rawCode !== undefined && rawCode !== null
              ? safeCloneValue(rawCode, ancestors, depth + 1, maxDepth)
              : null;
        } catch {
          safeCode = '[Unreadable]';
        }
        const errObj = {
          name: safeName,
          message: safeMessage,
          code: safeCode,
        };
        try {
          const rawDetails = value.details;
          if (rawDetails !== undefined) {
            errObj.details = safeCloneValue(rawDetails, ancestors, depth + 1, maxDepth);
          }
        } catch {
          errObj.details = '[Unreadable]';
        }
        return errObj;
      } finally {
        ancestors.delete(value);
      }
    }
    if (value instanceof Uint8Array) {
      return { type: 'Uint8Array', byteLength: value.byteLength };
    }

    ancestors.add(value);
    try {
      if (Array.isArray(value)) {
        const out = new Array(value.length);
        for (let i = 0; i < value.length; i++) {
          try {
            out[i] = safeCloneValue(value[i], ancestors, depth + 1, maxDepth);
          } catch {
            out[i] = '[Unreadable]';
          }
        }
        return out;
      }
      if (value instanceof Map) {
        const obj = {};
        for (const [k, v] of value.entries()) {
          const keyStr = safeStringifyKey(k);
          let clonedVal;
          try {
            clonedVal = safeCloneValue(v, ancestors, depth + 1, maxDepth);
          } catch {
            clonedVal = '[Unreadable]';
          }
          Object.defineProperty(obj, keyStr, {
            value: clonedVal,
            enumerable: true,
            configurable: true,
            writable: true,
          });
        }
        return obj;
      }
      if (value instanceof Set) {
        const out = [];
        for (const item of value) {
          try {
            out.push(safeCloneValue(item, ancestors, depth + 1, maxDepth));
          } catch {
            out.push('[Unreadable]');
          }
        }
        return out;
      }
      const out = {};
      for (const key of Object.keys(value)) {
        let clonedVal;
        try {
          clonedVal = safeCloneValue(value[key], ancestors, depth + 1, maxDepth);
        } catch {
          clonedVal = '[Unreadable]';
        }
        Object.defineProperty(out, key, {
          value: clonedVal,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
      return out;
    } finally {
      ancestors.delete(value);
    }
  } catch {
    return '[Unreadable]';
  }
}

function safeJsonStringify(value) {
  try {
    return JSON.stringify(safeCloneValue(value));
  } catch {
    return '{}';
  }
}

function safeJsonParse(raw, fallback = {}) {
  if (typeof raw !== 'string') return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

export class OmniKernel {
  constructor(options = {}) {
    const dbPath =
      typeof options.dbPath === 'string' && options.dbPath.length > 0
        ? options.dbPath
        : typeof options.dataDir === 'string' && options.dataDir.length > 0
          ? path.join(options.dataDir, 'omnios.sqlite')
          : ':memory:';

    const dmesgCapacity =
      Number.isInteger(options.dmesgCapacity) && options.dmesgCapacity >= 1
        ? options.dmesgCapacity
        : 2000;

    this.options = {
      dbPath,
      dataDir: options.dataDir ?? null,
      dmesgCapacity,
      baseQuantum:
        Number.isInteger(options.baseQuantum) && options.baseQuantum >= 1
          ? options.baseQuantum
          : DEFAULT_BASE_QUANTUM,
      tickMs:
        typeof options.tickMs === 'number' && Number.isFinite(options.tickMs) && options.tickMs > 0
          ? options.tickMs
          : DEFAULT_TICK_MS,
      autoStartScheduler: Boolean(options.autoStartScheduler),
      panicDumpWriter: typeof options.panicDumpWriter === 'function' ? options.panicDumpWriter : null,
    };

    this.state = KERNEL_STATES.UNINITIALIZED;
    this.bootReport = null;
    this._bootStartedAt = null;
    this._bootPerfStart = null;
    this._lastPanic = null;
    this._panicHistory = [];
    this._shuttingDown = false;
    this._shutdownDepth = 0;
    this._shutdownGen = 0;
    this._panicGen = 0;

    // Bounded circular dmesg ring buffer
    this._dmesgCapacity = dmesgCapacity;
    this._dmesgRing = new Array(dmesgCapacity);
    this._dmesgHead = 0;
    this._dmesgCount = 0;
    this._dmesgSeq = 0;

    // Pre-boot subsystems immediately available for registration before boot()
    this.eventBus = new KernelEventBus();
    this.cpuRegistry = new CpuRegistry();
    this.syscalls = new SyscallDispatcher({ eventBus: this.eventBus });
    this.processManager = new ProcessManager({
      eventBus: this.eventBus,
      dmesg: (lvl, sub, msg, meta) => this.log(lvl, sub, msg, meta),
    });
    this.scheduler = new Scheduler({
      processManager: this.processManager,
      eventBus: this.eventBus,
      getKernelState: () => this.state,
      log: (lvl, sub, msg, meta) => this.log(lvl, sub, msg, meta),
      baseQuantum: this.options.baseQuantum,
      defaultTickMs: this.options.tickMs,
    });
    this.serviceManager = new ServiceManager({
      eventBus: this.eventBus,
      log: (lvl, sub, msg, meta) => this.log(lvl, sub, msg, meta),
    });
    this.storage = null;
  }

  getUptimeMs() {
    if (this._bootPerfStart === null) return 0;
    return Number((performance.now() - this._bootPerfStart).toFixed(3));
  }

  // ---- Bounded Circular `dmesg` Ring Buffer (F-003) ----

  log(level = 'info', subsystem = 'kernel', message = '', meta = {}) {
    const entry = {
      seq: ++this._dmesgSeq,
      ts: new Date().toISOString(),
      uptimeMs: this.getUptimeMs(),
      level: String(level).toLowerCase(),
      subsystem: String(subsystem),
      message: String(message),
      meta: meta && typeof meta === 'object' ? { ...meta } : {},
    };

    if (this._dmesgCount < this._dmesgCapacity) {
      const writeIdx = (this._dmesgHead + this._dmesgCount) % this._dmesgCapacity;
      this._dmesgRing[writeIdx] = entry;
      this._dmesgCount += 1;
    } else {
      this._dmesgRing[this._dmesgHead] = entry;
      this._dmesgHead = (this._dmesgHead + 1) % this._dmesgCapacity;
    }

    this.eventBus.emit('kernel:dmesg', { ...entry, meta: { ...entry.meta } });
    return { ...entry, meta: { ...entry.meta } };
  }

  dmesg({ limit = 200, subsystem = undefined, level = undefined, sinceSeq = undefined } = {}) {
    const subFilter =
      subsystem === undefined
        ? null
        : Array.isArray(subsystem)
          ? new Set(subsystem.map((s) => String(s)))
          : new Set([String(subsystem)]);

    const lvlFilter =
      level === undefined
        ? null
        : Array.isArray(level)
          ? new Set(level.map((l) => String(l).toLowerCase()))
          : new Set([String(level).toLowerCase()]);

    const hasSince = typeof sinceSeq === 'number' && Number.isFinite(sinceSeq);

    const matched = [];
    for (let i = 0; i < this._dmesgCount; i++) {
      const entry = this._dmesgRing[(this._dmesgHead + i) % this._dmesgCapacity];
      if (!entry) continue;
      if (hasSince && entry.seq <= sinceSeq) continue;
      if (subFilter && !subFilter.has(entry.subsystem)) continue;
      if (lvlFilter && !lvlFilter.has(entry.level)) continue;
      matched.push({ ...entry, meta: { ...entry.meta } });
    }

    const maxEntries = Number.isInteger(limit) && limit >= 0 ? limit : 200;
    if (maxEntries === 0) return [];
    return matched.length <= maxEntries ? matched : matched.slice(-maxEntries);
  }

  // ---- Boot, Shutdown, Panic & Safe Recovery (F-001, F-004, F-005) ----

  async boot({ safeMode = false } = {}) {
    if (this._shuttingDown) {
      throw new OmniOSError('Kernel boot aborted: kernel is shutting down', {
        code: ERROR_CODES.E_KERNEL_NOT_RUNNING,
        details: { state: this.state },
      });
    }
    const bootReport = await runBootSequence(this, { safeMode: Boolean(safeMode) });
    if (
      !this._shuttingDown &&
      this.options.autoStartScheduler &&
      (this.state === KERNEL_STATES.RUNNING || this.state === KERNEL_STATES.SAFE_MODE)
    ) {
      this.scheduler.start(this.options.tickMs);
    }
    return bootReport;
  }

  async shutdown() {
    this._shutdownGen += 1;
    this._shutdownDepth += 1;
    this._shuttingDown = true;
    try {
      this.scheduler.stop();
      this.serviceManager.stopHealthMonitor();

      if (this.state === KERNEL_STATES.STOPPED || this.state === KERNEL_STATES.UNINITIALIZED) {
        if (this.storage?.isOpen) {
          this.storage.close();
        }
        this.state = KERNEL_STATES.STOPPED;
        return;
      }

      await this.serviceManager.stopAll();
      this.processManager.shutdownAll();
      this.log('info', 'kernel', 'Kernel shutting down cleanly');
      this.eventBus.emit('kernel:shutdown', { uptimeMs: this.getUptimeMs() });

      if (this.storage?.isOpen) {
        this.storage.close();
      }
      this.state = KERNEL_STATES.STOPPED;
    } finally {
      this._shutdownDepth -= 1;
      this._shuttingDown = this._shutdownDepth > 0;
    }
  }

  /**
   * Synchronous kernel panic: halts scheduling, transitions to PANIC,
   * and persists a JSON-safe crash dump to SQLite `panic_dumps`.
   */
  panic(code = 'E_KERNEL_PANIC', reason = 'Unhandled kernel panic', context = {}) {
    this._panicGen += 1;
    this.scheduler.stop();
    this.serviceManager.haltForPanic();
    this.state = KERNEL_STATES.PANIC;

    const codeStr = safeStringifyKey(code);
    const reasonStr = safeStringifyKey(reason);
    const ts = new Date().toISOString();
    const uptimeMs = this.getUptimeMs();

    this.log('panic', 'kernel', `KERNEL PANIC [${codeStr}]: ${reasonStr}`, { code: codeStr });

    const safeContext = safeCloneValue(context);
    let safeDiag = {};
    try {
      const rawDiag = this.getDiagnostics();
      // Avoid recursively embedding previous full panic dump diagnostics inside new dump
      safeDiag = safeCloneValue({
        ...rawDiag,
        lastPanic: rawDiag.lastPanic
          ? { id: rawDiag.lastPanic.id, code: rawDiag.lastPanic.code, ts: rawDiag.lastPanic.ts }
          : null,
      });
    } catch {
      safeDiag = { state: this.state, error: 'Failed to collect diagnostics during panic' };
    }

    const panicDump = {
      id: null,
      ts,
      uptimeMs,
      code: codeStr,
      reason: reasonStr,
      context: safeContext,
      diagnostics: safeDiag,
    };

    if (this.storage?.isOpen) {
      try {
        const res = this.storage.run(
          `INSERT INTO panic_dumps (ts, uptime_ms, code, reason, context_json, diagnostics_json)
           VALUES (?, ?, ?, ?, ?, ?)`,
          panicDump.ts,
          panicDump.uptimeMs,
          panicDump.code,
          panicDump.reason,
          safeJsonStringify(panicDump.context),
          safeJsonStringify(panicDump.diagnostics)
        );
        panicDump.id = Number(res.lastInsertRowid);
      } catch {
        // Never crash host Node if SQLite persistence fails during panic.
      }
    }

    if (this.options.panicDumpWriter) {
      try {
        this.options.panicDumpWriter(panicDump);
      } catch {
        // Isolate panic dump writer hook failures.
      }
    }

    this._lastPanic = panicDump;
    this._panicHistory.push(panicDump);
    this.eventBus.emit('kernel:panic', panicDump);

    return panicDump;
  }

  getPanicHistory({ limit = 50 } = {}) {
    const maxRows = Number.isInteger(limit) && limit >= 0 ? limit : 50;
    if (maxRows === 0) return [];

    if (this.storage?.isOpen) {
      try {
        const rows = this.storage.all(
          'SELECT id, ts, uptime_ms, code, reason, context_json, diagnostics_json FROM panic_dumps ORDER BY id DESC LIMIT ?',
          maxRows
        );
        return rows.map((row) => ({
          id: Number(row.id),
          ts: String(row.ts),
          uptimeMs: Number(row.uptime_ms),
          code: String(row.code),
          reason: String(row.reason),
          context: safeJsonParse(row.context_json, {}),
          diagnostics: safeJsonParse(row.diagnostics_json, {}),
        }));
      } catch {
        // Fall back to in-memory history if table does not exist yet.
      }
    }

    return this._panicHistory.slice(-maxRows).reverse();
  }

  async recover({ safeMode = false } = {}) {
    if (this._shuttingDown) {
      this.scheduler.stop();
      throw new OmniOSError('Kernel recovery aborted: kernel is shutting down', {
        code: ERROR_CODES.E_KERNEL_NOT_RUNNING,
        details: { state: this.state },
      });
    }

    const startShutdownGen = this._shutdownGen;
    const startPanicGen = this._panicGen;

    this.log('warn', 'kernel', `Initiating kernel recovery (safeMode=${Boolean(safeMode)})`, {
      safeMode: Boolean(safeMode),
      previousState: this.state,
    });

    this.scheduler.stop();
    await this.serviceManager.stopAll();

    if (
      this._shuttingDown ||
      this._shutdownGen !== startShutdownGen ||
      this.state === KERNEL_STATES.STOPPED
    ) {
      this.scheduler.stop();
      throw new OmniOSError('Kernel recovery aborted by kernel shutdown', {
        code: ERROR_CODES.E_KERNEL_NOT_RUNNING,
        details: { state: this.state },
      });
    }
    if (this._panicGen !== startPanicGen) {
      this.scheduler.stop();
      throw new OmniOSError('Kernel recovery aborted by kernel panic', {
        code: ERROR_CODES.E_KERNEL_PANIC,
        details: { state: this.state, lastPanic: this._lastPanic ?? null },
      });
    }

    this.serviceManager.resetStates();
    this.processManager.reset();

    const bootReport = await runBootSequence(this, { safeMode: Boolean(safeMode) });
    if (
      !this._shuttingDown &&
      this.options.autoStartScheduler &&
      (this.state === KERNEL_STATES.RUNNING || this.state === KERNEL_STATES.SAFE_MODE)
    ) {
      this.scheduler.start(this.options.tickMs);
    }
    if (
      !this._shuttingDown &&
      (this.state === KERNEL_STATES.RUNNING || this.state === KERNEL_STATES.SAFE_MODE)
    ) {
      this.eventBus.emit('kernel:recovered', {
        safeMode: Boolean(safeMode),
        bootReport,
      });
    }
    return bootReport;
  }

  getDiagnostics() {
    const procs = this.processManager.getAll();
    const mem = this.processManager.getAggregateMemoryStats();
    let activeProcessCount = 0;
    for (const p of procs) {
      if (p.state !== PROCESS_STATES.ZOMBIE && p.state !== PROCESS_STATES.TERMINATED) {
        activeProcessCount += 1;
      }
    }

    return {
      state: this.state,
      uptimeMs: this.getUptimeMs(),
      bootReport: this.bootReport,
      services: this.serviceManager.getStatus(),
      processCount: procs.length,
      activeProcessCount,
      scheduler: this.scheduler.getStats(),
      memoryStats: {
        totalMappedPages: mem.totalMappedPages,
        totalUsedBytes: mem.totalUsedBytes,
        totalPeakBytes: mem.totalPeakBytes,
        hostRssBytes: process.memoryUsage().rss,
      },
      dmesgTail: this.dmesg({ limit: 50 }),
      lastPanic: this._lastPanic,
    };
  }
}

export function createKernel(options = {}) {
  return new OmniKernel(options);
}
