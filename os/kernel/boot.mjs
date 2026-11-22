/**
 * OmniOS Deterministic 4-Stage Bootloader & Init (`F-001`)
 * Stages: EARLY_BOOT -> CORE_SUBSYSTEMS -> STORAGE_AND_STATE -> OS_SERVICES -> RUNNING / SAFE_MODE
 */

import { SqliteStorage } from '../common/storage-sqlite.mjs';
import { OmniOSError, SyscallError, ERROR_CODES } from '../common/errors.mjs';

export const BOOT_STAGES = Object.freeze([
  'EARLY_BOOT',
  'CORE_SUBSYSTEMS',
  'STORAGE_AND_STATE',
  'OS_SERVICES',
]);

export const KERNEL_MIGRATIONS = Object.freeze([
  {
    version: 1,
    name: 'init_kernel_meta_and_panic_dumps',
    sql: `
      CREATE TABLE IF NOT EXISTS kernel_meta (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS panic_dumps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        uptime_ms REAL NOT NULL,
        code TEXT NOT NULL,
        reason TEXT NOT NULL,
        context_json TEXT NOT NULL DEFAULT '{}',
        diagnostics_json TEXT NOT NULL DEFAULT '{}'
      );

      CREATE INDEX IF NOT EXISTS idx_panic_dumps_id ON panic_dumps(id DESC);
    `,
  },
]);

function safeJsonParse(raw, fallback = {}) {
  if (typeof raw !== 'string') return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function registerBuiltinSyscalls(kernel) {
  const { syscalls, processManager } = kernel;

  syscalls.register(
    'getpid',
    (ctx) => {
      if (ctx?.pid === null || ctx?.pid === undefined || !processManager.has(ctx.pid)) {
        throw new SyscallError(`Process not found for getpid: ${ctx?.pid}`, {
          code: ERROR_CODES.ESRCH,
          syscall: 'getpid',
          pid: ctx?.pid ?? null,
        });
      }
      return ctx.pid;
    },
    { number: 39, description: 'Return calling process PID' }
  );

  syscalls.register(
    'getppid',
    (ctx) => {
      const pcb = processManager.get(ctx?.pid);
      if (!pcb) {
        throw new SyscallError(`Process not found for getppid: ${ctx?.pid}`, {
          code: ERROR_CODES.ESRCH,
          syscall: 'getppid',
          pid: ctx?.pid ?? null,
        });
      }
      return pcb.ppid;
    },
    { number: 110, description: 'Return calling process parent PID' }
  );

  syscalls.register(
    'uptime',
    () => kernel.getUptimeMs(),
    { number: 1000, description: 'Return kernel uptime in milliseconds' }
  );

  syscalls.register(
    'dmesg',
    (_ctx, opts = {}) => kernel.dmesg(opts),
    { number: 1001, description: 'Read structured kernel dmesg log ring buffer' }
  );

  syscalls.register(
    'yield',
    (ctx) => ({ yielded: true, pid: ctx?.pid ?? null }),
    { number: 24, description: 'Cooperatively yield current execution slice' }
  );

  syscalls.register(
    'exit',
    (ctx, code = 0) => {
      const pcb = processManager.get(ctx?.pid);
      if (!pcb) {
        throw new SyscallError(`Process not found for exit: ${ctx?.pid}`, {
          code: ERROR_CODES.ESRCH,
          syscall: 'exit',
          pid: ctx?.pid ?? null,
        });
      }
      if (pcb.pid === 0 || pcb.pid === 1 || pcb.system) {
        throw new SyscallError(
          `Cannot exit protected system process PID ${pcb.pid} (${pcb.name})`,
          {
            code: ERROR_CODES.EPERM,
            syscall: 'exit',
            pid: pcb.pid,
          }
        );
      }
      const exitCode = Number.isFinite(code) ? Math.trunc(code) : 0;
      processManager.exit(pcb.pid, exitCode);
      return { exited: true, pid: pcb.pid, exitCode };
    },
    { number: 60, description: 'Terminate calling process with exit code' }
  );
}

/**
 * Execute the deterministic 4-stage OmniOS boot sequence on an OmniKernel instance.
 */
export async function runBootSequence(kernel, { safeMode = false } = {}) {
  if (kernel._shuttingDown) {
    kernel.scheduler?.stop();
    throw new OmniOSError('Kernel boot aborted by kernel shutdown', {
      code: ERROR_CODES.E_KERNEL_NOT_RUNNING,
      details: { state: kernel.state },
    });
  }

  const startShutdownGen = kernel._shutdownGen ?? 0;
  const startPanicGen = kernel._panicGen ?? 0;

  const bootPerfStart = performance.now();
  kernel._bootStartedAt = Date.now();
  kernel._bootPerfStart = bootPerfStart;
  kernel.state = 'BOOTING';

  const stages = [];

  const isShutdownAborted = () =>
    kernel._shuttingDown ||
    kernel.state === 'STOPPED' ||
    ((kernel._shutdownGen ?? 0) !== startShutdownGen && kernel.state !== 'PANIC');

  const isPanicAborted = () =>
    kernel.state === 'PANIC' || (kernel._panicGen ?? 0) !== startPanicGen;

  const assertBootNotAborted = () => {
    if (isShutdownAborted()) {
      kernel.scheduler?.stop();
      throw new OmniOSError('Kernel boot aborted by kernel shutdown', {
        code: ERROR_CODES.E_KERNEL_NOT_RUNNING,
        details: { state: kernel.state },
      });
    }
    if (isPanicAborted()) {
      kernel.scheduler?.stop();
      throw new OmniOSError('Kernel boot aborted by kernel panic', {
        code: ERROR_CODES.E_KERNEL_PANIC,
        details: { state: kernel.state, lastPanic: kernel._lastPanic ?? null },
      });
    }
  };

  const runStage = async (name, fn) => {
    assertBootNotAborted();
    const t0 = performance.now();
    try {
      const result = await fn();
      assertBootNotAborted();
      const durationMs = Number((performance.now() - t0).toFixed(3));
      const stageEntry = { name, durationMs, ok: true };
      stages.push(stageEntry);
      kernel.eventBus.emit('kernel:boot_stage', { ...stageEntry, safeMode: Boolean(safeMode) });
      return result;
    } catch (err) {
      const durationMs = Number((performance.now() - t0).toFixed(3));
      const msg = err?.message ? String(err.message) : String(err);
      const stageEntry = { name, durationMs, ok: false, error: msg };
      stages.push(stageEntry);
      kernel.log('error', 'boot', `Boot stage ${name} failed: ${msg}`, { stage: name });
      kernel.eventBus.emit('kernel:boot_stage', { ...stageEntry, safeMode: Boolean(safeMode) });
      const stopped = isShutdownAborted();
      const panicked = isPanicAborted();
      if (!panicked && !stopped) {
        kernel.state = 'BOOT_FAILED';
      }
      kernel.scheduler?.stop();
      if (stopped && err?.code !== ERROR_CODES.E_KERNEL_NOT_RUNNING) {
        throw new OmniOSError('Kernel boot aborted by kernel shutdown', {
          code: ERROR_CODES.E_KERNEL_NOT_RUNNING,
          details: { state: kernel.state },
          cause: err,
        });
      }
      if (panicked && err?.code !== ERROR_CODES.E_KERNEL_PANIC) {
        throw new OmniOSError('Kernel boot aborted by kernel panic', {
          code: ERROR_CODES.E_KERNEL_PANIC,
          details: { state: kernel.state, lastPanic: kernel._lastPanic ?? null },
          cause: err,
        });
      }
      throw err;
    }
  };

  // Stage 1: EARLY_BOOT
  await runStage('EARLY_BOOT', () => {
    kernel.scheduler.stop();
    kernel.processManager.reset();
    kernel.processManager.spawnSystemProcess({
      pid: 0,
      ppid: 0,
      name: 'kernel_idle',
      appId: 'kernel.idle',
      platform: 'kernel',
      arch: 'kernel',
      cwd: '/',
      priority: 19,
      executionContext: null,
    });
    kernel.log(
      'info',
      'boot',
      'EARLY_BOOT complete: EventBus, CpuRegistry, dmesg & PID 0 (kernel_idle) ready'
    );
  });

  // Stage 2: CORE_SUBSYSTEMS
  await runStage('CORE_SUBSYSTEMS', () => {
    registerBuiltinSyscalls(kernel);
    kernel.processManager.spawnSystemProcess({
      pid: 1,
      ppid: 0,
      name: 'omnid',
      appId: 'kernel.init',
      platform: 'kernel',
      arch: 'kernel',
      cwd: '/',
      priority: -20,
      executionContext: null,
    });
    kernel.log(
      'info',
      'boot',
      'CORE_SUBSYSTEMS complete: SyscallDispatcher (6 built-ins), ProcessManager, Scheduler & PID 1 (omnid) ready'
    );
  });

  // Stage 3: STORAGE_AND_STATE
  await runStage('STORAGE_AND_STATE', () => {
    if (!kernel.storage || !kernel.storage.isOpen) {
      kernel.storage = new SqliteStorage(kernel.options.dbPath);
    }
    if (kernel.options.liteMode) {
      kernel.storage.exec(
        'PRAGMA cache_size = -1024; PRAGMA temp_store = MEMORY; PRAGMA wal_autocheckpoint = 200;'
      );
    }
    kernel.storage.migrate('kernel', KERNEL_MIGRATIONS);

    const nowIso = new Date().toISOString();
    const bootCount = kernel.storage.transaction(() => {
      const existing = kernel.storage.get(
        'SELECT value_json FROM kernel_meta WHERE key = ?',
        'boot_count'
      );
      const prevCount = existing ? Number(safeJsonParse(existing.value_json, 0)) || 0 : 0;
      const nextCount = prevCount + 1;
      kernel.storage.run(
        `INSERT INTO kernel_meta (key, value_json, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
        'boot_count',
        JSON.stringify(nextCount),
        nowIso
      );
      kernel.storage.run(
        `INSERT INTO kernel_meta (key, value_json, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
        'last_boot',
        JSON.stringify({
          ts: nowIso,
          safeMode: Boolean(safeMode),
          bootCount: nextCount,
          nodeVersion: process.version,
        }),
        nowIso
      );
      return nextCount;
    });

    // Hydrate historical panic dump from SQLite so fresh instances surface lastPanic
    const latestPanicRow = kernel.storage.get(
      'SELECT id, ts, uptime_ms, code, reason, context_json, diagnostics_json FROM panic_dumps ORDER BY id DESC LIMIT 1'
    );
    if (latestPanicRow) {
      kernel._lastPanic = {
        id: Number(latestPanicRow.id),
        ts: String(latestPanicRow.ts),
        uptimeMs: Number(latestPanicRow.uptime_ms),
        code: String(latestPanicRow.code),
        reason: String(latestPanicRow.reason),
        context: safeJsonParse(latestPanicRow.context_json, {}),
        diagnostics: safeJsonParse(latestPanicRow.diagnostics_json, {}),
      };
    }

    const mode = kernel.storage.getJournalMode();
    kernel.log(
      'info',
      'boot',
      `STORAGE_AND_STATE complete: SQLite ready (mode=${mode}, bootCount=${bootCount})`,
      { journalMode: mode, bootCount }
    );
  });

  // Stage 4: OS_SERVICES
  await runStage('OS_SERVICES', async () => {
    const svcResult = await kernel.serviceManager.startAll({ safeMode: Boolean(safeMode) });
    assertBootNotAborted();
    kernel.log('info', 'boot', 'OS_SERVICES complete', {
      started: svcResult.started,
      skipped: svcResult.skipped,
      failed: svcResult.failed,
      safeMode: Boolean(safeMode),
    });
    return svcResult;
  });

  assertBootNotAborted();

  const bootMs = Number((performance.now() - bootPerfStart).toFixed(3));
  const status = safeMode ? 'SAFE_MODE' : 'RUNNING';
  kernel.state = status;

  const bootReport = {
    status,
    stages,
    bootMs,
    safeMode: Boolean(safeMode),
    bootedAt: new Date().toISOString(),
  };
  kernel.bootReport = bootReport;
  kernel.eventBus.emit('kernel:booted', bootReport);

  return bootReport;
}
