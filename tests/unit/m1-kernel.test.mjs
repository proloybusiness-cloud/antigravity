import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';

import {
  ERROR_CODES,
  POSIX_ERRNO,
  DARWIN_ERRNO,
  WIN32_ERROR,
  WASI_ERRNO,
  SIGNALS,
  SIGNAL_NAMES,
  OmniOSError,
  MemoryFaultError,
  IllegalInstructionError,
  UnsupportedOpcodeError,
  QuotaExceededError,
  SyscallError,
  VfsError,
  FormatError,
  SecurityError,
  KernelPanicError,
  UnresolvedImportError,
  ProcessError,
  ServiceError,
  isOmniOSError,
  resolveSignal,
  posixCodeToDarwinErrno,
  posixCodeToWin32,
  posixCodeToWasi,
} from '../../os/common/errors.mjs';

import {
  BinaryReader,
  BinaryWriter,
  crc32,
  adler32,
  encodeUleb128,
  decodeUleb128,
  encodeSleb128,
  decodeSleb128,
  encodeUleb128p1,
  decodeUleb128p1,
  encodeMutf8,
  decodeMutf8,
  decodeMutf8Z,
} from '../../os/common/binary.mjs';

import { SqliteStorage, openSqliteStorage } from '../../os/common/storage-sqlite.mjs';
import { CpuRegistry, SUPPORTED_ARCHS } from '../../os/cpu/registry.mjs';
import { KernelEventBus } from '../../os/kernel/event-bus.mjs';
import { SyscallDispatcher } from '../../os/kernel/syscalls.mjs';
import {
  AddressSpace,
  createAddressSpace,
  PAGE_SIZE,
  PROT_NONE,
  PROT_READ,
  PROT_WRITE,
  PROT_EXEC,
  HEAP_ALIGNMENT,
  HIGH_VA_HEAP_BASE,
  MAX_VA,
} from '../../os/kernel/vmm.mjs';
import {
  ProcessManager,
  ProcessStreamBuffer,
  PROCESS_STATES,
  THREAD_STATES,
} from '../../os/kernel/process.mjs';
import { Scheduler } from '../../os/kernel/scheduler.mjs';
import { ServiceManager, SERVICE_STATES, ServiceError as ReExportedServiceError } from '../../os/kernel/services.mjs';
import { BOOT_STAGES } from '../../os/kernel/boot.mjs';
import { OmniKernel, createKernel, KERNEL_STATES } from '../../os/kernel/kernel.mjs';

const tempDirs = [];
function makeTempDir(prefix = 'omnios-m1-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

after(() => {
  for (const dir of tempDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Helper creating deterministic ExecutionContexts with real step-budget consumption
function makeWorkContext({ totalWork = 100, exitCode = 0, onStep = null, onDispose = null } = {}) {
  let remaining = totalWork;
  let disposed = 0;
  return {
    get remaining() { return remaining; },
    get disposeCount() { return disposed; },
    step(budget) {
      if (onStep) {
        const custom = onStep(budget, remaining);
        if (custom) return custom;
      }
      const run = Math.min(budget, remaining);
      remaining -= run;
      if (remaining <= 0) {
        return { status: 'EXITED', instructionsExecuted: run, exitCode };
      }
      return { status: 'YIELD', instructionsExecuted: run };
    },
    deliverEvent() {},
    getDebugState() {
      return { arch: 'test', pc: totalWork - remaining, sp: 0, registers: {}, instructionsExecuted: totalWork - remaining };
    },
    dispose() {
      disposed += 1;
      onDispose?.();
    },
  };
}

// ============================================================================
// Suite 1: F-001 — 4-Stage Bootloader & Init
// ============================================================================
describe('F-001: 4-Stage Bootloader & Init', () => {
  it('1.1 boots deterministically through all 4 stages with exact order and timings', async () => {
    const kernel = createKernel();
    const observedStages = [];
    kernel.eventBus.on('kernel:boot_stage', (s) => observedStages.push(s.name));

    const report = await kernel.boot();
    assert.equal(report.status, KERNEL_STATES.RUNNING);
    assert.equal(report.safeMode, false);
    assert.equal(typeof report.bootMs, 'number');
    assert.ok(report.bootMs >= 0);
    assert.equal(typeof report.bootedAt, 'string');
    assert.deepStrictEqual(
      report.stages.map((s) => s.name),
      ['EARLY_BOOT', 'CORE_SUBSYSTEMS', 'STORAGE_AND_STATE', 'OS_SERVICES']
    );
    assert.deepStrictEqual(observedStages, Array.from(BOOT_STAGES));
    for (const stage of report.stages) {
      assert.equal(stage.ok, true);
      assert.ok(typeof stage.durationMs === 'number' && stage.durationMs >= 0);
    }
    await kernel.shutdown();
    assert.equal(kernel.state, KERNEL_STATES.STOPPED);
  });

  it('1.2 creates PID 0 (kernel_idle) and PID 1 (omnid), allocating user PIDs from 2', async () => {
    const kernel = createKernel();
    await kernel.boot();

    const pid0 = kernel.processManager.get(0);
    const pid1 = kernel.processManager.get(1);
    assert.ok(pid0);
    assert.ok(pid1);
    assert.equal(pid0.name, 'kernel_idle');
    assert.equal(pid0.ppid, 0);
    assert.equal(pid0.system, true);
    assert.equal(pid1.name, 'omnid');
    assert.equal(pid1.ppid, 0);
    assert.equal(pid1.system, true);

    const user = kernel.processManager.spawn({ name: 'hello-app' });
    assert.equal(user.pid, 2);
    assert.equal(user.ppid, 1);

    await kernel.shutdown();
  });

  it('1.3 wires all 6 built-in kernel syscalls at boot', async () => {
    const kernel = createKernel();
    await kernel.boot();

    const p = kernel.processManager.spawn({ name: 'sys-tester' });
    assert.equal(kernel.syscalls.dispatch('getpid', p), p.pid);
    assert.equal(kernel.syscalls.dispatch('getppid', p), 1);
    assert.ok(kernel.syscalls.dispatch('uptime', p) >= 0);
    assert.ok(Array.isArray(kernel.syscalls.dispatch('dmesg', p, { limit: 10 })));
    assert.deepStrictEqual(kernel.syscalls.dispatch('yield', p), { yielded: true, pid: p.pid });
    assert.equal(p.stats.syscallsCount, 5);

    const exitRes = kernel.syscalls.dispatch('exit', p, 42);
    assert.deepStrictEqual(exitRes, { exited: true, pid: p.pid, exitCode: 42 });
    assert.equal(p.state, PROCESS_STATES.ZOMBIE);
    assert.equal(p.stats.exitCode, 42);

    await kernel.shutdown();
  });

  it('1.4 persists incrementing boot_count across file-backed reboots', async () => {
    const dir = makeTempDir('omnios-boot-');
    const dbPath = path.join(dir, 'kernel.sqlite');

    const k1 = createKernel({ dbPath });
    await k1.boot();
    assert.equal(k1.storage.getJournalMode(), 'wal');
    const row1 = k1.storage.get('SELECT value_json FROM kernel_meta WHERE key = ?', 'boot_count');
    assert.equal(JSON.parse(row1.value_json), 1);
    await k1.shutdown();

    const k2 = createKernel({ dbPath });
    await k2.boot();
    const row2 = k2.storage.get('SELECT value_json FROM kernel_meta WHERE key = ?', 'boot_count');
    assert.equal(JSON.parse(row2.value_json), 2);
    await k2.shutdown();
  });
});

// ============================================================================
// Suite 2: F-002 — Systemd-like ServiceManager
// ============================================================================
describe('F-002: Systemd-like ServiceManager', () => {
  it('2.1 starts services in topological dependency order and stops in reverse order', async () => {
    const sm = new ServiceManager();
    const startLog = [];
    const stopLog = [];

    // Register out of order on purpose
    sm.register({
      name: 'compositord',
      deps: ['configd', 'ipc-brokerd'],
      start: async () => startLog.push('compositord'),
      stop: async () => stopLog.push('compositord'),
    });
    sm.register({
      name: 'ipc-brokerd',
      deps: ['vfsd'],
      start: async () => startLog.push('ipc-brokerd'),
      stop: async () => stopLog.push('ipc-brokerd'),
    });
    sm.register({
      name: 'configd',
      deps: ['vfsd'],
      start: async () => startLog.push('configd'),
      stop: async () => stopLog.push('configd'),
    });
    sm.register({
      name: 'vfsd',
      deps: [],
      start: async () => startLog.push('vfsd'),
      stop: async () => stopLog.push('vfsd'),
    });

    const res = await sm.startAll();
    assert.equal(res.started.length, 4);
    assert.equal(startLog[0], 'vfsd');
    assert.equal(startLog[3], 'compositord');
    assert.ok(startLog.indexOf('vfsd') < startLog.indexOf('configd'));
    assert.ok(startLog.indexOf('vfsd') < startLog.indexOf('ipc-brokerd'));

    await sm.stopAll();
    assert.equal(stopLog[0], 'compositord');
    assert.equal(stopLog[3], 'vfsd');
  });

  it('2.2 detects self-cycles, 2-node cycles, and multi-hop cycles with exact cycle path', async () => {
    assert.equal(ReExportedServiceError, ServiceError);

    // Self-cycle A -> A
    const sm1 = new ServiceManager();
    sm1.register({ name: 'A', deps: ['A'], start: async () => {} });
    await assert.rejects(
      () => sm1.startAll(),
      (err) => err instanceof ServiceError && err.code === ERROR_CODES.E_SERVICE_CYCLE && JSON.stringify(err.cycle) === JSON.stringify(['A', 'A'])
    );

    // 2-cycle A -> B -> A
    const sm2 = new ServiceManager();
    sm2.register({ name: 'A', deps: ['B'], start: async () => {} });
    sm2.register({ name: 'B', deps: ['A'], start: async () => {} });
    await assert.rejects(
      () => sm2.startAll(),
      (err) => err instanceof ServiceError && err.code === ERROR_CODES.E_SERVICE_CYCLE && err.cycle.length === 3 && err.cycle[0] === err.cycle[2]
    );

    // Multi-hop A -> B -> C -> A
    const sm3 = new ServiceManager();
    sm3.register({ name: 'A', deps: ['B'], start: async () => {} });
    sm3.register({ name: 'B', deps: ['C'], start: async () => {} });
    sm3.register({ name: 'C', deps: ['A'], start: async () => {} });
    await assert.rejects(
      () => sm3.startAll(),
      (err) => err instanceof ServiceError && err.code === ERROR_CODES.E_SERVICE_CYCLE && err.cycle.length === 4 && err.details.cycle.length === 4
    );
  });

  it('2.3 rejects missing dependencies, duplicate names, and invalid registrations', async () => {
    const sm = new ServiceManager();
    sm.register({ name: 'pkgd', deps: ['nonexistent'], start: async () => {} });

    await assert.rejects(
      () => sm.startAll(),
      (err) => err instanceof ServiceError && err.code === ERROR_CODES.E_SERVICE_MISSING_DEP && err.missingDep === 'nonexistent'
    );

    assert.throws(
      () => sm.register({ name: 'pkgd', start: async () => {} }),
      (err) => err instanceof ServiceError && err.code === ERROR_CODES.E_SERVICE_EXISTS
    );
    assert.throws(
      () => sm.register({ name: '', start: async () => {} }),
      (err) => err instanceof ServiceError && err.code === ERROR_CODES.E_SERVICE_INVALID
    );
  });

  it('2.4 performs health probes and crash restarts with exponential backoff up to maxRestarts', async () => {
    const bus = new KernelEventBus();
    const sm = new ServiceManager({ eventBus: bus });

    // (a) Single unhealthy probe (returns false) -> restarts once and recovers
    let recoverableStarts = 0;
    let recoverableHealthy = true;
    sm.register({
      name: 'recoverable',
      maxRestarts: 3,
      restartBackoffMs: 15,
      start: async () => {
        recoverableStarts += 1;
        recoverableHealthy = true;
      },
      healthCheck: async () => recoverableHealthy,
    });

    await sm.start('recoverable');
    assert.equal(recoverableStarts, 1);

    recoverableHealthy = false;
    const h1 = await sm.checkHealth('recoverable');
    assert.equal(h1.healthy, false);
    assert.equal(h1.state, SERVICE_STATES.RUNNING);
    assert.equal(h1.restarts, 1);
    const st1 = sm.getStatus('recoverable');
    assert.ok(st1.lastRestartAt !== null);
    assert.deepStrictEqual(st1.backoffHistory, [15]);

    // (b) Permanently failing start after thrown healthCheck -> [15, 30, 60] backoff -> FAILED
    let allowStart = true;
    sm.register({
      name: 'doomed',
      maxRestarts: 3,
      restartBackoffMs: 15,
      start: async () => {
        if (!allowStart) throw new Error('persistent start crash');
      },
      healthCheck: async () => {
        throw new Error('probe failed');
      },
    });

    await sm.start('doomed');
    allowStart = false;
    const t0 = performance.now();
    const h2 = await sm.checkHealth('doomed');
    const elapsed = performance.now() - t0;

    assert.equal(h2.healthy, false);
    assert.equal(h2.state, SERVICE_STATES.FAILED);
    assert.equal(h2.restarts, 3);
    assert.ok(elapsed >= 90, `Expected exponential backoff >= 90ms, got ${elapsed.toFixed(1)}ms`);

    const st2 = sm.getStatus('doomed');
    assert.deepStrictEqual(st2.backoffHistory, [15, 30, 60]);
    assert.match(st2.lastError, /persistent start crash/);

    // Manual restart recovers FAILED service once fixed
    allowStart = true;
    const recovered = await sm.restart('doomed');
    assert.equal(recovered.state, SERVICE_STATES.RUNNING);
    assert.equal(recovered.restarts, 0);

    await sm.stopAll();
  });

  it('2.5 runs .unref() background health monitor and detects unhealthy service', async () => {
    const sm = new ServiceManager();
    let healthy = true;
    let starts = 0;
    sm.register({
      name: 'monitored',
      maxRestarts: 2,
      restartBackoffMs: 10,
      start: async () => {
        starts += 1;
        healthy = true;
      },
      healthCheck: async () => healthy,
    });
    await sm.start('monitored');
    sm.startHealthMonitor(20);
    healthy = false;

    await new Promise((resolve) => setTimeout(resolve, 80));
    await sm.stopAll();
    assert.ok(starts >= 2, `Expected background health monitor to trigger restart, starts=${starts}`);
  });
});

// ============================================================================
// Suite 3: F-003 — Kernel dmesg Ring Buffer
// ============================================================================
describe('F-003: Kernel dmesg Ring Buffer', () => {
  it('3.1 records structured entries with monotonic seq, bounded eviction, and subsystem/level/limit filters', () => {
    const kernel = createKernel({ dmesgCapacity: 10 });
    for (let i = 1; i <= 25; i++) {
      const sub = i % 2 === 0 ? 'vmm' : 'scheduler';
      const lvl = i % 5 === 0 ? 'error' : i % 3 === 0 ? 'warn' : 'info';
      kernel.log(lvl, sub, `msg-${i}`, { idx: i });
    }

    const all = kernel.dmesg({ limit: 200 });
    assert.equal(all.length, 10);
    assert.equal(all[0].seq, 16);
    assert.equal(all[9].seq, 25);
    assert.equal(all[9].message, 'msg-25');
    assert.equal(all[9].meta.idx, 25);
    assert.equal(typeof all[0].ts, 'string');
    assert.equal(typeof all[0].uptimeMs, 'number');

    const vmmOnly = kernel.dmesg({ subsystem: 'vmm' });
    assert.ok(vmmOnly.length > 0);
    assert.ok(vmmOnly.every((e) => e.subsystem === 'vmm'));

    const errorsOnly = kernel.dmesg({ level: 'ERROR' });
    assert.deepStrictEqual(errorsOnly.map((e) => e.seq), [20, 25]);

    const limited = kernel.dmesg({ subsystem: 'scheduler', limit: 2 });
    assert.equal(limited.length, 2);
    assert.equal(limited[1].seq, 25);

    const since = kernel.dmesg({ sinceSeq: 22 });
    assert.deepStrictEqual(since.map((e) => e.seq), [23, 24, 25]);
  });
});

// ============================================================================
// Suite 4: F-004 — Kernel Panic (SQLite Persistence) & Safe Recovery
// ============================================================================
describe('F-004: Kernel Panic & Safe Recovery', () => {
  it('4.1 panic() halts scheduling, safely serializes BigInt/circular context, and persists across reopen', async () => {
    const dir = makeTempDir('omnios-panic-');
    const dbPath = path.join(dir, 'panic.sqlite');

    let writerCaptured = null;
    const k1 = createKernel({
      dbPath,
      panicDumpWriter: (dump) => {
        writerCaptured = dump;
      },
    });
    await k1.boot();

    const ctx = makeWorkContext({ totalWork: 1000 });
    const pcb = k1.processManager.spawn({ name: 'worker', executionContext: ctx });
    k1.scheduler.start(10);
    assert.equal(k1.scheduler.isRunning(), true);

    const circular = { regX0: 0xdeadbeef12345678n, tag: 'hw-fault' };
    circular.self = circular;

    const dump = k1.panic('E_HW_FAULT', 'Simulated bus error', circular);
    assert.equal(k1.state, KERNEL_STATES.PANIC);
    assert.equal(k1.scheduler.isRunning(), false);
    assert.equal(dump.code, 'E_HW_FAULT');
    assert.ok(typeof dump.id === 'number' && dump.id >= 1);
    assert.equal(dump.context.regX0, '16045690981402826360');
    assert.equal(dump.context.self, '[Circular]');
    assert.equal(writerCaptured.id, dump.id);

    // Scheduler MUST refuse to execute user processes while panicked
    const beforeInsns = pcb.stats.instructionsExecuted;
    const stepRes = k1.scheduler.step(5);
    assert.deepStrictEqual(stepRes, { ticksRun: 0, instructionsExecuted: 0, activePids: [] });
    assert.equal(pcb.stats.instructionsExecuted, beforeInsns);

    await k1.shutdown();

    // Brand-new kernel instance on same dbPath MUST hydrate lastPanic & history
    const k2 = createKernel({ dbPath });
    await k2.boot();
    const diag2 = k2.getDiagnostics();
    assert.ok(diag2.lastPanic !== null);
    assert.equal(diag2.lastPanic.code, 'E_HW_FAULT');
    assert.equal(diag2.lastPanic.reason, 'Simulated bus error');
    assert.equal(diag2.lastPanic.context.regX0, '16045690981402826360');
    const history = k2.getPanicHistory();
    assert.equal(history.length, 1);
    assert.equal(history[0].code, 'E_HW_FAULT');

    await k2.shutdown();
  });

  it('4.2 recover({ safeMode: true }) cleanly skips non-essential broken services and reboots', async () => {
    const dir = makeTempDir('omnios-recover-');
    const dbPath = path.join(dir, 'recover.sqlite');

    const kernel = createKernel({ dbPath });
    let failFlaky = false;

    kernel.serviceManager.register({
      name: 'vfsd',
      essential: true,
      start: async () => {},
    });
    kernel.serviceManager.register({
      name: 'flaky-ui',
      deps: ['vfsd'],
      essential: false,
      start: async () => {
        if (failFlaky) throw new Error('UI GPU driver corrupted');
      },
    });

    await kernel.boot();
    const stale = kernel.processManager.spawn({ name: 'stale-user', executionContext: makeWorkContext() });
    assert.equal(stale.pid, 2);

    failFlaky = true;
    kernel.panic('E_GPU_HANG', 'Compositor crashed');
    assert.equal(kernel.state, KERNEL_STATES.PANIC);

    const safeReport = await kernel.recover({ safeMode: true });
    assert.equal(safeReport.status, KERNEL_STATES.SAFE_MODE);
    assert.equal(safeReport.safeMode, true);
    assert.equal(kernel.state, KERNEL_STATES.SAFE_MODE);
    assert.equal(kernel.serviceManager.getStatus('vfsd').state, SERVICE_STATES.RUNNING);
    assert.equal(kernel.serviceManager.getStatus('flaky-ui').state, SERVICE_STATES.STOPPED);
    // Stale user process purged, PID 0 & 1 freshly recreated, lastPanic preserved
    assert.equal(kernel.processManager.get(2), null);
    assert.ok(kernel.processManager.get(0));
    assert.ok(kernel.processManager.get(1));
    assert.equal(kernel.getDiagnostics().lastPanic.code, 'E_GPU_HANG');

    // Recovering normally once flaky-ui is repaired returns to RUNNING
    failFlaky = false;
    const normalReport = await kernel.recover({ safeMode: false });
    assert.equal(normalReport.status, KERNEL_STATES.RUNNING);
    assert.equal(kernel.serviceManager.getStatus('flaky-ui').state, SERVICE_STATES.RUNNING);

    await kernel.shutdown();
  });
});

// ============================================================================
// Suite 5: F-005 — Runtime Diagnostics Snapshot
// ============================================================================
describe('F-005: Runtime Diagnostics Snapshot', () => {
  it('5.1 returns complete structured diagnostics snapshot including VMM stats and dmesgTail', async () => {
    const kernel = createKernel();
    kernel.serviceManager.register({ name: 'vfsd', essential: true, start: async () => {} });
    await kernel.boot();

    const p = kernel.processManager.spawn({ name: 'mem-user' });
    p.addressSpace.mmap(0x00400000, 8192, PROT_READ | PROT_WRITE, 'buf');

    const diag = kernel.getDiagnostics();
    assert.equal(diag.state, KERNEL_STATES.RUNNING);
    assert.ok(diag.uptimeMs >= 0);
    assert.equal(diag.bootReport.status, 'RUNNING');
    assert.equal(diag.services.length, 1);
    assert.equal(diag.services[0].name, 'vfsd');
    assert.equal(diag.processCount, 3);
    assert.equal(diag.activeProcessCount, 3);
    assert.equal(diag.memoryStats.totalMappedPages, 2);
    assert.equal(diag.memoryStats.totalUsedBytes, 8192);
    assert.equal(diag.memoryStats.totalPeakBytes, 8192);
    assert.ok(diag.memoryStats.hostRssBytes > 0);
    assert.ok(Array.isArray(diag.dmesgTail) && diag.dmesgTail.length > 0);
    assert.equal(diag.lastPanic, null);

    await kernel.shutdown();
  });
});

// ============================================================================
// Suite 6: F-006 — PCB Lifecycle, Strict FSM, Tree & Orphan Reparenting
// ============================================================================
describe('F-006: PCB Lifecycle, Strict FSM, Tree & Orphan Reparenting', () => {
  it('6.1 enforces valid FSM transitions and rejects illegal transitions', () => {
    const pm = new ProcessManager();
    const pcb = pm.spawn({ name: 'fsm-proc', autoReady: false });
    assert.equal(pcb.state, PROCESS_STATES.CREATED);

    // Illegal: CREATED -> RUNNING directly
    assert.throws(
      () => pm.transitionState(pcb.pid, PROCESS_STATES.RUNNING),
      (err) => err instanceof ProcessError && err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
    );

    pm.transitionState(pcb.pid, PROCESS_STATES.READY);
    pm.setState(pcb.pid, PROCESS_STATES.RUNNING);
    pm.transitionState(pcb.pid, PROCESS_STATES.BLOCKED);
    pm.transitionState(pcb.pid, PROCESS_STATES.READY);
    pm.transitionState(pcb.pid, PROCESS_STATES.STOPPED);

    // Illegal: STOPPED -> RUNNING directly
    assert.throws(
      () => pm.transitionState(pcb.pid, PROCESS_STATES.RUNNING),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );

    pm.transitionState(pcb.pid, PROCESS_STATES.READY);
    pm.transitionState(pcb.pid, PROCESS_STATES.RUNNING);
    pm.exit(pcb.pid, 0);
    assert.equal(pcb.state, PROCESS_STATES.ZOMBIE);

    // Illegal: ZOMBIE -> READY
    assert.throws(
      () => pm.transitionState(pcb.pid, PROCESS_STATES.READY),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );

    pm.reap(pcb.pid);
    assert.equal(pcb.state, PROCESS_STATES.TERMINATED);

    // Illegal: TERMINATED -> READY
    assert.throws(
      () => pm.transitionState(pcb.pid, PROCESS_STATES.READY),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );
  });

  it('6.2 reparents orphaned children to PID 1 (omnid) and builds accurate process tree', () => {
    const bus = new KernelEventBus();
    const reparented = [];
    bus.on('process:reparented', (e) => reparented.push(e));

    const pm = new ProcessManager({ eventBus: bus });
    pm.spawnSystemProcess({ pid: 0, ppid: 0, name: 'kernel_idle' });
    pm.spawnSystemProcess({ pid: 1, ppid: 0, name: 'omnid' });

    const parent = pm.spawn({ name: 'parent', ppid: 1 });
    const child1 = pm.spawn({ name: 'child1', ppid: parent.pid });
    const child2 = pm.spawn({ name: 'child2', ppid: parent.pid });
    const grandchild = pm.spawn({ name: 'grandchild', ppid: child2.pid });

    pm.exit(parent.pid, 0);

    assert.equal(child1.ppid, 1);
    assert.equal(child2.ppid, 1);
    assert.equal(grandchild.ppid, child2.pid);
    assert.equal(reparented.length, 2);
    assert.deepStrictEqual(
      reparented.map((r) => ({ pid: r.pid, oldPpid: r.oldPpid, newPpid: r.newPpid })),
      [
        { pid: child1.pid, oldPpid: parent.pid, newPpid: 1 },
        { pid: child2.pid, oldPpid: parent.pid, newPpid: 1 },
      ]
    );

    const tree = pm.getTree();
    assert.equal(tree.length, 1); // PID 0 root
    const omnidNode = tree[0].children.find((c) => c.pid === 1);
    assert.ok(omnidNode);
    const c2Node = omnidNode.children.find((c) => c.pid === child2.pid);
    assert.ok(c2Node);
    assert.equal(c2Node.children[0].pid, grandchild.pid);
  });
});

// ============================================================================
// Suite 7: F-007 — Multi-Thread TCB Support
// ============================================================================
describe('F-007: Multi-Thread TCB Support', () => {
  it('7.1 executes independent threads, blocks/wakes worker without stalling main, and disposes cleanly', () => {
    const pm = new ProcessManager();
    const scheduler = new Scheduler({ processManager: pm, baseQuantum: 50 });

    const mainCtx = makeWorkContext({ totalWork: 150, exitCode: 0 });
    let workerBlockedOnce = false;
    const workerCtx = makeWorkContext({
      totalWork: 100,
      exitCode: 0,
      onStep(budget, remaining) {
        if (!workerBlockedOnce && remaining === 100) {
          workerBlockedOnce = true;
          return { status: 'BLOCKED', instructionsExecuted: 10, waitReason: 'mutex' };
        }
        return null;
      },
    });

    const pcb = pm.spawn({
      name: 'mt-app',
      executionContext: mainCtx,
      registers: { r0: 1 },
    });
    const t2 = pm.createThread(pcb.pid, {
      name: 'worker-1',
      executionContext: workerCtx,
      registers: { r0: 99 },
    });

    assert.equal(pcb.threads.size, 2);
    assert.equal(pcb.threads.get(1).registers.r0, 1);
    assert.equal(t2.registers.r0, 99);

    // Tick 1: main runs 50 (100 left), worker runs 10 and blocks
    scheduler.step(1);
    assert.equal(pcb.state, PROCESS_STATES.READY);
    assert.equal(t2.state, THREAD_STATES.BLOCKED);
    assert.equal(pcb.threads.get(1).stats.instructionsExecuted, 50);
    assert.equal(t2.stats.instructionsExecuted, 10);

    // Tick 2: main runs 50 (50 left), worker stays blocked
    scheduler.step(1);
    assert.equal(pcb.threads.get(1).stats.instructionsExecuted, 100);
    assert.equal(t2.stats.instructionsExecuted, 10);

    // Wake worker -> both threads progress; worker finishes first while process stays alive
    assert.equal(scheduler.wake(pcb.pid, t2.tid), true);
    assert.equal(t2.state, THREAD_STATES.READY);

    // Run until worker finishes (needs 2 ticks of 50) while main finishes in 1 tick -> test worker exit first
    // Let's also test explicit worker-first exit on a dedicated process
    const mainCtx2 = makeWorkContext({ totalWork: 200 });
    const workerCtx2 = makeWorkContext({ totalWork: 40 });
    const pcb2 = pm.spawn({ name: 'mt-exit-order', executionContext: mainCtx2 });
    const w2 = pm.createThread(pcb2.pid, { name: 'short-worker', executionContext: workerCtx2 });

    scheduler.step(1); // main 50/200, worker 40/40 -> worker EXITED, process STILL ALIVE!
    assert.equal(w2.state, THREAD_STATES.EXITED);
    assert.equal(workerCtx2.disposeCount, 1);
    assert.equal(pcb2.state, PROCESS_STATES.READY);

    const summary = scheduler.runUntilIdle(pcb2.pid, 20);
    assert.equal(summary.state, PROCESS_STATES.ZOMBIE);
    assert.equal(summary.exitCode, 0);
    assert.equal(mainCtx2.disposeCount, 1);
    assert.equal(workerCtx2.disposeCount, 1); // disposed exactly once!
  });
});

// ============================================================================
// Suite 8: F-008 — Preemptive / Cooperative Priority Round-Robin Scheduler
// ============================================================================
describe('F-008: Preemptive / Cooperative Priority Round-Robin Scheduler', () => {
  it('8.1 weights quanta by priority without starving nice +19', () => {
    const pm = new ProcessManager();
    const scheduler = new Scheduler({ processManager: pm, baseQuantum: 100 });

    const pHigh = pm.spawn({ name: 'high', priority: -10, executionContext: makeWorkContext({ totalWork: 5000 }) });
    const pNorm = pm.spawn({ name: 'normal', priority: 0, executionContext: makeWorkContext({ totalWork: 5000 }) });
    const pLow = pm.spawn({ name: 'low', priority: 10, executionContext: makeWorkContext({ totalWork: 5000 }) });
    const pLowest = pm.spawn({ name: 'lowest', priority: 19, executionContext: makeWorkContext({ totalWork: 5000 }) });

    const res = scheduler.step(3);
    assert.equal(res.ticksRun, 3);
    assert.equal(res.activePids.length, 4);

    assert.ok(pHigh.stats.instructionsExecuted > pNorm.stats.instructionsExecuted);
    assert.ok(pNorm.stats.instructionsExecuted > pLow.stats.instructionsExecuted);
    assert.ok(pLow.stats.instructionsExecuted > pLowest.stats.instructionsExecuted);
    assert.ok(pLowest.stats.instructionsExecuted > 0, 'nice +19 process must never starve');
  });

  it('8.2 rotates equal-priority processes in fair round-robin order', () => {
    const pm = new ProcessManager();
    const scheduler = new Scheduler({ processManager: pm, baseQuantum: 10 });
    const order = [];

    const makeLoggerCtx = (tag) => ({
      step(budget) {
        order.push(tag);
        return { status: 'YIELD', instructionsExecuted: budget };
      },
      dispose() {},
    });

    pm.spawn({ name: 'A', priority: 0, executionContext: makeLoggerCtx('A') });
    pm.spawn({ name: 'B', priority: 0, executionContext: makeLoggerCtx('B') });
    pm.spawn({ name: 'C', priority: 0, executionContext: makeLoggerCtx('C') });

    scheduler.step(3);
    assert.deepStrictEqual(order, ['A', 'B', 'C', 'B', 'C', 'A', 'C', 'A', 'B']);
  });

  it('8.3 drives processes via runUntilIdle and respects in-step exit syscalls without clobbering state', async () => {
    const kernel = createKernel({ baseQuantum: 50 });
    await kernel.boot();

    const p = kernel.processManager.spawn({
      name: 'syscall-exit',
      executionContext: {
        step() {
          kernel.syscalls.dispatch('exit', p, 7);
          // Even if buggy runtime still returns YIELD after exit syscall, scheduler must NOT overwrite ZOMBIE
          return { status: 'YIELD', instructionsExecuted: 5 };
        },
        dispose() {},
      },
    });

    const summary = kernel.scheduler.runUntilIdle(p.pid, 10);
    assert.equal(summary.state, PROCESS_STATES.ZOMBIE);
    assert.equal(summary.exitCode, 7);

    await kernel.shutdown();
  });

  it('8.4 runs real .unref() timer ticks via start()/stop() and skips BLOCKED/STOPPED tasks', async () => {
    const pm = new ProcessManager();
    const scheduler = new Scheduler({ processManager: pm, baseQuantum: 50 });

    const active = pm.spawn({ name: 'timed', executionContext: makeWorkContext({ totalWork: 200, exitCode: 3 }) });
    const stopped = pm.spawn({ name: 'paused', executionContext: makeWorkContext({ totalWork: 200 }) });
    pm.kill(stopped.pid, 'SIGSTOP');

    assert.equal(scheduler.start(10), true);
    assert.equal(scheduler.isRunning(), true);

    const deadline = Date.now() + 500;
    while (active.state !== PROCESS_STATES.ZOMBIE && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 15));
    }

    scheduler.stop();
    assert.equal(scheduler.isRunning(), false);
    assert.equal(active.state, PROCESS_STATES.ZOMBIE);
    assert.equal(active.stats.exitCode, 3);
    assert.equal(stopped.stats.instructionsExecuted, 0);

    // Resuming with SIGCONT lets stopped process complete
    pm.kill(stopped.pid, 'SIGCONT');
    const s2 = scheduler.runUntilIdle(stopped.pid, 20);
    assert.equal(s2.state, PROCESS_STATES.ZOMBIE);
    assert.equal(s2.exitCode, 0);
  });
});

// ============================================================================
// Suite 9: F-009 — POSIX Signal Handling
// ============================================================================
describe('F-009: POSIX Signal Handling', () => {
  it('9.1 handles full signal table, custom catchers, uncatchable SIGKILL/SIGSTOP, and system PID protection', () => {
    const pm = new ProcessManager();
    pm.spawnSystemProcess({ pid: 0, ppid: 0, name: 'kernel_idle' });
    pm.spawnSystemProcess({ pid: 1, ppid: 0, name: 'omnid' });

    // System PID protection
    assert.throws(
      () => pm.kill(0, 'SIGKILL'),
      (err) => err instanceof SecurityError && err.code === ERROR_CODES.EPERM
    );
    assert.throws(
      () => pm.kill(1, 'SIGTERM'),
      (err) => err instanceof SecurityError && err.code === ERROR_CODES.EPERM
    );

    // Custom handler for SIGUSR1 & SIGTERM
    const caught = [];
    const p1 = pm.spawn({ name: 'catcher' });
    pm.onSignal(p1.pid, 'SIGUSR1', (sig, num) => {
      caught.push({ sig, num });
    });
    const rUsr = pm.kill(p1.pid, 'SIGUSR1');
    assert.equal(rUsr.ok, true);
    assert.equal(p1.state, PROCESS_STATES.READY);
    assert.deepStrictEqual(caught, [{ sig: 'SIGUSR1', num: 10 }]);

    // Reject catching SIGKILL & SIGSTOP
    assert.throws(() => pm.onSignal(p1.pid, 'SIGKILL', () => {}), (err) => err.code === ERROR_CODES.EINVAL);
    assert.throws(() => pm.onSignal(p1.pid, 'SIGSTOP', () => {}), (err) => err.code === ERROR_CODES.EINVAL);

    // SIGSTOP & SIGCONT
    pm.kill(p1.pid, 'SIGSTOP');
    assert.equal(p1.state, PROCESS_STATES.STOPPED);
    pm.kill(p1.pid, 'SIGCONT');
    assert.equal(p1.state, PROCESS_STATES.READY);

    // Default exit codes for fatal signals (128 + signum)
    const fatalCases = [
      ['SIGINT', 2, 130],
      ['SIGILL', 4, 132],
      ['SIGKILL', 9, 137],
      ['SIGSEGV', 11, 139],
      ['SIGALRM', 14, 142],
      ['SIGTERM', 15, 143],
      ['SIGXCPU', 24, 152],
    ];
    for (const [sigName, sigNum, expectedExit] of fatalCases) {
      const proc = pm.spawn({ name: `sig-${sigName}` });
      const res = pm.kill(proc.pid, sigName);
      assert.equal(res.ok, true);
      assert.equal(proc.state, PROCESS_STATES.ZOMBIE);
      assert.equal(proc.stats.exitSignal, sigName);
      assert.equal(proc.stats.exitSignalNumber, sigNum);
      assert.equal(proc.stats.exitCode, expectedExit);
    }
  });

  it('9.2 tears down executionContext, FDs, VMM, and cleanupHooks on SIGKILL', () => {
    const bus = new KernelEventBus();
    const exited = [];
    bus.on('process:exited', (e) => exited.push(e));

    const pm = new ProcessManager({ eventBus: bus });
    const ctx = makeWorkContext({ totalWork: 500 });
    const pcb = pm.spawn({ name: 'cleanup-target', executionContext: ctx });
    pcb.addressSpace.mmap(0x00400000, 4096, PROT_READ | PROT_WRITE, 'data');

    const closedFds = [];
    pm.openFd(pcb.pid, { path: '/a', onClose: (e) => closedFds.push(e.fd) });
    pm.openFd(pcb.pid, { path: '/b', close: (e) => closedFds.push(e.fd) });

    let hookRan = false;
    pm.addCleanupHook(pcb.pid, () => {
      hookRan = true;
    });

    pm.kill(pcb.pid, 'SIGKILL');

    assert.equal(ctx.disposeCount, 1);
    assert.deepStrictEqual(closedFds, [3, 4]);
    assert.equal(pcb.fdTable.size, 0);
    assert.equal(pcb.addressSpace.getStats().mappedPages, 0);
    assert.equal(hookRan, true);
    assert.equal(exited.length, 1);
    assert.equal(exited[0].exitCode, 137);
  });
});

// ============================================================================
// Suite 10: F-010 — Process Streams & FD Table
// ============================================================================
describe('F-010: Process Streams & FD Table', () => {
  it('10.1 enforces bounded ring buffers, live events, and wakes stdin-blocked threads', () => {
    const ring = new ProcessStreamBuffer(8);
    ring.write('123456');
    ring.write('7890');
    assert.equal(ring.size, 8);
    assert.equal(ring.droppedBytes, 2);
    assert.equal(ring.peek(), '34567890');
    assert.equal(ring.read(4), '3456');
    assert.equal(ring.read(), '7890');
    assert.equal(ring.size, 0);

    const bus = new KernelEventBus();
    const events = [];
    bus.on('process:stdout', (e) => events.push(['stdout', e.data]));
    bus.on('process:stderr', (e) => events.push(['stderr', e.data]));

    const pm = new ProcessManager({ eventBus: bus });
    const pcb = pm.spawn({ name: 'io-proc' });
    pm.markBlocked(pcb.pid, 1, 'stdin');
    assert.equal(pcb.state, PROCESS_STATES.BLOCKED);

    pm.writeStdin(pcb.pid, 'input-line\n');
    assert.equal(pcb.state, PROCESS_STATES.READY);
    assert.equal(pm.readStdin(pcb.pid), 'input-line\n');

    pm.writeStdout(pcb.pid, 'out-1');
    pm.writeStderr(pcb.pid, 'err-1');
    assert.equal(pm.readStdout(pcb.pid), 'out-1');
    assert.equal(pm.readStdout(pcb.pid), 'out-1'); // default non-destructive snapshot
    assert.equal(pm.readStderr(pcb.pid, { consume: true }), 'err-1');
    assert.equal(pm.readStderr(pcb.pid), '');
    assert.deepStrictEqual(events, [
      ['stdout', 'out-1'],
      ['stderr', 'err-1'],
    ]);
  });

  it('10.2 manages FD slots (0, 1, 2, 3+) with reuse, EMFILE quota, and maxWindows quota', () => {
    const pm = new ProcessManager();
    const pcb = pm.spawn({ name: 'fd-proc', quotas: { maxOpenFds: 5, maxWindows: 2 } });

    assert.deepStrictEqual(pm.listFds(pcb.pid).map((f) => f.fd), [0, 1, 2]);
    const fd3 = pm.openFd(pcb.pid, { path: '/f1' });
    const fd4 = pm.openFd(pcb.pid, { path: '/f2' });
    assert.equal(fd3, 3);
    assert.equal(fd4, 4);

    // 6th FD hits maxOpenFds=5 -> QuotaExceededError(EMFILE)
    assert.throws(
      () => pm.openFd(pcb.pid, { path: '/f3' }),
      (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.EMFILE
    );

    // Close FD 3 and ensure reuse allocates lowest available slot (3)
    pm.closeFd(pcb.pid, 3);
    assert.equal(pm.openFd(pcb.pid, { path: '/reused' }), 3);

    // Window quota
    pm.registerWindow(pcb.pid, 'win-1');
    pm.registerWindow(pcb.pid, 'win-2');
    assert.throws(
      () => pm.registerWindow(pcb.pid, 'win-3'),
      (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.E_WINDOW_QUOTA
    );
  });
});

// ============================================================================
// Suite 11: F-011 — Sandbox Quotas & Runaway / Fault Isolation
// ============================================================================
describe('F-011: Sandbox Quotas & Runaway / Fault Isolation', () => {
  it('11.1 kills infinite-loop runaway with SIGXCPU (152) while healthy sibling completes cleanly', async () => {
    const kernel = createKernel({ baseQuantum: 500 });
    await kernel.boot();

    const runaway = kernel.processManager.spawn({
      name: 'runaway-loop',
      quotas: { maxInstructionsPerTick: 200, maxTotalInstructions: 600 },
      executionContext: {
        step(budget) {
          return { status: 'YIELD', instructionsExecuted: budget };
        },
        dispose() {},
      },
    });

    const sibling = kernel.processManager.spawn({
      name: 'healthy-sibling',
      executionContext: makeWorkContext({ totalWork: 1000, exitCode: 0 }),
    });

    kernel.scheduler.step(10);

    assert.equal(runaway.state, PROCESS_STATES.ZOMBIE);
    assert.equal(runaway.stats.exitSignal, 'SIGXCPU');
    assert.equal(runaway.stats.exitCode, 152);

    assert.equal(sibling.state, PROCESS_STATES.ZOMBIE);
    assert.equal(sibling.stats.exitCode, 0);
    assert.equal(kernel.state, KERNEL_STATES.RUNNING);

    await kernel.shutdown();
  });

  it('11.2 kills uncooperative execCtx exceeding maxInstructionsPerTick with SIGXCPU (152)', () => {
    const pm = new ProcessManager();
    const scheduler = new Scheduler({ processManager: pm, baseQuantum: 500 });

    const hog = pm.spawn({
      name: 'budget-hog',
      quotas: { maxInstructionsPerTick: 200, maxTotalInstructions: 100000 },
      executionContext: {
        step() {
          return { status: 'YIELD', instructionsExecuted: 9999 };
        },
        dispose() {},
      },
    });

    scheduler.step(1);
    assert.equal(hog.state, PROCESS_STATES.ZOMBIE);
    assert.equal(hog.stats.exitSignal, 'SIGXCPU');
    assert.equal(hog.stats.exitCode, 152);
  });

  it('11.3 isolates synchronous throws (MemoryFaultError, IllegalInstructionError, QuotaExceededError, Error) to offending PIDs only', () => {
    const pm = new ProcessManager();
    const scheduler = new Scheduler({ processManager: pm, baseQuantum: 100 });

    const pSegv = pm.spawn({
      name: 'throw-segv',
      executionContext: {
        step() { throw new MemoryFaultError('Bad deref', { address: 0xdead }); },
        dispose() {},
      },
    });
    const pIll = pm.spawn({
      name: 'throw-ill',
      executionContext: {
        step() { throw new UnsupportedOpcodeError('Bad opcode 0xFF', { opcode: 0xff }); },
        dispose() {},
      },
    });
    const pQuota = pm.spawn({
      name: 'throw-quota',
      executionContext: {
        step() { throw new QuotaExceededError('CPU limit', { code: ERROR_CODES.E_CPU_QUOTA }); },
        dispose() {},
      },
    });
    const pErr = pm.spawn({
      name: 'throw-generic',
      executionContext: {
        step() { throw new Error('Unexpected runtime crash'); },
        dispose() {},
      },
    });
    const healthy = pm.spawn({
      name: 'survivor',
      executionContext: makeWorkContext({ totalWork: 250, exitCode: 0 }),
    });

    scheduler.step(5);

    assert.equal(pSegv.stats.exitSignal, 'SIGSEGV');
    assert.equal(pSegv.stats.exitCode, 139);
    assert.equal(pIll.stats.exitSignal, 'SIGILL');
    assert.equal(pIll.stats.exitCode, 132);
    assert.equal(pQuota.stats.exitSignal, 'SIGXCPU');
    assert.equal(pQuota.stats.exitCode, 152);
    assert.equal(pErr.state, PROCESS_STATES.ZOMBIE);
    assert.equal(pErr.stats.exitSignal, 'SIGSEGV');

    assert.equal(healthy.state, PROCESS_STATES.ZOMBIE);
    assert.equal(healthy.stats.exitCode, 0);
  });
});

// ============================================================================
// Suite 12: F-012 — Sparse 4KB-Page Virtual Memory & __PAGEZERO
// ============================================================================
describe('F-012: Sparse 4KB-Page Virtual Memory & __PAGEZERO', () => {
  it('12.1 maps sparse 64-bit / high VAs (including BigInt) without 32-bit truncation', () => {
    const vmm = createAddressSpace({ pid: 2 });

    const a1 = vmm.mmap(0x00400000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'pe32');
    const a2 = vmm.mmap(0x100000000, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, 'macho-text');
    const a3 = vmm.mmap(0x140000000n, PAGE_SIZE, PROT_READ | PROT_WRITE, 'pe32plus');
    const a4 = vmm.mmap(0x7fff00000000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'high-stack');

    assert.equal(a1, 0x00400000);
    assert.equal(a2, 0x100000000);
    assert.equal(a3, 0x140000000);
    assert.equal(a4, 0x7fff00000000);

    vmm.write(a1, new Uint8Array([0x11, 0x22]));
    vmm.write(a2, new Uint8Array([0x33, 0x44]));
    vmm.write(0x140000000n, new Uint8Array([0x55, 0x66]));
    vmm.write(a4, new Uint8Array([0x77, 0x88]));

    assert.deepStrictEqual(Array.from(vmm.read(a1, 2)), [0x11, 0x22]);
    assert.deepStrictEqual(Array.from(vmm.fetch(a2, 2)), [0x33, 0x44]);
    assert.deepStrictEqual(Array.from(vmm.read(0x140000000n, 2)), [0x55, 0x66]);
    assert.deepStrictEqual(Array.from(vmm.read(a4, 2)), [0x77, 0x88]);

    const stats = vmm.getStats();
    assert.equal(stats.mappedPages, 4);
    assert.equal(stats.usedBytes, 4 * PAGE_SIZE);

    // Reject negative / NaN / unsafe BigInt addresses
    assert.throws(() => vmm.read(-1, 4), MemoryFaultError);
    assert.throws(() => vmm.read(Number.NaN, 4), MemoryFaultError);
    assert.throws(() => vmm.read(0xffffffffffffffffn, 4), MemoryFaultError);
  });

  it('12.2 reserves 4 GiB __PAGEZERO guard with ZERO allocated pages and guard-aware heap placement', () => {
    const vmm = new AddressSpace({ pid: 3 });
    const rssBefore = process.memoryUsage().rss;

    vmm.reserveGuard(0, 0x100000000, '__PAGEZERO');
    const rssDelta = process.memoryUsage().rss - rssBefore;

    const stats = vmm.getStats();
    assert.equal(stats.mappedPages, 0);
    assert.equal(stats.usedBytes, 0);
    assert.equal(stats.guardRegions.length, 1);
    assert.ok(rssDelta < 32 * 1024 * 1024, `Guard allocated unexpected host RAM: ${rssDelta} bytes`);

    const isGuardFault = (err) =>
      err instanceof MemoryFaultError && err.signal === 'SIGSEGV' && err.faultType === 'GUARD_PAGE';

    assert.throws(() => vmm.read(0, 4), isGuardFault);
    assert.throws(() => vmm.read(0xfffff000, 4), isGuardFault);
    assert.throws(() => vmm.write(0x1000, new Uint8Array([1])), isGuardFault);
    assert.throws(() => vmm.fetch(0, 4), isGuardFault);
    assert.throws(() => vmm.mmap(0x10000, PAGE_SIZE, PROT_READ), isGuardFault);
    assert.throws(() => vmm.mprotect(0x1000, PAGE_SIZE, PROT_READ), isGuardFault);
    assert.throws(() => vmm.munmap(0x1000, PAGE_SIZE), isGuardFault);

    // Heap alloc MUST skip __PAGEZERO and land at >= HIGH_VA_HEAP_BASE (0x200000000)
    const ptr = vmm.alloc(128);
    assert.ok(ptr >= HIGH_VA_HEAP_BASE, `Expected heap ptr >= 0x200000000, got 0x${ptr.toString(16)}`);
    vmm.write(ptr, new Uint8Array([0xaa, 0xbb]));
    assert.deepStrictEqual(Array.from(vmm.read(ptr, 2)), [0xaa, 0xbb]);
  });

  it('12.3 isolates identical VAs across separate PIDs and supports munmap splitting', () => {
    const a = new AddressSpace({ pid: 10 });
    const b = new AddressSpace({ pid: 11 });

    a.mmap(0x00400000, 3 * PAGE_SIZE, PROT_READ | PROT_WRITE, 'seg');
    b.mmap(0x00400000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'seg');

    a.write(0x00400000, new Uint8Array([1, 2, 3]));
    a.write(0x00402000, new Uint8Array([7, 8, 9]));
    b.write(0x00400000, new Uint8Array([99, 98, 97]));

    assert.deepStrictEqual(Array.from(a.read(0x00400000, 3)), [1, 2, 3]);
    assert.deepStrictEqual(Array.from(b.read(0x00400000, 3)), [99, 98, 97]);

    // Unmap middle page of `a`
    a.munmap(0x00401000, PAGE_SIZE);
    assert.equal(a.getStats().mappedPages, 2);
    assert.throws(
      () => a.read(0x00401000, 4),
      (err) => err instanceof MemoryFaultError && err.faultType === 'UNMAPPED_PAGE'
    );
    assert.deepStrictEqual(Array.from(a.read(0x00400000, 3)), [1, 2, 3]);
    assert.deepStrictEqual(Array.from(a.read(0x00402000, 3)), [7, 8, 9]);
  });
});

// ============================================================================
// Suite 13: F-013 — Hardware-Style R/W/X Enforcement
// ============================================================================
describe('F-013: Hardware-Style R/W/X Enforcement', () => {
  it('13.1 enforces R/W/X faults, mprotect 3-way split, atomic cross-page write, and typed helpers', () => {
    const vmm = new AddressSpace({ pid: 20 });

    // Unmapped fault
    assert.throws(
      () => vmm.read(0x500000, 4),
      (err) => err instanceof MemoryFaultError && err.signal === 'SIGSEGV' && err.faultType === 'UNMAPPED_PAGE' && err.address === 0x500000 && err.addr === 0x500000
    );

    // PROT_NONE fault
    const noneBase = vmm.mmap(0x600000, PAGE_SIZE, PROT_NONE, 'none');
    assert.throws(
      () => vmm.read(noneBase, 1),
      (err) => err instanceof MemoryFaultError && err.signal === 'SIGSEGV' && err.faultType === 'READ_VIOLATION'
    );

    // 3-page region -> mprotect middle page to R-X
    const base = vmm.mmap(0x100000000, 3 * PAGE_SIZE, PROT_READ | PROT_WRITE, 'img');
    vmm.write(base + PAGE_SIZE, new Uint8Array([0x90, 0x90, 0xc3]));

    // NX fetch on RW page MUST fault
    assert.throws(
      () => vmm.fetch(base, 4),
      (err) => err instanceof MemoryFaultError && err.signal === 'SIGSEGV' && err.faultType === 'NX_EXEC_VIOLATION'
    );

    vmm.mprotect(base + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_EXEC);
    const regions = vmm.getStats().regions.filter((r) => r.label === 'img');
    assert.equal(regions.length, 3);
    assert.deepStrictEqual(regions.map((r) => r.permsString), ['rw-', 'r-x', 'rw-']);

    // Middle page now executable, NOT writable
    assert.deepStrictEqual(Array.from(vmm.fetch(base + PAGE_SIZE, 3)), [0x90, 0x90, 0xc3]);
    assert.throws(
      () => vmm.write(base + PAGE_SIZE, new Uint8Array([0xcc])),
      (err) => err instanceof MemoryFaultError && err.signal === 'SIGSEGV' && err.faultType === 'WRITE_VIOLATION'
    );

    // Atomic cross-page write from RW page 0 into R-X page 1 MUST mutate ZERO bytes on page 0
    assert.throws(
      () => vmm.write(base + PAGE_SIZE - 2, new Uint8Array([1, 2, 3, 4])),
      (err) => err instanceof MemoryFaultError && err.faultType === 'WRITE_VIOLATION'
    );
    assert.deepStrictEqual(Array.from(vmm.read(base + PAGE_SIZE - 2, 2)), [0, 0]);

    // Typed helpers (including cross-page & C-string right before unmapped page)
    const rw = vmm.mmap(0x700000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'typed');
    vmm.writeU8(rw, 0xab);
    vmm.writeU16(rw + 2, 0x1234, true);
    vmm.writeU32(rw + 4, 0x89abcdef, false);
    vmm.writeU64(rw + 8, 0x0123456789abcdefn, true);
    assert.equal(vmm.readU8(rw), 0xab);
    assert.equal(vmm.readU16(rw + 2, true), 0x1234);
    assert.equal(vmm.readU32(rw + 4, false), 0x89abcdef);
    assert.equal(vmm.readU64(rw + 8, true), 0x0123456789abcdefn);

    // CString right at end of mapped page adjacent to unmapped page
    const strAddr = rw + PAGE_SIZE - 6;
    vmm.writeCString(strAddr, 'hello');
    assert.equal(vmm.readCString(strAddr, 256), 'hello');
  });
});

// ============================================================================
// Suite 14: F-014 — Per-PID Heap Allocator & Telemetry
// ============================================================================
describe('F-014: Per-PID Heap Allocator & Telemetry', () => {
  it('14.1 performs 16B-aligned alloc, bidirectional coalescing, double-free detection, and exception-safe realloc', () => {
    const vmm = new AddressSpace({ pid: 30, maxMemoryBytes: 16384 });

    const a = vmm.alloc(1024);
    const b = vmm.alloc(1024);
    const c = vmm.alloc(1024);
    assert.equal(a % HEAP_ALIGNMENT, 0);
    assert.equal(b % HEAP_ALIGNMENT, 0);
    assert.equal(c % HEAP_ALIGNMENT, 0);
    assert.equal(vmm.getStats().mappedPages, 1);

    vmm.write(a, new Uint8Array([10, 20, 30, 40]));
    vmm.write(c, new Uint8Array([50, 60, 70, 80]));

    // Free A and B -> coalesced into 2048B free block; alloc(1800) reuses with ZERO new pages!
    vmm.free(a);
    vmm.free(b);
    const pagesBefore = vmm.getStats().mappedPages;
    const merged = vmm.alloc(1800);
    assert.equal(merged, a);
    assert.equal(vmm.getStats().mappedPages, pagesBefore);

    // Post-coalesce double-free (c coalesced backward into merged) & invalid free
    vmm.free(merged);
    vmm.free(c);
    assert.equal(vmm.getStats().heap.freeBlockCount, 1);
    assert.throws(
      () => vmm.free(c),
      (err) => err instanceof MemoryFaultError && err.faultType === 'DOUBLE_FREE'
    );
    assert.throws(
      () => vmm.free(0),
      (err) => err instanceof MemoryFaultError && err.faultType === 'INVALID_FREE'
    );
    assert.throws(
      () => vmm.free(a + 8),
      (err) => err instanceof MemoryFaultError && err.faultType === 'INVALID_FREE'
    );

    // Explicit 3-way bidirectional coalescing: free(x), free(z), then free(y) merges both sides
    const x = vmm.alloc(64);
    const y = vmm.alloc(64);
    const z = vmm.alloc(64);
    vmm.free(x);
    vmm.free(z);
    vmm.free(y);
    assert.equal(vmm.getStats().heap.freeBlockCount, 1);
    assert.throws(
      () => vmm.free(y),
      (err) => err instanceof MemoryFaultError && err.faultType === 'DOUBLE_FREE'
    );

    // realloc: null ptr, shrink, in-place grow, relocate, ENOMEM preservation, zero-size free
    const p1 = vmm.realloc(0, 64);
    vmm.write(p1, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    const p1Shrunk = vmm.realloc(p1, 32);
    assert.equal(p1Shrunk, p1);
    assert.deepStrictEqual(Array.from(vmm.read(p1Shrunk, 8)), [1, 2, 3, 4, 5, 6, 7, 8]);

    // Grow in-place into adjacent free space
    const p1Grown = vmm.realloc(p1Shrunk, 96);
    assert.equal(p1Grown, p1);
    assert.deepStrictEqual(Array.from(vmm.read(p1Grown, 8)), [1, 2, 3, 4, 5, 6, 7, 8]);

    // Block next slot to force relocate
    const blocker = vmm.alloc(64);
    assert.ok(blocker > p1Grown);
    const p1Moved = vmm.realloc(p1Grown, 256);
    assert.notEqual(p1Moved, p1Grown);
    assert.deepStrictEqual(Array.from(vmm.read(p1Moved, 8)), [1, 2, 3, 4, 5, 6, 7, 8]);

    // ENOMEM on realloc MUST keep original pointer and bytes 100% intact
    assert.throws(
      () => vmm.realloc(p1Moved, 32768),
      (err) => err instanceof MemoryFaultError && err.code === ERROR_CODES.ENOMEM && err.errno === 12 && err.signal === null
    );
    assert.deepStrictEqual(Array.from(vmm.read(p1Moved, 8)), [1, 2, 3, 4, 5, 6, 7, 8]);

    // realloc(ptr, 0) frees and returns 0
    assert.equal(vmm.realloc(p1Moved, 0), 0);
  });

  it('14.2 enforces ENOMEM quota on mmap/alloc and safely reports getStats() after destroy()', () => {
    const vmm = new AddressSpace({ pid: 31, maxMemoryBytes: 16384 });
    vmm.mmap(0x00400000, 16384, PROT_READ | PROT_WRITE, 'full');

    assert.throws(
      () => vmm.mmap(0x00500000, 4096, PROT_READ | PROT_WRITE, 'overflow'),
      (err) => err instanceof MemoryFaultError && err.code === ERROR_CODES.ENOMEM && err.errno === 12
    );
    assert.equal(vmm.getStats().mappedPages, 4);
    assert.equal(vmm.getStats().peakBytes, 16384);

    vmm.destroy();
    const afterStats = vmm.getStats();
    assert.equal(afterStats.mappedPages, 0);
    assert.equal(afterStats.usedBytes, 0);
    assert.equal(afterStats.peakBytes, 16384);
    assert.equal(afterStats.maxBytes, 16384);
    assert.throws(() => vmm.read(0x00400000, 1), MemoryFaultError);
  });
});

// ============================================================================
// Suite 15: F-015 — Errors, Binary Codecs, CpuRegistry, EventBus, Syscalls & WAL SQLite
// ============================================================================
describe('F-015: Foundation (Errors, Binary Codecs, CpuRegistry, EventBus, Syscalls, WAL SQLite)', () => {
  it('15.1 validates all 13 structured error classes, signal resolver, and cross-platform error codes', () => {
    const cause = new Error('root');
    const instances = [
      new OmniOSError('base', { code: ERROR_CODES.EINVAL, cause }),
      new MemoryFaultError('segv', { address: 0x1000 }),
      new IllegalInstructionError('ill', { pc: 0x400, opcode: 0xfe }),
      new UnsupportedOpcodeError('unsup', { pc: 0x404, opcode: 0xff }),
      new QuotaExceededError('cpu', { code: ERROR_CODES.E_CPU_QUOTA, limit: 100, actual: 200 }),
      new SyscallError('sys', { code: ERROR_CODES.ENOSYS, syscall: 'foo', pid: 2 }),
      new VfsError('vfs', { code: ERROR_CODES.ENOENT, path: '/missing' }),
      new FormatError('fmt', { code: ERROR_CODES.E_INVALID_LEB128, offset: 4 }),
      new SecurityError('sec', { code: ERROR_CODES.EACCES, capability: 'fs.write' }),
      new KernelPanicError('panic', { code: ERROR_CODES.E_KERNEL_PANIC }),
      new UnresolvedImportError('imp', { library: 'kernel32.dll', symbol: 'Foo' }),
      new ProcessError('proc', { code: ERROR_CODES.ESRCH, pid: 99 }),
      new ServiceError('svc', { code: ERROR_CODES.E_SERVICE_CYCLE, cycle: ['A', 'A'] }),
    ];

    assert.equal(instances.length, 13);
    for (const err of instances) {
      assert.ok(err instanceof Error);
      assert.ok(isOmniOSError(err));
      const json = err.toJSON();
      assert.equal(json.name, err.name);
      assert.equal(json.code, err.code);
    }

    assert.ok(instances[3] instanceof IllegalInstructionError);
    assert.equal(instances[3].signal, 'SIGILL');
    assert.equal(instances[1].signal, 'SIGSEGV');
    assert.equal(instances[1].address, 0x1000);
    assert.equal(instances[1].addr, 0x1000);

    const oom = new MemoryFaultError('oom', { code: ERROR_CODES.ENOMEM });
    assert.equal(oom.errno, 12);
    assert.equal(oom.signal, null);

    assert.deepStrictEqual(resolveSignal('TERM'), { name: 'SIGTERM', number: 15 });
    assert.deepStrictEqual(resolveSignal('SIGTERM'), { name: 'SIGTERM', number: 15 });
    assert.deepStrictEqual(resolveSignal(15), { name: 'SIGTERM', number: 15 });
    assert.deepStrictEqual(resolveSignal('SIGXCPU'), { name: 'SIGXCPU', number: 24 });
    assert.equal(SIGNAL_NAMES[24], 'SIGXCPU');
    assert.throws(() => resolveSignal('SIGBOGUS'), (err) => err.code === ERROR_CODES.EINVAL);

    assert.equal(POSIX_ERRNO.ENOSYS, 38);
    assert.equal(DARWIN_ERRNO.ENOSYS, 78);
    assert.equal(posixCodeToDarwinErrno('ENOSYS'), 78);
    assert.equal(WIN32_ERROR.ERROR_FILE_NOT_FOUND, 2);
    assert.equal(posixCodeToWin32('ENOENT'), 2);
    assert.equal(WASI_ERRNO.WASI_ENOTCAPABLE, 76);
    assert.equal(posixCodeToWasi('E_PATH_TRAVERSAL'), 76);
  });

  it('15.2 round-trips BinaryReader & BinaryWriter (LE/BE, subarrays, strings, patching, bounds)', () => {
    const w = new BinaryWriter({ initialCapacity: 8, littleEndian: true });
    w.u8(0xfe)
      .i8(-42)
      .u16le(0x1234)
      .u16be(0x5678)
      .i16(-12345)
      .u32le(0xdeadbeef)
      .u32be(0xcafebabe)
      .i32(-1000000)
      .u64le(0x0102030405060708n)
      .i64be(-0x1122334455667788n)
      .f32le(3.5)
      .f64be(-123.456)
      .ascii('OMNI', 8)
      .cstring('hello-utf8')
      .utf16le('AB')
      .utf16be('CD')
      .align(8, 0xcc);

    const patchPos = w.offset;
    w.u32le(0);
    w.u8(0x99);
    w.patchU32LE(patchPos, 0x11223344);
    assert.equal(w.offset, patchPos + 5); // cursor untouched by patch!

    // Wrap inside larger buffer with non-zero byteOffset to verify subarray view handling
    const payload = w.toUint8Array();
    const padded = new Uint8Array(payload.length + 10);
    padded.set(payload, 5);
    const sub = padded.subarray(5, 5 + payload.length);

    const r = new BinaryReader(sub, { littleEndian: true });
    assert.equal(r.u8(), 0xfe);
    assert.equal(r.i8(), -42);
    assert.equal(r.u16le(), 0x1234);
    assert.equal(r.u16be(), 0x5678);
    assert.equal(r.i16(), -12345);
    assert.equal(r.u32le(), 0xdeadbeef);
    assert.equal(r.u32be(), 0xcafebabe);
    assert.equal(r.i32(), -1000000);
    assert.equal(r.u64le(), 0x0102030405060708n);
    assert.equal(r.i64be(), -0x1122334455667788n);
    assert.equal(r.f32le(), 3.5);
    assert.equal(r.f64be(), -123.456);
    assert.equal(r.ascii(8, { trimNull: true }), 'OMNI');
    assert.equal(r.cstring(), 'hello-utf8');
    assert.equal(r.utf16le(4), 'AB');
    assert.equal(r.utf16be(4), 'CD');
    r.align(8);
    assert.equal(r.u32le(), 0x11223344);
    assert.equal(r.u8(), 0x99);
    assert.equal(r.eof, true);

    // Bounds checks
    assert.throws(() => r.u8(), (err) => err instanceof FormatError && err.code === ERROR_CODES.E_EOF);
    assert.throws(() => r.skip(-1), (err) => err instanceof FormatError && err.code === ERROR_CODES.ERANGE);
    assert.throws(() => new BinaryReader(new Uint8Array([1, 2, 3])).utf16le(3), FormatError);
    assert.throws(() => w.patchU32LE(w.length, 0), FormatError);
  });

  it('15.3 computes exact IEEE CRC-32 and RFC 1950 Adler-32 vectors', () => {
    assert.equal(crc32(new Uint8Array(0)), 0x00000000);
    assert.equal(crc32('123456789'), 0xcbf43926);
    assert.equal(crc32('56789', crc32('1234')), 0xcbf43926);
    assert.equal(crc32('hello world'), 0x0d4a1185);
    assert.equal(crc32('OmniOS'), 0x371289fd);
    assert.equal(crc32(new Uint8Array([0x00])), 0xd202ef8d);
    assert.equal(crc32(new Uint8Array([0xff])), 0xff000000);

    assert.equal(adler32(new Uint8Array(0)), 0x00000001);
    assert.equal(adler32('Wikipedia'), 0x11e60398);
    assert.equal(adler32('123456789'), 0x091e01de);
    assert.equal(adler32('a'), 0x00620062);
    assert.equal(adler32(new Uint8Array(10000).fill(0xff)), 0xb623eb2b);
    assert.equal(adler32(new TextEncoder().encode('XXXWikipediaYYY'), 3, 9), 0x11e60398);
  });

  it('15.4 encodes/decodes exact ULEB128/SLEB128/ULEB128p1 vectors and strictly rejects >5B & overflows', () => {
    const ulebCases = [
      [0, [0x00]],
      [1, [0x01]],
      [127, [0x7f]],
      [128, [0x80, 0x01]],
      [16256, [0x80, 0x7f]],
      [16384, [0x80, 0x80, 0x01]],
      [624485, [0xe5, 0x8e, 0x26]],
      [0xffffffff, [0xff, 0xff, 0xff, 0xff, 0x0f]],
    ];
    for (const [val, expected] of ulebCases) {
      const enc = encodeUleb128(val);
      assert.deepStrictEqual(Array.from(enc), expected);
      const dec = decodeUleb128(enc);
      assert.equal(dec.value, val);
      assert.equal(dec.bytesRead, expected.length);
    }

    const slebCases = [
      [0, [0x00]],
      [1, [0x01]],
      [-1, [0x7f]],
      [63, [0x3f]],
      [64, [0xc0, 0x00]],
      [-64, [0x40]],
      [-65, [0xbf, 0x7f]],
      [127, [0xff, 0x00]],
      [-128, [0x80, 0x7f]],
      [-123456, [0xc0, 0xbb, 0x78]],
      [2147483647, [0xff, 0xff, 0xff, 0xff, 0x07]],
      [-2147483648, [0x80, 0x80, 0x80, 0x80, 0x78]],
    ];
    for (const [val, expected] of slebCases) {
      const enc = encodeSleb128(val);
      assert.deepStrictEqual(Array.from(enc), expected);
      const dec = decodeSleb128(enc);
      assert.equal(dec.value, val);
      assert.equal(dec.bytesRead, expected.length);
    }

    const p1Cases = [
      [-1, [0x00]],
      [0, [0x01]],
      [127, [0x80, 0x01]],
      [0xfffffffe, [0xff, 0xff, 0xff, 0xff, 0x0f]],
    ];
    for (const [val, expected] of p1Cases) {
      const enc = encodeUleb128p1(val);
      assert.deepStrictEqual(Array.from(enc), expected);
      assert.equal(decodeUleb128p1(enc).value, val);
    }

    // Mandatory negative vectors
    const isLebErr = (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_LEB128;
    assert.throws(() => decodeUleb128(new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x01])), isLebErr);
    assert.throws(() => decodeUleb128(new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80])), isLebErr);
    assert.throws(() => decodeUleb128(new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x10])), isLebErr);
    assert.throws(() => decodeUleb128(new Uint8Array([0x80])), isLebErr);
    assert.throws(() => decodeUleb128(new Uint8Array([])), isLebErr);
    assert.throws(() => decodeSleb128(new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x00])), isLebErr);
    assert.throws(() => decodeSleb128(new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x08])), isLebErr);
    assert.throws(() => decodeSleb128(new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x70])), isLebErr);
    assert.throws(() => encodeUleb128(-1), isLebErr);
    assert.throws(() => encodeUleb128(0x100000000), isLebErr);
    assert.throws(() => encodeUleb128p1(-2), isLebErr);
    assert.throws(() => encodeSleb128(2147483648), isLebErr);
    assert.throws(() => encodeSleb128(-2147483649), isLebErr);
  });

  it('15.5 encodes/decodes exact MUTF-8 vectors (0xC0 0x80 NUL & surrogates) and rejects malformed sequences', () => {
    const cases = [
      ['', []],
      ['\u0000', [0xc0, 0x80]],
      ['a\u0000b', [0x61, 0xc0, 0x80, 0x62]],
      ['\u0080', [0xc2, 0x80]],
      ['\u00e9', [0xc3, 0xa9]],
      ['\u07ff', [0xdf, 0xbf]],
      ['\u0800', [0xe0, 0xa0, 0x80]],
      ['\u4e2d', [0xe4, 0xb8, 0xad]],
      ['\uffff', [0xef, 0xbf, 0xbf]],
      ['\u{1f600}', [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]],
      ['A\u0000\u{1f600}', [0x41, 0xc0, 0x80, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]],
    ];
    for (const [str, expected] of cases) {
      const enc = encodeMutf8(str);
      assert.deepStrictEqual(Array.from(enc), expected);
      assert.equal(decodeMutf8(enc), str);

      const encZ = encodeMutf8(str, { nullTerminate: true });
      const decZ = decodeMutf8Z(encZ, 0, { expectedUtf16Length: str.length });
      assert.equal(decZ.value, str);
      assert.equal(decZ.bytesRead, expected.length + 1);
    }

    const isMutfErr = (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MUTF8;
    const badInputs = [
      [0x00],
      [0x41, 0x00],
      [0xf0, 0x9f, 0x98, 0x80], // 4-byte standard UTF-8 forbidden in MUTF-8
      [0x80],
      [0xc0, 0x81],
      [0xc1, 0xbf],
      [0xe0, 0x80, 0x80],
      [0xe0, 0x9f, 0xbf],
      [0xc2],
      [0xe4, 0xb8],
      [0xc2, 0x41],
    ];
    for (const bad of badInputs) {
      assert.throws(() => decodeMutf8(new Uint8Array(bad)), isMutfErr);
    }
  });

  it('15.6 validates CpuRegistry with classes, factory functions, objects, aliases, and missing archs', () => {
    const reg = new CpuRegistry();
    assert.ok(SUPPORTED_ARCHS.includes('dalvik'));
    assert.equal(reg.get('unknown'), null);
    assert.equal(reg.has('dalvik'), false);

    class FakeArm64 {
      constructor(opts) { this.opts = opts; this.kind = 'class'; }
    }
    const dalvikFactory = (opts) => ({ opts, kind: 'fn' });
    const x64FactoryObj = { create: (opts) => ({ opts, kind: 'obj' }) };

    reg.register('aarch64', FakeArm64);
    reg.register('dalvik', dalvikFactory);
    reg.register('amd64', x64FactoryObj);

    assert.equal(reg.get('arm64'), FakeArm64);
    assert.equal(reg.has('x86_64'), true);
    assert.deepStrictEqual(reg.list(), ['arm64', 'dalvik', 'x86_64']);

    assert.equal(reg.create('arm64', { pid: 1 }).kind, 'class');
    assert.equal(reg.create('dalvik', { pid: 2 }).kind, 'fn');
    assert.equal(reg.create('x86-64', { pid: 3 }).kind, 'obj');

    assert.throws(
      () => reg.register('dalvik', dalvikFactory, { overwrite: false }),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EEXIST
    );
    assert.throws(
      () => reg.create('mips'),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT
    );

    assert.equal(reg.unregister('dex'), true);
    assert.equal(reg.get('dalvik'), null);
  });

  it('15.7 validates KernelEventBus exact/prefix/wildcard routing, recursive once, and error isolation', async () => {
    const capturedErrors = [];
    const bus = new KernelEventBus({ onError: (e) => capturedErrors.push(e) });
    const log = [];

    const unsubExact = bus.on('process:exited', (p, ev) => log.push(['exact', ev, p.pid]));
    bus.on('process:*', (p, ev) => log.push(['prefix', ev, p.pid]));
    bus.on('*', (p, ev) => log.push(['wild', ev, p.pid]));

    // Prefix boundary check: 'process:*' MUST NOT match 'process_x:foo'
    bus.emit('process_x:foo', { pid: 99 });
    assert.deepStrictEqual(log, [['wild', 'process_x:foo', 99]]);
    log.length = 0;

    // Registration order preserved across exact, prefix, and wildcard
    bus.emit('process:exited', { pid: 5 });
    assert.deepStrictEqual(log, [
      ['exact', 'process:exited', 5],
      ['prefix', 'process:exited', 5],
      ['wild', 'process:exited', 5],
    ]);

    unsubExact();
    assert.equal(bus.listenerCount('process:exited'), 0);

    // Recursive once fires strictly once
    let onceCalls = 0;
    bus.once('ping', () => {
      onceCalls += 1;
      bus.emit('ping', {});
    });
    bus.emit('ping', {});
    assert.equal(onceCalls, 1);

    // Throwing listener MUST NOT abort subsequent listeners
    let afterThrowCalled = false;
    bus.on('boom', () => { throw new Error('listener exploded'); });
    bus.on('boom', () => { afterThrowCalled = true; });
    const emitRes = bus.emit('boom', {});
    assert.equal(afterThrowCalled, true);
    assert.equal(emitRes.errors.length, 1);
    assert.equal(capturedErrors.length, 1);

    // Async rejecting listener MUST be isolated without unhandled rejection
    bus.on('async-boom', async () => { throw new Error('async explosion'); });
    bus.emit('async-boom', {});
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(capturedErrors.length, 2);
  });

  it('15.8 validates SyscallDispatcher sync/async dispatch, accounting, hooks, and error wrapping', async () => {
    const bus = new KernelEventBus();
    const events = [];
    bus.on('syscall:*', (p, ev) => events.push([ev, p.syscall, p.ok ?? null]));

    const disp = new SyscallDispatcher({ eventBus: bus });
    const mockPcb = { pid: 7, stats: { syscallsCount: 0 } };

    disp.register('add', (ctx, a, b) => a + b + ctx.pid, { number: 100 });
    disp.register('asyncMul', async (_ctx, a, b) => a * b, { number: 101 });
    disp.register('failVfs', () => { throw new VfsError('No file', { code: ERROR_CODES.ENOENT, path: '/x' }); });
    disp.register('failRaw', () => { throw new Error('plain crash'); });
    disp.register('failDirect', () => { throw new SyscallError('direct', { code: ERROR_CODES.EPERM }); });

    // Sync return preserved directly (not Promise)
    assert.equal(disp.dispatch('add', mockPcb, 10, 20), 37);
    assert.equal(disp.invoke(100, mockPcb, 1, 2), 10);

    // Async Promise return supported cleanly
    assert.equal(await disp.dispatch('asyncMul', mockPcb, 6, 7), 42);

    // Unknown -> SyscallError(ENOSYS)
    assert.throws(
      () => disp.dispatch('nope', mockPcb),
      (err) => err instanceof SyscallError && err.code === ERROR_CODES.ENOSYS && err.pid === 7
    );

    // Error wrapping preserves code/errno/cause without double-wrapping SyscallError
    assert.throws(
      () => disp.dispatch('failVfs', mockPcb),
      (err) => err instanceof SyscallError && err.code === ERROR_CODES.ENOENT && err.errno === 2 && err.cause instanceof VfsError
    );
    assert.throws(
      () => disp.dispatch('failRaw', mockPcb),
      (err) => err instanceof SyscallError && err.code === ERROR_CODES.EIO
    );
    assert.throws(
      () => disp.dispatch('failDirect', mockPcb),
      (err) => err instanceof SyscallError && err.code === ERROR_CODES.EPERM && err.cause === undefined
    );

    // Before-hook denial
    const removeHook = disp.addBeforeHook(({ syscall }) => {
      if (syscall === 'add') throw new SecurityError('Denied', { code: ERROR_CODES.EACCES });
    });
    assert.throws(
      () => disp.dispatch('add', mockPcb, 1, 1),
      (err) => err instanceof SyscallError && err.code === ERROR_CODES.EACCES
    );
    removeHook();

    assert.equal(mockPcb.stats.syscallsCount, 8);
    assert.equal(disp.getStats().totalCalls, 8);
    assert.equal(disp.getStats().totalErrors, 5);
    assert.ok(events.some(([ev]) => ev === 'syscall:before'));
    assert.ok(events.some(([ev]) => ev === 'syscall:after'));
    assert.ok(events.some(([ev]) => ev === 'syscall:error'));
  });

  it('15.9 validates WAL SqliteStorage, plain-object rows, BLOBs, nested SAVEPOINTs, async rejection & migrations', () => {
    // (a) :memory: checks
    const mem = openSqliteStorage(':memory:');
    assert.equal(mem.isOpen, true);
    assert.equal(mem.getJournalMode(), 'memory');
    assert.equal(mem.getPragma('foreign_keys'), 1);
    assert.equal(mem.getPragma('synchronous'), 1);
    assert.equal(mem.getPragma('busy_timeout'), 5000);
    mem.close();
    mem.close(); // idempotent double-close!
    assert.equal(mem.isOpen, false);
    assert.throws(() => mem.get('SELECT 1'), (err) => err.code === ERROR_CODES.E_STORAGE_CLOSED);

    // (b) File-backed WAL + nested directory creation + FK + BLOB + nested SAVEPOINT + reopen
    const dir = makeTempDir('omnios-sqlite-');
    const dbPath = path.join(dir, 'nested', 'sub', 'state.sqlite');
    const db = new SqliteStorage(dbPath);
    assert.equal(db.getJournalMode(), 'wal');

    const m1 = db.migrate([
      {
        id: '001_init',
        sql: `
          CREATE TABLE parents (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
          CREATE TABLE items (
            id INTEGER PRIMARY KEY,
            parent_id INTEGER NOT NULL REFERENCES parents(id),
            data BLOB
          );
        `,
      },
    ]);
    assert.deepStrictEqual(m1.applied, ['001_init']);
    // Second run is idempotent
    const m2 = db.migrate([{ id: '001_init', sql: 'INVALID SQL SHOULD NOT RUN' }]);
    assert.deepStrictEqual(m2.applied, []);
    assert.deepStrictEqual(m2.skipped, ['001_init']);

    // Foreign key enforcement
    assert.throws(() => db.run('INSERT INTO items (id, parent_id) VALUES (1, 999)'));

    // Plain-object deepStrictEqual + Uint8Array subarray & empty BLOB round-trip
    db.run('INSERT INTO parents (id, name) VALUES (?, ?)', 1, 'root');
    const sliceBlob = new Uint8Array([10, 20, 30, 40, 50]).subarray(1, 4);
    db.run('INSERT INTO items (id, parent_id, data) VALUES (?, ?, ?)', 1, 1, sliceBlob);
    db.run('INSERT INTO items (id, parent_id, data) VALUES (?, ?, ?)', 2, 1, new Uint8Array(0));

    const parentRow = db.get('SELECT id, name FROM parents WHERE id = ?', 1);
    assert.deepStrictEqual(parentRow, { id: 1, name: 'root' });
    assert.equal(db.get('SELECT id FROM parents WHERE id = ?', 999), null);

    const item1 = db.get('SELECT id, data FROM items WHERE id = ?', 1);
    assert.ok(item1.data instanceof Uint8Array);
    assert.deepStrictEqual(Array.from(item1.data), [20, 30, 40]);
    const item2 = db.get('SELECT id, data FROM items WHERE id = ?', 2);
    assert.ok(item2.data instanceof Uint8Array);
    assert.equal(item2.data.byteLength, 0);

    // Nested SAVEPOINT: inner rollback caught by outer while outer commits
    db.transaction(() => {
      db.run('INSERT INTO parents (id, name) VALUES (?, ?)', 2, 'outer-kept');
      try {
        db.transaction(() => {
          db.run('INSERT INTO parents (id, name) VALUES (?, ?)', 3, 'inner-rolled-back');
          throw new Error('inner fail');
        });
      } catch {
        // swallowed by outer
      }
    });
    assert.deepStrictEqual(db.get('SELECT id, name FROM parents WHERE id = ?', 2), { id: 2, name: 'outer-kept' });
    assert.equal(db.get('SELECT id FROM parents WHERE id = ?', 3), null);

    // Async callback in transaction MUST reject with E_ASYNC_TRANSACTION and roll back cleanly
    assert.throws(
      () =>
        db.transaction(async () => {
          db.run('INSERT INTO parents (id, name) VALUES (?, ?)', 4, 'async-bad');
        }),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_ASYNC_TRANSACTION
    );
    assert.equal(db.inTransaction, false);
    assert.equal(db.get('SELECT id FROM parents WHERE id = ?', 4), null);

    // Nested SAVEPOINT: inner commits, then outer throws -> BOTH rolled back
    assert.throws(() => {
      db.transaction(() => {
        db.run('INSERT INTO parents (id, name) VALUES (?, ?)', 5, 'outer-abort');
        db.transaction(() => {
          db.run('INSERT INTO parents (id, name) VALUES (?, ?)', 6, 'inner-commit-then-outer-abort');
        });
        throw new Error('outer fail');
      });
    });
    assert.equal(db.get('SELECT id FROM parents WHERE id = ?', 5), null);
    assert.equal(db.get('SELECT id FROM parents WHERE id = ?', 6), null);

    // Namespaced migrations & atomic rollback on failing migration
    const nsRes = db.migrate('vfs', [
      { version: 1, name: 'vfs_meta', sql: 'CREATE TABLE vfs_test (k TEXT PRIMARY KEY);' },
    ]);
    assert.deepStrictEqual(nsRes.applied, ['vfs_1']);
    assert.throws(
      () =>
        db.migrate('vfs', [
          {
            version: 2,
            up: (s) => {
              s.run('INSERT INTO vfs_test (k) VALUES (?)', 'should-rollback');
              throw new Error('broken migration');
            },
          },
        ]),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_MIGRATION_FAILED
    );
    assert.equal(db.get('SELECT k FROM vfs_test WHERE k = ?', 'should-rollback'), null);

    db.close();

    // Persistence across fresh reopen
    const db2 = new SqliteStorage(dbPath);
    assert.deepStrictEqual(db2.get('SELECT id, name FROM parents WHERE id = ?', 2), { id: 2, name: 'outer-kept' });
    assert.equal(db2.getAppliedMigrations().length, 2);
    db2.close();
  });
});

// ============================================================================
// Suite 16: Iteration 2 Hardening & Adversarial Regression Tests
// ============================================================================
describe('Suite 16: M1 Hardening & Adversarial Regressions', () => {
  it('16.1 SqliteStorage suppresses UnhandledPromiseRejection on rejecting async transaction (outer/nested) and rejects async migrate()', async () => {
    const unhandled = [];
    const onUnhandled = (reason) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);

    const db = openSqliteStorage(':memory:');
    try {
      db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);');

      // (a) Top-level rejecting async transaction callback
      assert.throws(
        () =>
          db.transaction(async () => {
            db.run('INSERT INTO t (id, v) VALUES (?, ?)', 1, 'outer-async');
            throw new Error('outer_async_boom');
          }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_ASYNC_TRANSACTION
      );
      assert.equal(db.inTransaction, false);
      assert.equal(db.get('SELECT id FROM t WHERE id = ?', 1), null);

      // (b) Nested SAVEPOINT rejecting async transaction callback (outer still commits)
      db.transaction(() => {
        db.run('INSERT INTO t (id, v) VALUES (?, ?)', 2, 'outer-sync-kept');
        assert.throws(
          () =>
            db.transaction(async () => {
              db.run('INSERT INTO t (id, v) VALUES (?, ?)', 3, 'nested-async');
              throw new Error('nested_async_boom');
            }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_ASYNC_TRANSACTION
        );
      });
      assert.deepStrictEqual(db.get('SELECT id, v FROM t WHERE id = ?', 2), { id: 2, v: 'outer-sync-kept' });
      assert.equal(db.get('SELECT id FROM t WHERE id = ?', 3), null);

      // (c) Async migration up() callback -> throws E_MIGRATION_FAILED (cause E_ASYNC_TRANSACTION), rolls back & does NOT record migration
      assert.throws(
        () =>
          db.migrate('async_ns', [
            {
              version: 1,
              up: async (s) => {
                s.run('INSERT INTO t (id, v) VALUES (?, ?)', 4, 'async-mig-row');
                await new Promise((r) => setTimeout(r, 10));
                throw new Error('async_migration_boom');
              },
            },
          ]),
        (err) =>
          err instanceof OmniOSError &&
          err.code === ERROR_CODES.E_MIGRATION_FAILED &&
          err.cause instanceof OmniOSError &&
          err.cause.code === ERROR_CODES.E_ASYNC_TRANSACTION
      );
      assert.equal(db.get('SELECT id FROM t WHERE id = ?', 4), null);
      assert.deepStrictEqual(db.getAppliedMigrations(), []);

      // Allow rejected async timers/microtasks to flush and prove ZERO unhandled rejections
      await new Promise((r) => setTimeout(r, 30));
      assert.deepStrictEqual(unhandled, []);
    } finally {
      process.off('unhandledRejection', onUnhandled);
      db.close();
    }
  });

  it('16.2 ServiceManager prevents stopped-service resurrection, deduplicates concurrent checkHealth, handles safeMode broken non-essential deps, and stops health monitor on kernel.panic()', async () => {
    // (a1) stop() during in-flight async healthCheck() keeps service STOPPED
    const sm1 = new ServiceManager();
    let starts1 = 0;
    let releaseProbe;
    sm1.register({
      name: 'probe-race',
      maxRestarts: 2,
      restartBackoffMs: 10,
      start: async () => { starts1 += 1; },
      healthCheck: () =>
        new Promise((resolve) => {
          releaseProbe = () => resolve(false);
        }),
    });
    await sm1.start('probe-race');
    const hc1 = sm1.checkHealth('probe-race');
    await sm1.stop('probe-race');
    releaseProbe();
    await hc1;
    assert.equal(sm1.getStatus('probe-race').state, SERVICE_STATES.STOPPED);
    assert.equal(starts1, 1);

    // (a2) stopAll() during in-flight async start() (both direct start and restart) keeps service STOPPED
    const sm2 = new ServiceManager();
    let startCalls2 = 0;
    let stopCalls2 = 0;
    sm2.register({
      name: 'start-race',
      maxRestarts: 2,
      restartBackoffMs: 10,
      start: async () => {
        startCalls2 += 1;
        if (startCalls2 >= 2) {
          await new Promise((r) => setTimeout(r, 70));
        }
      },
      stop: async () => { stopCalls2 += 1; },
      healthCheck: async () => false,
    });
    await sm2.start('start-race');
    const hc2 = sm2.checkHealth('start-race');
    await new Promise((r) => setTimeout(r, 30)); // inside 2nd async start()
    await sm2.stopAll();
    await hc2;
    assert.equal(sm2.getStatus('start-race').state, SERVICE_STATES.STOPPED);
    assert.ok(stopCalls2 >= 2);

    // Direct slow start() racing with stop()
    const smDirect = new ServiceManager();
    let directStops = 0;
    smDirect.register({
      name: 'direct-slow',
      start: async () => { await new Promise((r) => setTimeout(r, 50)); },
      stop: async () => { directStops += 1; },
    });
    const directStart = smDirect.start('direct-slow');
    await new Promise((r) => setTimeout(r, 15));
    await smDirect.stop('direct-slow');
    await directStart;
    assert.equal(smDirect.getStatus('direct-slow').state, SERVICE_STATES.STOPPED);
    assert.ok(directStops >= 1);

    // (b) Concurrent checkHealth() coalesces onto 1 crash loop respecting maxRestarts
    const sm3 = new ServiceManager();
    let allowStart3 = true;
    sm3.register({
      name: 'dup-health',
      maxRestarts: 2,
      restartBackoffMs: 15,
      start: async () => {
        if (!allowStart3) throw new Error('still broken');
      },
      healthCheck: async () => {
        await new Promise((r) => setTimeout(r, 15));
        return false;
      },
    });
    await sm3.start('dup-health');
    allowStart3 = false;
    const [r1, r2] = await Promise.all([sm3.checkHealth('dup-health'), sm3.checkHealth('dup-health')]);
    const st3 = sm3.getStatus('dup-health');
    assert.equal(r1.state, SERVICE_STATES.FAILED);
    assert.equal(r2.state, SERVICE_STATES.FAILED);
    assert.equal(st3.totalRestarts, 2);
    assert.deepStrictEqual(st3.backoffHistory, [15, 30]);

    // (c) startAll({ safeMode: true }) succeeds even when a non-essential service has a missing dependency
    const kernelSafe = createKernel();
    kernelSafe.serviceManager.register({ name: 'ess', essential: true, start: async () => {} });
    kernelSafe.serviceManager.register({
      name: 'broken-plugin',
      deps: ['nonexistent-plugin-dep'],
      essential: false,
      start: async () => {},
    });
    const safeReport = await kernelSafe.boot({ safeMode: true });
    assert.equal(safeReport.status, KERNEL_STATES.SAFE_MODE);
    assert.equal(kernelSafe.serviceManager.getStatus('ess').state, SERVICE_STATES.RUNNING);
    assert.equal(kernelSafe.serviceManager.getStatus('broken-plugin').state, SERVICE_STATES.STOPPED);
    await kernelSafe.shutdown();

    // (d) kernel.panic() stops the background health monitor
    const kernelPanicMon = createKernel();
    let probeCount = 0;
    kernelPanicMon.serviceManager.register({
      name: 'mon-svc',
      essential: true,
      start: async () => {},
      healthCheck: async () => {
        probeCount += 1;
        return true;
      },
    });
    await kernelPanicMon.boot();
    kernelPanicMon.serviceManager.startHealthMonitor(15);
    await new Promise((r) => setTimeout(r, 40));
    assert.ok(probeCount >= 1);

    kernelPanicMon.panic('E_TEST_PANIC', 'Testing health monitor halt');
    const probesAtPanic = probeCount;
    await new Promise((r) => setTimeout(r, 60));
    assert.equal(probeCount, probesAtPanic, 'Health monitor must not run probes after kernel.panic()');
    await kernelPanicMon.shutdown();
  });

  it('16.3 OmniKernel.panic() safely clones Date(NaN), throwing getters, null-proto Map keys, and deep graphs to SQLite', async () => {
    const dir = makeTempDir('omnios-hostile-panic-');
    const dbPath = path.join(dir, 'hostile.sqlite');
    const k = createKernel({ dbPath });
    await k.boot();

    // Top-level invalid Date
    const dump1 = k.panic('E_DATE_TOP', 'Invalid top-level Date', new Date(NaN));
    assert.equal(dump1.context, 'Invalid Date');
    assert.ok(typeof dump1.id === 'number' && dump1.id >= 1);

    // Array-nested invalid Date + throwing getter + Object.create(null) Map key + deep nesting
    const hostileObj = {};
    Object.defineProperty(hostileObj, 'boom', {
      enumerable: true,
      get() { throw new Error('getter exploded'); },
    });
    const nullKey = Object.create(null);
    const hostileMap = new Map([[nullKey, 'mapped-val']]);
    let deep = { leaf: 'end' };
    for (let i = 0; i < 40; i++) deep = { next: deep };

    const dump2 = k.panic('E_HOSTILE_CTX', 'Hostile context bundle', {
      arr: [1, new Date(NaN)],
      hostileObj,
      hostileMap,
      deep,
    });
    assert.deepStrictEqual(dump2.context.arr, [1, 'Invalid Date']);
    assert.equal(dump2.context.hostileObj.boom, '[Unreadable]');
    assert.equal(dump2.context.hostileMap['[UnstringifiableKey]'], 'mapped-val');
    assert.ok(typeof dump2.id === 'number' && dump2.id > dump1.id);

    const history = k.getPanicHistory();
    assert.equal(history.length, 2);
    assert.equal(history[0].code, 'E_HOSTILE_CTX');
    assert.deepStrictEqual(history[0].context.arr, [1, 'Invalid Date']);
    assert.equal(history[1].context, 'Invalid Date');
    await k.shutdown();
  });

  it('16.4 built-in exit syscall protects system PID 0 and PID 1 with SyscallError(EPERM)', async () => {
    const kernel = createKernel();
    await kernel.boot();

    assert.throws(
      () => kernel.syscalls.dispatch('exit', { pid: 0 }, 0),
      (err) => err instanceof SyscallError && err.code === ERROR_CODES.EPERM && err.pid === 0
    );
    assert.throws(
      () => kernel.syscalls.dispatch('exit', { pid: 1 }, 0),
      (err) => err instanceof SyscallError && err.code === ERROR_CODES.EPERM && err.pid === 1
    );
    assert.equal(kernel.processManager.get(0).state, PROCESS_STATES.READY);
    assert.equal(kernel.processManager.get(1).state, PROCESS_STATES.READY);

    await kernel.shutdown();
  });

  it('16.5 guards CpuRegistry/errors/SyscallDispatcher against prototype keys, EventBus custom thenables, and atomic BinaryWriter.ascii()', async () => {
    // CpuRegistry prototype keys (normalized to lowercase strings, never Object.prototype functions)
    const reg = new CpuRegistry();
    reg.register('constructor', () => ({ arch: 'constructor' }));
    reg.register('toString', () => ({ arch: 'toString' }));
    reg.register('__proto__', () => ({ arch: '__proto__' }));
    assert.deepStrictEqual(reg.list(), ['constructor', 'tostring', '__proto__']);
    assert.ok(reg.list().every((k) => typeof k === 'string'));
    assert.equal(reg.create('constructor').arch, 'constructor');
    assert.equal(reg.create('__proto__').arch, '__proto__');

    // errors.mjs prototype keys
    const protoErr = new OmniOSError('proto', { code: 'constructor' });
    assert.equal(protoErr.errno, null);
    assert.equal(POSIX_ERRNO['constructor'], undefined);
    assert.equal(DARWIN_ERRNO['toString'], undefined);
    assert.equal(WIN32_ERROR['__proto__'], undefined);
    assert.equal(WASI_ERRNO['constructor'], undefined);
    assert.equal(SIGNALS['constructor'], undefined);
    assert.equal(SIGNAL_NAMES['constructor'], undefined);
    assert.equal(ERROR_CODES['constructor'], undefined);

    // SyscallDispatcher.getStats() __proto__ safety
    const disp = new SyscallDispatcher();
    assert.throws(() => disp.dispatch('__proto__'), SyscallError);
    const stats = disp.getStats();
    assert.equal(Object.prototype.hasOwnProperty.call(stats.bySyscall, '__proto__'), true);
    assert.equal(Object.getPrototypeOf(stats.bySyscall), Object.prototype);
    assert.deepStrictEqual(stats.bySyscall['__proto__'], { calls: 1, errors: 1 });

    // KernelEventBus custom non-Promise thenable without .catch()
    const busErrors = [];
    const bus = new KernelEventBus({ onError: (e) => busErrors.push(e.error) });
    bus.on('custom-thenable', () => ({
      then(_onFulfilled, onRejected) {
        queueMicrotask(() => onRejected(new Error('thenable_boom')));
      },
    }));
    const emitRes = bus.emit('custom-thenable', {});
    assert.equal(emitRes.errors.length, 0);
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(busErrors.length, 1);
    assert.equal(busErrors[0].message, 'thenable_boom');

    // BinaryWriter.ascii() atomicity after seek()
    const w = new BinaryWriter();
    w.ascii('AAAAAAAAAA');
    w.seek(0);
    assert.throws(
      () => w.ascii('hello\u0100'),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL
    );
    assert.equal(new TextDecoder().decode(w.toUint8Array()), 'AAAAAAAAAA');
    assert.equal(w.offset, 0);
  });

  it('16.6 AddressSpace handles top 53-bit page, O(mappedPages) sparse munmap, mprotect re-coalesce, atomic alloc ENOMEM, and INVALID_FREE on remainder', () => {
    // (a) Top 53-bit VA page 0x1FFFFFFFFFF000
    const TOP_PAGE = 0x1ffffffffff000;
    const vmmTop = new AddressSpace({ pid: 100 });
    assert.equal(vmmTop.mmap(TOP_PAGE, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, 'top53'), TOP_PAGE);
    vmmTop.write(TOP_PAGE, new Uint8Array([0x90, 0x90, 0xc3]));
    assert.deepStrictEqual(Array.from(vmmTop.fetch(TOP_PAGE, 3)), [0x90, 0x90, 0xc3]);
    vmmTop.writeCString(MAX_VA - 2, 'hi'); // writes 'h','i','\0' right up to MAX_VA
    assert.equal(vmmTop.readCString(MAX_VA - 2, 256), 'hi');
    assert.equal(vmmTop.readU8(MAX_VA), 0x00);
    // Overflow past MAX_VA must still be rejected cleanly
    assert.throws(() => vmmTop.read(MAX_VA, 2), MemoryFaultError);
    assert.throws(() => vmmTop.mmap(TOP_PAGE, 2 * PAGE_SIZE, PROT_READ), MemoryFaultError);
    // mprotect & munmap on top page
    vmmTop.mprotect(TOP_PAGE, PAGE_SIZE, PROT_READ);
    assert.throws(() => vmmTop.write(TOP_PAGE, new Uint8Array([1])), (e) => e.faultType === 'WRITE_VIOLATION');
    vmmTop.munmap(TOP_PAGE, PAGE_SIZE);
    assert.equal(vmmTop.getStats().mappedPages, 0);
    // reserveGuard on top 53-bit page
    vmmTop.reserveGuard(TOP_PAGE, PAGE_SIZE, 'TOP_GUARD');
    assert.throws(
      () => vmmTop.read(MAX_VA, 1),
      (err) => err instanceof MemoryFaultError && err.faultType === 'GUARD_PAGE'
    );

    // (b) Huge sparse munmap (1 TiB) completes in < 50ms + mprotect re-coalescing back to 1 region
    const vmmSparse = new AddressSpace({ pid: 101 });
    vmmSparse.mmap(0x200000000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'island');
    const t0 = performance.now();
    vmmSparse.munmap(0x200000000, 0x10000000000); // 1 TiB sparse unmap
    const elapsed = performance.now() - t0;
    assert.ok(elapsed < 50, `Expected 1 TiB sparse munmap < 50ms, took ${elapsed.toFixed(2)}ms`);
    assert.equal(vmmSparse.getStats().mappedPages, 0);

    const coalBase = vmmSparse.mmap(0x300000000, 3 * PAGE_SIZE, PROT_READ | PROT_WRITE, 'coal');
    vmmSparse.mprotect(coalBase + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_EXEC);
    assert.equal(vmmSparse.getStats().regions.filter((r) => r.label === 'coal').length, 3);
    vmmSparse.mprotect(coalBase + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE);
    const coalesced = vmmSparse.getStats().regions.filter((r) => r.label === 'coal');
    assert.equal(coalesced.length, 1);
    assert.equal(coalesced[0].size, 3 * PAGE_SIZE);

    // (c) Failed initial alloc() (ENOMEM) must NOT poison _heapBase before __PAGEZERO
    const vmmOom = new AddressSpace({ pid: 102, maxMemoryBytes: PAGE_SIZE });
    assert.throws(
      () => vmmOom.alloc(2 * PAGE_SIZE),
      (err) => err instanceof MemoryFaultError && err.code === ERROR_CODES.ENOMEM
    );
    assert.equal(vmmOom.getStats().heap.base, null);
    vmmOom.reserveGuard(0, 0x100000000, '__PAGEZERO');
    const safePtr = vmmOom.alloc(64);
    assert.ok(safePtr >= HIGH_VA_HEAP_BASE);
    assert.ok(vmmOom.getStats().heap.base >= HIGH_VA_HEAP_BASE);

    // (d) free(p + 64) & realloc(p + 64, 32) on never-allocated remainder throws INVALID_FREE (not DOUBLE_FREE)
    const vmmFree = new AddressSpace({ pid: 103 });
    const p = vmmFree.alloc(64);
    assert.throws(
      () => vmmFree.free(p + 64),
      (err) => err instanceof MemoryFaultError && err.faultType === 'INVALID_FREE'
    );
    assert.throws(
      () => vmmFree.realloc(p + 64, 32),
      (err) => err instanceof MemoryFaultError && err.faultType === 'INVALID_FREE'
    );
    // Genuine free then double-free still throws DOUBLE_FREE
    vmmFree.free(p);
    assert.throws(
      () => vmmFree.free(p),
      (err) => err instanceof MemoryFaultError && err.faultType === 'DOUBLE_FREE'
    );
  });

  it('16.7 ProcessManager validates ppid, breaks getTree cycles, decodes stream payloads safely, enforces markRunning/CREATED FSM, and preserves BLOCKED threads across SIGSTOP/SIGCONT & exitThread', () => {
    const bus = new KernelEventBus();
    const streamEvents = [];
    bus.on('process:stdin', (e) => streamEvents.push(['stdin', e.data]));
    bus.on('process:stdout', (e) => streamEvents.push(['stdout', e.data]));
    bus.on('process:stderr', (e) => streamEvents.push(['stderr', e.data]));

    const pm = new ProcessManager({ eventBus: bus });
    pm.spawnSystemProcess({ pid: 0, ppid: 0, name: 'kernel_idle' });
    pm.spawnSystemProcess({ pid: 1, ppid: 0, name: 'omnid' });

    // (a) spawn() rejects forward/invalid/self ppid; getTree() breaks 2-node and 3-node cycles without dropping nodes
    assert.throws(
      () => pm.spawn({ name: 'bad-forward', ppid: 999 }),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.ESRCH
    );
    assert.throws(
      () => pm.spawn({ name: 'bad-self', ppid: 2 }),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.ESRCH
    );
    assert.throws(
      () => pm.spawn({ name: 'bad-neg', ppid: -1 }),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.ESRCH
    );

    const a = pm.spawn({ name: 'cycA', ppid: 1 });
    const b = pm.spawn({ name: 'cycB', ppid: a.pid });
    const c = pm.spawn({ name: 'cycC', ppid: b.pid });
    // Force a 3-node cycle directly on PCBs to test defensive getTree() cycle breaking
    a.ppid = c.pid;
    const tree = pm.getTree();
    assert.doesNotThrow(() => JSON.stringify(tree));
    const seen = new Set();
    const walk = (nodes) => {
      for (const n of nodes) {
        assert.equal(seen.has(n.pid), false, `Duplicate/cycle node PID ${n.pid}`);
        seen.add(n.pid);
        walk(n.children);
      }
    };
    walk(tree);
    assert.equal(seen.has(a.pid), true);
    assert.equal(seen.has(b.pid), true);
    assert.equal(seen.has(c.pid), true);
    a.ppid = 1; // restore

    // (b) Stream writes with Uint8Array, subarray, and numeric payloads under attached eventBus
    const ioProc = pm.spawn({ name: 'io-types' });
    pm.writeStdin(ioProc.pid, new Uint8Array([65, 66, 67]).subarray(1, 3));
    pm.writeStdout(ioProc.pid, 12345);
    pm.writeStderr(ioProc.pid, new TextEncoder().encode('err-bytes'));
    assert.equal(pm.readStdin(ioProc.pid), 'BC');
    assert.equal(pm.readStdout(ioProc.pid), '12345');
    assert.equal(pm.readStderr(ioProc.pid), 'err-bytes');
    assert.deepStrictEqual(streamEvents, [
      ['stdin', 'BC'],
      ['stdout', '12345'],
      ['stderr', 'err-bytes'],
    ]);

    // (c) markRunning() rejects invalid PCB & TCB states
    const createdP = pm.spawn({ name: 'created-fsm', autoReady: false });
    assert.throws(
      () => pm.markRunning(createdP.pid, 1),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );
    // (f) CREATED -> TERMINATED rejected; SIGSTOP on CREATED allowed and SIGCONT -> READY
    assert.throws(
      () => pm.transitionState(createdP.pid, PROCESS_STATES.TERMINATED),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );
    pm.kill(createdP.pid, 'SIGSTOP');
    assert.equal(createdP.state, PROCESS_STATES.STOPPED);
    assert.throws(
      () => pm.markRunning(createdP.pid, 1),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );
    pm.kill(createdP.pid, 'SIGCONT');
    assert.equal(createdP.state, PROCESS_STATES.READY);
    assert.equal(createdP.threads.get(1).state, THREAD_STATES.READY);

    // (d) SIGSTOP/SIGCONT preserves pre-stop BLOCKED threads without stale waitReason
    const mt = pm.spawn({ name: 'sigstop-mt' });
    const w = pm.createThread(mt.pid, { name: 'blocked-worker' });
    pm.markBlocked(mt.pid, w.tid, 'stdin');
    assert.equal(mt.state, PROCESS_STATES.READY);
    assert.equal(w.state, THREAD_STATES.BLOCKED);
    assert.throws(() => pm.markRunning(mt.pid, w.tid), ProcessError);

    pm.kill(mt.pid, 'SIGSTOP');
    assert.equal(mt.state, PROCESS_STATES.STOPPED);
    assert.equal(mt.threads.get(1).state, THREAD_STATES.STOPPED);
    assert.equal(w.state, THREAD_STATES.STOPPED);

    pm.kill(mt.pid, 'SIGCONT');
    assert.equal(mt.state, PROCESS_STATES.READY);
    assert.equal(mt.threads.get(1).state, THREAD_STATES.READY);
    assert.equal(mt.threads.get(1).waitReason, null);
    assert.equal(w.state, THREAD_STATES.BLOCKED);
    assert.equal(w.waitReason, 'stdin');

    // All-blocked process across SIGSTOP/SIGCONT restores PCB to BLOCKED
    const allBlocked = pm.spawn({ name: 'all-blocked' });
    pm.markBlocked(allBlocked.pid, 1, 'stdin');
    pm.kill(allBlocked.pid, 'SIGSTOP');
    assert.equal(allBlocked.state, PROCESS_STATES.STOPPED);
    pm.kill(allBlocked.pid, 'SIGCONT');
    assert.equal(allBlocked.state, PROCESS_STATES.BLOCKED);
    assert.equal(allBlocked.threads.get(1).state, THREAD_STATES.BLOCKED);
    assert.equal(allBlocked.threads.get(1).waitReason, 'stdin');
    pm.writeStdin(allBlocked.pid, 'wake!');
    assert.equal(allBlocked.state, PROCESS_STATES.READY);
    assert.equal(allBlocked.threads.get(1).waitReason, null);

    // (e) exitThread transitions READY -> BLOCKED when only blocked threads remain
    const mtExit = pm.spawn({ name: 'exit-thread-ready-to-blocked' });
    const wExit = pm.createThread(mtExit.pid, { name: 'last-ready-worker' });
    pm.markBlocked(mtExit.pid, 1, 'io');
    assert.equal(mtExit.state, PROCESS_STATES.READY);
    pm.exitThread(mtExit.pid, wExit.tid, 0);
    assert.equal(mtExit.state, PROCESS_STATES.BLOCKED);
    assert.equal(mtExit.threads.get(1).state, THREAD_STATES.BLOCKED);
  });

  it('16.8 Scheduler guards in-step thread mutations, rejects non-finite/negative instructionsExecuted, preserves exact-boundary FAULT, refuses STOPPED state, and respects per-thread priority', async () => {
    // (a) In-step worker exitThread + YIELD never resurrects disposed worker thread
    const pm = new ProcessManager();
    const sched = new Scheduler({ processManager: pm, baseQuantum: 50 });

    let workerSteps = 0;
    let workerDisposes = 0;
    const pRes = pm.spawn({
      name: 'in-step-exit-thread',
      executionContext: makeWorkContext({ totalWork: 500 }),
    });
    const wRes = pm.createThread(pRes.pid, {
      name: 'self-exit-worker',
      executionContext: {
        step() {
          workerSteps += 1;
          pm.exitThread(pRes.pid, wRes.tid, 7);
          return { status: 'YIELD', instructionsExecuted: 5 };
        },
        dispose() { workerDisposes += 1; },
      },
    });
    sched.step(5);
    assert.equal(workerSteps, 1);
    assert.equal(workerDisposes, 1);
    assert.equal(wRes.state, THREAD_STATES.EXITED);

    // (b) In-step markBlocked + YIELD never deadlocks PCB/TCB and wakes cleanly on writeStdin
    let blockedSteps = 0;
    const pBlk = pm.spawn({
      name: 'in-step-block',
      executionContext: {
        step() {
          blockedSteps += 1;
          if (blockedSteps === 1) {
            pm.markBlocked(pBlk.pid, 1, 'stdin');
            return { status: 'YIELD', instructionsExecuted: 2 };
          }
          return { status: 'EXITED', instructionsExecuted: 3, exitCode: 0 };
        },
        dispose() {},
      },
    });
    sched.step(1);
    assert.equal(pBlk.state, PROCESS_STATES.BLOCKED);
    assert.equal(pBlk.threads.get(1).state, THREAD_STATES.BLOCKED);
    assert.equal(pBlk.threads.get(1).waitReason, 'stdin');
    pm.writeStdin(pBlk.pid, 'go');
    assert.equal(pBlk.state, PROCESS_STATES.READY);
    assert.equal(pBlk.threads.get(1).state, THREAD_STATES.READY);
    const blkSummary = sched.runUntilIdle(pBlk.pid, 5);
    assert.equal(blkSummary.state, PROCESS_STATES.ZOMBIE);
    assert.equal(blkSummary.exitCode, 0);

    // (c) Infinity / -Infinity / NaN / -50 instructionsExecuted immediately fault with SIGXCPU (152)
    const pmQ = new ProcessManager();
    const schedQ = new Scheduler({ processManager: pmQ, baseQuantum: 100 });
    const badValues = [Infinity, -Infinity, Number.NaN, -50];
    const badProcs = badValues.map((val, i) =>
      pmQ.spawn({
        name: `bad-exec-${i}`,
        quotas: { maxInstructionsPerTick: 100, maxTotalInstructions: 500 },
        executionContext: {
          step: () => ({ status: 'YIELD', instructionsExecuted: val }),
          dispose: () => {},
        },
      })
    );
    const healthyQ = pmQ.spawn({
      name: 'healthy-sibling',
      executionContext: makeWorkContext({ totalWork: 100, exitCode: 0 }),
    });
    schedQ.step(3);
    for (const bp of badProcs) {
      assert.equal(bp.state, PROCESS_STATES.ZOMBIE);
      assert.equal(bp.stats.exitSignal, 'SIGXCPU');
      assert.equal(bp.stats.exitCode, 152);
    }
    assert.equal(healthyQ.state, PROCESS_STATES.ZOMBIE);
    assert.equal(healthyQ.stats.exitCode, 0);

    // (d) { status: 'FAULT' } return path & exact maxTotalInstructions boundary preserves SIGSEGV (139)
    const pmF = new ProcessManager();
    const schedF = new Scheduler({ processManager: pmF, baseQuantum: 200 });
    const pExactFault = pmF.spawn({
      name: 'exact-fault',
      quotas: { maxInstructionsPerTick: 200, maxTotalInstructions: 100 },
      executionContext: {
        step: () => ({
          status: 'FAULT',
          instructionsExecuted: 100,
          fault: new MemoryFaultError('segv at 100th instruction', { address: 0x0 }),
        }),
        dispose: () => {},
      },
    });
    const pOverrunFault = pmF.spawn({
      name: 'overrun-fault',
      quotas: { maxInstructionsPerTick: 200, maxTotalInstructions: 100 },
      executionContext: {
        step: () => ({
          status: 'FAULT',
          instructionsExecuted: 101,
          fault: new MemoryFaultError('overran quota', { address: 0x0 }),
        }),
        dispose: () => {},
      },
    });
    schedF.step(1);
    assert.equal(pExactFault.stats.exitSignal, 'SIGSEGV');
    assert.equal(pExactFault.stats.exitCode, 139);
    assert.equal(pOverrunFault.stats.exitSignal, 'SIGXCPU');
    assert.equal(pOverrunFault.stats.exitCode, 152);

    // (e) Strict refusal in STOPPED kernel state
    const kStopped = createKernel();
    await kStopped.boot();
    await kStopped.shutdown();
    assert.equal(kStopped.state, KERNEL_STATES.STOPPED);
    assert.equal(kStopped.scheduler.start(10), false);
    assert.equal(kStopped.scheduler.isRunning(), false);
    assert.deepStrictEqual(kStopped.scheduler.step(5), {
      ticksRun: 0,
      instructionsExecuted: 0,
      activePids: [],
    });

    // (f) Per-thread priority respected in scheduling order and quantum size
    const pmP = new ProcessManager();
    const schedP = new Scheduler({ processManager: pmP, baseQuantum: 100 });
    const runOrder = [];
    const pMultiPrio = pmP.spawn({
      name: 'per-thread-prio',
      priority: 10, // low-priority main thread
      executionContext: {
        step(budget) {
          runOrder.push(['main', budget]);
          return { status: 'YIELD', instructionsExecuted: budget };
        },
        dispose() {},
      },
    });
    pmP.createThread(pMultiPrio.pid, {
      name: 'high-prio-worker',
      priority: -10, // high-priority worker thread
      executionContext: {
        step(budget) {
          runOrder.push(['worker', budget]);
          return { status: 'YIELD', instructionsExecuted: budget };
        },
        dispose() {},
      },
    });
    schedP.step(1);
    assert.equal(runOrder.length, 2);
    assert.equal(runOrder[0][0], 'worker'); // -10 runs before +10
    assert.equal(runOrder[1][0], 'main');
    assert.ok(runOrder[0][1] > runOrder[1][1], 'High-priority worker must receive larger quantum');
  });

  it('16.9 ProcessManager & Scheduler hardening: markBlocked FSM guards, sibling RUNNING preservation, zero PID/TID leak, dead ppid rejection, and hostile throwing getter isolation', () => {
    // (a) markBlocked() rejects EXITED worker (no resurrection via writeStdin) and ZOMBIE/TERMINATED/STOPPED/CREATED PCBs
    const pm = new ProcessManager();
    pm.spawnSystemProcess({ pid: 0, ppid: 0, name: 'kernel_idle' });
    pm.spawnSystemProcess({ pid: 1, ppid: 0, name: 'omnid' });
    const sched = new Scheduler({ processManager: pm, baseQuantum: 50 });

    let workerRuns = 0;
    let workerDisposed = 0;
    const pRes = pm.spawn({
      name: 'no-resurrect-worker',
      executionContext: { step: () => ({ status: 'YIELD', instructionsExecuted: 1 }), dispose: () => {} },
    });
    const wRes = pm.createThread(pRes.pid, {
      name: 'worker',
      executionContext: {
        step: () => {
          workerRuns += 1;
          return { status: 'YIELD', instructionsExecuted: 1 };
        },
        dispose: () => {
          workerDisposed += 1;
        },
      },
    });
    pm.exitThread(pRes.pid, wRes.tid, 0);
    assert.equal(wRes.state, THREAD_STATES.EXITED);
    assert.equal(workerDisposed, 1);
    assert.throws(
      () => pm.markBlocked(pRes.pid, wRes.tid, 'stdin'),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );
    assert.equal(wRes.state, THREAD_STATES.EXITED);
    pm.writeStdin(pRes.pid, 'wake-attempt');
    sched.step(2);
    assert.equal(workerRuns, 0, 'Disposed EXITED worker must never be resurrected or executed');
    assert.equal(wRes.state, THREAD_STATES.EXITED);

    // Reject markBlocked on CREATED, STOPPED, ZOMBIE, TERMINATED PCBs
    const pCreated = pm.spawn({ name: 'created-block', autoReady: false });
    assert.throws(
      () => pm.markBlocked(pCreated.pid, 1, 'stdin'),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );
    assert.equal(pCreated.threads.get(1).state, THREAD_STATES.CREATED);

    const pStopped = pm.spawn({ name: 'stopped-block' });
    pm.kill(pStopped.pid, 'SIGSTOP');
    assert.throws(
      () => pm.markBlocked(pStopped.pid, 1, 'stdin'),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );
    assert.equal(pStopped.threads.get(1).state, THREAD_STATES.STOPPED);

    const pZombie = pm.spawn({ name: 'zombie-block' });
    pm.exit(pZombie.pid, 0);
    assert.throws(
      () => pm.markBlocked(pZombie.pid, 1, 'stdin'),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );
    assert.equal(pm.toSummary(pZombie).activeThreadCount, 0);

    pm.reap(pZombie.pid);
    assert.equal(pZombie.state, PROCESS_STATES.TERMINATED);
    assert.throws(
      () => pm.markBlocked(pZombie.pid, 1, 'stdin'),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
    );

    // (b) markBlocked() and exitThread() preserve pcb.state === RUNNING when sibling thread is still RUNNING
    const pSib = pm.spawn({ name: 'sib-running' });
    const w1 = pm.createThread(pSib.pid, { name: 'w1' });
    const w2 = pm.createThread(pSib.pid, { name: 'w2' });
    pm.markRunning(pSib.pid, 1);
    assert.equal(pSib.state, PROCESS_STATES.RUNNING);
    assert.equal(pSib.threads.get(1).state, THREAD_STATES.RUNNING);

    pm.markBlocked(pSib.pid, w1.tid, 'io');
    assert.equal(pSib.state, PROCESS_STATES.RUNNING, 'PCB must remain RUNNING while thread 1 is RUNNING');
    assert.equal(w1.state, THREAD_STATES.BLOCKED);

    pm.exitThread(pSib.pid, w2.tid, 0);
    assert.equal(pSib.state, PROCESS_STATES.RUNNING, 'PCB must remain RUNNING after sibling exit while thread 1 is RUNNING');
    assert.equal(w2.state, THREAD_STATES.EXITED);

    // Blocking the RUNNING thread itself when another READY thread exists transitions RUNNING -> READY
    const w3 = pm.createThread(pSib.pid, { name: 'w3' });
    pm.markBlocked(pSib.pid, 1, 'io');
    assert.equal(pSib.state, PROCESS_STATES.READY);
    assert.equal(w3.state, THREAD_STATES.READY);

    // (c) Zero _nextPid / _nextTid leak on validation failure + reject ZOMBIE/TERMINATED ppid
    const pmPid = new ProcessManager();
    pmPid.spawnSystemProcess({ pid: 0, ppid: 0, name: 'kernel_idle' });
    pmPid.spawnSystemProcess({ pid: 1, ppid: 0, name: 'omnid' });

    assert.throws(() => pmPid.spawn({ name: '' }), ProcessError);
    assert.throws(() => pmPid.spawn({ name: 'bad-prio', priority: 99 }), ProcessError);
    assert.throws(() => pmPid.spawn({ name: 'bad-fds', quotas: { maxOpenFds: 1 } }), ProcessError);
    const firstUser = pmPid.spawn({ name: 'first-user' });
    assert.equal(firstUser.pid, 2, 'Validation failures must not leak _nextPid');

    assert.throws(() => pmPid.createThread(firstUser.pid, { priority: 99 }), ProcessError);
    assert.throws(() => pmPid.createThread(firstUser.pid, { priority: -25 }), ProcessError);
    const firstWorker = pmPid.createThread(firstUser.pid, { name: 'first-worker' });
    assert.equal(firstWorker.tid, 2, 'Thread validation failures must not leak _nextTid');

    // Reject spawning under ZOMBIE and TERMINATED ppid with ESRCH
    pmPid.exit(firstUser.pid, 0);
    assert.equal(firstUser.state, PROCESS_STATES.ZOMBIE);
    assert.throws(
      () => pmPid.spawn({ name: 'child-of-zombie', ppid: firstUser.pid }),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.ESRCH
    );
    pmPid.reap(firstUser.pid);
    assert.equal(firstUser.state, PROCESS_STATES.TERMINATED);
    assert.throws(
      () => pmPid.spawn({ name: 'child-of-terminated', ppid: firstUser.pid }),
      (err) => err instanceof ProcessError && err.code === ERROR_CODES.ESRCH
    );
    const nextUser = pmPid.spawn({ name: 'after-dead-ppid-rejects' });
    assert.equal(nextUser.pid, 3, 'Dead ppid rejection must not leak _nextPid');

    // (d) Scheduler isolates hostile throwing getters on result & thrown fault objects; siblings execute cleanly
    const pmHostile = new ProcessManager();
    const schedHostile = new Scheduler({ processManager: pmHostile, baseQuantum: 50 });

    const hostileInstr = pmHostile.spawn({
      name: 'hostile-instr-getter',
      priority: -10,
      executionContext: {
        step: () => ({
          get instructionsExecuted() {
            throw new Error('instr_getter_boom');
          },
          status: 'YIELD',
        }),
        dispose: () => {},
      },
    });
    const hostileStatus = pmHostile.spawn({
      name: 'hostile-status-getter',
      priority: -10,
      executionContext: {
        step: () => ({
          instructionsExecuted: 3,
          get status() {
            throw new Error('status_getter_boom');
          },
        }),
        dispose: () => {},
      },
    });
    const hostileFaultProp = pmHostile.spawn({
      name: 'hostile-fault-getter',
      priority: -10,
      executionContext: {
        step: () => ({
          instructionsExecuted: 2,
          status: 'FAULT',
          get fault() {
            throw new Error('fault_getter_boom');
          },
        }),
        dispose: () => {},
      },
    });
    const hostileThrownObj = pmHostile.spawn({
      name: 'hostile-thrown-getters',
      priority: -10,
      executionContext: {
        step: () => {
          throw {
            get instructionsExecuted() {
              throw new Error('err_instr_boom');
            },
            get signal() {
              throw new Error('signal_getter_boom');
            },
            get code() {
              throw new Error('code_getter_boom');
            },
            get message() {
              throw new Error('msg_getter_boom');
            },
          };
        },
        dispose: () => {},
      },
    });

    const hostileWaitReason = pmHostile.spawn({
      name: 'hostile-wait-getter',
      priority: -10,
      executionContext: {
        step: () => ({
          instructionsExecuted: 1,
          status: 'BLOCKED',
          get waitReason() {
            throw new Error('wait_getter_boom');
          },
        }),
        dispose: () => {},
      },
    });
    const hostileExitCode = pmHostile.spawn({
      name: 'hostile-exit-getter',
      priority: -10,
      executionContext: {
        step: () => ({
          instructionsExecuted: 1,
          status: 'EXITED',
          get exitCode() {
            throw new Error('exit_getter_boom');
          },
        }),
        dispose: () => {},
      },
    });
    const hostileThenGetter = pmHostile.spawn({
      name: 'hostile-then-getter',
      priority: -10,
      executionContext: {
        step: () => ({
          get then() {
            throw new Error('then_getter_boom');
          },
          status: 'YIELD',
          instructionsExecuted: 1,
        }),
        dispose: () => {},
      },
    });
    const hostileAsyncStep = pmHostile.spawn({
      name: 'hostile-async-step',
      priority: -10,
      executionContext: {
        step: async () => ({ status: 'EXITED', exitCode: 0, instructionsExecuted: 1 }),
        dispose: () => {},
      },
    });

    const innocentSibling = pmHostile.spawn({
      name: 'innocent-sibling',
      priority: 10,
      executionContext: {
        step: () => ({ status: 'EXITED', exitCode: 0, instructionsExecuted: 7 }),
        dispose: () => {},
      },
    });

    assert.doesNotThrow(() => schedHostile.step(2));
    for (const offender of [
      hostileInstr,
      hostileStatus,
      hostileFaultProp,
      hostileThrownObj,
      hostileWaitReason,
      hostileExitCode,
      hostileThenGetter,
      hostileAsyncStep,
    ]) {
      assert.equal(offender.state, PROCESS_STATES.ZOMBIE, `${offender.name} must be terminated cleanly`);
      assert.notEqual(offender.threads.get(1).state, THREAD_STATES.RUNNING);
    }
    assert.equal(innocentSibling.state, PROCESS_STATES.ZOMBIE);
    assert.equal(innocentSibling.stats.exitCode, 0);
    assert.equal(innocentSibling.stats.instructionsExecuted, 7);
  });

  it('16.10 ServiceManager concurrency hardening & OmniKernel.panic() haltForPanic() + Error.code safe cloning', async () => {
    // (a) Direct concurrent start() & diamond shared async dep coalescing
    const smCoalesce = new ServiceManager();
    let directStarts = 0;
    smCoalesce.register({
      name: 'solo',
      start: async () => {
        directStarts += 1;
        await new Promise((r) => setTimeout(r, 25));
      },
    });
    const [solo1, solo2] = await Promise.all([smCoalesce.start('solo'), smCoalesce.start('solo')]);
    assert.equal(directStarts, 1);
    assert.equal(solo1.state, SERVICE_STATES.RUNNING);
    assert.equal(solo2.state, SERVICE_STATES.RUNNING);

    let aStarts = 0;
    let bStarts = 0;
    smCoalesce.register({
      name: 'dep-a',
      start: async () => {
        aStarts += 1;
        if (aStarts > 1) throw new Error('port_already_bound');
        await new Promise((r) => setTimeout(r, 25));
      },
    });
    smCoalesce.register({
      name: 'branch-b',
      deps: ['dep-a'],
      start: async () => {
        bStarts += 1;
        await new Promise((r) => setTimeout(r, 20));
      },
    });
    smCoalesce.register({ name: 'branch-c', deps: ['dep-a'], start: async () => {} });
    const [bRes1, bRes2, cRes] = await Promise.all([
      smCoalesce.start('branch-b'),
      smCoalesce.start('branch-b'),
      smCoalesce.start('branch-c'),
    ]);
    assert.equal(aStarts, 1);
    assert.equal(bStarts, 1);
    assert.equal(bRes1.state, SERVICE_STATES.RUNNING);
    assert.equal(bRes2.state, SERVICE_STATES.RUNNING);
    assert.equal(cRes.state, SERVICE_STATES.RUNNING);
    assert.equal(smCoalesce.getStatus('dep-a').state, SERVICE_STATES.RUNNING);

    // (b) stopAll() during in-flight startAll() aborts remaining DAG
    const smStopAll = new ServiceManager();
    let releaseA;
    let stopAllAStarts = 0;
    let stopAllBStarts = 0;
    smStopAll.register({
      name: 'a',
      start: () => {
        stopAllAStarts += 1;
        if (stopAllAStarts === 1) {
          return new Promise((r) => {
            releaseA = r;
          });
        }
        return undefined;
      },
    });
    smStopAll.register({
      name: 'b',
      deps: ['a'],
      start: () => {
        stopAllBStarts += 1;
      },
    });
    const startAllP = smStopAll.startAll();
    await new Promise((r) => setTimeout(r, 10));
    await smStopAll.stopAll();
    releaseA();
    const startAllRes = await startAllP;
    assert.equal(smStopAll.getStatus('a').state, SERVICE_STATES.STOPPED);
    assert.equal(smStopAll.getStatus('b').state, SERVICE_STATES.STOPPED);
    assert.equal(stopAllBStarts, 0);
    assert.deepStrictEqual(startAllRes.started, []);

    // (c1) Manual start() during _handleCrash()'s await svc.stop() ends cleanly RUNNING
    const smCrashStop = new ServiceManager();
    let csStarts = 0;
    let releaseCsStop;
    smCrashStop.register({
      name: 's',
      maxRestarts: 0,
      start: async () => {
        csStarts += 1;
      },
      stop: () =>
        new Promise((r) => {
          releaseCsStop = r;
        }),
      healthCheck: async () => false,
    });
    await smCrashStop.start('s');
    const hcCs = smCrashStop.checkHealth('s');
    await new Promise((r) => setTimeout(r, 10));
    const manualStartCs = await smCrashStop.start('s');
    releaseCsStop();
    await hcCs;
    assert.equal(manualStartCs.state, SERVICE_STATES.RUNNING);
    assert.equal(smCrashStop.getStatus('s').state, SERVICE_STATES.RUNNING);
    assert.equal(csStarts, 2);

    // (c2) Manual start() during _handleCrash()'s failing restart start() ends cleanly RUNNING
    const smCrashFail = new ServiceManager();
    let cfStarts = 0;
    let rejectStaleRestart;
    smCrashFail.register({
      name: 's',
      maxRestarts: 1,
      restartBackoffMs: 5,
      start: () => {
        cfStarts += 1;
        if (cfStarts === 2) {
          return new Promise((_res, rej) => {
            rejectStaleRestart = () => rej(new Error('stale_restart_boom'));
          });
        }
        return undefined;
      },
      healthCheck: async () => false,
    });
    await smCrashFail.start('s');
    const hcCf = smCrashFail.checkHealth('s');
    await new Promise((r) => setTimeout(r, 20)); // inside 2nd start (from _handleCrash)
    await smCrashFail.start('s'); // 3rd start succeeds manually
    rejectStaleRestart();
    await hcCf;
    assert.equal(smCrashFail.getStatus('s').state, SERVICE_STATES.RUNNING);

    // (c3) Stale _handleCrash start() does NOT stop/clobber concurrent restart()'s STARTING state
    const smRestartRace = new ServiceManager();
    let rrStarts = 0;
    let rrStops = 0;
    let releaseCrashStart;
    let releaseManualRestartStart;
    smRestartRace.register({
      name: 's',
      maxRestarts: 1,
      restartBackoffMs: 5,
      start: () => {
        rrStarts += 1;
        if (rrStarts === 2) {
          return new Promise((r) => {
            releaseCrashStart = r;
          });
        }
        if (rrStarts === 3) {
          return new Promise((r) => {
            releaseManualRestartStart = r;
          });
        }
        return undefined;
      },
      stop: async () => {
        rrStops += 1;
      },
      healthCheck: async () => false,
    });
    await smRestartRace.start('s');
    const hcRr = smRestartRace.checkHealth('s');
    await new Promise((r) => setTimeout(r, 20)); // inside crash's start #2
    const restartP = smRestartRace.restart('s');
    await new Promise((r) => setTimeout(r, 10)); // now inside restart's start #3 (STARTING)
    const stopsBefore = rrStops;
    releaseCrashStart(); // stale crash start resolves mid-restart
    await hcRr;
    assert.equal(smRestartRace.getStatus('s').state, SERVICE_STATES.STARTING);
    assert.equal(rrStops, stopsBefore, 'Stale _handleCrash must NOT stop active restart() instance');
    releaseManualRestartStart();
    await restartP;
    assert.equal(smRestartRace.getStatus('s').state, SERVICE_STATES.RUNNING);

    // (c4) Slow stop() + fast start() ends RUNNING
    const smSlowStop = new ServiceManager();
    let releaseSlowStop;
    smSlowStop.register({
      name: 's',
      start: async () => {},
      stop: () =>
        new Promise((r) => {
          releaseSlowStop = r;
        }),
    });
    await smSlowStop.start('s');
    const slowStopP = smSlowStop.stop('s');
    await new Promise((r) => setTimeout(r, 10));
    await smSlowStop.start('s');
    releaseSlowStop();
    await slowStopP;
    assert.equal(smSlowStop.getStatus('s').state, SERVICE_STATES.RUNNING);

    // (c5) Concurrent stop() aborts restart()
    const smAbortRestart = new ServiceManager();
    let arStarts = 0;
    let releaseArStop;
    let arStopCalls = 0;
    smAbortRestart.register({
      name: 's',
      start: async () => {
        arStarts += 1;
      },
      stop: () => {
        arStopCalls += 1;
        if (arStopCalls === 1) {
          return new Promise((r) => {
            releaseArStop = r;
          });
        }
        return undefined;
      },
    });
    await smAbortRestart.start('s');
    const abortRestartP = smAbortRestart.restart('s');
    await new Promise((r) => setTimeout(r, 10));
    await smAbortRestart.stop('s');
    releaseArStop();
    await abortRestartP;
    assert.equal(smAbortRestart.getStatus('s').state, SERVICE_STATES.STOPPED);
    assert.equal(arStarts, 1);

    // (d) Stale healthy checkHealth() during active _handleCrash() does NOT clobber lastHealthOk or return healthy: true
    const smHealthRace = new ServiceManager();
    let probeIdx = 0;
    let resolveProbe2;
    smHealthRace.register({
      name: 's',
      maxRestarts: 1,
      restartBackoffMs: 50,
      start: async () => {},
      healthCheck: () => {
        probeIdx += 1;
        if (probeIdx === 1) return Promise.resolve(false);
        return new Promise((r) => {
          resolveProbe2 = () => r(true);
        });
      },
    });
    await smHealthRace.start('s');
    const p1 = smHealthRace.checkHealth('s');
    const p2 = smHealthRace.checkHealth('s');
    await new Promise((r) => setTimeout(r, 10)); // p1 is in 50ms backoff (RESTARTING)
    resolveProbe2();
    await new Promise((r) => setTimeout(r, 10)); // still mid-backoff
    assert.equal(smHealthRace.getStatus('s').lastHealthOk, false);
    const [hr1, hr2] = await Promise.all([p1, p2]);
    assert.equal(hr1.healthy, false);
    assert.equal(hr2.healthy, false);

    // (e) kernel.panic() cancels mid-backoff service restart via haltForPanic()
    const kBackoff = createKernel();
    let flakyStarts = 0;
    kBackoff.serviceManager.register({
      name: 'flaky',
      essential: true,
      maxRestarts: 2,
      restartBackoffMs: 40,
      start: async () => {
        flakyStarts += 1;
      },
      healthCheck: async () => false,
    });
    await kBackoff.boot();
    assert.equal(flakyStarts, 1);
    const flakyHc = kBackoff.serviceManager.checkHealth('flaky');
    await new Promise((r) => setTimeout(r, 10)); // mid-40ms backoff
    kBackoff.panic('E_MID_BACKOFF', 'Panic during restart backoff');
    await flakyHc;
    await new Promise((r) => setTimeout(r, 60)); // past backoff window
    assert.equal(kBackoff.state, KERNEL_STATES.PANIC);
    assert.equal(kBackoff.serviceManager.getStatus('flaky').state, SERVICE_STATES.STOPPED);
    assert.equal(flakyStarts, 1, 'Panicked kernel must NOT restart services mid-backoff');
    await kBackoff.shutdown();

    // (f) OmniKernel.panic() safely clones BigInt, circular, and throwing-getter Error.code (JSON-serializable PanicDump & getDiagnostics)
    const dir = makeTempDir('omnios-errcode-panic-');
    const kErr = createKernel({ dbPath: path.join(dir, 'errcode.sqlite') });
    await kErr.boot();

    const errBig = new Error('err_bigint_code');
    errBig.code = 9007199254740993n;
    const dumpBig = kErr.panic('E_ERR_BIGINT', 'BigInt Error.code', errBig);
    assert.equal(dumpBig.context.code, '9007199254740993');
    assert.doesNotThrow(() => JSON.stringify(dumpBig));
    assert.doesNotThrow(() => JSON.stringify(kErr.getDiagnostics()));

    const errCirc = new Error('err_circ_code');
    errCirc.code = errCirc;
    const dumpCirc = kErr.panic('E_ERR_CIRC', 'Circular Error.code', errCirc);
    assert.equal(dumpCirc.context.code, '[Circular]');
    assert.doesNotThrow(() => JSON.stringify(dumpCirc));
    assert.doesNotThrow(() => JSON.stringify(kErr.getDiagnostics()));

    const errThrow = new Error('err_throw_code');
    Object.defineProperty(errThrow, 'code', {
      enumerable: true,
      get() {
        throw new Error('code_getter_exploded');
      },
    });
    const dumpThrow = kErr.panic('E_ERR_THROW', 'Throwing getter Error.code', errThrow);
    assert.equal(dumpThrow.context.code, '[Unreadable]');
    assert.doesNotThrow(() => JSON.stringify(dumpThrow));
    assert.doesNotThrow(() => JSON.stringify(kErr.getDiagnostics()));

    const hist = kErr.getPanicHistory();
    assert.equal(hist.length, 3);
    assert.equal(hist[0].context.code, '[Unreadable]');
    assert.equal(hist[1].context.code, '[Circular]');
    assert.equal(hist[2].context.code, '9007199254740993');
    await kErr.shutdown();
  });

  it('16.11 ProcessManager & Scheduler teardown/FSM/JSON/cross-realm hardening', async () => {
    // (a1) Throwing execCtx.dispose getter on EXITED never escapes, leaks resources, or starves siblings
    {
      const pm = new ProcessManager();
      pm.spawnSystemProcess({ pid: 0, ppid: 0, name: 'kernel_idle' });
      pm.spawnSystemProcess({ pid: 1, ppid: 0, name: 'omnid' });
      const sched = new Scheduler({ processManager: pm });

      let fdClosed = false;
      let hookRan = false;
      let siblingRan = false;
      const hostileExit = pm.spawn({
        name: 'hostile-dispose-exit',
        priority: -10,
        executionContext: {
          step: () => ({ status: 'EXITED', exitCode: 0, instructionsExecuted: 1 }),
          get dispose() {
            throw new Error('dispose_getter_exit_kaboom');
          },
        },
      });
      pm.openFd(hostileExit.pid, { path: '/tmp/leak-exit', onClose: () => { fdClosed = true; } });
      pm.addCleanupHook(hostileExit.pid, () => { hookRan = true; });
      hostileExit.addressSpace.mmap(0x10000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'data');

      const sibling = pm.spawn({
        name: 'innocent-sibling-exit',
        priority: 10,
        executionContext: {
          step: () => {
            siblingRan = true;
            return { status: 'EXITED', exitCode: 0, instructionsExecuted: 5 };
          },
          dispose: () => {},
        },
      });

      assert.doesNotThrow(() => sched.step(1));
      assert.equal(hostileExit.state, PROCESS_STATES.ZOMBIE);
      assert.equal(hostileExit.fdTable.size, 0);
      assert.equal(fdClosed, true);
      assert.equal(hookRan, true);
      assert.equal(hostileExit.addressSpace.getStats().mappedPages, 0);
      assert.equal(siblingRan, true);
      assert.equal(sibling.state, PROCESS_STATES.ZOMBIE);
      assert.equal(sibling.stats.exitCode, 0);
    }

    // (a2) Throwing execCtx.dispose getter on FAULT completes full teardown (FDs, hooks, VMM, orphan reparenting)
    {
      const pm = new ProcessManager();
      pm.spawnSystemProcess({ pid: 0, ppid: 0, name: 'kernel_idle' });
      pm.spawnSystemProcess({ pid: 1, ppid: 0, name: 'omnid' });
      const sched = new Scheduler({ processManager: pm });

      let fdClosed = false;
      let hookRan = false;
      const hostileFault = pm.spawn({
        name: 'hostile-dispose-fault',
        priority: -10,
        executionContext: {
          step: () => {
            throw new Error('step_fault');
          },
          get dispose() {
            throw new Error('dispose_getter_fault_kaboom');
          },
        },
      });
      pm.openFd(hostileFault.pid, { path: '/tmp/leak-fault', onClose: () => { fdClosed = true; } });
      pm.addCleanupHook(hostileFault.pid, () => { hookRan = true; });
      hostileFault.addressSpace.mmap(0x10000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'data');
      const orphanChild = pm.spawn({ name: 'orphan-child', ppid: hostileFault.pid });

      assert.doesNotThrow(() => sched.step(1));
      assert.equal(hostileFault.state, PROCESS_STATES.ZOMBIE);
      assert.equal(hostileFault.fdTable.size, 0);
      assert.equal(fdClosed, true);
      assert.equal(hookRan, true);
      assert.equal(hostileFault.addressSpace.getStats().mappedPages, 0);
      assert.equal(orphanChild.ppid, 1, 'Orphan child must be reparented to PID 1 despite throwing dispose getter');
    }

    // (a3) Throwing execCtx.dispose getter on pm.kill(SIGKILL) & pm.reset(), plus getRunnableThreads() throwing step getter
    {
      const pm = new ProcessManager();
      let killFdClosed = false;
      let killHookRan = false;
      const hostileKill = pm.spawn({
        name: 'hostile-dispose-kill',
        executionContext: {
          step: () => ({ status: 'YIELD', instructionsExecuted: 1 }),
          get dispose() {
            throw new Error('dispose_on_kill');
          },
        },
      });
      pm.openFd(hostileKill.pid, { path: '/tmp/kill-fd', onClose: () => { killFdClosed = true; } });
      pm.addCleanupHook(hostileKill.pid, () => { killHookRan = true; });
      hostileKill.addressSpace.mmap(0x10000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'data');

      assert.doesNotThrow(() => pm.kill(hostileKill.pid, 'SIGKILL'));
      assert.equal(hostileKill.state, PROCESS_STATES.ZOMBIE);
      assert.equal(hostileKill.fdTable.size, 0);
      assert.equal(killFdClosed, true);
      assert.equal(killHookRan, true);
      assert.equal(hostileKill.addressSpace.getStats().mappedPages, 0);

      // getRunnableThreads() isolates throwing step getter
      pm.spawn({
        name: 'hostile-step-getter',
        executionContext: {
          get step() {
            throw new Error('step_getter_kaboom');
          },
          get dispose() {
            throw new Error('dispose_on_reset');
          },
        },
      });
      const goodProc = pm.spawn({
        name: 'good-runnable',
        executionContext: {
          step: () => ({ status: 'YIELD', instructionsExecuted: 1 }),
          dispose: () => {},
        },
      });

      let runnable;
      assert.doesNotThrow(() => {
        runnable = pm.getRunnableThreads();
      });
      assert.equal(runnable.length, 1);
      assert.equal(runnable[0].pcb.pid, goodProc.pid);

      // pm.reset() never throws and clears _processes completely even with throwing dispose & onClose getters
      const badFd = pm.openFd(goodProc.pid, { path: '/tmp/bad-onclose' });
      const fdEntry = pm.getFd(goodProc.pid, badFd);
      Object.defineProperty(fdEntry, 'onClose', {
        get() {
          throw new Error('onclose_getter_kaboom');
        },
      });
      assert.doesNotThrow(() => pm.reset());
      assert.equal(pm.getAll().length, 0);
    }

    // (b) Strict PCB & TCB FSM guards in markReady()
    {
      const pm = new ProcessManager();
      const p = pm.spawn({ name: 'blocked-with-exited-worker' });
      const w = pm.createThread(p.pid, { name: 'worker' });
      pm.exitThread(p.pid, w.tid, 0);
      pm.markBlocked(p.pid, 1, 'stdin');
      assert.equal(p.state, PROCESS_STATES.BLOCKED);
      assert.equal(w.state, THREAD_STATES.EXITED);

      // Must reject EXITED worker and NEVER corrupt BLOCKED PCB to READY
      assert.throws(
        () => pm.markReady(p.pid, w.tid),
        (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(p.state, PROCESS_STATES.BLOCKED);
      assert.equal(p.threads.get(1).state, THREAD_STATES.BLOCKED);
      assert.equal(w.state, THREAD_STATES.EXITED);

      // Valid markReady on blocked thread transitions PCB BLOCKED -> READY
      pm.markReady(p.pid, 1);
      assert.equal(p.state, PROCESS_STATES.READY);
      assert.equal(p.threads.get(1).state, THREAD_STATES.READY);

      // Rejects CREATED, STOPPED, ZOMBIE, TERMINATED PCBs with EINVAL
      const pCreated = pm.spawn({ name: 'created-ready', autoReady: false });
      assert.throws(
        () => pm.markReady(pCreated.pid, 1),
        (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(pCreated.state, PROCESS_STATES.CREATED);

      const pStopped = pm.spawn({ name: 'stopped-ready' });
      pm.kill(pStopped.pid, 'SIGSTOP');
      assert.throws(
        () => pm.markReady(pStopped.pid, 1),
        (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(pStopped.state, PROCESS_STATES.STOPPED);

      const pZombie = pm.spawn({ name: 'zombie-ready' });
      pm.exit(pZombie.pid, 0);
      assert.throws(
        () => pm.markReady(pZombie.pid, 1),
        (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(pZombie.state, PROCESS_STATES.ZOMBIE);

      pm.reap(pZombie.pid);
      assert.throws(
        () => pm.markReady(pZombie.pid, 1),
        (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(pZombie.state, PROCESS_STATES.TERMINATED);
    }

    // (c) Real 64-bit BigInt AddressSpace fault & hostile Proxy fault.address yield 100% JSON-safe summary/list
    {
      const pm = new ProcessManager();
      const sched = new Scheduler({ processManager: pm });

      const pBigInt = pm.spawn({
        name: 'bigint-vmm-fault',
        executionContext: {
          step: () => {
            pBigInt.addressSpace.read(0xffffffffffffffffn, 4);
            return { status: 'YIELD', instructionsExecuted: 1 };
          },
          dispose: () => {},
        },
      });
      const hostileAddrProxy = new Proxy(
        {},
        {
          get() {
            throw new Error('addr_get_toJSON');
          },
        }
      );
      const pProxyAddr = pm.spawn({
        name: 'proxy-addr-fault',
        executionContext: {
          step: () => {
            throw { code: 'EFAULT', message: 'bad_addr_proxy', address: hostileAddrProxy };
          },
          dispose: () => {},
        },
      });

      assert.doesNotThrow(() => sched.step(1));
      assert.equal(pBigInt.state, PROCESS_STATES.ZOMBIE);
      assert.equal(pBigInt.stats.exitSignal, 'SIGSEGV');
      assert.equal(pBigInt.stats.lastFault.address, '0xffffffffffffffff');
      assert.equal(pProxyAddr.state, PROCESS_STATES.ZOMBIE);
      assert.equal(pProxyAddr.stats.lastFault.address, null);

      assert.doesNotThrow(() => JSON.stringify(pm.toSummary(pBigInt)));
      assert.doesNotThrow(() => JSON.stringify(pm.toSummary(pProxyAddr)));
      assert.doesNotThrow(() => JSON.stringify(pm.list()));
    }

    // (d) Cross-realm (vm) & shadowed-.catch/.then rejected Promises terminate PID with SIGILL (132) and ZERO UnhandledPromiseRejection
    {
      const pm = new ProcessManager();
      const sched = new Scheduler({ processManager: pm });
      const unhandled = [];
      const onUnhandled = (reason) => {
        unhandled.push(reason);
      };
      process.on('unhandledRejection', onUnhandled);
      try {
        const pVm = pm.spawn({
          name: 'vm-promise-reject',
          executionContext: {
            step: () => vm.runInNewContext('Promise.reject(new Error("vm_reject_boom"))'),
            dispose: () => {},
          },
        });
        const pShadowCatch = pm.spawn({
          name: 'shadowed-catch-promise',
          executionContext: {
            step: () => {
              const rej = Promise.reject(new Error('shadowed_catch_rej'));
              Object.defineProperty(rej, 'catch', {
                get() {
                  throw new Error('catch_getter_boom');
                },
              });
              return rej;
            },
            dispose: () => {},
          },
        });
        const pShadowThen = pm.spawn({
          name: 'shadowed-then-promise',
          executionContext: {
            step: () => {
              const rej = Promise.reject(new Error('shadowed_then_rej'));
              Object.defineProperty(rej, 'then', {
                get() {
                  throw new Error('then_getter_boom');
                },
              });
              return rej;
            },
            dispose: () => {},
          },
        });

        assert.doesNotThrow(() => sched.step(1));
        await new Promise((r) => setTimeout(r, 25));

        for (const proc of [pVm, pShadowCatch, pShadowThen]) {
          assert.equal(proc.state, PROCESS_STATES.ZOMBIE);
          assert.equal(proc.stats.exitSignal, 'SIGILL');
          assert.equal(proc.stats.exitCode, 132);
        }
        assert.equal(unhandled.length, 0, 'Must produce ZERO UnhandledPromiseRejection events');
      } finally {
        process.off('unhandledRejection', onUnhandled);
      }
    }
  });

  it('16.12 ServiceManager TDZ/backoff & boot()/recover() mid-boot panic/shutdown hardening', async () => {
    // (a1) Synchronous-throwing svc.start() rejects with REAL error (not ReferenceError) and succeeds on retry
    {
      const sm = new ServiceManager();
      let calls = 0;
      sm.register({
        name: 'syncFail',
        start: () => {
          calls += 1;
          if (calls === 1) throw new Error('sync_boom');
        },
      });
      await assert.rejects(
        () => sm.start('syncFail'),
        (err) => !(err instanceof ReferenceError) && err.message === 'sync_boom'
      );
      assert.equal(sm.getStatus('syncFail').state, SERVICE_STATES.FAILED);
      assert.equal(sm.getStatus('syncFail').lastError, 'sync_boom');

      const retryRes = await sm.start('syncFail');
      assert.equal(calls, 2);
      assert.equal(retryRes.state, SERVICE_STATES.RUNNING);
    }

    // (a2) startAll({ continueOnError: true }) and startAll({ safeMode: true }) report real sync error
    {
      const sm1 = new ServiceManager();
      sm1.register({
        name: 'badSync',
        essential: true,
        start: () => {
          throw new Error('real_sync_error');
        },
      });
      const res1 = await sm1.startAll({ continueOnError: true });
      assert.equal(res1.failed.length, 1);
      assert.equal(res1.failed[0].name, 'badSync');
      assert.equal(res1.failed[0].error, 'real_sync_error');

      const sm2 = new ServiceManager();
      sm2.register({
        name: 'badSync2',
        essential: true,
        start: () => {
          throw new Error('real_safe_error');
        },
      });
      const res2 = await sm2.startAll({ safeMode: true });
      assert.equal(res2.failed.length, 1);
      assert.equal(res2.failed[0].name, 'badSync2');
      assert.equal(res2.failed[0].error, 'real_safe_error');
    }

    // (a3) Sync stop() inside svc.start() before pending Promise does not poison _startPromise
    {
      const sm = new ServiceManager();
      let calls = 0;
      let releaseFirst;
      sm.register({
        name: 's',
        start: () => {
          calls += 1;
          if (calls === 1) {
            sm.stop('s');
            return new Promise((r) => {
              releaseFirst = r;
            });
          }
          return Promise.resolve();
        },
      });
      const p1 = sm.start('s');
      const p2 = sm.start('s');
      const r2 = await p2;
      assert.equal(calls, 2);
      assert.equal(r2.state, SERVICE_STATES.RUNNING);
      releaseFirst();
      await p1;
      assert.equal(sm.getStatus('s').state, SERVICE_STATES.RUNNING);
    }

    // (b1) kernel.panic() inside async start() during boot() with autoStartScheduler: true aborts boot & preserves PANIC
    {
      const k = createKernel({ dbPath: ':memory:', autoStartScheduler: true });
      let bootedCount = 0;
      k.eventBus.on('kernel:booted', () => {
        bootedCount += 1;
      });
      k.serviceManager.register({
        name: 'panicker',
        essential: true,
        start: async () => {
          await new Promise((r) => setTimeout(r, 10));
          k.panic('E_BOOT_PANIC', 'fatal during Stage 4');
        },
      });

      await assert.rejects(
        () => k.boot(),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_KERNEL_PANIC
      );
      assert.equal(k.state, KERNEL_STATES.PANIC);
      assert.equal(bootedCount, 0);
      assert.equal(k.scheduler.isRunning(), false);
      assert.equal(k.serviceManager.getStatus('panicker').state, SERVICE_STATES.STOPPED);
      await k.shutdown();
    }

    // (b2) External kernel.panic() during boot() AND panic+throw during recover({ safeMode: true }) with autoStartScheduler: true
    {
      const k = createKernel({ dbPath: ':memory:', autoStartScheduler: true });
      let bootedCount = 0;
      let recoveredCount = 0;
      let releaseSlow;
      let mode = 'external';
      k.eventBus.on('kernel:booted', () => {
        bootedCount += 1;
      });
      k.eventBus.on('kernel:recovered', () => {
        recoveredCount += 1;
      });
      k.serviceManager.register({
        name: 'slow-ess',
        essential: true,
        start: async () => {
          if (mode === 'external') {
            await new Promise((r) => {
              releaseSlow = r;
            });
            return;
          }
          await new Promise((r) => setTimeout(r, 10));
          k.panic('E_RECOVER_PANIC', 'fatal during recovery');
          throw new Error('corrupt_superblock');
        },
      });

      const bootP = k.boot();
      await new Promise((r) => setTimeout(r, 15));
      k.panic('E_EXT_BOOT_PANIC', 'external panic mid-boot');
      releaseSlow();
      await assert.rejects(
        () => bootP,
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_KERNEL_PANIC
      );
      assert.equal(k.state, KERNEL_STATES.PANIC);
      assert.equal(bootedCount, 0);
      assert.equal(k.scheduler.isRunning(), false);

      mode = 'recover_panic';
      await assert.rejects(
        () => k.recover({ safeMode: true }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_KERNEL_PANIC
      );
      assert.equal(k.state, KERNEL_STATES.PANIC);
      assert.equal(bootedCount, 0);
      assert.equal(recoveredCount, 0);
      assert.equal(k.scheduler.isRunning(), false);
      await k.shutdown();
    }

    // (b3) kernel.shutdown() during Stage 4 of boot() aborts cleanly with E_KERNEL_NOT_RUNNING and preserves STOPPED
    {
      const k = createKernel({ dbPath: ':memory:', autoStartScheduler: true });
      let bootedCount = 0;
      let releaseStart;
      k.eventBus.on('kernel:booted', () => {
        bootedCount += 1;
      });
      k.serviceManager.register({
        name: 'slow-svc',
        start: () =>
          new Promise((r) => {
            releaseStart = r;
          }),
      });

      const bootP = k.boot();
      await new Promise((r) => setTimeout(r, 15));
      await k.shutdown();
      releaseStart();

      await assert.rejects(
        () => bootP,
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_KERNEL_NOT_RUNNING
      );
      assert.equal(k.state, KERNEL_STATES.STOPPED);
      assert.equal(bootedCount, 0);
      assert.equal(k.scheduler.isRunning(), false);
      assert.equal(k.storage?.isOpen ?? false, false);
    }

    // (c) Manual sm.start('b') while 'b' is in crash backoff and dep 'a' is STOPPED cancels backoff BEFORE awaiting async a.start()
    {
      const sm = new ServiceManager();
      let aStarts = 0;
      let bStartsDuringDepDown = 0;
      sm.register({
        name: 'a',
        start: async () => {
          aStarts += 1;
          if (aStarts > 1) {
            await new Promise((r) => setTimeout(r, 40));
          }
        },
      });
      sm.register({
        name: 'b',
        deps: ['a'],
        maxRestarts: 1,
        restartBackoffMs: 10,
        start: async () => {
          if (sm.getStatus('a').state !== SERVICE_STATES.RUNNING) {
            bStartsDuringDepDown += 1;
            throw new Error('dep_a_not_running');
          }
        },
        healthCheck: async () => false,
      });

      await sm.start('b');
      await sm.stop('a');
      const hcP = sm.checkHealth('b');
      await new Promise((r) => setTimeout(r, 2)); // 'b' now in 10ms backoff while 'a' is STOPPED
      const manualRes = await sm.start('b');
      await hcP;

      assert.equal(bStartsDuringDepDown, 0, 'Old crash backoff must NOT start b while dep a is STOPPED/STARTING');
      assert.equal(manualRes.state, SERVICE_STATES.RUNNING);
      assert.equal(sm.getStatus('a').state, SERVICE_STATES.RUNNING);
      assert.equal(sm.getStatus('b').state, SERVICE_STATES.RUNNING);
    }
  });

  it('16.13 hardens BigInt error/fault JSON serialization, mid-recovery shutdown/panic abort guards, STARTING supersede cleanup, and shadowed-.then SqliteStorage rejection suppression', async () => {
    // (1) BigInt MemoryFaultError/IllegalInstructionError toJSON() & direct pm.kill()/exit()/toSummary()/list()
    {
      const as = new AddressSpace({ pid: 70 });
      let mmapErr = null;
      try {
        as.mmap(0xffffffffffffffffn, PAGE_SIZE);
      } catch (err) {
        mmapErr = err;
      }
      assert.ok(mmapErr instanceof MemoryFaultError);
      assert.equal(mmapErr.address, 0xffffffffffffffffn, 'Live BigInt err.address must remain intact');
      const mmapJson = JSON.parse(JSON.stringify(mmapErr));
      assert.equal(mmapJson.address, '0xffffffffffffffff');
      assert.equal(mmapJson.addr, '0xffffffffffffffff');

      let negErr = null;
      try {
        as.read(-1n, 4);
      } catch (err) {
        negErr = err;
      }
      assert.ok(negErr instanceof MemoryFaultError);
      assert.equal(negErr.address, -1n);
      const negJson = JSON.parse(JSON.stringify(negErr));
      assert.equal(negJson.address, '-0x1');
      assert.equal(negJson.addr, '-0x1');

      const illErr = new IllegalInstructionError('bad64', {
        pc: 0x1000000000000000n,
        opcode: 0xdeadbeefn,
        details: { reg: -0x20n, nonFinite: Number.POSITIVE_INFINITY },
      });
      assert.equal(illErr.pc, 0x1000000000000000n);
      assert.equal(illErr.opcode, 0xdeadbeefn);
      const illJson = JSON.parse(JSON.stringify(illErr));
      assert.equal(illJson.pc, '0x1000000000000000');
      assert.equal(illJson.opcode, '0xdeadbeef');
      assert.equal(illJson.details.reg, '-0x20');
      assert.equal(illJson.details.nonFinite, null);

      const pm = new ProcessManager();
      const p1 = pm.spawn({ name: 'direct-kill-bigint-fault' });
      let readFault = null;
      try {
        p1.addressSpace.read(0xffffffffffffffffn, 4);
      } catch (err) {
        readFault = err;
      }
      pm.kill(p1.pid, 'SIGSEGV', { fault: readFault });

      const p1SummaryJson = JSON.parse(JSON.stringify(pm.toSummary(p1)));
      assert.equal(p1SummaryJson.lastFault.name, 'MemoryFaultError');
      assert.equal(p1SummaryJson.lastFault.address, '0xffffffffffffffff');
      assert.equal(p1SummaryJson.lastFault.addr, '0xffffffffffffffff');
      assert.equal(p1SummaryJson.stats.lastFault.address, '0xffffffffffffffff');

      // Direct pm.exit() with circular + BigInt + throwing getter fault object
      const p2 = pm.spawn({ name: 'direct-exit-hostile-fault' });
      const hostileFault = { code: 'EFAULT', address: -0x42n };
      hostileFault.self = hostileFault;
      Object.defineProperty(hostileFault, 'boom', {
        enumerable: true,
        get() {
          throw new Error('fault_getter_boom');
        },
      });
      pm.exit(p2.pid, 139, { fault: hostileFault });
      const p2SummaryJson = JSON.parse(JSON.stringify(pm.toSummary(p2)));
      assert.equal(p2SummaryJson.lastFault.address, '-0x42');
      assert.equal(p2SummaryJson.lastFault.self, '[Circular]');
      assert.equal(p2SummaryJson.lastFault.boom, '[Unreadable]');

      assert.doesNotThrow(() => JSON.stringify(pm.list()));
    }

    // (2a) kernel.shutdown() completing during recover()'s await stopAll() must NOT resurrect kernel
    {
      const k = createKernel({ dbPath: ':memory:', autoStartScheduler: true });
      let stopRelease;
      let stopCalls = 0;
      let bootedCount = 0;
      let recoveredCount = 0;
      k.serviceManager.register({
        name: 'slowstop',
        essential: true,
        start: async () => {},
        stop: () =>
          ++stopCalls === 1
            ? new Promise((r) => {
                stopRelease = r;
              })
            : Promise.resolve(),
      });
      await k.boot();
      k.eventBus.on('kernel:booted', () => {
        bootedCount += 1;
      });
      k.eventBus.on('kernel:recovered', () => {
        recoveredCount += 1;
      });

      k.panic('E_PRE', 'pre-recovery panic');
      const recP = k.recover();
      await new Promise((r) => setTimeout(r, 10));
      await k.shutdown();
      assert.equal(k.state, KERNEL_STATES.STOPPED);
      assert.equal(k.storage.isOpen, false);
      stopRelease();

      await assert.rejects(
        () => recP,
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_KERNEL_NOT_RUNNING
      );
      assert.equal(k.state, KERNEL_STATES.STOPPED);
      assert.equal(k.storage.isOpen, false);
      assert.equal(k.scheduler.isRunning(), false);
      assert.equal(bootedCount, 0);
      assert.equal(recoveredCount, 0);
    }

    // (2b) In-flight shutdown() during recover() must abort BEFORE resetStates/runBootSequence with ZERO transient 'BOOTING' state
    {
      const k = createKernel({ dbPath: ':memory:', autoStartScheduler: true });
      let stopRelease1;
      let stopRelease2;
      let stopCalls = 0;
      let bootedCount = 0;
      let recoveredCount = 0;
      let sawTransientBooting = false;

      k.serviceManager.register({
        name: 'slowstop2',
        essential: true,
        start: async () => {},
        stop: () => {
          stopCalls += 1;
          if (stopCalls === 1) {
            return new Promise((r) => {
              stopRelease1 = r;
            });
          }
          return new Promise((r) => {
            stopRelease2 = r;
          });
        },
      });
      await k.boot();
      k.eventBus.on('kernel:booted', () => {
        bootedCount += 1;
      });
      k.eventBus.on('kernel:recovered', () => {
        recoveredCount += 1;
      });

      k.panic('E_PRE2', 'pre-recovery panic 2');

      // Intercept state writes to detect any transient 'BOOTING' mutation during in-flight shutdown
      let currentState = k.state;
      Object.defineProperty(k, 'state', {
        configurable: true,
        enumerable: true,
        get() {
          return currentState;
        },
        set(val) {
          if (val === KERNEL_STATES.BOOTING && k._shuttingDown) {
            sawTransientBooting = true;
          }
          currentState = val;
        },
      });

      const recP = k.recover();
      await new Promise((r) => setTimeout(r, 10));
      const shutP = k.shutdown();
      await new Promise((r) => setTimeout(r, 10));

      // Direct boot() while shutdown is in-flight must also reject without setting BOOTING
      await assert.rejects(
        () => k.boot(),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_KERNEL_NOT_RUNNING
      );

      stopRelease1();
      await assert.rejects(
        () => recP,
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_KERNEL_NOT_RUNNING
      );
      assert.equal(sawTransientBooting, false, 'kernel.state must NEVER transiently mutate to BOOTING during shutdown');
      assert.notEqual(k.state, KERNEL_STATES.BOOTING);

      stopRelease2();
      await shutP;
      assert.equal(k.state, KERNEL_STATES.STOPPED);
      assert.equal(k.storage.isOpen, false);
      assert.equal(k.scheduler.isRunning(), false);
      assert.equal(bootedCount, 0);
      assert.equal(recoveredCount, 0);
    }

    // (2c) New kernel.panic() during recover()'s await stopAll() aborts with E_KERNEL_PANIC
    {
      const k = createKernel({ dbPath: ':memory:', autoStartScheduler: true });
      let stopRelease;
      let stopCalls = 0;
      let bootedCount = 0;
      let recoveredCount = 0;
      k.serviceManager.register({
        name: 'slowstop3',
        essential: true,
        start: async () => {},
        stop: () =>
          ++stopCalls === 1
            ? new Promise((r) => {
                stopRelease = r;
              })
            : Promise.resolve(),
      });
      await k.boot();
      k.eventBus.on('kernel:booted', () => {
        bootedCount += 1;
      });
      k.eventBus.on('kernel:recovered', () => {
        recoveredCount += 1;
      });

      k.panic('E_PRE3', 'initial panic');
      const recP = k.recover();
      await new Promise((r) => setTimeout(r, 10));
      k.panic('E_NEW_PANIC_IN_STOPALL', 'new panic during recover stopAll');
      stopRelease();

      await assert.rejects(
        () => recP,
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_KERNEL_PANIC
      );
      assert.equal(k.state, KERNEL_STATES.PANIC);
      assert.equal(k.scheduler.isRunning(), false);
      assert.equal(k.getDiagnostics().lastPanic.code, 'E_NEW_PANIC_IN_STOPALL');
      assert.equal(bootedCount, 0);
      assert.equal(recoveredCount, 0);
      await k.shutdown();
    }

    // (3) Manual sm.start('b') superseding _handleCrash() while b.state === 'STARTING' cleans up stale start & stays STOPPED on dep failure
    {
      const sm = new ServiceManager();
      let aStartCalls = 0;
      let bStartCalls = 0;
      let bStopCalls = 0;
      let releaseStaleBStart;
      let failA = false;

      sm.register({
        name: 'a',
        start: async () => {
          aStartCalls += 1;
          if (failA) {
            await new Promise((r) => setTimeout(r, 25));
            throw new Error('dep_a_failed');
          }
        },
      });
      sm.register({
        name: 'b',
        deps: ['a'],
        maxRestarts: 2,
        restartBackoffMs: 1,
        start: async () => {
          bStartCalls += 1;
          if (bStartCalls === 2) {
            await new Promise((r) => {
              releaseStaleBStart = r;
            });
          }
        },
        stop: async () => {
          bStopCalls += 1;
        },
        healthCheck: async () => false,
      });

      await sm.start('b');
      await sm.stop('a');
      failA = true;

      const hcP = sm.checkHealth('b');
      await new Promise((r) => setTimeout(r, 15));
      assert.equal(sm.getStatus('b').state, SERVICE_STATES.STARTING);
      assert.equal(bStopCalls, 1);

      const manualP = sm.start('b');
      assert.equal(sm.getStatus('b').state, SERVICE_STATES.STOPPED, 'Superseding STARTING crash must reset b.state to STOPPED before awaiting dep a');

      await new Promise((r) => setTimeout(r, 5));
      releaseStaleBStart();
      await hcP;

      await assert.rejects(() => manualP, /dep_a_failed/);
      assert.equal(bStopCalls, 2, 'Superseded stale b.start() must run b.stop() cleanup');
      assert.equal(sm.getStatus('b').state, SERVICE_STATES.STOPPED, 'b must end STOPPED, never stuck in STARTING');
      assert.equal(aStartCalls, 2);

      // Recovering dep a allows subsequent manual sm.start('b') to reach RUNNING cleanly
      failA = false;
      const recoveredB = await sm.start('b');
      assert.equal(recoveredB.state, SERVICE_STATES.RUNNING);
      assert.equal(sm.getStatus('a').state, SERVICE_STATES.RUNNING);
    }

    // (4) Rejecting native & cross-realm Promises with shadowed throwing .then getters inside SqliteStorage.transaction()
    {
      const unhandled = [];
      const onUnhandled = (reason) => unhandled.push(reason);
      process.on('unhandledRejection', onUnhandled);
      const db = openSqliteStorage(':memory:');
      try {
        db.exec('CREATE TABLE t_shadow (id INTEGER PRIMARY KEY, v TEXT);');

        assert.throws(
          () =>
            db.transaction(() => {
              db.run('INSERT INTO t_shadow (id, v) VALUES (?, ?)', 1, 'shadow-native');
              const p = Promise.reject(new Error('shadowed_native_tx_boom'));
              Object.defineProperty(p, 'then', {
                get() {
                  throw new Error('shadowed_then_getter_boom');
                },
              });
              return p;
            }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_ASYNC_TRANSACTION
        );
        assert.equal(db.inTransaction, false);
        assert.equal(db.get('SELECT id FROM t_shadow WHERE id = ?', 1), null);

        // Nested SAVEPOINT with cross-realm vm rejected Promise with shadowed throwing .then getter
        db.transaction(() => {
          db.run('INSERT INTO t_shadow (id, v) VALUES (?, ?)', 2, 'outer-kept');
          assert.throws(
            () =>
              db.transaction(() => {
                db.run('INSERT INTO t_shadow (id, v) VALUES (?, ?)', 3, 'nested-vm-shadow');
                return vm.runInNewContext(`
                  const p = Promise.reject(new Error('shadowed_vm_tx_boom'));
                  Object.defineProperty(p, 'then', { get() { throw new Error('vm_then_getter_boom'); } });
                  p;
                `);
              }),
            (err) => err instanceof OmniOSError && err.code === ERROR_CODES.E_ASYNC_TRANSACTION
          );
        });
        assert.deepStrictEqual(db.get('SELECT id, v FROM t_shadow WHERE id = ?', 2), { id: 2, v: 'outer-kept' });
        assert.equal(db.get('SELECT id FROM t_shadow WHERE id = ?', 3), null);

        await new Promise((r) => setTimeout(r, 25));
        assert.deepStrictEqual(unhandled, [], 'Must produce ZERO UnhandledPromiseRejection events');
      } finally {
        process.off('unhandledRejection', onUnhandled);
        db.close();
      }
    }
  });

  it('16.14 hardens ProcessManager.kill()/exit()/toSummary() against hostile fault.message/faultReason and uniformly sanitizes all 13 OmniOSError classes in toJSON()', () => {
    const bus = new KernelEventBus();
    const exitedEvents = [];
    bus.on('process:exited', (ev) => exitedEvents.push(ev));
    const pm = new ProcessManager({ eventBus: bus });

    // (1) Hostile Proxy & throwing `message` getter faults on direct pm.kill(pid, 'SIGSEGV', { fault })
    {
      const pProxy = pm.spawn({ name: 'kill-hostile-proxy' });
      pProxy.addressSpace.mmap(0x10000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'data');
      pm.openFd(pProxy.pid, { path: '/tmp/proxy-fd', flags: 'r' });
      assert.equal(pProxy.addressSpace.getStats().mappedPages, 1);
      assert.equal(pProxy.fdTable.size, 4);

      const hostileProxy = new Proxy(
        {},
        {
          get() {
            throw new Error('proxy_get_boom');
          },
          ownKeys() {
            throw new Error('proxy_ownkeys_boom');
          },
        }
      );

      let res;
      assert.doesNotThrow(() => {
        res = pm.kill(pProxy.pid, 'SIGSEGV', { fault: hostileProxy });
      });
      assert.equal(res.ok, true);
      assert.equal(res.state, PROCESS_STATES.ZOMBIE);
      assert.equal(pProxy.state, PROCESS_STATES.ZOMBIE);
      assert.equal(pProxy.fdTable.size, 0);
      assert.equal(pProxy.addressSpace.getStats().mappedPages, 0);
      assert.equal(pProxy.stats.faultReason, 'Terminated by SIGSEGV');

      const sProxy = JSON.parse(JSON.stringify(pm.toSummary(pProxy)));
      assert.equal(sProxy.faultReason, 'Terminated by SIGSEGV');
      assert.equal(sProxy.stats.faultReason, 'Terminated by SIGSEGV');

      // Throwing `message` getter on fault object
      const pThrowMsg = pm.spawn({ name: 'kill-throwing-msg-getter' });
      pThrowMsg.addressSpace.mmap(0x20000, PAGE_SIZE, PROT_READ | PROT_WRITE, 'data');
      pm.openFd(pThrowMsg.pid, { path: '/tmp/getter-fd', flags: 'r' });
      const throwingMsgFault = { name: 'BadFault', code: 'E_BAD', address: 0xdeadbeefn };
      Object.defineProperty(throwingMsgFault, 'message', {
        enumerable: true,
        get() {
          throw new Error('msg_getter_boom');
        },
      });

      assert.doesNotThrow(() => {
        res = pm.kill(pThrowMsg.pid, 'SIGSEGV', { fault: throwingMsgFault });
      });
      assert.equal(res.ok, true);
      assert.equal(res.state, PROCESS_STATES.ZOMBIE);
      assert.equal(pThrowMsg.state, PROCESS_STATES.ZOMBIE);
      assert.equal(pThrowMsg.fdTable.size, 0);
      assert.equal(pThrowMsg.addressSpace.getStats().mappedPages, 0);
      assert.equal(pThrowMsg.stats.faultReason, 'Terminated by SIGSEGV');

      const sThrowMsg = JSON.parse(JSON.stringify(pm.toSummary(pThrowMsg)));
      assert.equal(sThrowMsg.faultReason, 'Terminated by SIGSEGV');
      assert.equal(sThrowMsg.stats.faultReason, 'Terminated by SIGSEGV');
      assert.equal(sThrowMsg.lastFault.address, '0xdeadbeef');
      assert.equal(sThrowMsg.lastFault.message, '[Unreadable]');

      // Revoked Proxy fault
      const pRevoked = pm.spawn({ name: 'kill-revoked-proxy' });
      pRevoked.addressSpace.mmap(0x30000, PAGE_SIZE, PROT_READ, 'ro');
      const { proxy: revokedProxy, revoke } = Proxy.revocable({}, {});
      revoke();
      assert.doesNotThrow(() => {
        res = pm.kill(pRevoked.pid, 'SIGSEGV', { fault: revokedProxy });
      });
      assert.equal(res.state, PROCESS_STATES.ZOMBIE);
      assert.equal(pRevoked.fdTable.size, 0);
      assert.equal(pRevoked.addressSpace.getStats().mappedPages, 0);
      assert.equal(pRevoked.stats.faultReason, 'Terminated by SIGSEGV');
      assert.doesNotThrow(() => JSON.stringify(pm.toSummary(pRevoked)));
    }

    // (2) BigInt / circular / Symbol / Object.create(null) / TypeError fault messages & reasons
    {
      const circularObj = { tag: 'loop' };
      circularObj.self = circularObj;

      const pBigIntMsg = pm.spawn({ name: 'kill-bigint-msg' });
      pm.kill(pBigIntMsg.pid, 'SIGSEGV', { fault: { message: 0xffffffffffffffffn, address: 0x10n } });
      const sBigIntMsg = JSON.parse(JSON.stringify(pm.toSummary(pBigIntMsg)));
      assert.equal(sBigIntMsg.faultReason, '0xffffffffffffffff');
      assert.equal(sBigIntMsg.stats.faultReason, '0xffffffffffffffff');
      assert.equal(sBigIntMsg.lastFault.address, '0x10');

      const pCircularMsg = pm.spawn({ name: 'kill-circular-msg' });
      pm.kill(pCircularMsg.pid, 'SIGSEGV', { fault: { message: circularObj } });
      const sCircularMsg = JSON.parse(JSON.stringify(pm.toSummary(pCircularMsg)));
      assert.equal(sCircularMsg.faultReason, '{"tag":"loop","self":"[Circular]"}');
      assert.equal(sCircularMsg.stats.faultReason, '{"tag":"loop","self":"[Circular]"}');

      const pExitBigIntReason = pm.spawn({ name: 'exit-bigint-reason' });
      pm.exit(pExitBigIntReason.pid, 139, { faultReason: 0xdeadbeefn });
      const sExitBigInt = JSON.parse(JSON.stringify(pm.toSummary(pExitBigIntReason)));
      assert.equal(sExitBigInt.faultReason, '0xdeadbeef');
      assert.equal(sExitBigInt.stats.faultReason, '0xdeadbeef');

      const pSigkillCirc = pm.spawn({ name: 'sigkill-circular-reason' });
      pm.kill(pSigkillCirc.pid, 'SIGKILL', { reason: circularObj });
      const sSigkillCirc = JSON.parse(JSON.stringify(pm.toSummary(pSigkillCirc)));
      assert.equal(sSigkillCirc.faultReason, '{"tag":"loop","self":"[Circular]"}');
      assert.equal(sSigkillCirc.stats.faultReason, '{"tag":"loop","self":"[Circular]"}');

      const pTypeErr = pm.spawn({ name: 'kill-direct-typeerr' });
      pm.kill(pTypeErr.pid, 'SIGSEGV', { fault: new TypeError('direct_type_err') });
      const sTypeErr = JSON.parse(JSON.stringify(pm.toSummary(pTypeErr)));
      assert.equal(sTypeErr.faultReason, 'direct_type_err');
      assert.equal(sTypeErr.stats.faultReason, 'direct_type_err');
      assert.equal(sTypeErr.lastFault.name, 'TypeError');
      assert.equal(sTypeErr.lastFault.message, 'direct_type_err');

      // Defensive normalization in toSummary() even if pcb.stats.faultReason is mutated directly
      const nullProto = Object.assign(Object.create(null), { sym: Symbol('s'), n: 7n });
      pTypeErr.stats.faultReason = nullProto;
      const sMutated = JSON.parse(JSON.stringify(pm.toSummary(pTypeErr)));
      assert.equal(sMutated.faultReason, '{"sym":"Symbol(s)","n":"0x7"}');
      assert.equal(sMutated.stats.faultReason, '{"sym":"Symbol(s)","n":"0x7"}');

      assert.doesNotThrow(() => JSON.stringify(pm.list()));
      assert.doesNotThrow(() => JSON.stringify(pm.getTree()));
      assert.ok(exitedEvents.length >= 8);
      assert.doesNotThrow(() => JSON.stringify(exitedEvents));
    }

    // (3) ProcessError from _requirePcb(BigInt) + all remaining OmniOSError subclasses toJSON()
    {
      let caughtProcErr = null;
      try {
        pm.kill(99999999999999999999n, 'SIGTERM');
      } catch (err) {
        caughtProcErr = err;
      }
      assert.ok(caughtProcErr instanceof ProcessError);
      assert.equal(caughtProcErr.pid, 99999999999999999999n, 'Live BigInt pid must remain intact');
      const procErrJson = JSON.parse(JSON.stringify(caughtProcErr));
      assert.equal(procErrJson.pid, '0x56bc75e2d630fffff');
      assert.equal(procErrJson.code, ERROR_CODES.ESRCH);

      const sysErr = new SyscallError('bad_sys', { syscall: 0x2000004n, pid: 42n });
      assert.equal(sysErr.syscall, 0x2000004n);
      assert.equal(sysErr.pid, 42n);
      const sysJson = JSON.parse(JSON.stringify(sysErr));
      assert.equal(sysJson.syscall, '0x2000004');
      assert.equal(sysJson.pid, '0x2a');

      const vfsErr = new VfsError('bad_vfs', { path: 0x100n, syscall: 0x200n });
      assert.equal(vfsErr.path, 0x100n);
      assert.equal(vfsErr.syscall, 0x200n);
      const vfsJson = JSON.parse(JSON.stringify(vfsErr));
      assert.equal(vfsJson.path, '0x100');
      assert.equal(vfsJson.syscall, '0x200');

      const secErr = new SecurityError('bad_sec', { capability: 1n, appId: 2n, pid: 42n });
      assert.equal(secErr.capability, 1n);
      assert.equal(secErr.appId, 2n);
      assert.equal(secErr.pid, 42n);
      const secJson = JSON.parse(JSON.stringify(secErr));
      assert.equal(secJson.capability, '0x1');
      assert.equal(secJson.appId, '0x2');
      assert.equal(secJson.pid, '0x2a');

      const impErr = new UnresolvedImportError('missing_ord', {
        library: 'kernel32.dll',
        symbol: null,
        ordinal: 0x8000000000000001n,
      });
      assert.equal(impErr.ordinal, 0x8000000000000001n, 'Live 64-bit BigInt PE32+ ordinal must remain intact');
      const impJson = JSON.parse(JSON.stringify(impErr));
      assert.equal(impJson.library, 'kernel32.dll');
      assert.equal(impJson.symbol, null);
      assert.equal(impJson.ordinal, '0x8000000000000001');

      const stateErr = new ProcessError('bad_transition', {
        pid: 99n,
        state: 1n,
        targetState: 2n,
      });
      assert.equal(stateErr.pid, 99n);
      assert.equal(stateErr.state, 1n);
      assert.equal(stateErr.targetState, 2n);
      const stateJson = JSON.parse(JSON.stringify(stateErr));
      assert.equal(stateJson.pid, '0x63');
      assert.equal(stateJson.state, '0x1');
      assert.equal(stateJson.targetState, '0x2');

      const cycleArr = ['svcA', 'svcB', 0xffn];
      cycleArr.push(cycleArr);
      const svcErr = new ServiceError('cycle_err', {
        serviceName: 'svcA',
        cycle: cycleArr,
        missingDep: 0xdeadn,
      });
      assert.equal(svcErr.missingDep, 0xdeadn);
      assert.equal(svcErr.cycle, cycleArr);
      const svcJson = JSON.parse(JSON.stringify(svcErr));
      assert.equal(svcJson.serviceName, 'svcA');
      assert.deepStrictEqual(svcJson.cycle, ['svcA', 'svcB', '0xff', '[Circular]']);
      assert.equal(svcJson.missingDep, '0xdead');

      const baseErr = new OmniOSError('base_bigint', { code: 0x10n, errno: 0x20n, signal: 0x30n });
      assert.equal(baseErr.code, 0x10n);
      assert.equal(baseErr.errno, 0x20n);
      assert.equal(baseErr.signal, 0x30n);
      const baseJson = JSON.parse(JSON.stringify(baseErr));
      assert.equal(baseJson.code, '0x10');
      assert.equal(baseJson.errno, '0x20');
      assert.equal(baseJson.signal, '0x30');
    }
  });
});




