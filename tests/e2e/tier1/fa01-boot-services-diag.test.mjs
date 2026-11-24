/**
 * Tier 1 E2E Tests — FA-01: OS Boot, System Services, dmesg & Panic/Recovery
 * Features covered: F-001, F-002, F-003, F-004, F-005
 * Contracts: Contract 1 (IKernel, IServiceManager, IProcessManager), Contract 7 (REST), Contract 8 (CLI)
 *
 * Strictly opaque-box: interacts ONLY through public OmniOS entrypoints via ../lib/env.mjs.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createTempDataDir,
  loadPublicOmniOS,
  runCli,
  startOmniServer,
} from '../lib/env.mjs';

const CORE_DAEMONS = ['vfsd', 'configd', 'ipc-brokerd', 'securityd', 'pkgd', 'compositord'];
const REQUIRED_BOOT_STAGES = ['EARLY_BOOT', 'CORE_SUBSYSTEMS', 'STORAGE_AND_STATE', 'OS_SERVICES'];

const LEVEL_RANK = new Map([
  ['trace', 0],
  ['debug', 1],
  ['info', 2],
  ['notice', 2],
  ['warn', 3],
  ['warning', 3],
  ['error', 4],
  ['err', 4],
  ['crit', 5],
  ['critical', 5],
  ['fatal', 6],
  ['panic', 6],
  ['emerg', 6],
]);

function makeNonce() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

function unwrapObject(payload, keys = ['data', 'status', 'diagnostics', 'kernel', 'result']) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return payload;
  for (const key of keys) {
    if (payload[key] && typeof payload[key] === 'object' && !Array.isArray(payload[key])) {
      return payload[key];
    }
  }
  return payload;
}

function unwrapList(payload, keys = ['entries', 'dmesg', 'logs', 'services', 'items', 'data', 'list']) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return [];
  for (const key of keys) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  if (payload.data && typeof payload.data === 'object') {
    for (const key of keys) {
      if (Array.isArray(payload.data[key])) return payload.data[key];
    }
  }
  return [];
}

function normalizeServicesMap(raw) {
  const map = new Map();
  if (!raw) return map;
  if (raw instanceof Map) {
    for (const [k, v] of raw.entries()) {
      map.set(String(k), typeof v === 'object' && v ? { name: String(k), ...v } : { name: String(k), state: String(v) });
    }
    return map;
  }
  const arr = Array.isArray(raw)
    ? raw
    : Array.isArray(raw?.services)
      ? raw.services
      : Array.isArray(raw?.data)
        ? raw.data
        : Array.isArray(raw?.data?.services)
          ? raw.data.services
          : null;
  if (arr) {
    for (const item of arr) {
      if (item && typeof item === 'object') {
        const name = item.name ?? item.id ?? item.service;
        if (name) map.set(String(name), item);
      }
    }
    return map;
  }
  const firstLevel = unwrapObject(raw, ['services', 'data', 'items']);
  const candidate =
    firstLevel && typeof firstLevel.services === 'object' && !Array.isArray(firstLevel.services)
      ? firstLevel.services
      : firstLevel;
  if (candidate && typeof candidate === 'object') {
    for (const [k, v] of Object.entries(candidate)) {
      if (k === 'ok' || k === 'ts' || k === 'count') continue;
      if (v && typeof v === 'object') {
        map.set(String(v.name ?? k), { name: String(v.name ?? k), ...v });
      } else if (typeof v === 'string') {
        map.set(k, { name: k, state: v });
      }
    }
  }
  return map;
}

function assertServiceHealthy(svc, name) {
  assert.ok(svc && typeof svc === 'object', `Expected service record for "${name}"`);
  assert.notEqual(svc.healthy, false, `Expected service "${name}" healthy !== false`);
  const hasExplicitStateKey = svc.state !== undefined || svc.status !== undefined;
  const rawState = svc.state ?? svc.status;
  if (hasExplicitStateKey) {
    assert.equal(
      typeof rawState,
      'string',
      `Expected service "${name}" state/status to be a non-empty string, got ${JSON.stringify(rawState)}`
    );
    const state = rawState.trim();
    assert.match(
      state,
      /^(running|active|healthy|ready|online|started|up|ok)$/i,
      `Expected service "${name}" to report an explicit running/healthy state, got state="${state}"`
    );
  } else {
    assert.equal(
      svc.healthy,
      true,
      `Expected service "${name}" to report explicit running/healthy state or healthy === true (got ${JSON.stringify(svc)})`
    );
  }
}

function makeYieldingContext(onStep) {
  let steps = 0;
  let disposed = false;
  return {
    get steps() {
      return steps;
    },
    get disposed() {
      return disposed;
    },
    step(budget = 1) {
      steps += 1;
      onStep?.(steps);
      return { status: 'YIELD', instructionsExecuted: Math.max(1, Math.min(budget, 4)) };
    },
    deliverEvent() {},
    getDebugState() {
      return {
        arch: 'test',
        pc: steps * 4,
        sp: 0x1000,
        registers: { r0: steps },
        instructionsExecuted: steps,
        lastSyscall: null,
        stackTop: 0x1000,
      };
    },
    dispose() {
      disposed = true;
    },
  };
}

describe('Tier 1 — FA-01: OS Boot, System Services, dmesg & Panic/Recovery', () => {
  test('T1 [F-001]: 4-stage deterministic boot sequence, stage timings & PID 0/1 init', async () => {
    const os = await loadPublicOmniOS({ autoBoot: false });
    try {
      const kernel = os.require('kernel');
      let bootReport;
      const preState = kernel.getDiagnostics?.()?.state;
      if (preState !== 'RUNNING') {
        bootReport = await (typeof os.raw.boot === 'function' ? os.raw.boot() : kernel.boot());
      } else {
        bootReport = kernel.getDiagnostics().bootReport;
      }

      assert.ok(bootReport && typeof bootReport === 'object', 'boot() must return a BootReport object');
      assert.equal(bootReport.status, 'RUNNING', `Expected bootReport.status === 'RUNNING', got ${bootReport.status}`);
      assert.equal(typeof bootReport.bootMs, 'number', 'bootReport.bootMs must be a number');
      assert.ok(Number.isFinite(bootReport.bootMs) && bootReport.bootMs >= 0, 'bootReport.bootMs must be >= 0');

      assert.ok(Array.isArray(bootReport.stages), 'bootReport.stages must be an Array');
      const stageNames = bootReport.stages.map((s) => String(s?.name ?? ''));
      let prevIdx = -1;
      for (const reqStage of REQUIRED_BOOT_STAGES) {
        const idx = stageNames.indexOf(reqStage);
        assert.ok(
          idx > prevIdx,
          `Expected stage "${reqStage}" in deterministic order ${JSON.stringify(REQUIRED_BOOT_STAGES)}; got ${JSON.stringify(stageNames)}`
        );
        const stageObj = bootReport.stages[idx];
        assert.equal(typeof stageObj.durationMs, 'number', `Stage "${reqStage}" must report numeric durationMs`);
        assert.ok(Number.isFinite(stageObj.durationMs) && stageObj.durationMs >= 0, `Stage "${reqStage}" durationMs must be >= 0`);
        prevIdx = idx;
      }

      const diag = kernel.getDiagnostics();
      assert.equal(diag.state, 'RUNNING', 'Kernel diagnostics must report state RUNNING');
      assert.ok(diag.bootReport && Array.isArray(diag.bootReport.stages), 'Diagnostics must include bootReport with stages');

      const pm = os.require('processManager');
      const p0 = pm.get(0);
      const p1 = pm.get(1);
      assert.ok(p0 && p0.pid === 0, 'PID 0 must exist after boot');
      assert.equal(p0.name, 'kernel_idle', `Expected PID 0 name "kernel_idle", got "${p0.name}"`);
      assert.ok(!['TERMINATED', 'ZOMBIE'].includes(p0.state), `PID 0 must be alive, got state=${p0.state}`);

      assert.ok(p1 && p1.pid === 1, 'PID 1 must exist after boot');
      assert.equal(p1.name, 'omnid', `Expected PID 1 name "omnid", got "${p1.name}"`);
      assert.equal(p1.ppid ?? p1.parentPid, 0, 'PID 1 parent PID must be 0');
      assert.ok(!['TERMINATED', 'ZOMBIE'].includes(p1.state), `PID 1 must be alive, got state=${p1.state}`);

      const list = pm.list();
      assert.ok(Array.isArray(list), 'processManager.list() must return an Array');
      assert.ok(list.some((p) => p.pid === 0), 'processManager.list() must contain PID 0');
      assert.ok(list.some((p) => p.pid === 1), 'processManager.list() must contain PID 1');
    } finally {
      await os.shutdown();
    }
  });

  test('T2 [F-002]: ServiceManager core daemons, dependency-order startup, health probes & manual restart', async () => {
    const os = await loadPublicOmniOS();
    try {
      const sm = os.require('serviceManager');
      const vfs = os.require('vfs');
      const nonce = makeNonce();

      const initialMap = normalizeServicesMap(sm.getStatus());
      for (const daemon of CORE_DAEMONS) {
        assertServiceHealthy(initialMap.get(daemon), daemon);
      }

      const svcA = `e2e-svc-a-${nonce}`;
      const svcB = `e2e-svc-b-${nonce}`;
      const svcC = `e2e-svc-c-${nonce}`;
      const startOrder = [];
      const counts = { startB: 0, stopB: 0, healthB: 0 };

      // Register deliberately in reverse dependency order: C -> B -> A
      sm.register({
        name: svcC,
        deps: [svcB],
        start() {
          startOrder.push(svcC);
        },
        stop() {},
        healthCheck() {
          return true;
        },
      });
      sm.register({
        name: svcB,
        deps: [svcA],
        start() {
          counts.startB += 1;
          startOrder.push(svcB);
        },
        stop() {
          counts.stopB += 1;
        },
        healthCheck() {
          counts.healthB += 1;
          return true;
        },
      });
      sm.register({
        name: svcA,
        deps: [],
        start() {
          startOrder.push(svcA);
        },
        stop() {},
        healthCheck() {
          return true;
        },
      });

      await sm.startAll();
      assert.deepEqual(
        startOrder,
        [svcA, svcB, svcC],
        `ServiceManager must start services in topological dependency order, got ${JSON.stringify(startOrder)}`
      );

      const postStartMap = normalizeServicesMap(sm.getStatus());
      assertServiceHealthy(postStartMap.get(svcA), svcA);
      assertServiceHealthy(postStartMap.get(svcB), svcB);
      assertServiceHealthy(postStartMap.get(svcC), svcC);

      await sm.restart(svcB);
      assert.ok(counts.stopB >= 1, `Expected svcB stop() called on restart (stopB=${counts.stopB})`);
      assert.ok(counts.startB >= 2, `Expected svcB start() called again on restart (startB=${counts.startB})`);
      if (counts.healthB === 0) {
        if (typeof sm.checkHealth === 'function') await sm.checkHealth(svcB);
        else if (typeof sm.runHealthChecks === 'function') await sm.runHealthChecks();
        else if (typeof sm.probeHealth === 'function') await sm.probeHealth(svcB);
      }
      assert.ok(counts.healthB >= 1, `Expected svcB healthCheck() probe to be invoked (healthB=${counts.healthB})`);
      assertServiceHealthy(normalizeServicesMap(sm.getStatus()).get(svcB), svcB);

      // Restart a genuine core OS daemon and verify VFS remains operational
      await sm.restart('vfsd');
      assertServiceHealthy(normalizeServicesMap(sm.getStatus()).get('vfsd'), 'vfsd');
      const homeStat = await vfs.stat('/home/user');
      assert.ok(homeStat && typeof homeStat === 'object', 'VFS /home/user must remain accessible after vfsd restart');
    } finally {
      await os.shutdown();
    }
  });

  test('T3 [F-003]: Kernel dmesg ring buffer schema, monotonic ordering, limit & subsystem/level filtering', async () => {
    const os = await loadPublicOmniOS();
    try {
      const kernel = os.require('kernel');
      const nonce = makeNonce();

      const all = kernel.dmesg({ limit: 200 });
      assert.ok(Array.isArray(all), 'kernel.dmesg() must return an Array');
      assert.ok(all.length >= 2, `Expected >= 2 boot dmesg entries, got ${all.length}`);

      let prevSeq = -Infinity;
      for (const entry of all) {
        assert.equal(typeof entry.seq, 'number', 'dmesg entry must have numeric seq');
        assert.ok(entry.seq > prevSeq, `dmesg seq must strictly increase (${prevSeq} -> ${entry.seq})`);
        prevSeq = entry.seq;
        assert.ok(entry.ts !== undefined && entry.ts !== null, 'dmesg entry must have ts');
        assert.equal(typeof entry.uptimeMs, 'number', 'dmesg entry must have numeric uptimeMs');
        assert.ok(entry.uptimeMs >= 0, 'dmesg entry uptimeMs must be >= 0');
        assert.equal(typeof entry.level, 'string', 'dmesg entry must have string level');
        assert.ok(entry.level.length > 0, 'dmesg entry level must be non-empty');
        assert.equal(typeof entry.subsystem, 'string', 'dmesg entry must have string subsystem');
        assert.ok(entry.subsystem.length > 0, 'dmesg entry subsystem must be non-empty');
        assert.equal(typeof entry.message, 'string', 'dmesg entry must have string message');
        assert.ok(entry.message.length > 0, 'dmesg entry message must be non-empty');
      }

      const limited = kernel.dmesg({ limit: 2 });
      assert.equal(limited.length, 2, `Expected limit=2 to return 2 entries, got ${limited.length}`);
      assert.ok(limited[0].seq < limited[1].seq, 'Limited dmesg entries must preserve ascending seq order');
      const allSeqs = new Set(all.map((e) => e.seq));
      assert.ok(allSeqs.has(limited[0].seq) && allSeqs.has(limited[1].seq), 'Limited entries must belong to the dmesg ring buffer');

      const targetSub = all[0].subsystem;
      const bySub = kernel.dmesg({ subsystem: targetSub, limit: 200 });
      assert.ok(bySub.length >= 1, `Expected >= 1 entry for subsystem "${targetSub}"`);
      for (const e of bySub) {
        assert.equal(e.subsystem.toLowerCase(), targetSub.toLowerCase(), 'Subsystem filter must return only matching entries');
      }

      const emptySub = kernel.dmesg({ subsystem: `no_such_sub_${nonce}`, limit: 200 });
      assert.deepEqual(emptySub, [], 'Nonexistent subsystem filter must return empty array');

      // Test a distinguishing level filter so ignoring `level` can never pass vacuously
      const presentLevels = Array.from(new Set(all.map((e) => String(e.level).toLowerCase())));
      let targetLevel = all[0].level;
      let targetRank = LEVEL_RANK.get(String(targetLevel).toLowerCase()) ?? 0;
      for (const entry of all) {
        const r = LEVEL_RANK.get(String(entry.level).toLowerCase()) ?? 0;
        if (r > targetRank) {
          targetRank = r;
          targetLevel = entry.level;
        }
      }

      const byLevel = kernel.dmesg({ level: targetLevel, limit: 200 });
      assert.ok(byLevel.length >= 1, `Expected >= 1 entry for level "${targetLevel}"`);
      for (const e of byLevel) {
        const entryRank = LEVEL_RANK.get(String(e.level).toLowerCase());
        const matches =
          e.level.toLowerCase() === targetLevel.toLowerCase() ||
          (entryRank !== undefined && entryRank >= targetRank);
        assert.ok(
          matches,
          `Level filter "${targetLevel}" returned incompatible level "${e.level}"`
        );
      }
      const hasStrictlyLowerRank = all.some((e) => {
        const r = LEVEL_RANK.get(String(e.level).toLowerCase());
        return r !== undefined && r < targetRank;
      });
      if (hasStrictlyLowerRank) {
        assert.ok(
          byLevel.length < all.length,
          `Level filter "${targetLevel}" must exclude lower-severity entries (got ${byLevel.length} of ${all.length})`
        );
      }

      // Verify a non-matching high-severity level excludes all lower-severity boot entries
      const maxPresentRank = Math.max(
        ...presentLevels.map((lvl) => LEVEL_RANK.get(lvl) ?? 0)
      );
      const absentLevel = ['error', 'warn', 'crit', 'fatal', 'panic'].find(
        (lvl) => !presentLevels.includes(lvl) && (LEVEL_RANK.get(lvl) ?? 0) > maxPresentRank
      );
      if (absentLevel) {
        const filteredOut = kernel.dmesg({ level: absentLevel, limit: 200 });
        assert.deepEqual(
          filteredOut,
          [],
          `Level filter "${absentLevel}" must exclude non-matching entries (got ${filteredOut.length})`
        );
      } else {
        const unknownLevel = kernel.dmesg({ level: `no_such_level_${nonce}`, limit: 200 });
        assert.deepEqual(unknownLevel, [], 'Nonexistent level filter must return empty array');
      }
    } finally {
      await os.shutdown();
    }
  });

  test('T4 [F-004]: Kernel panic SQLite dump, scheduling halt, safe-mode recovery & persistence across reopen', async () => {
    const temp = await createTempDataDir('omnios-fa01-panic-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      const panicCode = `E_TEST_PANIC_${nonce}`;
      const panicReason = `Controlled E2E kernel panic ${nonce}`;

      os1 = await loadPublicOmniOS({ dataDir: temp.dir });
      const kernel1 = os1.require('kernel');
      const pm1 = os1.require('processManager');
      const sched1 = os1.require('scheduler');
      sched1.stop?.();

      const workerCtx = makeYieldingContext();
      pm1.spawn({
        name: `panic-worker-${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        executionContext: workerCtx,
      });

      // Prove worker actually runs under the scheduler BEFORE panic() so halt check is non-vacuous
      for (let i = 0; i < 16 && workerCtx.steps === 0; i += 1) {
        sched1.step(1);
      }
      const stepsBefore = workerCtx.steps;
      assert.ok(stepsBefore > 0, `Worker must advance before kernel.panic() (stepsBefore=${stepsBefore})`);

      const dump = await kernel1.panic(panicCode, panicReason, { nonce });
      assert.ok(dump && typeof dump === 'object', 'kernel.panic() must return a PanicDump object');
      const dumpJson = JSON.stringify(dump);
      assert.ok(dumpJson.includes(panicCode), `PanicDump must contain code "${panicCode}"`);
      assert.ok(dumpJson.includes(panicReason), `PanicDump must contain reason "${panicReason}"`);

      const panicDiag = kernel1.getDiagnostics();
      assert.match(String(panicDiag.state), /PANIC/i, `Expected kernel state PANIC, got "${panicDiag.state}"`);
      assert.ok(panicDiag.lastPanic, 'Diagnostics must expose lastPanic after kernel.panic()');
      assert.ok(JSON.stringify(panicDiag.lastPanic).includes(panicCode), 'lastPanic must record panicCode');
      assert.ok(JSON.stringify(panicDiag.lastPanic).includes(panicReason), 'lastPanic must record panicReason');

      // User scheduling must be halted while kernel is in PANIC state
      const stepsAtPanic = workerCtx.steps;
      try {
        sched1.step(5);
      } catch {
        // Throwing on step while panicked is also valid halt behavior
      }
      assert.equal(workerCtx.steps, stepsAtPanic, 'User process scheduling must remain halted during kernel PANIC');
      assert.equal(stepsAtPanic, stepsBefore, 'Worker must not step during kernel.panic()');

      // Recover in safeMode without crashing host process
      const rec = await kernel1.recover({ safeMode: true });
      assert.ok(
        rec && (rec.status === 'RUNNING' || rec.status === 'SAFE_MODE'),
        `kernel.recover() must restore RUNNING or SAFE_MODE status, got ${JSON.stringify(rec)}`
      );
      const recDiag = kernel1.getDiagnostics();
      assert.ok(
        recDiag.state === 'RUNNING' || recDiag.state === 'SAFE_MODE',
        `Kernel diagnostics state must return to RUNNING or SAFE_MODE after recover(), got ${recDiag.state}`
      );
      assert.ok(
        recDiag.lastPanic && JSON.stringify(recDiag.lastPanic).includes(panicCode),
        'lastPanic must remain recorded after recovery'
      );

      await os1.shutdown();
      os1 = null;

      // Reopen on the same SQLite dataDir to prove crash dump persistence
      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      const diagAfterReboot = os2.require('kernel').getDiagnostics();
      assert.equal(diagAfterReboot.state, 'RUNNING', 'Reopened OS must boot cleanly to RUNNING');
      assert.ok(
        diagAfterReboot.lastPanic && JSON.stringify(diagAfterReboot.lastPanic).includes(panicCode),
        `Expected persisted SQLite lastPanic containing "${panicCode}" across reboot`
      );
      assert.ok(
        JSON.stringify(diagAfterReboot.lastPanic).includes(panicReason),
        `Expected persisted SQLite lastPanic containing "${panicReason}" across reboot`
      );
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });

  test('T5 [F-005]: Runtime diagnostics snapshot & live HTTP REST /api/health + /api/v1/kernel/*', async () => {
    const os = await loadPublicOmniOS();
    try {
      const diag = os.require('kernel').getDiagnostics();
      assert.equal(diag.state, 'RUNNING');
      assert.equal(typeof diag.uptimeMs, 'number');
      assert.ok(diag.uptimeMs >= 0);
      assert.ok(diag.bootReport && Array.isArray(diag.bootReport.stages) && diag.bootReport.stages.length >= 4);
      assert.ok(diag.services !== undefined && diag.services !== null, 'diagnostics must include services');
      assert.ok(typeof diag.processCount === 'number' && diag.processCount >= 2, 'processCount must be >= 2 (PID 0 & 1)');
      assert.ok(diag.memoryStats && typeof diag.memoryStats === 'object', 'diagnostics must include memoryStats object');
      assert.ok(Array.isArray(diag.dmesgTail), 'diagnostics must include dmesgTail array');
      assert.ok('lastPanic' in diag, 'diagnostics must include lastPanic key');
      assert.equal(diag.lastPanic, null, 'Clean boot diagnostics must report lastPanic === null');
    } finally {
      await os.shutdown();
    }

    const srv = await startOmniServer();
    try {
      const health = await srv.api.get('/api/health');
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true, 'GET /api/health must return ok: true');
      assert.equal(health.json?.os, 'OmniOS', 'GET /api/health must return os: "OmniOS"');
      assert.ok(Boolean(health.json?.status), 'GET /api/health must report status');

      const v1Health = await srv.api.get('/api/v1/health');
      assert.equal(v1Health.status, 200);
      assert.ok(
        v1Health.json &&
          typeof v1Health.json === 'object' &&
          !Array.isArray(v1Health.json) &&
          v1Health.json.ok !== false &&
          (v1Health.json.ok === true || Boolean(v1Health.json.status)),
        `GET /api/v1/health must return healthy JSON object (ok: true or status), got ${JSON.stringify(v1Health.json)}`
      );

      const statusRes = await srv.api.get('/api/v1/kernel/status');
      assert.equal(statusRes.status, 200);
      const statusDiag = unwrapObject(statusRes.json, ['diagnostics', 'kernel', 'data']);
      assert.equal(statusDiag?.state, 'RUNNING');
      assert.ok(typeof statusDiag?.uptimeMs === 'number' && statusDiag.uptimeMs >= 0);
      assert.ok(typeof statusDiag?.processCount === 'number' && statusDiag.processCount >= 2);
      assert.ok(statusDiag?.bootReport, 'GET /api/v1/kernel/status must include bootReport');
      assert.ok(statusDiag?.services, 'GET /api/v1/kernel/status must include services');

      const dmesgRes = await srv.api.get('/api/v1/kernel/dmesg', { query: { limit: 5 } });
      assert.equal(dmesgRes.status, 200);
      const dmesgList = unwrapList(dmesgRes.json);
      assert.ok(dmesgList.length >= 1 && dmesgList.length <= 5, `Expected 1..5 dmesg entries, got ${dmesgList.length}`);
      assert.equal(typeof dmesgList[0].message, 'string');

      const svcRes = await srv.api.get('/api/v1/kernel/services');
      assert.equal(svcRes.status, 200);
      const svcMap = normalizeServicesMap(svcRes.json);
      for (const daemon of CORE_DAEMONS) {
        assertServiceHealthy(svcMap.get(daemon), daemon);
      }

      const restartRes = await srv.api.post('/api/v1/kernel/services/vfsd/restart', {});
      assert.ok(restartRes.ok, `POST /api/v1/kernel/services/vfsd/restart failed with ${restartRes.status}`);

      const afterSvc = await srv.api.get('/api/v1/kernel/services');
      assert.equal(afterSvc.status, 200);
      assertServiceHealthy(normalizeServicesMap(afterSvc.json).get('vfsd'), 'vfsd');
    } finally {
      await srv.stop();
    }
  });

  test('T6 [F-005, Contract 8]: Remote & standalone headless CLI status, dmesg & services commands', async () => {
    let srv = null;
    let localTmp = null;
    try {
      srv = await startOmniServer();
      localTmp = await createTempDataDir('omnios-fa01-cli-');
      const statusCli = await srv.runCli(['status'], { json: true, expectZero: true });
      assert.ok(statusCli.json, 'Remote CLI "status --json" must output valid JSON');
      const remoteDiag = unwrapObject(statusCli.json, ['diagnostics', 'kernel', 'data']);
      assert.equal(remoteDiag?.state, 'RUNNING');
      assert.ok(typeof remoteDiag?.processCount === 'number' && remoteDiag.processCount >= 2);

      const dmesgCli = await srv.runCli(['dmesg'], { json: true, expectZero: true });
      const dmesgEntries = unwrapList(dmesgCli.json);
      assert.ok(dmesgEntries.length >= 1, 'Remote CLI "dmesg --json" must return >= 1 entry');
      assert.equal(typeof dmesgEntries[0].seq, 'number');
      assert.equal(typeof dmesgEntries[0].message, 'string');

      const servicesCli = await srv.runCli(['services'], { json: true, expectZero: true });
      const cliSvcMap = normalizeServicesMap(servicesCli.json);
      for (const daemon of CORE_DAEMONS) {
        assertServiceHealthy(cliSvcMap.get(daemon), daemon);
      }

      await srv.runCli(['services', 'restart', 'vfsd'], { json: true, expectZero: true });
      const servicesAfter = await srv.runCli(['services'], { json: true, expectZero: true });
      assertServiceHealthy(normalizeServicesMap(servicesAfter.json).get('vfsd'), 'vfsd');

      // Standalone headless CLI (no --remote server)
      const localStatus = await runCli(['status'], {
        dataDir: localTmp.dir,
        json: true,
        expectZero: true,
      });
      assert.ok(localStatus.json, 'Standalone headless CLI "status --json" must output valid JSON');
      const localDiag = unwrapObject(localStatus.json, ['diagnostics', 'kernel', 'data']);
      assert.equal(localDiag?.state, 'RUNNING');
    } finally {
      await srv?.stop();
      await localTmp?.cleanup();
    }
  });
});
