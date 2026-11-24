/**
 * Tier 2 Boundary, Corner & Negative E2E Suite — FA-01:
 * OS Boot, System Services, dmesg Ring Buffer & Panic/Recovery (F-001 – F-005).
 *
 * Strictly opaque-box: imports ONLY Node 24 built-ins and ../lib/env.mjs.
 * Zero skips, zero stubs, zero private internal os imports.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createTempDataDir,
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';

const CORE_DAEMONS = ['vfsd', 'configd', 'ipc-brokerd', 'securityd', 'pkgd', 'compositord'];
const REQUIRED_BOOT_STAGES = [
  'EARLY_BOOT',
  'CORE_SUBSYSTEMS',
  'STORAGE_AND_STATE',
  'OS_SERVICES',
];

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function unwrapObject(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  if (payload.data && typeof payload.data === 'object' && !Array.isArray(payload.data)) {
    return payload.data;
  }
  return payload;
}

function unwrapListStrict(payload, keys = ['entries', 'items', 'dmesg', 'logs', 'services', 'processes']) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return null;
  for (const key of keys) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  if (Array.isArray(payload.data)) return payload.data;
  if (payload.data && typeof payload.data === 'object') {
    for (const key of keys) {
      if (Array.isArray(payload.data[key])) return payload.data[key];
    }
  }
  return null;
}

function normalizeServicesMap(raw) {
  const map = new Map();
  if (!raw) return map;

  if (raw instanceof Map) {
    for (const [k, v] of raw.entries()) {
      map.set(String(k), v);
    }
    return map;
  }

  const candidate =
    Array.isArray(raw) ? raw
      : Array.isArray(raw.services) ? raw.services
        : Array.isArray(raw.data?.services) ? raw.data.services
          : Array.isArray(raw.data) ? raw.data
            : null;

  if (candidate) {
    for (const entry of candidate) {
      if (entry && typeof entry === 'object' && entry.name) {
        map.set(String(entry.name), entry);
      }
    }
    return map;
  }

  const obj =
    (raw.services && typeof raw.services === 'object' && !Array.isArray(raw.services)) ? raw.services
      : (raw.data?.services && typeof raw.data.services === 'object' && !Array.isArray(raw.data.services)) ? raw.data.services
        : (raw.data && typeof raw.data === 'object' && !Array.isArray(raw.data)) ? raw.data
          : (typeof raw === 'object' ? raw : null);

  if (obj) {
    for (const [k, v] of Object.entries(obj)) {
      if (v && typeof v === 'object') {
        map.set(String(v.name ?? k), v);
      }
    }
  }
  return map;
}

function assertServiceHealthyStrict(svc, name) {
  assert.ok(svc && typeof svc === 'object', `Service "${name}" must exist in ServiceManager status`);
  const state = String(svc.state ?? svc.status ?? '').trim();
  assert.ok(state.length > 0, `Service "${name}" must expose a non-empty state/status (got ${JSON.stringify(svc)})`);
  assert.match(
    state,
    /^(running|active|healthy|ready|started|ok)$/i,
    `Service "${name}" must be in a running/healthy state (got "${state}")`
  );
  assert.notEqual(svc.healthy, false, `Service "${name}" must not report healthy === false`);
}

function assertServiceFailedOrStopped(svc, name) {
  assert.ok(svc && typeof svc === 'object', `Service "${name}" must exist in ServiceManager status`);
  const state = String(svc.state ?? svc.status ?? '').trim();
  const isHealthyState = /^(running|active|healthy|ready|started|ok)$/i.test(state);
  assert.ok(
    svc.healthy === false || (state.length > 0 && !isHealthyState),
    `Service "${name}" must be failed/stopped/unhealthy after exhausting restarts (got ${JSON.stringify(svc)})`
  );
}

function assertBootStagesInOrder(stages, label) {
  assert.ok(Array.isArray(stages) && stages.length >= REQUIRED_BOOT_STAGES.length, `${label}: stages must be an array of >=4 stages`);
  const names = stages.map((s) => (typeof s === 'string' ? s : s?.name));
  let prevIdx = -1;
  for (const req of REQUIRED_BOOT_STAGES) {
    const idx = names.indexOf(req);
    assert.ok(idx > prevIdx, `${label}: required boot stage "${req}" missing or out of order in ${JSON.stringify(names)}`);
    prevIdx = idx;
  }
}

function makeYieldingContext() {
  const ctx = {
    steps: 0,
    totalBudget: 0,
    disposed: false,
    step(budget) {
      ctx.steps += 1;
      ctx.totalBudget += Number(budget) || 0;
      return { status: 'YIELD', instructionsExecuted: Math.max(1, Number(budget) || 1) };
    },
    deliverEvent() {},
    getDebugState() {
      return { arch: 'wasm', pc: ctx.steps, sp: 0, registers: {}, instructionsExecuted: ctx.totalBudget, lastSyscall: null, stackTop: 0 };
    },
    dispose() {
      ctx.disposed = true;
    },
  };
  return ctx;
}

test.describe('Tier 2 — FA-01: Boot, System Services, dmesg & Panic/Recovery (Boundary & Negative)', () => {
  test('T1 [F-001, F-005]: Boot idempotency (double-boot) & cold-reboot state integrity without duplicate PIDs/services', async () => {
    let temp = null;
    let os1 = null;
    let os2 = null;
    try {
      temp = await createTempDataDir('omnios-t2-fa01-boot-');
      os1 = await loadPublicOmniOS({ dataDir: temp.dir, autoBoot: false });
      const kernel = os1.require('kernel');
      const pm = os1.require('processManager');
      const sm = os1.require('serviceManager');

      const bootFn = () => (typeof os1.raw?.boot === 'function' ? os1.raw.boot() : kernel.boot());
      let firstReport = null;
      const preState = kernel.getDiagnostics?.()?.state;
      if (preState !== 'RUNNING') {
        firstReport = await bootFn();
        assert.equal(firstReport?.status, 'RUNNING', 'First boot must report status RUNNING');
        assertBootStagesInOrder(firstReport?.stages, 'First boot');
      } else {
        firstReport = kernel.getDiagnostics()?.bootReport;
        assertBootStagesInOrder(firstReport?.stages, 'Auto-booted report');
      }

      const initialProcs = pm.list();
      assert.ok(Array.isArray(initialProcs) && initialProcs.length >= 2, 'Booted OS must have PID 0 and PID 1');
      const initialProcCount = initialProcs.length;
      assert.equal(initialProcs.filter((p) => p.pid === 0).length, 1, 'PID 0 must appear exactly once after first boot');
      assert.equal(initialProcs.filter((p) => p.pid === 1).length, 1, 'PID 1 must appear exactly once after first boot');

      const initialSvcs = normalizeServicesMap(sm.getStatus());
      for (const daemon of CORE_DAEMONS) {
        assertServiceHealthyStrict(initialSvcs.get(daemon), daemon);
      }

      // Invoke boot() a second time while already RUNNING
      let secondReport = null;
      let doubleBootErr = null;
      try {
        secondReport = await bootFn();
      } catch (err) {
        doubleBootErr = err;
      }

      if (doubleBootErr) {
        assert.ok(doubleBootErr instanceof Error && doubleBootErr.message.length > 0, 'Double-boot rejection must be a structured Error');
      } else {
        assert.equal(secondReport?.status, 'RUNNING', 'Idempotent double-boot must return status RUNNING');
        assertBootStagesInOrder(secondReport?.stages, 'Double-boot report');
      }

      // Strict post-double-boot invariants: no duplicate PIDs, no leaked processes, all 6 core daemons strictly healthy
      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must remain RUNNING after double-boot');
      const afterProcs = pm.list();
      assert.equal(afterProcs.filter((p) => p.pid === 0).length, 1, 'PID 0 must not duplicate after double-boot');
      assert.equal(afterProcs.filter((p) => p.pid === 1).length, 1, 'PID 1 must not duplicate after double-boot');
      assert.equal(afterProcs.length, initialProcCount, 'Double-boot must not spawn duplicate processes');

      const afterSvcs = normalizeServicesMap(sm.getStatus());
      for (const daemon of CORE_DAEMONS) {
        assertServiceHealthyStrict(afterSvcs.get(daemon), daemon);
      }

      // Cold reboot on the same SQLite dataDir
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      const diag2 = os2.require('kernel').getDiagnostics();
      assert.equal(diag2?.state, 'RUNNING', 'Cold-rebooted kernel must reach RUNNING');
      assertBootStagesInOrder(diag2?.bootReport?.stages, 'Cold-reboot bootReport');

      const procs2 = os2.require('processManager').list();
      assert.equal(procs2.filter((p) => p.pid === 0).length, 1, 'Cold-reboot must have unique PID 0');
      assert.equal(procs2.filter((p) => p.pid === 1).length, 1, 'Cold-reboot must have unique PID 1');

      const svcs2 = normalizeServicesMap(os2.require('serviceManager').getStatus());
      for (const daemon of CORE_DAEMONS) {
        assertServiceHealthyStrict(svcs2.get(daemon), daemon);
      }
    } finally {
      await os2?.shutdown();
      await os1?.shutdown();
      await temp?.cleanup();
    }
  });

  test('T2 [F-002]: ServiceManager circular dependency rejection (2-node & 3-node cycles) & missing dependency rejection', async () => {
    const nonce = makeNonce();

    // Sub-case A: 2-node direct cycle A <-> B
    {
      let os = null;
      try {
        os = await loadPublicOmniOS();
        const kernel = os.require('kernel');
        const sm = os.require('serviceManager');
        const nameA = `cyc-a-${nonce}`;
        const nameB = `cyc-b-${nonce}`;
        let startedA = 0;
        let startedB = 0;

        let cycleErr = null;
        try {
          sm.register({ name: nameA, deps: [nameB], start: () => { startedA += 1; }, stop: () => {}, healthCheck: () => true });
          sm.register({ name: nameB, deps: [nameA], start: () => { startedB += 1; }, stop: () => {}, healthCheck: () => true });
          await sm.startAll();
        } catch (err) {
          cycleErr = err;
        }

        assert.ok(cycleErr instanceof Error && cycleErr.message.length > 0, '2-node service dependency cycle MUST be rejected with an Error');
        assert.ok(
          !(cycleErr instanceof RangeError && /call stack/i.test(cycleErr.message)),
          `2-node cycle detection must not overflow JS call stack: ${cycleErr.message}`
        );
        assert.equal(startedA, 0, 'Cyclic service A must not start');
        assert.equal(startedB, 0, 'Cyclic service B must not start');
        assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must stay RUNNING after 2-node cycle rejection');
        const svcs = normalizeServicesMap(sm.getStatus());
        for (const d of CORE_DAEMONS) assertServiceHealthyStrict(svcs.get(d), d);
      } finally {
        await os?.shutdown();
      }
    }

    // Sub-case B: 3-node transitive cycle X -> Y -> Z -> X
    {
      let os = null;
      try {
        os = await loadPublicOmniOS();
        const kernel = os.require('kernel');
        const sm = os.require('serviceManager');
        const nameX = `cyc-x-${nonce}`;
        const nameY = `cyc-y-${nonce}`;
        const nameZ = `cyc-z-${nonce}`;
        let startedX = 0;
        let startedY = 0;
        let startedZ = 0;

        let cycleErr = null;
        try {
          sm.register({ name: nameX, deps: [nameY], start: () => { startedX += 1; }, stop: () => {}, healthCheck: () => true });
          sm.register({ name: nameY, deps: [nameZ], start: () => { startedY += 1; }, stop: () => {}, healthCheck: () => true });
          sm.register({ name: nameZ, deps: [nameX], start: () => { startedZ += 1; }, stop: () => {}, healthCheck: () => true });
          await sm.startAll();
        } catch (err) {
          cycleErr = err;
        }

        assert.ok(cycleErr instanceof Error && cycleErr.message.length > 0, '3-node service dependency cycle MUST be rejected with an Error');
        assert.ok(
          !(cycleErr instanceof RangeError && /call stack/i.test(cycleErr.message)),
          `3-node cycle detection must not overflow JS call stack: ${cycleErr.message}`
        );
        assert.equal(startedX, 0, 'Cyclic service X must not start');
        assert.equal(startedY, 0, 'Cyclic service Y must not start');
        assert.equal(startedZ, 0, 'Cyclic service Z must not start');
        assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must stay RUNNING after 3-node cycle rejection');
      } finally {
        await os?.shutdown();
      }
    }

    // Sub-case C: Missing dependency
    {
      let os = null;
      try {
        os = await loadPublicOmniOS();
        const kernel = os.require('kernel');
        const sm = os.require('serviceManager');
        const orphan = `orphan-svc-${nonce}`;
        const missingDep = `missing-dep-${nonce}`;
        let startedOrphan = 0;

        let missingErr = null;
        try {
          sm.register({ name: orphan, deps: [missingDep], start: () => { startedOrphan += 1; }, stop: () => {}, healthCheck: () => true });
          await sm.startAll();
        } catch (err) {
          missingErr = err;
        }

        assert.ok(missingErr instanceof Error && missingErr.message.length > 0, 'Missing service dependency MUST be rejected with an Error');
        assert.equal(startedOrphan, 0, 'Service with missing dependency must not start');
        assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must stay RUNNING after missing dependency rejection');
      } finally {
        await os?.shutdown();
      }
    }
  });

  test('T3 [F-002]: ServiceManager crash restart backoff exhausting maxRestarts, inside-boundary recovery & unknown service restart error', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const kernel = os.require('kernel');
      const sm = os.require('serviceManager');

      // 1. Unknown service restart MUST reject cleanly
      await assert.rejects(
        async () => sm.restart(`unknown-svc-${nonce}`),
        (err) => err instanceof Error && err.message.length > 0,
        'Restarting a non-existent service must reject with a structured Error'
      );

      // 2. Inside-boundary recovery (flakySvc fails once, succeeds on attempt >= 2, maxRestarts: 3)
      const flakyName = `flaky-svc-${nonce}`;
      let flakyAttempts = 0;
      sm.register({
        name: flakyName,
        deps: [],
        maxRestarts: 3,
        start() {
          flakyAttempts += 1;
          if (flakyAttempts === 1) {
            throw new Error(`transient-boot-failure-${nonce}`);
          }
        },
        stop() {},
        healthCheck() {
          return flakyAttempts >= 2;
        },
      });

      try {
        await sm.startAll();
      } catch {
        // Initial start attempt may reject before backoff or manual restart
      }

      const flakyDeadline = Date.now() + 2000;
      while (flakyAttempts < 2 && Date.now() < flakyDeadline) {
        await sleep(40);
      }
      if (flakyAttempts === 1) {
        await sm.restart(flakyName);
      }

      assert.ok(flakyAttempts >= 2, `flakySvc must have recovered on attempt >= 2 (got ${flakyAttempts})`);
      assertServiceHealthyStrict(normalizeServicesMap(sm.getStatus()).get(flakyName), flakyName);

      // 3. Outside-boundary exhaustion (alwaysFailSvc with maxRestarts: 2 ALWAYS throws)
      const failName = `always-fail-${nonce}`;
      let failAttempts = 0;
      sm.register({
        name: failName,
        deps: [],
        maxRestarts: 2,
        start() {
          failAttempts += 1;
          throw new Error(`forced-crash-${nonce}-${failAttempts}`);
        },
        stop() {},
        healthCheck() {
          return false;
        },
      });

      try {
        await sm.startAll();
      } catch {
        // Expected rejection on persistent crash
      }

      // Allow async restart backoff to settle if implemented via timers.
      // Wait >=750ms quiet when fewer than 1+maxRestarts (3) attempts have fired so
      // slower exponential backoff timers (e.g. 350-500ms) while state === 'FAILED'
      // are not cut off prematurely; break fast if attempts exceed 3.
      const settleDeadline = Date.now() + 5000;
      let lastSeenAttempts = failAttempts;
      let stableSince = Date.now();
      while (Date.now() < settleDeadline) {
        if (failAttempts > 3) break;
        const entry = normalizeServicesMap(sm.getStatus()).get(failName);
        const st = String(entry?.state ?? entry?.status ?? '').trim();
        if (failAttempts !== lastSeenAttempts) {
          lastSeenAttempts = failAttempts;
          stableSince = Date.now();
        } else {
          const quietMs = failAttempts >= 3 ? 250 : 750;
          if (!/^(starting|restarting|backoff)$/i.test(st) && Date.now() - stableSince >= quietMs) {
            break;
          }
        }
        await sleep(50);
      }

      if (failAttempts >= 2) {
        // Auto-restart backoff path: must cap at 1 initial + maxRestarts (<= 3) and stop retrying
        assert.ok(
          failAttempts <= 3,
          `Auto-restart backoff with maxRestarts=2 must cap attempts at <=3 (got ${failAttempts})`
        );
        assertServiceFailedOrStopped(normalizeServicesMap(sm.getStatus()).get(failName), failName);
        const snapshotAttempts = failAttempts;
        await sleep(250);
        assert.equal(failAttempts, snapshotAttempts, 'Exhausted service must stop retrying (no infinite backoff loop)');
      } else {
        // Manual/deferred restart path: drive sm.restart() past maxRestarts and verify exhaustion enforcement
        assert.equal(failAttempts, 1, 'alwaysFailSvc must have attempted initial start once');
        let lastRestartErr = null;
        for (let i = 0; i < 4; i++) {
          lastRestartErr = null;
          try {
            await sm.restart(failName);
          } catch (err) {
            lastRestartErr = err;
          }
          assert.ok(lastRestartErr instanceof Error, `Restart #${i + 1} of always-failing service must fail with Error`);
        }
        assert.ok(
          failAttempts <= 4,
          `Exhausted maxRestarts=2 must stop invoking start() once limit reached (attempts=${failAttempts})`
        );
        assertServiceFailedOrStopped(normalizeServicesMap(sm.getStatus()).get(failName), failName);
      }

      // All 6 core daemons and kernel remain strictly healthy
      const finalSvcs = normalizeServicesMap(sm.getStatus());
      for (const daemon of CORE_DAEMONS) {
        assertServiceHealthyStrict(finalSvcs.get(daemon), daemon);
      }
      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must stay RUNNING after service restart exhaustion');
    } finally {
      await os?.shutdown();
    }
  });

  test('T4 [F-003]: dmesg ring-buffer overflow FIFO eviction & limit/subsystem/level boundary enforcement', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const kernel = os.require('kernel');
      const sm = os.require('serviceManager');
      const pm = os.require('processManager');
      os.scheduler?.stop?.();

      const full0 = kernel.dmesg({ limit: 100000 });
      assert.ok(Array.isArray(full0) && full0.length > 0, 'Booted kernel must have non-empty dmesg entries');

      // Boundary parameter checks
      const zeroRes = kernel.dmesg({ limit: 0 });
      assert.ok(Array.isArray(zeroRes) && zeroRes.length === 0, `dmesg({ limit: 0 }) MUST return [] (got length ${zeroRes?.length})`);

      for (const negLimit of [-1, -50]) {
        let negRes = null;
        let negErr = null;
        try {
          negRes = kernel.dmesg({ limit: negLimit });
        } catch (err) {
          negErr = err;
        }
        if (negErr) {
          assert.ok(negErr instanceof Error && negErr.message.length > 0);
        } else {
          assert.ok(
            Array.isArray(negRes) && negRes.length === 0,
            `dmesg({ limit: ${negLimit} }) must return [] or throw Error (got length ${negRes?.length})`
          );
        }
      }

      const oneRes = kernel.dmesg({ limit: 1 });
      assert.equal(oneRes.length, 1, 'dmesg({ limit: 1 }) must return exactly 1 entry');
      assert.equal(oneRes[0].seq, full0.at(-1).seq, 'dmesg({ limit: 1 }) must return the latest entry');

      const hugeRes = kernel.dmesg({ limit: 999999 });
      assert.ok(Array.isArray(hugeRes) && hugeRes.length <= full0.length && hugeRes.length > 0);
      assert.ok(hugeRes.every((e) => e && typeof e === 'object' && typeof e.seq === 'number'), 'dmesg must contain no undefined holes');

      const badSubRes = kernel.dmesg({ subsystem: `no-such-sub-${nonce}`, limit: 200 });
      assert.ok(Array.isArray(badSubRes) && badSubRes.length === 0, 'Unknown subsystem filter must return []');

      const errOnly = kernel.dmesg({ level: 'error', limit: 200 });
      assert.ok(Array.isArray(errOnly), 'dmesg({ level: "error" }) must return an array');
      for (const entry of errOnly) {
        const lvl = String(entry.level ?? '').toLowerCase();
        assert.ok(
          !['debug', 'info', 'warn', 'warning'].includes(lvl),
          `dmesg({ level: "error" }) leaked lower-severity entry: ${JSON.stringify(entry)}`
        );
      }

      let badLvlRes = null;
      let badLvlErr = null;
      try {
        badLvlRes = kernel.dmesg({ level: `no-such-lvl-${nonce}`, limit: 200 });
      } catch (err) {
        badLvlErr = err;
      }
      if (badLvlErr) {
        assert.ok(badLvlErr instanceof Error);
      } else {
        assert.ok(Array.isArray(badLvlRes) && badLvlRes.length === 0, 'Unknown level filter must return [] or throw Error');
      }

      // Discover an active public dmesg producer dynamically
      const noopName = `dmesg-noop-${nonce}`;
      sm.register({ name: noopName, deps: [], start() {}, stop() {}, healthCheck: () => true });
      await sm.startAll();

      const getLastSeq = () => {
        const tail = kernel.dmesg({ limit: 1 });
        return tail.length > 0 ? tail[0].seq : -1;
      };

      let producer = null;
      const beforeRestartSeq = getLastSeq();
      await sm.restart(noopName);
      if (getLastSeq() > beforeRestartSeq) {
        producer = () => sm.restart(noopName);
      }

      if (!producer) {
        const beforeSpawnSeq = getLastSeq();
        const pcb = pm.spawn({ name: `dmesg-probe-${nonce}`, appId: `com.dmesg.${nonce}`, platform: 'universal', arch: 'wasm', executionContext: makeYieldingContext() });
        pm.kill(pcb.pid, 'SIGKILL');
        if (getLastSeq() > beforeSpawnSeq) {
          producer = () => {
            const p = pm.spawn({ name: `dmesg-fill-${nonce}`, appId: `com.dmesg.${nonce}`, platform: 'universal', arch: 'wasm', executionContext: makeYieldingContext() });
            pm.kill(p.pid, 'SIGKILL');
          };
        }
      }

      if (!producer && typeof kernel.log === 'function') {
        const beforeLogSeq = getLastSeq();
        kernel.log('info', 'e2e', `probe-${nonce}`);
        if (getLastSeq() > beforeLogSeq) {
          let n = 0;
          producer = () => kernel.log('info', 'e2e', `fill-${nonce}-${n++}`);
        }
      }

      assert.ok(producer, 'At least one public OS operation (service restart, process lifecycle, or kernel.log) must emit dmesg entries');

      // Drive ring buffer past capacity to verify bounded FIFO eviction
      const baseline = kernel.dmesg({ limit: 100000 });
      const firstSeq = baseline[0].seq;
      const startLastSeq = baseline.at(-1).seq;
      let evicted = false;
      let capSizeAtEviction = 0;

      for (let batch = 0; batch < 24 && !evicted; batch++) {
        for (let i = 0; i < 250; i++) {
          await producer();
        }
        const cur = kernel.dmesg({ limit: 100000 });
        if (cur.length > 0 && cur[0].seq > firstSeq) {
          evicted = true;
          capSizeAtEviction = cur.length;
        }
      }

      assert.ok(evicted, 'dmesg ring buffer must evict oldest entries FIFO once capacity is exceeded');

      // Push 100 more entries and verify buffer remains bounded at capacity
      for (let i = 0; i < 100; i++) {
        await producer();
      }

      const finalEntries = kernel.dmesg({ limit: 100000 });
      const totalProduced = finalEntries.at(-1).seq - startLastSeq + baseline.length;
      assert.ok(finalEntries[0].seq > firstSeq, 'Oldest dmesg entries must have been evicted FIFO');
      assert.ok(finalEntries.length < totalProduced, `dmesg ring buffer must remain bounded (len=${finalEntries.length}, totalProduced=${totalProduced})`);
      assert.ok(
        finalEntries.length <= capSizeAtEviction,
        `dmesg buffer must not grow past ring capacity after eviction (atEviction=${capSizeAtEviction}, after100=${finalEntries.length})`
      );

      for (let i = 1; i < finalEntries.length; i++) {
        assert.ok(
          finalEntries[i].seq > finalEntries[i - 1].seq,
          `dmesg seq must be strictly monotonically increasing at index ${i} (${finalEntries[i - 1].seq} -> ${finalEntries[i].seq})`
        );
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T5 [F-004]: Double panic(), scheduler halt verification & recover({ safeMode: true }) preserving SQLite state across reboot', async () => {
    const nonce = makeNonce();
    let temp = null;
    let os1 = null;
    let os2 = null;
    try {
      temp = await createTempDataDir('omnios-t2-fa01-panic-');
      os1 = await loadPublicOmniOS({ dataDir: temp.dir });
      const kernel = os1.require('kernel');
      const pm = os1.require('processManager');
      const sched = os1.require('scheduler');
      const vfs = os1.require('vfs');
      const configStore = os1.require('configStore');
      sched.stop();

      // Persist pre-panic SQLite state across VFS, System Config, and Windows Registry
      const vfsPath = `/home/user/Documents/pre-panic-${nonce}.txt`;
      const vfsPayload = `survive-${nonce}`;
      await vfs.writeFile(vfsPath, vfsPayload, { uid: 0, gid: 0 });
      await configStore.system.set('system.locale', 'de-DE');
      const regKey = `Software\\PrePanic\\${nonce}`;
      await configStore.registry.setValue('HKCU', regKey, 'Token', 'REG_SZ', `reg-${nonce}`, { uid: 0, gid: 0 });

      // Non-vacuous pre-condition: verify worker process actually executes BEFORE panic
      const workerCtx = makeYieldingContext();
      const workerPcb = pm.spawn({
        name: `panic-worker-${nonce}`,
        appId: `com.panic.worker.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        executionContext: workerCtx,
      });
      const maxProbeTicks = Math.max(5, pm.list().length + 3);
      for (let i = 0; i < maxProbeTicks && workerCtx.steps === 0; i++) {
        sched.step(1);
      }
      assert.ok(workerCtx.steps > 0, 'Pre-condition failed: worker process must execute steps before kernel.panic()');

      // First panic()
      const panicCode1 = `E_PANIC1_${nonce}`;
      const dump1 = await kernel.panic(panicCode1, `first panic ${nonce}`, { n: 1 });
      assert.ok(dump1 && typeof dump1 === 'object', 'First kernel.panic() must return a PanicDump object');
      assert.match(String(kernel.getDiagnostics()?.state ?? ''), /PANIC/i, 'Kernel state must report PANIC after first panic()');

      const stepsAfterPanic1 = workerCtx.steps;
      try {
        sched.step(5);
      } catch {
        // Throwing when stepping a panicked kernel is also acceptable
      }
      assert.equal(workerCtx.steps, stepsAfterPanic1, 'User scheduling MUST be halted after kernel.panic()');

      // Second (double) panic()
      const panicCode2 = `E_PANIC2_${nonce}`;
      let dump2 = null;
      let doublePanicErr = null;
      try {
        dump2 = await kernel.panic(panicCode2, `second panic ${nonce}`, { n: 2 });
      } catch (err) {
        doublePanicErr = err;
      }
      if (doublePanicErr) {
        assert.ok(doublePanicErr instanceof Error && doublePanicErr.message.length > 0);
      } else {
        assert.ok(dump2 && typeof dump2 === 'object', 'Double panic must return valid PanicDump or throw Error');
      }

      const diagPanic2 = kernel.getDiagnostics();
      assert.match(String(diagPanic2?.state ?? ''), /PANIC/i, 'Kernel state must remain PANIC after double panic()');
      const lastPanicStr = JSON.stringify(diagPanic2?.lastPanic ?? '');
      assert.ok(
        lastPanicStr.includes(panicCode1) || lastPanicStr.includes(panicCode2),
        `lastPanic must reference first or second panic code (got ${lastPanicStr})`
      );

      try {
        sched.step(5);
      } catch {
        // Acceptable
      }
      assert.equal(workerCtx.steps, stepsAfterPanic1, 'User scheduling MUST remain halted after double panic()');

      // Safe-mode recovery
      const rec = await kernel.recover({ safeMode: true });
      assert.ok(
        rec?.status === 'RUNNING' || rec?.status === 'SAFE_MODE',
        `kernel.recover({ safeMode: true }) must restore RUNNING or SAFE_MODE (got ${JSON.stringify(rec)})`
      );
      const diagRec = kernel.getDiagnostics();
      assert.ok(
        diagRec?.state === 'RUNNING' || diagRec?.state === 'SAFE_MODE',
        `Kernel diagnostics state must be RUNNING or SAFE_MODE after recovery (got ${diagRec?.state})`
      );
      assert.ok(diagRec?.lastPanic, 'lastPanic must remain recorded after safe-mode recovery');

      // All 3 pre-panic SQLite artifacts must read back verbatim
      const readVfs = await vfs.readFile(vfsPath, { encoding: 'utf8', uid: 0, gid: 0 });
      assert.equal(readVfs, vfsPayload, 'VFS file must survive panic & safeMode recovery');
      assert.equal(await configStore.system.get('system.locale'), 'de-DE', 'System config must survive panic & recovery');
      const readReg = await configStore.registry.getValue('HKCU', regKey, 'Token', { uid: 0, gid: 0 });
      assert.equal(readReg?.data, `reg-${nonce}`, 'Registry value must survive panic & recovery');

      // Double recover() while already RUNNING must remain safe and non-destructive
      let rec2 = null;
      let rec2Err = null;
      try {
        rec2 = await kernel.recover({ safeMode: false });
      } catch (err) {
        rec2Err = err;
      }
      if (rec2Err) {
        assert.ok(rec2Err instanceof Error && rec2Err.message.length > 0, 'Double recover() rejection must be a structured Error');
      } else if (rec2 !== null && rec2 !== undefined) {
        assert.equal(rec2.status, 'RUNNING', `Idempotent double recover() must return status RUNNING (got ${JSON.stringify(rec2)})`);
      }
      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must remain RUNNING after double recover()');
      assert.equal(await vfs.readFile(vfsPath, { encoding: 'utf8', uid: 0, gid: 0 }), vfsPayload);

      // Clean up worker if still present, then cold-reboot to verify SQLite durability
      try { pm.kill(workerPcb.pid, 'SIGKILL'); } catch { /* may already be cleared on recovery */ }
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      const diagReboot = os2.require('kernel').getDiagnostics();
      assert.equal(diagReboot?.state, 'RUNNING');
      assert.ok(diagReboot?.lastPanic, 'Persisted lastPanic must survive cold reboot from SQLite');
      const rebootPanicStr = JSON.stringify(diagReboot.lastPanic);
      assert.ok(
        rebootPanicStr.includes(panicCode1) || rebootPanicStr.includes(panicCode2),
        `Rebooted lastPanic must match persisted panic code (got ${rebootPanicStr})`
      );
      assert.equal(
        await os2.require('vfs').readFile(vfsPath, { encoding: 'utf8', uid: 0, gid: 0 }),
        vfsPayload,
        'VFS file must survive cold reboot after panic recovery'
      );
      assert.equal(await os2.require('configStore').system.get('system.locale'), 'de-DE');
      const regReboot = await os2.require('configStore').registry.getValue('HKCU', regKey, 'Token', { uid: 0, gid: 0 });
      assert.equal(regReboot?.data, `reg-${nonce}`);
    } finally {
      await os2?.shutdown();
      await os1?.shutdown();
      await temp?.cleanup();
    }
  });

  test('T6 [F-002, F-003, F-004, F-005, Contracts 7 & 8]: Invalid REST /api/v1/kernel/* (400/404), malformed JSON, REST panic/recover & CLI negative boundaries', async () => {
    const nonce = makeNonce();
    let srv = null;
    try {
      srv = await startOmniServer();

      // Unknown service restart -> 400 or 404
      const resUnknownSvc = await srv.api.post(`/api/v1/kernel/services/unknown-${nonce}/restart`, {});
      assert.ok(
        resUnknownSvc.status === 400 || resUnknownSvc.status === 404,
        `Unknown service restart must return HTTP 400 or 404 (got ${resUnknownSvc.status}: ${resUnknownSvc.text})`
      );

      // Unknown action on real service -> 400 or 404
      const resBadAction = await srv.api.post(`/api/v1/kernel/services/vfsd/badAction-${nonce}`, {});
      assert.ok(
        resBadAction.status === 400 || resBadAction.status === 404,
        `Invalid service action must return HTTP 400 or 404 (got ${resBadAction.status}: ${resBadAction.text})`
      );

      // Unknown service + unknown action -> 400 or 404
      const resBothBad = await srv.api.post(`/api/v1/kernel/services/unknown-${nonce}/badAction-${nonce}`, {});
      assert.ok(
        resBothBad.status === 400 || resBothBad.status === 404,
        `Unknown service + action must return HTTP 400 or 404 (got ${resBothBad.status})`
      );

      // Raw malformed JSON -> HTTP 400
      const resBadJson = await srv.api.post('/api/v1/kernel/services/vfsd/restart', '{not-json', {
        headers: { 'content-type': 'application/json' },
      });
      assert.equal(resBadJson.status, 400, `Malformed JSON body must return HTTP 400 (got ${resBadJson.status})`);

      // dmesg limit=0 & limit=-5 boundaries
      const resZero = await srv.api.get('/api/v1/kernel/dmesg', { query: { limit: 0 } });
      if (resZero.status === 200) {
        const list = unwrapListStrict(resZero.json, ['entries', 'dmesg', 'logs', 'items']);
        assert.ok(Array.isArray(list) && list.length === 0, `GET dmesg?limit=0 must return [] (got ${JSON.stringify(resZero.json)})`);
      } else {
        assert.equal(resZero.status, 400, `GET dmesg?limit=0 must return 200 [] or 400 (got ${resZero.status})`);
      }

      const resNeg = await srv.api.get('/api/v1/kernel/dmesg', { query: { limit: -5 } });
      if (resNeg.status === 200) {
        const list = unwrapListStrict(resNeg.json, ['entries', 'dmesg', 'logs', 'items']);
        assert.ok(Array.isArray(list) && list.length === 0, `GET dmesg?limit=-5 must return [] (got ${JSON.stringify(resNeg.json)})`);
      } else {
        assert.equal(resNeg.status, 400, `GET dmesg?limit=-5 must return 200 [] or 400 (got ${resNeg.status})`);
      }

      // Unknown subsystem -> 200 strict []
      const resNoSub = await srv.api.get('/api/v1/kernel/dmesg', { query: { subsystem: `no_such_${nonce}` } });
      assert.equal(resNoSub.status, 200, `Unknown dmesg subsystem must return 200 (got ${resNoSub.status})`);
      const noSubList = unwrapListStrict(resNoSub.json, ['entries', 'dmesg', 'logs', 'items']);
      assert.ok(Array.isArray(noSubList) && noSubList.length === 0, 'Unknown dmesg subsystem must return exact []');

      // Controlled REST panic & safeMode recover cycle
      const resPanic = await srv.api.post('/api/v1/kernel/panic', {
        code: `E_HTTP_PANIC_${nonce}`,
        reason: `rest panic ${nonce}`,
      });
      assert.equal(resPanic.status, 200, `POST /api/v1/kernel/panic must succeed (got ${resPanic.status}: ${resPanic.text})`);

      const resPanicStatus = await srv.api.get('/api/v1/kernel/status');
      assert.equal(resPanicStatus.status, 200);
      const panicState = String(unwrapObject(resPanicStatus.json)?.state ?? '');
      assert.match(panicState, /PANIC/i, `Kernel status must report PANIC after REST panic (got "${panicState}")`);

      const resRecover = await srv.api.post('/api/v1/kernel/recover', { safeMode: true });
      assert.equal(resRecover.status, 200, `POST /api/v1/kernel/recover must succeed (got ${resRecover.status}: ${resRecover.text})`);

      const resAfterRec = await srv.api.get('/api/v1/kernel/status');
      assert.equal(resAfterRec.status, 200);
      const recState = unwrapObject(resAfterRec.json)?.state ?? unwrapObject(resAfterRec.json)?.status;
      assert.ok(
        recState === 'RUNNING' || recState === 'SAFE_MODE',
        `Kernel must return to RUNNING or SAFE_MODE after REST recover (got ${JSON.stringify(recState)})`
      );

      // Remote CLI negative boundary: restarting unknown service must exit non-zero
      const cliBadSvc = await srv.runCli(['services', 'restart', `unknown-${nonce}`], { json: true });
      assert.notEqual(cliBadSvc.code, 0, 'CLI services restart <unknown> must exit non-zero');

      // Final liveness & core service check
      const health = await srv.api.get('/api/health');
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
      assert.equal(health.json?.os, 'OmniOS');

      const svcsRes = await srv.api.get('/api/v1/kernel/services');
      assert.equal(svcsRes.status, 200);
      const svcsMap = normalizeServicesMap(svcsRes.json);
      assertServiceHealthyStrict(svcsMap.get('vfsd'), 'vfsd');
    } finally {
      await srv?.stop();
    }
  });
});
