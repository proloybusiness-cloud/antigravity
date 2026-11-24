/**
 * Tier 2 Boundary, Corner & Negative E2E Suite — FA-02:
 * Process Lifecycle, Scheduler, Signals, Streams & Fault Isolation (F-006 – F-010, F-035).
 *
 * Strictly opaque-box: imports ONLY Node 24 built-ins, ../lib/env.mjs, and ../lib/fixtures-apple-wasm.mjs.
 * Zero skips, zero stubs, zero hardcoded system app IDs, zero private internal os imports.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';
import { buildCustomUapp } from '../lib/fixtures-apple-wasm.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function unwrapListStrict(payload, keys = ['packages', 'apps', 'processes', 'items']) {
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

function makeScriptedContext({
  maxSteps = Number.POSITIVE_INFINITY,
  exitCode = 0,
  stepBehavior = null,
} = {}) {
  const ctx = {
    steps: 0,
    totalInsns: 0,
    totalBudget: 0,
    observedBudgets: [],
    disposed: false,
    events: [],
    step(budget) {
      ctx.steps += 1;
      const numericBudget = Number(budget);
      ctx.observedBudgets.push(numericBudget);
      ctx.totalBudget += Number.isFinite(numericBudget) ? numericBudget : 0;

      if (typeof stepBehavior === 'function') {
        const res = stepBehavior(ctx, budget);
        if (res && typeof res.instructionsExecuted === 'number') {
          ctx.totalInsns += res.instructionsExecuted;
        }
        return res;
      }

      const insns = Number.isFinite(numericBudget) && numericBudget > 0 ? numericBudget : 1;
      ctx.totalInsns += insns;
      if (ctx.steps >= maxSteps) {
        return { status: 'EXITED', instructionsExecuted: insns, exitCode };
      }
      return { status: 'YIELD', instructionsExecuted: insns };
    },
    deliverEvent(ev) {
      ctx.events.push(ev);
    },
    getDebugState() {
      return {
        arch: 'wasm',
        pc: ctx.steps,
        sp: 0,
        registers: {},
        instructionsExecuted: ctx.totalInsns,
        lastSyscall: null,
        stackTop: 0,
      };
    },
    dispose() {
      ctx.disposed = true;
    },
  };
  return ctx;
}

async function assertKillRejected(pm, pid, signal, label) {
  let result;
  let caught = null;
  try {
    result = await pm.kill(pid, signal);
  } catch (err) {
    caught = err;
  }

  if (caught) {
    assert.ok(caught instanceof Error && caught.message.length > 0, `${label}: thrown error must have a non-empty message`);
    return;
  }
  assert.ok(
    result && typeof result === 'object' && result.ok === false,
    `${label}: pm.kill(${pid}, ${JSON.stringify(signal)}) MUST throw Error or return { ok: false } (got ${JSON.stringify(result)})`
  );
}

test.describe('Tier 2 — FA-02: Process Lifecycle, Scheduler, Signals & Streams (Boundary & Negative)', () => {
  test('T1 [F-006, F-009]: Non-existent / negative PID rejection & PID 0 (kernel_idle) / PID 1 (omnid) kill protection', async () => {
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const kernel = os.require('kernel');
      const pm = os.require('processManager');
      os.require('scheduler').stop();

      // Non-existent & negative PID lookups
      assert.ok(pm.get(999999) === null || pm.get(999999) === undefined, 'pm.get(999999) must return null/undefined');
      let negGetErr = null;
      let negGetVal;
      try {
        negGetVal = pm.get(-1);
      } catch (err) {
        negGetErr = err;
      }
      if (negGetErr) {
        assert.ok(negGetErr instanceof Error && negGetErr.message.length > 0);
      } else {
        assert.ok(negGetVal === null || negGetVal === undefined, 'pm.get(-1) must return null/undefined or throw Error');
      }

      // Signaling non-existent / negative PIDs must fail cleanly
      await assertKillRejected(pm, 999999, 'SIGTERM', 'kill(999999, SIGTERM)');
      await assertKillRejected(pm, 999999, 'SIGKILL', 'kill(999999, SIGKILL)');
      await assertKillRejected(pm, -1, 'SIGTERM', 'kill(-1, SIGTERM)');

      // Protected kernel processes PID 0 and PID 1 MUST reject lethal/stop signals and stay alive
      for (const protectedPid of [0, 1]) {
        for (const sig of ['SIGTERM', 'SIGKILL', 'SIGSTOP', 'SIGINT']) {
          await assertKillRejected(pm, protectedPid, sig, `protected kill(${protectedPid}, ${sig})`);
          const pcb = pm.get(protectedPid);
          assert.ok(pcb && typeof pcb === 'object', `PID ${protectedPid} must still exist after rejected ${sig}`);
          const state = String(pcb.state ?? '').toUpperCase();
          assert.ok(
            !['STOPPED', 'ZOMBIE', 'TERMINATED'].includes(state),
            `Protected PID ${protectedPid} must remain alive after rejected ${sig} (state=${state})`
          );
        }
      }

      assert.equal(pm.get(0)?.name, 'kernel_idle', 'PID 0 must remain kernel_idle');
      assert.equal(pm.get(1)?.name, 'omnid', 'PID 1 must remain omnid');
      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING');
    } finally {
      await os?.shutdown();
    }
  });

  test('T2 [F-006, F-009]: Illegal signal names & signaling already-TERMINATED/ZOMBIE processes', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const pm = os.require('processManager');
      const sched = os.require('scheduler');
      sched.stop();

      const ctxLive = makeScriptedContext();
      const livePcb = pm.spawn({
        name: `sig-live-${nonce}`,
        appId: `com.sig.live.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        executionContext: ctxLive,
      });

      try {
        // Never pass undefined (Contract 1 defaults signal = 'SIGTERM')
        for (const badSig of ['SIGFAKE', 'NOT_A_SIGNAL', '', 9999, -5]) {
          await assertKillRejected(pm, livePcb.pid, badSig, `illegal signal ${JSON.stringify(badSig)}`);
          const cur = pm.get(livePcb.pid);
          assert.ok(
            cur && !['ZOMBIE', 'TERMINATED'].includes(String(cur.state ?? '').toUpperCase()),
            `Illegal signal ${JSON.stringify(badSig)} must not kill live process`
          );
          assert.equal(ctxLive.disposed, false, 'Illegal signal must not dispose live executionContext');
        }

        // Spawn and cleanly terminate a short-lived process
        const ctxDead = makeScriptedContext({ maxSteps: 1, exitCode: 0 });
        const deadPcb = pm.spawn({
          name: `sig-dead-${nonce}`,
          appId: `com.sig.dead.${nonce}`,
          platform: 'universal',
          arch: 'wasm',
          executionContext: ctxDead,
        });

        await sched.runUntilIdle(deadPcb.pid, 50);
        const deadState = String(pm.get(deadPcb.pid)?.state ?? '').toUpperCase();
        assert.ok(['ZOMBIE', 'TERMINATED'].includes(deadState), `Exited process must be ZOMBIE/TERMINATED (got ${deadState})`);
        assert.equal(ctxDead.disposed, true, 'Exited process executionContext must be disposed');
        const stepsAtDeath = ctxDead.steps;

        // Signaling an already-exited process MUST fail cleanly and NEVER resurrect it
        for (const sig of ['SIGSTOP', 'SIGCONT', 'SIGTERM', 'SIGKILL', 'SIGUSR1']) {
          await assertKillRejected(pm, deadPcb.pid, sig, `signal dead pid with ${sig}`);
          const post = pm.get(deadPcb.pid);
          if (post) {
            const st = String(post.state ?? '').toUpperCase();
            assert.ok(['ZOMBIE', 'TERMINATED'].includes(st), `Dead process must NEVER resurrect after ${sig} (got ${st})`);
          }
        }

        sched.step(5);
        assert.equal(ctxDead.steps, stepsAtDeath, 'Terminated process must never execute further scheduler steps');
      } finally {
        try { pm.kill(livePcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T3 [F-008]: scheduler.step(0) / negative ticks & runUntilIdle(pid, maxTicks) hard cap on non-exiting process', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const pm = os.require('processManager');
      const sched = os.require('scheduler');
      sched.stop();

      const infCtx = makeScriptedContext({ maxSteps: Number.POSITIVE_INFINITY });
      const infPcb = pm.spawn({
        name: `inf-loop-${nonce}`,
        appId: `com.sched.inf.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        quotas: { maxTotalInstructions: 1_000_000, maxInstructionsPerTick: 100 },
        executionContext: infCtx,
      });

      try {
        // step(0) boundary -> 0 steps executed
        let step0Res = null;
        let step0Err = null;
        try {
          step0Res = sched.step(0);
        } catch (err) {
          step0Err = err;
        }
        if (step0Err) {
          assert.ok(step0Err instanceof Error && step0Err.message.length > 0);
        }
        assert.equal(infCtx.steps, 0, 'scheduler.step(0) must execute 0 process steps');
        if (step0Res && typeof step0Res === 'object') {
          assert.equal(step0Res.ticksRun, 0, 'scheduler.step(0) must report ticksRun === 0');
          assert.equal(step0Res.instructionsExecuted, 0, 'scheduler.step(0) must report instructionsExecuted === 0');
        }

        // step(-5) negative boundary -> 0 steps executed (or throws Error)
        let stepNegRes = null;
        let stepNegErr = null;
        try {
          stepNegRes = sched.step(-5);
        } catch (err) {
          stepNegErr = err;
        }
        if (stepNegErr) {
          assert.ok(stepNegErr instanceof Error && stepNegErr.message.length > 0);
        }
        assert.equal(infCtx.steps, 0, 'scheduler.step(-5) must execute 0 process steps');
        if (stepNegRes && typeof stepNegRes === 'object') {
          assert.equal(stepNegRes.ticksRun, 0, 'scheduler.step(-5) must report ticksRun === 0');
          assert.equal(stepNegRes.instructionsExecuted, 0, 'scheduler.step(-5) must report instructionsExecuted === 0');
        }

        // Non-vacuity check: step(1) genuinely advances infPcb
        const probeLimit = Math.max(5, pm.list().length + 2);
        for (let i = 0; i < probeLimit && infCtx.steps === 0; i++) {
          sched.step(1);
        }
        assert.ok(infCtx.steps >= 1, 'Pre-condition: scheduler.step(1) must advance non-exiting process');

        // runUntilIdle(pid, maxTicks) must obey hard maxTicks cap and scale with maxTicks
        const cap1 = Math.max(15, pm.list().length + 2);
        const stepsBefore1 = infCtx.steps;
        const t0 = Date.now();
        const summary1 = await sched.runUntilIdle(infPcb.pid, cap1);
        const elapsedMs1 = Date.now() - t0;
        const delta1 = infCtx.steps - stepsBefore1;

        assert.ok(elapsedMs1 < 5000, `runUntilIdle(pid, ${cap1}) must return promptly without hanging (took ${elapsedMs1}ms)`);
        assert.ok(summary1 && typeof summary1 === 'object', 'runUntilIdle must return a ProcessSummary object');
        assert.ok(delta1 >= 1, `runUntilIdle(pid, ${cap1}) must advance target process (delta=${delta1})`);
        assert.ok(
          delta1 <= cap1 * 2,
          `runUntilIdle(pid, ${cap1}) must bound execution strictly by maxTicks (advanced ${delta1} steps, limit ${cap1 * 2})`
        );
        if (typeof summary1.ticksRun === 'number') {
          assert.ok(summary1.ticksRun <= cap1, `summary1.ticksRun must be <= ${cap1} (got ${summary1.ticksRun})`);
        }

        // Larger maxTicks (4x cap1) must advance strictly more steps than cap1 (defeats fixed-tick stubs)
        const cap2 = cap1 * 4;
        const stepsBefore2 = infCtx.steps;
        const summary2 = await sched.runUntilIdle(infPcb.pid, cap2);
        const delta2 = infCtx.steps - stepsBefore2;
        assert.ok(
          delta2 > delta1 && delta2 <= cap2 * 2,
          `runUntilIdle(pid, ${cap2}) must scale with maxTicks (cap1 delta=${delta1}, cap2 delta=${delta2}, max=${cap2 * 2})`
        );
        if (typeof summary2?.ticksRun === 'number') {
          assert.ok(summary2.ticksRun <= cap2, `summary2.ticksRun must be <= ${cap2} (got ${summary2.ticksRun})`);
        }

        const aliveState = String(pm.get(infPcb.pid)?.state ?? '').toUpperCase();
        assert.ok(!['ZOMBIE', 'TERMINATED'].includes(aliveState), `Process hitting maxTicks cap must remain alive (got ${aliveState})`);

        // runUntilIdle on SIGSTOPped process returns promptly without advancing it
        await pm.kill(infPcb.pid, 'SIGSTOP');
        const stoppedSteps = infCtx.steps;
        const tStop = Date.now();
        await sched.runUntilIdle(infPcb.pid, 20);
        assert.ok(Date.now() - tStop < 2000, 'runUntilIdle on STOPPED process must not hang');
        assert.equal(infCtx.steps, stoppedSteps, 'STOPPED process must execute 0 steps during runUntilIdle');

        // runUntilIdle on non-existent PID 999999 returns or rejects promptly
        const tGhost = Date.now();
        let ghostRunErr = null;
        try {
          await sched.runUntilIdle(999999, 20);
        } catch (err) {
          ghostRunErr = err;
        }
        if (ghostRunErr) {
          assert.ok(ghostRunErr instanceof Error && ghostRunErr.message.length > 0);
        }
        assert.ok(Date.now() - tGhost < 2000, 'runUntilIdle(999999) must complete promptly');
      } finally {
        try { pm.kill(infPcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T4 [F-008]: Extreme priority bounds (-20, +19) differentiation & out-of-range priority clamping (-999, +999, NaN)', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const pm = os.require('processManager');
      const sched = os.require('scheduler');
      sched.stop();

      // 1. Extreme valid POSIX nice bounds (-20 vs +19) — infinite maxSteps prevents premature convergence
      const ctxMin = makeScriptedContext({ maxSteps: Number.POSITIVE_INFINITY });
      const ctxMax = makeScriptedContext({ maxSteps: Number.POSITIVE_INFINITY });
      const pMin = pm.spawn({
        name: `prio-min-${nonce}`,
        appId: `com.prio.min.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        priority: -20,
        quotas: { maxTotalInstructions: 10_000_000 },
        executionContext: ctxMin,
      });
      const pMax = pm.spawn({
        name: `prio-max-${nonce}`,
        appId: `com.prio.max.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        priority: 19,
        quotas: { maxTotalInstructions: 10_000_000 },
        executionContext: ctxMax,
      });

      try {
        const prioTicks = Math.max(20, pm.list().length * 3);
        sched.step(prioTicks);
        assert.ok(ctxMin.steps + ctxMax.steps > 0, 'Scheduler must run priority-bound processes');
        assert.ok(
          ctxMin.steps !== ctxMax.steps || ctxMin.totalBudget !== ctxMax.totalBudget,
          `Extreme priorities (-20 vs +19) must differentiate scheduling steps or budget ` +
          `(min: steps=${ctxMin.steps} budget=${ctxMin.totalBudget}; max: steps=${ctxMax.steps} budget=${ctxMax.totalBudget})`
        );
        for (const b of [...ctxMin.observedBudgets, ...ctxMax.observedBudgets]) {
          assert.ok(Number.isFinite(b) && b > 0, `Observed scheduler budget must be finite and > 0 (got ${b})`);
        }
      } finally {
        try { pm.kill(pMin.pid, 'SIGKILL'); } catch { /* ignore */ }
        try { pm.kill(pMax.pid, 'SIGKILL'); } catch { /* ignore */ }
      }

      // 2. Out-of-range priority clamping or structured rejection (-999, +999)
      let pUnder = null;
      let pOver = null;
      let underErr = null;
      let overErr = null;
      const ctxUnder = makeScriptedContext({ maxSteps: 20 });
      const ctxOver = makeScriptedContext({ maxSteps: 20 });

      try {
        pUnder = pm.spawn({
          name: `prio-under-${nonce}`,
          appId: `com.prio.under.${nonce}`,
          platform: 'universal',
          arch: 'wasm',
          priority: -999,
          executionContext: ctxUnder,
        });
      } catch (err) {
        underErr = err;
      }

      try {
        pOver = pm.spawn({
          name: `prio-over-${nonce}`,
          appId: `com.prio.over.${nonce}`,
          platform: 'universal',
          arch: 'wasm',
          priority: 999,
          executionContext: ctxOver,
        });
      } catch (err) {
        overErr = err;
      }

      try {
        if (underErr) {
          assert.ok(underErr instanceof Error && underErr.message.length > 0);
        } else {
          assert.ok(Number.isFinite(pUnder.priority) && pUnder.priority > -999, `priority -999 must be clamped (got ${pUnder.priority})`);
        }
        if (overErr) {
          assert.ok(overErr instanceof Error && overErr.message.length > 0);
        } else {
          assert.ok(Number.isFinite(pOver.priority) && pOver.priority < 999, `priority +999 must be clamped (got ${pOver.priority})`);
        }
        if (pUnder && pOver) {
          assert.ok(pUnder.priority <= pOver.priority, `Clamped -999 (${pUnder.priority}) must be <= clamped +999 (${pOver.priority})`);
          sched.step(Math.max(6, pm.list().length + 2));
          for (const b of [...ctxUnder.observedBudgets, ...ctxOver.observedBudgets]) {
            assert.ok(Number.isFinite(b) && b > 0, `Clamped process budget must be finite and > 0 (got ${b})`);
          }
        }
      } finally {
        if (pUnder) try { pm.kill(pUnder.pid, 'SIGKILL'); } catch { /* ignore */ }
        if (pOver) try { pm.kill(pOver.pid, 'SIGKILL'); } catch { /* ignore */ }
      }

      // 3. NaN priority must be rejected OR normalized to a finite priority (never stored as NaN!)
      let pNaN = null;
      let nanErr = null;
      const ctxNaN = makeScriptedContext({ maxSteps: 10 });
      try {
        pNaN = pm.spawn({
          name: `prio-nan-${nonce}`,
          appId: `com.prio.nan.${nonce}`,
          platform: 'universal',
          arch: 'wasm',
          priority: Number.NaN,
          executionContext: ctxNaN,
        });
      } catch (err) {
        nanErr = err;
      }
      if (nanErr) {
        assert.ok(nanErr instanceof Error && nanErr.message.length > 0);
      }

      if (pNaN) {
        try {
          assert.ok(Number.isFinite(pNaN.priority), `Spawned PCB priority MUST NOT be NaN (got ${pNaN.priority})`);
          sched.step(Math.max(4, pm.list().length + 2));
          for (const b of ctxNaN.observedBudgets) {
            assert.ok(Number.isFinite(b) && b > 0, `Budget for NaN-normalized process must be finite and > 0 (got ${b})`);
          }
        } finally {
          try { pm.kill(pNaN.pid, 'SIGKILL'); } catch { /* ignore */ }
        }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T5 [F-010, F-009, F-035]: writeStdin on closed/terminated/non-existent PID & process FAULT/throw isolation', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const kernel = os.require('kernel');
      const pm = os.require('processManager');
      const sched = os.require('scheduler');
      sched.stop();

      // 1. writeStdin on non-existent PID 999999 must fail cleanly
      let ghostStdinOk = true;
      let ghostStdinErr = null;
      try {
        const r = await pm.writeStdin(999999, `ghost-${nonce}\n`);
        if (r === false || r?.ok === false) ghostStdinOk = false;
      } catch (err) {
        ghostStdinErr = err;
        ghostStdinOk = false;
      }
      if (ghostStdinErr) {
        assert.ok(ghostStdinErr instanceof Error && ghostStdinErr.message.length > 0);
      }
      assert.equal(ghostStdinOk, false, 'writeStdin(999999) MUST throw Error or return false/{ ok: false }');

      // 2. writeStdin succeeds while alive, then rejects after termination
      const ctxExit = makeScriptedContext({ maxSteps: 1, exitCode: 0 });
      const pExit = pm.spawn({
        name: `stdin-exit-${nonce}`,
        appId: `com.stdin.exit.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        executionContext: ctxExit,
      });

      // Non-vacuous check while alive
      await pm.writeStdin(pExit.pid, `alive-${nonce}\n`);
      await sched.runUntilIdle(pExit.pid, 50);
      assert.ok(
        ['ZOMBIE', 'TERMINATED'].includes(String(pm.get(pExit.pid)?.state ?? '').toUpperCase()),
        'pExit must be ZOMBIE or TERMINATED after runUntilIdle'
      );

      let deadStdinOk = true;
      let deadStdinErr = null;
      try {
        const r = await pm.writeStdin(pExit.pid, `after-dead-${nonce}\n`);
        if (r === false || r?.ok === false) deadStdinOk = false;
      } catch (err) {
        deadStdinErr = err;
        deadStdinOk = false;
      }
      if (deadStdinErr) {
        assert.ok(deadStdinErr instanceof Error && deadStdinErr.message.length > 0);
      }
      assert.equal(deadStdinOk, false, 'writeStdin on terminated PID MUST throw Error or return false/{ ok: false }');
      assert.ok(
        !JSON.stringify(ctxExit.events).includes(`after-dead-${nonce}`),
        'Dead process must not receive stdin events after exit'
      );

      // 3. Process FAULT return and synchronous step() throw isolation
      const healthyCtx = makeScriptedContext();
      const healthyPcb = pm.spawn({
        name: `iso-healthy-${nonce}`,
        appId: `com.iso.healthy.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        executionContext: healthyCtx,
      });

      const faultCtx = makeScriptedContext({
        stepBehavior: () => ({
          status: 'FAULT',
          instructionsExecuted: 1,
          fault: { signal: 'SIGILL', code: 'E_ILLEGAL_INSN', message: `fault-${nonce}` },
        }),
      });
      const faultPcb = pm.spawn({
        name: `iso-fault-${nonce}`,
        appId: `com.iso.fault.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        executionContext: faultCtx,
      });

      const throwCtx = makeScriptedContext({
        stepBehavior: () => {
          throw new Error(`vm-boom-${nonce}`);
        },
      });
      const throwPcb = pm.spawn({
        name: `iso-throw-${nonce}`,
        appId: `com.iso.throw.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        executionContext: throwCtx,
      });

      try {
        const isDead = (pid) => {
          const p = pm.get(pid);
          return !p || ['ZOMBIE', 'TERMINATED'].includes(String(p.state ?? '').toUpperCase());
        };

        const faultTicks = Math.max(30, pm.list().length * 3);
        for (let tick = 0; tick < faultTicks && !(isDead(faultPcb.pid) && isDead(throwPcb.pid)); tick++) {
          sched.step(1);
        }

        assert.equal(isDead(faultPcb.pid), true, 'Faulting process must be terminated by scheduler');
        assert.equal(isDead(throwPcb.pid), true, 'Throwing process must be terminated by scheduler');
        assert.equal(faultCtx.disposed, true, 'Faulting process context must be disposed');
        assert.equal(throwCtx.disposed, true, 'Throwing process context must be disposed');

        // Healthy sibling must remain alive and continue executing
        assert.equal(isDead(healthyPcb.pid), false, 'Healthy sibling process must survive sibling faults/throws');
        assert.equal(healthyCtx.disposed, false, 'Healthy sibling must not be disposed');
        const healthyStepsBefore = healthyCtx.steps;
        const probeTicks = Math.max(8, pm.list().length + 4);
        for (let i = 0; i < probeTicks && healthyCtx.steps === healthyStepsBefore; i++) {
          sched.step(1);
        }
        assert.ok(healthyCtx.steps > healthyStepsBefore, 'Healthy sibling must continue executing after sibling faults');
        assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must stay RUNNING after isolated process faults');
      } finally {
        try { pm.kill(healthyPcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T6 [F-006, F-009, F-010, Contracts 7 & 8]: REST /api/v1/processes/* 404/400/4xx negative matrix & CLI kill error handling', async () => {
    let srv = null;
    let launchedPid = null;
    try {
      srv = await startOmniServer();

      // Missing & non-numeric PID lookups
      const resGhost = await srv.api.get('/api/v1/processes/999999');
      assert.equal(resGhost.status, 404, `GET /api/v1/processes/999999 must return 404 (got ${resGhost.status})`);

      const resNaNPid = await srv.api.get('/api/v1/processes/not-a-pid');
      assert.ok(
        resNaNPid.status === 400 || resNaNPid.status === 404,
        `GET /api/v1/processes/not-a-pid must return 400 or 404 (got ${resNaNPid.status})`
      );

      const resGhostSig = await srv.api.post('/api/v1/processes/999999/signal', { signal: 'SIGTERM' });
      assert.equal(resGhostSig.status, 404, `POST /api/v1/processes/999999/signal must return 404 (got ${resGhostSig.status})`);

      const resGhostStdin = await srv.api.post('/api/v1/processes/999999/stdin', { data: 'ghost\n' });
      assert.equal(resGhostStdin.status, 404, `POST /api/v1/processes/999999/stdin must return 404 (got ${resGhostStdin.status})`);

      // Protected PID 0 and PID 1 via REST
      for (const pid of [0, 1]) {
        const resProt = await srv.api.post(`/api/v1/processes/${pid}/signal`, { signal: 'SIGKILL' });
        assert.ok(
          resProt.status >= 400 && resProt.status < 500,
          `POST /api/v1/processes/${pid}/signal SIGKILL must return 4xx (got ${resProt.status})`
        );
      }
      const resPid1 = await srv.api.get('/api/v1/processes/1');
      assert.equal(resPid1.status, 200, 'Protected PID 1 must remain accessible via REST');
      const pid1Obj = resPid1.json?.data ?? resPid1.json?.process ?? resPid1.json;
      assert.equal(pid1Obj?.name, 'omnid', 'PID 1 omnid must remain alive');

      // Dynamically discover a launchable package: /api/v1/packages -> /api/v1/packages/catalog -> install .uapp
      const pkgsRes = await srv.api.get('/api/v1/packages');
      assert.equal(pkgsRes.status, 200, 'GET /api/v1/packages must return 200');
      let pkgs = unwrapListStrict(pkgsRes.json, ['packages', 'systemApps', 'apps', 'items']) ?? [];

      if (pkgs.length === 0) {
        const catRes = await srv.api.get('/api/v1/packages/catalog');
        if (catRes.ok) {
          pkgs = unwrapListStrict(catRes.json, ['packages', 'catalog', 'apps', 'items']) ?? [];
        }
      }

      let targetAppId = null;
      if (pkgs.length > 0) {
        const preferred =
          pkgs.find((p) => /notes|term|files|settings|monitor/i.test(`${p?.name ?? ''} ${p?.title ?? ''} ${p?.appId ?? p?.id ?? ''}`)) ??
          pkgs[0];
        targetAppId = preferred?.appId ?? preferred?.id ?? preferred?.packageName ?? null;
      }

      if (!targetAppId) {
        const dynAppId = `com.e2e.proc.${makeNonce()}`;
        const uappBytes = buildCustomUapp({ appId: dynAppId, name: `ProcTest-${dynAppId}`, message: `hi-${dynAppId}\n` });
        let instRes = await srv.api.post('/api/v1/packages/install', uappBytes, {
          headers: { 'content-type': 'application/octet-stream', 'x-filename': `${dynAppId}.uapp` },
        });
        if (!instRes.ok) {
          instRes = await srv.api.post('/api/v1/packages/install', {
            filename: `${dynAppId}.uapp`,
            buffer: Buffer.from(uappBytes).toString('base64'),
            data: Buffer.from(uappBytes).toString('base64'),
          });
        }
        assert.ok(instRes.ok, `Fallback .uapp install must succeed (got ${instRes.status}: ${instRes.text})`);
        const instData = instRes.json?.data ?? instRes.json;
        targetAppId = instData?.appId ?? instData?.id ?? dynAppId;
      }
      assert.ok(typeof targetAppId === 'string' && targetAppId.length > 0, 'Discovered/installed package must expose an appId');

      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(targetAppId)}/launch`, {});
      assert.ok(launchRes.ok, `Launching app "${targetAppId}" must succeed (got ${launchRes.status}: ${launchRes.text})`);
      const launchData = launchRes.json?.data ?? launchRes.json;
      launchedPid = launchData?.pid ?? launchData?.process?.pid;
      assert.ok(Number.isInteger(launchedPid) && launchedPid > 1, `Launched app must have user PID > 1 (got ${launchedPid})`);

      // Illegal signal, empty string signal (NOT {} which defaults to SIGTERM per Contract 1), and malformed JSON -> HTTP 400
      const resBogusSig = await srv.api.post(`/api/v1/processes/${launchedPid}/signal`, { signal: 'SIGBOGUS' });
      assert.equal(resBogusSig.status, 400, `Illegal signal SIGBOGUS must return 400 (got ${resBogusSig.status})`);

      const resEmptySig = await srv.api.post(`/api/v1/processes/${launchedPid}/signal`, { signal: '' });
      assert.equal(resEmptySig.status, 400, `Empty signal string must return 400 (got ${resEmptySig.status})`);

      const resBadJson = await srv.api.post(`/api/v1/processes/${launchedPid}/signal`, '{broken', {
        headers: { 'content-type': 'application/json' },
      });
      assert.equal(resBadJson.status, 400, `Malformed JSON body must return 400 (got ${resBadJson.status})`);

      // Kill userPid, then confirm POST stdin rejects with 4xx (never 200 or 500)
      const resKill = await srv.api.post(`/api/v1/processes/${launchedPid}/signal`, { signal: 'SIGKILL' });
      assert.equal(resKill.status, 200, `Killing user PID ${launchedPid} must return 200 (got ${resKill.status})`);
      const deadPid = launchedPid;
      launchedPid = null;

      const resDeadStdin = await srv.api.post(`/api/v1/processes/${deadPid}/stdin`, { data: 'dead\n' });
      assert.ok(
        resDeadStdin.status >= 400 && resDeadStdin.status < 500,
        `POST stdin on killed PID must return 4xx (got ${resDeadStdin.status})`
      );

      // Remote CLI negative kill boundaries
      const cliGhost = await srv.runCli(['kill', '999999', '--signal', 'SIGTERM'], { json: true });
      assert.notEqual(cliGhost.code, 0, 'CLI kill 999999 must exit non-zero');

      const cliPid1 = await srv.runCli(['kill', '1', '--signal', 'SIGKILL'], { json: true });
      assert.notEqual(cliPid1.code, 0, 'CLI kill 1 SIGKILL must exit non-zero');
      const resPid1After = await srv.api.get('/api/v1/processes/1');
      assert.equal(resPid1After.status, 200, 'PID 1 must stay alive after CLI kill attempt');

      const health = await srv.api.get('/api/health');
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
      assert.equal(health.json?.os, 'OmniOS');
    } finally {
      if (srv && launchedPid) {
        try { await srv.api.post(`/api/v1/processes/${launchedPid}/signal`, { signal: 'SIGKILL' }); } catch { /* ignore */ }
      }
      await srv?.stop();
    }
  });
});
