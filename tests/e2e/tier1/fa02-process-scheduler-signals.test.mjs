/**
 * Tier 1 E2E Tests — FA-02: Process Lifecycle, Threads, Scheduler, Signals & Streams
 * Features covered: F-006, F-007, F-008, F-009, F-010, F-015
 * Contracts: Contract 1, Contract 5 (ICpuRegistry, IExecutionContext), Contract 7 (REST), Contract 8 (CLI)
 *
 * Strictly opaque-box: interacts ONLY through public OmniOS entrypoints via ../lib/env.mjs.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import {
  createTempDataDir,
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';

function makeNonce() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function unwrapList(payload, keys = ['processes', 'packages', 'items', 'data', 'list']) {
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

function unwrapObject(payload, keys = ['process', 'data', 'result']) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return payload;
  for (const key of keys) {
    if (payload[key] && typeof payload[key] === 'object' && !Array.isArray(payload[key])) {
      return payload[key];
    }
  }
  return payload;
}

function findInTree(node, targetPid) {
  if (!node || typeof node !== 'object') return null;
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = findInTree(item, targetPid);
      if (found) return found;
    }
    return null;
  }
  if (node.pid === targetPid) return node;
  const children = node.children ?? node.subprocesses ?? [];
  if (Array.isArray(children)) {
    for (const child of children) {
      const found = findInTree(child, targetPid);
      if (found) return found;
    }
  }
  return null;
}

function makeScriptedContext({
  maxSteps = 50,
  exitCode = 0,
  stepBehavior = null,
  initialRegs = { r0: 0 },
  initialPc = 0,
} = {}) {
  let steps = 0;
  let totalInsns = 0;
  let totalBudget = 0;
  let disposed = false;
  const events = [];
  const regs = { ...initialRegs };
  let pc = initialPc;

  return {
    get steps() {
      return steps;
    },
    get totalInsns() {
      return totalInsns;
    },
    get totalBudget() {
      return totalBudget;
    },
    get disposed() {
      return disposed;
    },
    events,
    step(budget = 1) {
      steps += 1;
      const numericBudget = Number(budget) || 0;
      totalBudget += numericBudget;
      const insns = Math.max(1, numericBudget || 1);
      totalInsns += insns;
      pc += 4;
      if (stepBehavior) {
        return stepBehavior(steps, insns, numericBudget);
      }
      if (steps >= maxSteps) {
        return { status: 'EXITED', instructionsExecuted: insns, exitCode };
      }
      return { status: 'YIELD', instructionsExecuted: insns };
    },
    deliverEvent(ev) {
      events.push(ev);
    },
    getDebugState() {
      return {
        arch: 'test',
        pc,
        sp: 0x2000,
        registers: { ...regs },
        instructionsExecuted: totalInsns,
        lastSyscall: null,
        stackTop: 0x2000,
      };
    },
    dispose() {
      disposed = true;
    },
  };
}

function getThreadsArray(pcb) {
  const threads = pcb?.threads;
  if (threads instanceof Map) {
    return Array.from(threads.entries()).map(([tid, tcb]) => ({ tid: tcb?.tid ?? tid, ...tcb }));
  }
  if (Array.isArray(threads)) {
    return threads;
  }
  if (threads && typeof threads === 'object') {
    return Object.entries(threads).map(([tid, tcb]) => ({ tid: tcb?.tid ?? tid, ...tcb }));
  }
  return [];
}

function tcbHasCallableStep(tcb) {
  const ctx = tcb?.executionContext ?? tcb?.context ?? tcb?.ctx;
  return Boolean(ctx && typeof ctx.step === 'function');
}

function createAdditionalThread(pm, pcb, opts) {
  const beforeTids = new Set(getThreadsArray(pm.get(pcb.pid)).map((t) => t.tid));
  for (const methodName of ['createThread', 'spawnThread', 'addThread']) {
    if (typeof pm?.[methodName] === 'function') {
      let firstRes;
      try {
        firstRes = pm[methodName](pcb.pid, opts);
      } catch (firstErr) {
        if (opts?.executionContext) {
          return pm[methodName](pcb.pid, opts.executionContext);
        }
        throw firstErr;
      }
      if (opts?.executionContext) {
        const addedTcbs = getThreadsArray(pm.get(pcb.pid)).filter((t) => !beforeTids.has(t.tid));
        const boundCallableStep = tcbHasCallableStep(firstRes) || addedTcbs.some(tcbHasCallableStep);
        if (!boundCallableStep) {
          try {
            return pm[methodName](pcb.pid, opts.executionContext);
          } catch {
            return firstRes;
          }
        }
      }
      return firstRes;
    }
  }
  for (const methodName of ['createThread', 'spawnThread', 'addThread']) {
    if (typeof pcb?.[methodName] === 'function') {
      let firstRes;
      try {
        firstRes = pcb[methodName](opts);
      } catch (firstErr) {
        if (opts?.executionContext) {
          return pcb[methodName](opts.executionContext);
        }
        throw firstErr;
      }
      if (opts?.executionContext) {
        const addedTcbs = getThreadsArray(pm.get(pcb.pid)).filter((t) => !beforeTids.has(t.tid));
        const boundCallableStep = tcbHasCallableStep(firstRes) || addedTcbs.some(tcbHasCallableStep);
        if (!boundCallableStep) {
          try {
            return pcb[methodName](opts.executionContext);
          } catch {
            return firstRes;
          }
        }
      }
      return firstRes;
    }
  }
  const pmMethods = Object.keys(pm ?? {}).filter((k) => typeof pm[k] === 'function');
  const pcbMethods = Object.keys(pcb ?? {}).filter((k) => typeof pcb[k] === 'function');
  throw new Error(
    `ProcessManager/PCB does not expose a thread-creation method (createThread/spawnThread/addThread). ` +
    `pm=[${pmMethods.join(', ')}], pcb=[${pcbMethods.join(', ')}]`
  );
}

function getFdCollection(pcb) {
  const fds = pcb?.fds ?? pcb?.fdTable ?? pcb?.openFds;
  if (fds instanceof Map) return fds;
  if (Array.isArray(fds)) {
    const m = new Map();
    fds.forEach((v, i) => {
      if (v !== null && v !== undefined) m.set(v.fd ?? i, v);
    });
    return m;
  }
  if (fds && typeof fds === 'object') {
    const m = new Map();
    for (const [k, v] of Object.entries(fds)) {
      if (v !== null && v !== undefined) m.set(Number.isNaN(Number(k)) ? k : Number(k), v);
    }
    return m;
  }
  return null;
}

function readStreamText(streamObj) {
  if (typeof streamObj === 'string') return streamObj;
  if (Array.isArray(streamObj)) {
    return streamObj
      .map((item) => (typeof item === 'string' ? item : item?.data ?? item?.text ?? item?.chunk ?? JSON.stringify(item)))
      .join('');
  }
  if (streamObj && typeof streamObj === 'object') {
    if (typeof streamObj.readAll === 'function') return String(streamObj.readAll());
    if (typeof streamObj.read === 'function') return String(streamObj.read() ?? '');
    if (typeof streamObj.toString === 'function' && streamObj.toString !== Object.prototype.toString) {
      return streamObj.toString();
    }
    if (Array.isArray(streamObj.chunks)) return readStreamText(streamObj.chunks);
    if (Array.isArray(streamObj.buffer)) return readStreamText(streamObj.buffer);
    if (typeof streamObj.buffer === 'string') return streamObj.buffer;
    if (typeof streamObj.data === 'string') return streamObj.data;
  }
  return '';
}

function writeProcessStream(pm, pcb, streamName, data) {
  const cap = streamName[0].toUpperCase() + streamName.slice(1);
  if (typeof pm?.[`write${cap}`] === 'function') {
    pm[`write${cap}`](pcb.pid, data);
    return;
  }
  if (typeof pcb?.[`write${cap}`] === 'function') {
    pcb[`write${cap}`](data);
    return;
  }
  const streamObj = pcb?.[streamName] ?? pcb?.streams?.[streamName];
  if (typeof streamObj?.write === 'function') {
    streamObj.write(data);
    return;
  }
  if (typeof streamObj?.push === 'function') {
    streamObj.push(data);
    return;
  }
  throw new Error(`Unable to write to process ${streamName} stream on ProcessManager or PCB`);
}

describe('Tier 1 — FA-02: Process Lifecycle, Threads, Scheduler, Signals & Streams', () => {
  test('T1 [F-006]: PCB FSM transitions, process tree & orphan reparenting to PID 1', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pm = os.require('processManager');
      const sched = os.require('scheduler');
      sched.stop?.();
      const nonce = makeNonce();

      let observedRunningState = null;
      let workerPid = null;
      let blockNow = false;
      const workerCtx = makeScriptedContext({
        stepBehavior(_stepNum, insns) {
          if (workerPid !== null && observedRunningState === null) {
            observedRunningState = pm.get(workerPid)?.state ?? null;
          }
          if (blockNow) {
            return { status: 'BLOCKED', instructionsExecuted: insns, waitReason: 'io' };
          }
          return { status: 'YIELD', instructionsExecuted: insns };
        },
      });

      const worker = pm.spawn({
        name: `fsm-worker-${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        executionContext: workerCtx,
      });
      workerPid = worker.pid;
      assert.ok(worker.pid > 1, `Expected user PID > 1, got ${worker.pid}`);
      assert.ok(
        ['CREATED', 'READY'].includes(worker.state),
        `Expected initial PCB state CREATED or READY, got ${worker.state}`
      );

      for (let i = 0; i < 16 && observedRunningState !== 'RUNNING'; i += 1) {
        sched.step(1);
      }
      assert.equal(observedRunningState, 'RUNNING', 'Process state must be RUNNING while executing step()');

      pm.kill(worker.pid, 'SIGSTOP');
      assert.equal(pm.get(worker.pid).state, 'STOPPED', 'SIGSTOP must transition PCB to STOPPED');

      pm.kill(worker.pid, 'SIGCONT');
      assert.equal(pm.get(worker.pid).state, 'READY', 'SIGCONT must transition PCB back to READY');

      blockNow = true;
      for (let i = 0; i < 16 && pm.get(worker.pid).state !== 'BLOCKED'; i += 1) {
        sched.step(1);
      }
      assert.equal(pm.get(worker.pid).state, 'BLOCKED', 'BLOCKED step result must transition PCB to BLOCKED');

      // Short exiting process -> ZOMBIE/TERMINATED + exitCode + dispose()
      const exitCtx = makeScriptedContext({ maxSteps: 2, exitCode: 42 });
      const pExit = pm.spawn({
        name: `fsm-exit-${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        executionContext: exitCtx,
      });
      await sched.runUntilIdle(pExit.pid, 50);
      const exitedPcb = pm.get(pExit.pid);
      assert.ok(
        ['ZOMBIE', 'TERMINATED'].includes(exitedPcb.state),
        `Expected exited PCB state ZOMBIE or TERMINATED, got ${exitedPcb.state}`
      );
      assert.equal(exitedPcb.exitCode, 42, 'Exited PCB must preserve exitCode === 42');
      assert.equal(exitCtx.disposed, true, 'Exited process executionContext.dispose() must be called');

      // Process tree & orphan reparenting to PID 1
      const parent = pm.spawn({
        name: `parent-${nonce}`,
        ppid: 1,
        parentPid: 1,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        executionContext: makeScriptedContext({ maxSteps: 100 }),
      });
      const child = pm.spawn({
        name: `child-${nonce}`,
        ppid: parent.pid,
        parentPid: parent.pid,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        executionContext: makeScriptedContext({ maxSteps: 100 }),
      });

      const treeBefore = pm.getTree();
      const parentNode = findInTree(treeBefore, parent.pid);
      assert.ok(parentNode, 'processManager.getTree() must include spawned parent process');
      assert.ok(
        findInTree(parentNode, child.pid),
        'processManager.getTree() must nest child process under parent'
      );

      pm.kill(parent.pid, 'SIGKILL');

      const reparentedChild = pm.get(child.pid);
      assert.ok(
        reparentedChild && !['ZOMBIE', 'TERMINATED'].includes(reparentedChild.state),
        'Orphaned child must remain alive after parent terminates'
      );
      assert.equal(
        reparentedChild.ppid ?? reparentedChild.parentPid,
        1,
        'Orphaned child must be reparented to PID 1 (omnid)'
      );

      const treeAfter = pm.getTree();
      const initNode = findInTree(treeAfter, 1);
      assert.ok(initNode, 'processManager.getTree() must contain PID 1');
      assert.ok(
        findInTree(initNode, child.pid),
        'Orphaned child must appear under PID 1 in processManager.getTree()'
      );

      pm.kill(worker.pid, 'SIGKILL');
      pm.kill(child.pid, 'SIGKILL');
    } finally {
      await os.shutdown();
    }
  });

  test('T2 [F-007]: Multi-thread TCBs per process with independent execution contexts & registers', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pm = os.require('processManager');
      const sched = os.require('scheduler');
      sched.stop?.();
      const nonce = makeNonce();

      const ctx1 = makeScriptedContext({ maxSteps: 25, initialRegs: { r0: 0x1111 }, initialPc: 100 });
      const ctx2 = makeScriptedContext({ maxSteps: 25, initialRegs: { r0: 0x2222 }, initialPc: 500 });

      const pcb = pm.spawn({
        name: `mt-proc-${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        executionContext: ctx1,
      });

      const initialThreads = getThreadsArray(pm.get(pcb.pid));
      assert.ok(initialThreads.length >= 1, `Expected >= 1 main thread TCB on spawned PCB, got ${initialThreads.length}`);

      createAdditionalThread(pm, pm.get(pcb.pid), {
        name: `worker-thread-${nonce}`,
        executionContext: ctx2,
      });

      const threads = getThreadsArray(pm.get(pcb.pid));
      assert.ok(threads.length >= 2, `Expected >= 2 TCBs after creating second thread, got ${threads.length}`);
      const tids = new Set(threads.map((t) => t.tid));
      assert.ok(tids.size >= 2, 'Multiple threads in a process must have distinct TIDs');
      assert.notEqual(threads[0], threads[1], 'PCB threads collection must store distinct TCB records');
      for (const tcb of threads) {
        assert.ok(
          typeof (tcb.state ?? tcb.status) === 'string' && String(tcb.state ?? tcb.status).length > 0,
          `Each TCB must track its own thread state (got ${JSON.stringify(tcb)})`
        );
      }
      const attachedContexts = threads
        .map((t) => t.executionContext ?? t.context ?? t.ctx)
        .filter((c) => c && typeof c.step === 'function');
      if (attachedContexts.length >= 2) {
        assert.notEqual(attachedContexts[0], attachedContexts[1], 'TCBs must reference distinct execution contexts');
        const attachedSet = new Set(attachedContexts);
        assert.ok(
          attachedSet.has(ctx1) && attachedSet.has(ctx2),
          'PCB TCBs must bind both main and secondary execution contexts independently'
        );
      }

      const readyCountMt = Math.max(2, pm.list().filter((p) => p.state === 'READY').length);
      for (let i = 0; i < Math.max(64, readyCountMt * 16) && (ctx1.steps === 0 || ctx2.steps === 0); i += 1) {
        sched.step(1);
      }
      assert.ok(ctx1.steps > 0, `Expected thread 1 to execute steps (got ${ctx1.steps})`);
      assert.ok(ctx2.steps > 0, `Expected thread 2 to execute steps (got ${ctx2.steps})`);

      const postThreads = getThreadsArray(pm.get(pcb.pid));
      assert.ok(postThreads.length >= 2, 'Both TCBs must remain tracked on PCB during active execution');
      const tcbDebugStates = postThreads
        .map((t) => (t.executionContext ?? t.context ?? t.ctx)?.getDebugState?.() ?? t.debugState ?? null)
        .filter(Boolean);
      if (tcbDebugStates.length >= 2) {
        const r0Vals = new Set(tcbDebugStates.map((d) => d.registers?.r0));
        assert.ok(r0Vals.has(0x1111) && r0Vals.has(0x2222), 'TCB debug states must reflect independent thread registers');
        assert.notEqual(tcbDebugStates[0].pc, tcbDebugStates[1].pc, 'TCB debug states must reflect distinct PC values');
      }

      pm.kill(pcb.pid, 'SIGKILL');
      assert.ok(['ZOMBIE', 'TERMINATED'].includes(pm.get(pcb.pid).state), 'SIGKILL must terminate multi-threaded process');
      assert.equal(ctx1.disposed, true, 'Main thread context must be disposed on process exit');
      assert.equal(ctx2.disposed, true, 'Secondary thread context must be disposed on process exit');
    } finally {
      await os.shutdown();
    }
  });

  test('T3 [F-008]: Cooperative step()/runUntilIdle(), priority round-robin & background preemptive ticks', async () => {
    const os = await loadPublicOmniOS();
    let sched = null;
    try {
      sched = os.require('scheduler');
      const pm = os.require('processManager');
      sched.stop?.();
      const nonce = makeNonce();

      // 1. Equal-priority round-robin fairness
      const baseReadyEq = pm.list().filter((p) => p.state === 'READY').length;
      const eqStepBudget = Math.max(6, Math.max(2, baseReadyEq + 2) * 2);
      const eqMaxSteps = Math.max(32, eqStepBudget + 16);
      const eq1Ctx = makeScriptedContext({ maxSteps: eqMaxSteps, exitCode: 0 });
      const eq2Ctx = makeScriptedContext({ maxSteps: eqMaxSteps, exitCode: 0 });
      const eq1 = pm.spawn({ name: `rr1-${nonce}`, platform: 'universal', arch: 'wasm', priority: 5, executionContext: eq1Ctx });
      const eq2 = pm.spawn({ name: `rr2-${nonce}`, platform: 'universal', arch: 'wasm', priority: 5, executionContext: eq2Ctx });

      const readyCount = Math.max(2, pm.list().filter((p) => p.state === 'READY').length);
      const stepRes = sched.step(Math.max(6, readyCount * 2));
      assert.ok(stepRes && typeof stepRes === 'object', 'scheduler.step() must return a summary object');
      assert.ok(typeof stepRes.ticksRun === 'number' && stepRes.ticksRun >= 1, 'ticksRun must be >= 1');
      assert.ok(typeof stepRes.instructionsExecuted === 'number' && stepRes.instructionsExecuted > 0, 'instructionsExecuted must be > 0');
      assert.ok(Array.isArray(stepRes.activePids), 'step() must return activePids array');
      for (let i = 0; i < Math.max(64, readyCount * 16) && (eq1Ctx.steps === 0 || eq2Ctx.steps === 0); i += 1) {
        sched.step(1);
      }
      assert.ok(eq1Ctx.steps > 0 && eq2Ctx.steps > 0, `Round-robin must advance both equal-priority processes (eq1=${eq1Ctx.steps}, eq2=${eq2Ctx.steps})`);

      const eqIdleLimit = Math.max(600, eqMaxSteps * readyCount * 12);
      await sched.runUntilIdle(eq1.pid, eqIdleLimit);
      await sched.runUntilIdle(eq2.pid, eqIdleLimit);
      assert.equal(eq1Ctx.steps, eqMaxSteps);
      assert.equal(eq2Ctx.steps, eqMaxSteps);

      // 2. Priority-weighted differentiation (supports both frequency-weighted & budget-weighted RR)
      const prioMaxSteps = 200;
      const highCtx = makeScriptedContext({ maxSteps: prioMaxSteps, exitCode: 0 });
      const lowCtx = makeScriptedContext({ maxSteps: prioMaxSteps, exitCode: 0 });
      const pHigh = pm.spawn({ name: `prio-a-${nonce}`, platform: 'universal', arch: 'wasm', priority: 10, executionContext: highCtx });
      const pLow = pm.spawn({ name: `prio-b-${nonce}`, platform: 'universal', arch: 'wasm', priority: 1, executionContext: lowCtx });

      const readyCountPrio = Math.max(2, pm.list().filter((p) => p.state === 'READY').length);
      sched.step(Math.max(12, readyCountPrio * 3));
      // If core daemons ahead in a weighted queue consumed the first cycle, step in exact
      // readyCountPrio multiples until priority 10 vs 1 can differentiate (keeps flat RR symmetric).
      for (
        let round = 0;
        round < 16 &&
        highCtx.steps < 2 &&
        highCtx.steps === lowCtx.steps &&
        highCtx.totalBudget === lowCtx.totalBudget;
        round += 1
      ) {
        sched.step(readyCountPrio);
      }
      assert.ok(highCtx.steps + lowCtx.steps > 0, 'Priority-weighted step() must execute runnable processes');
      assert.ok(
        highCtx.steps !== lowCtx.steps || highCtx.totalBudget !== lowCtx.totalBudget,
        `Priority-weighted scheduler must differentiate priority 10 vs priority 1 by step count or quantum budget ` +
          `(steps: ${highCtx.steps} vs ${lowCtx.steps}, totalBudget: ${highCtx.totalBudget} vs ${lowCtx.totalBudget})`
      );

      const prioIdleLimit = Math.max(4000, prioMaxSteps * readyCountPrio * 20);
      await sched.runUntilIdle(pHigh.pid, prioIdleLimit);
      await sched.runUntilIdle(pLow.pid, prioIdleLimit);
      assert.equal(pm.get(pHigh.pid).exitCode, 0);
      assert.equal(pm.get(pLow.pid).exitCode, 0);

      // 3. Background preemptive ticks
      const bgCtx = makeScriptedContext({ maxSteps: 3, exitCode: 7 });
      const bgProc = pm.spawn({ name: `bg-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: bgCtx });

      sched.start(10);
      try {
        const deadline = Date.now() + 2500;
        while (Date.now() < deadline) {
          if (['ZOMBIE', 'TERMINATED'].includes(pm.get(bgProc.pid)?.state)) break;
          await sleep(15);
        }
      } finally {
        sched.stop();
      }

      assert.ok(
        ['ZOMBIE', 'TERMINATED'].includes(pm.get(bgProc.pid).state),
        `Background scheduler ticks must run process to exit, got state=${pm.get(bgProc.pid).state}`
      );
      assert.equal(bgCtx.steps, 3);
      assert.equal(pm.get(bgProc.pid).exitCode, 7);
    } finally {
      sched?.stop?.();
      await os.shutdown();
    }
  });

  test('T4 [F-009]: POSIX signals (SIGSTOP/SIGCONT/SIGUSR1/SIGINT/SIGTERM/SIGKILL) via Public API, REST & CLI', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pm = os.require('processManager');
      const sched = os.require('scheduler');
      sched.stop?.();
      const nonce = makeNonce();

      const ctx1 = makeScriptedContext({ maxSteps: 100 });
      const p1 = pm.spawn({ name: `sig-stop-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: ctx1 });

      const stopRes = pm.kill(p1.pid, 'SIGSTOP');
      assert.equal(stopRes?.ok, true, 'SIGSTOP must return ok: true');
      assert.equal(pm.get(p1.pid).state, 'STOPPED');
      const stepsWhileStopped = ctx1.steps;
      const readyWhileStopped = Math.max(2, pm.list().filter((p) => p.state === 'READY').length);
      sched.step(Math.max(4, readyWhileStopped + 2));
      assert.equal(ctx1.steps, stepsWhileStopped, 'STOPPED process must not advance during scheduler ticks');

      const contRes = pm.kill(p1.pid, 'SIGCONT');
      assert.equal(contRes?.ok, true, 'SIGCONT must return ok: true');
      assert.equal(pm.get(p1.pid).state, 'READY');
      const readyCount = Math.max(2, pm.list().filter((p) => p.state === 'READY').length);
      for (let i = 0; i < Math.max(64, readyCount * 16) && ctx1.steps === stepsWhileStopped; i += 1) {
        sched.step(1);
      }
      assert.ok(ctx1.steps > stepsWhileStopped, 'SIGCONT must allow process to resume stepping');

      const usr1Res = pm.kill(p1.pid, 'SIGUSR1');
      assert.equal(usr1Res?.ok, true, 'SIGUSR1 must be acknowledged with ok: true');
      pm.kill(p1.pid, 'SIGTERM');

      const ctxInt = makeScriptedContext({ maxSteps: 100 });
      const pInt = pm.spawn({ name: `sig-int-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: ctxInt });
      assert.equal(pm.kill(pInt.pid, 'SIGINT')?.ok, true);
      assert.ok(['ZOMBIE', 'TERMINATED'].includes(pm.get(pInt.pid).state), 'SIGINT must terminate process');

      const ctxTerm = makeScriptedContext({ maxSteps: 100 });
      const pTerm = pm.spawn({ name: `sig-term-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: ctxTerm });
      assert.equal(pm.kill(pTerm.pid, 'SIGTERM')?.ok, true);
      assert.ok(['ZOMBIE', 'TERMINATED'].includes(pm.get(pTerm.pid).state), 'SIGTERM must terminate process');
      assert.equal(ctxTerm.disposed, true, 'SIGTERM must dispose executionContext');

      const ctxKill = makeScriptedContext({ maxSteps: 100 });
      const pKill = pm.spawn({ name: `sig-kill-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: ctxKill });
      pm.kill(pKill.pid, 'SIGSTOP');
      assert.equal(pm.kill(pKill.pid, 'SIGKILL')?.ok, true);
      assert.ok(['ZOMBIE', 'TERMINATED'].includes(pm.get(pKill.pid).state), 'SIGKILL must terminate even a STOPPED process');
      assert.equal(ctxKill.disposed, true, 'SIGKILL must dispose executionContext');
    } finally {
      await os.shutdown();
    }

    // Live REST & CLI process listing + signal delivery on a real launched user app
    const srv = await startOmniServer();
    try {
      const listRes = await srv.api.get('/api/v1/processes');
      assert.equal(listRes.status, 200);
      const procs = unwrapList(listRes.json);
      assert.ok(procs.some((p) => p.pid === 0), 'GET /api/v1/processes must include PID 0');
      assert.ok(procs.some((p) => p.pid === 1), 'GET /api/v1/processes must include PID 1');

      const treeRes = await srv.api.get('/api/v1/processes/tree');
      assert.equal(treeRes.status, 200);
      const tree = unwrapObject(treeRes.json, ['tree', 'root', 'data']);
      assert.ok(findInTree(tree, 1), 'GET /api/v1/processes/tree must contain PID 1');

      const p1Res = await srv.api.get('/api/v1/processes/1');
      assert.equal(p1Res.status, 200);
      const p1Obj = unwrapObject(p1Res.json);
      assert.equal(p1Obj?.pid, 1);
      assert.equal(p1Obj?.name, 'omnid');

      const psCli = await srv.runCli(['ps'], { json: true, expectZero: true });
      const psList = unwrapList(psCli.json);
      assert.ok(psList.some((p) => p.pid === 1 && p.name === 'omnid'), 'Remote CLI "ps --json" must list PID 1 omnid');

      // Launch a built-in system app to obtain a live user PID (> 1)
      const pkgRes = await srv.api.get('/api/v1/packages');
      assert.equal(pkgRes.status, 200);
      const pkgs = unwrapList(pkgRes.json);
      const targetPkg =
        pkgs.find((p) => (p.appId ?? p.id) === 'sys.notes') ??
        pkgs.find((p) => (p.appId ?? p.id) === 'sys.terminal') ??
        pkgs[0];
      assert.ok(targetPkg, 'Expected at least one installed built-in app in /api/v1/packages');
      const targetAppId = targetPkg.appId ?? targetPkg.id;

      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(targetAppId)}/launch`, {});
      assert.ok(launchRes.ok, `Launching ${targetAppId} failed with ${launchRes.status}: ${launchRes.text}`);
      const launched = unwrapObject(launchRes.json, ['launch', 'process', 'data']);
      const userPid = launched?.pid;
      assert.ok(typeof userPid === 'number' && userPid > 1, `Expected launched user PID > 1, got ${userPid}`);

      const sigStop = await srv.api.post(`/api/v1/processes/${userPid}/signal`, { signal: 'SIGSTOP' });
      assert.ok(sigStop.ok, `POST /api/v1/processes/${userPid}/signal SIGSTOP failed: ${sigStop.text}`);
      const stoppedView = unwrapObject((await srv.api.get(`/api/v1/processes/${userPid}`)).json);
      assert.equal(stoppedView?.state, 'STOPPED', 'REST SIGSTOP must update process state to STOPPED');

      const sigCont = await srv.api.post(`/api/v1/processes/${userPid}/signal`, { signal: 'SIGCONT' });
      assert.ok(sigCont.ok, `POST /api/v1/processes/${userPid}/signal SIGCONT failed: ${sigCont.text}`);
      const resumedView = unwrapObject((await srv.api.get(`/api/v1/processes/${userPid}`)).json);
      assert.notEqual(resumedView?.state, 'STOPPED', 'REST SIGCONT must resume process out of STOPPED');

      await srv.runCli(['kill', String(userPid), '--signal', 'SIGTERM'], { json: true, expectZero: true });
      const afterKill = await srv.api.get(`/api/v1/processes/${userPid}`);
      if (afterKill.status === 200) {
        const afterObj = unwrapObject(afterKill.json);
        assert.ok(
          ['ZOMBIE', 'TERMINATED'].includes(afterObj?.state),
          `Expected process ${userPid} terminated after CLI kill, got state=${afterObj?.state}`
        );
      } else {
        assert.equal(afterKill.status, 404, 'Reaped process may return 404 after termination');
      }
    } finally {
      await srv.stop();
    }
  });

  test('T5 [F-010]: Per-PID stdin/stdout/stderr streams, live process:stdout events & FD cleanup on exit', async () => {
    const os = await loadPublicOmniOS();
    const bus =
      os.raw.eventBus ??
      os.kernel?.eventBus ??
      os.raw.events ??
      os.kernel?.events ??
      os.raw.bus ??
      os.kernel?.bus;
    let unsub = null;
    try {
      const pm = os.require('processManager');
      const vfs = os.require('vfs');
      os.require('scheduler').stop?.();
      const nonce = makeNonce();

      assert.ok(bus && typeof bus === 'object', 'Public OmniOS runtime must expose KernelEventBus for live process:stdout events');
      const stdoutEvents = [];
      const handler = (ev) => stdoutEvents.push(ev);
      if (typeof bus.on === 'function') {
        const maybeUnsub = bus.on('process:stdout', handler);
        unsub = typeof maybeUnsub === 'function' ? maybeUnsub : () => bus.off?.('process:stdout', handler);
      } else if (typeof bus.subscribe === 'function') {
        unsub = bus.subscribe('process:stdout', handler);
      } else {
        throw new Error('KernelEventBus must expose on() or subscribe()');
      }

      const ctx = makeScriptedContext({ maxSteps: 100 });
      const pcb = pm.spawn({
        name: `stdio-${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        executionContext: ctx,
      });

      const initialFds = getFdCollection(pm.get(pcb.pid));
      assert.ok(initialFds, 'PCB must expose an open FD table');
      assert.ok(initialFds.has(0) && initialFds.has(1) && initialFds.has(2), 'PCB FD table must pre-open standard FDs 0, 1, 2');

      const tmpPath = `/tmp/fd-${nonce}.txt`;
      const opened = await vfs.open(tmpPath, 'w', { pid: pcb.pid, uid: 1000, gid: 1000 });
      assert.ok(opened !== null && opened !== undefined, 'vfs.open() must return a valid FD or handle');
      const openedFdNum = typeof opened === 'number' ? opened : opened.fd ?? opened.id;
      if (typeof openedFdNum === 'number') {
        assert.ok(openedFdNum >= 3, `Expected newly opened file descriptor >= 3, got ${openedFdNum}`);
      }

      const stdinText = `stdin-${nonce}\n`;
      pm.writeStdin(pcb.pid, stdinText);
      const currentPcb = pm.get(pcb.pid);
      const stdinCaptured =
        readStreamText(currentPcb.stdin ?? currentPcb.streams?.stdin).includes(`stdin-${nonce}`) ||
        JSON.stringify(ctx.events).includes(`stdin-${nonce}`);
      assert.ok(stdinCaptured, 'processManager.writeStdin() must deliver input to process stdin buffer or executionContext');

      const outText = `stdout-${nonce}\n`;
      const errText = `stderr-${nonce}\n`;
      writeProcessStream(pm, currentPcb, 'stdout', outText);
      writeProcessStream(pm, currentPcb, 'stderr', errText);

      const postIoPcb = pm.get(pcb.pid);
      assert.ok(
        readStreamText(postIoPcb.stdout ?? postIoPcb.streams?.stdout).includes(`stdout-${nonce}`),
        'Process stdout ring buffer must retain written stdout data'
      );
      assert.ok(
        readStreamText(postIoPcb.stderr ?? postIoPcb.streams?.stderr).includes(`stderr-${nonce}`),
        'Process stderr ring buffer must retain written stderr data'
      );
      assert.ok(
        stdoutEvents.some((ev) => JSON.stringify(ev).includes(`stdout-${nonce}`)),
        'Writing process stdout must emit a live process:stdout event on the KernelEventBus'
      );

      pm.kill(pcb.pid, 'SIGTERM');
      const afterExitFds = getFdCollection(pm.get(pcb.pid));
      if (afterExitFds) {
        const openRemaining = Array.from(afterExitFds.values()).filter(
          (entry) => entry && entry.closed !== true && entry.open !== false
        );
        assert.equal(openRemaining.length, 0, 'All open FDs must be closed upon process termination');
      }
    } finally {
      if (typeof unsub === 'function') unsub();
      await os.shutdown();
    }
  });

  test('T6 [F-015]: CpuRegistry, EventBus, SyscallDispatcher & WAL SQLite disk persistence across reopen', async () => {
    const temp = await createTempDataDir('omnios-fa02-wal-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      os1 = await loadPublicOmniOS({ dataDir: temp.dir });

      // 1. CpuRegistry contract
      const cpuRegistry = os1.require('cpuRegistry');
      assert.equal(typeof cpuRegistry.register, 'function', 'cpuRegistry.register must be a function');
      assert.equal(typeof cpuRegistry.get, 'function', 'cpuRegistry.get must be a function');

      const customArch = `custom_arch_${nonce}`;
      const customFactory = () => ({ arch: customArch });
      cpuRegistry.register(customArch, customFactory);
      assert.equal(cpuRegistry.get(customArch), customFactory, 'cpuRegistry.get() must return registered CpuFactory');
      assert.equal(cpuRegistry.get(`missing_${nonce}`) ?? null, null, 'Unknown arch must return null/undefined');

      const standardFound = ['dalvik', 'x86_64', 'x86', 'arm64', 'wasm'].some(
        (arch) => typeof cpuRegistry.get(arch) === 'function' || Boolean(cpuRegistry.get(arch))
      );
      assert.ok(standardFound, 'Full OmniOS runtime must register at least one standard CPU architecture');

      // 2. EventBus contract
      const bus =
        os1.raw.eventBus ??
        os1.kernel?.eventBus ??
        os1.raw.events ??
        os1.kernel?.events ??
        os1.raw.bus ??
        os1.kernel?.bus;
      assert.ok(bus && typeof bus === 'object', 'Public OmniOS runtime must expose KernelEventBus');
      const topic = `e2e:ping:${nonce}`;
      const received = [];
      const listener = (payload) => received.push(payload);
      let unsub;
      if (typeof bus.on === 'function') {
        const ret = bus.on(topic, listener);
        unsub = typeof ret === 'function' ? ret : () => bus.off?.(topic, listener);
      } else if (typeof bus.subscribe === 'function') {
        unsub = bus.subscribe(topic, listener);
      } else {
        throw new Error('EventBus missing on()/subscribe() method');
      }
      bus.emit(topic, { nonce });
      assert.equal(received.length, 1, 'EventBus listener must receive emitted event');
      assert.ok(JSON.stringify(received[0]).includes(nonce), 'EventBus payload must carry nonce');
      unsub?.();
      bus.emit(topic, { nonce: 'second' });
      assert.equal(received.length, 1, 'Unsubscribed EventBus listener must not fire again');

      // 3. Optional SyscallDispatcher contract check (signature-agnostic if exposed on public runtime)
      const syscalls =
        os1.raw.syscalls ??
        os1.raw.syscallDispatcher ??
        os1.kernel?.syscalls ??
        os1.kernel?.syscallDispatcher ??
        null;
      if (syscalls && typeof syscalls === 'object') {
        const dispatchFn = syscalls.dispatch ?? syscalls.call ?? syscalls.invoke;
        assert.equal(typeof dispatchFn, 'function', 'Exposed SyscallDispatcher must provide dispatch/call/invoke');
        if (typeof syscalls.register === 'function') {
          const scName = `e2e.echo.${nonce}`;
          let invoked = false;
          syscalls.register(scName, (...cbArgs) => {
            invoked = true;
            return { ok: true, echo: nonce, argCount: cbArgs.length };
          });
          const symPayload = { pid: 1, uid: 0, nonce };
          let scRes;
          try {
            scRes = await dispatchFn.call(syscalls, scName, symPayload, symPayload);
          } catch {
            // Fall through to alternate (ctx, name, args) signature below
          }
          if (!invoked) {
            scRes = await dispatchFn.call(syscalls, symPayload, scName, symPayload);
          }
          assert.equal(invoked, true, 'Registered custom syscall handler must be invoked by SyscallDispatcher');
          assert.ok(
            JSON.stringify(scRes).includes(nonce),
            `Custom syscall dispatch must return handler output containing nonce, got ${JSON.stringify(scRes)}`
          );
        }
      }

      // 4. WAL SQLite disk persistence across shutdown & reopen
      const walFile = `/home/user/Documents/wal-${nonce}.txt`;
      const walContent = `wal-data-${nonce}`;
      await os1.require('vfs').writeFile(walFile, walContent);
      await os1.require('configStore').system.set('system.locale', 'ja-JP');

      const entriesOnDisk = await fs.readdir(temp.dir, { recursive: true });
      const hasSqliteDb = entriesOnDisk.some((name) => /\.(db|sqlite|sqlite3)$/i.test(String(name)));
      assert.ok(
        hasSqliteDb,
        `Expected SQLite database file under dataDir "${temp.dir}", found: ${JSON.stringify(entriesOnDisk)}`
      );

      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      assert.equal(
        await os2.require('vfs').readFile(walFile, { encoding: 'utf8' }),
        walContent,
        'VFS file must persist in SQLite across reboot'
      );
      assert.equal(
        await os2.require('configStore').system.get('system.locale'),
        'ja-JP',
        'Config Store system.locale must persist in SQLite across reboot'
      );
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });
});
