/**
 * OmniOS Preemptive / Cooperative Priority Round-Robin Scheduler (`F-008`, `F-011`)
 * Features:
 *  - Priority-weighted fair round-robin (no starvation of nice +19, equal priorities rotate)
 *  - Both `.unref()` real background timer ticks (`start`/`stop`/`isRunning`) AND deterministic `step`/`runUntilIdle`
 *  - Complete process isolation: FAULT, thrown exceptions, and runaway quota overruns (SIGXCPU / 152)
 *    terminate ONLY the offending PID without affecting sibling processes or the kernel
 *  - Strict halt enforcement when kernel enters PANIC or STOPPED
 */

import { types } from 'node:util';
import {
  MemoryFaultError,
  IllegalInstructionError,
  QuotaExceededError,
  ProcessError,
  ERROR_CODES,
  SIGNALS,
} from '../common/errors.mjs';
import { PROCESS_STATES, THREAD_STATES } from './process.mjs';

export const DEFAULT_BASE_QUANTUM = 4096;
export const DEFAULT_TICK_MS = 16;
export const SCHEDULABLE_KERNEL_STATES = Object.freeze(new Set(['RUNNING', 'SAFE_MODE']));

export function clampPriority(priority = 0) {
  const n = Number.isFinite(priority) ? Math.trunc(priority) : 0;
  return Math.max(-20, Math.min(19, n));
}

export function priorityWeight(priority = 0) {
  // Exponential nice curve centered at 0 -> 1.0x (-20 -> 4.0x, -10 -> 2.0x, +10 -> 0.5x, +19 -> 0.268x)
  return Math.pow(2, -clampPriority(priority) / 10);
}

function safeReadProp(obj, prop, fallback = undefined) {
  try {
    return obj == null ? fallback : obj[prop];
  } catch {
    return fallback;
  }
}

function safeErrorString(val, fallback = 'Execution fault') {
  try {
    return String(val);
  } catch {
    return fallback;
  }
}

function safeInstanceOf(obj, Ctor) {
  try {
    return obj instanceof Ctor;
  } catch {
    return false;
  }
}

export function classifyFault(fault) {
  const sigProp = safeReadProp(fault, 'signal', undefined);
  if (typeof sigProp === 'string') {
    const upper = sigProp.toUpperCase();
    if (Object.prototype.hasOwnProperty.call(SIGNALS, upper)) {
      const signum = SIGNALS[upper];
      return { signal: upper, signum, exitCode: 128 + signum };
    }
  }
  if (safeInstanceOf(fault, MemoryFaultError)) {
    return { signal: 'SIGSEGV', signum: SIGNALS.SIGSEGV, exitCode: 128 + SIGNALS.SIGSEGV };
  }
  if (safeInstanceOf(fault, IllegalInstructionError)) {
    return { signal: 'SIGILL', signum: SIGNALS.SIGILL, exitCode: 128 + SIGNALS.SIGILL };
  }
  if (safeInstanceOf(fault, QuotaExceededError)) {
    return { signal: 'SIGXCPU', signum: SIGNALS.SIGXCPU, exitCode: 128 + SIGNALS.SIGXCPU };
  }

  const rawCode = safeReadProp(fault, 'code', undefined);
  const rawName = safeReadProp(fault, 'name', undefined);
  const rawMsg = safeReadProp(fault, 'message', undefined);
  const code = safeErrorString(rawCode ?? rawName ?? '', '').toUpperCase();
  const msg = safeErrorString(rawMsg ?? fault ?? '', '');

  if (
    code === 'E_MEMORY_FAULT' ||
    code === 'SIGSEGV' ||
    code === 'ENOMEM' ||
    code === 'EFAULT' ||
    /segv|unmapped|nx_exec|write_violation|read_violation|guard|page_fault/i.test(`${code} ${msg}`)
  ) {
    return { signal: 'SIGSEGV', signum: SIGNALS.SIGSEGV, exitCode: 128 + SIGNALS.SIGSEGV };
  }
  if (
    code === 'E_ILLEGAL_INSTRUCTION' ||
    code === 'E_UNSUPPORTED_OPCODE' ||
    code === 'SIGILL' ||
    /illegal|opcode|sigill/i.test(`${code} ${msg}`)
  ) {
    return { signal: 'SIGILL', signum: SIGNALS.SIGILL, exitCode: 128 + SIGNALS.SIGILL };
  }
  if (
    code === 'E_QUOTA_EXCEEDED' ||
    code === 'E_CPU_QUOTA' ||
    code === 'SIGXCPU' ||
    /quota|xcpu|budget|instruction/i.test(`${code} ${msg}`)
  ) {
    return { signal: 'SIGXCPU', signum: SIGNALS.SIGXCPU, exitCode: 128 + SIGNALS.SIGXCPU };
  }

  return { signal: 'SIGSEGV', signum: SIGNALS.SIGSEGV, exitCode: 128 + SIGNALS.SIGSEGV };
}

export class Scheduler {
  constructor({
    processManager,
    eventBus = null,
    getKernelState = () => 'RUNNING',
    log = () => {},
    baseQuantum = DEFAULT_BASE_QUANTUM,
    defaultTickMs = DEFAULT_TICK_MS,
  } = {}) {
    if (!processManager) {
      throw new ProcessError('Scheduler requires a processManager instance', {
        code: ERROR_CODES.EINVAL,
      });
    }
    this.processManager = processManager;
    this._eventBus = eventBus;
    this.getKernelState = typeof getKernelState === 'function' ? getKernelState : () => 'RUNNING';
    this._log = typeof log === 'function' ? log : () => {};
    this.baseQuantum =
      typeof baseQuantum === 'number' && Number.isFinite(baseQuantum) && baseQuantum >= 1
        ? Math.floor(baseQuantum)
        : DEFAULT_BASE_QUANTUM;
    this.defaultTickMs =
      typeof defaultTickMs === 'number' && Number.isFinite(defaultTickMs) && defaultTickMs > 0
        ? defaultTickMs
        : DEFAULT_TICK_MS;

    this._timer = null;
    this._tickMs = this.defaultTickMs;
    this._running = false;
    this._stepping = false;
    this._tickIndex = 0;
    this._totalTicks = 0;
    this._totalInstructions = 0;
  }

  isRunning() {
    return Boolean(this._running);
  }

  start(tickMs = this.defaultTickMs) {
    if (!SCHEDULABLE_KERNEL_STATES.has(this.getKernelState())) {
      return false;
    }
    if (typeof tickMs !== 'number' || !Number.isFinite(tickMs) || tickMs <= 0) {
      throw new ProcessError(`Invalid scheduler tickMs: ${tickMs}`, { code: ERROR_CODES.EINVAL });
    }
    if (this._running && this._tickMs === tickMs) {
      return true;
    }
    if (this._running) {
      this.stop();
    }

    this._tickMs = tickMs;
    this._running = true;
    this._timer = setInterval(() => this._onTimerTick(), tickMs);
    if (typeof this._timer.unref === 'function') {
      this._timer.unref();
    }
    this._eventBus?.emit('scheduler:started', { tickMs });
    return true;
  }

  stop() {
    if (this._timer !== null) {
      clearInterval(this._timer);
      this._timer = null;
    }
    if (this._running) {
      this._running = false;
      this._eventBus?.emit('scheduler:stopped', {});
    }
  }

  _onTimerTick() {
    if (!this._running || this._stepping) return;
    if (!SCHEDULABLE_KERNEL_STATES.has(this.getKernelState())) {
      this.stop();
      return;
    }
    this._stepping = true;
    try {
      this.step(1);
    } catch {
      // Never allow background tick errors to escape to host event loop.
    } finally {
      this._stepping = false;
    }
  }

  computeQuantum(pcb, tcb = null) {
    const effPriority = tcb?.priority ?? pcb.priority;
    const rawQuantum = Math.max(1, Math.round(this.baseQuantum * priorityWeight(effPriority)));
    const maxPerTick =
      Number.isFinite(pcb.quotas?.maxInstructionsPerTick) && pcb.quotas.maxInstructionsPerTick > 0
        ? Math.floor(pcb.quotas.maxInstructionsPerTick)
        : Infinity;
    const maxTotal =
      Number.isFinite(pcb.quotas?.maxTotalInstructions) && pcb.quotas.maxTotalInstructions > 0
        ? Math.floor(pcb.quotas.maxTotalInstructions)
        : Infinity;
    const alreadyExecuted = pcb.stats?.instructionsExecuted ?? 0;
    const remainingTotal = maxTotal === Infinity ? Infinity : Math.max(0, maxTotal - alreadyExecuted);

    if (maxTotal !== Infinity && remainingTotal <= 0) {
      return { budget: 0, quotaExhausted: true, maxPerTick, maxTotal, remainingTotal: 0 };
    }
    const budget = Math.max(1, Math.min(rawQuantum, maxPerTick, remainingTotal));
    return { budget, quotaExhausted: false, maxPerTick, maxTotal, remainingTotal };
  }

  _collectRunnableThreads() {
    const buckets = new Map();
    const pcbs = this.processManager.getAll();

    for (const pcb of pcbs) {
      if (pcb.state !== PROCESS_STATES.READY && pcb.state !== PROCESS_STATES.RUNNING) continue;
      for (const tcb of pcb.threads.values()) {
        if (tcb.state !== THREAD_STATES.READY) continue;
        const execCtx =
          tcb.executionContext ?? (tcb.tid === pcb.mainTid ? pcb.executionContext : null);
        if (!execCtx || typeof safeReadProp(execCtx, 'step', null) !== 'function') continue;

        const prio = clampPriority(tcb?.priority ?? pcb.priority);
        let list = buckets.get(prio);
        if (!list) {
          list = [];
          buckets.set(prio, list);
        }
        list.push({ pcb, tcb, execCtx });
      }
    }

    const sortedPrios = Array.from(buckets.keys()).sort((a, b) => a - b);
    const ordered = [];
    for (const prio of sortedPrios) {
      const list = buckets.get(prio);
      const len = list.length;
      if (len === 1) {
        ordered.push(list[0]);
      } else {
        const offset = this._tickIndex % len;
        for (let i = 0; i < len; i++) {
          ordered.push(list[(offset + i) % len]);
        }
      }
    }
    return ordered;
  }

  _handleThreadFault(pcb, tcb, fault, { instructionsExecuted = 0 } = {}) {
    if (instructionsExecuted > 0) {
      pcb.stats.instructionsExecuted += instructionsExecuted;
      tcb.stats.instructionsExecuted += instructionsExecuted;
      this._totalInstructions += instructionsExecuted;
    }

    const { signal, signum } = classifyFault(fault);
    const rawMsg = safeReadProp(fault, 'message', undefined);
    const reason = rawMsg ? safeErrorString(rawMsg) : safeErrorString(fault ?? 'Execution fault');
    const rawCode = safeReadProp(fault, 'code', undefined);
    const rawName = safeReadProp(fault, 'name', undefined);
    const codeCandidate = rawCode !== undefined ? rawCode : rawName !== undefined ? rawName : 'FAULT';
    const safeCode =
      typeof codeCandidate === 'string' ||
      (typeof codeCandidate === 'number' && Number.isFinite(codeCandidate))
        ? codeCandidate
        : safeErrorString(codeCandidate, 'FAULT');
    const rawAddress = safeReadProp(fault, 'address', undefined);
    const addrCandidate =
      rawAddress !== undefined ? rawAddress : safeReadProp(fault, 'addr', null);
    let safeAddress = null;
    if (typeof addrCandidate === 'number' && Number.isFinite(addrCandidate)) {
      safeAddress = addrCandidate;
    } else if (typeof addrCandidate === 'bigint') {
      safeAddress =
        addrCandidate < 0n
          ? `-0x${(-addrCandidate).toString(16)}`
          : `0x${addrCandidate.toString(16)}`;
    } else if (typeof addrCandidate === 'string') {
      safeAddress = addrCandidate;
    }
    const lastFault = {
      signal,
      code: safeCode,
      message: reason,
      address: safeAddress,
      ts: new Date().toISOString(),
    };
    pcb.stats.lastFault = lastFault;

    try {
      this.processManager.writeStderr(
        pcb.pid,
        `[kernel] PID ${pcb.pid} (${pcb.name}) terminated by ${signal}: ${reason}\n`
      );
    } catch {
      // Ignore stderr write failures if process is already torn down.
    }

    try {
      this.processManager.kill(pcb.pid, signal, {
        forceDefault: true,
        reason,
        fault: lastFault,
      });
    } catch {
      try {
        this.processManager.exit(pcb.pid, 128 + signum, { faultReason: reason, fault: lastFault });
      } catch {
        // Process already terminated.
      }
    }

    try {
      this._log('warn', 'scheduler', `PID ${pcb.pid} (${pcb.name}) faulted with ${signal}: ${reason}`, {
        pid: pcb.pid,
        tid: tcb.tid,
        signal,
        code: lastFault.code,
      });
    } catch {
      // Isolate logger failures during fault handling.
    }
    this._eventBus?.emit('scheduler:fault', {
      pid: pcb.pid,
      tid: tcb.tid,
      signal,
      fault: lastFault,
    });
  }

  step(maxTicks = 1) {
    if (!SCHEDULABLE_KERNEL_STATES.has(this.getKernelState())) {
      return { ticksRun: 0, instructionsExecuted: 0, activePids: [] };
    }

    const limit = Math.max(0, Math.floor(maxTicks));
    let ticksRun = 0;
    let totalStepInstructions = 0;
    const activePidSet = new Set();

    for (let tick = 0; tick < limit; tick++) {
      if (!SCHEDULABLE_KERNEL_STATES.has(this.getKernelState())) break;

      const snapshot = this._collectRunnableThreads();
      if (snapshot.length === 0) break;

      ticksRun += 1;
      this._totalTicks += 1;
      this._tickIndex += 1;

      for (const { pcb, tcb, execCtx } of snapshot) {
        if (!SCHEDULABLE_KERNEL_STATES.has(this.getKernelState())) break;
        if (pcb.state !== PROCESS_STATES.READY && pcb.state !== PROCESS_STATES.RUNNING) continue;
        if (tcb.state !== THREAD_STATES.READY) continue;

        activePidSet.add(pcb.pid);

        const quantum = this.computeQuantum(pcb, tcb);
        if (quantum.quotaExhausted) {
          this._handleThreadFault(
            pcb,
            tcb,
            new QuotaExceededError(
              `PID ${pcb.pid} exhausted maxTotalInstructions (${quantum.maxTotal})`,
              {
                code: ERROR_CODES.E_CPU_QUOTA,
                quotaType: 'cpu',
                limit: quantum.maxTotal,
                actual: pcb.stats.instructionsExecuted,
                pid: pcb.pid,
                signal: 'SIGXCPU',
              }
            )
          );
          continue;
        }

        // Transition to RUNNING
        if (pcb.state === PROCESS_STATES.READY) {
          this.processManager.setState(pcb.pid, PROCESS_STATES.RUNNING, { reason: 'dispatch' });
        }
        tcb.state = THREAD_STATES.RUNNING;

        let result;
        try {
          result = execCtx.step(quantum.budget);
        } catch (err) {
          pcb.stats.cpuTicks += 1;
          tcb.stats.cpuTicks += 1;
          const errExec = safeReadProp(err, 'instructionsExecuted', 0);
          const partial =
            typeof errExec === 'number' && Number.isFinite(errExec) && errExec > 0
              ? Math.trunc(errExec)
              : 0;
          totalStepInstructions += partial;
          this._handleThreadFault(pcb, tcb, err, { instructionsExecuted: partial });
          continue;
        }

        pcb.stats.cpuTicks += 1;
        tcb.stats.cpuTicks += 1;

        let isPromiseOrThenable = false;
        let isNativePromise = false;
        let rawExec;
        try {
          if (result !== null && result !== undefined) {
            try {
              isNativePromise = types.isPromise(result);
            } catch {
              isNativePromise = false;
            }
            if (isNativePromise) {
              isPromiseOrThenable = true;
              try {
                Promise.prototype.then.call(result, () => {}, () => {});
              } catch {
                try {
                  if (typeof result.then === 'function') {
                    result.then(() => {}, () => {});
                  }
                } catch {
                  // Ignore suppression failures on native/cross-realm Promises.
                }
              }
            } else {
              const resultThen = result.then;
              if (typeof resultThen === 'function') {
                isPromiseOrThenable = true;
                try {
                  resultThen.call(result, () => {}, () => {});
                } catch {
                  // Ignore suppression failures on custom thenables.
                }
              }
            }
            if (!isPromiseOrThenable) {
              rawExec = result.instructionsExecuted;
            }
          }
        } catch (readErr) {
          this._handleThreadFault(pcb, tcb, readErr);
          continue;
        }

        if (isPromiseOrThenable) {
          this._handleThreadFault(
            pcb,
            tcb,
            new IllegalInstructionError(
              'ExecutionContext.step() must be synchronous and must not return a Promise/thenable',
              { code: ERROR_CODES.E_ILLEGAL_INSTRUCTION, pid: pcb.pid }
            )
          );
          continue;
        }

        if (rawExec !== undefined) {
          if (
            typeof rawExec !== 'number' ||
            Number.isNaN(rawExec) ||
            !Number.isFinite(rawExec) ||
            rawExec < 0
          ) {
            this._handleThreadFault(
              pcb,
              tcb,
              new QuotaExceededError(`Invalid or infinite instructionsExecuted: ${safeErrorString(rawExec)}`, {
                code: ERROR_CODES.E_CPU_QUOTA,
                quotaType: 'cpu',
                limit: quantum.maxPerTick,
                actual: rawExec,
                pid: pcb.pid,
                signal: 'SIGXCPU',
              })
            );
            continue;
          }
        }

        const executed = rawExec !== undefined ? Math.trunc(rawExec) : 0;

        pcb.stats.instructionsExecuted += executed;
        tcb.stats.instructionsExecuted += executed;
        totalStepInstructions += executed;
        this._totalInstructions += executed;

        // Post-step check: did an in-step syscall/signal already stop or terminate this process?
        if (
          pcb.state === PROCESS_STATES.ZOMBIE ||
          pcb.state === PROCESS_STATES.TERMINATED ||
          pcb.state === PROCESS_STATES.STOPPED
        ) {
          continue;
        }

        // Runaway quota overrun checks
        if (executed > quantum.maxPerTick) {
          this._handleThreadFault(
            pcb,
            tcb,
            new QuotaExceededError(
              `PID ${pcb.pid} exceeded maxInstructionsPerTick (${executed} > ${quantum.maxPerTick})`,
              {
                code: ERROR_CODES.E_CPU_QUOTA,
                quotaType: 'cpu_per_tick',
                limit: quantum.maxPerTick,
                actual: executed,
                pid: pcb.pid,
                signal: 'SIGXCPU',
              }
            )
          );
          continue;
        }

        let status;
        let waitReason;
        let exitCode;
        let resultFault;
        try {
          if (result !== null && result !== undefined) {
            status = result.status;
            if (status === 'BLOCKED') {
              waitReason = result.waitReason;
            } else if (status === 'EXITED') {
              exitCode = result.exitCode;
            } else if (status === 'FAULT') {
              resultFault = result.fault;
            }
          }
        } catch (readErr) {
          this._handleThreadFault(pcb, tcb, readErr);
          continue;
        }

        if (
          quantum.maxTotal !== Infinity &&
          (pcb.stats.instructionsExecuted > quantum.maxTotal ||
            (pcb.stats.instructionsExecuted >= quantum.maxTotal &&
              status !== 'EXITED' &&
              status !== 'FAULT' &&
              tcb.state !== THREAD_STATES.EXITED))
        ) {
          this._handleThreadFault(
            pcb,
            tcb,
            new QuotaExceededError(
              `PID ${pcb.pid} exceeded maxTotalInstructions (${pcb.stats.instructionsExecuted}/${quantum.maxTotal})`,
              {
                code: ERROR_CODES.E_CPU_QUOTA,
                quotaType: 'cpu_total',
                limit: quantum.maxTotal,
                actual: pcb.stats.instructionsExecuted,
                pid: pcb.pid,
                signal: 'SIGXCPU',
              }
            )
          );
          continue;
        }

        // Respect in-step thread state transitions (e.g. exitThread / markBlocked / SIGSTOP)
        if (
          pcb.state === PROCESS_STATES.ZOMBIE ||
          pcb.state === PROCESS_STATES.TERMINATED ||
          pcb.state === PROCESS_STATES.STOPPED ||
          tcb.state !== THREAD_STATES.RUNNING
        ) {
          continue;
        }

        if (status === 'YIELD') {
          this.processManager.markReady(pcb.pid, tcb.tid);
        } else if (status === 'BLOCKED') {
          this.processManager.markBlocked(
            pcb.pid,
            tcb.tid,
            waitReason !== undefined && waitReason !== null ? safeErrorString(waitReason, 'io') : 'io'
          );
        } else if (status === 'EXITED') {
          const code = Number.isInteger(exitCode) ? exitCode : 0;
          this.processManager.exitThread(pcb.pid, tcb.tid, code);
        } else if (status === 'FAULT') {
          this._handleThreadFault(
            pcb,
            tcb,
            resultFault ?? new Error('ExecutionContext reported FAULT')
          );
        } else {
          this._handleThreadFault(
            pcb,
            tcb,
            new IllegalInstructionError(
              `Invalid ExecutionContext.step() status: ${safeErrorString(status)}`,
              { code: ERROR_CODES.E_ILLEGAL_INSTRUCTION, pid: pcb.pid }
            )
          );
        }
      }
    }

    return {
      ticksRun,
      instructionsExecuted: totalStepInstructions,
      activePids: Array.from(activePidSet),
    };
  }

  runUntilIdle(pid, maxTicks = 500) {
    const pcb = this.processManager.get(pid);
    if (!pcb) {
      throw new ProcessError(`Process not found: PID ${pid}`, {
        code: ERROR_CODES.ESRCH,
        pid,
      });
    }

    const limit = Math.max(0, Math.floor(maxTicks));
    for (let i = 0; i < limit; i++) {
      if (!SCHEDULABLE_KERNEL_STATES.has(this.getKernelState())) break;
      const current = this.processManager.get(pid);
      if (
        !current ||
        current.state === PROCESS_STATES.ZOMBIE ||
        current.state === PROCESS_STATES.TERMINATED ||
        current.state === PROCESS_STATES.STOPPED ||
        current.state === PROCESS_STATES.BLOCKED
      ) {
        break;
      }

      let hasRunnable = false;
      for (const tcb of current.threads.values()) {
        if (
          tcb.state === THREAD_STATES.READY &&
          tcb.executionContext &&
          typeof safeReadProp(tcb.executionContext, 'step', null) === 'function'
        ) {
          hasRunnable = true;
          break;
        }
      }
      if (!hasRunnable) break;

      const tickRes = this.step(1);
      if (tickRes.ticksRun === 0) break;
    }

    return this.processManager.toSummary(this.processManager.get(pid));
  }

  wake(pid, tid = null) {
    const woke = this.processManager.wake(pid, tid);
    if (woke) {
      this._eventBus?.emit('scheduler:woke', { pid, tid });
    }
    return woke;
  }

  getStats() {
    return {
      running: this._running,
      tickMs: this._tickMs,
      baseQuantum: this.baseQuantum,
      totalTicks: this._totalTicks,
      totalInstructions: this._totalInstructions,
    };
  }
}
