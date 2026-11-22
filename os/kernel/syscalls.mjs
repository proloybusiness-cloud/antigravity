/**
 * OmniOS Unified SyscallDispatcher
 * Supports string-named and numeric syscalls, per-process syscall accounting,
 * sync-preserving & async-capable dispatch, before/after hooks, and structured SyscallError wrapping.
 */

import { OmniOSError, SyscallError, ERROR_CODES } from '../common/errors.mjs';

export class SyscallDispatcher {
  constructor({ eventBus = null, onBefore = null, onAfter = null } = {}) {
    this._handlers = new Map();
    this._byNumber = new Map();
    this._beforeHooks = new Set();
    this._afterHooks = new Set();
    this._eventBus = eventBus;
    this._stats = {
      totalCalls: 0,
      totalErrors: 0,
      bySyscall: new Map(),
    };

    if (typeof onBefore === 'function') this._beforeHooks.add(onBefore);
    if (typeof onAfter === 'function') this._afterHooks.add(onAfter);
  }

  register(name, handler, { number = null, overwrite = true, description = '' } = {}) {
    if (typeof name !== 'string' || name.trim().length === 0) {
      throw new SyscallError('Syscall name must be a non-empty string', {
        code: ERROR_CODES.EINVAL,
        syscall: String(name),
      });
    }
    if (typeof handler !== 'function') {
      throw new SyscallError(`Syscall "${name}" handler must be a function`, {
        code: ERROR_CODES.EINVAL,
        syscall: name,
      });
    }
    if (!overwrite && this._handlers.has(name)) {
      throw new SyscallError(`Syscall already registered: ${name}`, {
        code: ERROR_CODES.EEXIST,
        syscall: name,
      });
    }
    if (number !== null && (!Number.isInteger(number) || number < 0)) {
      throw new SyscallError(`Syscall number must be a non-negative integer: ${number}`, {
        code: ERROR_CODES.EINVAL,
        syscall: name,
      });
    }

    // Clean up previous number binding if overwriting same name
    const existing = this._handlers.get(name);
    if (existing && existing.number !== null) {
      if (this._byNumber.get(existing.number) === name) {
        this._byNumber.delete(existing.number);
      }
    }

    // Clean up previous name binding if another syscall owned this number
    if (number !== null) {
      const prevOwner = this._byNumber.get(number);
      if (prevOwner && prevOwner !== name) {
        const prevEntry = this._handlers.get(prevOwner);
        if (prevEntry) prevEntry.number = null;
      }
      this._byNumber.set(number, name);
    }

    this._handlers.set(name, {
      name,
      number,
      handler,
      description: String(description ?? ''),
    });

    return this;
  }

  unregister(nameOrNumber) {
    const entry = this._resolveEntry(nameOrNumber);
    if (!entry) return false;
    this._handlers.delete(entry.name);
    if (entry.number !== null && this._byNumber.get(entry.number) === entry.name) {
      this._byNumber.delete(entry.number);
    }
    return true;
  }

  _resolveEntry(nameOrNumber) {
    if (typeof nameOrNumber === 'string') {
      return this._handlers.get(nameOrNumber) ?? null;
    }
    if (typeof nameOrNumber === 'number' && Number.isInteger(nameOrNumber)) {
      const name = this._byNumber.get(nameOrNumber);
      return name ? (this._handlers.get(name) ?? null) : null;
    }
    return null;
  }

  has(nameOrNumber) {
    return this._resolveEntry(nameOrNumber) !== null;
  }

  list() {
    return Array.from(this._handlers.keys());
  }

  describe() {
    return Array.from(this._handlers.values()).map((entry) => ({
      name: entry.name,
      number: entry.number,
      description: entry.description,
    }));
  }

  addBeforeHook(fn) {
    if (typeof fn !== 'function') {
      throw new SyscallError('Before-hook must be a function', { code: ERROR_CODES.EINVAL });
    }
    this._beforeHooks.add(fn);
    return () => {
      this._beforeHooks.delete(fn);
    };
  }

  addAfterHook(fn) {
    if (typeof fn !== 'function') {
      throw new SyscallError('After-hook must be a function', { code: ERROR_CODES.EINVAL });
    }
    this._afterHooks.add(fn);
    return () => {
      this._afterHooks.delete(fn);
    };
  }

  getStats() {
    const bySyscall = {};
    for (const [k, v] of this._stats.bySyscall.entries()) {
      Object.defineProperty(bySyscall, k, {
        value: { calls: v.calls, errors: v.errors },
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return {
      totalCalls: this._stats.totalCalls,
      totalErrors: this._stats.totalErrors,
      bySyscall,
    };
  }

  _normalizeContext(ctx) {
    let pcb = null;
    let extraCtx = {};
    if (ctx !== null && ctx !== undefined && typeof ctx === 'object') {
      if ('pcb' in ctx) {
        const { pcb: innerPcb, ...rest } = ctx;
        pcb = innerPcb ?? null;
        extraCtx = rest;
      } else if (ctx.stats && typeof ctx.stats.syscallsCount === 'number') {
        pcb = ctx;
        extraCtx = {};
      } else {
        extraCtx = ctx;
      }
    }
    const pid = pcb?.pid ?? extraCtx.pid ?? null;
    return { pcb, pid, extraCtx };
  }

  _bumpSyscallStat(key, isError) {
    let rec = this._stats.bySyscall.get(key);
    if (!rec) {
      rec = { calls: 0, errors: 0 };
      this._stats.bySyscall.set(key, rec);
    }
    if (isError) {
      rec.errors += 1;
    } else {
      rec.calls += 1;
    }
  }

  _wrapError(err, syscallName, pid) {
    if (err instanceof SyscallError) {
      if (err.syscall === null || err.syscall === undefined) err.syscall = syscallName;
      if (err.pid === null || err.pid === undefined) err.pid = pid;
      return err;
    }
    if (err instanceof OmniOSError) {
      return new SyscallError(err.message, {
        code: err.code,
        errno: err.errno,
        signal: err.signal,
        syscall: syscallName,
        pid,
        details: err.details,
        cause: err,
      });
    }
    const code = typeof err?.code === 'string' && err.code.length > 0 ? err.code : ERROR_CODES.EIO;
    return new SyscallError(err?.message ? String(err.message) : String(err), {
      code,
      syscall: syscallName,
      pid,
      cause: err,
    });
  }

  _runAfterHooks(info) {
    for (const hook of this._afterHooks) {
      try {
        hook(info);
      } catch {
        // Isolate after-hook errors so completed syscall results are preserved.
      }
    }
  }

  dispatch(nameOrNumber, ctx = null, ...args) {
    const startPerf = performance.now();
    const ts = new Date().toISOString();
    const { pcb, pid, extraCtx } = this._normalizeContext(ctx);

    this._stats.totalCalls += 1;
    if (pcb?.stats && typeof pcb.stats.syscallsCount === 'number') {
      pcb.stats.syscallsCount += 1;
    }

    const entry = this._resolveEntry(nameOrNumber);
    const syscallKey = entry ? entry.name : String(nameOrNumber);
    this._bumpSyscallStat(syscallKey, false);

    if (!entry) {
      const err = new SyscallError(`Unknown syscall: ${nameOrNumber}`, {
        code: ERROR_CODES.ENOSYS,
        syscall: syscallKey,
        pid,
      });
      const durationMs = Number((performance.now() - startPerf).toFixed(3));
      this._stats.totalErrors += 1;
      this._bumpSyscallStat(syscallKey, true);
      this._eventBus?.emit('syscall:error', {
        syscall: syscallKey,
        number: typeof nameOrNumber === 'number' ? nameOrNumber : null,
        pid,
        code: err.code,
        errno: err.errno,
        message: err.message,
        durationMs,
        ts,
      });
      this._eventBus?.emit('syscall:after', {
        syscall: syscallKey,
        number: typeof nameOrNumber === 'number' ? nameOrNumber : null,
        pid,
        ok: false,
        code: err.code,
        durationMs,
        ts,
      });
      this._runAfterHooks({
        syscall: syscallKey,
        number: typeof nameOrNumber === 'number' ? nameOrNumber : null,
        args,
        pcb,
        pid,
        ok: false,
        result: undefined,
        error: err,
        durationMs,
        ts,
      });
      throw err;
    }

    const normalizedCtx = {
      ...extraCtx,
      pcb,
      pid,
      syscall: entry.name,
      number: entry.number,
      dispatcher: this,
    };

    const finalizeSuccess = (result) => {
      const durationMs = Number((performance.now() - startPerf).toFixed(3));
      this._runAfterHooks({
        syscall: entry.name,
        number: entry.number,
        ctx: normalizedCtx,
        args,
        pcb,
        pid,
        ok: true,
        result,
        error: null,
        durationMs,
        ts,
      });
      this._eventBus?.emit('syscall:after', {
        syscall: entry.name,
        number: entry.number,
        pid,
        ok: true,
        durationMs,
        ts,
      });
      return result;
    };

    const finalizeFailure = (rawErr) => {
      const wrapped = this._wrapError(rawErr, entry.name, pid);
      const durationMs = Number((performance.now() - startPerf).toFixed(3));
      this._stats.totalErrors += 1;
      this._bumpSyscallStat(entry.name, true);
      this._eventBus?.emit('syscall:error', {
        syscall: entry.name,
        number: entry.number,
        pid,
        code: wrapped.code,
        errno: wrapped.errno,
        message: wrapped.message,
        durationMs,
        ts,
      });
      this._runAfterHooks({
        syscall: entry.name,
        number: entry.number,
        ctx: normalizedCtx,
        args,
        pcb,
        pid,
        ok: false,
        result: undefined,
        error: wrapped,
        durationMs,
        ts,
      });
      this._eventBus?.emit('syscall:after', {
        syscall: entry.name,
        number: entry.number,
        pid,
        ok: false,
        code: wrapped.code,
        durationMs,
        ts,
      });
      return wrapped;
    };

    this._eventBus?.emit('syscall:before', {
      syscall: entry.name,
      number: entry.number,
      pid,
      ts,
    });

    try {
      for (const hook of this._beforeHooks) {
        hook({
          syscall: entry.name,
          number: entry.number,
          ctx: normalizedCtx,
          args,
          pcb,
          pid,
          ts,
        });
      }

      const res = entry.handler(normalizedCtx, ...args);
      if (
        res !== null &&
        res !== undefined &&
        (typeof res === 'object' || typeof res === 'function') &&
        typeof res.then === 'function'
      ) {
        return res.then(
          (val) => finalizeSuccess(val),
          (rej) => {
            throw finalizeFailure(rej);
          }
        );
      }
      return finalizeSuccess(res);
    } catch (err) {
      throw finalizeFailure(err);
    }
  }

  invoke(nameOrNumber, ctx = null, ...args) {
    return this.dispatch(nameOrNumber, ctx, ...args);
  }
}
