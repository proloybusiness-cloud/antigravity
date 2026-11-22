/**
 * OmniOS Systemd-like ServiceManager (`F-002`)
 * Features:
 *  - 3-color DFS topological dependency resolution with exact cycle path & missing dep detection
 *  - Reverse-dependency shutdown (`stopAll`)
 *  - Essential-only safe-mode boot (`startAll({ safeMode: true })`)
 *  - Health probes (`checkHealth`, `checkAllHealth`, `.unref()` background monitor)
 *  - Exponential backoff crash recovery up to `maxRestarts` -> `FAILED`
 */

import { ServiceError, ERROR_CODES } from '../common/errors.mjs';

export { ServiceError };

export const SERVICE_STATES = Object.freeze({
  STOPPED: 'STOPPED',
  STARTING: 'STARTING',
  RUNNING: 'RUNNING',
  RESTARTING: 'RESTARTING',
  DEGRADED: 'DEGRADED',
  FAILED: 'FAILED',
});

export class ServiceManager {
  constructor({ eventBus = null, log = () => {} } = {}) {
    this._eventBus = eventBus;
    this._log = typeof log === 'function' ? log : () => {};
    this._services = new Map();
    this._healthTimer = null;
    this._healthChecking = false;
    this._stopAllGen = 0;
  }

  register({
    name,
    deps = [],
    start,
    stop = async () => {},
    healthCheck = null,
    maxRestarts = 3,
    restartBackoffMs = 20,
    essential = false,
    description = '',
  } = {}) {
    if (typeof name !== 'string' || name.trim().length === 0) {
      throw new ServiceError('Service name must be a non-empty string', {
        code: ERROR_CODES.E_SERVICE_INVALID,
        serviceName: String(name ?? ''),
      });
    }
    if (this._services.has(name)) {
      throw new ServiceError(`Service "${name}" is already registered`, {
        code: ERROR_CODES.E_SERVICE_EXISTS,
        serviceName: name,
      });
    }
    if (typeof start !== 'function') {
      throw new ServiceError(`Service "${name}" must provide a start() function`, {
        code: ERROR_CODES.E_SERVICE_INVALID,
        serviceName: name,
      });
    }
    if (stop !== null && stop !== undefined && typeof stop !== 'function') {
      throw new ServiceError(`Service "${name}" stop must be a function`, {
        code: ERROR_CODES.E_SERVICE_INVALID,
        serviceName: name,
      });
    }
    if (healthCheck !== null && healthCheck !== undefined && typeof healthCheck !== 'function') {
      throw new ServiceError(`Service "${name}" healthCheck must be a function or null`, {
        code: ERROR_CODES.E_SERVICE_INVALID,
        serviceName: name,
      });
    }
    if (!Array.isArray(deps)) {
      throw new ServiceError(`Service "${name}" deps must be an array`, {
        code: ERROR_CODES.E_SERVICE_INVALID,
        serviceName: name,
      });
    }

    const dedupDeps = [];
    const seen = new Set();
    for (const d of deps) {
      if (typeof d !== 'string' || d.trim().length === 0) {
        throw new ServiceError(`Service "${name}" contains invalid dependency name`, {
          code: ERROR_CODES.E_SERVICE_INVALID,
          serviceName: name,
        });
      }
      if (!seen.has(d)) {
        seen.add(d);
        dedupDeps.push(d);
      }
    }

    const record = {
      name,
      description: String(description ?? ''),
      deps: dedupDeps,
      start,
      stop: typeof stop === 'function' ? stop : async () => {},
      healthCheck: typeof healthCheck === 'function' ? healthCheck : null,
      maxRestarts: Number.isInteger(maxRestarts) && maxRestarts >= 0 ? maxRestarts : 3,
      restartBackoffMs:
        typeof restartBackoffMs === 'number' && Number.isFinite(restartBackoffMs) && restartBackoffMs >= 0
          ? restartBackoffMs
          : 20,
      essential: Boolean(essential),
      state: SERVICE_STATES.STOPPED,
      restarts: 0,
      totalRestarts: 0,
      lastError: null,
      startedAt: null,
      stoppedAt: null,
      lastHealthCheckAt: null,
      lastHealthOk: null,
      lastRestartAt: null,
      backoffHistory: [],
      _cancelBackoff: null,
      _lifecycleGen: 0,
      _crashPromise: null,
      _startPromise: null,
      _stopping: false,
    };

    this._services.set(name, record);
    return this;
  }

  has(name) {
    return this._services.has(name);
  }

  _requireService(name) {
    const svc = this._services.get(name);
    if (!svc) {
      throw new ServiceError(`Service not found: "${name}"`, {
        code: ERROR_CODES.E_SERVICE_NOT_FOUND,
        serviceName: String(name),
      });
    }
    return svc;
  }

  _snapshot(svc) {
    return {
      name: svc.name,
      description: svc.description,
      deps: [...svc.deps],
      essential: svc.essential,
      state: svc.state,
      restarts: svc.restarts,
      totalRestarts: svc.totalRestarts,
      maxRestarts: svc.maxRestarts,
      restartBackoffMs: svc.restartBackoffMs,
      lastError: svc.lastError,
      startedAt: svc.startedAt,
      stoppedAt: svc.stoppedAt,
      lastHealthCheckAt: svc.lastHealthCheckAt,
      lastHealthOk: svc.lastHealthOk,
      lastRestartAt: svc.lastRestartAt,
      backoffHistory: [...svc.backoffHistory],
    };
  }

  getStatus(name = undefined) {
    if (name !== undefined) {
      const svc = this._services.get(name);
      return svc ? this._snapshot(svc) : null;
    }
    return Array.from(this._services.values()).map((s) => this._snapshot(s));
  }

  /**
   * 3-color DFS topological sort detecting missing deps and exact cycle paths.
   */
  resolveOrder(names = null) {
    const targets = names === null ? Array.from(this._services.keys()) : [...names];
    const color = new Map(); // 0=UNVISITED, 1=VISITING, 2=VISITED
    const stack = [];
    const order = [];

    const visit = (u) => {
      if (!this._services.has(u)) {
        throw new ServiceError(`Service not found: "${u}"`, {
          code: ERROR_CODES.E_SERVICE_NOT_FOUND,
          serviceName: u,
        });
      }
      const c = color.get(u) ?? 0;
      if (c === 2) return;
      if (c === 1) {
        const cycle = [...stack.slice(stack.indexOf(u)), u];
        throw new ServiceError(`Circular service dependency detected: ${cycle.join(' -> ')}`, {
          code: ERROR_CODES.E_SERVICE_CYCLE,
          serviceName: u,
          cycle,
          details: { cycle },
        });
      }

      color.set(u, 1);
      stack.push(u);
      const svc = this._services.get(u);
      for (const dep of svc.deps) {
        if (!this._services.has(dep)) {
          throw new ServiceError(`Service "${u}" depends on missing service "${dep}"`, {
            code: ERROR_CODES.E_SERVICE_MISSING_DEP,
            serviceName: u,
            missingDep: dep,
            details: { serviceName: u, missingDep: dep },
          });
        }
        const depColor = color.get(dep) ?? 0;
        if (depColor === 1) {
          const cycle = [...stack.slice(stack.indexOf(dep)), dep];
          throw new ServiceError(`Circular service dependency detected: ${cycle.join(' -> ')}`, {
            code: ERROR_CODES.E_SERVICE_CYCLE,
            serviceName: dep,
            cycle,
            details: { cycle },
          });
        }
        if (depColor === 0) {
          visit(dep);
        }
      }
      stack.pop();
      color.set(u, 2);
      order.push(u);
    };

    for (const target of targets) {
      visit(target);
    }
    return order;
  }

  _collectEssentialClosure() {
    const needed = new Set();
    const visit = (name) => {
      if (needed.has(name)) return;
      const svc = this._services.get(name);
      if (!svc) return;
      needed.add(name);
      for (const dep of svc.deps) {
        visit(dep);
      }
    };
    for (const svc of this._services.values()) {
      if (svc.essential) visit(svc.name);
    }
    return needed;
  }

  _cancelPendingBackoff(svc) {
    if (typeof svc._cancelBackoff === 'function') {
      const cancel = svc._cancelBackoff;
      svc._cancelBackoff = null;
      cancel();
    }
  }

  _waitBackoff(svc, delayMs) {
    return new Promise((resolve) => {
      if (delayMs <= 0) {
        resolve(false);
        return;
      }
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        svc._cancelBackoff = null;
        resolve(false);
      }, delayMs);

      svc._cancelBackoff = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        svc._cancelBackoff = null;
        resolve(true);
      };
    });
  }

  async start(name) {
    const svc = this._requireService(name);
    const subOrder = this.resolveOrder([name]);

    if (svc._startPromise) {
      return svc._startPromise;
    }
    if (svc.state === SERVICE_STATES.RUNNING && !svc._stopping) {
      return this._snapshot(svc);
    }

    if (svc._crashPromise || svc._cancelBackoff) {
      svc._lifecycleGen += 1;
      this._cancelPendingBackoff(svc);
      svc._crashPromise = null;
      if (svc.state === SERVICE_STATES.RESTARTING || svc.state === SERVICE_STATES.STARTING) {
        svc.state = SERVICE_STATES.STOPPED;
      }
    }

    const entryGen = svc._lifecycleGen;
    for (const depName of subOrder) {
      if (depName === name) continue;
      const depSvc = this._services.get(depName);
      if (depSvc.state !== SERVICE_STATES.RUNNING || depSvc._stopping) {
        await this.start(depName);
        if (svc._startPromise) {
          return svc._startPromise;
        }
        if (svc._lifecycleGen !== entryGen) {
          return this._snapshot(svc);
        }
        if (depSvc.state !== SERVICE_STATES.RUNNING || depSvc._stopping) {
          return this._snapshot(svc);
        }
      }
    }

    if (svc.state === SERVICE_STATES.RUNNING && !svc._stopping) {
      return this._snapshot(svc);
    }
    if (svc._startPromise) {
      return svc._startPromise;
    }

    const startGen = ++svc._lifecycleGen;
    this._cancelPendingBackoff(svc);
    svc._crashPromise = null;
    svc._stopping = false;
    svc.state = SERVICE_STATES.STARTING;

    let startP = null;
    let settled = false;
    startP = (async () => {
      try {
        await svc.start(svc);
        if (svc._lifecycleGen !== startGen) {
          if (svc.state === SERVICE_STATES.STOPPED) {
            try {
              await svc.stop(svc);
            } catch {
              // Best-effort cleanup of stale start() when superseded by stop()/reset().
            }
          }
          return this._snapshot(svc);
        }
        svc.state = SERVICE_STATES.RUNNING;
        svc.startedAt = Date.now();
        svc.lastError = null;
        this._log('info', 'services', `Service "${svc.name}" started`);
        this._eventBus?.emit('service:started', { name: svc.name, startedAt: svc.startedAt });
        return this._snapshot(svc);
      } catch (err) {
        if (svc._lifecycleGen !== startGen) {
          return this._snapshot(svc);
        }
        svc.state = SERVICE_STATES.FAILED;
        svc.lastError = err?.message ? String(err.message) : String(err);
        this._log('error', 'services', `Service "${svc.name}" failed to start: ${svc.lastError}`);
        this._eventBus?.emit('service:failed', { name: svc.name, error: svc.lastError });
        throw err;
      } finally {
        settled = true;
        if (startP !== null && svc._startPromise === startP) {
          svc._startPromise = null;
        }
      }
    })();

    if (!settled && svc._lifecycleGen === startGen) {
      svc._startPromise = startP;
    }
    return startP;
  }

  async _stopInternal(svc) {
    const stopGen = ++svc._lifecycleGen;
    svc._crashPromise = null;
    svc._startPromise = null;
    this._cancelPendingBackoff(svc);

    const shouldCallStop = svc.state !== SERVICE_STATES.STOPPED;
    svc._stopping = true;
    try {
      if (shouldCallStop) {
        try {
          await svc.stop(svc);
        } catch (err) {
          const msg = err?.message ? String(err.message) : String(err);
          if (svc._lifecycleGen === stopGen) {
            svc.lastError = msg;
          }
          this._log('warn', 'services', `Service "${svc.name}" stop() threw: ${msg}`);
        }
      }
    } finally {
      if (svc._lifecycleGen === stopGen) {
        svc._stopping = false;
      }
    }

    if (svc._lifecycleGen === stopGen) {
      svc.state = SERVICE_STATES.STOPPED;
      svc.stoppedAt = Date.now();
      this._log('info', 'services', `Service "${svc.name}" stopped`);
      this._eventBus?.emit('service:stopped', { name: svc.name, stoppedAt: svc.stoppedAt });
    }
    return { snapshot: this._snapshot(svc), stopGen };
  }

  async stop(name) {
    const svc = this._requireService(name);
    return (await this._stopInternal(svc)).snapshot;
  }

  async restart(name) {
    const svc = this._requireService(name);
    const { stopGen } = await this._stopInternal(svc);
    if (svc._lifecycleGen !== stopGen) {
      return this._snapshot(svc);
    }
    svc.restarts = 0;
    svc.backoffHistory = [];
    svc.lastRestartAt = Date.now();
    svc.totalRestarts += 1;
    const status = await this.start(name);
    if (status.state === SERVICE_STATES.RUNNING) {
      this._eventBus?.emit('service:restarted', {
        name: svc.name,
        restarts: svc.restarts,
        totalRestarts: svc.totalRestarts,
        manual: true,
      });
    }
    return status;
  }

  async startAll({ safeMode = false, continueOnError = false } = {}) {
    const started = [];
    const skipped = [];
    const failed = [];
    const batchGen = this._stopAllGen;

    if (safeMode) {
      const essentialClosure = this._collectEssentialClosure();
      const essentialOrder = this.resolveOrder(Array.from(essentialClosure));
      const essentialSet = new Set(essentialOrder);

      for (const name of this._services.keys()) {
        if (!essentialSet.has(name)) {
          skipped.push(name);
          this._log('info', 'services', `Safe mode: skipping non-essential service "${name}"`);
        }
      }

      for (const name of essentialOrder) {
        if (this._stopAllGen !== batchGen) break;
        const svc = this._services.get(name);
        try {
          const status = await this.start(name);
          if (this._stopAllGen !== batchGen) break;
          if (status.state === SERVICE_STATES.RUNNING) {
            started.push(name);
          }
        } catch (err) {
          if (this._stopAllGen !== batchGen) break;
          const msg = err?.message ? String(err.message) : String(err);
          failed.push({ name, error: msg });
          if (!svc.essential) {
            svc.state = SERVICE_STATES.DEGRADED;
          }
          this._log('warn', 'services', `Safe mode: service "${name}" failed (${msg}); continuing boot`);
        }
      }
      return { started, skipped, failed };
    }

    const order = this.resolveOrder();
    for (const name of order) {
      if (this._stopAllGen !== batchGen) break;
      try {
        const status = await this.start(name);
        if (this._stopAllGen !== batchGen) break;
        if (status.state === SERVICE_STATES.RUNNING) {
          started.push(name);
        }
      } catch (err) {
        if (this._stopAllGen !== batchGen) break;
        const msg = err?.message ? String(err.message) : String(err);
        failed.push({ name, error: msg });
        if (!continueOnError) {
          throw err;
        }
      }
    }
    return { started, skipped, failed };
  }

  async stopAll() {
    this.stopHealthMonitor();
    this._stopAllGen += 1;
    for (const svc of this._services.values()) {
      svc._lifecycleGen += 1;
      svc._crashPromise = null;
      svc._startPromise = null;
      this._cancelPendingBackoff(svc);
    }

    let order;
    try {
      order = this.resolveOrder().reverse();
    } catch {
      order = Array.from(this._services.keys()).reverse();
    }

    for (const name of order) {
      const svc = this._services.get(name);
      if (svc && (svc.state !== SERVICE_STATES.STOPPED || svc._stopping)) {
        await this.stop(name);
      }
    }
  }

  haltForPanic() {
    this.stopHealthMonitor();
    this._stopAllGen += 1;
    for (const svc of this._services.values()) {
      svc._lifecycleGen += 1;
      this._cancelPendingBackoff(svc);
      svc._crashPromise = null;
      svc._startPromise = null;
      svc._stopping = false;
      if (svc.state === SERVICE_STATES.RESTARTING || svc.state === SERVICE_STATES.STARTING) {
        svc.state = SERVICE_STATES.STOPPED;
      }
    }
  }

  async checkHealth(name) {
    const svc = this._requireService(name);
    if (svc._crashPromise) {
      await svc._crashPromise;
      return {
        name: svc.name,
        healthy: false,
        state: svc.state,
        restarts: svc.restarts,
        error: svc.lastError,
      };
    }
    if (
      svc._stopping ||
      (svc.state !== SERVICE_STATES.RUNNING && svc.state !== SERVICE_STATES.DEGRADED)
    ) {
      return {
        name: svc.name,
        healthy: false,
        state: svc.state,
        restarts: svc.restarts,
        error: svc.lastError,
      };
    }

    const gen = svc._lifecycleGen;
    svc.lastHealthCheckAt = Date.now();
    if (!svc.healthCheck) {
      svc.lastHealthOk = true;
      return {
        name: svc.name,
        healthy: true,
        state: svc.state,
        restarts: svc.restarts,
        error: null,
      };
    }

    let unhealthyErr = null;
    try {
      const res = await svc.healthCheck(svc);
      if (svc._lifecycleGen !== gen) {
        return {
          name: svc.name,
          healthy: false,
          state: svc.state,
          restarts: svc.restarts,
          error: svc.lastError,
        };
      }
      const isHealthy = res !== false && !(res && typeof res === 'object' && res.ok === false);
      if (isHealthy) {
        if (svc._crashPromise) {
          await svc._crashPromise;
          return {
            name: svc.name,
            healthy: false,
            state: svc.state,
            restarts: svc.restarts,
            error: svc.lastError,
          };
        }
        if (
          svc._stopping ||
          (svc.state !== SERVICE_STATES.RUNNING && svc.state !== SERVICE_STATES.DEGRADED)
        ) {
          return {
            name: svc.name,
            healthy: false,
            state: svc.state,
            restarts: svc.restarts,
            error: svc.lastError,
          };
        }
        svc.lastHealthOk = true;
        return {
          name: svc.name,
          healthy: true,
          state: svc.state,
          restarts: svc.restarts,
          error: null,
        };
      }
      unhealthyErr = new Error(
        res && typeof res === 'object' && res.reason ? String(res.reason) : 'Health check returned unhealthy'
      );
    } catch (err) {
      if (svc._lifecycleGen !== gen) {
        return {
          name: svc.name,
          healthy: false,
          state: svc.state,
          restarts: svc.restarts,
          error: svc.lastError,
        };
      }
      unhealthyErr = err instanceof Error ? err : new Error(String(err));
    }

    if (svc._lifecycleGen !== gen) {
      return {
        name: svc.name,
        healthy: false,
        state: svc.state,
        restarts: svc.restarts,
        error: svc.lastError,
      };
    }
    if (svc._crashPromise) {
      await svc._crashPromise;
      return {
        name: svc.name,
        healthy: false,
        state: svc.state,
        restarts: svc.restarts,
        error: svc.lastError,
      };
    }
    if (
      svc._stopping ||
      (svc.state !== SERVICE_STATES.RUNNING && svc.state !== SERVICE_STATES.DEGRADED)
    ) {
      return {
        name: svc.name,
        healthy: false,
        state: svc.state,
        restarts: svc.restarts,
        error: svc.lastError,
      };
    }

    svc.lastHealthOk = false;
    svc.lastError = unhealthyErr.message;
    this._log('warn', 'services', `Service "${svc.name}" unhealthy: ${svc.lastError}`);
    this._eventBus?.emit('service:unhealthy', {
      name: svc.name,
      error: svc.lastError,
      restarts: svc.restarts,
    });

    let crashP = null;
    let crashSettled = false;
    crashP = (async () => {
      try {
        await this._handleCrash(svc, unhealthyErr, gen);
      } finally {
        crashSettled = true;
        if (crashP !== null && svc._crashPromise === crashP) {
          svc._crashPromise = null;
        }
      }
    })();
    if (!crashSettled && svc._lifecycleGen === gen) {
      svc._crashPromise = crashP;
    }
    await crashP;

    return {
      name: svc.name,
      healthy: false,
      state: svc.state,
      restarts: svc.restarts,
      error: svc.lastError,
    };
  }

  async checkAllHealth() {
    const results = [];
    for (const svc of this._services.values()) {
      if (svc.state === SERVICE_STATES.RUNNING || svc.state === SERVICE_STATES.DEGRADED) {
        results.push(await this.checkHealth(svc.name));
      }
    }
    return results;
  }

  startHealthMonitor(intervalMs = 1000) {
    this.stopHealthMonitor();
    if (typeof intervalMs !== 'number' || !Number.isFinite(intervalMs) || intervalMs <= 0) {
      throw new ServiceError(`Invalid health monitor interval: ${intervalMs}`, {
        code: ERROR_CODES.E_SERVICE_INVALID,
      });
    }
    this._healthTimer = setInterval(async () => {
      if (this._healthChecking) return;
      this._healthChecking = true;
      try {
        await this.checkAllHealth();
      } catch {
        // Isolate background health monitor errors.
      } finally {
        this._healthChecking = false;
      }
    }, intervalMs);
    if (typeof this._healthTimer.unref === 'function') {
      this._healthTimer.unref();
    }
    return true;
  }

  stopHealthMonitor() {
    if (this._healthTimer !== null) {
      clearInterval(this._healthTimer);
      this._healthTimer = null;
    }
  }

  async _handleCrash(svc, error, gen = svc._lifecycleGen) {
    if (svc._lifecycleGen !== gen) return;
    svc.lastError = error?.message ? String(error.message) : String(error);
    svc.state = svc.restarts >= svc.maxRestarts ? SERVICE_STATES.DEGRADED : SERVICE_STATES.RESTARTING;

    try {
      await svc.stop(svc);
    } catch {
      // Best-effort cleanup before restart attempt.
    }
    if (svc._lifecycleGen !== gen) {
      return;
    }

    if (svc.restarts >= svc.maxRestarts) {
      svc._lifecycleGen += 1;
      svc.state = SERVICE_STATES.FAILED;
      svc.stoppedAt = Date.now();
      this._log('error', 'services', `Service "${svc.name}" exhausted maxRestarts (${svc.maxRestarts})`);
      this._eventBus?.emit('service:failed', {
        name: svc.name,
        restarts: svc.restarts,
        error: svc.lastError,
      });
      return;
    }

    while (svc.restarts < svc.maxRestarts) {
      if (svc._lifecycleGen !== gen) {
        return;
      }
      const attempt = svc.restarts + 1;
      const delayMs = Math.round(svc.restartBackoffMs * Math.pow(2, attempt - 1));
      svc.state = SERVICE_STATES.RESTARTING;
      svc.backoffHistory.push(delayMs);

      this._log(
        'warn',
        'services',
        `Restarting service "${svc.name}" (attempt ${attempt}/${svc.maxRestarts}) after ${delayMs}ms`
      );
      this._eventBus?.emit('service:restarting', {
        name: svc.name,
        attempt,
        maxRestarts: svc.maxRestarts,
        delayMs,
        error: svc.lastError,
      });

      const cancelled = await this._waitBackoff(svc, delayMs);
      if (cancelled || svc._lifecycleGen !== gen || svc.state === SERVICE_STATES.STOPPED) {
        return;
      }

      svc.restarts = attempt;
      svc.totalRestarts += 1;
      svc.lastRestartAt = Date.now();
      svc.state = SERVICE_STATES.STARTING;

      try {
        await svc.start(svc);
        if (svc._lifecycleGen !== gen) {
          if (svc.state === SERVICE_STATES.STOPPED) {
            try {
              await svc.stop(svc);
            } catch {
              // Best-effort cleanup of stale restart start() when superseded by stop()/reset().
            }
          }
          return;
        }
        svc._lifecycleGen += 1;
        svc.state = SERVICE_STATES.RUNNING;
        svc.startedAt = Date.now();
        svc.lastError = null;
        this._log('info', 'services', `Service "${svc.name}" recovered on restart attempt ${attempt}`);
        this._eventBus?.emit('service:restarted', {
          name: svc.name,
          attempt,
          restarts: svc.restarts,
          totalRestarts: svc.totalRestarts,
          manual: false,
        });
        return;
      } catch (startErr) {
        if (svc._lifecycleGen !== gen) {
          return;
        }
        svc.lastError = startErr?.message ? String(startErr.message) : String(startErr);
        this._log(
          'error',
          'services',
          `Service "${svc.name}" restart attempt ${attempt} failed: ${svc.lastError}`
        );
        this._eventBus?.emit('service:restart_failed', {
          name: svc.name,
          attempt,
          error: svc.lastError,
        });
      }
    }

    if (svc._lifecycleGen === gen && svc.state !== SERVICE_STATES.STOPPED) {
      svc._lifecycleGen += 1;
      svc.state = SERVICE_STATES.FAILED;
      svc.stoppedAt = Date.now();
      this._eventBus?.emit('service:failed', {
        name: svc.name,
        restarts: svc.restarts,
        error: svc.lastError,
      });
    }
  }

  resetStates() {
    this.stopHealthMonitor();
    this._stopAllGen += 1;
    for (const svc of this._services.values()) {
      svc._lifecycleGen += 1;
      this._cancelPendingBackoff(svc);
      svc._crashPromise = null;
      svc._startPromise = null;
      svc._stopping = false;
      svc.state = SERVICE_STATES.STOPPED;
      svc.restarts = 0;
      svc.lastError = null;
      svc.startedAt = null;
      svc.stoppedAt = null;
      svc.lastHealthCheckAt = null;
      svc.lastHealthOk = null;
      svc.backoffHistory = [];
    }
  }
}
