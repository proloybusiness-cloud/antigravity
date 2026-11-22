/**
 * OmniOS Built-in System Apps Registry (`os/apps/registry.mjs`, F-067 – F-072)
 * Manages all 7 real kernel-backed built-in system apps, spawning real PCBs in ProcessManager,
 * attaching strictly synchronous `IExecutionContext` instances, creating real `CompositorWindow`s,
 * and registering cross-platform intent handlers cleanly.
 */

import { OmniOSError, ERROR_CODES } from '../common/errors.mjs';
import { PROCESS_STATES } from '../kernel/process.mjs';
import { TERMINAL_APP_DESCRIPTOR, createTerminalExecutionContext } from './terminal-app.mjs';
import { FILES_APP_DESCRIPTOR, createFilesExecutionContext } from './files-app.mjs';
import { MONITOR_APP_DESCRIPTOR, createMonitorExecutionContext } from './monitor-app.mjs';
import { APPHUB_APP_DESCRIPTOR, createAppHubExecutionContext } from './apphub-app.mjs';
import { SETTINGS_APP_DESCRIPTOR, createSettingsExecutionContext } from './settings-app.mjs';
import { INSPECTOR_APP_DESCRIPTOR, createInspectorExecutionContext } from './inspector-app.mjs';
import { NOTES_APP_DESCRIPTOR, createNotesExecutionContext } from './notes-app.mjs';

export const SYSTEM_APP_IDS = Object.freeze({
  TERMINAL: TERMINAL_APP_DESCRIPTOR.appId,
  FILES: FILES_APP_DESCRIPTOR.appId,
  MONITOR: MONITOR_APP_DESCRIPTOR.appId,
  APPHUB: APPHUB_APP_DESCRIPTOR.appId,
  SETTINGS: SETTINGS_APP_DESCRIPTOR.appId,
  INSPECTOR: INSPECTOR_APP_DESCRIPTOR.appId,
  NOTES: NOTES_APP_DESCRIPTOR.appId,
});

const APP_DEFINITIONS = Object.freeze([
  Object.freeze({ descriptor: TERMINAL_APP_DESCRIPTOR, factory: createTerminalExecutionContext }),
  Object.freeze({ descriptor: FILES_APP_DESCRIPTOR, factory: createFilesExecutionContext }),
  Object.freeze({ descriptor: MONITOR_APP_DESCRIPTOR, factory: createMonitorExecutionContext }),
  Object.freeze({ descriptor: APPHUB_APP_DESCRIPTOR, factory: createAppHubExecutionContext }),
  Object.freeze({ descriptor: SETTINGS_APP_DESCRIPTOR, factory: createSettingsExecutionContext }),
  Object.freeze({ descriptor: INSPECTOR_APP_DESCRIPTOR, factory: createInspectorExecutionContext }),
  Object.freeze({ descriptor: NOTES_APP_DESCRIPTOR, factory: createNotesExecutionContext }),
]);

export class SystemAppRegistry {
  constructor(os) {
    if (!os || typeof os !== 'object') {
      throw new OmniOSError('SystemAppRegistry requires an OmniOS instance', {
        code: ERROR_CODES.EINVAL,
      });
    }
    this.os = os;
    this._byId = new Map();
    this._aliasMap = new Map();
    this._runningByApp = new Map();
    this._pidToApp = new Map();

    for (const def of APP_DEFINITIONS) {
      const id = def.descriptor.appId;
      this._byId.set(id, def);
      this._aliasMap.set(id.toLowerCase(), id);
      for (const alias of def.descriptor.aliases) {
        this._aliasMap.set(alias.toLowerCase(), id);
      }
    }
  }

  resolveId(idOrAlias) {
    if (typeof idOrAlias !== 'string') return null;
    const key = idOrAlias.trim().toLowerCase();
    if (!key) return null;
    return this._aliasMap.get(key) ?? null;
  }

  has(idOrAlias) {
    return this.resolveId(idOrAlias) !== null;
  }

  _getLivePidsFor(appId) {
    const pidSet = this._runningByApp.get(appId);
    if (!pidSet || pidSet.size === 0) return [];
    const live = [];
    for (const pid of Array.from(pidSet)) {
      const pcb = this.os.processManager?.get(pid);
      if (pcb && pcb.state !== PROCESS_STATES.ZOMBIE && pcb.state !== PROCESS_STATES.TERMINATED) {
        live.push(pid);
      } else {
        pidSet.delete(pid);
        this._pidToApp.delete(pid);
      }
    }
    if (pidSet.size === 0) {
      this._runningByApp.delete(appId);
    }
    return live;
  }

  get(idOrAlias) {
    const id = this.resolveId(idOrAlias);
    if (!id) return null;
    const def = this._byId.get(id);
    if (!def) return null;
    return {
      ...def.descriptor,
      aliases: [...def.descriptor.aliases],
      runningPids: this._getLivePidsFor(id),
    };
  }

  list() {
    const out = [];
    for (const id of this._byId.keys()) {
      const desc = this.get(id);
      if (desc) out.push(desc);
    }
    return out;
  }

  async launch(idOrAlias, opts = {}) {
    const appId = this.resolveId(idOrAlias);
    if (!appId) {
      throw new OmniOSError(`Unknown system app: ${String(idOrAlias)}`, {
        code: ERROR_CODES.ENOENT,
        details: { appId: String(idOrAlias) },
      });
    }
    const def = this._byId.get(appId);
    const launchOpts = opts && typeof opts === 'object' ? opts : {};

    const pcb = this.os.processManager.spawn({
      name: def.descriptor.name,
      appId,
      platform: 'system',
      arch: 'native',
      uid: Number.isInteger(launchOpts.uid) ? launchOpts.uid : 1000,
      gid: Number.isInteger(launchOpts.gid) ? launchOpts.gid : 1000,
      cwd: typeof launchOpts.cwd === 'string' && launchOpts.cwd.length > 0 ? launchOpts.cwd : '/home/user',
      env: launchOpts.env && typeof launchOpts.env === 'object' ? { ...launchOpts.env } : {},
      args: Array.isArray(launchOpts.args) ? [...launchOpts.args] : [],
      priority: Number.isFinite(launchOpts.priority) ? launchOpts.priority : 0,
      autoReady: false,
      executionContext: null,
    });

    let execCtx;
    try {
      execCtx = def.factory(this.os, pcb, launchOpts);
      if (!execCtx || typeof execCtx.step !== 'function') {
        throw new OmniOSError(`System app "${appId}" returned an invalid IExecutionContext`, {
          code: ERROR_CODES.EINVAL,
        });
      }
      pcb.executionContext = execCtx;
      if (pcb.state === PROCESS_STATES.CREATED) {
        this.os.processManager.transitionState(pcb.pid, PROCESS_STATES.READY, {
          reason: 'system_app_launch',
        });
      }
    } catch (err) {
      try {
        if (pcb.state !== PROCESS_STATES.ZOMBIE && pcb.state !== PROCESS_STATES.TERMINATED) {
          this.os.processManager.exit(pcb.pid, 1, {
            faultReason: { name: err?.name ?? 'LaunchError', message: err?.message ?? String(err) },
          });
        }
      } catch (cleanupErr) {
        this.os.kernel?.log('warn', 'system-apps', `Orphan PCB cleanup error: ${cleanupErr.message}`);
      }
      throw err;
    }

    let pidSet = this._runningByApp.get(appId);
    if (!pidSet) {
      pidSet = new Set();
      this._runningByApp.set(appId, pidSet);
    }
    pidSet.add(pcb.pid);
    this._pidToApp.set(pcb.pid, appId);

    this.os.processManager.addCleanupHook(pcb.pid, () => {
      const set = this._runningByApp.get(appId);
      if (set) {
        set.delete(pcb.pid);
        if (set.size === 0) this._runningByApp.delete(appId);
      }
      this._pidToApp.delete(pcb.pid);
    });

    const windowIds = this.os.compositor
      .listWindows({ pid: pcb.pid })
      .map((w) => w.windowId);

    this.os.eventBus?.emit('system_app:launched', {
      pid: pcb.pid,
      appId,
      platform: 'system',
      windowIds,
    });

    return {
      pid: pcb.pid,
      appId,
      platform: 'system',
      windowIds,
    };
  }

  stop(idOrAliasOrPid, { signal = 'SIGTERM' } = {}) {
    const stoppedPids = [];

    if (typeof idOrAliasOrPid === 'number' && Number.isInteger(idOrAliasOrPid)) {
      const pid = idOrAliasOrPid;
      if (this._pidToApp.has(pid)) {
        const pcb = this.os.processManager.get(pid);
        if (pcb && pcb.state !== PROCESS_STATES.ZOMBIE && pcb.state !== PROCESS_STATES.TERMINATED) {
          this.os.processManager.kill(pid, signal);
          stoppedPids.push(pid);
        }
        const ownerApp = this._pidToApp.get(pid);
        this._pidToApp.delete(pid);
        this._runningByApp.get(ownerApp)?.delete(pid);
      }
      return { stoppedPids };
    }

    const appId = this.resolveId(idOrAliasOrPid);
    if (!appId) {
      return { stoppedPids };
    }

    const livePids = this._getLivePidsFor(appId);
    for (const pid of livePids) {
      try {
        this.os.processManager.kill(pid, signal);
        stoppedPids.push(pid);
      } catch (err) {
        this.os.kernel?.log('warn', 'system-apps', `Failed stopping ${appId} PID ${pid}: ${err.message}`);
      }
    }
    this._runningByApp.delete(appId);
    for (const pid of stoppedPids) {
      this._pidToApp.delete(pid);
    }
    return { stoppedPids };
  }

  stopAll({ signal = 'SIGTERM' } = {}) {
    const stoppedPids = [];
    for (const appId of Array.from(this._runningByApp.keys())) {
      const res = this.stop(appId, { signal });
      stoppedPids.push(...res.stoppedPids);
    }
    return { stoppedPids };
  }

  registerIntents() {
    if (!this.os.intentRouter) return;

    // Register OmniNotes only if not currently overridden by an installed package with the same appId
    const installedNotes = this.os.pkgManager?.isReady() ? this.os.pkgManager.get(SYSTEM_APP_IDS.NOTES) : null;
    if (!installedNotes) {
      this.os.intentRouter.registerHandlers(
        SYSTEM_APP_IDS.NOTES,
        [
          {
            actions: ['send', 'view', 'edit'],
            mimeTypes: ['text/plain', 'text/markdown'],
            extensions: ['.txt', '.md', '.markdown'],
            priority: 10,
          },
        ],
        { platform: 'system', label: NOTES_APP_DESCRIPTOR.name, replace: true }
      );
    }

    this.os.intentRouter.registerHandlers(
      SYSTEM_APP_IDS.FILES,
      [
        {
          actions: ['view'],
          schemes: ['file'],
          mimeTypes: ['inode/directory'],
          priority: 5,
        },
      ],
      { platform: 'system', label: FILES_APP_DESCRIPTOR.name, replace: true }
    );

    this.os.intentRouter.registerHandlers(
      SYSTEM_APP_IDS.INSPECTOR,
      [
        {
          actions: ['inspect'],
          extensions: ['.apk', '.exe', '.dll', '.msix', '.msi', '.ipa', '.dmg', '.pkg', '.uapp', '.wasm'],
          priority: 10,
        },
      ],
      { platform: 'system', label: INSPECTOR_APP_DESCRIPTOR.name, replace: true }
    );
  }
}

export function createSystemAppRegistry(os) {
  return new SystemAppRegistry(os);
}
