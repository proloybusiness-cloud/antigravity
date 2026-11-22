/**
 * OmniOS Built-in System App: Settings & Privacy Center (`com.omnios.settings`, F-071)
 * Controls Shell Mode (unified/windows/macos/ios/android), all 8 synced `system.*` keys,
 * per-app 14-capability Permission Matrix (Android/TCC/Gatekeeper/UAC/WASI), pending permission prompts,
 * Windows Registry / Apple Defaults / Android SharedPreferences viewer & editor, and Security Audit Log.
 */

import { ALL_CAPABILITIES, DEFAULT_CAPABILITY_POLICIES } from '../security/permissions.mjs';
import { SHELL_MODES } from '../compositor/compositor.mjs';
import { CANONICAL_SYSTEM_KEYS } from '../store/unified-config.mjs';

export const SETTINGS_APP_DESCRIPTOR = Object.freeze({
  appId: 'com.omnios.settings',
  aliases: Object.freeze(['settings', 'privacy']),
  name: 'Settings & Privacy',
  title: 'OmniOS Settings & Privacy Center',
  platform: 'system',
  category: 'System',
  icon: 'settings',
  description: 'Adaptive shell modes, synced system preferences, permission matrix, Registry/Defaults/Prefs & audit log',
});

export const SETTINGS_SECTIONS = Object.freeze([
  'general',
  'permissions',
  'registry',
  'defaults',
  'prefs',
  'audit',
]);

const SETTINGS_MENU_BAR = Object.freeze([
  {
    id: 'settings',
    label: 'Settings',
    items: [
      { id: 'settings.refresh', label: 'Refresh State' },
      { id: 'settings.close', label: 'Close Window' },
    ],
  },
  {
    id: 'section',
    label: 'Section',
    items: [
      { id: 'section.general', label: 'General & Shell Mode' },
      { id: 'section.permissions', label: 'Permission Matrix' },
      { id: 'section.registry', label: 'Windows Registry' },
      { id: 'section.defaults', label: 'Apple Defaults' },
      { id: 'section.prefs', label: 'Android SharedPrefs' },
      { id: 'section.audit', label: 'Security Audit Log' },
    ],
  },
]);

export function createSettingsExecutionContext(os, pcb, launchOpts = {}) {
  const initSection = SETTINGS_SECTIONS.includes(launchOpts.section) ? launchOpts.section : 'general';

  const state = {
    activeSection: initSection,
    selectedAppId: null,
    regHive: 'HKCU',
    regKeyPath: 'Software\\OmniOS\\System',
    defaultsDomain: 'NSGlobalDomain',
    prefsPackage: 'com.omnios.system',
    prefsName: 'system_settings',
    auditFilterAppId: null,
    statusMessage: 'All cross-platform settings synchronized live',
    errorMessage: null,
  };

  let exited = false;
  let disposed = false;
  let dirty = false;
  let instructionsExecuted = 0;
  let pc = 0x5000;
  let lastSyscall = 'config.system.getAll';
  let windowId = null;
  const unsubs = [];

  const collectPermissionMatrix = () => {
    const appIds = new Set();
    if (os.pkgManager?.isReady()) {
      for (const pkg of os.pkgManager.list()) appIds.add(pkg.appId);
    }
    if (os.systemApps) {
      for (const sys of os.systemApps.list()) appIds.add(sys.appId);
    }
    const grants = os.permissions?.isReady ? os.permissions.listGrants() : [];
    const grantLookup = new Map();
    for (const g of grants) {
      appIds.add(g.appId);
      grantLookup.set(`${g.appId}::${g.capability}`, g.state);
    }

    const matrix = [];
    for (const appId of Array.from(appIds).sort()) {
      const capabilities = {};
      for (const cap of ALL_CAPABILITIES) {
        capabilities[cap] = grantLookup.get(`${appId}::${cap}`) ?? DEFAULT_CAPABILITY_POLICIES[cap] ?? 'prompt';
      }
      matrix.push({ appId, capabilities });
    }
    return matrix;
  };

  const collectData = () => {
    const configReady = Boolean(os.configStore?.isReady());
    const systemSettings = configReady ? os.configStore.system.getAll() : {};
    const shellMode = os.compositor?.getSnapshot?.().shellMode ?? systemSettings['system.shellMode'] ?? 'unified';

    const permissionMatrix = collectPermissionMatrix();
    const pendingPrompts = os.permissions ? os.permissions.getPendingPrompts() : [];
    const auditLog = os.permissions?.isReady
      ? os.permissions.getAuditLog({
          ...(state.auditFilterAppId ? { appId: state.auditFilterAppId } : {}),
          limit: 100,
        })
      : [];

    let registryView = { hive: state.regHive, keyPath: state.regKeyPath, exists: false, subkeys: [], values: {} };
    let defaultsDomains = [];
    let defaultsValues = {};
    let defaultsPlistXml = '';
    let prefsValues = {};

    const regCtx = { uid: pcb.uid, privileged: pcb.uid === 0 };

    if (configReady) {
      try {
        registryView = os.configStore.registry.enumKey(state.regHive, state.regKeyPath, regCtx);
      } catch (err) {
        registryView.error = err?.message ?? String(err);
      }
      try {
        defaultsDomains = os.configStore.defaults.listDomains();
        defaultsValues = os.configStore.defaults.readDomain(state.defaultsDomain);
        defaultsPlistXml = os.configStore.defaults.exportPlistXml(state.defaultsDomain);
      } catch (err) {
        defaultsValues = { _error: err?.message ?? String(err) };
      }
      try {
        prefsValues = os.configStore.sharedPrefs.getAll(state.prefsPackage, state.prefsName);
      } catch (err) {
        prefsValues = { _error: err?.message ?? String(err) };
      }
    }

    return {
      shellMode,
      systemSettings,
      permissionMatrix,
      pendingPrompts,
      auditLog,
      registryView,
      defaultsDomains,
      defaultsValues,
      defaultsPlistXml,
      prefsValues,
    };
  };

  const buildUiTree = (data) => ({
    id: 'settings-root',
    type: 'container',
    role: 'settings',
    props: {
      appId: SETTINGS_APP_DESCRIPTOR.appId,
      activeSection: state.activeSection,
      shellMode: data.shellMode,
      systemSettings: data.systemSettings,
      canonicalSystemKeys: CANONICAL_SYSTEM_KEYS,
      capabilities: ALL_CAPABILITIES,
      pendingPromptCount: data.pendingPrompts.length,
      auditCount: data.auditLog.length,
      statusMessage: state.statusMessage,
      errorMessage: state.errorMessage,
    },
    children: [
      {
        id: 'settings-nav',
        type: 'toolbar',
        props: { activeSection: state.activeSection },
        children: SETTINGS_SECTIONS.map((sec) => ({
          id: `section-${sec}`,
          type: 'button',
          props: { label: sec.toUpperCase(), action: 'set_section', section: sec, active: state.activeSection === sec },
        })),
      },
      {
        id: 'settings-shell-modes',
        type: 'row',
        props: { currentMode: data.shellMode },
        children: SHELL_MODES.map((mode) => ({
          id: `shell-mode-${mode}`,
          type: 'button',
          props: {
            label: mode.toUpperCase(),
            action: 'set_shell_mode',
            mode,
            active: data.shellMode === mode,
          },
        })),
      },
      {
        id: 'settings-body',
        type: 'panel',
        props: {
          section: state.activeSection,
          systemSettings: data.systemSettings,
          permissionMatrix: data.permissionMatrix,
          pendingPrompts: data.pendingPrompts,
          registry: data.registryView,
          defaults: {
            domain: state.defaultsDomain,
            domains: data.defaultsDomains,
            values: data.defaultsValues,
            plistXml: data.defaultsPlistXml,
          },
          sharedPrefs: {
            packageName: state.prefsPackage,
            prefName: state.prefsName,
            values: data.prefsValues,
          },
          auditLog: data.auditLog,
        },
        children:
          state.activeSection === 'general'
            ? CANONICAL_SYSTEM_KEYS.map((key) => ({
                id: `sys-${key}`,
                type: 'setting',
                props: { key, value: data.systemSettings[key] },
              }))
            : state.activeSection === 'permissions'
              ? data.permissionMatrix.map((row) => ({
                  id: `perm-app-${row.appId}`,
                  type: 'row',
                  props: { appId: row.appId, capabilities: row.capabilities },
                }))
              : state.activeSection === 'audit'
                ? data.auditLog.map((entry) => ({
                    id: `audit-${entry.id}`,
                    type: 'row',
                    props: entry,
                  }))
                : [],
      },
      {
        id: 'settings-status',
        type: 'statusbar',
        props: {
          text: state.errorMessage ? `Error: ${state.errorMessage}` : state.statusMessage,
          error: state.errorMessage,
        },
      },
    ],
  });

  const renderSurface = () => {
    if (disposed || !windowId || !os.compositor) return;
    if (!os.compositor.getWindow(windowId)) return;
    const data = collectData();
    try {
      os.compositor.updateSurface(windowId, {
        title: `Settings & Privacy — ${state.activeSection} (${data.shellMode})`,
        menuBar: SETTINGS_MENU_BAR,
        uiTree: buildUiTree(data),
      });
      dirty = false;
    } catch (err) {
      os.kernel?.log('warn', 'settings-app', `Failed to update Settings surface: ${err.message}`);
    }
  };

  const dispose = (reason = 'disposed') => {
    if (disposed) return;
    disposed = true;
    exited = true;
    while (unsubs.length > 0) {
      const fn = unsubs.pop();
      if (typeof fn === 'function') fn();
    }
    if (windowId && os.compositor?.getWindow(windowId)) {
      try {
        os.compositor.closeWindow(windowId, { notifyProcess: false, reason });
      } catch (err) {
        os.kernel?.log('debug', 'settings-app', `Window already closed on dispose: ${err.message}`);
      }
    }
  };

  const handleEvent = (event) => {
    if (!event || typeof event !== 'object' || disposed) return;
    pc += 2;
    instructionsExecuted += 5;

    if (event.type === 'window_close' || event.type === 'terminate') {
      lastSyscall = 'window_close';
      dispose(event.type);
      return;
    }

    try {
      if (event.type === 'menu_action') {
        const aid = event.actionId ?? event.itemId ?? event.id ?? '';
        if (aid === 'settings.refresh') {
          state.errorMessage = null;
          renderSurface();
        } else if (aid === 'settings.close') {
          lastSyscall = 'menu_close';
          dispose('menu_close');
        } else if (aid.startsWith('section.')) {
          const sec = aid.slice('section.'.length);
          if (SETTINGS_SECTIONS.includes(sec)) {
            state.activeSection = sec;
            renderSurface();
          }
        }
        return;
      }

      const action = event.action ?? '';
      const targetId = event.targetId ?? '';

      if (action === 'set_section' || targetId.startsWith('section-')) {
        const sec = event.section ?? targetId.slice('section-'.length);
        if (SETTINGS_SECTIONS.includes(sec)) {
          state.activeSection = sec;
          state.errorMessage = null;
          state.statusMessage = `Section: ${sec}`;
          renderSurface();
        }
        return;
      }

      if (action === 'set_shell_mode' || targetId.startsWith('shell-mode-')) {
        const mode = String(event.mode ?? event.value ?? targetId.slice('shell-mode-'.length));
        lastSyscall = `compositor.setShellMode:${mode}`;
        os.compositor.setShellMode(mode);
        if (os.configStore?.isReady()) {
          os.configStore.system.set('system.shellMode', mode);
        }
        state.errorMessage = null;
        state.statusMessage = `Shell mode switched to ${mode}`;
        renderSurface();
        return;
      }

      if (action === 'set_system') {
        const rawKey = String(event.key ?? '');
        const key = rawKey.startsWith('system.') ? rawKey : `system.${rawKey}`;
        lastSyscall = `config.system.set:${key}`;
        os.configStore.system.set(key, event.value);
        if (key === 'system.shellMode') {
          os.compositor.setShellMode(String(event.value));
        }
        state.errorMessage = null;
        state.statusMessage = `Updated ${key} = ${JSON.stringify(event.value)}`;
        renderSurface();
        return;
      }

      if (action === 'toggle_system') {
        const rawKey = String(event.key ?? '');
        const key = rawKey.startsWith('system.') ? rawKey : `system.${rawKey}`;
        const cur = os.configStore.system.get(key);
        const next = key === 'system.theme' ? (cur === 'dark' ? 'light' : 'dark') : !cur;
        os.configStore.system.set(key, next);
        lastSyscall = `config.system.toggle:${key}`;
        state.errorMessage = null;
        state.statusMessage = `Toggled ${key} -> ${JSON.stringify(next)}`;
        renderSurface();
        return;
      }

      if (action === 'set_grant') {
        const appId = String(event.appId ?? '');
        const capability = String(event.capability ?? '');
        const grantState = String(event.state ?? event.value ?? 'prompt');
        lastSyscall = 'security.setGrant';
        os.permissions.setGrant(appId, capability, grantState, { source: 'settings' });
        state.errorMessage = null;
        state.statusMessage = `Permission ${appId} [${capability}] = ${grantState}`;
        renderSurface();
        return;
      }

      if (action === 'resolve_prompt') {
        const promptId = String(event.promptId ?? '');
        const decision = event.decision ?? 'deny_once';
        lastSyscall = 'security.resolvePrompt';
        const res = os.permissions.resolvePrompt(promptId, decision);
        state.errorMessage = null;
        state.statusMessage = res.ok
          ? `Resolved prompt ${promptId}: ${res.decision}`
          : `Prompt ${promptId} not found`;
        renderSurface();
        return;
      }

      if (action === 'reg_navigate') {
        if (event.hive) state.regHive = String(event.hive).toUpperCase();
        if (event.keyPath !== undefined) state.regKeyPath = String(event.keyPath);
        state.errorMessage = null;
        state.statusMessage = `Registry: ${state.regHive}\\${state.regKeyPath}`;
        renderSurface();
        return;
      }

      if (action === 'reg_set') {
        const hive = String(event.hive ?? state.regHive).toUpperCase();
        const keyPath = String(event.keyPath ?? state.regKeyPath);
        const valueName = String(event.valueName ?? event.name ?? '');
        const rawRegType =
          event.regType ??
          event.valueType ??
          (typeof event.type === 'string' && event.type.toUpperCase().startsWith('REG_')
            ? event.type
            : 'REG_SZ');
        const type = String(rawRegType).toUpperCase();
        const regCtx = { uid: pcb.uid, privileged: pcb.uid === 0 };
        lastSyscall = 'config.registry.setValue';
        os.configStore.registry.setValue(hive, keyPath, valueName, type, event.data ?? event.value ?? '', regCtx);
        state.regHive = hive;
        state.regKeyPath = keyPath;
        state.errorMessage = null;
        state.statusMessage = `Saved ${hive}\\${keyPath}\\${valueName}`;
        renderSurface();
        return;
      }

      if (action === 'reg_delete') {
        const hive = String(event.hive ?? state.regHive).toUpperCase();
        const keyPath = String(event.keyPath ?? state.regKeyPath);
        const valueName = event.valueName ?? event.name;
        const regCtx = { uid: pcb.uid, privileged: pcb.uid === 0 };
        lastSyscall = 'config.registry.delete';
        if (valueName) {
          os.configStore.registry.deleteValue(hive, keyPath, String(valueName), regCtx);
        } else {
          os.configStore.registry.deleteKey(hive, keyPath, regCtx);
        }
        state.errorMessage = null;
        state.statusMessage = `Deleted registry target`;
        renderSurface();
        return;
      }

      if (action === 'defaults_select') {
        if (event.domain) state.defaultsDomain = String(event.domain);
        state.errorMessage = null;
        renderSurface();
        return;
      }

      if (action === 'defaults_set') {
        const domain = String(event.domain ?? state.defaultsDomain);
        const key = String(event.key ?? '');
        lastSyscall = 'config.defaults.set';
        os.configStore.defaults.set(domain, key, event.value);
        state.defaultsDomain = domain;
        state.errorMessage = null;
        state.statusMessage = `Updated defaults ${domain}.${key}`;
        renderSurface();
        return;
      }

      if (action === 'defaults_delete') {
        const domain = String(event.domain ?? state.defaultsDomain);
        const key = String(event.key ?? '');
        lastSyscall = 'config.defaults.remove';
        os.configStore.defaults.remove(domain, key);
        state.errorMessage = null;
        state.statusMessage = `Removed defaults ${domain}.${key}`;
        renderSurface();
        return;
      }

      if (action === 'prefs_select') {
        if (event.packageName) state.prefsPackage = String(event.packageName);
        if (event.prefName) state.prefsName = String(event.prefName);
        state.errorMessage = null;
        renderSurface();
        return;
      }

      if (action === 'prefs_set') {
        const pkg = String(event.packageName ?? state.prefsPackage);
        const pref = String(event.prefName ?? state.prefsName);
        const key = String(event.key ?? '');
        lastSyscall = 'config.sharedPrefs.edit';
        os.configStore.sharedPrefs.edit(pkg, pref, [{ op: 'put', key, value: event.value, type: event.valueType }]);
        state.prefsPackage = pkg;
        state.prefsName = pref;
        state.errorMessage = null;
        state.statusMessage = `Saved SharedPref ${pkg}/${pref}/${key}`;
        renderSurface();
        return;
      }

      if (action === 'prefs_remove') {
        const pkg = String(event.packageName ?? state.prefsPackage);
        const pref = String(event.prefName ?? state.prefsName);
        const key = String(event.key ?? '');
        lastSyscall = 'config.sharedPrefs.edit';
        os.configStore.sharedPrefs.edit(pkg, pref, [{ op: 'remove', key }]);
        state.errorMessage = null;
        state.statusMessage = `Removed SharedPref ${pkg}/${pref}/${key}`;
        renderSurface();
        return;
      }

      if (action === 'audit_filter') {
        state.auditFilterAppId = event.appId ? String(event.appId) : null;
        state.errorMessage = null;
        renderSurface();
        return;
      }

      if (action === 'refresh') {
        state.errorMessage = null;
        renderSurface();
      }
    } catch (err) {
      state.errorMessage = err?.message ?? String(err);
      renderSurface();
    }
  };

  const initialData = collectData();
  const win = os.compositor.createWindow(pcb.pid, {
    appId: SETTINGS_APP_DESCRIPTOR.appId,
    platform: 'system',
    title: `Settings & Privacy — ${state.activeSection} (${initialData.shellMode})`,
    icon: SETTINGS_APP_DESCRIPTOR.icon,
    width: 860,
    height: 600,
    chromeStyle: 'unified',
    menuBar: SETTINGS_MENU_BAR,
    uiTree: buildUiTree(initialData),
  });
  windowId = win.windowId;

  if (os.eventBus && typeof os.eventBus.on === 'function') {
    for (const evName of ['config:changed', 'security:grant_changed', 'permission:prompt', 'permission:resolved']) {
      unsubs.push(
        os.eventBus.on(evName, () => {
          if (!disposed) dirty = true;
        })
      );
    }
  }

  return {
    windowId,
    step(budget = 100) {
      void budget;
      if (dirty && !disposed) {
        renderSurface();
      }
      if (exited || disposed) {
        return { status: 'EXITED', exitCode: 0, instructionsExecuted: 1 };
      }
      return { status: 'BLOCKED', waitReason: 'ui_event', instructionsExecuted: 1 };
    },
    deliverEvent(event) {
      handleEvent(event);
    },
    getDebugState() {
      const data = collectData();
      return {
        arch: 'native',
        appId: SETTINGS_APP_DESCRIPTOR.appId,
        pc,
        sp: 0x7ffb0000,
        registers: {
          r0: SETTINGS_SECTIONS.indexOf(state.activeSection),
          r1: data.pendingPrompts.length,
          r2: data.auditLog.length,
        },
        instructionsExecuted,
        lastSyscall,
        stackTop: 0x7ffb0000,
        windowId,
        stateSummary: {
          activeSection: state.activeSection,
          shellMode: data.shellMode,
          pendingPrompts: data.pendingPrompts.length,
          auditEntries: data.auditLog.length,
        },
      };
    },
    dispose() {
      dispose('disposed');
    },
  };
}
