// OmniOS M6 Browser GUI Boot Coordinator
// Connects live /ws stream, hydrates all 7 kernel REST subsystems, and wires
// CompositorUI, ShellModeController, and OverlaysController cleanly.

import { createOmniClient } from './ws-client.js';
import { createCompositorUI } from './compositor-ui.js';
import { createShellModeController } from './shell-modes.js';
import { createOverlaysController } from './overlays.js';

async function bootOmniUI() {
  const windowLayerEl = document.getElementById('window-layer');
  const snapPreviewEl = document.getElementById('snap-preview-ghost');

  const client = createOmniClient();

  let shellController = null;
  let compositorUI = null;
  let overlays = null;
  let hasConnectedOnce = false;
  let hasWsCompositorState = false;

  // Debounced background sync timers (prevent REST spam during rapid process/window bursts)
  let procRefreshTimer = null;
  let pkgRefreshTimer = null;

  async function refreshProcesses() {
    try {
      const res = await client.listProcesses();
      if (res && Array.isArray(res.processes)) {
        shellController?.setProcesses(res.processes);
      }
    } catch {
      // ignore transient network error
    }
  }

  async function refreshPackages() {
    try {
      const [pkgRes, catRes] = await Promise.all([client.listPackages(), client.getCatalog()]);
      shellController?.setPackagesData({
        systemApps: pkgRes?.systemApps ?? catRes?.systemApps ?? [],
        packages: pkgRes?.packages ?? [],
        catalog: catRes?.catalog ?? [],
      });
    } catch {
      // ignore transient network error
    }
  }

  function scheduleRefreshProcesses() {
    if (procRefreshTimer) return;
    procRefreshTimer = setTimeout(() => {
      procRefreshTimer = null;
      refreshProcesses();
    }, 220);
  }

  function scheduleRefreshPackages() {
    if (pkgRefreshTimer) return;
    pkgRefreshTimer = setTimeout(() => {
      pkgRefreshTimer = null;
      refreshPackages();
    }, 300);
  }

  compositorUI = createCompositorUI({
    windowLayerEl,
    snapPreviewEl,
    client,
    onStateChange: (state) => {
      shellController?.handleCompositorStateChange(state);
    },
  });

  overlays = createOverlaysController({
    client,
    onLaunchApp: async (appId, opts = {}) => {
      try {
        await client.launchApp(appId, opts);
      } catch {
        // kernel/app handles errors cleanly
      }
    },
    onSwitchShellMode: (mode) => {
      shellController?.switchShellMode(mode);
    },
    onToggleTheme: () => {
      shellController?.toggleSystemKey('system.theme');
    },
    onToggleDnd: () => {
      shellController?.toggleSystemKey('system.dnd');
    },
    onFocusProcess: (pid) => {
      const win = compositorUI.getWindows().find((w) => Number(w.pid) === Number(pid));
      if (win) {
        compositorUI.focusWindow(win.windowId);
      } else {
        client.launchApp('com.omnios.monitor', { preferSystem: true }).catch(() => {});
      }
    },
    onRefreshPackages: refreshPackages,
  });

  shellController = createShellModeController({
    client,
    compositorUI,
    overlays,
  });

  // Wire all live WebSocket server events
  client.on('ws:open', () => {
    shellController.setWsConnected(true);
    if (hasConnectedOnce) {
      // Re-sync REST state cleanly after a reconnect
      hydrateNonSnapshotSubsystems();
    }
    hasConnectedOnce = true;
  });

  client.on('ws:close', () => {
    shellController.setWsConnected(false);
  });

  client.on('compositor:snapshot', (payload) => {
    hasWsCompositorState = true;
    compositorUI.applySnapshot(payload);
  });

  client.on('compositor:window_created', (payload) => {
    hasWsCompositorState = true;
    compositorUI.handleWindowCreated(payload);
    scheduleRefreshProcesses();
    scheduleRefreshPackages();
  });

  client.on('compositor:window_updated', (payload) => {
    hasWsCompositorState = true;
    compositorUI.handleWindowUpdated(payload);
  });

  client.on('compositor:surface_patch', (payload) => {
    compositorUI.handleSurfacePatch(payload);
    const win = payload?.windowId ? compositorUI.getWindow(payload.windowId) : null;
    if (win && win.appId === 'com.omnios.apphub') {
      // Keep Dock / Start Menu / SpringBoard / Drawer in sync after App Hub installs/uninstalls
      scheduleRefreshPackages();
    }
  });

  client.on('compositor:window_closed', (payload) => {
    hasWsCompositorState = true;
    compositorUI.handleWindowClosed(payload);
    scheduleRefreshProcesses();
    scheduleRefreshPackages();
  });

  client.on('process:update', () => {
    scheduleRefreshProcesses();
    scheduleRefreshPackages();
  });

  client.on('notification:posted', (payload) => {
    shellController.handleNotificationPosted(payload);
  });

  client.on('notification:updated', (payload) => {
    shellController.handleNotificationUpdated(payload);
  });

  client.on('config:changed', (payload) => {
    shellController.handleConfigChanged(payload);
  });

  client.on('permission:prompt', (payload) => {
    overlays.enqueuePermissionPrompt(payload);
  });

  client.on('intent:chooser', (payload) => {
    overlays.openIntentChooser(payload);
  });

  client.on('kernel:event', (payload) => {
    const evt = String(payload?.event ?? '');
    if (evt.startsWith('kernel:') || evt.startsWith('service:')) {
      scheduleRefreshProcesses();
    }
  });

  async function hydrateNonSnapshotSubsystems() {
    const cfgSeq = shellController.getConfigSyncSeq();
    const [pkgR, catR, cfgR, notifR, procR, permR] = await Promise.allSettled([
      client.listPackages(),
      client.getCatalog(),
      client.getSystemConfig(),
      client.getNotifications(),
      client.listProcesses(),
      client.getPermissions(),
    ]);

    if (cfgR.status === 'fulfilled' && cfgR.value) {
      shellController.applySystemConfig(cfgR.value.system ?? cfgR.value.values ?? {}, cfgSeq);
    }

    const pkgVal = pkgR.status === 'fulfilled' ? pkgR.value : null;
    const catVal = catR.status === 'fulfilled' ? catR.value : null;
    if (pkgVal || catVal) {
      shellController.setPackagesData({
        systemApps: pkgVal?.systemApps ?? catVal?.systemApps ?? [],
        packages: pkgVal?.packages ?? [],
        catalog: catVal?.catalog ?? [],
      });
    }

    if (notifR.status === 'fulfilled' && notifR.value) {
      shellController.setNotificationsData({
        notifications: notifR.value.notifications ?? [],
        liveActivities: notifR.value.liveActivities ?? [],
      });
    }

    if (procR.status === 'fulfilled' && Array.isArray(procR.value?.processes)) {
      shellController.setProcesses(procR.value.processes);
    }

    if (permR.status === 'fulfilled' && Array.isArray(permR.value?.pendingPrompts)) {
      for (const prompt of permR.value.pendingPrompts) {
        overlays.enqueuePermissionPrompt(prompt);
      }
    }
  }

  async function hydrateAll() {
    const [snapR] = await Promise.allSettled([
      client.getSnapshot(),
      hydrateNonSnapshotSubsystems(),
    ]);
    if (snapR.status === 'fulfilled' && snapR.value && !hasWsCompositorState) {
      compositorUI.applySnapshot(snapR.value);
    }
    shellController.setHydrated(true);
  }

  // Minimal read-only diagnostic handle for legitimate inspection (zero mutators)
  window.__OMNIOS_UI__ = Object.freeze({
    isConnected: () => client.isConnected(),
    getState: () => ({
      wsConnected: client.isConnected(),
      shell: shellController.getState(),
      overlays: overlays.getState(),
      windows: compositorUI.getWindows().map((w) => ({
        windowId: w.windowId,
        pid: w.pid,
        appId: w.appId,
        platform: w.platform,
        title: w.title,
        state: w.state,
        focused: w.focused,
        surfaceRevision: w.surfaceRevision,
      })),
    }),
  });

  // Start WebSocket connection and parallel REST hydration
  client.connect();
  await hydrateAll();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      bootOmniUI();
    });
  } else {
    bootOmniUI();
  }
}
