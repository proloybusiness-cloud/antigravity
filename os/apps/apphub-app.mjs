/**
 * OmniOS Built-in System App: App Hub (`com.omnios.apphub`, F-070)
 * 4-Platform + Universal App Store & Package Manager UI merging `pkgManager.getCatalog()` + `pkgManager.list()`.
 * Supports platform filtering, package inspection preview, one-click install from VFS catalog or raw bytes,
 * launch, stop, and uninstall. Zero host filesystem access.
 */

export const APPHUB_APP_DESCRIPTOR = Object.freeze({
  appId: 'com.omnios.apphub',
  aliases: Object.freeze(['apphub', 'app-hub']),
  name: 'App Hub',
  title: 'OmniOS App Hub — 4-Platform Store',
  platform: 'system',
  category: 'Store',
  icon: 'store',
  description: 'Discover, inspect, install, launch & manage Android, Windows, iOS, macOS & Universal apps',
});

export const APPHUB_PLATFORMS = Object.freeze(['all', 'android', 'windows', 'ios', 'macos', 'universal']);

const APPHUB_MENU_BAR = Object.freeze([
  {
    id: 'apphub',
    label: 'App Hub',
    items: [
      { id: 'apphub.refresh', label: 'Refresh Catalog' },
      { id: 'apphub.close', label: 'Close Window' },
    ],
  },
  {
    id: 'platforms',
    label: 'Platform',
    items: [
      { id: 'filter.all', label: 'All Platforms' },
      { id: 'filter.android', label: 'Android (.apk)' },
      { id: 'filter.windows', label: 'Windows (.exe/.msix)' },
      { id: 'filter.ios', label: 'iOS (.ipa)' },
      { id: 'filter.macos', label: 'macOS (.app/.dmg)' },
      { id: 'filter.universal', label: 'Universal (.uapp/.wasm)' },
    ],
  },
]);

function decodePayloadBytes(event) {
  if (event.bytes instanceof Uint8Array) return event.bytes;
  if (typeof event.base64 === 'string' && event.base64.length > 0) {
    return new Uint8Array(Buffer.from(event.base64, 'base64'));
  }
  return null;
}

export function createAppHubExecutionContext(os, pcb, launchOpts = {}) {
  const initFilter = APPHUB_PLATFORMS.includes(launchOpts.platform) ? launchOpts.platform : 'all';

  const state = {
    platformFilter: initFilter,
    searchQuery: '',
    inspectedPackage: null,
    lastLaunchResult: null,
    statusMessage: 'Browse and manage cross-platform apps',
    errorMessage: null,
  };

  let exited = false;
  let disposed = false;
  let dirty = false;
  let instructionsExecuted = 0;
  let pc = 0x4000;
  let lastSyscall = 'pkg.catalog';
  let windowId = null;
  let pendingAsync = Promise.resolve();
  const unsubs = [];

  const buildMergedItems = () => {
    if (!os.pkgManager?.isReady()) return [];
    const filterOpt = state.platformFilter !== 'all' ? { platform: state.platformFilter } : {};
    const catalog = os.pkgManager.getCatalog(filterOpt);
    const installed = os.pkgManager.list(filterOpt);
    const runningProcs = os.processManager.list({ includeTerminated: false });

    const runningMap = new Map();
    for (const p of runningProcs) {
      if (p.platform === 'system' || p.platform === 'kernel') continue;
      if (!runningMap.has(p.appId)) runningMap.set(p.appId, []);
      runningMap.get(p.appId).push(p.pid);
    }

    const byAppId = new Map();
    for (const cat of catalog) {
      byAppId.set(cat.appId, {
        catalogId: cat.catalogId,
        appId: cat.appId,
        name: cat.name,
        platform: cat.platform,
        format: cat.format,
        version: cat.version,
        description: cat.description ?? '',
        icon: cat.icon ?? null,
        packagePath: cat.packagePath ?? null,
        sha256: cat.sha256 ?? null,
        sizeBytes: cat.sizeBytes ?? 0,
        arch: cat.metadata?.arch ?? 'native',
        category: cat.metadata?.category ?? 'Apps',
        installed: false,
        runningPids: runningMap.get(cat.appId) ?? [],
      });
    }

    for (const inst of installed) {
      const existing = byAppId.get(inst.appId);
      byAppId.set(inst.appId, {
        catalogId: existing?.catalogId ?? inst.appId,
        appId: inst.appId,
        name: inst.name,
        platform: inst.platform,
        format: inst.format,
        version: inst.version,
        description: existing?.description ?? '',
        icon: existing?.icon ?? null,
        packagePath: existing?.packagePath ?? null,
        sha256: inst.sha256,
        sizeBytes: inst.sizeBytes,
        arch: inst.arch,
        category: existing?.category ?? 'Installed',
        installed: true,
        installDir: inst.installDir,
        permissions: inst.permissions ?? [],
        runningPids: runningMap.get(inst.appId) ?? [],
      });
    }

    let items = Array.from(byAppId.values());
    const q = state.searchQuery.trim().toLowerCase();
    if (q) {
      items = items.filter(
        (it) =>
          it.name.toLowerCase().includes(q) ||
          it.appId.toLowerCase().includes(q) ||
          it.platform.toLowerCase().includes(q) ||
          it.description.toLowerCase().includes(q)
      );
    }
    return items.sort((a, b) => a.name.localeCompare(b.name));
  };

  const buildUiTree = (items) => ({
    id: 'apphub-root',
    type: 'container',
    role: 'app-store',
    props: {
      appId: APPHUB_APP_DESCRIPTOR.appId,
      platformFilter: state.platformFilter,
      searchQuery: state.searchQuery,
      totalItems: items.length,
      installedCount: items.filter((i) => i.installed).length,
      inspectedPackage: state.inspectedPackage,
      lastLaunchResult: state.lastLaunchResult,
      statusMessage: state.statusMessage,
      errorMessage: state.errorMessage,
    },
    children: [
      {
        id: 'apphub-toolbar',
        type: 'toolbar',
        props: { platformFilter: state.platformFilter, searchQuery: state.searchQuery },
        children: [
          ...APPHUB_PLATFORMS.map((plat) => ({
            id: `filter-${plat}`,
            type: 'button',
            props: {
              label: plat.toUpperCase(),
              action: 'set_filter',
              platform: plat,
              active: state.platformFilter === plat,
            },
          })),
          {
            id: 'apphub-search',
            type: 'input',
            props: { value: state.searchQuery, placeholder: 'Search 4-platform apps...' },
          },
          { id: 'apphub-refresh', type: 'button', props: { label: 'Refresh', action: 'refresh' } },
        ],
      },
      {
        id: 'apphub-grid',
        type: 'list',
        props: { count: items.length },
        children: items.map((item) => ({
          id: `app-${item.appId}`,
          type: 'card',
          props: {
            catalogId: item.catalogId,
            appId: item.appId,
            name: item.name,
            platform: item.platform,
            format: item.format,
            arch: item.arch,
            version: item.version,
            description: item.description,
            packagePath: item.packagePath,
            sizeBytes: item.sizeBytes,
            installed: item.installed,
            runningPids: item.runningPids,
          },
        })),
      },
      {
        id: 'apphub-inspector-preview',
        type: 'panel',
        props: { inspection: state.inspectedPackage },
      },
      {
        id: 'apphub-status',
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
    const items = buildMergedItems();
    try {
      os.compositor.updateSurface(windowId, {
        title: `App Hub — ${items.length} Apps (${state.platformFilter})`,
        menuBar: APPHUB_MENU_BAR,
        uiTree: buildUiTree(items),
      });
      dirty = false;
    } catch (err) {
      os.kernel?.log('warn', 'apphub-app', `Failed to update App Hub surface: ${err.message}`);
    }
  };

  const resolvePackageSource = (event) => {
    const rawBytes = decodePayloadBytes(event);
    if (rawBytes) return { source: rawBytes, hint: event.filenameHint ?? event.filename ?? '' };
    if (typeof event.packagePath === 'string' && event.packagePath.length > 0) {
      return { source: event.packagePath, hint: event.filenameHint ?? event.packagePath };
    }
    const lookupId = event.catalogId ?? event.appId;
    if (lookupId && os.pkgManager?.isReady()) {
      const cat = os.pkgManager.getCatalog().find((c) => c.catalogId === lookupId || c.appId === lookupId);
      if (cat?.packagePath) {
        return { source: cat.packagePath, hint: cat.metadata?.filename ?? cat.packagePath };
      }
    }
    return null;
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
        os.kernel?.log('debug', 'apphub-app', `Window already closed on dispose: ${err.message}`);
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

    if (event.type === 'menu_action') {
      const aid = event.actionId ?? event.itemId ?? event.id ?? '';
      if (aid === 'apphub.refresh') {
        state.errorMessage = null;
        renderSurface();
      } else if (aid === 'apphub.close') {
        lastSyscall = 'menu_close';
        dispose('menu_close');
      } else if (aid.startsWith('filter.')) {
        const plat = aid.slice('filter.'.length);
        if (APPHUB_PLATFORMS.includes(plat)) {
          state.platformFilter = plat;
          renderSurface();
        }
      }
      return;
    }

    if ((event.type === 'input' || event.type === 'change') && event.targetId === 'apphub-search') {
      state.searchQuery = String(event.value ?? '');
      renderSurface();
      return;
    }

    const action = event.action ?? '';
    const targetId = event.targetId ?? '';

    if (action === 'set_filter' || action === 'filter_platform' || targetId.startsWith('filter-')) {
      const plat = event.platform ?? targetId.slice('filter-'.length);
      if (APPHUB_PLATFORMS.includes(plat)) {
        state.platformFilter = plat;
        state.errorMessage = null;
        state.statusMessage = `Filtered by ${plat}`;
        renderSurface();
      }
      return;
    }

    if (action === 'search') {
      state.searchQuery = String(event.query ?? event.value ?? '');
      renderSurface();
      return;
    }

    if (action === 'refresh' || targetId === 'apphub-refresh') {
      state.errorMessage = null;
      state.statusMessage = 'Refreshed catalog';
      renderSurface();
      return;
    }

    if (action === 'inspect') {
      const resolved = resolvePackageSource(event);
      if (!resolved) {
        state.errorMessage = 'No packagePath, catalogId, or bytes supplied to inspect';
        renderSurface();
        return;
      }
      lastSyscall = 'pkg.inspect';
      state.errorMessage = null;
      state.statusMessage = `Inspecting ${resolved.hint || 'package'}...`;
      renderSurface();

      pendingAsync = pendingAsync
        .then(async () => {
          const insp = await os.pkgManager.inspect(resolved.source, resolved.hint);
          state.inspectedPackage = insp;
          state.statusMessage = `Inspected ${insp.name} (${insp.platform}/${insp.arch})`;
          if (!disposed) renderSurface();
        })
        .catch((err) => {
          state.errorMessage = err?.message ?? String(err);
          if (!disposed) renderSurface();
        });
      return;
    }

    if (action === 'install') {
      const resolved = resolvePackageSource(event);
      if (!resolved) {
        state.errorMessage = 'No packagePath, catalogId, or bytes supplied to install';
        renderSurface();
        return;
      }
      lastSyscall = 'pkg.install';
      state.errorMessage = null;
      state.statusMessage = `Installing ${resolved.hint || 'package'}...`;
      renderSurface();

      pendingAsync = pendingAsync
        .then(async () => {
          const rec = await os.pkgManager.install(resolved.source, {
            filenameHint: resolved.hint,
            grantAll: event.grantAll !== undefined ? Boolean(event.grantAll) : true,
            overwrite: Boolean(event.overwrite),
            upgrade: Boolean(event.upgrade),
            source: 'apphub',
          });
          state.statusMessage = `Installed ${rec.name} (${rec.appId})`;
          if (!disposed) renderSurface();
        })
        .catch((err) => {
          state.errorMessage = err?.message ?? String(err);
          if (!disposed) renderSurface();
        });
      return;
    }

    if (action === 'launch') {
      const appId = String(event.appId ?? '');
      if (!appId) {
        state.errorMessage = 'appId is required to launch';
        renderSurface();
        return;
      }
      lastSyscall = 'pkg.launch';
      state.errorMessage = null;
      state.statusMessage = `Launching ${appId}...`;
      renderSurface();

      pendingAsync = pendingAsync
        .then(async () => {
          const res = await os.pkgManager.launch(appId, {
            args: Array.isArray(event.args) ? event.args : [],
            env: event.env && typeof event.env === 'object' ? event.env : {},
            intent: event.intent ?? null,
          });
          if (os.scheduler) {
            os.scheduler.step(10);
          }
          const windowIds = os.compositor.listWindows({ pid: res.pid }).map((w) => w.windowId);
          state.lastLaunchResult = { ...res, windowIds };
          state.statusMessage = `Launched ${appId} (PID ${res.pid})`;
          if (!disposed) renderSurface();
        })
        .catch((err) => {
          state.errorMessage = err?.message ?? String(err);
          if (!disposed) renderSurface();
        });
      return;
    }

    if (action === 'stop') {
      const explicitPid =
        event.targetPid ??
        event.data?.pid ??
        event.payload?.pid ??
        (event.windowId === undefined && event.pid !== undefined ? event.pid : undefined);
      const target = explicitPid !== undefined ? Number(explicitPid) : String(event.appId ?? '');
      try {
        lastSyscall = 'pkg.stop';
        const res = os.pkgManager.stop(target, { signal: event.signal ?? 'SIGTERM' });
        state.errorMessage = null;
        state.statusMessage = `Stopped PIDs: ${res.stoppedPids.join(', ') || 'none'}`;
        renderSurface();
      } catch (err) {
        state.errorMessage = err?.message ?? String(err);
        renderSurface();
      }
      return;
    }

    if (action === 'uninstall') {
      const appId = String(event.appId ?? '');
      if (!appId) {
        state.errorMessage = 'appId is required to uninstall';
        renderSurface();
        return;
      }
      lastSyscall = 'pkg.uninstall';
      state.errorMessage = null;
      state.statusMessage = `Uninstalling ${appId}...`;
      renderSurface();

      pendingAsync = pendingAsync
        .then(async () => {
          await os.pkgManager.uninstall(appId, { purgeData: Boolean(event.purgeData) });
          state.statusMessage = `Uninstalled ${appId}`;
          if (!disposed) renderSurface();
        })
        .catch((err) => {
          state.errorMessage = err?.message ?? String(err);
          if (!disposed) renderSurface();
        });
    }
  };

  const initialItems = buildMergedItems();
  const win = os.compositor.createWindow(pcb.pid, {
    appId: APPHUB_APP_DESCRIPTOR.appId,
    platform: 'system',
    title: `App Hub — ${initialItems.length} Apps (${state.platformFilter})`,
    icon: APPHUB_APP_DESCRIPTOR.icon,
    width: 860,
    height: 580,
    chromeStyle: 'unified',
    menuBar: APPHUB_MENU_BAR,
    uiTree: buildUiTree(initialItems),
  });
  windowId = win.windowId;

  if (os.eventBus && typeof os.eventBus.on === 'function') {
    for (const evName of ['pkg:installed', 'pkg:uninstalled', 'pkg:launched', 'process:exited']) {
      unsubs.push(
        os.eventBus.on(evName, () => {
          if (!disposed) dirty = true;
        })
      );
    }
  }

  return {
    windowId,
    flushPending: () => pendingAsync,
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
      const items = buildMergedItems();
      return {
        arch: 'native',
        appId: APPHUB_APP_DESCRIPTOR.appId,
        pc,
        sp: 0x7ffc0000,
        registers: {
          r0: items.length,
          r1: items.filter((i) => i.installed).length,
        },
        instructionsExecuted,
        lastSyscall,
        stackTop: 0x7ffc0000,
        windowId,
        stateSummary: {
          platformFilter: state.platformFilter,
          totalItems: items.length,
          installedCount: items.filter((i) => i.installed).length,
          statusMessage: state.statusMessage,
        },
      };
    },
    dispose() {
      dispose('disposed');
    },
  };
}
