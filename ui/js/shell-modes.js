// OmniOS M6 5-Mode Adaptive Shell Controller
// Manages Unified Hybrid, Windows, macOS, iOS, and Android shell chrome, launchers,
// Global Menu Bar, Dynamic Island, Control Center, Notification Shade, and Android Recents.
// Strictly XSS-safe: zero HTML string parsing, textContent & createElement only.

import { normalizeShellMode, isSystemAppId } from './ws-client.js';

const PLATFORM_BADGES = Object.freeze({
  android: 'AND',
  windows: 'WIN',
  ios: 'iOS',
  macos: 'MAC',
  universal: 'WASM',
  system: 'SYS',
});

const APP_GLYPHS = Object.freeze({
  terminal: '>_',
  folder: 'DIR',
  activity: 'CPU',
  store: 'HUB',
  settings: 'CFG',
  'search-code': 'BIN',
  notes: 'TXT',
  calculator: '123',
  notepad: 'DOC',
  weather: 'SKY',
  studio: 'MAC',
  canvas: 'GFX',
});

function el(tag, className = '', attrs = null, text = null) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v !== undefined && v !== null) node.setAttribute(k, String(v));
    }
  }
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  return node;
}

function getPlatformBadge(platform) {
  const key = String(platform || 'system').toLowerCase();
  return PLATFORM_BADGES[key] || key.slice(0, 4).toUpperCase();
}

function getAppGlyph(icon, name) {
  if (typeof icon === 'string' && APP_GLYPHS[icon]) return APP_GLYPHS[icon];
  const fallback = String(name || 'APP').trim().slice(0, 3).toUpperCase();
  return fallback || 'APP';
}

function formatClock(date = new Date()) {
  const hh = String(date.getHours()).padStart(2, '0');
  const mm = String(date.getMinutes()).padStart(2, '0');
  return `${hh}:${mm}`;
}

export class ShellModeController {
  constructor({ client, compositorUI, overlays } = {}) {
    this._client = client;
    this._compositorUI = compositorUI;
    this._overlays = overlays;

    this._shellMode = 'unified';
    this._chromeMode = 'adaptive';
    this._systemConfig = {
      'system.theme': 'dark',
      'system.shellMode': 'unified',
      'system.volume': 75,
      'system.brightness': 80,
      'system.wifi': true,
      'system.bluetooth': true,
      'system.dnd': false,
      'system.locale': 'en-US',
    };

    this._systemApps = [];
    this._packages = [];
    this._catalog = [];
    this._processes = [];
    this._windows = [];
    this._focusedWindowId = null;
    this._activeMenuBar = [];
    this._notifications = [];
    this._liveActivities = new Map();
    this._selectedActivityId = null;
    this._openMenuId = null;
    this._clockTimer = null;

    this._dom = this._queryDom();
    this._bindEvents();
    this._startClock();
    this._applyShellModeDom('unified');
    this._applySystemConfigDom();
  }

  _queryDom() {
    const byId = (id) => (typeof document !== 'undefined' ? document.getElementById(id) : null);
    return {
      shell: byId('omni-shell'),
      globalMenuBar: byId('global-menu-bar'),
      menuDropdown: byId('menu-bar-dropdown'),
      dynamicIsland: byId('dynamic-island'),
      diPill: byId('dynamic-island-pill'),
      diLeading: byId('di-leading'),
      diTitle: byId('di-title'),
      diTrailing: byId('di-trailing'),
      diExpTitle: byId('di-exp-title'),
      diExpSubtitle: byId('di-exp-subtitle'),
      diExpBody: byId('di-exp-body'),
      diExpProgressBar: byId('di-exp-progress-bar'),
      diExpProgressFill: byId('di-exp-progress-fill'),
      diExpActions: byId('di-exp-actions'),
      diExpList: byId('di-exp-list'),
      btnSpotlight: byId('btn-spotlight'),
      btnUploadPkg: byId('btn-upload-pkg'),
      btnControlCenter: byId('btn-control-center'),
      btnNotifShade: byId('btn-notif-shade'),
      notifBadge: byId('notif-badge'),
      btnThemeToggle: byId('btn-theme-toggle'),
      btnChromeToggle: byId('btn-chrome-toggle'),
      wsStatusIndicator: byId('ws-status-indicator'),
      wsStatusText: byId('ws-status-text'),
      topClock: byId('top-clock'),
      desktopShortcuts: byId('desktop-shortcuts'),
      toastStack: byId('toast-stack'),
      dockApps: byId('dock-apps'),
      dockMinimized: byId('dock-minimized'),
      dockSeparator: byId('dock-separator'),
      btnWinStart: byId('btn-win-start'),
      btnWinSearch: byId('btn-win-search'),
      winTaskbarApps: byId('win-taskbar-apps'),
      btnWinTrayCc: byId('btn-win-tray-cc'),
      btnWinTrayNotifs: byId('btn-win-tray-notifs'),
      winNotifBadge: byId('win-notif-badge'),
      winTrayClock: byId('win-tray-clock'),
      winStartMenu: byId('win-start-menu'),
      startSearchInput: byId('start-search-input'),
      startPinnedGrid: byId('start-pinned-grid'),
      startAllAppsList: byId('start-all-apps-list'),
      startFooterActions: byId('start-footer-actions'),
      iosControlCenter: byId('ios-control-center'),
      btnCloseCc: byId('btn-close-cc'),
      ccBrightnessSlider: byId('cc-brightness-slider'),
      ccVolumeSlider: byId('cc-volume-slider'),
      ccBrightnessVal: byId('cc-brightness-val'),
      ccVolumeVal: byId('cc-volume-val'),
      iosSpringboard: byId('ios-springboard'),
      springboardSearch: byId('springboard-search'),
      springboardGrid: byId('springboard-grid'),
      appLibraryGrid: byId('app-library-grid'),
      btnIosHome: byId('btn-ios-home'),
      btnIosSwitcher: byId('btn-ios-switcher'),
      btnIosCcPull: byId('btn-ios-cc-pull'),
      androidShade: byId('android-shade'),
      qsBrightnessSlider: byId('qs-brightness-slider'),
      qsVolumeSlider: byId('qs-volume-slider'),
      btnClearNotifs: byId('btn-clear-notifs'),
      btnCloseShade: byId('btn-close-shade'),
      shadeNotifList: byId('shade-notif-list'),
      androidAppDrawer: byId('android-app-drawer'),
      drawerSearchInput: byId('drawer-search-input'),
      drawerAppsGrid: byId('drawer-apps-grid'),
      btnCloseDrawer: byId('btn-close-drawer'),
      androidRecents: byId('android-recents'),
      recentsCards: byId('recents-cards'),
      btnCloseRecents: byId('btn-close-recents'),
      btnAndroidBack: byId('btn-android-back'),
      btnAndroidHome: byId('btn-android-home'),
      btnAndroidRecents: byId('btn-android-recents'),
      btnAndroidDrawer: byId('btn-android-drawer'),
    };
  }

  destroy() {
    if (this._clockTimer) {
      clearInterval(this._clockTimer);
      this._clockTimer = null;
    }
    if (typeof document !== 'undefined' && this._onDocClick) {
      document.removeEventListener('click', this._onDocClick);
    }
  }

  getState() {
    return {
      shellMode: this._shellMode,
      chromeMode: this._chromeMode,
      systemConfig: { ...this._systemConfig },
      systemAppsCount: this._systemApps.length,
      installedPackagesCount: this._packages.length,
      catalogCount: this._catalog.length,
      notificationsCount: this._notifications.filter((n) => !n.dismissed).length,
      liveActivitiesCount: this._liveActivities.size,
      windowCount: this._windows.length,
      focusedWindowId: this._focusedWindowId,
    };
  }

  setHydrated(hydrated) {
    if (this._dom.shell) {
      this._dom.shell.setAttribute('data-hydrated', hydrated ? 'true' : 'false');
    }
  }

  setWsConnected(connected) {
    if (this._dom.shell) {
      this._dom.shell.setAttribute('data-ws-connected', connected ? 'true' : 'false');
    }
    if (this._dom.wsStatusIndicator) {
      this._dom.wsStatusIndicator.setAttribute('data-connected', connected ? 'true' : 'false');
    }
    if (this._dom.wsStatusText) {
      this._dom.wsStatusText.textContent = connected ? 'Live' : 'Reconnecting…';
    }
  }

  // ---- Shell Mode & System Config ----

  async switchShellMode(mode) {
    const normalized = normalizeShellMode(mode);
    const reqSeq = (this._modeSwitchSeq = (this._modeSwitchSeq || 0) + 1);
    this._applyShellModeDom(normalized);
    this._compositorUI?.setShellMode(normalized);
    this.closeAllPanels();
    try {
      const res = await this._client.setShellMode(normalized);
      if (reqSeq !== this._modeSwitchSeq) return;
      if (res?.shellMode) {
        this._applyShellModeDom(normalizeShellMode(res.shellMode));
      }
      // When WS is connected, compositor.setShellMode already emits compositor:snapshot in strict
      // server order; applying an older HTTP snapshot here could clobber newer window_created events.
      if (res?.snapshot && !this._client.isConnected()) {
        this._compositorUI?.applySnapshot(res.snapshot);
      }
    } catch {
      // Keep optimistic fallback if transient error; next snapshot reconciles
    }
  }

  applyShellModeFromServer(mode) {
    const normalized = normalizeShellMode(mode);
    if (this._shellMode !== normalized) {
      this._applyShellModeDom(normalized);
      this._compositorUI?.setShellMode(normalized);
    }
  }

  _applyShellModeDom(mode) {
    const normalized = normalizeShellMode(mode);
    this._shellMode = normalized;
    this._systemConfig['system.shellMode'] = normalized;

    const shell = this._dom.shell;
    if (shell) {
      shell.setAttribute('data-shell-mode', normalized);
      shell.classList.remove(
        'mode-unified',
        'mode-windows',
        'mode-macos',
        'mode-ios',
        'mode-android'
      );
      shell.classList.add(`mode-${normalized}`);
    }

    if (typeof document !== 'undefined') {
      const btns = document.querySelectorAll('[data-shell-mode-btn]');
      for (const btn of btns) {
        const target = normalizeShellMode(btn.getAttribute('data-shell-mode-btn'));
        const active = target === normalized;
        btn.setAttribute('data-active', active ? 'true' : 'false');
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        btn.classList.toggle('is-active', active);
      }
    }

    this._renderIosSpringboardVisibility();
  }

  applySystemConfig(configMap) {
    if (!configMap || typeof configMap !== 'object') return;
    for (const [k, v] of Object.entries(configMap)) {
      if (k.startsWith('system.')) {
        this._systemConfig[k] = k === 'system.shellMode' ? normalizeShellMode(v) : v;
      }
    }
    if (configMap['system.shellMode']) {
      this.applyShellModeFromServer(configMap['system.shellMode']);
    }
    this._applySystemConfigDom();
  }

  handleConfigChanged(payload) {
    if (!payload || typeof payload !== 'object') return;
    const key = payload.canonicalKey || payload.key;
    if (typeof key !== 'string' || !key.startsWith('system.')) return;
    if (key === 'system.shellMode') {
      this.applyShellModeFromServer(payload.value);
    } else {
      this._systemConfig[key] = payload.value;
    }
    this._applySystemConfigDom();
  }

  _resolveEffectiveTheme(themeVal) {
    if (themeVal === 'light') return 'light';
    if (themeVal === 'auto' && typeof window !== 'undefined' && window.matchMedia) {
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    return 'dark';
  }

  _applySystemConfigDom() {
    const theme = this._resolveEffectiveTheme(this._systemConfig['system.theme']);
    const brightness = Math.max(0, Math.min(100, Number(this._systemConfig['system.brightness'] ?? 80)));
    const volume = Math.max(0, Math.min(100, Number(this._systemConfig['system.volume'] ?? 75)));

    if (this._dom.shell) {
      this._dom.shell.setAttribute('data-theme', theme);
      this._dom.shell.setAttribute('data-chrome-mode', this._chromeMode);
      this._dom.shell.setAttribute('data-brightness', String(Math.round(brightness)));
      // Subtle dim overlay variable (0 at 100% brightness, max 0.42 at 0% so UI always remains legible)
      const dimAlpha = ((100 - brightness) / 100) * 0.42;
      this._dom.shell.style.setProperty('--omni-brightness-dim', dimAlpha.toFixed(3));
    }

    if (typeof document !== 'undefined') {
      const toggles = document.querySelectorAll('[data-system-toggle]');
      for (const btn of toggles) {
        const key = btn.getAttribute('data-system-toggle');
        let active = false;
        if (key === 'system.theme') {
          active = theme === 'dark';
        } else {
          active = Boolean(this._systemConfig[key]);
        }
        btn.setAttribute('data-active', active ? 'true' : 'false');
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        btn.classList.toggle('is-active', active);
        const stateSpan = btn.querySelector('.qs-tile-state');
        if (stateSpan) {
          stateSpan.textContent = key === 'system.theme' ? (active ? 'Dark' : 'Light') : (active ? 'On' : 'Off');
        }
      }

      const ranges = document.querySelectorAll('[data-system-range]');
      for (const slider of ranges) {
        const key = slider.getAttribute('data-system-range');
        const val = key === 'system.volume' ? volume : brightness;
        if (Number(slider.value) !== Math.round(val)) {
          slider.value = String(Math.round(val));
        }
      }
    }

    if (this._dom.ccBrightnessVal) {
      this._dom.ccBrightnessVal.textContent = `${Math.round(brightness)}%`;
    }
    if (this._dom.ccVolumeVal) {
      this._dom.ccVolumeVal.textContent = `${Math.round(volume)}%`;
    }
    if (this._dom.btnThemeToggle) {
      this._dom.btnThemeToggle.setAttribute('data-theme', theme);
      this._dom.btnThemeToggle.setAttribute(
        'title',
        theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme'
      );
    }
  }

  async toggleSystemKey(key) {
    let nextVal;
    if (key === 'system.theme') {
      const cur = this._resolveEffectiveTheme(this._systemConfig['system.theme']);
      nextVal = cur === 'dark' ? 'light' : 'dark';
    } else {
      nextVal = !Boolean(this._systemConfig[key]);
    }
    this._systemConfig[key] = nextVal;
    this._applySystemConfigDom();
    try {
      const res = await this._client.setSystemConfig(key, nextVal);
      if (res?.system) this.applySystemConfig(res.system);
    } catch {
      // ignore transient error
    }
  }

  async setSystemNumericKey(key, value) {
    const clamped = Math.max(0, Math.min(100, Math.round(Number(value))));
    this._systemConfig[key] = clamped;
    this._applySystemConfigDom();
    try {
      const res = await this._client.setSystemConfig(key, clamped);
      if (res?.system) this.applySystemConfig(res.system);
    } catch {
      // ignore transient error
    }
  }

  toggleChromeMode() {
    this._chromeMode = this._chromeMode === 'adaptive' ? 'unified' : 'adaptive';
    if (this._dom.shell) {
      this._dom.shell.setAttribute('data-chrome-mode', this._chromeMode);
    }
    if (this._dom.btnChromeToggle) {
      this._dom.btnChromeToggle.setAttribute('data-chrome-mode', this._chromeMode);
      this._dom.btnChromeToggle.setAttribute(
        'title',
        this._chromeMode === 'adaptive' ? 'Chrome: Adaptive Per-Platform' : 'Chrome: Unified'
      );
    }
    this._compositorUI?.setChromeMode(this._chromeMode);
  }

  // ---- Compositor State Sync ----

  handleCompositorStateChange({ shellMode, focusedWindowId, activeMenuBar, windows } = {}) {
    if (shellMode) this.applyShellModeFromServer(shellMode);
    this._focusedWindowId = focusedWindowId ?? null;
    if (Array.isArray(activeMenuBar)) this._activeMenuBar = activeMenuBar;
    if (Array.isArray(windows)) this._windows = windows;

    if (this._dom.shell) {
      this._dom.shell.setAttribute('data-window-count', String(this._windows.length));
      this._dom.shell.setAttribute('data-focused-window', this._focusedWindowId ?? '');
    }

    this._renderGlobalMenuBar();
    this._renderDock();
    this._renderWindowsTaskbar();
    this._renderIosSpringboardVisibility();
    if (this._dom.androidRecents?.getAttribute('data-open') === 'true') {
      this._renderRecents();
    }
  }

  // ---- Packages, Catalog & Processes Sync ----

  setPackagesData({ systemApps, packages, catalog } = {}) {
    if (Array.isArray(systemApps)) this._systemApps = systemApps;
    if (Array.isArray(packages)) this._packages = packages;
    if (Array.isArray(catalog)) this._catalog = catalog;

    this._renderDock();
    this._renderDesktopShortcuts();
    this._renderWindowsTaskbar();
    this._renderStartMenu();
    this._renderSpringboard();
    this._renderAndroidDrawer();
  }

  setProcesses(processes) {
    if (!Array.isArray(processes)) return;
    this._processes = processes;
    if (this._dom.androidRecents?.getAttribute('data-open') === 'true') {
      this._renderRecents();
    }
  }

  // ---- App Launch Helper (Enforces `preferSystem: true` for built-in system apps!) ----

  async launchOrFocusApp(app, { forceLaunch = false } = {}) {
    if (!app || !app.appId) return;
    const isBuiltin = Boolean(app.builtin || app.platform === 'system');

    if (!forceLaunch) {
      const existingWin = this._windows.find((w) => {
        if (w.appId !== app.appId) return false;
        const winIsSystem = String(w.platform).toLowerCase() === 'system';
        return isBuiltin ? winIsSystem : !winIsSystem;
      });
      if (existingWin) {
        this.closeAllPanels();
        this._compositorUI?.focusWindow(existingWin.windowId);
        return;
      }
    }

    this.closeAllPanels();

    // Uninstalled catalog app -> install first, then launch
    if (app.uninstalled && app.packagePath) {
      try {
        await this._client.installFromVfsPath(app.packagePath, { grantAll: true });
        await this._refreshPackagesSafe();
      } catch {
        return;
      }
    }

    const launchOpts = isBuiltin ? { preferSystem: true } : {};
    try {
      await this._client.launchApp(app.appId, launchOpts);
    } catch {
      // ignore error; kernel/app may post notification
    }
  }

  async _refreshPackagesSafe() {
    try {
      const [pkgRes, catRes] = await Promise.all([
        this._client.listPackages(),
        this._client.getCatalog(),
      ]);
      this.setPackagesData({
        systemApps: pkgRes?.systemApps ?? catRes?.systemApps,
        packages: pkgRes?.packages ?? [],
        catalog: catRes?.catalog ?? [],
      });
    } catch {
      // ignore
    }
  }

  _buildLauncherApps() {
    const installedIds = new Set(this._packages.map((p) => p.appId));
    const systemList = this._systemApps.map((s) => ({
      appId: s.appId,
      name: s.name || s.appId,
      platform: 'system',
      icon: s.icon || 'settings',
      category: s.category || 'System',
      builtin: true,
      uninstalled: false,
      runningPids: Array.isArray(s.runningPids) ? s.runningPids : [],
    }));

    const installedList = this._packages.map((p) => ({
      appId: p.appId,
      name: p.name || p.appId,
      platform: String(p.platform || 'universal').toLowerCase(),
      icon: p.metadata?.icon || p.icon || '',
      category: p.metadata?.category || 'Apps',
      builtin: false,
      uninstalled: false,
      format: p.format,
    }));

    const catalogOnlyList = this._catalog
      .filter((c) => !installedIds.has(c.appId))
      .map((c) => ({
        appId: c.appId,
        name: c.name || c.appId,
        platform: String(c.platform || 'universal').toLowerCase(),
        icon: c.icon || '',
        category: c.metadata?.category || 'Catalog',
        packagePath: c.packagePath,
        builtin: false,
        uninstalled: true,
        format: c.format,
      }));

    return { systemList, installedList, catalogOnlyList };
  }

  _isAppRunning(app) {
    const isBuiltin = Boolean(app.builtin || app.platform === 'system');
    return this._windows.some((w) => {
      if (w.appId !== app.appId) return false;
      const winIsSystem = String(w.platform).toLowerCase() === 'system';
      return isBuiltin ? winIsSystem : !winIsSystem;
    });
  }

  // ---- Global Top Menu Bar ----

  _renderGlobalMenuBar() {
    const bar = this._dom.globalMenuBar;
    if (!bar) return;
    const groups = Array.isArray(this._activeMenuBar) ? this._activeMenuBar : [];

    const frag = document.createDocumentFragment();
    for (const group of groups) {
      if (!group || !group.id) continue;
      const isOpen = this._openMenuId === group.id;
      const btn = el(
        'button',
        `menu-bar-trigger${isOpen ? ' is-open' : ''}`,
        {
          type: 'button',
          role: 'menuitem',
          'data-menu-id': String(group.id),
          'aria-expanded': isOpen ? 'true' : 'false',
        },
        String(group.label ?? group.id)
      );
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (this._openMenuId === group.id) {
          this._closeMenuDropdown();
        } else {
          this._openMenuDropdown(group, btn);
        }
      });
      frag.appendChild(btn);
    }
    bar.replaceChildren(frag);

    // Close dropdown if its menu group no longer exists in activeMenuBar
    if (this._openMenuId && !groups.some((g) => g.id === this._openMenuId)) {
      this._closeMenuDropdown();
    }
  }

  _openMenuDropdown(group, triggerEl) {
    const dropdown = this._dom.menuDropdown;
    if (!dropdown) return;
    this._openMenuId = group.id;

    const frag = document.createDocumentFragment();
    const items = Array.isArray(group.items) ? group.items : [];
    for (const item of items) {
      if (!item) continue;
      if (item.separator) {
        frag.appendChild(el('div', 'menu-separator', { role: 'separator' }));
        continue;
      }
      const btn = el('button', 'menu-dropdown-item', {
        type: 'button',
        role: 'menuitem',
        'data-menu-item-id': String(item.id ?? ''),
      });
      if (item.disabled) btn.disabled = true;
      btn.appendChild(el('span', 'menu-item-label', {}, String(item.label ?? item.id ?? '')));
      if (item.shortcut) {
        btn.appendChild(el('span', 'menu-item-shortcut', {}, String(item.shortcut)));
      }
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        this._closeMenuDropdown();
        this._invokeMenuItem(group, item);
      });
      frag.appendChild(btn);
    }

    dropdown.replaceChildren(frag);
    const rect = triggerEl.getBoundingClientRect();
    dropdown.style.left = `${Math.max(4, Math.round(rect.left))}px`;
    dropdown.style.top = `${Math.round(rect.bottom + 2)}px`;
    dropdown.setAttribute('data-open', 'true');
    this._renderGlobalMenuBar();
  }

  _closeMenuDropdown() {
    this._openMenuId = null;
    if (this._dom.menuDropdown) {
      this._dom.menuDropdown.setAttribute('data-open', 'false');
      this._dom.menuDropdown.replaceChildren();
    }
    if (this._dom.globalMenuBar) {
      for (const btn of this._dom.globalMenuBar.querySelectorAll('.menu-bar-trigger')) {
        btn.classList.remove('is-open');
        btn.setAttribute('aria-expanded', 'false');
      }
    }
  }

  _invokeMenuItem(group, item) {
    const focusedWin = this._windows.find((w) => w.windowId === this._focusedWindowId) ?? null;

    // Special case: macOS default `.quit` with `action: 'terminate:'`
    if (
      focusedWin &&
      focusedWin.platform === 'macos' &&
      item.action === 'terminate:' &&
      String(item.id || '').endsWith('.quit')
    ) {
      this._client
        .dispatchInput(focusedWin.windowId, {
          type: 'menu_action',
          menuId: group.id,
          itemId: item.id,
          actionId: item.id,
          action: item.action,
          label: item.label,
        })
        .catch(() => {});
      return;
    }

    this._client
      .dispatchMenuAction({
        windowId: this._focusedWindowId,
        menuId: group.id,
        itemId: item.id,
        actionId: item.id,
        label: item.label,
        ...(item.action ? { action: item.action } : {}),
      })
      .catch(() => {});
  }

  // ---- Floating Dock (Unified & macOS) ----

  _renderDock() {
    const dockApps = this._dom.dockApps;
    if (dockApps) {
      const { systemList, installedList } = this._buildLauncherApps();
      const items = [...systemList, ...installedList];
      const frag = document.createDocumentFragment();

      for (const app of items) {
        const running = this._isAppRunning(app);
        const btn = el('button', 'dock-item', {
          type: 'button',
          'data-app-id': app.appId,
          'data-platform': app.platform,
          'data-builtin': app.builtin ? 'true' : 'false',
          'data-running': running ? 'true' : 'false',
          title: `${app.name} (${getPlatformBadge(app.platform)})`,
        });
        btn.appendChild(el('span', `dock-glyph platform-${app.platform}`, {}, getAppGlyph(app.icon, app.name)));
        btn.appendChild(el('span', 'dock-label', {}, app.name));
        btn.appendChild(
          el('span', `platform-badge platform-${app.platform}`, {}, getPlatformBadge(app.platform))
        );
        btn.appendChild(el('span', 'dock-running-dot', { 'aria-hidden': 'true' }));
        btn.addEventListener('click', () => this.launchOrFocusApp(app));
        frag.appendChild(btn);
      }
      dockApps.replaceChildren(frag);
    }

    const dockMin = this._dom.dockMinimized;
    if (dockMin) {
      const minimized = this._windows.filter((w) => w.state === 'minimized');
      if (this._dom.dockSeparator) {
        this._dom.dockSeparator.hidden = minimized.length === 0;
      }
      const frag = document.createDocumentFragment();
      for (const win of minimized) {
        const btn = el('button', 'dock-item dock-minimized-item', {
          type: 'button',
          'data-window-id': win.windowId,
          title: `Restore ${win.title}`,
        });
        btn.appendChild(
          el('span', `platform-badge platform-${win.platform || 'system'}`, {}, getPlatformBadge(win.platform))
        );
        btn.appendChild(el('span', 'dock-label', {}, String(win.title ?? 'Window')));
        btn.addEventListener('click', () => this._compositorUI?.focusWindow(win.windowId));
        frag.appendChild(btn);
      }
      dockMin.replaceChildren(frag);
    }
  }

  // ---- Desktop Shortcuts ----

  _renderDesktopShortcuts() {
    const container = this._dom.desktopShortcuts;
    if (!container) return;
    const { systemList, installedList } = this._buildLauncherApps();
    const list = [...systemList, ...installedList];
    const frag = document.createDocumentFragment();

    for (const app of list) {
      const tile = el('button', 'desktop-shortcut', {
        type: 'button',
        'data-app-id': app.appId,
        'data-platform': app.platform,
        'data-builtin': app.builtin ? 'true' : 'false',
      });
      tile.appendChild(
        el('span', `shortcut-icon platform-${app.platform}`, {}, getAppGlyph(app.icon, app.name))
      );
      tile.appendChild(el('span', 'shortcut-label', {}, app.name));
      tile.appendChild(
        el('span', `platform-badge platform-${app.platform}`, {}, getPlatformBadge(app.platform))
      );
      tile.addEventListener('click', () => this.launchOrFocusApp(app));
      frag.appendChild(tile);
    }
    container.replaceChildren(frag);
  }

  // ---- Windows Taskbar & Start Menu ----

  _renderWindowsTaskbar() {
    const bar = this._dom.winTaskbarApps;
    if (!bar) return;
    const frag = document.createDocumentFragment();

    // Show open windows first, plus quick-launch pins for system apps without open windows
    const { systemList } = this._buildLauncherApps();
    const openSysAppIds = new Set(
      this._windows.filter((w) => w.platform === 'system').map((w) => w.appId)
    );

    for (const app of systemList.slice(0, 5)) {
      if (openSysAppIds.has(app.appId)) continue;
      const btn = el('button', 'taskbar-app-btn taskbar-pinned', {
        type: 'button',
        'data-app-id': app.appId,
        'data-builtin': 'true',
        title: app.name,
      });
      btn.appendChild(el('span', 'taskbar-glyph', {}, getAppGlyph(app.icon, app.name)));
      btn.appendChild(el('span', 'taskbar-label', {}, app.name));
      btn.addEventListener('click', () => this.launchOrFocusApp(app));
      frag.appendChild(btn);
    }

    for (const win of this._windows) {
      const isFocused = win.windowId === this._focusedWindowId && win.state !== 'minimized';
      const btn = el('button', `taskbar-app-btn taskbar-window${isFocused ? ' is-focused' : ''}`, {
        type: 'button',
        'data-window-id': win.windowId,
        'data-window-state': win.state,
        'data-focused': isFocused ? 'true' : 'false',
        title: String(win.title ?? 'Window'),
      });
      btn.appendChild(
        el('span', `platform-badge platform-${win.platform || 'system'}`, {}, getPlatformBadge(win.platform))
      );
      btn.appendChild(el('span', 'taskbar-label', {}, String(win.title ?? 'Window')));
      btn.addEventListener('click', () => {
        if (isFocused) {
          this._compositorUI?.setWindowState(win.windowId, 'minimized');
        } else {
          this._compositorUI?.focusWindow(win.windowId);
        }
      });
      frag.appendChild(btn);
    }

    bar.replaceChildren(frag);
  }

  _renderStartMenu() {
    const query = (this._dom.startSearchInput?.value ?? '').trim().toLowerCase();
    const { systemList, installedList, catalogOnlyList } = this._buildLauncherApps();
    const matches = (a) =>
      !query ||
      a.name.toLowerCase().includes(query) ||
      a.appId.toLowerCase().includes(query) ||
      a.platform.toLowerCase().includes(query);

    if (this._dom.startPinnedGrid) {
      const pinned = [...systemList, ...installedList].filter(matches);
      const frag = document.createDocumentFragment();
      for (const app of pinned) {
        const btn = el('button', 'start-tile', {
          type: 'button',
          'data-app-id': app.appId,
          'data-platform': app.platform,
          'data-builtin': app.builtin ? 'true' : 'false',
        });
        btn.appendChild(el('span', `shortcut-icon platform-${app.platform}`, {}, getAppGlyph(app.icon, app.name)));
        btn.appendChild(el('span', 'start-tile-name', {}, app.name));
        btn.appendChild(
          el('span', `platform-badge platform-${app.platform}`, {}, getPlatformBadge(app.platform))
        );
        btn.addEventListener('click', () => this.launchOrFocusApp(app));
        frag.appendChild(btn);
      }
      this._dom.startPinnedGrid.replaceChildren(frag);
    }

    if (this._dom.startAllAppsList) {
      const all = [...systemList, ...installedList, ...catalogOnlyList].filter(matches);
      const frag = document.createDocumentFragment();
      for (const app of all) {
        const btn = el('button', 'start-list-item', {
          type: 'button',
          'data-app-id': app.appId,
          'data-platform': app.platform,
          'data-builtin': app.builtin ? 'true' : 'false',
        });
        btn.appendChild(
          el('span', `platform-badge platform-${app.platform}`, {}, getPlatformBadge(app.platform))
        );
        btn.appendChild(el('span', 'start-list-name', {}, app.name));
        if (app.uninstalled) {
          btn.appendChild(el('span', 'omni-ui-badge', {}, 'Install'));
        }
        btn.addEventListener('click', () => this.launchOrFocusApp(app));
        frag.appendChild(btn);
      }
      this._dom.startAllAppsList.replaceChildren(frag);
    }
  }

  // ---- iOS SpringBoard & App Library ----

  _renderIosSpringboardVisibility() {
    if (!this._dom.iosSpringboard) return;
    const hasVisibleWindow = this._windows.some((w) => w.state !== 'minimized');
    this._dom.iosSpringboard.setAttribute(
      'data-visible',
      this._shellMode === 'ios' && !hasVisibleWindow ? 'true' : 'false'
    );
  }

  _renderSpringboard() {
    const query = (this._dom.springboardSearch?.value ?? '').trim().toLowerCase();
    const { systemList, installedList, catalogOnlyList } = this._buildLauncherApps();
    const matches = (a) =>
      !query ||
      a.name.toLowerCase().includes(query) ||
      a.appId.toLowerCase().includes(query) ||
      a.platform.toLowerCase().includes(query);

    if (this._dom.springboardGrid) {
      const primary = [...systemList, ...installedList].filter(matches);
      const frag = document.createDocumentFragment();
      for (const app of primary) {
        const btn = el('button', 'springboard-app-icon', {
          type: 'button',
          'data-app-id': app.appId,
          'data-platform': app.platform,
          'data-builtin': app.builtin ? 'true' : 'false',
        });
        btn.appendChild(
          el('span', `sb-glyph platform-${app.platform}`, {}, getAppGlyph(app.icon, app.name))
        );
        btn.appendChild(el('span', 'sb-label', {}, app.name));
        btn.addEventListener('click', () => this.launchOrFocusApp(app));
        frag.appendChild(btn);
      }
      this._dom.springboardGrid.replaceChildren(frag);
    }

    if (this._dom.appLibraryGrid) {
      const lib = [...installedList, ...catalogOnlyList].filter(matches);
      const frag = document.createDocumentFragment();
      for (const app of lib) {
        const btn = el('button', 'app-library-item', {
          type: 'button',
          'data-app-id': app.appId,
          'data-platform': app.platform,
        });
        btn.appendChild(
          el('span', `platform-badge platform-${app.platform}`, {}, getPlatformBadge(app.platform))
        );
        btn.appendChild(el('span', 'sb-label', {}, app.name));
        if (app.uninstalled) {
          btn.appendChild(el('span', 'omni-ui-badge', {}, 'Get'));
        }
        btn.addEventListener('click', () => this.launchOrFocusApp(app));
        frag.appendChild(btn);
      }
      this._dom.appLibraryGrid.replaceChildren(frag);
    }
  }

  // ---- Android App Drawer ----

  _renderAndroidDrawer() {
    const grid = this._dom.drawerAppsGrid;
    if (!grid) return;
    const query = (this._dom.drawerSearchInput?.value ?? '').trim().toLowerCase();
    const { systemList, installedList, catalogOnlyList } = this._buildLauncherApps();
    const all = [...systemList, ...installedList, ...catalogOnlyList].filter(
      (a) =>
        !query ||
        a.name.toLowerCase().includes(query) ||
        a.appId.toLowerCase().includes(query) ||
        a.platform.toLowerCase().includes(query)
    );

    const frag = document.createDocumentFragment();
    for (const app of all) {
      const btn = el('button', 'drawer-app-tile', {
        type: 'button',
        'data-app-id': app.appId,
        'data-platform': app.platform,
        'data-builtin': app.builtin ? 'true' : 'false',
      });
      btn.appendChild(
        el('span', `shortcut-icon platform-${app.platform}`, {}, getAppGlyph(app.icon, app.name))
      );
      btn.appendChild(el('span', 'drawer-app-name', {}, app.name));
      btn.appendChild(
        el('span', `platform-badge platform-${app.platform}`, {}, getPlatformBadge(app.platform))
      );
      btn.addEventListener('click', () => this.launchOrFocusApp(app));
      frag.appendChild(btn);
    }
    grid.replaceChildren(frag);
  }

  // ---- Android Recents / iOS App Switcher (Live Kernel PID Kill) ----

  _renderRecents() {
    const host = this._dom.recentsCards;
    if (!host) return;

    const cardsByPid = new Map();
    for (const win of this._windows) {
      const pid = Number(win.pid);
      cardsByPid.set(pid, {
        pid,
        windowId: win.windowId,
        title: String(win.title ?? win.appId ?? `PID ${pid}`),
        appId: String(win.appId ?? ''),
        platform: String(win.platform ?? 'system').toLowerCase(),
        state: String(win.state ?? 'normal'),
      });
    }
    for (const proc of this._processes) {
      const pid = Number(proc.pid);
      if (pid <= 1 || proc.system) continue;
      if (proc.state === 'TERMINATED' || proc.state === 'ZOMBIE') continue;
      if (!cardsByPid.has(pid)) {
        cardsByPid.set(pid, {
          pid,
          windowId: null,
          title: String(proc.name ?? proc.appId ?? `PID ${pid}`),
          appId: String(proc.appId ?? ''),
          platform: String(proc.platform ?? 'system').toLowerCase(),
          state: String(proc.state ?? 'RUNNING'),
        });
      }
    }

    const cards = [...cardsByPid.values()];
    if (cards.length === 0) {
      host.replaceChildren(el('div', 'omni-ui-empty', {}, 'No active user apps running.'));
      return;
    }

    const frag = document.createDocumentFragment();
    for (const item of cards) {
      const card = el('article', 'recents-card', {
        'data-pid': String(item.pid),
        'data-app-id': item.appId,
        'data-platform': item.platform,
      });

      const head = el('div', 'recents-card-header');
      head.appendChild(
        el('span', `platform-badge platform-${item.platform}`, {}, getPlatformBadge(item.platform))
      );
      head.appendChild(el('strong', 'recents-card-title', {}, item.title));
      head.appendChild(el('span', 'window-pid-chip', {}, `PID ${item.pid}`));
      card.appendChild(head);

      card.appendChild(el('div', 'recents-card-meta', {}, `${item.appId || 'process'} · ${item.state}`));

      const actions = el('div', 'recents-card-actions');
      if (item.windowId) {
        const btnFocus = el('button', 'omni-ui-btn omni-ui-btn-sm', { type: 'button' }, 'Switch To');
        btnFocus.addEventListener('click', () => {
          this.setRecentsOpen(false);
          this._compositorUI?.focusWindow(item.windowId);
        });
        actions.appendChild(btnFocus);
      }

      const btnKill = el(
        'button',
        'omni-ui-btn omni-ui-btn-sm omni-ui-btn-danger recents-kill-btn',
        {
          type: 'button',
          'data-recents-kill-pid': String(item.pid),
        },
        'Swipe / Kill'
      );
      btnKill.addEventListener('click', async () => {
        // Guard kernel PIDs 0/1; kill genuine user process PID!
        if (item.pid > 1) {
          try {
            await this._client.signalProcess(item.pid, 'SIGTERM');
          } catch {
            if (item.windowId) {
              await this._client.closeWindow(item.windowId).catch(() => {});
            }
          }
        } else if (item.windowId) {
          await this._client.closeWindow(item.windowId).catch(() => {});
        }
        try {
          const res = await this._client.listProcesses();
          if (res?.processes) this.setProcesses(res.processes);
        } catch {
          // ignore
        }
        this._renderRecents();
      });
      actions.appendChild(btnKill);

      card.appendChild(actions);
      frag.appendChild(card);
    }

    host.replaceChildren(frag);
  }

  // ---- Notifications & iOS Dynamic Island ----

  setNotificationsData({ notifications, liveActivities } = {}) {
    if (Array.isArray(notifications)) {
      const byId = new Map();
      for (const n of notifications) {
        if (n && n.id && !n.dismissed) byId.set(n.id, n);
      }
      for (const existing of this._notifications) {
        if (existing && existing.id && !existing.dismissed && !byId.has(existing.id)) {
          // Keep newer notification if WS delivered it during in-flight REST hydrate
          const maxRestTs = notifications[0]?.createdAt ?? '';
          if (String(existing.createdAt || '') > String(maxRestTs)) {
            byId.set(existing.id, existing);
          }
        }
      }
      this._notifications = [...byId.values()].sort((a, b) =>
        String(b.createdAt || '').localeCompare(String(a.createdAt || ''))
      );
    }
    if (Array.isArray(liveActivities)) {
      const restIds = new Set();
      for (const act of liveActivities) {
        if (act && act.id && act.state === 'active') {
          restIds.add(act.id);
          const prev = this._liveActivities.get(act.id);
          if (!prev || String(act.updatedAt || '') >= String(prev.updatedAt || '')) {
            this._liveActivities.set(act.id, act);
          }
        }
      }
      // Keep WS-pushed activities only if newer than REST set; drop stale ended ones
      const latestRestUpdate = liveActivities.reduce(
        (acc, a) => (String(a?.updatedAt || '') > acc ? String(a.updatedAt) : acc),
        ''
      );
      for (const [id, act] of [...this._liveActivities.entries()]) {
        if (!restIds.has(id) && latestRestUpdate && String(act.updatedAt || '') < latestRestUpdate) {
          this._liveActivities.delete(id);
        }
      }
    }
    this._renderNotifications();
    this._renderDynamicIsland();
  }

  handleNotificationPosted(notif) {
    if (!notif || typeof notif !== 'object') return;
    if (!notif.dismissed) {
      const idx = this._notifications.findIndex((n) => n.id === notif.id);
      if (idx >= 0) this._notifications[idx] = notif;
      else this._notifications.unshift(notif);
    }

    if (notif.liveActivity && notif.liveActivity.id && notif.liveActivity.state === 'active') {
      this._liveActivities.set(notif.liveActivity.id, notif.liveActivity);
      this._selectedActivityId = notif.liveActivity.id;
      this._renderDynamicIsland();
    }

    this._renderNotifications();

    const dnd = Boolean(this._systemConfig['system.dnd']);
    const bypassDnd = notif.priority === 'urgent' || notif.priority === 'critical';
    if (!notif.suppressed && !notif.silent && (!dnd || bypassDnd)) {
      this._spawnToast(notif);
    }
  }

  handleNotificationUpdated(payload) {
    if (!payload || typeof payload !== 'object') return;
    const subType = payload.type;

    if (subType === 'dismissed' && payload.notification?.id) {
      this._notifications = this._notifications.filter((n) => n.id !== payload.notification.id);
      this._renderNotifications();
      return;
    }

    if (subType === 'cleared') {
      if (payload.appId) {
        this._notifications = this._notifications.filter((n) => n.appId !== payload.appId);
      } else {
        this._notifications = [];
      }
      this._renderNotifications();
      return;
    }

    if (subType === 'read' && payload.notification?.id) {
      const idx = this._notifications.findIndex((n) => n.id === payload.notification.id);
      if (idx >= 0) this._notifications[idx] = payload.notification;
      this._renderNotifications();
      return;
    }

    if (subType === 'live_activity_updated' && payload.liveActivity?.id) {
      if (payload.liveActivity.state === 'active') {
        this._liveActivities.set(payload.liveActivity.id, payload.liveActivity);
        this._selectedActivityId = payload.liveActivity.id;
      } else {
        this._liveActivities.delete(payload.liveActivity.id);
      }
      this._renderDynamicIsland();
      return;
    }

    if (subType === 'live_activity_ended' && payload.liveActivity?.id) {
      this._liveActivities.delete(payload.liveActivity.id);
      if (this._selectedActivityId === payload.liveActivity.id) {
        this._selectedActivityId = null;
      }
      this._renderDynamicIsland();
    }
  }

  _renderNotifications() {
    const active = this._notifications.filter((n) => !n.dismissed);
    const countStr = String(active.length);

    for (const badge of [this._dom.notifBadge, this._dom.winNotifBadge]) {
      if (!badge) continue;
      badge.textContent = countStr;
      badge.setAttribute('data-count', countStr);
      badge.hidden = active.length === 0;
    }

    const list = this._dom.shadeNotifList;
    if (!list) return;
    if (active.length === 0) {
      list.replaceChildren(el('div', 'omni-ui-empty', {}, 'No notifications'));
      return;
    }

    const frag = document.createDocumentFragment();
    for (const n of active) {
      const platform = String(n.platform || 'system').toLowerCase();
      const card = el('article', 'notif-card', {
        'data-notif-id': String(n.id),
        'data-platform': platform,
        'data-priority': String(n.priority || 'normal'),
      });

      const head = el('div', 'notif-card-head');
      head.appendChild(el('span', `platform-badge platform-${platform}`, {}, getPlatformBadge(platform)));
      head.appendChild(el('strong', 'notif-title', {}, String(n.title ?? 'Notification')));
      const btnDismiss = el('button', 'notif-dismiss-btn', { type: 'button', 'aria-label': 'Dismiss' }, '×');
      btnDismiss.addEventListener('click', () => {
        this._client.dismissNotification(n.id).catch(() => {});
      });
      head.appendChild(btnDismiss);
      card.appendChild(head);

      if (n.body) {
        card.appendChild(el('div', 'notif-body', {}, String(n.body)));
      }
      if (n.suppressed) {
        card.appendChild(el('div', 'notif-meta', {}, 'Delivered silently (Do Not Disturb)'));
      }

      const actions = Array.isArray(n.actions) ? n.actions : [];
      if (actions.length > 0) {
        const actRow = el('div', 'notif-actions');
        for (const act of actions) {
          const btn = el(
            'button',
            `omni-ui-btn omni-ui-btn-xs${act.destructive ? ' omni-ui-btn-danger' : ''}`,
            { type: 'button', 'data-notif-action-id': String(act.id ?? '') },
            String(act.label ?? act.id ?? 'Action')
          );
          btn.addEventListener('click', () => {
            this._client.invokeNotificationAction(n.id, act.id).catch(() => {});
          });
          actRow.appendChild(btn);
        }
        card.appendChild(actRow);
      }

      frag.appendChild(card);
    }
    list.replaceChildren(frag);
  }

  _spawnToast(notif) {
    const stack = this._dom.toastStack;
    if (!stack) return;
    const platform = String(notif.platform || 'system').toLowerCase();
    const toast = el('div', 'omni-toast', {
      role: 'status',
      'data-notif-id': String(notif.id ?? ''),
      'data-platform': platform,
    });
    const head = el('div', 'toast-head');
    head.appendChild(el('span', `platform-badge platform-${platform}`, {}, getPlatformBadge(platform)));
    head.appendChild(el('strong', 'toast-title', {}, String(notif.title ?? 'Notification')));
    const closeBtn = el('button', 'toast-close-btn', { type: 'button', 'aria-label': 'Close' }, '×');
    closeBtn.addEventListener('click', () => toast.remove());
    head.appendChild(closeBtn);
    toast.appendChild(head);

    if (notif.body) {
      toast.appendChild(el('div', 'toast-body', {}, String(notif.body)));
    }
    stack.appendChild(toast);

    // Keep max 4 visible toasts
    while (stack.children.length > 4) {
      stack.firstElementChild?.remove();
    }
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, 5000);
  }

  _renderDynamicIsland() {
    const di = this._dom.dynamicIsland;
    if (!di) return;
    const list = [...this._liveActivities.values()].sort((a, b) =>
      String(b.updatedAt || '').localeCompare(String(a.updatedAt || ''))
    );

    if (list.length === 0) {
      di.setAttribute('data-active', 'false');
      di.setAttribute('data-expanded', 'false');
      this._dom.diPill?.setAttribute('aria-expanded', 'false');
      document.getElementById('dynamic-island-expanded')?.setAttribute('aria-hidden', 'true');
      if (this._dom.diLeading) this._dom.diLeading.textContent = '';
      if (this._dom.diTitle) this._dom.diTitle.textContent = 'OmniOS';
      if (this._dom.diTrailing) this._dom.diTrailing.textContent = '';
      if (this._dom.diExpTitle) this._dom.diExpTitle.textContent = 'No Live Activities';
      if (this._dom.diExpSubtitle) this._dom.diExpSubtitle.textContent = '';
      if (this._dom.diExpBody) this._dom.diExpBody.textContent = '';
      if (this._dom.diExpProgressBar) this._dom.diExpProgressBar.hidden = true;
      if (this._dom.diExpList) this._dom.diExpList.replaceChildren();
      return;
    }

    di.setAttribute('data-active', 'true');
    const primary =
      (this._selectedActivityId && this._liveActivities.get(this._selectedActivityId)) || list[0];
    this._selectedActivityId = primary.id;

    if (this._dom.diLeading) {
      this._dom.diLeading.textContent = String(primary.compactLeading ?? primary.icon ?? '●');
    }
    if (this._dom.diTitle) {
      this._dom.diTitle.textContent = String(primary.title ?? 'Live Activity');
    }
    if (this._dom.diTrailing) {
      this._dom.diTrailing.textContent = String(primary.compactTrailing ?? '');
    }

    if (this._dom.diExpTitle) {
      this._dom.diExpTitle.textContent = String(primary.title ?? 'Live Activity');
    }
    if (this._dom.diExpSubtitle) {
      this._dom.diExpSubtitle.textContent = String(primary.subtitle ?? '');
    }
    if (this._dom.diExpBody) {
      this._dom.diExpBody.textContent =
        typeof primary.expandedBody === 'object' && primary.expandedBody !== null
          ? JSON.stringify(primary.expandedBody)
          : String(primary.expandedBody ?? '');
    }

    if (this._dom.diExpProgressBar && this._dom.diExpProgressFill) {
      if (typeof primary.progress === 'number' && Number.isFinite(primary.progress)) {
        const pct = Math.max(0, Math.min(100, Math.round(primary.progress * 100)));
        this._dom.diExpProgressBar.hidden = false;
        this._dom.diExpProgressFill.style.width = `${pct}%`;
      } else {
        this._dom.diExpProgressBar.hidden = true;
      }
    }

    if (this._dom.diExpList) {
      if (list.length <= 1) {
        this._dom.diExpList.replaceChildren();
      } else {
        const frag = document.createDocumentFragment();
        for (const act of list) {
          const btn = el(
            'button',
            `di-list-item${act.id === primary.id ? ' is-active' : ''}`,
            { type: 'button', 'data-activity-id': String(act.id) },
            `${act.compactLeading ?? ''} ${act.title ?? act.id} ${act.compactTrailing ?? ''}`.trim()
          );
          btn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            this._selectedActivityId = act.id;
            this._renderDynamicIsland();
          });
          frag.appendChild(btn);
        }
        this._dom.diExpList.replaceChildren(frag);
      }
    }
  }

  // ---- Panel Open/Close Controls ----

  closeAllPanels() {
    this._closeMenuDropdown();
    this._setOpen(this._dom.winStartMenu, false);
    this._setOpen(this._dom.iosControlCenter, false);
    this._setOpen(this._dom.androidShade, false);
    this._setOpen(this._dom.androidAppDrawer, false);
    this._setOpen(this._dom.androidRecents, false);
    if (this._dom.dynamicIsland) {
      this._dom.dynamicIsland.setAttribute('data-expanded', 'false');
      this._dom.diPill?.setAttribute('aria-expanded', 'false');
      document.getElementById('dynamic-island-expanded')?.setAttribute('aria-hidden', 'true');
    }
  }

  _setOpen(node, open) {
    if (!node) return;
    node.setAttribute('data-open', open ? 'true' : 'false');
  }

  _togglePanel(node, onOpen = null) {
    if (!node) return;
    const isOpen = node.getAttribute('data-open') === 'true';
    this.closeAllPanels();
    if (!isOpen) {
      node.setAttribute('data-open', 'true');
      if (typeof onOpen === 'function') onOpen();
    }
  }

  setRecentsOpen(open) {
    if (!this._dom.androidRecents) return;
    if (open) {
      this.closeAllPanels();
      this._dom.androidRecents.setAttribute('data-open', 'true');
      this._renderRecents();
      this._client
        .listProcesses()
        .then((res) => {
          if (res?.processes) this.setProcesses(res.processes);
        })
        .catch(() => {});
    } else {
      this._dom.androidRecents.setAttribute('data-open', 'false');
    }
  }

  // ---- Event Wiring ----

  _bindEvents() {
    if (typeof document === 'undefined') return;

    // Delegated clicks for shell mode buttons & system toggles across all panels
    document.addEventListener('click', (ev) => {
      const target = ev.target instanceof Element ? ev.target : null;
      if (!target) return;

      const modeBtn = target.closest('[data-shell-mode-btn]');
      if (modeBtn) {
        ev.stopPropagation();
        const mode = modeBtn.getAttribute('data-shell-mode-btn');
        if (mode) this.switchShellMode(mode);
        return;
      }

      const toggleBtn = target.closest('[data-system-toggle]');
      if (toggleBtn) {
        ev.stopPropagation();
        const key = toggleBtn.getAttribute('data-system-toggle');
        if (key) this.toggleSystemKey(key);
        return;
      }

      const startActionBtn = target.closest('[data-start-action]');
      if (startActionBtn) {
        const act = startActionBtn.getAttribute('data-start-action');
        if (act === 'settings') {
          this.launchOrFocusApp({ appId: 'com.omnios.settings', platform: 'system', builtin: true });
        } else if (act === 'upload') {
          this.closeAllPanels();
          this._overlays?.openUploadModal();
        } else if (act === 'theme') {
          this.toggleSystemKey('system.theme');
        }
      }
    });

    // Close menu dropdown when clicking outside
    this._onDocClick = (ev) => {
      if (
        this._openMenuId &&
        this._dom.menuDropdown &&
        !this._dom.menuDropdown.contains(ev.target) &&
        !this._dom.globalMenuBar?.contains(ev.target)
      ) {
        this._closeMenuDropdown();
      }
    };
    document.addEventListener('click', this._onDocClick);

    // System range sliders (Control Center + Quick Settings)
    const rangeSliders = document.querySelectorAll('[data-system-range]');
    for (const slider of rangeSliders) {
      const key = slider.getAttribute('data-system-range');
      if (!key) continue;
      slider.addEventListener('input', () => {
        const val = Number(slider.value);
        this._systemConfig[key] = val;
        this._applySystemConfigDom();
      });
      slider.addEventListener('change', () => {
        this.setSystemNumericKey(key, Number(slider.value));
      });
    }

    // Top bar triggers
    this._dom.btnSpotlight?.addEventListener('click', () => {
      this.closeAllPanels();
      this._overlays?.openSpotlight();
    });
    this._dom.btnWinSearch?.addEventListener('click', () => {
      this.closeAllPanels();
      this._overlays?.openSpotlight();
    });
    this._dom.btnUploadPkg?.addEventListener('click', () => {
      this.closeAllPanels();
      this._overlays?.openUploadModal();
    });
    this._dom.btnThemeToggle?.addEventListener('click', () => this.toggleSystemKey('system.theme'));
    this._dom.btnChromeToggle?.addEventListener('click', () => this.toggleChromeMode());

    // Dynamic Island pill toggle
    this._dom.diPill?.addEventListener('click', (ev) => {
      ev.stopPropagation();
      if (!this._dom.dynamicIsland) return;
      const expanded = this._dom.dynamicIsland.getAttribute('data-expanded') === 'true';
      const next = !expanded;
      this._dom.dynamicIsland.setAttribute('data-expanded', next ? 'true' : 'false');
      this._dom.diPill?.setAttribute('aria-expanded', next ? 'true' : 'false');
      document.getElementById('dynamic-island-expanded')?.setAttribute('aria-hidden', next ? 'false' : 'true');
    });

    // Control Center toggles
    const toggleCc = () => this._togglePanel(this._dom.iosControlCenter);
    this._dom.btnControlCenter?.addEventListener('click', toggleCc);
    this._dom.btnWinTrayCc?.addEventListener('click', toggleCc);
    this._dom.btnIosCcPull?.addEventListener('click', toggleCc);
    this._dom.btnCloseCc?.addEventListener('click', () => this._setOpen(this._dom.iosControlCenter, false));

    // Notification Shade toggles
    const toggleShade = () => this._togglePanel(this._dom.androidShade);
    this._dom.btnNotifShade?.addEventListener('click', toggleShade);
    this._dom.btnWinTrayNotifs?.addEventListener('click', toggleShade);
    this._dom.btnCloseShade?.addEventListener('click', () => this._setOpen(this._dom.androidShade, false));
    this._dom.btnClearNotifs?.addEventListener('click', () => {
      this._client.clearNotifications().catch(() => {});
    });

    // Windows Start Menu
    this._dom.btnWinStart?.addEventListener('click', () => {
      this._togglePanel(this._dom.winStartMenu, () => {
        this._renderStartMenu();
        this._dom.startSearchInput?.focus();
      });
    });
    this._dom.startSearchInput?.addEventListener('input', () => this._renderStartMenu());

    // iOS SpringBoard & Home Bar
    this._dom.springboardSearch?.addEventListener('input', () => this._renderSpringboard());
    this._dom.btnIosHome?.addEventListener('click', () => {
      this.closeAllPanels();
      const visible = this._windows.filter((w) => w.state !== 'minimized');
      if (visible.length > 0) {
        for (const w of visible) {
          this._compositorUI?.setWindowState(w.windowId, 'minimized');
        }
      } else if (this._windows.length > 0) {
        this._compositorUI?.focusWindow(this._windows[this._windows.length - 1].windowId);
      }
    });
    this._dom.btnIosSwitcher?.addEventListener('click', () => {
      const isOpen = this._dom.androidRecents?.getAttribute('data-open') === 'true';
      this.setRecentsOpen(!isOpen);
    });

    // Android Drawer, Recents, and 3-Button Nav Bar
    this._dom.btnAndroidDrawer?.addEventListener('click', () => {
      this._togglePanel(this._dom.androidAppDrawer, () => {
        this._renderAndroidDrawer();
        this._dom.drawerSearchInput?.focus();
      });
    });
    this._dom.btnCloseDrawer?.addEventListener('click', () =>
      this._setOpen(this._dom.androidAppDrawer, false)
    );
    this._dom.drawerSearchInput?.addEventListener('input', () => this._renderAndroidDrawer());

    this._dom.btnAndroidRecents?.addEventListener('click', () => {
      const isOpen = this._dom.androidRecents?.getAttribute('data-open') === 'true';
      this.setRecentsOpen(!isOpen);
    });
    this._dom.btnCloseRecents?.addEventListener('click', () => this.setRecentsOpen(false));

    this._dom.btnAndroidHome?.addEventListener('click', () => {
      this.closeAllPanels();
      for (const w of this._windows) {
        if (w.state !== 'minimized') {
          this._compositorUI?.setWindowState(w.windowId, 'minimized');
        }
      }
    });

    this._dom.btnAndroidBack?.addEventListener('click', () => {
      const openPanel = [
        this._dom.androidRecents,
        this._dom.androidAppDrawer,
        this._dom.androidShade,
        this._dom.iosControlCenter,
        this._dom.winStartMenu,
      ].find((p) => p?.getAttribute('data-open') === 'true');
      if (openPanel) {
        openPanel.setAttribute('data-open', 'false');
        return;
      }
      if (this._focusedWindowId) {
        this._client
          .dispatchInput(this._focusedWindowId, { type: 'keydown', key: 'Escape', keyCode: 27 })
          .catch(() => {});
      }
    });
  }

  _startClock() {
    const update = () => {
      const str = formatClock();
      if (this._dom.topClock) this._dom.topClock.textContent = str;
      if (this._dom.winTrayClock) this._dom.winTrayClock.textContent = str;
    };
    update();
    this._clockTimer = setInterval(update, 15_000);
  }
}

export function createShellModeController(options) {
  return new ShellModeController(options);
}
