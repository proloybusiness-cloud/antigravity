// OmniOS M6 Compositor Window Manager & Dual-Mode uiTree + Canvas Surface Renderer
// Strictly XSS-safe: uses ONLY createElement / textContent / setAttribute / replaceChildren.

import { sanitizeCssColor, normalizeShellMode } from './ws-client.js';
import { renderDrawOps, attachCanvasInteraction } from './canvas-renderer.js';

const PLATFORM_BADGES = Object.freeze({
  android: 'AND',
  windows: 'WIN',
  ios: 'iOS',
  macos: 'MAC',
  universal: 'WASM',
  system: 'SYS',
});

const SNAP_ZONES = Object.freeze([
  { state: 'snapped-left', label: 'Left Half' },
  { state: 'snapped-right', label: 'Right Half' },
  { state: 'snapped-tl', label: 'Top Left' },
  { state: 'snapped-tr', label: 'Top Right' },
  { state: 'snapped-bl', label: 'Bottom Left' },
  { state: 'snapped-br', label: 'Bottom Right' },
  { state: 'maximized', label: 'Maximize' },
  { state: 'normal', label: 'Restore' },
]);

const SYSTEM_HIVES = Object.freeze(['HKCU', 'HKLM', 'HKCR', 'HKU', 'HKCC']);
const REG_TYPES = Object.freeze([
  'REG_SZ',
  'REG_DWORD',
  'REG_QWORD',
  'REG_EXPAND_SZ',
  'REG_MULTI_SZ',
  'REG_BINARY',
]);

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

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function safeJsonPreview(obj, maxLen = 400) {
  try {
    const s = JSON.stringify(obj, null, 2);
    if (!s) return '';
    return s.length > maxLen ? `${s.slice(0, maxLen)}…` : s;
  } catch {
    return String(obj ?? '');
  }
}

function treeContainsCanvas(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'canvas') return true;
  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      if (treeContainsCanvas(child)) return true;
    }
  }
  return false;
}

function getPlatformBadge(platform) {
  const key = String(platform || 'system').toLowerCase();
  return PLATFORM_BADGES[key] || key.slice(0, 4).toUpperCase();
}

export class CompositorUI {
  constructor({ windowLayerEl, snapPreviewEl, client, onStateChange } = {}) {
    this._layerEl = windowLayerEl ?? null;
    this._snapPreviewEl = snapPreviewEl ?? null;
    this._client = client;
    this._onStateChange = typeof onStateChange === 'function' ? onStateChange : () => {};

    this._windows = new Map();
    this._focusedWindowId = null;
    this._activeMenuBar = [];
    this._shellMode = 'unified';
    this._chromeMode = 'adaptive';
    this._viewport = { width: 1440, height: 900, insets: { top: 0, bottom: 0, left: 0, right: 0 } };
    this._openSnapMenuWinId = null;

    this._onDocClickClosePopovers = (ev) => {
      if (!this._openSnapMenuWinId) return;
      const entry = this._windows.get(this._openSnapMenuWinId);
      if (!entry) {
        this._openSnapMenuWinId = null;
        return;
      }
      if (!entry.refs.snapPopover.contains(ev.target) && !entry.refs.btnSnap.contains(ev.target)) {
        entry.refs.snapPopover.setAttribute('data-open', 'false');
        this._openSnapMenuWinId = null;
      }
    };
    if (typeof document !== 'undefined') {
      document.addEventListener('click', this._onDocClickClosePopovers);
    }

    this._onWindowResize = () => {
      for (const entry of this._windows.values()) {
        if (entry.data.state !== 'normal' && entry.data.state !== 'minimized') {
          this._applyWindowGeometry(entry);
        }
      }
    };
    if (typeof window !== 'undefined') {
      window.addEventListener('resize', this._onWindowResize);
    }
  }

  destroy() {
    if (typeof document !== 'undefined') {
      document.removeEventListener('click', this._onDocClickClosePopovers);
    }
    if (typeof window !== 'undefined') {
      window.removeEventListener('resize', this._onWindowResize);
    }
  }

  getWindows() {
    return [...this._windows.values()]
      .map((e) => e.data)
      .sort((a, b) => (a.zIndex ?? 0) - (b.zIndex ?? 0));
  }

  getWindow(windowId) {
    return this._windows.get(windowId)?.data ?? null;
  }

  getFocusedWindowId() {
    return this._focusedWindowId;
  }

  getActiveMenuBar() {
    return this._activeMenuBar;
  }

  setShellMode(mode) {
    this._shellMode = normalizeShellMode(mode);
    for (const entry of this._windows.values()) {
      this._applyWindowAttributes(entry);
      this._applyWindowGeometry(entry);
    }
  }

  setChromeMode(mode) {
    this._chromeMode = mode === 'unified' ? 'unified' : 'adaptive';
    for (const entry of this._windows.values()) {
      this._applyWindowAttributes(entry);
    }
  }

  applySnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== 'object') return;
    if (snapshot.shellMode) {
      this._shellMode = normalizeShellMode(snapshot.shellMode);
    }
    if (snapshot.viewport) {
      this._viewport = snapshot.viewport;
    }
    this._focusedWindowId = snapshot.focusedWindowId ?? null;
    if (Array.isArray(snapshot.activeMenuBar)) {
      this._activeMenuBar = snapshot.activeMenuBar;
    }

    const incoming = Array.isArray(snapshot.windows) ? snapshot.windows : [];
    const seen = new Set();

    for (const win of incoming) {
      if (!win || !win.windowId) continue;
      seen.add(win.windowId);
      this._upsertWindow(win, { renderSurface: true });
    }

    for (const winId of [...this._windows.keys()]) {
      if (!seen.has(winId)) {
        this._removeWindowDom(winId);
      }
    }

    this._syncFocusFlags();
    this._emitStateChange('snapshot');
  }

  handleWindowCreated(payload) {
    if (!payload || !payload.window) return;
    if (payload.focusedWindowId !== undefined) this._focusedWindowId = payload.focusedWindowId;
    if (Array.isArray(payload.activeMenuBar)) this._activeMenuBar = payload.activeMenuBar;
    this._upsertWindow(payload.window, { renderSurface: true });
    this._syncFocusFlags();
    this._emitStateChange('window_created');
  }

  handleWindowUpdated(payload) {
    if (!payload || !payload.window) return;
    if (payload.focusedWindowId !== undefined) this._focusedWindowId = payload.focusedWindowId;
    if (Array.isArray(payload.activeMenuBar)) this._activeMenuBar = payload.activeMenuBar;
    const prev = this._windows.get(payload.window.windowId);
    const shouldRenderSurface =
      !prev ||
      payload.reason === 'surface_meta' ||
      (payload.window.surfaceRevision ?? 0) > (prev.data.surfaceRevision ?? 0);
    this._upsertWindow(payload.window, { renderSurface: shouldRenderSurface });
    this._syncFocusFlags();
    this._emitStateChange('window_updated');
  }

  handleSurfacePatch(payload) {
    if (!payload || !payload.windowId) return;
    const entry = this._windows.get(payload.windowId);
    if (!entry) return;

    const nextRev = Number(payload.surfaceRevision ?? 0);
    const curRev = Number(entry.data.surfaceRevision ?? 0);
    // Guard against out-of-order stale surface patches
    if (nextRev > 0 && curRev > 0 && nextRev < curRev) return;

    if (typeof payload.title === 'string') entry.data.title = payload.title;
    if (payload.menuBar !== undefined) entry.data.menuBar = payload.menuBar;
    if (payload.surface && typeof payload.surface === 'object') {
      entry.data.surface = {
        uiTree: payload.surface.uiTree ?? null,
        drawOps: Array.isArray(payload.surface.drawOps) ? payload.surface.drawOps : [],
      };
    }
    if (nextRev > 0) entry.data.surfaceRevision = nextRev;
    if (Array.isArray(payload.activeMenuBar)) {
      this._activeMenuBar = payload.activeMenuBar;
    }

    this._applyWindowAttributes(entry);
    this._renderWindowSurface(entry);
    this._emitStateChange('surface_patch');
  }

  handleWindowClosed(payload) {
    if (!payload || !payload.windowId) return;
    if (payload.focusedWindowId !== undefined) this._focusedWindowId = payload.focusedWindowId;
    if (Array.isArray(payload.activeMenuBar)) this._activeMenuBar = payload.activeMenuBar;
    this._removeWindowDom(payload.windowId);
    this._syncFocusFlags();
    this._emitStateChange('window_closed');
  }

  focusWindow(windowId) {
    if (!windowId) return;
    const entry = this._windows.get(windowId);
    if (entry) {
      let maxZ = 1;
      for (const e of this._windows.values()) {
        const z = Number(e.data?.zIndex) || 1;
        if (z > maxZ) maxZ = z;
      }
      const nextZ = Math.max(Number(entry.data?.zIndex) || 1, maxZ + 1);
      entry.data.zIndex = nextZ;
      entry.el.style.zIndex = String(10 + nextZ);
      this._focusedWindowId = windowId;
      this._syncFocusFlags();
    }
    this._client?.focusWindow(windowId).catch(() => {});
  }

  closeWindow(windowId) {
    if (!windowId) return;
    this._client?.closeWindow(windowId).catch(() => {});
  }

  setWindowState(windowId, state) {
    if (!windowId || !state) return;
    this._client?.setWindowState(windowId, state).catch(() => {});
  }

  _emitStateChange(reason) {
    this._onStateChange({
      reason,
      shellMode: this._shellMode,
      focusedWindowId: this._focusedWindowId,
      activeMenuBar: this._activeMenuBar,
      windows: this.getWindows(),
    });
  }

  _syncFocusFlags() {
    for (const entry of this._windows.values()) {
      const isFocused = entry.data.windowId === this._focusedWindowId;
      entry.data.focused = isFocused;
      entry.el.setAttribute('data-focused', isFocused ? 'true' : 'false');
    }
  }

  _removeWindowDom(windowId) {
    const entry = this._windows.get(windowId);
    if (!entry) return;
    if (this._openSnapMenuWinId === windowId) this._openSnapMenuWinId = null;
    if (entry.canvasDetach) {
      try {
        entry.canvasDetach();
      } catch {
        // ignore
      }
    }
    if (entry.el.parentNode) {
      entry.el.parentNode.removeChild(entry.el);
    }
    this._windows.delete(windowId);
  }

  _upsertWindow(win, { renderSurface = false } = {}) {
    let entry = this._windows.get(win.windowId);
    if (!entry) {
      entry = this._createWindowElement(win);
      this._windows.set(win.windowId, entry);
      if (this._layerEl) {
        this._layerEl.appendChild(entry.el);
      }
      renderSurface = true;
    } else {
      entry.data = {
        ...entry.data,
        ...win,
        bounds: win.bounds ? { ...win.bounds } : entry.data.bounds,
        restoreBounds: win.restoreBounds ? { ...win.restoreBounds } : entry.data.restoreBounds,
        surface: win.surface
          ? {
              uiTree: win.surface.uiTree ?? null,
              drawOps: Array.isArray(win.surface.drawOps) ? win.surface.drawOps : [],
            }
          : entry.data.surface,
      };
    }

    this._applyWindowAttributes(entry);
    entry.el.style.zIndex = String(10 + (Number(entry.data.zIndex) || 1));
    if (!entry.isDragging && !entry.isResizing) {
      this._applyWindowGeometry(entry);
    }
    if (renderSurface) {
      this._renderWindowSurface(entry);
    }
  }

  _resolveChromeStyle(win) {
    if (this._chromeMode === 'unified') return 'unified';
    const raw = String(win.chromeStyle || win.platform || 'unified').toLowerCase();
    if (['unified', 'macos', 'windows', 'ios', 'android', 'frameless'].includes(raw)) {
      return raw;
    }
    return 'unified';
  }

  _applyWindowAttributes(entry) {
    const win = entry.data;
    const chrome = this._resolveChromeStyle(win);
    const platform = String(win.platform || 'system').toLowerCase();
    const isFocused = win.windowId === this._focusedWindowId || Boolean(win.focused);

    entry.el.setAttribute('data-window-id', String(win.windowId));
    entry.el.setAttribute('data-pid', String(win.pid ?? ''));
    entry.el.setAttribute('data-app-id', String(win.appId ?? ''));
    entry.el.setAttribute('data-platform', platform);
    entry.el.setAttribute('data-chrome-style', chrome);
    entry.el.setAttribute('data-window-state', String(win.state || 'normal'));
    entry.el.setAttribute('data-surface-revision', String(win.surfaceRevision ?? 1));
    entry.el.setAttribute('data-focused', isFocused ? 'true' : 'false');
    entry.el.setAttribute('aria-label', String(win.title ?? 'Window'));

    entry.refs.titleEl.textContent = String(win.title ?? 'Untitled');
    entry.refs.pidChip.textContent = `PID ${win.pid ?? '?'}`;
    entry.refs.platformBadge.className = `platform-badge platform-${platform}`;
    entry.refs.platformBadge.textContent = getPlatformBadge(platform);
  }

  _computeStateGeometry(state, bounds) {
    const layerW = this._layerEl?.clientWidth || this._viewport.width || 1280;
    const layerH = this._layerEl?.clientHeight || this._viewport.height || 760;
    const halfW = Math.floor(layerW / 2);
    const halfH = Math.floor(layerH / 2);

    switch (state) {
      case 'maximized':
      case 'fullscreen':
        return { x: 0, y: 0, width: layerW, height: layerH };
      case 'snapped-left':
        return { x: 0, y: 0, width: halfW, height: layerH };
      case 'snapped-right':
        return { x: halfW, y: 0, width: layerW - halfW, height: layerH };
      case 'snapped-tl':
        return { x: 0, y: 0, width: halfW, height: halfH };
      case 'snapped-tr':
        return { x: halfW, y: 0, width: layerW - halfW, height: halfH };
      case 'snapped-bl':
        return { x: 0, y: halfH, width: halfW, height: layerH - halfH };
      case 'snapped-br':
        return { x: halfW, y: halfH, width: layerW - halfW, height: layerH - halfH };
      default: {
        const x = Number.isFinite(bounds?.x) ? bounds.x : 60;
        const y = Number.isFinite(bounds?.y) ? bounds.y : 40;
        const width = Math.max(240, Number.isFinite(bounds?.width) ? bounds.width : 640);
        const height = Math.max(180, Number.isFinite(bounds?.height) ? bounds.height : 480);
        return { x, y, width, height };
      }
    }
  }

  _applyWindowGeometry(entry) {
    const win = entry.data;
    const geom = this._computeStateGeometry(win.state, win.bounds);
    entry.el.style.zIndex = String(10 + (Number(win.zIndex) || 1));

    // In mobile shell modes (iOS/Android), let mode CSS present full-bleed cards cleanly
    if (this._shellMode === 'ios' || this._shellMode === 'android') {
      entry.el.style.left = '';
      entry.el.style.top = '';
      entry.el.style.width = '';
      entry.el.style.height = '';
      return;
    }

    entry.el.style.left = `${Math.round(geom.x)}px`;
    entry.el.style.top = `${Math.round(geom.y)}px`;
    entry.el.style.width = `${Math.round(geom.width)}px`;
    entry.el.style.height = `${Math.round(geom.height)}px`;
  }

  _createWindowElement(win) {
    const winId = win.windowId;
    const article = el('article', 'omni-window', {
      role: 'dialog',
      'aria-label': String(win.title ?? 'Window'),
    });

    // Header
    const header = el('div', 'window-header');
    const controls = el('div', 'window-controls');

    const btnClose = el(
      'button',
      'win-btn win-btn-close',
      { type: 'button', 'data-win-action': 'close', 'aria-label': 'Close', title: 'Close' },
      '×'
    );
    const btnMin = el(
      'button',
      'win-btn win-btn-min',
      { type: 'button', 'data-win-action': 'minimize', 'aria-label': 'Minimize', title: 'Minimize' },
      '−'
    );
    const btnMax = el(
      'button',
      'win-btn win-btn-max',
      { type: 'button', 'data-win-action': 'maximize', 'aria-label': 'Maximize', title: 'Maximize' },
      '□'
    );
    const btnSnap = el(
      'button',
      'win-btn win-btn-snap',
      { type: 'button', 'data-win-action': 'snap-menu', 'aria-label': 'Snap Layouts', title: 'Snap Layouts' },
      '⊞'
    );

    const snapPopover = el('div', 'snap-layout-popover', { 'data-open': 'false', role: 'menu' });
    for (const zone of SNAP_ZONES) {
      const sBtn = el(
        'button',
        'snap-zone-btn',
        { type: 'button', 'data-snap-state': zone.state, role: 'menuitem' },
        zone.label
      );
      sBtn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        snapPopover.setAttribute('data-open', 'false');
        this._openSnapMenuWinId = null;
        this.setWindowState(winId, zone.state);
      });
      snapPopover.appendChild(sBtn);
    }

    controls.append(btnClose, btnMin, btnMax, btnSnap, snapPopover);

    const titleGroup = el('div', 'window-title-group');
    const platformBadge = el('span', 'platform-badge');
    const titleEl = el('span', 'window-title');
    const pidChip = el('span', 'window-pid-chip');
    titleGroup.append(platformBadge, titleEl, pidChip);

    header.append(controls, titleGroup);

    // Body
    const body = el('div', 'window-body');
    const canvasHost = el('div', 'window-canvas-host', { hidden: '' });
    const uiTreeHost = el('div', 'window-uitree-host');
    body.append(canvasHost, uiTreeHost);

    article.append(header, body);

    // 6 Resize handles
    const resizeDirs = ['e', 's', 'se', 'w', 'sw', 'ne'];
    for (const dir of resizeDirs) {
      const handle = el('div', `window-resize-handle resize-${dir}`, {
        'data-resize-dir': dir,
        'aria-hidden': 'true',
      });
      article.appendChild(handle);
    }

    const entry = {
      data: {
        ...win,
        bounds: win.bounds ? { ...win.bounds } : { x: 60, y: 40, width: 640, height: 480 },
        restoreBounds: win.restoreBounds
          ? { ...win.restoreBounds }
          : { x: 60, y: 40, width: 640, height: 480 },
        surface: {
          uiTree: win.surface?.uiTree ?? null,
          drawOps: Array.isArray(win.surface?.drawOps) ? win.surface.drawOps : [],
        },
      },
      el: article,
      refs: {
        header,
        controls,
        btnClose,
        btnMin,
        btnMax,
        btnSnap,
        snapPopover,
        platformBadge,
        titleEl,
        pidChip,
        body,
        canvasHost,
        uiTreeHost,
        topCanvas: null,
        embeddedCanvas: null,
      },
      isDragging: false,
      isResizing: false,
      canvasDetach: null,
      localDrafts: new Map(),
      reusableInputs: new Map(),
      lastTermLineCount: 0,
      formCache: new Map(),
    };

    // Focus on pointerdown anywhere inside window
    article.addEventListener('pointerdown', () => {
      if (this._focusedWindowId !== winId) {
        this.focusWindow(winId);
      }
    });

    // Window chrome buttons
    btnClose.addEventListener('click', (ev) => {
      ev.stopPropagation();
      this.closeWindow(winId);
    });
    btnMin.addEventListener('click', (ev) => {
      ev.stopPropagation();
      this.setWindowState(winId, 'minimized');
    });
    btnMax.addEventListener('click', (ev) => {
      ev.stopPropagation();
      const next = entry.data.state === 'maximized' ? 'normal' : 'maximized';
      this.setWindowState(winId, next);
    });
    btnSnap.addEventListener('click', (ev) => {
      ev.stopPropagation();
      const isOpen = snapPopover.getAttribute('data-open') === 'true';
      if (this._openSnapMenuWinId && this._openSnapMenuWinId !== winId) {
        const prevEntry = this._windows.get(this._openSnapMenuWinId);
        prevEntry?.refs.snapPopover.setAttribute('data-open', 'false');
      }
      snapPopover.setAttribute('data-open', isOpen ? 'false' : 'true');
      this._openSnapMenuWinId = isOpen ? null : winId;
    });

    // Double-click titlebar toggles maximize
    header.addEventListener('dblclick', (ev) => {
      if (controls.contains(ev.target)) return;
      const next = entry.data.state === 'maximized' ? 'normal' : 'maximized';
      this.setWindowState(winId, next);
    });

    this._bindDrag(entry);
    this._bindResize(entry);

    return entry;
  }

  _bindDrag(entry) {
    const { header, controls } = entry.refs;
    const winId = entry.data.windowId;

    header.addEventListener('pointerdown', (ev) => {
      if (ev.button !== 0) return;
      if (controls.contains(ev.target)) return;
      if (this._shellMode === 'ios' || this._shellMode === 'android') return;

      ev.preventDefault();
      if (this._focusedWindowId !== winId) this.focusWindow(winId);

      const startX = ev.clientX;
      const startY = ev.clientY;
      const origX = entry.el.offsetLeft;
      const origY = entry.el.offsetTop;
      let moved = false;
      let pendingSnap = null;
      let currentX = origX;
      let currentY = origY;

      entry.isDragging = true;
      entry.el.classList.add('is-dragging');
      try {
        header.setPointerCapture(ev.pointerId);
      } catch {
        // ignore if unsupported in headless synthetic event
      }

      const detectSnapZone = (clientX, clientY) => {
        if (!this._layerEl) return null;
        if (!this._layerRectResizeBound && typeof window !== 'undefined') {
          this._layerRectResizeBound = true;
          window.addEventListener('resize', () => {
            this._layerRectCache = null;
          });
        }
        const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
        let rect = this._layerRectCache;
        if (!rect || (now - (this._layerRectCacheTs || 0)) > 150) {
          rect = this._layerEl.getBoundingClientRect();
          this._layerRectCache = rect;
          this._layerRectCacheTs = now;
        }
        const nearLeft = clientX <= rect.left + 16;
        const nearRight = clientX >= rect.right - 16;
        const nearTop = clientY <= rect.top + 10;
        const nearBottom = clientY >= rect.bottom - 24;
        if (nearLeft && nearTop) return 'snapped-tl';
        if (nearLeft && nearBottom) return 'snapped-bl';
        if (nearRight && nearTop) return 'snapped-tr';
        if (nearRight && nearBottom) return 'snapped-br';
        if (nearLeft) return 'snapped-left';
        if (nearRight) return 'snapped-right';
        if (nearTop) return 'maximized';
        return null;
      };

      const onMove = (me) => {
        const dx = me.clientX - startX;
        const dy = me.clientY - startY;
        if (!moved && Math.hypot(dx, dy) < 3) return;
        moved = true;
        currentX = Math.round(origX + dx);
        currentY = Math.max(0, Math.round(origY + dy));
        entry.el.style.left = `${currentX}px`;
        entry.el.style.top = `${currentY}px`;

        pendingSnap = detectSnapZone(me.clientX, me.clientY);
        this._updateSnapPreview(pendingSnap);
      };

      const onUp = () => {
        entry.isDragging = false;
        entry.el.classList.remove('is-dragging');
        this._updateSnapPreview(null);
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        window.removeEventListener('pointercancel', onUp);

        if (pendingSnap) {
          this.setWindowState(winId, pendingSnap);
        } else if (moved) {
          entry.data.bounds.x = currentX;
          entry.data.bounds.y = currentY;
          if (entry.data.state !== 'normal') {
            this.setWindowState(winId, 'normal');
          }
          this._client?.moveWindow(winId, currentX, currentY).catch(() => {});
        }
      };

      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
      window.addEventListener('pointercancel', onUp);
    });
  }

  _bindResize(entry) {
    const winId = entry.data.windowId;
    const handles = entry.el.querySelectorAll('.window-resize-handle');

    for (const handle of handles) {
      const dir = handle.getAttribute('data-resize-dir') || 'se';
      handle.addEventListener('pointerdown', (ev) => {
        if (ev.button !== 0) return;
        if (this._shellMode === 'ios' || this._shellMode === 'android') return;

        ev.preventDefault();
        ev.stopPropagation();
        if (this._focusedWindowId !== winId) this.focusWindow(winId);

        const startX = ev.clientX;
        const startY = ev.clientY;
        const origX = entry.el.offsetLeft;
        const origY = entry.el.offsetTop;
        const origW = entry.el.offsetWidth || entry.data.bounds.width || 640;
        const origH = entry.el.offsetHeight || entry.data.bounds.height || 480;

        let newX = origX;
        let newY = origY;
        let newW = origW;
        let newH = origH;

        entry.isResizing = true;
        entry.el.classList.add('is-resizing');

        const onMove = (me) => {
          const dx = me.clientX - startX;
          const dy = me.clientY - startY;
          newX = origX;
          newY = origY;
          newW = origW;
          newH = origH;

          if (dir.includes('e')) {
            newW = Math.max(260, Math.round(origW + dx));
          }
          if (dir.includes('s')) {
            newH = Math.max(180, Math.round(origH + dy));
          }
          if (dir.includes('w')) {
            const clampedW = Math.max(260, Math.round(origW - dx));
            newX = Math.round(origX + (origW - clampedW));
            newW = clampedW;
          }
          if (dir.includes('n')) {
            const clampedH = Math.max(180, Math.round(origH - dy));
            newY = Math.max(0, Math.round(origY + (origH - clampedH)));
            newH = clampedH;
          }

          entry.el.style.left = `${newX}px`;
          entry.el.style.top = `${newY}px`;
          entry.el.style.width = `${newW}px`;
          entry.el.style.height = `${newH}px`;
        };

        const onUp = () => {
          entry.isResizing = false;
          entry.el.classList.remove('is-resizing');
          window.removeEventListener('pointermove', onMove);
          window.removeEventListener('pointerup', onUp);
          window.removeEventListener('pointercancel', onUp);

          entry.data.bounds.x = newX;
          entry.data.bounds.y = newY;
          entry.data.bounds.width = newW;
          entry.data.bounds.height = newH;

          if (newW !== origW || newH !== origH) {
            this._client?.resizeWindow(winId, newW, newH).catch(() => {});
          }
          if (newX !== origX || newY !== origY) {
            this._client?.moveWindow(winId, newX, newY).catch(() => {});
          }
        };

        window.addEventListener('pointermove', onMove);
        window.addEventListener('pointerup', onUp);
        window.addEventListener('pointercancel', onUp);
      });
    }
  }

  _updateSnapPreview(snapZone) {
    if (!this._snapPreviewEl) return;
    if (!snapZone) {
      this._snapPreviewEl.setAttribute('data-active', 'false');
      this._snapPreviewEl.removeAttribute('data-snap-zone');
      return;
    }
    const geom = this._computeStateGeometry(snapZone, null);
    this._snapPreviewEl.setAttribute('data-active', 'true');
    this._snapPreviewEl.setAttribute('data-snap-zone', snapZone);
    this._snapPreviewEl.style.left = `${Math.round(geom.x)}px`;
    this._snapPreviewEl.style.top = `${Math.round(geom.y)}px`;
    this._snapPreviewEl.style.width = `${Math.round(geom.width)}px`;
    this._snapPreviewEl.style.height = `${Math.round(geom.height)}px`;
  }

  // ---- Input Dispatch Helpers ----

  _sendInput(entry, event) {
    if (!this._client || !entry?.data?.windowId) return;
    this._client.dispatchInput(entry.data.windowId, event).catch(() => {});
  }

  _sendAction(entry, node, extra = {}) {
    const p = node?.props ?? {};
    const action = extra.action ?? p.action ?? node?.action ?? node?.id;
    const evt = {
      type: 'action',
      ...(node?.id ? { targetId: node.id, nodeId: node.id } : {}),
      ...(action ? { action } : {}),
      ...(typeof node?.viewId === 'number' ? { viewId: node.viewId } : {}),
      ...(typeof node?.controlId === 'number' ? { controlId: node.controlId } : {}),
      ...(typeof node?.tag === 'number' ? { tag: node.tag } : {}),
      ...(p.label || node?.label || p.text || node?.text
        ? { label: p.label ?? node?.label ?? p.text ?? node?.text }
        : {}),
      ...(p.command !== undefined ? { command: p.command } : {}),
      ...(p.mode !== undefined ? { mode: p.mode } : {}),
      ...(p.path !== undefined ? { path: p.path } : {}),
      ...(p.tab !== undefined ? { tab: p.tab } : {}),
      ...(p.platform !== undefined ? { platform: p.platform } : {}),
      ...(p.section !== undefined ? { section: p.section } : {}),
      ...extra,
    };
    this._sendInput(entry, evt);
  }

  // ---- Dual-Mode Surface Renderer ----

  _renderWindowSurface(entry) {
    const win = entry.data;
    const surface = win.surface ?? { uiTree: null, drawOps: [] };
    const uiTree = surface.uiTree ?? null;
    const drawOps = Array.isArray(surface.drawOps) ? surface.drawOps : [];
    const platform = String(win.platform || 'system').toLowerCase();
    const role = uiTree?.role ?? null;
    const embeddedCanvasInTree = treeContainsCanvas(uiTree);

    // 1. Capture focus & scroll positions before updating uiTreeHost
    const activeEl = document.activeElement;
    let focusSnapshot = null;
    if (activeEl && entry.refs.uiTreeHost.contains(activeEl)) {
      const key = activeEl.getAttribute('data-focus-key') || activeEl.getAttribute('data-node-id');
      if (key) {
        const isText = activeEl.tagName === 'INPUT' || activeEl.tagName === 'TEXTAREA';
        focusSnapshot = {
          key,
          isText,
          selectionStart: isText ? activeEl.selectionStart : null,
          selectionEnd: isText ? activeEl.selectionEnd : null,
          value: isText ? activeEl.value : null,
        };
      }
    }
    const prevBodyScroll = entry.refs.body.scrollTop;
    const prevTermOut = entry.refs.uiTreeHost.querySelector('[data-node-id="term-output"]');
    const prevTermScroll = prevTermOut ? prevTermOut.scrollTop : null;

    // 2. Decide top-level canvas host visibility per dual-surface rules (SCOPE.md § 2.4)
    const showTopCanvas =
      !embeddedCanvasInTree &&
      drawOps.length > 0 &&
      (role === 'activity-monitor' ||
        platform === 'windows' ||
        uiTree === null ||
        (platform !== 'ios' && platform !== 'macos'));

    if (showTopCanvas) {
      entry.refs.canvasHost.hidden = false;
      let canvas = entry.refs.topCanvas;
      if (!canvas) {
        canvas = el('canvas', 'omni-surface-canvas');
        entry.refs.topCanvas = canvas;
        entry.refs.canvasHost.replaceChildren(canvas);
        entry.canvasDetach = attachCanvasInteraction(canvas, {
          onCanvasClick: (evt) => this._sendInput(entry, evt),
          onCanvasDrag: (evt) => this._sendInput(entry, evt),
        });
      }
      const dims =
        role === 'activity-monitor'
          ? { width: 400, height: 90 }
          : {
              minWidth: Math.min(win.bounds?.width || 480, 640),
              minHeight: platform === 'windows' ? 120 : Math.min(win.bounds?.height || 360, 480),
            };
      renderDrawOps(canvas, drawOps, { ...dims, isAndroid: platform === 'android' });
    } else {
      entry.refs.canvasHost.hidden = true;
    }

    // 3. Render semantic uiTree
    const usedInputIds = new Set();
    if (uiTree && typeof uiTree === 'object') {
      entry.refs.uiTreeHost.hidden = false;
      const ctx = {
        entry,
        win,
        platform,
        role,
        drawOps,
        isAndroid: platform === 'android',
        usedInputIds,
      };
      const renderedRoot = this._renderUiNode(uiTree, ctx);
      const childrenToMount = [];
      if (renderedRoot) childrenToMount.push(renderedRoot);

      // macOS NSAlert sheet stored on root uiTree.modal
      if (uiTree.modal && typeof uiTree.modal === 'object') {
        childrenToMount.push(this._renderMacModal(uiTree.modal, ctx));
      }

      entry.refs.uiTreeHost.replaceChildren(...childrenToMount);
    } else {
      entry.refs.uiTreeHost.hidden = true;
      entry.refs.uiTreeHost.replaceChildren();
    }

    // Prune unused cached input elements so switching tabs never leaks DOM references
    for (const cachedId of [...entry.reusableInputs.keys()]) {
      if (!usedInputIds.has(cachedId)) {
        entry.reusableInputs.delete(cachedId);
      }
    }

    // 4. Restore scroll & focus seamlessly
    entry.refs.body.scrollTop = prevBodyScroll;

    const newTermOut = entry.refs.uiTreeHost.querySelector('[data-node-id="term-output"]');
    if (newTermOut) {
      const lineCount = newTermOut.children.length;
      if (lineCount !== entry.lastTermLineCount || prevTermScroll === null) {
        newTermOut.scrollTop = newTermOut.scrollHeight;
        entry.lastTermLineCount = lineCount;
      } else {
        newTermOut.scrollTop = prevTermScroll;
      }
    }

    if (focusSnapshot) {
      const esc =
        typeof CSS !== 'undefined' && typeof CSS.escape === 'function'
          ? CSS.escape(focusSnapshot.key)
          : focusSnapshot.key.replace(/["\\]/g, '\\$&');
      const target = entry.refs.uiTreeHost.querySelector(
        `[data-focus-key="${esc}"], [data-node-id="${esc}"]`
      );
      if (target && typeof target.focus === 'function') {
        target.focus({ preventScroll: true });
        if (
          focusSnapshot.isText &&
          typeof target.setSelectionRange === 'function' &&
          focusSnapshot.selectionStart !== null
        ) {
          try {
            const maxLen = target.value.length;
            target.setSelectionRange(
              Math.min(focusSnapshot.selectionStart, maxLen),
              Math.min(focusSnapshot.selectionEnd ?? focusSnapshot.selectionStart, maxLen)
            );
          } catch {
            // some input types don't support setSelectionRange
          }
        }
      }
    }
  }

  _applyCommonNodeStyle(domEl, node, ctx) {
    const p = node.props ?? {};
    const isAndroid = ctx.isAndroid || Boolean(node.androidClass);
    const bgRaw = node.backgroundColor ?? p.backgroundColor;
    const fgRaw = node.textColor ?? node.color ?? p.textColor ?? p.color;

    if (bgRaw) {
      const safeBg = sanitizeCssColor(bgRaw, { isAndroid });
      if (safeBg) domEl.style.backgroundColor = safeBg;
    }
    if (fgRaw) {
      const safeFg = sanitizeCssColor(fgRaw, { isAndroid });
      if (safeFg) domEl.style.color = safeFg;
    }
    const textSize = node.textSize ?? p.textSize;
    if (typeof textSize === 'number' && Number.isFinite(textSize) && textSize >= 8 && textSize <= 72) {
      domEl.style.fontSize = `${Math.round(textSize)}px`;
    } else if (typeof textSize === 'string') {
      const m = /^(\d{1,2}(?:\.\d+)?)\s*(?:sp|dp|px)?$/i.exec(textSize.trim());
      if (m) {
        const sz = Math.max(8, Math.min(72, Number(m[1])));
        domEl.style.fontSize = `${sz}px`;
      }
    }
  }

  _renderUiNode(node, ctx) {
    if (!node || typeof node !== 'object') return null;

    // Visibility handling: Android uses `visible: false`; iOS/macOS use `hidden: true`
    if (node.hidden === true || node.visible === false) return null;

    const p = node.props ?? {};
    const type = String(node.type || 'container').toLowerCase();
    const id = node.id ? String(node.id) : '';
    const children = Array.isArray(node.children) ? node.children : [];

    // Specialized system-app panels & rows
    if (id === 'monitor-content' && type === 'panel') {
      return this._renderMonitorPanel(node, ctx);
    }
    if (id === 'settings-body' && type === 'panel') {
      return this._renderSettingsPanel(node, ctx);
    }
    if (id === 'inspector-targets' && type === 'panel') {
      return this._renderInspectorTargets(node, ctx);
    }
    if (id === 'inspector-report' && type === 'panel') {
      return this._renderInspectorReport(node, ctx);
    }
    if (id === 'apphub-inspector-preview' && type === 'panel') {
      return this._renderAppHubPreview(node, ctx);
    }
    if (id === 'files-preview' && type === 'panel') {
      return this._renderFilesPreview(node, ctx);
    }
    if (id === 'files-toolbar' && type === 'toolbar') {
      return this._renderFilesToolbar(node, ctx);
    }
    if (type === 'card' && ctx.role === 'app-store') {
      return this._renderAppHubCard(node, ctx);
    }
    if (type === 'setting') {
      return this._renderSettingRow(node, ctx);
    }
    if (type === 'listitem') {
      return this._renderListItem(node, ctx);
    }
    if (type === 'canvas') {
      return this._renderEmbeddedCanvas(node, ctx);
    }
    if (type === 'alert') {
      return this._renderIosAlert(node, ctx);
    }

    // Specialized Monitor/Settings rows without children
    if (type === 'row' && id.startsWith('proc-')) {
      return this._renderMonitorProcessRow(node, ctx);
    }
    if (type === 'row' && id.startsWith('svc-')) {
      return this._renderMonitorServiceRow(node, ctx);
    }
    if (type === 'row' && id.startsWith('perm-app-')) {
      return this._renderPermissionMatrixRow(node, ctx);
    }
    if (type === 'row' && id.startsWith('audit-')) {
      return this._renderAuditRow(node, ctx);
    }

    // Standard controls
    if (type === 'button') {
      const label = String(p.label ?? node.label ?? p.text ?? node.text ?? id ?? 'Button');
      const isActive = p.active === true || node.active === true;
      const isDisabled = p.disabled === true || node.enabled === false;
      const btn = el(
        'button',
        `omni-ui-btn${isActive ? ' is-active' : ''}`,
        {
          type: 'button',
          ...(id ? { 'data-node-id': id } : {}),
          ...(isActive ? { 'data-active': 'true' } : {}),
        },
        label
      );
      if (isDisabled) btn.disabled = true;
      this._applyCommonNodeStyle(btn, node, ctx);
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (id === 'term-run') {
          const liveEl = ctx.entry.reusableInputs.get('term-input');
          const draft = liveEl ? liveEl.value : ctx.entry.localDrafts.get('term-input')?.value;
          ctx.entry.localDrafts.delete('term-input');
          if (liveEl) liveEl.value = '';
          this._sendAction(ctx.entry, node, {
            action: 'run',
            ...(draft !== undefined ? { value: draft } : {}),
          });
          return;
        }
        if (id === 'notes-save-btn') {
          const titleEl = ctx.entry.reusableInputs.get('note-title');
          const editorEl = ctx.entry.reusableInputs.get('note-editor');
          this._sendAction(ctx.entry, node, {
            action: 'save',
            ...(titleEl ? { filename: titleEl.value } : {}),
            ...(editorEl ? { content: editorEl.value } : {}),
          });
          return;
        }
        if (id === 'notes-new-btn' || id === 'notes-paste-btn') {
          ctx.entry.localDrafts.clear();
        }
        this._sendAction(ctx.entry, node);
      });
      return btn;
    }

    if (type === 'input') {
      const serverVal = String(p.value ?? node.value ?? node.text ?? '');
      const draft = ctx.entry.localDrafts.get(id);
      const useLocal = draft && Date.now() - draft.ts < 350;
      const placeholder = String(p.placeholder ?? node.placeholder ?? '');

      let inp = id ? ctx.entry.reusableInputs.get(id) : null;
      if (inp && inp.tagName !== 'INPUT') inp = null;

      if (!inp) {
        inp = el('input', 'omni-ui-input', {
          type: 'text',
          placeholder,
          ...(id ? { 'data-node-id': id, 'data-focus-key': id } : {}),
        });
        inp._omniNode = node;
        inp.addEventListener('input', () => {
          const curNode = inp._omniNode ?? node;
          if (id) ctx.entry.localDrafts.set(id, { value: inp.value, ts: Date.now() });
          this._sendInput(ctx.entry, {
            type: 'input',
            ...(id ? { targetId: id, nodeId: id } : {}),
            value: inp.value,
            text: inp.value,
            ...(typeof curNode.viewId === 'number' ? { viewId: curNode.viewId } : {}),
            ...(typeof curNode.controlId === 'number' ? { controlId: curNode.controlId } : {}),
            ...(typeof curNode.tag === 'number' ? { tag: curNode.tag } : {}),
          });
        });

        inp.addEventListener('keydown', (ev) => {
          if (id === 'term-input' && ev.key === 'Enter') {
            ev.preventDefault();
            const val = inp.value;
            ctx.entry.localDrafts.delete('term-input');
            inp.value = '';
            this._sendInput(ctx.entry, {
              type: 'keydown',
              targetId: 'term-input',
              nodeId: 'term-input',
              key: 'Enter',
              keyCode: 13,
              value: val,
            });
            return;
          }
          if (id === 'term-input' && (ev.key === 'ArrowUp' || ev.key === 'ArrowDown')) {
            ev.preventDefault();
            ctx.entry.localDrafts.delete('term-input');
            this._sendInput(ctx.entry, {
              type: 'keydown',
              targetId: 'term-input',
              nodeId: 'term-input',
              key: ev.key,
            });
          }
        });
        if (id) ctx.entry.reusableInputs.set(id, inp);
      } else {
        inp._omniNode = node;
        inp.placeholder = placeholder;
      }

      if (id && ctx.usedInputIds) ctx.usedInputIds.add(id);
      if (!useLocal && inp.value !== serverVal) {
        inp.value = serverVal;
      }
      this._applyCommonNodeStyle(inp, node, ctx);
      return inp;
    }

    if (type === 'textarea') {
      const serverVal = String(p.value ?? node.value ?? node.text ?? '');
      const draft = ctx.entry.localDrafts.get(id);
      const useLocal = draft && Date.now() - draft.ts < 350;
      const placeholder = String(p.placeholder ?? node.placeholder ?? '');

      let ta = id ? ctx.entry.reusableInputs.get(id) : null;
      if (ta && ta.tagName !== 'TEXTAREA') ta = null;

      if (!ta) {
        ta = el('textarea', 'omni-ui-textarea', {
          placeholder,
          rows: '12',
          ...(id ? { 'data-node-id': id, 'data-focus-key': id } : {}),
        });
        ta.addEventListener('input', () => {
          if (id) ctx.entry.localDrafts.set(id, { value: ta.value, ts: Date.now() });
          this._sendInput(ctx.entry, {
            type: 'input',
            ...(id ? { targetId: id, nodeId: id } : {}),
            value: ta.value,
            text: ta.value,
          });
        });
        if (id) ctx.entry.reusableInputs.set(id, ta);
      } else {
        ta.placeholder = placeholder;
      }

      if (id && ctx.usedInputIds) ctx.usedInputIds.add(id);
      if (!useLocal && ta.value !== serverVal) {
        ta.value = serverVal;
      }
      this._applyCommonNodeStyle(ta, node, ctx);
      return ta;
    }

    if (type === 'text' || type === 'label') {
      const textVal = String(p.text ?? node.text ?? p.value ?? node.value ?? '');
      const kind = p.kind ? ` kind-${String(p.kind).toLowerCase()}` : '';
      const level = p.level ? ` level-${String(p.level).toLowerCase()}` : '';
      const clickable = node.clickable === true;
      const span = el(
        'div',
        `omni-ui-text${kind}${level}${clickable ? ' is-clickable' : ''}`,
        { ...(id ? { 'data-node-id': id } : {}) },
        textVal
      );
      this._applyCommonNodeStyle(span, node, ctx);
      if (clickable) {
        span.setAttribute('role', 'button');
        span.tabIndex = 0;
        span.addEventListener('click', (ev) => {
          ev.stopPropagation();
          this._sendAction(ctx.entry, node);
        });
      }
      return span;
    }

    if (type === 'image') {
      const box = el(
        'div',
        `omni-ui-image${node.clickable ? ' is-clickable' : ''}`,
        { ...(id ? { 'data-node-id': id } : {}) },
        String(node.text || node.tag || 'Image')
      );
      this._applyCommonNodeStyle(box, node, ctx);
      if (node.clickable) {
        box.setAttribute('role', 'button');
        box.tabIndex = 0;
        box.addEventListener('click', (ev) => {
          ev.stopPropagation();
          this._sendAction(ctx.entry, node);
        });
      }
      return box;
    }

    if (type === 'statusbar') {
      const hasErr = Boolean(p.error);
      return el(
        'div',
        `omni-ui-statusbar${hasErr ? ' is-error' : ''}`,
        { ...(id ? { 'data-node-id': id } : {}) },
        String(p.text ?? '')
      );
    }

    if (type === 'list' && Array.isArray(node.items)) {
      // Win32 LISTBOX
      const ul = el('ul', 'omni-ui-listbox', { ...(id ? { 'data-node-id': id } : {}) });
      for (let i = 0; i < node.items.length; i += 1) {
        const itemText = String(node.items[i] ?? '');
        const li = el('li', 'omni-ui-listbox-item', {}, itemText);
        li.addEventListener('click', () => {
          this._sendAction(ctx.entry, node, { index: i, value: itemText });
        });
        ul.appendChild(li);
      }
      return ul;
    }

    // Generic containers: container, window, view, scroll, scrollview, vbox, hbox, toolbar, row, list, panel
    const orientation = node.orientation ?? node.layout ?? p.orientation ?? null;
    const isHorizontal =
      type === 'hbox' ||
      type === 'toolbar' ||
      type === 'row' ||
      orientation === 'horizontal';
    const roleClass = node.role ? ` role-${String(node.role)}` : '';
    const orientClass = isHorizontal ? ' layout-row' : ' layout-col';
    const wrap = el('div', `omni-ui-node omni-ui-${type}${roleClass}${orientClass}`, {
      ...(id ? { 'data-node-id': id } : {}),
      ...(node.role ? { 'data-app-role': String(node.role) } : {}),
    });
    this._applyCommonNodeStyle(wrap, node, ctx);

    if (typeof node.spacing === 'number' && Number.isFinite(node.spacing)) {
      wrap.style.gap = `${Math.max(0, Math.min(48, Math.round(node.spacing)))}px`;
    }

    if (type === 'toolbar' && p.badge) {
      wrap.appendChild(el('span', 'omni-ui-badge', {}, String(p.badge)));
    }
    if (type === 'list' && p.title) {
      wrap.appendChild(el('div', 'omni-ui-list-title', {}, String(p.title)));
    }

    if (node.clickable === true) {
      wrap.classList.add('is-clickable');
      wrap.setAttribute('role', 'button');
      wrap.addEventListener('click', (ev) => {
        if (ev.target !== wrap) return;
        this._sendAction(ctx.entry, node);
      });
    }

    // For OmniFiles root, wrap sidebar + entries + preview cleanly in a split layout
    if (node.role === 'file-manager') {
      const toolbarNode = children.find((c) => c.id === 'files-toolbar');
      const sidebarNode = children.find((c) => c.id === 'files-sidebar');
      const entriesNode = children.find((c) => c.id === 'files-entries');
      const previewNode = children.find((c) => c.id === 'files-preview');
      const statusNode = children.find((c) => c.id === 'files-status');

      if (toolbarNode) {
        const rendered = this._renderUiNode(toolbarNode, ctx);
        if (rendered) wrap.appendChild(rendered);
      }
      const split = el('div', 'files-split-body');
      if (sidebarNode) {
        const r = this._renderUiNode(sidebarNode, ctx);
        if (r) split.appendChild(r);
      }
      if (entriesNode) {
        const r = this._renderUiNode(entriesNode, ctx);
        if (r) split.appendChild(r);
      }
      if (previewNode) {
        const r = this._renderUiNode(previewNode, ctx);
        if (r) split.appendChild(r);
      }
      wrap.appendChild(split);
      if (statusNode) {
        const r = this._renderUiNode(statusNode, ctx);
        if (r) wrap.appendChild(r);
      }
      return wrap;
    }

    // For OmniNotes root, arrange toolbar, split (notes-list + editor col), statusbar
    if (node.role === 'notes-editor') {
      const toolbarNode = children.find((c) => c.id === 'notes-toolbar');
      const listNode = children.find((c) => c.id === 'notes-list');
      const titleNode = children.find((c) => c.id === 'note-title');
      const editorNode = children.find((c) => c.id === 'note-editor');
      const statusNode = children.find((c) => c.id === 'notes-status');

      if (toolbarNode) {
        const r = this._renderUiNode(toolbarNode, ctx);
        if (r) wrap.appendChild(r);
      }
      const split = el('div', 'notes-split-body');
      if (listNode) {
        const r = this._renderUiNode(listNode, ctx);
        if (r) split.appendChild(r);
      }
      const editorCol = el('div', 'notes-editor-col');
      if (titleNode) {
        const r = this._renderUiNode(titleNode, ctx);
        if (r) editorCol.appendChild(r);
      }
      if (editorNode) {
        const r = this._renderUiNode(editorNode, ctx);
        if (r) editorCol.appendChild(r);
      }
      split.appendChild(editorCol);
      wrap.appendChild(split);
      if (statusNode) {
        const r = this._renderUiNode(statusNode, ctx);
        if (r) wrap.appendChild(r);
      }
      return wrap;
    }

    for (const child of children) {
      const rendered = this._renderUiNode(child, ctx);
      if (rendered) wrap.appendChild(rendered);
    }

    if (type === 'list' && children.length === 0 && (p.count === 0 || p.count === undefined)) {
      wrap.appendChild(el('div', 'omni-ui-empty', {}, 'No items'));
    }

    return wrap;
  }

  _renderEmbeddedCanvas(node, ctx) {
    const p = node.props ?? {};
    const width = Number(node.width ?? p.width ?? 720) || 720;
    const height = Number(node.height ?? p.height ?? 480) || 480;
    const wrap = el('div', 'omni-ui-canvas-wrap', {
      ...(node.id ? { 'data-node-id': String(node.id) } : {}),
    });
    let canvas = ctx.entry.refs.embeddedCanvas;
    if (!canvas) {
      canvas = el('canvas', 'omni-surface-canvas');
      ctx.entry.refs.embeddedCanvas = canvas;
      attachCanvasInteraction(canvas, {
        onCanvasClick: (evt) => this._sendInput(ctx.entry, evt),
        onCanvasDrag: (evt) => this._sendInput(ctx.entry, evt),
      });
    }
    renderDrawOps(canvas, ctx.drawOps, { width, height, isAndroid: ctx.isAndroid });
    wrap.appendChild(canvas);
    return wrap;
  }

  _renderIosAlert(node, ctx) {
    const overlay = el('div', 'omni-ui-alert-backdrop', {
      ...(node.id ? { 'data-node-id': String(node.id) } : {}),
    });
    const card = el('div', 'omni-ui-alert-card');
    card.appendChild(el('div', 'omni-ui-alert-title', {}, String(node.title ?? 'Alert')));
    if (node.message) {
      card.appendChild(el('div', 'omni-ui-alert-msg', {}, String(node.message)));
    }
    const actionsRow = el('div', 'omni-ui-alert-actions');
    const actions = Array.isArray(node.actions) ? node.actions : [];
    for (const act of actions) {
      const btn = el(
        'button',
        'omni-ui-btn',
        { type: 'button', 'data-node-id': String(act.id ?? '') },
        String(act.label ?? 'OK')
      );
      if (act.enabled === false) btn.disabled = true;
      btn.addEventListener('click', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          nodeId: act.id,
          targetId: act.id,
          action: act.id,
          label: act.label,
        });
      });
      actionsRow.appendChild(btn);
    }
    card.appendChild(actionsRow);
    overlay.appendChild(card);
    return overlay;
  }

  _renderMacModal(modal, ctx) {
    const overlay = el('div', 'omni-ui-alert-backdrop', {
      'data-node-id': String(modal.id ?? 'nsalert'),
    });
    const card = el('div', 'omni-ui-alert-card');
    card.appendChild(
      el('div', 'omni-ui-alert-title', {}, String(modal.messageText ?? 'Alert'))
    );
    if (modal.informativeText) {
      card.appendChild(
        el('div', 'omni-ui-alert-msg', {}, String(modal.informativeText))
      );
    }
    const actionsRow = el('div', 'omni-ui-alert-actions');
    const buttons = Array.isArray(modal.buttons) && modal.buttons.length > 0 ? modal.buttons : ['OK'];
    for (let i = 0; i < buttons.length; i += 1) {
      const label = String(buttons[i]);
      const btn = el('button', 'omni-ui-btn', { type: 'button' }, label);
      btn.addEventListener('click', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          targetId: modal.id ?? 'nsalert',
          nodeId: modal.id ?? 'nsalert',
          action: 'dismiss_modal',
          label,
          index: i,
        });
      });
      actionsRow.appendChild(btn);
    }
    card.appendChild(actionsRow);
    overlay.appendChild(card);
    return overlay;
  }

  // ---- OmniFiles Specialized Renderers ----

  _renderFilesToolbar(node, ctx) {
    const wrap = el('div', 'omni-ui-node omni-ui-toolbar layout-row', {
      'data-node-id': 'files-toolbar',
    });
    for (const child of node.children ?? []) {
      const r = this._renderUiNode(child, ctx);
      if (r) wrap.appendChild(r);
    }

    // Inline quick create controls (New Folder / New File)
    const crudGroup = el('div', 'files-crud-bar');
    const nameInput = el('input', 'omni-ui-input omni-ui-input-sm', {
      type: 'text',
      placeholder: 'New name...',
      'data-focus-key': 'files-crud-name',
    });
    const cachedName = ctx.entry.formCache.get('files-crud-name') ?? '';
    nameInput.value = cachedName;
    nameInput.addEventListener('input', () => {
      ctx.entry.formCache.set('files-crud-name', nameInput.value);
    });

    const btnMkdir = el('button', 'omni-ui-btn omni-ui-btn-sm', { type: 'button' }, '+ Folder');
    btnMkdir.addEventListener('click', () => {
      const name = nameInput.value.trim();
      if (!name) return;
      ctx.entry.formCache.set('files-crud-name', '');
      this._sendInput(ctx.entry, { type: 'action', action: 'mkdir', name });
    });

    const btnNewFile = el('button', 'omni-ui-btn omni-ui-btn-sm', { type: 'button' }, '+ File');
    btnNewFile.addEventListener('click', () => {
      const name = nameInput.value.trim();
      if (!name) return;
      ctx.entry.formCache.set('files-crud-name', '');
      this._sendInput(ctx.entry, { type: 'action', action: 'create_file', name, content: '' });
    });

    crudGroup.append(nameInput, btnMkdir, btnNewFile);
    wrap.appendChild(crudGroup);
    return wrap;
  }

  _renderFilesPreview(node, ctx) {
    const p = node.props ?? {};
    const panel = el('div', 'omni-ui-panel files-preview-panel', { 'data-node-id': 'files-preview' });
    panel.appendChild(
      el(
        'div',
        'omni-ui-panel-header',
        {},
        p.selectedPath ? `Preview: ${p.selectedPath}` : 'File Preview'
      )
    );
    if (p.binary) {
      panel.appendChild(el('div', 'omni-ui-badge', {}, 'Binary File'));
    }
    if (p.content !== null && p.content !== undefined) {
      panel.appendChild(el('pre', 'omni-ui-code', {}, String(p.content)));
    } else {
      panel.appendChild(el('div', 'omni-ui-empty', {}, 'Select a file to preview'));
    }
    if (p.lastOpenWithResult) {
      panel.appendChild(
        el(
          'div',
          'omni-ui-subnote',
          {},
          `Open With: ${p.lastOpenWithResult.status ?? 'dispatched'}`
        )
      );
    }
    return panel;
  }

  _renderListItem(node, ctx) {
    const p = node.props ?? {};
    const id = String(node.id ?? '');
    const isSelected = Boolean(p.selected || p.active);
    const row = el('div', `omni-ui-listitem${isSelected ? ' is-active' : ''}`, {
      ...(id ? { 'data-node-id': id } : {}),
      ...(isSelected ? { 'data-active': 'true' } : {}),
    });

    // OmniFiles entry:<name>
    if (ctx.role === 'file-manager' && id.startsWith('entry:')) {
      const mainBtn = el('button', 'omni-ui-listitem-main', { type: 'button' });
      const iconText = p.entryType === 'dir' ? '[DIR]' : p.entryType === 'symlink' ? '[LNK]' : '[FILE]';
      mainBtn.appendChild(el('span', 'listitem-kind', {}, iconText));
      mainBtn.appendChild(el('span', 'listitem-name', {}, String(p.name ?? id)));
      if (p.entryType !== 'dir' && p.size !== undefined) {
        mainBtn.appendChild(el('span', 'listitem-meta', {}, formatBytes(p.size)));
      }
      mainBtn.addEventListener('click', () => {
        this._sendInput(ctx.entry, { type: 'action', targetId: id, nodeId: id });
      });

      const actions = el('div', 'listitem-actions');
      if (p.entryType === 'file') {
        const btnOpen = el('button', 'omni-ui-btn omni-ui-btn-xs', { type: 'button' }, 'Open With');
        btnOpen.addEventListener('click', (ev) => {
          ev.stopPropagation();
          // CRITICAL: Omit targetId 'entry:...' so files-app.mjs routes to open_with!
          this._sendInput(ctx.entry, { type: 'action', action: 'open_with', path: p.path });
        });
        actions.appendChild(btnOpen);
      }
      const btnDel = el('button', 'omni-ui-btn omni-ui-btn-xs omni-ui-btn-danger', { type: 'button' }, 'Del');
      btnDel.addEventListener('click', (ev) => {
        ev.stopPropagation();
        // CRITICAL: Omit targetId 'entry:...' so files-app.mjs routes to delete!
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'delete',
          path: p.path,
          recursive: p.entryType === 'dir',
        });
      });
      actions.appendChild(btnDel);

      row.append(mainBtn, actions);
      return row;
    }

    // OmniNotes note:<name>
    if (ctx.role === 'notes-editor' && id.startsWith('note:')) {
      const mainBtn = el('button', 'omni-ui-listitem-main', { type: 'button' });
      mainBtn.appendChild(el('span', 'listitem-name', {}, String(p.name ?? id)));
      if (p.size !== undefined) {
        mainBtn.appendChild(el('span', 'listitem-meta', {}, formatBytes(p.size)));
      }
      mainBtn.addEventListener('click', () => {
        ctx.entry.localDrafts.clear();
        this._sendInput(ctx.entry, { type: 'action', targetId: id, nodeId: id });
      });

      const btnDel = el('button', 'omni-ui-btn omni-ui-btn-xs omni-ui-btn-danger', { type: 'button' }, '×');
      btnDel.setAttribute('aria-label', 'Delete Note');
      btnDel.addEventListener('click', (ev) => {
        ev.stopPropagation();
        ctx.entry.localDrafts.clear();
        // CRITICAL: Omit targetId 'note:...' so notes-app.mjs routes to delete_note!
        this._sendInput(ctx.entry, { type: 'action', action: 'delete_note', path: p.path });
      });

      row.append(mainBtn, btnDel);
      return row;
    }

    // Generic listitem fallback
    row.textContent = String(p.name ?? p.text ?? node.text ?? id);
    row.addEventListener('click', () => this._sendAction(ctx.entry, node));
    return row;
  }

  // ---- Activity Monitor Specialized Renderers ----

  _renderMonitorPanel(node, ctx) {
    const p = node.props ?? {};
    const tab = String(p.tab || 'processes');
    const panel = el('div', `omni-ui-panel monitor-panel tab-${tab}`, {
      'data-node-id': 'monitor-content',
    });

    if (tab === 'tree') {
      const treeWrap = el('div', 'monitor-tree');
      const renderBranch = (nodes, depth) => {
        if (!Array.isArray(nodes)) return;
        for (const item of nodes) {
          const line = el('div', 'monitor-tree-node');
          line.style.paddingLeft = `${depth * 18}px`;
          line.appendChild(el('span', 'mono-chip', {}, `PID ${item.pid}`));
          line.appendChild(el('span', 'tree-name', {}, String(item.name ?? item.appId ?? 'proc')));
          line.appendChild(el('span', 'omni-ui-badge', {}, String(item.state ?? '')));
          line.appendChild(
            el('span', `platform-badge platform-${item.platform || 'system'}`, {}, getPlatformBadge(item.platform))
          );
          treeWrap.appendChild(line);
          if (Array.isArray(item.children) && item.children.length > 0) {
            renderBranch(item.children, depth + 1);
          }
        }
      };
      renderBranch(p.tree ?? [], 0);
      if (treeWrap.children.length === 0) {
        treeWrap.appendChild(el('div', 'omni-ui-empty', {}, 'No process tree data'));
      }
      panel.appendChild(treeWrap);
    } else if (tab === 'memory') {
      const mem = p.memory ?? {};
      const cards = el('div', 'monitor-mem-cards');
      const stats = [
        ['Mapped Pages', String(mem.totalMappedPages ?? 0)],
        ['Used Memory', formatBytes(mem.totalUsedBytes ?? 0)],
        ['Peak Memory', formatBytes(mem.totalPeakBytes ?? 0)],
        ['Active Processes', String((p.processes ?? []).length)],
      ];
      for (const [k, v] of stats) {
        const c = el('div', 'stat-card');
        c.appendChild(el('div', 'stat-label', {}, k));
        c.appendChild(el('div', 'stat-value', {}, v));
        cards.appendChild(c);
      }
      panel.appendChild(cards);

      const list = el('div', 'monitor-mem-list');
      for (const proc of p.processes ?? []) {
        const r = el('div', 'monitor-row');
        r.appendChild(el('span', 'mono-chip', {}, `PID ${proc.pid}`));
        r.appendChild(el('span', 'row-grow', {}, String(proc.name ?? '')));
        r.appendChild(el('span', 'mono-chip', {}, `${proc.memory?.mappedPages ?? 0} pages`));
        r.appendChild(el('span', 'mono-chip', {}, formatBytes(proc.memory?.usedBytes ?? 0)));
        list.appendChild(r);
      }
      panel.appendChild(list);
    } else {
      for (const child of node.children ?? []) {
        const rendered = this._renderUiNode(child, ctx);
        if (rendered) panel.appendChild(rendered);
      }
      if ((node.children ?? []).length === 0) {
        panel.appendChild(el('div', 'omni-ui-empty', {}, `No entries in ${tab}`));
      }
    }

    if (p.selectedProcessDetail) {
      const d = p.selectedProcessDetail;
      const box = el('div', 'monitor-detail-box');
      box.appendChild(
        el(
          'div',
          'omni-ui-panel-header',
          {},
          `Selected PID ${d.pid}: ${d.name ?? ''} (${d.platform ?? ''}/${d.arch ?? ''}) — ${d.state ?? ''}`
        )
      );
      const meta = el('div', 'detail-meta-grid');
      meta.appendChild(el('span', 'mono-chip', {}, `UID ${d.uid ?? 0}`));
      meta.appendChild(el('span', 'mono-chip', {}, `Threads: ${(d.threads ?? []).length}`));
      meta.appendChild(el('span', 'mono-chip', {}, `FDs: ${(d.fds ?? []).length}`));
      if (d.memory) {
        meta.appendChild(el('span', 'mono-chip', {}, `Mem: ${formatBytes(d.memory.usedBytes ?? 0)}`));
      }
      box.appendChild(meta);
      panel.appendChild(box);
    }

    return panel;
  }

  _renderMonitorProcessRow(node, ctx) {
    const p = node.props ?? {};
    const row = el('div', 'omni-ui-row monitor-row', { 'data-node-id': String(node.id) });
    row.appendChild(el('span', 'mono-chip', {}, `PID ${p.pid}`));
    row.appendChild(
      el('span', `platform-badge platform-${p.platform || 'system'}`, {}, getPlatformBadge(p.platform))
    );
    row.appendChild(el('span', 'row-grow', {}, `${p.name ?? ''} (${p.arch ?? ''})`));
    row.appendChild(el('span', 'omni-ui-badge', {}, String(p.state ?? '')));
    row.appendChild(el('span', 'mono-chip', {}, formatBytes(p.usedBytes ?? 0)));

    const actions = el('div', 'row-actions');
    const btnSel = el('button', 'omni-ui-btn omni-ui-btn-xs', { type: 'button' }, 'Detail');
    btnSel.addEventListener('click', () => {
      // CRITICAL: ALWAYS pass targetPid (Compositor overwrites event.pid)
      this._sendInput(ctx.entry, { type: 'action', action: 'select_pid', targetPid: p.pid });
    });
    actions.appendChild(btnSel);

    for (const sig of ['SIGTERM', 'SIGKILL', 'SIGSTOP', 'SIGCONT']) {
      const label = sig.replace('SIG', '');
      const btn = el(
        'button',
        `omni-ui-btn omni-ui-btn-xs${sig === 'SIGKILL' ? ' omni-ui-btn-danger' : ''}`,
        { type: 'button' },
        label
      );
      btn.addEventListener('click', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'signal',
          targetPid: p.pid,
          signal: sig,
        });
      });
      actions.appendChild(btn);
    }
    row.appendChild(actions);
    return row;
  }

  _renderMonitorServiceRow(node, ctx) {
    const p = node.props ?? {};
    const row = el('div', 'omni-ui-row monitor-row', { 'data-node-id': String(node.id) });
    row.appendChild(el('span', 'row-grow', {}, String(p.name ?? '')));
    row.appendChild(el('span', 'omni-ui-badge', {}, String(p.state ?? '')));
    row.appendChild(el('span', 'mono-chip', {}, p.healthy ? 'HEALTHY' : 'UNHEALTHY'));
    row.appendChild(el('span', 'mono-chip', {}, `Restarts: ${p.totalRestarts ?? p.restarts ?? 0}`));

    const btnRestart = el('button', 'omni-ui-btn omni-ui-btn-xs', { type: 'button' }, 'Restart');
    btnRestart.addEventListener('click', () => {
      this._sendInput(ctx.entry, {
        type: 'action',
        action: 'restart_service',
        name: p.name,
      });
    });
    row.appendChild(btnRestart);
    return row;
  }

  // ---- App Hub Specialized Renderers ----

  _renderAppHubCard(node, ctx) {
    const p = node.props ?? {};
    const platform = String(p.platform || 'universal').toLowerCase();
    const runningPids = Array.isArray(p.runningPids) ? p.runningPids : [];
    const card = el('div', 'apphub-card', {
      'data-node-id': String(node.id ?? ''),
      'data-app-id': String(p.appId ?? ''),
      'data-platform': platform,
    });

    const head = el('div', 'apphub-card-head');
    head.appendChild(el('span', `platform-badge platform-${platform}`, {}, getPlatformBadge(platform)));
    head.appendChild(el('strong', 'apphub-card-name', {}, String(p.name ?? p.appId ?? 'App')));
    head.appendChild(el('span', 'omni-ui-badge', {}, String(p.arch ?? p.format ?? '')));
    card.appendChild(head);

    card.appendChild(
      el(
        'div',
        'apphub-card-meta',
        {},
        `${p.appId ?? ''} · v${p.version ?? '1.0'} · ${formatBytes(p.sizeBytes ?? 0)}`
      )
    );
    if (p.description) {
      card.appendChild(el('div', 'apphub-card-desc', {}, String(p.description)));
    }

    const statusLine = el('div', 'apphub-card-status');
    statusLine.appendChild(
      el(
        'span',
        `omni-ui-badge${p.installed ? ' badge-ok' : ''}`,
        {},
        p.installed ? 'Installed' : 'Catalog'
      )
    );
    if (runningPids.length > 0) {
      statusLine.appendChild(
        el('span', 'omni-ui-badge badge-running', {}, `Running (PID ${runningPids.join(', ')})`)
      );
    }
    card.appendChild(statusLine);

    const actions = el('div', 'apphub-card-actions');

    const btnInspect = el('button', 'omni-ui-btn omni-ui-btn-sm', { type: 'button' }, 'Inspect');
    btnInspect.addEventListener('click', () => {
      this._sendInput(ctx.entry, {
        type: 'action',
        action: 'inspect',
        packagePath: p.packagePath,
        catalogId: p.catalogId,
        appId: p.appId,
      });
    });
    actions.appendChild(btnInspect);

    if (!p.installed) {
      const btnInstall = el(
        'button',
        'omni-ui-btn omni-ui-btn-sm omni-ui-btn-primary',
        { type: 'button' },
        'Install'
      );
      btnInstall.addEventListener('click', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'install',
          packagePath: p.packagePath,
          catalogId: p.catalogId,
          appId: p.appId,
          grantAll: true,
        });
      });
      actions.appendChild(btnInstall);
    } else {
      const btnLaunch = el(
        'button',
        'omni-ui-btn omni-ui-btn-sm omni-ui-btn-primary',
        { type: 'button' },
        'Launch'
      );
      btnLaunch.addEventListener('click', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'launch',
          appId: p.appId,
        });
      });
      actions.appendChild(btnLaunch);

      if (runningPids.length > 0) {
        const btnStop = el('button', 'omni-ui-btn omni-ui-btn-sm', { type: 'button' }, 'Stop');
        btnStop.addEventListener('click', () => {
          this._sendInput(ctx.entry, {
            type: 'action',
            action: 'stop',
            targetPid: runningPids[0],
            appId: p.appId,
          });
        });
        actions.appendChild(btnStop);
      }

      const btnUninst = el(
        'button',
        'omni-ui-btn omni-ui-btn-sm omni-ui-btn-danger',
        { type: 'button' },
        'Uninstall'
      );
      btnUninst.addEventListener('click', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'uninstall',
          appId: p.appId,
        });
      });
      actions.appendChild(btnUninst);
    }

    card.appendChild(actions);
    return card;
  }

  _renderAppHubPreview(node, ctx) {
    const insp = node.props?.inspection;
    const panel = el('div', 'omni-ui-panel apphub-preview-panel', {
      'data-node-id': 'apphub-inspector-preview',
    });
    if (!insp) {
      panel.hidden = true;
      return panel;
    }
    panel.appendChild(
      el('div', 'omni-ui-panel-header', {}, `Package Inspection: ${insp.name ?? insp.appId ?? ''}`)
    );
    const grid = el('div', 'kv-grid');
    const pairs = [
      ['App ID', insp.appId],
      ['Platform', insp.platform],
      ['Format', insp.format],
      ['Arch', insp.arch],
      ['Version', insp.version],
      ['Entry', insp.entryPoint],
      ['Size', formatBytes(insp.sizeBytes ?? 0)],
      ['SHA-256', insp.sha256 ? `${String(insp.sha256).slice(0, 20)}…` : '—'],
    ];
    for (const [k, v] of pairs) {
      grid.appendChild(el('span', 'kv-key', {}, k));
      grid.appendChild(el('span', 'kv-val', {}, String(v ?? '—')));
    }
    panel.appendChild(grid);
    return panel;
  }

  // ---- Settings & Privacy Specialized Renderers ----

  _renderSettingRow(node, ctx) {
    const p = node.props ?? {};
    const key = String(p.key ?? '');
    const val = p.value;
    const row = el('div', 'omni-ui-setting-row', { 'data-node-id': String(node.id ?? '') });
    row.appendChild(el('span', 'setting-label', {}, key));

    if (key === 'system.wifi' || key === 'system.bluetooth' || key === 'system.dnd') {
      const active = Boolean(val);
      const btn = el(
        'button',
        `omni-ui-btn omni-ui-toggle${active ? ' is-active' : ''}`,
        { type: 'button', 'aria-pressed': active ? 'true' : 'false' },
        active ? 'ON' : 'OFF'
      );
      btn.addEventListener('click', () => {
        this._sendInput(ctx.entry, { type: 'action', action: 'toggle_system', key });
      });
      row.appendChild(btn);
      return row;
    }

    if (key === 'system.volume' || key === 'system.brightness') {
      const wrap = el('div', 'setting-range-wrap');
      const numVal = Number.isFinite(Number(val)) ? Number(val) : 50;
      const slider = el('input', 'omni-ui-range', {
        type: 'range',
        min: '0',
        max: '100',
        value: String(numVal),
      });
      const readout = el('span', 'mono-chip', {}, `${numVal}%`);
      slider.addEventListener('input', () => {
        readout.textContent = `${slider.value}%`;
      });
      slider.addEventListener('change', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'set_system',
          key,
          value: Number(slider.value),
        });
      });
      wrap.append(slider, readout);
      row.appendChild(wrap);
      return row;
    }

    if (key === 'system.theme' || key === 'system.shellMode') {
      const options =
        key === 'system.theme'
          ? ['dark', 'light', 'auto']
          : ['unified', 'windows', 'macos', 'ios', 'android'];
      const select = el('select', 'omni-ui-select');
      for (const opt of options) {
        const o = el('option', '', { value: opt }, opt);
        if (String(val) === opt) o.selected = true;
        select.appendChild(o);
      }
      select.addEventListener('change', () => {
        if (key === 'system.shellMode') {
          this._sendInput(ctx.entry, {
            type: 'action',
            action: 'set_shell_mode',
            mode: select.value,
          });
        } else {
          this._sendInput(ctx.entry, {
            type: 'action',
            action: 'set_system',
            key,
            value: select.value,
          });
        }
      });
      row.appendChild(select);
      return row;
    }

    // Locale or generic text setting
    const wrap = el('div', 'setting-input-wrap');
    const inp = el('input', 'omni-ui-input omni-ui-input-sm', {
      type: 'text',
      'data-focus-key': `setting-${key}`,
    });
    inp.value = String(val ?? '');
    const btnApply = el('button', 'omni-ui-btn omni-ui-btn-sm', { type: 'button' }, 'Apply');
    btnApply.addEventListener('click', () => {
      this._sendInput(ctx.entry, {
        type: 'action',
        action: 'set_system',
        key,
        value: inp.value.trim(),
      });
    });
    wrap.append(inp, btnApply);
    row.appendChild(wrap);
    return row;
  }

  _renderPermissionMatrixRow(node, ctx) {
    const p = node.props ?? {};
    const appId = String(p.appId ?? '');
    const caps = p.capabilities && typeof p.capabilities === 'object' ? p.capabilities : {};
    const card = el('div', 'perm-matrix-card', { 'data-node-id': String(node.id ?? '') });
    card.appendChild(el('div', 'perm-matrix-app', {}, appId));

    const grid = el('div', 'perm-cap-grid');
    for (const [cap, state] of Object.entries(caps)) {
      const cell = el('div', 'perm-cap-cell');
      cell.appendChild(el('span', 'perm-cap-name', {}, cap));
      const sel = el('select', 'omni-ui-select omni-ui-select-xs');
      for (const opt of ['allow', 'prompt', 'deny']) {
        const o = el('option', '', { value: opt }, opt);
        if (String(state) === opt) o.selected = true;
        sel.appendChild(o);
      }
      sel.addEventListener('change', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'set_grant',
          appId,
          capability: cap,
          state: sel.value,
        });
      });
      cell.appendChild(sel);
      grid.appendChild(cell);
    }
    card.appendChild(grid);
    return card;
  }

  _renderAuditRow(node) {
    const p = node.props ?? {};
    const row = el('div', 'omni-ui-row audit-row', { 'data-node-id': String(node.id ?? '') });
    row.appendChild(el('span', 'mono-chip', {}, p.ts ? String(p.ts).slice(11, 19) : ''));
    row.appendChild(el('span', 'row-grow', {}, `${p.appId ?? ''} · ${p.capability ?? ''}`));
    row.appendChild(
      el(
        'span',
        `omni-ui-badge ${p.granted ? 'badge-ok' : 'badge-danger'}`,
        {},
        p.granted ? 'GRANTED' : 'DENIED'
      )
    );
    row.appendChild(el('span', 'mono-chip', {}, String(p.reason ?? p.policy ?? '')));
    return row;
  }

  _renderSettingsPanel(node, ctx) {
    const p = node.props ?? {};
    const sec = String(p.section || 'general');
    const panel = el('div', `omni-ui-panel settings-section-${sec}`, {
      'data-node-id': 'settings-body',
    });

    if (sec === 'permissions' && Array.isArray(p.pendingPrompts) && p.pendingPrompts.length > 0) {
      const pendingBox = el('div', 'settings-pending-prompts');
      pendingBox.appendChild(
        el('div', 'omni-ui-panel-header', {}, `Pending Prompts (${p.pendingPrompts.length})`)
      );
      for (const prompt of p.pendingPrompts) {
        const r = el('div', 'omni-ui-row');
        r.appendChild(
          el('span', 'row-grow', {}, `${prompt.appId} → ${prompt.capability} (PID ${prompt.pid ?? '?'})`)
        );
        for (const [dec, lbl] of [
          ['allow', 'Allow'],
          ['allow_once', 'Once'],
          ['deny_once', 'Deny Once'],
          ['deny', 'Deny'],
        ]) {
          const btn = el('button', 'omni-ui-btn omni-ui-btn-xs', { type: 'button' }, lbl);
          btn.addEventListener('click', () => {
            this._sendInput(ctx.entry, {
              type: 'action',
              action: 'resolve_prompt',
              promptId: prompt.promptId,
              decision: dec,
            });
          });
          r.appendChild(btn);
        }
        pendingBox.appendChild(r);
      }
      panel.appendChild(pendingBox);
    }

    if (sec === 'registry') {
      const reg = p.registry ?? { hive: 'HKCU', keyPath: '', subkeys: [], values: {} };
      const navRow = el('div', 'settings-editor-bar');
      const hiveSel = el('select', 'omni-ui-select');
      for (const h of SYSTEM_HIVES) {
        const o = el('option', '', { value: h }, h);
        if (String(reg.hive) === h) o.selected = true;
        hiveSel.appendChild(o);
      }
      const keyPathInp = el('input', 'omni-ui-input', {
        type: 'text',
        placeholder: 'Software\\OmniOS\\System',
        'data-focus-key': 'reg-key-path',
      });
      keyPathInp.value = String(reg.keyPath ?? '');
      const btnGo = el('button', 'omni-ui-btn omni-ui-btn-sm', { type: 'button' }, 'Open Key');
      btnGo.addEventListener('click', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'reg_navigate',
          hive: hiveSel.value,
          keyPath: keyPathInp.value.trim(),
        });
      });
      navRow.append(hiveSel, keyPathInp, btnGo);
      panel.appendChild(navRow);

      if (reg.error) {
        panel.appendChild(el('div', 'omni-ui-statusbar is-error', {}, String(reg.error)));
      }

      // Subkeys
      const subkeys = Array.isArray(reg.subkeys) ? reg.subkeys : [];
      if (subkeys.length > 0) {
        const skWrap = el('div', 'reg-subkeys');
        skWrap.appendChild(el('div', 'omni-ui-list-title', {}, 'Subkeys'));
        for (const sk of subkeys) {
          const nextPath = reg.keyPath ? `${reg.keyPath}\\${sk}` : sk;
          const btn = el('button', 'omni-ui-btn omni-ui-btn-xs', { type: 'button' }, sk);
          btn.addEventListener('click', () => {
            this._sendInput(ctx.entry, {
              type: 'action',
              action: 'reg_navigate',
              hive: reg.hive,
              keyPath: nextPath,
            });
          });
          skWrap.appendChild(btn);
        }
        panel.appendChild(skWrap);
      }

      // Values
      const valuesObj = reg.values && typeof reg.values === 'object' ? reg.values : {};
      const valList = el('div', 'reg-values-list');
      for (const [vName, vRec] of Object.entries(valuesObj)) {
        const r = el('div', 'omni-ui-row');
        r.appendChild(el('span', 'mono-chip', {}, vName || '(Default)'));
        r.appendChild(el('span', 'omni-ui-badge', {}, String(vRec?.type ?? 'REG_SZ')));
        r.appendChild(el('span', 'row-grow mono-text', {}, String(vRec?.data ?? '')));
        const btnDel = el('button', 'omni-ui-btn omni-ui-btn-xs omni-ui-btn-danger', { type: 'button' }, 'Del');
        btnDel.addEventListener('click', () => {
          this._sendInput(ctx.entry, {
            type: 'action',
            action: 'reg_delete',
            hive: reg.hive,
            keyPath: reg.keyPath,
            valueName: vName,
          });
        });
        r.appendChild(btnDel);
        valList.appendChild(r);
      }
      panel.appendChild(valList);

      // Add/update value form (CRITICAL: pass `regType`, NOT `type`!)
      const addRow = el('div', 'settings-editor-bar');
      const vNameInp = el('input', 'omni-ui-input omni-ui-input-sm', {
        type: 'text',
        placeholder: 'Value name',
      });
      const vTypeSel = el('select', 'omni-ui-select');
      for (const rt of REG_TYPES) {
        vTypeSel.appendChild(el('option', '', { value: rt }, rt));
      }
      const vDataInp = el('input', 'omni-ui-input omni-ui-input-sm', {
        type: 'text',
        placeholder: 'Data',
      });
      const btnSet = el('button', 'omni-ui-btn omni-ui-btn-sm omni-ui-btn-primary', { type: 'button' }, 'Set Value');
      btnSet.addEventListener('click', () => {
        const valueName = vNameInp.value.trim();
        if (!valueName) return;
        const regType = vTypeSel.value;
        const data = regType === 'REG_DWORD' ? Number(vDataInp.value) : vDataInp.value;
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'reg_set',
          hive: hiveSel.value,
          keyPath: keyPathInp.value.trim(),
          valueName,
          regType,
          data,
        });
      });
      addRow.append(vNameInp, vTypeSel, vDataInp, btnSet);
      panel.appendChild(addRow);
      return panel;
    }

    if (sec === 'defaults') {
      const def = p.defaults ?? { domain: 'NSGlobalDomain', domains: [], values: {}, plistXml: '' };
      const bar = el('div', 'settings-editor-bar');
      const domSel = el('select', 'omni-ui-select');
      const domains = Array.isArray(def.domains) && def.domains.length > 0 ? def.domains : [def.domain || 'NSGlobalDomain'];
      for (const d of domains) {
        const o = el('option', '', { value: d }, d);
        if (d === def.domain) o.selected = true;
        domSel.appendChild(o);
      }
      domSel.addEventListener('change', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'defaults_select',
          domain: domSel.value,
        });
      });
      bar.appendChild(domSel);
      panel.appendChild(bar);

      const vals = def.values && typeof def.values === 'object' ? def.values : {};
      for (const [k, v] of Object.entries(vals)) {
        const r = el('div', 'omni-ui-row');
        r.appendChild(el('span', 'mono-chip', {}, k));
        r.appendChild(el('span', 'row-grow mono-text', {}, typeof v === 'object' ? JSON.stringify(v) : String(v)));
        const btnDel = el('button', 'omni-ui-btn omni-ui-btn-xs omni-ui-btn-danger', { type: 'button' }, 'Del');
        btnDel.addEventListener('click', () => {
          this._sendInput(ctx.entry, {
            type: 'action',
            action: 'defaults_delete',
            domain: def.domain,
            key: k,
          });
        });
        r.appendChild(btnDel);
        panel.appendChild(r);
      }

      const addRow = el('div', 'settings-editor-bar');
      const kInp = el('input', 'omni-ui-input omni-ui-input-sm', { type: 'text', placeholder: 'Key' });
      const vInp = el('input', 'omni-ui-input omni-ui-input-sm', { type: 'text', placeholder: 'Value' });
      const btnSet = el('button', 'omni-ui-btn omni-ui-btn-sm omni-ui-btn-primary', { type: 'button' }, 'Set');
      btnSet.addEventListener('click', () => {
        if (!kInp.value.trim()) return;
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'defaults_set',
          domain: def.domain,
          key: kInp.value.trim(),
          value: vInp.value,
        });
      });
      addRow.append(kInp, vInp, btnSet);
      panel.appendChild(addRow);

      if (def.plistXml) {
        panel.appendChild(el('div', 'omni-ui-list-title', {}, 'Apple Plist XML Preview'));
        panel.appendChild(el('pre', 'omni-ui-code', {}, String(def.plistXml)));
      }
      return panel;
    }

    if (sec === 'prefs') {
      const sp = p.sharedPrefs ?? { packageName: 'com.omnios.system', prefName: 'system_settings', values: {} };
      const bar = el('div', 'settings-editor-bar');
      const pkgInp = el('input', 'omni-ui-input omni-ui-input-sm', { type: 'text', placeholder: 'Package' });
      pkgInp.value = String(sp.packageName ?? '');
      const prefInp = el('input', 'omni-ui-input omni-ui-input-sm', { type: 'text', placeholder: 'Pref name' });
      prefInp.value = String(sp.prefName ?? 'default');
      const btnSel = el('button', 'omni-ui-btn omni-ui-btn-sm', { type: 'button' }, 'Load');
      btnSel.addEventListener('click', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'prefs_select',
          packageName: pkgInp.value.trim(),
          prefName: prefInp.value.trim() || 'default',
        });
      });
      bar.append(pkgInp, prefInp, btnSel);
      panel.appendChild(bar);

      const vals = sp.values && typeof sp.values === 'object' ? sp.values : {};
      for (const [k, v] of Object.entries(vals)) {
        const r = el('div', 'omni-ui-row');
        r.appendChild(el('span', 'mono-chip', {}, k));
        r.appendChild(el('span', 'row-grow mono-text', {}, typeof v === 'object' ? JSON.stringify(v) : String(v)));
        const btnDel = el('button', 'omni-ui-btn omni-ui-btn-xs omni-ui-btn-danger', { type: 'button' }, 'Del');
        btnDel.addEventListener('click', () => {
          this._sendInput(ctx.entry, {
            type: 'action',
            action: 'prefs_remove',
            packageName: sp.packageName,
            prefName: sp.prefName,
            key: k,
          });
        });
        r.appendChild(btnDel);
        panel.appendChild(r);
      }

      const addRow = el('div', 'settings-editor-bar');
      const kInp = el('input', 'omni-ui-input omni-ui-input-sm', { type: 'text', placeholder: 'Key' });
      const vInp = el('input', 'omni-ui-input omni-ui-input-sm', { type: 'text', placeholder: 'Value' });
      const btnSet = el('button', 'omni-ui-btn omni-ui-btn-sm omni-ui-btn-primary', { type: 'button' }, 'Put');
      btnSet.addEventListener('click', () => {
        if (!kInp.value.trim()) return;
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'prefs_set',
          packageName: pkgInp.value.trim(),
          prefName: prefInp.value.trim() || 'default',
          key: kInp.value.trim(),
          value: vInp.value,
        });
      });
      addRow.append(kInp, vInp, btnSet);
      panel.appendChild(addRow);
      return panel;
    }

    // general, permissions matrix, audit children
    for (const child of node.children ?? []) {
      const rendered = this._renderUiNode(child, ctx);
      if (rendered) panel.appendChild(rendered);
    }
    if ((node.children ?? []).length === 0) {
      panel.appendChild(el('div', 'omni-ui-empty', {}, `No entries in ${sec}`));
    }
    return panel;
  }

  // ---- Binary & Process Inspector Specialized Renderers ----

  _renderInspectorTargets(node, ctx) {
    const p = node.props ?? {};
    const panel = el('div', 'omni-ui-panel inspector-targets-panel', {
      'data-node-id': 'inspector-targets',
    });

    const pkgs = Array.isArray(p.catalogPackages) ? p.catalogPackages : [];
    const procs = Array.isArray(p.runningProcesses) ? p.runningProcesses : [];

    const pkgRow = el('div', 'inspector-chips-group');
    pkgRow.appendChild(el('span', 'omni-ui-list-title', {}, 'Catalog Binaries:'));
    for (const pkg of pkgs) {
      const btn = el(
        'button',
        'omni-ui-btn omni-ui-btn-xs',
        { type: 'button' },
        `${pkg.name ?? pkg.appId} (${getPlatformBadge(pkg.platform)})`
      );
      btn.addEventListener('click', () => {
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'inspect_package',
          path: pkg.packagePath,
          catalogId: pkg.catalogId,
          appId: pkg.appId,
        });
      });
      pkgRow.appendChild(btn);
    }
    panel.appendChild(pkgRow);

    const procRow = el('div', 'inspector-chips-group');
    procRow.appendChild(el('span', 'omni-ui-list-title', {}, 'Running PIDs:'));
    for (const proc of procs) {
      const btn = el(
        'button',
        'omni-ui-btn omni-ui-btn-xs',
        { type: 'button' },
        `PID ${proc.pid}: ${proc.name} (${proc.arch})`
      );
      btn.addEventListener('click', () => {
        // CRITICAL: ALWAYS pass targetPid (Compositor overwrites event.pid)
        this._sendInput(ctx.entry, {
          type: 'action',
          action: 'inspect_pid',
          targetPid: proc.pid,
        });
      });
      procRow.appendChild(btn);
    }
    panel.appendChild(procRow);
    return panel;
  }

  _renderInspectorReport(node, ctx) {
    const p = node.props ?? {};
    const panel = el('div', 'omni-ui-panel inspector-report-panel', {
      'data-node-id': 'inspector-report',
    });

    if (p.mode === 'process' && p.processReport) {
      const pr = p.processReport;
      panel.appendChild(
        el(
          'div',
          'omni-ui-panel-header',
          {},
          `Process PID ${pr.pid} — ${pr.name} (${pr.platform}/${pr.arch}) [${pr.state}]`
        )
      );

      const grid = el('div', 'kv-grid');
      const kvs = [
        ['PID / PPID', `${pr.pid} / ${pr.ppid}`],
        ['App ID', pr.appId || '—'],
        ['UID / GID', `${pr.uid} / ${pr.gid}`],
        ['CWD', pr.cwd || '/'],
        ['Threads', String((pr.threads ?? []).length)],
        ['Open FDs', String((pr.fds ?? []).length)],
      ];
      for (const [k, v] of kvs) {
        grid.appendChild(el('span', 'kv-key', {}, k));
        grid.appendChild(el('span', 'kv-val', {}, String(v)));
      }
      panel.appendChild(grid);

      if (pr.debugState) {
        panel.appendChild(el('div', 'omni-ui-list-title', {}, 'CPU / Execution Debug State'));
        panel.appendChild(el('pre', 'omni-ui-code', {}, safeJsonPreview(pr.debugState, 1600)));
      }
      if (pr.vmmStats) {
        panel.appendChild(el('div', 'omni-ui-list-title', {}, 'Virtual Memory (VMM)'));
        panel.appendChild(el('pre', 'omni-ui-code', {}, safeJsonPreview(pr.vmmStats, 1200)));
      }
      if (Array.isArray(pr.fds) && pr.fds.length > 0) {
        panel.appendChild(el('div', 'omni-ui-list-title', {}, `File Descriptors (${pr.fds.length})`));
        panel.appendChild(el('pre', 'omni-ui-code', {}, safeJsonPreview(pr.fds, 800)));
      }
      return panel;
    }

    if (p.mode === 'package' && p.packageReport) {
      const r = p.packageReport;
      panel.appendChild(
        el(
          'div',
          'omni-ui-panel-header',
          {},
          `Binary Report: ${r.name ?? r.filenameHint ?? 'Package'} (${r.format})`
        )
      );

      const grid = el('div', 'kv-grid');
      const kvs = [
        ['Format', r.format],
        ['Platform', r.platform],
        ['Arch', Array.isArray(r.architectures) ? r.architectures.join(', ') : r.arch],
        ['App ID', r.appId || '—'],
        ['Version', r.version || '—'],
        ['Entry Point', r.entryPoint || '—'],
        ['Magic Hex', r.magicHex || '—'],
        ['Size', formatBytes(r.sizeBytes ?? 0)],
        ['SHA-256', r.sha256 || '—'],
      ];
      for (const [k, v] of kvs) {
        grid.appendChild(el('span', 'kv-key', {}, k));
        grid.appendChild(el('span', 'kv-val mono-text', {}, String(v ?? '—')));
      }
      panel.appendChild(grid);

      if (Array.isArray(r.zipEntries) && r.zipEntries.length > 0) {
        panel.appendChild(el('div', 'omni-ui-list-title', {}, `ZIP Archive Entries (${r.zipEntries.length})`));
        const list = el('div', 'inspector-zip-list');
        for (const ze of r.zipEntries.slice(0, 40)) {
          list.appendChild(
            el(
              'div',
              'mono-text',
              {},
              ze.error ? `Error: ${ze.error}` : `${ze.name} (${formatBytes(ze.uncompressedSize ?? 0)})`
            )
          );
        }
        panel.appendChild(list);
      }

      // Render children (inspector-sections & inspector-imports)
      for (const child of node.children ?? []) {
        const rendered = this._renderUiNode(child, ctx);
        if (rendered) {
          const title = child.id === 'inspector-sections' ? 'Sections / Classes' : 'Imports / Methods';
          panel.appendChild(el('div', 'omni-ui-list-title', {}, title));
          panel.appendChild(rendered);
        }
      }
      return panel;
    }

    panel.appendChild(
      el('div', 'omni-ui-empty', {}, 'Select a catalog binary or running PID above to inspect.')
    );
    return panel;
  }
}

export function createCompositorUI(options) {
  return new CompositorUI(options);
}
