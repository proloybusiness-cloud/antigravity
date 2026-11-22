// OmniOS M6 Global Overlays Controller
// Implements Spotlight Search, Universal Share Sheet / Intent Chooser,
// Security & Permission Prompt Modal, and Drag-and-Drop Package Uploader & Inspector.
// Strictly XSS-safe: textContent & createElement only.

const PLATFORM_BADGES = Object.freeze({
  android: 'AND',
  windows: 'WIN',
  ios: 'iOS',
  macos: 'MAC',
  universal: 'WASM',
  system: 'SYS',
});

const PERM_PLATFORM_TITLES = Object.freeze({
  android: 'Android Runtime Permission',
  ios: 'iOS TCC Privacy Prompt',
  macos: 'macOS Gatekeeper / TCC',
  windows: 'Windows UAC Security Prompt',
  universal: 'WASI Capability Request',
  system: 'OmniOS Security Prompt',
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

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export class OverlaysController {
  constructor({
    client,
    onLaunchApp,
    onSwitchShellMode,
    onToggleTheme,
    onToggleDnd,
    onFocusProcess,
    onRefreshPackages,
  } = {}) {
    this._client = client;
    this._onLaunchApp = typeof onLaunchApp === 'function' ? onLaunchApp : () => {};
    this._onSwitchShellMode = typeof onSwitchShellMode === 'function' ? onSwitchShellMode : () => {};
    this._onToggleTheme = typeof onToggleTheme === 'function' ? onToggleTheme : () => {};
    this._onToggleDnd = typeof onToggleDnd === 'function' ? onToggleDnd : () => {};
    this._onFocusProcess = typeof onFocusProcess === 'function' ? onFocusProcess : () => {};
    this._onRefreshPackages = typeof onRefreshPackages === 'function' ? onRefreshPackages : () => {};

    // Spotlight state
    this._searchTimer = null;
    this._searchSeq = 0;
    this._flatResults = [];
    this._selectedIdx = 0;

    // Chooser queue
    this._chooserQueue = [];
    this._activeChooser = null;

    // Permission prompt queue
    this._permQueue = [];
    this._activePerm = null;

    // Package upload state
    this._stagedUpload = null; // { bytes: Uint8Array, filename: string, inspection: object|null }
    this._dragDepth = 0;

    this._dom = this._queryDom();
    this._bindEvents();
  }

  _queryDom() {
    const byId = (id) => (typeof document !== 'undefined' ? document.getElementById(id) : null);
    return {
      // Spotlight
      spotlightOverlay: byId('spotlight-overlay'),
      spotlightInput: byId('spotlight-input'),
      spotlightResults: byId('spotlight-results'),
      spotlightStatus: byId('spotlight-status'),
      // Intent Chooser
      chooserModal: byId('intent-chooser-modal'),
      chooserTitle: byId('chooser-title'),
      chooserMeta: byId('chooser-intent-meta'),
      chooserCandidates: byId('chooser-candidates'),
      chooserDefaultCb: byId('chooser-default-checkbox'),
      btnChooserCancel: byId('btn-chooser-cancel'),
      // Permission Prompt
      permModal: byId('permission-modal'),
      permPlatformBadge: byId('perm-platform-badge'),
      permTitle: byId('perm-title'),
      permAppInfo: byId('perm-app-info'),
      permCapability: byId('perm-capability'),
      permNative: byId('perm-native'),
      permContext: byId('perm-context'),
      permQueueCount: byId('perm-queue-count'),
      btnPermAllow: byId('btn-perm-allow'),
      btnPermAllowOnce: byId('btn-perm-allow-once'),
      btnPermDenyOnce: byId('btn-perm-deny-once'),
      btnPermDeny: byId('btn-perm-deny'),
      // Upload
      uploadDropOverlay: byId('upload-drop-overlay'),
      uploadModal: byId('upload-modal'),
      fileInput: byId('package-file-input'),
      uploadDropzone: byId('upload-dropzone'),
      uploadPreview: byId('upload-inspection-preview'),
      uploadStatus: byId('upload-status'),
      btnUploadChoose: byId('btn-upload-choose'),
      btnUploadInstall: byId('btn-upload-install'),
      btnUploadInstallLaunch: byId('btn-upload-install-launch'),
      btnUploadClose: byId('btn-upload-close'),
    };
  }

  getState() {
    return {
      spotlightOpen: this._dom.spotlightOverlay?.getAttribute('data-open') === 'true',
      chooserOpen: this._dom.chooserModal?.getAttribute('data-open') === 'true',
      permissionOpen: this._dom.permModal?.getAttribute('data-open') === 'true',
      uploadOpen: this._dom.uploadModal?.getAttribute('data-open') === 'true',
      pendingPermissions: this._permQueue.length + (this._activePerm ? 1 : 0),
      pendingChoosers: this._chooserQueue.length + (this._activeChooser ? 1 : 0),
    };
  }

  // =========================================================================
  // 1. Spotlight Universal Search
  // =========================================================================

  openSpotlight(initialQuery = null) {
    const overlay = this._dom.spotlightOverlay;
    if (!overlay) return;
    overlay.setAttribute('data-open', 'true');
    if (this._dom.spotlightInput) {
      if (typeof initialQuery === 'string') {
        this._dom.spotlightInput.value = initialQuery;
      }
      this._dom.spotlightInput.focus();
      this._dom.spotlightInput.select();
    }
    this._runSpotlightQuery(this._dom.spotlightInput?.value ?? '');
  }

  closeSpotlight() {
    if (this._dom.spotlightOverlay) {
      this._dom.spotlightOverlay.setAttribute('data-open', 'false');
    }
    if (this._searchTimer) {
      clearTimeout(this._searchTimer);
      this._searchTimer = null;
    }
  }

  toggleSpotlight() {
    const isOpen = this._dom.spotlightOverlay?.getAttribute('data-open') === 'true';
    if (isOpen) this.closeSpotlight();
    else this.openSpotlight();
  }

  async _runSpotlightQuery(query) {
    const seq = ++this._searchSeq;
    if (this._dom.spotlightStatus) {
      this._dom.spotlightStatus.textContent = 'Searching…';
    }
    try {
      const data = await this._client.searchSpotlight(query, 25);
      if (seq !== this._searchSeq) return;
      this._renderSpotlightResults(data);
    } catch (err) {
      if (seq !== this._searchSeq) return;
      if (this._dom.spotlightStatus) {
        this._dom.spotlightStatus.textContent = `Search error: ${err?.message ?? 'failed'}`;
      }
    }
  }

  _renderSpotlightResults(data) {
    const host = this._dom.spotlightResults;
    if (!host) return;
    const groups = data?.groups ?? {};
    const groupOrder = [
      ['apps', 'Apps'],
      ['actions', 'Quick Actions'],
      ['files', 'Files'],
      ['settings', 'Settings'],
      ['processes', 'Processes'],
    ];

    this._flatResults = [];
    this._selectedIdx = 0;

    const frag = document.createDocumentFragment();
    for (const [key, heading] of groupOrder) {
      const items = Array.isArray(groups[key]) ? groups[key] : [];
      if (items.length === 0) continue;

      const section = el('div', 'spotlight-group', { 'data-group': key });
      section.appendChild(el('div', 'spotlight-group-title', {}, heading));

      for (const item of items) {
        const idx = this._flatResults.length;
        this._flatResults.push(item);

        const btn = el('button', `spotlight-item${idx === 0 ? ' is-selected' : ''}`, {
          type: 'button',
          role: 'option',
          'data-result-index': String(idx),
          'data-result-type': String(item.type ?? ''),
          'data-result-id': String(item.id ?? ''),
        });

        const badgePlat = item.platform || item.type || 'system';
        btn.appendChild(
          el('span', `platform-badge platform-${String(badgePlat).toLowerCase()}`, {}, getPlatformBadge(badgePlat))
        );

        const textWrap = el('span', 'spotlight-item-text');
        textWrap.appendChild(el('span', 'spotlight-item-title', {}, String(item.title ?? item.id ?? '')));
        if (item.subtitle) {
          textWrap.appendChild(el('span', 'spotlight-item-sub', {}, String(item.subtitle)));
        }
        btn.appendChild(textWrap);

        btn.addEventListener('mouseenter', () => this._setSpotlightSelection(idx));
        btn.addEventListener('click', () => this._executeSpotlightResult(item));
        section.appendChild(btn);
      }
      frag.appendChild(section);
    }

    if (this._flatResults.length === 0) {
      frag.appendChild(el('div', 'omni-ui-empty', {}, 'No matching results.'));
    }

    host.replaceChildren(frag);
    if (this._dom.spotlightStatus) {
      const total = Number(data?.total ?? this._flatResults.length);
      this._dom.spotlightStatus.textContent = `${total} result${total === 1 ? '' : 's'} · ↑↓ navigate · Enter open · Esc close`;
    }
  }

  _setSpotlightSelection(idx) {
    if (this._flatResults.length === 0) return;
    const next = ((idx % this._flatResults.length) + this._flatResults.length) % this._flatResults.length;
    this._selectedIdx = next;
    if (!this._dom.spotlightResults) return;
    const nodes = this._dom.spotlightResults.querySelectorAll('.spotlight-item');
    for (const node of nodes) {
      const itemIdx = Number(node.getAttribute('data-result-index'));
      const sel = itemIdx === next;
      node.classList.toggle('is-selected', sel);
      if (sel) node.scrollIntoView({ block: 'nearest' });
    }
  }

  async _executeSpotlightResult(item) {
    if (!item) return;
    this.closeSpotlight();

    if (item.type === 'action') {
      const act = String(item.action ?? '');
      if (act.startsWith('switch-shell-mode:')) {
        this._onSwitchShellMode(act.slice('switch-shell-mode:'.length));
        return;
      }
      if (act === 'toggle-theme') {
        this._onToggleTheme();
        return;
      }
      if (act === 'toggle-dnd') {
        this._onToggleDnd();
        return;
      }
      if (act.startsWith('launch:')) {
        const appId = act.slice('launch:'.length) || item.appId;
        if (appId) this._onLaunchApp(appId, { preferSystem: true });
        return;
      }
      if (item.appId) {
        this._onLaunchApp(item.appId, { preferSystem: true });
      }
      return;
    }

    if (item.type === 'app') {
      const id = String(item.id ?? '');
      const isBuiltin = id.startsWith('system:') || item.metadata?.builtin === true;
      const isCatalog = id.startsWith('catalog:') || item.metadata?.installed === false;
      if (isCatalog) {
        const pkgPath = item.metadata?.packagePath || item.path;
        if (pkgPath) {
          try {
            await this._client.installFromVfsPath(pkgPath, { grantAll: true });
            await this._onRefreshPackages();
          } catch {
            return;
          }
        }
        if (item.appId) this._onLaunchApp(item.appId, {});
        return;
      }
      if (item.appId) {
        this._onLaunchApp(item.appId, isBuiltin ? { preferSystem: true } : {});
      }
      return;
    }

    if (item.type === 'file') {
      this._onLaunchApp('com.omnios.files', {
        preferSystem: true,
        cwd: item.path,
        path: item.path,
        intent: { action: 'view', uri: `file://${item.path}`, extras: { path: item.path } },
      });
      return;
    }

    if (item.type === 'process') {
      this._onFocusProcess(item.pid);
      return;
    }

    if (item.type === 'setting') {
      this._onLaunchApp('com.omnios.settings', { preferSystem: true });
    }
  }

  // =========================================================================
  // 2. Universal Share Sheet / Intent Chooser Modal
  // =========================================================================

  openIntentChooser(payload) {
    if (!payload || !payload.requestId) return;
    if (this._activeChooser?.requestId === payload.requestId) return;
    if (this._chooserQueue.some((c) => c.requestId === payload.requestId)) return;

    if (!this._activeChooser) {
      this._showChooser(payload);
    } else {
      this._chooserQueue.push(payload);
    }
  }

  _showChooser(payload) {
    this._activeChooser = payload;
    const modal = this._dom.chooserModal;
    if (!modal) return;

    const intent = payload.intent ?? {};
    const candidates = Array.isArray(payload.candidates) ? payload.candidates : [];

    if (this._dom.chooserTitle) {
      this._dom.chooserTitle.textContent = `Open / Share With (${intent.action || 'intent'})`;
    }

    if (this._dom.chooserMeta) {
      const parts = [];
      if (intent.action) parts.push(`Action: ${intent.action}`);
      if (intent.mimeType) parts.push(`MIME: ${intent.mimeType}`);
      if (intent.uri) parts.push(`URI: ${intent.uri}`);
      if (intent.extras && Object.keys(intent.extras).length > 0) {
        try {
          parts.push(`Extras: ${JSON.stringify(intent.extras).slice(0, 160)}`);
        } catch {
          // ignore
        }
      }
      this._dom.chooserMeta.textContent = parts.join(' · ') || 'Select a target application';
    }

    if (this._dom.chooserDefaultCb) {
      this._dom.chooserDefaultCb.checked = false;
    }

    if (this._dom.chooserCandidates) {
      const frag = document.createDocumentFragment();
      for (const cand of candidates) {
        const platform = String(cand.platform || 'system').toLowerCase();
        const btn = el('button', 'chooser-candidate-btn', {
          type: 'button',
          'data-chooser-app-id': String(cand.appId ?? ''),
          'data-platform': platform,
        });
        btn.appendChild(
          el('span', `platform-badge platform-${platform}`, {}, getPlatformBadge(platform))
        );
        const textWrap = el('span', 'chooser-candidate-text');
        textWrap.appendChild(el('strong', '', {}, String(cand.label ?? cand.appId ?? 'App')));
        textWrap.appendChild(
          el(
            'span',
            'chooser-candidate-sub',
            {},
            `${cand.appId ?? ''}${Array.isArray(cand.matchedOn) && cand.matchedOn.length ? ` · ${cand.matchedOn.join(', ')}` : ''}`
          )
        );
        btn.appendChild(textWrap);
        btn.addEventListener('click', () => this._submitChooserChoice(cand.appId));
        frag.appendChild(btn);
      }
      this._dom.chooserCandidates.replaceChildren(frag);
    }

    modal.setAttribute('data-open', 'true');
  }

  async _submitChooserChoice(appId) {
    const active = this._activeChooser;
    if (!active) return;
    const setAsDefault = Boolean(this._dom.chooserDefaultCb?.checked);
    this._advanceChooserModal();
    try {
      await this._client.resolveIntentChooser(active.requestId, { appId, setAsDefault });
    } catch {
      // ignore if already resolved/expired
    }
  }

  async _cancelChooser() {
    const active = this._activeChooser;
    if (!active) return;
    this._advanceChooserModal();
    try {
      await this._client.resolveIntentChooser(active.requestId, { cancel: true });
    } catch {
      // ignore
    }
  }

  _advanceChooserModal() {
    this._activeChooser = null;
    if (this._chooserQueue.length > 0) {
      this._showChooser(this._chooserQueue.shift());
    } else if (this._dom.chooserModal) {
      this._dom.chooserModal.setAttribute('data-open', 'false');
    }
  }

  // =========================================================================
  // 3. Security & Permission Prompt Modal
  // =========================================================================

  enqueuePermissionPrompt(prompt) {
    if (!prompt || !prompt.promptId) return;
    if (this._activePerm?.promptId === prompt.promptId) return;
    if (this._permQueue.some((p) => p.promptId === prompt.promptId)) return;

    if (!this._activePerm) {
      this._showPermissionPrompt(prompt);
    } else {
      this._permQueue.push(prompt);
      this._updatePermQueueCount();
    }
  }

  _showPermissionPrompt(prompt) {
    this._activePerm = prompt;
    const modal = this._dom.permModal;
    if (!modal) return;

    const platform = String(prompt.platform || 'system').toLowerCase();
    modal.setAttribute('data-platform', platform);
    modal.setAttribute('data-prompt-id', String(prompt.promptId));

    if (this._dom.permPlatformBadge) {
      this._dom.permPlatformBadge.className = `platform-badge platform-${platform}`;
      this._dom.permPlatformBadge.textContent = getPlatformBadge(platform);
    }
    if (this._dom.permTitle) {
      this._dom.permTitle.textContent =
        PERM_PLATFORM_TITLES[platform] || PERM_PLATFORM_TITLES.system;
    }
    if (this._dom.permAppInfo) {
      this._dom.permAppInfo.textContent = `${prompt.appId ?? 'Unknown App'}${prompt.pid ? ` (PID ${prompt.pid})` : ''}`;
    }
    if (this._dom.permCapability) {
      this._dom.permCapability.textContent = String(prompt.capability ?? 'unknown');
    }
    if (this._dom.permNative) {
      this._dom.permNative.textContent = prompt.nativePermission
        ? String(prompt.nativePermission)
        : '—';
    }
    if (this._dom.permContext) {
      const ctx = prompt.context && Object.keys(prompt.context).length > 0 ? prompt.context : null;
      this._dom.permContext.textContent = ctx ? JSON.stringify(ctx, null, 2) : 'No extra context';
    }
    this._updatePermQueueCount();
    modal.setAttribute('data-open', 'true');
  }

  _updatePermQueueCount() {
    if (!this._dom.permQueueCount) return;
    const total = this._permQueue.length + (this._activePerm ? 1 : 0);
    this._dom.permQueueCount.textContent = total > 1 ? `1 of ${total} pending` : '';
  }

  async _submitPermissionDecision(decision) {
    const active = this._activePerm;
    if (!active) return;
    const promptId = active.promptId;
    this._activePerm = null;
    if (this._permQueue.length > 0) {
      this._showPermissionPrompt(this._permQueue.shift());
    } else if (this._dom.permModal) {
      this._dom.permModal.setAttribute('data-open', 'false');
    }

    try {
      await this._client.resolvePermissionPrompt(promptId, decision);
    } catch {
      // Prompt may have timed out on kernel side
    }
  }

  // =========================================================================
  // 4. Drag-and-Drop Binary Package Uploader & Inspector Modal
  // =========================================================================

  openUploadModal() {
    if (!this._dom.uploadModal) return;
    this._dom.uploadModal.setAttribute('data-open', 'true');
    this._syncUploadButtons();
  }

  closeUploadModal() {
    if (this._dom.uploadModal) {
      this._dom.uploadModal.setAttribute('data-open', 'false');
    }
  }

  _syncUploadButtons() {
    const hasFile = Boolean(this._stagedUpload && this._stagedUpload.bytes?.byteLength > 0);
    if (this._dom.btnUploadInstall) this._dom.btnUploadInstall.disabled = !hasFile;
    if (this._dom.btnUploadInstallLaunch) this._dom.btnUploadInstallLaunch.disabled = !hasFile;
  }

  async handleBinaryFile(file) {
    if (!file) return;
    this.openUploadModal();
    if (this._dom.uploadStatus) {
      this._dom.uploadStatus.textContent = `Inspecting ${file.name}…`;
    }
    if (this._dom.uploadPreview) {
      this._dom.uploadPreview.replaceChildren();
    }

    try {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      this._stagedUpload = { bytes, filename: file.name || 'package.bin', inspection: null };
      this._syncUploadButtons();

      const res = await this._client.inspectBinary(bytes, file.name || 'package.bin');
      const insp = res?.inspection ?? res;
      this._stagedUpload.inspection = insp;
      this._renderUploadInspection(insp, file.name);
      if (this._dom.uploadStatus) {
        this._dom.uploadStatus.textContent = `Ready to install: ${insp?.name || file.name} (${insp?.format || 'binary'})`;
      }
    } catch (err) {
      this._stagedUpload = null;
      this._syncUploadButtons();
      if (this._dom.uploadStatus) {
        this._dom.uploadStatus.textContent = `Inspection failed: ${err?.message ?? 'Invalid binary package'}`;
      }
    }
  }

  _renderUploadInspection(insp, filename) {
    const host = this._dom.uploadPreview;
    if (!host || !insp) return;

    const card = el('div', 'upload-inspect-card');
    const head = el('div', 'upload-inspect-head');
    const platform = String(insp.platform || 'universal').toLowerCase();
    head.appendChild(
      el('span', `platform-badge platform-${platform}`, {}, getPlatformBadge(platform))
    );
    head.appendChild(el('strong', '', {}, String(insp.name || filename || 'Package')));
    head.appendChild(el('span', 'omni-ui-badge', {}, String(insp.format || 'unknown')));
    card.appendChild(head);

    const grid = el('div', 'kv-grid');
    const rows = [
      ['App ID', insp.appId || '—'],
      ['Platform', insp.platform || '—'],
      ['Architecture', insp.arch || '—'],
      ['Version', insp.version || '—'],
      ['Entry Point', insp.entryPoint || '—'],
      ['Size', formatBytes(insp.sizeBytes ?? 0)],
      ['SHA-256', insp.sha256 ? `${String(insp.sha256).slice(0, 24)}…` : '—'],
      [
        'Permissions',
        Array.isArray(insp.permissions) && insp.permissions.length > 0
          ? insp.permissions.join(', ')
          : 'None requested',
      ],
      [
        'Intents',
        Array.isArray(insp.intents) && insp.intents.length > 0
          ? `${insp.intents.length} registered`
          : 'None',
      ],
    ];
    for (const [k, v] of rows) {
      grid.appendChild(el('span', 'kv-key', {}, k));
      grid.appendChild(el('span', 'kv-val mono-text', {}, String(v)));
    }
    card.appendChild(grid);
    host.replaceChildren(card);
  }

  async _installStagedPackage({ launchAfter = false } = {}) {
    const staged = this._stagedUpload;
    if (!staged || !staged.bytes) return;
    if (this._dom.btnUploadInstall) this._dom.btnUploadInstall.disabled = true;
    if (this._dom.btnUploadInstallLaunch) this._dom.btnUploadInstallLaunch.disabled = true;
    if (this._dom.uploadStatus) {
      this._dom.uploadStatus.textContent = `Installing ${staged.filename}…`;
    }

    try {
      const res = await this._client.installBinary(staged.bytes, staged.filename, {
        grantAll: true,
        overwrite: true,
        source: 'upload',
      });
      const pkg = res?.package ?? null;
      await this._onRefreshPackages();
      if (this._dom.uploadStatus) {
        this._dom.uploadStatus.textContent = `Installed ${pkg?.name || pkg?.appId || staged.filename}!`;
      }
      if (launchAfter && pkg?.appId) {
        this.closeUploadModal();
        // Uploaded binaries are installed user apps — omit preferSystem
        this._onLaunchApp(pkg.appId, {});
      }
    } catch (err) {
      if (this._dom.uploadStatus) {
        this._dom.uploadStatus.textContent = `Install failed: ${err?.message ?? 'Error'}`;
      }
    } finally {
      this._syncUploadButtons();
    }
  }

  // =========================================================================
  // Event Binding
  // =========================================================================

  _bindEvents() {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;

    // Global keyboard shortcuts: Ctrl/Cmd+Space -> Spotlight, Escape -> close active overlay
    window.addEventListener('keydown', (ev) => {
      if ((ev.metaKey || ev.ctrlKey) && (ev.code === 'Space' || ev.key === ' ')) {
        ev.preventDefault();
        this.toggleSpotlight();
        return;
      }

      if (ev.key === 'Escape') {
        if (this._dom.spotlightOverlay?.getAttribute('data-open') === 'true') {
          ev.preventDefault();
          this.closeSpotlight();
          return;
        }
        if (this._dom.uploadModal?.getAttribute('data-open') === 'true') {
          ev.preventDefault();
          this.closeUploadModal();
          return;
        }
        if (this._dom.chooserModal?.getAttribute('data-open') === 'true') {
          ev.preventDefault();
          this._cancelChooser();
        }
      }
    });

    // Spotlight interactions
    this._dom.spotlightOverlay?.addEventListener('click', (ev) => {
      if (ev.target === this._dom.spotlightOverlay) this.closeSpotlight();
    });
    this._dom.spotlightInput?.addEventListener('input', () => {
      if (this._searchTimer) clearTimeout(this._searchTimer);
      const q = this._dom.spotlightInput.value;
      this._searchTimer = setTimeout(() => {
        this._searchTimer = null;
        this._runSpotlightQuery(q);
      }, 100);
    });
    this._dom.spotlightInput?.addEventListener('keydown', (ev) => {
      if (ev.key === 'ArrowDown') {
        ev.preventDefault();
        this._setSpotlightSelection(this._selectedIdx + 1);
      } else if (ev.key === 'ArrowUp') {
        ev.preventDefault();
        this._setSpotlightSelection(this._selectedIdx - 1);
      } else if (ev.key === 'Enter') {
        ev.preventDefault();
        const chosen = this._flatResults[this._selectedIdx];
        if (chosen) this._executeSpotlightResult(chosen);
      }
    });

    // Chooser interactions
    this._dom.btnChooserCancel?.addEventListener('click', () => this._cancelChooser());

    // Permission modal 4 buttons
    const permButtons = [
      [this._dom.btnPermAllow, 'allow'],
      [this._dom.btnPermAllowOnce, 'allow_once'],
      [this._dom.btnPermDenyOnce, 'deny_once'],
      [this._dom.btnPermDeny, 'deny'],
    ];
    for (const [btn, fallbackDecision] of permButtons) {
      btn?.addEventListener('click', () => {
        const dec = btn.getAttribute('data-perm-decision') || fallbackDecision;
        this._submitPermissionDecision(dec);
      });
    }

    // Upload modal controls
    this._dom.btnUploadClose?.addEventListener('click', () => this.closeUploadModal());
    this._dom.uploadModal?.addEventListener('click', (ev) => {
      if (ev.target === this._dom.uploadModal) this.closeUploadModal();
    });
    this._dom.btnUploadChoose?.addEventListener('click', (ev) => {
      ev.stopPropagation();
      this._dom.fileInput?.click();
    });
    this._dom.uploadDropzone?.addEventListener('click', (ev) => {
      if (ev.target instanceof Element && ev.target.closest('#btn-upload-choose')) return;
      this._dom.fileInput?.click();
    });
    this._dom.fileInput?.addEventListener('change', () => {
      const file = this._dom.fileInput.files?.[0];
      if (file) this.handleBinaryFile(file);
      this._dom.fileInput.value = '';
    });
    this._dom.btnUploadInstall?.addEventListener('click', () =>
      this._installStagedPackage({ launchAfter: false })
    );
    this._dom.btnUploadInstallLaunch?.addEventListener('click', () =>
      this._installStagedPackage({ launchAfter: true })
    );

    // Drag & Drop handlers on dropzone and window
    const hasFiles = (ev) => {
      const types = ev.dataTransfer?.types;
      return Boolean(types && [...types].includes('Files'));
    };

    window.addEventListener('dragenter', (ev) => {
      if (!hasFiles(ev)) return;
      ev.preventDefault();
      this._dragDepth += 1;
      this._dom.uploadDropOverlay?.setAttribute('data-active', 'true');
    });

    window.addEventListener('dragover', (ev) => {
      if (!hasFiles(ev)) return;
      ev.preventDefault();
      if (ev.dataTransfer) ev.dataTransfer.dropEffect = 'copy';
    });

    window.addEventListener('dragleave', (ev) => {
      if (!hasFiles(ev)) return;
      this._dragDepth = Math.max(0, this._dragDepth - 1);
      if (this._dragDepth === 0) {
        this._dom.uploadDropOverlay?.setAttribute('data-active', 'false');
      }
    });

    window.addEventListener('drop', (ev) => {
      this._dragDepth = 0;
      this._dom.uploadDropOverlay?.setAttribute('data-active', 'false');
      const file = ev.dataTransfer?.files?.[0];
      if (!file) return;
      ev.preventDefault();
      this.handleBinaryFile(file);
    });
  }
}

export function createOverlaysController(options) {
  return new OverlaysController(options);
}
