// OmniOS M6 WebSocket & REST v1 Client
// Pure browser ES module — zero external dependencies, same-origin only.

export const CANONICAL_SHELL_MODES = Object.freeze([
  'unified',
  'windows',
  'macos',
  'ios',
  'android',
]);

export const SYSTEM_APP_IDS = Object.freeze([
  'com.omnios.terminal',
  'com.omnios.files',
  'com.omnios.monitor',
  'com.omnios.apphub',
  'com.omnios.settings',
  'com.omnios.inspector',
  'com.omnios.notes',
]);

const SYSTEM_APP_ID_SET = new Set(SYSTEM_APP_IDS);

const SAFE_NAMED_COLORS = new Set([
  'transparent', 'currentcolor',
  'black', 'white', 'red', 'green', 'blue', 'yellow', 'cyan', 'magenta',
  'gray', 'grey', 'silver', 'maroon', 'olive', 'lime', 'aqua', 'teal',
  'navy', 'fuchsia', 'purple', 'orange', 'pink', 'brown', 'gold', 'indigo',
  'violet', 'coral', 'crimson', 'salmon', 'tomato', 'khaki', 'plum', 'orchid',
  'turquoise', 'tan', 'beige', 'ivory', 'lavender', 'linen', 'mintcream',
  'mistyrose', 'moccasin', 'oldlace', 'peru', 'sienna', 'snow', 'thistle',
  'wheat', 'azure', 'bisque', 'chocolate', 'darkblue', 'darkcyan', 'darkgray',
  'darkgreen', 'darkgrey', 'darkkhaki', 'darkmagenta', 'darkolivegreen',
  'darkorange', 'darkorchid', 'darkred', 'darksalmon', 'darkseagreen',
  'darkslateblue', 'darkslategray', 'darkslategrey', 'darkturquoise',
  'darkviolet', 'deeppink', 'deepskyblue', 'dimgray', 'dimgrey', 'dodgerblue',
  'firebrick', 'forestgreen', 'gainsboro', 'ghostwhite', 'goldenrod',
  'greenyellow', 'honeydew', 'hotpink', 'indianred', 'lawngreen', 'lightblue',
  'lightcoral', 'lightcyan', 'lightgray', 'lightgreen', 'lightgrey',
  'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue',
  'lightslategray', 'lightslategrey', 'lightsteelblue', 'lightyellow',
  'limegreen', 'mediumaquamarine', 'mediumblue', 'mediumorchid',
  'mediumpurple', 'mediumseagreen', 'mediumslateblue', 'mediumspringgreen',
  'mediumturquoise', 'mediumvioletred', 'midnightblue', 'navajowhite',
  'olivedrab', 'orangered', 'palegoldenrod', 'palegreen', 'paleturquoise',
  'palevioletred', 'papayawhip', 'peachpuff', 'powderblue', 'rebeccapurple',
  'rosybrown', 'royalblue', 'saddlebrown', 'sandybrown', 'seagreen',
  'seashell', 'skyblue', 'slateblue', 'slategray', 'slategrey', 'springgreen',
  'steelblue', 'whitesmoke', 'yellowgreen',
]);

const HEX_COLOR_RE = /^#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;
const ANDROID_ARGB_RE = /^#([0-9a-f]{2})([0-9a-f]{6})$/i;
const RGB_COLOR_RE =
  /^rgba?\(\s*(?:\d{1,3}%?\s*[,\s]\s*){2}\d{1,3}%?(?:\s*[,/]\s*(?:0|1|0?\.\d+|\d{1,3}%))?\s*\)$/i;
const HSL_COLOR_RE =
  /^hsla?\(\s*\d{1,3}(?:deg)?\s*[,\s]\s*\d{1,3}%\s*[,\s]\s*\d{1,3}%(?:\s*[,/]\s*(?:0|1|0?\.\d+|\d{1,3}%))?\s*\)$/i;

export function isSystemAppId(appId) {
  return typeof appId === 'string' && SYSTEM_APP_ID_SET.has(appId);
}

export function normalizeShellMode(mode) {
  if (typeof mode !== 'string') return 'unified';
  const trimmed = mode.trim().toLowerCase();
  const mapped = trimmed === 'hybrid' ? 'unified' : trimmed;
  return CANONICAL_SHELL_MODES.includes(mapped) ? mapped : 'unified';
}

export function normalizeAndroidColor(raw) {
  if (typeof raw !== 'string') return raw;
  const trimmed = raw.trim();
  const m = ANDROID_ARGB_RE.exec(trimmed);
  if (!m) return trimmed;
  // Convert Android #AARRGGBB -> CSS #RRGGBBAA
  return `#${m[2]}${m[1]}`;
}

export function sanitizeCssColor(raw, { isAndroid = false } = {}) {
  if (typeof raw !== 'string') return null;
  let val = raw.trim();
  if (!val || val.length > 64) return null;
  // Reject any CSS injection characters or tokens outright
  if (/[;{}\\'"<>`]/.test(val) || /url\s*\(|expression\s*\(|var\s*\(|calc\s*\(/i.test(val)) {
    return null;
  }
  if (isAndroid && ANDROID_ARGB_RE.test(val)) {
    val = normalizeAndroidColor(val);
  }
  if (HEX_COLOR_RE.test(val)) return val;
  if (RGB_COLOR_RE.test(val)) return val;
  if (HSL_COLOR_RE.test(val)) return val;
  const lower = val.toLowerCase();
  if (SAFE_NAMED_COLORS.has(lower)) return lower;
  return null;
}

function toAsciiHeaderFilename(name) {
  const cleaned = String(name || 'package.bin')
    .replace(/[\r\n\0]/g, '')
    .replace(/[^\x20-\x7e]/g, '_');
  return cleaned || 'package.bin';
}

function toUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new TypeError('Expected ArrayBuffer or Uint8Array for binary upload');
}

export class OmniApiError extends Error {
  constructor(message, { status = 0, code = 'API_ERROR', details = null, payload = null } = {}) {
    super(message);
    this.name = 'OmniApiError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.payload = payload;
  }
}

export class OmniClient {
  constructor({ wsPath = '/ws', pingIntervalMs = 20_000 } = {}) {
    this._wsPath = wsPath;
    this._pingIntervalMs = pingIntervalMs;
    this._ws = null;
    this._connected = false;
    this._closedByUser = false;
    this._reconnectAttempts = 0;
    this._reconnectTimer = null;
    this._pingTimer = null;
    this._listeners = new Map();
    this._reqSeq = 0;
  }

  on(type, fn) {
    if (typeof type !== 'string' || typeof fn !== 'function') {
      return () => {};
    }
    let set = this._listeners.get(type);
    if (!set) {
      set = new Set();
      this._listeners.set(type, set);
    }
    set.add(fn);
    return () => this.off(type, fn);
  }

  off(type, fn) {
    const set = this._listeners.get(type);
    if (!set) return;
    set.delete(fn);
    if (set.size === 0) this._listeners.delete(type);
  }

  _emit(type, payload, envelope = null) {
    const set = this._listeners.get(type);
    if (!set || set.size === 0) return;
    for (const fn of [...set]) {
      try {
        fn(payload, envelope);
      } catch (err) {
        // Isolate subscriber errors so one handler never breaks WebSocket delivery
        if (typeof console !== 'undefined' && console.warn) {
          console.warn(`[OmniClient] listener error on ${type}:`, err);
        }
      }
    }
  }

  isConnected() {
    return this._connected && this._ws !== null && this._ws.readyState === WebSocket.OPEN;
  }

  connect() {
    this._closedByUser = false;
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (
      this._ws &&
      (this._ws.readyState === WebSocket.OPEN || this._ws.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }
    const loc = globalThis.location;
    if (!loc || typeof WebSocket === 'undefined') return;
    const proto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${loc.host}${this._wsPath}`;

    let socket;
    try {
      socket = new WebSocket(wsUrl);
    } catch (err) {
      this._emit('ws:error', err);
      this._scheduleReconnect();
      return;
    }
    this._ws = socket;

    socket.addEventListener('open', () => {
      if (this._ws !== socket) return;
      this._connected = true;
      this._reconnectAttempts = 0;
      this._startPing();
      this._emit('ws:open', { url: wsUrl });
    });

    socket.addEventListener('message', (event) => {
      if (this._ws !== socket) return;
      if (typeof event.data !== 'string') return;
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }
      if (!msg || typeof msg !== 'object') return;
      this._emit('ws:message', msg, msg);
      if (typeof msg.type === 'string') {
        this._emit(msg.type, msg.payload, msg);
      }
    });

    socket.addEventListener('error', (event) => {
      if (this._ws !== socket) return;
      this._emit('ws:error', event);
    });

    socket.addEventListener('close', (event) => {
      if (this._ws !== socket) return;
      this._stopPing();
      this._connected = false;
      this._ws = null;
      this._emit('ws:close', {
        code: event?.code ?? 1000,
        reason: event?.reason ?? '',
        wasClean: Boolean(event?.wasClean),
      });
      if (!this._closedByUser) {
        this._scheduleReconnect();
      }
    });
  }

  disconnect() {
    this._closedByUser = true;
    this._stopPing();
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    const socket = this._ws;
    this._ws = null;
    this._connected = false;
    if (socket) {
      try {
        socket.close(1000, 'client_disconnect');
      } catch {
        // ignore close errors
      }
    }
  }

  _startPing() {
    this._stopPing();
    this._pingTimer = setInterval(() => {
      if (this.isConnected()) {
        this.send('ping', { ts: Date.now() }, `ping-${++this._reqSeq}`);
      }
    }, this._pingIntervalMs);
  }

  _stopPing() {
    if (this._pingTimer) {
      clearInterval(this._pingTimer);
      this._pingTimer = null;
    }
  }

  _scheduleReconnect() {
    if (this._closedByUser || this._reconnectTimer) return;
    const delay = Math.min(8000, 400 * 2 ** Math.min(this._reconnectAttempts, 5));
    this._reconnectAttempts += 1;
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      if (!this._closedByUser) this.connect();
    }, delay);
  }

  send(type, payload = {}, id = undefined) {
    if (!this.isConnected()) return false;
    const envelope = {
      type,
      ...(id !== undefined && id !== null ? { id } : {}),
      payload: payload && typeof payload === 'object' ? payload : {},
    };
    try {
      this._ws.send(JSON.stringify(envelope));
      return true;
    } catch {
      return false;
    }
  }

  async apiFetch(path, opts = {}) {
    const method = (opts.method ?? 'GET').toUpperCase();
    const headers = { ...(opts.headers ?? {}) };
    let body = opts.body;

    const isBinary =
      body instanceof Uint8Array ||
      body instanceof ArrayBuffer ||
      ArrayBuffer.isView(body) ||
      (typeof Blob !== 'undefined' && body instanceof Blob);

    if (body !== undefined && body !== null && !isBinary && typeof body !== 'string') {
      if (!headers['Content-Type'] && !headers['content-type']) {
        headers['Content-Type'] = 'application/json; charset=utf-8';
      }
      body = JSON.stringify(body);
    }

    const res = await fetch(path, {
      method,
      headers,
      body: method === 'GET' || method === 'HEAD' ? undefined : body,
      credentials: 'same-origin',
      signal: opts.signal,
    });

    const contentType = res.headers.get('content-type') || '';
    let data = null;
    if (contentType.includes('application/json')) {
      try {
        data = await res.json();
      } catch {
        data = null;
      }
    } else {
      try {
        data = await res.text();
      } catch {
        data = null;
      }
    }

    if (!res.ok) {
      const code =
        (data && typeof data === 'object' && (data.code || data.error?.code)) ||
        `HTTP_${res.status}`;
      const message =
        (data && typeof data === 'object' && (data.error?.message || data.message)) ||
        (typeof data === 'string' && data.trim()) ||
        `Request failed (${res.status} ${res.statusText})`;
      const details = data && typeof data === 'object' ? (data.error?.details ?? null) : null;
      throw new OmniApiError(message, { status: res.status, code, details, payload: data });
    }

    return data;
  }

  // ---- Compositor ----

  getSnapshot() {
    return this.apiFetch('/api/v1/compositor/snapshot');
  }

  async setShellMode(mode) {
    const normalized = normalizeShellMode(mode);
    return this.apiFetch('/api/v1/compositor/shell-mode', {
      method: 'PUT',
      body: { mode: normalized },
    });
  }

  moveWindow(windowId, x, y) {
    const nx = Math.round(Number(x));
    const ny = Math.round(Number(y));
    if (this.send('compositor:move', { windowId, x: nx, y: ny })) {
      return Promise.resolve({ ok: true, transport: 'ws' });
    }
    return this.apiFetch(`/api/v1/compositor/windows/${encodeURIComponent(windowId)}/move`, {
      method: 'POST',
      body: { x: nx, y: ny },
    });
  }

  resizeWindow(windowId, width, height) {
    const nw = Math.max(1, Math.round(Number(width)));
    const nh = Math.max(1, Math.round(Number(height)));
    if (this.send('compositor:resize', { windowId, width: nw, height: nh })) {
      return Promise.resolve({ ok: true, transport: 'ws' });
    }
    return this.apiFetch(`/api/v1/compositor/windows/${encodeURIComponent(windowId)}/resize`, {
      method: 'POST',
      body: { width: nw, height: nh },
    });
  }

  focusWindow(windowId) {
    if (this.send('compositor:focus', { windowId })) {
      return Promise.resolve({ ok: true, transport: 'ws' });
    }
    return this.apiFetch(`/api/v1/compositor/windows/${encodeURIComponent(windowId)}/focus`, {
      method: 'POST',
      body: {},
    });
  }

  setWindowState(windowId, state) {
    if (this.send('compositor:state', { windowId, state })) {
      return Promise.resolve({ ok: true, transport: 'ws' });
    }
    return this.apiFetch(`/api/v1/compositor/windows/${encodeURIComponent(windowId)}/state`, {
      method: 'POST',
      body: { state },
    });
  }

  closeWindow(windowId) {
    if (this.send('compositor:close', { windowId })) {
      return Promise.resolve({ ok: true, transport: 'ws' });
    }
    return this.apiFetch(`/api/v1/compositor/windows/${encodeURIComponent(windowId)}/close`, {
      method: 'POST',
      body: {},
    });
  }

  dispatchInput(windowId, event) {
    // ALWAYS nest `{ windowId, event }` so websocket.mjs never strips event.id / event.type
    if (this.send('compositor:input', { windowId, event })) {
      return Promise.resolve({ ok: true, transport: 'ws' });
    }
    return this.apiFetch(`/api/v1/compositor/windows/${encodeURIComponent(windowId)}/input`, {
      method: 'POST',
      body: { event },
    });
  }

  dispatchMenuAction(payload) {
    if (this.send('compositor:menu_action', payload)) {
      return Promise.resolve({ ok: true, transport: 'ws' });
    }
    if (payload && payload.windowId) {
      return this.dispatchInput(payload.windowId, {
        type: 'menu_action',
        actionId: payload.actionId ?? payload.itemId,
        itemId: payload.itemId ?? payload.actionId,
        menuId: payload.menuId ?? null,
        label: payload.label ?? null,
        ...(payload.action ? { action: payload.action } : {}),
      });
    }
    return Promise.resolve({ ok: false });
  }

  // ---- Packages & Apps ----

  listPackages(platform = null) {
    const qs = platform ? `?platform=${encodeURIComponent(platform)}` : '';
    return this.apiFetch(`/api/v1/packages${qs}`);
  }

  getCatalog(platform = null) {
    const qs = platform ? `?platform=${encodeURIComponent(platform)}` : '';
    return this.apiFetch(`/api/v1/packages/catalog${qs}`);
  }

  launchApp(appId, opts = {}) {
    return this.apiFetch(`/api/v1/packages/${encodeURIComponent(appId)}/launch`, {
      method: 'POST',
      body: opts && typeof opts === 'object' ? opts : {},
    });
  }

  stopApp(appId, opts = {}) {
    return this.apiFetch(`/api/v1/packages/${encodeURIComponent(appId)}/stop`, {
      method: 'POST',
      body: opts && typeof opts === 'object' ? opts : {},
    });
  }

  uninstallApp(appId, opts = {}) {
    const qs = opts?.purgeData ? '?purgeData=true' : '';
    return this.apiFetch(`/api/v1/packages/${encodeURIComponent(appId)}${qs}`, {
      method: 'DELETE',
    });
  }

  inspectBinary(arrayBufferOrBytes, filenameHint = '') {
    const bytes = toUint8Array(arrayBufferOrBytes);
    const qs = filenameHint ? `?filenameHint=${encodeURIComponent(filenameHint)}` : '';
    return this.apiFetch(`/api/v1/packages/inspect${qs}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Filename': toAsciiHeaderFilename(filenameHint),
      },
      body: bytes,
    });
  }

  installBinary(arrayBufferOrBytes, filenameHint = '', opts = {}) {
    const bytes = toUint8Array(arrayBufferOrBytes);
    const params = new URLSearchParams();
    if (filenameHint) params.set('filenameHint', filenameHint);
    if (opts.grantAll !== undefined) params.set('grantAll', String(Boolean(opts.grantAll)));
    else params.set('grantAll', 'true');
    if (opts.overwrite) params.set('overwrite', 'true');
    if (opts.upgrade) params.set('upgrade', 'true');
    if (opts.source) params.set('source', String(opts.source));
    const qs = params.toString() ? `?${params.toString()}` : '';
    return this.apiFetch(`/api/v1/packages/install${qs}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Filename': toAsciiHeaderFilename(filenameHint),
      },
      body: bytes,
    });
  }

  installFromVfsPath(packagePath, opts = {}) {
    return this.apiFetch('/api/v1/packages/install', {
      method: 'POST',
      body: {
        path: packagePath,
        grantAll: opts.grantAll ?? true,
        overwrite: opts.overwrite ?? false,
        upgrade: opts.upgrade ?? false,
        source: opts.source ?? 'ui',
      },
    });
  }

  // ---- Processes ----

  listProcesses({ includeTerminated = false } = {}) {
    const qs = includeTerminated ? '?includeTerminated=true' : '';
    return this.apiFetch(`/api/v1/processes${qs}`);
  }

  signalProcess(pid, signal = 'SIGTERM') {
    return this.apiFetch(`/api/v1/processes/${encodeURIComponent(String(pid))}/signal`, {
      method: 'POST',
      body: { signal },
    });
  }

  // ---- System Config ----

  getSystemConfig(key = null) {
    const qs = key ? `?key=${encodeURIComponent(key)}` : '';
    return this.apiFetch(`/api/v1/config/system${qs}`);
  }

  setSystemConfig(keyOrMap, value = undefined) {
    const body =
      typeof keyOrMap === 'string'
        ? { key: keyOrMap, value }
        : { values: keyOrMap && typeof keyOrMap === 'object' ? keyOrMap : {} };
    return this.apiFetch('/api/v1/config/system', {
      method: 'PUT',
      body,
    });
  }

  // ---- Notifications & Live Activities ----

  getNotifications(opts = {}) {
    const params = new URLSearchParams();
    if (opts.includeDismissed) params.set('includeDismissed', 'true');
    if (opts.unreadOnly) params.set('unreadOnly', 'true');
    if (opts.appId) params.set('appId', opts.appId);
    const qs = params.toString() ? `?${params.toString()}` : '';
    return this.apiFetch(`/api/v1/ipc/notifications${qs}`);
  }

  dismissNotification(id) {
    return this.apiFetch(`/api/v1/ipc/notifications/${encodeURIComponent(id)}/dismiss`, {
      method: 'POST',
      body: {},
    });
  }

  clearNotifications(appId = null) {
    const qs = appId ? `?appId=${encodeURIComponent(appId)}` : '';
    return this.apiFetch(`/api/v1/ipc/notifications${qs}`, {
      method: 'DELETE',
    });
  }

  invokeNotificationAction(id, actionId, input = undefined) {
    return this.apiFetch(`/api/v1/ipc/notifications/${encodeURIComponent(id)}/action`, {
      method: 'POST',
      body: {
        actionId,
        ...(input !== undefined ? { input } : {}),
      },
    });
  }

  // ---- Permissions ----

  getPermissions(appId = null) {
    const qs = appId ? `?appId=${encodeURIComponent(appId)}` : '';
    return this.apiFetch(`/api/v1/security/permissions${qs}`);
  }

  resolvePermissionPrompt(promptId, decision) {
    return this.apiFetch('/api/v1/security/permissions', {
      method: 'POST',
      body: { promptId, decision },
    });
  }

  // ---- Intent Chooser ----

  resolveIntentChooser(requestId, choice = {}) {
    const body = choice.cancel
      ? { requestId, cancel: true }
      : {
          requestId,
          appId: choice.appId ?? choice.chosenAppId,
          setAsDefault: Boolean(choice.setAsDefault),
        };
    return this.apiFetch('/api/v1/ipc/intents/choose', {
      method: 'POST',
      body,
    });
  }

  // ---- Spotlight Search ----

  searchSpotlight(query = '', limit = 25, types = null) {
    const params = new URLSearchParams();
    params.set('q', String(query ?? ''));
    params.set('limit', String(limit));
    if (Array.isArray(types) && types.length > 0) {
      params.set('types', types.join(','));
    } else if (typeof types === 'string' && types.trim()) {
      params.set('types', types.trim());
    }
    return this.apiFetch(`/api/v1/search?${params.toString()}`);
  }

  // ---- Shell ----

  execShell(command, opts = {}) {
    return this.apiFetch('/api/v1/shell/exec', {
      method: 'POST',
      body: { command, ...opts },
    });
  }
}

export function createOmniClient(options) {
  return new OmniClient(options);
}
