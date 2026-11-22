/**
 * Zero-Dependency Node 24 Chrome DevTools Protocol (CDP) Client for Headless Chromium.
 *
 * Verified against /usr/lib/chromium/chromium 156.0.8078.79:
 * - Always launches /usr/lib/chromium/chromium directly (never /usr/bin/chromium wrapper).
 * - Connects directly to the browser WS endpoint emitted on stderr and multiplexes
 *   page sessions via Target.createTarget + Target.attachToTarget({ flatten: true }),
 *   avoiding Chromium 156's HTTP 405 on GET /json/new.
 * - Cleanly closes Chromium via Browser.close with SIGTERM/SIGKILL fallback and removes
 *   the isolated temporary userDataDir with EBUSY retry.
 */

import { spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { accessSync as _probeAccessSync, constants as _probeFsConstants } from 'node:fs';

function resolveDefaultChromiumPath() {
  const candidates = [
    process.env.OMNIOS_CHROMIUM_PATH,
    '/usr/lib/chromium/chromium',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      _probeAccessSync(candidate, _probeFsConstants.X_OK);
      return candidate;
    } catch {
      // try next candidate
    }
  }
  return '/usr/lib/chromium/chromium';
}

export const DEFAULT_CHROMIUM_PATH = resolveDefaultChromiumPath();

export const CDP_MODIFIERS = Object.freeze({
  Alt: 1,
  Ctrl: 2,
  Control: 2,
  Meta: 4,
  Command: 4,
  Shift: 8,
});

const KEY_MAP = Object.freeze({
  Enter: { key: 'Enter', code: 'Enter', keyCode: 13, text: '\r' },
  Escape: { key: 'Escape', code: 'Escape', keyCode: 27 },
  Esc: { key: 'Escape', code: 'Escape', keyCode: 27 },
  Tab: { key: 'Tab', code: 'Tab', keyCode: 9 },
  Backspace: { key: 'Backspace', code: 'Backspace', keyCode: 8 },
  Delete: { key: 'Delete', code: 'Delete', keyCode: 46 },
  Space: { key: ' ', code: 'Space', keyCode: 32, text: ' ' },
  ' ': { key: ' ', code: 'Space', keyCode: 32, text: ' ' },
  ArrowUp: { key: 'ArrowUp', code: 'ArrowUp', keyCode: 38 },
  ArrowDown: { key: 'ArrowDown', code: 'ArrowDown', keyCode: 40 },
  ArrowLeft: { key: 'ArrowLeft', code: 'ArrowLeft', keyCode: 37 },
  ArrowRight: { key: 'ArrowRight', code: 'ArrowRight', keyCode: 39 },
  Home: { key: 'Home', code: 'Home', keyCode: 36 },
  End: { key: 'End', code: 'End', keyCode: 35 },
  PageUp: { key: 'PageUp', code: 'PageUp', keyCode: 33 },
  PageDown: { key: 'PageDown', code: 'PageDown', keyCode: 34 },
});

const PUNCTUATION_CODES = Object.freeze({
  '-': { code: 'Minus', keyCode: 189 },
  '=': { code: 'Equal', keyCode: 187 },
  '[': { code: 'BracketLeft', keyCode: 219 },
  ']': { code: 'BracketRight', keyCode: 221 },
  '\\': { code: 'Backslash', keyCode: 220 },
  ';': { code: 'Semicolon', keyCode: 186 },
  "'": { code: 'Quote', keyCode: 222 },
  ',': { code: 'Comma', keyCode: 188 },
  '.': { code: 'Period', keyCode: 190 },
  '/': { code: 'Slash', keyCode: 191 },
  '`': { code: 'Backquote', keyCode: 192 },
});

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function raceWithTimeout(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((resolve) => {
      timer = setTimeout(resolve, ms);
      timer.unref?.();
    }),
  ]).finally(() => clearTimeout(timer));
}

async function removeDirWithRetry(dirPath) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await fs.rm(dirPath, { recursive: true, force: true });
      return;
    } catch (err) {
      if (attempt === 0 && (err?.code === 'EBUSY' || err?.code === 'ENOTEMPTY' || err?.code === 'EPERM')) {
        await sleep(100);
        continue;
      }
      throw err;
    }
  }
}

function normalizeModifiers(modifiers) {
  if (!modifiers) return 0;
  if (typeof modifiers === 'number') return modifiers & 0x0f;
  if (typeof modifiers === 'string') {
    return modifiers
      .split(/[+,|\s]+/)
      .filter(Boolean)
      .reduce((mask, part) => mask | (CDP_MODIFIERS[part] || CDP_MODIFIERS[part[0].toUpperCase() + part.slice(1).toLowerCase()] || 0), 0);
  }
  if (Array.isArray(modifiers)) {
    return modifiers.reduce((mask, item) => mask | normalizeModifiers(item), 0);
  }
  if (typeof modifiers === 'object') {
    let mask = 0;
    if (modifiers.alt || modifiers.Alt) mask |= 1;
    if (modifiers.ctrl || modifiers.control || modifiers.Ctrl || modifiers.Control) mask |= 2;
    if (modifiers.meta || modifiers.command || modifiers.Meta || modifiers.Command) mask |= 4;
    if (modifiers.shift || modifiers.Shift) mask |= 8;
    return mask;
  }
  return 0;
}

function resolveKeyDescriptor(key) {
  if (Object.prototype.hasOwnProperty.call(KEY_MAP, key)) {
    return KEY_MAP[key];
  }
  if (typeof key === 'string' && key.length === 1) {
    const ch = key;
    if (/^[a-zA-Z]$/.test(ch)) {
      const upper = ch.toUpperCase();
      return { key: ch, code: `Key${upper}`, keyCode: upper.charCodeAt(0), text: ch };
    }
    if (/^[0-9]$/.test(ch)) {
      return { key: ch, code: `Digit${ch}`, keyCode: ch.charCodeAt(0), text: ch };
    }
    const punct = PUNCTUATION_CODES[ch];
    if (punct) {
      return { key: ch, code: punct.code, keyCode: punct.keyCode, text: ch };
    }
    return { key: ch, code: '', keyCode: ch.charCodeAt(0), text: ch };
  }
  return { key: String(key), code: String(key), keyCode: 0 };
}

function formatRemoteObject(arg) {
  if (!arg) return '';
  if (Object.prototype.hasOwnProperty.call(arg, 'value')) {
    return typeof arg.value === 'string' ? arg.value : JSON.stringify(arg.value);
  }
  if (arg.description) return arg.description;
  if (arg.unserializableValue) return String(arg.unserializableValue);
  return `[${arg.type || 'unknown'}]`;
}

function formatExceptionDetails(details) {
  const ex = details?.exception;
  const desc = ex?.description || ex?.value || details?.text || 'Uncaught exception';
  const loc = details?.url ? ` at ${details.url}:${(details.lineNumber ?? 0) + 1}:${(details.columnNumber ?? 0) + 1}` : '';
  return `${desc}${loc}`;
}

async function waitProcessExit(proc, timeoutMs) {
  if (!proc || proc.exitCode !== null || proc.signalCode !== null) return true;
  return await new Promise((resolve) => {
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    const timer = setTimeout(() => {
      proc.removeListener('exit', onExit);
      resolve(false);
    }, timeoutMs);
    timer.unref?.();
    proc.once('exit', onExit);
  });
}

/**
 * Launches headless Chromium and returns a zero-dep multiplexed CDP browser handle.
 */
export async function launchBrowser({
  executablePath = DEFAULT_CHROMIUM_PATH,
  launchTimeoutMs = 15000,
  defaultViewport = { width: 1280, height: 800 },
  extraArgs = [],
} = {}) {
  try {
    await fs.access(executablePath, fsConstants.X_OK);
  } catch (cause) {
    const err = new Error(
      `Chromium executable not accessible/executable at "${executablePath}". ` +
      `Set OMNIOS_CHROMIUM_PATH or verify /usr/lib/chromium/chromium.`
    );
    err.code = 'E_CHROMIUM_MISSING';
    err.cause = cause;
    throw err;
  }

  const userDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'omnios-cdp-'));
  const args = [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--disable-extensions',
    '--disable-background-networking',
    '--no-first-run',
    '--no-default-browser-check',
    '--mute-audio',
    '--remote-debugging-port=0',
    `--user-data-dir=${userDataDir}`,
    ...extraArgs,
    'about:blank',
  ];

  const proc = spawn(executablePath, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderrBuf = '';

  let browserWsUrl;
  try {
    browserWsUrl = await new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error(`Timed out after ${launchTimeoutMs}ms waiting for Chromium DevTools endpoint.\nSTDERR:\n${stderrBuf}`));
      }, launchTimeoutMs);

      const onData = (chunk) => {
        stderrBuf += chunk.toString('utf8');
        const match = /DevTools listening on (ws:\/\/[^\s]+)/.exec(stderrBuf);
        if (match && !settled) {
          settled = true;
          clearTimeout(timer);
          proc.stderr.removeListener('data', onData);
          proc.removeListener('exit', onExit);
          proc.removeListener('error', onError);
          resolve(match[1]);
        }
      };

      const onError = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(new Error(`Failed to spawn Chromium (${executablePath}): ${err.message}`));
      };

      const onExit = (code, signal) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(new Error(`Chromium exited prematurely (code=${code}, signal=${signal}).\nSTDERR:\n${stderrBuf}`));
      };

      proc.stderr.on('data', onData);
      proc.once('error', onError);
      proc.once('exit', onExit);
    });
  } catch (err) {
    try { proc.kill('SIGKILL'); } catch { /* ignore */ }
    await waitProcessExit(proc, 1500);
    await removeDirWithRetry(userDataDir);
    throw err;
  }

  // Drain remaining stdout/stderr to avoid backpressure hangs.
  proc.stdout?.resume();
  proc.stderr?.resume();

  const parsedUrl = new URL(browserWsUrl);
  const httpOrigin = `http://${parsedUrl.host}`;

  const ws = new WebSocket(browserWsUrl);
  let nextId = 1;
  const pending = new Map();
  const eventListeners = new Set();
  const wsCloseListeners = new Set();

  let wsClosed = false;
  let resolveWsClose;
  const wsClosePromise = new Promise((resolve) => {
    resolveWsClose = resolve;
  });

  ws.addEventListener('message', (ev) => {
    const raw = typeof ev.data === 'string'
      ? ev.data
      : Buffer.from(ev.data).toString('utf8');

    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (typeof msg.id === 'number') {
      const entry = pending.get(msg.id);
      if (entry) {
        pending.delete(msg.id);
        clearTimeout(entry.timer);
        if (msg.error) {
          const err = new Error(`CDP ${entry.method} failed (${msg.error.code}): ${msg.error.message}`);
          err.cdpCode = msg.error.code;
          err.cdpMethod = entry.method;
          entry.reject(err);
        } else {
          entry.resolve(msg.result ?? {});
        }
      }
      return;
    }

    if (msg.method) {
      for (const listener of Array.from(eventListeners)) {
        try {
          listener(msg.method, msg.params ?? {}, msg.sessionId ?? null);
        } catch {
          // keep event loop resilient
        }
      }
    }
  });

  ws.addEventListener('close', () => {
    wsClosed = true;
    resolveWsClose();
    for (const fn of Array.from(wsCloseListeners)) {
      try { fn(); } catch { /* ignore */ }
    }
    wsCloseListeners.clear();
    for (const [id, entry] of pending.entries()) {
      clearTimeout(entry.timer);
      entry.reject(new Error(`CDP WebSocket closed while awaiting ${entry.method} (id=${id})`));
    }
    pending.clear();
  });

  try {
    await new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error(`Timed out connecting to Chromium CDP socket ${browserWsUrl}`));
      }, launchTimeoutMs);

      const onOpen = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        ws.removeEventListener('error', onError);
        resolve();
      };
      const onError = (ev) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        ws.removeEventListener('open', onOpen);
        reject(new Error(`CDP WebSocket error: ${ev?.message || 'connection failed'}`));
      };

      ws.addEventListener('open', onOpen, { once: true });
      ws.addEventListener('error', onError, { once: true });
    });
  } catch (err) {
    try { proc.kill('SIGKILL'); } catch { /* ignore */ }
    await waitProcessExit(proc, 1500);
    await removeDirWithRetry(userDataDir);
    throw err;
  }

  function send(method, params = {}, { sessionId = null, timeoutMs = 15000 } = {}) {
    if (wsClosed || ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error(`Cannot send CDP command "${method}": socket not open`));
    }
    const id = nextId++;
    const payload = sessionId
      ? { id, method, params, sessionId }
      : { id, method, params };

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`CDP command "${method}" timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      pending.set(id, { method, sessionId, resolve, reject, timer });
      try {
        ws.send(JSON.stringify(payload));
      } catch (err) {
        clearTimeout(timer);
        pending.delete(id);
        reject(err);
      }
    });
  }

  function onEvent(fn) {
    eventListeners.add(fn);
    return () => eventListeners.delete(fn);
  }

  const openPages = new Set();

  async function newPage({ viewport = defaultViewport } = {}) {
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });

    let pageClosed = false;
    let closePagePromise = null;
    const pageCloseListeners = new Set();

    function onTransportAbort(fn) {
      if (pageClosed) {
        fn('page closed');
        return () => {};
      }
      if (wsClosed) {
        fn('CDP WebSocket closed');
        return () => {};
      }
      const wsHandler = () => fn('CDP WebSocket closed');
      const pageHandler = () => fn('page closed');
      wsCloseListeners.add(wsHandler);
      pageCloseListeners.add(pageHandler);
      return () => {
        wsCloseListeners.delete(wsHandler);
        pageCloseListeners.delete(pageHandler);
      };
    }

    function sleepOrAbort(ms) {
      if (ms <= 0) return Promise.resolve();
      if (pageClosed || wsClosed || ws.readyState !== WebSocket.OPEN) {
        return Promise.reject(new Error(`CDP wait aborted: ${pageClosed ? 'page closed' : 'CDP WebSocket closed'}`));
      }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          unsub();
          resolve();
        }, ms);
        const unsub = onTransportAbort((reason) => {
          clearTimeout(timer);
          reject(new Error(`CDP wait aborted: ${reason}`));
        });
      });
    }

    const pageSend = (method, params = {}, opts = {}) => {
      if (pageClosed) {
        return Promise.reject(new Error(`Cannot send CDP command "${method}": page is closed`));
      }
      return send(method, params, { ...opts, sessionId });
    };

    const consoleMessages = [];
    const consoleErrors = [];
    const pageErrors = [];

    const unsubscribe = onEvent((method, params, sid) => {
      if (sid !== sessionId) return;

      if (method === 'Runtime.consoleAPICalled') {
        const text = (params.args || []).map(formatRemoteObject).join(' ');
        const entry = {
          type: params.type || 'log',
          text,
          timestamp: params.timestamp,
        };
        consoleMessages.push(entry);
        if (params.type === 'error') {
          consoleErrors.push(entry);
        }
      } else if (method === 'Log.entryAdded') {
        const logEntry = params.entry || {};
        if (logEntry.level === 'error') {
          consoleErrors.push({
            type: 'log:error',
            source: logEntry.source || 'browser',
            text: logEntry.text || '',
            url: logEntry.url || '',
            timestamp: logEntry.timestamp,
          });
        }
      } else if (method === 'Runtime.exceptionThrown') {
        const details = params.exceptionDetails || {};
        pageErrors.push({
          text: details.text || 'Uncaught',
          description: formatExceptionDetails(details),
          url: details.url || '',
          lineNumber: details.lineNumber ?? null,
          columnNumber: details.columnNumber ?? null,
          timestamp: params.timestamp,
        });
      }
    });

    await pageSend('Page.enable');
    await pageSend('Runtime.enable');
    await pageSend('Log.enable');
    await pageSend('DOM.enable');

    async function setViewport(width, height, { deviceScaleFactor = 1, mobile = false } = {}) {
      await pageSend('Emulation.setDeviceMetricsOverride', {
        width,
        height,
        deviceScaleFactor,
        mobile,
      });
    }

    if (viewport && viewport.width && viewport.height) {
      await setViewport(viewport.width, viewport.height, viewport);
    }

    async function evaluate(expr, { awaitPromise = true, returnByValue = true, userGesture = true } = {}) {
      const res = await pageSend('Runtime.evaluate', {
        expression: expr,
        awaitPromise,
        returnByValue,
        userGesture,
      });
      if (res.exceptionDetails) {
        const err = new Error(`Page eval exception: ${formatExceptionDetails(res.exceptionDetails)}`);
        err.exceptionDetails = res.exceptionDetails;
        throw err;
      }
      return res.result?.value;
    }

    async function evalFn(fn, ...fnArgs) {
      const serializedArgs = fnArgs
        .map((a) => (a === undefined ? 'undefined' : JSON.stringify(a)))
        .join(',');
      return await evaluate(`(${fn.toString()})(${serializedArgs})`);
    }

    async function goto(url, { timeoutMs = 15000, waitUntil = 'load' } = {}) {
      if (pageClosed || wsClosed || ws.readyState !== WebSocket.OPEN) {
        throw new Error(`Navigation to "${url}" aborted: ${pageClosed ? 'page closed' : 'CDP WebSocket closed'}`);
      }

      const eventName = waitUntil === 'domcontentloaded'
        ? 'Page.domContentEventFired'
        : 'Page.loadEventFired';

      let resolveLoad;
      let rejectLoad;
      let loadDone = false;

      const loadPromise = new Promise((resolve, reject) => {
        resolveLoad = resolve;
        rejectLoad = reject;
      });
      loadPromise.catch(() => {});

      let unsubLoad = () => {};
      let unsubAbort = () => {};
      let timer = null;

      const cleanupLoad = () => {
        loadDone = true;
        if (timer !== null) {
          clearTimeout(timer);
          timer = null;
        }
        unsubLoad();
        unsubAbort();
      };

      timer = setTimeout(() => {
        if (loadDone) return;
        cleanupLoad();
        rejectLoad(new Error(`Timed out after ${timeoutMs}ms waiting for ${eventName} on ${url}`));
      }, timeoutMs);

      unsubLoad = onEvent((method, _params, sid) => {
        if (sid === sessionId && method === eventName && !loadDone) {
          cleanupLoad();
          resolveLoad();
        }
      });

      unsubAbort = onTransportAbort((reason) => {
        if (loadDone) return;
        cleanupLoad();
        rejectLoad(new Error(`Navigation to "${url}" aborted: ${reason}`));
      });

      try {
        const navRes = await pageSend('Page.navigate', { url }, { timeoutMs });
        if (navRes.errorText) {
          cleanupLoad();
          throw new Error(`Navigation to "${url}" failed: ${navRes.errorText}`);
        }
        await loadPromise;
        return navRes;
      } catch (err) {
        cleanupLoad();
        throw err;
      }
    }

    async function waitForSelector(sel, timeoutOrOpts = 10000, maybeOpts = {}) {
      const opts =
        timeoutOrOpts !== null && typeof timeoutOrOpts === 'object'
          ? timeoutOrOpts
          : (maybeOpts || {});
      const timeoutMs =
        typeof timeoutOrOpts === 'number'
          ? timeoutOrOpts
          : (opts.timeoutMs ?? 10000);
      const visible = Boolean(opts.visible);
      const pollMs = opts.pollMs ?? 50;
      const deadline = Date.now() + timeoutMs;

      while (Date.now() < deadline) {
        if (pageClosed || wsClosed || ws.readyState !== WebSocket.OPEN) {
          throw new Error(`waitForSelector("${sel}") aborted: ${pageClosed ? 'page closed' : 'CDP WebSocket closed'}`);
        }
        const found = await evalFn((selector, requireVisible) => {
          const el = document.querySelector(selector);
          if (!el) return false;
          if (!requireVisible) return true;
          const style = window.getComputedStyle(el);
          if (style.display === 'none' || style.visibility === 'hidden' || !(parseFloat(style.opacity) > 0)) {
            return false;
          }
          let parent = el.parentElement;
          while (parent && parent.nodeType === 1) {
            const ps = window.getComputedStyle(parent);
            if (ps.display === 'none' || !(parseFloat(ps.opacity) > 0)) {
              return false;
            }
            parent = parent.parentElement;
          }
          const rect = el.getBoundingClientRect();
          return rect.width > 0 && rect.height > 0;
        }, sel, visible);

        if (found) return true;
        const waitMs = Math.min(pollMs, Math.max(0, deadline - Date.now()));
        if (waitMs > 0) await sleepOrAbort(waitMs);
      }

      throw new Error(`Timed out after ${timeoutMs}ms waiting for selector "${sel}"${visible ? ' (visible)' : ''}`);
    }

    async function waitForFunction(fnOrExpr, { timeoutMs = 10000, pollMs = 50, args: fnArgs = [] } = {}) {
      const deadline = Date.now() + timeoutMs;
      let lastErr = null;

      while (Date.now() < deadline) {
        if (pageClosed || wsClosed || ws.readyState !== WebSocket.OPEN) {
          throw new Error(`waitForFunction aborted: ${pageClosed ? 'page closed' : 'CDP WebSocket closed'}`);
        }
        try {
          const val = typeof fnOrExpr === 'function'
            ? await evalFn(fnOrExpr, ...fnArgs)
            : await evaluate(String(fnOrExpr));
          if (val) return val;
        } catch (err) {
          if (pageClosed || wsClosed || ws.readyState !== WebSocket.OPEN) {
            throw err;
          }
          lastErr = err;
        }
        const waitMs = Math.min(pollMs, Math.max(0, deadline - Date.now()));
        if (waitMs > 0) await sleepOrAbort(waitMs);
      }

      throw new Error(
        `Timed out after ${timeoutMs}ms waiting for function condition` +
        (lastErr ? ` (last error: ${lastErr.message})` : '')
      );
    }

    async function getElementCenter(sel, timeoutMs = 10000) {
      await waitForSelector(sel, timeoutMs, { visible: true });
      const info = await evalFn((selector) => {
        const el = document.querySelector(selector);
        if (!el) return { missing: true };
        el.scrollIntoView({ block: 'center', inline: 'center' });
        const style = window.getComputedStyle(el);
        let hiddenReason = null;
        if (style.display === 'none') {
          hiddenReason = 'display: none';
        } else if (style.visibility === 'hidden') {
          hiddenReason = 'visibility: hidden';
        } else if (!(parseFloat(style.opacity) > 0)) {
          hiddenReason = `opacity: ${style.opacity}`;
        } else {
          let parent = el.parentElement;
          while (parent && parent.nodeType === 1) {
            const ps = window.getComputedStyle(parent);
            if (ps.display === 'none') {
              hiddenReason = 'ancestor display: none';
              break;
            }
            if (!(parseFloat(ps.opacity) > 0)) {
              hiddenReason = `ancestor opacity: ${ps.opacity}`;
              break;
            }
            parent = parent.parentElement;
          }
        }
        const r = el.getBoundingClientRect();
        return {
          missing: false,
          hiddenReason,
          left: r.left,
          top: r.top,
          width: r.width,
          height: r.height,
        };
      }, sel);

      if (!info || info.missing) {
        throw new Error(`Element "${sel}" disappeared before interaction`);
      }
      if (info.hiddenReason) {
        throw new Error(`Element "${sel}" is not visible (${info.hiddenReason}) and cannot be clicked/dragged`);
      }
      if (info.width <= 0 || info.height <= 0) {
        throw new Error(`Element "${sel}" has zero dimensions (${info.width}x${info.height}) and cannot be clicked/dragged`);
      }
      return {
        x: info.left + info.width / 2,
        y: info.top + info.height / 2,
      };
    }

    async function clickAt(x, y, { button = 'left', clickCount = 1 } = {}) {
      const buttons = button === 'right' ? 2 : button === 'middle' ? 4 : 1;
      await pageSend('Input.dispatchMouseEvent', {
        type: 'mouseMoved',
        x,
        y,
        button: 'none',
        buttons: 0,
      });
      await pageSend('Input.dispatchMouseEvent', {
        type: 'mousePressed',
        x,
        y,
        button,
        buttons,
        clickCount,
      });
      await pageSend('Input.dispatchMouseEvent', {
        type: 'mouseReleased',
        x,
        y,
        button,
        buttons: 0,
        clickCount,
      });
    }

    async function click(sel, { button = 'left', clickCount = 1, timeoutMs = 10000 } = {}) {
      const pos = await getElementCenter(sel, timeoutMs);
      await clickAt(pos.x, pos.y, { button, clickCount });
    }

    async function type(sel, text, { clear = false, timeoutMs = 10000 } = {}) {
      const str = text == null ? '' : String(text);
      await waitForSelector(sel, timeoutMs, { visible: true });
      const focusRes = await evalFn((selector, shouldClear) => {
        const el = document.querySelector(selector);
        if (!el) return { ok: false, error: `Element not found: ${selector}` };
        el.scrollIntoView({ block: 'center', inline: 'center' });
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden' || !(parseFloat(style.opacity) > 0)) {
          return { ok: false, error: `Element "${selector}" is not visible and cannot be typed into` };
        }
        let parent = el.parentElement;
        while (parent && parent.nodeType === 1) {
          const ps = window.getComputedStyle(parent);
          if (ps.display === 'none' || !(parseFloat(ps.opacity) > 0)) {
            return { ok: false, error: `Element "${selector}" has a hidden ancestor and cannot be typed into` };
          }
          parent = parent.parentElement;
        }
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) {
          return { ok: false, error: `Element "${selector}" has zero dimensions (${rect.width}x${rect.height}) and cannot be typed into` };
        }
        el.focus();
        const active = document.activeElement;
        if (active !== el && !(active && el.contains(active))) {
          return { ok: false, error: `Failed to focus element "${selector}" (disabled, non-focusable, or hidden)` };
        }
        if (shouldClear && 'value' in el) {
          el.value = '';
          el.dispatchEvent(new Event('input', { bubbles: true }));
        } else if (!shouldClear && typeof el.value === 'string' && typeof el.setSelectionRange === 'function') {
          try {
            const end = el.value.length;
            el.setSelectionRange(end, end);
          } catch {
            // input types such as number/email may not support setSelectionRange
          }
        }
        return { ok: true };
      }, sel, clear);

      if (!focusRes || !focusRes.ok) {
        throw new Error(focusRes?.error || `Failed to prepare element "${sel}" for typing`);
      }

      if (str.length > 0) {
        await pageSend('Input.insertText', { text: str });
      }
    }

    async function pressKey(key, modifiers = 0) {
      const modMask = normalizeModifiers(modifiers);
      const desc = resolveKeyDescriptor(key);
      const hasCommandMod = (modMask & (1 | 2 | 4)) !== 0;

      if (!hasCommandMod && desc.text) {
        await pageSend('Input.dispatchKeyEvent', {
          type: 'keyDown',
          key: desc.key,
          code: desc.code,
          windowsVirtualKeyCode: desc.keyCode,
          nativeVirtualKeyCode: desc.keyCode,
          text: desc.text,
          unmodifiedText: desc.text,
          modifiers: modMask,
        });
      } else {
        await pageSend('Input.dispatchKeyEvent', {
          type: 'rawKeyDown',
          key: desc.key,
          code: desc.code,
          windowsVirtualKeyCode: desc.keyCode,
          nativeVirtualKeyCode: desc.keyCode,
          modifiers: modMask,
        });
      }

      await pageSend('Input.dispatchKeyEvent', {
        type: 'keyUp',
        key: desc.key,
        code: desc.code,
        windowsVirtualKeyCode: desc.keyCode,
        nativeVirtualKeyCode: desc.keyCode,
        modifiers: modMask,
      });
    }

    async function drag(fromSelOrPos, toPosOrSel, { steps = 10, timeoutMs = 10000 } = {}) {
      const start = typeof fromSelOrPos === 'string'
        ? await getElementCenter(fromSelOrPos, timeoutMs)
        : { x: Number(fromSelOrPos.x), y: Number(fromSelOrPos.y) };

      const end = typeof toPosOrSel === 'string'
        ? await getElementCenter(toPosOrSel, timeoutMs)
        : { x: Number(toPosOrSel.x), y: Number(toPosOrSel.y) };

      const numSteps = Math.max(1, Number(steps) || 10);

      await pageSend('Input.dispatchMouseEvent', {
        type: 'mouseMoved',
        x: start.x,
        y: start.y,
        button: 'none',
        buttons: 0,
      });
      await pageSend('Input.dispatchMouseEvent', {
        type: 'mousePressed',
        x: start.x,
        y: start.y,
        button: 'left',
        buttons: 1,
        clickCount: 1,
      });

      for (let i = 1; i <= numSteps; i++) {
        const t = i / numSteps;
        await pageSend('Input.dispatchMouseEvent', {
          type: 'mouseMoved',
          x: start.x + (end.x - start.x) * t,
          y: start.y + (end.y - start.y) * t,
          button: 'left',
          buttons: 1,
        });
      }

      await pageSend('Input.dispatchMouseEvent', {
        type: 'mouseReleased',
        x: end.x,
        y: end.y,
        button: 'left',
        buttons: 0,
        clickCount: 1,
      });
    }

    async function setFileInputFiles(sel, filePaths, { timeoutMs = 10000 } = {}) {
      await waitForSelector(sel, timeoutMs);
      const resolvedFiles = (Array.isArray(filePaths) ? filePaths : [filePaths]).map((p) => path.resolve(p));
      const { root } = await pageSend('DOM.getDocument', { depth: -1, pierce: true });
      const { nodeId } = await pageSend('DOM.querySelector', {
        nodeId: root.nodeId,
        selector: sel,
      });
      if (!nodeId) {
        throw new Error(`DOM.querySelector could not resolve file input "${sel}"`);
      }
      await pageSend('DOM.setFileInputFiles', {
        nodeId,
        files: resolvedFiles,
      });
    }

    function closePage() {
      if (!closePagePromise) {
        pageClosed = true;
        for (const fn of Array.from(pageCloseListeners)) {
          try { fn(); } catch { /* ignore */ }
        }
        pageCloseListeners.clear();
        for (const [id, entry] of Array.from(pending.entries())) {
          if (entry.sessionId === sessionId) {
            pending.delete(id);
            clearTimeout(entry.timer);
            entry.reject(new Error(`CDP page closed while awaiting ${entry.method} (id=${id})`));
          }
        }
        closePagePromise = (async () => {
          unsubscribe();
          openPages.delete(page);
          if (!wsClosed && ws.readyState === WebSocket.OPEN) {
            try {
              await send('Target.closeTarget', { targetId }, { timeoutMs: 3000 });
            } catch {
              // ignore if browser is already closing
            }
          }
        })();
      }
      return closePagePromise;
    }

    const page = {
      targetId,
      sessionId,
      send: pageSend,
      goto,
      eval: evaluate,
      evalFn,
      waitForSelector,
      waitForFunction,
      click,
      clickAt,
      type,
      pressKey,
      drag,
      setViewport,
      setFileInputFiles,
      getConsoleErrors() {
        return consoleErrors.slice();
      },
      getConsoleMessages() {
        return consoleMessages.slice();
      },
      getPageErrors() {
        return pageErrors.slice();
      },
      clearErrors() {
        consoleErrors.length = 0;
        pageErrors.length = 0;
      },
      close: closePage,
    };

    openPages.add(page);
    return page;
  }

  let browserClosePromise = null;
  function close() {
    if (!browserClosePromise) {
      browserClosePromise = (async () => {
        for (const p of Array.from(openPages)) {
          await p.close().catch(() => {});
        }
        openPages.clear();

        if (!wsClosed && ws.readyState === WebSocket.OPEN) {
          try {
            await send('Browser.close', {}, { timeoutMs: 2000 });
          } catch {
            // fallback to signal termination below
          }
          try { ws.close(1000, 'browser-close'); } catch { /* ignore */ }
          await raceWithTimeout(wsClosePromise, 1000);
        }

        let exited = await waitProcessExit(proc, 2000);
        if (!exited) {
          try { proc.kill('SIGTERM'); } catch { /* ignore */ }
          exited = await waitProcessExit(proc, 1500);
        }
        if (!exited) {
          try { proc.kill('SIGKILL'); } catch { /* ignore */ }
          await waitProcessExit(proc, 1500);
        }

        await removeDirWithRetry(userDataDir);
      })();
    }
    return browserClosePromise;
  }

  async function getTargets() {
    const res = await fetch(`${httpOrigin}/json/list`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error(`GET ${httpOrigin}/json/list failed with HTTP ${res.status}`);
    return await res.json();
  }

  return {
    wsUrl: browserWsUrl,
    httpOrigin,
    userDataDir,
    pid: proc.pid,
    send,
    on: onEvent,
    getTargets,
    newPage,
    close,
  };
}
