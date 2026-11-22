/**
 * OmniOS Milestone M6 Real Headless Chromium CDP GUI Test Suite (`F-073` – `F-084`)
 * - Zero external dependencies (Node.js 24 built-ins only: node:test, node:assert/strict,
 *   node:child_process, node:fs/promises, node:os, node:path, native global WebSocket & fetch).
 * - Zero mocks: boots genuine OmniOS microkernel + 6 daemons + 5 CPU architectures +
 *   5 platform runtimes + live HTTP/WS server on ephemeral port 0 + real Headless Chromium 156
 *   via `/usr/lib/chromium/chromium` controlled over Chrome DevTools Protocol (CDP).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fsp from 'node:fs/promises';
import osMod from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createOmniOS } from '../../os/os.mjs';
import { createHttpServer } from '../../os/server/http-server.mjs';
import { accessSync as _probeAccessSync, constants as _probeFsConstants } from 'node:fs';

function resolveChromiumBin() {
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
      // try next executable candidate
    }
  }
  return '/usr/lib/chromium/chromium';
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PACKAGES_DIR = path.join(REPO_ROOT, 'packages');
const CHROMIUM_BIN = resolveChromiumBin();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(fn, { timeoutMs = 10_000, intervalMs = 60, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastVal;
  let lastErr = null;
  while (Date.now() < deadline) {
    try {
      lastVal = await fn();
      if (lastVal) return lastVal;
      lastErr = null;
    } catch (err) {
      lastErr = err;
    }
    await sleep(intervalMs);
  }
  const detail = lastErr ? ` (last error: ${lastErr.message})` : ` (last value: ${JSON.stringify(lastVal)})`;
  throw new Error(`Timed out after ${timeoutMs}ms waiting for ${label}${detail}`);
}

/**
 * Pure Node 24 zero-dependency Headless Chromium CDP Driver.
 * Always invokes `/usr/lib/chromium/chromium` directly and filters `/json/list`
 * strictly for `t.type === 'page' && t.webSocketDebuggerUrl` (Chromium 156 quirk).
 */
async function launchChromiumCdp({ width = 1440, height = 900, startupTimeoutMs = 15_000 } = {}) {
  const userDataDir = await fsp.mkdtemp(path.join(osMod.tmpdir(), 'omnios-m6-cdp-'));
  const proc = spawn(
    CHROMIUM_BIN,
    [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-extensions',
      '--disable-background-networking',
      '--no-first-run',
      '--no-default-browser-check',
      `--window-size=${width},${height}`,
      `--user-data-dir=${userDataDir}`,
      '--remote-debugging-port=0',
      'about:blank',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );

  let stderrBuf = '';
  let browserWsUrl;
  try {
    browserWsUrl = await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`Chromium CDP startup timeout. stderr:\n${stderrBuf}`)),
        startupTimeoutMs
      );
      const onData = (chunk) => {
        stderrBuf += chunk.toString('utf8');
        const m = /DevTools listening on (ws:\/\/[^\s]+)/.exec(stderrBuf);
        if (m) {
          clearTimeout(timer);
          proc.stderr.off('data', onData);
          resolve(m[1]);
        }
      };
      proc.stderr.on('data', onData);
      proc.once('exit', (code, sig) => {
        clearTimeout(timer);
        reject(new Error(`Chromium exited early (code=${code}, sig=${sig}). stderr:\n${stderrBuf}`));
      });
    });
  } catch (err) {
    try {
      proc.kill('SIGKILL');
    } catch {
      // ignore
    }
    await fsp.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
    throw err;
  }

  const debugOrigin = `http://${new URL(browserWsUrl).host}`;
  let pageTarget = null;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const res = await fetch(`${debugOrigin}/json/list`);
    const targets = await res.json();
    pageTarget = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
    if (pageTarget) break;
    await sleep(100);
  }
  if (!pageTarget) {
    try {
      proc.kill('SIGKILL');
    } catch {
      // ignore
    }
    await fsp.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
    throw new Error('No CDP page target found in /json/list');
  }

  const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener(
      'error',
      (e) => reject(new Error(`CDP WebSocket error: ${e.message ?? 'connection failed'}`)),
      { once: true }
    );
  });

  let nextId = 0;
  const pending = new Map();
  const listeners = new Map();
  const consoleErrors = [];
  const pageErrors = [];
  const networkRequests = [];
  const failedResponses = [];

  ws.addEventListener('message', (ev) => {
    const raw = typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString('utf8');
    const msg = JSON.parse(raw);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(`CDP ${msg.error.code}: ${msg.error.message}`));
      else resolve(msg.result);
      return;
    }
    if (msg.method) {
      if (msg.method === 'Runtime.exceptionThrown') {
        const d = msg.params?.exceptionDetails;
        pageErrors.push(d?.exception?.description ?? d?.text ?? JSON.stringify(msg.params));
      } else if (msg.method === 'Runtime.consoleAPICalled' && msg.params?.type === 'error') {
        consoleErrors.push(
          (msg.params.args ?? []).map((a) => a.value ?? a.description ?? '').join(' ')
        );
      } else if (msg.method === 'Network.requestWillBeSent') {
        const req = msg.params?.request;
        if (req?.url) {
          networkRequests.push({
            url: req.url,
            method: req.method ?? 'GET',
            resourceType: msg.params?.type ?? '',
          });
        }
      } else if (msg.method === 'Network.responseReceived') {
        const resp = msg.params?.response;
        if (resp && resp.status >= 400) {
          failedResponses.push({
            url: resp.url,
            status: resp.status,
            statusText: resp.statusText ?? '',
          });
        }
      }

      const set = listeners.get(msg.method);
      if (set) {
        for (const fn of [...set]) fn(msg.params);
      }
    }
  });

  function send(method, params = {}, timeoutMs = 15_000) {
    const id = ++nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`CDP command timed out: ${method}`));
      }, timeoutMs);
      pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      ws.send(JSON.stringify({ id, method, params }));
    });
  }

  async function evaluate(expression, { awaitPromise = true } = {}) {
    const res = await send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise,
    });
    if (res.exceptionDetails) {
      throw new Error(
        `Page exception: ${res.exceptionDetails.exception?.description ?? res.exceptionDetails.text}`
      );
    }
    return res.result?.value;
  }

  async function navigate(url) {
    let loadedResolve;
    const loaded = new Promise((resolve) => {
      loadedResolve = resolve;
    });
    const set = listeners.get('Page.loadEventFired') ?? new Set();
    listeners.set('Page.loadEventFired', set);
    const handler = () => {
      set.delete(handler);
      loadedResolve();
    };
    set.add(handler);
    await send('Page.navigate', { url });
    await Promise.race([loaded, sleep(10_000)]);
  }

  async function mouseClick(x, y) {
    await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y, button: 'none', buttons: 0 });
    await send('Input.dispatchMouseEvent', {
      type: 'mousePressed',
      x,
      y,
      button: 'left',
      buttons: 1,
      clickCount: 1,
    });
    await send('Input.dispatchMouseEvent', {
      type: 'mouseReleased',
      x,
      y,
      button: 'left',
      buttons: 0,
      clickCount: 1,
    });
  }

  async function mouseDrag(fromX, fromY, toX, toY, steps = 8) {
    await send('Input.dispatchMouseEvent', {
      type: 'mouseMoved',
      x: fromX,
      y: fromY,
      button: 'none',
      buttons: 0,
    });
    await send('Input.dispatchMouseEvent', {
      type: 'mousePressed',
      x: fromX,
      y: fromY,
      button: 'left',
      buttons: 1,
      clickCount: 1,
    });
    for (let i = 1; i <= steps; i += 1) {
      const cx = fromX + ((toX - fromX) * i) / steps;
      const cy = fromY + ((toY - fromY) * i) / steps;
      await send('Input.dispatchMouseEvent', {
        type: 'mouseMoved',
        x: cx,
        y: cy,
        button: 'left',
        buttons: 1,
      });
      await sleep(16);
    }
    await send('Input.dispatchMouseEvent', {
      type: 'mouseReleased',
      x: toX,
      y: toY,
      button: 'left',
      buttons: 0,
      clickCount: 1,
    });
  }

  async function clickSelector(selector) {
    const ok = await evaluate(`(() => {
      const el = document.querySelector(${JSON.stringify(selector)});
      if (!el) return false;
      el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      el.click();
      return true;
    })()`);
    assert.equal(ok, true, `Expected element to exist and be clickable: ${selector}`);
  }

  async function setInputValue(selector, value, { dispatchChange = false } = {}) {
    const ok = await evaluate(`(() => {
      const el = document.querySelector(${JSON.stringify(selector)});
      if (!el) return false;
      el.focus();
      const proto = el.tagName === 'TEXTAREA'
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, ${JSON.stringify(String(value))});
      else el.value = ${JSON.stringify(String(value))};
      el.dispatchEvent(new Event('input', { bubbles: true }));
      if (${JSON.stringify(Boolean(dispatchChange))}) {
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }
      return true;
    })()`);
    assert.equal(ok, true, `Expected input element to exist: ${selector}`);
  }

  async function close() {
    try {
      ws.close();
    } catch {
      // ignore
    }
    if (proc.exitCode === null && proc.signalCode === null) {
      try {
        proc.kill('SIGTERM');
      } catch {
        // ignore
      }
      await Promise.race([
        new Promise((r) => proc.once('exit', r)),
        new Promise((r) =>
          setTimeout(() => {
            try {
              proc.kill('SIGKILL');
            } catch {
              // ignore
            }
            r();
          }, 3000)
        ),
      ]);
    }
    await fsp.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
  }

  await send('Page.enable');
  await send('Runtime.enable');
  await send('DOM.enable');
  await send('Network.enable');
  await send('Emulation.setDeviceMetricsOverride', {
    width,
    height,
    deviceScaleFactor: 1,
    mobile: false,
  });

  return {
    send,
    evaluate,
    navigate,
    mouseClick,
    mouseDrag,
    clickSelector,
    setInputValue,
    consoleErrors,
    pageErrors,
    networkRequests,
    failedResponses,
    close,
  };
}

describe('OmniOS M6 Real Browser GUI & Headless Chromium CDP Suite (F-073 – F-084)', { timeout: 180_000 }, () => {
  let dataDir = null;
  let omniOS = null;
  let server = null;
  let baseUrl = '';
  let cdp = null;

  async function apiJson(route, opts = {}) {
    const res = await fetch(`${baseUrl}${route}`, {
      ...opts,
      headers: {
        ...(opts.body && typeof opts.body === 'string' ? { 'Content-Type': 'application/json' } : {}),
        ...(opts.headers ?? {}),
      },
    });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }
    return { status: res.status, ok: res.ok, json };
  }

  async function closeAllWindows() {
    const snap = await apiJson('/api/v1/compositor/snapshot');
    for (const win of snap.json?.windows ?? []) {
      await apiJson(`/api/v1/compositor/windows/${encodeURIComponent(win.windowId)}/close`, {
        method: 'POST',
        body: '{}',
      });
    }
    await waitFor(
      async () =>
        (await cdp.evaluate(`document.querySelectorAll('#window-layer .omni-window').length`)) === 0,
      { label: 'all windows closed in DOM', timeoutMs: 8000 }
    );
  }

  before(async () => {
    dataDir = await fsp.mkdtemp(path.join(osMod.tmpdir(), 'omnios-m6-data-'));
    omniOS = createOmniOS({ dataDir });
    await omniOS.boot();
    server = createHttpServer(omniOS, { port: 0, host: '127.0.0.1' });
    const addr = await server.start({ port: 0, host: '127.0.0.1' });
    baseUrl = addr.url;
    cdp = await launchChromiumCdp({ width: 1440, height: 900 });
  });

  after(async () => {
    try {
      if (cdp) await cdp.close();
    } finally {
      try {
        if (server) await server.stop();
      } finally {
        try {
          if (omniOS) await omniOS.shutdown();
        } finally {
          if (dataDir) {
            await fsp.rm(dataDir, { recursive: true, force: true }).catch(() => {});
          }
        }
      }
    }
  });

  // =========================================================================
  // Suite 1: Offline Static Serving, Zero External Network & Live WS Hydration
  // =========================================================================
  it('Suite 1: serves ui/ offline with zero 404s, zero external URLs, and hydrates live WS (F-073, F-084)', async () => {
    const staticAssets = [
      '/',
      '/styles/base.css',
      '/styles/hybrid.css',
      '/styles/mode-windows.css',
      '/styles/mode-macos.css',
      '/styles/mode-ios.css',
      '/styles/mode-android.css',
      '/js/ws-client.js',
      '/js/canvas-renderer.js',
      '/js/compositor-ui.js',
      '/js/shell-modes.js',
      '/js/overlays.js',
      '/js/app.js',
    ];

    for (const asset of staticAssets) {
      const res = await fetch(`${baseUrl}${asset}`);
      assert.equal(res.status, 200, `Expected HTTP 200 for ${asset}, got ${res.status}`);
      const body = await res.text();
      assert.ok(body.length > 0, `Asset ${asset} must be non-empty`);
      if (asset === '/') {
        assert.match(body, /id="omni-shell"/, 'GET / must serve ui/index.html');
      }
    }

    await cdp.navigate(baseUrl);

    await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const s = document.getElementById('omni-shell');
          return Boolean(
            s &&
            s.getAttribute('data-hydrated') === 'true' &&
            s.getAttribute('data-ws-connected') === 'true'
          );
        })()`),
      { label: 'shell hydration & live WebSocket connection', timeoutMs: 12_000 }
    );

    // Assert 100% offline network hygiene: every single Chromium request targets 127.0.0.1, data:, or about:
    assert.ok(cdp.networkRequests.length >= 13, 'Chromium must load HTML + 6 CSS + 6 JS + API calls');
    for (const req of cdp.networkRequests) {
      const allowed =
        req.url.startsWith(`${baseUrl}`) ||
        req.url.startsWith('http://127.0.0.1:') ||
        req.url.startsWith('ws://127.0.0.1:') ||
        req.url.startsWith('data:') ||
        req.url.startsWith('about:');
      assert.equal(allowed, true, `Forbidden external network URL detected: ${req.url}`);
    }

    assert.deepEqual(cdp.failedResponses, [], 'Zero HTTP 4xx/5xx responses allowed on boot');
    assert.deepEqual(cdp.consoleErrors, [], 'Zero browser console errors allowed on boot');
    assert.deepEqual(cdp.pageErrors, [], 'Zero uncaught page exceptions allowed on boot');
  });

  // =========================================================================
  // Suite 2: Live 5-Mode Shell Switcher, Theme & Adaptive Chrome Sync
  // =========================================================================
  it('Suite 2: live 5-mode shell switching preserves open windows, syncs chrome, theme & chrome-mode (F-075, F-076, F-084)', async () => {
    // Launch real OmniTerm via UI dock so a live window stays open across all 5 shell modes
    await cdp.clickSelector('#dock-apps [data-app-id="com.omnios.terminal"][data-builtin="true"]');

    const termWinId = await waitFor(
      async () =>
        cdp.evaluate(`document.querySelector('#window-layer .omni-window[data-app-id="com.omnios.terminal"]')?.getAttribute('data-window-id') || null`),
      { label: 'OmniTerm window created via Dock click' }
    );
    assert.ok(termWinId, 'OmniTerm window must exist before switching shell modes');

    const modeChecks = [
      {
        mode: 'windows',
        visible: ['#win-taskbar'],
        hidden: ['#floating-dock', '#ios-springboard', '#ios-home-bar', '#android-navbar'],
      },
      {
        mode: 'macos',
        visible: ['#floating-dock', '#global-menu-bar'],
        hidden: ['#win-taskbar', '#ios-springboard', '#ios-home-bar', '#android-navbar'],
      },
      {
        mode: 'ios',
        visible: ['#ios-springboard', '#ios-home-bar', '#dynamic-island'],
        hidden: ['#floating-dock', '#win-taskbar', '#android-navbar'],
        checkMobileCard: true,
      },
      {
        mode: 'android',
        visible: ['#android-navbar'],
        hidden: ['#floating-dock', '#win-taskbar', '#ios-springboard', '#ios-home-bar'],
        checkMobileCard: true,
      },
      {
        mode: 'unified',
        visible: ['#floating-dock', '#global-menu-bar', '#dynamic-island'],
        hidden: ['#win-taskbar', '#ios-springboard', '#ios-home-bar', '#android-navbar'],
      },
    ];

    for (const check of modeChecks) {
      await cdp.clickSelector(`#shell-mode-switcher [data-shell-mode-btn="${check.mode}"]`);

      await waitFor(
        async () => {
          const domMode = await cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-shell-mode')`);
          if (domMode !== check.mode) return false;
          const cfg = await apiJson('/api/v1/config/system');
          return cfg.json?.system?.['system.shellMode'] === check.mode;
        },
        { label: `shell mode ${check.mode} synced to DOM and kernel config` }
      );

      const state = await cdp.evaluate(`(() => {
        const shell = document.getElementById('omni-shell');
        const win = document.querySelector('#window-layer .omni-window[data-window-id="${termWinId}"]');
        const rect = win ? win.getBoundingClientRect() : null;
        const vis = (sel) => {
          const el = document.querySelector(sel);
          return el ? getComputedStyle(el).display !== 'none' : false;
        };
        return {
          mode: shell.getAttribute('data-shell-mode'),
          winCount: Number(shell.getAttribute('data-window-count')),
          winExists: Boolean(win),
          winWidth: rect ? Math.round(rect.width) : 0,
          winHeight: rect ? Math.round(rect.height) : 0,
          visibleMap: Object.fromEntries(${JSON.stringify([...check.visible, ...check.hidden])}.map((s) => [s, vis(s)])),
        };
      })()`);

      assert.equal(state.mode, check.mode);
      assert.ok(state.winCount >= 1, `Open window count must stay >= 1 in ${check.mode} mode`);
      assert.equal(state.winExists, true, `Open OmniTerm DOM window must persist in ${check.mode} mode`);

      for (const sel of check.visible) {
        assert.equal(state.visibleMap[sel], true, `${sel} must be visible in ${check.mode} mode`);
      }
      for (const sel of check.hidden) {
        assert.equal(state.visibleMap[sel], false, `${sel} must be hidden in ${check.mode} mode`);
      }
      if (check.checkMobileCard) {
        assert.ok(
          state.winWidth >= 400 && state.winHeight >= 300,
          `Mobile window in ${check.mode} mode must size properly (got ${state.winWidth}x${state.winHeight})`
        );
      }
    }

    // Theme toggle: dark -> light -> dark persisted in kernel config
    await cdp.clickSelector('#btn-theme-toggle');
    await waitFor(
      async () => {
        const domTheme = await cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-theme')`);
        const cfg = await apiJson('/api/v1/config/system');
        return domTheme === 'light' && cfg.json?.system?.['system.theme'] === 'light';
      },
      { label: 'light theme toggled and persisted' }
    );

    await cdp.clickSelector('#btn-theme-toggle');
    await waitFor(
      async () => {
        const domTheme = await cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-theme')`);
        const cfg = await apiJson('/api/v1/config/system');
        return domTheme === 'dark' && cfg.json?.system?.['system.theme'] === 'dark';
      },
      { label: 'dark theme restored and persisted' }
    );

    // Adaptive vs Unified chrome mode toggle
    const initialChrome = await cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-chrome-mode')`);
    assert.equal(initialChrome, 'adaptive');
    await cdp.clickSelector('#btn-chrome-toggle');
    assert.equal(
      await cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-chrome-mode')`),
      'unified'
    );
    await cdp.clickSelector('#btn-chrome-toggle');
    assert.equal(
      await cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-chrome-mode')`),
      'adaptive'
    );

    await closeAllWindows();
  });

  // =========================================================================
  // Suite 3: All 7 Built-in System Apps Live in Chromium
  // =========================================================================
  it('Suite 3: operates all 7 built-in system apps live in Chromium including preferSystem coexistence (F-073, F-074)', async () => {
    // 1. OmniTerm
    await cdp.clickSelector('#dock-apps [data-app-id="com.omnios.terminal"][data-builtin="true"]');
    await waitFor(
      async () => cdp.evaluate(`Boolean(document.querySelector('[data-node-id="term-input"]'))`),
      { label: 'OmniTerm input mounted' }
    );
    await cdp.setInputValue('[data-node-id="term-input"]', 'echo OMNI_M6_TERM_OK');
    await cdp.clickSelector('[data-node-id="term-run"]');
    await waitFor(
      async () =>
        cdp.evaluate(`(document.querySelector('[data-node-id="term-output"]')?.textContent || '').includes('OMNI_M6_TERM_OK')`),
      { label: 'OmniTerm command output rendered' }
    );
    await closeAllWindows();

    // 2. OmniFiles
    await cdp.clickSelector('#dock-apps [data-app-id="com.omnios.files"][data-builtin="true"]');
    await waitFor(
      async () => cdp.evaluate(`Boolean(document.querySelector('[data-node-id="mode-explorer"]'))`),
      { label: 'OmniFiles Explorer mode button mounted' }
    );
    await cdp.clickSelector('[data-node-id="mode-explorer"]');
    await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const bar = document.querySelector('[data-node-id="files-path-bar"]')?.textContent || '';
          const entries = document.querySelectorAll('[data-node-id="files-entries"] .omni-ui-listitem').length;
          return bar.startsWith('C:\\\\') && entries > 0;
        })()`),
      { label: 'OmniFiles explorer C:\\ path and entries rendered' }
    );
    await closeAllWindows();

    // 3. Activity Monitor (live PIDs, real 400x90 telemetry canvas pixels, services/tree/memory/dmesg tabs)
    await cdp.clickSelector('#dock-apps [data-app-id="com.omnios.monitor"][data-builtin="true"]');
    await waitFor(
      async () =>
        cdp.evaluate(`document.querySelectorAll('.omni-window[data-app-id="com.omnios.monitor"] [data-node-id^="proc-"]').length > 0`),
      { label: 'Activity Monitor PID rows rendered' }
    );

    const canvasStats = await cdp.evaluate(`(() => {
      const c = document.querySelector('.omni-window[data-app-id="com.omnios.monitor"] .window-canvas-host canvas');
      if (!c) return null;
      const ctx = c.getContext('2d');
      const img = ctx.getImageData(0, 0, c.width, c.height).data;
      const colors = new Set();
      let nonZeroAlpha = 0;
      for (let i = 0; i < img.length; i += 4) {
        if (img[i + 3] > 0) {
          nonZeroAlpha += 1;
          if (colors.size < 20) {
            colors.add(img[i] + ',' + img[i + 1] + ',' + img[i + 2] + ',' + img[i + 3]);
          }
        }
      }
      return { width: c.width, height: c.height, nonZeroAlpha, distinctColors: colors.size };
    })()`);
    assert.ok(canvasStats, 'Activity Monitor must render its 400x90 telemetry canvas');
    assert.equal(canvasStats.width, 400);
    assert.equal(canvasStats.height, 90);
    assert.ok(canvasStats.nonZeroAlpha > 1000, 'Telemetry canvas must have painted pixels');
    assert.ok(canvasStats.distinctColors >= 2, `Telemetry canvas must have >=2 distinct colors, got ${canvasStats.distinctColors}`);

    await cdp.clickSelector('[data-node-id="tab-services"]');
    await waitFor(
      async () => cdp.evaluate(`document.querySelectorAll('[data-node-id^="svc-"]').length >= 6`),
      { label: 'Activity Monitor services tab rendered' }
    );
    await cdp.clickSelector('[data-node-id="tab-tree"]');
    await waitFor(
      async () => cdp.evaluate(`document.querySelectorAll('.monitor-tree-node').length > 0`),
      { label: 'Activity Monitor process tree tab rendered' }
    );
    await cdp.clickSelector('[data-node-id="tab-memory"]');
    await waitFor(
      async () => cdp.evaluate(`document.querySelectorAll('.stat-card').length >= 4`),
      { label: 'Activity Monitor memory tab rendered' }
    );
    await cdp.clickSelector('[data-node-id="tab-dmesg"]');
    await waitFor(
      async () => cdp.evaluate(`document.querySelectorAll('[data-node-id^="dmesg-"]').length > 0`),
      { label: 'Activity Monitor dmesg tab rendered' }
    );
    await closeAllWindows();

    // 4. App Hub (4-platform catalog cards)
    await cdp.clickSelector('#dock-apps [data-app-id="com.omnios.apphub"][data-builtin="true"]');
    const platformsFound = await waitFor(
      async () => {
        const plats = await cdp.evaluate(`[...new Set([...document.querySelectorAll('.apphub-card')].map((c) => c.getAttribute('data-platform')))]`);
        return plats.length >= 5 ? plats : null;
      },
      { label: 'App Hub 4-platform + universal cards rendered' }
    );
    for (const p of ['android', 'windows', 'ios', 'macos', 'universal']) {
      assert.ok(platformsFound.includes(p), `App Hub must render ${p} catalog card`);
    }
    await closeAllWindows();

    // 5. Settings & Privacy (all 8 canonical synced system.* keys)
    await cdp.clickSelector('#dock-apps [data-app-id="com.omnios.settings"][data-builtin="true"]');
    const settingsCount = await waitFor(
      async () => {
        const count = await cdp.evaluate(`document.querySelectorAll('.omni-window[data-app-id="com.omnios.settings"] [data-node-id^="sys-system."]').length`);
        return count === 8 ? count : null;
      },
      { label: 'Settings 8 canonical system.* keys rendered' }
    );
    assert.equal(settingsCount, 8);
    await closeAllWindows();

    // 6. Binary & Process Inspector (package binary + live PID)
    await cdp.clickSelector('#dock-apps [data-app-id="com.omnios.inspector"][data-builtin="true"]');
    await waitFor(
      async () =>
        cdp.evaluate(`document.querySelectorAll('[data-node-id="inspector-targets"] .inspector-chips-group button').length > 0`),
      { label: 'Binary Inspector targets rendered' }
    );
    // Click first catalog binary chip
    await cdp.clickSelector('[data-node-id="inspector-targets"] .inspector-chips-group:first-child button');
    await waitFor(
      async () =>
        cdp.evaluate(`(document.querySelector('[data-node-id="inspector-report"]')?.textContent || '').includes('Binary Report:')`),
      { label: 'Binary Inspector package report rendered' }
    );
    // Click first running PID chip
    await cdp.clickSelector('[data-node-id="inspector-targets"] .inspector-chips-group:nth-child(2) button');
    await waitFor(
      async () =>
        cdp.evaluate(`(document.querySelector('[data-node-id="inspector-report"]')?.textContent || '').includes('Process PID')`),
      { label: 'Binary Inspector live PID report rendered' }
    );
    await closeAllWindows();

    // 7. OmniNotes with `preferSystem: true` coexistence AFTER installing android-notes-sharer.apk!
    const installNotesRes = await apiJson('/api/v1/packages/install', {
      method: 'POST',
      body: JSON.stringify({ path: '/packages/android-notes-sharer.apk', grantAll: true }),
    });
    assert.equal(installNotesRes.ok, true, 'android-notes-sharer.apk must install cleanly');

    // Launch built-in OmniNotes via Dock built-in button (must send preferSystem: true!)
    await cdp.clickSelector('#dock-apps [data-app-id="com.omnios.notes"][data-builtin="true"]');
    const notesWinMeta = await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const w = document.querySelector('#window-layer .omni-window[data-app-id="com.omnios.notes"]');
          if (!w) return null;
          return {
            platform: w.getAttribute('data-platform'),
            hasEditorRole: Boolean(w.querySelector('[data-app-role="notes-editor"]')),
          };
        })()`),
      { label: 'Built-in OmniNotes launched with preferSystem: true' }
    );
    assert.equal(
      notesWinMeta.platform,
      'system',
      'Built-in OmniNotes must launch as platform=system even after android-notes-sharer.apk is installed'
    );
    assert.equal(notesWinMeta.hasEditorRole, true, 'Built-in OmniNotes must render notes-editor UI');

    await closeAllWindows();
  });

  // =========================================================================
  // Suite 4: Real 4-Platform + Universal Binary Apps Live in Chromium
  // =========================================================================
  it('Suite 4: runs real Android, Windows, iOS, macOS & Universal WASM binaries live in Chromium (F-074, F-075, F-077, F-079)', async () => {
    const samplePaths = [
      '/packages/android-calc.apk',
      '/packages/win-notepad.exe',
      '/packages/ios-weather-island.ipa',
      '/packages/macos-studio.app.zip',
      '/packages/universal-canvas.uapp',
    ];
    for (const pkgPath of samplePaths) {
      const r = await apiJson('/api/v1/packages/install', {
        method: 'POST',
        body: JSON.stringify({ path: pkgPath, grantAll: true, overwrite: true }),
      });
      assert.equal(r.ok, true, `Install failed for ${pkgPath}: ${JSON.stringify(r.json)}`);
    }

    // --- 4A. Android (`android-calc.apk`): real Dalvik VM arithmetic 7 * 6 = 42 ---
    const calcLaunch = await apiJson('/api/v1/packages/com.omnios.calc/launch', {
      method: 'POST',
      body: '{}',
    });
    assert.equal(calcLaunch.ok, true);

    await waitFor(
      async () =>
        cdp.evaluate(`document.querySelectorAll('.omni-window[data-app-id="com.omnios.calc"][data-platform="android"] .omni-ui-btn').length >= 10`),
      { label: 'Android OmniCalc Dalvik UI rendered' }
    );

    const clickCalcLabel = async (label) => {
      const clicked = await cdp.evaluate(`(() => {
        const win = document.querySelector('.omni-window[data-app-id="com.omnios.calc"]');
        if (!win) return false;
        const btn = [...win.querySelectorAll('button.omni-ui-btn')].find((b) => b.textContent.trim() === ${JSON.stringify(label)});
        if (!btn) return false;
        btn.click();
        return true;
      })()`);
      assert.equal(clicked, true, `Calculator button "${label}" must exist in Dalvik UI`);
      await sleep(120);
    };

    await clickCalcLabel('7');
    await clickCalcLabel('*');
    await clickCalcLabel('6');
    await clickCalcLabel('=');

    await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const win = document.querySelector('.omni-window[data-app-id="com.omnios.calc"]');
          if (!win) return false;
          return [...win.querySelectorAll('.omni-ui-text')].some((el) => el.textContent.trim() === '42');
        })()`),
      { label: 'Dalvik VM computed 7 * 6 = 42 in live DOM' }
    );
    await closeAllWindows();

    // --- 4B. Windows (`win-notepad.exe`): real PE32+ x86-64 window + Windows chrome + GDI canvas + Win32 controls ---
    const winLaunch = await apiJson('/api/v1/packages/win.win-notepad/launch', {
      method: 'POST',
      body: '{}',
    });
    assert.equal(winLaunch.ok, true);

    const winInfo = await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const w = document.querySelector('.omni-window[data-app-id="win.win-notepad"][data-platform="windows"]');
          if (!w) return null;
          const inp = w.querySelector('input.omni-ui-input');
          const btns = w.querySelectorAll('button.omni-ui-btn').length;
          const canvas = w.querySelector('.window-canvas-host canvas');
          if (!inp || btns < 1 || !canvas) return null;
          const ctx = canvas.getContext('2d');
          const data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
          let painted = 0;
          for (let i = 3; i < data.length; i += 4) if (data[i] > 0) painted += 1;
          return {
            chromeStyle: w.getAttribute('data-chrome-style'),
            btns,
            canvasW: canvas.width,
            canvasH: canvas.height,
            painted,
          };
        })()`),
      { label: 'Win32 Notepad PE32+ window, GDI canvas & controls rendered' }
    );
    assert.equal(winInfo.chromeStyle, 'windows');
    assert.ok(winInfo.painted > 200, 'Win32 GDI canvas must contain real painted pixels');

    await cdp.setInputValue('.omni-window[data-app-id="win.win-notepad"] input.omni-ui-input', 'OMNI_WIN32_LIVE');
    await cdp.evaluate(`(() => {
      const w = document.querySelector('.omni-window[data-app-id="win.win-notepad"]');
      const saveBtn = [...w.querySelectorAll('button.omni-ui-btn')].find((b) => /save/i.test(b.textContent));
      if (saveBtn) saveBtn.click();
    })()`);
    await waitFor(
      async () => {
        try {
          const txt = omniOS.vfs.readFile('/home/user/Documents/win-notepad.txt', { uid: 0, gid: 0, encoding: 'utf8' });
          return txt === 'OMNI_WIN32_LIVE';
        } catch {
          return false;
        }
      },
      { label: 'Win32 Notepad saved file via live UI click' }
    );
    await closeAllWindows();

    // --- 4C. iOS (`ios-weather-island.ipa`): ARM64 Mach-O UIKit window + Dynamic Island Live Activity ---
    const iosLaunch = await apiJson('/api/v1/packages/com.omnios.ios.weather-island/launch', {
      method: 'POST',
      body: '{}',
    });
    assert.equal(iosLaunch.ok, true);

    await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const w = document.querySelector('.omni-window[data-app-id="com.omnios.ios.weather-island"][data-platform="ios"]');
          const di = document.getElementById('dynamic-island');
          return Boolean(w && di && di.getAttribute('data-active') === 'true');
        })()`),
      { label: 'iOS Weather Island window & Dynamic Island Live Activity active' }
    );

    await cdp.clickSelector('#dynamic-island-pill');
    const diExpanded = await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const di = document.getElementById('dynamic-island');
          if (!di || di.getAttribute('data-expanded') !== 'true') return null;
          return {
            title: document.getElementById('di-exp-title')?.textContent || '',
            subtitle: document.getElementById('di-exp-subtitle')?.textContent || '',
            body: document.getElementById('di-exp-body')?.textContent || '',
          };
        })()`),
      { label: 'Dynamic Island expanded card rendered live weather' }
    );
    assert.ok(
      `${diExpanded.title} ${diExpanded.subtitle} ${diExpanded.body}`.trim().length > 0,
      'Expanded Dynamic Island must render live weather content'
    );
    // Collapse Dynamic Island
    await cdp.clickSelector('#dynamic-island-pill');
    await closeAllWindows();

    // --- 4D. macOS (`macos-studio.app.zip`): AppKit window + Global Top Menu Bar update & action ---
    const macLaunch = await apiJson('/api/v1/packages/com.omnios.macos.studio/launch', {
      method: 'POST',
      body: '{}',
    });
    assert.equal(macLaunch.ok, true);

    await cdp.clickSelector('#shell-mode-switcher [data-shell-mode-btn="macos"]');
    await waitFor(
      async () =>
        cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-shell-mode') === 'macos'`),
      { label: 'switched to macOS mode' }
    );

    // Focus macOS Studio window and verify Global Top Menu Bar updates dynamically
    const macWinId = await waitFor(
      async () =>
        cdp.evaluate(`document.querySelector('.omni-window[data-app-id="com.omnios.macos.studio"][data-platform="macos"]')?.getAttribute('data-window-id') || null`),
      { label: 'macOS Studio window mounted' }
    );
    await apiJson(`/api/v1/compositor/windows/${encodeURIComponent(macWinId)}/focus`, {
      method: 'POST',
      body: '{}',
    });

    const macMenuGroups = await waitFor(
      async () => {
        const labels = await cdp.evaluate(`[...document.querySelectorAll('#global-menu-bar .menu-bar-trigger')].map((b) => ({ id: b.getAttribute('data-menu-id'), label: b.textContent.trim() }))`);
        // macOS Studio exposes custom AppKit menu groups (e.g., OmniStudio / File / Edit / View) instead of default 'omnios'
        return labels.length > 0 && !labels.some((m) => m.id === 'omnios') ? labels : null;
      },
      { label: 'Global Top Menu Bar dynamically displays macOS Studio AppKit menus' }
    );
    assert.ok(macMenuGroups.length >= 2, 'macOS Studio must publish multiple AppKit menu groups');

    // Open a non-quit menu group (e.g. File or first group) and click a non-quit item
    const targetGroup = macMenuGroups.find((g) => /file|view|edit/i.test(g.label)) ?? macMenuGroups[0];
    await cdp.clickSelector(`#global-menu-bar .menu-bar-trigger[data-menu-id="${targetGroup.id}"]`);
    await waitFor(
      async () =>
        cdp.evaluate(`document.getElementById('menu-bar-dropdown').getAttribute('data-open') === 'true'`),
      { label: 'macOS Global Menu Bar dropdown opened' }
    );
    const clickedMenuItem = await cdp.evaluate(`(() => {
      const items = [...document.querySelectorAll('#menu-bar-dropdown .menu-dropdown-item')];
      const safe = items.find((b) => !/quit|close/i.test(b.textContent) && !b.disabled) || items[0];
      if (!safe) return null;
      safe.click();
      return safe.textContent.trim();
    })()`);
    assert.ok(clickedMenuItem, 'Must click a live macOS Studio menu item');
    await sleep(150);

    // Switch back to unified mode and close macOS Studio
    await cdp.clickSelector('#shell-mode-switcher [data-shell-mode-btn="unified"]');
    await closeAllWindows();

    // --- 4E. Universal WASM (`universal-canvas.uapp`): embedded canvas pixels + click plot + Clear Canvas ---
    const wasmLaunch = await apiJson('/api/v1/packages/com.omnios.universal.canvas/launch', {
      method: 'POST',
      body: '{}',
    });
    assert.equal(wasmLaunch.ok, true);

    const wasmInit = await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const w = document.querySelector('.omni-window[data-app-id="com.omnios.universal.canvas"][data-platform="universal"]');
          if (!w) return null;
          const c = w.querySelector('[data-node-id="main-canvas"] canvas');
          if (!c || c.width < 100 || c.height < 100) return null;
          const ctx = c.getContext('2d');
          const img = ctx.getImageData(0, 0, c.width, c.height).data;
          const colors = new Set();
          let nonZero = 0;
          for (let i = 0; i < img.length; i += 4) {
            if (img[i + 3] > 0) {
              nonZero += 1;
              if (colors.size < 25) colors.add(img[i] + ',' + img[i + 1] + ',' + img[i + 2]);
            }
          }
          const rect = c.getBoundingClientRect();
          return {
            windowId: w.getAttribute('data-window-id'),
            rev: Number(w.getAttribute('data-surface-revision')),
            width: c.width,
            height: c.height,
            nonZero,
            distinctColors: colors.size,
            rect: { left: rect.left, top: rect.top, width: rect.width, height: rect.height },
          };
        })()`),
      { label: 'Universal WASM canvas rendered with non-empty drawOps' }
    );
    assert.ok(wasmInit.nonZero > 5000, 'WASM canvas must contain real painted pixels');
    assert.ok(wasmInit.distinctColors >= 3, `WASM canvas must paint multiple colors, got ${wasmInit.distinctColors}`);

    // Click at logical (240, 200) via real CDP mouse click
    const clickX = wasmInit.rect.left + (240 / wasmInit.width) * wasmInit.rect.width;
    const clickY = wasmInit.rect.top + (200 / wasmInit.height) * wasmInit.rect.height;
    await cdp.mouseClick(clickX, clickY);

    const revAfterClick = await waitFor(
      async () => {
        const rev = await cdp.evaluate(`Number(document.querySelector('.omni-window[data-window-id="${wasmInit.windowId}"]')?.getAttribute('data-surface-revision') || 0)`);
        return rev > wasmInit.rev ? rev : null;
      },
      { label: 'WASM canvas surfaceRevision incremented after canvas click' }
    );
    assert.ok(revAfterClick > wasmInit.rev);

    // Click Clear Canvas (`btn-clear`)
    await cdp.clickSelector(`.omni-window[data-window-id="${wasmInit.windowId}"] [data-node-id="btn-clear"]`);
    const revAfterClear = await waitFor(
      async () => {
        const rev = await cdp.evaluate(`Number(document.querySelector('.omni-window[data-window-id="${wasmInit.windowId}"]')?.getAttribute('data-surface-revision') || 0)`);
        return rev > revAfterClick ? rev : null;
      },
      { label: 'WASM canvas surfaceRevision incremented after Clear Canvas' }
    );
    assert.ok(revAfterClear > revAfterClick);

    await closeAllWindows();
  });

  // =========================================================================
  // Suite 5: Multi-Window Manipulation (Focus, Drag, Resize, Snap, Min/Max/Close)
  // =========================================================================
  it('Suite 5: supports multi-window focus/z-order, CDP drag, CDP resize, snap layouts, minimize/restore/maximize/close (F-074, F-078)', async () => {
    await cdp.clickSelector('#shell-mode-switcher [data-shell-mode-btn="unified"]');
    await apiJson('/api/v1/packages/com.omnios.terminal/launch', {
      method: 'POST',
      body: JSON.stringify({ preferSystem: true }),
    });
    await apiJson('/api/v1/packages/com.omnios.files/launch', {
      method: 'POST',
      body: JSON.stringify({ preferSystem: true }),
    });

    const wins = await waitFor(
      async () => {
        const snap = await apiJson('/api/v1/compositor/snapshot');
        const list = snap.json?.windows ?? [];
        const domCount = await cdp.evaluate(`document.querySelectorAll('#window-layer .omni-window').length`);
        return list.length >= 2 && domCount >= 2 ? list : null;
      },
      { label: '2 live windows open' }
    );

    // Position the 2 windows side-by-side so both are clearly clickable for focus/drag/resize
    const winA = wins[0];
    const winB = wins[1];
    await apiJson(`/api/v1/compositor/windows/${encodeURIComponent(winA.windowId)}/move`, {
      method: 'POST',
      body: JSON.stringify({ x: 40, y: 40 }),
    });
    await apiJson(`/api/v1/compositor/windows/${encodeURIComponent(winA.windowId)}/resize`, {
      method: 'POST',
      body: JSON.stringify({ width: 520, height: 380 }),
    });
    await apiJson(`/api/v1/compositor/windows/${encodeURIComponent(winB.windowId)}/move`, {
      method: 'POST',
      body: JSON.stringify({ x: 600, y: 80 }),
    });
    await apiJson(`/api/v1/compositor/windows/${encodeURIComponent(winB.windowId)}/resize`, {
      method: 'POST',
      body: JSON.stringify({ width: 520, height: 380 }),
    });
    await apiJson(`/api/v1/compositor/windows/${encodeURIComponent(winB.windowId)}/focus`, {
      method: 'POST',
      body: '{}',
    });
    await sleep(150);

    // 1. Focus / z-order: click lower window (winA) via real CDP mouse click
    const rectA = await cdp.evaluate(`(() => {
      const r = document.querySelector('.omni-window[data-window-id="${winA.windowId}"] .window-title-group').getBoundingClientRect();
      return { x: r.left + 40, y: r.top + r.height / 2 };
    })()`);
    await cdp.mouseClick(rectA.x, rectA.y);

    await waitFor(
      async () => {
        const focused = await cdp.evaluate(`document.querySelector('.omni-window[data-window-id="${winA.windowId}"]')?.getAttribute('data-focused')`);
        const snap = await apiJson('/api/v1/compositor/snapshot');
        const a = snap.json.windows.find((w) => w.windowId === winA.windowId);
        const b = snap.json.windows.find((w) => w.windowId === winB.windowId);
        return focused === 'true' && snap.json.focusedWindowId === winA.windowId && a.zIndex > b.zIndex;
      },
      { label: 'winA focused with higher zIndex than winB' }
    );

    // 2. Real CDP mouse drag on winA header
    const snapBeforeDrag = (await apiJson('/api/v1/compositor/snapshot')).json.windows.find(
      (w) => w.windowId === winA.windowId
    );
    const dragStart = await cdp.evaluate(`(() => {
      const r = document.querySelector('.omni-window[data-window-id="${winA.windowId}"] .window-title-group').getBoundingClientRect();
      return { x: r.left + 60, y: r.top + r.height / 2 };
    })()`);
    await cdp.mouseDrag(dragStart.x, dragStart.y, dragStart.x + 120, dragStart.y + 70, 8);

    const movedWin = await waitFor(
      async () => {
        const w = (await apiJson('/api/v1/compositor/snapshot')).json.windows.find(
          (item) => item.windowId === winA.windowId
        );
        return w && w.bounds.x !== snapBeforeDrag.bounds.x && w.bounds.y !== snapBeforeDrag.bounds.y ? w : null;
      },
      { label: 'winA moved via real CDP mouse drag' }
    );
    assert.ok(movedWin.bounds.x > snapBeforeDrag.bounds.x + 50, 'Dragged window x must increase');
    assert.ok(movedWin.bounds.y > snapBeforeDrag.bounds.y + 30, 'Dragged window y must increase');

    // 3. Real CDP mouse drag resize on `.window-resize-handle[data-resize-dir="se"]`
    const boundsBeforeResize = { ...movedWin.bounds };
    const seHandle = await cdp.evaluate(`(() => {
      const r = document.querySelector('.omni-window[data-window-id="${winA.windowId}"] .window-resize-handle[data-resize-dir="se"]').getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    })()`);
    await cdp.mouseDrag(seHandle.x, seHandle.y, seHandle.x + 90, seHandle.y + 60, 8);

    const resizedWin = await waitFor(
      async () => {
        const w = (await apiJson('/api/v1/compositor/snapshot')).json.windows.find(
          (item) => item.windowId === winA.windowId
        );
        return w &&
          w.bounds.width !== boundsBeforeResize.width &&
          w.bounds.height !== boundsBeforeResize.height
          ? w
          : null;
      },
      { label: 'winA resized via real CDP SE handle drag' }
    );
    assert.ok(resizedWin.bounds.width > boundsBeforeResize.width + 40, 'Resized width must grow');
    assert.ok(resizedWin.bounds.height > boundsBeforeResize.height + 20, 'Resized height must grow');

    // 4. Snap Layouts popover: snapped-left then snapped-tl
    await cdp.clickSelector(`.omni-window[data-window-id="${winA.windowId}"] .win-btn-snap`);
    await cdp.clickSelector(`.omni-window[data-window-id="${winA.windowId}"] .snap-layout-popover [data-snap-state="snapped-left"]`);
    await waitFor(
      async () => {
        const domSt = await cdp.evaluate(`document.querySelector('.omni-window[data-window-id="${winA.windowId}"]')?.getAttribute('data-window-state')`);
        const w = (await apiJson('/api/v1/compositor/snapshot')).json.windows.find((x) => x.windowId === winA.windowId);
        return domSt === 'snapped-left' && w?.state === 'snapped-left';
      },
      { label: 'winA snapped-left' }
    );

    await cdp.clickSelector(`.omni-window[data-window-id="${winA.windowId}"] .win-btn-snap`);
    await cdp.clickSelector(`.omni-window[data-window-id="${winA.windowId}"] .snap-layout-popover [data-snap-state="snapped-tl"]`);
    await waitFor(
      async () => {
        const domSt = await cdp.evaluate(`document.querySelector('.omni-window[data-window-id="${winA.windowId}"]')?.getAttribute('data-window-state')`);
        const w = (await apiJson('/api/v1/compositor/snapshot')).json.windows.find((x) => x.windowId === winA.windowId);
        return domSt === 'snapped-tl' && w?.state === 'snapped-tl';
      },
      { label: 'winA snapped-tl' }
    );

    // 5. Minimize -> Dock minimized item -> Restore -> Maximize -> Close
    await cdp.clickSelector(`.omni-window[data-window-id="${winA.windowId}"] .win-btn-min`);
    await waitFor(
      async () =>
        cdp.evaluate(`Boolean(
          document.querySelector('.omni-window[data-window-id="${winA.windowId}"][data-window-state="minimized"]') &&
          document.querySelector('#dock-minimized .dock-minimized-item[data-window-id="${winA.windowId}"]')
        )`),
      { label: 'winA minimized and shown in Dock minimized tray' }
    );

    await cdp.clickSelector(`#dock-minimized .dock-minimized-item[data-window-id="${winA.windowId}"]`);
    await waitFor(
      async () =>
        cdp.evaluate(`document.querySelector('.omni-window[data-window-id="${winA.windowId}"]')?.getAttribute('data-window-state') === 'normal'`),
      { label: 'winA restored from Dock minimized tray' }
    );

    await cdp.clickSelector(`.omni-window[data-window-id="${winA.windowId}"] .win-btn-max`);
    await waitFor(
      async () => {
        const domSt = await cdp.evaluate(`document.querySelector('.omni-window[data-window-id="${winA.windowId}"]')?.getAttribute('data-window-state')`);
        const w = (await apiJson('/api/v1/compositor/snapshot')).json.windows.find((x) => x.windowId === winA.windowId);
        return domSt === 'maximized' && w?.state === 'maximized';
      },
      { label: 'winA maximized' }
    );

    await cdp.clickSelector(`.omni-window[data-window-id="${winA.windowId}"] .win-btn-close`);
    await waitFor(
      async () => {
        const goneDom = await cdp.evaluate(`!document.querySelector('.omni-window[data-window-id="${winA.windowId}"]')`);
        const snap = await apiJson('/api/v1/compositor/snapshot');
        return goneDom && !snap.json.windows.some((x) => x.windowId === winA.windowId);
      },
      { label: 'winA closed in DOM and backend snapshot' }
    );

    await closeAllWindows();
  });

  // =========================================================================
  // Suite 6: Platform UX Panels (Windows Start, iOS CC, Android Shade/Drawer/Recents Kill)
  // =========================================================================
  it('Suite 6: operates Windows Start Menu, iOS Control Center config sync, Android Shade, Drawer & Recents PID kill (F-078, F-079, F-080)', async () => {
    // --- 6A. Windows Mode: Start Menu + live search filter ---
    await cdp.clickSelector('#shell-mode-switcher [data-shell-mode-btn="windows"]');
    await waitFor(
      async () => cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-shell-mode') === 'windows'`),
      { label: 'Windows shell mode active' }
    );
    await cdp.clickSelector('#btn-win-start');
    await waitFor(
      async () => cdp.evaluate(`document.getElementById('win-start-menu').getAttribute('data-open') === 'true'`),
      { label: 'Windows Start Menu opened' }
    );
    await cdp.setInputValue('#start-search-input', 'OmniTerm');
    const filteredStart = await waitFor(
      async () => {
        const items = await cdp.evaluate(`[...document.querySelectorAll('#start-all-apps-list .start-list-item')].map((b) => b.textContent.trim())`);
        return items.length >= 1 && items.every((t) => /omniterm/i.test(t)) ? items : null;
      },
      { label: 'Windows Start Menu filtered to OmniTerm' }
    );
    assert.ok(filteredStart.length >= 1);
    await cdp.setInputValue('#start-search-input', '');
    await cdp.clickSelector('#btn-win-start');

    // --- 6B. iOS Mode: Control Center toggles & sliders syncing kernel config ---
    await cdp.clickSelector('#shell-mode-switcher [data-shell-mode-btn="ios"]');
    await waitFor(
      async () => cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-shell-mode') === 'ios'`),
      { label: 'iOS shell mode active' }
    );
    await cdp.clickSelector('#btn-ios-cc-pull');
    await waitFor(
      async () => cdp.evaluate(`document.getElementById('ios-control-center').getAttribute('data-open') === 'true'`),
      { label: 'iOS Control Center opened' }
    );

    await cdp.clickSelector('#ios-control-center [data-system-toggle="system.wifi"]');
    await cdp.clickSelector('#ios-control-center [data-system-toggle="system.dnd"]');
    await cdp.setInputValue('#cc-brightness-slider', '62', { dispatchChange: true });
    await cdp.setInputValue('#cc-volume-slider', '44', { dispatchChange: true });

    await waitFor(
      async () => {
        const cfg = (await apiJson('/api/v1/config/system')).json?.system;
        return (
          cfg &&
          cfg['system.wifi'] === false &&
          cfg['system.dnd'] === true &&
          cfg['system.brightness'] === 62 &&
          cfg['system.volume'] === 44
        );
      },
      { label: 'Control Center toggles & sliders persisted in /api/v1/config/system' }
    );

    // Restore clean defaults
    await cdp.clickSelector('#ios-control-center [data-system-toggle="system.wifi"]');
    await cdp.clickSelector('#ios-control-center [data-system-toggle="system.dnd"]');
    await cdp.setInputValue('#cc-brightness-slider', '80', { dispatchChange: true });
    await cdp.setInputValue('#cc-volume-slider', '75', { dispatchChange: true });
    await cdp.clickSelector('#btn-close-cc');

    // --- 6C. Android Mode: Notification Shade + Dismiss, App Drawer filter, Recents REAL PID kill ---
    await cdp.clickSelector('#shell-mode-switcher [data-shell-mode-btn="android"]');
    await waitFor(
      async () => cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-shell-mode') === 'android'`),
      { label: 'Android shell mode active' }
    );

    const postNotif = await apiJson('/api/v1/ipc/notifications', {
      method: 'POST',
      body: JSON.stringify({
        appId: 'com.omnios.calc',
        platform: 'android',
        title: 'M6 Android Alert',
        body: 'Notification shade live verification',
        actions: [{ id: 'ack', label: 'Acknowledge' }],
      }),
    });
    assert.equal(postNotif.status, 201);
    const notifId = postNotif.json.notification.id;

    await waitFor(
      async () =>
        cdp.evaluate(`Number(document.getElementById('notif-badge')?.getAttribute('data-count') || 0) >= 1`),
      { label: 'Notification unread badge updated' }
    );

    await cdp.clickSelector('#btn-notif-shade');
    await waitFor(
      async () =>
        cdp.evaluate(`Boolean(
          document.getElementById('android-shade').getAttribute('data-open') === 'true' &&
          document.querySelector('#shade-notif-list .notif-card[data-notif-id="${notifId}"]')
        )`),
      { label: 'Notification rendered inside Android Shade' }
    );

    await cdp.clickSelector(`#shade-notif-list .notif-card[data-notif-id="${notifId}"] .notif-dismiss-btn`);
    await waitFor(
      async () => {
        const list = (await apiJson('/api/v1/ipc/notifications')).json?.notifications ?? [];
        return !list.some((n) => n.id === notifId && !n.dismissed);
      },
      { label: 'Notification dismissed in backend /api/v1/ipc/notifications' }
    );
    await cdp.clickSelector('#btn-close-shade');

    // Android App Drawer + filter
    await cdp.clickSelector('#btn-android-drawer');
    await waitFor(
      async () => cdp.evaluate(`document.getElementById('android-app-drawer').getAttribute('data-open') === 'true'`),
      { label: 'Android App Drawer opened' }
    );
    await cdp.setInputValue('#drawer-search-input', 'OmniCalc');
    await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const tiles = [...document.querySelectorAll('#drawer-apps-grid .drawer-app-tile')];
          return tiles.length >= 1 && tiles.every((t) => /omnicalc/i.test(t.textContent));
        })()`),
      { label: 'Android App Drawer filtered to OmniCalc' }
    );
    await cdp.setInputValue('#drawer-search-input', '');
    await cdp.clickSelector('#btn-close-drawer');

    // Android Recents -> Kill a real running user app PID!
    const launchForKill = await apiJson('/api/v1/packages/com.omnios.calc/launch', {
      method: 'POST',
      body: '{}',
    });
    assert.equal(launchForKill.ok, true);
    const killPid = launchForKill.json.pid;
    assert.ok(Number.isInteger(killPid) && killPid > 1);

    await waitFor(
      async () =>
        cdp.evaluate(`Boolean(document.querySelector('.omni-window[data-pid="${killPid}"]'))`),
      { label: 'Running user app mounted before opening Android Recents' }
    );

    await cdp.clickSelector('#btn-android-recents');
    await waitFor(
      async () =>
        cdp.evaluate(`Boolean(
          document.getElementById('android-recents').getAttribute('data-open') === 'true' &&
          document.querySelector('#recents-cards [data-recents-kill-pid="${killPid}"]')
        )`),
      { label: 'Android Recents card with real PID kill button rendered' }
    );

    await cdp.clickSelector(`#recents-cards [data-recents-kill-pid="${killPid}"]`);
    await waitFor(
      async () => {
        const procs = (await apiJson('/api/v1/processes')).json?.processes ?? [];
        const stillAlive = procs.some(
          (p) => p.pid === killPid && p.state !== 'TERMINATED' && p.state !== 'ZOMBIE'
        );
        const winGone = await cdp.evaluate(`!document.querySelector('.omni-window[data-pid="${killPid}"]')`);
        return !stillAlive && winGone;
      },
      { label: 'Android Recents killed real kernel PID and closed its window' }
    );
    await cdp.clickSelector('#btn-close-recents');
  });

  // =========================================================================
  // Suite 7: Live Overlays (Spotlight Ctrl+Space, Intent Chooser, Permission Prompt, Binary Upload)
  // =========================================================================
  it('Suite 7: operates Spotlight (Ctrl+Space), Share Sheet Chooser, Permission Prompt & Binary Upload (F-077, F-081, F-082, F-083)', async () => {
    await cdp.clickSelector('#shell-mode-switcher [data-shell-mode-btn="unified"]');
    await waitFor(
      async () => cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-shell-mode') === 'unified'`),
      { label: 'Returned to unified mode' }
    );

    // --- 7A. Spotlight via real CDP Ctrl+Space keystroke ---
    await cdp.send('Input.dispatchKeyEvent', {
      type: 'rawKeyDown',
      modifiers: 2, // Ctrl
      windowsVirtualKeyCode: 32,
      nativeVirtualKeyCode: 32,
      key: ' ',
      code: 'Space',
    });
    await cdp.send('Input.dispatchKeyEvent', {
      type: 'keyUp',
      modifiers: 2,
      windowsVirtualKeyCode: 32,
      nativeVirtualKeyCode: 32,
      key: ' ',
      code: 'Space',
    });

    await waitFor(
      async () => cdp.evaluate(`document.getElementById('spotlight-overlay').getAttribute('data-open') === 'true'`),
      { label: 'Spotlight opened via CDP Ctrl+Space' }
    );

    const themeBefore = await cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-theme')`);
    await cdp.setInputValue('#spotlight-input', 'Toggle Dark');
    await waitFor(
      async () =>
        cdp.evaluate(`Boolean(document.querySelector('#spotlight-results .spotlight-item[data-result-id="action:toggle-theme"]'))`),
      { label: 'Spotlight live /api/v1/search toggle-theme quick action rendered' }
    );
    await cdp.clickSelector('#spotlight-results .spotlight-item[data-result-id="action:toggle-theme"]');

    const expectedTheme = themeBefore === 'dark' ? 'light' : 'dark';
    await waitFor(
      async () => {
        const domTheme = await cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-theme')`);
        const cfgTheme = (await apiJson('/api/v1/config/system')).json?.system?.['system.theme'];
        return domTheme === expectedTheme && cfgTheme === expectedTheme;
      },
      { label: 'Spotlight quick action toggled theme in DOM and kernel config' }
    );
    // Restore dark theme
    if (expectedTheme !== 'dark') {
      await cdp.clickSelector('#btn-theme-toggle');
      await waitFor(
        async () => cdp.evaluate(`document.getElementById('omni-shell').getAttribute('data-theme') === 'dark'`),
        { label: 'Restored dark theme' }
      );
    }

    // --- 7B. Universal Share Sheet / Intent Chooser (`intent:chooser` -> click candidate -> delivered) ---
    // Register a genuine second text/plain send handler (win.win-notepad alongside com.omnios.notes)
    omniOS.intentRouter.registerHandlers(
      'win.win-notepad',
      [{ actions: ['send', 'view'], mimeTypes: ['text/plain'], extensions: ['.txt'], priority: 10 }],
      { platform: 'windows', label: 'Win32 Notepad' }
    );
    const dispatchRes = await apiJson('/api/v1/ipc/intents/dispatch', {
      method: 'POST',
      body: JSON.stringify({
        action: 'send',
        mimeType: 'text/plain',
        extras: { text: 'Cross-platform M6 share payload' },
      }),
    });
    assert.equal(dispatchRes.ok, true);
    assert.equal(dispatchRes.json.status, 'CHOOSER_REQUIRED', 'Multi-handler intent must require Share Sheet chooser');

    const candidateIds = await waitFor(
      async () => {
        const open = await cdp.evaluate(`document.getElementById('intent-chooser-modal').getAttribute('data-open')`);
        if (open !== 'true') return null;
        const ids = await cdp.evaluate(`[...document.querySelectorAll('#chooser-candidates [data-chooser-app-id]')].map((b) => b.getAttribute('data-chooser-app-id'))`);
        return ids.length >= 2 ? ids : null;
      },
      { label: 'Intent Chooser modal opened automatically via /ws with >= 2 candidates' }
    );
    assert.ok(candidateIds.includes('win.win-notepad'), 'Chooser must list win.win-notepad');

    await cdp.clickSelector('#chooser-candidates [data-chooser-app-id="win.win-notepad"]');
    await waitFor(
      async () => {
        const closed = await cdp.evaluate(`document.getElementById('intent-chooser-modal').getAttribute('data-open') === 'false'`);
        const launched = await cdp.evaluate(`Boolean(document.querySelector('.omni-window[data-app-id="win.win-notepad"]'))`);
        return closed && launched;
      },
      { label: 'Intent Chooser closed and chosen app launched' }
    );
    await closeAllWindows();

    // --- 7C. Live Security & Permission Prompt Modal (`permission:prompt` -> Allow -> Audit Log) ---
    omniOS.permissions.setGrant('com.omnios.calc', 'camera.device', 'prompt', { source: 'test' });
    const permPromise = omniOS.permissions.checkPermission({
      appId: 'com.omnios.calc',
      platform: 'android',
      capability: 'camera.device',
      nativePermission: 'android.permission.CAMERA',
      context: { reason: 'M6 live permission prompt verification' },
      timeoutMs: 12_000,
    });

    await waitFor(
      async () =>
        cdp.evaluate(`(() => {
          const modal = document.getElementById('permission-modal');
          if (!modal || modal.getAttribute('data-open') !== 'true') return false;
          const cap = document.getElementById('perm-capability')?.textContent || '';
          const nat = document.getElementById('perm-native')?.textContent || '';
          return cap === 'camera.device' && nat === 'android.permission.CAMERA';
        })()`),
      { label: 'Permission modal opened automatically via /ws with capability details' }
    );

    await cdp.clickSelector('#btn-perm-allow');
    const permResult = await permPromise;
    assert.equal(permResult.granted, true, 'Clicking Allow must resolve checkPermission with granted=true');

    await waitFor(
      async () => cdp.evaluate(`document.getElementById('permission-modal').getAttribute('data-open') === 'false'`),
      { label: 'Permission modal closed after decision' }
    );

    const auditRes = await apiJson('/api/v1/security/audit?appId=com.omnios.calc&limit=20');
    assert.equal(auditRes.ok, true);
    const auditEntries = auditRes.json?.entries ?? auditRes.json?.audit ?? [];
    assert.ok(
      auditEntries.some((e) => e.appId === 'com.omnios.calc' && e.capability === 'camera.device' && e.granted === true),
      'Security audit log must record the live permission allow decision'
    );

    // --- 7D. Binary Package Upload (`#upload-modal` + real CDP `DOM.setFileInputFiles`) ---
    // Uninstall universal-canvas first so upload genuinely installs it fresh
    await apiJson('/api/v1/packages/com.omnios.universal.canvas', { method: 'DELETE' });
    const preUploadPkgs = (await apiJson('/api/v1/packages')).json?.packages ?? [];
    assert.equal(
      preUploadPkgs.some((p) => p.appId === 'com.omnios.universal.canvas'),
      false,
      'universal-canvas should be uninstalled before testing live binary upload'
    );

    await cdp.clickSelector('#btn-upload-pkg');
    await waitFor(
      async () => cdp.evaluate(`document.getElementById('upload-modal').getAttribute('data-open') === 'true'`),
      { label: 'Package upload modal opened' }
    );

    const docNode = await cdp.send('DOM.getDocument', { depth: -1 });
    const fileInputQuery = await cdp.send('DOM.querySelector', {
      nodeId: docNode.root.nodeId,
      selector: '#package-file-input',
    });
    assert.ok(fileInputQuery.nodeId > 0, '#package-file-input must exist in DOM');

    await cdp.send('DOM.setFileInputFiles', {
      nodeId: fileInputQuery.nodeId,
      files: [path.join(PACKAGES_DIR, 'universal-canvas.uapp')],
    });

    const previewText = await waitFor(
      async () => {
        const txt = await cdp.evaluate(`document.getElementById('upload-inspection-preview')?.textContent || ''`);
        const disabled = await cdp.evaluate(`document.getElementById('btn-upload-install')?.disabled`);
        return txt.includes('com.omnios.universal.canvas') && txt.includes('universal-uapp') && !disabled
          ? txt
          : null;
      },
      { label: 'Upload inspector preview rendered real /api/v1/packages/inspect metadata' }
    );
    assert.match(previewText, /SHA-256/i);
    assert.match(previewText, /wasm/i);

    await cdp.clickSelector('#btn-upload-install');
    await waitFor(
      async () => {
        const pkgs = (await apiJson('/api/v1/packages')).json?.packages ?? [];
        const status = await cdp.evaluate(`document.getElementById('upload-status')?.textContent || ''`);
        return /Installed/i.test(status) && pkgs.some((p) => p.appId === 'com.omnios.universal.canvas');
      },
      { label: 'Uploaded binary package genuinely installed in PackageManager' }
    );
    await cdp.clickSelector('#btn-upload-close');

    // --- 7E. Drag-and-Drop binary upload overlay + inspection + install (`win-sysinfo.exe`) ---
    const winSysInfoBytes = await fsp.readFile(path.join(PACKAGES_DIR, 'win-sysinfo.exe'));
    const dragOk = await cdp.evaluate(`(() => {
      const bytes = Uint8Array.from(atob(${JSON.stringify(winSysInfoBytes.toString('base64'))}), (c) => c.charCodeAt(0));
      const dt = new DataTransfer();
      dt.items.add(new File([bytes], 'win-sysinfo.exe', { type: 'application/octet-stream' }));
      window.dispatchEvent(new DragEvent('dragenter', { bubbles: true, cancelable: true, dataTransfer: dt }));
      const activeDuringDrag = document.getElementById('upload-drop-overlay')?.getAttribute('data-active') === 'true';
      window.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: dt }));
      const inactiveAfterDrop = document.getElementById('upload-drop-overlay')?.getAttribute('data-active') === 'false';
      return { activeDuringDrag, inactiveAfterDrop };
    })()`);
    assert.equal(dragOk.activeDuringDrag, true, 'dragenter must activate #upload-drop-overlay');
    assert.equal(dragOk.inactiveAfterDrop, true, 'drop must dismiss #upload-drop-overlay');

    await waitFor(
      async () => {
        const txt = await cdp.evaluate(`document.getElementById('upload-inspection-preview')?.textContent || ''`);
        return txt.includes('win.win-sysinfo') && txt.includes('windows-pe') && txt.includes('x86_64');
      },
      { label: 'Drag-and-drop win-sysinfo.exe inspected via /api/v1/packages/inspect' }
    );
    await cdp.clickSelector('#btn-upload-install');
    await waitFor(
      async () => {
        const pkgs = (await apiJson('/api/v1/packages')).json?.packages ?? [];
        return pkgs.some((p) => p.appId === 'win.win-sysinfo');
      },
      { label: 'Drag-and-drop win-sysinfo.exe installed in PackageManager' }
    );
    await cdp.clickSelector('#btn-upload-close');
  });

  // =========================================================================
  // Suite 8: XSS Defense & Zero-Error Hygiene
  // =========================================================================
  it('Suite 8: neutralizes XSS payloads across window titles, notifications, VFS files & Spotlight with zero browser errors', async () => {
    const XSS = '<img src=x onerror="window.__xss=1">';

    // 1. VFS file with XSS filename & content under /home/user/Documents/
    omniOS.vfs.writeFile(`/home/user/Documents/${XSS}.txt`, XSS, { uid: 0, gid: 0 });

    // 2. Live window title with XSS payload (launch OmniFiles pointing to /home/user/Documents)
    const launchRes = await apiJson('/api/v1/packages/com.omnios.files/launch', {
      method: 'POST',
      body: JSON.stringify({ preferSystem: true, cwd: '/home/user/Documents' }),
    });
    assert.equal(launchRes.ok, true);
    const filesWinId = await waitFor(
      async () =>
        cdp.evaluate(`document.querySelector('.omni-window[data-app-id="com.omnios.files"]')?.getAttribute('data-window-id') || null`),
      { label: 'OmniFiles window open for XSS test' }
    );

    // Update live window title with XSS payload through the real Compositor
    omniOS.compositor.updateSurface(filesWinId, { title: XSS });
    await waitFor(
      async () =>
        cdp.evaluate(`(document.querySelector('.omni-window[data-window-id="${filesWinId}"] .window-title')?.textContent || '') === ${JSON.stringify(XSS)}`),
      { label: 'XSS window title rendered literally via textContent' }
    );

    // Verify XSS filename rendered literally in OmniFiles listitem
    await waitFor(
      async () =>
        cdp.evaluate(`[...document.querySelectorAll('.omni-window[data-window-id="${filesWinId}"] .listitem-name')].some((el) => el.textContent.includes(${JSON.stringify(XSS)}))`),
      { label: 'XSS VFS filename rendered literally in OmniFiles' }
    );

    // 3. Live notification with XSS title and body
    await apiJson('/api/v1/ipc/notifications', {
      method: 'POST',
      body: JSON.stringify({
        appId: 'com.omnios.calc',
        platform: 'android',
        title: XSS,
        body: XSS,
      }),
    });
    await cdp.clickSelector('#btn-notif-shade');
    await waitFor(
      async () =>
        cdp.evaluate(`[...document.querySelectorAll('#shade-notif-list .notif-title')].some((el) => el.textContent === ${JSON.stringify(XSS)})`),
      { label: 'XSS notification rendered literally via textContent' }
    );
    await cdp.clickSelector('#btn-close-shade');

    // 4. Spotlight search with XSS query matching XSS file
    await cdp.clickSelector('#btn-spotlight');
    await waitFor(
      async () => cdp.evaluate(`document.getElementById('spotlight-overlay').getAttribute('data-open') === 'true'`),
      { label: 'Spotlight opened for XSS test' }
    );
    await cdp.setInputValue('#spotlight-input', 'onerror');
    await waitFor(
      async () =>
        cdp.evaluate(`[...document.querySelectorAll('#spotlight-results .spotlight-item-title')].some((el) => el.textContent.includes('onerror'))`),
      { label: 'XSS filename rendered safely in Spotlight results' }
    );

    // Assert zero injected <img> elements AND window.__xss is strictly undefined
    const xssAudit = await cdp.evaluate(`({
      xssFlag: window.__xss,
      injectedImgs: document.querySelectorAll('#omni-shell img').length,
    })`);
    assert.equal(xssAudit.xssFlag, undefined, 'XSS payload must NEVER execute');
    assert.equal(xssAudit.injectedImgs, 0, 'Zero untrusted <img> elements may be injected into DOM');

    // Close Spotlight & clean up
    await cdp.evaluate(`document.getElementById('spotlight-overlay')?.click()`);
    await closeAllWindows();

    // Final Zero-Error & Offline Hygiene Assertion across entire test run
    assert.deepEqual(cdp.failedResponses, [], `Unexpected HTTP >=400 responses: ${JSON.stringify(cdp.failedResponses)}`);
    assert.deepEqual(cdp.consoleErrors, [], `Unexpected console errors: ${JSON.stringify(cdp.consoleErrors)}`);
    assert.deepEqual(cdp.pageErrors, [], `Unexpected uncaught page errors: ${JSON.stringify(cdp.pageErrors)}`);
  });

  it('Suite 9: Potato-PC Lite Performance Mode toggles blur/animations off cleanly and persists', async () => {
    const initial = await cdp.evaluate(`({
      perf: document.getElementById('omni-shell')?.getAttribute('data-perf'),
      liteAttr: document.getElementById('omni-shell')?.getAttribute('data-lite-mode'),
      btnPresent: Boolean(document.getElementById('btn-perf-lite-toggle')),
    })`);
    assert.equal(initial.perf, 'standard');
    assert.equal(initial.liteAttr, 'false');
    assert.equal(initial.btnPresent, true);

    await cdp.evaluate(`document.getElementById('btn-perf-lite-toggle').click()`);
    const lite = await cdp.evaluate(`({
      perf: document.getElementById('omni-shell')?.getAttribute('data-perf'),
      liteAttr: document.getElementById('omni-shell')?.getAttribute('data-lite-mode'),
      stored: window.localStorage.getItem('omnios.perfMode'),
      blurVar: getComputedStyle(document.getElementById('omni-shell')).getPropertyValue('--blur-glass').trim(),
      ccBackdrop: getComputedStyle(document.getElementById('ios-control-center')).backdropFilter,
      btnActive: document.getElementById('btn-perf-lite-toggle')?.getAttribute('data-active'),
    })`);
    assert.equal(lite.perf, 'lite');
    assert.equal(lite.liteAttr, 'true');
    assert.equal(lite.stored, 'lite');
    assert.equal(lite.blurVar, 'none');
    assert.equal(lite.ccBackdrop, 'none');
    assert.equal(lite.btnActive, 'true');

    // Toggle back to standard cleanly
    await cdp.evaluate(`document.getElementById('btn-perf-lite-toggle').click()`);
    const restored = await cdp.evaluate(`({
      perf: document.getElementById('omni-shell')?.getAttribute('data-perf'),
      stored: window.localStorage.getItem('omnios.perfMode'),
    })`);
    assert.equal(restored.perf, 'standard');
    assert.equal(restored.stored, 'standard');

    assert.deepEqual(cdp.failedResponses, [], `Unexpected HTTP >=400 responses: ${JSON.stringify(cdp.failedResponses)}`);
    assert.deepEqual(cdp.consoleErrors, [], `Unexpected console errors: ${JSON.stringify(cdp.consoleErrors)}`);
    assert.deepEqual(cdp.pageErrors, [], `Unexpected uncaught page errors: ${JSON.stringify(cdp.pageErrors)}`);
  });
});
