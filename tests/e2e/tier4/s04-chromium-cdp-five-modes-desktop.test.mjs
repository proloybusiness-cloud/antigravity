/**
 * OmniOS Tier 4 E2E Suite — S04: Headless Chromium CDP Live 5-Mode Adaptive Desktop & Multi-Window UX
 * Covers PROJECT.md Features: F-086, F-073, F-074, F-075, F-076, F-077, F-078, F-079, F-080, F-084.
 *
 * Scenarios:
 * - T4-S04-01 (Scenario 7 / F-086): Live Adaptive 5-Mode Shell Tour (`unified`, `windows`, `macos`, `ios`,
 *   `android`) with 3 concurrent multi-platform apps (built-in Notes + dynamic custom Android .apk + real
 *   WASM Canvas2D .uapp), zero console/page/CDN errors, live /ws push, dom1-guarded bidirectional theme sync,
 *   and persistence across full browser page reload.
 * - T4-S04-02 (Scenario 8 / F-086): Live multi-window manipulation (focus raising + real CDP titlebar drag)
 *   and all 4 platform signature UX features: Windows Start Menu + Snap Layouts (left/right tiling geometry),
 *   macOS Global Top Menu Bar focus switch + Floating Dock + Spotlight (`Ctrl+Space` strict `.txt` check),
 *   iOS Dynamic Island expansion + Control Center real Config Store DND toggle, and Android Notification Shade
 *   + 3-Button Nav Recents real PID termination.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Server-first lazy init (`startOmniServer()` BEFORE `launchBrowser()`): 0 Chromium spawns & 0 temp leaks
 *   when os/ is absent.
 * - Zero hardcoded system app IDs, zero undocumented capability strings, zero skips, zero swallowed assertions.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  REPO_ROOT,
  startOmniServer,
} from '../lib/env.mjs';
import { launchBrowser } from '../lib/cdp-client.mjs';
import { buildCustomApk } from '../lib/fixtures-android-win.mjs';

function makeNonce(bytes = 4) {
  return crypto.randomBytes(bytes).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(fn, { timeoutMs = 8000, intervalMs = 60, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const val = await fn();
      if (val) return val;
    } catch (err) {
      lastError = err;
    }
    const remaining = deadline - Date.now();
    if (remaining > 0) await sleep(Math.min(intervalMs, remaining));
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for ${label}` +
    (lastError ? ` (last error: ${lastError.message})` : '')
  );
}

async function readNonEmptyFile(filePath, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const buf = await fs.readFile(filePath);
    if (buf.length > 0) return buf;
    if (attempt < retries) await sleep(60);
  }
  const finalBuf = await fs.readFile(filePath);
  assert.ok(finalBuf.length > 0, `Expected non-empty package file at ${filePath}`);
  return finalBuf;
}

function asArray(payload, keys = ['windows', 'packages', 'apps', 'catalog', 'processes', 'notifications', 'items', 'data', 'entries']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return [];
}

function unwrapSnapshot(json) {
  return json?.snapshot ?? json?.data ?? json ?? {};
}

function getWinId(w) {
  return w?.windowId ?? w?.id ?? null;
}

function getXY(win) {
  return {
    x: win?.bounds?.x ?? win?.x,
    y: win?.bounds?.y ?? win?.y,
  };
}

function getBounds(win) {
  const b = win?.bounds ?? win ?? {};
  return {
    x: Number(b.x),
    y: Number(b.y),
    width: Number(b.width),
    height: Number(b.height),
  };
}

function extractProcState(json) {
  return json?.state ?? json?.process?.state ?? json?.pcb?.state ?? json?.data?.state ?? null;
}

function assertAliveState(state, label) {
  assert.ok(
    typeof state === 'string' && state.length > 0 && state !== 'TERMINATED' && state !== 'ZOMBIE',
    `Expected live non-terminated process state for ${label}, got ${JSON.stringify(state)}`
  );
}

async function writeWithMethodFallback(api, methods, urlPath, body, opts = {}) {
  let lastRes = null;
  for (const method of methods) {
    const res = await api.request(method, urlPath, { ...opts, body });
    lastRes = res;
    if (res.ok) return res;
    if (res.status !== 404 && res.status !== 405) return res;
  }
  return lastRes;
}

async function installPackageHttp(api, bytes, filename, { grantAll = true } = {}) {
  let res = await api.post('/api/v1/packages/install', bytes, {
    query: { filename, grantAll: grantAll ? 'true' : 'false' },
    headers: {
      'content-type': 'application/octet-stream',
      'x-filename': filename,
    },
  });
  if (res.status === 400 || res.status === 415 || res.status === 422) {
    const b64 = Buffer.from(bytes).toString('base64');
    res = await api.post('/api/v1/packages/install', {
      base64: b64,
      data: b64,
      filename,
      grantAll,
    });
  }
  assert.ok(res.ok, `Expected HTTP 2xx installing ${filename}, got ${res.status}: ${res.text}`);
  return res.json;
}

const SYSTEM_APP_ROLES = [
  { role: 'terminal', pattern: /omniterm|terminal/i },
  { role: 'files', pattern: /omnifiles|\bfiles\b/i },
  { role: 'monitor', pattern: /activity[\s_-]*monitor|task[\s_-]*monitor|\bmonitor\b/i },
  { role: 'apphub', pattern: /apphub|app[\s_-]*hub/i },
  { role: 'settings', pattern: /settings|privacy/i },
  { role: 'inspector', pattern: /inspector/i },
  { role: 'notes', pattern: /omninotes|\bnotes\b/i },
];

function normalizeAppEntries(source, { fromInstalled = false } = {}) {
  const out = [];
  if (!source) return out;
  const add = (item, keyHint = '') => {
    if (typeof item === 'string') {
      const id = item.trim();
      if (id) out.push({ appId: id, name: id, platform: '', isBuiltin: false, fromInstalled });
      return;
    }
    if (!item || typeof item !== 'object') return;
    const appId = String(item.appId ?? item.id ?? keyHint ?? '').trim();
    if (!appId) return;
    const name = String(item.name ?? item.title ?? item.displayName ?? item.label ?? '').trim();
    const platform = String(item.platform ?? '').toLowerCase();
    const isBuiltin = Boolean(
      item.builtin ||
      item.builtIn ||
      item.isSystem ||
      item.system ||
      item.kind === 'system' ||
      item.type === 'system' ||
      platform === 'system' ||
      platform === 'omnios'
    );
    out.push({ appId, name, platform, isBuiltin, fromInstalled });
  };

  if (Array.isArray(source)) {
    for (const item of source) add(item);
  } else if (typeof source === 'object') {
    const arr = asArray(source, ['packages', 'apps', 'catalog', 'items', 'data', 'entries']);
    const sysArr = asArray(source, ['systemApps']);
    if (arr.length > 0 || sysArr.length > 0) {
      for (const item of arr) add(item);
      for (const item of sysArr) add(item);
    } else {
      for (const [k, v] of Object.entries(source)) add(v, k);
    }
  }
  return out;
}

async function discoverSystemAppsHttp(api) {
  const candidates = [];
  const pkgRes = await api.get('/api/v1/packages', { expectOk: true });
  candidates.push(...normalizeAppEntries(pkgRes.json, { fromInstalled: true }));
  const catRes = await api.get('/api/v1/packages/catalog');
  if (catRes.ok && catRes.json !== null) {
    candidates.push(...normalizeAppEntries(catRes.json, { fromInstalled: false }));
  }

  const byId = new Map();
  for (const c of candidates) {
    if (!c.appId) continue;
    const prev = byId.get(c.appId);
    if (!prev) {
      byId.set(c.appId, { ...c });
    } else {
      byId.set(c.appId, {
        appId: c.appId,
        name: prev.name || c.name,
        platform: prev.platform || c.platform,
        isBuiltin: prev.isBuiltin || c.isBuiltin,
        fromInstalled: prev.fromInstalled || c.fromInstalled,
      });
    }
  }

  const list = Array.from(byId.values());
  const resolved = {};
  const used = new Set();

  for (const { role, pattern } of SYSTEM_APP_ROLES) {
    const roleEndRe = new RegExp(`(?:^|[._-])${role}$`, 'i');
    const matches = list
      .filter((c) => !used.has(c.appId) && (pattern.test(c.appId) || pattern.test(c.name)))
      .map((c) => {
        let score = 0;
        if (c.fromInstalled) score += 200;
        if (c.isBuiltin) score += 60;
        if (roleEndRe.test(c.appId)) score += 30;
        if (!c.platform || c.platform === 'system' || c.platform === 'universal' || c.platform === 'omnios') score += 20;
        if (/sharer/i.test(`${c.appId} ${c.name}`)) score -= 40;
        return { c, score };
      })
      .sort((a, b) => b.score - a.score);

    assert.ok(
      matches.length > 0,
      `Expected built-in system app for role "${role}" in /api/v1/packages, candidates: ${JSON.stringify(list)}`
    );
    resolved[role] = matches[0].c.appId;
    used.add(matches[0].c.appId);
  }

  assert.equal(new Set(Object.values(resolved)).size, SYSTEM_APP_ROLES.length);
  return resolved;
}

async function getSystemConfig(api) {
  const res = await api.get('/api/v1/config/system', { expectOk: true });
  return res.json?.system ?? res.json?.config ?? res.json?.data ?? res.json ?? {};
}

async function setSystemConfigHttp(api, key, value) {
  const shortKey = key.startsWith('system.') ? key.slice('system.'.length) : key;
  const fullKey = key.startsWith('system.') ? key : `system.${key}`;
  for (const body of [
    { [shortKey]: value },
    { [fullKey]: value },
    { key: fullKey, value },
    { key: shortKey, value },
  ]) {
    const res = await writeWithMethodFallback(api, ['PUT', 'PATCH', 'POST'], '/api/v1/config/system', body);
    if (!res.ok) continue;
    const cfg = await getSystemConfig(api);
    if ((cfg[shortKey] ?? cfg[fullKey]) === value) return cfg;
  }
  throw new Error(`Failed to set /api/v1/config/system ${key}=${JSON.stringify(value)}`);
}

async function setShellModeHttp(api, mode) {
  const res = await writeWithMethodFallback(
    api,
    ['POST', 'PUT', 'PATCH'],
    '/api/v1/compositor/shell-mode',
    { mode, shellMode: mode }
  );
  assert.ok(res && res.ok, `Expected HTTP 2xx setting shell-mode=${mode}, got ${res?.status}: ${res?.text}`);
  return res;
}

// ============================================================================
// Hardened Semantic CDP DOM Helpers
// ============================================================================

function assertZeroBrowserErrors(page, contextLabel) {
  const consoleErrs = page.getConsoleErrors();
  const pageErrs = page.getPageErrors();
  assert.equal(
    consoleErrs.length,
    0,
    `[${contextLabel}] Expected 0 browser console errors, got ${consoleErrs.length}: ${JSON.stringify(consoleErrs)}`
  );
  assert.equal(
    pageErrs.length,
    0,
    `[${contextLabel}] Expected 0 uncaught page exceptions, got ${pageErrs.length}: ${JSON.stringify(pageErrs)}`
  );
}

async function waitForShellRendered(page) {
  await page.waitForFunction(() => {
    const body = document.body;
    return Boolean(body && (body.innerText || '').trim().length > 0 && document.readyState === 'complete');
  }, { timeoutMs: 10000 });
}

/**
 * Innermost-area visible control discovery:
 * Priority 1: data-* selectors -> Priority 2: ARIA -> Priority 3: smallest bounding-box area visible text
 * (excluding container wrappers >= 75% of viewport).
 */
async function findVisibleControl(page, {
  dataSelectors = [],
  ariaPatterns = [],
  textPatterns = [],
  tags = 'button, [role="button"], [role="tab"], [role="switch"], [role="menuitem"], [role="option"], a, select, input, label',
  scopeSelector = null,
  excludeDataSelector = null,
  excludeSelector = null,
  allowInExcludedSelector = null,
} = {}) {
  return await page.evalFn((spec) => {
    function isTrulyVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      let p = el.parentElement;
      while (p && p.nodeType === 1) {
        const ps = window.getComputedStyle(p);
        if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
        p = p.parentElement;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    function describe(el) {
      el.scrollIntoView({ block: 'center', inline: 'center' });
      const r = el.getBoundingClientRect();
      return {
        found: true,
        x: r.left + r.width / 2,
        y: r.top + r.height / 2,
        tag: el.tagName.toLowerCase(),
        text: String(el.innerText || el.textContent || el.value || '').trim().slice(0, 80),
        aria: el.getAttribute('aria-label') || el.getAttribute('title') || '',
        rect: { left: r.left, top: r.top, width: r.width, height: r.height },
      };
    }

    const root = spec.scopeSelector ? document.querySelector(spec.scopeSelector) : document;
    if (!root) return { found: false, visibleControlsSample: [`scope missing: ${spec.scopeSelector}`] };

    // Priority 1: data-* selectors (smallest area if multiple match)
    for (const sel of spec.dataSelectors || []) {
      const hits = Array.from(root.querySelectorAll(sel)).filter((el) => {
        if (!isTrulyVisible(el)) return false;
        if (spec.excludeDataSelector && el.closest(spec.excludeDataSelector)) return false;
        return true;
      });
      if (hits.length > 0) {
        hits.sort((a, b) => {
          const ra = a.getBoundingClientRect();
          const rb = b.getBoundingClientRect();
          return (ra.width * ra.height) - (rb.width * rb.height);
        });
        return describe(hits[0]);
      }
    }

    const candidates = Array.from(root.querySelectorAll(spec.tags)).filter((el) => {
      if (!isTrulyVisible(el)) return false;
      if (spec.excludeDataSelector && el.closest(spec.excludeDataSelector)) return false;
      if (spec.excludeSelector && el.closest(spec.excludeSelector)) {
        if (!spec.allowInExcludedSelector || !el.matches(spec.allowInExcludedSelector)) {
          return false;
        }
      }
      return true;
    });

    // Priority 2: ARIA aria-label / title (tested separately & trimmed so anchored ^...$ patterns match cleanly)
    const ariaRes = (spec.ariaPatterns || []).map((p) => new RegExp(p, 'i'));
    for (const re of ariaRes) {
      const hit = candidates.find((el) =>
        [el.getAttribute('aria-label'), el.getAttribute('title')].some((v) => v && re.test(v.trim()))
      );
      if (hit) return describe(hit);
    }

    // Priority 3: smallest bounding-box area visible text (excluding near-full-viewport wrappers)
    const containerTags = new Set(['div', 'section', 'article', 'main', 'aside', 'header', 'footer', 'nav', 'body', 'html']);
    const vpArea = Math.max(1, window.innerWidth * window.innerHeight);
    const textRes = (spec.textPatterns || []).map((p) => new RegExp(p, 'i'));
    for (const re of textRes) {
      let best = null;
      let bestArea = Infinity;
      for (const el of candidates) {
        const t = String(el.innerText || el.textContent || el.value || '').trim();
        if (!t || !re.test(t)) continue;
        const r = el.getBoundingClientRect();
        const area = r.width * r.height;
        const tag = el.tagName.toLowerCase();
        if (containerTags.has(tag) && area >= vpArea * 0.75) continue;
        if (area < bestArea || (area === bestArea && best && best.contains(el))) {
          bestArea = area;
          best = el;
        }
      }
      if (best) return describe(best);
    }

    const sample = candidates.slice(0, 35).map((el) => ({
      tag: el.tagName.toLowerCase(),
      text: String(el.innerText || el.textContent || el.value || '').trim().slice(0, 40),
      aria: el.getAttribute('aria-label') || el.getAttribute('title') || '',
      data: Object.fromEntries(Array.from(el.attributes).filter((a) => a.name.startsWith('data-')).map((a) => [a.name, a.value])),
    }));
    return { found: false, visibleControlsSample: sample };
  }, {
    dataSelectors,
    ariaPatterns,
    textPatterns,
    tags,
    scopeSelector,
    excludeDataSelector,
    excludeSelector,
    allowInExcludedSelector,
  });
}

async function clickSemanticControl(page, spec, label, timeoutMs = 6000) {
  let lastResult = null;
  const hit = await waitUntil(async () => {
    lastResult = await findVisibleControl(page, spec);
    return lastResult?.found ? lastResult : null;
  }, { timeoutMs, intervalMs: 80, label }).catch((err) => {
    throw new Error(
      `${err.message}\nVisible interactive controls sample: ${JSON.stringify(lastResult?.visibleControlsSample ?? [])}`
    );
  });
  await page.clickAt(hit.x, hit.y);
  return hit;
}

/**
 * Hardened live desktop window finder:
 * - Never falls back to Dock/Taskbar/Desktop chrome on disappearance once [data-window-id] is used!
 * - Excludes Recents overlay cards, Dock, Taskbar, Menu Bar, and nav/footer chrome.
 */
async function findVisibleWindow(page, { windowId = null, titleSubstring = null, strictWindowId = false } = {}) {
  return await page.evalFn((opts) => {
    const CHROME_EXCLUDE_SEL =
      '[data-recents-overlay], [data-overlay="recents"], [data-recents-card], [data-dock], [data-taskbar], [data-menubar], [data-menu-bar], [data-desktop-icons], [data-start-menu], nav, footer';
    const LEAF_CONTROL_SEL =
      'button, a, input, select, option, [role="button"], [role="tab"], [role="menuitem"]';

    function isVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      let p = el.parentElement;
      while (p && p.nodeType === 1) {
        const ps = window.getComputedStyle(p);
        if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
        p = p.parentElement;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    function pickLargestWindow(matches) {
      if (matches.length === 0) return null;
      const nonVp = matches.filter((el) => {
        const r = el.getBoundingClientRect();
        return !(r.width >= window.innerWidth * 0.98 && r.height >= window.innerHeight * 0.98);
      });
      const pool = nonVp.length > 0 ? nonVp : matches;
      pool.sort((a, b) => {
        const ra = a.getBoundingClientRect();
        const rb = b.getBoundingClientRect();
        return (rb.width * rb.height) - (ra.width * ra.height);
      });
      return pool[0];
    }

    let winEl = null;
    let matchedByWindowId = false;

    if (opts.windowId) {
      const escId = String(opts.windowId).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      for (const sel of [
        `[data-window-id="${escId}"]`,
        `[data-win-id="${escId}"]`,
        `[id="${escId}"]`,
      ]) {
        const matches = Array.from(document.querySelectorAll(sel)).filter(
          (el) =>
            el !== document.documentElement &&
            el !== document.body &&
            !el.matches(LEAF_CONTROL_SEL) &&
            !el.closest(CHROME_EXCLUDE_SEL) &&
            isVisible(el)
        );
        const picked = pickLargestWindow(matches);
        if (picked) {
          winEl = picked;
          matchedByWindowId = true;
          break;
        }
      }
    }

    // Disappearance guard: once desktop windows use [data-window-id]/[data-win-id], NEVER fall back to titleSubstring!
    const pageUsesWindowIdAttr = Array.from(document.querySelectorAll('[data-window-id], [data-win-id]')).some(
      (el) => !el.matches(LEAF_CONTROL_SEL) && !el.closest(CHROME_EXCLUDE_SEL)
    );
    const allowTitleFallback = Boolean(
      !winEl &&
      opts.titleSubstring &&
      !opts.strictWindowId &&
      !(opts.windowId && pageUsesWindowIdAttr)
    );

    if (allowTitleFallback) {
      const needle = opts.titleSubstring.toLowerCase();
      const all = Array.from(document.querySelectorAll('section, article, div, [role="dialog"], [role="region"]'));
      let best = null;
      let bestArea = Infinity;
      for (const el of all) {
        if (!isVisible(el) || el.closest(CHROME_EXCLUDE_SEL) || el.closest('[data-overlay]')) continue;
        const r = el.getBoundingClientRect();
        if (r.width < 160 || r.height < 100) continue;
        if (r.width >= window.innerWidth * 0.98 && r.height >= window.innerHeight * 0.98) continue;
        const txt = (el.innerText || '').toLowerCase();
        if (!txt.includes(needle)) continue;
        const area = r.width * r.height;
        if (area < bestArea) {
          bestArea = area;
          best = el;
        }
      }
      winEl = best;
    }

    if (!winEl) return { found: false, matchedByWindowId: false };
    const r = winEl.getBoundingClientRect();
    const st = window.getComputedStyle(winEl);
    const zIndex = Number.parseInt(st.zIndex, 10);

    const header = winEl.querySelector('[data-window-titlebar], [data-titlebar], header, [role="heading"]');
    const hr = header && isVisible(header) ? header.getBoundingClientRect() : null;
    const titleBarCenter = hr
      ? { x: hr.left + hr.width * 0.5, y: hr.top + Math.min(hr.height * 0.5, 16) }
      : { x: r.left + r.width * 0.5, y: r.top + 16 };

    const canvas = winEl.querySelector('canvas');
    const cr = canvas && isVisible(canvas) ? canvas.getBoundingClientRect() : null;
    const chromeButtons = Array.from(winEl.querySelectorAll('button, [role="button"]')).filter((b) => {
      if (!isVisible(b)) return false;
      const br = b.getBoundingClientRect();
      return br.top <= r.top + 48;
    });

    return {
      found: true,
      matchedByWindowId,
      rect: { left: r.left, top: r.top, width: r.width, height: r.height },
      titleBarCenter,
      zIndex: Number.isFinite(zIndex) ? zIndex : 0,
      hasCanvas: Boolean(cr),
      canvasRect: cr ? { left: cr.left, top: cr.top, width: cr.width, height: cr.height } : null,
      chromeButtonsCount: chromeButtons.length,
      text: (winEl.innerText || '').slice(0, 400),
    };
  }, { windowId, titleSubstring, strictWindowId });
}

/**
 * Strictly window-scoped <canvas> pixel inspection (never inspects wallpaper/desktop canvas).
 */
async function inspectWindowCanvas(page, { windowId = null, titleSubstring = null } = {}) {
  return await page.evalFn((opts) => {
    const CHROME_EXCLUDE_SEL =
      '[data-recents-overlay], [data-overlay="recents"], [data-recents-card], [data-dock], [data-taskbar], [data-menubar], [data-menu-bar], [data-desktop-icons], [data-start-menu], nav, footer';
    const LEAF_CONTROL_SEL =
      'button, a, input, select, option, [role="button"], [role="tab"], [role="menuitem"]';

    function isVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      let p = el.parentElement;
      while (p && p.nodeType === 1) {
        const ps = window.getComputedStyle(p);
        if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
        p = p.parentElement;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    function pickLargestWindow(matches) {
      if (matches.length === 0) return null;
      const nonVp = matches.filter((el) => {
        const r = el.getBoundingClientRect();
        return !(r.width >= window.innerWidth * 0.98 && r.height >= window.innerHeight * 0.98);
      });
      const pool = nonVp.length > 0 ? nonVp : matches;
      pool.sort((a, b) => {
        const ra = a.getBoundingClientRect();
        const rb = b.getBoundingClientRect();
        return (rb.width * rb.height) - (ra.width * ra.height);
      });
      return pool[0];
    }

    let winEl = null;
    if (opts.windowId) {
      const escId = String(opts.windowId).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      for (const sel of [
        `[data-window-id="${escId}"]`,
        `[data-win-id="${escId}"]`,
        `[id="${escId}"]`,
      ]) {
        const matches = Array.from(document.querySelectorAll(sel)).filter(
          (el) =>
            el !== document.documentElement &&
            el !== document.body &&
            !el.matches(LEAF_CONTROL_SEL) &&
            !el.closest(CHROME_EXCLUDE_SEL) &&
            isVisible(el)
        );
        const picked = pickLargestWindow(matches);
        if (picked) {
          winEl = picked;
          break;
        }
      }
    }

    const pageUsesWindowIdAttr = Array.from(document.querySelectorAll('[data-window-id], [data-win-id]')).some(
      (el) => !el.matches(LEAF_CONTROL_SEL) && !el.closest(CHROME_EXCLUDE_SEL)
    );
    if (!winEl && opts.titleSubstring && !(opts.windowId && pageUsesWindowIdAttr)) {
      const needle = opts.titleSubstring.toLowerCase();
      let best = null;
      let bestArea = Infinity;
      for (const el of document.querySelectorAll('section, article, div, [role="dialog"], [role="region"]')) {
        if (!isVisible(el) || el.closest(CHROME_EXCLUDE_SEL)) continue;
        const r = el.getBoundingClientRect();
        if (r.width < 160 || r.height < 100) continue;
        if (r.width >= window.innerWidth * 0.98 && r.height >= window.innerHeight * 0.98) continue;
        if (!(el.innerText || '').toLowerCase().includes(needle)) continue;
        const area = r.width * r.height;
        if (area < bestArea) {
          bestArea = area;
          best = el;
        }
      }
      winEl = best;
    }

    if (!winEl) return { found: false, reason: 'window container not found' };
    const canvas = Array.from(winEl.querySelectorAll('canvas')).find(isVisible) || null;
    if (!canvas) return { found: false, reason: 'visible canvas not found inside window container' };
    const ctx = canvas.getContext('2d');
    if (!ctx || canvas.width === 0 || canvas.height === 0) {
      return { found: true, width: canvas.width, height: canvas.height, nonZeroPixels: 0 };
    }
    const img = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
    let nonZero = 0;
    for (let i = 0; i < img.length; i += 4) {
      if (img[i] !== 0 || img[i + 1] !== 0 || img[i + 2] !== 0 || img[i + 3] !== 0) {
        nonZero++;
        if (nonZero > 20) break;
      }
    }
    return { found: true, width: canvas.width, height: canvas.height, nonZeroPixels: nonZero };
  }, { windowId, titleSubstring });
}

/**
 * Hardened non-vacuous shell-mode DOM check:
 * - Strictly EXCLUDES interactive switcher controls (`button, a, option, input, select, [role="button"], ...`)
 *   from container attribute checks so unselected mode buttons can NEVER cause a false pass!
 * - Accepts ONLY non-interactive shell containers with matching mode attr/class, OR explicitly active
 *   mode switcher controls (`aria-pressed="true"`, `aria-selected="true"`, `aria-current="true"`, `.active`,
 *   `:checked`), OR a shell-mode `<select>` whose `.value` matches `mode`.
 */
async function domReflectsMode(page, mode) {
  return await page.evalFn((targetMode) => {
    const INTERACTIVE_SEL =
      'button, a, option, input, select, [role="button"], [role="tab"], [role="option"], [role="menuitem"], [role="radio"]';
    const WINDOW_EXCLUDE_SEL = '[data-window-id], [data-win-id]';
    const modeTokenRe = new RegExp(`(?:^|[\\s_-])${targetMode}(?:$|[\\s_-])`, 'i');

    function isTrulyVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      let p = el.parentElement;
      while (p && p.nodeType === 1) {
        const ps = window.getComputedStyle(p);
        if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
        p = p.parentElement;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    // 1. Non-interactive shell root/container elements (excluding app windows & hidden non-root sections!)
    const containerSet = new Set([
      document.documentElement,
      document.body,
      ...Array.from(document.querySelectorAll('[data-shell-root], [data-shell-mode], [data-mode], main, #app')),
    ]);
    for (const el of containerSet) {
      if (!el || el.nodeType !== 1) continue;
      if (el.matches(INTERACTIVE_SEL)) continue;
      const isRoot = el === document.documentElement || el === document.body;
      if (!isRoot) {
        if (el.closest(WINDOW_EXCLUDE_SEL)) continue;
        if (!isTrulyVisible(el)) continue;
      }
      const dsShell = String(el.getAttribute('data-shell-mode') || '').trim().toLowerCase();
      const dsMode = String(el.getAttribute('data-mode') || '').trim().toLowerCase();
      const cls = String(el.className || '');
      if (dsShell === targetMode || dsMode === targetMode || modeTokenRe.test(cls)) {
        return true;
      }
    }

    // 2. Explicitly ACTIVE, visible shell-level mode switcher controls ONLY (excluding app windows!)
    const modeControls = document.querySelectorAll(
      `[data-shell-mode="${targetMode}"], [data-mode="${targetMode}"], [data-action="shell-mode"][data-value="${targetMode}"]`
    );
    for (const el of modeControls) {
      if (!el.matches(INTERACTIVE_SEL)) continue;
      if (el.closest(WINDOW_EXCLUDE_SEL)) continue;
      if (!isTrulyVisible(el)) continue;
      if (
        el.getAttribute('aria-pressed') === 'true' ||
        el.getAttribute('aria-selected') === 'true' ||
        el.getAttribute('aria-current') === 'true' ||
        (typeof el.matches === 'function' && el.matches(':checked')) ||
        /\b(?:active|selected)\b/i.test(String(el.className || ''))
      ) {
        return true;
      }
    }

    // 3. Visible shell-level <select> switcher (excluded from app windows, must include 'unified' or 'hybrid')
    const knownModes = ['unified', 'windows', 'macos', 'ios', 'android'];
    for (const sel of document.querySelectorAll('select')) {
      if (sel.closest(WINDOW_EXCLUDE_SEL)) continue;
      if (!isTrulyVisible(sel)) continue;
      const optVals = Array.from(sel.options).map((o) => String(o.value || '').trim().toLowerCase());
      const optTexts = Array.from(sel.options).map((o) => String(o.textContent || '').trim().toLowerCase());
      const hasUnifiedOrHybrid =
        optVals.some((v) => v === 'unified' || v === 'hybrid') ||
        optTexts.some((t) => /\b(?:unified|hybrid)\b/i.test(t));
      if (!hasUnifiedOrHybrid) continue;
      const modeOptCount = knownModes.filter((m) => optVals.includes(m)).length;
      if (modeOptCount >= 2 && String(sel.value || '').trim().toLowerCase() === targetMode) {
        return true;
      }
    }

    return false;
  }, mode);
}

async function switchShellModeInUi(page, api, mode) {
  const modeLabelMap = {
    unified: [
      '^(?:[^a-z0-9]*)(?:unified(?:\\s+hybrid)?|hybrid)(?:\\s+(?:shell|mode|desktop))?$',
      '(?:shell|mode)\\s*[:\\-]\\s*(?:unified|hybrid)\\b',
      'switch\\s+to\\s+(?:unified|hybrid)\\b',
    ],
    windows: [
      '^(?:[^a-z0-9]*)(?:windows|win)(?:\\s+(?:shell|mode|desktop))?$',
      '(?:shell|mode)\\s*[:\\-]\\s*windows\\b',
      'switch\\s+to\\s+windows\\b',
    ],
    macos: [
      '^(?:[^a-z0-9]*)(?:macos|mac\\s*os)(?:\\s+(?:shell|mode|desktop))?$',
      '(?:shell|mode)\\s*[:\\-]\\s*(?:macos|mac\\s*os)\\b',
      'switch\\s+to\\s+(?:macos|mac\\s*os)\\b',
    ],
    ios: [
      '^(?:[^a-z0-9]*)ios(?:\\s+(?:shell|mode|mobile))?$',
      '(?:shell|mode)\\s*[:\\-]\\s*ios\\b',
      'switch\\s+to\\s+ios\\b',
    ],
    android: [
      '^(?:[^a-z0-9]*)android(?:\\s+(?:shell|mode|mobile))?$',
      '(?:shell|mode)\\s*[:\\-]\\s*android\\b',
      'switch\\s+to\\s+android\\b',
    ],
  };
  const patterns = modeLabelMap[mode] ?? [mode];

  const btn = await findVisibleControl(page, {
    dataSelectors: [
      `button[data-shell-mode="${mode}"]`,
      `button[data-mode="${mode}"]`,
      `[role="button"][data-shell-mode="${mode}"]`,
      `[role="button"][data-mode="${mode}"]`,
      `[role="tab"][data-shell-mode="${mode}"]`,
      `[role="tab"][data-mode="${mode}"]`,
      `[role="menuitem"][data-shell-mode="${mode}"]`,
      `[data-action="shell-mode"][data-value="${mode}"]`,
    ],
    ariaPatterns: patterns,
    textPatterns: patterns,
    tags: 'button, [role="button"], [role="tab"], [role="menuitem"], [role="radio"], a, label',
    excludeDataSelector: '[data-window-id], [data-win-id]',
    excludeSelector: '[data-menubar], [data-menu-bar], [role="menubar"], [data-dock], [data-desktop-icons], [data-springboard], [data-app-id]',
    allowInExcludedSelector: '[data-shell-mode], [data-action="shell-mode"]',
  });

  if (btn.found) {
    await page.clickAt(btn.x, btn.y);
  } else {
    const selected = await page.evalFn((targetMode, pats) => {
      function isTrulyVisible(el) {
        if (!el || el.nodeType !== 1) return false;
        const st = window.getComputedStyle(el);
        if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
        let p = el.parentElement;
        while (p && p.nodeType === 1) {
          const ps = window.getComputedStyle(p);
          if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
          p = p.parentElement;
        }
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
      }

      const res = pats.map((p) => new RegExp(p, 'i'));
      for (const sel of Array.from(document.querySelectorAll('select'))) {
        if (sel.closest('[data-window-id], [data-win-id]')) continue;
        if (!isTrulyVisible(sel)) continue;
        const optVals = Array.from(sel.options).map((o) => String(o.value || '').trim().toLowerCase());
        const optTexts = Array.from(sel.options).map((o) => String(o.textContent || '').trim().toLowerCase());
        const hasUnifiedOrHybrid =
          optVals.some((v) => v === 'unified' || v === 'hybrid') ||
          optTexts.some((t) => /\b(?:unified|hybrid)\b/i.test(t));
        if (!hasUnifiedOrHybrid) continue;
        const opt = Array.from(sel.options).find(
          (o) =>
            String(o.value || '').trim().toLowerCase() === targetMode ||
            res.some((r) => r.test(String(o.textContent || '').trim()))
        );
        if (opt) {
          sel.value = opt.value;
          sel.dispatchEvent(new Event('input', { bubbles: true }));
          sel.dispatchEvent(new Event('change', { bubbles: true }));
          return true;
        }
      }
      return false;
    }, mode, patterns);
    assert.ok(
      selected,
      `Could not find visible UI shell-mode switcher control for mode "${mode}". Sample: ${JSON.stringify(btn.visibleControlsSample)}`
    );
  }

  // Cross-verify BOTH real backend compositor snapshot AND persisted config store
  await waitUntil(async () => {
    const snapRes = await api.get('/api/v1/compositor/snapshot', { expectOk: true });
    const snap = unwrapSnapshot(snapRes.json);
    const cfg = await getSystemConfig(api);
    const cfgMode = cfg.shellMode ?? cfg['system.shellMode'];
    return snap.shellMode === mode && cfgMode === mode;
  }, { timeoutMs: 6000, label: `backend shellMode === "${mode}"` });

  // Strict non-vacuous DOM mode reflection check
  await waitUntil(async () => await domReflectsMode(page, mode), {
    timeoutMs: 5000,
    label: `hardened domReflectsMode("${mode}")`,
  });
}

/**
 * Hardened Spotlight input focus helper:
 * Checks Spotlight-specific selectors sequentially and NEVER matches arbitrary app-window `input[type="text"]`!
 */
async function focusSpotlightInput(page) {
  return await page.evalFn(() => {
    function isTrulyVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      let p = el.parentElement;
      while (p && p.nodeType === 1) {
        const ps = window.getComputedStyle(p);
        if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
        p = p.parentElement;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    const stages = [
      {
        selector: '[data-spotlight] input, [data-spotlight-input], [data-overlay="spotlight"] input, [data-search-overlay] input',
        allowInsideWindow: false,
      },
      {
        selector: 'input[aria-label*="spotlight" i], input[placeholder*="spotlight" i]',
        allowInsideWindow: false,
      },
      {
        selector: '[role="searchbox"], [role="combobox"], input[type="search"]',
        allowInsideWindow: false,
      },
      {
        selector: 'input[aria-label*="search" i], input[placeholder*="search" i]',
        allowInsideWindow: false,
      },
    ];

    for (const stage of stages) {
      const matches = Array.from(document.querySelectorAll(stage.selector));
      for (const el of matches) {
        if (!isTrulyVisible(el)) continue;
        if (!stage.allowInsideWindow && el.closest('[data-window-id], [data-win-id]')) continue;
        el.focus();
        if (document.activeElement === el) return true;
      }
    }
    return false;
  });
}

const APP_LAUNCHER_RE_SRC = 'omniterm|terminal|omnifiles|\\bfiles\\b|omninotes|\\bnotes\\b|app\\s*hub|apphub|settings|monitor|inspector';

async function captureOverlayBaseline(page, overlaySelectors) {
  return await page.evalFn((selectors, reSrc) => {
    function isVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      let p = el.parentElement;
      while (p && p.nodeType === 1) {
        const ps = window.getComputedStyle(p);
        if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
        p = p.parentElement;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }
    const re = new RegExp(reSrc, 'i');
    const visibleOverlaySigs = [];
    for (const sel of selectors) {
      for (const el of document.querySelectorAll(sel)) {
        if (isVisible(el)) {
          visibleOverlaySigs.push(`${el.tagName}:${el.id}:${el.className}:${(el.innerText || '').trim().slice(0, 80)}`);
        }
      }
    }
    const launcherEls = Array.from(document.querySelectorAll('button, [role="button"], [role="menuitem"], [role="option"], a, li'))
      .filter((el) => isVisible(el) && re.test(`${el.innerText || el.textContent || ''} ${el.getAttribute('aria-label') || ''}`));
    const distinctNames = new Set(
      launcherEls.map((el) => String(el.innerText || el.textContent || el.getAttribute('aria-label') || '').trim().toLowerCase()).filter(Boolean)
    );
    return {
      bodyText: (document.body.innerText || '').trim(),
      visibleOverlaySigs,
      launcherCount: launcherEls.length,
      distinctAppCount: distinctNames.size,
    };
  }, overlaySelectors, APP_LAUNCHER_RE_SRC);
}

async function waitForNewAppOverlay(page, before, overlaySelectors, timeoutMs = 5000) {
  await page.waitForFunction((prev, selectors, reSrc) => {
    function isVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      let p = el.parentElement;
      while (p && p.nodeType === 1) {
        const ps = window.getComputedStyle(p);
        if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
        p = p.parentElement;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }
    const re = new RegExp(reSrc, 'i');
    const curBodyText = (document.body.innerText || '').trim();
    if (curBodyText === prev.bodyText) return false;

    for (const sel of selectors) {
      for (const el of document.querySelectorAll(sel)) {
        if (!isVisible(el)) continue;
        const sig = `${el.tagName}:${el.id}:${el.className}:${(el.innerText || '').trim().slice(0, 80)}`;
        const launchers = Array.from(el.querySelectorAll('button, [role="button"], [role="menuitem"], [role="option"], a, li'))
          .filter((item) => isVisible(item) && re.test(`${item.innerText || item.textContent || ''} ${item.getAttribute('aria-label') || ''}`));
        if (launchers.length >= 2 && !prev.visibleOverlaySigs.includes(sig)) {
          return true;
        }
      }
    }

    const allLaunchers = Array.from(document.querySelectorAll('button, [role="button"], [role="menuitem"], [role="option"], a, li'))
      .filter((el) => isVisible(el) && re.test(`${el.innerText || el.textContent || ''} ${el.getAttribute('aria-label') || ''}`));
    const distinctAfter = new Set(
      allLaunchers.map((el) => String(el.innerText || el.textContent || el.getAttribute('aria-label') || '').trim().toLowerCase()).filter(Boolean)
    );
    return (allLaunchers.length >= prev.launcherCount + 2) ||
      (distinctAfter.size >= Math.max(2, prev.distinctAppCount + 1));
  }, { timeoutMs, args: [before, overlaySelectors, APP_LAUNCHER_RE_SRC] });
}

async function captureRecentsBaseline(page) {
  return await page.evalFn(() => {
    function isVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      let p = el.parentElement;
      while (p && p.nodeType === 1) {
        const ps = window.getComputedStyle(p);
        if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
        p = p.parentElement;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    const preCloseCenters = [];
    for (const btn of document.querySelectorAll('button, [role="button"]')) {
      if (!isVisible(btn)) continue;
      const txt = String(btn.innerText || btn.textContent || '').trim();
      const aria = `${btn.getAttribute('aria-label') || ''} ${btn.getAttribute('title') || ''}`;
      if (/close|kill|dismiss|×|x|✕|✖/i.test(`${txt} ${aria}`)) {
        const r = btn.getBoundingClientRect();
        preCloseCenters.push({ x: r.left + r.width / 2, y: r.top + r.height / 2 });
      }
    }

    const preVisibleDialogs = [];
    for (const el of document.querySelectorAll('[role="dialog"], [role="list"], [data-overlay]')) {
      if (isVisible(el)) {
        preVisibleDialogs.push(`${el.tagName}:${el.id}:${el.className}:${(el.innerText || '').trim().slice(0, 80)}`);
      }
    }

    return { preCloseCenters, preVisibleDialogs };
  });
}

/**
 * Hardened Android Recents dismiss finder:
 * - Explicitly ALLOWS Recents cards carrying `data-window-id` inside `[data-recents-overlay]` (and inside
 *   newly appeared Recents overlays) while STRICTLY rejecting live desktop app window titlebar `×`!
 */
async function findRecentsDismissControl(page, baseline, { windowId, notesPid, notesTitle, notesAppId }) {
  return await page.evalFn((base, opts) => {
    function isVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      let p = el.parentElement;
      while (p && p.nodeType === 1) {
        const ps = window.getComputedStyle(p);
        if (ps.display === 'none' || ps.visibility === 'hidden' || !(parseFloat(ps.opacity) > 0)) return false;
        p = p.parentElement;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    const EXPLICIT_RECENTS_SEL =
      '[data-recents-overlay], [data-overlay="recents"], [data-recents], [data-recents-list], [data-recents-pid], [data-recents-card]';

    function isInsideExplicitRecents(el) {
      return Boolean(el && el.nodeType === 1 && el.closest(EXPLICIT_RECENTS_SEL));
    }

    function isInsideLiveWindow(el, stopAtContainer = null) {
      let cur = el;
      while (cur && cur.nodeType === 1) {
        if (stopAtContainer && cur === stopAtContainer) return false;
        if (
          cur.hasAttribute('data-recents-card') ||
          cur.hasAttribute('data-recents-pid') ||
          cur.hasAttribute('data-recents-overlay') ||
          cur.getAttribute('data-overlay') === 'recents' ||
          cur.hasAttribute('data-recents') ||
          cur.hasAttribute('data-recents-list')
        ) {
          return false;
        }
        if (cur.hasAttribute('data-window-titlebar') || cur.hasAttribute('data-titlebar')) {
          return true;
        }
        if (
          !stopAtContainer &&
          !isInsideExplicitRecents(cur) &&
          opts.windowId &&
          (cur.getAttribute('data-window-id') === String(opts.windowId) ||
            cur.getAttribute('data-win-id') === String(opts.windowId))
        ) {
          return true;
        }
        cur = cur.parentElement;
      }
      return false;
    }

    function matchesPreCloseCenter(btn) {
      const r = btn.getBoundingClientRect();
      const cx = r.left + r.width / 2;
      const cy = r.top + r.height / 2;
      return base.preCloseCenters.some((pt) => Math.abs(pt.x - cx) <= 10 && Math.abs(pt.y - cy) <= 10);
    }

    function hasDifferentPid(el) {
      if (!el || el.nodeType !== 1) return false;
      const p = el.getAttribute('data-recents-pid') || el.getAttribute('data-pid');
      return Boolean(p && p !== String(opts.notesPid));
    }

    function mentionsNotes(el) {
      if (hasDifferentPid(el) && !el.querySelector(`[data-recents-pid="${opts.notesPid}"], [data-pid="${opts.notesPid}"]`)) {
        return false;
      }
      const txt = `${el.innerText || el.textContent || ''} ${el.getAttribute('data-app-id') || ''} ${el.getAttribute('data-recents-pid') || ''} ${el.getAttribute('data-pid') || ''}`.toLowerCase();
      return (
        txt.includes('notes') ||
        (opts.notesTitle && txt.includes(String(opts.notesTitle).toLowerCase())) ||
        (opts.notesAppId && txt.includes(String(opts.notesAppId).toLowerCase())) ||
        Boolean(el.querySelector(`[data-recents-pid="${opts.notesPid}"], [data-pid="${opts.notesPid}"]`)) ||
        el.getAttribute('data-recents-pid') === String(opts.notesPid) ||
        el.getAttribute('data-pid') === String(opts.notesPid)
      );
    }

    function describeBtn(btn) {
      btn.scrollIntoView({ block: 'center', inline: 'center' });
      const r = btn.getBoundingClientRect();
      return {
        found: true,
        x: r.left + r.width / 2,
        y: r.top + r.height / 2,
        text: String(btn.innerText || btn.textContent || '').trim().slice(0, 40),
        aria: btn.getAttribute('aria-label') || btn.getAttribute('title') || '',
      };
    }

    function findDismissInside(container, requireNewPosition) {
      const INTERACTIVE_ITEM_SEL = 'button, [role="button"], a';
      const isPidMatchedEl = (el) =>
        el.getAttribute('data-recents-pid') === String(opts.notesPid) ||
        el.getAttribute('data-pid') === String(opts.notesPid);
      const isEligibleBtn = (b) => {
        if (!isVisible(b) || isInsideLiveWindow(b, container) || (requireNewPosition && matchesPreCloseCenter(b))) {
          return false;
        }
        if (hasDifferentPid(b)) return false;
        if (!isPidMatchedEl(b)) {
          const pidCardAncestor = b.closest('[data-recents-card][data-pid], [data-recents-card][data-recents-pid]');
          if (pidCardAncestor && hasDifferentPid(pidCardAncestor)) return false;
          let cur = b.parentElement;
          while (cur && cur.nodeType === 1 && cur !== container) {
            if (hasDifferentPid(cur)) return false;
            cur = cur.parentElement;
          }
        }
        return true;
      };

      const pickDismissBtn = (actionPool, btnPool, allowSingleFallback) => {
        // 1. Explicit semantic kill/close/dismiss action attribute
        for (const sel of ['[data-action="kill"]', '[data-action="close"]', '[data-action="dismiss"]']) {
          const hits = actionPool(sel);
          if (hits.length > 0) return describeBtn(hits[0]);
        }

        // 2. aria-label / title close/kill/dismiss match
        const ariaHit = btnPool.find((b) =>
          /close|kill|dismiss|remove|end\s*task/i.test(`${b.getAttribute('aria-label') || ''} ${b.getAttribute('title') || ''}`)
        );
        if (ariaHit) return describeBtn(ariaHit);

        // 3. Explicit close/kill/dismiss text match
        const textHit = btnPool.find((b) =>
          /^(?:close|kill|dismiss|×|x|✕|✖)$/i.test(String(b.innerText || b.textContent || '').trim())
        );
        if (textHit) return describeBtn(textHit);

        // 4. Generic single-button fallback ONLY when scoped to a non-interactive card with exactly 1 non-focus button
        if (allowSingleFallback && btnPool.length === 1) {
          const sole = btnPool[0];
          const soleAction = String(sole.getAttribute('data-action') || '').trim();
          const soleText = String(sole.innerText || sole.textContent || '').trim();
          const soleAria = String(sole.getAttribute('aria-label') || '').trim();
          const soleTitle = String(sole.getAttribute('title') || '').trim();
          const nonDismissActionRe = /^(?:focus|open|switch|launch|resume|restore|activate|select|show)$/i;
          const nonDismissWordRe = /\b(?:focus|open|switch|launch|resume|restore|activate|select|show)\b/i;
          const soleLower = soleText.toLowerCase();
          const appNames = new Set(
            ['notes', 'omninotes', opts.notesTitle, opts.notesAppId]
              .filter(Boolean)
              .map((s) => String(s).trim().toLowerCase())
          );
          const isNonDismiss =
            nonDismissActionRe.test(soleAction) ||
            nonDismissWordRe.test(soleText) ||
            nonDismissWordRe.test(soleAria) ||
            nonDismissWordRe.test(soleTitle) ||
            (soleLower.length > 0 && appNames.has(soleLower));
          if (!isNonDismiss) {
            return describeBtn(sole);
          }
        }

        return null;
      };

      const tryScope = (scope, isScopedCard) => {
        const isScopeInteractive = scope.matches(INTERACTIVE_ITEM_SEL);
        const isScopeButton = scope.matches('button, [role="button"]');
        const collectActionHits = (sel) => {
          if (isScopeInteractive) {
            return scope.matches(sel) && isEligibleBtn(scope) ? [scope] : [];
          }
          return Array.from(scope.querySelectorAll(sel)).filter(isEligibleBtn);
        };
        const allBtns = (
          isScopeButton
            ? [scope]
            : (isScopeInteractive ? [] : Array.from(scope.querySelectorAll('button, [role="button"]')))
        ).filter(isEligibleBtn);

        const pidBtns = allBtns.filter(isPidMatchedEl);
        if (pidBtns.length > 0) {
          const pidHit = pickDismissBtn(
            (sel) => collectActionHits(sel).filter(isPidMatchedEl),
            pidBtns,
            false
          );
          if (pidHit) return pidHit;
        }

        return pickDismissBtn(collectActionHits, allBtns, !isScopeInteractive && isScopedCard);
      };

      const isContainerInteractive = container.matches(INTERACTIVE_ITEM_SEL);
      const isDirectPidCard = !isContainerInteractive && isPidMatchedEl(container);

      if (isContainerInteractive || isDirectPidCard || container.hasAttribute('data-recents-card')) {
        return tryScope(container, !isContainerInteractive);
      }

      // 1. Non-interactive element explicitly tagged with target PID (two-pass: explicit dismiss first)
      const pidCards = Array.from(
        container.querySelectorAll(`[data-recents-pid="${opts.notesPid}"], [data-pid="${opts.notesPid}"]`)
      ).filter((el) => !el.matches(INTERACTIVE_ITEM_SEL) && isVisible(el) && !isInsideLiveWindow(el, container));
      for (const pidCard of pidCards) {
        const hit = tryScope(pidCard, false);
        if (hit) return hit;
      }
      for (const pidCard of pidCards) {
        const hit = tryScope(pidCard, true);
        if (hit) return hit;
      }

      // 2. Candidate cards inside overlay sorted by PID descendant match first, then smallest area
      const cardCandidates = [];
      for (const el of container.querySelectorAll('article, section, li, div, [role="listitem"]')) {
        if (!isVisible(el) || isInsideLiveWindow(el, container)) continue;
        const hasBtn = Array.from(el.querySelectorAll('button, [role="button"]')).some(isEligibleBtn);
        if (!hasBtn) continue;
        const hasPidDescendant = Boolean(
          el.querySelector(`[data-recents-pid="${opts.notesPid}"], [data-pid="${opts.notesPid}"]`)
        );
        if (!hasPidDescendant && !mentionsNotes(el)) continue;
        const r = el.getBoundingClientRect();
        cardCandidates.push({ el, hasPidDescendant, area: r.width * r.height });
      }
      cardCandidates.sort((a, b) => {
        if (a.hasPidDescendant !== b.hasPidDescendant) return a.hasPidDescendant ? -1 : 1;
        if (a.area !== b.area) return a.area - b.area;
        if (a.el.contains(b.el)) return 1;
        if (b.el.contains(a.el)) return -1;
        return 0;
      });
      // Pass 1: explicit kill/close/dismiss controls ONLY across ALL candidates
      for (const cand of cardCandidates) {
        const hit = tryScope(cand.el, false);
        if (hit) return hit;
      }
      // Pass 2: generic single-button fallback only if Pass 1 found no explicit dismiss control
      for (const cand of cardCandidates) {
        const hit = tryScope(cand.el, true);
        if (hit) return hit;
      }

      // 3. Fallback directly on container (e.g. flat Recents list without per-card wrapper divs)
      return tryScope(container, false);
    }

    // Step 1: Explicit Recents overlay/card container (exempting data-window-id on cards inside Recents)
    const explicitSelectors = [
      `[data-recents-pid="${opts.notesPid}"]:not(button):not([role="button"]):not(a)`,
      `[data-recents-card][data-pid="${opts.notesPid}"]`,
      '[data-recents-card]',
      '[data-recents-overlay]',
      '[data-overlay="recents"]',
      '[data-recents]',
      '[data-recents-list]',
      '[aria-label*="recents" i]:not(button)',
      '[aria-label*="recent apps" i]:not(button)',
      `[data-recents-pid="${opts.notesPid}"]`,
    ];
    const hasNotesPidMatch = (el) =>
      el.getAttribute('data-recents-pid') === String(opts.notesPid) ||
      el.getAttribute('data-pid') === String(opts.notesPid) ||
      Boolean(el.querySelector(`[data-recents-pid="${opts.notesPid}"], [data-pid="${opts.notesPid}"]`));
    for (const sel of explicitSelectors) {
      const matched = Array.from(document.querySelectorAll(sel));
      matched.sort((a, b) => (hasNotesPidMatch(b) ? 1 : 0) - (hasNotesPidMatch(a) ? 1 : 0));
      for (const container of matched) {
        if (!isVisible(container) || isInsideLiveWindow(container)) continue;
        if (!mentionsNotes(container)) continue;
        const btn = findDismissInside(container, false);
        if (btn) return btn;
      }
    }

    // Step 2: Newly appeared generic overlay/dialog (excluding pre-click desktop close positions)
    for (const container of document.querySelectorAll('[role="dialog"], [role="list"], [data-overlay]')) {
      if (!isVisible(container) || isInsideLiveWindow(container)) continue;
      const sig = `${container.tagName}:${container.id}:${container.className}:${(container.innerText || '').trim().slice(0, 80)}`;
      if (base.preVisibleDialogs.includes(sig)) continue;
      if (!mentionsNotes(container)) continue;
      const btn = findDismissInside(container, true);
      if (btn) return btn;
    }

    return { found: false };
  }, baseline, { windowId, notesPid, notesTitle, notesAppId });
}

// ============================================================================
// Server-First Lazy Suite Environment (0 Chromium spawned if os/ absent!)
// ============================================================================

let suiteServer = null;
let suiteBrowser = null;

async function getSuiteEnv() {
  if (!suiteServer) {
    suiteServer = await startOmniServer();
  }
  if (!suiteBrowser) {
    try {
      suiteBrowser = await launchBrowser({ defaultViewport: { width: 1280, height: 800 } });
    } catch (err) {
      await suiteServer.stop().catch(() => {});
      suiteServer = null;
      throw err;
    }
  }
  return { server: suiteServer, browser: suiteBrowser };
}

after(async () => {
  if (suiteBrowser) {
    const b = suiteBrowser;
    suiteBrowser = null;
    await b.close().catch(() => {});
  }
  if (suiteServer) {
    const s = suiteServer;
    suiteServer = null;
    await s.stop().catch(() => {});
  }
});

describe('Tier 4 — S04: Headless Chromium CDP Live 5-Mode Desktop & Multi-Window UX (F-086)', () => {
  it('T4-S04-01 [Scenario 7 / F-086, F-073–F-076, F-084]: Live Adaptive 5-Mode Shell Tour, 3-Platform Concurrent Windows, Theme Sync & Reload Persistence', async () => {
    let page = null;
    let unsubNet = () => {};
    let notesAppId = null;
    let dynApkId = null;
    let canvasAppId = null;
    let initialTheme = 'dark';
    try {
      // Server-first lazy init (fails immediately with E_OMNIOS_NOT_IMPLEMENTED if os/ absent)
      const { server, browser } = await getSuiteEnv();
      const sysApps = await discoverSystemAppsHttp(server.api);
      notesAppId = sysApps.notes;
      const nonce = makeNonce(4);

      const cfg0 = await getSystemConfig(server.api);
      initialTheme = (cfg0.theme ?? cfg0['system.theme'] ?? 'dark') === 'light' ? 'light' : 'dark';
      const oppositeTheme = initialTheme === 'dark' ? 'light' : 'dark';

      // Open Chromium page & attach Network inspection for /ws + 0 external CDN traffic
      page = await browser.newPage();
      const wsUrls = [];
      const externalRequests = [];
      await page.send('Network.enable');
      unsubNet = browser.on((method, params, sid) => {
        if (sid !== page.sessionId) return;
        if (method === 'Network.webSocketCreated' && params.url) {
          wsUrls.push(String(params.url));
        } else if (method === 'Network.requestWillBeSent' && params.request?.url) {
          const url = String(params.request.url);
          if (/^https?:\/\//i.test(url) && !url.startsWith(server.baseUrl)) {
            externalRequests.push(url);
          }
        }
      });

      await page.goto(server.baseUrl);
      await waitForShellRendered(page);

      // 1. Live /ws connection + 0 external CDN requests/tags
      await waitUntil(
        () => wsUrls.some((u) => u.endsWith('/ws') || u.includes('/ws?')),
        { timeoutMs: 6000, label: 'Chromium frontend /ws WebSocket connection' }
      );
      assert.deepEqual(externalRequests, [], `Offline-safe violated: external requests=${JSON.stringify(externalRequests)}`);
      const externalTags = await page.evalFn((origin) => {
        const bad = [];
        for (const el of document.querySelectorAll('script[src], link[href]')) {
          const u = el.getAttribute('src') || el.getAttribute('href') || '';
          if (/^https?:\/\//i.test(u) && !u.startsWith(origin)) bad.push(u);
        }
        return bad;
      }, server.baseUrl);
      assert.deepEqual(externalTags, [], `External CDN tags found in DOM: ${JSON.stringify(externalTags)}`);

      // 2. Live /ws notification push without reload (concatenated badge count regex)
      const readNotifBadges = () => page.evalFn(() => {
        const els = Array.from(document.querySelectorAll('[data-notification-count], [data-badge], [aria-label*="notification" i]'));
        let maxCount = 0;
        let sumCount = 0;
        for (const el of els) {
          const st = window.getComputedStyle(el);
          if (st.display === 'none' || st.visibility === 'hidden') continue;
          const txt = [
            el.innerText,
            el.textContent,
            el.getAttribute('data-notification-count'),
            el.getAttribute('data-badge'),
          ].filter(Boolean).join(' ').trim();
          const m = txt.match(/\d+/);
          if (m) {
            const n = Number(m[0]);
            if (Number.isFinite(n)) {
              if (n > maxCount) maxCount = n;
              sumCount += n;
            }
          }
        }
        return { maxCount, sumCount };
      });
      const beforeBadges = await readNotifBadges();
      const tourNotifTitle = `TourWs_${nonce}`;
      await server.api.post('/api/v1/ipc/notifications', {
        appId: notesAppId,
        platform: 'universal',
        title: tourNotifTitle,
        body: `Push_${nonce}`,
        priority: 'high',
        category: 'system',
      }, { expectOk: true });

      await page.waitForFunction((needle, prevBadges) => {
        if ((document.body.innerText || '').includes(needle)) return true;
        const els = Array.from(document.querySelectorAll('[data-notification-count], [data-badge], [aria-label*="notification" i]'));
        let maxCount = 0;
        let sumCount = 0;
        for (const el of els) {
          const st = window.getComputedStyle(el);
          if (st.display === 'none' || st.visibility === 'hidden') continue;
          const txt = [
            el.innerText,
            el.textContent,
            el.getAttribute('data-notification-count'),
            el.getAttribute('data-badge'),
          ].filter(Boolean).join(' ').trim();
          const m = txt.match(/\d+/);
          if (m) {
            const n = Number(m[0]);
            if (Number.isFinite(n)) {
              if (n > maxCount) maxCount = n;
              sumCount += n;
            }
          }
        }
        return maxCount > prevBadges.maxCount || sumCount > prevBadges.sumCount;
      }, { timeoutMs: 6000, args: [tourNotifTitle, beforeBadges] });

      // 3. Launch 3 real multi-platform apps concurrently: Notes + Dynamic Android .apk + WASM Canvas2D .uapp
      const opA = 1100 + crypto.randomInt(3000);
      const opB = 1100 + crypto.randomInt(3000);
      const expectedSum = String((opA + opB) | 0);
      dynApkId = `com.omnios.t4s04.apk${nonce}`;
      const dynApkBytes = buildCustomApk({
        packageName: dynApkId,
        appLabel: `TourApk_${nonce}`,
        computeA: opA,
        computeB: opB,
        computeOp: 'add',
      });
      await installPackageHttp(server.api, dynApkBytes, `tour-${nonce}.apk`, { grantAll: true });

      const canvasBytes = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', 'universal-canvas.uapp'));
      const instCanvas = await installPackageHttp(server.api, canvasBytes, 'universal-canvas.uapp', { grantAll: true });
      canvasAppId = instCanvas?.appId ?? instCanvas?.package?.appId ?? instCanvas?.id;
      assert.ok(canvasAppId, `Expected appId installing universal-canvas.uapp: ${JSON.stringify(instCanvas)}`);

      const lNotes = await server.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/launch`, {}, { expectOk: true });
      const lApk = await server.api.post(`/api/v1/packages/${encodeURIComponent(dynApkId)}/launch`, {}, { expectOk: true });
      const lCanvas = await server.api.post(`/api/v1/packages/${encodeURIComponent(canvasAppId)}/launch`, {}, { expectOk: true });

      const notesPid = lNotes.json?.pid ?? lNotes.json?.process?.pid;
      const apkPid = lApk.json?.pid ?? lApk.json?.process?.pid;
      const canvasPid = lCanvas.json?.pid ?? lCanvas.json?.process?.pid;
      assert.ok(notesPid > 1 && apkPid > 1 && canvasPid > 1, 'Expected valid PIDs > 1 for all 3 apps');
      assert.equal(new Set([notesPid, apkPid, canvasPid]).size, 3, 'Expected 3 distinct concurrent PIDs');

      const winsSnap = await waitUntil(async () => {
        const res = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(unwrapSnapshot(res.json), ['windows']);
        const wNotes = wins.find((w) => w.pid === notesPid || w.appId === notesAppId);
        const wApk = wins.find((w) => w.pid === apkPid || w.appId === dynApkId);
        const wCanvas = wins.find((w) => w.pid === canvasPid || w.appId === canvasAppId);
        return wNotes && wApk && wCanvas ? { wNotes, wApk, wCanvas } : null;
      }, { timeoutMs: 8000, label: '3 concurrent multi-platform windows in compositor snapshot' });

      const notesWinId = getWinId(winsSnap.wNotes);
      const apkWinId = getWinId(winsSnap.wApk);
      const canvasWinId = getWinId(winsSnap.wCanvas);
      assert.equal(new Set([notesWinId, apkWinId, canvasWinId]).size, 3);

      // Verify all 3 windows visible in live Chromium DOM + dynamic APK computed sum + window-scoped Canvas2D pixels
      const domApk = await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: apkWinId, titleSubstring: winsSnap.wApk.title || `TourApk_${nonce}` });
        return w.found && w.text.includes(expectedSum) ? w : null;
      }, { timeoutMs: 8000, label: `dynamic Android APK window rendering computed sum ${expectedSum}` });
      assert.ok(domApk.text.includes(expectedSum));

      await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: notesWinId, titleSubstring: winsSnap.wNotes.title || 'Notes' });
        return w.found ? w : null;
      }, { timeoutMs: 8000, label: 'visible Notes window in DOM' });

      const canvasStats = await waitUntil(async () => {
        const stats = await inspectWindowCanvas(page, {
          windowId: canvasWinId,
          titleSubstring: winsSnap.wCanvas.title || 'Canvas',
        });
        return stats.found && stats.width > 0 && stats.height > 0 && stats.nonZeroPixels > 0 ? stats : null;
      }, { timeoutMs: 8000, label: 'window-scoped Canvas2D non-zero rasterized pixels' });
      assert.ok(canvasStats.nonZeroPixels > 0);

      // 4. Full 5-Mode Shell Tour preserving all 3 multi-platform windows & live PIDs
      await setShellModeHttp(server.api, 'unified');
      for (const mode of ['windows', 'macos', 'ios', 'android', 'unified']) {
        await switchShellModeInUi(page, server.api, mode);

        const snapRes = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(unwrapSnapshot(snapRes.json), ['windows']);
        for (const [label, winId, pid] of [
          ['Notes', notesWinId, notesPid],
          ['DynamicAPK', apkWinId, apkPid],
          ['UniversalCanvas', canvasWinId, canvasPid],
        ]) {
          assert.ok(
            wins.some((w) => getWinId(w) === winId),
            `Window ${label} (${winId}) must remain open in "${mode}" mode`
          );
          const pRes = await server.api.get(`/api/v1/processes/${pid}`, { expectOk: true });
          assertAliveState(extractProcState(pRes.json), `${label} in ${mode} mode`);
        }
      }

      // 5. Bidirectional Dark/Light Theme Sync (dom1-guarded)
      const readDomTheme = () => page.evalFn(() => ({
        rootTheme: document.documentElement.dataset?.theme || document.body.dataset?.theme || '',
        classes: `${document.documentElement.className} ${document.body.className}`,
        bg: window.getComputedStyle(document.body).backgroundColor,
      }));
      const dom0 = await readDomTheme();

      await clickSemanticControl(page, {
        dataSelectors: ['[data-toggle="theme"]', '[data-action="toggle-theme"]', '[data-theme-toggle]', '[data-config-key="theme"]'],
        ariaPatterns: ['theme', 'dark\\s*mode', 'light\\s*mode'],
        textPatterns: ['theme', 'dark', 'light'],
      }, 'Theme toggle button');

      await waitUntil(async () => {
        const cfgNow = await getSystemConfig(server.api);
        return (cfgNow.theme ?? cfgNow['system.theme']) === oppositeTheme;
      }, { timeoutMs: 5000, label: `backend system.theme === "${oppositeTheme}"` });

      await page.waitForFunction((prev, target) => {
        const curRoot = (document.documentElement.dataset?.theme || document.body.dataset?.theme || '').toLowerCase();
        const curCls = `${document.documentElement.className} ${document.body.className}`.toLowerCase();
        const curBg = window.getComputedStyle(document.body).backgroundColor;
        return curRoot === target || curCls.includes(target) || curBg !== prev.bg;
      }, { timeoutMs: 5000, args: [dom0, oppositeTheme] });

      const dom1 = await readDomTheme();

      // Backend -> UI live /ws revert guarded by dom1.bg !== dom0.bg
      await setSystemConfigHttp(server.api, 'theme', initialTheme);
      await page.waitForFunction((target, before0, before1) => {
        const curRoot = (document.documentElement.dataset?.theme || document.body.dataset?.theme || '').toLowerCase();
        const curCls = `${document.documentElement.className} ${document.body.className}`.toLowerCase();
        const curBg = window.getComputedStyle(document.body).backgroundColor;
        return (
          curRoot === target ||
          curCls.includes(target) ||
          (before1.bg !== before0.bg && curBg === before0.bg)
        );
      }, { timeoutMs: 6000, args: [initialTheme, dom0, dom1] });

      // 6. Full Page Reload Persistence
      await switchShellModeInUi(page, server.api, 'macos');
      await page.goto(server.baseUrl);
      await waitForShellRendered(page);

      await waitUntil(async () => await domReflectsMode(page, 'macos'), {
        timeoutMs: 8000,
        label: 'hydrated DOM reflects persisted macos shellMode after full reload',
      });

      const snapReload = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
      const cfgReload = await getSystemConfig(server.api);
      assert.equal(snapReload.shellMode, 'macos');
      assert.equal(cfgReload.shellMode ?? cfgReload['system.shellMode'], 'macos');

      for (const [winId, title] of [
        [notesWinId, winsSnap.wNotes.title || 'Notes'],
        [apkWinId, winsSnap.wApk.title || `TourApk_${nonce}`],
        [canvasWinId, winsSnap.wCanvas.title || 'Canvas'],
      ]) {
        assert.ok(asArray(snapReload, ['windows']).some((w) => getWinId(w) === winId));
        const hydrated = await waitUntil(async () => {
          const w = await findVisibleWindow(page, { windowId: winId, titleSubstring: title });
          return w.found ? w : null;
        }, { timeoutMs: 6000, label: `hydrated window ${winId} after reload` });
        assert.equal(hydrated.found, true);
      }

      await switchShellModeInUi(page, server.api, 'unified');
      assertZeroBrowserErrors(page, 'T4-S04-01');
    } finally {
      unsubNet();
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        if (notesAppId) await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/stop`, {}).catch(() => {});
        if (canvasAppId) await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(canvasAppId)}/stop`, {}).catch(() => {});
        if (dynApkId) {
          await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(dynApkId)}/stop`, {}).catch(() => {});
          await suiteServer.api.delete(`/api/v1/packages/${encodeURIComponent(dynApkId)}`).catch(() => {});
        }
        await setShellModeHttp(suiteServer.api, 'unified').catch(() => {});
        await setSystemConfigHttp(suiteServer.api, 'theme', initialTheme).catch(() => {});
      }
    }
  });

  it('T4-S04-02 [Scenario 8 / F-086, F-074, F-077–F-080]: Multi-Window Focus & CDP Drag + All 4 Platform Signature UX Features (Windows Snap, macOS Menu Bar/Spotlight, iOS Island/CC, Android Shade/Recents Kill)', async () => {
    let page = null;
    let notesAppId = null;
    let macAppId = null;
    let dndBefore = null;
    try {
      // Server-first lazy init
      const { server, browser } = await getSuiteEnv();
      const sysApps = await discoverSystemAppsHttp(server.api);
      notesAppId = sysApps.notes;
      const nonce = makeNonce(4);

      // Seed Spotlight document (we will type ONLY stem without `.txt` and assert full `.txt` hit!)
      const docStem = `t4-spot-${nonce}`;
      const docName = `${docStem}.txt`;
      const docPath = `/home/user/Documents/${docName}`;
      const wDocRes = await writeWithMethodFallback(
        server.api,
        ['PUT', 'POST'],
        '/api/v1/vfs/file',
        { path: docPath, content: `T4_SPOT_BODY_${nonce}`, data: `T4_SPOT_BODY_${nonce}`, encoding: 'utf8' }
      );
      assert.ok(wDocRes && wDocRes.ok, `Expected 2xx seeding Spotlight file: ${wDocRes?.status} ${wDocRes?.text}`);

      // Install & launch macos-studio.app.zip + built-in Notes
      const macBytes = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', 'macos-studio.app.zip'));
      const instMac = await installPackageHttp(server.api, macBytes, 'macos-studio.app.zip', { grantAll: true });
      macAppId = instMac?.appId ?? instMac?.package?.appId ?? instMac?.id;
      assert.ok(macAppId, `Expected appId installing macos-studio.app.zip: ${JSON.stringify(instMac)}`);

      const lMac = await server.api.post(`/api/v1/packages/${encodeURIComponent(macAppId)}/launch`, {}, { expectOk: true });
      const lNotes = await server.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/launch`, {}, { expectOk: true });
      const macPid = lMac.json?.pid ?? lMac.json?.process?.pid;
      const notesPid = lNotes.json?.pid ?? lNotes.json?.process?.pid;
      assert.ok(macPid > 1 && notesPid > 1 && macPid !== notesPid);

      const snap0 = await waitUntil(async () => {
        const res = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const s = unwrapSnapshot(res.json);
        const wins = asArray(s, ['windows']);
        const wMac = wins.find((w) => w.pid === macPid || w.appId === macAppId);
        const wNotes = wins.find((w) => w.pid === notesPid || w.appId === notesAppId);
        return wMac && wNotes ? { wMac, wNotes, focusedWindowId: s.focusedWindowId } : null;
      }, { timeoutMs: 8000, label: 'both macos-studio and Notes windows in backend snapshot' });

      const macWinId = getWinId(snap0.wMac);
      const notesWinId = getWinId(snap0.wNotes);
      const macTitle = snap0.wMac.title || 'Studio';
      const notesTitle = snap0.wNotes.title || 'Notes';

      await setShellModeHttp(server.api, 'unified');
      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(macWinId)}/move`, { x: 60, y: 80 });
      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(notesWinId)}/move`, { x: 520, y: 120 });

      page = await browser.newPage();
      await page.goto(server.baseUrl);
      await waitForShellRendered(page);

      const domMac0 = await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: macWinId, titleSubstring: macTitle });
        return w.found ? w : null;
      }, { timeoutMs: 8000, label: 'visible macos-studio window in DOM' });

      const domNotes0 = await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: notesWinId, titleSubstring: notesTitle });
        return w.found ? w : null;
      }, { timeoutMs: 8000, label: 'visible Notes window in DOM' });
      const notesUsedWindowIdAttr = Boolean(domNotes0.matchedByWindowId);

      // ----------------------------------------------------------------------
      // 1. Focus Raising & Real CDP Titlebar Drag
      // ----------------------------------------------------------------------
      const targetFocusId = snap0.focusedWindowId === macWinId ? notesWinId : macWinId;
      const targetTitle = targetFocusId === macWinId ? macTitle : notesTitle;
      const otherWinId = targetFocusId === macWinId ? notesWinId : macWinId;
      const otherTitle = otherWinId === macWinId ? macTitle : notesTitle;
      const targetDom0 = targetFocusId === macWinId ? domMac0 : domNotes0;

      await page.clickAt(targetDom0.titleBarCenter.x, targetDom0.titleBarCenter.y);
      await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return s.focusedWindowId === targetFocusId;
      }, { timeoutMs: 5000, label: `focusedWindowId === ${targetFocusId}` });

      const zFocused = (await findVisibleWindow(page, { windowId: targetFocusId, titleSubstring: targetTitle })).zIndex;
      const zOther = (await findVisibleWindow(page, { windowId: otherWinId, titleSubstring: otherTitle })).zIndex;
      assert.ok(zFocused >= zOther, `Focused window z-index (${zFocused}) must be >= background (${zOther})`);

      const beforeDragSnap = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
      const beforeDragWin = asArray(beforeDragSnap, ['windows']).find((w) => getWinId(w) === targetFocusId);
      const beforeXY = getXY(beforeDragWin);
      assert.ok(beforeXY.x !== undefined && beforeXY.y !== undefined, `Expected numeric coordinates: ${JSON.stringify(beforeDragWin)}`);
      const beforeDragDom = await findVisibleWindow(page, { windowId: targetFocusId, titleSubstring: targetTitle });

      await page.drag(
        { x: beforeDragDom.titleBarCenter.x, y: beforeDragDom.titleBarCenter.y },
        { x: beforeDragDom.titleBarCenter.x + 75, y: beforeDragDom.titleBarCenter.y + 45 },
        { steps: 10 }
      );

      await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const cur = asArray(s, ['windows']).find((w) => getWinId(w) === targetFocusId);
        const curXY = getXY(cur);
        const curDom = await findVisibleWindow(page, { windowId: targetFocusId, titleSubstring: targetTitle });
        const backendMoved = Boolean(cur && curXY.x !== undefined && curXY.y !== undefined && (curXY.x !== beforeXY.x || curXY.y !== beforeXY.y));
        const domMoved = curDom.found && (Math.abs(curDom.rect.left - beforeDragDom.rect.left) > 10 || Math.abs(curDom.rect.top - beforeDragDom.rect.top) > 10);
        return backendMoved && domMoved;
      }, { timeoutMs: 5000, label: 'window moved in both backend bounds and live Chromium DOM after CDP drag' });

      // ----------------------------------------------------------------------
      // 2. Windows Signature UX: Start Menu + Left/Right Snap Layout Geometry
      // ----------------------------------------------------------------------
      await switchShellModeInUi(page, server.api, 'windows');

      const startSelectors = [
        '[data-start-menu]',
        '[data-overlay="start"]',
        '[role="menu"]',
        '[role="dialog"]',
        '[aria-label*="start menu" i]',
        '[aria-label*="start" i]:not(button)',
      ];
      const startBase = await captureOverlayBaseline(page, startSelectors);
      await clickSemanticControl(page, {
        dataSelectors: ['[data-start-button]', '[data-action="start-menu"]', '[data-windows-start]'],
        ariaPatterns: ['start'],
        textPatterns: ['^start$'],
      }, 'Windows Start button');
      await waitForNewAppOverlay(page, startBase, startSelectors, 5000);
      await page.pressKey('Escape');

      // Snap macWinId left & notesWinId right (use visible UI snap control if present, else REST state endpoint)
      const snapLeftBtn = await findVisibleControl(page, {
        dataSelectors: [
          `[data-window-id="${macWinId}"] [data-snap="snapped-left"]`,
          `[data-window-id="${macWinId}"] [data-snap="left"]`,
        ],
        ariaPatterns: ['snap\\s*left', 'tile\\s*left'],
        textPatterns: ['snap\\s*left'],
      });
      if (snapLeftBtn.found) {
        await page.clickAt(snapLeftBtn.x, snapLeftBtn.y);
      } else {
        const sLeft = await writeWithMethodFallback(
          server.api,
          ['POST', 'PUT', 'PATCH'],
          `/api/v1/compositor/windows/${encodeURIComponent(macWinId)}/state`,
          { state: 'snapped-left' }
        );
        assert.ok(sLeft && sLeft.ok, `Expected 2xx snapping ${macWinId} left: ${sLeft?.status}`);
      }

      const snapRightBtn = await findVisibleControl(page, {
        dataSelectors: [
          `[data-window-id="${notesWinId}"] [data-snap="snapped-right"]`,
          `[data-window-id="${notesWinId}"] [data-snap="right"]`,
        ],
        ariaPatterns: ['snap\\s*right', 'tile\\s*right'],
        textPatterns: ['snap\\s*right'],
      });
      if (snapRightBtn.found) {
        await page.clickAt(snapRightBtn.x, snapRightBtn.y);
      } else {
        const sRight = await writeWithMethodFallback(
          server.api,
          ['POST', 'PUT', 'PATCH'],
          `/api/v1/compositor/windows/${encodeURIComponent(notesWinId)}/state`,
          { state: 'snapped-right' }
        );
        assert.ok(sRight && sRight.ok, `Expected 2xx snapping ${notesWinId} right: ${sRight?.status}`);
      }

      await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const wins = asArray(s, ['windows']);
        const wMac = wins.find((w) => getWinId(w) === macWinId);
        const wNotes = wins.find((w) => getWinId(w) === notesWinId);
        if (!wMac || !wNotes) return false;
        if (wMac.state !== 'snapped-left' || wNotes.state !== 'snapped-right') return false;
        const bMac = getBounds(wMac);
        const bNotes = getBounds(wNotes);
        if (!(bNotes.x > bMac.x)) return false;

        const dMac = await findVisibleWindow(page, { windowId: macWinId, titleSubstring: macTitle });
        const dNotes = await findVisibleWindow(page, { windowId: notesWinId, titleSubstring: notesTitle });
        return Boolean(
          dMac.found &&
          dNotes.found &&
          dMac.rect.width > 250 && dMac.rect.width <= 760 &&
          dNotes.rect.width > 250 && dNotes.rect.width <= 760 &&
          dNotes.rect.left > dMac.rect.left
        );
      }, { timeoutMs: 6000, label: 'Windows left/right Snap Layout geometry in backend and Chromium DOM' });

      // Restore windows to normal non-overlapping bounds
      await writeWithMethodFallback(server.api, ['POST', 'PUT', 'PATCH'], `/api/v1/compositor/windows/${encodeURIComponent(macWinId)}/state`, { state: 'normal' });
      await writeWithMethodFallback(server.api, ['POST', 'PUT', 'PATCH'], `/api/v1/compositor/windows/${encodeURIComponent(notesWinId)}/state`, { state: 'normal' });
      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(macWinId)}/move`, { x: 60, y: 90 });
      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(notesWinId)}/move`, { x: 540, y: 130 });

      // ----------------------------------------------------------------------
      // 3. macOS Signature UX: Global Top Menu Bar Focus Switch, Dock & Spotlight
      // ----------------------------------------------------------------------
      await switchShellModeInUi(page, server.api, 'macos');

      const extractMenuLabels = (arr) =>
        (Array.isArray(arr) ? arr : [])
          .map((item) => String(item?.label ?? item?.title ?? item ?? '').trim())
          .filter(Boolean);

      // Focus Notes first, capture its menu labels
      const dNotesMacMode = await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: notesWinId, titleSubstring: notesTitle });
        return w.found ? w : null;
      }, { timeoutMs: 5000, label: 'Notes window visible in macOS mode' });
      await page.clickAt(dNotesMacMode.titleBarCenter.x, dNotesMacMode.titleBarCenter.y);
      const notesSnapMac = await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return s.focusedWindowId === notesWinId ? s : null;
      }, { timeoutMs: 5000, label: 'Notes focused in macOS mode' });
      const notesMenuLabels = extractMenuLabels(notesSnapMac.activeMenuBar);

      // Click macOS Studio titlebar -> Global Top Menu Bar updates
      const dMacMacMode = await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: macWinId, titleSubstring: macTitle });
        return w.found ? w : null;
      }, { timeoutMs: 5000, label: 'macos-studio window visible in macOS mode' });
      await page.clickAt(dMacMacMode.titleBarCenter.x, dMacMacMode.titleBarCenter.y);
      const macSnapFocused = await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return s.focusedWindowId === macWinId ? s : null;
      }, { timeoutMs: 5000, label: 'macos-studio focused in macOS mode' });

      const macWinNow = asArray(macSnapFocused, ['windows']).find((w) => getWinId(w) === macWinId);
      const macMenuLabels = extractMenuLabels(
        Array.isArray(macSnapFocused.activeMenuBar) && macSnapFocused.activeMenuBar.length > 0
          ? macSnapFocused.activeMenuBar
          : macWinNow?.menuBar
      );
      assert.ok(macMenuLabels.length > 0, `Expected non-empty Global Top Menu Bar for macos-studio: ${JSON.stringify(macSnapFocused)}`);
      const preferredMenuLabel = macMenuLabels.find((l) => !notesMenuLabels.includes(l)) ?? macMenuLabels[0];
      await page.waitForFunction((lbl) => Boolean(lbl) && (document.body.innerText || '').includes(lbl), {
        timeoutMs: 5000,
        args: [preferredMenuLabel],
      });

      // Verify Floating Dock renders >= 2 launchers
      const dockOk = await page.evalFn(() => {
        const dock = document.querySelector('[data-dock], [role="toolbar"][aria-label*="dock" i], [aria-label*="dock" i], nav');
        if (!dock) return false;
        const r = dock.getBoundingClientRect();
        return r.width > 0 && r.height > 0 && dock.querySelectorAll('button, [role="button"], a').length >= 2;
      });
      assert.ok(dockOk, 'Expected visible macOS Floating Dock with >= 2 launcher items');

      // Spotlight (Ctrl+Space) with hardened Spotlight-specific focus + strict `.txt` check
      await page.pressKey('Space', 'Ctrl');
      const spotFocused = await waitUntil(async () => (await focusSpotlightInput(page)) ? true : null, {
        timeoutMs: 5000,
        label: 'Spotlight-specific search input focused after Ctrl+Space',
      });
      assert.equal(spotFocused, true);
      await page.send('Input.insertText', { text: docStem }); // WITHOUT `.txt`!
      await page.waitForFunction((fullName) => (document.body.innerText || '').includes(fullName), {
        timeoutMs: 6000,
        args: [docName],
      });
      await page.pressKey('Escape');

      // ----------------------------------------------------------------------
      // 4. iOS Signature UX: Dynamic Island Expansion + Control Center DND Toggle
      // ----------------------------------------------------------------------
      await switchShellModeInUi(page, server.api, 'ios');

      const islandTitle = `Island_${nonce}`;
      const islandBody = `IslandNotifBody_${nonce}`;
      const islandStatus = `IslandExpanded_${nonce}`;
      await server.api.post('/api/v1/ipc/notifications', {
        appId: macAppId,
        platform: 'ios',
        title: islandTitle,
        body: islandBody,
        priority: 'high',
        category: 'live',
        liveActivity: {
          id: `la-${nonce}`,
          title: islandTitle,
          status: islandStatus,
          progress: 0.72,
        },
      }, { expectOk: true });

      await page.waitForFunction((needle) => (document.body.innerText || '').includes(needle), {
        timeoutMs: 6000,
        args: [islandTitle],
      });

      const islandBefore = await page.evalFn(() => {
        const el = document.querySelector('[data-dynamic-island], [data-island], [aria-label*="dynamic island" i]');
        if (!el) return null;
        return { height: el.getBoundingClientRect().height };
      });

      await clickSemanticControl(page, {
        dataSelectors: ['[data-dynamic-island]', '[data-island]'],
        ariaPatterns: ['dynamic\\s*island', 'live\\s*activity'],
        textPatterns: [islandTitle],
        tags: 'button, [role="button"], [data-dynamic-island], [data-island], div, section',
      }, 'iOS Dynamic Island pill');

      // Strictly verify genuine Dynamic Island expansion (distinct liveActivity.status vs toast body!)
      const islandExpanded = await waitUntil(async () => {
        return await page.evalFn((statusTxt, prevHeight) => {
          const el = document.querySelector('[data-dynamic-island], [data-island], [aria-label*="dynamic island" i]');
          if (el) {
            const r = el.getBoundingClientRect();
            const hasStatus = (el.innerText || '').includes(statusTxt);
            const attrExpanded =
              el.getAttribute('aria-expanded') === 'true' ||
              /\b(?:expand|expanded|open)\b/i.test(String(el.className || ''));
            const grew = r.height > 44 && (prevHeight === null || r.height > prevHeight + 8);
            if (hasStatus || attrExpanded || grew) return true;
          }
          return (document.body.innerText || '').includes(statusTxt);
        }, islandStatus, islandBefore ? islandBefore.height : null);
      }, { timeoutMs: 4000, label: `iOS Dynamic Island expansion (${islandStatus})` });
      assert.equal(islandExpanded, true, 'Expected iOS Dynamic Island pill to expand on click');

      // Control Center DND toggle -> real backend Config Store mutation
      await clickSemanticControl(page, {
        dataSelectors: ['[data-control-center-toggle]', '[data-action="control-center"]', '[data-control-center-trigger]'],
        ariaPatterns: ['control\\s*center'],
        textPatterns: ['control\\s*center'],
      }, 'iOS Control Center trigger');

      const cfgIos = await getSystemConfig(server.api);
      dndBefore = Boolean(cfgIos.dnd ?? cfgIos['system.dnd']);
      await clickSemanticControl(page, {
        dataSelectors: ['[data-toggle="dnd"]', '[data-config-key="dnd"]', '[data-config-key="system.dnd"]'],
        ariaPatterns: ['do\\s*not\\s*disturb', '\\bdnd\\b'],
        textPatterns: ['do\\s*not\\s*disturb', '^dnd$', 'focus'],
      }, 'Control Center DND toggle');

      await waitUntil(async () => {
        const cur = await getSystemConfig(server.api);
        return Boolean(cur.dnd ?? cur['system.dnd']) === !dndBefore;
      }, { timeoutMs: 5000, label: 'backend system.dnd toggled via Control Center' });

      await setSystemConfigHttp(server.api, 'dnd', dndBefore);
      await page.pressKey('Escape');

      // ----------------------------------------------------------------------
      // 5. Android Signature UX: Notification Shade + Hardened Recents Real PID Kill
      // ----------------------------------------------------------------------
      await switchShellModeInUi(page, server.api, 'android');

      const shadeTitle = `AndShade_${nonce}`;
      await server.api.post('/api/v1/ipc/notifications', {
        appId: notesAppId,
        platform: 'android',
        title: shadeTitle,
        body: `ShadeBody_${nonce}`,
        priority: 'normal',
        category: 'system',
      }, { expectOk: true });

      await clickSemanticControl(page, {
        dataSelectors: ['[data-notification-shade-toggle]', '[data-action="notification-shade"]', '[data-shade-trigger]'],
        ariaPatterns: ['notification\\s*shade', 'notifications', 'quick\\s*settings'],
        textPatterns: ['notifications', 'shade'],
      }, 'Android Notification Shade trigger');

      await page.waitForFunction((needle) => (document.body.innerText || '').includes(needle), {
        timeoutMs: 6000,
        args: [shadeTitle],
      });
      await page.pressKey('Escape');

      // Capture baseline BEFORE opening Recents so pre-existing live window titlebar `×` is blocked
      const recentsBaseline = await captureRecentsBaseline(page);
      await clickSemanticControl(page, {
        dataSelectors: ['[data-nav="recents"]', '[data-action="recents"]', '[data-android-recents]'],
        ariaPatterns: ['recents', 'overview', 'recent\\s*apps'],
        textPatterns: ['recents', 'overview'],
      }, 'Android 3-Button Nav Recents');

      const recentsDismiss = await waitUntil(async () => {
        const hit = await findRecentsDismissControl(page, recentsBaseline, {
          windowId: notesWinId,
          notesPid,
          notesTitle,
          notesAppId,
        });
        return hit?.found ? hit : null;
      }, { timeoutMs: 6000, label: `Android Recents close/kill button for Notes (PID ${notesPid})` });

      await page.clickAt(recentsDismiss.x, recentsDismiss.y);

      // Strictly assert backend PID killed + window disappeared (with strictWindowId disappearance guard!) + sibling macPid alive
      await waitUntil(async () => {
        const pRes = await server.api.get('/api/v1/processes', { expectOk: true });
        const procs = asArray(pRes.json, ['processes', 'items', 'data']);
        const hit = procs.find((p) => p.pid === notesPid);
        const procDead = !hit || hit.state === 'TERMINATED' || hit.state === 'ZOMBIE';
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const winGone = !asArray(s, ['windows']).some((w) => getWinId(w) === notesWinId);
        return procDead && winGone;
      }, { timeoutMs: 6000, label: `Notes PID ${notesPid} and window ${notesWinId} terminated via Android Recents` });

      await page.pressKey('Escape');
      const domNotesGone = await findVisibleWindow(page, {
        windowId: notesWinId,
        titleSubstring: notesTitle,
        strictWindowId: notesUsedWindowIdAttr,
      });
      assert.equal(domNotesGone.found, false, 'Killed Notes window must not remain visible in DOM');

      const macProcNow = await server.api.get(`/api/v1/processes/${macPid}`, { expectOk: true });
      assertAliveState(extractProcState(macProcNow.json), `sibling macos-studio PID ${macPid}`);

      await switchShellModeInUi(page, server.api, 'unified');
      assertZeroBrowserErrors(page, 'T4-S04-02');
    } finally {
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        if (notesAppId) await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/stop`, {}).catch(() => {});
        if (macAppId) await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(macAppId)}/stop`, {}).catch(() => {});
        if (dndBefore !== null) await setSystemConfigHttp(suiteServer.api, 'dnd', dndBefore).catch(() => {});
        await setShellModeHttp(suiteServer.api, 'unified').catch(() => {});
      }
    }
  });
});
