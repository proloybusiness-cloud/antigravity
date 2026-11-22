/**
 * OmniOS Tier 1 E2E Suite — FA-16: Live Adaptive 5-Mode Web/Desktop Shell GUI (Headless Chromium CDP)
 * Covers PROJECT.md Features: F-073, F-074, F-075, F-076, F-077, F-078, F-079, F-080, F-081, F-082, F-083, F-084.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Drives /usr/lib/chromium/chromium live via zero-dep CDP client (../lib/cdp-client.mjs).
 * - Resilient semantic DOM discovery (data-* -> ARIA -> accessible text -> native elements)
 *   cross-verified against REAL backend REST /api/v1/* truth + strict 0 console/page/CDN errors.
 * - Zero skips, zero stubs, guaranteed browser & server teardown.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  REPO_ROOT,
  createTempDataDir,
  startOmniServer,
} from '../lib/env.mjs';
import { launchBrowser } from '../lib/cdp-client.mjs';
import { buildCustomApk } from '../lib/fixtures-android-win.mjs';
import { buildCustomUapp } from '../lib/fixtures-apple-wasm.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
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

function asArray(payload, keys = ['items', 'data', 'windows', 'processes', 'packages', 'audit', 'entries', 'notifications']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return [];
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
  { role: 'terminal', preferredId: 'sys.terminal', pattern: /omniterm|terminal/i },
  { role: 'files', preferredId: 'sys.files', pattern: /omnifiles|files/i },
  { role: 'monitor', preferredId: 'sys.monitor', pattern: /monitor|task/i },
  { role: 'apphub', preferredId: 'sys.apphub', pattern: /apphub|app[\s_-]*hub/i },
  { role: 'settings', preferredId: 'sys.settings', pattern: /settings|privacy/i },
  { role: 'inspector', preferredId: 'sys.inspector', pattern: /inspector/i },
  { role: 'notes', preferredId: 'sys.notes', pattern: /omninotes|notes/i },
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
      /^(?:sys|system|builtin)\./i.test(appId)
    );
    out.push({ appId, name, platform, isBuiltin, fromInstalled });
  };

  if (Array.isArray(source)) {
    for (const item of source) add(item);
  } else if (typeof source === 'object') {
    const arr = asArray(source, ['packages', 'apps', 'catalog', 'items', 'data', 'entries']);
    if (arr.length > 0) {
      for (const item of arr) add(item);
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
    if (!c?.appId) continue;
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

  for (const { role, preferredId, pattern } of SYSTEM_APP_ROLES) {
    const matches = list
      .filter((c) => !used.has(c.appId) && (c.appId === preferredId || pattern.test(c.appId) || pattern.test(c.name)))
      .map((c) => {
        let score = 0;
        if (c.fromInstalled) score += 200;
        if (c.appId === preferredId) score += 50;
        if (c.isBuiltin) score += 40;
        if (!c.platform || c.platform === 'system' || c.platform === 'universal' || c.platform === 'omnios') score += 10;
        if (/sharer/i.test(`${c.appId} ${c.name}`)) score -= 25;
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

  assert.equal(
    new Set(Object.values(resolved)).size,
    SYSTEM_APP_ROLES.length,
    `Expected 7 distinct built-in system apps, resolved: ${JSON.stringify(resolved)}`
  );
  return resolved;
}

function getXY(win) {
  return {
    x: win?.bounds?.x ?? win?.x,
    y: win?.bounds?.y ?? win?.y,
  };
}

async function getSystemConfig(api) {
  const res = await api.get('/api/v1/config/system', { expectOk: true });
  return res.json?.system ?? res.json?.config ?? res.json ?? {};
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

// ============================================================================
// Semantic Resilient DOM Discovery & Assertion Helpers
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

/**
 * Discovers a visible interactive control using resilient semantic priority:
 * (1) data-* selectors -> (2) ARIA aria-label/title -> (3) accessible visible text on semantic interactive elements.
 * Never depends on guessed private CSS class names.
 */
async function findVisibleControl(page, {
  dataSelectors = [],
  ariaPatterns = [],
  textPatterns = [],
  tags = 'button, [role="button"], [role="tab"], [role="switch"], [role="menuitem"], [role="option"], a, select, input, label',
  scopeSelector = null,
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

    // Priority 1: data-* selectors
    for (const sel of spec.dataSelectors || []) {
      const list = Array.from(root.querySelectorAll(sel));
      const hit = list.find(isTrulyVisible);
      if (hit) return describe(hit);
    }

    const candidates = Array.from(root.querySelectorAll(spec.tags)).filter(isTrulyVisible);

    // Priority 2: ARIA aria-label / title
    const ariaRes = (spec.ariaPatterns || []).map((p) => new RegExp(p, 'i'));
    for (const re of ariaRes) {
      const hit = candidates.find((el) => {
        const a = `${el.getAttribute('aria-label') || ''} ${el.getAttribute('title') || ''}`.trim();
        return a.length > 0 && re.test(a);
      });
      if (hit) return describe(hit);
    }

    // Priority 3: accessible visible text — pick smallest bounding-box area (innermost matching control),
    // skipping near-full-viewport container wrappers (div/section/etc.)
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
  }, { dataSelectors, ariaPatterns, textPatterns, tags, scopeSelector });
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

async function findVisibleWindow(page, { windowId = null, titleSubstring = null } = {}) {
  return await page.evalFn((opts) => {
    function isVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    let winEl = null;
    if (opts.windowId) {
      for (const sel of [
        `[data-window-id="${opts.windowId}"]`,
        `[data-win-id="${opts.windowId}"]`,
        `[id="${opts.windowId}"]`,
      ]) {
        const el = document.querySelector(sel);
        if (el && isVisible(el)) {
          winEl = el;
          break;
        }
      }
    }

    if (!winEl && opts.titleSubstring) {
      const needle = opts.titleSubstring.toLowerCase();
      const all = Array.from(document.querySelectorAll('section, article, div, [role="dialog"], [role="region"], [data-window-id]'));
      let best = null;
      let bestArea = Infinity;
      for (const el of all) {
        if (!isVisible(el)) continue;
        const r = el.getBoundingClientRect();
        if (r.width < 120 || r.height < 80) continue;
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

    if (!winEl) return { found: false };
    const r = winEl.getBoundingClientRect();
    const st = window.getComputedStyle(winEl);
    const zIndex = Number.parseInt(st.zIndex, 10);

    // Locate header/titlebar drag area near top center of window (avoiding corner chrome buttons)
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
      rect: { left: r.left, top: r.top, width: r.width, height: r.height },
      titleBarCenter,
      zIndex: Number.isFinite(zIndex) ? zIndex : 0,
      hasCanvas: Boolean(cr),
      canvasRect: cr ? { left: cr.left, top: cr.top, width: cr.width, height: cr.height } : null,
      chromeButtonsCount: chromeButtons.length,
      text: (winEl.innerText || '').slice(0, 400),
    };
  }, { windowId, titleSubstring });
}

async function inspectWindowCanvas(page, { windowId = null, titleSubstring = null } = {}) {
  return await page.evalFn((opts) => {
    function isVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    let winEl = null;
    if (opts.windowId) {
      for (const sel of [
        `[data-window-id="${opts.windowId}"]`,
        `[data-win-id="${opts.windowId}"]`,
        `[id="${opts.windowId}"]`,
      ]) {
        const el = document.querySelector(sel);
        if (el && isVisible(el)) {
          winEl = el;
          break;
        }
      }
    }

    if (!winEl && opts.titleSubstring) {
      const needle = opts.titleSubstring.toLowerCase();
      const all = Array.from(document.querySelectorAll('section, article, div, [role="dialog"], [role="region"], [data-window-id]'));
      let best = null;
      let bestArea = Infinity;
      for (const el of all) {
        if (!isVisible(el)) continue;
        const r = el.getBoundingClientRect();
        if (r.width < 120 || r.height < 80) continue;
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

    if (!winEl) return { found: false, reason: 'window container not found' };
    const canvas = Array.from(winEl.querySelectorAll('canvas')).find(isVisible) || winEl.querySelector('canvas');
    if (!canvas) return { found: false, reason: 'canvas not found inside window container' };
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

    return {
      preCloseCenters,
      preVisibleDialogs,
    };
  });
}

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

    function mentionsNotes(el) {
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
      const pidSelectors = [
        `[data-recents-pid="${opts.notesPid}"] [data-action="kill"]`,
        `[data-recents-pid="${opts.notesPid}"] [data-action="close"]`,
        `[data-recents-pid="${opts.notesPid}"] [data-action="dismiss"]`,
        `[data-recents-pid="${opts.notesPid}"] button`,
        `[data-pid="${opts.notesPid}"] [data-action="kill"]`,
        `[data-pid="${opts.notesPid}"] [data-action="close"]`,
        `[data-pid="${opts.notesPid}"] button`,
      ];
      for (const sel of pidSelectors) {
        const hit = Array.from(container.querySelectorAll(sel)).find((b) => isVisible(b) && !isInsideLiveWindow(b, container) && (!requireNewPosition || !matchesPreCloseCenter(b)));
        if (hit) return describeBtn(hit);
      }

      // Narrow to the smallest visible card inside `container` that mentions Notes and holds a visible button
      let scope = container;
      const isDirectPidCard = container.getAttribute('data-recents-pid') === String(opts.notesPid) ||
        container.getAttribute('data-pid') === String(opts.notesPid);
      if (!isDirectPidCard) {
        let bestCard = null;
        let bestArea = Infinity;
        for (const el of container.querySelectorAll('article, section, li, div, [role="listitem"]')) {
          if (!isVisible(el) || isInsideLiveWindow(el, container)) continue;
          if (!mentionsNotes(el)) continue;
          const hasBtn = Array.from(el.querySelectorAll('button, [role="button"]')).some(
            (b) => isVisible(b) && !isInsideLiveWindow(b, container) && (!requireNewPosition || !matchesPreCloseCenter(b))
          );
          if (!hasBtn) continue;
          const r = el.getBoundingClientRect();
          const area = r.width * r.height;
          if (area < bestArea || (area === bestArea && bestCard && bestCard.contains(el))) {
            bestArea = area;
            bestCard = el;
          }
        }
        if (bestCard) scope = bestCard;
      }

      // Check explicit close/kill action buttons inside narrowed scope
      for (const sel of ['[data-action="kill"]', '[data-action="close"]', '[data-action="dismiss"]']) {
        const hits = Array.from(scope.querySelectorAll(sel)).filter((b) => isVisible(b) && !isInsideLiveWindow(b, container) && (!requireNewPosition || !matchesPreCloseCenter(b)));
        if (hits.length > 0) return describeBtn(hits[0]);
      }

      // Semantic close/kill buttons inside narrowed scope
      const btns = Array.from(scope.querySelectorAll('button, [role="button"]')).filter((b) => isVisible(b) && !isInsideLiveWindow(b, container) && (!requireNewPosition || !matchesPreCloseCenter(b)));
      const ariaHit = btns.find((b) => /close|kill|dismiss|remove|end\s*task/i.test(`${b.getAttribute('aria-label') || ''} ${b.getAttribute('title') || ''}`));
      if (ariaHit) return describeBtn(ariaHit);

      const textHit = btns.find((b) => /^(?:close|kill|dismiss|×|x|✕|✖)$/i.test(String(b.innerText || b.textContent || '').trim()));
      if (textHit) return describeBtn(textHit);

      return null;
    }

    // Step 1: Explicit Recents overlay / card container (strictly outside live app window)
    const explicitSelectors = [
      `[data-recents-pid="${opts.notesPid}"]`,
      '[data-recents-card]',
      '[data-recents-overlay]',
      '[data-overlay="recents"]',
      '[data-recents]',
      '[data-recents-list]',
      '[aria-label*="recents" i]:not(button)',
      '[aria-label*="recent apps" i]:not(button)',
    ];
    for (const sel of explicitSelectors) {
      for (const container of document.querySelectorAll(sel)) {
        if (!isVisible(container) || isInsideLiveWindow(container)) continue;
        if (!mentionsNotes(container)) continue;
        const btn = findDismissInside(container, false);
        if (btn) return btn;
      }
    }

    // Step 2: Newly appeared generic overlay/dialog container (strictly outside live window & excluding pre-click close positions)
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

async function switchShellModeInUi(page, api, mode) {
  const modeLabelMap = {
    unified: ['unified', 'hybrid', 'all-in-one'],
    windows: ['windows', 'win'],
    macos: ['macos', 'mac\\s*os'],
    ios: ['^ios$', '\\bios\\b'],
    android: ['android'],
  };
  const patterns = modeLabelMap[mode] ?? [mode];

  // Try direct button/tab first, else <select> mode switcher
  const btn = await findVisibleControl(page, {
    dataSelectors: [
      `[data-shell-mode="${mode}"]`,
      `[data-mode="${mode}"]`,
      `[data-action="shell-mode"][data-value="${mode}"]`,
    ],
    ariaPatterns: patterns,
    textPatterns: patterns,
    tags: 'button, [role="button"], [role="tab"], [role="menuitem"], [role="radio"], a, label',
  });

  if (btn.found) {
    await page.clickAt(btn.x, btn.y);
  } else {
    const selected = await page.evalFn((targetMode, pats) => {
      const res = pats.map((p) => new RegExp(p, 'i'));
      for (const sel of Array.from(document.querySelectorAll('select'))) {
        const opt = Array.from(sel.options).find(
          (o) => o.value.toLowerCase() === targetMode || res.some((r) => r.test(o.textContent || ''))
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

  // Cross-verify against REAL backend snapshot + config store
  await waitUntil(async () => {
    const snap = await api.get('/api/v1/compositor/snapshot', { expectOk: true });
    const cfg = await getSystemConfig(api);
    const cfgMode = cfg.shellMode ?? cfg['system.shellMode'];
    return snap.json?.shellMode === mode && cfgMode === mode;
  }, { timeoutMs: 6000, label: `backend shellMode === "${mode}"` });

  // Verify live DOM reflects active mode
  await page.waitForFunction((targetMode) => {
    const roots = [document.documentElement, document.body, document.querySelector('[data-shell-mode], [data-mode], main, #app')].filter(Boolean);
    const attrHit = roots.some((el) => {
      const ds = `${el.dataset?.shellMode || ''} ${el.dataset?.mode || ''} ${el.className || ''}`.toLowerCase();
      return ds.includes(targetMode);
    });
    const activeBtn = Array.from(document.querySelectorAll(`[data-shell-mode="${targetMode}"], [data-mode="${targetMode}"]`)).some(
      (el) => el.getAttribute('aria-pressed') === 'true' || el.getAttribute('aria-selected') === 'true' || /active|selected/i.test(el.className || '')
    );
    return attrHit || activeBtn;
  }, { timeoutMs: 5000, args: [mode] });
}

// ============================================================================
// Lazy Shared Suite Environment (Server FIRST so absent OS fails cleanly
// with E_OMNIOS_NOT_IMPLEMENTED without spawning Chromium!)
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

describe('Tier 1 — FA-16: Live Adaptive 5-Mode Web/Desktop Shell GUI (Headless Chromium CDP)', () => {
  it('T1-FA16-01 [F-073/F-084]: Offline-safe Chromium load, zero console/page/CDN errors, live /ws & push rendering', async () => {
    let page = null;
    let unsubNet = () => {};
    try {
      const { server, browser } = await getSuiteEnv();
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
      await page.waitForFunction(() => Boolean(document.body && document.body.innerText.trim().length > 0), { timeoutMs: 8000 });

      // Assert live /ws connection opened by frontend
      await waitUntil(
        () => wsUrls.some((u) => u.endsWith('/ws') || u.includes('/ws?')),
        { timeoutMs: 6000, label: 'Chromium frontend /ws WebSocket connection' }
      );

      // Assert 0 external CDN requests (both network traffic and HTML tags)
      assert.deepEqual(externalRequests, [], `Offline-safe violated: external HTTP requests sent: ${JSON.stringify(externalRequests)}`);
      const externalTags = await page.evalFn((origin) => {
        const bad = [];
        for (const el of document.querySelectorAll('script[src], link[href]')) {
          const u = el.getAttribute('src') || el.getAttribute('href') || '';
          if (/^https?:\/\//i.test(u) && !u.startsWith(origin)) bad.push(u);
        }
        return bad;
      }, server.baseUrl);
      assert.deepEqual(externalTags, [], `External CDN tags found in DOM: ${JSON.stringify(externalTags)}`);

      // Live /ws push without page reload: snapshot baseline badge counts BEFORE posting
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

      const nonce = makeNonce();
      const notifTitle = `LiveWs_${nonce}`;
      await server.api.post('/api/v1/ipc/notifications', {
        appId: 'sys.test',
        platform: 'universal',
        title: notifTitle,
        body: `Push_${nonce}`,
        priority: 'high',
        category: 'system',
      }, { expectOk: true });

      await page.waitForFunction((needle, prevBadges) => {
        if ((document.body.innerText || '').includes(needle)) return true;
        // Also accept live notification badge count strictly increasing above pre-POST baseline
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
      }, { timeoutMs: 6000, args: [notifTitle, beforeBadges] });

      assertZeroBrowserErrors(page, 'T1-FA16-01');
    } finally {
      unsubNet();
      if (page) await page.close().catch(() => {});
    }
  });

  it('T1-FA16-02 [F-074/F-075]: Live Multi-Window Compositor (uiTree + <canvas> DrawOps), adaptive chrome, focus/z-order & CDP drag', async () => {
    let page = null;
    let canvasAppId = null;
    let notesAppId = null;
    try {
      const { server, browser } = await getSuiteEnv();
      const sysApps = await discoverSystemAppsHttp(server.api);
      notesAppId = sysApps.notes;

      // Ensure universal-canvas.uapp is installed
      const uappBuf = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', 'universal-canvas.uapp'));
      const inst = await installPackageHttp(server.api, uappBuf, 'universal-canvas.uapp');
      canvasAppId = inst?.appId ?? inst?.package?.appId ?? inst?.id;
      assert.ok(canvasAppId, `Expected appId installing universal-canvas.uapp: ${JSON.stringify(inst)}`);

      // Launch both built-in Notes (uiTree) and universal-canvas (DrawOps <canvas>)
      await server.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/launch`, {}, { expectOk: true });
      await server.api.post(`/api/v1/packages/${encodeURIComponent(canvasAppId)}/launch`, {}, { expectOk: true });

      const snap0 = await waitUntil(async () => {
        const res = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(res.json, ['windows']);
        const wNotes = wins.find((w) => w.appId === notesAppId);
        const wCanvas = wins.find((w) => w.appId === canvasAppId);
        return wNotes && wCanvas ? { wNotes, wCanvas, focusedWindowId: res.json.focusedWindowId } : null;
      }, { timeoutMs: 8000, label: `both ${notesAppId} and universal-canvas windows in backend snapshot` });

      const notesWinId = snap0.wNotes.windowId ?? snap0.wNotes.id;
      const canvasWinId = snap0.wCanvas.windowId ?? snap0.wCanvas.id;

      // Place windows apart so neither completely occludes the other
      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(notesWinId)}/move`, { x: 60, y: 80 });
      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(canvasWinId)}/move`, { x: 480, y: 120 });

      page = await browser.newPage();
      await page.goto(server.baseUrl);

      const domNotes = await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: notesWinId, titleSubstring: snap0.wNotes.title || 'Notes' });
        return w.found ? w : null;
      }, { timeoutMs: 8000, label: `visible ${notesAppId} window in DOM` });

      const domCanvas = await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: canvasWinId, titleSubstring: snap0.wCanvas.title || 'Canvas' });
        return w.found && w.hasCanvas ? w : null;
      }, { timeoutMs: 8000, label: 'visible universal-canvas window with <canvas> in DOM' });

      assert.ok(domNotes.text.trim().length > 0, `Expected rendered semantic uiTree text inside ${notesAppId} window`);
      assert.ok(domNotes.chromeButtonsCount >= 1, 'Expected adaptive window chrome control buttons in title bar');

      // Verify real 2D DrawOps rasterized non-zero RGBA pixels onto <canvas> scoped strictly to matched window container
      const canvasStats = await inspectWindowCanvas(page, {
        windowId: canvasWinId,
        titleSubstring: snap0.wCanvas.title || 'Canvas',
      });
      assert.ok(canvasStats.found && canvasStats.width > 0 && canvasStats.height > 0, `Expected sized <canvas> inside window container, got: ${JSON.stringify(canvasStats)}`);
      assert.ok(canvasStats.nonZeroPixels > 0, `Expected non-zero rendered DrawOp pixels on window <canvas>, got: ${JSON.stringify(canvasStats)}`);

      // Click the currently unfocused window to raise z-order & focus
      const targetFocusId = snap0.focusedWindowId === notesWinId ? canvasWinId : notesWinId;
      const targetTitle = targetFocusId === notesWinId ? (snap0.wNotes.title || 'Notes') : (snap0.wCanvas.title || 'Canvas');
      const targetDom = targetFocusId === notesWinId ? domNotes : domCanvas;
      const otherDomId = targetFocusId === notesWinId ? canvasWinId : notesWinId;
      const otherTitle = otherDomId === notesWinId ? (snap0.wNotes.title || 'Notes') : (snap0.wCanvas.title || 'Canvas');

      await page.clickAt(targetDom.titleBarCenter.x, targetDom.titleBarCenter.y);
      await waitUntil(async () => {
        const s = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        return s.json?.focusedWindowId === targetFocusId;
      }, { timeoutMs: 5000, label: `backend focusedWindowId to become ${targetFocusId}` });

      const zFocused = (await findVisibleWindow(page, { windowId: targetFocusId, titleSubstring: targetTitle })).zIndex;
      const zOther = (await findVisibleWindow(page, { windowId: otherDomId, titleSubstring: otherTitle })).zIndex;
      assert.ok(zFocused >= zOther, `Expected focused window z-index (${zFocused}) >= background (${zOther})`);

      // Real CDP drag on focused window title bar by (+70, +45)
      const beforeSnap = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      const beforeWin = asArray(beforeSnap.json, ['windows']).find((w) => (w.windowId ?? w.id) === targetFocusId);
      const beforeXY = getXY(beforeWin);
      assert.ok(
        beforeXY.x !== undefined && beforeXY.y !== undefined,
        `Expected numeric window coordinates in backend snapshot, got: ${JSON.stringify(beforeWin)}`
      );
      const beforeDom = await findVisibleWindow(page, { windowId: targetFocusId, titleSubstring: targetTitle });

      await page.drag(
        { x: beforeDom.titleBarCenter.x, y: beforeDom.titleBarCenter.y },
        { x: beforeDom.titleBarCenter.x + 70, y: beforeDom.titleBarCenter.y + 45 },
        { steps: 10 }
      );

      await waitUntil(async () => {
        const s = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const cur = asArray(s.json, ['windows']).find((w) => (w.windowId ?? w.id) === targetFocusId);
        const curDom = await findVisibleWindow(page, { windowId: targetFocusId, titleSubstring: targetTitle });
        const curXY = getXY(cur);
        const backendMoved = Boolean(
          cur &&
          curXY.x !== undefined &&
          curXY.y !== undefined &&
          (curXY.x !== beforeXY.x || curXY.y !== beforeXY.y)
        );
        const domMoved = curDom.found && (Math.abs(curDom.rect.left - beforeDom.rect.left) > 10 || Math.abs(curDom.rect.top - beforeDom.rect.top) > 10);
        return Boolean(backendMoved && domMoved);
      }, { timeoutMs: 5000, label: 'window DOM rect and backend bounds updated after CDP drag' });

      assertZeroBrowserErrors(page, 'T1-FA16-02');
    } finally {
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        if (notesAppId) {
          await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/stop`, {}).catch(() => {});
        }
        if (canvasAppId) {
          await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(canvasAppId)}/stop`, {}).catch(() => {});
        }
      }
    }
  });

  it('T1-FA16-03 [F-076/F-075]: Live 5-Mode Shell Switcher (windows, macos, ios, android, unified) preserving open windows & persisting across reload', async () => {
    let page = null;
    let notesAppId = null;
    try {
      const { server, browser } = await getSuiteEnv();
      const sysApps = await discoverSystemAppsHttp(server.api);
      notesAppId = sysApps.notes;

      const launched = await server.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/launch`, {}, { expectOk: true });
      const notesPid = launched.json?.pid ?? launched.json?.process?.pid;
      assert.ok(notesPid > 1);

      const notesWin = await waitUntil(async () => {
        const s = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        return asArray(s.json, ['windows']).find((w) => w.pid === notesPid || w.appId === notesAppId) ?? null;
      }, { timeoutMs: 6000, label: `${notesAppId} window` });
      const notesWinId = notesWin.windowId ?? notesWin.id;

      page = await browser.newPage();
      await page.goto(server.baseUrl);
      await page.waitForFunction(() => Boolean(document.body && document.body.innerText.trim().length > 0), { timeoutMs: 8000 });

      for (const mode of ['windows', 'macos', 'ios', 'android', 'unified']) {
        await switchShellModeInUi(page, server.api, mode);

        const snap = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(snap.json, ['windows']);
        assert.ok(
          wins.some((w) => (w.windowId ?? w.id) === notesWinId && w.pid === notesPid),
          `Expected ${notesAppId} window (${notesWinId}, PID ${notesPid}) to remain open after switching to "${mode}" mode`
        );
      }

      // Verify persistence across full page reload
      await switchShellModeInUi(page, server.api, 'macos');
      await page.goto(server.baseUrl);
      await page.waitForFunction(() => {
        const roots = [document.documentElement, document.body, document.querySelector('[data-shell-mode], [data-mode], main, #app')].filter(Boolean);
        return roots.some((el) => `${el.dataset?.shellMode || ''} ${el.dataset?.mode || ''} ${el.className || ''}`.toLowerCase().includes('macos'));
      }, { timeoutMs: 8000 });

      const snapAfter = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      assert.equal(snapAfter.json?.shellMode, 'macos');

      await switchShellModeInUi(page, server.api, 'unified');
      assertZeroBrowserErrors(page, 'T1-FA16-03');
    } finally {
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        if (notesAppId) {
          await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/stop`, {}).catch(() => {});
        }
        await suiteServer.api.post('/api/v1/compositor/shell-mode', { mode: 'unified', shellMode: 'unified' }).catch(() => {});
      }
    }
  });

  it('T1-FA16-04 [F-077/F-078]: macOS UX (Global Top Menu Bar, Floating Dock, Spotlight Ctrl+Space) & Windows UX (Start Menu, Snap Layout)', async () => {
    let page = null;
    let macAppId = null;
    try {
      const { server, browser } = await getSuiteEnv();
      const nonce = makeNonce();

      // Seed unique VFS document for live Spotlight verification
      const docName = `gui-spot-${nonce}.txt`;
      const docPath = `/home/user/Documents/${docName}`;
      const wRes = await writeWithMethodFallback(
        server.api,
        ['PUT', 'POST'],
        '/api/v1/vfs/file',
        { path: docPath, content: `SPOT_${nonce}`, data: `SPOT_${nonce}`, encoding: 'utf8' }
      );
      assert.ok(wRes.ok, `Expected 2xx seeding Spotlight file: ${wRes.status}`);

      // Install & launch macOS Studio sample app (publishes Global Top Menu Bar)
      const macBuf = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', 'macos-studio.app.zip'));
      const inst = await installPackageHttp(server.api, macBuf, 'macos-studio.app.zip');
      macAppId = inst?.appId ?? inst?.package?.appId ?? inst?.id;
      await server.api.post(`/api/v1/packages/${encodeURIComponent(macAppId)}/launch`, {}, { expectOk: true });

      const macWin = await waitUntil(async () => {
        const s = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        return asArray(s.json, ['windows']).find((w) => w.appId === macAppId) ?? null;
      }, { timeoutMs: 8000, label: 'macos-studio window' });
      const macWinId = macWin.windowId ?? macWin.id;
      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(macWinId)}/focus`, {});

      page = await browser.newPage();
      await page.goto(server.baseUrl);
      await page.waitForFunction(() => Boolean(document.body && document.body.innerText.trim().length > 0), { timeoutMs: 8000 });

      // ---- macOS Mode UX ----
      await switchShellModeInUi(page, server.api, 'macos');

      const snapMac = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      const activeMenus = Array.isArray(snapMac.json?.activeMenuBar) && snapMac.json.activeMenuBar.length > 0
        ? snapMac.json.activeMenuBar
        : (macWin.menuBar ?? []);
      assert.ok(activeMenus.length > 0, `Expected non-empty activeMenuBar for macos-studio, got: ${JSON.stringify(snapMac.json)}`);

      const firstMenuLabel = String(activeMenus[0]?.label ?? activeMenus[0]?.title ?? activeMenus[0] ?? '');
      await page.waitForFunction((lbl) => {
        return Boolean(lbl) && (document.body.innerText || '').includes(lbl);
      }, { timeoutMs: 5000, args: [firstMenuLabel] });

      // Verify visible Floating Dock renders launcher items
      const dockVisible = await page.evalFn(() => {
        const dock = document.querySelector('[data-dock], [role="toolbar"][aria-label*="dock" i], [aria-label*="dock" i], nav');
        if (!dock) return false;
        const r = dock.getBoundingClientRect();
        return r.width > 0 && r.height > 0 && dock.querySelectorAll('button, [role="button"], a').length >= 2;
      });
      assert.ok(dockVisible, 'Expected visible macOS Floating Dock with app launcher items');

      // Spotlight via Ctrl+Space -> type unique filename -> verify live search hit
      await page.pressKey('Space', 'Ctrl');
      const spotInput = await waitUntil(async () => {
        const hit = await page.evalFn(() => {
          const candidates = Array.from(document.querySelectorAll(
            '[data-spotlight] input, [role="searchbox"], [role="combobox"], [aria-label*="spotlight" i], [aria-label*="search" i], input[type="search"], input[type="text"]'
          ));
          for (const el of candidates) {
            const st = window.getComputedStyle(el);
            const r = el.getBoundingClientRect();
            if (st.display !== 'none' && st.visibility !== 'hidden' && r.width > 0 && r.height > 0) {
              el.focus();
              return true;
            }
          }
          return false;
        });
        return hit ? true : null;
      }, { timeoutMs: 5000, label: 'visible Spotlight search input after Ctrl+Space' });
      assert.ok(spotInput);

      await page.send('Input.insertText', { text: `gui-spot-${nonce}` });
      // Require full docName (including .txt, which was NOT typed) so "No results for gui-spot-..." cannot pass
      await page.waitForFunction((needle) => (document.body.innerText || '').includes(needle), {
        timeoutMs: 6000,
        args: [docName],
      });
      await page.pressKey('Escape');

      // ---- Windows Mode UX ----
      await switchShellModeInUi(page, server.api, 'windows');

      // Click Start Menu button & assert a NEWLY visible Start Menu overlay displays multiple app launchers
      const startMenuSelectors = [
        '[data-start-menu]',
        '[data-overlay="start"]',
        '[role="menu"]',
        '[role="dialog"]',
        '[aria-label*="start menu" i]',
        '[aria-label*="start" i]:not(button)',
      ];
      const startBaseline = await captureOverlayBaseline(page, startMenuSelectors);
      await clickSemanticControl(page, {
        dataSelectors: ['[data-start-button]', '[data-action="start-menu"]', '[data-windows-start]'],
        ariaPatterns: ['start'],
        textPatterns: ['^start$'],
      }, 'Windows Start button');

      await waitForNewAppOverlay(page, startBaseline, startMenuSelectors, 5000);
      await page.pressKey('Escape');

      // Window Snap Layout (via visible snap button if exposed, else via snap state + live DOM width check)
      const snapCtrl = await findVisibleControl(page, {
        dataSelectors: [
          `[data-window-id="${macWinId}"] [data-snap="snapped-left"]`,
          `[data-window-id="${macWinId}"] [data-snap="left"]`,
          '[data-snap="snapped-left"]',
          '[data-action="snap-left"]',
        ],
        ariaPatterns: ['snap\\s*left', 'tile\\s*left'],
        textPatterns: ['snap\\s*left'],
      });
      if (snapCtrl.found) {
        await page.clickAt(snapCtrl.x, snapCtrl.y);
      } else {
        await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(macWinId)}/state`, { state: 'snapped-left' }, { expectOk: true });
      }

      await waitUntil(async () => {
        const s = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const w = asArray(s.json, ['windows']).find((x) => (x.windowId ?? x.id) === macWinId);
        const domW = await findVisibleWindow(page, { windowId: macWinId, titleSubstring: macWin.title || 'Studio' });
        return Boolean(
          w &&
          w.state === 'snapped-left' &&
          domW.found &&
          domW.rect.width > 300 &&
          domW.rect.width <= 760
        );
      }, { timeoutMs: 6000, label: 'Windows Snap Layout (snapped-left) reflected in backend & DOM half-width' });

      await switchShellModeInUi(page, server.api, 'unified');
      assertZeroBrowserErrors(page, 'T1-FA16-04');
    } finally {
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        if (macAppId) await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(macAppId)}/stop`, {}).catch(() => {});
        await suiteServer.api.post('/api/v1/compositor/shell-mode', { mode: 'unified', shellMode: 'unified' }).catch(() => {});
      }
    }
  });

  it('T1-FA16-05 [F-079/F-080]: iOS UX (Dynamic Island, Control Center -> Config Store) & Android UX (Shade, App Drawer, 3-Button Recents PID kill)', async () => {
    let page = null;
    let notesAppId = null;
    try {
      const { server, browser } = await getSuiteEnv();
      const sysApps = await discoverSystemAppsHttp(server.api);
      notesAppId = sysApps.notes;
      const nonce = makeNonce();

      page = await browser.newPage();
      await page.goto(server.baseUrl);
      await page.waitForFunction(() => Boolean(document.body && document.body.innerText.trim().length > 0), { timeoutMs: 8000 });

      // ---- iOS Mode UX ----
      await switchShellModeInUi(page, server.api, 'ios');

      const islandTitle = `Island_${nonce}`;
      await server.api.post('/api/v1/ipc/notifications', {
        appId: 'sys.weather',
        platform: 'ios',
        title: islandTitle,
        body: `LiveStatus_${nonce}`,
        priority: 'high',
        category: 'live',
        liveActivity: {
          id: `la-${nonce}`,
          title: islandTitle,
          status: `Active_${nonce}`,
          progress: 0.65,
        },
      }, { expectOk: true });

      await page.waitForFunction((needle) => (document.body.innerText || '').includes(needle), {
        timeoutMs: 6000,
        args: [islandTitle],
      });

      await clickSemanticControl(page, {
        dataSelectors: ['[data-dynamic-island]', '[data-island]'],
        ariaPatterns: ['dynamic\\s*island', 'live\\s*activity'],
        textPatterns: [islandTitle],
        tags: 'button, [role="button"], [data-dynamic-island], [data-island], div, section',
      }, 'iOS Dynamic Island pill');

      await page.waitForFunction((statusTxt) => (document.body.innerText || '').includes(statusTxt), {
        timeoutMs: 5000,
        args: [`Active_${nonce}`],
      }).catch(async () => {
        // Accept expanded Dynamic Island state attribute/size growth if status text is rendered concisely
        const expanded = await page.evalFn(() => {
          const el = document.querySelector('[data-dynamic-island], [data-island], [aria-label*="dynamic island" i]');
          if (!el) return false;
          return el.getAttribute('aria-expanded') === 'true' || /expand|open/i.test(el.className || '') || el.getBoundingClientRect().height > 44;
        });
        assert.ok(expanded, 'Expected Dynamic Island to expand on click');
      });

      // Open Control Center & flip DND (or Wi-Fi) toggle -> verify live backend Config Store flip
      await clickSemanticControl(page, {
        dataSelectors: ['[data-control-center-toggle]', '[data-action="control-center"]', '[data-control-center-trigger]'],
        ariaPatterns: ['control\\s*center'],
        textPatterns: ['control\\s*center'],
      }, 'iOS Control Center trigger');

      const cfgBefore = await getSystemConfig(server.api);
      const dndBefore = Boolean(cfgBefore.dnd ?? cfgBefore['system.dnd']);
      await clickSemanticControl(page, {
        dataSelectors: ['[data-toggle="dnd"]', '[data-config-key="dnd"]', '[data-config-key="system.dnd"]'],
        ariaPatterns: ['do\\s*not\\s*disturb', '\\bdnd\\b'],
        textPatterns: ['do\\s*not\\s*disturb', '^dnd$', 'focus'],
      }, 'Control Center DND toggle');

      await waitUntil(async () => {
        const cfgNow = await getSystemConfig(server.api);
        return Boolean(cfgNow.dnd ?? cfgNow['system.dnd']) === !dndBefore;
      }, { timeoutMs: 5000, label: 'backend system.dnd boolean flip from Control Center' });

      // Restore DND state cleanly
      await setSystemConfigHttp(server.api, 'dnd', dndBefore);
      await page.pressKey('Escape');

      // ---- Android Mode UX ----
      await switchShellModeInUi(page, server.api, 'android');

      const notesLaunch = await server.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/launch`, {}, { expectOk: true });
      const notesPid = notesLaunch.json?.pid ?? notesLaunch.json?.process?.pid;
      assert.ok(notesPid > 1);

      const notesWin = await waitUntil(async () => {
        const s = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        return asArray(s.json, ['windows']).find((w) => w.pid === notesPid || w.appId === notesAppId) ?? null;
      }, { timeoutMs: 6000, label: `${notesAppId} window in Android mode` });
      const notesWinId = notesWin.windowId ?? notesWin.id;

      const andNotif = `AndNotif_${nonce}`;
      await server.api.post('/api/v1/ipc/notifications', {
        appId: 'sys.test',
        platform: 'android',
        title: andNotif,
        body: `Shade_${nonce}`,
        priority: 'normal',
        category: 'system',
      }, { expectOk: true });

      // Notification Shade
      await clickSemanticControl(page, {
        dataSelectors: ['[data-notification-shade-toggle]', '[data-action="notification-shade"]', '[data-shade-trigger]'],
        ariaPatterns: ['notification\\s*shade', 'notifications', 'quick\\s*settings'],
        textPatterns: ['notifications', 'shade'],
      }, 'Android Notification Shade trigger');

      await page.waitForFunction((needle) => (document.body.innerText || '').includes(needle), {
        timeoutMs: 6000,
        args: [andNotif],
      });
      await page.pressKey('Escape');

      // App Drawer — verify a NEWLY visible overlay/drawer displays multiple app launchers
      const drawerSelectors = [
        '[data-app-drawer]',
        '[data-drawer]',
        '[data-overlay="drawer"]',
        '[data-overlay="app-drawer"]',
        '[role="dialog"]',
        '[role="menu"]',
        '[aria-label*="app drawer" i]',
        '[aria-label*="all apps" i]',
      ];
      const drawerBaseline = await captureOverlayBaseline(page, drawerSelectors);
      await clickSemanticControl(page, {
        dataSelectors: ['[data-app-drawer-toggle]', '[data-action="app-drawer"]', '[data-drawer-trigger]'],
        ariaPatterns: ['app\\s*drawer', 'all\\s*apps'],
        textPatterns: ['apps', 'drawer'],
      }, 'Android App Drawer trigger');

      await waitForNewAppOverlay(page, drawerBaseline, drawerSelectors, 5000);
      await page.pressKey('Escape');

      // 3-Button Nav Bar -> Recents -> verify Recents overlay/card appeared & click close/kill strictly inside Recents
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
          notesTitle: notesWin.title || 'Notes',
          notesAppId,
        });
        return hit?.found ? hit : null;
      }, { timeoutMs: 6000, label: `Android Recents overlay card & close/kill button for ${notesAppId} (PID ${notesPid})` });

      await page.clickAt(recentsDismiss.x, recentsDismiss.y);

      await waitUntil(async () => {
        const pRes = await server.api.get('/api/v1/processes', { expectOk: true });
        const procs = asArray(pRes.json, ['processes', 'items', 'data']);
        const hit = procs.find((p) => p.pid === notesPid);
        return !hit || hit.state === 'TERMINATED' || hit.state === 'ZOMBIE';
      }, { timeoutMs: 6000, label: `${notesAppId} PID ${notesPid} terminated via Android Recents` });

      await switchShellModeInUi(page, server.api, 'unified');
      assertZeroBrowserErrors(page, 'T1-FA16-05');
    } finally {
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        if (notesAppId) {
          await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/stop`, {}).catch(() => {});
        }
        await suiteServer.api.post('/api/v1/compositor/shell-mode', { mode: 'unified', shellMode: 'unified' }).catch(() => {});
      }
    }
  });

  it('T1-FA16-06 [F-084]: Live Bidirectional Dark/Light Theme Synchronization (ui/ <-> Backend system.theme)', async () => {
    let page = null;
    let initialTheme = 'dark';
    try {
      const { server, browser } = await getSuiteEnv();
      const cfg0 = await getSystemConfig(server.api);
      initialTheme = (cfg0.theme ?? cfg0['system.theme'] ?? 'dark') === 'light' ? 'light' : 'dark';
      const oppositeTheme = initialTheme === 'dark' ? 'light' : 'dark';

      page = await browser.newPage();
      await page.goto(server.baseUrl);
      await page.waitForFunction(() => Boolean(document.body && document.body.innerText.trim().length > 0), { timeoutMs: 8000 });

      const readDomTheme = () => page.evalFn(() => ({
        rootTheme: document.documentElement.dataset?.theme || document.body.dataset?.theme || '',
        classes: `${document.documentElement.className} ${document.body.className}`,
        bg: window.getComputedStyle(document.body).backgroundColor,
      }));
      const dom0 = await readDomTheme();

      // 1. UI -> Backend: click visible Theme toggle control
      await clickSemanticControl(page, {
        dataSelectors: ['[data-toggle="theme"]', '[data-action="toggle-theme"]', '[data-theme-toggle]', '[data-config-key="theme"]'],
        ariaPatterns: ['theme', 'dark\\s*mode', 'light\\s*mode'],
        textPatterns: ['theme', 'dark', 'light'],
      }, 'Theme toggle button');

      await waitUntil(async () => {
        const cfgNow = await getSystemConfig(server.api);
        return (cfgNow.theme ?? cfgNow['system.theme']) === oppositeTheme;
      }, { timeoutMs: 5000, label: `backend system.theme flipped to ${oppositeTheme}` });

      await page.waitForFunction((prev, target) => {
        const curRoot = document.documentElement.dataset?.theme || document.body.dataset?.theme || '';
        const curCls = `${document.documentElement.className} ${document.body.className}`;
        const curBg = window.getComputedStyle(document.body).backgroundColor;
        return curRoot.toLowerCase() === target || curCls.toLowerCase().includes(target) || curBg !== prev.bg;
      }, { timeoutMs: 5000, args: [dom0, oppositeTheme] });

      const dom1 = await readDomTheme();

      // 2. Backend -> UI (live /ws config:changed WITHOUT reloading page)
      await setSystemConfigHttp(server.api, 'theme', initialTheme);

      await page.waitForFunction((target, before0, before1) => {
        const curRoot = document.documentElement.dataset?.theme || document.body.dataset?.theme || '';
        const curCls = `${document.documentElement.className} ${document.body.className}`;
        const curBg = window.getComputedStyle(document.body).backgroundColor;
        return (
          curRoot.toLowerCase() === target ||
          curCls.toLowerCase().includes(target) ||
          (before1.bg !== before0.bg && curBg === before0.bg)
        );
      }, { timeoutMs: 6000, args: [initialTheme, dom0, dom1] });

      assertZeroBrowserErrors(page, 'T1-FA16-06');
    } finally {
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        await setSystemConfigHttp(suiteServer.api, 'theme', initialTheme).catch(() => {});
      }
    }
  });

  it('T1-FA16-07 [F-081/F-082/F-083]: Live Universal Share Sheet (intent:chooser), Permission Prompt Modal (permission:prompt) & App Hub Binary Upload', async () => {
    let page = null;
    let ws = null;
    let tmp = null;
    let apphubAppId = null;
    const cleanupAppIds = [];
    try {
      const { server, browser } = await getSuiteEnv();
      const sysApps = await discoverSystemAppsHttp(server.api);
      apphubAppId = sysApps.apphub;
      tmp = await createTempDataDir('omnios-fa16-upload-');
      ws = await server.connectWs();
      const nonce = makeNonce();

      // ---- Part 1: Universal Share Sheet (F-081) ----
      const shareScheme = `share${nonce}`;
      const appIdA = `com.omnios.sharea.${nonce}`;
      const appIdB = `com.omnios.shareb.${nonce}`;
      const nameA = `ShareA_${nonce}`;
      const nameB = `ShareB_${nonce}`;
      cleanupAppIds.push(appIdA, appIdB);

      await installPackageHttp(
        server.api,
        buildCustomUapp({ appId: appIdA, name: nameA, urlSchemes: [shareScheme], message: `SA_${nonce}\n` }),
        `sharea-${nonce}.uapp`
      );
      await installPackageHttp(
        server.api,
        buildCustomUapp({ appId: appIdB, name: nameB, urlSchemes: [shareScheme], message: `SB_${nonce}\n` }),
        `shareb-${nonce}.uapp`
      );

      page = await browser.newPage();
      await page.goto(server.baseUrl);
      await page.waitForFunction(() => Boolean(document.body && document.body.innerText.trim().length > 0), { timeoutMs: 8000 });

      const shareWsCursor = ws.mark();
      const dispatchRes = await server.api.post('/api/v1/ipc/intents/dispatch', {
        action: 'android.intent.action.VIEW',
        uri: `${shareScheme}://doc`,
        scheme: shareScheme,
      }, { expectOk: true });
      assert.equal(dispatchRes.json?.status, 'CHOOSER_REQUIRED', `Expected CHOOSER_REQUIRED, got: ${dispatchRes.text}`);

      await page.waitForFunction(
        (a, b) => {
          const txt = document.body.innerText || '';
          return txt.includes(a) && txt.includes(b);
        },
        { timeoutMs: 6000, args: [nameA, nameB] }
      );

      await clickSemanticControl(page, {
        dataSelectors: [`[data-app-id="${appIdA}"]`, `[data-choice-app="${appIdA}"]`],
        ariaPatterns: [nameA],
        textPatterns: [nameA],
      }, `Share Sheet choice ${nameA}`);

      // Verify Share Sheet modal genuinely dismisses (nameB gone from visible body text)
      await page.waitForFunction((b) => {
        if ((document.body.innerText || '').includes(b)) return false;
        const modal = document.querySelector('[data-share-sheet], [data-intent-chooser], [role="dialog"]');
        if (modal && window.getComputedStyle(modal).display !== 'none' && (modal.innerText || '').includes(b)) {
          return false;
        }
        return true;
      }, { timeoutMs: 5000, args: [nameB] });

      // Verify real backend dispatch/execution proof that chosen appIdA was launched
      await waitUntil(async () => {
        const wsMsgs = ws.getMessages(shareWsCursor);
        const wsDispatched = wsMsgs.some((m) => {
          if (m?.type === 'process:update' || m?.type === 'process:stdout') {
            const blob = JSON.stringify(m.payload ?? {});
            return blob.includes(`SA_${nonce}`) || blob.includes(appIdA);
          }
          return false;
        });
        if (wsDispatched) return true;

        const pRes = await server.api.get('/api/v1/processes', { expectOk: true });
        const procs = asArray(pRes.json, ['processes', 'items', 'data']);
        return procs.some((p) => p.appId === appIdA || JSON.stringify(p).includes(`SA_${nonce}`));
      }, { timeoutMs: 6000, label: `backend dispatch/execution proof for Share Sheet choice ${appIdA}` });

      // ---- Part 2: Security Permission Prompt Modal (F-082) ----
      const permAppId = `com.omnios.permprompt.${nonce}`;
      cleanupAppIds.push(permAppId);
      const permApk = buildCustomApk({
        packageName: permAppId,
        appLabel: `PermApp_${nonce}`,
        permissions: ['android.permission.WRITE_EXTERNAL_STORAGE'],
        outputFile: `/sdcard/Documents/perm-prompt-${nonce}.txt`,
        outputContent: `PERM_OK_${nonce}`,
      });
      await installPackageHttp(server.api, permApk, `perm-${nonce}.apk`, { grantAll: false });
      const permSetRes = await writeWithMethodFallback(server.api, ['PUT', 'POST'], '/api/v1/security/permissions', {
        appId: permAppId,
        capability: 'fs.write.user',
        state: 'prompt',
      });
      assert.ok(
        permSetRes && permSetRes.ok,
        `Expected HTTP 2xx setting fs.write.user=prompt for ${permAppId}, got ${permSetRes?.status}: ${permSetRes?.text}`
      );

      // Trigger real kernel permission:prompt by launching the APK
      await server.api.post(`/api/v1/packages/${encodeURIComponent(permAppId)}/launch`, {}, { expectOk: true });

      await page.waitForFunction((needle, appId) => {
        const modal = document.querySelector('[data-permission-modal], [data-permission-prompt], [role="dialog"], [role="alertdialog"]');
        const txt = (modal ? modal.innerText : document.body.innerText) || '';
        return txt.includes(needle) || txt.includes(appId) || (Boolean(modal) && /allow|deny/i.test(txt));
      }, { timeoutMs: 6000, args: [`PermApp_${nonce}`, permAppId] });

      await clickSemanticControl(page, {
        dataSelectors: ['[data-permission-decision="allow"]', '[data-action="permission-allow"]', '[data-allow]'],
        ariaPatterns: ['^allow$', 'grant'],
        textPatterns: ['^allow$', 'allow\\s*once', 'grant'],
      }, 'Permission Prompt Allow button');

      // Verify genuine backend Allow decision (audit allow/granted or updated permission grant) AND/OR VFS file write
      const isAllowAuditEntry = (e) => {
        if (!e || typeof e !== 'object') return false;
        if (e.appId !== permAppId && !JSON.stringify(e).includes(permAppId)) return false;
        if (e.capability && e.capability !== 'fs.write.user') return false;
        if (e.granted === false) return false;
        const decision = String(e.decision ?? e.state ?? e.policy ?? e.result ?? e.outcome ?? '').trim().toLowerCase();
        if (decision === 'deny' || decision === 'denied' || decision === 'prompt') return false;
        return e.granted === true || decision === 'allow' || decision === 'allowed' || decision === 'granted';
      };

      const hasAllowPolicy = (payload) => {
        const list = asArray(payload, ['permissions', 'grants', 'entries', 'items', 'data']);
        if (list.some((g) => (
          g?.appId === permAppId &&
          (!g.capability || g.capability === 'fs.write.user') &&
          (g.granted === true || /^(?:allow|allowed|granted)$/i.test(String(g.state ?? g.policy ?? g.decision ?? '')))
        ))) {
          return true;
        }
        const appGrants = payload?.permissions?.[permAppId] ?? payload?.grants?.[permAppId] ?? payload?.[permAppId];
        if (appGrants && typeof appGrants === 'object') {
          const v = appGrants['fs.write.user'];
          return v === true || /^(?:allow|allowed|granted)$/i.test(String(v ?? ''));
        }
        return false;
      };

      await waitUntil(async () => {
        const audRes = await server.api.get('/api/v1/security/audit', { query: { appId: permAppId, limit: 20 }, expectOk: true });
        const entries = asArray(audRes.json, ['audit', 'entries', 'items', 'data']);
        const auditAllowed = entries.some(isAllowAuditEntry);

        const permsRes = await server.api.get('/api/v1/security/permissions', { query: { appId: permAppId } });
        const policyAllowed = permsRes.ok && hasAllowPolicy(permsRes.json);

        const fRes = await server.api.get('/api/v1/vfs/file', {
          query: { path: `/home/user/Documents/perm-prompt-${nonce}.txt` },
        });
        const fContent = fRes.ok
          ? (typeof fRes.json?.content === 'string'
            ? fRes.json.content
            : (typeof fRes.json?.data === 'string' ? fRes.json.data : fRes.text))
          : '';
        const vfsWritten = fContent.includes(`PERM_OK_${nonce}`);

        return auditAllowed || policyAllowed || vfsWritten;
      }, { timeoutMs: 6000, label: `allow/granted decision or VFS file write for ${permAppId}` });

      // ---- Part 3: Binary Package Upload via <input type="file"> (F-083) ----
      const uploadAppId = `com.omnios.upload.${nonce}`;
      const uploadName = `UploadApp_${nonce}`;
      cleanupAppIds.push(uploadAppId);
      const uploadUapp = buildCustomUapp({
        appId: uploadAppId,
        name: uploadName,
        message: `UPLOAD_${nonce}\n`,
      });
      const hostPkgPath = path.join(tmp.dir, `upload-${nonce}.uapp`);
      await fs.writeFile(hostPkgPath, uploadUapp);

      // Launch built-in App Hub so package uploader input is present
      await server.api.post(`/api/v1/packages/${encodeURIComponent(apphubAppId)}/launch`, {}, { expectOk: true });
      await page.waitForSelector('input[type="file"]', 8000);
      await page.setFileInputFiles('input[type="file"]', hostPkgPath);

      // Click explicit Install confirmation button if inspection preview requires confirmation
      const maybeInstallBtn = await waitUntil(async () => {
        const pkgsRes = await server.api.get('/api/v1/packages', { expectOk: true });
        if (JSON.stringify(pkgsRes.json).includes(uploadAppId)) return 'installed';
        const btn = await findVisibleControl(page, {
          dataSelectors: ['[data-action="install-upload"]', '[data-action="install-package"]', '[data-install-btn]'],
          ariaPatterns: ['install'],
          textPatterns: ['^install$', 'install\\s*package', 'install\\s*app'],
        });
        if (btn.found) return btn;
        return null;
      }, { timeoutMs: 6000, label: 'package upload inspection or install button' });

      if (maybeInstallBtn && maybeInstallBtn !== 'installed') {
        await page.clickAt(maybeInstallBtn.x, maybeInstallBtn.y);
      }

      await waitUntil(async () => {
        const pkgsRes = await server.api.get('/api/v1/packages', { expectOk: true });
        return JSON.stringify(pkgsRes.json).includes(uploadAppId);
      }, { timeoutMs: 8000, label: `uploaded package ${uploadAppId} present in /api/v1/packages` });

      assertZeroBrowserErrors(page, 'T1-FA16-07');
    } finally {
      if (ws) await ws.close().catch(() => {});
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        if (apphubAppId) {
          await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(apphubAppId)}/stop`, {}).catch(() => {});
        }
        for (const id of cleanupAppIds) {
          await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(id)}/stop`, {}).catch(() => {});
          await suiteServer.api.delete(`/api/v1/packages/${encodeURIComponent(id)}`).catch(() => {});
        }
      }
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });
});
