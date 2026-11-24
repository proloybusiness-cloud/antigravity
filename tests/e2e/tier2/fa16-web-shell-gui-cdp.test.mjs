/**
 * OmniOS Tier 2 E2E Suite — FA-16: Live Adaptive 5-Mode Web/Desktop Shell GUI (Headless Chromium CDP)
 * Boundary, Corner & Negative Resilience Cases.
 * Covers PROJECT.md Features: F-070, F-073, F-074, F-076, F-077, F-083, F-084.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Server-first lazy initialization: startOmniServer() ALWAYS precedes launchBrowser() and temp dirs,
 *   ensuring 0 Chromium launches & 0 temp leaks if os/ is absent.
 * - Zero hardcoded system app identifiers; all built-in apps are discovered dynamically.
 * - Resilient window geometry (`w?.bounds ?? w`) & smallest-area DOM discovery.
 * - Zero skips, zero stubs, guaranteed browser & server teardown.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  createTempDataDir,
  startOmniServer,
} from '../lib/env.mjs';
import { launchBrowser } from '../lib/cdp-client.mjs';
import {
  buildMalformedPe,
  buildZipSlipArchive,
} from '../lib/fixtures-malformed.mjs';

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
      if (err?.code === 'ERR_ASSERTION') throw err;
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

function asArray(payload, keys = ['windows', 'packages', 'apps', 'catalog', 'processes', 'items', 'data', 'entries']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return [];
}

function getWinBounds(win) {
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

async function setShellModeHttp(api, mode) {
  const res = await writeWithMethodFallback(
    api,
    ['POST', 'PUT', 'PATCH'],
    '/api/v1/compositor/shell-mode',
    { mode, shellMode: mode }
  );
  assert.ok(res.ok, `Expected HTTP 2xx setting shell-mode=${mode}, got ${res.status}: ${res.text}`);
  return res;
}

async function resetShellModeBestEffort(api, mode = 'unified') {
  await writeWithMethodFallback(
    api,
    ['POST', 'PUT', 'PATCH'],
    '/api/v1/compositor/shell-mode',
    { mode, shellMode: mode }
  ).catch(() => {});
}

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
      platform === 'system'
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

async function listAllAppCandidates(api) {
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
  return Array.from(byId.values());
}

async function discoverBuiltInApp(api, patterns, excludeIds = new Set()) {
  const all = await listAllAppCandidates(api);
  for (const pattern of patterns) {
    const matches = all
      .filter((c) => !excludeIds.has(c.appId) && (pattern.test(c.appId) || pattern.test(c.name)))
      .map((c) => {
        let score = 0;
        if (c.fromInstalled) score += 200;
        if (c.isBuiltin) score += 60;
        if (!c.platform || c.platform === 'system' || c.platform === 'universal' || c.platform === 'omnios') score += 20;
        if (/sharer/i.test(`${c.appId} ${c.name}`)) score -= 40;
        return { c, score };
      })
      .sort((a, b) => b.score - a.score);
    if (matches.length > 0) {
      return matches[0].c;
    }
  }
  assert.fail(
    `Could not dynamically discover built-in app matching ${patterns.join(', ')}; available=${JSON.stringify(all.map((x) => ({ appId: x.appId, name: x.name })))}`
  );
}

async function launchAppAndAwaitWindow(api, appId) {
  const launchRes = await api.post(`/api/v1/packages/${encodeURIComponent(appId)}/launch`, {}, { expectOk: true });
  const pid = launchRes.json?.pid ?? launchRes.json?.process?.pid;
  assert.ok(Number.isInteger(pid) && pid > 1, `Expected valid PID > 1 launching ${appId}, got: ${launchRes.text}`);

  const win = await waitUntil(async () => {
    const snapRes = await api.get('/api/v1/compositor/snapshot', { expectOk: true });
    const wins = asArray(snapRes.json?.windows ?? snapRes.json?.snapshot?.windows ?? snapRes.json);
    return wins.find((w) => w.pid === pid || w.appId === appId) ?? null;
  }, { timeoutMs: 8000, label: `compositor window for ${appId} (pid=${pid})` });

  return {
    pid,
    win,
    winId: win.windowId ?? win.id,
    title: String(win.title ?? ''),
  };
}

// ============================================================================
// Error & Resilient Semantic DOM Discovery Helpers
// ============================================================================

function assertZeroBrowserErrors(page, label) {
  const pageErrs = page.getPageErrors();
  const consoleErrs = page.getConsoleErrors();
  assert.equal(
    pageErrs.length,
    0,
    `[${label}] Expected 0 uncaught page exceptions, got ${pageErrs.length}: ${JSON.stringify(pageErrs)}`
  );
  assert.equal(
    consoleErrs.length,
    0,
    `[${label}] Expected 0 console/browser errors, got ${consoleErrs.length}: ${JSON.stringify(consoleErrs)}`
  );
}

/**
 * Strict exception/JS error gate for negative upload test:
 * - Strictly 0 uncaught page exceptions
 * - Strictly 0 JS console.error messages (`type === 'error'`)
 * - Strictly 0 HTTP 5xx network errors
 * - Tolerates ONLY expected Chromium `Log.entryAdded` `source === 'network'` 4xx entries on `/api/v1/packages/`.
 */
function assertZeroPageAndUnexpectedConsoleErrors(page, label) {
  const pageErrs = page.getPageErrors();
  assert.equal(
    pageErrs.length,
    0,
    `[${label}] Expected 0 uncaught page exceptions during negative upload, got ${pageErrs.length}: ${JSON.stringify(pageErrs)}`
  );

  const unexpected = page.getConsoleErrors().filter((entry) => {
    if (entry.type !== 'log:error' || entry.source !== 'network') return true;
    const combined = `${entry.url ?? ''} ${entry.text ?? ''}`;
    const isExpectedPkg4xx =
      /\/api\/v1\/packages\//i.test(combined) &&
      /\b4\d{2}\b/.test(combined) &&
      !/\b5\d{2}\b/.test(combined);
    return !isExpectedPkg4xx;
  });

  assert.equal(
    unexpected.length,
    0,
    `[${label}] Unexpected console/network errors during negative upload: ${JSON.stringify(unexpected)}`
  );
}

async function findVisibleControl(page, {
  dataSelectors = [],
  ariaPatterns = [],
  textPatterns = [],
  tags = 'button, [role="button"], [role="tab"], [role="switch"], [role="menuitem"], [role="option"], [role="radio"], a, select, input, label',
  scopeSelector = null,
} = {}) {
  return await page.evalFn((spec) => {
    const containerTags = new Set(['div', 'section', 'article', 'main', 'aside', 'header', 'footer', 'nav', 'body', 'html']);
    const vpArea = Math.max(1, window.innerWidth * window.innerHeight);

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

    function isFullViewportContainer(el) {
      const tag = el.tagName.toLowerCase();
      if (tag === 'html' || tag === 'body') return true;
      if (!containerTags.has(tag)) return false;
      const r = el.getBoundingClientRect();
      return (r.width * r.height) >= vpArea * 0.75;
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
    if (!root) return { found: false };

    for (const sel of spec.dataSelectors || []) {
      const hit = Array.from(root.querySelectorAll(sel)).find(
        (el) => isTrulyVisible(el) && !isFullViewportContainer(el)
      );
      if (hit) return describe(hit);
    }

    const candidates = Array.from(root.querySelectorAll(spec.tags)).filter(
      (el) => isTrulyVisible(el) && !isFullViewportContainer(el)
    );

    const ariaRes = (spec.ariaPatterns || []).map((p) => new RegExp(p, 'i'));
    for (const re of ariaRes) {
      const hit = candidates.find((el) => {
        const a = `${el.getAttribute('aria-label') || ''} ${el.getAttribute('title') || ''}`.trim();
        return a.length > 0 && re.test(a);
      });
      if (hit) return describe(hit);
    }

    // Smallest-area visible match (excludes near-full-viewport container wrappers)
    const textRes = (spec.textPatterns || []).map((p) => new RegExp(p, 'i'));
    for (const re of textRes) {
      let best = null;
      let bestArea = Infinity;
      for (const el of candidates) {
        const t = String(el.innerText || el.textContent || el.value || '').trim();
        if (!t || !re.test(t)) continue;
        const r = el.getBoundingClientRect();
        const area = r.width * r.height;
        if (area < bestArea || (area === bestArea && best && best.contains(el))) {
          bestArea = area;
          best = el;
        }
      }
      if (best) return describe(best);
    }

    return { found: false };
  }, { dataSelectors, ariaPatterns, textPatterns, tags, scopeSelector });
}

async function findVisibleWindow(page, { windowId = null, titleSubstring = null, allowTitleFallback = true } = {}) {
  return await page.evalFn((opts) => {
    const INTERACTIVE_SEL = 'button, a, li, input, select, textarea, [role="button"], [role="tab"], [role="menuitem"], [role="option"]';
    const EXCLUDED_CHROME_SEL = [
      '.dock', '.taskbar', 'nav', 'header', 'footer',
      '[role="toolbar"]', '[role="menubar"]', '[role="navigation"]',
      '[data-dock]', '[data-taskbar]', '[data-menubar]',
      '[class*="dock" i]', '[class*="taskbar" i]', '[class*="launcher" i]',
      '[class*="desktop-icon" i]', '[class*="start-menu" i]', '[class*="app-drawer" i]',
      '[class*="status-bar" i]', '[class*="menubar" i]', '[class*="menu-bar" i]',
    ].join(', ');
    const WINDOW_SEMANTIC_SEL = '[data-window-id], [data-win-id], [data-window], .window, .os-window, .app-window, .compositor-window, [role="dialog"]';

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

    function isChromeOrControl(el) {
      return el.matches(INTERACTIVE_SEL) || Boolean(el.closest(EXCLUDED_CHROME_SEL));
    }

    let winEl = null;
    let matchedBy = null;

    if (opts.windowId != null && String(opts.windowId).length > 0) {
      const targetId = String(opts.windowId);
      const idCandidates = Array.from(document.querySelectorAll('[data-window-id], [data-win-id], [id]'));
      winEl = idCandidates.find((el) => {
        if (!isVisible(el) || isChromeOrControl(el)) return false;
        return (
          el.getAttribute('data-window-id') === targetId ||
          el.getAttribute('data-win-id') === targetId ||
          el.id === targetId
        );
      }) || null;
      if (winEl) matchedBy = 'id';
    }

    // Never fall back to titleSubstring when the UI attributes open windows with data-window-id / data-win-id
    const pageUsesWindowIds = Array.from(document.querySelectorAll('[data-window-id], [data-win-id]'))
      .some((el) => !isChromeOrControl(el));

    if (!winEl && opts.allowTitleFallback !== false && opts.titleSubstring && !(opts.windowId && pageUsesWindowIds)) {
      const needle = String(opts.titleSubstring).toLowerCase();
      const targetId = opts.windowId != null ? String(opts.windowId) : null;
      const all = Array.from(document.querySelectorAll(WINDOW_SEMANTIC_SEL));
      let best = null;
      let bestArea = Infinity;
      for (const el of all) {
        if (!isVisible(el) || isChromeOrControl(el)) continue;
        const elId = el.getAttribute('data-window-id') ?? el.getAttribute('data-win-id');
        if (targetId && elId && elId !== targetId) continue;
        const r = el.getBoundingClientRect();
        if (r.width < 100 || r.height < 60) continue;
        // Exclude full-viewport root containers (>= 98% of viewport)
        if (r.width >= window.innerWidth * 0.98 && r.height >= window.innerHeight * 0.98) continue;
        const txt = (el.innerText || '').toLowerCase();
        if (!txt.includes(needle)) continue;
        const area = r.width * r.height;
        if (area < bestArea) {
          bestArea = area;
          best = el;
        }
      }
      if (best) {
        winEl = best;
        matchedBy = 'title';
      }
    }

    if (!winEl) return { found: false, matchedBy: null };
    const r = winEl.getBoundingClientRect();
    return {
      found: true,
      matchedBy,
      rect: { left: r.left, top: r.top, width: r.width, height: r.height },
      text: (winEl.innerText || '').slice(0, 300),
    };
  }, { windowId, titleSubstring, allowTitleFallback });
}

async function waitForVisibleWindow(page, opts, { timeoutMs = 6000, intervalMs = 60, label = 'visible window' } = {}) {
  return await waitUntil(async () => {
    const w = await findVisibleWindow(page, opts);
    return w?.found ? w : null;
  }, { timeoutMs, intervalMs, label });
}

async function waitForShellRendered(page) {
  await page.waitForFunction(() => {
    const body = document.body;
    if (!body) return false;
    return (body.innerText || '').trim().length > 0 && document.readyState === 'complete';
  }, { timeoutMs: 10000 });
}

async function domReflectsMode(page, mode) {
  return await page.evalFn((targetMode) => {
    const lower = String(targetMode).trim().toLowerCase();
    const escaped = lower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const KNOWN_MODES = new Set(['unified', 'hybrid', 'windows', 'macos', 'ios', 'android']);
    const INTERACTIVE_SEL = 'button, a, option, input, select, textarea, [role="button"], [role="tab"], [role="option"], [role="menuitem"], [role="radio"], [role="switch"]';
    const SWITCHER_BAR_SEL = '[role="tablist"], [role="radiogroup"], [role="menu"], [role="menubar"], ul, ol';

    function isVisible(el) {
      if (!el || el.nodeType !== 1) return false;
      if (el === document.documentElement || el === document.body) return true;
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

    function attrMatchesMode(val) {
      if (!val) return false;
      const v = String(val).trim().toLowerCase();
      if (v === lower) return true;
      if (lower === 'unified' && v === 'hybrid') return true;
      return false;
    }

    function classMatchesMode(el) {
      const cls = typeof el.className === 'string' ? el.className : (el.getAttribute?.('class') || '');
      if (!cls) return false;
      const tokenRe = new RegExp(`(^|[\\s_-])${escaped}($|[\\s_-])`, 'i');
      if (tokenRe.test(cls)) return true;
      if (lower === 'unified' && /(^|\s)(?:mode-hybrid|shell-hybrid|hybrid-mode|hybrid)(\s|$)/i.test(cls)) return true;
      return false;
    }

    // 1. Primary shell root / app containers (strictly excluding interactive controls)
    const rootCandidates = [
      document.documentElement,
      document.body,
      ...Array.from(document.querySelectorAll('#app, #shell, #root, #desktop, #omnios, main, [data-shell-root], [data-shell], .shell, .os-shell, .omnios-shell')),
    ].filter((el, idx, arr) =>
      el && arr.indexOf(el) === idx && !el.matches(INTERACTIVE_SEL) && !el.closest(INTERACTIVE_SEL) && isVisible(el)
    );

    // Pass 1A: Explicit data-shell-mode / data-mode attributes on shell roots are authoritative
    let rootDeclaredOtherMode = false;
    for (const el of rootCandidates) {
      const explicitAttr = (el.getAttribute('data-shell-mode') || el.getAttribute('data-mode') || '').trim().toLowerCase();
      if (explicitAttr) {
        if (attrMatchesMode(explicitAttr)) return true;
        if (KNOWN_MODES.has(explicitAttr)) {
          rootDeclaredOtherMode = true;
        }
      }
    }
    if (rootDeclaredOtherMode) return false;

    // Pass 1B: Token-boundary mode class names on shell roots (immune to 'omnios-shell' -> 'ios')
    for (const el of rootCandidates) {
      if (classMatchesMode(el)) return true;
    }

    // 2. Non-interactive visible shell mode containers (ONLY when a single active mode is shown)
    const nonInteractiveContainers = Array.from(document.querySelectorAll('[data-shell-mode], [data-mode]'))
      .filter((el) =>
        !el.matches(INTERACTIVE_SEL) &&
        !el.closest(INTERACTIVE_SEL) &&
        !el.closest(SWITCHER_BAR_SEL) &&
        isVisible(el)
      );
    const distinctContainerModes = new Set(
      nonInteractiveContainers
        .map((el) => (el.getAttribute('data-shell-mode') || el.getAttribute('data-mode') || '').trim().toLowerCase())
        .filter((v) => KNOWN_MODES.has(v))
    );
    if (distinctContainerModes.size === 1) {
      const [onlyMode] = distinctContainerModes;
      return attrMatchesMode(onlyMode);
    }

    // 3. Explicitly active interactive switcher controls (never inactive static buttons)
    const activeControls = Array.from(document.querySelectorAll(
      '[data-shell-mode], [data-mode], [data-action="shell-mode"][data-value], input[type="radio"]:checked'
    ));
    for (const el of activeControls) {
      const isRadio = el.tagName === 'INPUT' && el.type === 'radio';
      if (isRadio) {
        const isModeRadio =
          el.hasAttribute('data-shell-mode') ||
          el.hasAttribute('data-mode') ||
          /mode|shell/i.test(el.name || '');
        if (!isModeRadio) continue;
      }
      const val = (
        el.getAttribute('data-shell-mode') ||
        el.getAttribute('data-mode') ||
        (el.getAttribute('data-action') === 'shell-mode' ? el.getAttribute('data-value') : '') ||
        (isRadio ? el.value : '')
      ).trim().toLowerCase();
      if (!attrMatchesMode(val)) continue;
      const ariaCur = el.getAttribute('aria-current');
      const isActive =
        el.getAttribute('aria-pressed') === 'true' ||
        el.getAttribute('aria-selected') === 'true' ||
        ariaCur === 'true' ||
        ariaCur === 'page' ||
        el.getAttribute('data-active') === 'true' ||
        el.classList.contains('active') ||
        el.classList.contains('is-active') ||
        el.classList.contains('selected') ||
        (isRadio && el.checked === true) ||
        (el.tagName === 'OPTION' && el.selected === true);
      if (isActive && (el.tagName === 'OPTION' || isRadio || isVisible(el))) {
        return true;
      }
    }

    // 4. <select> shell-mode dropdown (requires unified/hybrid + >=3 known modes to avoid platform filters)
    for (const sel of document.querySelectorAll('select')) {
      if (!isVisible(sel)) continue;
      const optVals = Array.from(sel.options).map((o) => String(o.value || '').trim().toLowerCase());
      const knownCount = optVals.filter((v) => KNOWN_MODES.has(v)).length;
      const hasUnified = optVals.includes('unified') || optVals.includes('hybrid');
      if (hasUnified && knownCount >= 3 && attrMatchesMode(sel.value)) return true;
    }

    return false;
  }, mode);
}

async function focusSpotlightInput(page) {
  return await page.evalFn(() => {
    const WINDOW_ANCESTOR_SEL = '[data-window-id], [data-win-id], .os-window, .app-window, .compositor-window, .window';
    const SPOTLIGHT_ANCESTOR_SEL = '[data-spotlight], [data-overlay="spotlight"], #spotlight, [class*="spotlight" i]';

    function isTrulyVisible(el) {
      if (!el || el.nodeType !== 1 || el.disabled) return false;
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

    function isEditableInput(el) {
      const tag = el.tagName.toLowerCase();
      if (tag === 'textarea' || el.isContentEditable) return true;
      if (tag === 'input') {
        const t = (el.type || 'text').toLowerCase();
        return !['hidden', 'checkbox', 'radio', 'file', 'button', 'submit', 'reset', 'image', 'range', 'color'].includes(t);
      }
      return false;
    }

    const spotlightSpecificSelectors = [
      '[data-spotlight-input]',
      '[data-testid="spotlight-input"]',
      '[data-spotlight] input',
      '[data-overlay="spotlight"] input',
      '#spotlight input',
      '[class*="spotlight" i] input',
      'input[aria-label*="spotlight" i]',
      'input[placeholder*="spotlight" i]',
    ];
    const shellSearchFallbackSelectors = [
      'input[role="searchbox"]',
      '[role="searchbox"]',
      'input[type="search"]',
      'input[aria-label*="search" i]',
      'input[placeholder*="search" i]',
      'input[role="combobox"]',
    ];

    for (const sel of spotlightSpecificSelectors) {
      for (const el of document.querySelectorAll(sel)) {
        if (!isEditableInput(el) || !isTrulyVisible(el)) continue;
        el.focus();
        if (document.activeElement === el) return true;
      }
    }

    for (const sel of shellSearchFallbackSelectors) {
      for (const el of document.querySelectorAll(sel)) {
        if (!isEditableInput(el) || !isTrulyVisible(el)) continue;
        if (el.closest(WINDOW_ANCESTOR_SEL) && !el.closest(SPOTLIGHT_ANCESTOR_SEL)) continue;
        el.focus();
        if (document.activeElement === el) return true;
      }
    }

    return false;
  });
}

// ============================================================================
// Server-First Lazy Suite Environment (0 Chromium spawned if os/ absent!)
// ============================================================================

let suiteEnvPromise = null;
let suiteServer = null;
let suiteBrowser = null;

async function getSuiteEnv() {
  if (!suiteEnvPromise) {
    suiteEnvPromise = (async () => {
      // CRITICAL: Start OmniOS server FIRST so missing os/ fails immediately with E_OMNIOS_NOT_IMPLEMENTED
      const server = await startOmniServer();
      suiteServer = server;
      try {
        const browser = await launchBrowser({ defaultViewport: { width: 1280, height: 800 } });
        suiteBrowser = browser;
        return { server, browser };
      } catch (err) {
        await server.stop().catch(() => {});
        suiteServer = null;
        throw err;
      }
    })();
  }
  return await suiteEnvPromise;
}

describe('Tier 2 — FA-16: Live Adaptive 5-Mode Web/Desktop Shell GUI (Headless Chromium CDP Boundary & Negative)', () => {
  after(async () => {
    if (suiteBrowser) {
      await suiteBrowser.close().catch(() => {});
      suiteBrowser = null;
    }
    if (suiteServer) {
      await suiteServer.stop().catch(() => {});
      suiteServer = null;
    }
    suiteEnvPromise = null;
  });

  it('T2-FA16-01 [F-076/F-084]: Extreme viewports (375x667 mobile iOS/Android & 1920x1080 desktop Unified/Windows/macOS) render cleanly without overflow or errors', async () => {
    let page = null;
    let launchedAppId = null;
    let serverRef = null;
    try {
      const { server, browser } = await getSuiteEnv();
      serverRef = server;

      const app = await discoverBuiltInApp(server.api, [/omninotes|notes/i, /omnifiles|files/i, /omniterm|terminal/i, /settings|privacy/i]);
      launchedAppId = app.appId;
      const { winId, title } = await launchAppAndAwaitWindow(server.api, app.appId);

      // Mobile portrait viewport 375x667
      page = await browser.newPage({ viewport: { width: 375, height: 667, mobile: true, deviceScaleFactor: 2 } });
      await page.goto(server.baseUrl);
      await waitForShellRendered(page);

      for (const mode of ['ios', 'android']) {
        await setShellModeHttp(server.api, mode);
        await waitUntil(async () => {
          const snapRes = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
          const curMode = snapRes.json?.shellMode ?? snapRes.json?.snapshot?.shellMode;
          return curMode === mode && (await domReflectsMode(page, mode));
        }, { timeoutMs: 6000, label: `mobile DOM sync for mode=${mode}` });

        const metrics = await page.evalFn(() => ({
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          scrollWidth: document.documentElement.scrollWidth,
          bodyLen: (document.body.innerText || '').trim().length,
        }));
        assert.equal(metrics.innerWidth, 375);
        assert.equal(metrics.innerHeight, 667);
        assert.ok(metrics.bodyLen > 0, `Expected non-empty rendered UI in ${mode} mode at 375x667`);
        assert.ok(
          metrics.scrollWidth <= 375 + 32,
          `Unexpected horizontal overflow in ${mode} mode at 375px viewport: scrollWidth=${metrics.scrollWidth}`
        );
      }

      // Live resize to ultrawide desktop 1920x1080
      await page.setViewport(1920, 1080, { mobile: false, deviceScaleFactor: 1 });
      for (const mode of ['unified', 'windows', 'macos']) {
        await setShellModeHttp(server.api, mode);
        await waitUntil(async () => {
          const snapRes = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
          const curMode = snapRes.json?.shellMode ?? snapRes.json?.snapshot?.shellMode;
          return curMode === mode && (await domReflectsMode(page, mode));
        }, { timeoutMs: 6000, label: `desktop DOM sync for mode=${mode}` });

        const dims = await page.evalFn(() => ({ w: window.innerWidth, h: window.innerHeight }));
        assert.equal(dims.w, 1920);
        assert.equal(dims.h, 1080);

        const domWin = await waitForVisibleWindow(
          page,
          { windowId: winId, titleSubstring: title || app.name },
          { timeoutMs: 5000, label: `visible window in ${mode} at 1920x1080` }
        );
        assert.equal(domWin.found, true);
        assert.ok(Number.isFinite(domWin.rect.width) && domWin.rect.width > 0);
        assert.ok(Number.isFinite(domWin.rect.height) && domWin.rect.height > 0);
      }

      assertZeroBrowserErrors(page, 'T2-FA16-01');
    } finally {
      if (page) await page.close().catch(() => {});
      if (serverRef && launchedAppId) {
        await serverRef.api.post(`/api/v1/packages/${encodeURIComponent(launchedAppId)}/stop`, {}).catch(() => {});
      }
      if (serverRef) await resetShellModeBestEffort(serverRef.api, 'unified');
    }
  });

  it('T2-FA16-02 [F-083/F-070]: Uploading malformed PE & ZIP-slip APK via Web GUI / App Hub <input type="file"> keeps UI & catalog intact', async () => {
    let page = null;
    let tmp = null;
    let launchedAppId = null;
    let serverRef = null;
    let unsubNet = () => {};
    try {
      // Server-first init BEFORE creating temp directory!
      const { server, browser } = await getSuiteEnv();
      serverRef = server;
      tmp = await createTempDataDir('omnios-t2-fa16-upload-');
      const nonce = makeNonce();

      // Neutral filenames so merely echoing filename in UI can never trigger rejection regexes
      const peFile = path.join(tmp.dir, `pkg-pe-${nonce}.exe`);
      const slipFile = path.join(tmp.dir, `pkg-apk-${nonce}.apk`);
      await fs.writeFile(peFile, buildMalformedPe('bad-pe-magic'));
      await fs.writeFile(slipFile, buildZipSlipArchive('dotdot', { wrapAsApk: true }));

      const beforeRes = await server.api.get('/api/v1/packages', { expectOk: true });
      const beforeIds = asArray(beforeRes.json).map((p) => p?.appId ?? p?.id).filter(Boolean).sort();

      const appHub = await discoverBuiltInApp(server.api, [/apphub|app[\s_-]*hub/i]);
      launchedAppId = appHub.appId;
      await launchAppAndAwaitWindow(server.api, appHub.appId);

      page = await browser.newPage({ viewport: { width: 1280, height: 800 } });

      // Enable CDP Network capture BEFORE navigation so both HTTP POST/PUT uploads and /ws frames are observed
      const uploadRequests = new Map();
      const wsUploadFrames = [];
      await page.send('Network.enable');
      unsubNet = browser.on((method, params, sid) => {
        if (sid !== page.sessionId) return;
        if (method === 'Network.requestWillBeSent') {
          const url = String(params.request?.url || '');
          const httpMethod = String(params.request?.method || '').toUpperCase();
          if ((httpMethod === 'POST' || httpMethod === 'PUT') && /\/api\/v1\/packages(?:\/|$|\?)/i.test(url)) {
            uploadRequests.set(params.requestId, {
              url,
              method: httpMethod,
              status: null,
              done: false,
              failed: false,
              errorText: '',
            });
          }
        } else if (method === 'Network.responseReceived' && uploadRequests.has(params.requestId)) {
          const rec = uploadRequests.get(params.requestId);
          rec.status = params.response?.status ?? null;
          rec.done = true;
        } else if (method === 'Network.loadingFailed' && uploadRequests.has(params.requestId)) {
          const rec = uploadRequests.get(params.requestId);
          rec.done = true;
          rec.failed = true;
          rec.errorText = String(params.errorText || '');
        } else if (method === 'Network.webSocketFrameSent') {
          const data = String(params.response?.payloadData || '');
          if (/\b(package|inspect|install|upload)\b/i.test(data)) {
            wsUploadFrames.push(data.slice(0, 200));
          }
        }
      });

      await page.goto(server.baseUrl);
      await waitForShellRendered(page);
      await page.waitForSelector('input[type="file"]', 8000);

      const rejectRe = /\b(error|invalid|reject\w*|fail\w*|corrupt\w*|malform\w*|traversal|unsafe|denied|unsupported|cannot\s+install)\b/i;

      const captureVisibleDomSnapshot = () => page.evalFn(() => {
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

        const lines = String(document.body?.innerText || '')
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter(Boolean);
        const alerts = Array.from(document.querySelectorAll(
          '[role="alert"], [aria-live], [data-toast], [data-error], [data-upload-error], [data-upload-status]'
        ))
          .filter(isTrulyVisible)
          .map((el) => String(el.innerText || el.textContent || '').trim())
          .filter(Boolean);
        return { lines, alerts };
      });

      const toCountMap = (arr) => {
        const m = new Map();
        for (const item of arr) m.set(item, (m.get(item) || 0) + 1);
        return m;
      };
      const multisetDiff = (currentArr, baselineMap) => {
        const rem = new Map(baselineMap);
        const added = [];
        for (const item of currentArr) {
          const left = rem.get(item) || 0;
          if (left > 0) rem.set(item, left - 1);
          else added.push(item);
        }
        return added;
      };

      for (const uploadPath of [peFile, slipFile]) {
        const baseName = path.basename(uploadPath);
        const seenReqIds = new Set(uploadRequests.keys());
        const wsCursor = wsUploadFrames.length;
        const domBefore = await captureVisibleDomSnapshot();
        const beforeLinesMap = toCountMap(domBefore.lines);
        const beforeAlertsMap = toCountMap(domBefore.alerts);

        await page.setFileInputFiles('input[type="file"]', uploadPath);
        await sleep(200);
        // Click an explicit Install / Upload action button if the UI stages uploads before submit
        const submitCtrl = await findVisibleControl(page, {
          dataSelectors: [
            '[data-action="upload"]',
            '[data-action="install-upload"]',
            '[data-action="install-package"]',
            '[data-install-btn]',
            '[data-testid="upload-submit"]',
          ],
          textPatterns: ['^upload$', '^install package$', '^install file$'],
        });
        if (submitCtrl.found) {
          await page.clickAt(submitCtrl.x, submitCtrl.y);
        }

        // Non-vacuous proof that UI genuinely attempted package upload/inspection or displayed a rejection notice
        const proof = await waitUntil(async () => {
          for (const [rid, info] of uploadRequests.entries()) {
            if (!seenReqIds.has(rid) && info.done) {
              return { via: 'network', status: info.status, url: info.url, failed: info.failed };
            }
          }
          if (wsUploadFrames.length > wsCursor) {
            return { via: 'ws' };
          }
          const domNow = await captureVisibleDomSnapshot();
          const newAlerts = multisetDiff(domNow.alerts, beforeAlertsMap);
          for (const a of newAlerts) {
            const cleaned = a.split(baseName).join('');
            if (rejectRe.test(cleaned)) return { via: 'dom', text: cleaned.slice(0, 160) };
          }
          const newLines = multisetDiff(domNow.lines, beforeLinesMap);
          for (const line of newLines) {
            const cleaned = line.split(baseName).join('');
            if (rejectRe.test(cleaned)) return { via: 'dom', text: cleaned.slice(0, 160) };
          }
          return null;
        }, {
          timeoutMs: 6000,
          label: `upload handling proof (POST/PUT /api/v1/packages/*, WS upload, or visible rejection notice) for ${baseName}`,
        });

        assert.ok(proof, `[T2-FA16-02] Expected UI to handle upload of ${baseName}`);
        for (const [rid, info] of uploadRequests.entries()) {
          if (seenReqIds.has(rid)) continue;
          assert.equal(
            info.failed,
            false,
            `[T2-FA16-02] Upload ${info.method} ${info.url} for ${baseName} failed at network layer: ${info.errorText}`
          );
          if (typeof info.status === 'number') {
            assert.ok(
              info.status < 500,
              `[T2-FA16-02] Upload ${info.method} ${info.url} for ${baseName} crashed server with HTTP ${info.status}`
            );
          }
        }
      }

      // Strictly 0 uncaught JS exceptions & 0 JS console errors (expected HTTP 4xx on /api/v1/packages/ tolerated)
      assertZeroPageAndUnexpectedConsoleErrors(page, 'T2-FA16-02');

      // Installed packages set MUST remain identical to baseline (neither corrupt PE nor zipslip installed)
      const afterRes = await server.api.get('/api/v1/packages', { expectOk: true });
      const afterIds = asArray(afterRes.json).map((p) => p?.appId ?? p?.id).filter(Boolean).sort();
      assert.deepEqual(afterIds, beforeIds, 'Corrupt PE and ZIP-slip uploads must not install any package');
      assert.ok(!afterIds.includes('com.omnios.zipslip'), 'ZIP-slip package leaked into installed catalog!');

      // Verify backend health & live Chromium page responsiveness
      const health = await server.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);

      const aliveEval = await page.evalFn(() => document.readyState === 'complete' && (document.body.innerText || '').trim().length > 0);
      assert.equal(aliveEval, true, 'Chromium GUI must remain responsive after malformed uploads');
    } finally {
      unsubNet();
      if (page) await page.close().catch(() => {});
      if (serverRef && launchedAppId) {
        await serverRef.api.post(`/api/v1/packages/${encodeURIComponent(launchedAppId)}/stop`, {}).catch(() => {});
      }
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });

  it('T2-FA16-03 [F-076/F-074]: Rapid 5-mode shell switching (windows -> macos -> ios -> android -> unified x2) preserves live kernel window & DOM', async () => {
    let page = null;
    let launchedAppId = null;
    let serverRef = null;
    try {
      const { server, browser } = await getSuiteEnv();
      serverRef = server;

      const app = await discoverBuiltInApp(server.api, [/omninotes|notes/i, /omniterm|terminal/i, /omnifiles|files/i, /settings|privacy/i]);
      launchedAppId = app.appId;
      const { pid, winId, title } = await launchAppAndAwaitWindow(server.api, app.appId);

      page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      await page.goto(server.baseUrl);
      await waitForShellRendered(page);

      const initialDomWin = await waitForVisibleWindow(
        page,
        { windowId: winId, titleSubstring: title || app.name },
        { timeoutMs: 6000, label: 'initial visible window before rapid mode switch' }
      );
      assert.equal(initialDomWin.found, true);

      const sequence = ['windows', 'macos', 'ios', 'android', 'unified', 'windows', 'macos', 'ios', 'android', 'unified'];
      for (const mode of sequence) {
        await setShellModeHttp(server.api, mode);
        // Also click matching interactive mode switcher control if visibly exposed
        const modeBtn = await findVisibleControl(page, {
          dataSelectors: [
            `button[data-shell-mode="${mode}"]`,
            `button[data-mode="${mode}"]`,
            `[role="button"][data-shell-mode="${mode}"]`,
            `[role="button"][data-mode="${mode}"]`,
            `[role="tab"][data-shell-mode="${mode}"]`,
            `[role="tab"][data-mode="${mode}"]`,
            `[role="radio"][data-shell-mode="${mode}"]`,
            `[role="radio"][data-mode="${mode}"]`,
            `[data-action="shell-mode"][data-value="${mode}"]`,
          ],
          tags: 'button, [role="button"], [role="tab"], [role="radio"], [role="menuitem"]',
        });
        if (modeBtn.found) {
          await page.clickAt(modeBtn.x, modeBtn.y);
        }
        await sleep(40);
      }

      // Settle on unified mode
      await waitUntil(async () => {
        const snapRes = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const curMode = snapRes.json?.shellMode ?? snapRes.json?.snapshot?.shellMode;
        return curMode === 'unified' && (await domReflectsMode(page, 'unified'));
      }, { timeoutMs: 6000, label: 'settled unified mode after rapid switching' });

      // Backend window & process MUST remain completely intact with finite positive bounds
      const snapRes = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      const wins = asArray(snapRes.json?.windows ?? snapRes.json?.snapshot?.windows ?? snapRes.json);
      const liveWin = wins.find((w) => (w.windowId ?? w.id) === winId);
      assert.ok(liveWin, `Window ${winId} vanished after rapid 5-mode switching`);
      const b = getWinBounds(liveWin);
      assert.ok(Number.isFinite(b.width) && b.width > 0 && Number.isFinite(b.height) && b.height > 0, `Invalid backend bounds: ${JSON.stringify(b)}`);

      const procRes = await server.api.get(`/api/v1/processes/${pid}`, { expectOk: true });
      const state = extractProcState(procRes.json);
      assert.ok(typeof state === 'string' && state !== 'TERMINATED' && state !== 'ZOMBIE', `Owning PID ${pid} died during mode switching: state=${state}`);

      // Window MUST still render visibly in Chromium DOM
      const afterDomWin = await waitForVisibleWindow(
        page,
        { windowId: winId, titleSubstring: title || app.name },
        { timeoutMs: 6000, label: 'visible window after rapid 5-mode switching' }
      );
      assert.equal(afterDomWin.found, true);

      assertZeroBrowserErrors(page, 'T2-FA16-03');
    } finally {
      if (page) await page.close().catch(() => {});
      if (serverRef && launchedAppId) {
        await serverRef.api.post(`/api/v1/packages/${encodeURIComponent(launchedAppId)}/stop`, {}).catch(() => {});
      }
      if (serverRef) await resetShellModeBestEffort(serverRef.api, 'unified');
    }
  });

  it('T2-FA16-04 [F-076/F-073]: Invalid /api/v1/compositor/shell-mode rejected 4xx without crashing connected Chromium UI', async () => {
    let page = null;
    let serverRef = null;
    try {
      const { server, browser } = await getSuiteEnv();
      serverRef = server;

      await setShellModeHttp(server.api, 'unified');
      page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      await page.goto(server.baseUrl);
      await waitForShellRendered(page);

      const beforeSnap = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      const beforeMode = beforeSnap.json?.shellMode ?? beforeSnap.json?.snapshot?.shellMode;
      assert.equal(beforeMode, 'unified');

      const invalidPayloads = [
        { mode: 'bogus-os-mode', shellMode: 'bogus-os-mode' },
        { mode: '', shellMode: '' },
        { mode: 12345, shellMode: 12345 },
      ];

      for (const body of invalidPayloads) {
        const res = await writeWithMethodFallback(server.api, ['POST', 'PUT', 'PATCH'], '/api/v1/compositor/shell-mode', body);
        assert.ok(
          res.status >= 400 && res.status < 500,
          `Expected HTTP 4xx for invalid shell-mode payload ${JSON.stringify(body)}, got ${res.status}: ${res.text}`
        );
      }

      const midSnap = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      assert.equal(midSnap.json?.shellMode ?? midSnap.json?.snapshot?.shellMode, beforeMode);

      // Prove connected Chromium UI still receives live /ws mode updates cleanly (and modes are mutually exclusive)
      await setShellModeHttp(server.api, 'macos');
      await waitUntil(() => domReflectsMode(page, 'macos'), { timeoutMs: 6000, label: 'Chromium live flip to macos' });
      assert.equal(
        await domReflectsMode(page, 'unified'),
        false,
        'Expected unified mode to no longer be reflected after switching to macos'
      );

      await setShellModeHttp(server.api, 'unified');
      await waitUntil(() => domReflectsMode(page, 'unified'), { timeoutMs: 6000, label: 'Chromium live flip back to unified' });
      assert.equal(
        await domReflectsMode(page, 'macos'),
        false,
        'Expected macos mode to no longer be reflected after switching back to unified'
      );

      assertZeroBrowserErrors(page, 'T2-FA16-04');
    } finally {
      if (page) await page.close().catch(() => {});
      if (serverRef) await resetShellModeBestEffort(serverRef.api, 'unified');
    }
  });

  it('T2-FA16-05 [F-073/F-074]: Server-side window close & SIGKILL remove windows cleanly over /ws in connected Chromium DOM', async () => {
    let page = null;
    let serverRef = null;
    const launchedApps = [];
    try {
      const { server, browser } = await getSuiteEnv();
      serverRef = server;

      // Dynamically discover TWO distinct built-in system apps
      const appA = await discoverBuiltInApp(server.api, [/omninotes|notes/i, /omniterm|terminal/i, /settings|privacy/i]);
      const appB = await discoverBuiltInApp(
        server.api,
        [/omnifiles|files/i, /monitor|task/i, /inspector/i, /settings|privacy/i, /omniterm|terminal/i],
        new Set([appA.appId])
      );
      assert.notEqual(appA.appId, appB.appId, 'Expected two distinct built-in system apps');

      const launchA = await launchAppAndAwaitWindow(server.api, appA.appId);
      launchedApps.push(appA.appId);
      const launchB = await launchAppAndAwaitWindow(server.api, appB.appId);
      launchedApps.push(appB.appId);

      page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      await page.goto(server.baseUrl);
      await waitForShellRendered(page);

      // Wait for BOTH windows to appear visibly in Chromium DOM
      const initialDomWins = await waitUntil(async () => {
        const a = await findVisibleWindow(page, { windowId: launchA.winId, titleSubstring: launchA.title || appA.name });
        const b = await findVisibleWindow(page, { windowId: launchB.winId, titleSubstring: launchB.title || appB.name });
        return a.found && b.found ? { a, b } : null;
      }, { timeoutMs: 8000, label: 'both windows visible in Chromium DOM' });
      const allowFallbackA = initialDomWins.a.matchedBy !== 'id';
      const allowFallbackB = initialDomWins.b.matchedBy !== 'id';

      // Step 1: Close winIdA server-side -> winIdA disappears from backend & DOM while winIdB stays visible
      const closeRes = await writeWithMethodFallback(
        server.api,
        ['POST', 'DELETE'],
        `/api/v1/compositor/windows/${encodeURIComponent(launchA.winId)}/close`,
        {}
      );
      assert.ok(closeRes.ok, `Expected 2xx closing window ${launchA.winId}, got ${closeRes.status}: ${closeRes.text}`);

      await waitUntil(async () => {
        const snap = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(snap.json?.windows ?? snap.json?.snapshot?.windows ?? snap.json);
        const goneBackend = !wins.some((w) => (w.windowId ?? w.id) === launchA.winId);
        const domA = await findVisibleWindow(page, {
          windowId: launchA.winId,
          titleSubstring: launchA.title || appA.name,
          allowTitleFallback: allowFallbackA,
        });
        return goneBackend && !domA.found;
      }, { timeoutMs: 6000, label: 'winIdA removed from backend and Chromium DOM' });

      const domBStillThere = await findVisibleWindow(page, {
        windowId: launchB.winId,
        titleSubstring: launchB.title || appB.name,
        allowTitleFallback: allowFallbackB,
      });
      assert.equal(domBStillThere.found, true, 'Sibling window B must remain visible when window A closes');

      // Step 2: SIGKILL pidB -> pidB terminates, winIdB disappears from backend AND Chromium DOM
      const killRes = await server.api.post(`/api/v1/processes/${launchB.pid}/signal`, { signal: 'SIGKILL' });
      assert.ok(killRes.ok, `Expected 2xx sending SIGKILL to pid=${launchB.pid}, got ${killRes.status}: ${killRes.text}`);

      await waitUntil(async () => {
        const procRes = await server.api.get(`/api/v1/processes/${launchB.pid}`);
        const st = procRes.ok ? extractProcState(procRes.json) : 'TERMINATED';
        const procDead = !procRes.ok || st === 'TERMINATED' || st === 'ZOMBIE';
        const snap = await server.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(snap.json?.windows ?? snap.json?.snapshot?.windows ?? snap.json);
        const goneBackend = !wins.some((w) => (w.windowId ?? w.id) === launchB.winId);
        const domB = await findVisibleWindow(page, {
          windowId: launchB.winId,
          titleSubstring: launchB.title || appB.name,
          allowTitleFallback: allowFallbackB,
        });
        return procDead && goneBackend && !domB.found;
      }, { timeoutMs: 6000, label: 'pidB SIGKILL removing winIdB from backend and Chromium DOM' });

      assertZeroBrowserErrors(page, 'T2-FA16-05');
    } finally {
      if (page) await page.close().catch(() => {});
      if (serverRef) {
        for (const appId of launchedApps) {
          await serverRef.api.post(`/api/v1/packages/${encodeURIComponent(appId)}/stop`, {}).catch(() => {});
        }
      }
    }
  });

  it('T2-FA16-06 [F-073/F-077]: Extreme window geometry updates & live Spotlight regex/empty boundary queries in Chromium', async () => {
    let page = null;
    let launchedAppId = null;
    let serverRef = null;
    try {
      const { server, browser } = await getSuiteEnv();
      serverRef = server;
      const nonce = makeNonce();

      const app = await discoverBuiltInApp(server.api, [/omninotes|notes/i, /omniterm|terminal/i, /omnifiles|files/i, /settings|privacy/i]);
      launchedAppId = app.appId;
      const { winId, title } = await launchAppAndAwaitWindow(server.api, app.appId);

      page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      await page.goto(server.baseUrl);
      await waitForShellRendered(page);

      const initialGeomWin = await waitForVisibleWindow(
        page,
        { windowId: winId, titleSubstring: title || app.name },
        { timeoutMs: 6000, label: 'visible window before extreme geometry test' }
      );
      assert.equal(initialGeomWin.found, true);
      const allowGeomFallback = initialGeomWin.matchedBy !== 'id';

      // Part A: Push extreme boundary move/resize coordinates, then restore normal finite geometry
      const extremeMove = await writeWithMethodFallback(
        server.api,
        ['POST', 'PUT', 'PATCH'],
        `/api/v1/compositor/windows/${encodeURIComponent(winId)}/move`,
        { x: -500, y: -500 }
      );
      assert.ok(extremeMove.status < 500, `Extreme move caused HTTP ${extremeMove.status}`);

      const extremeResize = await writeWithMethodFallback(
        server.api,
        ['POST', 'PUT', 'PATCH'],
        `/api/v1/compositor/windows/${encodeURIComponent(winId)}/resize`,
        { width: 20, height: 20 }
      );
      assert.ok(extremeResize.status < 500, `Extreme resize caused HTTP ${extremeResize.status}`);
      await sleep(200);

      // Restore normal bounds & verify Chromium renders clean finite positive DOM rect
      await writeWithMethodFallback(
        server.api,
        ['POST', 'PUT', 'PATCH'],
        `/api/v1/compositor/windows/${encodeURIComponent(winId)}/move`,
        { x: 120, y: 100 }
      );
      await writeWithMethodFallback(
        server.api,
        ['POST', 'PUT', 'PATCH'],
        `/api/v1/compositor/windows/${encodeURIComponent(winId)}/resize`,
        { width: 520, height: 360 }
      );

      const restoredDomWin = await waitUntil(async () => {
        const w = await findVisibleWindow(page, {
          windowId: winId,
          titleSubstring: title || app.name,
          allowTitleFallback: allowGeomFallback,
        });
        return w.found && Number.isFinite(w.rect.width) && w.rect.width >= 100 && Number.isFinite(w.rect.height) && w.rect.height >= 80 ? w : null;
      }, { timeoutMs: 6000, label: 'restored visible window rect in Chromium DOM' });
      assert.ok(restoredDomWin.found);

      // Part B: Open Spotlight (Ctrl+Space, fallback clicking visible Spotlight trigger) & test regex/empty/non-matching queries
      await page.pressKey('Space', 'Ctrl');
      await sleep(250);

      let spotOpened = await focusSpotlightInput(page);
      if (!spotOpened) {
        const spotTrigger = await findVisibleControl(page, {
          dataSelectors: ['[data-action="spotlight"]', '[data-spotlight-trigger]', 'button[data-overlay="spotlight"]', '[data-testid="spotlight-btn"]'],
          ariaPatterns: ['spotlight', 'search'],
          textPatterns: ['spotlight', 'search'],
          tags: 'button, [role="button"], [role="menuitem"], a',
        });
        if (spotTrigger.found) {
          await page.clickAt(spotTrigger.x, spotTrigger.y);
        }
        spotOpened = await waitUntil(() => focusSpotlightInput(page), {
          timeoutMs: 5000,
          label: 'visible Spotlight search input after Ctrl+Space / trigger click',
        });
      }
      assert.equal(spotOpened, true, 'Expected Spotlight search input to open and receive focus');

      // Insert regex metacharacters .*([?+, then empty string, then unique non-matching query
      await page.send('Input.insertText', { text: '.*([?+' });
      await sleep(300);
      await page.evalFn(() => {
        const el = document.activeElement;
        if (el && 'value' in el) {
          el.value = '';
          el.dispatchEvent(new Event('input', { bubbles: true }));
        }
      });
      await sleep(200);
      await page.send('Input.insertText', { text: `nomatch_${nonce}` });
      await sleep(300);
      await page.pressKey('Escape');
      await sleep(200);

      // Also verify live REST /api/v1/search with regex metachars returns 200 alongside Chromium session
      const spotApiRes = await server.api.get('/api/v1/search', { query: { q: '.*([?+' } });
      assert.equal(spotApiRes.status, 200, `Expected HTTP 200 from Spotlight regex query, got ${spotApiRes.status}`);

      assertZeroBrowserErrors(page, 'T2-FA16-06');

      const health = await server.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
    } finally {
      if (page) await page.close().catch(() => {});
      if (serverRef && launchedAppId) {
        await serverRef.api.post(`/api/v1/packages/${encodeURIComponent(launchedAppId)}/stop`, {}).catch(() => {});
      }
    }
  });
});
