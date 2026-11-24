/**
 * OmniOS Tier 4 E2E Suite — S05: Headless Chromium CDP App Hub Upload, Click-to-Execution & Security Modals
 * Covers PROJECT.md Features: F-086, F-070, F-073, F-074, F-081, F-082, F-083, F-024, F-028, F-040, F-046, F-056, F-059.
 *
 * Scenarios:
 * - T4-S05-01 (Scenario 9 / F-086): End-to-end App Hub dynamic custom binary upload (`<input type="file">`) ->
 *   install -> launch -> live Dalvik execution & DOM/VFS/Notification verification, PLUS real binary
 *   click-to-execution on `packages/android-calc.apk` (non-chrome body controls -> real backend surfaceRevision /
 *   uiTree mutation & live DOM update) AND real WASM Canvas2D rasterization + pointer interaction on
 *   `packages/universal-canvas.uapp`.
 * - T4-S05-02 (Scenario 10 / F-086): Live Universal Share Sheet Chooser (`intent:chooser` with symmetric dual
 *   handlers verifying chosen execution & non-chosen isolation) AND live Security Permission Prompt Modal
 *   (`permission:prompt` with dynamically discovered capability, strict capability-filtered audit/policy
 *   verification across BOTH Allow and Deny loops).
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Server-first lazy init (`startOmniServer()` BEFORE `launchBrowser()` and BEFORE temp dirs / package reads):
 *   0 Chromium spawns & 0 temp leaks when os/ is absent.
 * - Zero hardcoded system app IDs, zero hardcoded undocumented capability strings, zero skips, zero swallowed assertions.
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

function asArray(payload, keys = ['windows', 'packages', 'apps', 'catalog', 'processes', 'permissions', 'grants', 'audit', 'entries', 'items', 'data', 'notifications']) {
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

function getUiTree(w) {
  return w?.uiTree ?? w?.surface?.uiTree ?? null;
}

function getSurfaceRev(w) {
  return Number(w?.surfaceRevision ?? w?.surface?.surfaceRevision ?? w?.surface?.revision ?? 0);
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

function extractFileText(res) {
  if (!res || !res.ok) return '';
  if (typeof res.json?.content === 'string') return res.json.content;
  if (typeof res.json?.data === 'string') return res.json.data;
  return typeof res.text === 'string' ? res.text : '';
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

// ============================================================================
// Dynamic Capability Discovery & Strictly Filtered Audit/Policy Checkers
// (ZERO hardcoded undocumented capability strings!)
// ============================================================================

function isGrantStateValue(v) {
  const grantTokenRe = /^(?:allow|allowed|granted|deny|denied|reject|rejected|prompt|ask|default)$/i;
  if (typeof v === 'boolean') return true;
  if (typeof v === 'string') {
    return grantTokenRe.test(v.trim());
  }
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    return (
      typeof v.granted === 'boolean' ||
      (typeof v.state === 'string' && grantTokenRe.test(v.state.trim())) ||
      (typeof v.policy === 'string' && grantTokenRe.test(v.policy.trim())) ||
      (typeof v.decision === 'string' && grantTokenRe.test(v.decision.trim()))
    );
  }
  return false;
}

function collectCanonicalCapabilitiesFromObject(
  obj,
  targetAppId = null,
  { scopedToTarget = false, allowTopLevelMap = false } = {}
) {
  const appCaps = new Set();
  const catalogCaps = new Set();
  const isNativePerm = (s) => /^android\.permission\.|^com\.apple\.|^NSCamera|^NSPhoto/i.test(s);
  const metaKeys = new Set([
    'appId', 'id', 'ok', 'status', 'platform', 'count', 'total', 'limit',
    'permissions', 'grants', 'entries', 'items', 'data', 'package',
    'capabilities', 'availableCapabilities', 'canonicalCapabilities', 'requestedCapabilities',
  ]);
  const envelopeKeys = [
    'permissions', 'grants', 'entries', 'items', 'data',
    'capabilities', 'availableCapabilities', 'canonicalCapabilities', 'requestedCapabilities',
  ];
  const addCap = (set, raw) => {
    const s = typeof raw === 'string'
      ? raw.trim()
      : String(raw?.capability ?? raw?.cap ?? raw?.id ?? raw?.name ?? '').trim();
    if (s && !isNativePerm(s) && !metaKeys.has(s) && s.length < 80) set.add(s);
  };

  if (!obj || typeof obj !== 'object') return { appCaps, catalogCaps };

  const objScopedToTarget = Boolean(
    scopedToTarget || (targetAppId && (obj.appId === targetAppId || obj.id === targetAppId))
  );

  // Check explicit capability arrays
  for (const k of ['capabilities', 'availableCapabilities', 'canonicalCapabilities', 'requestedCapabilities']) {
    if (Array.isArray(obj[k])) {
      const dest = targetAppId && (objScopedToTarget || k === 'requestedCapabilities') ? appCaps : catalogCaps;
      for (const item of obj[k]) addCap(dest, item);
    }
  }

  // Check grant/permission record arrays (including filtered single-app rows omitting redundant appId)
  const rows = asArray(obj, ['permissions', 'grants', 'entries', 'items', 'data']);
  for (const row of rows) {
    if (typeof row === 'string') {
      addCap(objScopedToTarget ? appCaps : catalogCaps, row);
      continue;
    }
    if (!row || typeof row !== 'object') continue;
    const cap = row.capability ?? row.cap ?? row.permission ?? null;
    if (!cap) continue;
    const belongsToTarget = !targetAppId || row.appId === targetAppId || (!row.appId && objScopedToTarget);
    if (belongsToTarget) {
      addCap(appCaps, cap);
    } else {
      addCap(catalogCaps, cap);
    }
  }

  // Check both nested multi-app maps ({ permissions: { [appId]: { [cap]: state } } })
  // and bare flat maps ({ [cap]: state }) ONLY when allowTopLevelMap is true and obj is not a structured envelope
  const hasEnvelopeKey = envelopeKeys.some((k) => Object.prototype.hasOwnProperty.call(obj, k));
  const mapContainers = [obj.permissions, obj.grants];
  if (allowTopLevelMap && !hasEnvelopeKey) {
    mapContainers.push(obj);
  }
  for (const container of mapContainers) {
    if (!container || typeof container !== 'object' || Array.isArray(container)) continue;

    if (
      targetAppId &&
      container[targetAppId] &&
      typeof container[targetAppId] === 'object' &&
      !Array.isArray(container[targetAppId])
    ) {
      for (const [capKey, capVal] of Object.entries(container[targetAppId])) {
        if (!metaKeys.has(capKey) && isGrantStateValue(capVal)) {
          addCap(appCaps, capKey);
        }
      }
    }

    for (const [k, v] of Object.entries(container)) {
      if (metaKeys.has(k)) continue;
      if (isGrantStateValue(v)) {
        addCap(objScopedToTarget ? appCaps : catalogCaps, k);
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        const dest = targetAppId && k === targetAppId ? appCaps : catalogCaps;
        for (const [subKey, subVal] of Object.entries(v)) {
          if (!metaKeys.has(subKey) && isGrantStateValue(subVal)) {
            addCap(dest, subKey);
          }
        }
      }
    }
  }

  if (obj.package && typeof obj.package === 'object') {
    const nested = collectCanonicalCapabilitiesFromObject(obj.package, targetAppId, {
      scopedToTarget: objScopedToTarget,
      allowTopLevelMap: false,
    });
    for (const c of nested.appCaps) appCaps.add(c);
    for (const c of nested.catalogCaps) catalogCaps.add(c);
  }

  return { appCaps, catalogCaps };
}

async function discoverCapabilitiesSnapshot(api, appId, instJson = null) {
  const appCaps = new Set();
  const catalogCaps = new Set();

  const merge = (res) => {
    for (const c of res.appCaps) appCaps.add(c);
    for (const c of res.catalogCaps) catalogCaps.add(c);
  };

  if (instJson) {
    merge(collectCanonicalCapabilitiesFromObject(instJson, appId, { scopedToTarget: true, allowTopLevelMap: false }));
  }

  const appPerms = await api.get('/api/v1/security/permissions', { query: { appId } });
  if (appPerms.ok && appPerms.json) {
    merge(collectCanonicalCapabilitiesFromObject(appPerms.json, appId, { scopedToTarget: true, allowTopLevelMap: true }));
  }

  const allPerms = await api.get('/api/v1/security/permissions');
  if (allPerms.ok && allPerms.json) {
    merge(collectCanonicalCapabilitiesFromObject(allPerms.json, appId, { scopedToTarget: false, allowTopLevelMap: true }));
    for (const k of ['capabilities', 'availableCapabilities', 'canonicalCapabilities']) {
      if (Array.isArray(allPerms.json[k])) {
        for (const item of allPerms.json[k]) {
          const s = typeof item === 'string' ? item.trim() : String(item?.id ?? item?.name ?? item?.capability ?? '').trim();
          if (s) catalogCaps.add(s);
        }
      }
    }
  }

  return {
    appCaps: Array.from(appCaps),
    catalogCaps: Array.from(catalogCaps),
  };
}

/**
 * Dynamically discovers the canonical user-file-write capability registered by PermissionBroker
 * for an app declaring WRITE_EXTERNAL_STORAGE (never hardcodes capability names!).
 */
async function discoverUserWriteCapability(api, appId, instJson = null) {
  const { appCaps, catalogCaps } = await discoverCapabilitiesSnapshot(api, appId, instJson);
  const notWindow = (c) => !/window|^ui\./i.test(c);
  const writeAndStorage = (c) => /write/i.test(c) && /fs|file|storage|user|vfs/i.test(c) && notWindow(c);
  const anyStorage = (c) => /storage|fs|file|write/i.test(c) && notWindow(c);

  const chosen =
    appCaps.find(writeAndStorage) ??
    appCaps.find(anyStorage) ??
    catalogCaps.find(writeAndStorage) ??
    catalogCaps.find(anyStorage) ??
    appCaps.find(notWindow) ??
    null;

  assert.ok(
    chosen,
    `Could not dynamically discover canonical user-file-write capability for ${appId}. ` +
    `appCaps=${JSON.stringify(appCaps)}, catalogCaps=${JSON.stringify(catalogCaps)}, inst=${JSON.stringify(instJson)}`
  );
  return chosen;
}

async function allowDiscoveredAppCapabilities(api, appId, instJson = null) {
  const { appCaps, catalogCaps } = await discoverCapabilitiesSnapshot(api, appId, instJson);
  const toAllow = new Set(appCaps);
  for (const c of catalogCaps) {
    if (/write|read|storage|fs|file|notif/i.test(c)) toAllow.add(c);
  }
  for (const cap of toAllow) {
    await writeWithMethodFallback(api, ['PUT', 'POST', 'PATCH'], '/api/v1/security/permissions', {
      appId,
      capability: cap,
      state: 'allow',
    }).catch(() => {});
  }
}

/**
 * Strictly capability-filtered audit & policy checkers:
 * Rejects entries for any other capability (such as window creation capabilities),
 * preventing false-positive bleed!
 */
function makeAuditCheckers(appId, targetCapability) {
  const matchesApp = (e, scopedPayloadAppId = null) =>
    Boolean(
      e &&
      typeof e === 'object' &&
      (e.appId === appId ||
        (!e.appId && (scopedPayloadAppId === appId || JSON.stringify(e).includes(appId))))
    );
  const matchesCap = (e) => {
    const cap = String(e?.capability ?? e?.cap ?? e?.permission ?? '').trim();
    if (cap) return cap === targetCapability;
    return String(e?.nativePermission ?? '') === 'android.permission.WRITE_EXTERNAL_STORAGE';
  };

  const isAllowAuditEntry = (e, scopedPayloadAppId = null) => {
    if (!matchesApp(e, scopedPayloadAppId) || !matchesCap(e)) return false;
    if (e.granted === false) return false;
    const decision = String(e.decision ?? e.state ?? e.result ?? e.outcome ?? e.policy ?? '').trim().toLowerCase();
    if (decision === 'deny' || decision === 'denied' || decision === 'reject' || decision === 'rejected') return false;
    if (e.granted !== true && decision === 'prompt') return false;
    return e.granted === true || decision === 'allow' || decision === 'allowed' || decision === 'granted';
  };

  const isDenyAuditEntry = (e, scopedPayloadAppId = null) => {
    if (!matchesApp(e, scopedPayloadAppId) || !matchesCap(e)) return false;
    if (e.granted === true) return false;
    if (String(e.decision ?? '').trim().toLowerCase() === 'prompt') return false;
    const decision = String(e.decision ?? e.state ?? e.result ?? e.outcome ?? e.policy ?? '').trim().toLowerCase();
    if (decision === 'allow' || decision === 'allowed' || decision === 'granted') return false;
    return e.granted === false || decision === 'deny' || decision === 'denied' || decision === 'reject' || decision === 'rejected';
  };

  const hasPolicyState = (payload, wantAllow, { scopedToApp = false } = {}) => {
    if (!payload || typeof payload !== 'object') return false;
    const matchVal = (v) => {
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        return wantAllow
          ? (v.granted === true || /^(?:allow|allowed|granted)$/i.test(String(v.state ?? v.policy ?? v.decision ?? '')))
          : (v.granted === false || /^(?:deny|denied|reject|rejected)$/i.test(String(v.state ?? v.policy ?? v.decision ?? '')));
      }
      return wantAllow
        ? (v === true || /^(?:allow|allowed|granted)$/i.test(String(v ?? '')))
        : (v === false || /^(?:deny|denied|reject|rejected)$/i.test(String(v ?? '')));
    };

    const payloadIsForApp = Boolean(
      payload.appId === appId ||
      payload.id === appId ||
      (scopedToApp && !payload.appId && !payload.id)
    );

    // 1. Array of records (accepts rows omitting redundant appId when payload is scoped to appId)
    const list = asArray(payload, ['permissions', 'grants', 'entries', 'items', 'data']);
    if (
      list.some(
        (g) =>
          g &&
          typeof g === 'object' &&
          (g.appId === appId || (!g.appId && payloadIsForApp)) &&
          String(g.capability ?? g.cap ?? g.permission ?? '').trim() === targetCapability &&
          (wantAllow
            ? (g.granted === true || matchVal(g.state ?? g.policy ?? g.decision))
            : (g.granted === false || matchVal(g.state ?? g.policy ?? g.decision)))
      )
    ) {
      return true;
    }

    // 2. Nested multi-app map: { permissions: { [appId]: { [cap]: state } } }
    const appGrants = payload?.permissions?.[appId] ?? payload?.grants?.[appId] ?? payload?.[appId];
    if (appGrants && typeof appGrants === 'object' && !Array.isArray(appGrants)) {
      if (Object.prototype.hasOwnProperty.call(appGrants, targetCapability)) {
        return matchVal(appGrants[targetCapability]);
      }
    }

    // 3. Natural filtered single-app map: { appId, permissions: { [cap]: state } }
    if (payloadIsForApp) {
      for (const container of [payload.permissions, payload.grants, payload]) {
        if (container && typeof container === 'object' && !Array.isArray(container)) {
          if (Object.prototype.hasOwnProperty.call(container, targetCapability)) {
            return matchVal(container[targetCapability]);
          }
        }
      }
    }

    return false;
  };

  return {
    isAllowAuditEntry,
    isDenyAuditEntry,
    hasAllowPolicy: (payload, opts) => hasPolicyState(payload, true, opts),
    hasDenyPolicy: (payload, opts) => hasPolicyState(payload, false, opts),
  };
}

// ============================================================================
// Hardened CDP DOM Helpers
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

    const roots = spec.scopeSelector
      ? Array.from(document.querySelectorAll(spec.scopeSelector)).filter(isTrulyVisible)
      : [document];
    if (roots.length === 0) return { found: false, visibleControlsSample: [`scope missing/hidden: ${spec.scopeSelector}`] };

    for (const sel of spec.dataSelectors || []) {
      const hits = roots.flatMap((root) => Array.from(root.querySelectorAll(sel))).filter(isTrulyVisible);
      if (hits.length > 0) {
        hits.sort((a, b) => {
          const ra = a.getBoundingClientRect();
          const rb = b.getBoundingClientRect();
          return (ra.width * ra.height) - (rb.width * rb.height);
        });
        return describe(hits[0]);
      }
    }

    const candidates = roots.flatMap((root) => Array.from(root.querySelectorAll(spec.tags))).filter(isTrulyVisible);

    const ariaRes = (spec.ariaPatterns || []).map((p) => new RegExp(p, 'i'));
    for (const re of ariaRes) {
      const hit = candidates.find((el) => {
        const a = `${el.getAttribute('aria-label') || ''} ${el.getAttribute('title') || ''}`.trim();
        return a.length > 0 && re.test(a);
      });
      if (hit) return describe(hit);
    }

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
      let best = null;
      let bestArea = Infinity;
      for (const el of document.querySelectorAll('section, article, div, [role="dialog"], [role="region"]')) {
        if (!isVisible(el) || el.closest(CHROME_EXCLUDE_SEL) || el.closest('[data-overlay]')) continue;
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

    if (!winEl) return { found: false, matchedByWindowId: false };
    const r = winEl.getBoundingClientRect();
    const canvas = Array.from(winEl.querySelectorAll('canvas')).find(isVisible) || null;
    const cr = canvas ? canvas.getBoundingClientRect() : null;
    const fullText = String(winEl.innerText || '');
    const inputValues = Array.from(winEl.querySelectorAll('input, textarea, select'))
      .filter(isVisible)
      .map((el) => `${el.tagName}:${el.name || el.id || ''}=${String(el.value ?? '')}`);
    const bodyEl =
      winEl.querySelector('[data-window-body], [data-win-body], [data-surface], main') || winEl;
    const domHtml = String(bodyEl.innerHTML || '');

    return {
      found: true,
      matchedByWindowId,
      rect: { left: r.left, top: r.top, width: r.width, height: r.height },
      hasCanvas: Boolean(cr),
      canvasRect: cr ? { left: cr.left, top: cr.top, width: cr.width, height: cr.height } : null,
      text: fullText.slice(0, 600),
      fullText,
      inputValues,
      domHtml,
    };
  }, { windowId, titleSubstring, strictWindowId });
}

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
    const cr = canvas.getBoundingClientRect();
    return {
      found: true,
      width: canvas.width,
      height: canvas.height,
      nonZeroPixels: nonZero,
      rect: { left: cr.left, top: cr.top, width: cr.width, height: cr.height },
    };
  }, { windowId, titleSubstring });
}

/**
 * Strictly scopes inside a live desktop window body, EXCLUDING titlebar / window chrome buttons
 * (close/min/max/snap/header controls).
 */
async function findInteractiveBodyControl(page, { windowId = null, titleSubstring = null } = {}) {
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
    if (!winEl && opts.titleSubstring) {
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
    if (!winEl) return { found: false, reason: 'window not found' };

    const winRect = winEl.getBoundingClientRect();

    function isWindowChromeControl(el) {
      if (el.closest('[data-window-titlebar], [data-titlebar], [data-window-controls], [data-window-chrome], header')) {
        return true;
      }
      if (el.hasAttribute('data-window-action') || el.hasAttribute('data-snap') || el.hasAttribute('data-chrome-action')) {
        return true;
      }
      const r = el.getBoundingClientRect();
      if (r.top <= winRect.top + 44) {
        const txt = String(el.innerText || el.textContent || '').trim();
        const aria = `${el.getAttribute('aria-label') || ''} ${el.getAttribute('title') || ''}`;
        if (
          /^(?:×|x|✕|✖|—|−|-|_|□|⬜|▭|🗖|🗕|close|minimize|maximize|snap)$/i.test(txt) ||
          /close|minimize|maximize|snap|restore|fullscreen/i.test(aria)
        ) {
          return true;
        }
      }
      return false;
    }

    const bodyButtons = Array.from(winEl.querySelectorAll('button, [role="button"]')).filter(
      (b) => isVisible(b) && !isWindowChromeControl(b)
    );

    const describeBtn = (b, kind) => {
      b.scrollIntoView({ block: 'center', inline: 'center' });
      const r = b.getBoundingClientRect();
      return {
        found: true,
        kind,
        x: r.left + r.width / 2,
        y: r.top + r.height / 2,
        text: String(b.innerText || b.textContent || '').trim().slice(0, 40),
      };
    };

    // Priority 1: Non-zero digit button (e.g. calculator keypad '7' or '1'..'9')
    const digitBtn = bodyButtons.find((b) => /^[1-9]$/.test(String(b.innerText || b.textContent || '').trim()));
    if (digitBtn) return describeBtn(digitBtn, 'digit_button');

    // Priority 2: Visible body text/number inputs + compute/action button
    const bodyInputs = Array.from(winEl.querySelectorAll('input:not([type="file"]):not([type="hidden"]), textarea')).filter(
      (inp) => isVisible(inp) && !isWindowChromeControl(inp)
    );
    if (bodyInputs.length > 0 && bodyButtons.length > 0) {
      const b = bodyButtons[0];
      const br = b.getBoundingClientRect();
      return {
        found: true,
        kind: 'inputs_plus_button',
        inputs: bodyInputs.slice(0, 2).map((inp) => {
          const ir = inp.getBoundingClientRect();
          return { x: ir.left + ir.width / 2, y: ir.top + ir.height / 2 };
        }),
        button: {
          x: br.left + br.width / 2,
          y: br.top + br.height / 2,
          text: String(b.innerText || b.textContent || '').trim().slice(0, 40),
        },
      };
    }

    // Priority 3: Any visible non-chrome body button
    if (bodyButtons.length > 0) return describeBtn(bodyButtons[0], 'body_button');

    return { found: false, reason: 'no visible non-chrome body controls found' };
  }, { windowId, titleSubstring });
}

async function findCalculatorButton(page, { windowId, titleSubstring, labelPattern }) {
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
      for (const sel of [`[data-window-id="${escId}"]`, `[data-win-id="${escId}"]`, `[id="${escId}"]`]) {
        const matches = Array.from(document.querySelectorAll(sel)).filter(
          (el) =>
            el !== document.documentElement &&
            el !== document.body &&
            !el.matches(LEAF_CONTROL_SEL) &&
            !el.closest(CHROME_EXCLUDE_SEL) &&
            isVisible(el)
        );
        const picked = pickLargestWindow(matches);
        if (picked) { winEl = picked; break; }
      }
    }
    if (!winEl && opts.titleSubstring) {
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
    if (!winEl) return { found: false };
    const winRect = winEl.getBoundingClientRect();
    const re = new RegExp(opts.labelPattern, 'i');
    for (const b of winEl.querySelectorAll('button, [role="button"]')) {
      if (!isVisible(b)) continue;
      if (b.closest('[data-window-titlebar], [data-titlebar], [data-window-controls], [data-window-chrome], header')) continue;
      if (b.hasAttribute('data-window-action') || b.hasAttribute('data-snap')) continue;
      const r = b.getBoundingClientRect();
      if (r.top <= winRect.top + 40 && /^(?:×|x|✕|-|—)$/i.test(String(b.innerText || '').trim())) continue;
      const txt = String(b.innerText || b.textContent || '').trim();
      if (re.test(txt)) {
        return { found: true, x: r.left + r.width / 2, y: r.top + r.height / 2, text: txt };
      }
    }
    return { found: false };
  }, { windowId, titleSubstring, labelPattern });
}

async function waitForPermissionModalVisible(page, { appLabel, appId, timeoutMs = 6000 }) {
  await page.waitForFunction((lbl, id) => {
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
    const visibleModals = Array.from(
      document.querySelectorAll('[data-permission-modal], [data-permission-prompt], [role="alertdialog"], [role="dialog"]')
    ).filter(isTrulyVisible);

    return visibleModals.some((m) => {
      const txt = m.innerText || '';
      return txt.includes(lbl) || txt.includes(id) || (/allow/i.test(txt) && /deny|don.?t\s*allow|reject/i.test(txt));
    });
  }, { timeoutMs, args: [appLabel, appId] });
}

async function waitForPermissionModalDismissed(page, { appLabel, appId, timeoutMs = 5000 }) {
  await page.waitForFunction((lbl, id) => {
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
    const visibleModals = Array.from(
      document.querySelectorAll('[data-permission-modal], [data-permission-prompt], [role="alertdialog"], [role="dialog"]')
    ).filter(isTrulyVisible);

    for (const m of visibleModals) {
      const txt = m.innerText || '';
      if ((txt.includes(lbl) || txt.includes(id)) && /allow|deny|don.?t\s*allow|reject/i.test(txt)) {
        return false;
      }
    }
    return true;
  }, { timeoutMs, args: [appLabel, appId] });
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

describe('Tier 4 — S05: Headless Chromium CDP App Upload, Click-to-Execution & Security Modals (F-086)', () => {
  it('T4-S05-01 [Scenario 9 / F-086, F-070, F-073, F-074, F-083, F-040, F-046, F-056, F-059]: App Hub Dynamic Binary Upload -> Install -> Launch -> Real Click-to-Execution & Canvas2D Loop in Chromium', async () => {
    let page = null;
    let tmp = null;
    let apphubAppId = null;
    let dynAppId = null;
    let calcAppId = null;
    let canvasAppId = null;
    try {
      // Server-first lazy init (BEFORE createTempDataDir & readNonEmptyFile!)
      const { server, browser } = await getSuiteEnv();
      const sysApps = await discoverSystemAppsHttp(server.api);
      apphubAppId = sysApps.apphub;
      tmp = await createTempDataDir('omnios-t4-s05-upload-');

      const nonce = makeNonce(4);
      const opA = 1200 + crypto.randomInt(4000);
      const opB = 1200 + crypto.randomInt(4000);
      const expectedSum = String((opA + opB) | 0);

      // ----------------------------------------------------------------------
      // Phase A: App Hub Dynamic Custom .apk Upload -> Install -> Launch -> Live Execution
      // ----------------------------------------------------------------------
      dynAppId = `com.omnios.t4s05.dyn${nonce}`;
      const dynLabel = `T4Upload_${nonce}`;
      const dynNotifTitle = `DynUpload_${nonce}`;
      const dynOutVfsPath = `/home/user/Documents/cdp-dyn-${nonce}.txt`;

      const dynApkBytes = buildCustomApk({
        packageName: dynAppId,
        appLabel: dynLabel,
        computeA: opA,
        computeB: opB,
        computeOp: 'add',
        outputFile: `/sdcard/Documents/cdp-dyn-${nonce}.txt`,
        // Omit outputContent so Dalvik writes dynamically computed sum
        sharedPrefName: 'cdp_prefs',
        sharedPrefKey: 'run_tok',
        sharedPrefVal: `VAL_${nonce}`,
        notificationTitle: dynNotifTitle,
        notificationBody: `Sum=${expectedSum}`,
        permissions: [
          'android.permission.WRITE_EXTERNAL_STORAGE',
          'android.permission.POST_NOTIFICATIONS',
        ],
      });
      const hostApkPath = path.join(tmp.dir, `cdp-dyn-${nonce}.apk`);
      await fs.writeFile(hostApkPath, dynApkBytes);

      // Launch dynamically discovered App Hub
      const lHub = await server.api.post(`/api/v1/packages/${encodeURIComponent(apphubAppId)}/launch`, {}, { expectOk: true });
      const hubPid = lHub.json?.pid ?? lHub.json?.process?.pid;
      const hubWin = await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return asArray(s, ['windows']).find((w) => w.pid === hubPid || w.appId === apphubAppId) ?? null;
      }, { timeoutMs: 8000, label: 'App Hub Compositor window' });
      const apphubWinId = getWinId(hubWin);

      page = await browser.newPage();
      await page.goto(server.baseUrl);
      await waitForShellRendered(page);
      await page.waitForSelector('input[type="file"]', 8000);

      // Scope upload to App Hub window's <input type="file"> if present
      const scopedSel = `[data-window-id="${apphubWinId}"] input[type="file"]`;
      const hasScopedInput = await page.evalFn((sel) => Boolean(document.querySelector(sel)), scopedSel);
      await page.setFileInputFiles(hasScopedInput ? scopedSel : 'input[type="file"]', hostApkPath);

      // Click Install confirmation button if App Hub shows an inspection preview before installing
      const uploadStage = await waitUntil(async () => {
        const pkgsRes = await server.api.get('/api/v1/packages', { expectOk: true });
        if (JSON.stringify(pkgsRes.json).includes(dynAppId)) return 'installed';
        const uploadBtn = await findVisibleControl(page, {
          dataSelectors: ['[data-action="install-upload"]', '[data-action="install-package"]', '[data-install-btn]'],
          ariaPatterns: [],
          textPatterns: [],
        });
        if (uploadBtn.found) return uploadBtn;
        const uploadDialog = await page.evalFn((needleName, needleId) => {
          const dlg = Array.from(document.querySelectorAll('[role="dialog"], [data-upload-modal]'))
            .find((el) => {
              const st = window.getComputedStyle(el);
              if (st.display === 'none' || st.visibility === 'hidden' || !(parseFloat(st.opacity) > 0)) return false;
              if (el.getBoundingClientRect().width <= 0) return false;
              const txt = el.innerText || '';
              return txt.includes(needleName) || txt.includes(needleId);
            });
          return dlg ? (dlg.id ? `#${dlg.id}` : '[data-upload-modal]') : null;
        }, dynLabel, dynAppId);
        if (!uploadDialog) return null;
        const btn = await findVisibleControl(page, {
          scopeSelector: uploadDialog,
          dataSelectors: ['[data-action="install-upload"]', '[data-action="install-package"]', '[data-install-btn]'],
          ariaPatterns: ['install'],
          textPatterns: ['^install$', 'install\\s*package', 'install\\s*app'],
        });
        return btn.found ? btn : null;
      }, { timeoutMs: 8000, label: 'App Hub upload inspection or auto-install' });

      if (uploadStage && uploadStage !== 'installed') {
        await page.clickAt(uploadStage.x, uploadStage.y);
      }

      await waitUntil(async () => {
        const pkgsRes = await server.api.get('/api/v1/packages', { expectOk: true });
        return JSON.stringify(pkgsRes.json).includes(dynAppId);
      }, { timeoutMs: 8000, label: `uploaded dynamic APK ${dynAppId} present in /api/v1/packages` });

      // Dynamically allow discovered capabilities on dynAppId so Phase A tests execution cleanly
      await allowDiscoveredAppCapabilities(server.api, dynAppId);

      // Launch uploaded dynamic APK (via visible Launch control in App Hub if exposed, else REST)
      const launchCtrl = await findVisibleControl(page, {
        dataSelectors: [`[data-launch-app="${dynAppId}"]`, `[data-action="launch"][data-app-id="${dynAppId}"]`],
        ariaPatterns: [`launch.*${dynLabel}`, `open.*${dynLabel}`],
        scopeSelector: hasScopedInput
          ? `[data-window-id="${apphubWinId}"]:not(button):not(a):not([role="button"]):not([role="tab"])`
          : null,
      });
      if (launchCtrl.found) {
        await page.clickAt(launchCtrl.x, launchCtrl.y);
      } else {
        await server.api.post(`/api/v1/packages/${encodeURIComponent(dynAppId)}/launch`, {}, { expectOk: true });
      }

      const dynWin = await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const w = asArray(s, ['windows']).find((x) => x.appId === dynAppId);
        return w && JSON.stringify(getUiTree(w)).includes(expectedSum) ? w : null;
      }, { timeoutMs: 8000, label: `dynamic APK window rendering computed sum ${expectedSum} in uiTree` });
      assert.equal(dynWin.platform, 'android');
      const dynWinId = getWinId(dynWin);

      // Verify live Chromium DOM renders dynWin with computed sum, plus VFS file & notification
      const domDyn = await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: dynWinId, titleSubstring: dynWin.title || dynLabel });
        return w.found && w.text.includes(expectedSum) ? w : null;
      }, { timeoutMs: 8000, label: `Chromium DOM rendering computed sum ${expectedSum}` });
      assert.ok(domDyn.text.includes(expectedSum));

      await waitUntil(async () => {
        const fRes = await server.api.get('/api/v1/vfs/file', { query: { path: dynOutVfsPath } });
        return extractFileText(fRes).includes(expectedSum);
      }, { timeoutMs: 6000, label: `canonical VFS ${dynOutVfsPath} containing ${expectedSum}` });

      await waitUntil(async () => {
        const nRes = await server.api.get('/api/v1/ipc/notifications', { expectOk: true });
        return JSON.stringify(nRes.json).includes(dynNotifTitle);
      }, { timeoutMs: 6000, label: `Notification Center containing ${dynNotifTitle}` });

      // ----------------------------------------------------------------------
      // Phase B1: Real Binary Click-to-Execution (packages/android-calc.apk)
      // ----------------------------------------------------------------------
      const calcBytes = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', 'android-calc.apk'));
      const instCalc = await installPackageHttp(server.api, calcBytes, 'android-calc.apk', { grantAll: true });
      calcAppId = instCalc?.appId ?? instCalc?.package?.appId ?? instCalc?.id;
      assert.ok(calcAppId, `Expected appId installing android-calc.apk: ${JSON.stringify(instCalc)}`);

      const lCalc = await server.api.post(`/api/v1/packages/${encodeURIComponent(calcAppId)}/launch`, {}, { expectOk: true });
      const calcPid = lCalc.json?.pid ?? lCalc.json?.process?.pid;
      assert.ok(calcPid > 1);

      const calcWin0 = await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return asArray(s, ['windows']).find((w) => w.pid === calcPid || w.appId === calcAppId) ?? null;
      }, { timeoutMs: 8000, label: 'android-calc Compositor window' });
      const calcWinId = getWinId(calcWin0);
      const calcTitle = calcWin0.title || 'Calc';

      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(calcWinId)}/move`, { x: 100, y: 90 });
      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(calcWinId)}/focus`, {});

      const domCalcBefore = await waitUntil(async () => {
        const w = await findVisibleWindow(page, { windowId: calcWinId, titleSubstring: calcTitle });
        return w.found ? w : null;
      }, { timeoutMs: 8000, label: 'visible android-calc window in Chromium DOM' });

      const calcSnapBefore = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
      const calcWinBefore = asArray(calcSnapBefore, ['windows']).find((w) => getWinId(w) === calcWinId) ?? calcWin0;
      const beforeRev = getSurfaceRev(calcWinBefore);
      const beforeTreeJson = JSON.stringify(getUiTree(calcWinBefore));

      const bodyCtrl = await waitUntil(async () => {
        const c = await findInteractiveBodyControl(page, { windowId: calcWinId, titleSubstring: calcTitle });
        return c.found ? c : null;
      }, { timeoutMs: 6000, label: 'visible non-chrome interactive control inside android-calc window body' });
      assert.equal(bodyCtrl.found, true);

      let beforeClickDom = domCalcBefore;
      if (bodyCtrl.kind === 'inputs_plus_button') {
        const vals = ['13', '29'];
        for (let i = 0; i < bodyCtrl.inputs.length; i++) {
          await page.clickAt(bodyCtrl.inputs[i].x, bodyCtrl.inputs[i].y);
          await page.send('Input.insertText', { text: vals[i] });
        }
        beforeClickDom = await findVisibleWindow(page, { windowId: calcWinId, titleSubstring: calcTitle });
        await page.clickAt(bodyCtrl.button.x, bodyCtrl.button.y);
      } else {
        await page.clickAt(bodyCtrl.x, bodyCtrl.y);
      }

      const beforeFullText = beforeClickDom.fullText ?? beforeClickDom.text;
      const beforeInputsJson = JSON.stringify(beforeClickDom.inputValues ?? []);
      const beforeDomHtml = beforeClickDom.domHtml ?? '';

      // Strictly assert BOTH backend surface mutation AND genuine live Chromium DOM mutation (no tautology!)
      await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const w = asArray(s, ['windows']).find((x) => getWinId(x) === calcWinId);
        if (!w) return false;
        const backendChanged = getSurfaceRev(w) > beforeRev || JSON.stringify(getUiTree(w)) !== beforeTreeJson;
        if (!backendChanged) return false;
        const domNow = await findVisibleWindow(page, { windowId: calcWinId, titleSubstring: calcTitle });
        if (!domNow.found) return false;
        const domMutated =
          (domNow.fullText ?? domNow.text) !== beforeFullText ||
          JSON.stringify(domNow.inputValues ?? []) !== beforeInputsJson ||
          (domNow.domHtml ?? '') !== beforeDomHtml;
        return domMutated;
      }, { timeoutMs: 6000, label: 'android-calc backend surfaceRevision/uiTree and genuine live DOM mutation after click' });

      // Optional keypad follow-up (+, 5, =) when calculator keypad buttons exist
      const plusBtn = await findCalculatorButton(page, { windowId: calcWinId, titleSubstring: calcTitle, labelPattern: '^\\+$' });
      const fiveBtn = await findCalculatorButton(page, { windowId: calcWinId, titleSubstring: calcTitle, labelPattern: '^5$' });
      const eqBtn = await findCalculatorButton(page, { windowId: calcWinId, titleSubstring: calcTitle, labelPattern: '^=$' });
      if (plusBtn.found && fiveBtn.found && eqBtn.found) {
        await page.clickAt(plusBtn.x, plusBtn.y);
        await page.clickAt(fiveBtn.x, fiveBtn.y);
        await page.clickAt(eqBtn.x, eqBtn.y);
      }

      const calcProc = await server.api.get(`/api/v1/processes/${calcPid}`, { expectOk: true });
      assertAliveState(extractProcState(calcProc.json), `android-calc PID ${calcPid}`);

      // ----------------------------------------------------------------------
      // Phase B2: Real Universal WASM Canvas2D Rasterization & Pointer Interaction
      // ----------------------------------------------------------------------
      const canvasBytes = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', 'universal-canvas.uapp'));
      const instCanvas = await installPackageHttp(server.api, canvasBytes, 'universal-canvas.uapp', { grantAll: true });
      canvasAppId = instCanvas?.appId ?? instCanvas?.package?.appId ?? instCanvas?.id;
      assert.ok(canvasAppId, `Expected appId installing universal-canvas.uapp: ${JSON.stringify(instCanvas)}`);

      const lCanvas = await server.api.post(`/api/v1/packages/${encodeURIComponent(canvasAppId)}/launch`, {}, { expectOk: true });
      const canvasPid = lCanvas.json?.pid ?? lCanvas.json?.process?.pid;
      assert.ok(canvasPid > 1);

      const canvasWin = await waitUntil(async () => {
        const s = unwrapSnapshot((await server.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return asArray(s, ['windows']).find((w) => w.pid === canvasPid || w.appId === canvasAppId) ?? null;
      }, { timeoutMs: 8000, label: 'universal-canvas Compositor window' });
      const canvasWinId = getWinId(canvasWin);
      const canvasTitle = canvasWin.title || 'Canvas';

      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(canvasWinId)}/move`, { x: 540, y: 100 });
      await server.api.post(`/api/v1/compositor/windows/${encodeURIComponent(canvasWinId)}/focus`, {});

      const canvasStats = await waitUntil(async () => {
        const st = await inspectWindowCanvas(page, { windowId: canvasWinId, titleSubstring: canvasTitle });
        return st.found && st.width > 0 && st.height > 0 && st.nonZeroPixels > 0 ? st : null;
      }, { timeoutMs: 8000, label: 'window-scoped universal-canvas <canvas> non-zero DrawOp pixels' });
      assert.ok(canvasStats.nonZeroPixels > 0);

      // Click canvas center via real CDP + optional body control
      await page.clickAt(
        canvasStats.rect.left + canvasStats.rect.width / 2,
        canvasStats.rect.top + canvasStats.rect.height / 2
      );
      const canvasBodyBtn = await findInteractiveBodyControl(page, { windowId: canvasWinId, titleSubstring: canvasTitle });
      if (canvasBodyBtn.found && canvasBodyBtn.x !== undefined) {
        await page.clickAt(canvasBodyBtn.x, canvasBodyBtn.y);
      }

      const canvasProc = await server.api.get(`/api/v1/processes/${canvasPid}`, { expectOk: true });
      assertAliveState(extractProcState(canvasProc.json), `universal-canvas PID ${canvasPid}`);

      assertZeroBrowserErrors(page, 'T4-S05-01');
    } finally {
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        if (apphubAppId) await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(apphubAppId)}/stop`, {}).catch(() => {});
        if (calcAppId) await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(calcAppId)}/stop`, {}).catch(() => {});
        if (canvasAppId) await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(canvasAppId)}/stop`, {}).catch(() => {});
        if (dynAppId) {
          await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(dynAppId)}/stop`, {}).catch(() => {});
          await suiteServer.api.delete(`/api/v1/packages/${encodeURIComponent(dynAppId)}`).catch(() => {});
        }
      }
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });

  it('T4-S05-02 [Scenario 10 / F-086, F-024, F-028, F-081, F-082]: Live Universal Share Sheet Chooser (intent:chooser) & Security Permission Prompt (permission:prompt Allow + Deny) Loops in Chromium', async () => {
    let page = null;
    let ws = null;
    const cleanupAppIds = [];
    try {
      // Server-first lazy init
      const { server, browser } = await getSuiteEnv();
      ws = await server.connectWs();
      page = await browser.newPage();
      await page.goto(server.baseUrl);
      await waitForShellRendered(page);

      const nonce = makeNonce(4);

      // ----------------------------------------------------------------------
      // Part A: Live Universal Share Sheet Chooser (intent:chooser)
      // Two symmetric dynamic .uapp packages sharing identical scheme -> guaranteed CHOOSER_REQUIRED
      // ----------------------------------------------------------------------
      const shareScheme = `t4share${nonce}`;
      const appIdA = `com.omnios.t4s05.sharea.${nonce}`;
      const appIdB = `com.omnios.t4s05.shareb.${nonce}`;
      const nameA = `T4ShareA_${nonce}`;
      const nameB = `T4ShareB_${nonce}`;
      const tokenA = `T4_SA_EXEC_${nonce}`;
      const tokenB = `T4_SB_EXEC_${nonce}`;
      cleanupAppIds.push(appIdA, appIdB);

      await installPackageHttp(
        server.api,
        buildCustomUapp({ appId: appIdA, name: nameA, urlSchemes: [shareScheme], message: `${tokenA}\n` }),
        `t4-sharea-${nonce}.uapp`,
        { grantAll: true }
      );
      await installPackageHttp(
        server.api,
        buildCustomUapp({ appId: appIdB, name: nameB, urlSchemes: [shareScheme], message: `${tokenB}\n` }),
        `t4-shareb-${nonce}.uapp`,
        { grantAll: true }
      );

      const shareWsCursor = ws.mark();
      const dispatchRes = await server.api.post('/api/v1/ipc/intents/dispatch', {
        action: 'android.intent.action.VIEW',
        uri: `${shareScheme}://doc`,
        scheme: shareScheme,
      }, { expectOk: true });
      assert.equal(dispatchRes.json?.status, 'CHOOSER_REQUIRED', `Expected CHOOSER_REQUIRED, got: ${dispatchRes.text}`);

      await page.waitForFunction(
        (a, b) => {
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
          const modalEls = Array.from(
            document.querySelectorAll('[data-share-sheet], [data-intent-chooser], [role="dialog"], [role="alertdialog"]')
          );
          if (modalEls.length > 0) {
            return modalEls.some((m) => {
              if (!isTrulyVisible(m)) return false;
              const txt = m.innerText || '';
              return txt.includes(a) && txt.includes(b);
            });
          }
          const txt = document.body.innerText || '';
          return txt.includes(a) && txt.includes(b);
        },
        { timeoutMs: 6000, args: [nameA, nameB] }
      );

      const shareModalScope = await page.evalFn((a, b) => {
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
        for (const sel of ['[data-share-sheet]', '[data-intent-chooser]', '[role="dialog"]', '[role="alertdialog"]']) {
          const hit = Array.from(document.querySelectorAll(sel)).find((m) => {
            if (!isTrulyVisible(m)) return false;
            const t = m.innerText || '';
            return t.includes(a) && t.includes(b);
          });
          if (hit) {
            if (hit.id) {
              const escId = String(hit.id).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
              return `[id="${escId}"]`;
            }
            return sel;
          }
        }
        return null;
      }, nameA, nameB);

      await clickSemanticControl(page, {
        dataSelectors: [`[data-app-id="${appIdA}"]`, `[data-choice-app="${appIdA}"]`],
        ariaPatterns: [nameA],
        textPatterns: [nameA],
        scopeSelector: shareModalScope,
      }, `Share Sheet choice ${nameA}`);

      // Verify Share Sheet modal genuinely dismissed (scoped strictly to truly visible modal elements
      // so Desktop icons / Dock listing installed app nameB never cause a false timeout!)
      await page.waitForFunction((b) => {
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
        const visibleModals = Array.from(
          document.querySelectorAll('[data-share-sheet], [data-intent-chooser], [role="dialog"], [role="alertdialog"]')
        ).filter(isTrulyVisible);
        return !visibleModals.some((m) => (m.innerText || '').includes(b));
      }, { timeoutMs: 5000, args: [nameB] });

      // Verify chosen appIdA genuinely executed on backend AND unchosen appIdB did NOT
      await waitUntil(async () => {
        const wsMsgs = ws.getMessages(shareWsCursor);
        const wsHit = wsMsgs.some((m) => {
          if (m?.type === 'process:update' || m?.type === 'process:stdout') {
            const blob = JSON.stringify(m.payload ?? {});
            return blob.includes(tokenA) || blob.includes(appIdA);
          }
          return false;
        });
        if (wsHit) return true;
        const pRes = await server.api.get('/api/v1/processes', { expectOk: true });
        const procs = asArray(pRes.json, ['processes', 'items', 'data']);
        return procs.some((p) => p.appId === appIdA || JSON.stringify(p).includes(tokenA));
      }, { timeoutMs: 6000, label: `backend execution proof for chosen Share Sheet handler ${appIdA}` });

      const wsMsgsAfterShare = ws.getMessages(shareWsCursor);
      assert.equal(
        wsMsgsAfterShare.some((m) => JSON.stringify(m.payload ?? {}).includes(tokenB)),
        false,
        `Unchosen Share Sheet handler ${appIdB} must NOT have executed`
      );

      // ----------------------------------------------------------------------
      // Part B1: Security Permission Prompt Modal (permission:prompt -> Allow)
      // ----------------------------------------------------------------------
      const permAppAllow = `com.omnios.t4s05.pallow.${nonce}`;
      const permLabelAllow = `T4PermAllow_${nonce}`;
      const allowFilePath = `/home/user/Documents/t4-perm-allow-${nonce}.txt`;
      const allowFileToken = `T4_PERM_ALLOW_${nonce}`;
      cleanupAppIds.push(permAppAllow);

      const instAllow = await installPackageHttp(
        server.api,
        buildCustomApk({
          packageName: permAppAllow,
          appLabel: permLabelAllow,
          permissions: ['android.permission.WRITE_EXTERNAL_STORAGE'],
          outputFile: `/sdcard/Documents/t4-perm-allow-${nonce}.txt`,
          outputContent: allowFileToken,
        }),
        `t4-perm-allow-${nonce}.apk`,
        { grantAll: false }
      );

      // Dynamically discover the canonical user-file-write capability (ZERO hardcoded cap strings!)
      const writeCap = await discoverUserWriteCapability(server.api, permAppAllow, instAllow);

      const allowSetRes = await writeWithMethodFallback(
        server.api,
        ['PUT', 'POST', 'PATCH'],
        '/api/v1/security/permissions',
        { appId: permAppAllow, capability: writeCap, state: 'prompt' }
      );
      assert.ok(
        allowSetRes && allowSetRes.ok,
        `Expected HTTP 2xx setting ${writeCap}=prompt for ${permAppAllow}, got ${allowSetRes?.status}: ${allowSetRes?.text}`
      );

      await server.api.post(`/api/v1/packages/${encodeURIComponent(permAppAllow)}/launch`, {}, { expectOk: true });

      await waitForPermissionModalVisible(page, { appLabel: permLabelAllow, appId: permAppAllow });

      await clickSemanticControl(page, {
        dataSelectors: ['[data-permission-decision="allow"]', '[data-action="permission-allow"]', '[data-allow]'],
        ariaPatterns: ['^allow$', 'grant'],
        textPatterns: ['^allow$', 'allow\\s*once', 'grant'],
      }, 'Permission Prompt Allow button');

      await waitForPermissionModalDismissed(page, { appLabel: permLabelAllow, appId: permAppAllow });

      // Strictly capability-filtered verification: MUST prove BOTH Audit Log Allow entry AND Allow effect (policy or VFS write)!
      const allowCheckers = makeAuditCheckers(permAppAllow, writeCap);
      await waitUntil(async () => {
        const audRes = await server.api.get('/api/v1/security/audit', { query: { appId: permAppAllow, limit: 30 }, expectOk: true });
        const audPayloadAppId = audRes.json && typeof audRes.json === 'object' && !Array.isArray(audRes.json) ? (audRes.json.appId ?? null) : null;
        const auditAllowed = asArray(audRes.json, ['audit', 'entries', 'items', 'data']).some((e) =>
          allowCheckers.isAllowAuditEntry(e, audPayloadAppId)
        );

        const permsRes = await server.api.get('/api/v1/security/permissions', { query: { appId: permAppAllow } });
        const policyAllowed = permsRes.ok && allowCheckers.hasAllowPolicy(permsRes.json, { scopedToApp: true });

        const fRes = await server.api.get('/api/v1/vfs/file', { query: { path: allowFilePath } });
        const vfsWritten = extractFileText(fRes).includes(allowFileToken);

        return auditAllowed && (policyAllowed || vfsWritten);
      }, { timeoutMs: 6000, label: `capability-filtered Allow audit log + decision/VFS write (${writeCap}) for ${permAppAllow}` });

      // ----------------------------------------------------------------------
      // Part B2: Security Permission Prompt Modal (permission:prompt -> Deny)
      // ----------------------------------------------------------------------
      const permAppDeny = `com.omnios.t4s05.pdeny.${nonce}`;
      const permLabelDeny = `T4PermDeny_${nonce}`;
      const denyFilePath = `/home/user/Documents/t4-perm-deny-${nonce}.txt`;
      const denyFileToken = `T4_PERM_DENY_${nonce}`;
      cleanupAppIds.push(permAppDeny);

      await installPackageHttp(
        server.api,
        buildCustomApk({
          packageName: permAppDeny,
          appLabel: permLabelDeny,
          permissions: ['android.permission.WRITE_EXTERNAL_STORAGE'],
          outputFile: `/sdcard/Documents/t4-perm-deny-${nonce}.txt`,
          outputContent: denyFileToken,
        }),
        `t4-perm-deny-${nonce}.apk`,
        { grantAll: false }
      );

      const denySetRes = await writeWithMethodFallback(
        server.api,
        ['PUT', 'POST', 'PATCH'],
        '/api/v1/security/permissions',
        { appId: permAppDeny, capability: writeCap, state: 'prompt' }
      );
      assert.ok(
        denySetRes && denySetRes.ok,
        `Expected HTTP 2xx setting ${writeCap}=prompt for ${permAppDeny}, got ${denySetRes?.status}: ${denySetRes?.text}`
      );

      await server.api.post(`/api/v1/packages/${encodeURIComponent(permAppDeny)}/launch`, {}, { expectOk: true });

      await waitForPermissionModalVisible(page, { appLabel: permLabelDeny, appId: permAppDeny });

      await clickSemanticControl(page, {
        dataSelectors: ['[data-permission-decision="deny"]', '[data-action="permission-deny"]', '[data-deny]'],
        ariaPatterns: ['^deny$', 'reject', 'don.?t\\s*allow'],
        textPatterns: ['^deny$', 'don.?t\\s*allow', 'reject'],
      }, 'Permission Prompt Deny button');

      await waitForPermissionModalDismissed(page, { appLabel: permLabelDeny, appId: permAppDeny });

      // Strictly capability-filtered Deny Audit Log verification + VFS file NOT created!
      const denyCheckers = makeAuditCheckers(permAppDeny, writeCap);
      await waitUntil(async () => {
        const audRes = await server.api.get('/api/v1/security/audit', { query: { appId: permAppDeny, limit: 30 }, expectOk: true });
        const audPayloadAppId = audRes.json && typeof audRes.json === 'object' && !Array.isArray(audRes.json) ? (audRes.json.appId ?? null) : null;
        const auditDenied = asArray(audRes.json, ['audit', 'entries', 'items', 'data']).some((e) =>
          denyCheckers.isDenyAuditEntry(e, audPayloadAppId)
        );
        return auditDenied;
      }, { timeoutMs: 6000, label: `capability-filtered Deny audit log (${writeCap}) for ${permAppDeny}` });

      await sleep(300);
      const denyFileRes = await server.api.get('/api/v1/vfs/file', { query: { path: denyFilePath } });
      assert.equal(
        denyFileRes.ok && extractFileText(denyFileRes).includes(denyFileToken),
        false,
        `Denied app ${permAppDeny} must NOT have created ${denyFilePath} (got HTTP ${denyFileRes.status}: ${denyFileRes.text})`
      );

      assertZeroBrowserErrors(page, 'T4-S05-02');
    } finally {
      if (ws) await ws.close().catch(() => {});
      if (page) await page.close().catch(() => {});
      if (suiteServer) {
        for (const id of cleanupAppIds) {
          await suiteServer.api.post(`/api/v1/packages/${encodeURIComponent(id)}/stop`, {}).catch(() => {});
          await suiteServer.api.delete(`/api/v1/packages/${encodeURIComponent(id)}`).catch(() => {});
        }
      }
    }
  });
});
