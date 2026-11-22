/**
 * OmniOS Tier 3 Pairwise E2E Suite — P-05:
 * Headless Compositor (Multi-Window, Focus, Z-Order, Snap Layouts, Global Menu Bar,
 * Dual Surfaces) × Dual RFC 6455 /ws Clients × Live 5-Mode Shell Switching
 * × Remote CLI (--remote --json) × Multi-Syntax Shell / OmniTerm × Spotlight Search.
 *
 * Feature Pairs Exercised:
 *   F-022, F-029, F-030, F-031, F-034, F-055, F-062, F-063, F-064, F-065, F-066, F-067, F-076
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded system app IDs or capability names.
 * - Supports flat & nested compositor bounds and surface.{uiTree,drawOps,surfaceRevision/revision}.
 * - Echo-stripped OmniTerm output assertions.
 * - Zero assertions inside try/catch blocks.
 * - Clean try/finally teardown on every test.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';
import { buildCustomApk } from '../lib/fixtures-android-win.mjs';
import { buildCustomMacAppZip } from '../lib/fixtures-apple-wasm.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(fn, { timeoutMs = 8000, intervalMs = 50, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    let val = null;
    try {
      val = await fn();
    } catch (err) {
      lastError = err;
    }
    if (val) return val;
    const rem = deadline - Date.now();
    if (rem > 0) await sleep(Math.min(intervalMs, rem));
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for ${label}` +
    (lastError ? ` (last error: ${lastError.message})` : '')
  );
}

function getWinId(win) {
  const id = win?.windowId ?? win?.id;
  assert.ok(typeof id === 'string' && id.length > 0, `Window missing string windowId: ${JSON.stringify(win)}`);
  return id;
}

function getBounds(win) {
  const b = win?.bounds ?? win;
  assert.ok(b && typeof b === 'object', `Window missing bounds: ${JSON.stringify(win)}`);
  return {
    x: b.x,
    y: b.y,
    width: b.width ?? b.w,
    height: b.height ?? b.h,
  };
}

function getUiTree(win) {
  return win?.uiTree ?? win?.surface?.uiTree ?? null;
}

function getDrawOps(win) {
  return win?.drawOps ?? win?.surface?.drawOps ?? null;
}

function getSurfaceRev(win) {
  return win?.surfaceRevision ?? win?.surface?.surfaceRevision ?? win?.surface?.revision ?? null;
}

function unwrapSnapshot(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  if (Array.isArray(payload.windows)) return payload;
  if (payload.snapshot && typeof payload.snapshot === 'object') return payload.snapshot;
  if (payload.data && typeof payload.data === 'object') return payload.data;
  if (payload.payload && typeof payload.payload === 'object') return payload.payload;
  return payload;
}

function findWindow(snapshot, winId) {
  return (snapshot?.windows ?? []).find((w) => (w?.windowId ?? w?.id) === winId) ?? null;
}

function assertWindowRaisedAbove(snap, topWinId, belowWinId, contextMsg) {
  const wins = snap?.windows ?? [];
  const topIdx = wins.findIndex((w) => (w?.windowId ?? w?.id) === topWinId);
  const belowIdx = wins.findIndex((w) => (w?.windowId ?? w?.id) === belowWinId);
  assert.ok(topIdx >= 0 && belowIdx >= 0, `${contextMsg}: both windows must exist in snapshot`);
  const wTop = wins[topIdx];
  const wBelow = wins[belowIdx];
  const zTop = wTop.zIndex ?? wTop.zOrder ?? wTop.z;
  const zBelow = wBelow.zIndex ?? wBelow.zOrder ?? wBelow.z;
  if (typeof zTop === 'number' && typeof zBelow === 'number') {
    assert.ok(zTop > zBelow, `${contextMsg}: focused window z (${zTop}) must exceed lower window z (${zBelow})`);
  } else {
    assert.ok(topIdx > belowIdx, `${contextMsg}: focused window index (${topIdx}) must rank above lower window (${belowIdx})`);
  }
  if (typeof wTop.focused === 'boolean') {
    assert.equal(wTop.focused, true, `${contextMsg}: focused window must have focused === true`);
  }
  if (typeof wBelow.focused === 'boolean') {
    assert.equal(wBelow.focused, false, `${contextMsg}: unfocused window must have focused === false`);
  }
}

function unwrapExplicitArray(payload, keys = ['results', 'packages', 'apps', 'catalog', 'items', 'processes', 'windows', 'data', 'entries', 'list']) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return null;
  for (const key of keys) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  if (payload.data && typeof payload.data === 'object') {
    for (const key of keys) {
      if (Array.isArray(payload.data[key])) return payload.data[key];
    }
  }
  return null;
}

const SYSTEM_ROLE_DEFS = [
  { role: 'terminal', pattern: /omniterm|terminal/i },
  { role: 'files', pattern: /omnifiles|files/i },
  { role: 'monitor', pattern: /monitor|task/i },
  { role: 'apphub', pattern: /apphub|app[\s_-]*hub/i },
  { role: 'settings', pattern: /settings|privacy/i },
  { role: 'inspector', pattern: /inspector/i },
  { role: 'notes', pattern: /omninotes|notes/i },
];

function extractAppEntries(source, fromInstalled) {
  const out = [];
  const arr = unwrapExplicitArray(source, ['packages', 'apps', 'catalog', 'items', 'data', 'entries']);
  const list = arr ?? (source && typeof source === 'object' ? Object.entries(source).map(([k, v]) => (typeof v === 'object' && v ? { id: k, ...v } : v)) : []);
  for (const item of list) {
    if (typeof item === 'string' && item.trim()) {
      out.push({ appId: item.trim(), name: item.trim(), platform: '', isBuiltin: false, fromInstalled });
    } else if (item && typeof item === 'object') {
      const appId = String(item.appId ?? item.id ?? '').trim();
      if (!appId) continue;
      const name = String(item.name ?? item.title ?? item.displayName ?? item.label ?? '').trim();
      const platform = String(item.platform ?? '').toLowerCase();
      const isBuiltin = Boolean(
        item.builtin || item.builtIn || item.isSystem || item.system ||
        item.kind === 'system' || item.type === 'system' || platform === 'system'
      );
      out.push({ appId, name, platform, isBuiltin, fromInstalled });
    }
  }
  return out;
}

function resolveRoleMap(entries) {
  const byId = new Map();
  for (const e of entries) {
    const prev = byId.get(e.appId);
    byId.set(e.appId, prev
      ? { ...e, name: prev.name || e.name, platform: prev.platform || e.platform, isBuiltin: prev.isBuiltin || e.isBuiltin, fromInstalled: prev.fromInstalled || e.fromInstalled }
      : e);
  }
  const list = Array.from(byId.values());
  const resolved = {};
  const used = new Set();
  for (const { role, pattern } of SYSTEM_ROLE_DEFS) {
    const matches = list
      .filter((c) => !used.has(c.appId) && (pattern.test(c.appId) || pattern.test(c.name)))
      .map((c) => {
        let score = 0;
        if (c.fromInstalled) score += 200;
        if (c.isBuiltin) score += 50;
        if (!c.platform || c.platform === 'system' || c.platform === 'universal' || c.platform === 'omnios') score += 15;
        if (/sharer/i.test(`${c.appId} ${c.name}`)) score -= 25;
        return { c, score };
      })
      .sort((a, b) => b.score - a.score);
    if (matches.length > 0) {
      resolved[role] = matches[0].c.appId;
      used.add(matches[0].c.appId);
    }
  }
  return resolved;
}

async function discoverSystemAppsHttp(api) {
  const entries = [];
  const pkgRes = await api.get('/api/v1/packages', { expectOk: true });
  entries.push(...extractAppEntries(pkgRes.json, true));
  const catRes = await api.get('/api/v1/packages/catalog');
  if (catRes.ok && catRes.json !== null) {
    entries.push(...extractAppEntries(catRes.json, false));
  }
  return resolveRoleMap(entries);
}

async function restMutate(api, urlPath, body, opts = {}) {
  let res = await api.put(urlPath, body, opts);
  if (res.status === 404 || res.status === 405) {
    res = await api.post(urlPath, body, opts);
  }
  if (res.status === 404 || res.status === 405) {
    res = await api.patch(urlPath, body, opts);
  }
  return res;
}

async function installPackageHttp(api, bytes, filename) {
  const buf = bytes instanceof Uint8Array ? bytes : Buffer.from(String(bytes), 'utf8');
  let res = await api.post('/api/v1/packages/install', buf, {
    query: { filename, grantAll: 'true' },
    headers: { 'content-type': 'application/octet-stream', 'x-filename': filename },
  });
  if (!res.ok) {
    const b64 = Buffer.from(buf).toString('base64');
    res = await api.post('/api/v1/packages/install', {
      filename,
      grantAll: true,
      base64: b64,
      data: b64,
      buffer: b64,
    });
  }
  return res;
}

function readSystemShellMode(payload) {
  const roots = [payload, payload?.data, payload?.config, payload?.system].filter(
    (obj) => obj && typeof obj === 'object' && !Array.isArray(obj)
  );
  for (const obj of roots) {
    if (typeof obj['system.shellMode'] === 'string') return obj['system.shellMode'];
    if (typeof obj.shellMode === 'string') return obj.shellMode;
  }
  return undefined;
}

function collectTreeNodes(node, out = []) {
  if (!node || typeof node !== 'object') return out;
  if (Array.isArray(node)) {
    for (const item of node) collectTreeNodes(item, out);
    return out;
  }
  out.push(node);
  for (const key of ['children', 'items', 'tabs', 'panels', 'actions', 'buttons', 'rows']) {
    if (Array.isArray(node[key])) {
      for (const child of node[key]) collectTreeNodes(child, out);
    }
  }
  for (const key of ['body', 'content', 'header', 'footer', 'sidebar', 'main']) {
    if (node[key] && typeof node[key] === 'object') collectTreeNodes(node[key], out);
  }
  return out;
}

function findInputNode(uiTree) {
  const nodes = collectTreeNodes(uiTree);
  const inputTypes = new Set(['input', 'textarea', 'textfield', 'terminal-input', 'command-input', 'editor', 'search']);
  return (
    nodes.find((n) => n.id && inputTypes.has(String(n.type ?? '').toLowerCase())) ??
    nodes.find((n) => n.id && /input|editor|command|term|text/i.test(String(n.id))) ??
    null
  );
}

function hasExecutedTerminalOutput(uiTree, needle, typedCmd) {
  if (!uiTree) return false;
  const blob = JSON.stringify(uiTree);
  if (!blob.includes(needle)) return false;

  const inputTypes = new Set(['input', 'textarea', 'textfield', 'terminal-input', 'command-input', 'editor', 'search']);
  const nodes = collectTreeNodes(uiTree);
  for (const n of nodes) {
    const t = String(n.type ?? '').toLowerCase();
    if (inputTypes.has(t)) continue;
    for (const [k, v] of Object.entries(n)) {
      if (['children', 'items', 'tabs', 'panels', 'actions', 'buttons', 'rows'].includes(k)) continue;
      if (typeof v === 'string' && v.replaceAll(typedCmd, '').includes(needle)) return true;
      if (Array.isArray(v) && v.some((x) => typeof x === 'string' && x.replaceAll(typedCmd, '').includes(needle))) return true;
    }
  }
  return blob.replaceAll(typedCmd, '').includes(needle);
}

function extractSpotlightItems(payload) {
  const arr = unwrapExplicitArray(payload, ['results', 'items', 'hits', 'matches', 'data']);
  if (Array.isArray(arr)) return arr;
  if (payload && typeof payload === 'object') {
    const combined = [];
    let sawCategoryArray = false;
    const containers = [payload, payload.data, payload.results, payload.data?.results].filter(
      (c) => c && typeof c === 'object' && !Array.isArray(c)
    );
    for (const container of containers) {
      for (const key of ['apps', 'packages', 'files', 'processes', 'settings', 'actions']) {
        if (Array.isArray(container[key])) {
          sawCategoryArray = true;
          combined.push(...container[key]);
        }
      }
    }
    return sawCategoryArray ? combined : null;
  }
  return null;
}

async function execShellRest(api, command) {
  const res = await api.post('/api/v1/shell/exec', { command }, { expectOk: true });
  const stdout = typeof res.json?.stdout === 'string'
    ? res.json.stdout
    : (typeof res.json?.output === 'string' ? res.json.output : res.text);
  return { res, stdout };
}

describe('Tier 3 — P-05: Compositor, Dual WebSocket, Live Shell Modes, Remote CLI, OmniTerm & Spotlight Sync', () => {
  test('T3-P05-01 [F-029, F-030, F-062, F-063]: Multi-Window Focus, Z-Order, Snap Layouts & Global Menu Bar Synced Across REST + Dual /ws Clients', async () => {
    const srv = await startOmniServer();
    let wsA = null;
    let wsB = null;
    try {
      wsA = await srv.connectWs();
      wsB = await srv.connectWs();

      await Promise.all([
        wsA.waitForType('compositor:snapshot', { timeoutMs: 5000 }),
        wsB.waitForType('compositor:snapshot', { timeoutMs: 5000 }),
      ]);

      const roles = await discoverSystemAppsHttp(srv.api);
      const roleOrder = ['notes', 'files', 'terminal', 'settings', 'monitor', 'apphub', 'inspector'];
      const picked = roleOrder.map((r) => roles[r]).filter(Boolean);
      assert.ok(picked.length >= 2, `Must dynamically discover >=2 built-in system apps (found ${JSON.stringify(roles)})`);
      const [app1, app2] = picked;

      // Launch 2 distinct system apps and assert BOTH wsA and wsB observe window_created
      const cA1 = wsA.mark();
      const cB1 = wsB.mark();
      const l1 = await srv.api.post(`/api/v1/packages/${encodeURIComponent(app1)}/launch`, {}, { expectOk: true });
      const pid1 = l1.json?.pid ?? l1.json?.process?.pid;
      await Promise.all([
        wsA.waitForType('compositor:window_created', { since: cA1, timeoutMs: 5000 }),
        wsB.waitForType('compositor:window_created', { since: cB1, timeoutMs: 5000 }),
      ]);

      const cA2 = wsA.mark();
      const cB2 = wsB.mark();
      const l2 = await srv.api.post(`/api/v1/packages/${encodeURIComponent(app2)}/launch`, {}, { expectOk: true });
      const pid2 = l2.json?.pid ?? l2.json?.process?.pid;
      await Promise.all([
        wsA.waitForType('compositor:window_created', { since: cA2, timeoutMs: 5000 }),
        wsB.waitForType('compositor:window_created', { since: cB2, timeoutMs: 5000 }),
      ]);

      const snapInit = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
      const w1Obj = (snapInit?.windows ?? []).find((w) => w?.pid === pid1 || w?.appId === app1);
      const w2Obj = (snapInit?.windows ?? []).find((w) => (w?.pid === pid2 || w?.appId === app2) && getWinId(w) !== getWinId(w1Obj));
      assert.ok(w1Obj && w2Obj, `Both launched apps must appear in compositor snapshot (got ${JSON.stringify(snapInit?.windows)})`);
      const win1 = getWinId(w1Obj);
      const win2 = getWinId(w2Obj);

      // Move & resize win1 from wsA -> wsB observes compositor:window_updated
      const cMove = wsB.mark();
      wsA.send({ type: 'compositor:move', payload: { windowId: win1, x: 120, y: 90 } });
      await wsB.waitForType('compositor:window_updated', { since: cMove, timeoutMs: 5000 });

      const cResize = wsB.mark();
      wsA.send({ type: 'compositor:resize', payload: { windowId: win1, width: 620, height: 420 } });
      await wsB.waitForType('compositor:window_updated', { since: cResize, timeoutMs: 5000 });

      await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const cur = findWindow(s, win1);
        if (!cur) return false;
        const b = getBounds(cur);
        return b.x === 120 && b.y === 90 && b.width === 620 && b.height === 420;
      }, { timeoutMs: 5000, label: 'WS move/resize reflected in REST snapshot' });

      // Apply Windows Snap Layouts (snapped-left & snapped-right) via wsA -> verify geometry in REST snapshot
      const cSnap = wsB.mark();
      wsA.send({ type: 'compositor:state', payload: { windowId: win1, state: 'snapped-left' } });
      wsA.send({ type: 'compositor:state', payload: { windowId: win2, state: 'snapped-right' } });
      await wsB.waitForType('compositor:window_updated', { since: cSnap, timeoutMs: 5000 });

      const snapTiled = await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const a = findWindow(s, win1);
        const b = findWindow(s, win2);
        if (!a || !b) return null;
        if (getBounds(b).x > getBounds(a).x) return s;
        return null;
      }, { timeoutMs: 5000, label: 'snapped-right x > snapped-left x' });
      assert.ok(getBounds(findWindow(snapTiled, win2)).x > getBounds(findWindow(snapTiled, win1)).x, 'snapped-right window must sit right of snapped-left window');

      // Focus switching win1 -> win2 -> verify z-order raising, focusedWindowId & activeMenuBar
      wsA.send({ type: 'compositor:focus', payload: { windowId: win1 } });
      await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return s?.focusedWindowId === win1;
      }, { timeoutMs: 5000, label: 'focus win1' });

      const cFocus2 = wsB.mark();
      wsA.send({ type: 'compositor:focus', payload: { windowId: win2 } });
      await wsB.waitForMessage(
        (m) =>
          m?.type === 'compositor:window_updated' ||
          (m?.type === 'compositor:snapshot' && unwrapSnapshot(m?.payload ?? m)?.focusedWindowId === win2),
        { since: cFocus2, timeoutMs: 5000 }
      );

      const snapFocused2 = await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return s?.focusedWindowId === win2 ? s : null;
      }, { timeoutMs: 5000, label: 'focus win2' });
      assertWindowRaisedAbove(snapFocused2, win2, win1, 'Focusing win2 must raise it strictly above win1');
      assert.ok(
        snapFocused2?.activeMenuBar !== undefined && snapFocused2?.activeMenuBar !== null,
        `Compositor snapshot must expose activeMenuBar (got ${JSON.stringify(snapFocused2?.activeMenuBar)})`
      );

      // Close win1 via wsA -> wsB receives compositor:window_closed, win1 disappears from REST while win2 stays
      const cClose = wsB.mark();
      wsA.send({ type: 'compositor:close', payload: { windowId: win1 } });
      await wsB.waitForType('compositor:window_closed', { since: cClose, timeoutMs: 5000 });

      const snapAfterClose = await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return !findWindow(s, win1) ? s : null;
      }, { timeoutMs: 5000, label: 'win1 removal from snapshot' });
      assert.equal(findWindow(snapAfterClose, win1), null, 'Closed window win1 must disappear from REST snapshot');
      assert.ok(findWindow(snapAfterClose, win2), 'Sibling window win2 must remain open after win1 closes');
    } finally {
      await wsA?.close();
      await wsB?.close();
      await srv.stop();
    }
  });

  test('T3-P05-02 [F-022, F-029, F-063, F-076]: Live 5-Mode Shell Switching Preserving Open Multi-Platform Windows (Built-In + Installed Android .apk)', async () => {
    const srv = await startOmniServer();
    let ws = null;
    try {
      ws = await srv.connectWs();
      const nonce = makeNonce();
      const roles = await discoverSystemAppsHttp(srv.api);
      const sysAppId = roles.notes ?? roles.files ?? Object.values(roles)[0];
      assert.ok(sysAppId, 'Must dynamically discover built-in system app');

      // 1. Launch built-in system app
      const sysLaunch = await srv.api.post(`/api/v1/packages/${encodeURIComponent(sysAppId)}/launch`, {}, { expectOk: true });
      const sysPid = sysLaunch.json?.pid ?? sysLaunch.json?.process?.pid;

      // 2. Install & launch dynamic Android .apk with TextView window
      const andPkg = `com.p05.keep.${nonce}`;
      const apkBytes = buildCustomApk({
        packageName: andPkg,
        appLabel: `Keep_${nonce}`,
        outputContent: `KEEP_WIN_${nonce}`,
      });
      const andInst = await installPackageHttp(srv.api, apkBytes, `p05-keep-${nonce}.apk`);
      assert.ok(andInst.ok, `Android APK install must succeed (got ${andInst.status}: ${andInst.text})`);
      const andAppId = andInst.json?.appId ?? andInst.json?.id ?? andInst.json?.package?.appId ?? andPkg;
      const andLaunch = await srv.api.post(`/api/v1/packages/${encodeURIComponent(andAppId)}/launch`, {}, { expectOk: true });
      const andPid = andLaunch.json?.pid ?? andLaunch.json?.process?.pid;

      // Wait until BOTH system window and Android runtime window are present in compositor snapshot
      const pair = await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const wins = s?.windows ?? [];
        const sw = wins.find((w) => w?.pid === sysPid || w?.appId === sysAppId);
        const aw = wins.find((w) => w?.pid === andPid || w?.appId === andAppId);
        return sw && aw ? { sysWinId: getWinId(sw), andWinId: getWinId(aw) } : null;
      }, { timeoutMs: 8000, label: 'both built-in and Android windows in compositor snapshot' });

      // 3. Cycle all 5 adaptive shell modes alternating REST and WS
      const modes = ['windows', 'macos', 'ios', 'android', 'unified'];
      for (let i = 0; i < modes.length; i++) {
        const mode = modes[i];
        if (i % 2 === 0) {
          const r = await restMutate(srv.api, '/api/v1/compositor/shell-mode', { mode, shellMode: mode });
          assert.ok(r.ok, `REST shell-mode switch to "${mode}" must succeed (got ${r.status}: ${r.text})`);
        } else {
          ws.send({ type: 'shell:mode', payload: { mode, shellMode: mode } });
        }

        const snap = await waitUntil(async () => {
          const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
          return s?.shellMode === mode ? s : null;
        }, { timeoutMs: 6000, label: `shellMode === ${mode}` });

        const cfgRes = await srv.api.get('/api/v1/config/system', { expectOk: true });
        assert.equal(readSystemShellMode(cfgRes.json), mode, `Config store must persist shellMode "${mode}"`);
        assert.ok(findWindow(snap, pair.sysWinId), `Built-in window ${pair.sysWinId} must stay open in mode "${mode}"`);
        assert.ok(findWindow(snap, pair.andWinId), `Android APK window ${pair.andWinId} must stay open in mode "${mode}"`);
      }

      // Confirm both PIDs remained alive across all 5 shell modes
      for (const pid of [sysPid, andPid]) {
        const pRes = await srv.api.get(`/api/v1/processes/${pid}`, { expectOk: true });
        const st = pRes.json?.state ?? pRes.json?.process?.state ?? pRes.json?.data?.state;
        assert.ok(st && st !== 'TERMINATED' && st !== 'ZOMBIE', `PID ${pid} must remain alive across 5-mode switches (state=${st})`);
      }
    } finally {
      await ws?.close();
      await srv.stop();
    }
  });

  test('T3-P05-03 [F-029, F-034, F-063, F-065]: Remote CLI (--remote --json) ospm launch / ps / ospm stop & kill Synced With Compositor & /ws', async () => {
    const srv = await startOmniServer();
    let ws = null;
    try {
      ws = await srv.connectWs();

      // 1. Dynamically discover long-lived built-in system app strictly via Remote CLI ospm list --json
      const cliList = await srv.runCli(['ospm', 'list'], { json: true, expectZero: true });
      const pkgArr = unwrapExplicitArray(cliList.json, ['packages', 'apps', 'items', 'data']);
      assert.ok(Array.isArray(pkgArr) && pkgArr.length > 0, `Remote CLI ospm list --json must return explicit array (stdout=${cliList.stdout})`);
      const roles = resolveRoleMap(extractAppEntries(pkgArr, true));
      const appId = roles.notes ?? roles.files ?? roles.terminal ?? Object.values(roles)[0];
      assert.ok(appId, `Must dynamically discover launchable app via Remote CLI ospm list (got ${JSON.stringify(pkgArr)})`);

      // 2. Launch via Remote CLI -> verify WS compositor:window_created, REST /processes/:pid & Remote CLI ps
      const cCreate = ws.mark();
      const cliLaunch = await srv.runCli(['ospm', 'launch', appId], { json: true, expectZero: true });
      const wsCreated = await ws.waitForType('compositor:window_created', { since: cCreate, timeoutMs: 6000 });
      assert.equal(wsCreated?.type, 'compositor:window_created');

      const winCreated = wsCreated?.payload?.window ?? wsCreated?.payload ?? {};
      const pid = cliLaunch.json?.pid ?? cliLaunch.json?.process?.pid ?? cliLaunch.json?.data?.pid ?? winCreated?.pid;
      assert.ok(Number.isInteger(pid) && pid > 0, `Remote CLI ospm launch must yield valid PID (cli=${cliLaunch.stdout})`);

      const restProc = await srv.api.get(`/api/v1/processes/${pid}`, { expectOk: true });
      const st = restProc.json?.state ?? restProc.json?.process?.state ?? restProc.json?.data?.state;
      assert.ok(st && st !== 'TERMINATED' && st !== 'ZOMBIE', `REST /api/v1/processes/${pid} must show live process`);

      const cliPs = await srv.runCli(['ps'], { json: true, expectZero: true });
      const psArr = unwrapExplicitArray(cliPs.json, ['processes', 'items', 'data']);
      assert.ok(Array.isArray(psArr), `Remote CLI ps --json must return explicit array (stdout=${cliPs.stdout})`);
      assert.ok(psArr.some((p) => Number(p?.pid) === pid), `Remote CLI ps must include launched PID ${pid}`);

      const snapBeforeStop = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
      const winObj = (snapBeforeStop?.windows ?? []).find((w) => w?.pid === pid || w?.appId === appId);
      assert.ok(winObj, `Compositor snapshot must include window for CLI-launched PID ${pid}`);
      const winId = getWinId(winObj);

      // 3. Stop via Remote CLI ospm stop (falling back to kill SIGTERM if stop requires appId or pid form)
      const cClose = ws.mark();
      let stopRes = await srv.runCli(['ospm', 'stop', String(pid)], { json: true });
      if (!stopRes.ok) {
        stopRes = await srv.runCli(['ospm', 'stop', appId], { json: true });
      }
      if (!stopRes.ok) {
        stopRes = await srv.runCli(['kill', String(pid), '--signal', 'SIGTERM'], { json: true, expectZero: true });
      }
      assert.equal(stopRes.ok, true, `Stopping PID ${pid} via Remote CLI must succeed`);

      // Verify process terminated & compositor window closed
      await waitUntil(async () => {
        const p = await srv.api.get(`/api/v1/processes/${pid}`);
        const pState = p.json?.state ?? p.json?.process?.state ?? p.json?.data?.state;
        const procGone = p.status === 404 || pState === 'TERMINATED' || pState === 'ZOMBIE';
        const snapNow = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return procGone && !findWindow(snapNow, winId);
      }, { timeoutMs: 6000, label: `PID ${pid} termination & window ${winId} closure` });

      const wsCloseMsg = await ws.waitForMessage(
        (m) =>
          (m?.type === 'compositor:window_closed' &&
            ((m?.payload?.windowId ?? m?.payload?.id ?? m?.windowId ?? winId) === winId)) ||
          (m?.type === 'compositor:snapshot' &&
            Array.isArray(unwrapSnapshot(m?.payload ?? m)?.windows) &&
            !findWindow(unwrapSnapshot(m?.payload ?? m), winId)),
        { since: cClose, timeoutMs: 5000 }
      );
      assert.ok(
        wsCloseMsg && (wsCloseMsg.type === 'compositor:window_closed' || wsCloseMsg.type === 'compositor:snapshot'),
        `Stopping app via Remote CLI must broadcast WS compositor:window_closed or snapshot removal for ${winId} (got ${JSON.stringify(wsCloseMsg)})`
      );
    } finally {
      await ws?.close();
      await srv.stop();
    }
  });

  test('T3-P05-04 [F-031, F-066, F-067]: Multi-Syntax Shell (POSIX + Windows + macOS + Android) x Live OmniTerm Compositor Input & Echo-Stripped Output', async () => {
    const srv = await startOmniServer();
    try {
      const nonce = makeNonce();
      const dirPosix = `/home/user/Documents/sh-${nonce}`;
      const filePosix = `${dirPosix}/hello.txt`;
      const dirWin = `C:\\Users\\user\\Documents\\sh-${nonce}`;
      const fileWin = `${dirWin}\\hello.txt`;
      const body = `SHELL_SYNC_${nonce}`;

      // 1. Provision file and cross-verify POSIX (ls/cat) vs Windows (dir/type) in Multi-Syntax Shell
      const mkRes = await srv.api.post('/api/v1/vfs/mkdir', { path: dirPosix, recursive: true });
      assert.ok(mkRes.ok, `mkdir ${dirPosix} must succeed (got ${mkRes.status}: ${mkRes.text})`);
      const wfRes = await restMutate(srv.api, '/api/v1/vfs/file', { path: filePosix, content: body });
      assert.ok(wfRes.ok, `write ${filePosix} must succeed (got ${wfRes.status}: ${wfRes.text})`);

      const posixLs = await execShellRest(srv.api, `ls ${dirPosix}`);
      assert.ok(posixLs.stdout.includes('hello.txt'), `POSIX ls must list hello.txt (got ${posixLs.stdout})`);
      const posixCat = await execShellRest(srv.api, `cat ${filePosix}`);
      assert.ok(posixCat.stdout.includes(body), `POSIX cat must return "${body}" (got ${posixCat.stdout})`);

      const winDir = await execShellRest(srv.api, `dir ${dirWin}`);
      assert.ok(winDir.stdout.includes('hello.txt'), `Windows dir must list hello.txt (got ${winDir.stdout})`);
      const winType = await execShellRest(srv.api, `type ${fileWin}`);
      assert.ok(winType.stdout.includes(body), `Windows type must return "${body}" (got ${winType.stdout})`);

      // 2. Compare POSIX ps & Windows tasklist — both include PID 1 (omnid)
      const psOut = await execShellRest(srv.api, 'ps');
      const taskOut = await execShellRest(srv.api, 'tasklist');
      assert.ok(/omnid/i.test(psOut.stdout) && psOut.stdout.includes('1'), `POSIX ps must list PID 1 omnid (got ${psOut.stdout})`);
      assert.ok(/omnid/i.test(taskOut.stdout) && taskOut.stdout.includes('1'), `Windows tasklist must list PID 1 omnid (got ${taskOut.stdout})`);

      // 3. macOS defaults write in shell -> verified via REST /api/v1/config/defaults
      const shDom = `com.p05.sh.${nonce}`;
      const shVal = `v_${nonce}`;
      await execShellRest(srv.api, `defaults write ${shDom} k ${shVal}`);
      const defRes = await srv.api.get('/api/v1/config/defaults', { query: { domain: shDom, key: 'k' }, expectOk: true });
      assert.ok(defRes.text.includes(shVal), `REST defaults must reflect shell defaults write (got ${defRes.text})`);

      // 4. Package listing via shell ospm list
      const ospmOut = await execShellRest(srv.api, 'ospm list');
      assert.ok(ospmOut.stdout.trim().length > 0, 'Shell ospm list must output installed packages');

      // 5. Launch live OmniTerm window, dispatch real command via compositor input, verify echo-stripped execution output
      const roles = await discoverSystemAppsHttp(srv.api);
      assert.ok(roles.terminal, `Must dynamically discover OmniTerm system app (roles=${JSON.stringify(roles)})`);
      const termLaunch = await srv.api.post(`/api/v1/packages/${encodeURIComponent(roles.terminal)}/launch`, {}, { expectOk: true });
      const termPid = termLaunch.json?.pid ?? termLaunch.json?.process?.pid;

      const termWin = await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return (s?.windows ?? []).find((w) => w?.pid === termPid || w?.appId === roles.terminal) ?? null;
      }, { timeoutMs: 6000, label: 'OmniTerm compositor window' });
      const termWinId = getWinId(termWin);

      const inputNode = findInputNode(getUiTree(termWin));
      const targetId = inputNode?.id ?? 'terminal-input';
      const needle = `TERM_EXEC_${nonce}`;
      const typedCmd = `echo ${needle}`;

      await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(termWinId)}/input`, {
        type: 'input',
        nodeId: targetId,
        targetId,
        value: typedCmd,
        text: typedCmd,
      }, { expectOk: true });
      await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(termWinId)}/input`, {
        type: 'keydown',
        nodeId: targetId,
        targetId,
        key: 'Enter',
        code: 'Enter',
        value: typedCmd,
      }, { expectOk: true });

      const executed = await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const w = findWindow(s, termWinId);
        return w && hasExecutedTerminalOutput(getUiTree(w), needle, typedCmd);
      }, { timeoutMs: 6000, label: `echo-stripped OmniTerm output "${needle}"` });
      assert.equal(executed, true, `OmniTerm UI tree must display executed output "${needle}" beyond echoed input "${typedCmd}"`);
    } finally {
      await srv.stop();
    }
  });

  test('T3-P05-05 [F-034, F-055, F-062, F-064]: Spotlight Universal Search Live Indexing of Installed macOS .app + Android .apk + VFS Doc & Post-Removal Cleanup', async () => {
    const srv = await startOmniServer();
    try {
      const nonce = makeNonce();

      // 1. Baseline zero-match Spotlight query
      const zeroRes = await srv.api.get('/api/v1/search', { query: { q: `SpotZero${nonce}` }, expectOk: true });
      const zeroItems = extractSpotlightItems(zeroRes.json);
      assert.ok(Array.isArray(zeroItems), `GET /api/v1/search must return structured results array (got ${zeroRes.text})`);
      assert.equal(
        zeroItems.some((r) => JSON.stringify(r).includes(`SpotZero${nonce}`)),
        false,
        'Baseline Spotlight query for absent nonce must return 0 matches'
      );

      // 2. Install dynamic macOS .app.zip & Android .apk + write VFS document
      const macBundle = `com.p05.spotmac.${nonce}`;
      const macName = `SpotMac${nonce}`;
      const macInst = await installPackageHttp(
        srv.api,
        buildCustomMacAppZip({ bundleId: macBundle, appName: macName, executableName: macName, message: `${macName}\n` }),
        `${macName}.app.zip`
      );
      assert.ok(macInst.ok, `Installing Spotlight macOS app must succeed (got ${macInst.status}: ${macInst.text})`);

      const andPkg = `com.p05.spotand.${nonce}`;
      const andLabel = `SpotAnd${nonce}`;
      const andInst = await installPackageHttp(
        srv.api,
        buildCustomApk({ packageName: andPkg, appLabel: andLabel }),
        `${andLabel}.apk`
      );
      assert.ok(andInst.ok, `Installing Spotlight Android app must succeed (got ${andInst.status}: ${andInst.text})`);

      const docName = `SpotDoc${nonce}.txt`;
      const docPath = `/home/user/Documents/${docName}`;
      const docWrite = await restMutate(srv.api, '/api/v1/vfs/file', {
        path: docPath,
        content: `Spotlight document body ${nonce}`,
      });
      assert.ok(docWrite.ok, `Writing Spotlight VFS doc must succeed (got ${docWrite.status})`);

      // 3. Query Spotlight for macOS app, Android app, and VFS document
      for (const [label, q] of [['macOS app', macName], ['Android app', andLabel], ['VFS doc', `SpotDoc${nonce}`]]) {
        const res = await srv.api.get('/api/v1/search', { query: { q }, expectOk: true });
        const items = extractSpotlightItems(res.json);
        assert.ok(
          Array.isArray(items) && items.length > 0 && JSON.stringify(items).includes(q),
          `Spotlight must index and return ${label} "${q}" (got ${res.text})`
        );
      }

      // 4. Uninstall macOS app via REST & delete VFS doc via Remote CLI -> verify Spotlight & Remote CLI de-index both!
      const delPkg = await srv.api.delete(`/api/v1/packages/${encodeURIComponent(macBundle)}`);
      assert.ok(delPkg.ok, `DELETE /api/v1/packages/${macBundle} must succeed (got ${delPkg.status}: ${delPkg.text})`);

      const cliAfterDel = await srv.runCli(['ospm', 'list'], { json: true, expectZero: true });
      const cliAfterArr = unwrapExplicitArray(cliAfterDel.json, ['packages', 'apps', 'items', 'data']);
      assert.ok(Array.isArray(cliAfterArr), `Remote CLI ospm list --json after uninstall must return explicit array (stdout=${cliAfterDel.stdout})`);
      assert.equal(
        cliAfterArr.some((p) => (p?.appId ?? p?.id) === macBundle) || cliAfterDel.stdout.includes(macBundle),
        false,
        `Uninstalled app "${macBundle}" must disappear from Remote CLI ospm list JSON & stdout`
      );

      await srv.runCli(['vfs', 'rm', docPath], { json: true, expectZero: true });

      const postMacSearch = await srv.api.get('/api/v1/search', { query: { q: macName }, expectOk: true });
      const postMacItems = extractSpotlightItems(postMacSearch.json);
      assert.ok(Array.isArray(postMacItems), 'Post-uninstall Spotlight query must return valid array');
      assert.equal(
        postMacItems.some((r) => JSON.stringify(r).includes(macName) || JSON.stringify(r).includes(macBundle)),
        false,
        `Uninstalled macOS app "${macName}" must be de-indexed from Spotlight (got ${postMacSearch.text})`
      );

      const postDocSearch = await srv.api.get('/api/v1/search', { query: { q: `SpotDoc${nonce}` }, expectOk: true });
      const postDocItems = extractSpotlightItems(postDocSearch.json);
      assert.ok(Array.isArray(postDocItems), 'Post-delete Spotlight query must return valid array');
      assert.equal(
        postDocItems.some((r) => JSON.stringify(r).includes(`SpotDoc${nonce}`)),
        false,
        `Deleted VFS doc "${docName}" must be de-indexed from Spotlight (got ${postDocSearch.text})`
      );
    } finally {
      await srv.stop();
    }
  });

  test('T3-P05-06 [F-029, F-030, F-031, F-063]: Dual-Mode Compositor Surfaces (uiTree + drawOps + appendDrawOps + surfaceRevision) x 6-Type Input Routing x WS terminal:exec & ping', async () => {
    const nonce = makeNonce();
    let os = null;
    let srv = null;
    let ws = null;
    try {
      // Part A: Programmatic dual-mode surface revisions + 6 input event types
      os = await loadPublicOmniOS();
      const pm = os.require('processManager');
      const compositor = os.require('compositor');

      const receivedEvents = [];
      const proc = pm.spawn({
        name: `p05-surf-${nonce}`,
        appId: `com.p05.surf.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        cwd: '/home/user',
        executionContext: {
          step() { return { status: 'YIELD', instructionsExecuted: 1 }; },
          deliverEvent(ev) { receivedEvents.push(ev); },
          getDebugState() { return { arch: 'wasm', pc: 0, sp: 0, registers: {}, instructionsExecuted: 0, lastSyscall: null, stackTop: 0 }; },
          dispose() {},
        },
      });

      const created = compositor.createWindow(proc.pid, {
        appId: proc.appId,
        platform: 'universal',
        title: `Surface_${nonce}`,
        width: 500,
        height: 360,
        x: 60,
        y: 60,
        uiTree: { type: 'view', id: 'root', children: [{ type: 'text', id: 'lbl', text: 'v0' }] },
        drawOps: [{ op: 'rect', x: 0, y: 0, w: 100, h: 40, fill: '#112233' }],
      });
      const winId = getWinId(created);
      const rev0 = getSurfaceRev(findWindow(compositor.getSnapshot(), winId));
      assert.equal(typeof rev0, 'number', `Initial surfaceRevision must be numeric (got ${rev0})`);

      // Update uiTree -> monotonic revision bump
      compositor.updateSurface(winId, {
        uiTree: { type: 'view', id: 'root', children: [{ type: 'button', id: 'btn', text: `Go-${nonce}` }] },
      });
      const w1 = findWindow(compositor.getSnapshot(), winId);
      const rev1 = getSurfaceRev(w1);
      assert.ok(rev1 > rev0, `surfaceRevision must increment on uiTree update (${rev0} -> ${rev1})`);

      // Update drawOps -> monotonic revision bump
      compositor.updateSurface(winId, {
        drawOps: [
          { op: 'clear', color: '#000000' },
          { op: 'text', x: 12, y: 24, text: `Draw_${nonce}` },
        ],
      });
      const w2 = findWindow(compositor.getSnapshot(), winId);
      const rev2 = getSurfaceRev(w2);
      assert.ok(rev2 > rev1, `surfaceRevision must increment on drawOps update (${rev1} -> ${rev2})`);

      // appendDrawOps -> monotonic revision bump, 3 ordered drawOps, preserved uiTree
      compositor.updateSurface(winId, {
        appendDrawOps: [{ op: 'circle', x: 40, y: 40, r: 10, fill: '#00ffaa' }],
      });
      const w3 = findWindow(compositor.getSnapshot(), winId);
      const rev3 = getSurfaceRev(w3);
      assert.ok(rev3 > rev2, `surfaceRevision must increment on appendDrawOps (${rev2} -> ${rev3})`);

      const finalOps = getDrawOps(w3);
      assert.ok(Array.isArray(finalOps) && finalOps.length === 3, `Expected 3 ordered drawOps after appendDrawOps (got ${JSON.stringify(finalOps)})`);
      assert.equal(finalOps[0].op, 'clear');
      assert.equal(finalOps[1].op, 'text');
      assert.equal(finalOps[2].op, 'circle');
      assert.ok(JSON.stringify(getUiTree(w3)).includes(`Go-${nonce}`), 'appendDrawOps must preserve retained uiTree');

      // Dispatch all 6 input event types -> every event reaches owning process ExecutionContext.deliverEvent()
      const inputEvents = [
        { type: 'click', nodeId: 'btn', x: 20, y: 20 },
        { type: 'action', nodeId: 'btn', action: 'submit' },
        { type: 'input', nodeId: 'txt', value: `in-${nonce}` },
        { type: 'keydown', key: 'Enter', code: 'Enter' },
        { type: 'canvas_pointer', action: 'down', x: 40, y: 40 },
        { type: 'menu_action', itemId: 'file.save' },
      ];
      for (const ev of inputEvents) {
        compositor.dispatchInput(winId, ev);
      }
      assert.equal(receivedEvents.length, 6, `All 6 input event types must route to deliverEvent() (got ${receivedEvents.length})`);
      for (let i = 0; i < inputEvents.length; i++) {
        assert.equal(receivedEvents[i]?.type, inputEvents[i].type, `Event #${i} type mismatch`);
      }

      compositor.closeWindow(winId);
      await pm.kill(proc.pid, 'SIGKILL');
      await os.shutdown();
      os = null;

      // Part B: Live Server WS ping + terminal:exec
      srv = await startOmniServer();
      ws = await srv.connectWs();
      ws.send({ type: 'ping', payload: { nonce } });
      await sleep(150);
      assert.equal(ws.isOpen(), true, 'WebSocket must stay open and healthy after client ping');

      const cTerm = ws.mark();
      const wsToken = `WS_PING_${nonce}`;
      const wsCmd = `echo ${wsToken}`;
      ws.send({ type: 'terminal:exec', payload: { command: wsCmd } });

      const isValidTerminalWsReply = (m) => {
        if (!m || typeof m !== 'object') return false;
        if (/error/i.test(String(m.type ?? ''))) return false;
        if (m.ok === false || m.payload?.ok === false || m.error || m.payload?.error) return false;
        if (typeof m.payload?.exitCode === 'number' && m.payload.exitCode !== 0) return false;
        const serialized = JSON.stringify(m);
        return serialized.replaceAll(wsCmd, '').includes(wsToken);
      };

      const wsReply = await ws.waitForMessage(isValidTerminalWsReply, { since: cTerm, timeoutMs: 5000 });
      assert.ok(
        isValidTerminalWsReply(wsReply),
        `WS terminal:exec must return a non-error WS reply containing executed output "${wsToken}" beyond echoed command "${wsCmd}" (got ${JSON.stringify(wsReply)})`
      );
      assert.equal(ws.isOpen(), true, 'WebSocket must remain open after terminal:exec');
    } finally {
      await ws?.close();
      await srv?.stop();
      await os?.shutdown();
    }
  });
});
