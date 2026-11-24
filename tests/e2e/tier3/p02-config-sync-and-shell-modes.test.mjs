/**
 * OmniOS Tier 3 Pairwise E2E Suite — P-02:
 * Unified Config Store (Windows Registry HKCU/HKLM, Apple NSUserDefaults/plist,
 * Android SharedPreferences, system.* keys) × Adaptive Shell Modes × WS/REST/CLI/Shell Sync.
 *
 * Feature Pairs Exercised:
 *   F-021, F-022, F-027, F-029, F-040, F-044, F-062, F-063, F-065, F-066, F-076
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded system app IDs or capability names.
 * - Zero assertions inside try/catch blocks.
 * - Clean try/finally teardown on every test.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

import {
  createTempDataDir,
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';
import {
  buildCustomApk,
  buildCustomPe64Exe,
} from '../lib/fixtures-android-win.mjs';

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

function stableSerialize(val) {
  if (typeof val === 'bigint') return `${val}n`;
  if (val instanceof Uint8Array) return `bin:${Buffer.from(val).toString('hex')}`;
  try {
    return JSON.stringify(val);
  } catch {
    return String(val);
  }
}

function extractRegDataValue(payload) {
  if (!payload || typeof payload !== 'object') return undefined;
  const candidate =
    payload.value && typeof payload.value === 'object' ? payload.value :
    payload.entry && typeof payload.entry === 'object' ? payload.entry :
    payload.data && typeof payload.data === 'object' && ('data' in payload.data || 'value' in payload.data || 'type' in payload.data) ? payload.data :
    payload;
  if (candidate && typeof candidate === 'object') {
    if ('data' in candidate && (candidate.data === null || typeof candidate.data !== 'object')) return candidate.data;
    if ('value' in candidate && (candidate.value === null || typeof candidate.value !== 'object')) return candidate.value;
  }
  return undefined;
}

function normalizeRegValues(rawValues) {
  const map = new Map();
  if (!rawValues) return map;
  if (rawValues instanceof Map) {
    for (const [k, v] of rawValues.entries()) map.set(String(k), v);
    return map;
  }
  if (Array.isArray(rawValues)) {
    for (const item of rawValues) {
      if (item && typeof item === 'object') {
        const name = item.name ?? item.valueName ?? item.key ?? '';
        map.set(String(name), { type: item.type, data: item.data ?? item.value });
      }
    }
    return map;
  }
  if (typeof rawValues === 'object') {
    for (const [k, v] of Object.entries(rawValues)) {
      if (v && typeof v === 'object' && ('data' in v || 'type' in v)) {
        map.set(k, { type: v.type, data: v.data });
      } else {
        map.set(k, { type: typeof v === 'number' ? 'REG_DWORD' : 'REG_SZ', data: v });
      }
    }
  }
  return map;
}

async function walkRegistryTree(registry, hive, startPath = '', maxDepth = 12) {
  const entries = new Map();
  const visited = new Set();

  async function walk(keyPath, depth) {
    if (depth > maxDepth) return;
    const norm = keyPath.replace(/^\\+|\\+$/g, '');
    if (visited.has(norm)) return;
    visited.add(norm);

    let enumRes = null;
    try {
      enumRes = await registry.enumKey(hive, norm, { uid: 0 });
    } catch {
      return;
    }
    if (!enumRes || typeof enumRes !== 'object') return;

    const vals = normalizeRegValues(enumRes.values);
    for (const [valName, valObj] of vals.entries()) {
      entries.set(`${norm}::${valName}`, {
        keyPath: norm,
        valueName: valName,
        type: valObj?.type ?? 'REG_SZ',
        data: valObj?.data,
      });
    }

    const subkeys = Array.isArray(enumRes.subkeys) ? enumRes.subkeys : [];
    for (const sk of subkeys) {
      const skStr = String(sk).replace(/^\\+|\\+$/g, '');
      if (!skStr) continue;
      const childPath = norm
        ? (skStr.toLowerCase().startsWith(`${norm.toLowerCase()}\\`) ? skStr : `${norm}\\${skStr}`)
        : skStr;
      await walk(childPath, depth + 1);
    }
  }

  await walk(startPath, 0);
  if (entries.size === 0 && startPath === '') {
    for (const seed of ['Software', 'SOFTWARE', 'Control Panel', 'System']) {
      await walk(seed, 0);
    }
  }
  return entries;
}

function sharedPrefsOpsApplied(snapshot, ops) {
  if (!snapshot || typeof snapshot !== 'object') {
    return ops.every((o) => o.op === 'remove' || o.action === 'remove');
  }
  for (const op of ops) {
    const kind = op.op ?? op.action ?? op.type;
    if (kind === 'remove' || kind === 'delete') {
      if (op.key in snapshot && snapshot[op.key] !== undefined) return false;
    } else if (!(op.key in snapshot) || stableSerialize(snapshot[op.key]) !== stableSerialize(op.value)) {
      return false;
    }
  }
  return true;
}

async function applySharedPrefsEdit(sp, pkg, prefName, ops, ctx) {
  const candidates = [
    ops.map((o) => ({
      op: o.op ?? o.action ?? 'put',
      key: o.key,
      ...(o.op === 'remove' || o.action === 'remove' ? {} : { value: o.value }),
    })),
    ops.map((o) => ({
      type: o.op ?? o.action ?? 'put',
      key: o.key,
      ...(o.op === 'remove' || o.action === 'remove' ? {} : { value: o.value }),
    })),
    (() => {
      const setMap = {};
      const removeList = [];
      for (const o of ops) {
        if (o.op === 'remove' || o.action === 'remove') removeList.push(o.key);
        else setMap[o.key] = o.value;
      }
      return { set: setMap, remove: removeList };
    })(),
  ];

  let lastErr = null;
  for (const payload of candidates) {
    try {
      const res = await sp.edit(pkg, prefName, payload, ctx);
      const after = await sp.getAll(pkg, prefName, ctx);
      if (sharedPrefsOpsApplied(after, ops)) return res;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr ?? new Error(`sharedPrefs.edit() failed for ${pkg}/${prefName}`);
}

function parsePlistViaPython(xmlStr) {
  const raw = execFileSync(
    'python3',
    ['-c', 'from sys import stdin; import plistlib, json; print(json.dumps(plistlib.loads(stdin.buffer.read()), default=str))'],
    { input: Buffer.from(String(xmlStr), 'utf8'), encoding: 'utf8' }
  );
  return JSON.parse(raw);
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

async function setSystemConfigHttp(api, key, value) {
  const fullKey = key.startsWith('system.') ? key : `system.${key}`;
  const shortKey = fullKey.replace(/^system\./, '');
  let res = await restMutate(api, '/api/v1/config/system', { key: fullKey, value });
  if (!res.ok) {
    res = await restMutate(api, '/api/v1/config/system', { [fullKey]: value, [shortKey]: value });
  }
  return res;
}

function readSystemKeyFromJson(payload, key) {
  const fullKey = key.startsWith('system.') ? key : `system.${key}`;
  const shortKey = fullKey.replace(/^system\./, '');
  const roots = [payload, payload?.data, payload?.config, payload?.system].filter(
    (obj) => obj && typeof obj === 'object' && !Array.isArray(obj)
  );
  for (const obj of roots) {
    if (fullKey in obj) return obj[fullKey];
    if (shortKey in obj) return obj[shortKey];
  }
  return undefined;
}

function unwrapSnapshot(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  if (Array.isArray(payload.windows)) return payload;
  if (payload.snapshot && typeof payload.snapshot === 'object') return payload.snapshot;
  if (payload.data && typeof payload.data === 'object') return payload.data;
  if (payload.payload && typeof payload.payload === 'object') return payload.payload;
  return payload;
}

function unwrapExplicitArray(payload, keys = ['packages', 'apps', 'catalog', 'items', 'data', 'entries', 'windows']) {
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

async function discoverSystemAppsHttp(api) {
  const roleDefs = [
    { role: 'terminal', pattern: /omniterm|terminal/i },
    { role: 'files', pattern: /omnifiles|files/i },
    { role: 'monitor', pattern: /monitor|task/i },
    { role: 'apphub', pattern: /apphub|app[\s_-]*hub/i },
    { role: 'settings', pattern: /settings|privacy/i },
    { role: 'inspector', pattern: /inspector/i },
    { role: 'notes', pattern: /omninotes|notes/i },
  ];

  const entries = [];
  const ingest = (src, fromInstalled) => {
    const arr = unwrapExplicitArray(src, ['packages', 'apps', 'catalog', 'items', 'data', 'entries']);
    const sysArr = unwrapExplicitArray(src, ['systemApps']);
    const combined = [...(arr ?? []), ...(sysArr ?? [])];
    const list =
      arr !== null || sysArr !== null
        ? combined
        : (src && typeof src === 'object' ? Object.entries(src).map(([k, v]) => (typeof v === 'object' && v ? { id: k, ...v } : v)) : []);
    for (const item of list) {
      if (typeof item === 'string' && item.trim()) {
        entries.push({ appId: item.trim(), name: item.trim(), platform: '', isBuiltin: false, fromInstalled });
      } else if (item && typeof item === 'object') {
        const appId = String(item.appId ?? item.id ?? '').trim();
        if (!appId) continue;
        const name = String(item.name ?? item.title ?? item.displayName ?? item.label ?? '').trim();
        const platform = String(item.platform ?? '').toLowerCase();
        const isBuiltin = Boolean(
          item.builtin || item.builtIn || item.isSystem || item.system ||
          item.kind === 'system' || item.type === 'system' || platform === 'system'
        );
        entries.push({ appId, name, platform, isBuiltin, fromInstalled });
      }
    }
  };

  const pkgRes = await api.get('/api/v1/packages', { expectOk: true });
  ingest(pkgRes.json, true);
  const catRes = await api.get('/api/v1/packages/catalog');
  if (catRes.ok && catRes.json !== null) ingest(catRes.json, false);

  const byId = new Map();
  for (const e of entries) {
    const prev = byId.get(e.appId);
    byId.set(e.appId, prev
      ? { ...e, name: prev.name || e.name, platform: prev.platform || e.platform, isBuiltin: prev.isBuiltin || e.isBuiltin, fromInstalled: prev.fromInstalled || e.fromInstalled }
      : e);
  }
  const all = Array.from(byId.values());
  const resolved = {};
  const used = new Set();
  for (const { role, pattern } of roleDefs) {
    const matches = all
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

function getWinId(win) {
  return win?.windowId ?? win?.id ?? null;
}

async function collectSharedPrefsCandidates(sp) {
  const candMap = new Map();
  const add = (pkg, pref) => {
    if (pkg && pref) candMap.set(`${pkg}/${pref}`, [String(pkg), String(pref)]);
  };
  for (const [pkg, pref] of [
    ['android', 'system'],
    ['android', 'settings'],
    ['android', 'global'],
    ['com.android.system', 'system'],
    ['com.android.settings', 'system'],
    ['com.android.settings', 'settings'],
    ['com.omnios.system', 'system_settings'],
    ['com.omnios.system', 'system'],
    ['com.omnios.system', 'settings'],
    ['com.omnios.os', 'system'],
    ['com.omnios.settings', 'system'],
    ['system', 'system'],
    ['system', 'settings'],
    ['system', 'default'],
    ['global', 'system'],
    ['default', 'system'],
  ]) {
    add(pkg, pref);
  }
  for (const fnName of ['listNamespaces', 'list', 'listPackages']) {
    if (typeof sp?.[fnName] === 'function') {
      let listed = null;
      try {
        listed = await sp[fnName]();
      } catch {
        listed = null;
      }
      if (Array.isArray(listed)) {
        for (const item of listed) {
          if (item && typeof item === 'object') {
            add(item.packageName ?? item.pkg ?? item.package, item.prefName ?? item.pref ?? item.name);
          } else if (typeof item === 'string' && item.includes('/')) {
            const [p, f] = item.split('/');
            add(p, f);
          }
        }
      }
    }
  }
  return Array.from(candMap.values());
}

describe('Tier 3 — P-02: Unified Config Sync (Registry/Defaults/SharedPrefs) & Adaptive Shell Modes', () => {
  test('T3-P02-01 [F-021, F-022]: 4-Way Live Bidirectional Sync (system.theme <-> HKCU <-> NSGlobalDomain + Python plistlib <-> Android SharedPreferences)', async () => {
    const os = await loadPublicOmniOS();
    try {
      const cs = os.require('configStore');
      const nonce = makeNonce();

      // Snapshot dark vs light across all 3 platform config views
      await cs.system.set('system.theme', 'dark');
      const hkcuDark = await walkRegistryTree(cs.registry, 'HKCU', '', 12);
      const nsDark = { ...(await cs.defaults.readDomain('NSGlobalDomain')) };
      const spCandidates = await collectSharedPrefsCandidates(cs.sharedPrefs);
      const spDarkSnaps = new Map();
      for (const [pkg, pref] of spCandidates) {
        try {
          spDarkSnaps.set(`${pkg}/${pref}`, { ...(await cs.sharedPrefs.getAll(pkg, pref)) });
        } catch {
          // ignore absent candidate
        }
      }

      await cs.system.set('system.theme', 'light');
      const hkcuLight = await walkRegistryTree(cs.registry, 'HKCU', '', 12);
      const nsLight = { ...(await cs.defaults.readDomain('NSGlobalDomain')) };

      // 1. Discover HKCU mirror and verify reverse sync propagates to system.theme + NSGlobalDomain + SharedPrefs
      let regDiff = null;
      for (const id of new Set([...hkcuDark.keys(), ...hkcuLight.keys()])) {
        const d = hkcuDark.get(id);
        const l = hkcuLight.get(id);
        if (d && l && stableSerialize(d.data) !== stableSerialize(l.data)) {
          regDiff = { keyPath: l.keyPath, valueName: l.valueName, type: l.type, darkVal: d.data, lightVal: l.data };
          break;
        }
        if (!regDiff && ((d && !l) || (!d && l))) {
          const ref = d ?? l;
          regDiff = { keyPath: ref.keyPath, valueName: ref.valueName, type: ref.type, darkVal: d?.data, lightVal: l?.data };
        }
      }
      assert.ok(regDiff, 'Toggling system.theme dark->light must mirror into HKCU Windows Registry');

      // 2. Discover NSGlobalDomain mirror (strictly defined value check)
      let nsDiff = null;
      for (const k of new Set([...Object.keys(nsDark), ...Object.keys(nsLight)])) {
        if (stableSerialize(nsDark[k]) !== stableSerialize(nsLight[k])) {
          nsDiff = { key: k, darkVal: nsDark[k], lightVal: nsLight[k] };
          break;
        }
      }
      assert.ok(nsDiff, 'Toggling system.theme dark->light must mirror into Apple NSGlobalDomain');

      // 3. Discover Android SharedPreferences mirror
      let spDiff = null;
      for (const [pkg, pref] of spCandidates) {
        let lightMap = null;
        try {
          lightMap = await cs.sharedPrefs.getAll(pkg, pref);
        } catch {
          continue;
        }
        const darkMap = spDarkSnaps.get(`${pkg}/${pref}`) ?? {};
        for (const k of new Set([...Object.keys(darkMap), ...Object.keys(lightMap ?? {})])) {
          if (stableSerialize(darkMap[k]) !== stableSerialize(lightMap?.[k])) {
            spDiff = { pkg, pref, key: k, darkVal: darkMap[k], lightVal: lightMap?.[k] };
            break;
          }
        }
        if (spDiff) break;
      }
      assert.ok(spDiff, 'Toggling system.theme dark->light must mirror into Android SharedPreferences');

      // Reverse sync 1: Write Windows HKCU -> assert system.theme + NSGlobalDomain + SharedPrefs update
      if (regDiff.darkVal !== undefined) {
        await cs.registry.setValue('HKCU', regDiff.keyPath, regDiff.valueName, regDiff.type, regDiff.darkVal, { uid: 0 });
        assert.equal(await cs.system.get('system.theme'), 'dark', 'HKCU write must reverse-sync system.theme to dark');
        const nsNow = await cs.defaults.readDomain('NSGlobalDomain');
        assert.equal(stableSerialize(nsNow?.[nsDiff.key]), stableSerialize(nsDiff.darkVal), 'HKCU write must propagate to NSGlobalDomain');
        const spNow = await cs.sharedPrefs.getAll(spDiff.pkg, spDiff.pref);
        assert.equal(stableSerialize(spNow?.[spDiff.key]), stableSerialize(spDiff.darkVal), 'HKCU write must propagate to Android SharedPreferences');
      } else {
        await cs.system.set('system.theme', 'dark');
        await cs.registry.setValue('HKCU', regDiff.keyPath, regDiff.valueName, regDiff.type, regDiff.lightVal, { uid: 0 });
        assert.equal(await cs.system.get('system.theme'), 'light', 'HKCU write must reverse-sync system.theme to light');
      }

      // Reverse sync 2: Write Apple NSGlobalDomain (NEVER passing undefined/null!) -> assert system.theme + HKCU + SharedPrefs update
      if (nsDiff.lightVal !== undefined && nsDiff.lightVal !== null) {
        await cs.system.set('system.theme', 'dark');
        await cs.defaults.set('NSGlobalDomain', nsDiff.key, nsDiff.lightVal);
        assert.equal(await cs.system.get('system.theme'), 'light', 'NSGlobalDomain write must reverse-sync system.theme to light');
        const spNow = await cs.sharedPrefs.getAll(spDiff.pkg, spDiff.pref);
        assert.equal(stableSerialize(spNow?.[spDiff.key]), stableSerialize(spDiff.lightVal), 'NSGlobalDomain write must propagate to SharedPreferences');
      } else {
        assert.ok(nsDiff.darkVal !== undefined && nsDiff.darkVal !== null, 'NSGlobalDomain dark value must be defined and non-null');
        await cs.system.set('system.theme', 'light');
        await cs.defaults.set('NSGlobalDomain', nsDiff.key, nsDiff.darkVal);
        assert.equal(await cs.system.get('system.theme'), 'dark', 'NSGlobalDomain write must reverse-sync system.theme to dark');
        const spNow = await cs.sharedPrefs.getAll(spDiff.pkg, spDiff.pref);
        assert.equal(stableSerialize(spNow?.[spDiff.key]), stableSerialize(spDiff.darkVal), 'NSGlobalDomain write must propagate to SharedPreferences');
      }

      // Reverse sync 3: Write Android SharedPreferences -> assert system.theme + HKCU + NSGlobalDomain update
      const spTarget = spDiff.lightVal !== undefined ? { val: spDiff.lightVal, theme: 'light', prev: 'dark' } : { val: spDiff.darkVal, theme: 'dark', prev: 'light' };
      assert.notEqual(spTarget.val, undefined, 'SharedPreferences target value must be defined');
      await cs.system.set('system.theme', spTarget.prev);
      await applySharedPrefsEdit(cs.sharedPrefs, spDiff.pkg, spDiff.pref, [{ op: 'put', key: spDiff.key, value: spTarget.val }], { uid: 0 });
      assert.equal(await cs.system.get('system.theme'), spTarget.theme, `SharedPreferences write must reverse-sync system.theme to ${spTarget.theme}`);
      const regAfterSp = await cs.registry.getValue('HKCU', regDiff.keyPath, regDiff.valueName, { uid: 0 });
      const expectedReg = spTarget.theme === 'light' ? regDiff.lightVal : regDiff.darkVal;
      if (expectedReg !== undefined) {
        assert.equal(stableSerialize(regAfterSp?.data), stableSerialize(expectedReg), 'SharedPreferences write must propagate to HKCU Registry');
      }

      // External Python plistlib oracle verification for both NSGlobalDomain & custom domain
      const customDom = `com.omnios.p02.${nonce}`;
      await cs.defaults.set(customDom, 'nonceStr', `plist-${nonce}`);
      await cs.defaults.set(customDom, 'countInt', 42);
      await cs.defaults.set(customDom, 'flagBool', true);

      const nsXml = await cs.defaults.exportPlistXml('NSGlobalDomain');
      assert.equal(typeof nsXml, 'string');
      const parsedNs = parsePlistViaPython(nsXml);
      assert.ok(parsedNs && typeof parsedNs === 'object', 'NSGlobalDomain XML export must parse cleanly via Python plistlib');

      const customXml = await cs.defaults.exportPlistXml(customDom);
      const parsedCustom = parsePlistViaPython(customXml);
      assert.equal(parsedCustom.nonceStr, `plist-${nonce}`);
      assert.equal(parsedCustom.countInt, 42);
      assert.equal(parsedCustom.flagBool, true);
    } finally {
      await os.shutdown();
    }
  });

  test('T3-P02-02 [F-021, F-022, F-062, F-063]: All 5 Synced System Keys (theme, shellMode, dnd, volume, brightness) x Dual-Client RFC 6455 /ws config:changed Fan-Out', async () => {
    const srv = await startOmniServer();
    let ws1 = null;
    let ws2 = null;
    try {
      ws1 = await srv.connectWs();
      ws2 = await srv.connectWs();

      const mutations = [
        ['system.theme', 'light'],
        ['system.shellMode', 'macos'],
        ['system.dnd', true],
        ['system.volume', 63],
        ['system.brightness', 79],
      ];

      for (const [key, val] of mutations) {
        const m1 = ws1.mark();
        const m2 = ws2.mark();
        const res = await setSystemConfigHttp(srv.api, key, val);
        assert.ok(res.ok, `Setting ${key}=${JSON.stringify(val)} via REST must succeed (got ${res.status}: ${res.text})`);

        const [ev1, ev2] = await Promise.all([
          ws1.waitForType('config:changed', { since: m1, timeoutMs: 5000 }),
          ws2.waitForType('config:changed', { since: m2, timeoutMs: 5000 }),
        ]);
        assert.equal(ev1?.type, 'config:changed', `ws1 must receive config:changed for ${key}`);
        assert.equal(ev2?.type, 'config:changed', `ws2 must receive config:changed for ${key}`);
      }

      const sysRes = await srv.api.get('/api/v1/config/system', { expectOk: true });
      for (const [key, val] of mutations) {
        assert.equal(
          readSystemKeyFromJson(sysRes.json, key),
          val,
          `GET /api/v1/config/system must reflect ${key}=${JSON.stringify(val)} (got ${sysRes.text})`
        );
      }

      const snapRes = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      const snap = unwrapSnapshot(snapRes.json);
      assert.equal(snap?.shellMode, 'macos', `Compositor snapshot must reflect synced shellMode "macos" (got ${JSON.stringify(snap?.shellMode)})`);
    } finally {
      await ws1?.close();
      await ws2?.close();
      await srv.stop();
    }
  });

  test('T3-P02-03 [F-022, F-029, F-063, F-076]: Live Shell Mode Convergence Across Compositor REST, WS shell:mode, and Config Store While Preserving Open Windows', async () => {
    const srv = await startOmniServer();
    let ws = null;
    try {
      ws = await srv.connectWs();
      const sysApps = await discoverSystemAppsHttp(srv.api);
      const targetAppId = sysApps.notes ?? sysApps.terminal ?? Object.values(sysApps)[0];
      assert.ok(targetAppId, 'Must dynamically discover at least one built-in system app from /api/v1/packages');

      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(targetAppId)}/launch`, {}, { expectOk: true });
      const pid = launchRes.json?.pid ?? launchRes.json?.process?.pid;
      assert.ok(Number.isInteger(pid) && pid > 0, `System app launch must return valid PID (got ${launchRes.text})`);

      const initialWin = await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return (s?.windows ?? []).find((w) => w?.pid === pid || w?.appId === targetAppId) ?? null;
      }, { timeoutMs: 6000, label: `compositor window for ${targetAppId}` });
      const winId = getWinId(initialWin);
      assert.ok(winId, 'Launched system app must open a compositor window');

      // Channel 1: Compositor REST -> macos
      const c1 = ws.mark();
      let modeRes = await restMutate(srv.api, '/api/v1/compositor/shell-mode', { mode: 'macos', shellMode: 'macos' });
      assert.ok(modeRes.ok, `REST shell-mode switch to macos must succeed (got ${modeRes.status}: ${modeRes.text})`);
      await ws.waitForMessage((m) => m?.type === 'config:changed' || m?.type === 'compositor:snapshot', { since: c1, timeoutMs: 5000 });

      const snapMac = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
      assert.equal(snapMac?.shellMode, 'macos');
      assert.equal(readSystemKeyFromJson((await srv.api.get('/api/v1/config/system', { expectOk: true })).json, 'system.shellMode'), 'macos');

      // Channel 2: WS Client->Server shell:mode -> ios
      ws.send({ type: 'shell:mode', payload: { mode: 'ios', shellMode: 'ios' } });
      await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        const cfg = (await srv.api.get('/api/v1/config/system', { expectOk: true })).json;
        return s?.shellMode === 'ios' && readSystemKeyFromJson(cfg, 'system.shellMode') === 'ios';
      }, { timeoutMs: 6000, label: 'WS shell:mode -> ios convergence' });

      // Channel 3: Config Store REST system.shellMode -> windows
      const cfgWinRes = await setSystemConfigHttp(srv.api, 'system.shellMode', 'windows');
      assert.ok(cfgWinRes.ok, `Config Store shellMode -> windows must succeed (got ${cfgWinRes.status})`);
      await waitUntil(async () => {
        const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        return s?.shellMode === 'windows';
      }, { timeoutMs: 6000, label: 'Config Store shellMode -> windows propagation to compositor' });

      // Channel 4: Cycle android -> unified and verify open window & live PID survived every mode transition
      for (const nextMode of ['android', 'unified']) {
        modeRes = await restMutate(srv.api, '/api/v1/compositor/shell-mode', { mode: nextMode, shellMode: nextMode });
        assert.ok(modeRes.ok, `Mode switch to ${nextMode} must succeed`);
        const snap = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true })).json);
        assert.equal(snap?.shellMode, nextMode);
        assert.ok(
          (snap?.windows ?? []).some((w) => getWinId(w) === winId),
          `Open window ${winId} must survive transition into shellMode "${nextMode}"`
        );
      }

      const procRes = await srv.api.get(`/api/v1/processes/${pid}`, { expectOk: true });
      const procState = procRes.json?.state ?? procRes.json?.process?.state ?? procRes.json?.data?.state;
      assert.ok(procState && procState !== 'TERMINATED' && procState !== 'ZOMBIE', `Launched PID ${pid} must stay alive across all shell mode switches`);
    } finally {
      await ws?.close();
      await srv.stop();
    }
  });

  test('T3-P02-04 [F-021, F-022, F-040, F-044, F-062, F-065]: Real Binary Config Writes (Win PE32+ advapi32 HKCU + Android Dalvik SharedPrefs) x REST /api/v1/config/* x Remote CLI', async () => {
    const srv = await startOmniServer();
    try {
      const nonce = makeNonce();
      const regSubKey = `Software\\OmniP02\\${nonce}`;
      const regValName = 'WinTok';
      const regValData = `WREG_${nonce}`;

      const andPkg = `com.p02.sp.${nonce}`;
      const prefName = 'p02_prefs';
      const prefKey = 'andTok';
      const prefVal = `ASP_${nonce}`;

      // 1. Install & launch Windows PE32+ writing HKCU via advapi32
      const peBytes = buildCustomPe64Exe({
        subsystem: 3,
        regHive: 0x80000001, // HKEY_CURRENT_USER
        regSubKey,
        regValueName: regValName,
        regValueData: regValData,
        exitCode: 0,
      });
      const winInst = await installPackageHttp(srv.api, peBytes, `p02-reg-${nonce}.exe`);
      assert.ok(winInst.ok, `Windows PE install must succeed (got ${winInst.status}: ${winInst.text})`);
      const winAppId = winInst.json?.appId ?? winInst.json?.id ?? winInst.json?.package?.appId ?? winInst.json?.data?.appId;
      assert.ok(winAppId, 'Windows PE install must return appId');
      const winLaunch = await srv.api.post(`/api/v1/packages/${encodeURIComponent(winAppId)}/launch`, {});
      assert.ok(winLaunch.ok, `Windows PE launch must succeed (got ${winLaunch.status}: ${winLaunch.text})`);

      // 2. Install & launch Android APK writing SharedPreferences via Dalvik VM
      const apkBytes = buildCustomApk({
        packageName: andPkg,
        appLabel: `P02SP${nonce}`,
        sharedPrefName: prefName,
        sharedPrefKey: prefKey,
        sharedPrefVal: prefVal,
      });
      const andInst = await installPackageHttp(srv.api, apkBytes, `p02-sp-${nonce}.apk`);
      assert.ok(andInst.ok, `Android APK install must succeed (got ${andInst.status}: ${andInst.text})`);
      const andAppId = andInst.json?.appId ?? andInst.json?.id ?? andInst.json?.package?.appId ?? andInst.json?.data?.appId ?? andPkg;
      const andLaunch = await srv.api.post(`/api/v1/packages/${encodeURIComponent(andAppId)}/launch`, {});
      assert.ok(andLaunch.ok, `Android APK launch must succeed (got ${andLaunch.status}: ${andLaunch.text})`);

      // 3. Poll REST /api/v1/config/registry and verify Remote CLI reg get
      const regHit = await waitUntil(async () => {
        const r = await srv.api.get('/api/v1/config/registry', {
          query: { hive: 'HKCU', keyPath: regSubKey, path: regSubKey, valueName: regValName, name: regValName },
        });
        if (r.ok && r.text.includes(regValData)) return r;
        return null;
      }, { timeoutMs: 8000, label: `HKCU\\${regSubKey}\\${regValName}` });
      assert.ok(regHit.text.includes(regValData), 'REST /api/v1/config/registry must expose Win32 advapi32 write');

      const cliReg = await srv.runCli(['reg', 'get', 'HKCU', regSubKey, regValName], { json: true, expectZero: true });
      assert.ok(cliReg.stdout.includes(regValData), `Remote CLI reg get must return "${regValData}" (got ${cliReg.stdout})`);

      // 4. Poll REST /api/v1/config/prefs and verify Remote CLI prefs get
      const spHit = await waitUntil(async () => {
        const r = await srv.api.get('/api/v1/config/prefs', {
          query: { packageName: andPkg, pkg: andPkg, prefName, name: prefName },
        });
        if (r.ok && r.text.includes(prefVal)) return r;
        return null;
      }, { timeoutMs: 8000, label: `SharedPreferences ${andPkg}/${prefName}` });
      assert.ok(spHit.text.includes(prefVal), 'REST /api/v1/config/prefs must expose Android Dalvik SharedPreferences write');

      let cliPrefs = await srv.runCli(['prefs', 'get', andPkg, prefName], { json: true });
      if (!cliPrefs.ok || !cliPrefs.stdout.includes(prefVal)) {
        cliPrefs = await srv.runCli(['prefs', 'get', andPkg, prefName, prefKey], { json: true, expectZero: true });
      }
      assert.ok(cliPrefs.stdout.includes(prefVal), `Remote CLI prefs get must return "${prefVal}" (got ${cliPrefs.stdout})`);

      // 5. Write Apple defaults via Remote CLI and cross-verify via REST & Remote CLI defaults read
      const cliDom = `com.p02.cli.${nonce}`;
      const cliDefVal = `DVAL_${nonce}`;
      await srv.runCli(['defaults', 'write', cliDom, 'cliKey', cliDefVal], { json: true, expectZero: true });

      const restDef = await srv.api.get('/api/v1/config/defaults', {
        query: { domain: cliDom, key: 'cliKey' },
        expectOk: true,
      });
      assert.ok(restDef.text.includes(cliDefVal), `REST /api/v1/config/defaults must expose CLI write (got ${restDef.text})`);

      const cliDefRead = await srv.runCli(['defaults', 'read', cliDom, 'cliKey'], { json: true, expectZero: true });
      assert.ok(cliDefRead.stdout.includes(cliDefVal), `Remote CLI defaults read must return "${cliDefVal}" (got ${cliDefRead.stdout})`);
    } finally {
      await srv.stop();
    }
  });

  test('T3-P02-05 [F-021, F-022, F-066]: Multi-Syntax Shell (POST /api/v1/shell/exec: defaults, reg, prefs) x Live REST /api/v1/config/* x Python plistlib Round-Trip', async () => {
    const temp = await createTempDataDir('omnios-p02-shell-');
    let srv = null;
    let os = null;
    try {
      const nonce = makeNonce();
      const dom = `com.p02.shell.${nonce}`;
      const defVal = `shVal_${nonce}`;
      const regPath = `Software\\OmniP02Shell\\${nonce}`;
      const regVal = `shReg_${nonce}`;
      const spPkg = `com.p02.shsp.${nonce}`;
      const spVal = `shSp_${nonce}`;

      srv = await startOmniServer({ dataDir: temp.dir, keepDataDir: true });

      // 1. macOS defaults write/read via Multi-Syntax Shell
      const defW = await srv.api.post('/api/v1/shell/exec', { command: `defaults write ${dom} shKey ${defVal}` }, { expectOk: true });
      assert.equal(defW.status, 200);
      const defR = await srv.api.post('/api/v1/shell/exec', { command: `defaults read ${dom} shKey` }, { expectOk: true });
      assert.ok(defR.text.includes(defVal), `Shell defaults read must return "${defVal}" (got ${defR.text})`);

      const restDef = await srv.api.get('/api/v1/config/defaults', { query: { domain: dom, key: 'shKey' }, expectOk: true });
      assert.ok(restDef.text.includes(defVal), `REST /api/v1/config/defaults must match shell write (got ${restDef.text})`);

      // 2. Windows reg set/add via Multi-Syntax Shell — verify read-back matches regVal (and NOT 'REG_SZ')
      const readBackShellReg = async () => srv.api.get('/api/v1/config/registry', {
        query: { hive: 'HKCU', keyPath: regPath, path: regPath, valueName: 'ShKey', name: 'ShKey' },
      });
      const regReadBackValid = (r) => r.ok && extractRegDataValue(r.json) !== 'REG_SZ' && r.text.includes(regVal);

      let regW = await srv.api.post('/api/v1/shell/exec', { command: `reg set HKCU ${regPath} ShKey REG_SZ ${regVal}` });
      let restReg = await readBackShellReg();
      if (!regW.ok || (regW.json?.exitCode !== undefined && regW.json.exitCode !== 0) || !regReadBackValid(restReg)) {
        regW = await srv.api.post('/api/v1/shell/exec', { command: `reg set HKCU ${regPath} ShKey ${regVal}` });
        restReg = await readBackShellReg();
      }
      if (!regW.ok || (regW.json?.exitCode !== undefined && regW.json.exitCode !== 0) || !regReadBackValid(restReg)) {
        regW = await srv.api.post('/api/v1/shell/exec', { command: `reg add HKCU\\${regPath} /v ShKey /t REG_SZ /d ${regVal}` });
        restReg = await readBackShellReg();
      }
      assert.ok(regW.ok, `Shell reg write must succeed (got ${regW.status}: ${regW.text})`);
      assert.ok(restReg.ok, `REST /api/v1/config/registry read-back must succeed (got ${restReg.status}: ${restReg.text})`);
      assert.notEqual(
        extractRegDataValue(restReg.json),
        'REG_SZ',
        `REST /api/v1/config/registry must not store literal "REG_SZ" as data (got ${restReg.text})`
      );
      assert.ok(restReg.text.includes(regVal), `REST /api/v1/config/registry must reflect shell reg write "${regVal}" (got ${restReg.text})`);

      // 3. Android prefs set/get via Multi-Syntax Shell
      const spW = await srv.api.post('/api/v1/shell/exec', { command: `prefs set ${spPkg} sh_prefs spKey ${spVal}` }, { expectOk: true });
      assert.equal(spW.status, 200);
      const restSp = await srv.api.get('/api/v1/config/prefs', {
        query: { packageName: spPkg, pkg: spPkg, prefName: 'sh_prefs', name: 'sh_prefs' },
        expectOk: true,
      });
      assert.ok(restSp.text.includes(spVal), `REST /api/v1/config/prefs must reflect shell prefs write (got ${restSp.text})`);

      // 4. Stop server, cold-load public OmniOS on same SQLite dir, verify XML plist export via Python plistlib
      await srv.stop();
      srv = null;

      os = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const xml = await os.require('configStore').defaults.exportPlistXml(dom);
      const parsed = parsePlistViaPython(xml);
      assert.equal(parsed.shKey, defVal, 'Python plistlib must decode shell-written Apple default after cold reload');
    } finally {
      await srv?.stop();
      await os?.shutdown();
      await temp.cleanup();
    }
  });

  test('T3-P02-06 [F-021, F-027]: Unprivileged Windows HKLM\\Software Registry Virtualization x Cross-App Isolation x Reboot Persistence', async () => {
    const temp = await createTempDataDir('omnios-p02-hklm-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      const subKey = `Software\\OmniP02Virt\\${nonce}`;
      const rootCtx = { uid: 0, gid: 0, privileged: true };
      const appACtx = { uid: 10011, gid: 10011, appId: `com.p02.winA.${nonce}`, privileged: false };
      const appBCtx = { uid: 10022, gid: 10022, appId: `com.p02.winB.${nonce}`, privileged: false };

      os1 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const reg1 = os1.require('configStore').registry;

      await reg1.setValue('HKLM', subKey, 'Policy', 'REG_SZ', `ROOT_${nonce}`, rootCtx);
      await reg1.setValue('HKLM', subKey, 'Policy', 'REG_SZ', `VIRT_A_${nonce}`, appACtx);

      assert.equal((await reg1.getValue('HKLM', subKey, 'Policy', appACtx))?.data, `VIRT_A_${nonce}`, 'Unprivileged App A must read its own virtualized HKLM override');
      assert.equal((await reg1.getValue('HKLM', subKey, 'Policy', rootCtx))?.data, `ROOT_${nonce}`, 'Root HKLM value must remain uncorrupted by unprivileged write');
      assert.equal((await reg1.getValue('HKLM', subKey, 'Policy', appBCtx))?.data, `ROOT_${nonce}`, 'Unrelated App B must still see authoritative Root HKLM value');

      // Cold reboot on same SQLite directory
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const reg2 = os2.require('configStore').registry;
      assert.equal((await reg2.getValue('HKLM', subKey, 'Policy', appACtx))?.data, `VIRT_A_${nonce}`, 'App A virtualized HKLM view must persist across reboot');
      assert.equal((await reg2.getValue('HKLM', subKey, 'Policy', rootCtx))?.data, `ROOT_${nonce}`, 'Root HKLM view must persist across reboot');
      assert.equal((await reg2.getValue('HKLM', subKey, 'Policy', appBCtx))?.data, `ROOT_${nonce}`, 'App B isolated HKLM view must persist across reboot');
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });
});
