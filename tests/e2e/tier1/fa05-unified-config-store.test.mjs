/**
 * Tier 1 E2E Tests — FA-05: Unified Config Store (Registry, Apple Defaults & Android SharedPrefs)
 * Features covered: F-021, F-022
 * Contracts: Contract 3 (IUnifiedConfigStore), Contract 7 (REST & WS config:changed), Contract 8 (CLI)
 *
 * Strictly opaque-box: interacts ONLY through public OmniOS entrypoints via ../lib/env.mjs.
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

function makeNonce() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

function decodeRegBinary(data) {
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (Array.isArray(data)) return Buffer.from(data);
  if (typeof data === 'string') {
    const trimmed = data.trim();
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0 && trimmed.length === 10) {
      return Buffer.from(trimmed, 'hex');
    }
    return Buffer.from(trimmed, 'base64');
  }
  if (data && typeof data === 'object' && data.type === 'Buffer' && Array.isArray(data.data)) {
    return Buffer.from(data.data);
  }
  throw new TypeError(`Cannot decode REG_BINARY data of type ${typeof data}: ${JSON.stringify(data)}`);
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

    let enumRes;
    try {
      enumRes = await registry.enumKey(hive, norm, { uid: 0 });
    } catch {
      return;
    }
    if (!enumRes || typeof enumRes !== 'object') return;

    const vals = normalizeRegValues(enumRes.values);
    for (const [valName, valObj] of vals.entries()) {
      const fullId = `${norm}::${valName}`;
      entries.set(fullId, {
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

function stableSerialize(val) {
  if (typeof val === 'bigint') return `${val}n`;
  if (val instanceof Uint8Array) return `bin:${Buffer.from(val).toString('hex')}`;
  try {
    return JSON.stringify(val);
  } catch {
    return String(val);
  }
}

function sharedPrefsOpsApplied(snapshot, ops) {
  if (!snapshot || typeof snapshot !== 'object') {
    return ops.every((o) => o.op === 'remove' || o.action === 'remove');
  }
  for (const op of ops) {
    const kind = op.op ?? op.action ?? op.type;
    if (kind === 'remove' || kind === 'delete') {
      if (op.key in snapshot && snapshot[op.key] !== undefined) return false;
    } else {
      if (!(op.key in snapshot) || stableSerialize(snapshot[op.key]) !== stableSerialize(op.value)) {
        return false;
      }
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
        if (o.op === 'remove' || o.action === 'remove') {
          removeList.push(o.key);
        } else {
          setMap[o.key] = o.value;
        }
      }
      return { set: setMap, remove: removeList };
    })(),
  ];

  let lastErr = null;
  for (const payload of candidates) {
    try {
      const res = await sp.edit(pkg, prefName, payload, ctx);
      const after = await sp.getAll(pkg, prefName, ctx);
      if (sharedPrefsOpsApplied(after, ops)) {
        return res;
      }
    } catch (err) {
      lastErr = err;
    }
  }
  if (lastErr) throw lastErr;
  throw new Error(
    `sharedPrefs.edit(${pkg}, ${prefName}) did not apply expected mutations across supported ops shapes: ${JSON.stringify(ops)}`
  );
}

async function restMutate(api, urlPath, body, { query } = {}) {
  let res = await api.put(urlPath, body, { query });
  if (res.status === 404 || res.status === 405) {
    res = await api.post(urlPath, body, { query });
  }
  if (res.status === 404 || res.status === 405) {
    res = await api.patch(urlPath, body, { query });
  }
  return res;
}

describe('Tier 1 — FA-05: Unified Config Store (Registry, Apple Defaults & Android SharedPrefs)', () => {
  test('T1 [F-021]: Windows Registry — all 5 hives, all 6 value types, enumKey, deleteValue & SQLite persistence', async () => {
    const temp = await createTempDataDir('omnios-fa05-reg-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      const rootCtx = { uid: 0, gid: 0 };
      os1 = await loadPublicOmniOS({ dataDir: temp.dir });
      const reg = os1.require('configStore').registry;

      // All 5 Windows Registry hives
      const hives = ['HKCR', 'HKCU', 'HKLM', 'HKU', 'HKCC'];
      const hiveKey = `Software\\OmniE2E\\${nonce}`;
      for (const hive of hives) {
        const marker = `hive-${hive}-${nonce}`;
        await reg.setValue(hive, hiveKey, 'Marker', 'REG_SZ', marker, rootCtx);
        const got = await reg.getValue(hive, hiveKey, 'Marker', rootCtx);
        assert.ok(got && typeof got === 'object', `Expected value object from hive ${hive}`);
        assert.equal(got.type, 'REG_SZ');
        assert.equal(got.data, marker, `Hive ${hive} round-trip mismatch`);
      }

      // All 6 Registry value types under HKCU
      const typesKey = `Software\\OmniTypes\\${nonce}`;
      const binBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x42]);
      const multiStr = [`one-${nonce}`, `two-${nonce}`, 'three'];
      const qwordVal = 0x0011223344556677; // within Number.MAX_SAFE_INTEGER and > 32-bit

      await reg.setValue('HKCU', typesKey, 'SzVal', 'REG_SZ', `sz-${nonce}`, rootCtx);
      await reg.setValue('HKCU', typesKey, 'ExpandVal', 'REG_EXPAND_SZ', `%HOME%\\docs\\${nonce}`, rootCtx);
      await reg.setValue('HKCU', typesKey, 'BinVal', 'REG_BINARY', binBytes, rootCtx);
      await reg.setValue('HKCU', typesKey, 'DwordVal', 'REG_DWORD', 0x12345678, rootCtx);
      await reg.setValue('HKCU', typesKey, 'MultiVal', 'REG_MULTI_SZ', multiStr, rootCtx);
      await reg.setValue('HKCU', typesKey, 'QwordVal', 'REG_QWORD', qwordVal, rootCtx);

      assert.equal((await reg.getValue('HKCU', typesKey, 'SzVal', rootCtx))?.data, `sz-${nonce}`);
      assert.equal((await reg.getValue('HKCU', typesKey, 'ExpandVal', rootCtx))?.data, `%HOME%\\docs\\${nonce}`);
      assert.equal((await reg.getValue('HKCU', typesKey, 'DwordVal', rootCtx))?.data, 0x12345678);
      assert.deepEqual((await reg.getValue('HKCU', typesKey, 'MultiVal', rootCtx))?.data, multiStr);
      assert.ok(
        decodeRegBinary((await reg.getValue('HKCU', typesKey, 'BinVal', rootCtx))?.data).equals(Buffer.from(binBytes)),
        'REG_BINARY must round-trip exact 5 bytes'
      );
      const qGot = await reg.getValue('HKCU', typesKey, 'QwordVal', rootCtx);
      assert.equal(qGot?.type, 'REG_QWORD');
      assert.equal(BigInt(qGot?.data), 0x0011223344556677n, 'REG_QWORD must preserve full 64-bit integer value');

      // enumKey: subkeys + values
      await reg.setValue('HKCU', `${typesKey}\\SubA`, 'ChildVal', 'REG_SZ', 'ok', rootCtx);
      const listed = await reg.enumKey('HKCU', typesKey, rootCtx);
      assert.ok(Array.isArray(listed?.subkeys), 'enumKey() must return subkeys array');
      assert.ok(
        listed.subkeys.some((sk) => String(sk).endsWith('SubA')),
        `enumKey() subkeys must contain "SubA", got ${JSON.stringify(listed.subkeys)}`
      );
      const valMap = normalizeRegValues(listed?.values);
      for (const vn of ['SzVal', 'ExpandVal', 'BinVal', 'DwordVal', 'MultiVal', 'QwordVal']) {
        assert.ok(valMap.has(vn), `enumKey() values must include "${vn}"`);
      }

      // deleteValue
      await reg.deleteValue('HKCU', typesKey, 'SzVal', rootCtx);
      assert.equal((await reg.getValue('HKCU', typesKey, 'SzVal', rootCtx)) ?? null, null, 'Deleted registry value must return null');
      assert.equal((await reg.getValue('HKCU', typesKey, 'DwordVal', rootCtx))?.data, 0x12345678, 'Sibling value must remain intact');

      // SQLite persistence across reboot
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      const reg2 = os2.require('configStore').registry;
      assert.equal((await reg2.getValue('HKCU', typesKey, 'DwordVal', rootCtx))?.data, 0x12345678);
      assert.ok(decodeRegBinary((await reg2.getValue('HKCU', typesKey, 'BinVal', rootCtx))?.data).equals(Buffer.from(binBytes)));
      assert.deepEqual((await reg2.getValue('HKCU', typesKey, 'MultiVal', rootCtx))?.data, multiStr);
      assert.equal(BigInt((await reg2.getValue('HKCU', typesKey, 'QwordVal', rootCtx))?.data), 0x0011223344556677n);
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });

  test('T2 [F-022]: Apple NSUserDefaults domains, types, XML 1.0 plist export (python3 plistlib oracle) & persistence', async () => {
    const temp = await createTempDataDir('omnios-fa05-def-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      const dom = `com.omnios.e2e.${nonce}`;

      os1 = await loadPublicOmniOS({ dataDir: temp.dir });
      const defaults = os1.require('configStore').defaults;

      await defaults.set(dom, 'strKey', `s-${nonce}`);
      await defaults.set(dom, 'intKey', 42);
      await defaults.set(dom, 'boolKey', true);
      await defaults.set(dom, 'arrKey', ['a', nonce]);
      await defaults.set(dom, 'dictKey', { inner: `in-${nonce}`, n: 7 });

      assert.equal(await defaults.get(dom, 'strKey'), `s-${nonce}`);
      assert.equal(await defaults.get(dom, 'intKey'), 42);
      assert.equal(await defaults.get(dom, 'boolKey'), true);
      assert.deepEqual(await defaults.get(dom, 'arrKey'), ['a', nonce]);
      assert.deepEqual(await defaults.get(dom, 'dictKey'), { inner: `in-${nonce}`, n: 7 });

      const allDom = await defaults.readDomain(dom);
      assert.equal(allDom?.strKey, `s-${nonce}`);
      assert.equal(allDom?.intKey, 42);
      assert.equal(allDom?.boolKey, true);

      // NSGlobalDomain support
      const globalKey = `E2EGlobal_${nonce}`;
      await defaults.set('NSGlobalDomain', globalKey, `g-${nonce}`);
      assert.equal(await defaults.get('NSGlobalDomain', globalKey), `g-${nonce}`);

      // XML 1.0 plist export verified by independent Python 3 plistlib oracle
      const xml = await defaults.exportPlistXml(dom);
      assert.equal(typeof xml, 'string', 'exportPlistXml() must return a string');
      assert.ok(xml.includes('<plist') && xml.includes(nonce), 'Exported XML plist must contain <plist> and domain values');

      const parsedJson = execFileSync(
        'python3',
        ['-c', 'import sys, plistlib, json; print(json.dumps(plistlib.loads(sys.stdin.buffer.read())))'],
        { input: Buffer.from(xml, 'utf8'), encoding: 'utf8' }
      );
      const parsed = JSON.parse(parsedJson);
      assert.equal(parsed.strKey, `s-${nonce}`);
      assert.equal(parsed.intKey, 42);
      assert.equal(parsed.boolKey, true);
      assert.deepEqual(parsed.arrKey, ['a', nonce]);
      assert.deepEqual(parsed.dictKey, { inner: `in-${nonce}`, n: 7 });

      // SQLite persistence across reboot
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      const defaults2 = os2.require('configStore').defaults;
      assert.equal(await defaults2.get(dom, 'strKey'), `s-${nonce}`);
      assert.deepEqual(await defaults2.get(dom, 'dictKey'), { inner: `in-${nonce}`, n: 7 });
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });

  test('T3 [F-022]: Android SharedPreferences atomic edit/getAll, key removal, namespace isolation & persistence', async () => {
    const temp = await createTempDataDir('omnios-fa05-sp-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      const pkg = `com.omnios.sp.${nonce.replace(/-/g, '_')}`;

      os1 = await loadPublicOmniOS({ dataDir: temp.dir });
      const sp = os1.require('configStore').sharedPrefs;

      await applySharedPrefsEdit(sp, pkg, 'user_prefs', [
        { op: 'put', key: 'strKey', value: `sp-${nonce}` },
        { op: 'put', key: 'intKey', value: 99 },
        { op: 'put', key: 'boolKey', value: true },
        { op: 'put', key: 'dropKey', value: 'temp' },
      ]);

      const firstAll = await sp.getAll(pkg, 'user_prefs');
      assert.equal(firstAll?.strKey, `sp-${nonce}`);
      assert.equal(firstAll?.intKey, 99);
      assert.equal(firstAll?.boolKey, true);
      assert.equal(firstAll?.dropKey, 'temp');

      // Second atomic transaction removing dropKey & adding keepKey
      await applySharedPrefsEdit(sp, pkg, 'user_prefs', [
        { op: 'remove', key: 'dropKey' },
        { op: 'put', key: 'keepKey', value: `kept-${nonce}` },
      ]);

      const secondAll = await sp.getAll(pkg, 'user_prefs');
      assert.equal('dropKey' in secondAll, false, 'Removed key must no longer exist in SharedPreferences');
      assert.equal(secondAll?.strKey, `sp-${nonce}`);
      assert.equal(secondAll?.intKey, 99);
      assert.equal(secondAll?.boolKey, true);
      assert.equal(secondAll?.keepKey, `kept-${nonce}`);

      // Namespace isolation between different pref files in same package
      const otherAll = await sp.getAll(pkg, 'other_prefs');
      assert.equal(otherAll?.strKey, undefined, 'Different SharedPreferences prefName must be isolated');

      // SQLite persistence across reboot
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      const persisted = await os2.require('configStore').sharedPrefs.getAll(pkg, 'user_prefs');
      assert.equal(persisted?.strKey, `sp-${nonce}`);
      assert.equal(persisted?.keepKey, `kept-${nonce}`);
      assert.equal('dropKey' in persisted, false);
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });

  test('T4 [F-022]: Live cross-platform sync across all 8 system.* keys (Registry + Defaults + SharedPrefs + EventBus)', async () => {
    const os = await loadPublicOmniOS();
    const bus =
      os.raw.eventBus ??
      os.kernel?.eventBus ??
      os.raw.events ??
      os.kernel?.events ??
      os.raw.bus ??
      os.kernel?.bus;
    let unsub = null;
    try {
      const cs = os.require('configStore');
      assert.ok(bus && typeof bus === 'object', 'Public OmniOS runtime must expose KernelEventBus for live config:changed events');
      const configEvents = [];
      const handler = (ev) => configEvents.push(ev);
      if (typeof bus.on === 'function') {
        const ret = bus.on('config:changed', handler);
        unsub = typeof ret === 'function' ? ret : () => bus.off?.('config:changed', handler);
      } else if (typeof bus.subscribe === 'function') {
        unsub = bus.subscribe('config:changed', handler);
      } else {
        throw new Error('KernelEventBus must expose on() or subscribe()');
      }

      // Exercise all 8 documented synced system.* keys
      const targetSystemValues = {
        'system.theme': 'dark',
        'system.shellMode': 'macos',
        'system.volume': 67,
        'system.brightness': 82,
        'system.wifi': false,
        'system.bluetooth': true,
        'system.dnd': true,
        'system.locale': 'fr-FR',
      };

      for (const [k, v] of Object.entries(targetSystemValues)) {
        await cs.system.set(k, v);
      }

      const allSys = await cs.system.getAll();
      for (const [k, v] of Object.entries(targetSystemValues)) {
        assert.equal(await cs.system.get(k), v, `configStore.system.get("${k}") mismatch`);
        const shortKey = k.replace(/^system\./, '');
        const fromAll = k in allSys ? allSys[k] : allSys[shortKey];
        assert.equal(fromAll, v, `configStore.system.getAll() mismatch for "${k}"`);
      }

      assert.ok(configEvents.length >= 1, 'Mutating system.* keys must emit live config:changed events on KernelEventBus');

      // Dynamic bidirectional cross-store sync proof (no hardcoded internal subkey guesses)
      await cs.system.set('system.theme', 'dark');
      const hkcuDark = await walkRegistryTree(cs.registry, 'HKCU', '', 12);
      const nsDark = { ...(await cs.defaults.readDomain('NSGlobalDomain')) };

      const spCandidateSet = new Map();
      const addSpCand = (pkg, pref) => {
        if (pkg && pref) spCandidateSet.set(`${pkg}/${pref}`, [String(pkg), String(pref)]);
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
        addSpCand(pkg, pref);
      }
      // Also include any dynamically enumerable SharedPreferences namespaces if exposed
      for (const listFnName of ['listNamespaces', 'list', 'listPackages']) {
        if (typeof cs.sharedPrefs?.[listFnName] === 'function') {
          try {
            const listed = await cs.sharedPrefs[listFnName]();
            if (Array.isArray(listed)) {
              for (const item of listed) {
                if (item && typeof item === 'object') {
                  addSpCand(item.packageName ?? item.pkg ?? item.package, item.prefName ?? item.pref ?? item.name);
                } else if (typeof item === 'string' && item.includes('/')) {
                  const [p, f] = item.split('/');
                  addSpCand(p, f);
                }
              }
            }
          } catch {
            // ignore optional discovery helper failure
          }
        }
      }
      const spCandidates = Array.from(spCandidateSet.values());

      const spDarkSnaps = new Map();
      for (const [pkg, pref] of spCandidates) {
        try {
          spDarkSnaps.set(`${pkg}/${pref}`, { ...(await cs.sharedPrefs.getAll(pkg, pref)) });
        } catch {
          // ignore non-existent candidate
        }
      }

      await cs.system.set('system.theme', 'light');
      const hkcuLight = await walkRegistryTree(cs.registry, 'HKCU', '', 12);
      const nsLight = { ...(await cs.defaults.readDomain('NSGlobalDomain')) };

      // 1. Verify HKCU Registry mirrored system.theme (including appeared/disappeared keys) & reverse-writes back
      let regDiff = null;
      const allRegIds = new Set([...hkcuDark.keys(), ...hkcuLight.keys()]);
      for (const id of allRegIds) {
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
      assert.ok(regDiff, 'Toggling system.theme dark->light must live-sync at least one HKCU Windows Registry value');
      if (regDiff.darkVal !== undefined) {
        await cs.registry.setValue('HKCU', regDiff.keyPath, regDiff.valueName, regDiff.type, regDiff.darkVal, { uid: 0 });
        assert.equal(
          await cs.system.get('system.theme'),
          'dark',
          `Writing Registry ${regDiff.keyPath}\\${regDiff.valueName} must live-sync system.theme back to "dark"`
        );
      } else {
        await cs.system.set('system.theme', 'dark');
        await cs.registry.setValue('HKCU', regDiff.keyPath, regDiff.valueName, regDiff.type, regDiff.lightVal, { uid: 0 });
        assert.equal(
          await cs.system.get('system.theme'),
          'light',
          `Writing Registry ${regDiff.keyPath}\\${regDiff.valueName} must live-sync system.theme back to "light"`
        );
      }

      // 2. Verify NSGlobalDomain Apple Defaults mirrored system.theme & reverse-writes back (never writing undefined!)
      let nsDiff = null;
      const allNsKeys = new Set([...Object.keys(nsDark), ...Object.keys(nsLight)]);
      for (const k of allNsKeys) {
        if (stableSerialize(nsDark[k]) !== stableSerialize(nsLight[k])) {
          nsDiff = { key: k, darkVal: nsDark[k], lightVal: nsLight[k] };
          break;
        }
      }
      assert.ok(nsDiff, 'Toggling system.theme dark->light must live-sync at least one NSGlobalDomain key');
      if (nsDiff.lightVal !== undefined) {
        await cs.system.set('system.theme', 'dark');
        await cs.defaults.set('NSGlobalDomain', nsDiff.key, nsDiff.lightVal);
        assert.equal(
          await cs.system.get('system.theme'),
          'light',
          `Writing NSGlobalDomain.${nsDiff.key} must live-sync system.theme back to "light"`
        );
      } else {
        // Authentic macOS AppleInterfaceStyle deletes the key in light mode; test reverse sync via defined darkVal
        assert.notEqual(nsDiff.darkVal, undefined, `NSGlobalDomain.${nsDiff.key} must have a defined dark value`);
        await cs.system.set('system.theme', 'light');
        await cs.defaults.set('NSGlobalDomain', nsDiff.key, nsDiff.darkVal);
        assert.equal(
          await cs.system.get('system.theme'),
          'dark',
          `Writing NSGlobalDomain.${nsDiff.key} must live-sync system.theme back to "dark"`
        );
      }

      // 3. Non-vacuously verify Android SharedPreferences live sync on system.* (F-022)
      await cs.system.set('system.theme', 'light');
      let spDiff = null;
      for (const [pkg, pref] of spCandidates) {
        let lightMap;
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
      assert.ok(
        spDiff,
        'Toggling system.theme dark->light must live-sync at least one Android SharedPreferences system entry (F-022)'
      );
      if (spDiff.darkVal !== undefined) {
        await cs.system.set('system.theme', 'light');
        await applySharedPrefsEdit(cs.sharedPrefs, spDiff.pkg, spDiff.pref, [
          { op: 'put', key: spDiff.key, value: spDiff.darkVal },
        ]);
        assert.equal(
          await cs.system.get('system.theme'),
          'dark',
          `Writing Android SharedPreferences ${spDiff.pkg}/${spDiff.pref}.${spDiff.key} must live-sync system.theme back to "dark"`
        );
      } else {
        assert.notEqual(spDiff.lightVal, undefined, `SharedPreferences ${spDiff.pkg}/${spDiff.pref}.${spDiff.key} must have a defined light value`);
        await cs.system.set('system.theme', 'dark');
        await applySharedPrefsEdit(cs.sharedPrefs, spDiff.pkg, spDiff.pref, [
          { op: 'put', key: spDiff.key, value: spDiff.lightVal },
        ]);
        assert.equal(
          await cs.system.get('system.theme'),
          'light',
          `Writing Android SharedPreferences ${spDiff.pkg}/${spDiff.pref}.${spDiff.key} must live-sync system.theme back to "light"`
        );
      }
    } finally {
      if (typeof unsub === 'function') unsub();
      await os.shutdown();
    }
  });

  test('T5 [F-021, F-022, Contract 7]: REST /api/v1/config/{system,registry,defaults,prefs} & live WS config:changed', async () => {
    const srv = await startOmniServer();
    let ws = null;
    try {
      const nonce = makeNonce();
      ws = await srv.connectWs();

      const sysGet1 = await srv.api.get('/api/v1/config/system');
      assert.equal(sysGet1.status, 200);
      assert.ok(sysGet1.json && typeof sysGet1.json === 'object');

      const mark = ws.mark();
      let sysMut = await restMutate(srv.api, '/api/v1/config/system', {
        'system.volume': 54,
        'system.theme': 'light',
        volume: 54,
        theme: 'light',
      });
      if (!sysMut.ok && sysMut.status === 400) {
        const r1 = await restMutate(srv.api, '/api/v1/config/system', { key: 'system.volume', value: 54 });
        const r2 = await restMutate(srv.api, '/api/v1/config/system', { key: 'system.theme', value: 'light' });
        sysMut = r1.ok && r2.ok ? r2 : (!r1.ok ? r1 : r2);
      }
      assert.ok(sysMut.ok, `Mutating /api/v1/config/system failed (${sysMut.status}): ${sysMut.text}`);

      const wsEv = await ws.waitForType('config:changed', { since: mark, timeoutMs: 4000 });
      assert.equal(wsEv.type, 'config:changed', 'System config mutation must broadcast WS config:changed');

      const sysGet2 = await srv.api.get('/api/v1/config/system');
      assert.equal(sysGet2.status, 200);
      const sysObj = sysGet2.json?.system ?? sysGet2.json?.config ?? sysGet2.json?.data ?? sysGet2.json;
      assert.ok(sysObj && typeof sysObj === 'object', `GET /api/v1/config/system must return a JSON object: ${sysGet2.text}`);
      const gotVolume = sysObj['system.volume'] ?? sysObj.volume;
      const gotTheme = sysObj['system.theme'] ?? sysObj.theme;
      assert.equal(gotVolume, 54, `Updated system config must report volume === 54, got ${JSON.stringify(sysObj)}`);
      assert.equal(gotTheme, 'light', `Updated system config must report theme === "light", got ${JSON.stringify(sysObj)}`);

      // Registry REST round-trip
      const regPath = `Software\\OmniRest\\${nonce}`;
      const regVal = `rval-${nonce}`;
      const regMut = await restMutate(srv.api, '/api/v1/config/registry', {
        hive: 'HKCU',
        keyPath: regPath,
        valueName: 'Key',
        name: 'Key',
        type: 'REG_SZ',
        data: regVal,
        value: regVal,
      });
      assert.ok(regMut.ok, `Mutating /api/v1/config/registry failed (${regMut.status}): ${regMut.text}`);
      const regRead = await srv.api.get('/api/v1/config/registry', {
        query: { hive: 'HKCU', keyPath: regPath, valueName: 'Key' },
      });
      assert.equal(regRead.status, 200);
      assert.ok(regRead.text.includes(regVal), `GET /api/v1/config/registry must return "${regVal}", got: ${regRead.text}`);

      // Apple Defaults REST round-trip
      const defDom = `com.omnios.rest.${nonce}`;
      const defVal = `dval-${nonce}`;
      const defMut = await restMutate(srv.api, '/api/v1/config/defaults', {
        domain: defDom,
        key: 'Greeting',
        value: defVal,
      });
      assert.ok(defMut.ok, `Mutating /api/v1/config/defaults failed (${defMut.status}): ${defMut.text}`);
      const defRead = await srv.api.get('/api/v1/config/defaults', {
        query: { domain: defDom, key: 'Greeting' },
      });
      assert.equal(defRead.status, 200);
      assert.ok(defRead.text.includes(defVal), `GET /api/v1/config/defaults must return "${defVal}", got: ${defRead.text}`);

      // Android SharedPreferences REST round-trip
      const prefPkg = `com.omnios.rest.${nonce.replace(/-/g, '_')}`;
      const prefVal = `pval-${nonce}`;
      const prefMut = await restMutate(srv.api, '/api/v1/config/prefs', {
        packageName: prefPkg,
        pkg: prefPkg,
        prefName: 'main',
        key: 'Token',
        value: prefVal,
        ops: [{ op: 'put', key: 'Token', value: prefVal }],
      });
      assert.ok(prefMut.ok, `Mutating /api/v1/config/prefs failed (${prefMut.status}): ${prefMut.text}`);
      const prefRead = await srv.api.get('/api/v1/config/prefs', {
        query: { packageName: prefPkg, prefName: 'main' },
      });
      assert.equal(prefRead.status, 200);
      assert.ok(prefRead.text.includes(prefVal), `GET /api/v1/config/prefs must return "${prefVal}", got: ${prefRead.text}`);
    } finally {
      await ws?.close();
      await srv.stop();
    }
  });

  test('T6 [F-021, F-022, Contract 8]: Remote CLI defaults, reg & prefs commands', async () => {
    const srv = await startOmniServer();
    try {
      const nonce = makeNonce();

      // 1. macOS defaults write / read
      const defDom = `com.omnios.cli.${nonce}`;
      const defVal = `def-${nonce}`;
      await srv.runCli(['defaults', 'write', defDom, 'ThemeTag', defVal], { json: true, expectZero: true });
      const defRead = await srv.runCli(['defaults', 'read', defDom, 'ThemeTag'], { json: true, expectZero: true });
      assert.ok(defRead.stdout.includes(defVal), `CLI "defaults read" must return "${defVal}", got: ${defRead.stdout}`);

      // 2. Windows reg set / get / list
      const regVal = `reg-${nonce}`;
      const fullRegPath = `HKCU\\Software\\OmniCli\\${nonce}`;
      const subRegPath = `Software\\OmniCli\\${nonce}`;

      let regSet = await srv.runCli(['reg', 'set', fullRegPath, 'Tag', regVal], { json: true });
      let usedSplitHive = false;
      if (!regSet.ok) {
        regSet = await srv.runCli(['reg', 'set', 'HKCU', subRegPath, 'Tag', 'REG_SZ', regVal], { json: true });
        usedSplitHive = true;
      }
      assert.equal(regSet.ok, true, `CLI "reg set" failed: stdout=${regSet.stdout} stderr=${regSet.stderr}`);

      const regGetArgs = usedSplitHive
        ? ['reg', 'get', 'HKCU', subRegPath, 'Tag']
        : ['reg', 'get', fullRegPath, 'Tag'];
      const regGet = await srv.runCli(regGetArgs, { json: true, expectZero: true });
      assert.ok(regGet.stdout.includes(regVal), `CLI "reg get" must return "${regVal}", got: ${regGet.stdout}`);

      const regListArgs = usedSplitHive ? ['reg', 'list', 'HKCU', subRegPath] : ['reg', 'list', fullRegPath];
      const regList = await srv.runCli(regListArgs, { json: true, expectZero: true });
      assert.ok(
        regList.stdout.includes('Tag') || regList.stdout.includes(regVal),
        `CLI "reg list" must include Tag/${regVal}, got: ${regList.stdout}`
      );

      // 3. Android prefs set / get
      const prefPkg = `com.omnios.cli.${nonce.replace(/-/g, '_')}`;
      const prefVal = `pref-${nonce}`;
      let prefSet = await srv.runCli(['prefs', 'set', prefPkg, 'app_prefs', 'Tag', prefVal], { json: true });
      let usedTwoPartPrefs = false;
      if (!prefSet.ok) {
        prefSet = await srv.runCli(['prefs', 'set', prefPkg, 'Tag', prefVal], { json: true });
        usedTwoPartPrefs = true;
      }
      assert.equal(prefSet.ok, true, `CLI "prefs set" failed: stdout=${prefSet.stdout} stderr=${prefSet.stderr}`);

      const prefGetArgs = usedTwoPartPrefs
        ? ['prefs', 'get', prefPkg, 'Tag']
        : ['prefs', 'get', prefPkg, 'app_prefs'];
      const prefGet = await srv.runCli(prefGetArgs, { json: true, expectZero: true });
      assert.ok(prefGet.stdout.includes(prefVal), `CLI "prefs get" must return "${prefVal}", got: ${prefGet.stdout}`);
    } finally {
      await srv.stop();
    }
  });
});
