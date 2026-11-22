/**
 * Tier 2 Boundary, Corner & Negative E2E Suite — FA-05:
 * Unified Config Store: Windows Registry, Apple NSUserDefaults/Plist & Android SharedPreferences
 * (F-021, F-022).
 *
 * Strictly opaque-box: imports ONLY Node 24 built-ins and ../lib/env.mjs.
 * Uses external Python 3 `plistlib.loads` oracle for XML 1.0 plist verification.
 * Zero skips, zero stubs, zero private internal os imports.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  createTempDataDir,
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function decodeRegBinary(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (Array.isArray(data)) return Buffer.from(data);
  if (data && typeof data === 'object' && data.type === 'Buffer' && Array.isArray(data.data)) {
    return Buffer.from(data.data);
  }
  if (typeof data === 'string') {
    if (data.length === 0) return Buffer.alloc(0);
    if (/^[0-9a-fA-F]+$/.test(data) && data.length % 2 === 0) {
      return Buffer.from(data, 'hex');
    }
    return Buffer.from(data, 'base64');
  }
  throw new TypeError(`Unsupported REG_BINARY data representation: ${typeof data}`);
}

async function applySharedPrefsEdit(sp, pkg, prefName, ops, ctx = { uid: 0, gid: 0 }) {
  try {
    await sp.edit(pkg, prefName, ops, ctx);
    return 'op';
  } catch (err) {
    // Fallback ONLY on op-schema shape differences for valid nominal ops
    if (Array.isArray(ops)) {
      const altOps = ops.map((o) => {
        if (o.op === 'clear') return { type: 'clear' };
        if (o.op === 'remove') return { type: 'remove', key: o.key };
        return { type: 'put', key: o.key, value: o.value };
      });
      try {
        await sp.edit(pkg, prefName, altOps, ctx);
        return 'type';
      } catch {
        // Also try object-style transaction shape { clear, set, remove }
        const hasClear = ops.some((o) => o.op === 'clear');
        const setMap = {};
        const removeList = [];
        for (const o of ops) {
          if (o.op === 'put') setMap[o.key] = o.value;
          if (o.op === 'remove') removeList.push(o.key);
        }
        await sp.edit(pkg, prefName, { clear: hasClear, set: setMap, remove: removeList }, ctx);
        return 'object';
      }
    }
    throw err;
  }
}

function parsePlistViaPython(xmlString) {
  assert.equal(typeof xmlString, 'string', 'exportPlistXml() must return a string');
  assert.ok(xmlString.trim().length > 0, 'exportPlistXml() must not be empty');
  const res = spawnSync(
    'python3',
    ['-c', 'import sys, plistlib, json; print(json.dumps(plistlib.loads(sys.stdin.buffer.read())))'],
    { input: Buffer.from(xmlString, 'utf8'), encoding: 'utf8', timeout: 10000 }
  );
  assert.equal(
    res.status,
    0,
    `Python plistlib.loads() rejected exported XML plist (exit=${res.status}):\nSTDERR: ${res.stderr}\nXML:\n${xmlString.slice(0, 600)}`
  );
  return JSON.parse(res.stdout);
}

async function discoverWorkingVerb(api, urlPath, body, methods = ['PUT', 'POST', 'PATCH'], opts = {}) {
  let lastRes = null;
  let chosenMethod = methods[0];
  for (const method of methods) {
    chosenMethod = method;
    const res = await api.request(method, urlPath, { ...opts, body });
    lastRes = res;
    if (res.ok) return { method, res };
    if (res.status !== 404 && res.status !== 405) return { method, res };
  }
  return { method: chosenMethod, res: lastRes };
}

test.describe('Tier 2 — FA-05: Unified Config Store: Registry, Apple Defaults & Android SharedPrefs (Boundary & Negative)', () => {
  test('T1 [F-021]: Invalid Registry hive (HKBAD), invalid value type, non-existent getValue === null & graceful deleteValue', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const reg = os.require('configStore').registry;
      const rootCtx = { uid: 0, gid: 0 };

      // Invalid hives ('HKBAD', '') MUST reject across all Registry methods
      for (const badHive of ['HKBAD', '']) {
        await assert.rejects(
          async () => reg.setValue(badHive, `Software\\Bad\\${nonce}`, 'K', 'REG_SZ', 'v', rootCtx),
          (err) => err instanceof Error && err.message.length > 0,
          `registry.setValue with invalid hive ${JSON.stringify(badHive)} must reject`
        );
        await assert.rejects(
          async () => reg.getValue(badHive, `Software\\Bad\\${nonce}`, 'K', rootCtx),
          (err) => err instanceof Error && err.message.length > 0,
          `registry.getValue with invalid hive ${JSON.stringify(badHive)} must reject`
        );
        await assert.rejects(
          async () => reg.enumKey(badHive, `Software\\Bad\\${nonce}`, rootCtx),
          (err) => err instanceof Error && err.message.length > 0,
          `registry.enumKey with invalid hive ${JSON.stringify(badHive)} must reject`
        );
        await assert.rejects(
          async () => reg.deleteValue(badHive, `Software\\Bad\\${nonce}`, 'K', rootCtx),
          (err) => err instanceof Error && err.message.length > 0,
          `registry.deleteValue with invalid hive ${JSON.stringify(badHive)} must reject`
        );
      }

      // Invalid Registry value type MUST reject
      await assert.rejects(
        async () => reg.setValue('HKCU', `Software\\BadType\\${nonce}`, 'K', 'REG_INVALID', 'v', rootCtx),
        (err) => err instanceof Error && err.message.length > 0,
        'registry.setValue with invalid type REG_INVALID must reject'
      );

      // Non-existent key & missing value under existing key MUST return exact null
      const missingKey = `Software\\Missing\\${nonce}`;
      assert.equal(await reg.getValue('HKCU', missingKey, 'V', rootCtx), null, 'Missing key getValue must return exact null');

      const existingKey = `Software\\Existing\\${nonce}`;
      await reg.setValue('HKCU', existingKey, 'Sibling', 'REG_SZ', `keep-${nonce}`, rootCtx);
      assert.equal(
        await reg.getValue('HKCU', existingKey, 'MissingSibling', rootCtx),
        null,
        'Missing value under existing key must return exact null'
      );

      // enumKey on non-existent key -> empty result OR structured ENOENT
      let enumErr = null;
      let enumRes = null;
      try {
        enumRes = await reg.enumKey('HKCU', missingKey, rootCtx);
      } catch (err) {
        enumErr = err;
      }
      if (enumErr) {
        assert.ok(enumErr instanceof Error && enumErr.message.length > 0);
      } else {
        assert.ok(enumRes && typeof enumRes === 'object');
        assert.ok(Array.isArray(enumRes.subkeys) && enumRes.subkeys.length === 0, 'Missing enumKey subkeys must be empty');
        const valsLen = Array.isArray(enumRes.values)
          ? enumRes.values.length
          : Object.keys(enumRes.values ?? {}).length;
        assert.equal(valsLen, 0, 'Missing enumKey values must be empty');
      }

      // deleteValue on non-existent value (existing key & missing key) -> graceful OR ENOENT, never harms sibling
      for (const [k, v] of [[existingKey, 'NoSuchVal'], [missingKey, 'NoSuchVal']]) {
        let delErr = null;
        try {
          await reg.deleteValue('HKCU', k, v, rootCtx);
        } catch (err) {
          delErr = err;
        }
        if (delErr) {
          assert.ok(delErr instanceof Error && (delErr.code === 'ENOENT' || delErr.message.length > 0));
        }
      }
      const sib = await reg.getValue('HKCU', existingKey, 'Sibling', rootCtx);
      assert.equal(sib?.data, `keep-${nonce}`, 'Deleting non-existent values must not corrupt existing sibling values');
    } finally {
      await os?.shutdown();
    }
  });

  test('T2 [F-021]: Registry type boundary values (REG_DWORD 0/0xFFFFFFFF, REG_QWORD 0n/INT64_MAX/UINT64_MAX, empty REG_MULTI_SZ/REG_BINARY/REG_SZ), out-of-range rejection & persistence', async () => {
    const nonce = makeNonce();
    let temp = null;
    let os1 = null;
    let os2 = null;
    try {
      temp = await createTempDataDir('omnios-t2-fa05-reg-');
      os1 = await loadPublicOmniOS({ dataDir: temp.dir });
      const reg1 = os1.require('configStore').registry;
      const rootCtx = { uid: 0, gid: 0 };
      const key = `Software\\Bounds\\${nonce}`;

      // Valid boundary values across all 6 Registry types
      await reg1.setValue('HKCU', key, 'DwZero', 'REG_DWORD', 0, rootCtx);
      await reg1.setValue('HKCU', key, 'DwMax', 'REG_DWORD', 0xffffffff, rootCtx);
      await reg1.setValue('HKCU', key, 'QwZero', 'REG_QWORD', 0n, rootCtx);
      await reg1.setValue('HKCU', key, 'QwInt64Max', 'REG_QWORD', 0x7fffffffffffffffn, rootCtx);
      await reg1.setValue('HKCU', key, 'QwUint64Max', 'REG_QWORD', 0xffffffffffffffffn, rootCtx);
      await reg1.setValue('HKCU', key, 'MultiEmpty', 'REG_MULTI_SZ', [], rootCtx);
      await reg1.setValue('HKCU', key, 'MultiOne', 'REG_MULTI_SZ', [`single-${nonce}`], rootCtx);
      await reg1.setValue('HKCU', key, 'BinEmpty', 'REG_BINARY', new Uint8Array(0), rootCtx);
      await reg1.setValue('HKCU', key, 'SzEmpty', 'REG_SZ', '', rootCtx);
      await reg1.setValue('HKCU', key, 'SzSpecial', 'REG_SZ', `<tag>&"'★-${nonce}`, rootCtx);
      await reg1.setValue('HKCU', key, 'ExpEmpty', 'REG_EXPAND_SZ', '', rootCtx);

      const assertAllBounds = async (reg, phase) => {
        const dw0 = await reg.getValue('HKCU', key, 'DwZero', rootCtx);
        assert.equal(dw0?.type, 'REG_DWORD', `${phase}: DwZero type`);
        assert.equal(dw0?.data, 0, `${phase}: DwZero value`);

        const dwMax = await reg.getValue('HKCU', key, 'DwMax', rootCtx);
        assert.equal(dwMax?.type, 'REG_DWORD', `${phase}: DwMax type`);
        assert.equal(dwMax?.data, 4294967295, `${phase}: REG_DWORD 0xFFFFFFFF must round-trip unsigned (not -1)`);

        const qw0 = await reg.getValue('HKCU', key, 'QwZero', rootCtx);
        assert.equal(qw0?.type, 'REG_QWORD', `${phase}: QwZero type`);
        assert.equal(BigInt(qw0?.data), 0n, `${phase}: QwZero value`);

        const qwI64 = await reg.getValue('HKCU', key, 'QwInt64Max', rootCtx);
        assert.equal(qwI64?.type, 'REG_QWORD', `${phase}: QwInt64Max type`);
        assert.equal(BigInt(qwI64?.data), 0x7fffffffffffffffn, `${phase}: QwInt64Max exact 64-bit precision`);

        const qwU64 = await reg.getValue('HKCU', key, 'QwUint64Max', rootCtx);
        assert.equal(qwU64?.type, 'REG_QWORD', `${phase}: QwUint64Max type`);
        assert.equal(BigInt(qwU64?.data), 0xffffffffffffffffn, `${phase}: QwUint64Max exact 64-bit precision`);

        const mEmpty = await reg.getValue('HKCU', key, 'MultiEmpty', rootCtx);
        assert.equal(mEmpty?.type, 'REG_MULTI_SZ', `${phase}: MultiEmpty type`);
        assert.deepEqual(mEmpty?.data, [], `${phase}: empty REG_MULTI_SZ`);

        const mOne = await reg.getValue('HKCU', key, 'MultiOne', rootCtx);
        assert.deepEqual(mOne?.data, [`single-${nonce}`], `${phase}: single-element REG_MULTI_SZ`);

        const bEmpty = await reg.getValue('HKCU', key, 'BinEmpty', rootCtx);
        assert.equal(bEmpty?.type, 'REG_BINARY', `${phase}: BinEmpty type`);
        assert.equal(decodeRegBinary(bEmpty?.data).length, 0, `${phase}: empty REG_BINARY must be 0 bytes`);

        const sEmpty = await reg.getValue('HKCU', key, 'SzEmpty', rootCtx);
        assert.equal(sEmpty?.type, 'REG_SZ', `${phase}: SzEmpty type`);
        assert.equal(sEmpty?.data, '', `${phase}: empty REG_SZ must be "" (not null)`);

        const sSpec = await reg.getValue('HKCU', key, 'SzSpecial', rootCtx);
        assert.equal(sSpec?.data, `<tag>&"'★-${nonce}`, `${phase}: special-char REG_SZ`);

        const eEmpty = await reg.getValue('HKCU', key, 'ExpEmpty', rootCtx);
        assert.equal(eEmpty?.type, 'REG_EXPAND_SZ', `${phase}: ExpEmpty type`);
        assert.equal(eEmpty?.data, '', `${phase}: empty REG_EXPAND_SZ`);
      };

      await assertAllBounds(reg1, 'pre-reboot');

      // Out-of-range & type mismatch validation MUST reject cleanly
      for (const badDw of [-1, 0x100000000, 'not-a-dword']) {
        await assert.rejects(
          async () => reg1.setValue('HKCU', key, 'BadDw', 'REG_DWORD', badDw, rootCtx),
          (err) => err instanceof Error && err.message.length > 0,
          `REG_DWORD must reject out-of-range/invalid value ${JSON.stringify(badDw)}`
        );
      }
      for (const badQw of [-1n, 0x10000000000000000n, 'not-a-qword']) {
        await assert.rejects(
          async () => reg1.setValue('HKCU', key, 'BadQw', 'REG_QWORD', badQw, rootCtx),
          (err) => err instanceof Error && err.message.length > 0,
          `REG_QWORD must reject out-of-range/invalid value ${String(badQw)}`
        );
      }
      await assert.rejects(
        async () => reg1.setValue('HKCU', key, 'BadMulti', 'REG_MULTI_SZ', 12345, rootCtx),
        (err) => err instanceof Error && err.message.length > 0,
        'REG_MULTI_SZ must reject non-array input'
      );

      // Persist across cold reboot
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      await assertAllBounds(os2.require('configStore').registry, 'post-reboot');
    } finally {
      await os2?.shutdown();
      await os1?.shutdown();
      await temp?.cleanup();
    }
  });

  test('T3 [F-021, F-027]: Unprivileged HKLM\\Software Registry virtualization & cross-app/system isolation across reboot', async () => {
    const nonce = makeNonce();
    let temp = null;
    let os1 = null;
    let os2 = null;
    try {
      temp = await createTempDataDir('omnios-t2-fa05-virt-');
      os1 = await loadPublicOmniOS({ dataDir: temp.dir });
      const reg1 = os1.require('configStore').registry;

      const rootCtx = { uid: 0, gid: 0, privileged: true };
      const appACtx = { uid: 10010, gid: 10010, appId: `com.win.appA.${nonce}`, privileged: false };
      const appBCtx = { uid: 10020, gid: 10020, appId: `com.win.appB.${nonce}`, privileged: false };
      const key = `Software\\OmniVirt\\${nonce}`;

      // Root writes authoritative system HKLM value -> readable by Root, App A, and App B
      await reg1.setValue('HKLM', key, 'Setting', 'REG_SZ', `sys-${nonce}`, rootCtx);
      assert.equal((await reg1.getValue('HKLM', key, 'Setting', rootCtx))?.data, `sys-${nonce}`);
      assert.equal((await reg1.getValue('HKLM', key, 'Setting', appACtx))?.data, `sys-${nonce}`);
      assert.equal((await reg1.getValue('HKLM', key, 'Setting', appBCtx))?.data, `sys-${nonce}`);

      // Unprivileged App A writes to HKLM\Software -> virtualized into App A's private VirtualStore
      await reg1.setValue('HKLM', key, 'Setting', 'REG_SZ', `virtA-${nonce}`, appACtx);
      await reg1.setValue('HKLM', key, 'AppOnly', 'REG_SZ', `onlyA-${nonce}`, appACtx);

      assert.equal((await reg1.getValue('HKLM', key, 'Setting', appACtx))?.data, `virtA-${nonce}`, 'App A must read its virtualized HKLM override');
      assert.equal((await reg1.getValue('HKLM', key, 'AppOnly', appACtx))?.data, `onlyA-${nonce}`, 'App A must read its virtualized AppOnly value');

      // System HKLM & unrelated App B MUST remain completely untouched!
      assert.equal((await reg1.getValue('HKLM', key, 'Setting', rootCtx))?.data, `sys-${nonce}`, 'Unprivileged write MUST NOT modify global HKLM seen by root');
      assert.equal(await reg1.getValue('HKLM', key, 'AppOnly', rootCtx), null, 'App A virtualized value MUST NOT leak into global HKLM');
      assert.equal((await reg1.getValue('HKLM', key, 'Setting', appBCtx))?.data, `sys-${nonce}`, 'App A virtualized write MUST NOT leak to App B');
      assert.equal(await reg1.getValue('HKLM', key, 'AppOnly', appBCtx), null, 'App A AppOnly MUST NOT leak to App B');

      // App B writes its own independent virtualized overlay
      await reg1.setValue('HKLM', key, 'Setting', 'REG_SZ', `virtB-${nonce}`, appBCtx);
      assert.equal((await reg1.getValue('HKLM', key, 'Setting', appBCtx))?.data, `virtB-${nonce}`);
      assert.equal((await reg1.getValue('HKLM', key, 'Setting', appACtx))?.data, `virtA-${nonce}`);
      assert.equal((await reg1.getValue('HKLM', key, 'Setting', rootCtx))?.data, `sys-${nonce}`);

      // Reboot and confirm all 3 views persisted independently in SQLite
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      const reg2 = os2.require('configStore').registry;
      assert.equal((await reg2.getValue('HKLM', key, 'Setting', rootCtx))?.data, `sys-${nonce}`, 'Root HKLM value must persist after reboot');
      assert.equal((await reg2.getValue('HKLM', key, 'Setting', appACtx))?.data, `virtA-${nonce}`, 'App A virtualized HKLM value must persist after reboot');
      assert.equal((await reg2.getValue('HKLM', key, 'AppOnly', appACtx))?.data, `onlyA-${nonce}`);
      assert.equal((await reg2.getValue('HKLM', key, 'Setting', appBCtx))?.data, `virtB-${nonce}`, 'App B virtualized HKLM value must persist after reboot');
    } finally {
      await os2?.shutdown();
      await os1?.shutdown();
      await temp?.cleanup();
    }
  });

  test('T4 [F-022]: NSUserDefaults empty/unknown domain, falsy values & XML 1.0 special chars (<>&"\', ]]>, Unicode) verified via Python plistlib.loads()', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const defaults = os.require('configStore').defaults;
      const rootCtx = { uid: 0, gid: 0 };

      // Empty / unknown domain boundaries
      const missingDom = `com.unknown.${nonce}`;
      const missingVal = await defaults.get(missingDom, 'NoSuchKey', rootCtx);
      assert.ok(missingVal === null || missingVal === undefined, 'Unknown domain get() must return null/undefined');

      const missingRead = await defaults.readDomain(missingDom, rootCtx);
      assert.deepEqual(missingRead, {}, 'Unknown domain readDomain() must return empty {}');

      const emptyXml = await defaults.exportPlistXml(missingDom);
      assert.deepEqual(parsePlistViaPython(emptyXml), {}, 'Empty domain exportPlistXml() must parse to {} via Python plistlib');

      // XML 1.0 special characters, CDATA terminator ]]>, falsy scalars, empty collections & Unicode
      const dom = `com.xml.edge.${nonce}`;
      const specialKey = `k<1>&"2"'3'`;
      const expected = {
        xmlText: `<tag attr="d" single='s'>A & B &amp; ]]> ${nonce}</tag>`,
        [specialKey]: `v-${nonce}`,
        emptyStr: '',
        zero: 0,
        neg: -42,
        flagFalse: false,
        emptyArr: [],
        emptyDict: {},
        nested: {
          chars: ['<', '>', '&', '"', "'"],
          unicode: 'OmniOS ★🚀 café',
          f: false,
          z: 0,
        },
      };

      for (const [k, v] of Object.entries(expected)) {
        await defaults.set(dom, k, v, rootCtx);
      }

      // Verify direct readDomain() & Python 3 plistlib.loads() external oracle
      const readBack = await defaults.readDomain(dom, rootCtx);
      for (const [k, v] of Object.entries(expected)) {
        assert.deepEqual(readBack[k], v, `readDomain() mismatch on key "${k}"`);
      }

      const exportedXml = await defaults.exportPlistXml(dom);
      const parsed = parsePlistViaPython(exportedXml);
      assert.deepEqual(parsed, expected, 'Exported XML plist must round-trip identically through external Python plistlib.loads()');

      // Invalid empty domain / empty key MUST reject
      await assert.rejects(
        async () => defaults.set('', 'k', 'v', rootCtx),
        (err) => err instanceof Error && err.message.length > 0,
        'defaults.set with empty domain must reject'
      );
      await assert.rejects(
        async () => defaults.set(dom, '', 'v', rootCtx),
        (err) => err instanceof Error && err.message.length > 0,
        'defaults.set with empty key must reject'
      );
    } finally {
      await os?.shutdown();
    }
  });

  test('T5 [F-022]: Android SharedPreferences empty/unknown pref, falsy values, empty ops, clear+put transaction boundary & atomic rollback on invalid op', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const sp = os.require('configStore').sharedPrefs;
      const rootCtx = { uid: 0, gid: 0 };
      const pkg = `com.sp.edge.${nonce.replace(/-/g, '_')}`;

      // Unknown package / pref returns empty {}
      const missing = await sp.getAll(`com.missing.${nonce.replace(/-/g, '_')}`, 'none', rootCtx);
      assert.deepEqual(missing, {}, 'Unknown SharedPreferences must return {}');

      // Populate main (including falsy values) and sibling pref file 'other'
      const opStyle = await applySharedPrefsEdit(sp, pkg, 'main', [
        { op: 'put', key: 'str', value: `v-${nonce}` },
        { op: 'put', key: 'zero', value: 0 },
        { op: 'put', key: 'boolFalse', value: false },
        { op: 'put', key: 'empty', value: '' },
      ], rootCtx);
      await applySharedPrefsEdit(sp, pkg, 'other', [
        { op: 'put', key: 'keep', value: `other-${nonce}` },
      ], rootCtx);

      const main1 = await sp.getAll(pkg, 'main', rootCtx);
      assert.deepEqual(main1, { str: `v-${nonce}`, zero: 0, boolFalse: false, empty: '' });

      // Empty ops transaction -> no-op
      await sp.edit(pkg, 'main', opStyle === 'object' ? { set: {}, remove: [] } : [], rootCtx);
      assert.deepEqual(await sp.getAll(pkg, 'main', rootCtx), main1, 'Empty ops edit must leave values unchanged');

      // Removing a non-existent key -> safe no-op
      await applySharedPrefsEdit(sp, pkg, 'main', [{ op: 'remove', key: 'ghost_key' }], rootCtx);
      assert.deepEqual(await sp.getAll(pkg, 'main', rootCtx), main1);

      // clear alone empties the target pref
      await applySharedPrefsEdit(sp, pkg, 'clear_only', [
        { op: 'put', key: 'a', value: 1 },
        { op: 'put', key: 'b', value: 2 },
      ], rootCtx);
      await applySharedPrefsEdit(sp, pkg, 'clear_only', [{ op: 'clear' }], rootCtx);
      assert.deepEqual(await sp.getAll(pkg, 'clear_only', rootCtx), {}, 'clear op must empty pref file');

      // clear + put in ONE atomic transaction wipes old keys, retains new key, and preserves sibling pref 'other'
      await applySharedPrefsEdit(sp, pkg, 'main', [
        { op: 'clear' },
        { op: 'put', key: 'fresh', value: `after-${nonce}` },
      ], rootCtx);
      assert.deepEqual(await sp.getAll(pkg, 'main', rootCtx), { fresh: `after-${nonce}` }, 'clear+put must atomically replace all keys');
      assert.deepEqual(await sp.getAll(pkg, 'other', rootCtx), { keep: `other-${nonce}` }, 'Sibling pref file must remain untouched');

      // Invalid empty package / prefName MUST reject
      const sampleOp = opStyle === 'type'
        ? [{ type: 'put', key: 'x', value: 1 }]
        : opStyle === 'object'
          ? { set: { x: 1 } }
          : [{ op: 'put', key: 'x', value: 1 }];
      await assert.rejects(
        async () => sp.edit('', 'main', sampleOp, rootCtx),
        (err) => err instanceof Error && err.message.length > 0,
        'sharedPrefs.edit with empty packageName must reject'
      );
      await assert.rejects(
        async () => sp.edit(pkg, '', sampleOp, rootCtx),
        (err) => err instanceof Error && err.message.length > 0,
        'sharedPrefs.edit with empty prefName must reject'
      );

      // Atomic rollback on invalid op: call sp.edit() DIRECTLY without schema fallback!
      const badBatch = opStyle === 'type'
        ? [
            { type: 'put', key: 'shouldRollback', value: 'bad' },
            { type: 'BOGUS_OP_999', key: 'z' },
          ]
        : [
            { op: 'put', key: 'shouldRollback', value: 'bad' },
            { op: 'BOGUS_OP_999', key: 'z' },
          ];
      await assert.rejects(
        async () => sp.edit(pkg, 'main', badBatch, rootCtx),
        (err) => err instanceof Error && err.message.length > 0,
        'sharedPrefs.edit containing an invalid operation MUST reject'
      );

      const afterRollback = await sp.getAll(pkg, 'main', rootCtx);
      assert.equal('shouldRollback' in afterRollback, false, 'Failed atomic transaction MUST roll back prior put in the same batch');
      assert.equal(afterRollback.fresh, `after-${nonce}`, 'Pre-existing key must remain intact after rolled-back transaction');
    } finally {
      await os?.shutdown();
    }
  });

  test('T6 [F-021, F-022, Contracts 7 & 8]: Invalid REST /api/v1/config/* returning HTTP 400 & CLI reg negative boundaries', async () => {
    const nonce = makeNonce();
    let srv = null;
    try {
      srv = await startOmniServer();

      // 0. Positive pre-conditions: prove all 4 config mutation routes work and discover their exact verbs/schemas
      const regProbeKey = `Software\\OmniProbe_${nonce}`;
      let { method: regMethod, res: regProbeRes } = await discoverWorkingVerb(srv.api, '/api/v1/config/registry', {
        hive: 'HKCU',
        keyPath: regProbeKey,
        valueName: 'Probe',
        type: 'REG_SZ',
        data: `ok-${nonce}`,
      });
      if (!regProbeRes.ok && regProbeRes.status === 400) {
        ({ method: regMethod, res: regProbeRes } = await discoverWorkingVerb(srv.api, '/api/v1/config/registry', {
          hive: 'HKCU',
          keyPath: regProbeKey,
          valueName: 'Probe',
          name: 'Probe',
          type: 'REG_SZ',
          data: `ok-${nonce}`,
          value: `ok-${nonce}`,
        }));
      }
      assert.ok(regProbeRes.ok, `Pre-condition: valid /api/v1/config/registry write must succeed (got ${regProbeRes.status}: ${regProbeRes.text})`);

      // Discover /api/v1/config/system verb & single-key schema cleanly (NEVER mix map keys + key/value!)
      let sysMethod = null;
      let sysSchema = 'map';
      const sysProbeMap = await discoverWorkingVerb(srv.api, '/api/v1/config/system', { 'system.locale': 'fr-FR' });
      if (sysProbeMap.res.ok) {
        sysMethod = sysProbeMap.method;
        sysSchema = 'map';
      } else {
        const sysProbeKv = await discoverWorkingVerb(srv.api, '/api/v1/config/system', { key: 'system.locale', value: 'fr-FR' });
        assert.ok(
          sysProbeKv.res.ok,
          `Pre-condition: valid single-key /api/v1/config/system write must succeed (map=${sysProbeMap.res.status}, kv=${sysProbeKv.res.status}: ${sysProbeKv.res.text})`
        );
        sysMethod = sysProbeKv.method;
        sysSchema = 'kv';
      }
      const sysVerify = await srv.api.get('/api/v1/config/system');
      assert.equal(sysVerify.status, 200);
      assert.ok(sysVerify.text.includes('fr-FR'), `Pre-condition: GET /api/v1/config/system must reflect fr-FR (got ${sysVerify.text})`);

      const { method: defMethod, res: defProbeRes } = await discoverWorkingVerb(srv.api, '/api/v1/config/defaults', {
        domain: `com.rest.probe.${nonce}`,
        key: 'ProbeKey',
        value: `ok-${nonce}`,
      });
      assert.ok(defProbeRes.ok, `Pre-condition: valid /api/v1/config/defaults write must succeed (got ${defProbeRes.status}: ${defProbeRes.text})`);

      const prefProbePkg = `com.rest.pref.${nonce.replace(/-/g, '_')}`;
      const prefCandidates = [
        { packageName: prefProbePkg, prefName: 'main', ops: [{ op: 'put', key: 'Probe', value: `ok-${nonce}` }] },
        { packageName: prefProbePkg, prefName: 'main', ops: [{ type: 'put', key: 'Probe', value: `ok-${nonce}` }] },
        { packageName: prefProbePkg, prefName: 'main', ops: { set: { Probe: `ok-${nonce}` } } },
        {
          packageName: prefProbePkg,
          pkg: prefProbePkg,
          prefName: 'main',
          key: 'Probe',
          value: `ok-${nonce}`,
          ops: [{ op: 'put', key: 'Probe', value: `ok-${nonce}` }],
        },
      ];
      let prefMethod = 'PUT';
      let prefProbeRes = null;
      for (const candidate of prefCandidates) {
        ({ method: prefMethod, res: prefProbeRes } = await discoverWorkingVerb(srv.api, '/api/v1/config/prefs', candidate));
        if (prefProbeRes.ok) break;
        if (prefProbeRes.status !== 400) break;
      }
      assert.ok(prefProbeRes.ok, `Pre-condition: valid /api/v1/config/prefs write must succeed (got ${prefProbeRes.status}: ${prefProbeRes.text})`);

      // 1. Invalid hive on GET /api/v1/config/registry -> HTTP 400
      const r1 = await srv.api.get('/api/v1/config/registry', {
        query: { hive: 'HKBAD', keyPath: 'Software', valueName: 'X' },
      });
      assert.equal(r1.status, 400, `GET registry with hive=HKBAD must return 400 (got ${r1.status}: ${r1.text})`);

      // 2. Invalid hive on write /api/v1/config/registry (EXACT regMethod, zero fallback!) -> HTTP 400
      const r2 = await srv.api.request(regMethod, '/api/v1/config/registry', {
        body: {
          hive: 'HKBAD',
          keyPath: `Software\\X_${nonce}`,
          valueName: 'K',
          type: 'REG_SZ',
          data: 'v',
        },
      });
      assert.equal(r2.status, 400, `${regMethod} registry with hive=HKBAD must return 400 (got ${r2.status}: ${r2.text})`);

      // 3. Invalid type on write /api/v1/config/registry (EXACT regMethod) -> HTTP 400
      const r3 = await srv.api.request(regMethod, '/api/v1/config/registry', {
        body: {
          hive: 'HKCU',
          keyPath: `Software\\X_${nonce}`,
          valueName: 'K',
          type: 'REG_INVALID',
          data: 'v',
        },
      });
      assert.equal(r3.status, 400, `${regMethod} registry with type=REG_INVALID must return 400 (got ${r3.status}: ${r3.text})`);

      // 4. Raw malformed JSON to /api/v1/config/system (EXACT sysMethod) -> HTTP 400
      const r4 = await srv.api.request(sysMethod, '/api/v1/config/system', {
        body: '{not-valid-json',
        headers: { 'content-type': 'application/json' },
      });
      assert.equal(r4.status, 400, `Malformed JSON via ${sysMethod} config/system must return 400 (got ${r4.status}: ${r4.text})`);

      // 5. Missing required fields on /api/v1/config/defaults (EXACT defMethod) -> HTTP 400
      const r5 = await srv.api.request(defMethod, '/api/v1/config/defaults', { body: {} });
      assert.equal(r5.status, 400, `Empty payload via ${defMethod} config/defaults must return 400 (got ${r5.status}: ${r5.text})`);

      // 6. Missing required fields on /api/v1/config/prefs (EXACT prefMethod) -> HTTP 400
      const r6 = await srv.api.request(prefMethod, '/api/v1/config/prefs', { body: {} });
      assert.equal(r6.status, 400, `Empty payload via ${prefMethod} config/prefs must return 400 (got ${r6.status}: ${r6.text})`);

      // 7. Clean single-key invalid (empty key) payload on /api/v1/config/system matching discovered sysSchema -> HTTP 400
      const invalidSysBody = sysSchema === 'kv' ? { key: '', value: 'bad' } : { '': 'bad' };
      const r7 = await srv.api.request(sysMethod, '/api/v1/config/system', { body: invalidSysBody });
      assert.equal(
        r7.status,
        400,
        `Empty key via ${sysMethod} config/system (${sysSchema}) must return 400 (got ${r7.status}: ${r7.text})`
      );
      const sysVerifyAfter = await srv.api.get('/api/v1/config/system');
      assert.equal(sysVerifyAfter.status, 200);
      assert.ok(sysVerifyAfter.text.includes('fr-FR'), 'Rejected config/system write must preserve prior system.locale');

      // 8 & 9. Remote CLI negative Registry hive boundaries
      const cliGet = await srv.runCli(['reg', 'get', 'HKBAD\\Software\\Test', 'K'], { json: true });
      assert.notEqual(cliGet.code, 0, 'CLI reg get with invalid hive HKBAD must exit non-zero');

      const cliSet = await srv.runCli(['reg', 'set', 'HKBAD\\Software\\Test', 'K', 'v'], { json: true });
      assert.notEqual(cliSet.code, 0, 'CLI reg set with invalid hive HKBAD must exit non-zero');

      // Final liveness & healthy config read
      const health = await srv.api.get('/api/health');
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
      assert.equal(health.json?.os, 'OmniOS');

      const sysCfg = await srv.api.get('/api/v1/config/system');
      assert.equal(sysCfg.status, 200);
      assert.ok(sysCfg.json && typeof sysCfg.json === 'object');
    } finally {
      await srv?.stop();
    }
  });
});
