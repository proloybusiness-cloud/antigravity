/**
 * Tier 2 Boundary, Corner & Negative E2E Suite — FA-07:
 * Users, Sandbox UIDs (10000+), POSIX ACLs, Unified Permission Broker, Audit Log
 * & Unprivileged HKLM Boundary (F-027, F-028, F-021).
 *
 * Strictly opaque-box: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * Dynamic capability discovery — ZERO hardcoded undocumented capability strings!
 * Zero skips, zero stubs, zero private internal os imports.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';
import { buildCustomUapp } from '../lib/fixtures-apple-wasm.mjs';
import { buildCustomApk } from '../lib/fixtures-android-win.mjs';

function makeToken() {
  return crypto.randomBytes(4).toString('hex');
}

function assertKernelHealthy(os) {
  assert.equal(os.require('kernel').getDiagnostics()?.state, 'RUNNING', 'Kernel must remain RUNNING');
}

async function assertVfsDenied(fn, label, allowedCodes = ['EACCES']) {
  let caught = null;
  try {
    await fn();
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof Error, `${label}: MUST be denied with ${allowedCodes.join('|')}`);
  assert.ok(
    allowedCodes.includes(caught.code),
    `${label}: expected code in [${allowedCodes.join(', ')}] (got code=${caught.code}, msg=${caught.message})`
  );
}

/**
 * Dynamically discovers a canonical capability name from the live PermissionBroker
 * via Android's standard `android.permission.CAMERA` mapping (zero hardcoded capability names!).
 */
async function discoverValidCapability(security, tok, pkgManager = null) {
  const probeApp = `com.sec.capprobe.${tok}`;
  const probe = await security.checkPermission({
    appId: probeApp,
    pid: 1,
    platform: 'android',
    nativePermission: 'android.permission.CAMERA',
  });
  if (typeof probe?.capability === 'string' && probe.capability.length > 0) {
    return { capability: probe.capability, fromCameraNative: true };
  }

  const logs = await security.getAuditLog({ appId: probeApp, limit: 10 });
  if (Array.isArray(logs)) {
    const capFromLog = logs
      .map((e) => e?.capability ?? e?.cap)
      .find((c) => typeof c === 'string' && c.length > 0);
    if (capFromLog) {
      return { capability: capFromLog, fromCameraNative: true };
    }
  }

  const listed =
    (typeof security.listCapabilities === 'function' ? await security.listCapabilities() : null) ??
    (Array.isArray(security.capabilities) ? security.capabilities : null);
  if (Array.isArray(listed) && listed.length > 0) {
    const first = typeof listed[0] === 'string' ? listed[0] : (listed[0]?.id ?? listed[0]?.name ?? listed[0]?.capability);
    if (typeof first === 'string' && first.length > 0) {
      return { capability: first, fromCameraNative: false };
    }
  }

  if (pkgManager && typeof pkgManager.inspect === 'function') {
    const apk = buildCustomApk({
      packageName: `com.sec.apkcap.${tok}`,
      appLabel: `ApkCap-${tok}`,
      permissions: ['android.permission.CAMERA'],
    });
    const insp = await pkgManager.inspect(apk);
    const caps = extractCapabilitiesFromPayload(insp);
    if (caps.length > 0) {
      return { capability: caps[0], fromCameraNative: true };
    }
  }

  assert.fail(
    `Unable to dynamically discover a canonical capability from PermissionBroker ` +
    `(probe=${JSON.stringify(probe)}, auditLogs=${JSON.stringify(logs)})`
  );
}

function extractCapabilitiesFromPayload(payload) {
  const found = [];
  const walk = (node, depth = 0) => {
    if (!node || depth > 5) return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    if (typeof node === 'object') {
      if (typeof node.capability === 'string' && node.capability.length > 0) {
        found.push(node.capability);
      }
      if (Array.isArray(node.capabilities)) {
        for (const c of node.capabilities) {
          if (typeof c === 'string' && c.length > 0) found.push(c);
          else if (typeof c?.id === 'string') found.push(c.id);
          else if (typeof c?.name === 'string') found.push(c.name);
          else if (typeof c?.capability === 'string') found.push(c.capability);
        }
      }
      if (node.grants && typeof node.grants === 'object' && !Array.isArray(node.grants)) {
        for (const k of Object.keys(node.grants)) {
          if (k.length > 0) found.push(k);
        }
      }
      for (const key of ['data', 'permissions', 'grants', 'entries', 'items', 'records', 'inspection', 'package', 'app']) {
        if (node[key] !== undefined) walk(node[key], depth + 1);
      }
    }
  };
  walk(payload);
  return [...new Set(found)];
}

async function discoverWorkingMethod(api, methods, urlPath, body, opts = {}) {
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

async function discoverValidCapabilityRest(api, tok) {
  // 1. Query GET /api/v1/security/permissions first
  const permRes = await api.get('/api/v1/security/permissions');
  if (permRes.ok && permRes.json) {
    const caps = extractCapabilitiesFromPayload(permRes.json);
    if (caps.length > 0) return caps[0];
  }

  // 2. Install a real dynamic APK declaring android.permission.CAMERA to trigger OS capability mapping
  const probePkg = `com.rest.capprobe.${tok}`;
  const apkBytes = buildCustomApk({
    packageName: probePkg,
    appLabel: `CapProbe-${tok}`,
    permissions: ['android.permission.CAMERA'],
  });

  // Try raw octet-stream upload first, then JSON base64 payload if server expects JSON
  let instRes = await api.post('/api/v1/packages/install', apkBytes, {
    headers: { 'content-type': 'application/octet-stream', 'x-filename': `${probePkg}.apk` },
  });
  if (!instRes.ok) {
    instRes = await api.post('/api/v1/packages/install', {
      filename: `${probePkg}.apk`,
      buffer: Buffer.from(apkBytes).toString('base64'),
      data: Buffer.from(apkBytes).toString('base64'),
    });
  }
  if (instRes.ok && instRes.json) {
    const caps = extractCapabilitiesFromPayload(instRes.json);
    if (caps.length > 0) return caps[0];
  }

  const appPermRes = await api.get('/api/v1/security/permissions', { query: { appId: probePkg } });
  if (appPermRes.ok && appPermRes.json) {
    const caps = extractCapabilitiesFromPayload(appPermRes.json);
    if (caps.length > 0) return caps[0];
  }

  const allPermRes = await api.get('/api/v1/security/permissions');
  if (allPermRes.ok && allPermRes.json) {
    const caps = extractCapabilitiesFromPayload(allPermRes.json);
    if (caps.length > 0) return caps[0];
  }

  // 3. Fallback: inspect the dynamic APK via POST /api/v1/packages/inspect in case /security/permissions only lists explicit grants
  let inspRes = await api.post('/api/v1/packages/inspect', apkBytes, {
    headers: { 'content-type': 'application/octet-stream', 'x-filename': `${probePkg}.apk` },
  });
  if (!inspRes.ok) {
    inspRes = await api.post('/api/v1/packages/inspect', {
      filename: `${probePkg}.apk`,
      buffer: Buffer.from(apkBytes).toString('base64'),
      data: Buffer.from(apkBytes).toString('base64'),
    });
  }
  if (inspRes.ok && inspRes.json) {
    const caps = extractCapabilitiesFromPayload(inspRes.json);
    if (caps.length > 0) return caps[0];
  }

  assert.fail(
    `Unable to dynamically discover a valid capability via REST /api/v1/security/permissions or APK inspect/install ` +
    `(permRes=${permRes.status}, instRes=${instRes.status}, appPermRes=${appPermRes.status}, inspRes=${inspRes.status})`
  );
}

async function resolveSandboxUid(os, appId, installedRecord) {
  const fromRec = installedRecord?.sandboxUid ?? installedRecord?.uid;
  if (Number.isInteger(fromRec) && fromRec >= 10000) return fromRec;

  const pkg = await os.require('pkgManager').get(appId);
  const fromPkg = pkg?.sandboxUid ?? pkg?.uid;
  if (Number.isInteger(fromPkg) && fromPkg >= 10000) return fromPkg;

  const users = os.users ?? os.raw?.users ?? os.raw?.security?.users;
  if (users) {
    const fromFn =
      (await users.getAppUid?.(appId)) ??
      (await users.getUserByApp?.(appId))?.uid ??
      (await users.getByName?.(appId))?.uid;
    if (Number.isInteger(fromFn) && fromFn >= 10000) return fromFn;

    const list = (await users.list?.()) ?? (await users.listUsers?.());
    if (Array.isArray(list)) {
      const match = list.find((u) => u?.appId === appId || u?.name === appId || u?.username === appId);
      if (Number.isInteger(match?.uid) && match.uid >= 10000) return match.uid;
    }
  }
  return null;
}

test.describe('Tier 2 — FA-07: Users, Sandbox UIDs, Unified Permission Broker & Audit Log (Boundary & Negative)', () => {
  test('T1 [F-027]: Sandbox UID (10000+) cross-app container escape denial (EACCES) on /var/appdata/* & Android /data/data/*', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const vfs = os.require('vfs');
      const pkgManager = os.require('pkgManager');
      const rootCtx = { uid: 0, gid: 0 };

      const appA = `com.sec.appa.${tok}`;
      const appB = `com.sec.appb.${tok}`;
      const recA = await pkgManager.install(buildCustomUapp({ appId: appA, name: `AppA-${tok}`, message: `A-${tok}\n` }), { grantAll: true });
      const recB = await pkgManager.install(buildCustomUapp({ appId: appB, name: `AppB-${tok}`, message: `B-${tok}\n` }), { grantAll: true });

      const uidA = await resolveSandboxUid(os, appA, recA);
      const uidB = await resolveSandboxUid(os, appB, recB);
      assert.ok(Number.isInteger(uidA) && uidA >= 10000, `App A must receive isolated sandbox UID >= 10000 (got ${uidA})`);
      assert.ok(Number.isInteger(uidB) && uidB >= 10000, `App B must receive isolated sandbox UID >= 10000 (got ${uidB})`);
      assert.notEqual(uidA, uidB, 'App A and App B MUST receive distinct sandbox UIDs');

      // Provision App A's private universal & Android containers owned by uidA:uidA (0o700 dir, 0o600 file)
      const containerDirA = `/var/appdata/universal/${appA}`;
      const secretPath = `${containerDirA}/secret-${tok}.txt`;
      const secretBody = `SECRET_${tok}`;
      await vfs.mkdir(containerDirA, { recursive: true, mode: 0o700, ...rootCtx });
      await vfs.chown(containerDirA, uidA, uidA, rootCtx);
      await vfs.chmod(containerDirA, 0o700, rootCtx);
      await vfs.writeFile(secretPath, secretBody, { mode: 0o600, ...rootCtx });
      await vfs.chown(secretPath, uidA, uidA, rootCtx);
      await vfs.chmod(secretPath, 0o600, rootCtx);

      const andDir = `/var/appdata/android/${appA}`;
      const andDb = `${andDir}/private.db`;
      const andSecret = `AND_SECRET_${tok}`;
      await vfs.mkdir(andDir, { recursive: true, mode: 0o700, ...rootCtx });
      await vfs.chown(andDir, uidA, uidA, rootCtx);
      await vfs.chmod(andDir, 0o700, rootCtx);
      await vfs.writeFile(andDb, andSecret, { mode: 0o600, ...rootCtx });
      await vfs.chown(andDb, uidA, uidA, rootCtx);
      await vfs.chmod(andDb, 0o600, rootCtx);

      // Owner uidA reads its own container files cleanly (uid AND appId === appA both match!)
      const ownerCtx = { uid: uidA, gid: uidA, appId: appA };
      assert.equal(await vfs.readFile(secretPath, { encoding: 'utf8', ...ownerCtx }), secretBody);
      assert.equal(
        await vfs.readFile(`/data/data/${appA}/private.db`, { encoding: 'utf8', platform: 'android', ...ownerCtx }),
        andSecret
      );

      // Attacker uidB MUST be denied with EACCES across all cross-container operations
      const attackerCtx = { uid: uidB, gid: uidB, appId: appB };
      await assertVfsDenied(() => vfs.readFile(secretPath, { encoding: 'utf8', ...attackerCtx }), 'cross-app readFile');
      await assertVfsDenied(() => vfs.writeFile(secretPath, 'PWN', attackerCtx), 'cross-app writeFile');
      await assertVfsDenied(() => vfs.unlink(secretPath, attackerCtx), 'cross-app unlink');
      await assertVfsDenied(() => vfs.readdir(containerDirA, attackerCtx), 'cross-app readdir');
      await assertVfsDenied(
        () => vfs.readFile(`/data/data/${appA}/private.db`, { encoding: 'utf8', platform: 'android', ...attackerCtx }),
        'cross-app Android /data/data readFile'
      );

      // Secret remains intact for owner uidA
      assert.equal(await vfs.readFile(secretPath, { encoding: 'utf8', ...ownerCtx }), secretBody);
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T2 [F-027]: POSIX 0o000, 0o400, 0o600, 0o640 ACL denial & non-owner chmod/chown escalation denial', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const vfs = os.require('vfs');
      const rootCtx = { uid: 0, gid: 0 };
      const ownerCtx = { uid: 10041, gid: 10041 };
      const otherCtx = { uid: 10042, gid: 10042 };
      const groupCtx = { uid: 10043, gid: 10041 };
      const thirdCtx = { uid: 10044, gid: 10044 };

      const dir = `/tmp/acl-${tok}`;
      await vfs.mkdir(dir, { recursive: true, mode: 0o755, ...rootCtx });

      const makeOwned = async (name, mode, body) => {
        const p = `${dir}/${name}`;
        await vfs.writeFile(p, body, { mode, ...rootCtx });
        await vfs.chown(p, 10041, 10041, rootCtx);
        await vfs.chmod(p, mode, rootCtx);
        return p;
      };

      // 0o000: both owner & non-owner denied; root bypasses
      const f000 = await makeOwned('f000.txt', 0o000, `v000-${tok}`);
      await assertVfsDenied(() => vfs.readFile(f000, { encoding: 'utf8', ...ownerCtx }), '0o000 owner read');
      await assertVfsDenied(() => vfs.writeFile(f000, 'x', ownerCtx), '0o000 owner write');
      await assertVfsDenied(() => vfs.readFile(f000, { encoding: 'utf8', ...otherCtx }), '0o000 other read');
      await assertVfsDenied(() => vfs.writeFile(f000, 'x', otherCtx), '0o000 other write');
      assert.equal(await vfs.readFile(f000, { encoding: 'utf8', ...rootCtx }), `v000-${tok}`, 'root must read 0o000');

      // 0o400: owner reads, owner write denied, other read & write denied
      const f400 = await makeOwned('f400.txt', 0o400, `v400-${tok}`);
      assert.equal(await vfs.readFile(f400, { encoding: 'utf8', ...ownerCtx }), `v400-${tok}`);
      await assertVfsDenied(() => vfs.writeFile(f400, 'x', ownerCtx), '0o400 owner write');
      await assertVfsDenied(() => vfs.readFile(f400, { encoding: 'utf8', ...otherCtx }), '0o400 other read');
      await assertVfsDenied(() => vfs.writeFile(f400, 'x', otherCtx), '0o400 other write');

      // 0o600: owner reads & writes, other denied both
      const f600 = await makeOwned('f600.txt', 0o600, `v600-${tok}`);
      assert.equal(await vfs.readFile(f600, { encoding: 'utf8', ...ownerCtx }), `v600-${tok}`);
      await vfs.writeFile(f600, `v600-upd-${tok}`, ownerCtx);
      assert.equal(await vfs.readFile(f600, { encoding: 'utf8', ...ownerCtx }), `v600-upd-${tok}`);
      await assertVfsDenied(() => vfs.readFile(f600, { encoding: 'utf8', ...otherCtx }), '0o600 other read');
      await assertVfsDenied(() => vfs.writeFile(f600, 'x', otherCtx), '0o600 other write');

      // 0o640: same-group reads, same-group write denied, unrelated other denied both
      const f640 = await makeOwned('f640.txt', 0o640, `v640-${tok}`);
      assert.equal(await vfs.readFile(f640, { encoding: 'utf8', ...groupCtx }), `v640-${tok}`);
      await assertVfsDenied(() => vfs.writeFile(f640, 'x', groupCtx), '0o640 group write');
      await assertVfsDenied(() => vfs.readFile(f640, { encoding: 'utf8', ...thirdCtx }), '0o640 other read');
      await assertVfsDenied(() => vfs.writeFile(f640, 'x', thirdCtx), '0o640 other write');

      // Non-owner privilege escalation denial: chmod & chown MUST fail with EACCES/EPERM
      await assertVfsDenied(() => vfs.chmod(f600, 0o777, otherCtx), 'non-owner chmod escalation', ['EACCES', 'EPERM']);
      await assertVfsDenied(() => vfs.chown(f600, 10042, 10042, otherCtx), 'non-owner chown escalation', ['EACCES', 'EPERM']);

      const st = await vfs.stat(f600, rootCtx);
      assert.equal(st.uid, 10041, 'f600 uid must remain 10041 after rejected chown');
      assert.equal(st.mode & 0o777, 0o600, 'f600 mode must remain 0o600 after rejected chmod');
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T3 [F-028]: Permission Broker "deny" blocks capability & records denial in getAuditLog() (dynamic capability discovery)', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const security = os.require('security');

      const { capability: cap, fromCameraNative } = await discoverValidCapability(security, tok, os.pkgManager);
      const appDeny = `com.sec.deny.${tok}`;

      await security.setGrant(appDeny, cap, 'deny');
      const resCap = await security.checkPermission({
        appId: appDeny,
        pid: 1,
        platform: 'android',
        capability: cap,
      });
      assert.equal(resCap?.granted, false, 'Denied capability MUST return granted === false');
      assert.equal(resCap?.policy, 'deny', 'Denied capability MUST return policy === "deny"');
      assert.ok(typeof resCap?.reason === 'string' && resCap.reason.length > 0, 'Denial must include a non-empty reason');

      if (fromCameraNative) {
        const resNative = await security.checkPermission({
          appId: appDeny,
          pid: 1,
          platform: 'android',
          nativePermission: 'android.permission.CAMERA',
        });
        assert.equal(resNative?.granted, false, 'Native CAMERA permission mapped to denied capability must return granted === false');
        assert.equal(resNative?.policy, 'deny', 'Native CAMERA permission must enforce policy === "deny"');
      }

      // Audit log MUST record denial for appDeny and isolate unrelated apps
      const logs = await security.getAuditLog({ appId: appDeny, limit: 50 });
      assert.ok(Array.isArray(logs) && logs.length >= 1, 'getAuditLog must record denied permission check');
      for (const entry of logs) {
        assert.equal(entry?.appId, appDeny, `Filtered audit log leaked entry for wrong appId: ${JSON.stringify(entry)}`);
      }
      assert.ok(
        logs.some((e) =>
          (e?.granted === false || e?.policy === 'deny' || e?.decision === 'deny') &&
          JSON.stringify(e).includes(cap)
        ),
        `Audit log must include a denial entry referencing capability "${cap}" (got ${JSON.stringify(logs)})`
      );

      const unrelatedLogs = await security.getAuditLog({ appId: `com.sec.unrelated.${tok}`, limit: 50 });
      assert.ok(Array.isArray(unrelatedLogs) && unrelatedLogs.length === 0, 'Audit log for unrelated appId must be []');
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T4 [F-028]: Invalid grant state rejected cleanly without corrupting existing "allow" / "deny" grants', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const security = os.require('security');
      const { capability: cap } = await discoverValidCapability(security, tok, os.pkgManager);
      const appId = `com.sec.invalidstate.${tok}`;

      // Establish valid 'allow' grant
      await security.setGrant(appId, cap, 'allow');
      const allowCheck = await security.checkPermission({ appId, pid: 1, platform: 'android', capability: cap });
      assert.equal(allowCheck?.granted, true, 'Pre-condition: valid allow grant must grant permission');
      assert.equal(allowCheck?.policy, 'allow');

      // Attempt invalid grant states -> EVERY ONE must throw/reject and leave 'allow' intact!
      for (const badState of ['bogus-state', 'grant-all', '', null, 123]) {
        await assert.rejects(
          async () => security.setGrant(appId, cap, badState),
          (err) => err instanceof Error && err.message.length > 0,
          `setGrant with invalid state ${JSON.stringify(badState)} MUST reject`
        );
        const verifyAllow = await security.checkPermission({ appId, pid: 1, platform: 'android', capability: cap });
        assert.equal(verifyAllow?.granted, true, `Invalid setGrant(${JSON.stringify(badState)}) corrupted existing "allow" grant`);
        assert.equal(verifyAllow?.policy, 'allow');
      }

      // Flip to 'deny', try invalid 'super-allow' -> rejected & 'deny' stays intact
      await security.setGrant(appId, cap, 'deny');
      await assert.rejects(
        async () => security.setGrant(appId, cap, 'super-allow'),
        (err) => err instanceof Error && err.message.length > 0,
        'setGrant("super-allow") MUST reject'
      );
      const verifyDeny = await security.checkPermission({ appId, pid: 1, platform: 'android', capability: cap });
      assert.equal(verifyDeny?.granted, false, 'Invalid setGrant must not corrupt existing "deny" grant');
      assert.equal(verifyDeny?.policy, 'deny');
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T5 [F-028]: Headless "prompt" fail-closed, default-deny for untrusted apps & empty appId rejection', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const security = os.require('security');
      const { capability: cap } = await discoverValidCapability(security, tok, os.pkgManager);

      // 'prompt' in headless mode MUST fail closed (granted === false, policy === 'prompt') and log audit entry
      const appPrompt = `com.sec.prompt.${tok}`;
      await security.setGrant(appPrompt, cap, 'prompt');
      const promptRes = await security.checkPermission({
        appId: appPrompt,
        pid: 1,
        platform: 'ios',
        capability: cap,
      });
      assert.equal(promptRes?.granted, false, 'Headless "prompt" policy MUST fail closed with granted === false');
      assert.equal(promptRes?.policy, 'prompt', 'Headless "prompt" policy must report policy === "prompt"');

      const promptLogs = await security.getAuditLog({ appId: appPrompt, limit: 20 });
      assert.ok(Array.isArray(promptLogs) && promptLogs.length >= 1, 'Prompt decision must be logged in Audit Log');

      // Brand-new untrusted app with no prior setGrant MUST NOT silently receive granted === true
      const appFresh = `com.sec.fresh.${tok}`;
      const freshRes = await security.checkPermission({
        appId: appFresh,
        pid: 1,
        platform: 'android',
        capability: cap,
      });
      assert.equal(freshRes?.granted, false, 'Untrusted app with no prior grant MUST fail closed (granted === false)');

      // Empty appId MUST reject cleanly without crashing kernel
      await assert.rejects(
        async () => security.setGrant('', cap, 'allow'),
        (err) => err instanceof Error && err.message.length > 0,
        'setGrant with empty appId MUST reject'
      );
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T6 [F-021, F-027]: Unprivileged HKLM Registry virtualization / protection boundary', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const reg = os.require('configStore').registry;
      const rootCtx = { uid: 0, gid: 0, privileged: true };
      const sandboxCtx = { uid: 10055, gid: 10055, appId: `com.sandbox.hklm.${tok}`, privileged: false };
      const otherSandboxCtx = { uid: 10056, gid: 10056, appId: `com.sandbox.other.${tok}`, privileged: false };

      const keyPath = `Software\\OmniSec\\Guard_${tok}`;
      const rootVal = `ROOT_VALUE_${tok}`;
      await reg.setValue('HKLM', keyPath, 'Truth', 'REG_SZ', rootVal, rootCtx);

      // Unprivileged sandbox writes to HKLM: MUST either throw EACCES OR virtualize privately
      let deniedErr = null;
      try {
        await reg.setValue('HKLM', keyPath, 'Truth', 'REG_SZ', `SANDBOX_OVERRIDE_${tok}`, sandboxCtx);
      } catch (err) {
        deniedErr = err;
      }

      if (deniedErr) {
        assert.ok(
          deniedErr.code === 'EACCES' || /EACCES|denied|priv|permission/i.test(deniedErr.message),
          `Unprivileged HKLM denial must be EACCES/permission error (got code=${deniedErr.code}, msg=${deniedErr.message})`
        );
      } else {
        // Virtualization path: sandbox sees its private override
        const sandboxRead = await reg.getValue('HKLM', keyPath, 'Truth', sandboxCtx);
        assert.equal(sandboxRead?.data, `SANDBOX_OVERRIDE_${tok}`);
      }

      // Mandatory security invariant: global HKLM seen by root AND unrelated sandbox MUST remain unmodified!
      const rootRead = await reg.getValue('HKLM', keyPath, 'Truth', rootCtx);
      assert.equal(rootRead?.data, rootVal, 'Unprivileged HKLM write MUST NEVER overwrite global root HKLM value');
      const otherRead = await reg.getValue('HKLM', keyPath, 'Truth', otherSandboxCtx);
      assert.equal(otherRead?.data, rootVal, 'Unprivileged HKLM write MUST NEVER leak to unrelated sandbox UID');
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T7 [F-028, Contract 7]: Live REST /api/v1/security/permissions bad payload 400 handling & grant preservation', async () => {
    const tok = makeToken();
    let srv = null;
    try {
      srv = await startOmniServer();
      const cap = await discoverValidCapabilityRest(srv.api, tok);
      const appRest = `com.rest.sec.${tok}`;

      // Positive verb discovery (404 || 405 fallback ONLY on positive 2xx-asserted grant write!)
      const { method: permMethod, res: setOkRes } = await discoverWorkingMethod(
        srv.api,
        ['PUT', 'POST', 'PATCH'],
        '/api/v1/security/permissions',
        { appId: appRest, capability: cap, state: 'allow', decision: 'allow' }
      );
      assert.ok(setOkRes.ok, `Setting valid allow grant via REST must succeed (got ${setOkRes.status}: ${setOkRes.text})`);

      const verifyGrantAllow = async (phase) => {
        const getRes = await srv.api.get('/api/v1/security/permissions', { query: { appId: appRest } });
        assert.equal(getRes.status, 200, `${phase}: GET permissions must return 200`);
        assert.ok(
          JSON.stringify(getRes.json).includes(cap) && /\ballow\b/i.test(JSON.stringify(getRes.json)),
          `${phase}: GET permissions for ${appRest} must reflect active "allow" grant on "${cap}" (got ${getRes.text})`
        );
      };
      await verifyGrantAllow('baseline');

      // Bad payloads using EXACT proven permMethod (ZERO fallback!) -> 4xx strictly excluding 404 & 405
      const badPayloads = [
        ['empty object {}', {}],
        ['invalid grant state', { appId: appRest, capability: cap, state: 'bogus-state', decision: 'bogus-state' }],
        ['missing appId', { capability: cap, state: 'allow', decision: 'allow' }],
      ];
      for (const [label, body] of badPayloads) {
        const res = await srv.api.request(permMethod, '/api/v1/security/permissions', { body });
        assert.ok(
          res.status >= 400 && res.status < 500 && res.status !== 404 && res.status !== 405,
          `REST ${permMethod} /api/v1/security/permissions with ${label} must return 400/422 (not 404/405, got ${res.status}: ${res.text})`
        );
      }

      // Raw malformed JSON using EXACT proven permMethod -> exact HTTP 400
      const resBadJson = await srv.api.request(permMethod, '/api/v1/security/permissions', {
        body: '{"appId": broken',
        headers: { 'content-type': 'application/json' },
      });
      assert.equal(
        resBadJson.status,
        400,
        `Malformed JSON via ${permMethod} /api/v1/security/permissions must return HTTP 400 (got ${resBadJson.status}: ${resBadJson.text})`
      );

      // Original valid grant MUST remain preserved and server healthy
      await verifyGrantAllow('post-bad-payloads');
      const health = await srv.api.get('/api/health');
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
    } finally {
      await srv?.stop();
    }
  });
});
