/**
 * Tier 1 E2E Tests — FA-07: Users, Sandbox UIDs, Unified Permission Broker & Audit Log
 * Features covered: F-027, F-028
 * Contracts: Contract 2 (IVFS POSIX ownership/modes), Contract 4 (ISecurityManager), Contract 7 (REST)
 *
 * Strictly opaque-box: interacts ONLY through public OmniOS entrypoints via ../lib/env.mjs.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createTempDataDir,
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';
import { buildCustomUapp } from '../lib/fixtures-apple-wasm.mjs';

function makeToken() {
  return crypto.randomBytes(4).toString('hex');
}

function unwrapList(payload, keys = ['users', 'entries', 'audit', 'logs', 'permissions', 'items', 'data', 'list']) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return [];
  for (const key of keys) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  if (payload.data && typeof payload.data === 'object') {
    for (const key of keys) {
      if (Array.isArray(payload.data[key])) return payload.data[key];
    }
  }
  return [];
}

function unwrapExplicitArray(payload, keys = ['users', 'entries', 'audit', 'logs', 'permissions', 'items', 'data', 'list']) {
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

function unwrapObject(payload, keys = ['package', 'record', 'app', 'permissions', 'data', 'result']) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return payload;
  for (const key of keys) {
    if (payload[key] && typeof payload[key] === 'object' && !Array.isArray(payload[key])) {
      return payload[key];
    }
  }
  return payload;
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

function findSandboxUid(users, appId, installedRecord) {
  const direct = installedRecord?.uid ?? installedRecord?.sandboxUid;
  if (typeof direct === 'number' && direct >= 10000) return direct;
  const matched = users.find((u) => {
    const str = JSON.stringify(u);
    return (u?.appId === appId || u?.name === appId || str.includes(appId)) && typeof u?.uid === 'number';
  });
  return matched?.uid ?? null;
}

async function probeNativePermissionMapping(security, { appId, platform, nativePermission }) {
  const decision = await security.checkPermission({
    appId,
    pid: 1,
    platform,
    nativePermission,
  });
  let mappedCap = decision?.capability ?? decision?.canonicalCapability ?? null;
  if (!mappedCap) {
    const audit = await security.getAuditLog({ appId, limit: 20 });
    if (Array.isArray(audit)) {
      const matching = audit.filter((e) => e?.appId === appId);
      const latest = matching[matching.length - 1] ?? matching[0] ?? null;
      mappedCap = latest?.capability ?? latest?.canonicalCapability ?? null;
    }
  }
  if (typeof mappedCap !== 'string' || mappedCap.trim().length === 0) {
    mappedCap = null;
  }
  return { decision, mappedCap };
}

function getKnownBrokerCapabilities(security) {
  const raw =
    (typeof security?.listCapabilities === 'function' ? security.listCapabilities() : null) ??
    security?.capabilities ??
    security?.CAPABILITIES ??
    null;
  if (Array.isArray(raw)) {
    return raw
      .map((item) => (typeof item === 'string' ? item : item?.id ?? item?.name ?? item?.capability))
      .filter((s) => typeof s === 'string' && s.length > 0);
  }
  if (raw && typeof raw === 'object') {
    return Object.keys(raw);
  }
  return [];
}

async function discoverCanonicalCap(security, probeAppId, platform, nativePermission, fallbackCap) {
  try {
    const { mappedCap } = await probeNativePermissionMapping(security, {
      appId: probeAppId,
      platform,
      nativePermission,
    });
    if (mappedCap && mappedCap !== nativePermission && !/^unknown$/i.test(mappedCap)) {
      return mappedCap;
    }
  } catch {
    // Fall back to default canonical capability name
  }
  return fallbackCap;
}

describe('Tier 1 — FA-07: Users, Sandbox UIDs, Unified Permission Broker & Audit Log', () => {
  test('T1 [F-027]: Default system users root(0)/user(1000) and distinct per-app sandbox UIDs (10000+) on package install', async () => {
    const srv = await startOmniServer();
    try {
      const tok = makeToken();

      const usersBeforeRes = await srv.api.get('/api/v1/security/users');
      assert.equal(usersBeforeRes.status, 200);
      const usersBefore = unwrapList(usersBeforeRes.json);
      assert.ok(usersBefore.length >= 2, `Expected default users root & user, got ${JSON.stringify(usersBefore)}`);

      const rootUser = usersBefore.find((u) => u?.uid === 0 || u?.name === 'root' || u?.username === 'root');
      const stdUser = usersBefore.find((u) => u?.uid === 1000 || u?.name === 'user' || u?.username === 'user');
      assert.ok(rootUser && rootUser.uid === 0, `Expected root user with uid=0: ${JSON.stringify(rootUser)}`);
      assert.equal(rootUser.gid ?? 0, 0, 'root user must have gid=0');
      assert.ok(stdUser && stdUser.uid === 1000, `Expected standard user with uid=1000: ${JSON.stringify(stdUser)}`);
      assert.equal(stdUser.gid ?? 1000, 1000, 'user must have gid=1000');

      const existingUids = new Set(usersBefore.map((u) => u?.uid));

      // Install two fresh dynamic .uapp packages
      const appA = `com.test.uida.${tok}`;
      const appB = `com.test.uidb.${tok}`;
      const bytesA = buildCustomUapp({ appId: appA, name: `UidA-${tok}`, message: `A-${tok}\n` });
      const bytesB = buildCustomUapp({ appId: appB, name: `UidB-${tok}`, message: `B-${tok}\n` });
      const b64A = Buffer.from(bytesA).toString('base64');
      const b64B = Buffer.from(bytesB).toString('base64');

      const instA = await srv.api.post('/api/v1/packages/install', {
        base64: b64A,
        data: b64A,
        filename: `uida-${tok}.uapp`,
        grantAll: true,
      });
      assert.ok(instA.ok, `Installing ${appA} failed (${instA.status}): ${instA.text}`);

      const instB = await srv.api.post('/api/v1/packages/install', {
        base64: b64B,
        data: b64B,
        filename: `uidb-${tok}.uapp`,
        grantAll: true,
      });
      assert.ok(instB.ok, `Installing ${appB} failed (${instB.status}): ${instB.text}`);

      const usersAfterRes = await srv.api.get('/api/v1/security/users');
      assert.equal(usersAfterRes.status, 200);
      const usersAfter = unwrapList(usersAfterRes.json);

      let uidA = findSandboxUid(usersAfter, appA, unwrapObject(instA.json));
      let uidB = findSandboxUid(usersAfter, appB, unwrapObject(instB.json));

      // Fallback if sandbox usernames use derived slugs: inspect newly created UIDs >= 10000
      if (uidA === null || uidB === null) {
        const newlyAdded = usersAfter
          .filter((u) => typeof u?.uid === 'number' && u.uid >= 10000 && !existingUids.has(u.uid))
          .map((u) => u.uid);
        if (newlyAdded.length >= 2) {
          uidA = uidA ?? newlyAdded[0];
          uidB = uidB ?? newlyAdded[1];
        }
      }

      assert.ok(typeof uidA === 'number' && uidA >= 10000, `Expected sandbox UID >= 10000 for ${appA}, got ${uidA}`);
      assert.ok(typeof uidB === 'number' && uidB >= 10000, `Expected sandbox UID >= 10000 for ${appB}, got ${uidB}`);
      assert.notEqual(uidA, uidB, `Per-app sandbox UIDs must be distinct (${uidA} vs ${uidB})`);
    } finally {
      await srv.stop();
    }
  });

  test('T2 [F-027]: POSIX ownership (chown) and file mode (chmod) enforcement across root(0), user(1000), group & sandbox UID', async () => {
    const os = await loadPublicOmniOS();
    try {
      const vfs = os.require('vfs');
      const tok = makeToken();
      const filePath = `/home/user/Documents/posix-${tok}.txt`;
      const initialBody = `priv-${tok}`;

      await vfs.writeFile(filePath, initialBody, { mode: 0o640, uid: 1000, gid: 1000 });
      const st1 = await vfs.stat(filePath, { uid: 1000, gid: 1000 });
      assert.equal(st1.uid, 1000);
      assert.equal(st1.gid, 1000);
      assert.equal(st1.mode & 0o777, 0o640);

      // Owner (uid 1000) reads & updates cleanly
      assert.equal(await vfs.readFile(filePath, { encoding: 'utf8', uid: 1000, gid: 1000 }), initialBody);
      const updatedBody = `owner-upd-${tok}`;
      await vfs.writeFile(filePath, updatedBody, { uid: 1000, gid: 1000 });

      // Same-group sandbox user (uid 10042, gid 1000) reads 0o640 file cleanly
      assert.equal(await vfs.readFile(filePath, { encoding: 'utf8', uid: 10042, gid: 1000 }), updatedBody);

      // root (uid 0) changes mode to 0o600 and transfers ownership to sandbox UID 10042
      await vfs.chmod(filePath, 0o600, { uid: 0, gid: 0 });
      await vfs.chown(filePath, 10042, 10042, { uid: 0, gid: 0 });

      const st2 = await vfs.stat(filePath, { uid: 0, gid: 0 });
      assert.equal(st2.uid, 10042);
      assert.equal(st2.gid, 10042);
      assert.equal(st2.mode & 0o777, 0o600);

      // New owner (uid 10042, gid 10042) reads & writes cleanly
      assert.equal(await vfs.readFile(filePath, { encoding: 'utf8', uid: 10042, gid: 10042 }), updatedBody);
      const sandboxBody = `sandbox-upd-${tok}`;
      await vfs.writeFile(filePath, sandboxBody, { uid: 10042, gid: 10042 });
      assert.equal(await vfs.readFile(filePath, { encoding: 'utf8', uid: 10042, gid: 10042 }), sandboxBody);

      // Distinct unprivileged sandbox UID (10099) MUST be denied EACCES on 0o600 file owned by 10042
      await assert.rejects(
        async () => vfs.readFile(filePath, { encoding: 'utf8', uid: 10099, gid: 10099 }),
        (err) => err?.code === 'EACCES',
        'Reading 0o600 file owned by uid 10042 as distinct unprivileged uid 10099 must fail with EACCES'
      );
      await assert.rejects(
        async () => vfs.writeFile(filePath, 'unauthorized', { uid: 10099, gid: 10099 }),
        (err) => err?.code === 'EACCES',
        'Writing 0o600 file owned by uid 10042 as distinct unprivileged uid 10099 must fail with EACCES'
      );

      // World-readable file (0o644) created by user(1000) is readable by unrelated uid 10099
      const pubFile = `/home/user/Documents/pub-${tok}.txt`;
      await vfs.writeFile(pubFile, `pub-${tok}`, { mode: 0o644, uid: 1000, gid: 1000 });
      assert.equal(await vfs.readFile(pubFile, { encoding: 'utf8', uid: 10099, gid: 10099 }), `pub-${tok}`);
    } finally {
      await os.shutdown();
    }
  });

  test('T3 [F-028]: Unified Permission Broker setGrant (allow/deny/prompt) and checkPermission() policy evaluation', async () => {
    const os = await loadPublicOmniOS();
    try {
      const security = os.require('security');
      const tok = makeToken();
      const probeApp = `com.test.probe3.${tok}`;
      const appId = `com.test.perm.${tok}`;

      const capRead = await discoverCanonicalCap(security, `${probeApp}.r`, 'android', 'android.permission.READ_EXTERNAL_STORAGE', 'fs.read.user');
      const capCamera = await discoverCanonicalCap(security, `${probeApp}.c`, 'android', 'android.permission.CAMERA', 'camera.device');
      const capNet = await discoverCanonicalCap(security, `${probeApp}.n`, 'macos', 'com.apple.security.network.client', 'network.outbound');

      await security.setGrant(appId, capRead, 'allow');
      const allowRes = await security.checkPermission({
        appId,
        pid: 1,
        platform: 'android',
        capability: capRead,
      });
      assert.equal(allowRes?.granted, true, `allow grant for ${capRead} must yield granted=true: ${JSON.stringify(allowRes)}`);
      assert.equal(allowRes?.policy, 'allow');
      assert.equal(typeof allowRes?.reason, 'string');

      await security.setGrant(appId, capCamera, 'deny');
      const denyRes = await security.checkPermission({
        appId,
        pid: 1,
        platform: 'ios',
        capability: capCamera,
      });
      assert.equal(denyRes?.granted, false, `deny grant for ${capCamera} must yield granted=false: ${JSON.stringify(denyRes)}`);
      assert.equal(denyRes?.policy, 'deny');

      await security.setGrant(appId, capNet, 'prompt');
      const promptRes = await security.checkPermission({
        appId,
        pid: 1,
        platform: 'macos',
        capability: capNet,
      });
      assert.equal(promptRes?.policy, 'prompt', `Expected policy='prompt' for ${capNet}, got ${JSON.stringify(promptRes)}`);
      assert.equal(promptRes?.granted, false, 'Headless prompt policy must not silently grant capability');

      // Upgrade prompt -> allow and re-check
      await security.setGrant(appId, capNet, 'allow');
      const upgraded = await security.checkPermission({
        appId,
        pid: 1,
        platform: 'macos',
        capability: capNet,
      });
      assert.equal(upgraded?.granted, true);
      assert.equal(upgraded?.policy, 'allow');
    } finally {
      await os.shutdown();
    }
  });

  test('T4 [F-028]: Cross-platform native permission translation (Android, iOS TCC, macOS entitlements, Windows UAC, WASI)', async () => {
    const os = await loadPublicOmniOS();
    try {
      const security = os.require('security');
      const tok = makeToken();
      const brokerCaps = getKnownBrokerCapabilities(security);

      async function verifyNativeMapping({ appId, platform, nativeCandidates, fallbackCaps }) {
        let chosenNative = nativeCandidates[0];
        let mappedCap = null;

        // 1. Probe nativePermission first and inspect returned decision or audit entry for mapped canonical capability
        for (const cand of nativeCandidates) {
          const probeAppId = `${appId}.probe.${cand.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 20)}`;
          const { mappedCap: discovered } = await probeNativePermissionMapping(security, {
            appId: probeAppId,
            platform,
            nativePermission: cand,
          });
          if (discovered && discovered !== cand && !/^unknown$/i.test(discovered)) {
            chosenNative = cand;
            mappedCap = discovered;
            break;
          }
        }

        // 2. If mappedCap was discovered directly, verify allow/deny toggle via nativePermission ONLY (no capability arg)
        if (mappedCap) {
          await security.setGrant(appId, mappedCap, 'allow');
          const allowed = await security.checkPermission({
            appId,
            pid: 1,
            platform,
            nativePermission: chosenNative,
          });
          assert.equal(
            allowed?.granted,
            true,
            `Expected ${platform} ${chosenNative} (mapped -> ${mappedCap}) to grant when ${mappedCap}='allow', got ${JSON.stringify(allowed)}`
          );

          await security.setGrant(appId, mappedCap, 'deny');
          const denied = await security.checkPermission({
            appId,
            pid: 1,
            platform,
            nativePermission: chosenNative,
          });
          assert.equal(
            denied?.granted,
            false,
            `Expected ${platform} ${chosenNative} (mapped -> ${mappedCap}) to deny when ${mappedCap}='deny', got ${JSON.stringify(denied)}`
          );
          return { chosenNative, mappedCap };
        }

        // 3. Fallback when broker omits capability name from decision & audit: discover controlling canonical capability dynamically
        const candidateCaps = Array.from(new Set([...fallbackCaps, ...brokerCaps]));
        for (const cand of nativeCandidates) {
          for (const cap of candidateCaps) {
            if (cap === cand) continue;
            try {
              await security.setGrant(appId, cap, 'allow');
              const rAllow = await security.checkPermission({ appId, pid: 1, platform, nativePermission: cand });
              if (rAllow?.granted === true) {
                await security.setGrant(appId, cap, 'deny');
                const rDeny = await security.checkPermission({ appId, pid: 1, platform, nativePermission: cand });
                if (rDeny?.granted === false) {
                  return { chosenNative: cand, mappedCap: cap };
                }
              }
            } catch {
              // ignore unsupported capability candidate
            }
          }
        }

        assert.fail(
          `Could not verify native->canonical permission mapping for ${platform} (${nativeCandidates.join(' | ')}) ` +
            `against discovered/candidate capabilities`
        );
      }

      // Android runtime permissions -> canonical capabilities
      const andCam = await verifyNativeMapping({
        appId: `com.and.cam.${tok}`,
        platform: 'android',
        nativeCandidates: ['android.permission.CAMERA'],
        fallbackCaps: ['camera.device', 'camera', 'media.camera', 'device.camera'],
      });
      const andFs = await verifyNativeMapping({
        appId: `com.and.fs.${tok}`,
        platform: 'android',
        nativeCandidates: ['android.permission.READ_EXTERNAL_STORAGE'],
        fallbackCaps: ['fs.read.user', 'fs.read', 'storage.read', 'files.read'],
      });

      // iOS TCC permissions -> canonical capabilities (supports both NS*UsageDescription & kTCCService* forms)
      const iosCam = await verifyNativeMapping({
        appId: `com.ios.cam.${tok}`,
        platform: 'ios',
        nativeCandidates: ['NSCameraUsageDescription', 'kTCCServiceCamera'],
        fallbackCaps: [andCam.mappedCap, 'camera.device', 'camera', 'media.camera', 'device.camera'],
      });
      assert.equal(
        iosCam.mappedCap,
        andCam.mappedCap,
        `Android CAMERA ("${andCam.mappedCap}") and iOS Camera ("${iosCam.mappedCap}") must map to the same unified canonical capability`
      );

      const andLoc = await verifyNativeMapping({
        appId: `com.and.loc.${tok}`,
        platform: 'android',
        nativeCandidates: ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_COARSE_LOCATION'],
        fallbackCaps: ['location.device', 'location', 'device.location', 'geo.location'],
      });

      const iosLoc = await verifyNativeMapping({
        appId: `com.ios.loc.${tok}`,
        platform: 'ios',
        nativeCandidates: ['NSLocationWhenInUseUsageDescription', 'kTCCServiceLocation'],
        fallbackCaps: [andLoc.mappedCap, 'location.device', 'location', 'device.location', 'geo.location'],
      });
      assert.equal(
        iosLoc.mappedCap,
        andLoc.mappedCap,
        `Android Location ("${andLoc.mappedCap}") and iOS Location ("${iosLoc.mappedCap}") must map to the same unified canonical capability`
      );

      // macOS sandbox entitlement -> canonical capability
      await verifyNativeMapping({
        appId: `com.mac.net.${tok}`,
        platform: 'macos',
        nativeCandidates: ['com.apple.security.network.client'],
        fallbackCaps: ['network.outbound', 'network.client', 'network', 'net.outbound'],
      });

      // Windows UAC elevation -> canonical system capability
      await verifyNativeMapping({
        appId: `com.win.uac.${tok}`,
        platform: 'windows',
        nativeCandidates: ['requireAdministrator', 'uac:requireAdministrator', 'Windows.UAC.Admin'],
        fallbackCaps: ['registry.system.write', 'fs.write.system', 'system.admin', 'admin', 'uac.elevate', 'system.write'],
      });

      // WASI explicit capability round-trip using discovered fs-read canonical capability
      const wasiApp = `com.wasi.fs.${tok}`;
      const wasiCap = andFs.mappedCap;
      await security.setGrant(wasiApp, wasiCap, 'allow');
      const wasiAllow = await security.checkPermission({ appId: wasiApp, pid: 1, platform: 'universal', capability: wasiCap });
      assert.equal(wasiAllow?.granted, true, `WASI capability "${wasiCap}" must grant when allowed`);
      await security.setGrant(wasiApp, wasiCap, 'deny');
      const wasiDeny = await security.checkPermission({ appId: wasiApp, pid: 1, platform: 'universal', capability: wasiCap });
      assert.equal(wasiDeny?.granted, false, `WASI capability "${wasiCap}" must deny when denied`);
    } finally {
      await os.shutdown();
    }
  });

  test('T5 [F-028]: SQLite Security Audit Log recording, per-app filtering & persistence across OS reboot', async () => {
    const tmp = await createTempDataDir('omnios-fa07-audit-');
    let os1 = null;
    let os2 = null;
    try {
      const tok = makeToken();
      const probeApp = `com.test.probe5.${tok}`;
      const appA = `com.test.auda.${tok}`;
      const appB = `com.test.audb.${tok}`;

      os1 = await loadPublicOmniOS({ dataDir: tmp.dir, keepDataDir: true });
      const sec1 = os1.require('security');

      const capA1 = await discoverCanonicalCap(sec1, `${probeApp}.w`, 'android', 'android.permission.WRITE_EXTERNAL_STORAGE', 'fs.write.user');
      const capA2 = await discoverCanonicalCap(sec1, `${probeApp}.l`, 'android', 'android.permission.ACCESS_FINE_LOCATION', 'location.device');
      const capB1 = await discoverCanonicalCap(sec1, `${probeApp}.n`, 'android', 'android.permission.POST_NOTIFICATIONS', 'notifications.post');

      await sec1.setGrant(appA, capA1, 'allow');
      await sec1.checkPermission({ appId: appA, pid: 1, platform: 'android', capability: capA1 });

      await sec1.setGrant(appA, capA2, 'deny');
      await sec1.checkPermission({ appId: appA, pid: 1, platform: 'ios', capability: capA2 });

      await sec1.setGrant(appB, capB1, 'allow');
      await sec1.checkPermission({ appId: appB, pid: 1, platform: 'windows', capability: capB1 });

      const log1 = await sec1.getAuditLog({ appId: appA, limit: 50 });
      assert.ok(Array.isArray(log1) && log1.length >= 2, `Expected >= 2 audit entries for ${appA}, got ${JSON.stringify(log1)}`);
      for (const entry of log1) {
        assert.equal(entry.appId, appA, `Per-app audit filter must exclude other apps (got ${entry.appId})`);
      }
      const log1Str = JSON.stringify(log1);
      assert.ok(log1Str.includes(capA1), `Audit log must record allowed ${capA1} check`);
      assert.ok(log1Str.includes(capA2), `Audit log must record denied ${capA2} check`);

      await os1.shutdown();
      os1 = null;

      // Reboot on identical dataDir and verify SQLite persistence of BOTH audit log AND grants
      os2 = await loadPublicOmniOS({ dataDir: tmp.dir, keepDataDir: true });
      const sec2 = os2.require('security');

      const log2 = await sec2.getAuditLog({ appId: appA, limit: 50 });
      assert.ok(Array.isArray(log2) && log2.length >= 2, 'SQLite security audit log must persist across reboot');
      const log2Str = JSON.stringify(log2);
      assert.ok(log2Str.includes(capA1) && log2Str.includes(capA2));

      const recheckAllow = await sec2.checkPermission({ appId: appA, pid: 1, platform: 'android', capability: capA1 });
      assert.equal(recheckAllow?.granted, true, 'Persisted allow grant must survive reboot');
      const recheckDeny = await sec2.checkPermission({ appId: appA, pid: 1, platform: 'ios', capability: capA2 });
      assert.equal(recheckDeny?.granted, false, 'Persisted deny grant must survive reboot');
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await tmp.cleanup();
    }
  });

  test('T6 [F-027, F-028, Contract 7]: Live HTTP REST /api/v1/security/{users,permissions,audit}', async () => {
    const tmp = await createTempDataDir('omnios-fa07-rest-');
    let osSeed = null;
    let srv = null;
    try {
      const tok = makeToken();
      const appId = `com.rest.perm.${tok}`;

      // Trigger a real Contract 4 permission check in SQLite first so /api/v1/security/audit is verified non-vacuously
      osSeed = await loadPublicOmniOS({ dataDir: tmp.dir, keepDataDir: true });
      const secSeed = osSeed.require('security');
      const targetCap = await discoverCanonicalCap(
        secSeed,
        `com.rest.probe.${tok}`,
        'android',
        'android.permission.POST_NOTIFICATIONS',
        'notifications.post'
      );
      await secSeed.setGrant(appId, targetCap, 'allow');
      const seededCheck = await secSeed.checkPermission({
        appId,
        pid: 1,
        platform: 'android',
        capability: targetCap,
      });
      assert.equal(seededCheck?.granted, true, `Seeded checkPermission for ${targetCap} must succeed`);
      await osSeed.shutdown();
      osSeed = null;

      srv = await startOmniServer({ dataDir: tmp.dir, keepDataDir: true });

      const usersRes = await srv.api.get('/api/v1/security/users');
      assert.equal(usersRes.status, 200);
      const users = unwrapExplicitArray(usersRes.json, ['users', 'items', 'data', 'list']);
      assert.ok(Array.isArray(users), `GET /api/v1/security/users must return an explicit JSON array, got: ${usersRes.text}`);
      assert.ok(users.some((u) => u?.uid === 0), 'GET /api/v1/security/users must include root (uid 0)');
      assert.ok(users.some((u) => u?.uid === 1000), 'GET /api/v1/security/users must include user (uid 1000)');

      // Update grant to deny via REST
      const setDeny = await restMutate(srv.api, '/api/v1/security/permissions', {
        appId,
        capability: targetCap,
        state: 'deny',
        decision: 'deny',
      });
      assert.ok(setDeny.ok, `Setting permission deny failed (${setDeny.status}): ${setDeny.text}`);

      const getDeny = await srv.api.get('/api/v1/security/permissions', { query: { appId } });
      assert.equal(getDeny.status, 200);
      assert.ok(
        getDeny.text.includes(targetCap) && getDeny.text.includes('deny'),
        `GET /api/v1/security/permissions must reflect updated deny state for ${targetCap}: ${getDeny.text}`
      );

      // Update grant back to allow via REST
      const setAllow = await restMutate(srv.api, '/api/v1/security/permissions', {
        appId,
        capability: targetCap,
        state: 'allow',
        decision: 'allow',
      });
      assert.ok(setAllow.ok, `Setting permission allow failed (${setAllow.status}): ${setAllow.text}`);

      const getAllow = await srv.api.get('/api/v1/security/permissions', { query: { appId } });
      assert.equal(getAllow.status, 200);
      assert.ok(
        getAllow.text.includes(targetCap) && getAllow.text.includes('allow'),
        `GET /api/v1/security/permissions must reflect allow state for ${targetCap}: ${getAllow.text}`
      );

      // Audit log endpoint MUST return an explicit array containing the real permission check entry for appId
      const auditRes = await srv.api.get('/api/v1/security/audit', { query: { appId, limit: 50 } });
      assert.equal(auditRes.status, 200);
      const auditEntries = unwrapExplicitArray(auditRes.json, ['entries', 'audit', 'logs', 'items', 'data', 'list']);
      assert.ok(
        Array.isArray(auditEntries),
        `GET /api/v1/security/audit must return an explicit JSON array/list field, got: ${auditRes.text}`
      );
      assert.ok(
        auditEntries.length >= 1 && auditEntries.some((e) => e?.appId === appId),
        `GET /api/v1/security/audit must contain recorded permission check for "${appId}", got: ${JSON.stringify(auditEntries)}`
      );
    } finally {
      await osSeed?.shutdown();
      await srv?.stop();
      await tmp.cleanup();
    }
  });
});
