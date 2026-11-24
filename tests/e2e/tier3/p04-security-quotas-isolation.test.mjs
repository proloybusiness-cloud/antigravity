/**
 * OmniOS Tier 3 Pairwise E2E Suite — P-04:
 * Unified Permission Broker (deny/allow/prompt + Audit Log) × VFS/HKLM/IPC Enforcement
 * × Runaway CPU / __PAGEZERO SIGSEGV / Memory Quota ENOMEM / Deep Recursion / Malformed Package Isolation.
 *
 * Feature Pairs Exercised:
 *   F-011, F-012, F-013, F-014, F-021, F-023, F-027, F-028, F-032, F-035,
 *   F-039, F-041, F-043, F-048, F-050, F-054, F-062 (Edge Cases #1, #11, #12, #20, #21)
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded system app IDs or undocumented capability names.
 * - Zero assertions inside try/catch blocks.
 * - 405-only method fallback on negative REST assertions.
 * - Clean try/finally teardown on every test.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';

import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';
import {
  buildCustomApk,
  buildCustomPe64Exe,
} from '../lib/fixtures-android-win.mjs';
import {
  buildCustomIpa,
  buildCustomMacAppZip,
  buildCustomUapp,
} from '../lib/fixtures-apple-wasm.mjs';
import {
  buildDexDeepRecursionApk,
  buildDexInfiniteLoopApk,
  buildFairPlayEncryptedIpa,
  buildMalformedPe,
  buildPageZeroDerefMachO,
  buildZipSlipArchive,
} from '../lib/fixtures-malformed.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function makeSmallOperands() {
  const a = 11 + crypto.randomInt(40);
  const b = 13 + crypto.randomInt(40);
  const c = 7 + crypto.randomInt(50);
  return [a, b, c];
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

function unwrapExplicitArray(payload, keys = ['audit', 'entries', 'items', 'users', 'permissions', 'grants', 'packages', 'apps', 'catalog', 'data']) {
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

function extractCapabilitiesFromPayload(payload) {
  const found = [];
  const walk = (node, depth = 0) => {
    if (!node || depth > 5) return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    if (typeof node === 'object') {
      for (const field of ['capability', 'canonicalCapability']) {
        if (typeof node[field] === 'string' && node[field].length > 0) found.push(node[field]);
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
        const META_KEYS = new Set(['appId', 'id', 'platform', 'reason', 'state', 'policy', 'capability', 'canonicalCapability', 'updatedAt', 'createdAt', 'granted']);
        for (const [k, v] of Object.entries(node.grants)) {
          if (k.length > 0 && typeof v === 'string' && !META_KEYS.has(k)) {
            found.push(k);
          } else if (Array.isArray(v)) {
            walk(v, depth + 1);
          } else if (v && typeof v === 'object') {
            if ((typeof v.state === 'string' || typeof v.policy === 'string') && !v.capability && !v.canonicalCapability) {
              if (k.length > 0 && !META_KEYS.has(k)) found.push(k);
            } else {
              for (const [innerK, innerV] of Object.entries(v)) {
                if (innerK.length > 0 && !META_KEYS.has(innerK)) {
                  if (typeof innerV === 'string') {
                    found.push(innerK);
                  } else if (innerV && typeof innerV === 'object' && !Array.isArray(innerV) && (typeof innerV.state === 'string' || typeof innerV.policy === 'string')) {
                    found.push(innerV.capability ?? innerV.canonicalCapability ?? innerK);
                  }
                }
              }
            }
            walk(v, depth + 1);
          }
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

function extractGrantState(payload, appId, cap) {
  if (!payload || typeof payload !== 'object') return null;

  const readStateFromObj = (obj) => {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
    for (const k of ['state', 'policy', 'grant', 'decision', 'status']) {
      if (typeof obj[k] === 'string' && /^(allow|deny|prompt)$/i.test(obj[k])) {
        return obj[k].toLowerCase();
      }
    }
    return null;
  };

  const inspectCapMap = (map) => {
    if (!map || typeof map !== 'object' || Array.isArray(map)) return null;
    if (!(cap in map)) return null;
    const v = map[cap];
    if (typeof v === 'string' && /^(allow|deny|prompt)$/i.test(v)) return v.toLowerCase();
    return readStateFromObj(v);
  };

  const inspectArray = (arr, scopedAppId, depth) => {
    if (!Array.isArray(arr)) return null;
    for (const item of arr) {
      if (!item || typeof item !== 'object') continue;
      const itemApp = item.appId ?? item.app ?? item.packageName ?? scopedAppId;
      const itemCap = item.capability ?? item.canonicalCapability ?? item.cap ?? item.name;
      if ((itemApp === null || itemApp === appId) && itemCap === cap) {
        const st = readStateFromObj(item);
        if (st) return st;
      }
      if (itemApp === appId && !itemCap && (item.grants || item.permissions)) {
        const nested = walk(item, appId, depth + 1);
        if (nested) return nested;
      }
    }
    return null;
  };

  const walk = (node, scopedAppId = null, depth = 0) => {
    if (!node || depth > 5) return null;
    if (Array.isArray(node)) return inspectArray(node, scopedAppId, depth);
    if (typeof node !== 'object') return null;

    const currentApp = typeof node.appId === 'string' ? node.appId : scopedAppId;

    if (node[appId] && typeof node[appId] === 'object') {
      const hit = Array.isArray(node[appId])
        ? inspectArray(node[appId], appId, depth + 1)
        : inspectCapMap(node[appId]) ?? walk(node[appId], appId, depth + 1);
      if (hit) return hit;
    }

    if (currentApp === null || currentApp === appId) {
      const directCap = inspectCapMap(node);
      if (directCap) return directCap;
    }

    for (const key of ['data', 'grants', 'permissions', 'entries', 'items', 'records', 'result']) {
      if (node[key] !== undefined) {
        const hit = walk(node[key], currentApp, depth + 1);
        if (hit) return hit;
      }
    }

    return null;
  };

  return walk(payload);
}

/**
 * Dynamically discovers a canonical capability mapped from a native platform permission.
 * Strictly rejects untranslated echoes (mapped === nativePermission) or "unknown".
 */
async function discoverCanonicalCap(security, probeAppId, platform, nativePermission, pkgManager = null) {
  const probe = await security.checkPermission({
    appId: probeAppId,
    pid: 1,
    platform,
    nativePermission,
  });

  const isTranslated = (cap) =>
    typeof cap === 'string' &&
    cap.length > 0 &&
    cap !== nativePermission &&
    !/^unknown$/i.test(cap.trim());

  const direct = probe?.capability ?? probe?.canonicalCapability;
  if (isTranslated(direct)) return direct;

  const logs = await security.getAuditLog({ appId: probeAppId, limit: 15 });
  if (Array.isArray(logs)) {
    const fromLog = logs
      .map((e) => e?.capability ?? e?.canonicalCapability ?? e?.cap)
      .find(isTranslated);
    if (fromLog) return fromLog;
  }

  if (pkgManager && typeof pkgManager.inspect === 'function' && platform === 'android') {
    const apk = buildCustomApk({
      packageName: `${probeAppId}.insp`,
      appLabel: 'CapInspect',
      permissions: [nativePermission],
    });
    const insp = await pkgManager.inspect(apk);
    const fromInsp = extractCapabilitiesFromPayload(insp).find(isTranslated);
    if (fromInsp) return fromInsp;
  }

  assert.fail(
    `PermissionBroker failed to map native permission "${nativePermission}" (${platform}) to a canonical capability ` +
    `(probe=${JSON.stringify(probe)}, auditLogs=${JSON.stringify(logs)})`
  );
}

async function discoverValidCapabilityRest(api, nonce) {
  const permRes = await api.get('/api/v1/security/permissions');
  if (permRes.ok && permRes.json) {
    const caps = extractCapabilitiesFromPayload(permRes.json).filter((c) => !/^unknown$/i.test(c));
    if (caps.length > 0) return caps[0];
  }

  const probePkg = `com.p04.restcap.${nonce}`;
  const apkBytes = buildCustomApk({
    packageName: probePkg,
    appLabel: `P04Cap${nonce}`,
    permissions: ['android.permission.CAMERA'],
  });
  const instRes = await installPackageHttp(api, apkBytes, `${probePkg}.apk`);
  if (instRes.ok && instRes.json) {
    const caps = extractCapabilitiesFromPayload(instRes.json).filter((c) => c !== 'android.permission.CAMERA' && !/^unknown$/i.test(c));
    if (caps.length > 0) return caps[0];
  }

  for (const query of [{ appId: probePkg }, undefined]) {
    const r = await api.get('/api/v1/security/permissions', query ? { query } : {});
    if (r.ok && r.json) {
      const caps = extractCapabilitiesFromPayload(r.json).filter((c) => c !== 'android.permission.CAMERA' && !/^unknown$/i.test(c));
      if (caps.length > 0) return caps[0];
    }
  }

  assert.fail(`Unable to dynamically discover canonical capability via REST /api/v1/security/permissions (permRes=${permRes.status})`);
}

async function installPackageHttp(api, bytes, filename, { grantAll = true } = {}) {
  const buf = bytes instanceof Uint8Array ? bytes : Buffer.from(String(bytes), 'utf8');
  let res = await api.post('/api/v1/packages/install', buf, {
    query: { filename, grantAll: String(grantAll) },
    headers: { 'content-type': 'application/octet-stream', 'x-filename': filename },
  });
  if (res.status === 415 || res.status === 400) {
    // Only fall back to JSON envelope if raw octet-stream isn't accepted for valid packages
    const b64 = Buffer.from(buf).toString('base64');
    const jsonRes = await api.post('/api/v1/packages/install', {
      filename,
      grantAll,
      base64: b64,
      data: b64,
      buffer: b64,
    });
    if (jsonRes.ok) return jsonRes;
  }
  return res;
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

async function restNegative405Only(api, methods, urlPath, body, opts = {}) {
  let lastRes = null;
  for (const method of methods) {
    const res = await api.request(method, urlPath, { ...opts, body });
    lastRes = res;
    if (res.status !== 405) return res;
  }
  return lastRes;
}

async function resolveSandboxUid(osHandle, appId, installedRecord) {
  const fromRec = installedRecord?.sandboxUid ?? installedRecord?.uid;
  if (Number.isInteger(fromRec) && fromRec >= 10000) return fromRec;

  const pkg = await osHandle.require('pkgManager').get(appId);
  const fromPkg = pkg?.sandboxUid ?? pkg?.uid;
  if (Number.isInteger(fromPkg) && fromPkg >= 10000) return fromPkg;

  const users = osHandle.users ?? osHandle.raw?.users ?? osHandle.raw?.security?.users;
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

function extractAppId(rec, fallback = null) {
  return rec?.appId ?? rec?.id ?? rec?.packageName ?? rec?.bundleId ?? rec?.package?.appId ?? rec?.data?.appId ?? fallback;
}

function extractPid(launchRes) {
  const pid = launchRes?.pid ?? launchRes?.process?.pid ?? launchRes?.data?.pid;
  assert.ok(Number.isInteger(pid) && pid > 0, `Expected positive PID from launch(), got ${JSON.stringify(launchRes)}`);
  return pid;
}

function extractStdout(pcb) {
  const raw = pcb?.streams?.stdout ?? pcb?.stdout ?? '';
  if (typeof raw === 'string') return raw;
  if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) return Buffer.from(raw).toString('utf8');
  if (Array.isArray(raw)) {
    return raw.map((c) => (Buffer.isBuffer(c) || c instanceof Uint8Array ? Buffer.from(c).toString('utf8') : String(c ?? ''))).join('');
  }
  return String(raw ?? '');
}

function extractExitCode(pcb) {
  const code = pcb?.stats?.exitCode ?? pcb?.exitCode;
  return code === undefined || code === null ? null : Number(code);
}

function isTerminated(pcb) {
  return !pcb || pcb.state === 'TERMINATED' || pcb.state === 'ZOMBIE' || pcb.state === 'FAULT';
}

function makeYieldingContext() {
  const ctx = {
    steps: 0,
    disposed: false,
    step(budget) {
      ctx.steps += 1;
      return { status: 'YIELD', instructionsExecuted: Math.max(1, Number(budget) || 1) };
    },
    deliverEvent() {},
    getDebugState() {
      return { arch: 'wasm', pc: ctx.steps, sp: 0, registers: {}, instructionsExecuted: ctx.steps, lastSyscall: null, stackTop: 0 };
    },
    dispose() {
      ctx.disposed = true;
    },
  };
  return ctx;
}

async function stepUntil(osHandle, pred, minSteps = 120) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  const limit = Math.max(minSteps, pm.list().length * 25);
  for (let i = 0; i < limit; i++) {
    if (await pred()) return true;
    await scheduler.step(1);
  }
  return Boolean(await pred());
}

async function discoverBuiltinAppHttp(api) {
  const pkgRes = await api.get('/api/v1/packages', { expectOk: true });
  const pkgArr = unwrapExplicitArray(pkgRes.json, ['packages', 'apps', 'items', 'data']) ?? [];
  const sysArr = unwrapExplicitArray(pkgRes.json, ['systemApps']) ?? [];
  const arr = [...pkgArr, ...sysArr];
  const match =
    arr.find((p) => /omninotes|notes|omniterm|terminal/i.test(`${p?.appId ?? p?.id ?? ''} ${p?.name ?? p?.title ?? ''}`) && !/sharer/i.test(`${p?.appId ?? ''} ${p?.name ?? ''}`)) ??
    arr.find((p) => p?.builtin || p?.builtIn || p?.isSystem || p?.system || p?.platform === 'system') ??
    arr[0];
  const id = match?.appId ?? match?.id ?? null;
  assert.ok(id, `Must dynamically discover a built-in system app from /api/v1/packages (got ${pkgRes.text})`);
  return id;
}

function getAddressSpace(pcb) {
  const as = pcb?.addressSpace ?? pcb?.vmm ?? pcb?.memory ?? null;
  assert.ok(as && typeof as.mmap === 'function', `PCB missing IAddressSpace contract (got ${JSON.stringify(Object.keys(pcb ?? {}))})`);
  return as;
}

describe('Tier 3 — P-04: Security Permission Broker, Audit Log, Resource Quotas & Fault Process Isolation', () => {
  test('T3-P04-01 [F-028]: Permission Broker Full Lifecycle (deny -> allow -> prompt) x Cross-Platform Native Mapping Parity (Android <-> iOS) x Per-App Audit Log', async () => {
    const os = await loadPublicOmniOS();
    try {
      const security = os.require('security');
      const pkgManager = os.require('pkgManager');
      const nonce = makeNonce();

      // Dynamically discover canonical capability for Android CAMERA and verify iOS NSCameraUsageDescription maps identically
      const camCap = await discoverCanonicalCap(security, `com.p04.camand.${nonce}`, 'android', 'android.permission.CAMERA', pkgManager);
      const iosCamCap = await discoverCanonicalCap(security, `com.p04.camios.${nonce}`, 'ios', 'NSCameraUsageDescription', pkgManager);
      assert.equal(iosCamCap, camCap, `Android CAMERA (${camCap}) and iOS NSCameraUsageDescription (${iosCamCap}) must map to identical canonical capability`);
      assert.notEqual(camCap, 'android.permission.CAMERA', 'Canonical capability must not be an untranslated echo');

      // Discover a second distinct capability
      const storageCap = await discoverCanonicalCap(
        security,
        `com.p04.stor.${nonce}`,
        'android',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        pkgManager
      );
      assert.notEqual(storageCap, camCap, 'Storage and Camera native permissions must map to distinct canonical capabilities');

      const appA = `com.p04.appa.${nonce}`;
      const appB = `com.p04.appb.${nonce}`;
      await pkgManager.install(buildCustomApk({ packageName: appA, appLabel: `AppA${nonce}`, permissions: ['android.permission.CAMERA'] }), {
        filename: `p04-a-${nonce}.apk`,
        grantAll: false,
      });
      await pkgManager.install(buildCustomUapp({ appId: appB, name: `AppB${nonce}`, message: `B_${nonce}\n` }), {
        filename: `p04-b-${nonce}.uapp`,
        grantAll: true,
      });

      // 1. deny -> checkPermission must return granted: false, policy: 'deny' + append audit record
      await security.setGrant(appA, camCap, 'deny');
      const denyDec = await security.checkPermission({ appId: appA, pid: 1, platform: 'android', capability: camCap });
      assert.equal(denyDec?.granted, false, `Denied capability must return granted===false (got ${JSON.stringify(denyDec)})`);
      assert.equal(denyDec?.policy, 'deny', `Denied capability must report policy==="deny" (got ${JSON.stringify(denyDec)})`);

      const auditAfterDeny = await security.getAuditLog({ appId: appA, limit: 50 });
      assert.ok(Array.isArray(auditAfterDeny) && auditAfterDeny.length >= 1, 'Audit log must record denied check');

      // 2. allow -> checkPermission must return granted: true, policy: 'allow' + append audit record
      await security.setGrant(appA, camCap, 'allow');
      const allowDec = await security.checkPermission({ appId: appA, pid: 1, platform: 'android', capability: camCap });
      assert.equal(allowDec?.granted, true, `Allowed capability must return granted===true (got ${JSON.stringify(allowDec)})`);
      assert.equal(allowDec?.policy, 'allow', `Allowed capability must report policy==="allow" (got ${JSON.stringify(allowDec)})`);

      const auditAfterAllow = await security.getAuditLog({ appId: appA, limit: 50 });
      assert.ok(
        auditAfterAllow.length > auditAfterDeny.length,
        `Audit log must append a new entry for allow decision (before=${auditAfterDeny.length}, after=${auditAfterAllow.length})`
      );

      // 3. prompt -> checkPermission must never auto-grant pending user decision
      await security.setGrant(appA, camCap, 'prompt');
      const promptDec = await security.checkPermission({ appId: appA, pid: 1, platform: 'android', capability: camCap });
      assert.equal(
        promptDec?.granted,
        false,
        `Prompt policy must return granted===false pending user decision (got ${JSON.stringify(promptDec)})`
      );

      // 4. Strict per-app audit filtering: appB's audit log must NOT leak appA's entries
      const auditB = await security.getAuditLog({ appId: appB, limit: 50 });
      assert.ok(Array.isArray(auditB), 'getAuditLog({ appId: appB }) must return an array');
      assert.equal(
        auditB.some((e) => e?.appId === appA),
        false,
        `Audit log filtered for ${appB} must NEVER include entries belonging to ${appA}`
      );
    } finally {
      await os.shutdown();
    }
  });

  test('T3-P04-02 [F-021, F-023, F-027, F-028, F-062]: Security Enforcement Across VFS (Sandbox UID EACCES + Permission Broker Grant), HKLM Virtualization & REST /api/v1/security/*', async () => {
    const nonce = makeNonce();
    let os = null;
    let srv = null;
    const pids = [];
    try {
      // Part A: Programmatic VFS container EACCES + Permission Broker deny->allow + HKLM virtualization
      os = await loadPublicOmniOS();
      os.require('scheduler').stop?.();
      const vfs = os.require('vfs');
      const security = os.require('security');
      const pkgManager = os.require('pkgManager');
      const reg = os.require('configStore').registry;
      const rootCtx = { uid: 0, gid: 0, platform: 'posix' };

      const andApp = `com.p04.vfsand.${nonce}`;
      const uappB = `com.p04.vfsuapp.${nonce}`;
      const permOutPath = `/sdcard/Documents/perm-ok-${nonce}.txt`;
      const permCanonPath = `/home/user/Documents/perm-ok-${nonce}.txt`;
      const permBody = `PERM_OK_${nonce}`;

      const recA = await pkgManager.install(
        buildCustomApk({
          packageName: andApp,
          appLabel: `PermAnd${nonce}`,
          permissions: ['android.permission.WRITE_EXTERNAL_STORAGE'],
          outputFile: permOutPath,
          outputContent: permBody,
        }),
        { filename: `p04-vfsand-${nonce}.apk`, grantAll: false }
      );
      const recB = await pkgManager.install(
        buildCustomUapp({ appId: uappB, name: `PermUapp${nonce}`, message: `UB_${nonce}\n` }),
        { filename: `p04-vfsuapp-${nonce}.uapp`, grantAll: true }
      );

      const uidA = await resolveSandboxUid(os, extractAppId(recA, andApp), recA);
      const uidB = await resolveSandboxUid(os, extractAppId(recB, uappB), recB);
      assert.ok(Number.isInteger(uidA) && uidA >= 10000, `App A needs sandbox UID >= 10000 (got ${uidA})`);
      assert.ok(Number.isInteger(uidB) && uidB >= 10000, `App B needs sandbox UID >= 10000 (got ${uidB})`);
      assert.notEqual(uidA, uidB, 'Apps must get distinct sandbox UIDs');

      // Private vault owned by uidA:uidA (0o700 / 0o600) -> uidB MUST receive EACCES on read, write, unlink
      const vaultDir = `/var/appdata/android/${andApp}`;
      const vaultFile = `${vaultDir}/vault-${nonce}.txt`;
      await vfs.mkdir(vaultDir, { recursive: true, mode: 0o700, ...rootCtx });
      await vfs.chown(vaultDir, uidA, uidA, rootCtx);
      await vfs.chmod(vaultDir, 0o700, rootCtx);
      await vfs.writeFile(vaultFile, `VAULT_${nonce}`, { mode: 0o600, ...rootCtx });
      await vfs.chown(vaultFile, uidA, uidA, rootCtx);
      await vfs.chmod(vaultFile, 0o600, rootCtx);

      const ctxB = { uid: uidB, gid: uidB, platform: 'posix', appId: uappB };
      for (const [opName, fn] of [
        ['readFile', () => vfs.readFile(vaultFile, { encoding: 'utf8', ...ctxB })],
        ['writeFile', () => vfs.writeFile(vaultFile, 'TAMPER', ctxB)],
        ['unlink', () => vfs.unlink(vaultFile, ctxB)],
      ]) {
        let err = null;
        try {
          await fn();
        } catch (e) {
          err = e;
        }
        assert.ok(err instanceof Error, `Cross-UID ${opName} on private vault must reject`);
        assert.equal(err.code, 'EACCES', `Cross-UID ${opName} must throw EACCES (got ${err.code})`);
      }

      // Permission Broker deny -> allow -> real Android binary writes /sdcard/Documents/perm-ok-<nonce>.txt
      const writeCap = await discoverCanonicalCap(security, `com.p04.wprobe.${nonce}`, 'android', 'android.permission.WRITE_EXTERNAL_STORAGE', pkgManager);
      await security.setGrant(andApp, writeCap, 'deny');
      const deniedCheck = await security.checkPermission({ appId: andApp, pid: 1, platform: 'android', capability: writeCap });
      assert.equal(deniedCheck?.granted, false, 'Denied storage write capability must report granted===false');

      await security.setGrant(andApp, writeCap, 'allow');
      const allowedCheck = await security.checkPermission({ appId: andApp, pid: 1, platform: 'android', capability: writeCap });
      assert.equal(allowedCheck?.granted, true, 'Granted storage write capability must report granted===true');

      const andPid = extractPid(await pkgManager.launch(extractAppId(recA, andApp), {}));
      pids.push(andPid);
      const wrote = await stepUntil(os, async () => {
        try {
          return (await vfs.readFile(permCanonPath, { platform: 'posix', encoding: 'utf8' })) === permBody;
        } catch {
          return false;
        }
      }, 300);
      assert.equal(wrote, true, `Android app granted ${writeCap} must write ${permCanonPath}`);

      // HKLM virtualization isolation under uidB
      const hklmPath = `Software\\OmniP04\\${nonce}`;
      await reg.setValue('HKLM', hklmPath, 'Sec', 'REG_SZ', `ROOT_${nonce}`, { uid: 0, gid: 0, privileged: true });
      await reg.setValue('HKLM', hklmPath, 'Sec', 'REG_SZ', `UNPRIV_${nonce}`, { uid: uidB, gid: uidB, appId: uappB, privileged: false });
      assert.equal(
        (await reg.getValue('HKLM', hklmPath, 'Sec', { uid: 0, gid: 0, privileged: true }))?.data,
        `ROOT_${nonce}`,
        'Root HKLM view must stay isolated from unprivileged sandbox writes'
      );

      for (const pid of pids) {
        try {
          await os.require('processManager').kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
      pids.length = 0;
      await os.shutdown();
      os = null;

      // Part B: Live HTTP REST /api/v1/security/{users,permissions,audit}
      srv = await startOmniServer();
      const usersRes = await srv.api.get('/api/v1/security/users', { expectOk: true });
      const usersArr = unwrapExplicitArray(usersRes.json, ['users', 'items', 'data']);
      assert.ok(Array.isArray(usersArr), `GET /api/v1/security/users must return explicit array (got ${usersRes.text})`);
      assert.ok(usersArr.some((u) => u?.uid === 0 || u?.name === 'root'), 'Security users must expose root (uid 0)');
      assert.ok(usersArr.some((u) => u?.uid === 1000 || u?.name === 'user'), 'Security users must expose user (uid 1000)');

      const restCap = await discoverValidCapabilityRest(srv.api, nonce);
      const restApp = `com.p04.restapp.${nonce}`;
      const denyPut = await restMutate(srv.api, '/api/v1/security/permissions', {
        appId: restApp,
        capability: restCap,
        state: 'deny',
        policy: 'deny',
      });
      assert.ok(denyPut.ok, `Setting REST permission grant=deny must succeed (got ${denyPut.status}: ${denyPut.text})`);

      const getDeniedPerms = await srv.api.get('/api/v1/security/permissions', { query: { appId: restApp }, expectOk: true });
      const deniedGrantState = extractGrantState(getDeniedPerms.json, restApp, restCap);
      assert.equal(
        deniedGrantState,
        'deny',
        `GET /api/v1/security/permissions?appId=${restApp} must reflect "deny" for ${restCap} after denyPut (got ${getDeniedPerms.text})`
      );

      const allowPut = await restMutate(srv.api, '/api/v1/security/permissions', {
        appId: restApp,
        capability: restCap,
        state: 'allow',
        policy: 'allow',
      });
      assert.ok(allowPut.ok, `Setting REST permission grant=allow must succeed (got ${allowPut.status}: ${allowPut.text})`);

      const getPerms = await srv.api.get('/api/v1/security/permissions', { query: { appId: restApp }, expectOk: true });
      const allowedGrantState = extractGrantState(getPerms.json, restApp, restCap);
      assert.equal(
        allowedGrantState,
        'allow',
        `GET /api/v1/security/permissions?appId=${restApp} must reflect "allow" (not "deny") for ${restCap} after allowPut (got ${getPerms.text})`
      );

      const auditRes = await srv.api.get('/api/v1/security/audit', { expectOk: true });
      const auditArr = unwrapExplicitArray(auditRes.json, ['audit', 'entries', 'items', 'logs', 'data']);
      assert.ok(Array.isArray(auditArr) && auditArr.length >= 1, `GET /api/v1/security/audit must return non-empty array (got ${auditRes.text})`);
    } finally {
      if (os) {
        const pm = os.processManager;
        for (const pid of pids) {
          try {
            const pcb = pm?.get?.(pid);
            if (pcb && !isTerminated(pcb)) await pm.kill(pid, 'SIGKILL');
          } catch {
            // ignore
          }
        }
        await os.shutdown();
      }
      await srv?.stop();
    }
  });

  test('T3-P04-03 [F-011, F-039, F-043, F-050, F-054]: Runaway Dalvik Infinite Loop (E_CPU_QUOTA/SIGXCPU) Alongside 3 Healthy Multi-Platform Binaries (Win PE32+ + macOS + iOS) & Yielding Sibling', async () => {
    const os = await loadPublicOmniOS();
    const pids = [];
    try {
      const scheduler = os.require('scheduler');
      scheduler.stop?.();
      const kernel = os.require('kernel');
      const vfs = os.require('vfs');
      const pm = os.require('processManager');
      const pkgManager = os.require('pkgManager');

      const nonce = makeNonce();
      const [a, b, c] = makeSmallOperands();

      // Continuous yielding sibling process
      const keepAliveCtx = makeYieldingContext();
      const keepAlivePcb = pm.spawn({
        name: `keepalive-${nonce}`,
        appId: `com.p04.keep.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        cwd: '/home/user',
        priority: 10,
        executionContext: keepAliveCtx,
      });
      pids.push(keepAlivePcb.pid);
      const started = await stepUntil(os, () => keepAliveCtx.steps > 0, 80);
      assert.equal(started, true, 'Continuous sibling must begin stepping before runaway launch');

      // Install 4 binaries: 1 runaway Dalvik infinite loop + 3 healthy platforms
      const loopRec = await pkgManager.install(buildDexInfiniteLoopApk(), {
        filename: `p04-loop-${nonce}.apk`,
        grantAll: true,
      });
      const winRec = await pkgManager.install(
        buildCustomPe64Exe({ subsystem: 3, message: `WIN_ALIVE_${nonce}\n`, computeExitSum: [a, b] }),
        { filename: `p04-win-${nonce}.exe`, grantAll: true }
      );
      const macFile = `/Users/user/Documents/mac-alive-${nonce}.txt`;
      const macCanon = `/home/user/Documents/mac-alive-${nonce}.txt`;
      const macRec = await pkgManager.install(
        buildCustomMacAppZip({
          bundleId: `com.p04.mac.${nonce}`,
          appName: `MacIso${nonce}`,
          executableName: `MacIso${nonce}`,
          arch: 'universal',
          fileWrite: { path: macFile, content: `MAC_ALIVE_${nonce}` },
          exitCode: 0,
        }),
        { filename: `p04-mac-${nonce}.app.zip`, grantAll: true }
      );
      const iosRec = await pkgManager.install(
        buildCustomIpa({
          bundleId: `com.p04.ios.${nonce}`,
          displayName: `IosIso${nonce}`,
          executableName: `IosIso${nonce}`,
          message: `IOS_ALIVE_${nonce}\n`,
          exitCode: c,
        }),
        { filename: `p04-ios-${nonce}.ipa`, grantAll: true }
      );

      // Launch all 4 concurrently
      const loopPid = extractPid(await pkgManager.launch(extractAppId(loopRec, 'com.omnios.infloop'), {}));
      const winPid = extractPid(await pkgManager.launch(extractAppId(winRec), {}));
      const macPid = extractPid(await pkgManager.launch(extractAppId(macRec, `com.p04.mac.${nonce}`), {}));
      const iosPid = extractPid(await pkgManager.launch(extractAppId(iosRec, `com.p04.ios.${nonce}`), {}));
      pids.push(loopPid, winPid, macPid, iosPid);

      // Deterministically step scheduler until all 4 binaries settle
      const maxTicks = Math.max(4000, pm.list().length * 100);
      for (let i = 0; i < Math.ceil(maxTicks / 10); i++) {
        await scheduler.step(10);
        if (
          isTerminated(pm.get(loopPid)) &&
          isTerminated(pm.get(winPid)) &&
          isTerminated(pm.get(macPid)) &&
          isTerminated(pm.get(iosPid))
        ) {
          break;
        }
      }

      // 1. Runaway Dalvik loop MUST terminate with CPU quota / SIGXCPU / non-zero fault
      const loopPcb = pm.get(loopPid);
      assert.equal(isTerminated(loopPcb), true, `Runaway Dalvik infinite loop PID ${loopPid} must terminate under quota`);
      const loopBlob = JSON.stringify({
        state: loopPcb?.state,
        signal: loopPcb?.signal ?? loopPcb?.exitSignal ?? loopPcb?.termSignal,
        fault: loopPcb?.fault ?? loopPcb?.lastFault ?? loopPcb?.error,
        exitCode: extractExitCode(loopPcb),
      });
      assert.ok(
        /QUOTA|SIGXCPU|CPU|TIMEOUT|FAULT/i.test(loopBlob) || (extractExitCode(loopPcb) !== null && extractExitCode(loopPcb) !== 0),
        `Runaway Dalvik loop must show CPU quota/SIGXCPU/non-zero fault (got ${loopBlob})`
      );

      // 2. All 3 healthy siblings completed with exact runtime-nonce results
      const winPcb = pm.get(winPid);
      assert.equal(isTerminated(winPcb), true, 'Windows sibling must complete cleanly');
      assert.ok(extractStdout(winPcb).includes(`WIN_ALIVE_${nonce}`), 'Windows sibling stdout must match runtime nonce');
      assert.equal(extractExitCode(winPcb), a + b, `Windows sibling must exit with computed sum ${a + b}`);

      const macPcb = pm.get(macPid);
      assert.equal(isTerminated(macPcb), true, 'macOS sibling must complete cleanly');
      assert.equal(extractExitCode(macPcb), 0, 'macOS sibling must exit 0');
      assert.equal(await vfs.readFile(macCanon, { platform: 'posix', encoding: 'utf8' }), `MAC_ALIVE_${nonce}`);

      const iosPcb = pm.get(iosPid);
      assert.equal(isTerminated(iosPcb), true, 'iOS sibling must complete cleanly');
      assert.ok(extractStdout(iosPcb).includes(`IOS_ALIVE_${nonce}`), 'iOS sibling stdout must match runtime nonce');
      assert.equal(extractExitCode(iosPcb), c, `iOS sibling must exit with runtime code ${c}`);

      // 3. Continuous yielding sibling STILL alive and advances after runaway kill; kernel RUNNING
      const stepsBefore = keepAliveCtx.steps;
      const alivePost = await stepUntil(os, () => keepAliveCtx.steps > stepsBefore, 80);
      assert.equal(alivePost, true, 'Continuous yielding sibling must continue stepping after runaway termination');
      assert.equal(isTerminated(pm.get(keepAlivePcb.pid)), false, 'Continuous sibling PCB must remain alive');
      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must remain RUNNING after isolating runaway Dalvik loop');
    } finally {
      const pm = os.processManager;
      for (const pid of pids) {
        try {
          const pcb = pm?.get?.(pid);
          if (pcb && !isTerminated(pcb)) await pm.kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
      await os.shutdown();
    }
  });

  test('T3-P04-04 [F-012, F-013, F-048, F-050, Edge Case #21]: Faulting ARM64 __PAGEZERO Dereference (SIGSEGV, <64MiB RSS) Alongside Healthy Android, Windows & Universal Siblings', async () => {
    const os = await loadPublicOmniOS();
    const pids = [];
    try {
      const scheduler = os.require('scheduler');
      scheduler.stop?.();
      const kernel = os.require('kernel');
      const vfs = os.require('vfs');
      const pm = os.require('processManager');
      const pkgManager = os.require('pkgManager');

      const nonce = makeNonce();
      const [a, b] = makeSmallOperands();
      const rssBefore = process.memoryUsage().rss;

      // Faulting iOS .ipa dereferencing __PAGEZERO (0x100)
      const pzBundle = `com.p04.pz.${nonce}`;
      const pzRec = await pkgManager.install(
        buildCustomIpa({
          bundleId: pzBundle,
          displayName: `PzFault${nonce}`,
          executableName: `PzFault${nonce}`,
          machoBytes: buildPageZeroDerefMachO({ addr: 0x100 }),
        }),
        { filename: `p04-pz-${nonce}.ipa`, grantAll: true }
      );

      // 3 healthy siblings: Android .apk, Windows PE32+ .exe, Universal .uapp
      const andPkg = `com.p04.andpz.${nonce}`;
      const andOut = `/sdcard/Documents/and-iso-${nonce}.txt`;
      const andCanon = `/home/user/Documents/and-iso-${nonce}.txt`;
      const andRec = await pkgManager.install(
        buildCustomApk({ packageName: andPkg, appLabel: `AndPz${nonce}`, computeA: a, computeB: b, computeOp: 'add', outputFile: andOut }),
        { filename: `p04-andpz-${nonce}.apk`, grantAll: true }
      );
      const winRec = await pkgManager.install(
        buildCustomPe64Exe({ subsystem: 3, message: `WIN_PZ_${nonce}\n`, exitCode: 0 }),
        { filename: `p04-winpz-${nonce}.exe`, grantAll: true }
      );
      const uappId = `com.p04.uapppz.${nonce}`;
      const uappRec = await pkgManager.install(
        buildCustomUapp({ appId: uappId, name: `UappPz${nonce}`, message: `UAPP_PZ_${nonce}\n`, exitCode: 0 }),
        { filename: `p04-uapppz-${nonce}.uapp`, grantAll: true }
      );

      const pzPid = extractPid(await pkgManager.launch(extractAppId(pzRec, pzBundle), {}));
      const andPid = extractPid(await pkgManager.launch(extractAppId(andRec, andPkg), {}));
      const winPid = extractPid(await pkgManager.launch(extractAppId(winRec), {}));
      const uappPid = extractPid(await pkgManager.launch(extractAppId(uappRec, uappId), {}));
      pids.push(pzPid, andPid, winPid, uappPid);

      // __PAGEZERO must be a non-allocating virtual guard (< 64 MiB RSS delta, NOT 4 GiB!)
      const rssDelta = process.memoryUsage().rss - rssBefore;
      assert.ok(
        rssDelta < 64 * 1024 * 1024,
        `__PAGEZERO guard must not allocate 4 GiB RAM (RSS delta=${(rssDelta / (1024 * 1024)).toFixed(1)} MiB)`
      );

      const maxTicks = Math.max(3000, pm.list().length * 80);
      for (let i = 0; i < Math.ceil(maxTicks / 10); i++) {
        await scheduler.step(10);
        let andDone = false;
        try {
          andDone = (await vfs.readFile(andCanon, { platform: 'posix', encoding: 'utf8' })).trim() === String(a + b);
        } catch {
          andDone = false;
        }
        if (isTerminated(pm.get(pzPid)) && isTerminated(pm.get(winPid)) && isTerminated(pm.get(uappPid)) && andDone) {
          break;
        }
      }

      // 1. Faulting iOS PID terminated with SIGSEGV / MemoryFaultError
      const pzPcb = pm.get(pzPid);
      assert.equal(isTerminated(pzPcb), true, `Faulting __PAGEZERO PID ${pzPid} must terminate`);
      const pzBlob = JSON.stringify({
        state: pzPcb?.state,
        signal: pzPcb?.signal ?? pzPcb?.exitSignal ?? pzPcb?.termSignal,
        fault: pzPcb?.fault ?? pzPcb?.lastFault ?? pzPcb?.error,
        exitCode: extractExitCode(pzPcb),
      });
      assert.ok(
        /SIGSEGV|SEGV|PAGEZERO|FAULT|MEMORY/i.test(pzBlob) || (extractExitCode(pzPcb) !== null && extractExitCode(pzPcb) !== 0),
        `__PAGEZERO dereference must fault with SIGSEGV/MemoryFault (got ${pzBlob})`
      );

      // 2. All 3 healthy siblings produced exact outputs
      assert.equal(
        (await vfs.readFile(andCanon, { platform: 'posix', encoding: 'utf8' })).trim(),
        String(a + b),
        `Android sibling must write ${a}+${b}=${a + b}`
      );
      const winPcb = pm.get(winPid);
      assert.equal(extractExitCode(winPcb), 0);
      assert.ok(extractStdout(winPcb).includes(`WIN_PZ_${nonce}`));

      const uappPcb = pm.get(uappPid);
      assert.equal(extractExitCode(uappPcb), 0);
      assert.ok(extractStdout(uappPcb).includes(`UAPP_PZ_${nonce}`));

      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must stay RUNNING after isolating __PAGEZERO SIGSEGV');
    } finally {
      const pm = os.processManager;
      for (const pid of pids) {
        try {
          const pcb = pm?.get?.(pid);
          if (pcb && !isTerminated(pcb)) await pm.kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
      await os.shutdown();
    }
  });

  test('T3-P04-05 [F-011, F-012, F-013, F-014, F-039]: Per-PID Memory Quota (ENOMEM) + Deep Recursion Fault + Cross-PID Virtual Address Space Isolation', async () => {
    const os = await loadPublicOmniOS();
    const pids = [];
    try {
      const scheduler = os.require('scheduler');
      scheduler.stop?.();
      const kernel = os.require('kernel');
      const pm = os.require('processManager');
      const pkgManager = os.require('pkgManager');
      const nonce = makeNonce();

      const healthyCtx = makeYieldingContext();
      const quotaCtx = makeYieldingContext();
      const procHealthy = pm.spawn({
        name: `vmm-healthy-${nonce}`,
        appId: `com.p04.vmmh.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        cwd: '/home/user',
        quotas: { maxMemoryBytes: 4 * 1024 * 1024 },
        executionContext: healthyCtx,
      });
      const procQuota = pm.spawn({
        name: `vmm-quota-${nonce}`,
        appId: `com.p04.vmmq.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        cwd: '/home/user',
        quotas: { maxMemoryBytes: 64 * 1024 },
        executionContext: quotaCtx,
      });
      pids.push(procHealthy.pid, procQuota.pid);

      const asHealthy = getAddressSpace(procHealthy);
      const asQuota = getAddressSpace(procQuota);
      const PROT_RW = 1 | 2; // PROT_READ | PROT_WRITE

      // Map identical VA 0x00400000 in both PIDs and verify strict per-PID memory isolation
      const secretBytes = crypto.randomBytes(32);
      const otherBytes = Buffer.alloc(32, 0xa5);
      asHealthy.mmap(0x00400000, 4096, PROT_RW, 'healthy-secret');
      asHealthy.write(0x00400000, secretBytes);

      asQuota.mmap(0x00400000, 4096, PROT_RW, 'quota-other');
      asQuota.write(0x00400000, otherBytes);

      const readQuota = Buffer.from(asQuota.read(0x00400000, 32));
      const readHealthy = Buffer.from(asHealthy.read(0x00400000, 32));
      assert.equal(Buffer.compare(readQuota, otherBytes), 0, 'procQuota must read only its own virtual page');
      assert.notEqual(Buffer.compare(readQuota, secretBytes), 0, 'procQuota must NEVER observe procHealthy memory at identical VA');
      assert.equal(Buffer.compare(readHealthy, secretBytes), 0, 'procHealthy memory must remain untouched');

      // Exhaust procQuota's 64 KiB memory quota -> structured ENOMEM
      let enomemErr = null;
      try {
        for (let i = 0; i < 64; i++) {
          if (typeof asQuota.alloc === 'function') {
            asQuota.alloc(4096);
          } else {
            asQuota.mmap(0x00500000 + i * 4096, 4096, PROT_RW, `q-${i}`);
          }
        }
      } catch (err) {
        enomemErr = err;
      }
      assert.ok(enomemErr instanceof Error, 'Exceeding per-PID 64 KiB quota must throw MemoryFaultError');
      assert.ok(
        enomemErr.code === 'ENOMEM' || /ENOMEM|quota|memory/i.test(`${enomemErr.code ?? ''} ${enomemErr.message}`),
        `Expected ENOMEM on quota exhaustion (got code=${enomemErr.code}, msg=${enomemErr.message})`
      );

      // Launch deep-recursion Android APK alongside procHealthy -> only deep-recursion PID terminates
      const recApk = await pkgManager.install(buildDexDeepRecursionApk(), {
        filename: `p04-deeprec-${nonce}.apk`,
        grantAll: true,
      });
      const recPid = extractPid(await pkgManager.launch(extractAppId(recApk, 'com.omnios.deeprec'), {}));
      pids.push(recPid);

      const recTerminated = await stepUntil(os, () => isTerminated(pm.get(recPid)), 1500);
      assert.equal(recTerminated, true, `Deep-recursion Dalvik PID ${recPid} must terminate under stack/CPU fault`);

      // Verify procHealthy's secret page is 100% intact and procHealthy keeps stepping
      const readHealthyPost = Buffer.from(asHealthy.read(0x00400000, 32));
      assert.equal(Buffer.compare(readHealthyPost, secretBytes), 0, 'procHealthy VMM page must survive sibling ENOMEM & StackOverflow faults');
      const prevSteps = healthyCtx.steps;
      const steppedAfter = await stepUntil(os, () => healthyCtx.steps > prevSteps, 80);
      assert.equal(steppedAfter, true, 'procHealthy must keep stepping after sibling faults');
      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING');
    } finally {
      const pm = os.processManager;
      for (const pid of pids) {
        try {
          const pcb = pm?.get?.(pid);
          if (pcb && !isTerminated(pcb)) await pm.kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
      await os.shutdown();
    }
  });

  test('T3-P04-06 [F-032, F-035, F-041, F-048, F-062]: Adversarial Malformed Packages (ZIP-Slip + FairPlay DRM + Malformed PE) Rejected Without Disrupting Live Session or Host/VFS Integrity', async () => {
    const srv = await startOmniServer();
    let os = null;
    try {
      const nonce = makeNonce();
      const etcPasswdBefore = await fs.readFile('/etc/passwd', 'utf8');

      // 1. Provision guard VFS file and launch a live dynamically-discovered system app
      const guardPath = `/home/user/Documents/guard-${nonce}.txt`;
      const guardBody = `GUARD_${nonce}`;
      const writeRes = await restMutate(srv.api, '/api/v1/vfs/file', { path: guardPath, content: guardBody });
      assert.ok(writeRes.ok, `Provisioning guard VFS file must succeed (got ${writeRes.status}: ${writeRes.text})`);

      const liveAppId = await discoverBuiltinAppHttp(srv.api);
      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(liveAppId)}/launch`, {}, { expectOk: true });
      const livePid = launchRes.json?.pid ?? launchRes.json?.process?.pid;
      assert.ok(Number.isInteger(livePid) && livePid > 0, `Live system app launch must return valid PID (got ${launchRes.text})`);

      // 2. Submit all 3 adversarial packages via HTTP POST /api/v1/packages/install (405-only fallback) -> MUST reject 4xx
      const adversarialHttp = [
        ['zip-slip.apk', buildZipSlipArchive('dotdot', { wrapAsApk: true })],
        ['fairplay.ipa', buildFairPlayEncryptedIpa()],
        ['malformed-pe.exe', buildMalformedPe('too-many-sections')],
      ];
      for (const [fname, bytes] of adversarialHttp) {
        let res = await restNegative405Only(srv.api, ['POST', 'PUT'], '/api/v1/packages/install', bytes, {
          query: { filename: fname },
          headers: { 'content-type': 'application/octet-stream', 'x-filename': fname },
        });
        if (res.status === 415) {
          const b64 = Buffer.from(bytes).toString('base64');
          res = await restNegative405Only(srv.api, ['POST', 'PUT'], '/api/v1/packages/install', {
            filename: fname,
            base64: b64,
            data: b64,
            buffer: b64,
          });
        }
        assert.ok(
          res.status >= 400 && res.status < 500 && res.status !== 404 && res.status !== 415,
          `Adversarial package "${fname}" MUST be genuinely rejected with HTTP 4xx (not 404/415, got ${res.status}: ${res.text})`
        );
      }

      // 3. Verify host /etc/passwd, VFS guard file, live system app PID, and /api/health are completely intact
      const etcPasswdAfter = await fs.readFile('/etc/passwd', 'utf8');
      assert.equal(etcPasswdAfter, etcPasswdBefore, 'Host /etc/passwd must never be altered by ZIP-slip');

      const guardRead = await srv.api.get('/api/v1/vfs/file', { query: { path: guardPath }, expectOk: true });
      assert.ok(guardRead.text.includes(guardBody), 'Guard VFS file must stay intact after adversarial rejections');

      const procRes = await srv.api.get(`/api/v1/processes/${livePid}`, { expectOk: true });
      const liveState = procRes.json?.state ?? procRes.json?.process?.state ?? procRes.json?.data?.state;
      assert.ok(liveState && liveState !== 'TERMINATED' && liveState !== 'ZOMBIE', `Live system app PID ${livePid} must remain alive (state=${liveState})`);

      const healthRes = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(healthRes.status, 200);

      // 4. Programmatic structured error code verification for all 3 adversarial formats
      os = await loadPublicOmniOS();
      const pkgManager = os.require('pkgManager');
      const expectedCodes = [
        ['zip-slip', buildZipSlipArchive('dotdot', { wrapAsApk: true }), /E_PATH_TRAVERSAL|TRAVERSAL|SLIP/i],
        ['fairplay', buildFairPlayEncryptedIpa(), /E_ENCRYPTED_BINARY|ENCRYPT|FAIRPLAY/i],
        ['malformed-pe', buildMalformedPe('too-many-sections'), /E_INVALID_PE|E_MALFORMED_PE|\bPE\b|\bPE32|SECTION/i],
      ];
      for (const [label, bytes, codePattern] of expectedCodes) {
        let caught = null;
        try {
          await pkgManager.install(bytes, { filename: `${label}-${nonce}.bin` });
        } catch (err) {
          caught = err;
        }
        assert.ok(caught instanceof Error, `Programmatic pkgManager.install(${label}) must reject`);
        assert.match(
          `${caught.code ?? ''} ${caught.message ?? ''}`,
          codePattern,
          `Expected structured error for ${label} (got code=${caught.code}, msg=${caught.message})`
        );
      }
      assert.equal(os.require('kernel').getDiagnostics()?.state, 'RUNNING');
    } finally {
      await os?.shutdown();
      await srv.stop();
    }
  });
});
