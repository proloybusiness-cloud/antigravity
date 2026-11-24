/**
 * OmniOS Tier 3 Pairwise E2E Suite — P-06:
 * Kernel Panic (SQLite Crash Dump & Scheduling Halt) × Safe-Mode Recovery
 * × Full Cold-Restart Persistence Across All 7 Subsystems (VFS, Installed & Runnable
 * Packages, Registry/Defaults/SharedPrefs, Permissions & Audit Log, Ephemeral /tmp,
 * Sequential Panics & Uninstall Durability).
 *
 * Feature Pairs Exercised:
 *   F-002, F-003, F-004, F-005, F-016, F-020, F-021, F-022, F-028, F-034,
 *   F-043, F-050, F-056, F-062, F-065
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded system app IDs or undocumented capability names.
 * - Zero assertions inside try/catch blocks.
 * - Clean try/finally teardown on every test (zero /tmp/omnios-* leaks).
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
import {
  buildCustomIpa,
  buildCustomUapp,
} from '../lib/fixtures-apple-wasm.mjs';

const CORE_DAEMONS = ['vfsd', 'configd', 'ipc-brokerd', 'securityd', 'pkgd', 'compositord'];

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function makeSmallOperands() {
  const a = 12 + crypto.randomInt(35);
  const b = 15 + crypto.randomInt(35);
  const c = 5 + crypto.randomInt(40);
  return [a, b, c];
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

function decodeRegBinary(data) {
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (Array.isArray(data)) return Buffer.from(data);
  if (typeof data === 'string') {
    const t = data.trim();
    if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0 && t.length === 16) return Buffer.from(t, 'hex');
    return Buffer.from(t, 'base64');
  }
  if (data && typeof data === 'object' && data.type === 'Buffer' && Array.isArray(data.data)) {
    return Buffer.from(data.data);
  }
  throw new TypeError(`Cannot decode REG_BINARY value: ${JSON.stringify(data)}`);
}

function parsePlistViaPython(xmlStr) {
  const raw = execFileSync(
    'python3',
    ['-c', 'from sys import stdin; import plistlib, json; print(json.dumps(plistlib.loads(stdin.buffer.read()), default=str))'],
    { input: Buffer.from(String(xmlStr), 'utf8'), encoding: 'utf8' }
  );
  return JSON.parse(raw);
}

function normalizeServicesMap(raw) {
  const map = new Map();
  if (!raw) return map;
  if (raw instanceof Map) {
    for (const [k, v] of raw.entries()) map.set(String(k), v);
    return map;
  }
  const arr =
    Array.isArray(raw) ? raw
      : Array.isArray(raw.services) ? raw.services
        : Array.isArray(raw.data?.services) ? raw.data.services
          : Array.isArray(raw.data) ? raw.data
            : null;
  if (arr) {
    for (const entry of arr) {
      if (entry && typeof entry === 'object' && entry.name) map.set(String(entry.name), entry);
    }
    return map;
  }
  const obj =
    (raw.services && typeof raw.services === 'object' && !Array.isArray(raw.services)) ? raw.services
      : (raw.data?.services && typeof raw.data.services === 'object' && !Array.isArray(raw.data.services)) ? raw.data.services
        : (raw.data && typeof raw.data === 'object' && !Array.isArray(raw.data)) ? raw.data
          : (typeof raw === 'object' ? raw : null);
  if (obj) {
    for (const [k, v] of Object.entries(obj)) {
      if (v && typeof v === 'object') map.set(String(v.name ?? k), v);
    }
  }
  return map;
}

function assertAllCoreDaemonsHealthy(serviceManager, label) {
  const svcs = normalizeServicesMap(serviceManager.getStatus());
  for (const name of CORE_DAEMONS) {
    const svc = svcs.get(name);
    assert.ok(svc && typeof svc === 'object', `${label}: core daemon "${name}" must exist in ServiceManager`);
    const state = String(svc.state ?? svc.status ?? '').trim();
    assert.match(state, /^(running|active|healthy|ready|started|ok)$/i, `${label}: daemon "${name}" must be healthy (got "${state}")`);
    assert.notEqual(svc.healthy, false, `${label}: daemon "${name}" must not report healthy === false`);
  }
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
    ops.map((o) => ({ op: o.op ?? 'put', key: o.key, ...(o.op === 'remove' ? {} : { value: o.value }) })),
    ops.map((o) => ({ type: o.op ?? 'put', key: o.key, ...(o.op === 'remove' ? {} : { value: o.value }) })),
    (() => {
      const setMap = {};
      const removeList = [];
      for (const o of ops) {
        if (o.op === 'remove') removeList.push(o.key);
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

async function discoverCanonicalCap(security, probeAppId, pkgManager = null) {
  const nativePermission = 'android.permission.CAMERA';
  const isTranslated = (cap) =>
    typeof cap === 'string' && cap.length > 0 && cap !== nativePermission && !/^unknown$/i.test(cap.trim());

  const probe = await security.checkPermission({
    appId: probeAppId,
    pid: 1,
    platform: 'android',
    nativePermission,
  });
  const direct = probe?.capability ?? probe?.canonicalCapability;
  if (isTranslated(direct)) return direct;

  const logs = await security.getAuditLog({ appId: probeAppId, limit: 15 });
  if (Array.isArray(logs)) {
    const fromLog = logs.map((e) => e?.capability ?? e?.canonicalCapability ?? e?.cap).find(isTranslated);
    if (fromLog) return fromLog;
  }

  if (pkgManager && typeof pkgManager.inspect === 'function') {
    const apk = buildCustomApk({ packageName: `${probeAppId}.apk`, appLabel: 'CapProbe', permissions: [nativePermission] });
    const insp = await pkgManager.inspect(apk);
    const fromInsp = extractCapabilitiesFromPayload(insp).find(isTranslated);
    if (fromInsp) return fromInsp;
  }

  assert.fail(`Unable to dynamically discover canonical capability from PermissionBroker (probe=${JSON.stringify(probe)})`);
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

async function discoverValidCapabilityRest(api, nonce) {
  const permRes = await api.get('/api/v1/security/permissions');
  if (permRes.ok && permRes.json) {
    const caps = extractCapabilitiesFromPayload(permRes.json).filter((c) => !/^unknown$/i.test(c));
    if (caps.length > 0) return caps[0];
  }
  const probePkg = `com.p06.capprobe.${nonce}`;
  const inst = await installPackageHttp(
    api,
    buildCustomApk({ packageName: probePkg, appLabel: `P06Cap${nonce}`, permissions: ['android.permission.CAMERA'] }),
    `${probePkg}.apk`
  );
  if (inst.ok && inst.json) {
    const caps = extractCapabilitiesFromPayload(inst.json).filter((c) => c !== 'android.permission.CAMERA' && !/^unknown$/i.test(c));
    if (caps.length > 0) return caps[0];
  }
  const afterRes = await api.get('/api/v1/security/permissions', { query: { appId: probePkg } });
  if (afterRes.ok && afterRes.json) {
    const caps = extractCapabilitiesFromPayload(afterRes.json).filter((c) => c !== 'android.permission.CAMERA' && !/^unknown$/i.test(c));
    if (caps.length > 0) return caps[0];
  }
  assert.fail('Unable to dynamically discover canonical capability via REST /api/v1/security/permissions');
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

function readSystemKey(payload, key) {
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

function unwrapExplicitArray(payload, keys = ['packages', 'apps', 'audit', 'entries', 'items', 'logs', 'data', 'list']) {
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

function getInode(st) {
  const ino = st?.ino ?? st?.inode ?? st?.inodeId ?? st?.id;
  assert.ok(ino !== undefined && ino !== null, `stat() missing inode: ${JSON.stringify(st)}`);
  return String(ino);
}

function extractAppId(rec, fallback = null) {
  return rec?.appId ?? rec?.id ?? rec?.packageName ?? rec?.bundleId ?? rec?.package?.appId ?? rec?.data?.appId ?? fallback;
}

function extractPid(launchRes) {
  const pid = launchRes?.pid ?? launchRes?.process?.pid ?? launchRes?.data?.pid;
  assert.ok(Number.isInteger(pid) && pid > 0, `Expected positive integer PID from launch(), got ${JSON.stringify(launchRes)}`);
  return pid;
}

function extractStdout(pcb, summary) {
  const raw = summary?.stdout ?? pcb?.streams?.stdout ?? pcb?.stdout ?? '';
  if (typeof raw === 'string') return raw;
  if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) return Buffer.from(raw).toString('utf8');
  if (Array.isArray(raw)) {
    return raw.map((c) => (Buffer.isBuffer(c) || c instanceof Uint8Array ? Buffer.from(c).toString('utf8') : String(c ?? ''))).join('');
  }
  return String(raw ?? '');
}

function extractExitCode(pcb, summary) {
  const code = summary?.exitCode ?? pcb?.stats?.exitCode ?? pcb?.exitCode;
  return code === undefined || code === null ? null : Number(code);
}

async function runToCompletion(osHandle, pid, maxTicks = 2500) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  const scaled = Math.max(maxTicks, pm.list().length * 50);
  let summary = null;
  if (typeof scheduler.runUntilIdle === 'function') {
    summary = await scheduler.runUntilIdle(pid, scaled);
  } else {
    for (let i = 0; i < Math.ceil(scaled / 25); i++) {
      await scheduler.step(25);
      const cur = pm.get(pid);
      if (!cur || cur.state === 'TERMINATED' || cur.state === 'ZOMBIE') break;
    }
  }
  const pcb = pm.get(pid);
  return { pcb, summary, stdout: extractStdout(pcb, summary), exitCode: extractExitCode(pcb, summary) };
}

async function stepUntil(osHandle, pred, minSteps = 80) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  const limit = Math.max(minSteps, pm.list().length * 20);
  for (let i = 0; i < limit; i++) {
    if (await pred()) return true;
    await scheduler.step(1);
  }
  return Boolean(await pred());
}

describe('Tier 3 — P-06: Kernel Panic, Safe Recovery & Full SQLite Cold-Restart Persistence', () => {
  test('T3-P06-01 [F-004, F-005, F-016, F-021, F-022, F-028, F-034]: Multi-Subsystem Provisioning -> kernel.panic() SQLite Dump & Scheduling Halt -> recover({ safeMode: true }) Survival', async () => {
    const temp = await createTempDataDir('omnios-p06-rec-');
    let os = null;
    try {
      const nonce = makeNonce();
      os = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const kernel = os.require('kernel');
      const sm = os.require('serviceManager');
      const pm = os.require('processManager');
      const scheduler = os.require('scheduler');
      const vfs = os.require('vfs');
      const cs = os.require('configStore');
      const pkgManager = os.require('pkgManager');
      const security = os.require('security');
      scheduler.stop?.();

      // 1. Spawn yielding worker & prove it actively steps BEFORE panic
      const workerCtx = makeYieldingContext();
      pm.spawn({
        name: `p06-worker-${nonce}`,
        appId: `com.p06.wrk.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        cwd: '/home/user',
        priority: 10,
        executionContext: workerCtx,
      });
      const steppedPre = await stepUntil(os, () => workerCtx.steps > 0, 80);
      assert.equal(steppedPre, true, 'Worker process must advance under scheduler BEFORE panic');

      // 2. Provision real state across all 6 subsystems
      const filePath = `/home/user/Documents/p06-rec-${nonce}.txt`;
      const linkPath = `/home/user/Documents/p06-lnk-${nonce}.txt`;
      await vfs.writeFile(filePath, `REC_FILE_${nonce}`, { mode: 0o640, uid: 0, gid: 0 });
      await vfs.chmod(filePath, 0o640, { uid: 0, gid: 0 });
      await vfs.symlink(filePath, linkPath, { uid: 0, gid: 0 });

      const uappId = `com.p06.rec.${nonce}`;
      await pkgManager.install(buildCustomUapp({ appId: uappId, name: `RecUapp${nonce}`, message: `REC_${nonce}\n` }), {
        filename: `p06-rec-${nonce}.uapp`,
        grantAll: true,
      });

      const regKey = `Software\\OmniP06\\${nonce}`;
      await cs.registry.setValue('HKCU', regKey, 'StrVal', 'REG_SZ', `REG_${nonce}`, { uid: 0 });
      await cs.registry.setValue('HKCU', regKey, 'NumVal', 'REG_DWORD', 4242, { uid: 0 });

      const dom = `com.p06.dom.${nonce}`;
      await cs.defaults.set(dom, 'prefKey', `DEF_${nonce}`);
      await cs.system.set('system.theme', 'light');
      await cs.system.set('system.volume', 73);

      const spPkg = `com.p06.sp.${nonce}`;
      await applySharedPrefsEdit(cs.sharedPrefs, spPkg, 'p06_prefs', [{ op: 'put', key: 'tok', value: `SP_${nonce}` }], { uid: 0 });

      const cap = await discoverCanonicalCap(security, `com.p06.cap.${nonce}`, pkgManager);
      await security.setGrant(uappId, cap, 'deny');
      const preDec = await security.checkPermission({ appId: uappId, pid: 1, platform: 'universal', capability: cap });
      assert.equal(preDec?.granted, false, 'Pre-panic denied grant must report granted === false');

      // 3. Trigger kernel.panic() -> verify dump, PANIC state & scheduling halt
      const panicCode = `E_P06_PANIC_${nonce}`;
      const panicReason = `Pairwise panic test ${nonce}`;
      const dump = await kernel.panic(panicCode, panicReason, { nonce });
      assert.ok(JSON.stringify(dump).includes(panicCode), `Panic dump must include ${panicCode}`);
      assert.ok(JSON.stringify(dump).includes(panicReason), `Panic dump must include ${panicReason}`);

      const diagPanic = kernel.getDiagnostics();
      assert.match(String(diagPanic?.state ?? ''), /PANIC/i, `Kernel state must reflect PANIC (got ${diagPanic?.state})`);
      assert.ok(JSON.stringify(diagPanic?.lastPanic ?? '').includes(panicCode), 'Diagnostics lastPanic must include panicCode');

      const stepsAtPanic = workerCtx.steps;
      const haltSteps = Math.max(8, pm.list().length * 2);
      for (let i = 0; i < haltSteps; i++) {
        try {
          await scheduler.step(1);
        } catch {
          // scheduler may reject stepping during PANIC — either no-op or structured reject is valid
          break;
        }
      }
      assert.equal(workerCtx.steps, stepsAtPanic, 'User process scheduling MUST remain halted while kernel is in PANIC');

      // 4. Recover in safeMode -> verify RUNNING, lastPanic retained, all 6 daemons healthy & all 6 subsystems intact
      const rec = await kernel.recover({ safeMode: true });
      assert.ok(
        rec?.status === 'RUNNING' || rec?.status === 'SAFE_MODE',
        `recover({ safeMode: true }) must return status RUNNING or SAFE_MODE (got ${JSON.stringify(rec)})`
      );

      const diagRec = kernel.getDiagnostics();
      assert.ok(
        diagRec?.state === 'RUNNING' || diagRec?.state === 'SAFE_MODE',
        `Kernel diagnostics state must be RUNNING or SAFE_MODE after recovery (got ${diagRec?.state})`
      );
      assert.ok(JSON.stringify(diagRec?.lastPanic ?? '').includes(panicCode), 'lastPanic must persist after safe-mode recovery');
      assertAllCoreDaemonsHealthy(sm, 'Post safe-mode recovery');

      assert.equal(await vfs.readFile(filePath, { encoding: 'utf8', uid: 0, gid: 0 }), `REC_FILE_${nonce}`);
      assert.equal(await vfs.readlink(linkPath, { uid: 0, gid: 0 }), filePath);
      assert.ok((await pkgManager.list()).some((p) => extractAppId(p) === uappId), 'Installed package must survive safe-mode recovery');
      assert.equal((await cs.registry.getValue('HKCU', regKey, 'StrVal', { uid: 0 }))?.data, `REG_${nonce}`);
      assert.equal((await cs.registry.getValue('HKCU', regKey, 'NumVal', { uid: 0 }))?.data, 4242);
      assert.equal(await cs.defaults.get(dom, 'prefKey'), `DEF_${nonce}`);
      assert.equal(await cs.system.get('system.theme'), 'light');
      assert.equal(await cs.system.get('system.volume'), 73);
      assert.equal((await cs.sharedPrefs.getAll(spPkg, 'p06_prefs'))?.tok, `SP_${nonce}`);
      assert.equal((await security.checkPermission({ appId: uappId, pid: 1, platform: 'universal', capability: cap }))?.granted, false);
      assert.ok((await security.getAuditLog({ appId: uappId, limit: 50 })).length >= 1, 'Security audit log must survive safe-mode recovery');
    } finally {
      await os?.shutdown();
      await temp.cleanup();
    }
  });

  test('T3-P06-02 [F-004, F-016, F-021, F-022, F-028, F-034, F-043, F-050, F-056]: Full Cold Restart After Panic + Safe Recovery — Complete 7-Subsystem Persistence & Post-Reboot Binary Execution', async () => {
    const temp = await createTempDataDir('omnios-p06-cold-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      const [a, b, c] = makeSmallOperands();
      const binPayload = crypto.randomBytes(8);
      const qwordVal = 0x0102030405060708n;

      const coldFile = `/home/user/Documents/cold-${nonce}.txt`;
      const coldLink = `/home/user/Documents/cold-lnk-${nonce}.txt`;
      const regKey = `Software\\OmniP06Cold\\${nonce}`;
      const appleDom = `com.p06.cold.${nonce}`;
      const spPkg = `com.p06.coldsp.${nonce}`;
      const iosBundle = `com.p06.coldios.${nonce}`;
      const uappId = `com.p06.colduapp.${nonce}`;
      const panicCode = `E_P06_COLD_${nonce}`;
      const panicReason = `Cold restart crash dump ${nonce}`;

      // ---- Boot 1: Provision all 7 persistent layers + panic + safe recovery ----
      os1 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const vfs1 = os1.require('vfs');
      const pkg1 = os1.require('pkgManager');
      const cs1 = os1.require('configStore');
      const sec1 = os1.require('security');
      const kern1 = os1.require('kernel');

      // 1. VFS file (0o600, uid/gid 10042) + symlink
      await vfs1.writeFile(coldFile, `COLD_VFS_${nonce}`, { mode: 0o600, uid: 0, gid: 0 });
      await vfs1.chown(coldFile, 10042, 10042, { uid: 0, gid: 0 });
      await vfs1.chmod(coldFile, 0o600, { uid: 0, gid: 0 });
      await vfs1.symlink(coldFile, coldLink, { uid: 0, gid: 0 });

      // 2. Install 3 real dynamic packages (Win PE32+, iOS IPA, Universal UAPP)
      const winRec1 = await pkg1.install(
        buildCustomPe64Exe({ subsystem: 3, message: `COLD_WIN_${nonce}\n`, computeExitSum: [a, b] }),
        { filename: `p06-cold-win-${nonce}.exe`, grantAll: true }
      );
      const winAppId = extractAppId(winRec1);
      assert.ok(winAppId, 'Windows PE install must yield persistent appId');

      await pkg1.install(
        buildCustomIpa({ bundleId: iosBundle, displayName: `ColdIos${nonce}`, executableName: `ColdIos${nonce}`, message: `COLD_IOS_${nonce}\n`, exitCode: c }),
        { filename: `p06-cold-ios-${nonce}.ipa`, grantAll: true }
      );
      await pkg1.install(
        buildCustomUapp({ appId: uappId, name: `ColdUapp${nonce}`, message: `COLD_UAPP_${nonce}\n`, exitCode: 0 }),
        { filename: `p06-cold-uapp-${nonce}.uapp`, grantAll: true }
      );

      // 3. Registry (REG_SZ, REG_DWORD, REG_BINARY, REG_QWORD)
      await cs1.registry.setValue('HKCU', regKey, 'Sz', 'REG_SZ', `COLD_SZ_${nonce}`, { uid: 0 });
      await cs1.registry.setValue('HKCU', regKey, 'Dw', 'REG_DWORD', 1337, { uid: 0 });
      await cs1.registry.setValue('HKCU', regKey, 'Bin', 'REG_BINARY', binPayload, { uid: 0 });
      await cs1.registry.setValue('HKCU', regKey, 'Qw', 'REG_QWORD', qwordVal, { uid: 0 });

      // 4. Apple NSUserDefaults + system.* keys
      await cs1.defaults.set(appleDom, 'str', `cold-${nonce}`);
      await cs1.defaults.set(appleDom, 'num', 88);
      await cs1.defaults.set(appleDom, 'arr', ['x', nonce]);
      await cs1.defaults.set(appleDom, 'dict', { k: `v-${nonce}` });
      await cs1.system.set('system.theme', 'dark');
      await cs1.system.set('system.brightness', 64);

      // 5. Android SharedPreferences
      await applySharedPrefsEdit(cs1.sharedPrefs, spPkg, 'cold_prefs', [{ op: 'put', key: 'persist', value: `CSP_${nonce}` }], { uid: 0 });

      // 6. Dynamically discovered canonical capability 'deny' grant + Audit Log
      const cap = await discoverCanonicalCap(sec1, `com.p06.coldcap.${nonce}`, pkg1);
      await sec1.setGrant(uappId, cap, 'deny');
      const d1 = await sec1.checkPermission({ appId: uappId, pid: 1, platform: 'universal', capability: cap });
      assert.equal(d1?.granted, false);

      // 7. Kernel panic -> safe recovery -> clean shutdown
      await kern1.panic(panicCode, panicReason, { nonce });
      const rec1 = await kern1.recover({ safeMode: true });
      assert.ok(
        rec1?.status === 'RUNNING' || rec1?.status === 'SAFE_MODE',
        `recover({ safeMode: true }) must return RUNNING or SAFE_MODE (got ${JSON.stringify(rec1)})`
      );

      await os1.shutdown();
      os1 = null;

      // ---- Boot 2: Full Cold Restart on same SQLite dataDir ----
      os2 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      os2.require('scheduler').stop?.();
      const kern2 = os2.require('kernel');
      const vfs2 = os2.require('vfs');
      const pkg2 = os2.require('pkgManager');
      const cs2 = os2.require('configStore');
      const sec2 = os2.require('security');

      const diag2 = kern2.getDiagnostics();
      assert.equal(diag2?.state, 'RUNNING', 'Cold-restarted kernel must boot to RUNNING');
      assert.ok(JSON.stringify(diag2?.lastPanic ?? '').includes(panicCode), `Cold-restarted kernel must preserve lastPanic "${panicCode}"`);
      assert.ok(JSON.stringify(diag2?.lastPanic ?? '').includes(panicReason), `Cold-restarted kernel must preserve panic reason`);

      // Verify VFS file, mode, uid/gid & symlink
      assert.equal(await vfs2.readFile(coldFile, { encoding: 'utf8', uid: 0, gid: 0 }), `COLD_VFS_${nonce}`);
      const st2 = await vfs2.stat(coldFile, { uid: 0, gid: 0 });
      assert.equal((st2.mode & 0o777), 0o600, `Persisted VFS mode must equal 0o600 (got 0o${(st2.mode & 0o777).toString(8)})`);
      assert.equal(st2.uid, 10042, 'Persisted VFS uid must equal 10042');
      assert.equal(st2.gid, 10042, 'Persisted VFS gid must equal 10042');
      assert.equal(await vfs2.readlink(coldLink, { uid: 0, gid: 0 }), coldFile);

      // Verify all 3 packages persisted AND execute Windows .exe & Universal .uapp AFTER cold restart!
      const installedIds2 = (await pkg2.list()).map((p) => extractAppId(p));
      assert.ok(installedIds2.includes(winAppId), `Persisted packages must include Windows app ${winAppId}`);
      assert.ok(installedIds2.includes(iosBundle), `Persisted packages must include iOS app ${iosBundle}`);
      assert.ok(installedIds2.includes(uappId), `Persisted packages must include Universal app ${uappId}`);

      const winLaunch2 = await pkg2.launch(winAppId, {});
      const winRun2 = await runToCompletion(os2, extractPid(winLaunch2), 2500);
      assert.ok(winRun2.stdout.includes(`COLD_WIN_${nonce}`), `Post-reboot Windows .exe stdout mismatch: ${JSON.stringify(winRun2.stdout)}`);
      assert.equal(winRun2.exitCode, a + b, `Post-reboot Windows .exe must exit with computed sum ${a + b}`);

      const uappLaunch2 = await pkg2.launch(uappId, {});
      const uappRun2 = await runToCompletion(os2, extractPid(uappLaunch2), 2500);
      assert.ok(uappRun2.stdout.includes(`COLD_UAPP_${nonce}`), `Post-reboot Universal .uapp stdout mismatch: ${JSON.stringify(uappRun2.stdout)}`);
      assert.equal(uappRun2.exitCode, 0);

      // Verify Registry all 4 types
      assert.equal((await cs2.registry.getValue('HKCU', regKey, 'Sz', { uid: 0 }))?.data, `COLD_SZ_${nonce}`);
      assert.equal((await cs2.registry.getValue('HKCU', regKey, 'Dw', { uid: 0 }))?.data, 1337);
      const binRead = decodeRegBinary((await cs2.registry.getValue('HKCU', regKey, 'Bin', { uid: 0 }))?.data);
      assert.equal(Buffer.compare(binRead, binPayload), 0, 'Persisted REG_BINARY must match byte-for-byte');
      const qwRead = (await cs2.registry.getValue('HKCU', regKey, 'Qw', { uid: 0 }))?.data;
      assert.equal(BigInt(qwRead), qwordVal, 'Persisted REG_QWORD must match exact 64-bit BigInt');

      // Verify Apple NSUserDefaults via Python plistlib & system.brightness
      const plistXml2 = await cs2.defaults.exportPlistXml(appleDom);
      const parsedPlist2 = parsePlistViaPython(plistXml2);
      assert.equal(parsedPlist2.str, `cold-${nonce}`);
      assert.equal(parsedPlist2.num, 88);
      assert.deepEqual(parsedPlist2.arr, ['x', nonce]);
      assert.deepEqual(parsedPlist2.dict, { k: `v-${nonce}` });
      assert.equal(await cs2.system.get('system.brightness'), 64);

      // Verify Android SharedPreferences
      assert.equal((await cs2.sharedPrefs.getAll(spPkg, 'cold_prefs'))?.persist, `CSP_${nonce}`);

      // Verify Permission grant & Security Audit Log persisted
      const d2 = await sec2.checkPermission({ appId: uappId, pid: 1, platform: 'universal', capability: cap });
      assert.equal(d2?.granted, false, 'Persisted deny grant must remain enforced after cold reboot');
      const audit2 = await sec2.getAuditLog({ appId: uappId, limit: 50 });
      assert.ok(Array.isArray(audit2) && audit2.length >= 2, `Audit log must retain pre- and post-reboot entries (got ${audit2?.length})`);
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });

  test('T3-P06-03 [F-016, F-020]: Ephemeral /tmp Volatility vs Durable /home/user/Documents Persistence Across Cold Restart', async () => {
    const temp = await createTempDataDir('omnios-p06-tmp-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      const durablePath = `/home/user/Documents/durable-${nonce}.txt`;
      const tmpPath = `/tmp/ephemeral-${nonce}.txt`;
      const postTmpPath = `/tmp/postboot-${nonce}.txt`;

      os1 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const vfs1 = os1.require('vfs');
      await vfs1.writeFile(durablePath, `DURABLE_${nonce}`, { mode: 0o644 });
      await vfs1.writeFile(tmpPath, `EPHEMERAL_${nonce}`, { mode: 0o644 });

      assert.equal(await vfs1.readFile(durablePath, { encoding: 'utf8' }), `DURABLE_${nonce}`);
      assert.equal(await vfs1.readFile(tmpPath, { encoding: 'utf8' }), `EPHEMERAL_${nonce}`);
      const durableIno = getInode(await vfs1.stat(durablePath));

      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const vfs2 = os2.require('vfs');

      // Durable file persists with identical inode
      assert.equal(await vfs2.readFile(durablePath, { encoding: 'utf8' }), `DURABLE_${nonce}`);
      assert.equal(getInode(await vfs2.stat(durablePath)), durableIno, 'Durable VFS inode must survive cold restart');

      // Ephemeral /tmp file MUST be wiped across cold restart (ENOENT)
      let tmpErr = null;
      try {
        await vfs2.readFile(tmpPath, { encoding: 'utf8' });
      } catch (err) {
        tmpErr = err;
      }
      assert.ok(tmpErr instanceof Error, 'Ephemeral /tmp file must NOT survive cold restart');
      assert.equal(tmpErr.code, 'ENOENT', `Expected ENOENT for cleared /tmp file (got ${tmpErr.code})`);

      // Fresh /tmp write works cleanly after reboot
      await vfs2.writeFile(postTmpPath, `POST_${nonce}`, { mode: 0o644 });
      assert.equal(await vfs2.readFile(postTmpPath, { encoding: 'utf8' }), `POST_${nonce}`);
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });

  test('T3-P06-04 [F-004, F-016, F-021, F-022, F-028, F-034, F-062, F-065]: Live HTTP Server Cold Restart x REST /api/v1/kernel/{panic,recover} x Remote CLI Persistence', async () => {
    const temp = await createTempDataDir('omnios-p06-srv-');
    let srv1 = null;
    let srv2 = null;
    try {
      const nonce = makeNonce();
      const docPath = `/home/user/Documents/srv-cold-${nonce}.txt`;
      const docBody = `SRV_COLD_${nonce}`;
      const uappId = `com.p06.srv.${nonce}`;
      const regPath = `Software\\OmniP06Srv\\${nonce}`;
      const appleDom = `com.p06.srvdom.${nonce}`;
      const spPkg = `com.p06.srvsp.${nonce}`;
      const panicCode = `E_P06_HTTP_${nonce}`;
      const panicReason = `HTTP panic recovery test ${nonce}`;

      // ---- Server 1: Populate state across REST + Remote CLI + Panic + Recover ----
      srv1 = await startOmniServer({ dataDir: temp.dir, keepDataDir: true });

      const wf = await restMutate(srv1.api, '/api/v1/vfs/file', { path: docPath, content: docBody });
      assert.ok(wf.ok, `REST VFS write must succeed (got ${wf.status}: ${wf.text})`);

      const pkgInst = await installPackageHttp(
        srv1.api,
        buildCustomUapp({ appId: uappId, name: `SrvUapp${nonce}`, message: `SRV_RUN_${nonce}\n`, exitCode: 0 }),
        `p06-srv-${nonce}.uapp`
      );
      assert.ok(pkgInst.ok, `REST .uapp install must succeed (got ${pkgInst.status}: ${pkgInst.text})`);

      const volRes = await setSystemConfigHttp(srv1.api, 'system.volume', 58);
      assert.ok(volRes.ok, `Setting system.volume=58 must succeed (got ${volRes.status})`);

      const expectedRegVal = `REG_SRV_${nonce}`;
      let regSetCli = await srv1.runCli(['reg', 'set', 'HKCU', regPath, 'SrvVal', 'REG_SZ', expectedRegVal], { json: true });
      let regVerifyCli = regSetCli.ok
        ? await srv1.runCli(['reg', 'get', 'HKCU', regPath, 'SrvVal'], { json: true })
        : null;
      if (!regSetCli.ok || !regVerifyCli?.ok || extractRegDataValue(regVerifyCli.json) === 'REG_SZ' || !regVerifyCli.stdout.includes(expectedRegVal)) {
        regSetCli = await srv1.runCli(['reg', 'set', 'HKCU', regPath, 'SrvVal', expectedRegVal], { json: true, expectZero: true });
        regVerifyCli = await srv1.runCli(['reg', 'get', 'HKCU', regPath, 'SrvVal'], { json: true, expectZero: true });
      }
      assert.equal(regSetCli.ok, true, 'Remote CLI reg set must succeed');
      assert.notEqual(
        extractRegDataValue(regVerifyCli?.json),
        'REG_SZ',
        `Remote CLI reg set must not store literal "REG_SZ" as data (got ${regVerifyCli?.stdout})`
      );
      assert.ok(
        regVerifyCli?.stdout.includes(expectedRegVal),
        `Remote CLI reg get read-back must return "${expectedRegVal}" (got ${regVerifyCli?.stdout})`
      );
      await srv1.runCli(['defaults', 'write', appleDom, 'srvKey', `DEF_SRV_${nonce}`], { json: true, expectZero: true });
      await srv1.runCli(['prefs', 'set', spPkg, 'srv_prefs', 'srvTok', `SP_SRV_${nonce}`], { json: true, expectZero: true });

      const cap = await discoverValidCapabilityRest(srv1.api, nonce);
      const permMut = await restMutate(srv1.api, '/api/v1/security/permissions', {
        appId: uappId,
        capability: cap,
        state: 'deny',
        policy: 'deny',
      });
      assert.ok(permMut.ok, `Setting REST permission grant must succeed (got ${permMut.status}: ${permMut.text})`);

      const panicRes = await srv1.api.post('/api/v1/kernel/panic', { code: panicCode, reason: panicReason });
      assert.ok(panicRes.ok, `POST /api/v1/kernel/panic must succeed (got ${panicRes.status}: ${panicRes.text})`);

      const panicStat = await srv1.api.get('/api/v1/kernel/status', { expectOk: true });
      assert.match(panicStat.text, /PANIC/i, `Kernel status must report PANIC (got ${panicStat.text})`);
      assert.ok(panicStat.text.includes(panicCode), `Kernel status must expose lastPanic "${panicCode}"`);

      const recRes = await srv1.api.post('/api/v1/kernel/recover', { safeMode: true });
      assert.ok(recRes.ok, `POST /api/v1/kernel/recover must succeed (got ${recRes.status}: ${recRes.text})`);
      const recStat = await srv1.api.get('/api/v1/kernel/status', { expectOk: true });
      const recState = recStat.json?.state ?? recStat.json?.status;
      assert.ok(
        recState === 'RUNNING' || recState === 'SAFE_MODE',
        `Kernel status must return to RUNNING or SAFE_MODE after recovery (got ${recStat.text})`
      );

      await srv1.stop();
      srv1 = null;

      // ---- Server 2: Cold Restart on same SQLite temp.dir (fresh ephemeral port) ----
      srv2 = await startOmniServer({ dataDir: temp.dir, keepDataDir: true });

      assert.equal((await srv2.api.get('/api/health')).status, 200);
      const stat2 = await srv2.api.get('/api/v1/kernel/status', { expectOk: true });
      assert.ok(stat2.text.includes(panicCode), `Cold-restarted HTTP server must preserve lastPanic "${panicCode}"`);

      // Verify VFS file via REST & Remote CLI
      const vf2 = await srv2.api.get('/api/v1/vfs/file', { query: { path: docPath }, expectOk: true });
      assert.ok(vf2.text.includes(docBody), 'Persisted VFS file must be readable via REST after server cold restart');
      const cliCat = await srv2.runCli(['vfs', 'cat', docPath], { json: true, expectZero: true });
      assert.ok(cliCat.stdout.includes(docBody), 'Remote CLI vfs cat must read persisted file after server cold restart');

      // Verify installed package via REST & Remote CLI ospm list --json AND post-restart launch!
      const pkgs2 = await srv2.api.get('/api/v1/packages', { expectOk: true });
      const pkgArr2 = unwrapExplicitArray(pkgs2.json, ['packages', 'apps', 'items', 'data']);
      assert.ok(Array.isArray(pkgArr2) && pkgArr2.some((p) => extractAppId(p) === uappId), `REST packages must retain ${uappId}`);

      const cliPkgs = await srv2.runCli(['ospm', 'list'], { json: true, expectZero: true });
      const cliArr = unwrapExplicitArray(cliPkgs.json, ['packages', 'apps', 'items', 'data']);
      assert.ok(Array.isArray(cliArr) && cliArr.some((p) => extractAppId(p) === uappId), `Remote CLI ospm list must retain ${uappId}`);

      const launch2 = await srv2.api.post(`/api/v1/packages/${encodeURIComponent(uappId)}/launch`, {});
      assert.ok(launch2.ok, `Launching persisted package ${uappId} after server cold restart must succeed (got ${launch2.status}: ${launch2.text})`);

      // Verify unified config & audit log persistence
      const sys2 = await srv2.api.get('/api/v1/config/system', { expectOk: true });
      assert.equal(readSystemKey(sys2.json, 'system.volume'), 58, 'Persisted system.volume must equal 58 after cold restart');

      const reg2 = await srv2.runCli(['reg', 'get', 'HKCU', regPath, 'SrvVal'], { json: true, expectZero: true });
      assert.notEqual(extractRegDataValue(reg2.json), 'REG_SZ', 'Persisted registry value must not be literal "REG_SZ"');
      assert.ok(reg2.stdout.includes(expectedRegVal), 'Registry write must survive HTTP server cold restart');

      const def2 = await srv2.runCli(['defaults', 'read', appleDom, 'srvKey'], { json: true, expectZero: true });
      assert.ok(def2.stdout.includes(`DEF_SRV_${nonce}`), 'Apple defaults write must survive HTTP server cold restart');

      let sp2 = await srv2.runCli(['prefs', 'get', spPkg, 'srv_prefs'], { json: true });
      if (!sp2.ok || !sp2.stdout.includes(`SP_SRV_${nonce}`)) {
        sp2 = await srv2.runCli(['prefs', 'get', spPkg, 'srv_prefs', 'srvTok'], { json: true, expectZero: true });
      }
      assert.ok(sp2.stdout.includes(`SP_SRV_${nonce}`), 'Android SharedPrefs write must survive HTTP server cold restart');

      const perms2 = await srv2.api.get('/api/v1/security/permissions', { query: { appId: uappId }, expectOk: true });
      const persistedDenyState = extractGrantState(perms2.json, uappId, cap);
      assert.equal(
        persistedDenyState,
        'deny',
        `Persisted "deny" grant for (${uappId}, ${cap}) must survive HTTP server cold restart (got ${perms2.text})`
      );

      const audit2 = await srv2.api.get('/api/v1/security/audit', { expectOk: true });
      const auditArr2 = unwrapExplicitArray(audit2.json, ['audit', 'entries', 'items', 'logs', 'data']);
      assert.ok(Array.isArray(auditArr2) && auditArr2.length >= 1, 'Security audit log must survive HTTP server cold restart');
    } finally {
      await srv1?.stop();
      await srv2?.stop();
      await temp.cleanup();
    }
  });

  test('T3-P06-05 [F-002, F-003, F-004]: Sequential Panics (panic1 -> safeMode -> Post-Recovery Writes -> panic2 -> normal recover -> Cold Reboot) & Core Daemon Health', async () => {
    const temp = await createTempDataDir('omnios-p06-seq-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      const panic1 = `E_P06_ONE_${nonce}`;
      const panic2 = `E_P06_TWO_${nonce}`;
      const betweenFile = `/home/user/Documents/between-panics-${nonce}.txt`;

      os1 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const kern1 = os1.require('kernel');
      const sm1 = os1.require('serviceManager');
      const vfs1 = os1.require('vfs');
      const cs1 = os1.require('configStore');

      // Panic 1 -> Safe-Mode Recovery
      await kern1.panic(panic1, `First sequential panic ${nonce}`, { seq: 1 });
      const r1 = await kern1.recover({ safeMode: true });
      assert.ok(
        r1?.status === 'RUNNING' || r1?.status === 'SAFE_MODE',
        `recover({ safeMode: true }) must return RUNNING or SAFE_MODE (got ${JSON.stringify(r1)})`
      );
      assertAllCoreDaemonsHealthy(sm1, 'After panic1 safe-mode recovery');

      // Perform new writes BETWEEN panics
      await vfs1.writeFile(betweenFile, `BETWEEN_${nonce}`, { mode: 0o644 });
      await cs1.system.set('system.locale', 'de-DE');

      // Panic 2 -> Full Recovery (safeMode: false)
      await kern1.panic(panic2, `Second sequential panic ${nonce}`, { seq: 2 });
      const r2 = await kern1.recover({ safeMode: false });
      assert.equal(r2?.status, 'RUNNING');

      const diagAfter2 = kern1.getDiagnostics();
      assert.ok(JSON.stringify(diagAfter2?.lastPanic ?? '').includes(panic2), `lastPanic must update to "${panic2}"`);

      const logs = kern1.dmesg({ limit: 200 });
      assert.ok(Array.isArray(logs) && logs.length > 0, 'dmesg() must remain non-empty after sequential panics');
      for (let i = 1; i < logs.length; i++) {
        assert.ok(logs[i].seq >= logs[i - 1].seq, 'dmesg() seq values must remain monotonically non-decreasing');
      }

      await os1.shutdown();
      os1 = null;

      // Cold reboot verification
      os2 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const kern2 = os2.require('kernel');
      const sm2 = os2.require('serviceManager');
      const vfs2 = os2.require('vfs');
      const cs2 = os2.require('configStore');

      assert.equal(kern2.getDiagnostics()?.state, 'RUNNING');
      assert.ok(JSON.stringify(kern2.getDiagnostics()?.lastPanic ?? '').includes(panic2), `Cold reboot must retain latest panic "${panic2}"`);
      assert.equal(await vfs2.readFile(betweenFile, { encoding: 'utf8' }), `BETWEEN_${nonce}`);
      assert.equal(await cs2.system.get('system.locale'), 'de-DE');
      assertAllCoreDaemonsHealthy(sm2, 'After sequential panics and cold reboot');
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });

  test('T3-P06-06 [F-004, F-034]: Package Uninstall Deletion Durability (purgeData: true) x Panic/Recovery x Cold Reboot', async () => {
    const temp = await createTempDataDir('omnios-p06-uninst-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      const keepApp = `com.p06.keep.${nonce}`;
      const dropApp = `com.p06.drop.${nonce}`;

      os1 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      const pkg1 = os1.require('pkgManager');
      const kern1 = os1.require('kernel');

      await pkg1.install(buildCustomUapp({ appId: keepApp, name: `Keep${nonce}`, message: `KEEP_${nonce}\n`, exitCode: 0 }), {
        filename: `p06-keep-${nonce}.uapp`,
        grantAll: true,
      });
      await pkg1.install(buildCustomUapp({ appId: dropApp, name: `Drop${nonce}`, message: `DROP_${nonce}\n`, exitCode: 0 }), {
        filename: `p06-drop-${nonce}.uapp`,
        grantAll: true,
      });

      const beforeIds = (await pkg1.list()).map((p) => extractAppId(p));
      assert.ok(beforeIds.includes(keepApp) && beforeIds.includes(dropApp), 'Both installed packages must appear before uninstall');

      // Uninstall dropApp with purgeData: true
      await pkg1.uninstall(dropApp, { purgeData: true });
      const afterUninstIds = (await pkg1.list()).map((p) => extractAppId(p));
      assert.equal(afterUninstIds.includes(dropApp), false, 'Uninstalled package must disappear immediately from pkgManager.list()');
      assert.equal(afterUninstIds.includes(keepApp), true, 'Remaining package must stay installed');

      // Trigger panic -> recover -> cold reboot
      await kern1.panic(`E_P06_DEL_${nonce}`, `Uninstall durability test ${nonce}`, { nonce });
      await kern1.recover({ safeMode: true });
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir, keepDataDir: true });
      os2.require('scheduler').stop?.();
      const pkg2 = os2.require('pkgManager');

      const postRebootIds = (await pkg2.list()).map((p) => extractAppId(p));
      assert.equal(postRebootIds.includes(keepApp), true, `Kept package ${keepApp} must survive panic + cold reboot`);
      assert.equal(postRebootIds.includes(dropApp), false, `Uninstalled package ${dropApp} must remain ABSENT after panic + cold reboot`);

      let droppedLookup = null;
      try {
        droppedLookup = await pkg2.get(dropApp);
      } catch {
        droppedLookup = null;
      }
      assert.ok(droppedLookup === null || droppedLookup === undefined, `pkgManager.get("${dropApp}") must return null/undefined post-reboot`);

      // Kept package launches and executes cleanly after cold reboot
      const launchKeep = await pkg2.launch(keepApp, {});
      const runKeep = await runToCompletion(os2, extractPid(launchKeep), 2500);
      assert.equal(runKeep.exitCode, 0, 'Kept package must exit 0 after cold reboot');
      assert.ok(runKeep.stdout.includes(`KEEP_${nonce}`), `Kept package must output KEEP_${nonce} post-reboot (got ${JSON.stringify(runKeep.stdout)})`);
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });
});
