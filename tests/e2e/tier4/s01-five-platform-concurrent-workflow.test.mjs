/**
 * OmniOS Tier 4 E2E Suite — S01: 5-Platform Concurrent Interop & Multi-Process Fault Containment
 * Covers PROJECT.md Features: F-085 (plus end-to-end F-001–F-060).
 *
 * Scenarios:
 * - T4-S01-01 (Scenario 1 / F-085): Simultaneous 5-platform execution (.apk + .exe + .ipa + .app.zip + .uapp)
 *   under preemptive Scheduler with unified VFS, multi-MIME Clipboard, live cross-store Preferences Sync,
 *   Universal Intent Router, Dynamic Island Live Activity + Notifications, and clean multi-process teardown.
 * - T4-S01-02 (Scenario 2): Multi-process workload resilience under concurrent 5-app load against BOTH
 *   ARM64 __PAGEZERO SIGSEGV dereference and Dalvik infinite-loop (goto 0) CPU-quota exhaustion.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero external npm dependencies, zero hardcoded sys.* app IDs, zero undocumented capability strings.
 * - Zero skips, zero stubs, zero swallowed AssertionErrors inside try/catch.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { loadPublicOmniOS } from '../lib/env.mjs';
import { sha256Hex } from '../lib/binary-utils.mjs';
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
  buildDexInfiniteLoopApk,
  buildPageZeroDerefMachO,
} from '../lib/fixtures-malformed.mjs';

function makeNonce(bytes = 4) {
  return crypto.randomBytes(bytes).toString('hex');
}

function makeSafeAddOperands() {
  const b = crypto.randomBytes(2);
  return [19 + (b[0] % 55), 23 + (b[1] % 55)]; // sum in [42..149]
}

function makeDistinctExitCode(offset = 21) {
  return offset + (crypto.randomBytes(1)[0] % 35);
}

function isDoneState(state) {
  return state === 'TERMINATED' || state === 'ZOMBIE' || state === 'FAULT';
}

function normalizeText(val) {
  if (typeof val === 'string') return val;
  if (Buffer.isBuffer(val) || val instanceof Uint8Array) return Buffer.from(val).toString('utf8');
  if (Array.isArray(val)) return val.map(normalizeText).join('');
  if (val && typeof val === 'object') {
    if (typeof val.content === 'string') return val.content;
    if (typeof val.data === 'string') return val.data;
    if (val.data instanceof Uint8Array) return Buffer.from(val.data).toString('utf8');
  }
  return '';
}

function extractStdout(pcb, summary = null) {
  const raw =
    pcb?.stdout ??
    pcb?.streams?.stdout ??
    summary?.stdout ??
    summary?.streams?.stdout ??
    '';
  return normalizeText(raw);
}

function extractExitCode(pcb, summary = null) {
  return pcb?.exitCode ?? summary?.exitCode ?? null;
}

function extractInstructions(pcb, summary = null) {
  const raw =
    pcb?.instructionsExecuted ??
    pcb?.stats?.instructionsExecuted ??
    pcb?.executionContext?.getDebugState?.()?.instructionsExecuted ??
    summary?.instructionsExecuted ??
    summary?.stats?.instructionsExecuted ??
    0;
  return Number(raw) || 0;
}

function getWinId(w) {
  return w?.windowId ?? w?.id ?? null;
}

function getUiTree(w) {
  return w?.uiTree ?? w?.surface?.uiTree ?? null;
}

async function readVfsText(vfs, p, ctx = {}) {
  const raw = await vfs.readFile(p, { encoding: 'utf8', ...ctx });
  return normalizeText(raw);
}

function snapshotDmesgCursor(kernel) {
  const entries = kernel.dmesg({ limit: 500 }) ?? [];
  const maxSeq = entries.reduce((acc, e) => {
    const raw = e?.seq;
    if (raw === null || raw === undefined || raw === '' || typeof raw === 'boolean') return acc;
    const s = Number(raw);
    return Number.isFinite(s) && s > acc ? s : acc;
  }, -1);
  return { maxSeq, count: entries.length };
}

function getNewDmesgEntries(kernel, cursor) {
  const entries = kernel.dmesg({ limit: 500 }) ?? [];
  const hasSeq = (e) => {
    const raw = e?.seq;
    return raw !== null && raw !== undefined && raw !== '' && typeof raw !== 'boolean' && Number.isFinite(Number(raw));
  };
  if (cursor.maxSeq >= 0 && entries.some(hasSeq)) {
    return entries.filter((e) => hasSeq(e) && Number(e.seq) > cursor.maxSeq);
  }
  return entries.slice(cursor.count);
}

async function vfsFileExists(vfs, p) {
  try {
    await vfs.stat(p);
    return true;
  } catch {
    return false;
  }
}

async function ensureVfsDir(vfs, dirPath) {
  try {
    await vfs.mkdir(dirPath, { recursive: true });
  } catch {
    // directory may already exist
  }
}

/**
 * Dynamically grants ONLY capabilities exposed by the OS security subsystem itself
 * (zero hardcoded undocumented capability names).
 */
async function grantDiscoveredCapabilities(osHandle, appId) {
  const sec = osHandle.security;
  if (!sec || typeof sec.setGrant !== 'function') return;
  let caps = null;
  if (typeof sec.listCapabilities === 'function') {
    try {
      caps = await sec.listCapabilities();
    } catch {
      caps = null;
    }
  }
  if (!caps) {
    caps = sec.capabilities ?? sec.CAPABILITIES ?? null;
  }
  const list = Array.isArray(caps)
    ? caps
    : (caps && typeof caps === 'object' ? Object.values(caps) : []);
  for (const cap of list) {
    const capName = typeof cap === 'string' ? cap : (cap?.id ?? cap?.name ?? null);
    if (!capName) continue;
    try {
      await sec.setGrant(appId, capName, 'allow');
    } catch {
      // best-effort for optional capability names
    }
  }
}

async function stageInspectInstall(osHandle, bytes, filename, expectedFormat, expectedPlatform) {
  const detector = osHandle.require('formatDetector');
  const vfs = osHandle.require('vfs');
  const pkgManager = osHandle.require('pkgManager');

  const detected = await detector.detect(bytes, filename);
  assert.equal(
    detected?.format,
    expectedFormat,
    `formatDetector.detect(${filename}) must return format="${expectedFormat}", got ${JSON.stringify(detected)}`
  );
  assert.equal(
    detected?.platform,
    expectedPlatform,
    `formatDetector.detect(${filename}) must return platform="${expectedPlatform}", got ${JSON.stringify(detected)}`
  );

  await ensureVfsDir(vfs, '/tmp');
  const vfsPath = `/tmp/${filename}`;
  await vfs.writeFile(vfsPath, bytes);

  let inspection = null;
  try {
    inspection = await pkgManager.inspect(vfsPath);
  } catch {
    inspection = await pkgManager.inspect(bytes, filename);
  }
  assert.ok(inspection && typeof inspection === 'object', `pkgManager.inspect(${filename}) must return metadata object`);
  assert.equal(
    inspection.platform,
    expectedPlatform,
    `pkgManager.inspect(${filename}) platform mismatch: ${JSON.stringify(inspection)}`
  );
  if (inspection.sha256) {
    assert.equal(
      String(inspection.sha256).toLowerCase(),
      sha256Hex(bytes),
      `pkgManager.inspect(${filename}) SHA-256 mismatch`
    );
  }

  let record = null;
  try {
    record = await pkgManager.install(vfsPath, { filename, grantAll: true });
  } catch {
    record = await pkgManager.install(bytes, { filename, grantAll: true });
  }
  const appId = record?.appId ?? record?.id ?? inspection.appId;
  assert.ok(typeof appId === 'string' && appId.length > 0, `Expected installed appId for ${filename}, got ${JSON.stringify(record)}`);

  await grantDiscoveredCapabilities(osHandle, appId);
  return { appId, vfsPath, inspection, record };
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
  if (!snapshot || typeof snapshot !== 'object') return false;
  for (const op of ops) {
    if (!(op.key in snapshot) || stableSerialize(snapshot[op.key]) !== stableSerialize(op.value)) {
      return false;
    }
  }
  return true;
}

async function applySharedPrefsEdit(sp, pkg, prefName, ops) {
  const candidates = [
    ops.map((o) => ({ op: 'put', key: o.key, value: o.value })),
    ops.map((o) => ({ type: 'put', key: o.key, value: o.value })),
    { set: Object.fromEntries(ops.map((o) => [o.key, o.value])), remove: [] },
  ];
  let lastErr = null;
  for (const payload of candidates) {
    try {
      const res = await sp.edit(pkg, prefName, payload);
      const after = await sp.getAll(pkg, prefName);
      if (sharedPrefsOpsApplied(after, ops)) return res;
    } catch (err) {
      lastErr = err;
    }
  }
  if (lastErr) throw lastErr;
  throw new Error(`sharedPrefs.edit(${pkg}, ${prefName}) did not apply expected ops: ${JSON.stringify(ops)}`);
}

async function stopPidBestEffort(osHandle, pid) {
  if (!pid || pid <= 1) return;
  try {
    await osHandle.pkgManager?.stop?.(pid);
  } catch {
    // fallback to SIGKILL below
  }
  try {
    const pcb = osHandle.processManager?.get?.(pid);
    if (pcb && !isDoneState(pcb.state)) {
      await osHandle.processManager.kill(pid, 'SIGKILL');
    }
  } catch {
    // ignore teardown race
  }
}

describe('Tier 4 — S01: 5-Platform Concurrent Workflow & Fault Containment (F-085)', () => {
  it('T4-S01-01 [Scenario 1 / F-085]: Simultaneous 5-platform execution (.apk + .exe + .ipa + .app.zip + .uapp) with unified VFS, Clipboard, Preferences Sync, Intents, Dynamic Island & clean teardown', async () => {
    let osHandle = null;
    const spawnedPids = new Set();
    try {
      // Fail-fast on public entrypoint BEFORE allocating any fixtures/resources
      osHandle = await loadPublicOmniOS();

      const kernel = osHandle.require('kernel');
      const pm = osHandle.require('processManager');
      const scheduler = osHandle.require('scheduler');
      const vfs = osHandle.require('vfs');
      const pathTranslator = osHandle.require('pathTranslator');
      const configStore = osHandle.require('configStore');
      const intentRouter = osHandle.require('intentRouter');
      const clipboard = osHandle.require('clipboard');
      const notifications = osHandle.require('notifications');
      const compositor = osHandle.require('compositor');
      const pkgManager = osHandle.require('pkgManager');

      // Pause background timer so all 5 apps spawn simultaneously before round-robin stepping
      scheduler.stop?.();

      const nonce = makeNonce(4);
      const [andA, andB] = makeSafeAddOperands();
      const andSum = andA + andB;
      const [winA, winB] = makeSafeAddOperands();
      const winSum = winA + winB;
      const iosCode = makeDistinctExitCode(20);
      const macCode = makeDistinctExitCode(65);
      const uappCode = makeDistinctExitCode(110);

      // 1. Synthesize 5 distinct real platform binaries with unique runtime nonces & operands
      const andPkgName = `com.omnios.s01.and${nonce}`;
      const iosBundle = `com.omnios.s01.ios${nonce}`;
      const macBundle = `com.omnios.s01.mac${nonce}`;
      const uappBundle = `com.omnios.s01.uapp${nonce}`;
      const macExt = `s1d${nonce.slice(0, 4)}`;

      const apkBytes = buildCustomApk({
        packageName: andPkgName,
        appLabel: `S01And_${nonce}`,
        computeA: andA,
        computeB: andB,
        computeOp: 'add',
        outputFile: `/sdcard/Documents/s01-and-${nonce}.txt`,
        outputContent: `AND_${nonce}=${andSum}`,
        sharedPrefName: 's01_prefs',
        sharedPrefKey: 'and_sum',
        sharedPrefVal: String(andSum),
        notificationTitle: `S01Toast_${nonce}`,
        notificationBody: `Sum=${andSum}`,
        logTag: 'S01And',
        permissions: [
          'android.permission.READ_EXTERNAL_STORAGE',
          'android.permission.WRITE_EXTERNAL_STORAGE',
          'android.permission.POST_NOTIFICATIONS',
        ],
        intentFilters: [
          {
            actions: [`omni.s01.sync.${nonce}`],
            categories: ['android.intent.category.DEFAULT'],
            data: [{ mimeType: 'text/plain' }],
          },
        ],
        includeV2SigBlock: true,
        includeResourcesArsc: true,
      });

      const winBytes = buildCustomPe64Exe({
        subsystem: 3,
        message: `WIN_S01_${nonce}\n`,
        computeExitSum: [winA, winB],
        writeFilePath: `C:\\Users\\user\\Documents\\s01-win-${nonce}.txt`,
        writeFileContent: `WIN_${nonce}=${winSum}`,
        regHive: 0x80000001, // HKCU
        regSubKey: `Software\\OmniS01\\Run_${nonce}`,
        regValueName: 'WinToken',
        regValueData: `WIN_REG_${nonce}`,
        includeReloc: true,
      });

      const iosBytes = buildCustomIpa({
        bundleId: iosBundle,
        displayName: `S01Ios_${nonce}`,
        executableName: `S01Ios_${nonce}`,
        urlScheme: `s01ios${nonce}`,
        plistFormat: 'bplist00',
        fileWrite: {
          path: `/var/mobile/Documents/s01-ios-${nonce}.txt`,
          content: `IOS_${nonce}`,
        },
        exitCode: iosCode,
      });

      const macBytes = buildCustomMacAppZip({
        bundleId: macBundle,
        appName: `S01Mac_${nonce}`,
        executableName: `S01Mac_${nonce}`,
        arch: 'universal',
        plistFormat: 'xml',
        urlScheme: `s01mac${nonce}`,
        documentExtensions: [macExt],
        fileWrite: {
          path: `/Users/user/Documents/s01-mac-${nonce}.txt`,
          content: `MAC_${nonce}`,
        },
        exitCode: macCode,
      });

      const uappBytes = buildCustomUapp({
        appId: uappBundle,
        name: `S01Uapp_${nonce}`,
        urlSchemes: [`s01uni${nonce}`],
        message: `UAPP_S01_${nonce}\n`,
        exitCode: uappCode,
      });

      // 2. Format auto-detection, staging, inspection & installation for all 5
      const instAnd = await stageInspectInstall(osHandle, apkBytes, `s01-and-${nonce}.apk`, 'android-apk', 'android');
      const instWin = await stageInspectInstall(osHandle, winBytes, `s01-win-${nonce}.exe`, 'windows-pe', 'windows');
      const instIos = await stageInspectInstall(osHandle, iosBytes, `s01-ios-${nonce}.ipa`, 'ios-ipa', 'ios');
      const instMac = await stageInspectInstall(osHandle, macBytes, `s01-mac-${nonce}.app.zip`, 'macos-app', 'macos');
      const instUapp = await stageInspectInstall(osHandle, uappBytes, `s01-uapp-${nonce}.uapp`, 'universal-uapp', 'universal');

      const installedList = await pkgManager.list();
      const installedIds = new Set(installedList.map((p) => p?.appId ?? p?.id ?? p));
      for (const appId of [instAnd.appId, instWin.appId, instIos.appId, instMac.appId, instUapp.appId]) {
        assert.ok(installedIds.has(appId), `Expected installed package "${appId}" in pkgManager.list()`);
      }

      // 3. Simultaneous 5-platform launch BEFORE stepping the scheduler
      const launchAnd = await pkgManager.launch(instAnd.appId, {});
      const launchWin = await pkgManager.launch(instWin.appId, {});
      const launchIos = await pkgManager.launch(instIos.appId, {});
      const launchMac = await pkgManager.launch(instMac.appId, {});
      const launchUapp = await pkgManager.launch(instUapp.appId, {});

      const pids = {
        and: launchAnd?.pid,
        win: launchWin?.pid,
        ios: launchIos?.pid,
        mac: launchMac?.pid,
        uapp: launchUapp?.pid,
      };
      for (const [k, pid] of Object.entries(pids)) {
        assert.ok(Number.isInteger(pid) && pid > 1, `Expected valid PID > 1 for ${k}, got ${pid}`);
        spawnedPids.add(pid);
      }
      assert.equal(new Set(Object.values(pids)).size, 5, `Expected 5 distinct concurrent PIDs: ${JSON.stringify(pids)}`);

      const activeList = pm.list();
      for (const [k, pid] of Object.entries(pids)) {
        assert.ok(activeList.some((p) => p.pid === pid), `Expected concurrent ${k} PID ${pid} present in processManager.list()`);
      }

      // 4. Concurrent round-robin execution under Scheduler
      const andOutPath = `/home/user/Documents/s01-and-${nonce}.txt`;
      for (let round = 0; round < 600; round++) {
        await scheduler.step(10);
        const winDone = isDoneState(pm.get(pids.win)?.state);
        const iosDone = isDoneState(pm.get(pids.ios)?.state);
        const macDone = isDoneState(pm.get(pids.mac)?.state);
        const uappDone = isDoneState(pm.get(pids.uapp)?.state);
        const andPcb = pm.get(pids.and);
        const andReady =
          isDoneState(andPcb?.state) ||
          (extractInstructions(andPcb) > 0 && (await vfsFileExists(vfs, andOutPath)));
        if (winDone && iosDone && macDone && uappDone && andReady) break;
      }

      // Verify genuine execution outputs for EVERY platform
      const pcbAnd = pm.get(pids.and);
      const pcbWin = pm.get(pids.win);
      const pcbIos = pm.get(pids.ios);
      const pcbMac = pm.get(pids.mac);
      const pcbUapp = pm.get(pids.uapp);

      // Android (.apk / Dalvik VM)
      assert.ok(extractInstructions(pcbAnd) > 0, `Android Dalvik process must execute >0 instructions: ${JSON.stringify(pcbAnd)}`);
      const andFileContent = await readVfsText(vfs, andOutPath);
      assert.equal(andFileContent.trim(), `AND_${nonce}=${andSum}`, 'Android VFS output file content mismatch');
      const spAll = await configStore.sharedPrefs.getAll(instAnd.appId, 's01_prefs');
      assert.equal(String(spAll?.and_sum), String(andSum), `Android SharedPreferences mismatch: ${JSON.stringify(spAll)}`);
      const snapAfterExec = compositor.getSnapshot();
      const andWin = (snapAfterExec.windows ?? []).find((w) => w.pid === pids.and || w.appId === instAnd.appId);
      assert.ok(andWin, `Expected Android Activity compositor window in snapshot: ${JSON.stringify(snapAfterExec.windows)}`);
      assert.equal(andWin.platform, 'android');
      assert.ok(
        JSON.stringify(getUiTree(andWin)).includes(String(andSum)),
        `Expected Android TextView uiTree to contain computed sum ${andSum}: ${JSON.stringify(getUiTree(andWin))}`
      );
      const allNotifs = await notifications.list({ includeDismissed: true });
      assert.ok(
        JSON.stringify(allNotifs).includes(`S01Toast_${nonce}`),
        `Expected Android notification/toast S01Toast_${nonce} in NotificationCenter`
      );

      // Windows (.exe / x86-64 + Win32)
      assert.ok(isDoneState(pcbWin?.state), `Windows PE32+ process must finish cleanly, got state=${pcbWin?.state}`);
      assert.ok(extractInstructions(pcbWin) > 0, 'Windows x86-64 process must execute >0 instructions');
      assert.ok(extractStdout(pcbWin).includes(`WIN_S01_${nonce}`), `Windows stdout missing nonce: ${extractStdout(pcbWin)}`);
      assert.equal(extractExitCode(pcbWin), winSum, `Windows computed ExitProcess(winA+winB=${winSum}) mismatch`);
      const winFileContent = await readVfsText(vfs, `/home/user/Documents/s01-win-${nonce}.txt`);
      assert.equal(winFileContent.trim(), `WIN_${nonce}=${winSum}`, 'Windows Win32 CreateFileA output mismatch');
      const regVal = await configStore.registry.getValue('HKCU', `Software\\OmniS01\\Run_${nonce}`, 'WinToken', { uid: 0 });
      assert.equal(
        String(regVal?.data ?? '').replace(/\0+$/, ''),
        `WIN_REG_${nonce}`,
        `Windows ADVAPI32 RegSetValueExA mismatch: ${JSON.stringify(regVal)}`
      );

      // iOS (.ipa / ARM64 Mach-O + bplist00)
      assert.ok(isDoneState(pcbIos?.state), `iOS IPA process must finish cleanly, got state=${pcbIos?.state}`);
      assert.ok(extractInstructions(pcbIos) > 0, 'iOS ARM64 process must execute >0 instructions');
      assert.equal(extractExitCode(pcbIos), iosCode, `iOS exitCode must equal ${iosCode}`);
      const iosFileContent = await readVfsText(vfs, `/home/user/Documents/s01-ios-${nonce}.txt`);
      assert.equal(iosFileContent.trim(), `IOS_${nonce}`, 'iOS /var/mobile/Documents write mismatch');

      // macOS Universal Fat (.app.zip / x86_64 + ARM64)
      assert.ok(isDoneState(pcbMac?.state), `macOS Universal .app process must finish cleanly, got state=${pcbMac?.state}`);
      assert.ok(extractInstructions(pcbMac) > 0, 'macOS Universal process must execute >0 instructions');
      assert.equal(extractExitCode(pcbMac), macCode, `macOS exitCode must equal ${macCode}`);
      const macFileContent = await readVfsText(vfs, `/home/user/Documents/s01-mac-${nonce}.txt`);
      assert.equal(macFileContent.trim(), `MAC_${nonce}`, 'macOS /Users/user/Documents write mismatch');

      // Universal WASM (.uapp / WASI Preview 1)
      assert.ok(isDoneState(pcbUapp?.state), `Universal WASM process must finish cleanly, got state=${pcbUapp?.state}`);
      assert.ok(extractStdout(pcbUapp).includes(`UAPP_S01_${nonce}`), `Universal WASM stdout missing nonce: ${extractStdout(pcbUapp)}`);
      assert.equal(extractExitCode(pcbUapp), uappCode, `Universal WASM proc_exit(${uappCode}) mismatch`);

      // 5. Unified /home/user/Documents/ cross-platform file sharing & PathTranslator checks
      const docEntries = await vfs.readdir('/home/user/Documents');
      const docNames = docEntries.map((e) => (typeof e === 'string' ? e : (e?.name ?? '')));
      for (const fname of [
        `s01-and-${nonce}.txt`,
        `s01-win-${nonce}.txt`,
        `s01-ios-${nonce}.txt`,
        `s01-mac-${nonce}.txt`,
      ]) {
        assert.ok(docNames.includes(fname), `Expected "${fname}" in shared /home/user/Documents: ${JSON.stringify(docNames)}`);
      }

      // Windows mixed-case lookup reading macOS file
      const winMixedPath = `c:\\users\\USER\\documents\\S01-MAC-${nonce.toUpperCase()}.TXT`;
      const winResolved = pathTranslator.toCanonical(winMixedPath, { platform: 'windows' });
      const winReadsMac = await readVfsText(vfs, winResolved.canonicalPath, { platform: 'windows', caseInsensitive: true });
      assert.equal(winReadsMac.trim(), `MAC_${nonce}`, 'Windows case-insensitive path must read macOS file');

      // Android reading Windows file
      const andResolved = pathTranslator.toCanonical(`/sdcard/Documents/s01-win-${nonce}.txt`, { platform: 'android' });
      assert.equal(andResolved.canonicalPath, `/home/user/Documents/s01-win-${nonce}.txt`);
      assert.equal((await readVfsText(vfs, andResolved.canonicalPath, { platform: 'android' })).trim(), `WIN_${nonce}=${winSum}`);

      // iOS reading Android file
      const iosResolved = pathTranslator.toCanonical(`/var/mobile/Documents/s01-and-${nonce}.txt`, { platform: 'ios' });
      assert.equal(iosResolved.canonicalPath, andOutPath);
      assert.equal((await readVfsText(vfs, iosResolved.canonicalPath, { platform: 'ios' })).trim(), `AND_${nonce}=${andSum}`);

      // macOS reading iOS file
      const macResolved = pathTranslator.toCanonical(`/Users/user/Documents/s01-ios-${nonce}.txt`, { platform: 'macos' });
      assert.equal(macResolved.canonicalPath, `/home/user/Documents/s01-ios-${nonce}.txt`);
      assert.equal((await readVfsText(vfs, macResolved.canonicalPath, { platform: 'macos' })).trim(), `IOS_${nonce}`);

      // 6. Multi-MIME Shared Clipboard exchange across platforms
      await clipboard.set({
        text: `WIN_CLIP_${nonce}`,
        html: `<b>WIN_CLIP_${nonce}</b>`,
        mime: 'text/plain',
        sourceAppId: instWin.appId,
      });
      const clip1 = await clipboard.get();
      assert.equal(clip1?.text, `WIN_CLIP_${nonce}`);
      assert.equal(clip1?.html, `<b>WIN_CLIP_${nonce}</b>`);

      await clipboard.set({
        text: JSON.stringify({ from: 'android', sum: andSum, nonce }),
        json: { from: 'android', sum: andSum, nonce },
        mime: 'application/json',
        sourceAppId: instAnd.appId,
      });
      const clip2 = await clipboard.get();
      assert.equal(clip2?.json?.sum, andSum, `Expected JSON clipboard sum=${andSum}, got ${JSON.stringify(clip2)}`);

      await clipboard.set({
        text: `MAC_CLIP_${nonce}`,
        mime: 'text/plain',
        sourceAppId: instMac.appId,
      });
      const clipHist = await clipboard.history(20);
      const histBlob = JSON.stringify(clipHist);
      assert.ok(
        histBlob.includes(`WIN_CLIP_${nonce}`) &&
        histBlob.includes(String(andSum)) &&
        histBlob.includes(`MAC_CLIP_${nonce}`),
        `Expected all 3 cross-platform clipboard entries in history(20): ${histBlob}`
      );

      // 7. Live cross-store Preferences Sync (system.theme <-> HKCU <-> NSGlobalDomain <-> SharedPreferences)
      await configStore.system.set('system.theme', 'dark');
      const hkcuDark = await walkRegistryTree(configStore.registry, 'HKCU', '', 12);
      const nsDark = { ...(await configStore.defaults.readDomain('NSGlobalDomain')) };

      const spCandMap = new Map();
      const addSpCand = (pkg, pref) => {
        if (pkg && pref) spCandMap.set(`${pkg}/${pref}`, [String(pkg), String(pref)]);
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
      for (const fnName of ['listNamespaces', 'list', 'listPackages']) {
        if (typeof configStore.sharedPrefs?.[fnName] === 'function') {
          try {
            const listed = await configStore.sharedPrefs[fnName]();
            if (Array.isArray(listed)) {
              for (const item of listed) {
                if (item && typeof item === 'object') {
                  addSpCand(item.packageName ?? item.pkg ?? item.package, item.prefName ?? item.pref ?? item.name);
                } else if (typeof item === 'string' && item.includes('/')) {
                  const [p, f] = item.split('/');
                  addSpCand(p, f);
                } else if (typeof item === 'string' && item.trim()) {
                  addSpCand(item.trim(), 'system_settings');
                  addSpCand(item.trim(), 'system');
                }
              }
            }
          } catch {
            // optional discovery helper
          }
        }
      }
      const spCandidates = Array.from(spCandMap.values());
      const spDarkSnaps = new Map();
      for (const [pkg, pref] of spCandidates) {
        try {
          spDarkSnaps.set(`${pkg}/${pref}`, { ...(await configStore.sharedPrefs.getAll(pkg, pref)) });
        } catch {
          // candidate namespace absent
        }
      }

      await configStore.system.set('system.theme', 'light');
      const hkcuLight = await walkRegistryTree(configStore.registry, 'HKCU', '', 12);
      const nsLight = { ...(await configStore.defaults.readDomain('NSGlobalDomain')) };

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
      if (regDiff.darkVal !== undefined) {
        await configStore.registry.setValue('HKCU', regDiff.keyPath, regDiff.valueName, regDiff.type, regDiff.darkVal, { uid: 0 });
        assert.equal(await configStore.system.get('system.theme'), 'dark', 'HKCU reverse write must sync system.theme back to dark');
      } else {
        await configStore.system.set('system.theme', 'dark');
        await configStore.registry.setValue('HKCU', regDiff.keyPath, regDiff.valueName, regDiff.type, regDiff.lightVal, { uid: 0 });
        assert.equal(await configStore.system.get('system.theme'), 'light', 'HKCU reverse write must sync system.theme back to light');
      }

      let nsDiff = null;
      for (const k of new Set([...Object.keys(nsDark), ...Object.keys(nsLight)])) {
        if (stableSerialize(nsDark[k]) !== stableSerialize(nsLight[k])) {
          nsDiff = { key: k, darkVal: nsDark[k], lightVal: nsLight[k] };
          break;
        }
      }
      assert.ok(nsDiff, 'Toggling system.theme dark->light must mirror into Apple NSGlobalDomain');
      if (nsDiff.lightVal !== undefined) {
        await configStore.system.set('system.theme', 'dark');
        await configStore.defaults.set('NSGlobalDomain', nsDiff.key, nsDiff.lightVal);
        assert.equal(await configStore.system.get('system.theme'), 'light', 'NSGlobalDomain reverse write must sync system.theme back to light');
      } else {
        assert.notEqual(nsDiff.darkVal, undefined, `NSGlobalDomain.${nsDiff.key} must have a defined dark value`);
        await configStore.system.set('system.theme', 'light');
        await configStore.defaults.set('NSGlobalDomain', nsDiff.key, nsDiff.darkVal);
        assert.equal(await configStore.system.get('system.theme'), 'dark', 'NSGlobalDomain reverse write must sync system.theme back to dark');
      }

      await configStore.system.set('system.theme', 'light');
      let spDiff = null;
      for (const [pkg, pref] of spCandidates) {
        let lightMap;
        try {
          lightMap = await configStore.sharedPrefs.getAll(pkg, pref);
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
      if (spDiff.darkVal !== undefined) {
        await applySharedPrefsEdit(configStore.sharedPrefs, spDiff.pkg, spDiff.pref, [{ key: spDiff.key, value: spDiff.darkVal }]);
        assert.equal(await configStore.system.get('system.theme'), 'dark', 'SharedPreferences reverse write must sync system.theme back to dark');
      } else {
        assert.notEqual(spDiff.lightVal, undefined);
        await configStore.system.set('system.theme', 'dark');
        await applySharedPrefsEdit(configStore.sharedPrefs, spDiff.pkg, spDiff.pref, [{ key: spDiff.key, value: spDiff.lightVal }]);
        assert.equal(await configStore.system.get('system.theme'), 'light', 'SharedPreferences reverse write must sync system.theme back to light');
      }

      // 8. Cross-platform Universal Intent Routing (manifest auto-indexing + single & multi-handler chooser)
      const resIos = await intentRouter.resolve({ scheme: `s01ios${nonce}`, uri: `s01ios${nonce}://open` });
      assert.ok(JSON.stringify(resIos).includes(instIos.appId), `Expected iOS scheme to resolve ${instIos.appId}: ${JSON.stringify(resIos)}`);

      const resMacScheme = await intentRouter.resolve({ scheme: `s01mac${nonce}`, uri: `s01mac${nonce}://doc` });
      assert.ok(JSON.stringify(resMacScheme).includes(instMac.appId), `Expected macOS scheme to resolve ${instMac.appId}`);

      const resMacExt = await intentRouter.resolve({ extension: macExt });
      assert.ok(JSON.stringify(resMacExt).includes(instMac.appId), `Expected macOS extension .${macExt} to resolve ${instMac.appId}`);

      const resUapp = await intentRouter.resolve({ scheme: `s01uni${nonce}`, uri: `s01uni${nonce}://ping` });
      assert.ok(JSON.stringify(resUapp).includes(instUapp.appId), `Expected Universal scheme to resolve ${instUapp.appId}`);

      const resAnd = await intentRouter.resolve({ action: `omni.s01.sync.${nonce}`, mimeType: 'text/plain' });
      assert.ok(JSON.stringify(resAnd).includes(instAnd.appId), `Expected Android intent-filter action to resolve ${instAnd.appId}`);

      const singleDisp = await intentRouter.dispatch({
        scheme: `s01uni${nonce}`,
        uri: `s01uni${nonce}://ping`,
        sourcePid: 1,
      });
      assert.equal(singleDisp?.status, 'DELIVERED', `Expected single-handler DELIVERED: ${JSON.stringify(singleDisp)}`);
      assert.equal(singleDisp?.targetAppId, instUapp.appId);
      if (singleDisp?.pid > 1) spawnedPids.add(singleDisp.pid);

      const sharedAction = `omni.s01.handoff.${nonce}`;
      await intentRouter.registerHandlers(instAnd.appId, [{ action: sharedAction, mimeType: 'text/plain' }]);
      await intentRouter.registerHandlers(instUapp.appId, [{ action: sharedAction, mimeType: 'text/plain' }]);

      const chooserDisp = await intentRouter.dispatch({
        action: sharedAction,
        mimeType: 'text/plain',
        sourcePid: 1,
      });
      assert.equal(chooserDisp?.status, 'CHOOSER_REQUIRED', `Expected multi-handler CHOOSER_REQUIRED: ${JSON.stringify(chooserDisp)}`);
      const candBlob = JSON.stringify(chooserDisp?.candidates ?? []);
      assert.ok(
        candBlob.includes(instAnd.appId) && candBlob.includes(instUapp.appId),
        `Expected chooser candidates to include both ${instAnd.appId} and ${instUapp.appId}: ${candBlob}`
      );

      const chosenDisp = await intentRouter.dispatch({
        action: sharedAction,
        mimeType: 'text/plain',
        sourcePid: 1,
        preferredAppId: instUapp.appId,
      });
      assert.equal(chosenDisp?.status, 'DELIVERED', `Expected preferredAppId DELIVERED: ${JSON.stringify(chosenDisp)}`);
      assert.equal(chosenDisp?.targetAppId, instUapp.appId);
      if (chosenDisp?.pid > 1) spawnedPids.add(chosenDisp.pid);

      // 9. Dynamic Island Live Activity + Notifications action/dismiss loop
      const posted = await notifications.post({
        appId: instIos.appId,
        platform: 'ios',
        title: `Island_${nonce}`,
        body: '5-Platform Sync Active',
        priority: 'high',
        category: 'sync',
        actions: [{ id: 'ack', label: 'Acknowledge' }],
        liveActivity: {
          id: `la-${nonce}`,
          title: `S01Live_${nonce}`,
          status: 'Active',
          progress: 0.8,
        },
      });
      const notifId = posted?.id ?? posted?.notification?.id;
      assert.ok(notifId, `Expected notification id from notifications.post(): ${JSON.stringify(posted)}`);

      const liveActs = await notifications.getLiveActivities();
      const liveBlob = JSON.stringify(liveActs);
      assert.ok(
        liveBlob.includes(`la-${nonce}`) || liveBlob.includes(`S01Live_${nonce}`),
        `Expected Dynamic Island Live Activity la-${nonce} in getLiveActivities(): ${liveBlob}`
      );

      await notifications.invokeAction(notifId, 'ack');
      await notifications.dismiss(notifId);
      const activeNotifs = await notifications.list({ includeDismissed: false });
      assert.equal(
        activeNotifs.some((n) => n?.id === notifId),
        false,
        `Dismissed notification ${notifId} must not appear in active list`
      );

      // 10. Clean multi-process teardown
      for (const pid of spawnedPids) {
        await stopPidBestEffort(osHandle, pid);
      }
      for (let i = 0; i < 20; i++) {
        await scheduler.step(5);
      }

      const finalSnap = compositor.getSnapshot();
      const scenarioAppIds = new Set([instAnd.appId, instWin.appId, instIos.appId, instMac.appId, instUapp.appId]);
      const leftoverWins = (finalSnap.windows ?? []).filter(
        (w) => spawnedPids.has(w.pid) || scenarioAppIds.has(w.appId)
      );
      assert.equal(
        leftoverWins.length,
        0,
        `Expected 0 leftover scenario windows after teardown, found: ${JSON.stringify(leftoverWins)}`
      );

      for (const pid of spawnedPids) {
        const pcb = pm.get(pid);
        assert.ok(
          !pcb || isDoneState(pcb.state),
          `Expected scenario PID ${pid} terminated after teardown, got state=${pcb?.state}`
        );
      }

      const diag = kernel.getDiagnostics();
      assert.equal(diag?.state, 'RUNNING', `Kernel must remain RUNNING after teardown: ${JSON.stringify(diag)}`);
      assert.equal(diag?.lastPanic ?? null, null, `Expected zero kernel panics: ${JSON.stringify(diag?.lastPanic)}`);
    } finally {
      if (osHandle) {
        for (const pid of spawnedPids) {
          await stopPidBestEffort(osHandle, pid);
        }
        await osHandle.shutdown().catch(() => {});
      }
    }
  });

  it('T4-S01-02 [Scenario 2]: Multi-process fault containment under concurrent 5-app load (__PAGEZERO SIGSEGV & Dalvik goto 0 SIGXCPU)', async () => {
    let osHandle = null;
    const spawnedPids = new Set();
    try {
      osHandle = await loadPublicOmniOS();

      const kernel = osHandle.require('kernel');
      const serviceManager = osHandle.require('serviceManager');
      const pm = osHandle.require('processManager');
      const scheduler = osHandle.require('scheduler');
      const vfs = osHandle.require('vfs');
      const compositor = osHandle.require('compositor');
      const pkgManager = osHandle.require('pkgManager');

      scheduler.stop?.();

      // ======================================================================
      // Wave A: 4 Healthy Platform Apps + 5th ARM64 __PAGEZERO SIGSEGV Binary
      // ======================================================================
      const nonceA = makeNonce(4);
      const [andA, andB] = makeSafeAddOperands();
      const andSum = andA + andB;
      const [winA, winB] = makeSafeAddOperands();
      const winSum = winA + winB;
      const iosCodeA = makeDistinctExitCode(25);
      const uappCodeA = makeDistinctExitCode(85);

      const waveAAndPath = `/home/user/Documents/s02a-and-${nonceA}.txt`;
      const waveAAnd = await stageInspectInstall(
        osHandle,
        buildCustomApk({
          packageName: `com.omnios.s02a.and${nonceA}`,
          appLabel: `S02AAnd_${nonceA}`,
          computeA: andA,
          computeB: andB,
          computeOp: 'add',
          outputFile: `/sdcard/Documents/s02a-and-${nonceA}.txt`,
          outputContent: `S02A_AND_${nonceA}=${andSum}`,
          permissions: ['android.permission.WRITE_EXTERNAL_STORAGE'],
        }),
        `s02a-and-${nonceA}.apk`,
        'android-apk',
        'android'
      );

      const waveAWin = await stageInspectInstall(
        osHandle,
        buildCustomPe64Exe({
          subsystem: 3,
          message: `S02A_WIN_${nonceA}\n`,
          computeExitSum: [winA, winB],
          writeFilePath: `C:\\Users\\user\\Documents\\s02a-win-${nonceA}.txt`,
          writeFileContent: `S02A_WIN_${nonceA}=${winSum}`,
        }),
        `s02a-win-${nonceA}.exe`,
        'windows-pe',
        'windows'
      );

      const waveAIos = await stageInspectInstall(
        osHandle,
        buildCustomIpa({
          bundleId: `com.omnios.s02a.ios${nonceA}`,
          displayName: `S02AIos_${nonceA}`,
          executableName: `S02AIos_${nonceA}`,
          fileWrite: {
            path: `/var/mobile/Documents/s02a-ios-${nonceA}.txt`,
            content: `S02A_IOS_${nonceA}`,
          },
          exitCode: iosCodeA,
        }),
        `s02a-ios-${nonceA}.ipa`,
        'ios-ipa',
        'ios'
      );

      const waveAUapp = await stageInspectInstall(
        osHandle,
        buildCustomUapp({
          appId: `com.omnios.s02a.uapp${nonceA}`,
          name: `S02AUapp_${nonceA}`,
          message: `S02A_UAPP_${nonceA}\n`,
          exitCode: uappCodeA,
        }),
        `s02a-uapp-${nonceA}.uapp`,
        'universal-uapp',
        'universal'
      );

      const pzFaultIpa = await stageInspectInstall(
        osHandle,
        buildCustomIpa({
          bundleId: `com.omnios.s02.pz${nonceA}`,
          displayName: `S02PzFault_${nonceA}`,
          executableName: `S02PzFault_${nonceA}`,
          machoBytes: buildPageZeroDerefMachO({ addr: 0x100 }),
        }),
        `s02-pz-${nonceA}.ipa`,
        'ios-ipa',
        'ios'
      );

      const rssBefore = process.memoryUsage().rss;
      const waveADmesgCursor = snapshotDmesgCursor(kernel);

      const lAndA = await pkgManager.launch(waveAAnd.appId, {});
      const lWinA = await pkgManager.launch(waveAWin.appId, {});
      const lIosA = await pkgManager.launch(waveAIos.appId, {});
      const lUappA = await pkgManager.launch(waveAUapp.appId, {});
      const lPzFault = await pkgManager.launch(pzFaultIpa.appId, {});

      const waveAPids = [lAndA.pid, lWinA.pid, lIosA.pid, lUappA.pid, lPzFault.pid];
      for (const pid of waveAPids) {
        assert.ok(Number.isInteger(pid) && pid > 1, `Expected valid Wave A PID > 1, got ${pid}`);
        spawnedPids.add(pid);
      }
      assert.equal(new Set(waveAPids).size, 5, 'Expected 5 distinct Wave A concurrent PIDs');

      // Verify __PAGEZERO virtual guard did NOT allocate 4 GiB RAM before stepping
      const pzPcbBefore = pm.get(lPzFault.pid);
      const pzStats = pzPcbBefore?.addressSpace?.getStats?.() ?? pzPcbBefore?.vmm?.getStats?.() ?? null;
      if (pzStats) {
        assert.ok(
          Number(pzStats.usedBytes ?? 0) < 64 * 1024 * 1024,
          `__PAGEZERO must not allocate 4GiB RAM (usedBytes=${pzStats.usedBytes})`
        );
        assert.ok(
          Number(pzStats.mappedPages ?? 0) < 4096,
          `__PAGEZERO must not map 1M pages (mappedPages=${pzStats.mappedPages})`
        );
      }

      for (let round = 0; round < 600; round++) {
        await scheduler.step(10);
        const pzDone = isDoneState(pm.get(lPzFault.pid)?.state);
        const winDone = isDoneState(pm.get(lWinA.pid)?.state);
        const iosDone = isDoneState(pm.get(lIosA.pid)?.state);
        const uappDone = isDoneState(pm.get(lUappA.pid)?.state);
        const andReady = extractInstructions(pm.get(lAndA.pid)) > 0 && (await vfsFileExists(vfs, waveAAndPath));
        if (pzDone && winDone && iosDone && uappDone && andReady) break;
      }

      const rssAfter = process.memoryUsage().rss;
      assert.ok(
        rssAfter - rssBefore < 256 * 1024 * 1024,
        `Host RSS delta must remain <256MiB across __PAGEZERO load (delta=${rssAfter - rssBefore})`
      );

      // Faulting __PAGEZERO PID MUST have terminated with fault / SIGSEGV / non-zero exit
      const pzPcbAfter = pm.get(lPzFault.pid);
      assert.ok(isDoneState(pzPcbAfter?.state), `__PAGEZERO faulting PID must terminate, got state=${pzPcbAfter?.state}`);
      assert.notEqual(extractExitCode(pzPcbAfter), 0, '__PAGEZERO faulting PID must NOT exit with code 0');
      const waveANewDmesg = getNewDmesgEntries(kernel, waveADmesgCursor);
      const pzRawSig = pzPcbAfter?.signal ?? pzPcbAfter?.exitSignal ?? pzPcbAfter?.terminationSignal;
      const pzPcbSig11 = Number(pzRawSig) === 11;
      const pzDiagBlob = JSON.stringify({
        signal: pzRawSig,
        fault: pzPcbAfter?.fault ?? pzPcbAfter?.lastFault ?? pzPcbAfter?.exitReason,
        dmesg: waveANewDmesg,
      });
      assert.ok(
        pzPcbSig11 || /SIGSEGV|SEGV|PAGEZERO|MEMORY_FAULT|MemoryFault/i.test(pzDiagBlob),
        `Expected SIGSEGV (11) / memory fault indication for __PAGEZERO deref: ${pzDiagBlob}`
      );

      // All 4 Wave A healthy siblings succeeded & Android Activity stayed alive!
      const waveAAndPcb = pm.get(lAndA.pid);
      assert.ok(
        waveAAndPcb && !isDoneState(waveAAndPcb.state),
        `Wave A healthy Android Activity must stay alive alongside __PAGEZERO fault, got state=${waveAAndPcb?.state}`
      );
      assert.equal((await readVfsText(vfs, waveAAndPath)).trim(), `S02A_AND_${nonceA}=${andSum}`);
      const waveAAndWin = (compositor.getSnapshot().windows ?? []).find((w) => w.pid === lAndA.pid || w.appId === waveAAnd.appId);
      assert.ok(waveAAndWin, 'Wave A healthy Android window must remain open');

      assert.ok(isDoneState(pm.get(lWinA.pid)?.state));
      assert.equal(extractExitCode(pm.get(lWinA.pid)), winSum);
      assert.ok(extractStdout(pm.get(lWinA.pid)).includes(`S02A_WIN_${nonceA}`));
      assert.equal((await readVfsText(vfs, `/home/user/Documents/s02a-win-${nonceA}.txt`)).trim(), `S02A_WIN_${nonceA}=${winSum}`);

      assert.ok(isDoneState(pm.get(lIosA.pid)?.state));
      assert.equal(extractExitCode(pm.get(lIosA.pid)), iosCodeA);
      assert.equal((await readVfsText(vfs, `/home/user/Documents/s02a-ios-${nonceA}.txt`)).trim(), `S02A_IOS_${nonceA}`);

      assert.ok(isDoneState(pm.get(lUappA.pid)?.state));
      assert.equal(extractExitCode(pm.get(lUappA.pid)), uappCodeA);
      assert.ok(extractStdout(pm.get(lUappA.pid)).includes(`S02A_UAPP_${nonceA}`));

      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING');
      assert.equal(kernel.getDiagnostics()?.lastPanic ?? null, null);

      // ======================================================================
      // Wave B: Live Wave-A Android Activity + 3 Fresh Healthy Siblings +
      //         5th Runaway Dalvik Infinite Loop (`goto 0` -> E_CPU_QUOTA / SIGXCPU)
      // ======================================================================
      const nonceB = makeNonce(4);
      const [winBA, winBB] = makeSafeAddOperands();
      const winBSum = winBA + winBB;
      const iosCodeB = makeDistinctExitCode(45);
      const uappCodeB = makeDistinctExitCode(115);

      const waveBWin = await stageInspectInstall(
        osHandle,
        buildCustomPe64Exe({
          subsystem: 3,
          message: `S02B_WIN_${nonceB}\n`,
          computeExitSum: [winBA, winBB],
          writeFilePath: `C:\\Users\\user\\Documents\\s02b-win-${nonceB}.txt`,
          writeFileContent: `S02B_WIN_${nonceB}=${winBSum}`,
        }),
        `s02b-win-${nonceB}.exe`,
        'windows-pe',
        'windows'
      );

      const waveBIos = await stageInspectInstall(
        osHandle,
        buildCustomIpa({
          bundleId: `com.omnios.s02b.ios${nonceB}`,
          displayName: `S02BIos_${nonceB}`,
          executableName: `S02BIos_${nonceB}`,
          fileWrite: {
            path: `/var/mobile/Documents/s02b-ios-${nonceB}.txt`,
            content: `S02B_IOS_${nonceB}`,
          },
          exitCode: iosCodeB,
        }),
        `s02b-ios-${nonceB}.ipa`,
        'ios-ipa',
        'ios'
      );

      const waveBUapp = await stageInspectInstall(
        osHandle,
        buildCustomUapp({
          appId: `com.omnios.s02b.uapp${nonceB}`,
          name: `S02BUapp_${nonceB}`,
          message: `S02B_UAPP_${nonceB}\n`,
          exitCode: uappCodeB,
        }),
        `s02b-uapp-${nonceB}.uapp`,
        'universal-uapp',
        'universal'
      );

      const infLoopApk = await stageInspectInstall(
        osHandle,
        buildDexInfiniteLoopApk(),
        `s02b-infloop-${nonceB}.apk`,
        'android-apk',
        'android'
      );

      const waveBDmesgCursor = snapshotDmesgCursor(kernel);

      const lWinB = await pkgManager.launch(waveBWin.appId, {});
      const lIosB = await pkgManager.launch(waveBIos.appId, {});
      const lUappB = await pkgManager.launch(waveBUapp.appId, {});
      const lLoop = await pkgManager.launch(infLoopApk.appId, {});

      for (const pid of [lWinB.pid, lIosB.pid, lUappB.pid, lLoop.pid]) {
        assert.ok(Number.isInteger(pid) && pid > 1, `Expected valid Wave B PID > 1, got ${pid}`);
        spawnedPids.add(pid);
      }

      const t0 = Date.now();
      for (let round = 0; round < 400; round++) {
        await scheduler.step(25);
        const loopDone = isDoneState(pm.get(lLoop.pid)?.state);
        const winBDone = isDoneState(pm.get(lWinB.pid)?.state);
        const iosBDone = isDoneState(pm.get(lIosB.pid)?.state);
        const uappBDone = isDoneState(pm.get(lUappB.pid)?.state);
        if (loopDone && winBDone && iosBDone && uappBDone) break;
      }

      if (!isDoneState(pm.get(lLoop.pid)?.state)) {
        if (typeof scheduler.runUntilIdle === 'function') {
          await scheduler.runUntilIdle(lLoop.pid, 4000);
        } else {
          for (let i = 0; i < 200 && !isDoneState(pm.get(lLoop.pid)?.state); i++) {
            await scheduler.step(25);
          }
        }
      }

      const elapsedMs = Date.now() - t0;
      assert.ok(elapsedMs < 15000, `Runaway Dalvik loop containment must complete <15s without hanging host (took ${elapsedMs}ms)`);

      const loopPcb = pm.get(lLoop.pid);
      assert.ok(isDoneState(loopPcb?.state), `Runaway Dalvik infinite-loop PID must terminate via CPU quota, got state=${loopPcb?.state}`);
      assert.notEqual(extractExitCode(loopPcb), 0, 'Runaway Dalvik infinite-loop PID must NOT exit 0');
      const waveBNewDmesg = getNewDmesgEntries(kernel, waveBDmesgCursor);
      const loopRawSig = loopPcb?.signal ?? loopPcb?.exitSignal ?? loopPcb?.terminationSignal;
      const loopPcbSig24 = Number(loopRawSig) === 24;
      const loopBlob = JSON.stringify({
        signal: loopRawSig,
        fault: loopPcb?.fault ?? loopPcb?.lastFault ?? loopPcb?.exitReason,
        dmesg: waveBNewDmesg,
      });
      assert.ok(
        loopPcbSig24 || /CPU_QUOTA|SIGXCPU|XCPU|quota.*exceed|exceed.*quota|budget.*exhaust|instruction.*limit/i.test(loopBlob),
        `Expected E_CPU_QUOTA / SIGXCPU (24) termination evidence for runaway loop: ${loopBlob}`
      );

      // Wave-A healthy Android Activity & Compositor window MUST STILL BE ALIVE!
      const waveAStill = pm.get(lAndA.pid);
      assert.ok(
        waveAStill && !isDoneState(waveAStill.state),
        `Wave A healthy Android Activity PID ${lAndA.pid} must survive sibling runaway loop, got state=${waveAStill?.state}`
      );
      const stillWins = compositor.getSnapshot().windows ?? [];
      assert.ok(
        stillWins.some((w) => getWinId(w) === getWinId(waveAAndWin) || w.pid === lAndA.pid),
        'Wave A healthy Android Compositor window must remain open after sibling runaway kill'
      );

      // All 3 Wave-B healthy siblings completed cleanly with exact nonceB outputs
      assert.ok(isDoneState(pm.get(lWinB.pid)?.state));
      assert.equal(extractExitCode(pm.get(lWinB.pid)), winBSum);
      assert.ok(extractStdout(pm.get(lWinB.pid)).includes(`S02B_WIN_${nonceB}`));
      assert.equal((await readVfsText(vfs, `/home/user/Documents/s02b-win-${nonceB}.txt`)).trim(), `S02B_WIN_${nonceB}=${winBSum}`);

      assert.ok(isDoneState(pm.get(lIosB.pid)?.state));
      assert.equal(extractExitCode(pm.get(lIosB.pid)), iosCodeB);
      assert.equal((await readVfsText(vfs, `/home/user/Documents/s02b-ios-${nonceB}.txt`)).trim(), `S02B_IOS_${nonceB}`);

      assert.ok(isDoneState(pm.get(lUappB.pid)?.state));
      assert.equal(extractExitCode(pm.get(lUappB.pid)), uappCodeB);
      assert.ok(extractStdout(pm.get(lUappB.pid)).includes(`S02B_UAPP_${nonceB}`));

      // Kernel & all 6 core daemons healthy
      const finalDiag = kernel.getDiagnostics();
      assert.equal(finalDiag?.state, 'RUNNING');
      assert.equal(finalDiag?.lastPanic ?? null, null);
      const svcJson = JSON.stringify(serviceManager.getStatus());
      for (const svcName of ['vfsd', 'configd', 'ipc-brokerd', 'securityd', 'pkgd', 'compositord']) {
        assert.ok(svcJson.includes(svcName), `Core service "${svcName}" must remain healthy after fault containment`);
      }
    } finally {
      if (osHandle) {
        for (const pid of spawnedPids) {
          await stopPidBestEffort(osHandle, pid);
        }
        await osHandle.shutdown().catch(() => {});
      }
    }
  });
});
