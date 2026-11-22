/**
 * OmniOS Tier 1 E2E Suite — FA-10: Android Runtime
 * Covers PROJECT.md Features: F-036, F-037, F-038, F-039, F-040, F-046.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded app outputs (runtime nonces & operands).
 * - Clean try/finally teardown on every test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  REPO_ROOT,
  createTempDataDir,
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';
import {
  buildAxmlManifest,
  buildResourcesArsc,
  buildZip,
  sha256Hex,
} from '../lib/binary-utils.mjs';
import {
  DALVIK,
  buildCustomApk,
  buildDex,
} from '../lib/fixtures-android-win.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(fn, { timeoutMs = 5000, intervalMs = 40, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value) return value;
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

function asArray(payload, keys = ['items', 'data', 'notifications', 'windows', 'packages', 'entries']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return [];
}

function treeContainsText(node, needle) {
  if (node === null || node === undefined) return false;
  if (typeof node === 'string' || typeof node === 'number' || typeof node === 'boolean') {
    return String(node).includes(needle);
  }
  if (Array.isArray(node)) {
    return node.some((item) => treeContainsText(item, needle));
  }
  if (typeof node === 'object') {
    for (const val of Object.values(node)) {
      if (treeContainsText(val, needle)) return true;
    }
  }
  return false;
}

function extractStdout(pcb, summary) {
  const raw = summary?.stdout ?? pcb?.streams?.stdout ?? pcb?.stdout ?? '';
  if (typeof raw === 'string') return raw;
  if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) return Buffer.from(raw).toString('utf8');
  if (Array.isArray(raw)) {
    return raw
      .map((chunk) => (Buffer.isBuffer(chunk) || chunk instanceof Uint8Array
        ? Buffer.from(chunk).toString('utf8')
        : String(chunk ?? '')))
      .join('');
  }
  return String(raw ?? '');
}

function extractInstructions(pcb, summary) {
  return Number(
    summary?.instructionsExecuted ??
    pcb?.stats?.instructionsExecuted ??
    pcb?.instructionsExecuted ??
    0
  );
}

async function runAndroidTicks(osHandle, pid, maxTicks = 500) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  let summary = null;
  if (typeof scheduler.runUntilIdle === 'function') {
    summary = await scheduler.runUntilIdle(pid, maxTicks);
  } else {
    for (let i = 0; i < Math.ceil(maxTicks / 25); i++) {
      await scheduler.step(25);
      const cur = pm.get(pid);
      if (!cur || cur.state === 'TERMINATED' || cur.state === 'ZOMBIE' || cur.state === 'BLOCKED') {
        break;
      }
    }
  }
  const pcb = pm.get(pid);
  return {
    pcb,
    summary,
    stdout: extractStdout(pcb, summary),
    instructionsExecuted: extractInstructions(pcb, summary),
  };
}

function grantAndroidCaps(osHandle, appId) {
  const security = osHandle.require('security');
  for (const cap of ['fs.read.user', 'fs.write.user', 'notifications.post', 'ui.window', 'ipc.broadcast', 'clipboard.read', 'clipboard.write']) {
    security.setGrant(appId, cap, 'allow');
  }
}

async function installPackageHttp(api, bytes, filename) {
  const b64 = Buffer.from(bytes).toString('base64');
  let res = await api.post('/api/v1/packages/install', {
    base64: b64,
    data: b64,
    filename,
    grantAll: true,
  });
  if (res.status === 400 || res.status === 415 || res.status === 422) {
    res = await api.post('/api/v1/packages/install', bytes, {
      query: { filename, grantAll: 'true' },
      headers: {
        'content-type': 'application/octet-stream',
        'x-filename': filename,
      },
    });
  }
  assert.ok(res.ok, `Expected HTTP 2xx installing ${filename}, got ${res.status}: ${res.text}`);
  return res.json;
}

function buildMinimalActivityDex(packageName) {
  const classDesc = `L${packageName.replace(/\./g, '/')}/MainActivity;`;
  return buildDex({
    dexVersion: '035',
    classes: [
      {
        descriptor: classDesc,
        accessFlags: 0x0001,
        superclass: 'Landroid/app/Activity;',
        sourceFile: 'MainActivity.java',
        directMethods: [
          {
            name: '<init>',
            returnType: 'V',
            params: [],
            accessFlags: 0x10001,
            registersSize: 1,
            insSize: 1,
            outsSize: 1,
            buildInsns: (ctx) => [
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_DIRECT,
                [0],
                ctx.method('Landroid/app/Activity;', '<init>', 'V', [])
              ),
              ...DALVIK.returnVoid(),
            ],
          },
        ],
        virtualMethods: [
          {
            name: 'onCreate',
            returnType: 'V',
            params: ['Landroid/os/Bundle;'],
            accessFlags: 0x0001,
            registersSize: 2,
            insSize: 2,
            outsSize: 2,
            buildInsns: (ctx) => [
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_SUPER,
                [0, 1],
                ctx.method('Landroid/app/Activity;', 'onCreate', 'V', ['Landroid/os/Bundle;'])
              ),
              ...DALVIK.returnVoid(),
            ],
          },
        ],
      },
    ],
  });
}

describe('Tier 1 — FA-10: Android Runtime (APK, AXML/ARSC, DEX, Dalvik VM & Framework)', () => {
  it('T1-FA10-01 [F-036]: Android .apk loader & verifier extracting manifest, DEX, resources & APK v2 Signing Block', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const intentRouter = osHandle.require('intentRouter');
      const tok = makeNonce();
      const packageName = `com.omnios.apkload.${tok}`;
      const appLabel = `ApkLoad-${tok}`;
      const scheme = `omniload${tok}`;

      const apkBytes = buildCustomApk({
        packageName,
        appLabel,
        permissions: [
          'android.permission.READ_EXTERNAL_STORAGE',
          'android.permission.POST_NOTIFICATIONS',
        ],
        intentFilters: [
          {
            actions: ['android.intent.action.VIEW'],
            categories: ['android.intent.category.DEFAULT'],
            data: [{ scheme }],
          },
        ],
        includeResourcesArsc: true,
        includeV2SigBlock: true,
        dexVersion: '035',
      });

      const insp = await pkgManager.inspect(apkBytes);
      assert.equal(insp.format, 'android-apk');
      assert.equal(insp.platform, 'android');
      assert.equal(insp.arch, 'dalvik');
      assert.equal(insp.appId, packageName);
      assert.equal(insp.name ?? insp.label, appLabel);
      assert.equal(insp.sha256, sha256Hex(apkBytes));
      assert.ok(
        JSON.stringify(insp).includes('MainActivity'),
        `Expected APK inspection metadata to include MainActivity, got: ${JSON.stringify(insp)}`
      );

      await pkgManager.install(apkBytes, { grantAll: true });
      const resolved = intentRouter.resolve({ scheme });
      assert.ok(
        Array.isArray(resolved) && resolved.some((h) => (h.appId ?? h.id) === packageName),
        `Expected intentRouter to index APK <intent-filter> scheme "${scheme}" for ${packageName}, got: ${JSON.stringify(resolved)}`
      );
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA10-02 [F-037]: Binary AXML AndroidManifest.xml (UTF-16 & UTF-8 pools) and resources.arsc @string/app_name (0x7f010000) resolution', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');

      // Case A: UTF-16 ResStringPool + 0x7f010000 reference
      const tok1 = makeNonce();
      const pkg1 = `com.omnios.arsc16.${tok1}`;
      const label1 = `ArscUtf16-${tok1}`;
      const apkUtf16 = buildZip([
        {
          name: 'AndroidManifest.xml',
          data: buildAxmlManifest({
            packageName: pkg1,
            versionCode: 24,
            versionName: '2.4.0',
            labelResId: 0x7f010000,
            mainActivity: '.MainActivity',
            utf8Pool: false,
          }),
          method: 8,
        },
        { name: 'classes.dex', data: buildMinimalActivityDex(pkg1), method: 8 },
        {
          name: 'resources.arsc',
          data: buildResourcesArsc({
            packageId: 0x7f,
            packageName: pkg1,
            strings: { app_name: label1 },
            utf8Pool: false,
          }),
          method: 0,
          alignDataTo: 4,
        },
      ]);

      const insp1 = await pkgManager.inspect(apkUtf16);
      assert.equal(insp1.format, 'android-apk');
      assert.equal(insp1.appId, pkg1);
      assert.equal(
        insp1.name ?? insp1.label ?? insp1.manifest?.label,
        label1,
        `Expected @string/app_name (0x7f010000) UTF-16 lookup to resolve "${label1}", got: ${JSON.stringify(insp1)}`
      );
      assert.ok(
        String(insp1.version ?? insp1.versionName ?? insp1.manifest?.versionName ?? '').includes('2.4.0'),
        `Expected versionName 2.4.0 in UTF-16 manifest inspection, got: ${JSON.stringify(insp1)}`
      );

      // Case B: UTF-8 ResStringPool + 0x7f010000 reference
      const tok2 = makeNonce();
      const pkg2 = `com.omnios.arsc8.${tok2}`;
      const label2 = `ArscUtf8-${tok2}`;
      const apkUtf8 = buildZip([
        {
          name: 'AndroidManifest.xml',
          data: buildAxmlManifest({
            packageName: pkg2,
            versionCode: 31,
            versionName: '3.1.0',
            labelResId: 0x7f010000,
            mainActivity: '.MainActivity',
            utf8Pool: true,
          }),
          method: 8,
        },
        { name: 'classes.dex', data: buildMinimalActivityDex(pkg2), method: 8 },
        {
          name: 'resources.arsc',
          data: buildResourcesArsc({
            packageId: 0x7f,
            packageName: pkg2,
            strings: { app_name: label2 },
            utf8Pool: true,
          }),
          method: 0,
          alignDataTo: 4,
        },
      ]);

      const insp2 = await pkgManager.inspect(apkUtf8);
      assert.equal(insp2.format, 'android-apk');
      assert.equal(insp2.appId, pkg2);
      assert.equal(
        insp2.name ?? insp2.label ?? insp2.manifest?.label,
        label2,
        `Expected @string/app_name (0x7f010000) UTF-8 lookup to resolve "${label2}", got: ${JSON.stringify(insp2)}`
      );
      assert.ok(
        String(insp2.version ?? insp2.versionName ?? insp2.manifest?.versionName ?? '').includes('3.1.0'),
        `Expected versionName 3.1.0 in UTF-8 manifest inspection, got: ${JSON.stringify(insp2)}`
      );
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA10-03 [F-038]: DEX v035 & v039 parsing, Adler-32/SHA-1 validation and bytecode execution', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const vfs = osHandle.require('vfs');
      const compositor = osHandle.require('compositor');
      const tok = makeNonce();

      const a35 = 1000 + crypto.randomInt(5000);
      const b35 = 1000 + crypto.randomInt(5000);
      const expected35 = String((a35 + b35) | 0);
      const pkg35 = `com.omnios.dex35.${tok}`;
      const apk35 = buildCustomApk({
        packageName: pkg35,
        appLabel: `Dex35-${tok}`,
        dexVersion: '035',
        computeA: a35,
        computeB: b35,
        computeOp: 'add',
        outputFile: `/sdcard/Documents/dex35-${tok}.txt`,
      });

      const a39 = 20000 + crypto.randomInt(20000);
      const b39 = 1000 + crypto.randomInt(9000);
      const expected39 = String((a39 - b39) | 0);
      const pkg39 = `com.omnios.dex39.${tok}`;
      const apk39 = buildCustomApk({
        packageName: pkg39,
        appLabel: `Dex39-${tok}`,
        dexVersion: '039',
        computeA: a39,
        computeB: b39,
        computeOp: 'sub',
        outputFile: `/sdcard/Documents/dex39-${tok}.txt`,
      });

      const insp35 = await pkgManager.inspect(apk35);
      const insp39 = await pkgManager.inspect(apk39);
      assert.equal(insp35.format, 'android-apk');
      assert.equal(insp39.format, 'android-apk');

      await pkgManager.install(apk35, { grantAll: true });
      await pkgManager.install(apk39, { grantAll: true });
      grantAndroidCaps(osHandle, pkg35);
      grantAndroidCaps(osHandle, pkg39);

      const l35 = await pkgManager.launch(pkg35);
      await runAndroidTicks(osHandle, l35.pid, 500);
      const l39 = await pkgManager.launch(pkg39);
      await runAndroidTicks(osHandle, l39.pid, 500);

      const file35 = String(await vfs.readFile(`/home/user/Documents/dex35-${tok}.txt`, { encoding: 'utf8' })).trim();
      const file39 = String(await vfs.readFile(`/home/user/Documents/dex39-${tok}.txt`, { encoding: 'utf8' })).trim();
      assert.equal(file35, expected35, `Expected DEX v035 computed add result ${expected35}`);
      assert.equal(file39, expected39, `Expected DEX v039 computed sub result ${expected39}`);

      const wins = compositor.getSnapshot().windows ?? [];
      const win35 = wins.find((w) => w.appId === pkg35 || w.pid === l35.pid);
      const win39 = wins.find((w) => w.appId === pkg39 || w.pid === l39.pid);
      assert.ok(win35 && treeContainsText(win35.uiTree, expected35), 'Expected DEX v035 window uiTree to display computed sum');
      assert.ok(win39 && treeContainsText(win39.uiTree, expected39), 'Expected DEX v039 window uiTree to display computed diff');

      await pkgManager.stop(l35.pid);
      await pkgManager.stop(l39.pid);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA10-04 [F-039]: Dalvik register bytecode VM dynamic runtime-nonce arithmetic (add-int & mul-int anti-hardcoding proof)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const vfs = osHandle.require('vfs');
      const compositor = osHandle.require('compositor');
      const tok = makeNonce();

      const a1 = 10000 + crypto.randomInt(40000);
      const b1 = 10000 + crypto.randomInt(40000);
      const expectedAdd = String((a1 + b1) | 0);
      const pkgAdd = `com.omnios.vmadd.${tok}`;

      const a2 = 100 + crypto.randomInt(900);
      const b2 = 100 + crypto.randomInt(900);
      const expectedMul = String(Math.imul(a2, b2));
      const pkgMul = `com.omnios.vmmul.${tok}`;

      const apkAdd = buildCustomApk({
        packageName: pkgAdd,
        appLabel: `VmAdd-${tok}`,
        computeA: a1,
        computeB: b1,
        computeOp: 'add',
        outputFile: `/sdcard/Documents/vm-add-${tok}.txt`,
      });
      const apkMul = buildCustomApk({
        packageName: pkgMul,
        appLabel: `VmMul-${tok}`,
        computeA: a2,
        computeB: b2,
        computeOp: 'mul',
        outputFile: `/sdcard/Documents/vm-mul-${tok}.txt`,
      });

      await pkgManager.install(apkAdd, { grantAll: true });
      await pkgManager.install(apkMul, { grantAll: true });
      grantAndroidCaps(osHandle, pkgAdd);
      grantAndroidCaps(osHandle, pkgMul);

      const lAdd = await pkgManager.launch(pkgAdd);
      const resAdd = await runAndroidTicks(osHandle, lAdd.pid, 500);
      const lMul = await pkgManager.launch(pkgMul);
      const resMul = await runAndroidTicks(osHandle, lMul.pid, 500);

      assert.ok(resAdd.instructionsExecuted > 0, 'Expected Dalvik add-int process to execute > 0 instructions');
      assert.ok(resMul.instructionsExecuted > 0, 'Expected Dalvik mul-int process to execute > 0 instructions');

      const outAdd = String(await vfs.readFile(`/home/user/Documents/vm-add-${tok}.txt`, { encoding: 'utf8' })).trim();
      const outMul = String(await vfs.readFile(`/home/user/Documents/vm-mul-${tok}.txt`, { encoding: 'utf8' })).trim();
      assert.equal(outAdd, expectedAdd, `Expected Dalvik add-int ${a1}+${b1}=${expectedAdd}`);
      assert.equal(outMul, expectedMul, `Expected Dalvik mul-int ${a2}*${b2}=${expectedMul}`);

      const wins = compositor.getSnapshot().windows ?? [];
      const winAdd = wins.find((w) => w.appId === pkgAdd || w.pid === lAdd.pid);
      const winMul = wins.find((w) => w.appId === pkgMul || w.pid === lMul.pid);
      assert.ok(winAdd && treeContainsText(winAdd.uiTree, expectedAdd), 'Expected add-int TextView in uiTree');
      assert.ok(winMul && treeContainsText(winMul.uiTree, expectedMul), 'Expected mul-int TextView in uiTree');

      await pkgManager.stop(lAdd.pid);
      await pkgManager.stop(lMul.pid);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA10-05 [F-040]: Android Framework Bridge (Activity.onCreate, TextView, SharedPreferences, /sdcard/Documents/, Intent cross-app launch, Toast & Log)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const vfs = osHandle.require('vfs');
      const configStore = osHandle.require('configStore');
      const compositor = osHandle.require('compositor');
      const notifications = osHandle.require('notifications');
      const pm = osHandle.require('processManager');
      const scheduler = osHandle.require('scheduler');
      const kernel = osHandle.require('kernel');

      const tok = makeNonce();
      const a = 500 + crypto.randomInt(4000);
      const b = 500 + crypto.randomInt(4000);
      const expectedSum = String((a + b) | 0);
      const bridgeScheme = `omnibridge${tok}`;

      const recvPkg = `com.omnios.recv.${tok}`;
      const recvApk = buildCustomApk({
        packageName: recvPkg,
        appLabel: `Recv-${tok}`,
        intentFilters: [
          {
            actions: ['android.intent.action.VIEW'],
            categories: ['android.intent.category.DEFAULT'],
            data: [{ scheme: bridgeScheme }],
          },
        ],
        outputFile: `/sdcard/Documents/intent-recv-${tok}.txt`,
        outputContent: `INTENT_OK_${tok}`,
      });

      const sendPkg = `com.omnios.send.${tok}`;
      const sendApk = buildCustomApk({
        packageName: sendPkg,
        appLabel: `Send-${tok}`,
        computeA: a,
        computeB: b,
        computeOp: 'add',
        outputFile: `/sdcard/Documents/bridge-${tok}.txt`,
        outputContent: `FILE_${tok}_${expectedSum}`,
        sharedPrefName: 'bridge_prefs',
        sharedPrefKey: 'nonce_k',
        sharedPrefVal: `val_${tok}`,
        intentAction: 'android.intent.action.VIEW',
        intentUri: `${bridgeScheme}://go`,
        notificationTitle: `Toast-${tok}`,
        notificationBody: `Body-${tok}`,
        logTag: `Log-${tok}`,
      });

      await pkgManager.install(recvApk, { grantAll: true });
      await pkgManager.install(sendApk, { grantAll: true });
      grantAndroidCaps(osHandle, recvPkg);
      grantAndroidCaps(osHandle, sendPkg);

      const sendLaunched = await pkgManager.launch(sendPkg);
      const sendRun = await runAndroidTicks(osHandle, sendLaunched.pid, 500);

      // Step newly spawned receiver process deterministically
      const recvProc = pm.list().find((p) => p.appId === recvPkg);
      if (recvProc) {
        await runAndroidTicks(osHandle, recvProc.pid, 500);
      }
      await scheduler.step(200);

      // 1. Compositor window & TextView
      const wins = compositor.getSnapshot().windows ?? [];
      const sendWin = wins.find((w) => w.appId === sendPkg || w.pid === sendLaunched.pid);
      assert.ok(sendWin, `Expected Android Compositor window for ${sendPkg}`);
      assert.equal(sendWin.platform, 'android');
      assert.ok(treeContainsText(sendWin.uiTree, expectedSum), `Expected TextView with ${expectedSum} in uiTree`);

      // 2. SharedPreferences
      const prefs = configStore.sharedPrefs.getAll(sendPkg, 'bridge_prefs');
      assert.equal(prefs?.nonce_k, `val_${tok}`, `Expected SharedPreferences nonce_k === val_${tok}`);

      // 3. /sdcard/Documents/ -> /home/user/Documents/ VFS file write
      const bridgeFile = String(await vfs.readFile(`/home/user/Documents/bridge-${tok}.txt`, { encoding: 'utf8' })).trim();
      assert.equal(bridgeFile, `FILE_${tok}_${expectedSum}`);

      // 4. Toast notification
      const notifList = notifications.list({ includeDismissed: true });
      assert.ok(
        JSON.stringify(notifList).includes(`Toast-${tok}`),
        `Expected Toast-${tok} in Notification Center, got: ${JSON.stringify(notifList)}`
      );

      // 5. Cross-app Intent receiver execution side effect
      const recvFile = String(await vfs.readFile(`/home/user/Documents/intent-recv-${tok}.txt`, { encoding: 'utf8' })).trim();
      assert.equal(recvFile, `INTENT_OK_${tok}`, 'Expected cross-app Intent receiver APK to execute and write marker file');

      // 6. Log.i emitted to process stdout or kernel dmesg
      const dmesgText = JSON.stringify(kernel.dmesg({ limit: 200 }));
      assert.ok(
        sendRun.stdout.includes(`Log-${tok}`) ||
        sendRun.stdout.includes(expectedSum) ||
        dmesgText.includes(`Log-${tok}`) ||
        dmesgText.includes(expectedSum),
        `Expected Log.i output (Log-${tok} / ${expectedSum}) in stdout or dmesg`
      );

      await pkgManager.stop(sendLaunched.pid);
      if (recvProc) await pkgManager.stop(recvProc.pid).catch(() => {});
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA10-06 [F-046]: Built-in SDK sample APKs packages/android-calc.apk & packages/android-notes-sharer.apk inspect and launch cleanly', async () => {
    let osHandle = null;
    try {
      // Boot public OS FIRST so absent os/os.mjs fails loudly with E_OMNIOS_NOT_IMPLEMENTED
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const compositor = osHandle.require('compositor');

      for (const sampleName of ['android-calc.apk', 'android-notes-sharer.apk']) {
        const samplePath = path.join(REPO_ROOT, 'packages', sampleName);
        const buf = await readNonEmptyFile(samplePath);
        assert.equal(buf[0], 0x50, `Expected PK ZIP magic byte 0 in ${sampleName}`);
        assert.equal(buf[1], 0x4b, `Expected PK ZIP magic byte 1 in ${sampleName}`);
        assert.equal(buf[2], 0x03, `Expected PK ZIP magic byte 2 in ${sampleName}`);
        assert.equal(buf[3], 0x04, `Expected PK ZIP magic byte 3 in ${sampleName}`);

        const insp = await pkgManager.inspect(buf);
        assert.equal(insp.format, 'android-apk');
        assert.equal(insp.platform, 'android');
        assert.equal(insp.arch, 'dalvik');
        assert.equal(insp.sha256, sha256Hex(buf));

        const rec = await pkgManager.install(buf, { grantAll: true });
        const appId = rec.appId ?? insp.appId;
        assert.ok(appId, `Expected valid appId for ${sampleName}`);
        grantAndroidCaps(osHandle, appId);

        const launched = await pkgManager.launch(appId);
        assert.ok(launched.pid > 1, `Expected valid PID > 1 launching ${sampleName}`);
        const run = await runAndroidTicks(osHandle, launched.pid, 400);

        assert.ok(run.instructionsExecuted > 0, `Expected ${sampleName} to execute > 0 Dalvik instructions`);
        const sig = run.pcb?.exitSignal ?? run.pcb?.signal ?? null;
        assert.ok(sig !== 'SIGSEGV' && sig !== 'SIGILL', `${sampleName} faulted with signal ${sig}`);

        const wins = compositor.getSnapshot().windows ?? [];
        const win = wins.find((w) => w.pid === launched.pid || w.appId === appId);
        assert.ok(win, `Expected Android Compositor window for ${sampleName}`);
        assert.equal(win.platform, 'android');
        assert.ok(win.uiTree && Object.keys(win.uiTree).length > 0, `Expected non-empty uiTree for ${sampleName}`);

        await pkgManager.stop(launched.pid);
      }
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA10-07 [F-036/F-039/F-040]: Live HTTP REST & Remote CLI dynamic .apk inspect, install, launch & side-effect verification', async () => {
    let srv = null;
    let tmp = null;
    try {
      srv = await startOmniServer();
      tmp = await createTempDataDir('omnios-fa10-rest-');

      const tok = makeNonce();
      const a = 2000 + crypto.randomInt(8000);
      const b = 2000 + crypto.randomInt(8000);
      const expectedSum = String((a + b) | 0);
      const pkgName = `com.omnios.restapk.${tok}`;

      const apkBytes = buildCustomApk({
        packageName: pkgName,
        appLabel: `RestApk-${tok}`,
        computeA: a,
        computeB: b,
        computeOp: 'add',
        outputFile: `/sdcard/Documents/rest-apk-${tok}.txt`,
        sharedPrefName: 'rest_prefs',
        sharedPrefKey: 'rk',
        sharedPrefVal: `rv_${tok}`,
        notificationTitle: `RestToast-${tok}`,
        notificationBody: `Sum=${expectedSum}`,
      });

      const apkHostPath = path.join(tmp.dir, `dyn-${tok}.apk`);
      await fs.writeFile(apkHostPath, apkBytes);

      const cliInsp = await srv.runCli(['ospm', 'inspect', apkHostPath], {
        json: true,
        expectZero: true,
      });
      assert.ok(cliInsp.json, `Expected JSON output from CLI ospm inspect, got: ${cliInsp.stdout}`);
      assert.equal(cliInsp.json.format, 'android-apk');
      assert.equal(cliInsp.json.appId, pkgName);

      await installPackageHttp(srv.api, apkBytes, `dyn-${tok}.apk`);

      const launchRes = await srv.api.post(
        `/api/v1/packages/${encodeURIComponent(pkgName)}/launch`,
        {},
        { expectOk: true }
      );
      const pid = launchRes.json?.pid ?? launchRes.json?.process?.pid;
      assert.ok(typeof pid === 'number' && pid > 1, `Expected launched PID > 1, got: ${launchRes.text}`);

      await waitUntil(async () => {
        const fRes = await srv.api.get('/api/v1/vfs/file', {
          query: { path: `/home/user/Documents/rest-apk-${tok}.txt` },
        });
        if (!fRes.ok) return false;
        const content = typeof fRes.json?.content === 'string'
          ? fRes.json.content
          : (typeof fRes.json?.data === 'string' ? fRes.json.data : fRes.text);
        return content.includes(expectedSum);
      }, { timeoutMs: 6000, label: `VFS output file containing ${expectedSum}` });

      await waitUntil(async () => {
        const snap = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(snap.json, ['windows']);
        const win = wins.find((w) => w.appId === pkgName || w.pid === pid);
        return Boolean(win && treeContainsText(win.uiTree, expectedSum));
      }, { timeoutMs: 6000, label: `Compositor window uiTree containing ${expectedSum}` });

      await waitUntil(async () => {
        const nRes = await srv.api.get('/api/v1/ipc/notifications', { expectOk: true });
        return JSON.stringify(nRes.json).includes(`RestToast-${tok}`);
      }, { timeoutMs: 6000, label: `Notification containing RestToast-${tok}` });

      const stopRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(pkgName)}/stop`, {});
      assert.ok(stopRes.ok, `Expected HTTP 2xx stopping ${pkgName}, got ${stopRes.status}`);
      const delRes = await srv.api.delete(`/api/v1/packages/${encodeURIComponent(pkgName)}`);
      assert.ok(delRes.ok, `Expected HTTP 2xx uninstalling ${pkgName}, got ${delRes.status}`);
    } finally {
      if (srv) await srv.stop().catch(() => {});
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });
});
