/**
 * OmniOS Tier 1 E2E Suite — FA-13: macOS & Universal WASM Runtimes
 * Covers PROJECT.md Features: F-054, F-055, F-056, F-058, F-059, F-060.
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
  runCli,
} from '../lib/env.mjs';
import { sha256Hex } from '../lib/binary-utils.mjs';
import {
  buildCustomDmg,
  buildCustomMacAppZip,
  buildCustomPkg,
  buildCustomUapp,
  buildCustomWasm,
} from '../lib/fixtures-apple-wasm.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

function extractExitCode(pcb, summary) {
  const code = summary?.exitCode ?? pcb?.stats?.exitCode ?? pcb?.exitCode;
  return code === undefined || code === null ? null : Number(code);
}

function extractInstructions(pcb, summary) {
  return Number(
    summary?.instructionsExecuted ??
    pcb?.stats?.instructionsExecuted ??
    pcb?.instructionsExecuted ??
    0
  );
}

async function runToCompletion(osHandle, pid, maxTicks = 2000) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  let summary = null;
  if (typeof scheduler.runUntilIdle === 'function') {
    summary = await scheduler.runUntilIdle(pid, maxTicks);
  } else {
    for (let i = 0; i < Math.ceil(maxTicks / 50); i++) {
      await scheduler.step(50);
      const cur = pm.get(pid);
      if (!cur || cur.state === 'TERMINATED' || cur.state === 'ZOMBIE') break;
    }
  }
  const pcb = pm.get(pid);
  return {
    pcb,
    summary,
    stdout: extractStdout(pcb, summary),
    exitCode: extractExitCode(pcb, summary),
    instructionsExecuted: extractInstructions(pcb, summary),
  };
}

function grantUserCaps(osHandle, appId) {
  const security = osHandle.require('security');
  for (const cap of ['fs.read.user', 'fs.write.user', 'notifications.post', 'ui.window', 'clipboard.read', 'clipboard.write', 'ipc.broadcast']) {
    security.setGrant(appId, cap, 'allow');
  }
}

async function runSpotlightQuery(searchEngine, query) {
  if (typeof searchEngine.query === 'function') {
    return await searchEngine.query(query);
  }
  if (typeof searchEngine.search === 'function') {
    return await searchEngine.search(query);
  }
  throw new Error('Spotlight search engine exposes neither query() nor search()');
}

describe('Tier 1 — FA-13: macOS & Universal WASM Runtimes (.app/.dmg/.pkg, AppKit, WASI & SDK)', () => {
  it('T1-FA13-01 [F-054/F-055]: Dynamic macOS .app.zip (ARM64) /Users/user/Documents/ VFS write, CFBundleURLTypes/DocumentTypes & Spotlight indexing', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const intentRouter = osHandle.require('intentRouter');
      const search = osHandle.require('search');

      const nonce = makeNonce();
      const bundleId = `com.omnios.macos.arm${nonce}`;
      const appName = `MacArm_${nonce}`;
      const scheme = `omnimac${nonce}`;
      const ext = `omd${nonce.slice(0, 4)}`;
      const macDocPath = `/Users/user/Documents/mac-doc-${nonce}.txt`;
      const content = `MAC_VFS_${nonce}`;

      const appZip = buildCustomMacAppZip({
        bundleId,
        appName,
        executableName: appName,
        arch: 'arm64',
        plistFormat: 'xml',
        urlScheme: scheme,
        documentExtensions: [ext],
        fileWrite: { path: macDocPath, content },
        exitCode: 0,
      });

      const det = formatDetector.detect(appZip, `${appName}.app.zip`);
      assert.equal(det.format, 'macos-app');
      assert.equal(det.platform, 'macos');

      const vfsPath = `/tmp/${appName}.app.zip`;
      await vfs.writeFile(vfsPath, appZip);
      const insp = await pkgManager.inspect(vfsPath);
      assert.equal(insp.platform, 'macos');
      assert.equal(insp.appId ?? insp.bundleId, bundleId);

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId ?? bundleId;
      grantUserCaps(osHandle, appId);

      // URL scheme & Document type registration
      const schemeHits = intentRouter.resolve({ scheme });
      assert.ok(
        Array.isArray(schemeHits) && schemeHits.some((h) => (h.appId ?? h.id) === appId),
        `Expected macOS CFBundleURLTypes scheme "${scheme}" registered for ${appId}, got: ${JSON.stringify(schemeHits)}`
      );

      const extHitsA = intentRouter.resolve({ extension: `.${ext}` }) ?? [];
      const extHitsB = intentRouter.resolve({ extension: ext }) ?? [];
      const extHits = [...extHitsA, ...extHitsB];
      assert.ok(
        extHits.some((h) => (h.appId ?? h.id) === appId),
        `Expected macOS CFBundleDocumentTypes extension "${ext}" registered for ${appId}, got: ${JSON.stringify(extHits)}`
      );

      // Spotlight indexing
      const spotRes = await runSpotlightQuery(search, appName);
      assert.ok(
        JSON.stringify(spotRes).includes(appName) || JSON.stringify(spotRes).includes(appId),
        `Expected Spotlight index to find installed macOS app "${appName}", got: ${JSON.stringify(spotRes)}`
      );

      // Live execution & /Users/user/Documents/ -> /home/user/Documents/ VFS write
      const launched = await pkgManager.launch(appId);
      const run = await runToCompletion(osHandle, launched.pid);
      assert.equal(run.exitCode, 0, `Expected macOS ARM64 app exitCode 0, got ${run.exitCode}`);

      const written = String(await vfs.readFile(`/home/user/Documents/mac-doc-${nonce}.txt`, { encoding: 'utf8' }));
      assert.equal(written, content);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA13-02 [F-054]: Dynamic macOS .app.zip Intel x86-64 slice AND Universal Fat (x86_64 + arm64) execution', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const code1 = 15 + (crypto.randomBytes(1)[0] % 50);
      const code2 = 70 + (crypto.randomBytes(1)[0] % 50);

      // 1. Intel x86-64 macOS .app.zip
      const x64BundleId = `com.omnios.macos.x64${nonce}`;
      const x64App = buildCustomMacAppZip({
        bundleId: x64BundleId,
        appName: `MacX64_${nonce}`,
        executableName: `MacX64_${nonce}`,
        arch: 'x86_64',
        message: `MAC_X64_${nonce}\n`,
        exitCode: code1,
      });
      const x64Path = `/tmp/MacX64_${nonce}.app.zip`;
      await vfs.writeFile(x64Path, x64App);
      const x64Rec = await pkgManager.install(x64Path, { grantAll: true });
      const x64Launched = await pkgManager.launch(x64Rec.appId ?? x64BundleId);
      const x64Run = await runToCompletion(osHandle, x64Launched.pid);
      assert.ok(
        x64Run.stdout.includes(`MAC_X64_${nonce}`),
        `Expected Intel x86-64 macOS stdout MAC_X64_${nonce}, got: ${JSON.stringify(x64Run.stdout)}`
      );
      assert.equal(x64Run.exitCode, code1);

      // 2. Universal Fat (x86_64 + arm64) macOS .app.zip
      const uniBundleId = `com.omnios.macos.uni${nonce}`;
      const uniApp = buildCustomMacAppZip({
        bundleId: uniBundleId,
        appName: `MacUni_${nonce}`,
        executableName: `MacUni_${nonce}`,
        arch: 'universal',
        message: `MAC_FAT_${nonce}\n`,
        exitCode: code2,
      });
      const uniPath = `/tmp/MacUni_${nonce}.app.zip`;
      await vfs.writeFile(uniPath, uniApp);
      const uniInsp = await pkgManager.inspect(uniPath);
      const uniInspJson = JSON.stringify(uniInsp).toLowerCase();
      assert.ok(
        uniInspJson.includes('arm64') && (uniInspJson.includes('x86_64') || uniInspJson.includes('x64') || uniInspJson.includes('universal')),
        `Expected Universal Fat multi-arch metadata in inspection, got: ${JSON.stringify(uniInsp)}`
      );

      const uniRec = await pkgManager.install(uniPath, { grantAll: true });
      const uniLaunched = await pkgManager.launch(uniRec.appId ?? uniBundleId);
      const uniRun = await runToCompletion(osHandle, uniLaunched.pid);
      assert.ok(
        uniRun.stdout.includes(`MAC_FAT_${nonce}`),
        `Expected Universal Fat macOS stdout MAC_FAT_${nonce}, got: ${JSON.stringify(uniRun.stdout)}`
      );
      assert.equal(uniRun.exitCode, code2);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA13-03 [F-054]: macOS UDIF .dmg (koly + blkx) & Flat Installer .pkg (xar! + CPIO) inspection', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();

      // UDIF .dmg
      const dmgBuf = buildCustomDmg({
        volumeName: `OmniVol_${nonce}`,
        appName: `DmgApp_${nonce}`,
        bundleId: `com.omnios.macos.dmg${nonce}`,
        message: `DMG_${nonce}\n`,
      });
      const dmgDet = formatDetector.detect(dmgBuf, `disk-${nonce}.dmg`);
      assert.equal(dmgDet.format, 'macos-dmg');
      assert.equal(dmgDet.platform, 'macos');

      const dmgPath = `/tmp/disk-${nonce}.dmg`;
      await vfs.writeFile(dmgPath, dmgBuf);
      const dmgInsp = await pkgManager.inspect(dmgPath);
      const dmgJson = JSON.stringify(dmgInsp);
      assert.equal(dmgInsp.platform, 'macos');
      assert.ok(
        dmgJson.includes(`OmniVol_${nonce}`) || /koly|blkx|partition/i.test(dmgJson),
        `Expected UDIF .dmg koly/blkx metadata, got: ${dmgJson}`
      );

      // Flat Installer .pkg (XAR + CPIO)
      const pkgBuf = buildCustomPkg({
        bundleId: `com.omnios.macos.pkg${nonce}`,
        appName: `PkgApp_${nonce}`,
        version: '3.1.0',
        message: `PKG_${nonce}\n`,
      });
      const pkgDet = formatDetector.detect(pkgBuf, `inst-${nonce}.pkg`);
      assert.equal(pkgDet.format, 'macos-pkg');
      assert.equal(pkgDet.platform, 'macos');

      const pkgPath = `/tmp/inst-${nonce}.pkg`;
      await vfs.writeFile(pkgPath, pkgBuf);
      const pkgInsp = await pkgManager.inspect(pkgPath);
      const pkgJson = JSON.stringify(pkgInsp);
      assert.equal(pkgInsp.platform, 'macos');
      assert.ok(
        pkgJson.includes(`com.omnios.macos.pkg${nonce}`) ||
        pkgJson.includes(`PkgApp_${nonce}`) ||
        /PackageInfo|Payload|xar/i.test(pkgJson),
        `Expected XAR .pkg TOC / PackageInfo metadata, got: ${pkgJson}`
      );
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA13-04 [F-055/F-058]: SDK sample packages/macos-studio.app.zip (AppKit window + Global Top Menu Bar + Spotlight)', async () => {
    let osHandle = null;
    try {
      // Boot public OS FIRST so absent os/os.mjs fails loudly with E_OMNIOS_NOT_IMPLEMENTED
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const pkgManager = osHandle.require('pkgManager');
      const scheduler = osHandle.require('scheduler');
      const compositor = osHandle.require('compositor');
      const search = osHandle.require('search');

      const appBuf = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', 'macos-studio.app.zip'));
      const det = formatDetector.detect(appBuf, 'macos-studio.app.zip');
      assert.equal(det.format, 'macos-app');
      assert.equal(det.platform, 'macos');

      const insp = await pkgManager.inspect(appBuf);
      assert.equal(insp.platform, 'macos');

      const rec = await pkgManager.install(appBuf, { grantAll: true });
      const appId = rec.appId ?? insp.appId;
      grantUserCaps(osHandle, appId);

      const spotRes = await runSpotlightQuery(search, insp.name ?? 'Studio');
      assert.ok(
        JSON.stringify(spotRes).toLowerCase().includes('studio') || JSON.stringify(spotRes).includes(appId),
        `Expected macos-studio indexed in Spotlight, got: ${JSON.stringify(spotRes)}`
      );

      const launched = await pkgManager.launch(appId);
      assert.ok(launched.pid > 1);
      await scheduler.step(200);

      const snap1 = compositor.getSnapshot();
      const win = (snap1.windows ?? []).find((w) => w.pid === launched.pid || w.appId === appId);
      assert.ok(win, 'Expected AppKit Compositor window for macos-studio.app.zip');
      assert.equal(win.platform, 'macos');

      const winId = win.windowId ?? win.id;
      compositor.focusWindow(winId);
      const snap2 = compositor.getSnapshot();
      const menuBar = win.menuBar ?? snap2.activeMenuBar;
      assert.ok(
        Array.isArray(menuBar) && menuBar.length > 0,
        `Expected macOS Global Top Menu Bar entries when focused, got: ${JSON.stringify(snap2.activeMenuBar)}`
      );

      await pkgManager.stop(launched.pid);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA13-05 [F-056]: Dynamic raw .wasm & .uapp (\\0asm v1) executing dynamic nonce WASI Preview 1 fd_write + proc_exit', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const code1 = 13 + (crypto.randomBytes(1)[0] % 50);
      const code2 = 67 + (crypto.randomBytes(1)[0] % 50);

      // 1. Raw standalone .wasm binary
      const wasmBuf = buildCustomWasm({
        message: `RAW_WASM_${nonce}\n`,
        exitCode: code1,
        useOmniOsImport: false,
      });
      assert.equal(WebAssembly.validate(wasmBuf), true, 'Host WebAssembly.validate() must accept fixture .wasm');

      const wasmDet = formatDetector.detect(wasmBuf, `raw-${nonce}.wasm`);
      assert.equal(wasmDet.format, 'universal-wasm');
      assert.equal(wasmDet.platform, 'universal');

      const wasmVfs = `/tmp/raw-${nonce}.wasm`;
      await vfs.writeFile(wasmVfs, wasmBuf);
      const wasmRec = await pkgManager.install(wasmVfs, { grantAll: true });
      const wasmLaunched = await pkgManager.launch(wasmRec.appId);
      const wasmRun = await runToCompletion(osHandle, wasmLaunched.pid);
      assert.ok(
        wasmRun.stdout.includes(`RAW_WASM_${nonce}`),
        `Expected raw .wasm WASI stdout RAW_WASM_${nonce}, got: ${JSON.stringify(wasmRun.stdout)}`
      );
      assert.equal(wasmRun.exitCode, code1);

      // 2. Packaged .uapp container
      const uappId = `com.omnios.uapp.${nonce}`;
      const uappBuf = buildCustomUapp({
        appId: uappId,
        name: `UappDyn_${nonce}`,
        message: `UAPP_OUT_${nonce}\n`,
        exitCode: code2,
        useOmniOsImport: false,
      });
      const uappDet = formatDetector.detect(uappBuf, `dyn-${nonce}.uapp`);
      assert.equal(uappDet.format, 'universal-uapp');
      assert.equal(uappDet.platform, 'universal');

      const uappVfs = `/tmp/dyn-${nonce}.uapp`;
      await vfs.writeFile(uappVfs, uappBuf);
      const uappInsp = await pkgManager.inspect(uappVfs);
      assert.equal(uappInsp.appId, uappId);

      const uappRec = await pkgManager.install(uappVfs, { grantAll: true });
      const uappLaunched = await pkgManager.launch(uappRec.appId ?? uappId);
      const uappRun = await runToCompletion(osHandle, uappLaunched.pid);
      assert.ok(
        uappRun.stdout.includes(`UAPP_OUT_${nonce}`),
        `Expected .uapp WASI stdout UAPP_OUT_${nonce}, got: ${JSON.stringify(uappRun.stdout)}`
      );
      assert.equal(uappRun.exitCode, code2);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA13-06 [F-056/F-059]: SDK sample packages/universal-canvas.uapp (omni_os_v1 Compositor/Canvas host imports)', async () => {
    let osHandle = null;
    try {
      // Boot public OS FIRST so absent os/os.mjs fails loudly with E_OMNIOS_NOT_IMPLEMENTED
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const pkgManager = osHandle.require('pkgManager');
      const scheduler = osHandle.require('scheduler');
      const compositor = osHandle.require('compositor');

      const uappBuf = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', 'universal-canvas.uapp'));
      const det = formatDetector.detect(uappBuf, 'universal-canvas.uapp');
      assert.equal(det.format, 'universal-uapp');
      assert.equal(det.platform, 'universal');

      const insp = await pkgManager.inspect(uappBuf);
      assert.equal(insp.platform, 'universal');

      const rec = await pkgManager.install(uappBuf, { grantAll: true });
      const appId = rec.appId ?? insp.appId;
      grantUserCaps(osHandle, appId);

      const launched = await pkgManager.launch(appId);
      assert.ok(launched.pid > 1);
      await scheduler.step(200);

      const wins = compositor.getSnapshot().windows ?? [];
      const win = wins.find((w) => w.pid === launched.pid || w.appId === appId);
      assert.ok(win, 'Expected universal-canvas.uapp to create a Compositor window via omni_os_v1 host imports');
      const hasDrawOps = Array.isArray(win.drawOps) && win.drawOps.length > 0;
      const hasUiTree = Boolean(win.uiTree && Object.keys(win.uiTree).length > 0);
      assert.ok(
        hasDrawOps || hasUiTree,
        `Expected populated drawOps or uiTree from universal-canvas.uapp, got: ${JSON.stringify(win)}`
      );

      await pkgManager.stop(launched.pid);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA13-07 [F-060]: Deterministic SDK sample build pipeline (sdk build-samples) generating all 7 authentic packages', async () => {
    const expectedPackages = [
      { file: 'android-calc.apk', format: 'android-apk' },
      { file: 'android-notes-sharer.apk', format: 'android-apk' },
      { file: 'win-sysinfo.exe', format: 'windows-pe' },
      { file: 'win-notepad.exe', format: 'windows-pe' },
      { file: 'ios-weather-island.ipa', format: 'ios-ipa' },
      { file: 'macos-studio.app.zip', format: 'macos-app' },
      { file: 'universal-canvas.uapp', format: 'universal-uapp' },
    ];

    let tmpData = null;
    let tmpOut1 = null;
    let tmpOut2 = null;
    let osHandle = null;
    try {
      tmpData = await createTempDataDir('omnios-fa13-sdkdata-');
      tmpOut1 = await createTempDataDir('omnios-fa13-sdkout1-');
      tmpOut2 = await createTempDataDir('omnios-fa13-sdkout2-');

      const probe = await runCli(['sdk', 'build-samples', '--out-dir', tmpOut1.dir], {
        dataDir: tmpData.dir,
        expectZero: false,
        timeoutMs: 30000,
      });

      let wroteToOutDir = Boolean(probe.ok);
      if (wroteToOutDir) {
        for (const item of expectedPackages) {
          try {
            const st = await fs.stat(path.join(tmpOut1.dir, item.file));
            if (st.size === 0) {
              wroteToOutDir = false;
              break;
            }
          } catch {
            wroteToOutDir = false;
            break;
          }
        }
      }

      const hashes1 = new Map();
      const hashes2 = new Map();
      const finalBuffers = new Map();

      if (wroteToOutDir) {
        await runCli(['sdk', 'build-samples', '--out-dir', tmpOut2.dir], {
          dataDir: tmpData.dir,
          expectZero: true,
          timeoutMs: 30000,
        });
        for (const item of expectedPackages) {
          const b1 = await readNonEmptyFile(path.join(tmpOut1.dir, item.file));
          const b2 = await readNonEmptyFile(path.join(tmpOut2.dir, item.file));
          hashes1.set(item.file, sha256Hex(b1));
          hashes2.set(item.file, sha256Hex(b2));
          finalBuffers.set(item.file, b1);
        }
      } else {
        const pkgDir = path.join(REPO_ROOT, 'packages');
        // Run 1 of Contract-8 `sdk build-samples`
        await runCli(['sdk', 'build-samples'], {
          dataDir: tmpData.dir,
          expectZero: true,
          timeoutMs: 30000,
        });
        for (const item of expectedPackages) {
          const b1 = await readNonEmptyFile(path.join(pkgDir, item.file));
          hashes1.set(item.file, sha256Hex(b1));
        }

        // Run 2 of Contract-8 `sdk build-samples` to prove deterministic repeatability
        await runCli(['sdk', 'build-samples'], {
          dataDir: tmpData.dir,
          expectZero: true,
          timeoutMs: 30000,
        });
        for (const item of expectedPackages) {
          const b2 = await readNonEmptyFile(path.join(pkgDir, item.file));
          hashes2.set(item.file, sha256Hex(b2));
          finalBuffers.set(item.file, b2);
        }
      }

      for (const item of expectedPackages) {
        assert.equal(
          hashes1.get(item.file),
          hashes2.get(item.file),
          `Expected deterministic SHA-256 across repeated sdk build-samples runs for ${item.file}`
        );
      }

      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      for (const item of expectedPackages) {
        const det = formatDetector.detect(finalBuffers.get(item.file), item.file);
        assert.equal(det.format, item.format, `Expected ${item.file} to detect as ${item.format}, got ${det.format}`);
      }
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
      if (tmpOut2) await tmpOut2.cleanup().catch(() => {});
      if (tmpOut1) await tmpOut1.cleanup().catch(() => {});
      if (tmpData) await tmpData.cleanup().catch(() => {});
    }
  });
});
