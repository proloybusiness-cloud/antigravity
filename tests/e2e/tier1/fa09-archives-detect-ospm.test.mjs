/**
 * Tier 1 E2E Tests — FA-09: Zero-Dep PKZIP/ZIP64, Magic-Byte Format Detector & ospm Package Manager
 * Features covered: F-032, F-033, F-034
 * Contracts: Contract 5 (IFormatDetector, IPackageManager), Contract 7 (REST /api/v1/packages/*), Contract 8 (CLI ospm)
 *
 * Strictly opaque-box: interacts ONLY through public OmniOS entrypoints and dynamic fixture builders.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  createTempDataDir,
  loadPublicOmniOS,
  runCli,
  startOmniServer,
} from '../lib/env.mjs';
import {
  buildZip,
  crc32,
  sha256Hex,
} from '../lib/binary-utils.mjs';
import {
  buildBatScript,
  buildCustomApk,
  buildCustomMsi,
  buildCustomMsix,
  buildCustomPe32Exe,
  buildCustomPe64Exe,
} from '../lib/fixtures-android-win.mjs';
import {
  buildCustomDmg,
  buildCustomIpa,
  buildCustomMacAppZip,
  buildCustomPkg,
  buildCustomUapp,
  buildCustomWasm,
  buildMachO64,
  buildUniversalMachO,
} from '../lib/fixtures-apple-wasm.mjs';

function makeToken() {
  return crypto.randomBytes(4).toString('hex');
}

function unwrapObject(payload, keys = ['inspection', 'package', 'record', 'app', 'launch', 'data', 'result']) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return payload;
  for (const key of keys) {
    if (payload[key] && typeof payload[key] === 'object' && !Array.isArray(payload[key])) {
      return payload[key];
    }
  }
  return payload;
}

function unwrapExplicitArray(payload, keys = ['packages', 'catalog', 'apps', 'items', 'data', 'list']) {
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

function unwrapList(payload, keys = ['packages', 'catalog', 'apps', 'items', 'data', 'list']) {
  return unwrapExplicitArray(payload, keys) ?? [];
}

function getAppId(rec) {
  return rec?.appId ?? rec?.id ?? rec?.packageName ?? rec?.bundleId ?? null;
}

describe('Tier 1 — FA-09: Zero-Dep PKZIP/ZIP64, Magic-Byte Format Detector & ospm Package Manager', () => {
  test('T1 [F-032]: Zero-dep PKZIP STORE(0), DEFLATE(8), UTF-8 bit 11 filenames & CRC-32 verified through public package inspect/install', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pkgManager = os.require('pkgManager');
      const tok = makeToken();
      const appId = `com.omnios.zip.${tok}`;

      const wasmBytes = buildCustomWasm({ message: `ZIP_WASM_${tok}\n`, exitCode: 0 });
      const manifest = {
        id: appId,
        appId,
        name: `ZipCodec-${tok}`,
        version: '1.2.3',
        platform: 'universal',
        entry: 'app.wasm',
        permissions: [],
      };
      const storeBin = crypto.randomBytes(256);
      assert.equal(typeof crc32(storeBin), 'number');

      // Mix STORE(0), DEFLATE(8), and non-ASCII UTF-8 filename (general-purpose bit 11 = 0x0800)
      const uappZip = buildZip([
        { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'), method: 0, utf8: true },
        { name: 'app.wasm', data: wasmBytes, method: 8, utf8: true },
        { name: `assets/café-★-${tok}.txt`, data: Buffer.from(`utf8-body-${tok}`, 'utf8'), method: 8, utf8: true },
        { name: `assets/store-${tok}.bin`, data: storeBin, method: 0 },
      ]);
      const uappSha = sha256Hex(uappZip);

      const inspUapp = await pkgManager.inspect(uappZip);
      assert.equal(inspUapp?.format, 'universal-uapp');
      assert.equal(getAppId(inspUapp), appId);
      assert.equal(inspUapp?.sha256, uappSha, 'inspect() must compute exact SHA-256 of ZIP container');

      const installed = await pkgManager.install(uappZip, { grantAll: true });
      assert.equal(getAppId(installed), appId);
      assert.equal(installed?.sha256, uappSha);

      // Dynamic APK mixing DEFLATE (AndroidManifest.xml, classes.dex) + STORE (resources.arsc)
      const apkPkg = `com.omnios.zipapk.${tok}`;
      const apkZip = buildCustomApk({
        packageName: apkPkg,
        appLabel: `ZipApk-${tok}`,
        includeResourcesArsc: true,
        computeA: 12,
        computeB: 30,
      });
      const apkSha = sha256Hex(apkZip);
      const inspApk = await pkgManager.inspect(apkZip);
      assert.equal(inspApk?.format, 'android-apk');
      assert.equal(getAppId(inspApk), apkPkg);
      assert.equal(inspApk?.sha256, apkSha);
    } finally {
      await os.shutdown();
    }
  });

  test('T2 [F-033]: Magic-byte formatDetector.detect() across all 12 formats even with mismatched/misleading extensions', async () => {
    const os = await loadPublicOmniOS();
    try {
      const detector = os.require('formatDetector');
      const tok = makeToken();

      const cases = [
        {
          label: 'android-apk',
          bytes: buildCustomApk({ packageName: `com.det.apk.${tok}`, appLabel: `DetApk-${tok}` }),
          hint: 'decoy.exe',
          format: 'android-apk',
          platform: 'android',
        },
        {
          label: 'windows-pe (PE32+ x64)',
          bytes: buildCustomPe64Exe({ message: `pe64-${tok}\n` }),
          hint: 'decoy.ipa',
          format: 'windows-pe',
          platform: 'windows',
        },
        {
          label: 'windows-pe (PE32 x86)',
          bytes: buildCustomPe32Exe({ message: `pe32-${tok}\n` }),
          hint: 'decoy.dmg',
          format: 'windows-pe',
          platform: 'windows',
        },
        {
          label: 'windows-msix',
          bytes: buildCustomMsix({ identityName: `OmniOS.Det.${tok}`, displayName: `DetMsix-${tok}` }),
          hint: 'decoy.apk',
          format: 'windows-msix',
          platform: 'windows',
        },
        {
          label: 'windows-msi',
          bytes: buildCustomMsi({ productName: `DetMsi-${tok}` }),
          hint: 'decoy.pkg',
          format: 'windows-msi',
          platform: 'windows',
        },
        {
          label: 'windows-bat',
          bytes: Buffer.from(buildBatScript({ echoMessage: `bat-${tok}` }), 'utf8'),
          hint: 'run.bat',
          format: 'windows-bat',
          platform: 'windows',
        },
        {
          label: 'ios-ipa',
          bytes: buildCustomIpa({ bundleId: `com.det.ios.${tok}`, displayName: `DetIpa${tok}` }),
          hint: 'decoy.exe',
          format: 'ios-ipa',
          platform: 'ios',
        },
        {
          label: 'macos-app',
          bytes: buildCustomMacAppZip({ bundleId: `com.det.mac.${tok}`, appName: `DetMac${tok}` }),
          hint: 'decoy.apk',
          format: 'macos-app',
          platform: 'macos',
        },
        {
          label: 'macos-macho (ARM64)',
          bytes: buildMachO64({ arch: 'arm64', platform: 1, message: `arm64-${tok}\n` }),
          hint: 'decoy.wasm',
          format: 'macos-macho',
          platform: 'macos',
        },
        {
          label: 'macos-macho (Universal Fat)',
          bytes: buildUniversalMachO({ platform: 1, message: `fat-${tok}\n` }),
          hint: 'decoy.zip',
          format: 'macos-macho',
          platform: 'macos',
        },
        {
          label: 'macos-dmg',
          bytes: buildCustomDmg({ volumeName: `Vol${tok}`, bundleId: `com.det.dmg.${tok}` }),
          hint: 'decoy.msi',
          format: 'macos-dmg',
          platform: 'macos',
        },
        {
          label: 'macos-pkg',
          bytes: buildCustomPkg({ bundleId: `com.det.pkg.${tok}`, appName: `DetPkg${tok}` }),
          hint: 'decoy.ipa',
          format: 'macos-pkg',
          platform: 'macos',
        },
        {
          label: 'universal-uapp',
          bytes: buildCustomUapp({ appId: `com.det.uapp.${tok}`, message: `uapp-${tok}\n` }),
          hint: 'decoy.apk',
          format: 'universal-uapp',
          platform: 'universal',
        },
        {
          label: 'universal-wasm',
          bytes: buildCustomWasm({ message: `wasm-${tok}\n` }),
          hint: 'decoy.exe',
          format: 'universal-wasm',
          platform: 'universal',
        },
      ];

      for (const tc of cases) {
        const res = detector.detect(tc.bytes, tc.hint);
        assert.equal(
          res?.format,
          tc.format,
          `formatDetector failed for ${tc.label} (hint=${tc.hint}): expected format="${tc.format}", got ${JSON.stringify(res)}`
        );
        assert.equal(
          res?.platform,
          tc.platform,
          `formatDetector platform mismatch for ${tc.label}: expected "${tc.platform}", got "${res?.platform}"`
        );
        assert.ok(
          typeof res?.magicHex === 'string' && res.magicHex.length > 0,
          `formatDetector must return non-empty magicHex for ${tc.label}`
        );
      }

      const unknown = detector.detect(Buffer.from(`UNKNOWN_PAYLOAD_${tok}`, 'utf8'), 'x.bin');
      assert.equal(unknown?.format, 'unknown', `Arbitrary text must detect as "unknown", got ${JSON.stringify(unknown)}`);
    } finally {
      await os.shutdown();
    }
  });

  test('T3 [F-034]: ospm programmatic lifecycle inspect -> install -> list -> get -> launch -> stop -> uninstall + SHA-256 verification', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pkgManager = os.require('pkgManager');
      const sched = os.require('scheduler');
      sched.stop?.();
      const tok = makeToken();
      const appId = `com.omnios.life.${tok}`;

      const bytes = buildCustomUapp({
        appId,
        name: `LifeApp-${tok}`,
        version: '2.1.0',
        message: `LIFE_${tok}\n`,
        exitCode: 0,
      });
      const expectedSha = sha256Hex(bytes);

      const insp = await pkgManager.inspect(bytes);
      assert.equal(insp?.format, 'universal-uapp');
      assert.equal(getAppId(insp), appId);
      assert.equal(insp?.sha256, expectedSha);

      const rec = await pkgManager.install(bytes, { grantAll: true });
      assert.equal(getAppId(rec), appId);
      assert.equal(rec?.sha256, expectedSha);

      const allList = await pkgManager.list();
      assert.ok(allList.some((p) => getAppId(p) === appId), 'pkgManager.list() must include installed package');

      const uniList = await pkgManager.list({ platform: 'universal' });
      assert.ok(uniList.some((p) => getAppId(p) === appId), 'pkgManager.list({ platform: "universal" }) must include installed .uapp');

      const got = await pkgManager.get(appId);
      assert.equal(getAppId(got), appId);
      assert.equal(got?.sha256, expectedSha);

      const launched = await pkgManager.launch(appId, { args: [], env: {} });
      assert.ok(typeof launched?.pid === 'number' && launched.pid > 1, `launch() must spawn user PID > 1: ${JSON.stringify(launched)}`);
      assert.equal(launched.appId, appId);
      assert.equal(launched.platform, 'universal');

      await sched.runUntilIdle(launched.pid, 200);
      await pkgManager.stop(launched.pid);

      await pkgManager.uninstall(appId, { purgeData: true });
      assert.equal((await pkgManager.get(appId)) ?? null, null, 'Uninstalled package must return null from get()');
      assert.equal(
        (await pkgManager.list()).some((p) => getAppId(p) === appId),
        false,
        'Uninstalled package must not remain in list()'
      );
    } finally {
      await os.shutdown();
    }
  });

  test('T4 [F-034]: ospm SQLite package registry persistence across OS reboot', async () => {
    const tmp = await createTempDataDir('omnios-fa09-db-');
    let os1 = null;
    let os2 = null;
    try {
      const tok = makeToken();
      const appId = `com.omnios.db.${tok}`;
      const bytes = buildCustomUapp({ appId, name: `DbApp-${tok}`, version: '1.5.0', message: `DB_${tok}\n` });
      const expectedSha = sha256Hex(bytes);

      os1 = await loadPublicOmniOS({ dataDir: tmp.dir, keepDataDir: true });
      await os1.require('pkgManager').install(bytes, { grantAll: true });
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: tmp.dir, keepDataDir: true });
      const persisted = await os2.require('pkgManager').get(appId);
      assert.ok(persisted, `Expected installed package ${appId} to persist across reboot`);
      assert.equal(getAppId(persisted), appId);
      assert.equal(persisted.platform, 'universal');
      assert.equal(persisted.sha256, expectedSha);
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await tmp.cleanup();
    }
  });

  test('T5 [F-034]: App Hub catalog and platform-filtered package listing via live REST', async () => {
    const srv = await startOmniServer();
    try {
      const tok = makeToken();

      const catRes = await srv.api.get('/api/v1/packages/catalog');
      assert.equal(catRes.status, 200);
      const catalog = unwrapList(catRes.json);
      assert.ok(catalog.length >= 1, `Expected non-empty App Hub catalog, got ${catRes.text}`);
      const first = catalog[0];
      assert.ok(Boolean(getAppId(first)), 'Catalog item must have id/appId');
      assert.ok(typeof first.platform === 'string' && first.platform.length > 0, 'Catalog item must have platform');
      assert.ok(typeof first.name === 'string' && first.name.length > 0, 'Catalog item must have name');

      // Install one dynamic Android .apk and one dynamic Universal .uapp
      const andId = `com.hub.and.${tok}`;
      const uniId = `com.hub.uni.${tok}`;
      const apkB64 = Buffer.from(buildCustomApk({ packageName: andId, appLabel: `HubAnd-${tok}` })).toString('base64');
      const uappB64 = Buffer.from(buildCustomUapp({ appId: uniId, name: `HubUni-${tok}` })).toString('base64');

      const i1 = await srv.api.post('/api/v1/packages/install', { base64: apkB64, data: apkB64, filename: `hub-${tok}.apk`, grantAll: true });
      assert.ok(i1.ok, `APK install failed (${i1.status}): ${i1.text}`);
      const i2 = await srv.api.post('/api/v1/packages/install', { base64: uappB64, data: uappB64, filename: `hub-${tok}.uapp`, grantAll: true });
      assert.ok(i2.ok, `UAPP install failed (${i2.status}): ${i2.text}`);

      const andList = unwrapList((await srv.api.get('/api/v1/packages', { query: { platform: 'android' } })).json);
      assert.ok(andList.some((p) => getAppId(p) === andId), 'platform=android filter must include installed Android APK');
      assert.equal(andList.some((p) => getAppId(p) === uniId), false, 'platform=android filter must exclude Universal .uapp');

      const uniList = unwrapList((await srv.api.get('/api/v1/packages', { query: { platform: 'universal' } })).json);
      assert.ok(uniList.some((p) => getAppId(p) === uniId), 'platform=universal filter must include installed Universal .uapp');
      assert.equal(uniList.some((p) => getAppId(p) === andId), false, 'platform=universal filter must exclude Android APK');
    } finally {
      await srv.stop();
    }
  });

  test('T6 [F-034, Contract 7]: Live HTTP REST /api/v1/packages/* full CRUD and launch/stop lifecycle', async () => {
    const srv = await startOmniServer();
    try {
      const tok = makeToken();
      const appId = `com.omnios.rest.${tok}`;
      const bytes = buildCustomUapp({ appId, name: `RestApp-${tok}`, version: '1.0.1', message: `REST_${tok}\n` });
      const expectedSha = sha256Hex(bytes);
      const b64 = Buffer.from(bytes).toString('base64');

      const inspRes = await srv.api.post('/api/v1/packages/inspect', { base64: b64, data: b64, filename: 'r.uapp' });
      assert.equal(inspRes.status, 200);
      const inspObj = unwrapObject(inspRes.json);
      assert.equal(getAppId(inspObj), appId);
      assert.equal(inspObj?.sha256, expectedSha);

      const instRes = await srv.api.post('/api/v1/packages/install', {
        base64: b64,
        data: b64,
        filename: 'r.uapp',
        grantAll: true,
      });
      assert.ok(instRes.ok, `POST /api/v1/packages/install failed (${instRes.status}): ${instRes.text}`);

      const list1 = unwrapList((await srv.api.get('/api/v1/packages')).json);
      assert.ok(list1.some((p) => getAppId(p) === appId), 'GET /api/v1/packages must list newly installed package');

      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(appId)}/launch`, {});
      assert.ok(launchRes.ok, `POST /api/v1/packages/:appId/launch failed (${launchRes.status}): ${launchRes.text}`);
      const launchObj = unwrapObject(launchRes.json);
      assert.ok(typeof launchObj?.pid === 'number' && launchObj.pid > 1, `Expected launched PID > 1, got ${launchRes.text}`);

      const stopRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(appId)}/stop`, {});
      assert.ok(stopRes.ok, `POST /api/v1/packages/:appId/stop failed (${stopRes.status}): ${stopRes.text}`);

      const delRes = await srv.api.delete(`/api/v1/packages/${encodeURIComponent(appId)}`);
      assert.ok(delRes.ok, `DELETE /api/v1/packages/:appId failed (${delRes.status}): ${delRes.text}`);

      const list2 = unwrapList((await srv.api.get('/api/v1/packages')).json);
      assert.equal(list2.some((p) => getAppId(p) === appId), false, 'Deleted package must no longer appear in GET /api/v1/packages');
    } finally {
      await srv.stop();
    }
  });

  test('T7 [F-034, Contract 8]: Standalone --data-dir CLI ospm inspect/install/list/uninstall & live --remote ospm launch/stop', async () => {
    const tmp = await createTempDataDir('omnios-fa09-cli-');
    let srv = null;
    try {
      const tok = makeToken();
      const appId = `com.omnios.cli.${tok}`;
      const bytes = buildCustomUapp({ appId, name: `CliApp-${tok}`, version: '3.0.0', message: `CLI_${tok}\n` });
      const expectedSha = sha256Hex(bytes);

      const pkgPath = path.join(tmp.dir, `app-${tok}.uapp`);
      const dataDir = path.join(tmp.dir, 'data');
      await fs.mkdir(dataDir, { recursive: true });
      await fs.writeFile(pkgPath, bytes);

      // 1. Standalone headless CLI (--data-dir) persistent SQLite package operations
      const inspCli = await runCli(['ospm', 'inspect', pkgPath], { dataDir, json: true, expectZero: true });
      const inspObj = unwrapObject(inspCli.json);
      assert.equal(inspObj?.format, 'universal-uapp');
      assert.equal(getAppId(inspObj), appId);
      assert.equal(inspObj?.sha256, expectedSha);

      await runCli(['ospm', 'install', pkgPath], { dataDir, json: true, expectZero: true });

      const listCli1 = await runCli(['ospm', 'list'], { dataDir, json: true, expectZero: true });
      const list1Arr = unwrapExplicitArray(listCli1.json);
      assert.ok(
        listCli1.json !== null && Array.isArray(list1Arr),
        `Standalone CLI "ospm list --json" must return valid JSON package array, got stdout=${JSON.stringify(listCli1.stdout)}`
      );
      assert.ok(
        list1Arr.some((p) => getAppId(p) === appId),
        `Standalone CLI "ospm list" must persist installed package ${appId} across invocations`
      );

      await runCli(['ospm', 'uninstall', appId], { dataDir, json: true, expectZero: true });

      const listCli2 = await runCli(['ospm', 'list'], { dataDir, json: true, expectZero: true });
      const list2Arr = unwrapExplicitArray(listCli2.json);
      assert.ok(
        listCli2.json !== null && Array.isArray(list2Arr),
        `Standalone CLI "ospm list --json" after uninstall must return valid JSON package array, got stdout=${JSON.stringify(listCli2.stdout)}`
      );
      assert.equal(
        list2Arr.some((p) => getAppId(p) === appId) || listCli2.stdout.includes(appId),
        false,
        `Standalone CLI "ospm uninstall" must persistently remove ${appId} from ospm list`
      );

      // 2. Live daemon (--remote) ospm launch + ospm stop terminating a genuinely running PID
      srv = await startOmniServer();
      const pkgsRes = await srv.api.get('/api/v1/packages');
      assert.equal(pkgsRes.status, 200);
      const pkgs = unwrapList(pkgsRes.json);
      const longLivedPkg =
        pkgs.find((p) => getAppId(p) === 'sys.notes') ??
        pkgs.find((p) => getAppId(p) === 'sys.terminal') ??
        pkgs.find((p) => String(getAppId(p) ?? '').startsWith('sys.')) ??
        pkgs[0];
      assert.ok(longLivedPkg, 'Expected at least one long-lived built-in system app in daemon /api/v1/packages');
      const liveAppId = getAppId(longLivedPkg);

      const launchCli = await srv.runCli(['ospm', 'launch', liveAppId], { json: true, expectZero: true });
      const launchObj = unwrapObject(launchCli.json);
      const livePid = launchObj?.pid;
      assert.ok(
        typeof livePid === 'number' && livePid > 1,
        `Remote CLI "ospm launch ${liveAppId}" must spawn active PID > 1, got: ${launchCli.stdout}`
      );

      const beforeStop = await srv.api.get(`/api/v1/processes/${livePid}`);
      assert.equal(beforeStop.status, 200, `Launched PID ${livePid} must be visible in live daemon before stop`);
      const beforeObj = unwrapObject(beforeStop.json, ['process', 'data', 'result']);
      assert.ok(
        !['ZOMBIE', 'TERMINATED'].includes(beforeObj?.state),
        `Launched PID ${livePid} must be alive before ospm stop, got state=${beforeObj?.state}`
      );

      await srv.runCli(['ospm', 'stop', liveAppId], { json: true, expectZero: true });

      const afterStop = await srv.api.get(`/api/v1/processes/${livePid}`);
      if (afterStop.status === 200) {
        const afterObj = unwrapObject(afterStop.json, ['process', 'data', 'result']);
        assert.ok(
          ['ZOMBIE', 'TERMINATED'].includes(afterObj?.state),
          `Remote CLI "ospm stop ${liveAppId}" must terminate running PID ${livePid}, got state=${afterObj?.state}`
        );
      } else {
        assert.equal(afterStop.status, 404, 'Reaped process may return 404 after ospm stop');
      }
    } finally {
      await srv?.stop();
      await tmp.cleanup();
    }
  });
});
