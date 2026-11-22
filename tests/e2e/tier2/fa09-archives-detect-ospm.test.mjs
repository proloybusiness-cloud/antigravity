/**
 * OmniOS Tier 2 E2E Suite — FA-09: PKZIP/ZIP64, Magic-Byte Format Detector & ospm
 * Boundary, Corner & Negative Cases (Edge Cases #1, #2, #4, #19).
 * Covers PROJECT.md Features: F-032, F-033, F-034, Contracts 5, 7 & 8.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero vacuous assertions.
 * - Clean try/finally teardown on every test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';

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
  buildJavaClassBytes,
  buildZipBomb,
  buildZipSlipArchive,
  buildZipWithDataDescriptor,
} from '../lib/fixtures-malformed.mjs';
import { buildCustomApk } from '../lib/fixtures-android-win.mjs';
import {
  buildCustomUapp,
  buildCustomWasm,
} from '../lib/fixtures-apple-wasm.mjs';

const textEncoder = new TextEncoder();

function makeToken() {
  return crypto.randomBytes(4).toString('hex');
}

function extractErrorCode(err) {
  if (!err || typeof err !== 'object') return null;
  const direct = err.code ?? err.cause?.code ?? err.error?.code;
  if (typeof direct === 'string' && direct.length > 0) return direct;
  const m = /\b(E_[A-Z0-9_]+)\b/.exec(String(err.message ?? ''));
  return m ? m[1] : null;
}

function assertKernelHealthy(osHandle, label = 'kernel') {
  const diag = osHandle.require('kernel').getDiagnostics();
  assert.equal(
    diag?.state,
    'RUNNING',
    `[${label}] Expected kernel state RUNNING, got ${JSON.stringify(diag?.state)}`
  );
}

function extractArrayStrict(payload, keys = ['packages', 'items', 'data', 'entries']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return null;
}

async function assertRejectsCleanly(fn, { expectedCode = null, codePattern = null, allowFalseResult = false, label = 'operation' } = {}) {
  let result;
  let caught = null;
  try {
    result = await fn();
  } catch (err) {
    caught = err;
  }

  if (caught?.code === 'ERR_ASSERTION') throw caught;

  if (caught) {
    const code = extractErrorCode(caught);
    const msg = String(caught.message ?? caught);
    if (expectedCode) {
      assert.ok(
        code === expectedCode || msg.includes(expectedCode),
        `[${label}] Expected error code ${expectedCode}, got code=${JSON.stringify(code)} message=${JSON.stringify(msg)}`
      );
    } else if (codePattern) {
      assert.ok(
        codePattern.test(`${code ?? ''} ${msg}`),
        `[${label}] Expected error matching ${codePattern}, got code=${JSON.stringify(code)} message=${JSON.stringify(msg)}`
      );
    }
    return { rejected: true, error: caught, code };
  }

  if (allowFalseResult && (result === false || result === null || result?.ok === false)) {
    return { rejected: true, error: null, result };
  }

  assert.fail(
    `[${label}] Expected operation to reject cleanly${expectedCode ? ` with ${expectedCode}` : ''}, ` +
    `but it resolved with: ${JSON.stringify(result)}`
  );
}

function extractStdout(pcb, summary) {
  const raw = summary?.stdout ?? pcb?.streams?.stdout ?? pcb?.stdout ?? '';
  if (typeof raw === 'string') return raw;
  if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) return Buffer.from(raw).toString('utf8');
  if (Array.isArray(raw)) {
    return raw
      .map((c) => (Buffer.isBuffer(c) || c instanceof Uint8Array ? Buffer.from(c).toString('utf8') : String(c ?? '')))
      .join('');
  }
  return String(raw ?? '');
}

function extractExitCode(pcb, summary) {
  const code = summary?.exitCode ?? pcb?.stats?.exitCode ?? pcb?.exitCode;
  return code === undefined || code === null ? null : Number(code);
}

async function runToCompletion(osHandle, pid, maxTicks = 1500) {
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
  };
}

const wrappedZipBombCache = new Map();

function getWrappedCompressedZeros(uncompBytes) {
  if (wrappedZipBombCache.has(uncompBytes)) return wrappedZipBombCache.get(uncompBytes);
  const zeros = Buffer.alloc(uncompBytes);
  const compBuf = zlib.deflateRawSync(zeros, { level: 9 });
  const compBytes = new Uint8Array(compBuf.buffer, compBuf.byteOffset, compBuf.byteLength);
  const crc = typeof zlib.crc32 === 'function' ? (zlib.crc32(zeros) >>> 0) : crc32(zeros);
  const cached = { compBytes, crc, uncompBytes };
  wrappedZipBombCache.set(uncompBytes, cached);
  return cached;
}

function buildPackageWrappedZipBomb(appId, { fakeSmallUncompSize = false, uncompBytes = 110 * 1024 * 1024 } = {}) {
  const { compBytes, crc } = getWrappedCompressedZeros(uncompBytes);
  const manifest = {
    id: appId,
    appId,
    name: fakeSmallUncompSize ? 'BombLyingUapp' : 'BombStdUapp',
    version: '1.0.0',
    platform: 'universal',
    entry: 'app.wasm',
  };
  return buildZip([
    { name: 'manifest.json', data: textEncoder.encode(JSON.stringify(manifest)), method: 8 },
    {
      name: 'app.wasm',
      method: 8,
      rawCompData: compBytes,
      overrideCrc32: crc,
      overrideUncompSize: fakeSmallUncompSize ? 1024 : uncompBytes,
      overrideCompSize: compBytes.length,
    },
  ]);
}

async function assertUappBombRejected(pkgManager, uappBytes, appId, label) {
  let stage = 'install';
  let caught = null;
  let launchedRes = null;
  try {
    await pkgManager.install(uappBytes);
    // If install deferred inflating app.wasm lazily, launch MUST hit E_ARCHIVE_BOMB before running
    stage = 'launch';
    launchedRes = await pkgManager.launch(appId);
  } catch (err) {
    caught = err;
  }

  if (caught?.code === 'ERR_ASSERTION') throw caught;
  assert.ok(
    caught,
    `[${label}] Expected E_ARCHIVE_BOMB during install or launch, but launch succeeded: ${JSON.stringify(launchedRes)}`
  );
  assert.ok(
    !(caught instanceof RangeError),
    `[${label}] Must reject cleanly with E_ARCHIVE_BOMB (not RangeError) at stage=${stage}: ${caught.message}`
  );
  const code = extractErrorCode(caught);
  const msg = String(caught.message ?? caught);
  assert.ok(
    code === 'E_ARCHIVE_BOMB' || msg.includes('E_ARCHIVE_BOMB'),
    `[${label}] Expected E_ARCHIVE_BOMB at stage=${stage}, got code=${JSON.stringify(code)} msg=${JSON.stringify(msg)}`
  );
  return { stage, error: caught, code };
}

async function readVfsTextIfExists(vfs, filePath) {
  try {
    const content = await vfs.readFile(filePath, { encoding: 'utf8', uid: 0, gid: 0 });
    return typeof content === 'string' ? content : Buffer.from(content).toString('utf8');
  } catch (err) {
    if (err?.code === 'ENOENT' || /ENOENT|not found/i.test(String(err?.message))) {
      return null;
    }
    throw err;
  }
}

describe('Tier 2 — FA-09: PKZIP/ZIP64, Magic-Byte Format Detector & ospm (Boundary & Negative)', () => {
  it('T2-FA09-01 [F-032, Edge #1]: ZIP-slip rejection across all 4 variants (dotdot, win-drive, leading-slash, nul-byte -> E_PATH_TRAVERSAL)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const vfs = osHandle.require('vfs');

      const variants = ['dotdot', 'win-drive', 'leading-slash', 'nul-byte'];
      for (const variant of variants) {
        const slipApk = buildZipSlipArchive(variant, { wrapAsApk: true });

        // install() MUST strictly reject with E_PATH_TRAVERSAL
        await assertRejectsCleanly(
          () => pkgManager.install(slipApk),
          { expectedCode: 'E_PATH_TRAVERSAL', label: `install(zip-slip:${variant})` }
        );

        // inspect() should reject with E_PATH_TRAVERSAL (or if header-only, must never escape VFS)
        let inspectErr = null;
        try {
          await pkgManager.inspect(slipApk);
        } catch (err) {
          inspectErr = err;
        }
        if (inspectErr) {
          const code = extractErrorCode(inspectErr);
          const msg = String(inspectErr.message ?? '');
          assert.ok(
            code === 'E_PATH_TRAVERSAL' || /E_PATH_TRAVERSAL|traversal|slip|path/i.test(`${code ?? ''} ${msg}`),
            `[inspect(zip-slip:${variant})] Expected traversal error, got code=${code} msg=${msg}`
          );
        }

        // Verify zero files leaked outside sandbox into VFS
        const etcPasswd = await readVfsTextIfExists(vfs, '/etc/passwd');
        assert.ok(
          etcPasswd === null || !etcPasswd.includes('OMNIOS_ZIP_SLIP'),
          `ZIP-slip variant "${variant}" overwrote /etc/passwd!`
        );
        const etcShadow = await readVfsTextIfExists(vfs, '/etc/shadow');
        assert.ok(
          etcShadow === null || !etcShadow.includes('OMNIOS_ZIP_SLIP'),
          `ZIP-slip variant "${variant}" created/overwrote /etc/shadow!`
        );
        const evilDll = await readVfsTextIfExists(vfs, '/system/windows/evil.dll');
        assert.equal(evilDll, null, `ZIP-slip variant "${variant}" created /system/windows/evil.dll!`);

        const installedList = extractArrayStrict(await pkgManager.list());
        assert.ok(Array.isArray(installedList), 'Expected pkgManager.list() to return an Array');
        assert.ok(
          !installedList.some((p) => (p?.appId ?? p?.id) === 'com.omnios.zipslip'),
          `ZIP-slip APK (${variant}) must NOT appear in pkgManager.list()`
        );
      }

      // Raw unwrapped ZIP-slip archive must also be rejected cleanly
      const rawSlip = buildZipSlipArchive('dotdot', { wrapAsApk: false });
      await assertRejectsCleanly(
        () => pkgManager.install(rawSlip),
        { label: 'install(raw-zip-slip:dotdot)' }
      );

      assertKernelHealthy(osHandle, 'T2-FA09-01');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA09-02 [F-032, Edge #2]: ZIP bomb rejection (.uapp-wrapped standard 110 MiB & lying bombs -> E_ARCHIVE_BOMB; raw bombs reject cleanly before RAM exhaustion)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const pm = osHandle.require('processManager');
      const tok = makeToken();
      const bombStdAppId = `com.omnios.bombstd.${tok}`;
      const bombLyingAppId = `com.omnios.bomblying.${tok}`;

      // Build ALL bomb fixtures BEFORE measuring heap & latency so fixture creation is not charged to OmniOS
      const bombStdUapp = buildPackageWrappedZipBomb(bombStdAppId, { fakeSmallUncompSize: false });
      const bombLyingUapp = buildPackageWrappedZipBomb(bombLyingAppId, { fakeSmallUncompSize: true });
      const bombStd = buildZipBomb();
      const bombLyingRaw = buildZipBomb({ fakeSmallUncompSize: true });

      const heapBefore = process.memoryUsage().heapUsed;
      const t0 = Date.now();

      // 1. .uapp-wrapped standard 110 MiB declared ZIP bomb -> MUST strictly reject with E_ARCHIVE_BOMB
      const stdRes = await assertUappBombRejected(
        pkgManager,
        bombStdUapp,
        bombStdAppId,
        'uapp-standard-110MiB-zip-bomb'
      );

      // 2. .uapp-wrapped lying bomb (header lies 1024B while inflating 110 MiB) -> MUST strictly hit streaming cap E_ARCHIVE_BOMB
      const lyingRes = await assertUappBombRejected(
        pkgManager,
        bombLyingUapp,
        bombLyingAppId,
        'uapp-lying-110MiB-zip-bomb'
      );

      // 3. Raw unwrapped standard 110 MiB bomb (no manifest) -> MUST reject cleanly (E_ARCHIVE_BOMB or unsupported format), never exhaust RAM
      await assertRejectsCleanly(
        () => pkgManager.install(bombStd),
        { label: 'install(raw-standard-zip-bomb)' }
      );

      // 4. Raw unwrapped lying bomb (no manifest) -> MUST reject cleanly (E_ARCHIVE_BOMB or unknown format), never install
      await assertRejectsCleanly(
        () => pkgManager.install(bombLyingRaw),
        { label: 'install(raw-lying-zip-bomb)' }
      );

      const elapsedMs = Date.now() - t0;
      const heapDelta = process.memoryUsage().heapUsed - heapBefore;

      assert.ok(
        elapsedMs < 10000,
        `ZIP bomb defense took ${elapsedMs}ms (>= 10000ms); expected fast bounded abort`
      );
      assert.ok(
        heapDelta < 100 * 1024 * 1024,
        `ZIP bomb inflated ${Math.round(heapDelta / (1024 * 1024))} MiB into V8 heap; streaming cap must abort before 100 MiB!`
      );

      // Consistent post-rejection state check for both eager (install) and lazy (launch) bomb rejections
      const installedList = extractArrayStrict(await pkgManager.list());
      assert.ok(Array.isArray(installedList), 'Expected pkgManager.list() to return an Array');
      const procs = extractArrayStrict(pm.list(), ['processes', 'items', 'data']) ?? [];

      for (const item of [
        { appId: bombStdAppId, stage: stdRes.stage, label: 'standard .uapp bomb' },
        { appId: bombLyingAppId, stage: lyingRes.stage, label: 'lying .uapp bomb' },
      ]) {
        if (item.stage === 'install') {
          assert.ok(
            !installedList.some((p) => (p?.appId ?? p?.id) === item.appId),
            `ZIP bomb app ${item.appId} (${item.label}) rejected at install() must NOT remain installed`
          );
        } else {
          // Install deferred app.wasm extraction lazily and launch() rejected with E_ARCHIVE_BOMB:
          // verify no active process survived and clean up the package cleanly via uninstall().
          const leaked = procs.find(
            (p) => p?.appId === item.appId && p.state !== 'TERMINATED' && p.state !== 'ZOMBIE'
          );
          assert.equal(
            leaked ?? null,
            null,
            `ZIP bomb app ${item.appId} (${item.label}) rejected at launch() left active process: ${JSON.stringify(leaked)}`
          );
          await pkgManager.uninstall(item.appId, { purgeData: true });
          const afterCleanup = extractArrayStrict(await pkgManager.list());
          assert.ok(Array.isArray(afterCleanup), 'Expected pkgManager.list() to return an Array after cleanup');
          assert.ok(
            !afterCleanup.some((p) => (p?.appId ?? p?.id) === item.appId),
            `Expected uninstall(${item.appId}) to remove lazily-rejected ZIP bomb package`
          );
        }
      }

      assertKernelHealthy(osHandle, 'T2-FA09-02');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA09-03 [F-032, Edge #4]: ZIP Data Descriptor flag bit 3 (0x0008) positive extraction & live execution', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();
      const appId = `com.omnios.dd3.${tok}`;
      const expectedCode = 13 + (crypto.randomBytes(1)[0] % 40);
      const expectedMsg = `DD3_EXEC_${tok}\n`;

      const wasmBytes = buildCustomWasm({ message: expectedMsg, exitCode: expectedCode });
      const manifest = {
        id: appId,
        appId,
        name: `DD3App_${tok}`,
        version: '1.0.0',
        platform: 'universal',
        entry: 'app.wasm',
      };
      const uappDD = buildZipWithDataDescriptor([
        { name: 'manifest.json', data: textEncoder.encode(JSON.stringify(manifest)), method: 8 },
        { name: 'app.wasm', data: wasmBytes, method: 8 },
      ]);

      // Verify raw Local File Header actually has flag bit 3 (0x0008) set and LFH crc/sizes == 0
      const lfhView = new DataView(uappDD.buffer, uappDD.byteOffset, uappDD.byteLength);
      assert.equal(lfhView.getUint32(0, true), 0x04034b50, 'Expected PK\\x03\\x04 LFH signature');
      assert.ok((lfhView.getUint16(6, true) & 0x0008) !== 0, 'Expected ZIP GP flag bit 3 (0x0008) set');
      assert.equal(lfhView.getUint32(14, true), 0, 'Expected LFH crc32 === 0 when bit 3 is set');
      assert.equal(lfhView.getUint32(18, true), 0, 'Expected LFH compSize === 0 when bit 3 is set');
      assert.equal(lfhView.getUint32(22, true), 0, 'Expected LFH uncompSize === 0 when bit 3 is set');

      const det = formatDetector.detect(uappDD, `dd3-${tok}.uapp`);
      assert.equal(det.format, 'universal-uapp');
      assert.equal(det.platform, 'universal');

      const insp = await pkgManager.inspect(uappDD);
      assert.equal(insp.appId ?? insp.id, appId);
      assert.equal(insp.sha256, sha256Hex(uappDD));

      await pkgManager.install(uappDD, { grantAll: true });
      const launched = await pkgManager.launch(appId);
      assert.ok(launched.pid > 1, 'Expected valid PID > 1 for bit-3 .uapp');
      const run = await runToCompletion(osHandle, launched.pid);

      assert.ok(
        run.stdout.includes(`DD3_EXEC_${tok}`),
        `Expected Data-Descriptor .uapp stdout to include DD3_EXEC_${tok}, got: ${JSON.stringify(run.stdout)}`
      );
      assert.equal(run.exitCode, expectedCode, `Expected bit-3 .uapp exitCode ${expectedCode}, got ${run.exitCode}`);

      // Also verify Android APK encoded with Data Descriptor bit 3 inspects cleanly
      const apkPkg = `com.omnios.dd3apk.${tok}`;
      const apkDD = buildCustomApk({
        packageName: apkPkg,
        appLabel: `DD3Apk-${tok}`,
        useDataDescriptor: true,
      });
      const apkInsp = await pkgManager.inspect(apkDD);
      assert.equal(apkInsp.format, 'android-apk');
      assert.equal(apkInsp.appId ?? apkInsp.packageName, apkPkg);

      assertKernelHealthy(osHandle, 'T2-FA09-03');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA09-04 [F-033, Edge #19]: Java .class (0xCAFEBABE 00000034) guarded against Mach-O Fat misdetection', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const pkgManager = osHandle.require('pkgManager');

      const javaBytes = buildJavaClassBytes();
      for (const hint of ['Test.class', 'decoy.macho', 'decoy', 'libfoo.dylib']) {
        const res = formatDetector.detect(javaBytes, hint);
        assert.notEqual(
          res.format,
          'macos-macho',
          `Java .class with hint "${hint}" must NOT be misidentified as macos-macho`
        );
        assert.notEqual(res.platform, 'macos', `Java .class (${hint}) must NOT map to platform macos`);
        assert.notEqual(res.platform, 'ios', `Java .class (${hint}) must NOT map to platform ios`);
        assert.equal(res.format, 'unknown', `Java .class (${hint}) should detect as format 'unknown', got ${JSON.stringify(res)}`);
      }

      // Bogus 0xCAFEBABE headers with nfat_arch = 0 and nfat_arch = 33 (> 32)
      for (const nfat of [0, 33]) {
        const bogusFat = new Uint8Array(64);
        const dv = new DataView(bogusFat.buffer);
        dv.setUint32(0, 0xcafebabe, false);
        dv.setUint32(4, nfat, false);
        const res = formatDetector.detect(bogusFat, `bogus-${nfat}.macho`);
        assert.notEqual(
          res.format,
          'macos-macho',
          `0xCAFEBABE with nfat_arch=${nfat} must NOT detect as macos-macho`
        );
        assert.equal(res.format, 'unknown');
      }

      await assertRejectsCleanly(() => pkgManager.inspect(javaBytes), { label: 'inspect(java.class)' });
      await assertRejectsCleanly(() => pkgManager.install(javaBytes), { label: 'install(java.class)' });

      assertKernelHealthy(osHandle, 'T2-FA09-04');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA09-05 [F-033]: Empty, truncated & random buffers detect safely as format "unknown" without OOB throws', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const pkgManager = osHandle.require('pkgManager');

      const empty = new Uint8Array(0);
      for (const hint of ['', 'a.apk', 'a.exe', 'a.ipa', 'a.wasm']) {
        const res = formatDetector.detect(empty, hint);
        assert.equal(res.format, 'unknown', `Empty buffer with hint "${hint}" must detect as unknown`);
      }

      const truncatedCases = [
        { label: '2B PK', bytes: Uint8Array.from([0x50, 0x4b]), hint: 't.apk' },
        { label: '2B MZ', bytes: Uint8Array.from([0x4d, 0x5a]), hint: 't.exe' },
        { label: '3B \\0as', bytes: Uint8Array.from([0x00, 0x61, 0x73]), hint: 't.wasm' },
        { label: '3B Mach-O', bytes: Uint8Array.from([0xcf, 0xfa, 0xed]), hint: 't.macho' },
        { label: '3B Fat', bytes: Uint8Array.from([0xca, 0xfe, 0xba]), hint: 't.fat' },
        { label: '4B XAR (<28B)', bytes: Uint8Array.from([0x78, 0x61, 0x72, 0x21]), hint: 't.pkg' },
        {
          label: '30B truncated ZIP LFH (no CD/EOCD)',
          bytes: Uint8Array.from([
            0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x21, 0x54, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
          ]),
          hint: 'trunc.zip',
        },
      ];

      for (const tc of truncatedCases) {
        const res = formatDetector.detect(tc.bytes, tc.hint);
        assert.equal(
          res.format,
          'unknown',
          `Truncated case "${tc.label}" must return format "unknown" without throwing, got ${JSON.stringify(res)}`
        );
      }

      const randBuf = crypto.randomBytes(128);
      randBuf[0] = 0xde;
      randBuf[1] = 0xad;
      randBuf[2] = 0xbe;
      randBuf[3] = 0xef;
      const randDet = formatDetector.detect(randBuf, 'random.bin');
      assert.equal(randDet.format, 'unknown');

      await assertRejectsCleanly(() => pkgManager.inspect(empty), { label: 'inspect(empty)' });
      await assertRejectsCleanly(() => pkgManager.install(randBuf), { label: 'install(random)' });

      assertKernelHealthy(osHandle, 'T2-FA09-05');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA09-06 [F-034]: ospm programmatic negative lifecycle (missing get/launch/stop/uninstall & invalid PID) preserves healthy packages', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();

      // Install a healthy package first to prove negative calls do not corrupt the registry
      const healthyId = `com.omnios.healthy.${tok}`;
      const healthyUapp = buildCustomUapp({
        appId: healthyId,
        name: `Healthy_${tok}`,
        message: `HEALTHY_${tok}\n`,
        exitCode: 0,
      });
      await pkgManager.install(healthyUapp, { grantAll: true });
      assert.ok(await pkgManager.get(healthyId), `Expected healthy package ${healthyId} to be installed`);

      const missingId = `com.omnios.missing.${tok}`;
      assert.equal((await pkgManager.get(missingId)) ?? null, null, 'Expected pkgManager.get(missing) to be null/undefined');

      await assertRejectsCleanly(
        () => pkgManager.launch(missingId),
        { label: `launch(${missingId})` }
      );
      await assertRejectsCleanly(
        () => pkgManager.uninstall(missingId),
        { allowFalseResult: true, label: `uninstall(${missingId})` }
      );
      await assertRejectsCleanly(
        () => pkgManager.stop(missingId),
        { allowFalseResult: true, label: `stop(${missingId})` }
      );
      await assertRejectsCleanly(
        () => pkgManager.stop(999999),
        { allowFalseResult: true, label: 'stop(999999)' }
      );

      // Healthy package must still be intact and launchable
      const stillThere = await pkgManager.get(healthyId);
      assert.ok(stillThere, `Healthy package ${healthyId} disappeared after negative ops`);
      const launched = await pkgManager.launch(healthyId);
      assert.ok(launched.pid > 1, 'Expected healthy package to still launch with valid PID > 1');
      const run = await runToCompletion(osHandle, launched.pid);
      assert.ok(run.stdout.includes(`HEALTHY_${tok}`), `Expected HEALTHY_${tok}, got: ${run.stdout}`);

      assertKernelHealthy(osHandle, 'T2-FA09-06');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA09-07 [F-032, F-034, Contracts 7 & 8]: Live REST & CLI negative ospm handling (404 missing app, 4xx ZIP-slip upload, CLI non-zero exit)', async () => {
    let srv = null;
    let tmp = null;
    try {
      srv = await startOmniServer();
      tmp = await createTempDataDir('omnios-t2-fa09-');
      const tok = makeToken();
      const missingId = `com.omnios.missing.${tok}`;

      // REST 404 on nonexistent app launch & delete
      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(missingId)}/launch`, {});
      assert.equal(
        launchRes.status,
        404,
        `Expected HTTP 404 launching nonexistent app ${missingId}, got ${launchRes.status}: ${launchRes.text}`
      );

      const delRes = await srv.api.delete(`/api/v1/packages/${encodeURIComponent(missingId)}`);
      assert.equal(
        delRes.status,
        404,
        `Expected HTTP 404 deleting nonexistent app ${missingId}, got ${delRes.status}: ${delRes.text}`
      );

      // REST 4xx on ZIP-slip upload (JSON base64 first, fallback to octet-stream ONLY on 415)
      const slipApk = buildZipSlipArchive('dotdot', { wrapAsApk: true });
      const b64 = Buffer.from(slipApk).toString('base64');
      let uploadRes = await srv.api.post('/api/v1/packages/install', {
        base64: b64,
        data: b64,
        filename: `slip-${tok}.apk`,
      });
      if (uploadRes.status === 415) {
        uploadRes = await srv.api.post('/api/v1/packages/install', slipApk, {
          query: { filename: `slip-${tok}.apk` },
          headers: {
            'content-type': 'application/octet-stream',
            'x-filename': `slip-${tok}.apk`,
          },
        });
      }
      assert.ok(
        uploadRes.status >= 400 && uploadRes.status < 500,
        `Expected HTTP 4xx rejecting ZIP-slip upload, got ${uploadRes.status}: ${uploadRes.text}`
      );

      // Confirm ZIP-slip package did NOT get installed
      const listRes = await srv.api.get('/api/v1/packages', { expectOk: true });
      const pkgs = extractArrayStrict(listRes.json);
      assert.ok(Array.isArray(pkgs), `Expected package array from GET /api/v1/packages, got: ${listRes.text}`);
      assert.ok(
        !pkgs.some((p) => (p?.appId ?? p?.id) === 'com.omnios.zipslip'),
        'ZIP-slip package must not appear in GET /api/v1/packages'
      );

      // Remote CLI uninstall on nonexistent package must fail cleanly
      const cliUninst = await srv.runCli(['ospm', 'uninstall', missingId], { json: true });
      assert.ok(
        cliUninst.code !== 0 || cliUninst.json?.ok === false,
        `Expected CLI ospm uninstall ${missingId} to fail cleanly, got code=${cliUninst.code} stdout=${cliUninst.stdout}`
      );

      // Standalone CLI install on ZIP-slip archive file must exit non-zero
      const slipPath = path.join(tmp.dir, `slip-${tok}.apk`);
      await fs.writeFile(slipPath, slipApk);
      const cliDataDir = path.join(tmp.dir, 'cli-data');
      await fs.mkdir(cliDataDir, { recursive: true });
      const cliSlip = await runCli(['ospm', 'install', slipPath], { dataDir: cliDataDir, json: true });
      assert.notEqual(
        cliSlip.code,
        0,
        `Expected standalone CLI ospm install on ZIP-slip archive to exit non-zero, got code=0 stdout=${cliSlip.stdout}`
      );

      // Server remains completely healthy
      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
    } finally {
      if (srv) await srv.stop().catch(() => {});
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });
});
