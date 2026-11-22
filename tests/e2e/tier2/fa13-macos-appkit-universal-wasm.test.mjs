/**
 * OmniOS Tier 2 E2E Suite — FA-13: macOS & Universal WASM/WASI Runtimes
 * Boundary, Corner & Negative Cases (Edge Case #29 + Malformed Apple/WASM Containers).
 * Covers PROJECT.md Features: F-033, F-054, F-055, F-056.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero vacuous assertions.
 * - Clean try/finally teardown on every test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { loadPublicOmniOS } from '../lib/env.mjs';
import {
  buildXmlPlist,
  buildZip,
} from '../lib/binary-utils.mjs';
import {
  buildCustomDmg,
  buildCustomPkg,
  buildCustomUapp,
  buildCustomWasm,
  buildMachO64,
} from '../lib/fixtures-apple-wasm.mjs';
import {
  buildMalformedDmg,
  buildMalformedPkg,
  buildWasiEdgeUapp,
  buildWasiInvalidIovsLenWasm,
  buildWasiOobPointerWasm,
  buildWasiUngrantedFdWasm,
} from '../lib/fixtures-malformed.mjs';

const textEncoder = new TextEncoder();

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function assertKernelHealthy(osHandle, label = 'kernel') {
  const diag = osHandle.require('kernel').getDiagnostics();
  assert.equal(
    diag?.state,
    'RUNNING',
    `[${label}] Expected kernel state RUNNING, got ${JSON.stringify(diag?.state)}`
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
  };
}

async function installAndRunBytes(osHandle, bytes, vfsPath) {
  const vfs = osHandle.require('vfs');
  const pkgManager = osHandle.require('pkgManager');
  await vfs.writeFile(vfsPath, bytes);
  const rec = await pkgManager.install(vfsPath, { grantAll: true });
  const appId = rec.appId ?? rec.id;
  assert.ok(appId, `Expected non-empty appId after installing ${vfsPath}`);
  const launched = await pkgManager.launch(appId);
  assert.ok(launched.pid > 1, `Expected valid PID > 1 launching ${appId}`);
  return await runToCompletion(osHandle, launched.pid);
}

async function expectPipelineReject(osHandle, bytes, vfsPath, { label = 'pipeline' } = {}) {
  const vfs = osHandle.require('vfs');
  const pkgManager = osHandle.require('pkgManager');
  const pm = osHandle.require('processManager');
  await vfs.writeFile(vfsPath, bytes);

  let caught = null;
  let stage = 'inspect';
  let appId = null;
  let launchedPid = null;
  let runResult = null;
  try {
    const insp = await pkgManager.inspect(vfsPath);
    stage = 'install';
    const rec = await pkgManager.install(vfsPath, { grantAll: true });
    appId = rec?.appId ?? insp?.appId ?? rec?.id ?? null;
    if (appId) {
      stage = 'launch';
      const launched = await pkgManager.launch(appId);
      launchedPid = launched?.pid ?? null;
      if (launchedPid) {
        stage = 'run';
        runResult = await runToCompletion(osHandle, launchedPid, 500);
      }
    }
  } catch (err) {
    caught = err;
  }

  if (caught?.code === 'ERR_ASSERTION') throw caught;

  if (!caught && runResult) {
    const isFaulted =
      runResult.pcb?.state === 'FAULT' ||
      Boolean(runResult.summary?.fault) ||
      Boolean(runResult.pcb?.fault) ||
      (runResult.exitCode !== null && runResult.exitCode !== 0);
    if (isFaulted) {
      if (launchedPid) {
        const pcb = pm.get(launchedPid);
        assert.ok(
          !pcb || pcb.state === 'TERMINATED' || pcb.state === 'ZOMBIE' || pcb.state === 'FAULT',
          `[${label}] Faulted malformed container left surviving active process pid=${launchedPid} state=${pcb?.state}`
        );
      }
      return { rejected: true, faultedAtRun: true, run: runResult };
    }
  }

  if (!caught) {
    assert.fail(
      `[${label}] Expected malformed container to reject cleanly, but pipeline succeeded at stage=${stage} ` +
      `(appId=${JSON.stringify(appId)}, pid=${launchedPid}, exitCode=${runResult?.exitCode ?? null}, state=${runResult?.pcb?.state ?? null})`
    );
  }

  assert.ok(
    !(caught instanceof RangeError),
    `[${label}] Must not throw unhandled RangeError at stage=${stage}: ${caught.message}`
  );
  if (launchedPid) {
    const pcb = pm.get(launchedPid);
    assert.ok(
      !pcb || pcb.state === 'TERMINATED' || pcb.state === 'ZOMBIE' || pcb.state === 'FAULT',
      `[${label}] Failed launch left surviving active process pid=${launchedPid} state=${pcb?.state}`
    );
  }
  return { rejected: true, stage, error: caught };
}

describe('Tier 2 — FA-13: macOS & Universal WASM/WASI Runtimes (Boundary & Negative)', () => {
  it('T2-FA13-01 [Edge #29 / F-056]: WASI fd_write iovs_len > 1024 returns WASI_EINVAL (28) in both raw .wasm and .uapp', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const nonce = makeNonce();

      const rawWasm = buildWasiInvalidIovsLenWasm();
      assert.equal(WebAssembly.validate(rawWasm), true, 'Expected invalid-iovs-len WASI fixture to be valid WASM');

      const rawRun = await installAndRunBytes(osHandle, rawWasm, `/tmp/wasi-iovs-${nonce}.wasm`);
      assert.equal(
        rawRun.exitCode,
        28,
        `Expected WASI_EINVAL (28) for raw .wasm iovs_len=2048, got exitCode=${rawRun.exitCode}`
      );

      const uapp = buildWasiEdgeUapp('invalid-iovs-len');
      const uappRun = await installAndRunBytes(osHandle, uapp, `/tmp/wasi-iovs-${nonce}.uapp`);
      assert.equal(
        uappRun.exitCode,
        28,
        `Expected WASI_EINVAL (28) for .uapp iovs_len=2048, got exitCode=${uappRun.exitCode}`
      );

      assertKernelHealthy(osHandle, 'T2-FA13-01-after-einval');

      // Follow-up valid dynamic .uapp executes cleanly
      const okUapp = buildCustomUapp({
        appId: `com.omnios.uapp.ok.${nonce}`,
        name: `OkUapp_${nonce}`,
        message: `OK_${nonce}\n`,
        exitCode: 0,
      });
      const okRun = await installAndRunBytes(osHandle, okUapp, `/tmp/wasi-ok-${nonce}.uapp`);
      assert.equal(okRun.exitCode, 0);
      assert.ok(okRun.stdout.includes(`OK_${nonce}`), `Expected OK_${nonce}, got: ${JSON.stringify(okRun.stdout)}`);

      assertKernelHealthy(osHandle, 'T2-FA13-01');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA13-02 [Edge #29 / F-056]: WASI fd_write OOB pointer -> WASI_EFAULT (21) & ungranted FD -> WASI_ENOTCAPABLE (76) / WASI_EBADF (8)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const nonce = makeNonce();

      // 1. OOB pointer (0x100000 beyond 64 KiB linear memory)
      const oobWasm = buildWasiOobPointerWasm();
      assert.equal(WebAssembly.validate(oobWasm), true);
      const oobRawRun = await installAndRunBytes(osHandle, oobWasm, `/tmp/wasi-oob-${nonce}.wasm`);
      assert.equal(oobRawRun.exitCode, 21, `Expected WASI_EFAULT (21) for raw .wasm OOB ptr, got ${oobRawRun.exitCode}`);

      const oobUappRun = await installAndRunBytes(osHandle, buildWasiEdgeUapp('oob-pointer'), `/tmp/wasi-oob-${nonce}.uapp`);
      assert.equal(oobUappRun.exitCode, 21, `Expected WASI_EFAULT (21) for .uapp OOB ptr, got ${oobUappRun.exitCode}`);

      // 2. Ungranted FD (fd = 99)
      const fdWasm = buildWasiUngrantedFdWasm();
      assert.equal(WebAssembly.validate(fdWasm), true);
      const fdRawRun = await installAndRunBytes(osHandle, fdWasm, `/tmp/wasi-fd-${nonce}.wasm`);
      assert.ok(
        fdRawRun.exitCode === 76 || fdRawRun.exitCode === 8,
        `Expected WASI_ENOTCAPABLE (76) or WASI_EBADF (8) for raw .wasm ungranted fd=99, got ${fdRawRun.exitCode}`
      );
      assert.notEqual(fdRawRun.exitCode, 0);

      const fdUappRun = await installAndRunBytes(osHandle, buildWasiEdgeUapp('ungranted-fd'), `/tmp/wasi-fd-${nonce}.uapp`);
      assert.ok(
        fdUappRun.exitCode === 76 || fdUappRun.exitCode === 8,
        `Expected WASI_ENOTCAPABLE (76) or WASI_EBADF (8) for .uapp ungranted fd=99, got ${fdUappRun.exitCode}`
      );
      assert.notEqual(fdUappRun.exitCode, 0);

      assertKernelHealthy(osHandle, 'T2-FA13-02');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA13-03 [Edge #29 / F-056]: WASI high-bit u32 wraparound (0xfffffff0, 0xffffffff, 0x80000000) properly enforced as unsigned u32', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const nonce = makeNonce();

      // 1. oobPointer = 0xfffffff0 (would look negative -16 if signed i32 not coerced with >>> 0)
      const ptrWrapWasm = buildCustomWasm({ oobPointer: 0xfffffff0, returnFdWriteErrno: true });
      assert.equal(WebAssembly.validate(ptrWrapWasm), true);
      const ptrWrapRun = await installAndRunBytes(osHandle, ptrWrapWasm, `/tmp/wasi-u32ptr-${nonce}.wasm`);
      assert.ok(
        ptrWrapRun.exitCode === 21 || ptrWrapRun.exitCode === 28,
        `Expected WASI_EFAULT(21) or WASI_EINVAL(28) for oobPointer=0xfffffff0, got ${ptrWrapRun.exitCode}`
      );
      assert.notEqual(ptrWrapRun.exitCode, 0);

      // 2. invalidIovsLen = 0xffffffff (signed i32 -1: catches `iovsLen <= 1024` signedness bypass returning ESUCCESS=0!)
      const lenWrapWasm = buildCustomWasm({ invalidIovsLen: 0xffffffff, returnFdWriteErrno: true });
      assert.equal(WebAssembly.validate(lenWrapWasm), true);
      const lenWrapRun = await installAndRunBytes(osHandle, lenWrapWasm, `/tmp/wasi-u32len-${nonce}.wasm`);
      assert.ok(
        lenWrapRun.exitCode === 28 || lenWrapRun.exitCode === 21,
        `Expected WASI_EINVAL(28) or WASI_EFAULT(21) for invalidIovsLen=0xffffffff (never 0!), got ${lenWrapRun.exitCode}`
      );
      assert.notEqual(lenWrapRun.exitCode, 0);

      // 3. ungrantedFd = 0x80000000
      const fdWrapWasm = buildCustomWasm({ ungrantedFd: 0x80000000, returnFdWriteErrno: true });
      assert.equal(WebAssembly.validate(fdWrapWasm), true);
      const fdWrapRun = await installAndRunBytes(osHandle, fdWrapWasm, `/tmp/wasi-u32fd-${nonce}.wasm`);
      assert.ok(
        fdWrapRun.exitCode === 76 || fdWrapRun.exitCode === 8,
        `Expected WASI_ENOTCAPABLE(76) or WASI_EBADF(8) for ungrantedFd=0x80000000, got ${fdWrapRun.exitCode}`
      );
      assert.notEqual(fdWrapRun.exitCode, 0);

      assertKernelHealthy(osHandle, 'T2-FA13-03');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA13-04 [F-056]: Truncated / corrupt \\0asm magic & invalid .uapp manifest.json rejected cleanly', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const nonce = makeNonce();

      const truncHeader = Uint8Array.from([0x00, 0x61, 0x73, 0x6d]); // 4B truncated
      const badVersion = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x99, 0x00, 0x00, 0x00]); // version 0x99
      const truncSection = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x7f, 0xff]);

      assert.equal(WebAssembly.validate(truncHeader), false);
      assert.equal(WebAssembly.validate(badVersion), false);
      assert.equal(WebAssembly.validate(truncSection), false);

      await expectPipelineReject(osHandle, truncHeader, `/tmp/wasm-trunc-${nonce}.wasm`, { label: '4B truncated \\0asm' });
      await expectPipelineReject(osHandle, badVersion, `/tmp/wasm-badver-${nonce}.wasm`, { label: 'bad WASM version 0x99' });

      const corruptUapp = buildCustomUapp({
        appId: `com.omnios.uapp.corrupt.${nonce}`,
        name: 'CorruptWasmUapp',
        wasmBytes: truncSection,
      });
      await expectPipelineReject(osHandle, corruptUapp, `/tmp/uapp-corrupt-${nonce}.uapp`, { label: '.uapp with truncated WASM section' });

      const badManifestUapp = buildZip([
        { name: 'manifest.json', data: textEncoder.encode('{bad-json'), method: 8 },
        { name: 'app.wasm', data: buildCustomWasm({ message: 'x\n' }), method: 8 },
      ]);
      await expectPipelineReject(osHandle, badManifestUapp, `/tmp/uapp-badjson-${nonce}.uapp`, { label: '.uapp with malformed manifest.json' });

      assertKernelHealthy(osHandle, 'T2-FA13-04');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA13-05 [F-054]: Malformed macOS .dmg (corrupt koly magic & valid-koly OOB XMLOffset) and .pkg (corrupt xar! magic & corrupt zlib TOC)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const nonce = makeNonce();

      // 1. Corrupt-magic DMG ('BAD!')
      const badMagicDmg = buildMalformedDmg();
      const dmgDet = formatDetector.detect(badMagicDmg, `bad-${nonce}.dmg`);
      assert.notEqual(dmgDet.format, 'macos-dmg', 'Corrupt-magic DMG ("BAD!") must not detect as valid macos-dmg');
      await expectPipelineReject(osHandle, badMagicDmg, `/tmp/bad-magic-${nonce}.dmg`, { label: 'corrupt-magic .dmg' });

      // 2. Valid-magic 'koly' DMG with OOB XMLOffset = 0x7fffffffn (forces deep DMG parser bounds check)
      const validDmg = new Uint8Array(buildCustomDmg({ volumeName: `DmgOob_${nonce}` }));
      const kolyOff = validDmg.length - 512;
      assert.equal(Buffer.from(validDmg.subarray(kolyOff, kolyOff + 4)).toString('ascii'), 'koly');
      const dmgView = new DataView(validDmg.buffer, validDmg.byteOffset, validDmg.byteLength);
      dmgView.setBigUint64(kolyOff + 0xd8, 0x7fffffffn, false);
      await expectPipelineReject(osHandle, validDmg, `/tmp/oob-xml-${nonce}.dmg`, { label: 'valid-koly OOB XMLOffset .dmg' });

      // 3. Corrupt-magic PKG ('BAD!')
      const badMagicPkg = buildMalformedPkg();
      const pkgDet = formatDetector.detect(badMagicPkg, `bad-${nonce}.pkg`);
      assert.notEqual(pkgDet.format, 'macos-pkg', 'Corrupt-magic PKG ("BAD!") must not detect as valid macos-pkg');
      await expectPipelineReject(osHandle, badMagicPkg, `/tmp/bad-magic-${nonce}.pkg`, { label: 'corrupt-magic .pkg' });

      // 4. Valid-magic 'xar!' PKG with corrupted zlib TOC bytes 28..35 (forces deep XAR inflate error handling)
      const validPkg = new Uint8Array(buildCustomPkg({ bundleId: `com.omnios.pkg.corrupt.${nonce}` }));
      const pkgView = new DataView(validPkg.buffer, validPkg.byteOffset, validPkg.byteLength);
      assert.equal(pkgView.getUint32(0, false), 0x78617221); // 'xar!'
      for (let i = 28; i < 36; i++) validPkg[i] = 0xff;
      await expectPipelineReject(osHandle, validPkg, `/tmp/bad-toc-${nonce}.pkg`, { label: 'valid-xar! corrupt zlib TOC .pkg' });

      assertKernelHealthy(osHandle, 'T2-FA13-05');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA13-06 [F-054]: Malformed macOS .app.zip bundles (missing Info.plist, missing CFBundleExecutable/file, non-Mach-O executable)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const nonce = makeNonce();

      // (a) Missing Info.plist
      const noPlistApp = buildZip([
        { name: 'NoPlist.app/Contents/MacOS/NoPlist', data: buildMachO64({ arch: 'arm64', platform: 1 }), method: 8 },
      ]);
      await expectPipelineReject(osHandle, noPlistApp, `/tmp/app-noplist-${nonce}.app.zip`, { label: '.app.zip missing Info.plist' });

      // (b1) Info.plist omitting CFBundleExecutable key
      const noExecKeyPlist = textEncoder.encode(buildXmlPlist({
        CFBundleIdentifier: `com.omnios.mac.noexeckey.${nonce}`,
        CFBundleName: 'NoExecKey',
        CFBundlePackageType: 'APPL',
      }));
      const noExecKeyApp = buildZip([
        { name: 'NoExecKey.app/Contents/Info.plist', data: noExecKeyPlist, method: 8 },
      ]);
      await expectPipelineReject(osHandle, noExecKeyApp, `/tmp/app-noexeckey-${nonce}.app.zip`, { label: '.app.zip missing CFBundleExecutable key' });

      // (b2) Info.plist pointing to nonexistent Contents/MacOS/GhostBin
      const ghostExecPlist = textEncoder.encode(buildXmlPlist({
        CFBundleIdentifier: `com.omnios.mac.ghostexec.${nonce}`,
        CFBundleName: 'GhostExec',
        CFBundleExecutable: 'GhostBin',
        CFBundlePackageType: 'APPL',
      }));
      const ghostExecApp = buildZip([
        { name: 'GhostExec.app/Contents/Info.plist', data: ghostExecPlist, method: 8 },
      ]);
      await expectPipelineReject(osHandle, ghostExecApp, `/tmp/app-ghostexec-${nonce}.app.zip`, { label: '.app.zip missing Mach-O binary file' });

      // (c) Valid Info.plist pointing to non-Mach-O ASCII text executable
      const badBinPlist = textEncoder.encode(buildXmlPlist({
        CFBundleIdentifier: `com.omnios.mac.badbin.${nonce}`,
        CFBundleName: 'BadBin',
        CFBundleExecutable: 'BadBin',
        CFBundlePackageType: 'APPL',
      }));
      const badBinApp = buildZip([
        { name: 'BadBin.app/Contents/Info.plist', data: badBinPlist, method: 8 },
        { name: 'BadBin.app/Contents/MacOS/BadBin', data: textEncoder.encode('NOT_A_MACHO_HEADER_AT_ALL'), method: 8 },
      ]);
      await expectPipelineReject(osHandle, badBinApp, `/tmp/app-badbin-${nonce}.app.zip`, { label: '.app.zip non-Mach-O executable' });

      assertKernelHealthy(osHandle, 'T2-FA13-06');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA13-07 [F-056/F-033]: Zero-byte .uapp / .wasm, empty ZIP .uapp & missing entry rejected cleanly while healthy follow-up .uapp runs', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const nonce = makeNonce();

      // (a) Zero-byte buffers
      const empty = new Uint8Array(0);
      assert.equal(formatDetector.detect(empty, 'empty.uapp').format, 'unknown');
      assert.equal(formatDetector.detect(empty, 'empty.wasm').format, 'unknown');
      await expectPipelineReject(osHandle, empty, `/tmp/empty-${nonce}.uapp`, { label: '0-byte .uapp' });
      await expectPipelineReject(osHandle, empty, `/tmp/empty-${nonce}.wasm`, { label: '0-byte .wasm' });

      // (b) Empty ZIP archive as .uapp
      const emptyZip = buildZip([]);
      await expectPipelineReject(osHandle, emptyZip, `/tmp/empty-zip-${nonce}.uapp`, { label: 'empty ZIP .uapp' });

      // (c) .uapp manifest pointing to missing entry wasm
      const missingEntryUapp = buildZip([
        {
          name: 'manifest.json',
          data: textEncoder.encode(JSON.stringify({
            id: `com.omnios.uapp.missingentry.${nonce}`,
            appId: `com.omnios.uapp.missingentry.${nonce}`,
            name: 'MissingEntry',
            version: '1.0.0',
            platform: 'universal',
            entry: 'missing.wasm',
          })),
          method: 8,
        },
      ]);
      await expectPipelineReject(osHandle, missingEntryUapp, `/tmp/missing-entry-${nonce}.uapp`, { label: '.uapp missing entry wasm' });

      // Follow-up healthy dynamic .uapp installs & executes cleanly
      const healthyUapp = buildCustomUapp({
        appId: `com.omnios.uapp.healthy.${nonce}`,
        name: `Healthy_${nonce}`,
        message: `HEALTHY_${nonce}\n`,
        exitCode: 0,
      });
      const run = await installAndRunBytes(osHandle, healthyUapp, `/tmp/healthy-${nonce}.uapp`);
      assert.equal(run.exitCode, 0);
      assert.ok(run.stdout.includes(`HEALTHY_${nonce}`), `Expected HEALTHY_${nonce}, got: ${JSON.stringify(run.stdout)}`);

      assertKernelHealthy(osHandle, 'T2-FA13-07');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });
});
