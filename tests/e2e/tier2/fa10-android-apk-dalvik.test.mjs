/**
 * OmniOS Tier 2 E2E Suite — FA-10: Android Runtime (APK, AXML, resources.arsc, DEX & Dalvik VM)
 * Boundary, Corner & Negative Cases (Edge Cases #3, #5, #6, #7, #8, #9, #10, #11).
 * Covers PROJECT.md Features: F-011, F-036, F-037, F-038, F-039, F-040.
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
  buildAxmlManifest,
  buildZip,
  sha256Hex,
} from '../lib/binary-utils.mjs';
import {
  DALVIK,
  buildCustomApk,
  buildDex,
} from '../lib/fixtures-android-win.mjs';
import {
  buildApkWithV2SigningBlock,
  buildDexDeepRecursionApk,
  buildDexDivByZeroApk,
  buildDexInfiniteLoopApk,
  buildDexInt32MinDivNeg1Apk,
  buildDexMutf8Valid,
  buildDexOddInsnsTryCatchApk,
  buildDexOverlongLeb128,
  buildMalformedAxmlApk,
  buildMalformedDexApk,
  buildResourcesArsc,
} from '../lib/fixtures-malformed.mjs';

function makeToken() {
  return crypto.randomBytes(4).toString('hex');
}

function makeOperands() {
  const b = crypto.randomBytes(2);
  return [17 + (b[0] % 60), 29 + (b[1] % 60)];
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

async function assertRejectsCleanly(fn, { expectedCode = null, codePattern = null, label = 'operation' } = {}) {
  let result;
  let caught = null;
  try {
    result = await fn();
  } catch (err) {
    caught = err;
  }

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
    return caught;
  }

  assert.fail(
    `[${label}] Expected operation to reject cleanly${expectedCode ? ` with ${expectedCode}` : ''}, ` +
    `but it resolved with: ${JSON.stringify(result)}`
  );
}

function extractStream(raw) {
  if (typeof raw === 'string') return raw;
  if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) return Buffer.from(raw).toString('utf8');
  if (Array.isArray(raw)) {
    return raw
      .map((c) => (Buffer.isBuffer(c) || c instanceof Uint8Array ? Buffer.from(c).toString('utf8') : String(c ?? '')))
      .join('');
  }
  return String(raw ?? '');
}

function extractStdout(pcb, summary) {
  return extractStream(summary?.stdout ?? pcb?.streams?.stdout ?? pcb?.stdout ?? '');
}

function extractStderr(pcb, summary) {
  return extractStream(summary?.stderr ?? pcb?.streams?.stderr ?? pcb?.stderr ?? '');
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
    stderr: extractStderr(pcb, summary),
    exitCode: extractExitCode(pcb, summary),
    instructionsExecuted: extractInstructions(pcb, summary),
  };
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

function buildArscLabelApk({ packageName, labelResId, mode, strings }) {
  const axml = buildAxmlManifest({ packageName, labelResId });
  const dex = buildMinimalActivityDex(packageName);
  const arsc = buildResourcesArsc({
    mode,
    packageId: 0x7f,
    packageName,
    strings,
  });
  return buildZip([
    { name: 'AndroidManifest.xml', data: axml, method: 8 },
    { name: 'classes.dex', data: dex, method: 8 },
    { name: 'resources.arsc', data: arsc, method: 0, alignDataTo: 4 },
  ]);
}

function extractLabelCandidates(insp) {
  return [insp?.label, insp?.manifest?.label, insp?.name]
    .filter((v) => v !== undefined && v !== null)
    .map((v) => String(v));
}

describe('Tier 2 — FA-10: Android Runtime (APK, AXML/ARSC, DEX & Dalvik VM Boundary & Negative)', () => {
  it('T2-FA10-01 [F-036, Edge #3]: APK Signing Block v2 (0x7109871a) & v3 (0xf05368c0) before Central Directory inspect & execute cleanly', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const vfs = osHandle.require('vfs');
      const tok = makeToken();

      const cases = [
        { label: 'v2', schemeId: 0x7109871a },
        { label: 'v3', schemeId: 0xf05368c0 },
      ];

      for (const tc of cases) {
        const [a, b] = makeOperands();
        const expected = String((a + b) | 0);
        const pkgName = `com.omnios.sig${tc.label}.${tok}`;
        const outSdPath = `/sdcard/Documents/sig-${tc.label}-${tok}.txt`;
        const outCanonical = `/home/user/Documents/sig-${tc.label}-${tok}.txt`;

        const baseApk = buildCustomApk({
          packageName: pkgName,
          appLabel: `Sig${tc.label}-${tok}`,
          computeA: a,
          computeB: b,
          computeOp: 'add',
          outputFile: outSdPath,
          permissions: ['android.permission.WRITE_EXTERNAL_STORAGE'],
          includeV2SigBlock: false,
        });
        const signedApk = buildApkWithV2SigningBlock(baseApk, { schemeId: tc.schemeId });

        assert.ok(
          Buffer.from(signedApk).includes(Buffer.from('APK Sig Block 42', 'ascii')),
          `Expected APK Sig Block 42 magic in ${tc.label} fixture`
        );

        const insp = await pkgManager.inspect(signedApk);
        assert.equal(insp.format, 'android-apk', `Expected android-apk for ${tc.label}`);
        assert.equal(insp.appId ?? insp.packageName, pkgName);
        assert.equal(insp.sha256, sha256Hex(signedApk));

        await pkgManager.install(signedApk, { grantAll: true });
        const launched = await pkgManager.launch(pkgName);
        assert.ok(launched.pid > 1, `Expected valid PID > 1 for ${tc.label} signed APK`);

        const run = await runAndroidTicks(osHandle, launched.pid, 800);
        assert.ok(run.instructionsExecuted > 0, `Expected Dalvik instructions executed for ${tc.label}`);

        const written = await vfs.readFile(outCanonical, { encoding: 'utf8', uid: 0, gid: 0 });
        assert.equal(
          String(written).trim(),
          expected,
          `Expected ${tc.label} APK to write ${a}+${b}=${expected} to ${outCanonical}, got ${JSON.stringify(written)}`
        );
      }

      assertKernelHealthy(osHandle, 'T2-FA10-01');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA10-02 [F-037, Edge #5]: Malformed binary AXML all 4 variants (zero-size, subchunk-zero-size, size-lt-header, oob-size -> E_MALFORMED_AXML, no loop)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();

      const variants = ['zero-size', 'subchunk-zero-size', 'size-lt-header', 'oob-size'];
      for (const variant of variants) {
        const badApk = buildMalformedAxmlApk(variant);

        const tInspect = Date.now();
        await assertRejectsCleanly(
          () => pkgManager.inspect(badApk),
          { expectedCode: 'E_MALFORMED_AXML', label: `inspect(malformed-axml:${variant})` }
        );
        assert.ok(
          Date.now() - tInspect < 3000,
          `inspect(malformed-axml:${variant}) exceeded 3000ms (possible infinite chunk loop)`
        );

        const tInstall = Date.now();
        await assertRejectsCleanly(
          () => pkgManager.install(badApk),
          { expectedCode: 'E_MALFORMED_AXML', label: `install(malformed-axml:${variant})` }
        );
        assert.ok(
          Date.now() - tInstall < 3000,
          `install(malformed-axml:${variant}) exceeded 3000ms (possible infinite chunk loop)`
        );
      }

      // Subsequent valid APK still inspects cleanly
      const validPkg = `com.omnios.axmlok.${tok}`;
      const validApk = buildCustomApk({ packageName: validPkg, appLabel: `AxmlOk-${tok}` });
      const insp = await pkgManager.inspect(validApk);
      assert.equal(insp.format, 'android-apk');
      assert.equal(insp.appId ?? insp.packageName, validPkg);

      assertKernelHealthy(osHandle, 'T2-FA10-02');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA10-03 [F-037, Edge #6]: resources.arsc FLAG_OFFSET16 (0x02) & FLAG_SPARSE (0x01) resolve sparse ID 0x7f010005 & safely handle NO_ENTRY (0xFFFF) gaps', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();

      const zeroA = `ZeroA_${tok}`;
      const hitOff16 = `Off16Hit_${tok}`;
      const zeroB = `ZeroB_${tok}`;
      const hitSparse = `SparseHit_${tok}`;

      // APK A: FLAG_OFFSET16 with NO_ENTRY gaps at id 1..4 and target label at id 5 (0x7f010005)
      const apkOffset16 = buildArscLabelApk({
        packageName: `com.omnios.arsc.off16.${tok}`,
        labelResId: 0x7f010005,
        mode: 'offset16',
        strings: [
          { id: 0, name: 'app_name', value: zeroA },
          { id: 5, name: 'sparse_label', value: hitOff16 },
        ],
      });
      const inspOff16 = await pkgManager.inspect(apkOffset16);
      const off16Candidates = extractLabelCandidates(inspOff16);
      assert.ok(
        off16Candidates.includes(hitOff16),
        `Expected FLAG_OFFSET16 labelResId 0x7f010005 to resolve to "${hitOff16}" in [label, manifest.label, name], got ${JSON.stringify(off16Candidates)} (full=${JSON.stringify(inspOff16)})`
      );
      assert.ok(!off16Candidates.includes(zeroA), `FLAG_OFFSET16 must not resolve id 0 ("${zeroA}")`);

      // APK B: FLAG_SPARSE with sparse (idx, off16) pairs (0, 0) & (5, 4) and target at 0x7f010005
      const apkSparse = buildArscLabelApk({
        packageName: `com.omnios.arsc.sparse.${tok}`,
        labelResId: 0x7f010005,
        mode: 'sparse',
        strings: [
          { id: 0, name: 'app_name', value: zeroB },
          { id: 5, name: 'sparse_label', value: hitSparse },
        ],
      });
      const inspSparse = await pkgManager.inspect(apkSparse);
      const sparseCandidates = extractLabelCandidates(inspSparse);
      assert.ok(
        sparseCandidates.includes(hitSparse),
        `Expected FLAG_SPARSE labelResId 0x7f010005 to resolve to "${hitSparse}" in [label, manifest.label, name], got ${JSON.stringify(sparseCandidates)} (full=${JSON.stringify(inspSparse)})`
      );
      assert.ok(!sparseCandidates.includes(zeroB), `FLAG_SPARSE must not resolve id 0 ("${zeroB}")`);

      // APK C1 & C2: labelResId 0x7f010002 points at an explicit NO_ENTRY gap (0xFFFF / absent)
      for (const mode of ['offset16', 'sparse']) {
        const apkGap = buildArscLabelApk({
          packageName: `com.omnios.arsc.gap.${mode}.${tok}`,
          labelResId: 0x7f010002,
          mode,
          strings: [
            { id: 0, name: 'app_name', value: zeroA },
            { id: 5, name: 'sparse_label', value: hitOff16 },
          ],
        });
        const inspGap = await pkgManager.inspect(apkGap);
        const gapCandidates = extractLabelCandidates(inspGap);
        assert.ok(
          !gapCandidates.includes(zeroA),
          `NO_ENTRY gap (${mode}) must not falsely resolve id 0 ("${zeroA}"), got ${JSON.stringify(gapCandidates)}`
        );
        assert.ok(
          !gapCandidates.includes(hitOff16),
          `NO_ENTRY gap (${mode}) must not falsely resolve id 5 ("${hitOff16}"), got ${JSON.stringify(gapCandidates)}`
        );
      }

      assertKernelHealthy(osHandle, 'T2-FA10-03');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA10-04 [F-038, Edge #7]: Malformed DEX all 6 isolated variants (bad-adler32, bad-sha1, bad-header-size, bad-endian, type-ids-overflow, truncated)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');

      const variants = [
        'bad-adler32',
        'bad-sha1',
        'bad-header-size',
        'bad-endian',
        'type-ids-overflow',
        'truncated',
      ];
      const dexErrPattern = /DEX|ADLER|SHA1|CHECKSUM|HEADER|ENDIAN|TYPE_IDS|TRUNCATED|MALFORMED|INVALID|CORRUPT/i;

      for (const variant of variants) {
        const badApk = buildMalformedDexApk(variant);
        const badPkgId = `com.omnios.baddex.${variant.replace(/-/g, '')}`;

        // install() MUST reject every isolated DEX corruption variant cleanly
        await assertRejectsCleanly(
          () => pkgManager.install(badApk),
          { codePattern: dexErrPattern, label: `install(malformed-dex:${variant})` }
        );

        // inspect() should either reject with structured DEX error (preferred) or not install anything
        let inspectErr = null;
        try {
          await pkgManager.inspect(badApk);
        } catch (err) {
          inspectErr = err;
        }
        if (inspectErr) {
          const code = extractErrorCode(inspectErr);
          assert.ok(
            dexErrPattern.test(`${code ?? ''} ${inspectErr.message ?? ''}`),
            `[inspect(malformed-dex:${variant})] Unexpected error: code=${code} msg=${inspectErr.message}`
          );
        }

        const installedList = extractArrayStrict(await pkgManager.list());
        assert.ok(Array.isArray(installedList), 'Expected pkgManager.list() to return an Array');
        assert.ok(
          !installedList.some((p) => (p?.appId ?? p?.id) === badPkgId),
          `Malformed DEX APK (${variant}) must NOT be installed`
        );
      }

      assertKernelHealthy(osHandle, 'T2-FA10-04');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA10-05 [F-038, Edge #8]: DEX MUTF-8 (0xC0 0x80 embedded NUL + surrogate pair 😀 positive) & 6-byte overlong LEB128 rejection (negative)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const vfs = osHandle.require('vfs');
      const tok = makeToken();

      // Part A1: Wrap buildDexMutf8Valid() raw DEX in an APK and verify clean inspection
      const mutf8InspectPkg = `com.omnios.mutf8insp.${tok}`;
      const mutf8InspectApk = buildZip([
        { name: 'AndroidManifest.xml', data: buildAxmlManifest({ packageName: mutf8InspectPkg, label: `Mutf8_${tok}` }), method: 8 },
        { name: 'classes.dex', data: buildDexMutf8Valid(), method: 8 },
      ]);
      const insp = await pkgManager.inspect(mutf8InspectApk);
      assert.equal(insp.format, 'android-apk');
      assert.equal(insp.appId ?? insp.packageName, mutf8InspectPkg);

      // Part A2: Execute real APK containing MUTF-8 embedded NUL (0xC0 0x80 -> \u0000) + CESU-8 emoji surrogate
      const mutf8RunPkg = `com.omnios.mutf8run.${tok}`;
      const payloadStr = `A\u0000B_${tok}_😀`;
      const outSdPath = `/sdcard/Documents/mutf8-${tok}.txt`;
      const outCanonical = `/home/user/Documents/mutf8-${tok}.txt`;

      const mutf8RunApk = buildCustomApk({
        packageName: mutf8RunPkg,
        appLabel: `Mutf8Run-${tok}`,
        outputFile: outSdPath,
        outputContent: payloadStr,
        permissions: ['android.permission.WRITE_EXTERNAL_STORAGE'],
        extraStrings: ['Omni\u0000MUTF8\uD83D\uDE00'],
      });
      await pkgManager.install(mutf8RunApk, { grantAll: true });
      const launched = await pkgManager.launch(mutf8RunPkg);
      assert.ok(launched.pid > 1, 'Expected valid PID > 1 for MUTF-8 runnable APK');
      const run = await runAndroidTicks(osHandle, launched.pid, 800);
      assert.ok(run.instructionsExecuted > 0, 'Expected Dalvik instructions executed for MUTF-8 APK');

      const rawOut = await vfs.readFile(outCanonical, { uid: 0, gid: 0 });
      const rawBuf = Buffer.isBuffer(rawOut)
        ? rawOut
        : (rawOut instanceof Uint8Array ? Buffer.from(rawOut) : Buffer.from(String(rawOut), 'utf8'));
      const expectedUtf8 = Buffer.from(payloadStr, 'utf8');
      assert.ok(
        rawBuf.includes(expectedUtf8),
        `Expected ${outCanonical} bytes (${rawBuf.toString('hex')}) to contain UTF-8 bytes of "A\\0B_${tok}_😀" (${expectedUtf8.toString('hex')})`
      );

      // Part B: 6-byte overlong LEB128 (>5B max) wrapped in APK MUST be rejected cleanly
      const overlongPkg = `com.omnios.overlongleb.${tok}`;
      const overlongApk = buildZip([
        { name: 'AndroidManifest.xml', data: buildAxmlManifest({ packageName: overlongPkg, label: 'OverlongLeb' }), method: 8 },
        { name: 'classes.dex', data: buildDexOverlongLeb128(), method: 8 },
      ]);
      const t0 = Date.now();
      await assertRejectsCleanly(
        () => pkgManager.install(overlongApk),
        { label: 'install(overlong-6B-leb128)' }
      );
      assert.ok(Date.now() - t0 < 5000, 'Overlong 6-byte LEB128 rejection must terminate promptly');

      const installedList = extractArrayStrict(await pkgManager.list());
      assert.ok(Array.isArray(installedList));
      assert.ok(
        !installedList.some((p) => (p?.appId ?? p?.id) === overlongPkg),
        'Overlong LEB128 APK must NOT be installed'
      );

      assertKernelHealthy(osHandle, 'T2-FA10-05');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA10-06 [F-038, F-039, Edge #9]: Dalvik odd-insns_size (15 code units) try_item 2-byte padding skips pad & catches ArithmeticException', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const kernel = osHandle.require('kernel');
      const tok = makeToken();
      const catchToken = `ODD_PAD_CATCH_${tok}`;

      const apk = buildDexOddInsnsTryCatchApk({ token: catchToken });
      const insp = await pkgManager.inspect(apk);
      assert.equal(insp.format, 'android-apk');

      const appId = insp.appId ?? insp.packageName ?? 'com.omnios.oddpad';
      await pkgManager.install(apk, { grantAll: true });
      const launched = await pkgManager.launch(appId);
      assert.ok(launched.pid > 1, 'Expected valid PID > 1 for odd-insns try/catch APK');

      const run = await runAndroidTicks(osHandle, launched.pid, 500);
      assert.ok(run.instructionsExecuted > 0, 'Expected Dalvik instructions executed');

      const faultSig = run.summary?.fault?.signal ?? run.pcb?.fault?.signal ?? run.pcb?.signal ?? null;
      assert.ok(
        run.pcb?.state !== 'FAULT' && faultSig !== 'SIGSEGV' && faultSig !== 'SIGILL',
        `Expected odd-insns try_item catch handler to absorb ArithmeticException cleanly, got state=${run.pcb?.state} signal=${faultSig}`
      );

      const dmesgBlob = JSON.stringify(kernel.dmesg({ limit: 200 }));
      const observed = `${run.stdout}\n${run.stderr}\n${dmesgBlob}`;
      assert.ok(
        observed.includes(catchToken),
        `Expected catch handler Log.i("${catchToken}") in stdout/dmesg (proving 2-byte odd-insns padding skipped!), got stdout=${JSON.stringify(run.stdout)}`
      );

      assertKernelHealthy(osHandle, 'T2-FA10-06');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA10-07 [F-039, Edge #10]: Dalvik div-int by 0 faults with ArithmeticException & INT32_MIN / -1 wraps to -2147483648 without faulting', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const pkgManager = osHandle.require('pkgManager');
      const kernel = osHandle.require('kernel');

      // Part A: Uncaught div-int by 0 -> offending PID terminates with ArithmeticException / fault / non-zero exit
      const divZeroApk = buildDexDivByZeroApk();
      const divInsp = await pkgManager.inspect(divZeroApk);
      const divAppId = divInsp.appId ?? divInsp.packageName ?? 'com.omnios.divzero';
      await pkgManager.install(divZeroApk, { grantAll: true });
      const divLaunch = await pkgManager.launch(divAppId);
      const divRun = await runAndroidTicks(osHandle, divLaunch.pid, 500);

      const divState = divRun.pcb?.state ?? divRun.summary?.state;
      assert.ok(
        divState === 'TERMINATED' || divState === 'ZOMBIE' || divState === 'FAULT',
        `Expected div-by-zero PID to terminate, got state=${divState}`
      );
      const divFault = divRun.summary?.fault ?? divRun.pcb?.fault ?? null;
      const divDmesg = JSON.stringify(kernel.dmesg({ limit: 100 }));
      const divDiag = `${divRun.stdout}\n${divRun.stderr}\n${JSON.stringify(divFault)}\n${divDmesg}`;
      assert.ok(
        (divRun.exitCode !== null && divRun.exitCode !== 0) ||
        Boolean(divFault) ||
        /ArithmeticException|div.*zero|SIGFPE|FAULT/i.test(divDiag),
        `Expected ArithmeticException / non-zero fault for div-by-zero, got exitCode=${divRun.exitCode} fault=${JSON.stringify(divFault)}`
      );
      assertKernelHealthy(osHandle, 'T2-FA10-07-div0');

      // Part B: INT32_MIN / -1 MUST wrap to -2147483648 and log it without faulting
      const minDivApk = buildDexInt32MinDivNeg1Apk();
      const minInsp = await pkgManager.inspect(minDivApk);
      const minAppId = minInsp.appId ?? minInsp.packageName ?? 'com.omnios.int32mindiv';
      await pkgManager.install(minDivApk, { grantAll: true });
      const minLaunch = await pkgManager.launch(minAppId);
      const minRun = await runAndroidTicks(osHandle, minLaunch.pid, 500);

      assert.ok(minRun.instructionsExecuted > 0, 'Expected Dalvik instructions executed for INT32_MIN / -1');
      assert.ok(
        minRun.pcb?.state !== 'FAULT' && !minRun.summary?.fault && !minRun.pcb?.fault,
        `INT32_MIN / -1 must NOT fault, got state=${minRun.pcb?.state} fault=${JSON.stringify(minRun.summary?.fault ?? minRun.pcb?.fault)}`
      );
      const minObserved = `${minRun.stdout}\n${minRun.stderr}\n${JSON.stringify(kernel.dmesg({ limit: 200 }))}`;
      assert.ok(
        minObserved.includes('-2147483648'),
        `Expected INT32_MIN / -1 result "-2147483648" in stdout/dmesg, got stdout=${JSON.stringify(minRun.stdout)}`
      );

      assertKernelHealthy(osHandle, 'T2-FA10-07');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA10-08 [F-011, F-039, Edge #11]: Dalvik infinite loop (goto 0 -> E_CPU_QUOTA/SIGXCPU) & deep recursion (StackOverflowError) kill ONLY offending PID while sibling survives', async () => {
    let osHandle = null;
    let siblingPid = null;
    try {
      osHandle = await loadPublicOmniOS();
      const scheduler = osHandle.require('scheduler');
      const pm = osHandle.require('processManager');
      const pkgManager = osHandle.require('pkgManager');
      const kernel = osHandle.require('kernel');
      const tok = makeToken();

      // Drive scheduler deterministically so sibling survival is verified synchronously
      scheduler.stop?.();

      const siblingCtx = {
        steps: 0,
        step(budget) {
          this.steps += 1;
          return { status: 'YIELD', instructionsExecuted: Math.min(1, budget || 1) };
        },
        deliverEvent() {},
        getDebugState() {
          return { arch: 'wasm', pc: this.steps, sp: 0, registers: {}, instructionsExecuted: this.steps, lastSyscall: null, stackTop: 0 };
        },
        dispose() {},
      };
      const siblingPcb = pm.spawn({
        name: `healthy-sibling-${tok}`,
        appId: `com.omnios.sibling.${tok}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        cwd: '/home/user',
        env: {},
        args: [],
        priority: 10,
        executionContext: siblingCtx,
      });
      siblingPid = siblingPcb.pid;
      assert.ok(siblingPid > 1, 'Expected valid sibling PID > 1');

      await scheduler.step(2);
      assert.ok(siblingCtx.steps > 0, 'Expected healthy sibling to execute before adversarial workloads');

      // Sub-case A: Infinite loop (goto +0) -> hits CPU instruction quota & terminates offending PID only
      const loopApk = buildDexInfiniteLoopApk();
      const loopInsp = await pkgManager.inspect(loopApk);
      const loopAppId = loopInsp.appId ?? loopInsp.packageName ?? 'com.omnios.infloop';
      await pkgManager.install(loopApk, { grantAll: true });
      const loopLaunch = await pkgManager.launch(loopAppId);
      const loopRun = await runAndroidTicks(osHandle, loopLaunch.pid, 2500);

      const loopState = loopRun.pcb?.state ?? loopRun.summary?.state;
      assert.ok(
        loopState === 'TERMINATED' || loopState === 'ZOMBIE' || loopState === 'FAULT',
        `Expected infinite-loop Dalvik PID to be terminated by CPU quota, got state=${loopState}`
      );
      const loopFault = loopRun.summary?.fault ?? loopRun.pcb?.fault ?? null;
      const loopDiag = `${JSON.stringify(loopFault)} ${loopRun.pcb?.signal ?? ''} ${loopRun.stderr} ${JSON.stringify(kernel.dmesg({ limit: 80 }))}`;
      assert.ok(
        (loopRun.exitCode !== null && loopRun.exitCode !== 0) ||
        Boolean(loopFault) ||
        /E_CPU_QUOTA|SIGXCPU|quota|limit|timeout/i.test(loopDiag),
        `Expected CPU quota / SIGXCPU termination for infinite loop, got exitCode=${loopRun.exitCode} diag=${loopDiag.slice(0, 300)}`
      );

      // Verify healthy sibling survived and continues making progress
      const stepsBeforeA = siblingCtx.steps;
      await scheduler.step(5);
      const sibAfterA = pm.get(siblingPid);
      assert.ok(
        sibAfterA && sibAfterA.state !== 'TERMINATED' && sibAfterA.state !== 'ZOMBIE',
        `Healthy sibling died after infinite-loop fault! state=${sibAfterA?.state}`
      );
      assert.ok(siblingCtx.steps > stepsBeforeA, 'Expected healthy sibling to continue stepping after infinite-loop kill');

      // Sub-case B: Deep recursive onCreate() -> terminates cleanly with StackOverflowError / quota without crashing host Node
      const recApk = buildDexDeepRecursionApk();
      const recInsp = await pkgManager.inspect(recApk);
      const recAppId = recInsp.appId ?? recInsp.packageName ?? 'com.omnios.deeprec';
      await pkgManager.install(recApk, { grantAll: true });
      const recLaunch = await pkgManager.launch(recAppId);
      const recRun = await runAndroidTicks(osHandle, recLaunch.pid, 2500);

      const recState = recRun.pcb?.state ?? recRun.summary?.state;
      assert.ok(
        recState === 'TERMINATED' || recState === 'ZOMBIE' || recState === 'FAULT',
        `Expected deep-recursion Dalvik PID to terminate cleanly, got state=${recState}`
      );
      const recFault = recRun.summary?.fault ?? recRun.pcb?.fault ?? null;
      const recDiag = `${JSON.stringify(recFault)} ${recRun.pcb?.signal ?? ''} ${recRun.stderr} ${JSON.stringify(kernel.dmesg({ limit: 80 }))}`;
      assert.ok(
        (recRun.exitCode !== null && recRun.exitCode !== 0) ||
        Boolean(recFault) ||
        /StackOverflow|E_STACK|E_CPU_QUOTA|SIGXCPU|SIGSEGV|recursion/i.test(recDiag),
        `Expected StackOverflowError / quota fault for deep recursion, got exitCode=${recRun.exitCode} diag=${recDiag.slice(0, 300)}`
      );

      // Verify healthy sibling STILL alive and advancing
      const stepsBeforeB = siblingCtx.steps;
      await scheduler.step(5);
      const sibAfterB = pm.get(siblingPid);
      assert.ok(
        sibAfterB && sibAfterB.state !== 'TERMINATED' && sibAfterB.state !== 'ZOMBIE',
        `Healthy sibling died after deep-recursion fault! state=${sibAfterB?.state}`
      );
      assert.ok(siblingCtx.steps > stepsBeforeB, 'Expected healthy sibling to continue stepping after deep-recursion kill');

      assertKernelHealthy(osHandle, 'T2-FA10-08');
    } finally {
      if (osHandle && siblingPid) {
        try { osHandle.processManager?.kill?.(siblingPid, 'SIGKILL'); } catch { /* ignore */ }
      }
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });
});
