/**
 * OmniOS Tier 2 E2E Suite — FA-11: Windows Runtime (PE32/PE32+, x86-64 CPU, Win32 & Batch)
 * Boundary, Corner & Negative Cases (Edge Cases #12–#18).
 * Covers PROJECT.md Features: F-041, F-043, F-044, F-045.
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
import { buildCustomPe64Exe } from '../lib/fixtures-android-win.mjs';
import {
  buildBatVsCmdErrorlevelScripts,
  buildMalformedPe,
  buildPeRipRelativeTestExe,
  buildPeSectionSizingEdgeExe,
  buildPeWithCertificateTableExe,
  buildPeX64RegisterWidthTestExe,
  buildPeZeroOftExe,
} from '../lib/fixtures-malformed.mjs';

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

async function assertRejectsCleanly(fn, { codePattern = null, label = 'operation' } = {}) {
  let result;
  let caught = null;
  try {
    result = await fn();
  } catch (err) {
    caught = err;
  }

  if (caught) {
    assert.ok(
      !(caught instanceof RangeError),
      `[${label}] Must throw a structured OS/PE error, NOT an unhandled RangeError: ${caught.message}`
    );
    const code = extractErrorCode(caught);
    const msg = String(caught.message ?? caught);
    if (codePattern) {
      assert.ok(
        codePattern.test(`${code ?? ''} ${msg}`),
        `[${label}] Expected error matching ${codePattern}, got code=${JSON.stringify(code)} message=${JSON.stringify(msg)}`
      );
    }
    return caught;
  }

  assert.fail(
    `[${label}] Expected operation to reject cleanly, but it resolved with: ${JSON.stringify(result)}`
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

describe('Tier 2 — FA-11: Windows Runtime (PE32/PE32+, x86-64, Win32 & Batch Boundary & Negative)', () => {
  it('T2-FA11-01 [F-041, Edge #12]: Malformed PE all 5 variants (strict reject on lfanew/sections/magic + contract-fair clamp-or-reject on bad-rva-count)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const formatDetector = osHandle.require('formatDetector');
      const tok = makeToken();

      // 4 strict-rejection structural PE violations
      const strictVariants = ['lfanew-lt-64', 'lfanew-past-eof', 'too-many-sections', 'bad-pe-magic'];
      const peErrPattern = /E_INVALID_PE|PE|INVALID|MALFORMED|LFANEW|SECTION|MAGIC|UNKNOWN|UNSUPPORTED|CORRUPT/i;

      for (const variant of strictVariants) {
        const badPe = buildMalformedPe(variant);
        const vfsPath = `/tmp/badpe-${variant}-${tok}.exe`;
        await vfs.writeFile(vfsPath, badPe);

        // formatDetector must NEVER throw an unhandled RangeError
        const det = formatDetector.detect(badPe, `bad-${variant}.exe`);
        assert.ok(det && typeof det.format === 'string', `formatDetector must return descriptor for ${variant}`);

        await assertRejectsCleanly(
          () => pkgManager.inspect(vfsPath),
          { codePattern: peErrPattern, label: `inspect(malformed-pe:${variant})` }
        );
        await assertRejectsCleanly(
          () => pkgManager.install(vfsPath),
          { codePattern: peErrPattern, label: `install(malformed-pe:${variant})` }
        );
      }

      // 5th variant ('bad-rva-count', NumberOfRvaAndSizes = 99):
      // PROJECT.md explicitly permits clamping NumberOfRvaAndSizes <= 16 OR rejecting with E_INVALID_PE.
      const badRvaPe = buildMalformedPe('bad-rva-count');
      const rvaPath = `/tmp/badpe-rvacount-${tok}.exe`;
      await vfs.writeFile(rvaPath, badRvaPe);

      let rvaInsp = null;
      let rvaErr = null;
      try {
        rvaInsp = await pkgManager.inspect(rvaPath);
      } catch (err) {
        rvaErr = err;
      }

      if (rvaErr) {
        assert.ok(
          !(rvaErr instanceof RangeError),
          `bad-rva-count must not throw unhandled RangeError: ${rvaErr.message}`
        );
        const code = extractErrorCode(rvaErr);
        assert.ok(
          peErrPattern.test(`${code ?? ''} ${rvaErr.message ?? ''}`),
          `Expected structured PE error on bad-rva-count rejection, got code=${code} msg=${rvaErr.message}`
        );
      } else {
        assert.equal(rvaInsp?.platform, 'windows', 'Clamped bad-rva-count inspection must report platform=windows');
        const dirs =
          rvaInsp?.dataDirectories ??
          rvaInsp?.pe?.dataDirectories ??
          rvaInsp?.details?.dataDirectories ??
          null;
        if (Array.isArray(dirs)) {
          assert.ok(
            dirs.length <= 16,
            `Clamped NumberOfRvaAndSizes must yield <= 16 data directories, got ${dirs.length}`
          );
        }
      }

      // Prove Windows PE loader/runtime remains fully healthy afterwards
      const recoverMsg = `PE_RECOVER_${tok}\n`;
      const validExe = buildCustomPe64Exe({ message: recoverMsg, exitCode: 0 });
      const validPath = `/tmp/pe-recover-${tok}.exe`;
      await vfs.writeFile(validPath, validExe);
      const rec = await pkgManager.install(validPath, { grantAll: true });
      const appId = rec.appId ?? rec.id;
      const launched = await pkgManager.launch(appId);
      const run = await runToCompletion(osHandle, launched.pid);
      assert.ok(run.stdout.includes(`PE_RECOVER_${tok}`), `Expected PE_RECOVER_${tok}, got: ${run.stdout}`);
      assert.equal(run.exitCode, 0);

      assertKernelHealthy(osHandle, 'T2-FA11-01');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA11-02 [F-041, Edge #13]: PE .bss zero-fill (VirtualSize=0x2000 > Raw=0) & padded .text (Raw=0x200 > VirtualSize=0x100)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();

      const exeBuf = buildPeSectionSizingEdgeExe();
      const vfsPath = `/tmp/pe13-bss-${tok}.exe`;
      await vfs.writeFile(vfsPath, exeBuf);

      const insp = await pkgManager.inspect(vfsPath);
      const inspJson = JSON.stringify(insp);
      assert.equal(insp.platform, 'windows');
      assert.ok(
        inspJson.includes('.bss') && inspJson.includes('.text'),
        `Expected PE inspection to list .bss and .text sections, got: ${inspJson}`
      );

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId ?? insp.appId;
      const launched = await pkgManager.launch(appId);
      assert.ok(launched.pid > 1);

      const run = await runToCompletion(osHandle, launched.pid);
      assert.equal(
        run.exitCode,
        0,
        `PE section sizing test failed with exitCode=${run.exitCode} (1 = .bss+0x1500 was NOT zero-filled; 2 = .bss write/readback failed)`
      );
      assert.ok(run.instructionsExecuted > 0, 'Expected x86-64 instructionsExecuted > 0');
      assert.ok(!run.summary?.fault && !run.pcb?.fault, 'Expected zero CPU/VMM faults on .bss/.text edge binary');

      assertKernelHealthy(osHandle, 'T2-FA11-02');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA11-03 [F-041, Edge #14]: PE OriginalFirstThunk == 0 (null ILT) falls back to FirstThunk IAT resolution', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();
      const expectedCode = 17 + (crypto.randomBytes(1)[0] % 40);
      const msg = `OFT_ZERO_${tok}\n`;

      const exeBuf = buildPeZeroOftExe({ message: msg, exitCode: expectedCode });
      const vfsPath = `/tmp/pe14-oft0-${tok}.exe`;
      await vfs.writeFile(vfsPath, exeBuf);

      const insp = await pkgManager.inspect(vfsPath);
      assert.equal(insp.platform, 'windows');
      assert.ok(
        /kernel32\.dll/i.test(JSON.stringify(insp)),
        `Expected KERNEL32.dll import discovered via FirstThunk fallback when OriginalFirstThunk == 0, got: ${JSON.stringify(insp)}`
      );

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId ?? insp.appId;
      const launched = await pkgManager.launch(appId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.ok(
        run.stdout.includes(`OFT_ZERO_${tok}`),
        `Expected stdout to include OFT_ZERO_${tok}, got: ${JSON.stringify(run.stdout)}`
      );
      assert.equal(run.exitCode, expectedCode, `Expected exitCode ${expectedCode}, got ${run.exitCode}`);
      assert.ok(run.instructionsExecuted > 0);

      assertKernelHealthy(osHandle, 'T2-FA11-03');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA11-04 [F-041, Edge #15]: PE CERTIFICATE_TABLE (DataDir[4]) treated as raw file offset (not section RVA)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();
      const expectedCode = 21 + (crypto.randomBytes(1)[0] % 40);
      const msg = `CERT_RAW_${tok}\n`;

      const exeBuf = buildPeWithCertificateTableExe({ message: msg, exitCode: expectedCode });
      const vfsPath = `/tmp/pe15-cert-${tok}.exe`;
      await vfs.writeFile(vfsPath, exeBuf);

      const insp = await pkgManager.inspect(vfsPath);
      assert.equal(insp.platform, 'windows');

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId ?? insp.appId;
      const launched = await pkgManager.launch(appId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.ok(
        run.stdout.includes(`CERT_RAW_${tok}`),
        `Expected stdout to include CERT_RAW_${tok}, got: ${JSON.stringify(run.stdout)}`
      );
      assert.equal(run.exitCode, expectedCode, `Expected exitCode ${expectedCode}, got ${run.exitCode}`);
      assert.ok(run.instructionsExecuted > 0);

      assertKernelHealthy(osHandle, 'T2-FA11-04');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA11-05 [F-043, Edge #16]: x86-64 32-bit zero-extension (mov eax) vs 16-bit (mov ax) & 8-bit (mov al) upper-bit preservation', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();

      const exeBuf = buildPeX64RegisterWidthTestExe();
      const vfsPath = `/tmp/pe16-regw-${tok}.exe`;
      await vfs.writeFile(vfsPath, exeBuf);

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId ?? rec.id;
      const launched = await pkgManager.launch(appId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.equal(
        run.exitCode,
        0,
        `x86-64 register-width semantics failed with exitCode=${run.exitCode} ` +
        `(1 = 8-bit mov al clobbered upper 56b; 2 = 16-bit mov ax clobbered upper 48b; 3 = 32-bit mov eax failed to zero upper 32b)`
      );
      assert.ok(run.instructionsExecuted > 0, 'Expected x86-64 instructionsExecuted > 0');
      assert.ok(!run.summary?.fault && !run.pcb?.fault);

      assertKernelHealthy(osHandle, 'T2-FA11-05');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA11-06 [F-043, Edge #17]: x86-64 RIP-relative addressing uses exact next-RIP (instRva + insnLen + disp32)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();
      const expectedCode = 13 + (crypto.randomBytes(1)[0] % 40);
      const line = `RIP_NEXT_${tok}_END`;

      const exeBuf = buildPeRipRelativeTestExe({ message: `${line}\n`, exitCode: expectedCode });
      const vfsPath = `/tmp/pe17-rip-${tok}.exe`;
      await vfs.writeFile(vfsPath, exeBuf);

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId ?? rec.id;
      const launched = await pkgManager.launch(appId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.equal(
        run.stdout.trim(),
        line,
        `Expected exact RIP-relative message "${line}" (no off-by-7 displacement error), got ${JSON.stringify(run.stdout)}`
      );
      assert.equal(run.exitCode, expectedCode, `Expected exitCode ${expectedCode}, got ${run.exitCode}`);
      assert.ok(run.instructionsExecuted > 0);

      assertKernelHealthy(osHandle, 'T2-FA11-06');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA11-07 [F-045, Edge #18]: .bat preserves ERRORLEVEL on successful SET whereas byte-identical .cmd resets ERRORLEVEL to 0', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const tok = makeToken();
      const failCode = 5 + (crypto.randomBytes(1)[0] % 15);

      const {
        script,
        expectedBatExitCode,
        expectedCmdExitCode,
      } = buildBatVsCmdErrorlevelScripts({ failCode });

      // Write byte-for-byte identical script bytes to .bat and .cmd paths
      const scriptBytes = Buffer.from(script, 'utf8');
      const batPath = `/tmp/el-${tok}.bat`;
      const cmdPath = `/tmp/el-${tok}.cmd`;
      await vfs.writeFile(batPath, scriptBytes);
      await vfs.writeFile(cmdPath, scriptBytes);

      const batRec = await pkgManager.install(batPath, { grantAll: true });
      const batAppId = batRec.appId ?? batRec.id;
      const batLaunch = await pkgManager.launch(batAppId);
      const batRun = await runToCompletion(osHandle, batLaunch.pid);

      const cmdRec = await pkgManager.install(cmdPath, { grantAll: true });
      const cmdAppId = cmdRec.appId ?? cmdRec.id;
      const cmdLaunch = await pkgManager.launch(cmdAppId);
      const cmdRun = await runToCompletion(osHandle, cmdLaunch.pid);

      assert.ok(
        batRun.stdout.includes(`EL=${expectedBatExitCode}`),
        `Expected .bat stdout to preserve ERRORLEVEL (${expectedBatExitCode}), got: ${JSON.stringify(batRun.stdout)}`
      );
      assert.equal(
        batRun.exitCode,
        expectedBatExitCode,
        `Expected .bat exitCode === ${expectedBatExitCode}, got ${batRun.exitCode}`
      );

      assert.ok(
        cmdRun.stdout.includes('EL=0'),
        `Expected .cmd stdout to reset ERRORLEVEL to 0 after successful SET, got: ${JSON.stringify(cmdRun.stdout)}`
      );
      assert.equal(
        cmdRun.exitCode,
        expectedCmdExitCode,
        `Expected .cmd exitCode === ${expectedCmdExitCode}, got ${cmdRun.exitCode}`
      );

      assert.notEqual(
        batRun.exitCode,
        cmdRun.exitCode,
        `Byte-identical .bat (${batRun.exitCode}) and .cmd (${cmdRun.exitCode}) must diverge on SET ERRORLEVEL semantics`
      );

      assertKernelHealthy(osHandle, 'T2-FA11-07');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });
});
