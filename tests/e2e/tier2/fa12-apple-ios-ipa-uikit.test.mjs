/**
 * OmniOS Tier 2 E2E Suite — FA-12: Apple Core & iOS Runtime
 * Boundary, Corner & Negative Cases (Edge Cases #20–#27).
 * Covers PROJECT.md Features: F-012, F-013, F-048, F-049, F-050, F-051, F-052, F-053.
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
import { buildZip } from '../lib/binary-utils.mjs';
import {
  buildCustomIpa,
  buildCustomMacAppZip,
  buildMachO64,
} from '../lib/fixtures-apple-wasm.mjs';
import {
  buildArm64Reg31TestMachO,
  buildArm64VariadicStackArgsMachO,
  buildBplistEdgeValues,
  buildCyclicBplistIpa,
  buildDarwinErrnoCarryMachO,
  buildFairPlayEncryptedIpa,
  buildFairPlayEncryptedMachO,
  buildNonZeroEntryOffMachO,
  buildObjcNilMsgSendMachO,
  buildPageZeroDerefMachO,
} from '../lib/fixtures-malformed.mjs';

function makeNonce() {
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

function safeJsonStringify(val) {
  const seen = new WeakSet();
  return JSON.stringify(val, (_k, v) => {
    if (typeof v === 'bigint') return v.toString();
    if (v && typeof v === 'object') {
      if (seen.has(v)) return '[Circular]';
      seen.add(v);
    }
    return v;
  });
}

function findKeyRecursive(root, targetKey) {
  const seen = new WeakSet();
  const queue = [root];
  while (queue.length > 0) {
    const cur = queue.shift();
    if (!cur || typeof cur !== 'object') continue;
    if (seen.has(cur)) continue;
    seen.add(cur);
    if (Array.isArray(cur)) {
      for (const item of cur) queue.push(item);
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(cur, targetKey)) {
      return { found: true, value: cur[targetKey] };
    }
    for (const v of Object.values(cur)) {
      if (v && typeof v === 'object') queue.push(v);
    }
  }
  return { found: false, value: undefined };
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

/**
 * Walks inspect -> install -> launch for negative Apple binaries, allowing a compliant
 * Binary Inspector to either reject at inspect() OR report metadata at inspect() and
 * reject at install() / launch() BEFORE executing any instruction.
 */
async function expectPipelineReject(osHandle, bytes, vfsPath, { expectedCode = null, disallowRangeError = false, label = 'pipeline' } = {}) {
  const vfs = osHandle.require('vfs');
  const pkgManager = osHandle.require('pkgManager');
  await vfs.writeFile(vfsPath, bytes);

  let caught = null;
  let stage = 'inspect';
  let succeededInfo = null;
  try {
    const insp = await pkgManager.inspect(vfsPath);
    stage = 'install';
    const rec = await pkgManager.install(vfsPath, { grantAll: true });
    const appId = rec?.appId ?? insp?.appId ?? rec?.id ?? null;
    if (appId) {
      stage = 'launch';
      const launched = await pkgManager.launch(appId);
      succeededInfo = { appId, pid: launched?.pid ?? null };
    } else {
      succeededInfo = { appId: null, pid: null };
    }
  } catch (err) {
    caught = err;
  }

  if (caught?.code === 'ERR_ASSERTION') throw caught;

  if (!caught) {
    const pm = osHandle.require('processManager');
    const pcb = succeededInfo?.pid != null ? pm.get(succeededInfo.pid) : null;
    const insns = extractInstructions(pcb, null);
    assert.fail(
      `[${label}] Expected pipeline rejection${expectedCode ? ` (${expectedCode})` : ''}, ` +
      `but pipeline succeeded at stage=${stage} ` +
      `(appId=${JSON.stringify(succeededInfo?.appId)}, pid=${succeededInfo?.pid}, instructionsExecuted=${insns})`
    );
  }

  if (disallowRangeError) {
    assert.ok(
      !(caught instanceof RangeError),
      `[${label}] Must reject cleanly (not stack overflow / RangeError) at stage=${stage}: ${caught.message}`
    );
  }
  const code = extractErrorCode(caught);
  const msg = String(caught.message ?? caught);
  if (expectedCode) {
    assert.ok(
      code === expectedCode || msg.includes(expectedCode),
      `[${label}] Expected ${expectedCode} at stage=${stage}, got code=${JSON.stringify(code)} msg=${JSON.stringify(msg)}`
    );
  }
  return { stage, error: caught, code };
}

describe('Tier 2 — FA-12: Apple Core & iOS Runtime (Mach-O, Plist, ARM64, Darwin, ObjC & IPA Boundary & Negative)', () => {
  it('T2-FA12-01 [Edge #20 / F-048]: FairPlay DRM (LC_ENCRYPTION_INFO_64.cryptid == 1) rejected cleanly with E_ENCRYPTED_BINARY', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const nonce = makeNonce();

      // 1. FairPlay-encrypted .ipa
      const encIpa = buildFairPlayEncryptedIpa();
      await expectPipelineReject(osHandle, encIpa, `/tmp/fairplay-${nonce}.ipa`, {
        expectedCode: 'E_ENCRYPTED_BINARY',
        label: 'FairPlay .ipa',
      });

      // 2. Raw FairPlay-encrypted Mach-O binary
      const encMachO = buildFairPlayEncryptedMachO();
      await expectPipelineReject(osHandle, encMachO, `/tmp/fairplay-${nonce}.macho`, {
        expectedCode: 'E_ENCRYPTED_BINARY',
        label: 'FairPlay raw Mach-O',
      });

      assertKernelHealthy(osHandle, 'T2-FA12-01-after-fairplay');

      // 3. Recovery proof: unencrypted dynamic .ipa installs and runs cleanly right afterward
      const clearBundle = `com.omnios.ios.clear${nonce}`;
      const clearIpa = buildCustomIpa({
        bundleId: clearBundle,
        displayName: `Clear_${nonce}`,
        executableName: `Clear_${nonce}`,
        message: `CLEAR_${nonce}\n`,
        exitCode: 0,
      });
      const clearPath = `/tmp/clear-${nonce}.ipa`;
      await vfs.writeFile(clearPath, clearIpa);
      const rec = await pkgManager.install(clearPath, { grantAll: true });
      const launched = await pkgManager.launch(rec.appId ?? clearBundle);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.ok(run.stdout.includes(`CLEAR_${nonce}`), `Expected CLEAR_${nonce}, got: ${JSON.stringify(run.stdout)}`);
      assert.equal(run.exitCode, 0);
      assertKernelHealthy(osHandle, 'T2-FA12-01');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA12-02 [Edge #21 / F-048/F-012/F-013]: ARM64 __PAGEZERO dereference faults SIGSEGV without 4 GiB RAM alloc and isolates offending PID', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const pm = osHandle.require('processManager');
      const scheduler = osHandle.require('scheduler');
      const nonce = makeNonce();

      // Stop background scheduler briefly so we can inspect addressSpace BEFORE stepping
      scheduler.stop?.();

      const sibCode = 11 + (crypto.randomBytes(1)[0] % 40);
      const sibBundle = `com.omnios.ios.sib${nonce}`;
      const sibIpa = buildCustomIpa({
        bundleId: sibBundle,
        displayName: `Sib_${nonce}`,
        executableName: `Sib_${nonce}`,
        message: `SIBLING_${nonce}\n`,
        exitCode: sibCode,
      });

      const faultBundle = `com.omnios.ios.pz${nonce}`;
      const faultIpa = buildCustomIpa({
        bundleId: faultBundle,
        displayName: `Pz_${nonce}`,
        executableName: `Pz_${nonce}`,
        machoBytes: buildPageZeroDerefMachO({ addr: 0x100 }),
      });

      const sibPath = `/tmp/sib-${nonce}.ipa`;
      const faultPath = `/tmp/pz-${nonce}.ipa`;
      await vfs.writeFile(sibPath, sibIpa);
      await vfs.writeFile(faultPath, faultIpa);

      const rssBefore = process.memoryUsage().rss;

      const sibRec = await pkgManager.install(sibPath, { grantAll: true });
      const faultRec = await pkgManager.install(faultPath, { grantAll: true });

      const sibLaunch = await pkgManager.launch(sibRec.appId ?? sibBundle);
      const faultLaunch = await pkgManager.launch(faultRec.appId ?? faultBundle);

      // Inspect __PAGEZERO virtual reservation BEFORE stepping (before SIGSEGV tears down addressSpace)
      const faultPcbPre = pm.get(faultLaunch.pid);
      const vmmStats = faultPcbPre?.addressSpace?.getStats?.();
      if (vmmStats) {
        assert.ok(
          vmmStats.usedBytes < 64 * 1024 * 1024,
          `__PAGEZERO must be a virtual guard without allocating 4 GiB RAM; usedBytes=${vmmStats.usedBytes}`
        );
        assert.ok(
          vmmStats.mappedPages < 4096,
          `__PAGEZERO must not materialize 1,048,576 4KB pages; mappedPages=${vmmStats.mappedPages}`
        );
      }

      const faultRun = await runToCompletion(osHandle, faultLaunch.pid);
      const sibRun = await runToCompletion(osHandle, sibLaunch.pid);
      const rssDelta = process.memoryUsage().rss - rssBefore;

      assert.ok(
        rssDelta < 256 * 1024 * 1024,
        `Host RSS jumped by ${Math.round(rssDelta / (1024 * 1024))} MiB on __PAGEZERO Mach-O load`
      );

      // Faulting PID MUST NOT exit 0 and MUST signal SIGSEGV / memory fault
      assert.notEqual(faultRun.exitCode, 0, '__PAGEZERO dereference must fault and never exit 0');
      const sig = faultRun.pcb?.signal ?? faultRun.summary?.signal ?? faultRun.summary?.fault?.signal ?? faultRun.pcb?.fault?.signal;
      const faultBlob = safeJsonStringify({
        state: faultRun.pcb?.state,
        signal: sig,
        fault: faultRun.summary?.fault ?? faultRun.pcb?.fault,
        stderr: faultRun.pcb?.streams?.stderr ?? faultRun.summary?.stderr,
      });
      assert.ok(
        sig === 'SIGSEGV' || sig === 11 || /SIGSEGV|PAGEZERO|FAULT|MEMORY|SEGFAULT/i.test(faultBlob),
        `Expected SIGSEGV / __PAGEZERO fault for offending PID, got: ${faultBlob}`
      );

      // Healthy sibling PID MUST run cleanly to exact nonce output & exitCode
      assert.ok(
        sibRun.stdout.includes(`SIBLING_${nonce}`),
        `Healthy sibling stdout expected SIBLING_${nonce}, got: ${JSON.stringify(sibRun.stdout)}`
      );
      assert.equal(sibRun.exitCode, sibCode, `Healthy sibling expected exitCode ${sibCode}, got ${sibRun.exitCode}`);

      assertKernelHealthy(osHandle, 'T2-FA12-02');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA12-03 [Edge #22 / F-048]: Mach-O LC_MAIN non-zero entryoff (0x1200 & 0x1380) enters at __TEXT.vmaddr + slide + entryoff', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const nonce = makeNonce();
      const b = crypto.randomBytes(2);
      const code1 = 15 + (b[0] % 40); // guaranteed != 0 and != 99
      const code2 = 56 + (b[1] % 35); // guaranteed != 0 and != 99

      const cases = [
        { entryOffset: 0x1200, expectedCode: code1, tag: `ENTRYOFF_A_${nonce}` },
        { entryOffset: 0x1380, expectedCode: code2, tag: `ENTRYOFF_B_${nonce}` },
      ];

      for (const tc of cases) {
        const macho = buildNonZeroEntryOffMachO({
          entryOffset: tc.entryOffset,
          message: `${tc.tag}\n`,
          exitCode: tc.expectedCode,
        });
        const bundleId = `com.omnios.macos.entry${tc.entryOffset.toString(16)}.${nonce}`;
        const appZip = buildCustomMacAppZip({
          bundleId,
          appName: `Entry_${tc.entryOffset.toString(16)}_${nonce}`,
          executableName: `Entry_${tc.entryOffset.toString(16)}_${nonce}`,
          machoBytes: macho,
        });
        const vfsPath = `/tmp/entry-${tc.entryOffset.toString(16)}-${nonce}.app.zip`;
        await vfs.writeFile(vfsPath, appZip);

        const rec = await pkgManager.install(vfsPath, { grantAll: true });
        const launched = await pkgManager.launch(rec.appId ?? bundleId);
        const run = await runToCompletion(osHandle, launched.pid);

        assert.notEqual(
          run.exitCode,
          99,
          `Loader ignored LC_MAIN.entryoff=0x${tc.entryOffset.toString(16)} and hit trap exit(99) at __text+0!`
        );
        assert.equal(
          run.exitCode,
          tc.expectedCode,
          `Expected exitCode ${tc.expectedCode} for entryoff 0x${tc.entryOffset.toString(16)}, got ${run.exitCode}`
        );
        assert.ok(
          run.stdout.includes(tc.tag),
          `Expected stdout to contain ${tc.tag}, got: ${JSON.stringify(run.stdout)}`
        );
      }

      assertKernelHealthy(osHandle, 'T2-FA12-03');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA12-04 [Edge #23 / F-050]: ARM64 Register 31 dual SP vs XZR semantics', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const nonce = makeNonce();

      const bundleId = `com.omnios.ios.reg31.${nonce}`;
      const ipa = buildCustomIpa({
        bundleId,
        displayName: `Reg31_${nonce}`,
        executableName: `Reg31_${nonce}`,
        machoBytes: buildArm64Reg31TestMachO(),
      });
      const vfsPath = `/tmp/reg31-${nonce}.ipa`;
      await vfs.writeFile(vfsPath, ipa);

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const launched = await pkgManager.launch(rec.appId ?? bundleId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.equal(
        run.exitCode,
        0,
        `ARM64 reg-31 SP/XZR test failed with exitCode=${run.exitCode} ` +
        `(11 = ADD X1, SP, #0 read 0; 12 = ADD X2, XZR, XZR read non-zero; 13 = SUBS XZR, SP, #0 clobbered SP)`
      );
      assert.ok(
        run.instructionsExecuted >= 14,
        `Expected >= 14 ARM64 instructions executed, got ${run.instructionsExecuted}`
      );

      assertKernelHealthy(osHandle, 'T2-FA12-04');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA12-05 [Edge #24 / F-050]: Apple ARM64 variadic arguments read from 8-byte stack slots (ignoring poisoned X1=777, X2=888)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const nonce = makeNonce();
      const rnd = crypto.randomBytes(2);
      const dynV1 = 100 + (rnd[0] % 200); // 100..299 (disjoint from 42, 99, 777, 888)
      const dynV2 = 300 + (rnd[1] % 200); // 300..499

      const cases = [
        { tag: 'fixed', v1: 42, v2: 99 },
        { tag: 'dynamic', v1: dynV1, v2: dynV2 },
      ];

      for (const tc of cases) {
        const macho = buildArm64VariadicStackArgsMachO({ value1: tc.v1, value2: tc.v2 });
        const bundleId = `com.omnios.macos.varargs.${tc.tag}.${nonce}`;
        const appZip = buildCustomMacAppZip({
          bundleId,
          appName: `Varargs_${tc.tag}_${nonce}`,
          executableName: `Varargs_${tc.tag}_${nonce}`,
          machoBytes: macho,
        });
        const vfsPath = `/tmp/varargs-${tc.tag}-${nonce}.app.zip`;
        await vfs.writeFile(vfsPath, appZip);

        const rec = await pkgManager.install(vfsPath, { grantAll: true });
        const launched = await pkgManager.launch(rec.appId ?? bundleId);
        const run = await runToCompletion(osHandle, launched.pid);

        assert.equal(run.exitCode, 0, `[${tc.tag}] Expected exitCode 0, got ${run.exitCode}`);
        assert.ok(
          run.stdout.includes(`V=${tc.v1},${tc.v2}`),
          `[${tc.tag}] Expected Apple variadic printf output "V=${tc.v1},${tc.v2}", got: ${JSON.stringify(run.stdout)}`
        );
        assert.ok(!run.stdout.includes('777'), `[${tc.tag}] Variadic ABI erroneously read poisoned X1=777: ${run.stdout}`);
        assert.ok(!run.stdout.includes('888'), `[${tc.tag}] Variadic ABI erroneously read poisoned X2=888: ${run.stdout}`);
      }

      assertKernelHealthy(osHandle, 'T2-FA12-05');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA12-06 [Edge #25 / F-051]: Darwin XNU BSD syscall error sets PSTATE Carry flag (C=1) + positive errno (ENOENT=2)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const nonce = makeNonce();

      const macho = buildDarwinErrnoCarryMachO({
        missingPath: `/nonexistent/omnios_e2e_missing_${nonce}`,
      });
      const bundleId = `com.omnios.macos.errno.${nonce}`;
      const appZip = buildCustomMacAppZip({
        bundleId,
        appName: `DarwinErrno_${nonce}`,
        executableName: `DarwinErrno_${nonce}`,
        machoBytes: macho,
      });
      const vfsPath = `/tmp/darwin-errno-${nonce}.app.zip`;
      await vfs.writeFile(vfsPath, appZip);

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const launched = await pkgManager.launch(rec.appId ?? bundleId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.notEqual(
        run.exitCode,
        99,
        'Darwin SYS_open(ENOENT) failed to set ARM64 PSTATE Carry flag (C=1); b.cc took fail_99!'
      );
      assert.ok(
        run.exitCode !== 254 && run.exitCode !== -2,
        `Darwin syscall returned Linux negative -errno (${run.exitCode}) instead of positive Darwin errno 2!`
      );
      assert.equal(run.exitCode, 2, `Expected positive Darwin ENOENT (2), got ${run.exitCode}`);

      assertKernelHealthy(osHandle, 'T2-FA12-06');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA12-07 [Edge #26 / F-052]: Objective-C objc_msgSend(nil, sel) returns 0 cleanly without faulting', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const nonce = makeNonce();

      const bundleId = `com.omnios.ios.objcnil.${nonce}`;
      const ipa = buildCustomIpa({
        bundleId,
        displayName: `ObjcNil_${nonce}`,
        executableName: `ObjcNil_${nonce}`,
        machoBytes: buildObjcNilMsgSendMachO(),
      });
      const vfsPath = `/tmp/objc-nil-${nonce}.ipa`;
      await vfs.writeFile(vfsPath, ipa);

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const launched = await pkgManager.launch(rec.appId ?? bundleId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.ok(
        run.pcb?.state !== 'FAULT' && !run.summary?.fault && !run.pcb?.fault,
        `objc_msgSend(nil, "length") must NOT fault, got state=${run.pcb?.state} fault=${safeJsonStringify(run.summary?.fault ?? run.pcb?.fault)}`
      );
      assert.equal(run.exitCode, 0, `Expected objc_msgSend(nil) to return 0 and exit 0, got ${run.exitCode}`);
      assert.ok(run.instructionsExecuted >= 7, `Expected >= 7 instructions executed, got ${run.instructionsExecuted}`);

      assertKernelHealthy(osHandle, 'T2-FA12-07');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T2-FA12-08 [Edge #27 / F-049/F-053]: bplist00 cyclic references (E_CYCLIC_PLIST), signed 8B int (0x13), 2001 CF date (0x33) & malformed .ipa', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const nonce = makeNonce();

      // Part A: All 3 cyclic bplist00 graph topologies MUST reject with E_CYCLIC_PLIST (never RangeError stack overflow!)
      for (const variant of ['self-dict', 'ab-dict', 'self-array']) {
        const cyclicIpa = buildCyclicBplistIpa(variant);
        await expectPipelineReject(osHandle, cyclicIpa, `/tmp/cyclic-${variant}-${nonce}.ipa`, {
          expectedCode: 'E_CYCLIC_PLIST',
          disallowRangeError: true,
          label: `cyclic-bplist:${variant}`,
        });
      }

      // Part B: Verify standalone buildBplistEdgeValues bytes & non-crash handling
      const edgePlist = buildBplistEdgeValues({ negInt64: -1234567890123n, cfSeconds: 86400.0 });
      assert.equal(Buffer.from(edgePlist.subarray(0, 8)).toString('ascii'), 'bplist00');
      assert.ok(edgePlist.includes(0x13), 'Expected 0x13 (8B signed int) marker in edge bplist');
      assert.ok(edgePlist.includes(0x33), 'Expected 0x33 (2001 CF epoch date) marker in edge bplist');
      let edgeInspectErr = null;
      try {
        await pkgManager.inspect(edgePlist);
      } catch (err) {
        edgeInspectErr = err;
      }
      if (edgeInspectErr) {
        if (edgeInspectErr.code === 'ERR_ASSERTION') throw edgeInspectErr;
        assert.ok(
          !(edgeInspectErr instanceof RangeError),
          `Standalone edge bplist inspect threw RangeError: ${edgeInspectErr.message}`
        );
      }

      // Wrap full .ipa with bplist00 containing 0x13 signed negative 64-bit int, 0x33 2001-01-02 CF date, and UTF-16BE Unicode
      const edgeBundle = `com.omnios.ios.edgebp.${nonce}`;
      const expectedDateMs = Date.UTC(2001, 0, 2, 0, 0, 0);
      const edgeIpa = buildCustomIpa({
        bundleId: edgeBundle,
        displayName: 'OmniOS ★🚀',
        executableName: 'EdgeBp',
        plistFormat: 'bplist00',
        message: `EDGE_BP_${nonce}\n`,
        exitCode: 0,
        extraPlistKeys: {
          negInt: -1234567890123n,
          cfDate: new Date(expectedDateMs),
          unicode: 'OmniOS ★🚀',
        },
      });
      const edgePath = `/tmp/edge-bp-${nonce}.ipa`;
      await vfs.writeFile(edgePath, edgeIpa);

      const insp = await pkgManager.inspect(edgePath);
      const inspBlob = safeJsonStringify(insp);
      assert.ok(inspBlob.includes('OmniOS ★🚀'), `Expected UTF-16BE string "OmniOS ★🚀" in bplist inspection, got: ${inspBlob}`);

      const negHit = findKeyRecursive(insp, 'negInt');
      assert.ok(negHit.found, `Expected bplist key "negInt" preserved in inspection metadata, got: ${inspBlob}`);
      assert.equal(
        String(negHit.value),
        '-1234567890123',
        `bplist00 0x13 signed int64 must decode as negative -1234567890123 (never unsigned 18446742839141661493), got ${String(negHit.value)}`
      );

      const dateHit = findKeyRecursive(insp, 'cfDate');
      assert.ok(dateHit.found, `Expected bplist key "cfDate" preserved in inspection metadata, got: ${inspBlob}`);
      const dVal = dateHit.value;
      const decodedDate = dVal instanceof Date ? dVal : new Date(dVal);
      assert.ok(
        !Number.isNaN(decodedDate.getTime()) &&
        decodedDate.getUTCFullYear() === 2001 &&
        decodedDate.getUTCMonth() === 0 &&
        decodedDate.getUTCDate() === 2,
        `bplist00 0x33 date (86400s from 2001-01-01 CF epoch) must decode to 2001-01-02 UTC (NOT 1970!), got ${safeJsonStringify(dVal)}`
      );

      const rec = await pkgManager.install(edgePath, { grantAll: true });
      const launched = await pkgManager.launch(rec.appId ?? edgeBundle);
      const run = await runToCompletion(osHandle, launched.pid);
      assert.equal(run.exitCode, 0);
      assert.ok(run.stdout.includes(`EDGE_BP_${nonce}`));

      // Part C: Malformed .ipa missing Info.plist rejected cleanly
      const noPlistIpa = buildZip([
        { name: 'Payload/NoPlist.app/NoPlist', data: buildMachO64({ arch: 'arm64', platform: 2 }), method: 8 },
      ]);
      await expectPipelineReject(osHandle, noPlistIpa, `/tmp/noplist-${nonce}.ipa`, {
        disallowRangeError: true,
        label: 'malformed .ipa missing Info.plist',
      });

      assertKernelHealthy(osHandle, 'T2-FA12-08');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });
});
