/**
 * OmniOS Tier 1 E2E Suite — FA-12: Apple Core & iOS Runtime
 * Covers PROJECT.md Features: F-048, F-049, F-050, F-051, F-052, F-053, F-057.
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

import { REPO_ROOT, loadPublicOmniOS } from '../lib/env.mjs';
import { alignUp, concatBytes } from '../lib/binary-utils.mjs';
import {
  ARM64_NOP,
  ARM64_RET,
  ARM64_SVC_80,
  arm64AddReg,
  arm64Adr,
  arm64Adrp,
  arm64Blr,
  arm64Cbz,
  arm64Ldr64,
  arm64MovReg,
  arm64Movz,
  buildCustomIpa,
  buildMachO64WithLayout,
  buildUniversalMachO,
  packArm64Insns,
} from '../lib/fixtures-apple-wasm.mjs';

const textEncoder = new TextEncoder();

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function makeOperands() {
  const b = crypto.randomBytes(2);
  const a = 19 + (b[0] % 55);
  const c = 23 + (b[1] % 55);
  return [a, c];
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

function grantIosCaps(osHandle, appId) {
  const security = osHandle.require('security');
  for (const cap of ['fs.read.user', 'fs.write.user', 'notifications.post', 'ui.window', 'clipboard.read', 'clipboard.write', 'network.outbound']) {
    security.setGrant(appId, cap, 'allow');
  }
}

/**
 * Builds a 2-pass ARM64 Mach-O invoking _objc_getClass("NSObject") ->
 * _objc_msgSend(cls, "alloc") -> _objc_msgSend(obj, "init") ->
 * _objc_msgSend(obj, "release") -> SYS_exit(expectedCode) (or 99 on nil failure),
 * while embedding custom ObjC ABI2 class/method metadata for inspect().
 */
function buildObjcDispatchMachO({ clsName, selName, expectedCode, bundleId }) {
  const textOff = 0x1000;
  const cstringBytes = concatBytes(textEncoder.encode('NSObject'), [0]);
  const commonOpts = {
    arch: 'arm64',
    platform: 2,
    textOffset: textOff,
    cstringBytes,
    dylibs: ['/usr/lib/libSystem.B.dylib', '/usr/lib/libobjc.A.dylib'],
    gotSymbols: [
      { name: '_objc_getClass', dylibOrdinal: 2 },
      { name: '_objc_msgSend', dylibOrdinal: 2 },
    ],
    objcClasses: [
      {
        name: clsName,
        methods: [{ name: selName, types: 'q16@0:8', impOffset: 28 * 4 }],
      },
    ],
    objcSelectors: ['alloc', 'init', 'release'],
    codeSignIdent: bundleId,
  };

  // Pass 1: 30 sizing NOP instructions (120 bytes) to freeze section VAs
  const pass1 = buildMachO64WithLayout({
    ...commonOpts,
    codeBytes: packArm64Insns(Array(30).fill(ARM64_NOP)),
  });
  const L = pass1.layout;
  const pcVa = (idx) => L.textBase + BigInt(L.textOff + idx * 4);
  const gotPageOff = Number(L.gotVmAddr & 0xfffn);
  const selPageOff = Number(L.selRefsVmAddr & 0xfffn);
  const failIdx = 25;

  const insns = [
    arm64Adrp(19, pcVa(0), L.gotVmAddr),            // [0]  x19 = got page
    arm64Ldr64(20, 19, gotPageOff + 0),             // [1]  x20 = _objc_getClass
    arm64Ldr64(21, 19, gotPageOff + 8),             // [2]  x21 = _objc_msgSend
    arm64Adrp(22, pcVa(3), L.selRefsVmAddr),        // [3]  x22 = __objc_selrefs page
    arm64Adr(0, L.cstringOff - (L.textOff + 4 * 4)), // [4] x0 = &"NSObject"
    arm64Blr(20),                                   // [5]  x0 = objc_getClass("NSObject")
    arm64Cbz(0, (failIdx - 6) * 4),                 // [6]  if !cls goto fail
    arm64Ldr64(1, 22, selPageOff + 0),              // [7]  x1 = sel["alloc"]
    arm64Blr(21),                                   // [8]  x0 = objc_msgSend(cls, "alloc")
    arm64Cbz(0, (failIdx - 9) * 4),                 // [9]  if !obj goto fail
    arm64Ldr64(1, 22, selPageOff + 8),              // [10] x1 = sel["init"]
    arm64Blr(21),                                   // [11] x0 = objc_msgSend(obj, "init")
    arm64Cbz(0, (failIdx - 12) * 4),                // [12] if !obj goto fail
    arm64Ldr64(1, 22, selPageOff + 16),             // [13] x1 = sel["release"]
    arm64Blr(21),                                   // [14] objc_msgSend(obj, "release")
    arm64Movz(0, expectedCode & 0xffff),            // [15] x0 = expectedCode
    arm64Movz(16, 1),                               // [16] SYS_exit
    ARM64_SVC_80,                                   // [17] svc #0x80
    ARM64_NOP,                                      // [18]
    ARM64_NOP,                                      // [19]
    ARM64_NOP,                                      // [20]
    ARM64_NOP,                                      // [21]
    ARM64_NOP,                                      // [22]
    ARM64_NOP,                                      // [23]
    ARM64_NOP,                                      // [24]
    arm64Movz(0, 99),                               // [25] fail: x0 = 99
    arm64Movz(16, 1),                               // [26] SYS_exit
    ARM64_SVC_80,                                   // [27] svc #0x80
    arm64Movz(0, expectedCode & 0xffff),            // [28] IMP for custom ObjC method
    ARM64_RET,                                      // [29] ret
  ];

  const pass2 = buildMachO64WithLayout({
    ...commonOpts,
    codeBytes: packArm64Insns(insns),
  });
  assert.equal(pass2.layout.gotVmAddr, L.gotVmAddr);
  assert.equal(pass2.layout.selRefsVmAddr, L.selRefsVmAddr);
  assert.equal(pass2.layout.cstringOff, L.cstringOff);
  return pass2.buffer;
}

describe('Tier 1 — FA-12: Apple Core & iOS Runtime (Mach-O, Plist, ARM64, Darwin, ObjC, IPA & UIKit)', () => {
  it('T1-FA12-01 [F-048/F-049]: iOS .ipa with binary bplist00 Info.plist + ARM64 Mach-O + LC_CODE_SIGNATURE (0xFADE7171) entitlements', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const bundleId = `com.omnios.ios.bp${nonce}`;
      const displayName = `IosBp_${nonce}`;
      const entitlementsXml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        '<plist version="1.0"><dict>',
        `<key>application-identifier</key><string>TEAM.com.omnios.ios.ent${nonce}</string>`,
        '<key>com.apple.security.network.client</key><true/>',
        '</dict></plist>',
      ].join('\n');

      const ipaBuf = buildCustomIpa({
        bundleId,
        displayName,
        executableName: displayName,
        version: '2.3.4',
        plistFormat: 'bplist00',
        message: `BP_OUT_${nonce}\n`,
        exitCode: 0,
        entitlementsXml,
      });

      const det = formatDetector.detect(ipaBuf, `bp-${nonce}.ipa`);
      assert.equal(det.format, 'ios-ipa');
      assert.equal(det.platform, 'ios');

      const vfsPath = `/tmp/bp-${nonce}.ipa`;
      await vfs.writeFile(vfsPath, ipaBuf);
      const insp = await pkgManager.inspect(vfsPath);
      const inspJson = JSON.stringify(insp);

      assert.equal(insp.format, 'ios-ipa');
      assert.equal(insp.platform, 'ios');
      assert.equal(insp.appId ?? insp.bundleId, bundleId);
      assert.ok(String(insp.name ?? insp.displayName ?? inspJson).includes(displayName));
      assert.ok(String(insp.version ?? inspJson).includes('2.3.4'));
      assert.ok(/arm64|aarch64/i.test(String(insp.arch ?? inspJson)), `Expected arm64 arch, got: ${inspJson}`);
      assert.ok(
        inspJson.includes(`TEAM.com.omnios.ios.ent${nonce}`) ||
        inspJson.includes('com.apple.security.network.client'),
        `Expected LC_CODE_SIGNATURE entitlements in inspection, got: ${inspJson}`
      );
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA12-02 [F-049]: iOS .ipa with XML Info.plist decoding & live launch', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const bundleId = `com.omnios.ios.xml${nonce}`;
      const expectedCode = 17 + (crypto.randomBytes(1)[0] % 80);
      const ipaXml = buildCustomIpa({
        bundleId,
        displayName: `IosXml_${nonce}`,
        executableName: `IosXml_${nonce}`,
        version: '1.5.0',
        plistFormat: 'xml',
        message: `XML_PLIST_${nonce}\n`,
        exitCode: expectedCode,
      });

      const vfsPath = `/tmp/xml-${nonce}.ipa`;
      await vfs.writeFile(vfsPath, ipaXml);
      const insp = await pkgManager.inspect(vfsPath);
      assert.equal(insp.appId ?? insp.bundleId, bundleId);
      assert.ok(String(insp.version ?? JSON.stringify(insp)).includes('1.5.0'));

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const launched = await pkgManager.launch(rec.appId ?? bundleId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.ok(
        run.stdout.includes(`XML_PLIST_${nonce}`),
        `Expected XML-plist IPA stdout to include XML_PLIST_${nonce}, got: ${JSON.stringify(run.stdout)}`
      );
      assert.equal(run.exitCode, expectedCode);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA12-03 [F-050/F-051]: ARM64 AArch64 CPU emulator + Darwin XNU BSD SYS_write & SYS_exit executing dynamic runtime-nonce arithmetic', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const [a, b] = makeOperands();
      const expectedSum = a + b;
      const msg = `ARM64_CALC_${nonce}\n`;
      const msgBytes = textEncoder.encode(msg);
      const cstringBytes = concatBytes(msgBytes, [0]);

      const textOff = 0x1000;
      const codeLen = 11 * 4;
      const strOff = alignUp(textOff + codeLen, 16);
      const codeBytes = packArm64Insns([
        arm64Movz(3, a),                          // [0] mov x3, #a
        arm64Movz(4, b),                          // [1] mov x4, #b
        arm64AddReg(5, 3, 4),                     // [2] add x5, x3, x4
        arm64Adr(1, strOff - (textOff + 3 * 4)),  // [3] adr x1, msg
        arm64Movz(0, 1),                          // [4] mov x0, #1 (stdout)
        arm64Movz(2, msgBytes.length),            // [5] mov x2, #len
        arm64Movz(16, 4),                         // [6] mov x16, #4 (SYS_write)
        ARM64_SVC_80,                             // [7] svc #0x80
        arm64MovReg(0, 5),                        // [8] mov x0, x5 (a + b)
        arm64Movz(16, 1),                         // [9] mov x16, #1 (SYS_exit)
        ARM64_SVC_80,                             // [10] svc #0x80
      ]);

      const { buffer: machoBytes, layout } = buildMachO64WithLayout({
        arch: 'arm64',
        platform: 2,
        textOffset: textOff,
        codeBytes,
        cstringBytes,
      });
      assert.equal(layout.cstringOff, strOff);

      const bundleId = `com.omnios.ios.arm${nonce}`;
      const ipaBuf = buildCustomIpa({
        bundleId,
        displayName: `ArmCalc_${nonce}`,
        executableName: `ArmCalc_${nonce}`,
        machoBytes,
      });

      const vfsPath = `/tmp/armcalc-${nonce}.ipa`;
      await vfs.writeFile(vfsPath, ipaBuf);
      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const launched = await pkgManager.launch(rec.appId ?? bundleId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.ok(
        run.stdout.includes(`ARM64_CALC_${nonce}`),
        `Expected ARM64 stdout to include ARM64_CALC_${nonce}, got: ${JSON.stringify(run.stdout)}`
      );
      assert.equal(run.exitCode, expectedSum, `Expected ARM64 computed sum ${a}+${b}=${expectedSum}, got ${run.exitCode}`);
      assert.ok(run.instructionsExecuted >= 11, `Expected >= 11 ARM64 instructions executed, got ${run.instructionsExecuted}`);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA12-04 [F-050/F-051/F-053]: ARM64 Darwin BSD File I/O (open/write/close/exit) + iOS UUID container sandbox', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pathTranslator = osHandle.require('pathTranslator');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const bundleId = `com.omnios.ios.io${nonce}`;
      const iosDocPath = `/var/mobile/Documents/ios-doc-${nonce}.txt`;
      const content = `IOS_VFS_${nonce}`;

      const translated = pathTranslator.toCanonical(iosDocPath, { platform: 'ios' });
      assert.equal(translated.canonicalPath, `/home/user/Documents/ios-doc-${nonce}.txt`);

      const ipaIo = buildCustomIpa({
        bundleId,
        displayName: `IosIo_${nonce}`,
        executableName: `IosIo_${nonce}`,
        fileWrite: { path: iosDocPath, content },
        exitCode: 0,
      });

      const vfsPath = `/tmp/ios-io-${nonce}.ipa`;
      await vfs.writeFile(vfsPath, ipaIo);
      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId ?? bundleId;
      grantIosCaps(osHandle, appId);

      const launched = await pkgManager.launch(appId);
      const run = await runToCompletion(osHandle, launched.pid);
      assert.equal(run.exitCode, 0, `Expected exitCode 0 from iOS BSD file write, got ${run.exitCode}`);

      // Verify UUID sandbox container provisioned under /var/appdata/ios/ (supports eager-on-install or lazy-on-launch)
      const iosContainers = await vfs.readdir('/var/appdata/ios');
      assert.ok(
        Array.isArray(iosContainers) && iosContainers.length > 0,
        `Expected provisioned iOS UUID container under /var/appdata/ios, got: ${JSON.stringify(iosContainers)}`
      );

      const readBack = String(await vfs.readFile(`/home/user/Documents/ios-doc-${nonce}.txt`, { encoding: 'utf8' }));
      assert.equal(readBack, content, 'Expected /var/mobile/Documents/ write to map to canonical /home/user/Documents/');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA12-05 [F-052]: Objective-C ABI2 metadata (__objc_classlist/__objc_selrefs/__objc_methname) & live objc_msgSend dispatch', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const bundleId = `com.omnios.ios.objc${nonce}`;
      const clsName = `OmniCls_${nonce}`;
      const selName = `runTok_${nonce}`;
      const expectedCode = 31 + (crypto.randomBytes(1)[0] % 55); // guaranteed != 99

      const machoBytes = buildObjcDispatchMachO({
        clsName,
        selName,
        expectedCode,
        bundleId,
      });

      const ipaBuf = buildCustomIpa({
        bundleId,
        displayName: `IosObjc_${nonce}`,
        executableName: `IosObjc_${nonce}`,
        machoBytes,
      });

      const vfsPath = `/tmp/objc-${nonce}.ipa`;
      await vfs.writeFile(vfsPath, ipaBuf);
      const insp = await pkgManager.inspect(vfsPath);
      const inspJson = JSON.stringify(insp);
      assert.ok(
        inspJson.includes(clsName) && inspJson.includes(selName),
        `Expected ObjC ABI2 inspection metadata to include ${clsName} and ${selName}, got: ${inspJson}`
      );

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const launched = await pkgManager.launch(rec.appId ?? bundleId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.notEqual(run.exitCode, 99, 'objc_getClass or objc_msgSend returned nil/0 (failed guard)');
      assert.equal(run.exitCode, expectedCode, `Expected ObjC dispatch exitCode ${expectedCode}, got ${run.exitCode}`);
      assert.ok(run.instructionsExecuted > 0, 'Expected ARM64 ObjC dispatch instructionsExecuted > 0');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA12-06 [F-048/F-053]: iOS CFBundleURLTypes URL scheme registration & Universal Fat (0xCAFEBABE) Mach-O slice inspection', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const intentRouter = osHandle.require('intentRouter');

      const nonce = makeNonce();
      const bundleId = `com.omnios.ios.url${nonce}`;
      const scheme = `omniios${nonce}`;

      const ipaUrl = buildCustomIpa({
        bundleId,
        displayName: `IosUrl_${nonce}`,
        executableName: `IosUrl_${nonce}`,
        urlScheme: scheme,
        message: `URL_${nonce}\n`,
      });

      const ipaPath = `/tmp/url-${nonce}.ipa`;
      await vfs.writeFile(ipaPath, ipaUrl);
      await pkgManager.install(ipaPath, { grantAll: true });

      const resolved = intentRouter.resolve({ scheme });
      assert.ok(
        Array.isArray(resolved) && resolved.some((h) => (h.appId ?? h.id) === bundleId),
        `Expected intentRouter to resolve iOS CFBundleURLTypes scheme "${scheme}" to ${bundleId}, got: ${JSON.stringify(resolved)}`
      );

      // Universal Fat Mach-O (0xCAFEBABE) multi-slice inspection
      const fatMacho = buildUniversalMachO({
        message: `FAT_${nonce}\n`,
        exitCode: 0,
        platform: 2,
      });
      const det = formatDetector.detect(fatMacho, `fat-${nonce}.macho`);
      assert.notEqual(det.format, 'unknown', 'Expected Universal Fat Mach-O to be detected');
      assert.ok(
        det.format === 'macos-macho' || det.format.includes('macho'),
        `Expected Mach-O format for Universal Fat binary, got: ${JSON.stringify(det)}`
      );

      const fatPath = `/tmp/fat-${nonce}.macho`;
      await vfs.writeFile(fatPath, fatMacho);
      const fatInsp = await pkgManager.inspect(fatPath);
      const fatJson = JSON.stringify(fatInsp).toLowerCase();
      assert.ok(
        fatJson.includes('arm64') && (fatJson.includes('x86_64') || fatJson.includes('x64')),
        `Expected Universal Fat inspection to extract both arm64 and x86_64 slices, got: ${JSON.stringify(fatInsp)}`
      );
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA12-07 [F-057/F-053]: SDK sample packages/ios-weather-island.ipa (UIKit window + Dynamic Island Live Activity + omniweather:// scheme)', async () => {
    let osHandle = null;
    try {
      // Boot public OS FIRST so absent os/os.mjs fails loudly with E_OMNIOS_NOT_IMPLEMENTED
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const pkgManager = osHandle.require('pkgManager');
      const intentRouter = osHandle.require('intentRouter');
      const scheduler = osHandle.require('scheduler');
      const compositor = osHandle.require('compositor');
      const notifications = osHandle.require('notifications');
      const pm = osHandle.require('processManager');

      const ipaBuf = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', 'ios-weather-island.ipa'));
      const det = formatDetector.detect(ipaBuf, 'ios-weather-island.ipa');
      assert.equal(det.format, 'ios-ipa');
      assert.equal(det.platform, 'ios');

      const insp = await pkgManager.inspect(ipaBuf);
      assert.equal(insp.platform, 'ios');

      const rec = await pkgManager.install(ipaBuf, { grantAll: true });
      const appId = rec.appId ?? insp.appId;
      grantIosCaps(osHandle, appId);

      const schemeHandlers = intentRouter.resolve({ scheme: 'omniweather' });
      assert.ok(
        Array.isArray(schemeHandlers) && schemeHandlers.some((h) => (h.appId ?? h.id) === appId),
        `Expected omniweather:// scheme to resolve to ${appId}, got: ${JSON.stringify(schemeHandlers)}`
      );

      const launched = await pkgManager.launch(appId);
      assert.ok(launched.pid > 1);
      await scheduler.step(200);

      const pcb = pm.get(launched.pid);
      assert.ok(extractInstructions(pcb, null) > 0, 'Expected ios-weather-island.ipa to execute > 0 ARM64 instructions');

      const wins = compositor.getSnapshot().windows ?? [];
      const win = wins.find((w) => w.pid === launched.pid || w.appId === appId);
      assert.ok(win, 'Expected UIKit Compositor window from ios-weather-island.ipa');
      assert.equal(win.platform, 'ios');

      const liveActivities = notifications.getLiveActivities();
      assert.ok(
        Array.isArray(liveActivities) && liveActivities.length > 0,
        `Expected ios-weather-island.ipa to publish a Dynamic Island Live Activity, got: ${JSON.stringify(liveActivities)}`
      );

      await pkgManager.stop(launched.pid);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });
});
