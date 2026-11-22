/**
 * OmniOS Tier 4 E2E Suite — S02: Dynamic Custom Binaries Anti-Hardcoding & CLI-Only Operator Lifecycle
 * Covers PROJECT.md Features: F-032–F-060, F-065, F-066, F-085.
 *
 * Scenarios:
 * - T4-S02-01 (Scenario 3): Synthesize brand-new custom binaries with fresh cryptographic runtime nonces
 *   & random arithmetic operands across all 5 platforms (.apk, PE32+ .exe, ARM64 .ipa, Universal Fat .app.zip,
 *   WASM .uapp), cross-verify EVERY binary inline against independent host toolchains (llvm-readobj,
 *   llvm-objdump, Python 3 zipfile/plistlib/adler32/sha1, file, WebAssembly.validate), then install via
 *   ospm and execute live in OmniOS asserting exact nonce-derived outputs + Python plistlib round-trip.
 * - T4-S02-02 (Scenario 4): Complete CLI-only operator lifecycle using os/cli/omnios-cli.mjs in local
 *   headless (--data-dir --json) mode persisted into a CLI-booted daemon (--remote --json) across status,
 *   dmesg, services, vfs, reg, defaults, prefs, ospm inspect/install/list/launch/stop/uninstall, ps,
 *   clipboard, notify, intent, and piped shell exec.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero external npm dependencies, zero hardcoded sys.* IDs, zero undocumented capability strings.
 * - Zero skips, zero stubs, zero swallowed AssertionErrors inside try/catch.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  PUBLIC_PATHS,
  assertPublicEntryExists,
  createTempDataDir,
  loadPublicOmniOS,
  runCli,
  startOmniServer,
} from '../lib/env.mjs';
import {
  alignUp,
  buildXmlPlist,
  concatBytes,
  sha256Hex,
} from '../lib/binary-utils.mjs';
import {
  buildCustomApk,
  buildCustomPe64Exe,
} from '../lib/fixtures-android-win.mjs';
import {
  ARM64_SVC_80,
  arm64AddReg,
  arm64Adr,
  arm64MovReg,
  arm64Movz,
  buildCustomIpa,
  buildCustomMacAppZip,
  buildCustomUapp,
  buildCustomWasm,
  buildMachO64WithLayout,
  packArm64Insns,
} from '../lib/fixtures-apple-wasm.mjs';

const execFileAsync = promisify(execFile);
const textEncoder = new TextEncoder();

function makeNonce(bytes = 4) {
  return crypto.randomBytes(bytes).toString('hex');
}

function makeSafeAddOperands() {
  const b = crypto.randomBytes(2);
  return [19 + (b[0] % 55), 23 + (b[1] % 55)]; // sum in [42..149]
}

function makeDistinctExitCode(offset = 31) {
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
  return normalizeText(pcb?.stdout ?? pcb?.streams?.stdout ?? summary?.stdout ?? summary?.streams?.stdout ?? '');
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

function getUiTree(w) {
  return w?.uiTree ?? w?.surface?.uiTree ?? null;
}

function unwrapExplicitArray(payload, keys = ['packages', 'items', 'data', 'entries', 'processes', 'notifications']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return null;
}

async function runTool(cmd, args, { input } = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
      timeout: 15000,
      ...(input !== undefined ? { input } : {}),
    });
    return { code: 0, stdout: String(stdout ?? ''), stderr: String(stderr ?? '') };
  } catch (err) {
    return {
      code: typeof err?.code === 'number' ? err.code : 1,
      stdout: String(err?.stdout ?? ''),
      stderr: String(err?.stderr ?? err?.message ?? ''),
    };
  }
}

async function runPython(script, args = [], { stdin } = {}) {
  if (stdin === undefined) {
    return await runTool('python3', ['-c', script, ...args]);
  }
  const { spawn } = await import('node:child_process');
  return await new Promise((resolve, reject) => {
    const child = spawn('python3', ['-c', script, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString('utf8'); });
    child.stderr.on('data', (c) => { stderr += c.toString('utf8'); });
    child.once('error', reject);
    child.once('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

async function readVfsText(vfs, p) {
  return normalizeText(await vfs.readFile(p, { encoding: 'utf8' }));
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
    // already exists
  }
}

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
  if (!caps) caps = sec.capabilities ?? sec.CAPABILITIES ?? null;
  const list = Array.isArray(caps)
    ? caps
    : (caps && typeof caps === 'object' ? Object.values(caps) : []);
  for (const cap of list) {
    const capName = typeof cap === 'string' ? cap : (cap?.id ?? cap?.name ?? null);
    if (!capName) continue;
    try {
      await sec.setGrant(appId, capName, 'allow');
    } catch {
      // ignore optional cap grant error
    }
  }
}

async function stageInspectInstall(osHandle, bytes, filename, expectedFormat, expectedPlatform) {
  const detector = osHandle.require('formatDetector');
  const vfs = osHandle.require('vfs');
  const pkgManager = osHandle.require('pkgManager');

  const detected = await detector.detect(bytes, filename);
  assert.equal(detected?.format, expectedFormat, `formatDetector format mismatch for ${filename}: ${JSON.stringify(detected)}`);
  assert.equal(detected?.platform, expectedPlatform, `formatDetector platform mismatch for ${filename}: ${JSON.stringify(detected)}`);

  await ensureVfsDir(vfs, '/tmp');
  const vfsPath = `/tmp/${filename}`;
  await vfs.writeFile(vfsPath, bytes);

  let insp = null;
  try {
    insp = await pkgManager.inspect(vfsPath);
  } catch {
    insp = await pkgManager.inspect(bytes, filename);
  }
  assert.ok(insp && typeof insp === 'object', `pkgManager.inspect(${filename}) must return object`);
  assert.equal(insp.platform, expectedPlatform);
  if (insp.sha256) {
    assert.equal(String(insp.sha256).toLowerCase(), sha256Hex(bytes));
  }

  let rec = null;
  try {
    rec = await pkgManager.install(vfsPath, { filename, grantAll: true });
  } catch {
    rec = await pkgManager.install(bytes, { filename, grantAll: true });
  }
  const appId = rec?.appId ?? rec?.id ?? insp.appId;
  assert.ok(typeof appId === 'string' && appId.length > 0, `Expected appId installing ${filename}`);
  await grantDiscoveredCapabilities(osHandle, appId);
  return { appId, vfsPath, inspection: insp, record: rec };
}

async function runPidToDone(osHandle, pid, maxRounds = 400) {
  const pm = osHandle.require('processManager');
  const scheduler = osHandle.require('scheduler');
  if (typeof scheduler.runUntilIdle === 'function') {
    await scheduler.runUntilIdle(pid, maxRounds * 10);
  }
  for (let i = 0; i < maxRounds; i++) {
    if (isDoneState(pm.get(pid)?.state)) break;
    await scheduler.step(10);
  }
  return pm.get(pid);
}

async function stopPidBestEffort(osHandle, pid) {
  if (!pid || pid <= 1) return;
  try {
    await osHandle.pkgManager?.stop?.(pid);
  } catch {
    // ignore
  }
  try {
    const pcb = osHandle.processManager?.get?.(pid);
    if (pcb && !isDoneState(pcb.state)) {
      await osHandle.processManager.kill(pid, 'SIGKILL');
    }
  } catch {
    // ignore
  }
}

describe('Tier 4 — S02: Dynamic Anti-Hardcoding External Oracles & CLI-Only Operator Lifecycle', () => {
  it('T4-S02-01 [Scenario 3]: Anti-hardcoding external-oracle proof across all 5 platforms (llvm-readobj, llvm-objdump, Python zipfile/plistlib/hashes, file, WebAssembly.validate -> live OmniOS execution)', async () => {
    let osHandle = null;
    let tmp = null;
    const spawnedPids = new Set();
    try {
      // Fail-fast on public entrypoint BEFORE allocating scratch dirs or spawning host oracles
      osHandle = await loadPublicOmniOS();
      tmp = await createTempDataDir('omnios-s02-oracles-');

      const pm = osHandle.require('processManager');
      const scheduler = osHandle.require('scheduler');
      const vfs = osHandle.require('vfs');
      const configStore = osHandle.require('configStore');
      const compositor = osHandle.require('compositor');
      const pkgManager = osHandle.require('pkgManager');

      scheduler.stop?.();

      const nonce = makeNonce(6);
      const randBytes = crypto.randomBytes(2);
      const andA = 23 + (randBytes[0] % 60);
      const andB = 29 + (randBytes[1] % 60);
      const andProd = Math.imul(andA, andB);
      const [winA, winB] = makeSafeAddOperands();
      const winSum = winA + winB;
      const [iosA, iosB] = makeSafeAddOperands();
      const iosSum = iosA + iosB;
      const macCode = makeDistinctExitCode(31);
      const uappCode = makeDistinctExitCode(101);

      // ----------------------------------------------------------------------
      // #1 Android .apk — Dynamic runtime Dalvik multiplication + Python & file oracles
      // ----------------------------------------------------------------------
      const andPkg = `com.omnios.oracle.and${nonce}`;
      const apkBytes = buildCustomApk({
        packageName: andPkg,
        appLabel: `OracleAnd_${nonce}`,
        computeA: andA,
        computeB: andB,
        computeOp: 'mul',
        outputFile: `/sdcard/Documents/oracle-and-${nonce}.txt`,
        // Omit outputContent so Dalvik writes dynamically computed Integer.toString(andA * andB)
        sharedPrefName: 'oracle_sp',
        sharedPrefKey: 'tok',
        sharedPrefVal: `SP_${nonce}`,
        logTag: 'OracleAnd',
        permissions: ['android.permission.WRITE_EXTERNAL_STORAGE'],
        dexVersion: '035',
        includeV2SigBlock: true,
        includeResourcesArsc: true,
      });

      const apkPath = path.join(tmp.dir, `oracle-${nonce}.apk`);
      const dexOutPath = path.join(tmp.dir, `oracle-${nonce}.dex`);
      await fs.writeFile(apkPath, apkBytes);

      const pyApk = await runPython(
        `
import sys, zipfile, zlib, hashlib, struct, json
apk_path, dex_out = sys.argv[1], sys.argv[2]
raw = open(apk_path, 'rb').read()
assert b'APK Sig Block 42' in raw, 'Missing APK Signing Block v2 magic'
with zipfile.ZipFile(apk_path, 'r') as zf:
    assert zf.testzip() is None, 'ZIP CRC integrity check failed'
    dex = zf.read('classes.dex')
    axml = zf.read('AndroidManifest.xml')
    arsc = zf.read('resources.arsc')
assert dex[:8] == b'dex\\n035\\x00', f'Bad DEX magic: {dex[:8]!r}'
adler_hdr = struct.unpack_from('<I', dex, 8)[0]
adler_calc = zlib.adler32(dex[0x0c:]) & 0xffffffff
assert adler_hdr == adler_calc, f'DEX Adler-32 mismatch: {adler_hdr:#x} != {adler_calc:#x}'
sha1_hdr = dex[0x0c:0x20]
sha1_calc = hashlib.sha1(dex[0x20:]).digest()
assert sha1_hdr == sha1_calc, 'DEX SHA-1 mismatch'
ax_type, ax_hdr, ax_sz = struct.unpack_from('<HHI', axml, 0)
assert (ax_type, ax_hdr, ax_sz) == (0x0003, 8, len(axml)), f'Bad AXML chunk: {(ax_type, ax_hdr, ax_sz)}'
ar_type, ar_hdr, ar_sz = struct.unpack_from('<HHI', arsc, 0)
assert (ar_type, ar_hdr, ar_sz) == (0x0002, 12, len(arsc)), f'Bad ARSC chunk: {(ar_type, ar_hdr, ar_sz)}'
open(dex_out, 'wb').write(dex)
print(json.dumps({'ok': True, 'dexLen': len(dex)}))
        `,
        [apkPath, dexOutPath]
      );
      assert.equal(pyApk.code, 0, `Python APK/DEX oracle failed: ${pyApk.stderr}`);

      const fileDex = await runTool('file', ['-b', dexOutPath]);
      assert.equal(fileDex.code, 0, `file oracle failed on classes.dex: ${fileDex.stderr}`);
      assert.match(fileDex.stdout, /Dalvik dex file version 035/i, `Unexpected file(1) DEX output: ${fileDex.stdout}`);

      // ----------------------------------------------------------------------
      // #2 Windows PE32+ .exe — Dynamic x86-64 sum + Win32 file/reg + llvm oracles
      // ----------------------------------------------------------------------
      const peBytes = buildCustomPe64Exe({
        subsystem: 3,
        message: `ORACLE_PE64_${nonce}\n`,
        computeExitSum: [winA, winB],
        writeFilePath: `C:\\Users\\user\\Documents\\oracle-win-${nonce}.txt`,
        writeFileContent: `WIN_ORACLE_${nonce}`,
        regHive: 0x80000001,
        regSubKey: `Software\\OmniOracle\\Run_${nonce}`,
        regValueName: 'OracleKey',
        regValueData: `REG_ORACLE_${nonce}`,
        addCertTableRawOffset: true,
        includeReloc: true,
      });

      const pePath = path.join(tmp.dir, `oracle64-${nonce}.exe`);
      await fs.writeFile(pePath, peBytes);

      const readobjPe = await runTool('llvm-readobj', ['--file-headers', '--coff-imports', '--coff-basereloc', pePath]);
      assert.equal(readobjPe.code, 0, `llvm-readobj PE64 oracle failed: ${readobjPe.stderr}`);
      assert.equal(readobjPe.stderr.trim(), '', `Unexpected llvm-readobj stderr: ${readobjPe.stderr}`);
      assert.match(readobjPe.stdout, /IMAGE_FILE_MACHINE_AMD64/);
      assert.match(readobjPe.stdout, /KERNEL32\.dll/i);
      assert.match(readobjPe.stdout, /ADVAPI32\.dll/i);
      assert.match(readobjPe.stdout, /CreateFileA/);
      assert.match(readobjPe.stdout, /RegSetValueExA/);
      assert.match(readobjPe.stdout, /DIR64/);

      const objdumpPe = await runTool('llvm-objdump', ['--private-headers', '-d', pePath]);
      assert.equal(objdumpPe.code, 0, `llvm-objdump PE64 oracle failed: ${objdumpPe.stderr}`);
      assert.equal(objdumpPe.stderr.trim(), '', `Unexpected llvm-objdump PE stderr: ${objdumpPe.stderr}`);
      assert.match(objdumpPe.stdout, /callq\s+\*/);

      // ----------------------------------------------------------------------
      // #3 iOS .ipa — Custom 11-instruction ARM64 Mach-O (add x5, x3, x4) + bplist00 + llvm/Python oracles
      // ----------------------------------------------------------------------
      const iosBundle = `com.omnios.oracle.ios${nonce}`;
      const iosExecName = `OracleIos_${nonce}`;
      const iosMsg = `ORACLE_IOS_${nonce}\n`;
      const iosMsgBytes = textEncoder.encode(iosMsg);
      const iosCstringBytes = concatBytes(iosMsgBytes, [0]);
      const iosTextOff = 0x1000;
      const iosCstringOff = alignUp(iosTextOff + 11 * 4, 16);

      const iosCodeBytes = packArm64Insns([
        arm64Movz(3, iosA & 0xffff),
        arm64Movz(4, iosB & 0xffff),
        arm64AddReg(5, 3, 4),
        arm64Adr(1, iosCstringOff - (iosTextOff + 12)),
        arm64Movz(0, 1),
        arm64Movz(2, iosMsgBytes.length & 0xffff),
        arm64Movz(16, 4), // Darwin SYS_write
        ARM64_SVC_80,
        arm64MovReg(0, 5),
        arm64Movz(16, 1), // Darwin SYS_exit
        ARM64_SVC_80,
      ]);

      const iosEntitlements = buildXmlPlist({
        'application-identifier': `TEAMID.${iosBundle}`,
        'com.apple.security.app-sandbox': true,
      });

      const { buffer: iosMacho, layout: iosLayout } = buildMachO64WithLayout({
        arch: 'arm64',
        platform: 2,
        textOffset: iosTextOff,
        codeBytes: iosCodeBytes,
        cstringBytes: iosCstringBytes,
        entitlementsXml: iosEntitlements,
        includePageZero: true,
        codeSignIdent: iosBundle,
      });
      assert.equal(iosLayout.cstringOff, iosCstringOff, 'ARM64 Mach-O __cstring offset must match ADR target');

      const ipaBytes = buildCustomIpa({
        bundleId: iosBundle,
        displayName: iosExecName,
        executableName: iosExecName,
        plistFormat: 'bplist00',
        machoBytes: iosMacho,
      });

      const ipaPath = path.join(tmp.dir, `oracle-${nonce}.ipa`);
      const iosMachoPath = path.join(tmp.dir, `oracle-ios-macho-${nonce}`);
      await fs.writeFile(ipaPath, ipaBytes);

      const pyIpa = await runPython(
        `
import sys, zipfile, plistlib, json
ipa_path, macho_out, expected_bid, exec_name = sys.argv[1:5]
with zipfile.ZipFile(ipa_path, 'r') as zf:
    assert zf.testzip() is None, 'IPA ZIP CRC check failed'
    plist_raw = zf.read(f'Payload/{exec_name}.app/Info.plist')
    macho_raw = zf.read(f'Payload/{exec_name}.app/{exec_name}')
assert plist_raw[:8] == b'bplist00', f'Expected bplist00 magic, got {plist_raw[:8]!r}'
pl = plistlib.loads(plist_raw)
assert pl['CFBundleIdentifier'] == expected_bid, f"BundleId mismatch: {pl['CFBundleIdentifier']}"
assert pl['LSRequiresIPhoneOS'] is True, 'LSRequiresIPhoneOS must be True'
open(macho_out, 'wb').write(macho_raw)
print(json.dumps({'ok': True, 'bundleId': pl['CFBundleIdentifier']}))
        `,
        [ipaPath, iosMachoPath, iosBundle, iosExecName]
      );
      assert.equal(pyIpa.code, 0, `Python IPA/bplist00 oracle failed: ${pyIpa.stderr}`);

      const objdumpIos = await runTool('llvm-objdump', ['--macho', '--private-headers', '--syms', '-d', iosMachoPath]);
      assert.equal(objdumpIos.code, 0, `llvm-objdump ARM64 Mach-O oracle failed: ${objdumpIos.stderr}`);
      assert.match(objdumpIos.stdout, /MH_MAGIC_64/);
      assert.match(objdumpIos.stdout, /ARM64/);
      assert.match(objdumpIos.stdout, /LC_CODE_SIGNATURE/);
      assert.match(objdumpIos.stdout, /add\s+x5,\s+x3,\s+x4/i);
      assert.match(objdumpIos.stdout, /svc\s+#0x80/i);

      // ----------------------------------------------------------------------
      // #4 macOS Universal Fat .app.zip — ARM64 + x86_64 parity + llvm/Python oracles
      // ----------------------------------------------------------------------
      const macBundle = `com.omnios.oracle.mac${nonce}`;
      const macAppName = `OracleMac_${nonce}`;
      const macExt = `om${nonce.slice(0, 4)}`;
      const macFilePath = `/Users/user/Documents/oracle-mac-${nonce}.txt`;
      const macFileContent = `MAC_ORACLE_${nonce}`;

      const macZipBytes = buildCustomMacAppZip({
        bundleId: macBundle,
        appName: macAppName,
        executableName: macAppName,
        arch: 'universal',
        plistFormat: 'xml',
        documentExtensions: [macExt],
        fileWrite: {
          path: macFilePath,
          content: macFileContent,
        },
        exitCode: macCode,
      });

      const macZipPath = path.join(tmp.dir, `oracle-${nonce}.app.zip`);
      const macExecPath = path.join(tmp.dir, `oracle-mac-fat-${nonce}`);
      await fs.writeFile(macZipPath, macZipBytes);

      const pyMac = await runPython(
        `
import sys, zipfile, plistlib, json
zip_path, exec_out, expected_bid, app_name, ext = sys.argv[1:6]
with zipfile.ZipFile(zip_path, 'r') as zf:
    assert zf.testzip() is None, 'macOS .app.zip CRC check failed'
    plist_raw = zf.read(f'{app_name}.app/Contents/Info.plist')
    exec_raw = zf.read(f'{app_name}.app/Contents/MacOS/{app_name}')
pl = plistlib.loads(plist_raw)
assert pl['CFBundleIdentifier'] == expected_bid
doc_types = pl.get('CFBundleDocumentTypes', [])
assert any(ext in dt.get('CFBundleTypeExtensions', []) for dt in doc_types), f'Missing ext {ext} in {doc_types}'
open(exec_out, 'wb').write(exec_raw)
print(json.dumps({'ok': True}))
        `,
        [macZipPath, macExecPath, macBundle, macAppName, macExt]
      );
      assert.equal(pyMac.code, 0, `Python macOS .app.zip oracle failed: ${pyMac.stderr}`);

      const fatRaw = await fs.readFile(macExecPath);
      assert.ok(fatRaw.includes(Buffer.from(macFilePath, 'utf8')), 'Universal Fat binary must contain runtime filePath');
      assert.ok(fatRaw.includes(Buffer.from(macFileContent, 'utf8')), 'Universal Fat binary must contain runtime content');

      const objdumpFat = await runTool('llvm-objdump', ['--macho', '--universal-headers', macExecPath]);
      assert.equal(objdumpFat.code, 0, `llvm-objdump universal-headers failed: ${objdumpFat.stderr}`);
      assert.match(objdumpFat.stdout, /X86_64/);
      assert.match(objdumpFat.stdout, /ARM64/);

      const objdumpMacArm = await runTool('llvm-objdump', ['--macho', '--private-headers', '-d', '--arch=arm64', macExecPath]);
      assert.equal(objdumpMacArm.code, 0, `llvm-objdump macOS arm64 slice failed: ${objdumpMacArm.stderr}`);
      assert.match(objdumpMacArm.stdout, /svc\s+#0x80/i);

      const objdumpMacX64 = await runTool('llvm-objdump', ['--macho', '--private-headers', '-d', '--arch=x86_64', macExecPath]);
      assert.equal(objdumpMacX64.code, 0, `llvm-objdump macOS x86_64 slice failed: ${objdumpMacX64.stderr}`);
      assert.match(objdumpMacX64.stdout, /syscall/i);

      // ----------------------------------------------------------------------
      // #5 Universal .uapp — WebAssembly.validate + Python zipfile oracle
      // ----------------------------------------------------------------------
      const uappId = `com.omnios.oracle.uapp${nonce}`;
      const wasmBytes = buildCustomWasm({
        message: `ORACLE_WASM_${nonce}\n`,
        exitCode: uappCode,
      });
      assert.equal(WebAssembly.validate(wasmBytes), true, 'Host WebAssembly.validate() must validate generated .wasm');

      const uappBytes = buildCustomUapp({
        appId: uappId,
        name: `OracleUapp_${nonce}`,
        wasmBytes,
      });
      const uappPath = path.join(tmp.dir, `oracle-${nonce}.uapp`);
      await fs.writeFile(uappPath, uappBytes);

      const pyUapp = await runPython(
        `
import sys, zipfile, json
uapp_path, expected_id = sys.argv[1:3]
with zipfile.ZipFile(uapp_path, 'r') as zf:
    assert zf.testzip() is None, 'UAPP ZIP CRC check failed'
    mf = json.loads(zf.read('manifest.json').decode('utf-8'))
    wasm = zf.read('app.wasm')
assert mf['id'] == expected_id and mf['entry'] == 'app.wasm'
assert wasm[:4] == b'\\x00asm', f'Bad WASM magic: {wasm[:4]!r}'
print(json.dumps({'ok': True}))
        `,
        [uappPath, uappId]
      );
      assert.equal(pyUapp.code, 0, `Python .uapp oracle failed: ${pyUapp.stderr}`);

      // ----------------------------------------------------------------------
      // Install ALL 5 verified custom binaries via ospm & execute LIVE in OmniOS
      // ----------------------------------------------------------------------
      const instAnd = await stageInspectInstall(osHandle, apkBytes, `oracle-and-${nonce}.apk`, 'android-apk', 'android');
      const instWin = await stageInspectInstall(osHandle, peBytes, `oracle-win-${nonce}.exe`, 'windows-pe', 'windows');
      const instIos = await stageInspectInstall(osHandle, ipaBytes, `oracle-ios-${nonce}.ipa`, 'ios-ipa', 'ios');
      const instMac = await stageInspectInstall(osHandle, macZipBytes, `oracle-mac-${nonce}.app.zip`, 'macos-app', 'macos');
      const instUapp = await stageInspectInstall(osHandle, uappBytes, `oracle-uapp-${nonce}.uapp`, 'universal-uapp', 'universal');

      // Execute Android (.apk)
      const lAnd = await pkgManager.launch(instAnd.appId, {});
      spawnedPids.add(lAnd.pid);
      const andOutPath = `/home/user/Documents/oracle-and-${nonce}.txt`;
      for (let i = 0; i < 400; i++) {
        await scheduler.step(10);
        if (isDoneState(pm.get(lAnd.pid)?.state)) break;
        if (extractInstructions(pm.get(lAnd.pid)) > 0 && (await vfsFileExists(vfs, andOutPath))) break;
      }
      assert.ok(extractInstructions(pm.get(lAnd.pid)) > 0, 'Android oracle APK must execute Dalvik instructions');
      assert.equal(
        (await readVfsText(vfs, andOutPath)).trim(),
        String(andProd),
        `Android Dalvik mul-int must compute ${andA}*${andB}=${andProd} dynamically into VFS`
      );
      const andSp = await configStore.sharedPrefs.getAll(instAnd.appId, 'oracle_sp');
      assert.equal(andSp?.tok, `SP_${nonce}`);
      const andWin = (compositor.getSnapshot().windows ?? []).find((w) => w.pid === lAnd.pid || w.appId === instAnd.appId);
      assert.ok(andWin && JSON.stringify(getUiTree(andWin)).includes(String(andProd)), 'Android TextView uiTree must display computed product');

      // Execute Windows PE32+ (.exe)
      const lWin = await pkgManager.launch(instWin.appId, {});
      spawnedPids.add(lWin.pid);
      const pcbWin = await runPidToDone(osHandle, lWin.pid);
      assert.ok(isDoneState(pcbWin?.state));
      assert.ok(extractInstructions(pcbWin) > 0);
      assert.ok(extractStdout(pcbWin).includes(`ORACLE_PE64_${nonce}`));
      assert.equal(extractExitCode(pcbWin), winSum, `PE32+ x86-64 must compute ${winA}+${winB}=${winSum}`);
      assert.equal((await readVfsText(vfs, `/home/user/Documents/oracle-win-${nonce}.txt`)).trim(), `WIN_ORACLE_${nonce}`);
      const winReg = await configStore.registry.getValue('HKCU', `Software\\OmniOracle\\Run_${nonce}`, 'OracleKey', { uid: 0 });
      assert.equal(String(winReg?.data ?? '').replace(/\0+$/, ''), `REG_ORACLE_${nonce}`);

      // Execute iOS (.ipa with custom ARM64 add x5, x3, x4)
      const lIos = await pkgManager.launch(instIos.appId, {});
      spawnedPids.add(lIos.pid);
      const pcbIos = await runPidToDone(osHandle, lIos.pid);
      assert.ok(isDoneState(pcbIos?.state));
      assert.ok(extractInstructions(pcbIos) > 0);
      assert.ok(extractStdout(pcbIos).includes(`ORACLE_IOS_${nonce}`), `iOS ARM64 stdout missing nonce: ${extractStdout(pcbIos)}`);
      assert.equal(extractExitCode(pcbIos), iosSum, `iOS ARM64 add x5, x3, x4 must compute ${iosA}+${iosB}=${iosSum}`);

      // Execute macOS Universal Fat (.app.zip) + Python plistlib XML defaults verification
      const lMac = await pkgManager.launch(instMac.appId, {});
      spawnedPids.add(lMac.pid);
      const pcbMac = await runPidToDone(osHandle, lMac.pid);
      assert.ok(isDoneState(pcbMac?.state));
      assert.ok(extractInstructions(pcbMac) > 0);
      assert.equal(extractExitCode(pcbMac), macCode);
      assert.equal((await readVfsText(vfs, `/home/user/Documents/oracle-mac-${nonce}.txt`)).trim(), macFileContent);

      await configStore.defaults.set(macBundle, 'oracleNonce', nonce);
      const exportedXml = await configStore.defaults.exportPlistXml(macBundle);
      const pyDef = await runPython(
        'import sys, plistlib, json; print(json.dumps(plistlib.loads(sys.stdin.buffer.read())))',
        [],
        { stdin: Buffer.from(exportedXml, 'utf8') }
      );
      assert.equal(pyDef.code, 0, `Python plistlib failed parsing exported NSUserDefaults XML: ${pyDef.stderr}`);
      assert.equal(JSON.parse(pyDef.stdout).oracleNonce, nonce, 'Exported Apple XML plist round-trip mismatch');

      // Execute Universal WASM (.uapp)
      const lUapp = await pkgManager.launch(instUapp.appId, {});
      spawnedPids.add(lUapp.pid);
      const pcbUapp = await runPidToDone(osHandle, lUapp.pid);
      assert.ok(isDoneState(pcbUapp?.state));
      assert.ok(extractStdout(pcbUapp).includes(`ORACLE_WASM_${nonce}`));
      assert.equal(extractExitCode(pcbUapp), uappCode);
    } finally {
      if (osHandle) {
        for (const pid of spawnedPids) {
          await stopPidBestEffort(osHandle, pid);
        }
        await osHandle.shutdown().catch(() => {});
      }
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });

  it('T4-S02-02 [Scenario 4]: Complete Headless + Remote CLI-Only Operator Lifecycle (os/cli/omnios-cli.mjs)', async () => {
    let sharedData = null;
    let pkgScratch = null;
    let srv = null;
    try {
      // Fail-fast BEFORE creating any temporary directories
      await assertPublicEntryExists(PUBLIC_PATHS.cliEntry, 'os/cli/omnios-cli.mjs');

      sharedData = await createTempDataDir('omnios-s02-clidata-');
      pkgScratch = await createTempDataDir('omnios-s02-clipkg-');
      const nonce = makeNonce(4);

      // ======================================================================
      // Phase A: Standalone Local Headless CLI (--data-dir --json)
      // ======================================================================
      const localOpts = { dataDir: sharedData.dir, json: true, expectZero: true };

      const stLocal = await runCli(['status'], localOpts);
      assert.ok(stLocal.json && /running/i.test(JSON.stringify(stLocal.json)), `CLI status must report RUNNING: ${stLocal.stdout}`);

      const dmLocal = await runCli(['dmesg'], localOpts);
      assert.ok(dmLocal.json !== null && JSON.stringify(dmLocal.json).length > 2, `CLI dmesg must return non-empty JSON: ${dmLocal.stdout}`);

      const svcLocal = await runCli(['services'], localOpts);
      const svcBlob = JSON.stringify(svcLocal.json ?? svcLocal.stdout);
      for (const svcName of ['vfsd', 'configd', 'ipc-brokerd', 'securityd', 'pkgd', 'compositord']) {
        assert.ok(svcBlob.includes(svcName), `CLI services missing core daemon "${svcName}": ${svcBlob}`);
      }

      // VFS write/cat/resolve
      const vfsDir = `/home/user/Documents/cli-${nonce}`;
      const vfsFile = `${vfsDir}/ops.txt`;
      await runCli(['vfs', 'mkdir', vfsDir], localOpts);
      await runCli(['vfs', 'write', vfsFile, `CLI_LOCAL_${nonce}`], localOpts);
      const vfsCat = await runCli(['vfs', 'cat', vfsFile], localOpts);
      assert.ok(vfsCat.stdout.includes(`CLI_LOCAL_${nonce}`), `CLI vfs cat mismatch: ${vfsCat.stdout}`);

      const vfsRes = await runCli(['vfs', 'resolve', `C:\\Users\\user\\Documents\\cli-${nonce}\\ops.txt`, '--platform', 'windows'], localOpts);
      assert.ok(vfsRes.stdout.includes(vfsFile), `CLI vfs resolve must map Windows path to ${vfsFile}: ${vfsRes.stdout}`);

      // Registry (probe combined HKCU\SubKey vs split HKCU SubKey REG_SZ shapes)
      const regSubKey = `Software\\OmniCliOps\\${nonce}`;
      const regCombined = `HKCU\\${regSubKey}`;
      let regSet = await runCli(['reg', 'set', regCombined, 'OpTag', `REG_CLI_${nonce}`], { dataDir: sharedData.dir, json: true });
      let usedSplitReg = false;
      if (!regSet.ok) {
        regSet = await runCli(['reg', 'set', 'HKCU', regSubKey, 'OpTag', 'REG_SZ', `REG_CLI_${nonce}`], { dataDir: sharedData.dir, json: true });
        usedSplitReg = true;
      }
      assert.equal(regSet.ok, true, `Local CLI reg set failed: ${regSet.stdout} ${regSet.stderr}`);

      const regGetArgs = usedSplitReg ? ['reg', 'get', 'HKCU', regSubKey, 'OpTag'] : ['reg', 'get', regCombined, 'OpTag'];
      const regGetLocal = await runCli(regGetArgs, localOpts);
      assert.ok(regGetLocal.stdout.includes(`REG_CLI_${nonce}`), `Local CLI reg get mismatch: ${regGetLocal.stdout}`);

      const regListArgs = usedSplitReg ? ['reg', 'list', 'HKCU', regSubKey] : ['reg', 'list', regCombined];
      const regListLocal = await runCli(regListArgs, localOpts);
      assert.ok(
        regListLocal.stdout.includes('OpTag') || regListLocal.stdout.includes(`REG_CLI_${nonce}`),
        `Local CLI reg list mismatch: ${regListLocal.stdout}`
      );

      // Apple Defaults
      const defDomain = `com.omnios.cliops.${nonce}`;
      await runCli(['defaults', 'write', defDomain, 'OpKey', `DEF_CLI_${nonce}`], localOpts);
      const defReadLocal = await runCli(['defaults', 'read', defDomain, 'OpKey'], localOpts);
      assert.ok(defReadLocal.stdout.includes(`DEF_CLI_${nonce}`), `Local CLI defaults read mismatch: ${defReadLocal.stdout}`);

      // Android SharedPreferences (probe 4-arg vs 3-arg CLI shape)
      const prefPkg = `com.omnios.cliops.sp${nonce}`;
      let prefSet = await runCli(['prefs', 'set', prefPkg, 'ops_prefs', 'OpPref', `PREF_CLI_${nonce}`], { dataDir: sharedData.dir, json: true });
      let usedShortPrefs = false;
      if (!prefSet.ok) {
        prefSet = await runCli(['prefs', 'set', prefPkg, 'OpPref', `PREF_CLI_${nonce}`], { dataDir: sharedData.dir, json: true });
        usedShortPrefs = true;
      }
      assert.equal(prefSet.ok, true, `Local CLI prefs set failed: ${prefSet.stdout} ${prefSet.stderr}`);

      const prefGetArgs = usedShortPrefs ? ['prefs', 'get', prefPkg, 'OpPref'] : ['prefs', 'get', prefPkg, 'ops_prefs'];
      const prefGetLocal = await runCli(prefGetArgs, localOpts);
      assert.ok(prefGetLocal.stdout.includes(`PREF_CLI_${nonce}`), `Local CLI prefs get mismatch: ${prefGetLocal.stdout}`);

      // Local ospm inspect / install / list on custom .uapp
      const uappId = `com.omnios.cliops.uapp${nonce}`;
      const uappScheme = `cliops${nonce}`;
      const localUappPath = path.join(pkgScratch.dir, `local-${nonce}.uapp`);
      await fs.writeFile(
        localUappPath,
        buildCustomUapp({
          appId: uappId,
          name: `CliOpsUapp_${nonce}`,
          urlSchemes: [uappScheme],
          message: `CLIOPS_WASM_${nonce}\n`,
          exitCode: 0,
        })
      );

      const inspLocal = await runCli(['ospm', 'inspect', localUappPath], localOpts);
      assert.equal(inspLocal.json?.appId, uappId, `Local CLI ospm inspect appId mismatch: ${inspLocal.stdout}`);

      await runCli(['ospm', 'install', localUappPath], localOpts);
      const listLocal = await runCli(['ospm', 'list'], localOpts);
      const listLocalArr = unwrapExplicitArray(listLocal.json, ['packages', 'items', 'data']);
      assert.ok(listLocalArr !== null, `Local CLI ospm list must return JSON array: ${listLocal.stdout}`);
      assert.ok(
        listLocalArr.some((p) => (p?.appId ?? p?.id ?? p) === uappId),
        `Local CLI ospm list missing ${uappId}: ${listLocal.stdout}`
      );

      // ======================================================================
      // Phase B: Boot Live Daemon via CLI (`omnios-cli.mjs boot`) & Full --remote Lifecycle
      // ======================================================================
      srv = await startOmniServer({ mode: 'cli', dataDir: sharedData.dir, keepDataDir: true });
      const remoteOpts = { json: true, expectZero: true };

      // Verify Phase-A persistence across headless -> CLI-booted daemon transition
      const stRemote = await srv.runCli(['status'], remoteOpts);
      assert.ok(stRemote.json && /running/i.test(JSON.stringify(stRemote.json)));
      const dmRemote = await srv.runCli(['dmesg'], remoteOpts);
      assert.ok(dmRemote.json !== null);
      const svcRemote = await srv.runCli(['services'], remoteOpts);
      assert.ok(JSON.stringify(svcRemote.json ?? svcRemote.stdout).includes('vfsd'));

      const vfsCatRemote = await srv.runCli(['vfs', 'cat', vfsFile], remoteOpts);
      assert.ok(vfsCatRemote.stdout.includes(`CLI_LOCAL_${nonce}`), 'Phase-A VFS file must persist into CLI-booted daemon');
      const regGetRemote = await srv.runCli(regGetArgs, remoteOpts);
      assert.ok(regGetRemote.stdout.includes(`REG_CLI_${nonce}`), 'Phase-A Registry value must persist into CLI-booted daemon');
      const defReadRemote = await srv.runCli(['defaults', 'read', defDomain, 'OpKey'], remoteOpts);
      assert.ok(defReadRemote.stdout.includes(`DEF_CLI_${nonce}`), 'Phase-A Defaults value must persist into CLI-booted daemon');
      const prefGetRemote = await srv.runCli(prefGetArgs, remoteOpts);
      assert.ok(prefGetRemote.stdout.includes(`PREF_CLI_${nonce}`), 'Phase-A SharedPrefs value must persist into CLI-booted daemon');

      const listRemote0 = await srv.runCli(['ospm', 'list'], remoteOpts);
      const listRemote0Arr = unwrapExplicitArray(listRemote0.json, ['packages', 'items', 'data']);
      assert.ok(listRemote0Arr !== null, `Remote ospm list must return JSON array: ${listRemote0.stdout}`);
      assert.ok(
        listRemote0Arr.some((p) => (p?.appId ?? p?.id ?? p) === uappId),
        `Phase-A package ${uappId} must persist into CLI-booted daemon`
      );

      // Remote ospm lifecycle with persistent Android .apk so PID stays alive for `ps` + `ospm stop`
      const apkId = `com.omnios.cliops.apk${nonce}`;
      const remoteApkPath = path.join(pkgScratch.dir, `remote-${nonce}.apk`);
      await fs.writeFile(
        remoteApkPath,
        buildCustomApk({
          packageName: apkId,
          appLabel: `CliOpsApk_${nonce}`,
          computeA: 17,
          computeB: 25,
          computeOp: 'add',
        })
      );

      const inspApk = await srv.runCli(['ospm', 'inspect', remoteApkPath], remoteOpts);
      assert.equal(inspApk.json?.appId, apkId, `Remote ospm inspect appId mismatch: ${inspApk.stdout}`);
      assert.equal(inspApk.json?.format, 'android-apk', `Remote ospm inspect format mismatch: ${inspApk.stdout}`);

      await srv.runCli(['ospm', 'install', remoteApkPath], remoteOpts);
      const listWithApk = await srv.runCli(['ospm', 'list'], remoteOpts);
      const listWithApkArr = unwrapExplicitArray(listWithApk.json, ['packages', 'items', 'data']);
      assert.ok(listWithApkArr !== null && listWithApkArr.some((p) => (p?.appId ?? p?.id ?? p) === apkId));

      const launchApk = await srv.runCli(['ospm', 'launch', apkId], remoteOpts);
      const apkPid = launchApk.json?.pid ?? launchApk.json?.process?.pid;
      assert.ok(Number.isInteger(apkPid) && apkPid > 1, `Expected valid PID > 1 launching ${apkId}: ${launchApk.stdout}`);

      const psRes = await srv.runCli(['ps'], remoteOpts);
      const psArr = unwrapExplicitArray(psRes.json, ['processes', 'items', 'data']);
      assert.ok(psArr !== null, `Remote CLI ps must return JSON array: ${psRes.stdout}`);
      assert.ok(psArr.some((p) => p?.pid === apkPid), `Remote CLI ps missing live PID ${apkPid}: ${psRes.stdout}`);

      await srv.runCli(['ospm', 'stop', apkId], remoteOpts);
      await srv.runCli(['ospm', 'uninstall', apkId], remoteOpts);

      const listNoApk = await srv.runCli(['ospm', 'list'], remoteOpts);
      const listNoApkArr = unwrapExplicitArray(listNoApk.json, ['packages', 'items', 'data']);
      assert.ok(listNoApkArr !== null, `Remote ospm list after uninstall must return JSON array: ${listNoApk.stdout}`);
      assert.equal(
        listNoApkArr.some((p) => (p?.appId ?? p?.id ?? p) === apkId),
        false,
        `Uninstalled package ${apkId} must be absent from ospm list array`
      );
      assert.equal(
        listNoApk.stdout.includes(apkId),
        false,
        `Uninstalled package ${apkId} must not appear anywhere in ospm list stdout`
      );

      // Remote clipboard
      await srv.runCli(['clipboard', 'set', `CLI_CLIP_${nonce}`], remoteOpts);
      const clipGet = await srv.runCli(['clipboard', 'get'], remoteOpts);
      assert.ok(clipGet.stdout.includes(`CLI_CLIP_${nonce}`), `Remote clipboard get mismatch: ${clipGet.stdout}`);

      // Remote notifications send -> list -> dismiss -> verify absent
      const notifSend = await srv.runCli(['notify', 'send', `CliAlert_${nonce}`, `CliBody_${nonce}`], remoteOpts);
      const notifList1 = await srv.runCli(['notify', 'list'], remoteOpts);
      assert.ok(notifList1.stdout.includes(`CliAlert_${nonce}`), `Remote notify list missing CliAlert_${nonce}: ${notifList1.stdout}`);
      const notifArr1 = unwrapExplicitArray(notifList1.json, ['notifications', 'items', 'data']) ?? [];
      const notifId =
        notifSend.json?.id ??
        notifSend.json?.notification?.id ??
        notifArr1.find((n) => String(n?.title ?? '').includes(`CliAlert_${nonce}`))?.id;
      assert.ok(notifId, `Could not extract notification ID from CLI output: ${notifSend.stdout} / ${notifList1.stdout}`);

      await srv.runCli(['notify', 'dismiss', String(notifId)], remoteOpts);
      const notifList2 = await srv.runCli(['notify', 'list'], remoteOpts);
      const notifArr2 = unwrapExplicitArray(notifList2.json, ['notifications', 'items', 'data']);
      assert.ok(notifArr2 !== null, `Remote notify list after dismiss must return JSON array: ${notifList2.stdout}`);
      assert.equal(
        notifArr2.some((n) => String(n?.id) === String(notifId) && !n?.dismissed),
        false,
        `Dismissed notification ${notifId} must be absent from active notify list: ${notifList2.stdout}`
      );

      // Remote intent resolve & dispatch (positional URI with --scheme fallback)
      let intResolve = await srv.runCli(['intent', 'resolve', `${uappScheme}://open`], { json: true });
      if (!intResolve.ok || !intResolve.stdout.includes(uappId)) {
        intResolve = await srv.runCli(['intent', 'resolve', '--scheme', uappScheme], { json: true });
      }
      assert.equal(intResolve.ok, true, `Remote intent resolve failed: ${intResolve.stdout} ${intResolve.stderr}`);
      assert.ok(intResolve.stdout.includes(uappId), `Remote intent resolve must include ${uappId}: ${intResolve.stdout}`);

      let intDispatch = await srv.runCli(['intent', 'dispatch', `${uappScheme}://open`], { json: true });
      if (!intDispatch.ok) {
        intDispatch = await srv.runCli(['intent', 'dispatch', '--scheme', uappScheme], { json: true });
      }
      assert.equal(intDispatch.ok, true, `Remote intent dispatch failed: ${intDispatch.stdout} ${intDispatch.stderr}`);
      assert.ok(
        intDispatch.stdout.includes('DELIVERED') || intDispatch.stdout.includes(uappId),
        `Remote intent dispatch must deliver to ${uappId}: ${intDispatch.stdout}`
      );

      // Remote piped shell exec (strictly inspect stdout/output fields, never echoed `command`)
      const execRes = await srv.runCli(['exec', `cat ${vfsFile} | grep CLI_LOCAL_${nonce}`], remoteOpts);
      const execOut = typeof execRes.json === 'string'
        ? execRes.json
        : String(
            execRes.json?.stdout ??
            execRes.json?.output ??
            execRes.json?.data?.stdout ??
            execRes.json?.data?.output ??
            execRes.json?.result?.stdout ??
            execRes.json?.result?.output ??
            (typeof execRes.json?.result === 'string' ? execRes.json.result : undefined) ??
            (execRes.json && typeof execRes.json === 'object' ? '' : execRes.stdout)
          );
      assert.ok(
        execOut.includes(`CLI_LOCAL_${nonce}`),
        `Remote piped shell exec output missing CLI_LOCAL_${nonce}: ${execRes.stdout}`
      );

      // Cleanly uninstall uappId and verify strict removal
      await srv.runCli(['ospm', 'uninstall', uappId], remoteOpts);
      const listFinal = await srv.runCli(['ospm', 'list'], remoteOpts);
      const listFinalArr = unwrapExplicitArray(listFinal.json, ['packages', 'items', 'data']);
      assert.ok(listFinalArr !== null, `Final ospm list must return JSON array: ${listFinal.stdout}`);
      assert.equal(listFinalArr.some((p) => (p?.appId ?? p?.id ?? p) === uappId), false);
      assert.equal(listFinal.stdout.includes(uappId), false);
    } finally {
      if (srv) await srv.stop().catch(() => {});
      if (pkgScratch) await pkgScratch.cleanup().catch(() => {});
      if (sharedData) await sharedData.cleanup().catch(() => {});
    }
  });
});
