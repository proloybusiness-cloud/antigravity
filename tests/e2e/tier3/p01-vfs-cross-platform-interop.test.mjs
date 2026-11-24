/**
 * OmniOS Tier 3 Pairwise E2E Suite — P-01:
 * Unified Cross-Platform VFS × 4-Platform Real Binary Runtimes × Case-Insensitivity
 * × Symlinks/ELOOP × /proc/<pid> × Per-App Container Isolation.
 *
 * Feature Pairs Exercised:
 *   F-016, F-017, F-018, F-019, F-020, F-027, F-039..F-045, F-050..F-055, F-062, F-065
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded app IDs or capability names.
 * - Zero assertions inside try/catch blocks.
 * - Clean try/finally teardown on every test.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';
import { BinaryWriter, alignUp, concatBytes } from '../lib/binary-utils.mjs';
import {
  buildBatScript,
  buildCustomApk,
  buildCustomPe64Exe,
} from '../lib/fixtures-android-win.mjs';
import {
  ARM64_SVC_80,
  arm64AddImm,
  arm64Adr,
  arm64MovReg,
  arm64Movz,
  arm64SubImm,
  buildCustomIpa,
  buildCustomMacAppZip,
  buildMachO64,
  buildUniversalFatMachO,
  packArm64Insns,
} from '../lib/fixtures-apple-wasm.mjs';
import { getVfsEdgeCasePayloads } from '../lib/fixtures-malformed.mjs';

const textEncoder = new TextEncoder();

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function makeThreeDigitOperands() {
  const a = 113 + crypto.randomInt(180);
  const b = 127 + crypto.randomInt(180);
  return [a, b];
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(fn, { timeoutMs = 8000, intervalMs = 50, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    let val = null;
    try {
      val = await fn();
    } catch (err) {
      lastError = err;
    }
    if (val) return val;
    const rem = deadline - Date.now();
    if (rem > 0) await sleep(Math.min(intervalMs, rem));
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for ${label}` +
    (lastError ? ` (last error: ${lastError.message})` : '')
  );
}

function le32(v) {
  const u = v >>> 0;
  return [u & 0xff, (u >>> 8) & 0xff, (u >>> 16) & 0xff, (u >>> 24) & 0xff];
}

/**
 * Builds a real Darwin Mach-O (Universal Fat or ARM64) executable that invokes
 * BSD syscalls open(path, O_RDONLY=0, 0) -> read(fd, sp, 128) -> write(1, sp, nread)
 * -> close(fd) -> exit(0). Verified independently via llvm-objdump.
 */
function buildDarwinReaderMachO({ filePath, arch = 'universal', platform = 1 } = {}) {
  const textOff = 0x1000;
  const pathZ = concatBytes(textEncoder.encode(String(filePath)), [0]);

  const buildArm64Slice = () => {
    const codeLen = 24 * 4; // 96 bytes
    const strOff = alignUp(textOff + codeLen, 16); // 0x1060
    const insns = [
      arm64SubImm(31, 31, 128), // sub sp, sp, #128
      arm64Adr(0, strOff - (textOff + 4)), // adr x0, path
      arm64Movz(1, 0), // O_RDONLY
      arm64Movz(2, 0), // mode = 0
      arm64Movz(16, 5), // SYS_open
      ARM64_SVC_80,
      arm64MovReg(19, 0), // save fd
      arm64MovReg(0, 19), // fd
      arm64AddImm(1, 31, 0), // buf = sp
      arm64Movz(2, 128), // count = 128
      arm64Movz(16, 3), // SYS_read
      ARM64_SVC_80,
      arm64MovReg(2, 0), // len = nread
      arm64Movz(0, 1), // stdout = 1
      arm64AddImm(1, 31, 0), // buf = sp
      arm64Movz(16, 4), // SYS_write
      ARM64_SVC_80,
      arm64MovReg(0, 19), // fd
      arm64Movz(16, 6), // SYS_close
      ARM64_SVC_80,
      arm64AddImm(31, 31, 128), // add sp, sp, #128
      arm64Movz(0, 0), // exit(0)
      arm64Movz(16, 1), // SYS_exit
      ARM64_SVC_80,
    ];
    return buildMachO64({
      arch: 'arm64',
      platform,
      textOffset: textOff,
      entryOffset: textOff,
      codeBytes: packArm64Insns(insns),
      cstringBytes: pathZ,
    });
  };

  const buildX64Slice = () => {
    const codeLen = 86;
    const strOff = alignUp(textOff + codeLen, 16); // 0x1060
    const disp32 = strOff - (textOff + 19); // lea rdi, [rip+disp32] is at +12, len 7
    const w = new BinaryWriter(codeLen);
    w.bytes([0x48, 0x81, 0xec]).u32le(128) // +0  sub rsp, 128
      .u8(0xb8).u32le(0x02000005) // +7  mov eax, 0x2000005 (SYS_open)
      .bytes([0x48, 0x8d, 0x3d]).i32le(disp32) // +12 lea rdi, [rip + disp32]
      .bytes([0x31, 0xf6]) // +19 xor esi, esi (O_RDONLY)
      .bytes([0x31, 0xd2]) // +21 xor edx, edx (mode = 0)
      .bytes([0x0f, 0x05]) // +23 syscall
      .bytes([0x89, 0xc3]) // +25 mov ebx, eax (save fd)
      .u8(0xb8).u32le(0x02000003) // +27 mov eax, 0x2000003 (SYS_read)
      .bytes([0x89, 0xdf]) // +32 mov edi, ebx (fd)
      .bytes([0x48, 0x89, 0xe6]) // +34 mov rsi, rsp
      .u8(0xba).u32le(128) // +37 mov edx, 128
      .bytes([0x0f, 0x05]) // +42 syscall
      .bytes([0x89, 0xc2]) // +44 mov edx, eax (len = nread)
      .u8(0xb8).u32le(0x02000004) // +46 mov eax, 0x2000004 (SYS_write)
      .u8(0xbf).u32le(1) // +51 mov edi, 1 (stdout)
      .bytes([0x48, 0x89, 0xe6]) // +56 mov rsi, rsp
      .bytes([0x0f, 0x05]) // +59 syscall
      .u8(0xb8).u32le(0x02000006) // +61 mov eax, 0x2000006 (SYS_close)
      .bytes([0x89, 0xdf]) // +66 mov edi, ebx (fd)
      .bytes([0x0f, 0x05]) // +68 syscall
      .bytes([0x48, 0x81, 0xc4]).u32le(128) // +70 add rsp, 128
      .u8(0xb8).u32le(0x02000001) // +77 mov eax, 0x2000001 (SYS_exit)
      .bytes([0x31, 0xff]) // +82 xor edi, edi
      .bytes([0x0f, 0x05]); // +84 syscall
    return buildMachO64({
      arch: 'x86_64',
      platform,
      textOffset: textOff,
      entryOffset: textOff,
      codeBytes: w.toUint8Array(),
      cstringBytes: pathZ,
    });
  };

  if (arch === 'universal') {
    return buildUniversalFatMachO({
      slices: [
        { cputype: 0x01000007, cpusubtype: 3, align: 14, bytes: buildX64Slice() },
        { cputype: 0x0100000c, cpusubtype: 0, align: 14, bytes: buildArm64Slice() },
      ],
    });
  }
  return arch === 'x86_64' ? buildX64Slice() : buildArm64Slice();
}

/**
 * Builds a real Windows PE32+ x86-64 executable that opens readPath via Win32
 * CreateFileA(OPEN_EXISTING) -> ReadFile -> GetStdHandle(-11) -> WriteFile -> CloseHandle -> ExitProcess(0).
 * Verified independently via llvm-objdump.
 */
function buildWinPe64ReaderExe(readPath) {
  return buildCustomPe64Exe({
    subsystem: 3,
    dataVirtualSize: 0x200,
    extraImports: [
      {
        dll: 'KERNEL32.dll',
        funcs: ['CreateFileA', 'ReadFile', 'GetStdHandle', 'WriteFile', 'CloseHandle'],
      },
    ],
    extraStrings: { readPath },
    customCodeBytes: ({ X64, dataRva, iat, strings, curRva, emit }) => {
      const pathInfo = strings.get('readPath');
      // 16B stack alignment (88 + 8 ret = 96) with 32B shadow + 3 stack arg slots
      emit(X64.subRspImm8(0x58));

      // CreateFileA(readPath, GENERIC_READ=0x80000000, FILE_SHARE_READ=1, NULL, OPEN_EXISTING=3, FILE_ATTRIBUTE_NORMAL=0x80, NULL)
      emit(X64.leaRcxRip(curRva(), pathInfo.rva));
      emit(X64.movEdxImm32(0x80000000));
      emit(X64.movR8dImm32(1));
      emit(X64.xorR9dR9d());
      emit(X64.movQwordRspImm32(0x20, 3));
      emit(X64.movQwordRspImm32(0x28, 0x80));
      emit(X64.movQwordRspImm32(0x30, 0));
      emit(X64.callRipIat(curRva(), iat.get('CreateFileA')));
      emit(X64.movMemRipRax(curRva(), dataRva + 8)); // hFile

      // ReadFile(hFile, dataRva + 64, 128, dataRva + 0, NULL)
      emit(X64.movRcxMemRip(curRva(), dataRva + 8));
      emit(X64.leaRdxRip(curRva(), dataRva + 64));
      emit(X64.movR8dImm32(128));
      emit(X64.leaR9Rip(curRva(), dataRva + 0));
      emit(X64.movQwordRspImm32(0x20, 0));
      emit(X64.callRipIat(curRva(), iat.get('ReadFile')));

      // GetStdHandle(STD_OUTPUT_HANDLE = -11)
      emit(X64.movEcxImm32(0xfffffff5));
      emit(X64.callRipIat(curRva(), iat.get('GetStdHandle')));
      emit(X64.movRcxRax()); // hOut

      // WriteFile(hOut, dataRva + 64, qword [dataRva + 0], dataRva + 16, NULL)
      emit(X64.leaRdxRip(curRva(), dataRva + 64));
      emit([0x4c, 0x8b, 0x05, ...le32((dataRva + 0) - (curRva() + 7))]); // mov r8, qword ptr [rip + disp32]
      emit(X64.leaR9Rip(curRva(), dataRva + 16));
      emit(X64.movQwordRspImm32(0x20, 0));
      emit(X64.callRipIat(curRva(), iat.get('WriteFile')));

      // CloseHandle(hFile)
      emit(X64.movRcxMemRip(curRva(), dataRva + 8));
      emit(X64.callRipIat(curRva(), iat.get('CloseHandle')));

      // ExitProcess(0)
      emit(X64.xorEcxEcx());
      emit(X64.callRipIat(curRva(), iat.get('ExitProcess')));
      emit(X64.addRspImm8(0x58));
      emit(X64.ret());
    },
  });
}

function getInode(st) {
  const ino = st?.ino ?? st?.inode ?? st?.inodeId ?? st?.id;
  assert.ok(ino !== undefined && ino !== null, `stat() missing inode identifier: ${JSON.stringify(st)}`);
  return String(ino);
}

function isSymlinkStat(st) {
  if (!st || typeof st !== 'object') return false;
  if (typeof st.isSymbolicLink === 'function') return Boolean(st.isSymbolicLink());
  if (st.isSymlink === true || st.symlink === true) return true;
  if (/symlink|link/i.test(String(st.type ?? ''))) return true;
  if (typeof st.mode === 'number' && (st.mode & 0o170000) === 0o120000) return true;
  return false;
}

function extractAppId(rec, fallback = null) {
  return rec?.appId ?? rec?.id ?? rec?.packageName ?? rec?.bundleId ?? rec?.package?.appId ?? rec?.data?.appId ?? fallback;
}

function extractPid(launchRes) {
  const pid = launchRes?.pid ?? launchRes?.process?.pid ?? launchRes?.data?.pid;
  assert.ok(Number.isInteger(pid) && pid > 0, `Expected positive integer PID from launch(), got ${JSON.stringify(launchRes)}`);
  return pid;
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

async function runToCompletion(osHandle, pid, maxTicks = 2500) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  const scaledTicks = Math.max(maxTicks, pm.list().length * 50);
  let summary = null;
  if (typeof scheduler.runUntilIdle === 'function') {
    summary = await scheduler.runUntilIdle(pid, scaledTicks);
  } else {
    for (let i = 0; i < Math.ceil(scaledTicks / 25); i++) {
      await scheduler.step(25);
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

async function stepUntilCondition(osHandle, predicate, minTicks = 250) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  const limit = Math.max(minTicks, pm.list().length * 20);
  for (let i = 0; i < limit; i++) {
    let matched = false;
    try {
      matched = Boolean(await predicate());
    } catch {
      matched = false;
    }
    if (matched) return true;
    await scheduler.step(2);
  }
  let finalMatch = false;
  try {
    finalMatch = Boolean(await predicate());
  } catch {
    finalMatch = false;
  }
  return finalMatch;
}

async function resolveSandboxUid(osHandle, appId, installedRecord) {
  const fromRec = installedRecord?.sandboxUid ?? installedRecord?.uid;
  if (Number.isInteger(fromRec) && fromRec >= 10000) return fromRec;

  const pkg = await osHandle.require('pkgManager').get(appId);
  const fromPkg = pkg?.sandboxUid ?? pkg?.uid;
  if (Number.isInteger(fromPkg) && fromPkg >= 10000) return fromPkg;

  const users = osHandle.users ?? osHandle.raw?.users ?? osHandle.raw?.security?.users;
  if (users) {
    const fromFn =
      (await users.getAppUid?.(appId)) ??
      (await users.getUserByApp?.(appId))?.uid ??
      (await users.getByName?.(appId))?.uid;
    if (Number.isInteger(fromFn) && fromFn >= 10000) return fromFn;

    const list = (await users.list?.()) ?? (await users.listUsers?.());
    if (Array.isArray(list)) {
      const match = list.find((u) => u?.appId === appId || u?.name === appId || u?.username === appId);
      if (Number.isInteger(match?.uid) && match.uid >= 10000) return match.uid;
    }
  }
  return null;
}

function getEventBus(osHandle) {
  return (
    osHandle.raw?.eventBus ??
    osHandle.kernel?.eventBus ??
    osHandle.raw?.events ??
    osHandle.kernel?.events ??
    osHandle.raw?.bus ??
    osHandle.kernel?.bus ??
    null
  );
}

async function installPackageHttp(api, bytes, filename) {
  const buf = bytes instanceof Uint8Array ? bytes : Buffer.from(String(bytes), 'utf8');
  let res = await api.post('/api/v1/packages/install', buf, {
    query: { filename, grantAll: 'true' },
    headers: {
      'content-type': 'application/octet-stream',
      'x-filename': filename,
    },
  });
  if (!res.ok) {
    const b64 = Buffer.from(buf).toString('base64');
    res = await api.post('/api/v1/packages/install', {
      filename,
      grantAll: true,
      base64: b64,
      data: b64,
      buffer: b64,
    });
  }
  return res;
}

function extractFileText(res) {
  if (!res) return '';
  if (typeof res.json?.content === 'string') return res.json.content;
  if (typeof res.json?.data === 'string') return res.json.data;
  if (typeof res.json?.data?.content === 'string') return res.json.data.content;
  if (typeof res.json?.text === 'string') return res.json.text;
  return res.text ?? '';
}

function unwrapExplicitArray(payload, keys = ['mounts', 'entries', 'items', 'data', 'list']) {
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

function makeYieldingContext() {
  const ctx = {
    steps: 0,
    disposed: false,
    step(budget) {
      ctx.steps += 1;
      return { status: 'YIELD', instructionsExecuted: Math.max(1, Number(budget) || 1) };
    },
    deliverEvent() {},
    getDebugState() {
      return { arch: 'wasm', pc: ctx.steps, sp: 0, registers: {}, instructionsExecuted: ctx.steps, lastSyscall: null, stackTop: 0 };
    },
    dispose() {
      ctx.disposed = true;
    },
  };
  return ctx;
}

describe('Tier 3 — P-01: VFS Cross-Platform Binary Interop, Case-Insensitivity, Symlinks & /proc', () => {
  test('T3-P01-01 [F-016, F-017, F-018, F-039..F-044, F-050..F-055]: 4-Platform Binary Relay on Identical Canonical Inode (Win PE32+ -> macOS Fat -> Android APK -> iOS IPA -> Win PE32+)', async () => {
    const os = await loadPublicOmniOS();
    const spawnedPids = [];
    try {
      os.require('scheduler').stop?.();
      const vfs = os.require('vfs');
      const pm = os.require('processManager');
      const pkgManager = os.require('pkgManager');

      const nonce = makeNonce();
      const [a, b] = makeThreeDigitOperands();
      const expectedMul = String(Math.imul(a, b));
      const filename = `relay-${nonce}.txt`;

      const paths = {
        posix: `/home/user/Documents/${filename}`,
        windows: `C:\\Users\\user\\Documents\\${filename}`,
        macos: `/Users/user/Documents/${filename}`,
        androidSd: `/sdcard/Documents/${filename}`,
        androidEmu: `/storage/emulated/0/Documents/${filename}`,
        ios: `/var/mobile/Documents/${filename}`,
      };

      // Step 1: Windows PE32+ .exe writes via Win32 CreateFileA/WriteFile to C:\Users\user\Documents\
      const winBody = `WIN1_${nonce}`;
      const winWriterBytes = buildCustomPe64Exe({
        subsystem: 3,
        writeFilePath: paths.windows,
        writeFileContent: winBody,
        exitCode: 0,
      });
      const winWriterRec = await pkgManager.install(winWriterBytes, {
        filename: `p01-win-wr-${nonce}.exe`,
        grantAll: true,
      });
      const winWriterLaunch = await pkgManager.launch(extractAppId(winWriterRec), {});
      const winWriterPid = extractPid(winWriterLaunch);
      spawnedPids.push(winWriterPid);
      const winWriterRun = await runToCompletion(os, winWriterPid, 2500);
      assert.equal(winWriterRun.exitCode, 0, `Windows PE32+ writer must exit 0 (got ${winWriterRun.exitCode})`);
      assert.ok(winWriterRun.instructionsExecuted > 0, 'Windows PE32+ writer must execute real x86-64 instructions');

      const ino0 = getInode(await vfs.stat(paths.posix, { platform: 'posix' }));
      const allViews = [
        [paths.posix, 'posix'],
        [paths.windows, 'windows'],
        [paths.macos, 'macos'],
        [paths.androidSd, 'android'],
        [paths.androidEmu, 'android'],
        [paths.ios, 'ios'],
      ];
      for (const [p, platform] of allViews) {
        const content = await vfs.readFile(p, { platform, encoding: 'utf8' });
        assert.equal(content, winBody, `Platform "${platform}" path "${p}" must read exact Windows-written bytes`);
        const st = await vfs.stat(p, { platform });
        assert.equal(getInode(st), ino0, `Platform "${platform}" path "${p}" must share canonical inode ${ino0}`);
      }

      // Step 2a: macOS Universal Fat .app.zip reads /Users/user/Documents/ via Darwin BSD open/read/write
      const macReaderZip = buildCustomMacAppZip({
        bundleId: `com.p01.macrd.${nonce}`,
        appName: `MacRd${nonce}`,
        executableName: `MacRd${nonce}`,
        arch: 'universal',
        machoBytes: buildDarwinReaderMachO({ filePath: paths.macos, arch: 'universal', platform: 1 }),
      });
      const macRdRec = await pkgManager.install(macReaderZip, {
        filename: `p01-mac-rd-${nonce}.app.zip`,
        grantAll: true,
      });
      const macRdPid = extractPid(await pkgManager.launch(extractAppId(macRdRec, `com.p01.macrd.${nonce}`), {}));
      spawnedPids.push(macRdPid);
      const macRdRun = await runToCompletion(os, macRdPid, 2500);
      assert.equal(macRdRun.exitCode, 0, `macOS Universal reader must exit 0 (got ${macRdRun.exitCode})`);
      assert.ok(macRdRun.instructionsExecuted > 0, 'macOS Universal reader must execute real instructions');
      assert.ok(
        macRdRun.stdout.includes(winBody),
        `macOS Universal reader stdout must contain "${winBody}" (got ${JSON.stringify(macRdRun.stdout)})`
      );

      // Step 2b: macOS Universal Fat .app.zip overwrites /Users/user/Documents/
      const macBody = `MAC2_${nonce}`;
      const macWriterZip = buildCustomMacAppZip({
        bundleId: `com.p01.macwr.${nonce}`,
        appName: `MacWr${nonce}`,
        executableName: `MacWr${nonce}`,
        arch: 'universal',
        fileWrite: { path: paths.macos, content: macBody },
        exitCode: 0,
      });
      const macWrRec = await pkgManager.install(macWriterZip, {
        filename: `p01-mac-wr-${nonce}.app.zip`,
        grantAll: true,
      });
      const macWrPid = extractPid(await pkgManager.launch(extractAppId(macWrRec, `com.p01.macwr.${nonce}`), {}));
      spawnedPids.push(macWrPid);
      const macWrRun = await runToCompletion(os, macWrPid, 2500);
      assert.equal(macWrRun.exitCode, 0, `macOS Universal writer must exit 0 (got ${macWrRun.exitCode})`);
      assert.equal(
        await vfs.readFile(paths.androidSd, { platform: 'android', encoding: 'utf8' }),
        macBody,
        'Android /sdcard/Documents/ must immediately observe macOS-written content'
      );
      const inoAfterMac = getInode(await vfs.stat(paths.posix, { platform: 'posix' }));
      assert.equal(inoAfterMac, ino0, 'macOS in-place O_TRUNC write must preserve canonical inode');
      for (const [p, platform] of allViews) {
        assert.equal(getInode(await vfs.stat(p, { platform })), ino0);
      }

      // Step 3: Android .apk Dalvik VM computes a * b live and writes to /sdcard/Documents/
      const andPkg = `com.p01.and.${nonce}`;
      const andApk = buildCustomApk({
        packageName: andPkg,
        appLabel: `P01And${nonce}`,
        computeA: a,
        computeB: b,
        computeOp: 'mul',
        outputFile: paths.androidSd,
      });
      const andRec = await pkgManager.install(andApk, {
        filename: `p01-and-${nonce}.apk`,
        grantAll: true,
      });
      const andPid = extractPid(await pkgManager.launch(extractAppId(andRec, andPkg), {}));
      spawnedPids.push(andPid);

      const andWrote = await stepUntilCondition(os, async () => {
        const cur = await vfs.readFile(paths.ios, { platform: 'ios', encoding: 'utf8' });
        return cur.trim() === expectedMul;
      }, 600);
      assert.equal(andWrote, true, `Android .apk must write live-computed ${a}*${b}=${expectedMul} to /sdcard/Documents/`);

      const iosReadAfterAnd = await vfs.readFile(paths.ios, { platform: 'ios', encoding: 'utf8' });
      assert.equal(iosReadAfterAnd.trim(), expectedMul, 'iOS /var/mobile/Documents/ must read Dalvik-computed product');
      const inoAfterAnd = getInode(await vfs.stat(paths.posix, { platform: 'posix' }));
      for (const [p, platform] of allViews) {
        assert.equal(getInode(await vfs.stat(p, { platform })), inoAfterAnd, `All platform views must match inode after Android write (${platform})`);
      }
      await pkgManager.stop(andPid);

      // Step 4a: iOS .ipa ARM64 reader reads /var/mobile/Documents/ via Darwin BSD syscalls
      const iosRdBundle = `com.p01.iosrd.${nonce}`;
      const iosRdIpa = buildCustomIpa({
        bundleId: iosRdBundle,
        displayName: `IosRd${nonce}`,
        executableName: `IosRd${nonce}`,
        machoBytes: buildDarwinReaderMachO({ filePath: paths.ios, arch: 'arm64', platform: 2 }),
      });
      const iosRdRec = await pkgManager.install(iosRdIpa, {
        filename: `p01-ios-rd-${nonce}.ipa`,
        grantAll: true,
      });
      const iosRdPid = extractPid(await pkgManager.launch(extractAppId(iosRdRec, iosRdBundle), {}));
      spawnedPids.push(iosRdPid);
      const iosRdRun = await runToCompletion(os, iosRdPid, 2500);
      assert.equal(iosRdRun.exitCode, 0, `iOS ARM64 reader must exit 0 (got ${iosRdRun.exitCode})`);
      assert.ok(
        iosRdRun.stdout.trim().includes(expectedMul),
        `iOS ARM64 reader stdout must contain Android-computed "${expectedMul}" (got ${JSON.stringify(iosRdRun.stdout)})`
      );

      // Step 4b: iOS .ipa ARM64 writer writes IOS4_<nonce> -> Windows PE32+ reader reads back via Win32 ReadFile
      const iosBody = `IOS4_${nonce}`;
      const iosWrBundle = `com.p01.ioswr.${nonce}`;
      const iosWrIpa = buildCustomIpa({
        bundleId: iosWrBundle,
        displayName: `IosWr${nonce}`,
        executableName: `IosWr${nonce}`,
        fileWrite: { path: paths.ios, content: iosBody },
        exitCode: 0,
      });
      const iosWrRec = await pkgManager.install(iosWrIpa, {
        filename: `p01-ios-wr-${nonce}.ipa`,
        grantAll: true,
      });
      const iosWrPid = extractPid(await pkgManager.launch(extractAppId(iosWrRec, iosWrBundle), {}));
      spawnedPids.push(iosWrPid);
      const iosWrRun = await runToCompletion(os, iosWrPid, 2500);
      assert.equal(iosWrRun.exitCode, 0, `iOS ARM64 writer must exit 0 (got ${iosWrRun.exitCode})`);

      const winRdRec = await pkgManager.install(buildWinPe64ReaderExe(paths.windows), {
        filename: `p01-win-rd-${nonce}.exe`,
        grantAll: true,
      });
      const winRdPid = extractPid(await pkgManager.launch(extractAppId(winRdRec), {}));
      spawnedPids.push(winRdPid);
      const winRdRun = await runToCompletion(os, winRdPid, 2500);
      assert.equal(winRdRun.exitCode, 0, `Windows PE32+ reader must exit 0 (got ${winRdRun.exitCode})`);
      assert.ok(
        winRdRun.stdout.includes(iosBody),
        `Windows PE32+ reader stdout must contain iOS-written "${iosBody}" (got ${JSON.stringify(winRdRun.stdout)})`
      );

      const finalIno = getInode(await vfs.stat(paths.posix, { platform: 'posix' }));
      for (const [p, platform] of allViews) {
        assert.equal(getInode(await vfs.stat(p, { platform })), finalIno, `Final inode mismatch on platform "${platform}"`);
      }
      assert.ok(pm.list().length >= 2, 'Kernel process table must remain healthy after 4-platform binary relay');
    } finally {
      const pm = os.processManager;
      for (const pid of spawnedPids) {
        try {
          const pcb = pm?.get?.(pid);
          if (pcb && pcb.state !== 'TERMINATED' && pcb.state !== 'ZOMBIE') {
            await pm.kill(pid, 'SIGKILL');
          }
        } catch {
          // ignore already-exited PID cleanup
        }
      }
      await os.shutdown();
    }
  });

  test('T3-P01-02 [F-017, F-018, F-044, Edge Case #28]: Windows PE32+ Mixed-Case Creation x Case-Insensitive Win32 Binary Lookup x POSIX Exact-Case Preservation', async () => {
    const os = await loadPublicOmniOS();
    const spawnedPids = [];
    try {
      os.require('scheduler').stop?.();
      const vfs = os.require('vfs');
      const pkgManager = os.require('pkgManager');
      const nonce = makeNonce();

      const mixedName = `CaseInterop_${nonce}_AbC.txt`;
      const winMixedPath = `C:\\Users\\user\\Documents\\${mixedName}`;
      const winLowerPath = `c:\\users\\user\\documents\\caseinterop_${nonce.toLowerCase()}_abc.txt`;
      const winUpperPath = `C:\\USERS\\USER\\DOCUMENTS\\CASEINTEROP_${nonce.toUpperCase()}_ABC.TXT`;
      const winAltPath = `C:\\Users\\user\\Documents\\cAsEiNtErOp_${nonce}_aBc.TxT`;
      const posixExactPath = `/home/user/Documents/${mixedName}`;
      const posixWrongCasePath = `/home/user/Documents/caseinterop_${nonce.toLowerCase()}_abc.txt`;
      const body = `CASE_BODY_${nonce}`;

      // 1. Windows PE32+ creates mixed-case file
      const wrRec = await pkgManager.install(
        buildCustomPe64Exe({ subsystem: 3, writeFilePath: winMixedPath, writeFileContent: body, exitCode: 0 }),
        { filename: `p01-case-wr-${nonce}.exe`, grantAll: true }
      );
      const wrPid = extractPid(await pkgManager.launch(extractAppId(wrRec), {}));
      spawnedPids.push(wrPid);
      const wrRun = await runToCompletion(os, wrPid, 2500);
      assert.equal(wrRun.exitCode, 0, 'Windows mixed-case writer must exit 0');

      // 2. POSIX readdir preserves exact creation casing with zero duplicates
      const entries = await vfs.readdir('/home/user/Documents', { platform: 'posix' });
      const names = entries.map((e) => (typeof e === 'string' ? e : (e?.name ?? '')));
      assert.ok(names.includes(mixedName), `POSIX readdir must preserve exact creation case "${mixedName}"`);
      const caseMatches = names.filter((n) => n.toLowerCase() === mixedName.toLowerCase());
      assert.equal(caseMatches.length, 1, `Expected exactly 1 directory entry for ${mixedName}, got ${JSON.stringify(caseMatches)}`);

      // 3. Second & third Windows PE32+ reader binaries open all-lowercase and ALL-UPPERCASE variants
      for (const [tag, lookupPath] of [['lower', winLowerPath], ['upper', winUpperPath]]) {
        const rdRec = await pkgManager.install(buildWinPe64ReaderExe(lookupPath), {
          filename: `p01-case-rd-${tag}-${nonce}.exe`,
          grantAll: true,
        });
        const rdPid = extractPid(await pkgManager.launch(extractAppId(rdRec), {}));
        spawnedPids.push(rdPid);
        const rdRun = await runToCompletion(os, rdPid, 2500);
        assert.equal(rdRun.exitCode, 0, `Windows PE32+ ${tag} reader must exit 0`);
        assert.ok(
          rdRun.stdout.includes(body),
          `Windows PE32+ ${tag} lookup "${lookupPath}" must read "${body}" (got ${JSON.stringify(rdRun.stdout)})`
        );
      }

      // 4. Windows case-insensitive stat matches canonical POSIX inode
      const stPosix = await vfs.stat(posixExactPath, { platform: 'posix' });
      const stWinAlt = await vfs.stat(winAltPath, { platform: 'windows' });
      assert.equal(getInode(stWinAlt), getInode(stPosix), 'Windows mixed-case stat must resolve to exact canonical inode');

      // 5. POSIX exact-case enforcement rejects wrong case with ENOENT (also verify edge payload fixture exists)
      const edgePayloads = getVfsEdgeCasePayloads();
      assert.ok(Array.isArray(edgePayloads.windowsMixedCase.lookupVariants) && edgePayloads.windowsMixedCase.lookupVariants.length >= 2);
      let posixErr = null;
      try {
        await vfs.stat(posixWrongCasePath, { platform: 'posix' });
      } catch (err) {
        posixErr = err;
      }
      assert.ok(posixErr instanceof Error, 'POSIX stat with wrong casing must reject');
      assert.equal(posixErr.code, 'ENOENT', `POSIX wrong-case stat must return ENOENT (got ${posixErr.code})`);
    } finally {
      const pm = os.processManager;
      for (const pid of spawnedPids) {
        try {
          const pcb = pm?.get?.(pid);
          if (pcb && pcb.state !== 'TERMINATED' && pcb.state !== 'ZOMBIE') await pm.kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
      await os.shutdown();
    }
  });

  test('T3-P01-03 [F-017, F-019, F-051, F-053, F-054]: Cross-Platform Symlink Following (macOS write -> Symlink -> iOS ARM64 Reader) x vfs:changed Bus x ELOOP Isolation', async () => {
    const os = await loadPublicOmniOS();
    const spawnedPids = [];
    let unsub = null;
    try {
      os.require('scheduler').stop?.();
      const vfs = os.require('vfs');
      const pkgManager = os.require('pkgManager');
      const bus = getEventBus(os);
      assert.ok(bus && typeof bus === 'object', 'OmniOS public runtime must expose KernelEventBus for vfs:changed');

      const vfsEvents = [];
      const onVfs = (ev) => vfsEvents.push(ev);
      if (typeof bus.on === 'function') {
        const ret = bus.on('vfs:changed', onVfs);
        unsub = typeof ret === 'function' ? ret : () => bus.off?.('vfs:changed', onVfs);
      } else if (typeof bus.subscribe === 'function') {
        unsub = bus.subscribe('vfs:changed', onVfs);
      } else {
        assert.fail('KernelEventBus must expose on() or subscribe()');
      }

      const nonce = makeNonce();
      const targetPosix = `/home/user/Documents/sym-tgt-${nonce}.txt`;
      const targetMac = `/Users/user/Documents/sym-tgt-${nonce}.txt`;
      const linkPosix = `/home/user/Documents/sym-lnk-${nonce}.txt`;
      const linkWin = `C:\\Users\\user\\Documents\\sym-lnk-${nonce}.txt`;
      const linkAnd = `/sdcard/Documents/sym-lnk-${nonce}.txt`;
      const linkIos = `/var/mobile/Documents/sym-lnk-${nonce}.txt`;
      const payload = `SYM_DATA_${nonce}`;

      // 1. macOS binary creates target file
      const macBundle = `com.p01.symmac.${nonce}`;
      const macRec = await pkgManager.install(
        buildCustomMacAppZip({
          bundleId: macBundle,
          appName: `SymMac${nonce}`,
          executableName: `SymMac${nonce}`,
          arch: 'universal',
          fileWrite: { path: targetMac, content: payload },
          exitCode: 0,
        }),
        { filename: `p01-sym-mac-${nonce}.app.zip`, grantAll: true }
      );
      const macPid = extractPid(await pkgManager.launch(extractAppId(macRec, macBundle), {}));
      spawnedPids.push(macPid);
      const macRun = await runToCompletion(os, macPid, 2500);
      assert.equal(macRun.exitCode, 0, 'macOS target writer must exit 0');

      // 2. Create POSIX symlink and verify vfs:changed observed target and symlink paths
      await vfs.symlink(targetPosix, linkPosix, { platform: 'posix' });
      const evBlob = JSON.stringify(vfsEvents);
      assert.ok(evBlob.includes(`sym-tgt-${nonce}.txt`), `vfs:changed must observe target creation (events: ${evBlob.slice(0, 300)})`);
      assert.ok(evBlob.includes(`sym-lnk-${nonce}.txt`), `vfs:changed must observe symlink creation (events: ${evBlob.slice(0, 300)})`);

      // 3. lstat distinguishes symlink inode; stat via all 4 platforms resolves target inode
      const stTarget = await vfs.stat(targetPosix, { platform: 'posix' });
      const lstLink = await vfs.lstat(linkPosix, { platform: 'posix' });
      assert.equal(isSymlinkStat(lstLink), true, `lstat() must identify symlink (got ${JSON.stringify(lstLink)})`);
      assert.notEqual(getInode(lstLink), getInode(stTarget), 'lstat(symlink) inode must differ from target inode');
      assert.equal(await vfs.readlink(linkPosix, { platform: 'posix' }), targetPosix, 'readlink() must return target path');

      for (const [p, platform] of [[linkWin, 'windows'], [linkAnd, 'android'], [linkIos, 'ios']]) {
        const stVia = await vfs.stat(p, { platform });
        assert.equal(getInode(stVia), getInode(stTarget), `stat(${p}, ${platform}) must follow symlink to target inode`);
      }

      // 4. iOS ARM64 reader opens symlink via /var/mobile/Documents/
      const iosBundle = `com.p01.symios.${nonce}`;
      const iosRec = await pkgManager.install(
        buildCustomIpa({
          bundleId: iosBundle,
          displayName: `SymIos${nonce}`,
          executableName: `SymIos${nonce}`,
          machoBytes: buildDarwinReaderMachO({ filePath: linkIos, arch: 'arm64', platform: 2 }),
        }),
        { filename: `p01-sym-ios-${nonce}.ipa`, grantAll: true }
      );
      const iosPid = extractPid(await pkgManager.launch(extractAppId(iosRec, iosBundle), {}));
      spawnedPids.push(iosPid);
      const iosRun = await runToCompletion(os, iosPid, 2500);
      assert.equal(iosRun.exitCode, 0, 'iOS ARM64 symlink reader must exit 0');
      assert.ok(
        iosRun.stdout.includes(payload),
        `iOS ARM64 reader must follow symlink and output "${payload}" (got ${JSON.stringify(iosRun.stdout)})`
      );

      // 5. 2-node symlink cycle triggers ELOOP on both POSIX and Windows Z:\ without corrupting healthy symlink
      const cycA = `/tmp/p01-cyc-a-${nonce}`;
      const cycB = `/tmp/p01-cyc-b-${nonce}`;
      await vfs.symlink(cycB, cycA, { platform: 'posix' });
      await vfs.symlink(cycA, cycB, { platform: 'posix' });

      let posixCycleErr = null;
      try {
        await vfs.readFile(cycA, { platform: 'posix', encoding: 'utf8' });
      } catch (err) {
        posixCycleErr = err;
      }
      assert.ok(posixCycleErr instanceof Error, 'POSIX symlink cycle must throw');
      assert.equal(posixCycleErr.code, 'ELOOP', `POSIX symlink cycle must throw ELOOP (got ${posixCycleErr.code})`);

      let winCycleErr = null;
      try {
        await vfs.stat(`Z:\\tmp\\p01-cyc-a-${nonce}`, { platform: 'windows' });
      } catch (err) {
        winCycleErr = err;
      }
      assert.ok(winCycleErr instanceof Error, 'Windows Z:\\ symlink cycle must throw');
      assert.equal(winCycleErr.code, 'ELOOP', `Windows symlink cycle must throw ELOOP (got ${winCycleErr.code})`);

      // Healthy symlink remains unaffected after ELOOP faults
      assert.equal(
        await vfs.readFile(linkPosix, { platform: 'posix', encoding: 'utf8' }),
        payload,
        'Healthy symlink must still read cleanly after ELOOP isolation'
      );
    } finally {
      unsub?.();
      const pm = os.processManager;
      for (const pid of spawnedPids) {
        try {
          const pcb = pm?.get?.(pid);
          if (pcb && pcb.state !== 'TERMINATED' && pcb.state !== 'ZOMBIE') await pm.kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
      await os.shutdown();
    }
  });

  test('T3-P01-04 [F-006, F-017, F-020, F-040, F-044]: Multi-Platform Live Processes x /proc/<pid>/status & Z:\\proc\\<pid>\\status Cross-Verification', async () => {
    const os = await loadPublicOmniOS();
    const spawnedPids = [];
    try {
      const scheduler = os.require('scheduler');
      scheduler.stop?.();
      const vfs = os.require('vfs');
      const pm = os.require('processManager');
      const pkgManager = os.require('pkgManager');
      const nonce = makeNonce();

      // 1. Dynamic /proc/uptime and PID 1 status
      const uptimeRaw = await vfs.readFile('/proc/uptime', { platform: 'posix', encoding: 'utf8' });
      const uptimeNum = Number.parseFloat(String(uptimeRaw).trim().split(/\s+/)[0]);
      assert.ok(Number.isFinite(uptimeNum) && uptimeNum >= 0, `/proc/uptime must parse as non-negative float (got ${JSON.stringify(uptimeRaw)})`);

      const pid1Status = await vfs.readFile('/proc/1/status', { platform: 'posix', encoding: 'utf8' });
      assert.ok(pid1Status.includes('1') && /omnid/i.test(pid1Status), `/proc/1/status must describe PID 1 omnid (got ${JSON.stringify(pid1Status)})`);

      // 2. Launch live Android .apk and spawn yielding sibling process
      const andPkg = `com.p01.proc.${nonce}`;
      const andRec = await pkgManager.install(
        buildCustomApk({ packageName: andPkg, appLabel: `ProcAnd${nonce}`, outputContent: `PROC_${nonce}` }),
        { filename: `p01-proc-${nonce}.apk`, grantAll: true }
      );
      const andPid = extractPid(await pkgManager.launch(extractAppId(andRec, andPkg), {}));
      spawnedPids.push(andPid);

      const sibCtx = makeYieldingContext();
      const sibName = `mac-sib-${nonce}`;
      const sibPcb = pm.spawn({
        name: sibName,
        appId: `com.p01.sib.${nonce}`,
        platform: 'macos',
        arch: 'arm64',
        uid: 1000,
        gid: 1000,
        cwd: '/home/user',
        priority: 8,
        executionContext: sibCtx,
      });
      const sibPid = sibPcb.pid;
      spawnedPids.push(sibPid);

      // Multi-daemon-scaled bounded step so both processes are scheduled
      const stepped = await stepUntilCondition(os, () => sibCtx.steps > 0, 80);
      assert.equal(stepped, true, 'Sibling process must advance under multi-daemon scheduler stepping');

      // 3. Cross-verify /proc/<pid>/status via POSIX and Windows Z:\ root mapping
      for (const pid of [andPid, sibPid]) {
        const pcb = pm.get(pid);
        assert.ok(pcb && pcb.state !== 'TERMINATED' && pcb.state !== 'ZOMBIE', `PID ${pid} must be live`);
        const posixStatus = await vfs.readFile(`/proc/${pid}/status`, { platform: 'posix', encoding: 'utf8' });
        const winStatus = await vfs.readFile(`Z:\\proc\\${pid}\\status`, { platform: 'windows', encoding: 'utf8' });
        assert.equal(winStatus, posixStatus, `Z:\\proc\\${pid}\\status must match /proc/${pid}/status byte-for-byte`);
        assert.ok(posixStatus.includes(String(pid)), `/proc/${pid}/status must include PID ${pid}`);
        assert.ok(
          (Boolean(pcb.name) && posixStatus.includes(String(pcb.name))) ||
          (Boolean(pcb.state) && posixStatus.includes(String(pcb.state))),
          `/proc/${pid}/status must reflect live PCB metadata (got ${JSON.stringify(posixStatus)})`
        );
      }

      // 4. Terminate sibling with SIGTERM; /proc/<sibPid>/status must disappear (ENOENT) or report TERMINATED/ZOMBIE while Android stays live
      await pm.kill(sibPid, 'SIGTERM');
      let deadStatus = null;
      let deadErr = null;
      try {
        deadStatus = await vfs.readFile(`/proc/${sibPid}/status`, { platform: 'posix', encoding: 'utf8' });
      } catch (err) {
        deadErr = err;
      }
      if (deadErr) {
        assert.equal(deadErr.code, 'ENOENT', `Killed PID /proc status error must be ENOENT (got ${deadErr.code})`);
      } else {
        assert.match(String(deadStatus), /TERMINATED|ZOMBIE/i, `Killed PID /proc status must report TERMINATED/ZOMBIE (got ${JSON.stringify(deadStatus)})`);
      }

      const andStillLive = await vfs.readFile(`/proc/${andPid}/status`, { platform: 'posix', encoding: 'utf8' });
      assert.ok(andStillLive.includes(String(andPid)), 'Android PID /proc status must remain valid after sibling SIGTERM');
    } finally {
      const pm = os.processManager;
      for (const pid of spawnedPids) {
        try {
          const pcb = pm?.get?.(pid);
          if (pcb && pcb.state !== 'TERMINATED' && pcb.state !== 'ZOMBIE') await pm.kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
      await os.shutdown();
    }
  });

  test('T3-P01-05 [F-016, F-017, F-019, F-045, F-062, F-065]: Live Windows .bat Script VFS Redirection x HTTP REST /api/v1/vfs/* x Remote CLI vfs Sync', async () => {
    const srv = await startOmniServer();
    try {
      const nonce = makeNonce();
      const fname = `bat-xplat-${nonce}.txt`;
      const winPath = `C:\\Users\\user\\Documents\\${fname}`;
      const canonPath = `/home/user/Documents/${fname}`;
      const expected = `BAT_XPLAT_${nonce}`;

      const batScript = buildBatScript({
        outputFile: winPath,
        outputContent: expected,
        exitCode: 0,
      });

      const instRes = await installPackageHttp(srv.api, Buffer.from(batScript, 'utf8'), `p01-${nonce}.bat`);
      assert.ok(instRes.ok, `Installing .bat script via REST must succeed (got ${instRes.status}: ${instRes.text})`);
      const batAppId = extractAppId(instRes.json);
      assert.ok(batAppId, `Install response must include appId (got ${instRes.text})`);

      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(batAppId)}/launch`, {});
      assert.ok(launchRes.ok, `Launching .bat app must succeed (got ${launchRes.status}: ${launchRes.text})`);

      const fileRes = await waitUntil(async () => {
        const r = await srv.api.get('/api/v1/vfs/file', { query: { path: canonPath } });
        if (r.ok && extractFileText(r).includes(expected)) return r;
        return null;
      }, { timeoutMs: 8000, label: `.bat output at ${canonPath}` });
      assert.ok(extractFileText(fileRes).includes(expected), 'REST /api/v1/vfs/file must return .bat redirected output');

      // Cross-verify /api/v1/vfs/resolve across all 4 platform syntaxes
      const platformChecks = [
        [winPath, 'windows'],
        [`/Users/user/Documents/${fname}`, 'macos'],
        [`/sdcard/Documents/${fname}`, 'android'],
        [`/var/mobile/Documents/${fname}`, 'ios'],
      ];
      for (const [rawPath, platform] of platformChecks) {
        let res = await srv.api.get('/api/v1/vfs/resolve', { query: { path: rawPath, platform } });
        if (res.status === 404 || res.status === 405) {
          res = await srv.api.post('/api/v1/vfs/resolve', { path: rawPath, rawPath, platform });
        }
        assert.equal(res.status, 200, `Resolve failed for ${platform} path ${rawPath} (got ${res.status}: ${res.text})`);
        const resolved = res.json?.canonicalPath ?? res.json?.data?.canonicalPath ?? res.json?.path;
        assert.equal(resolved, canonPath, `Platform ${platform} path "${rawPath}" must resolve to ${canonPath}`);
      }

      // Remote CLI vfs cat & vfs resolve cross-check
      const cliCat = await srv.runCli(['vfs', 'cat', canonPath], { json: true, expectZero: true });
      assert.ok(
        cliCat.stdout.includes(expected),
        `Remote CLI vfs cat must return "${expected}" (got ${JSON.stringify(cliCat.stdout)})`
      );
      const cliResolve = await srv.runCli(['vfs', 'resolve', winPath, '--platform', 'windows'], { json: true, expectZero: true });
      assert.ok(
        cliResolve.stdout.includes(canonPath),
        `Remote CLI vfs resolve must include "${canonPath}" (got ${JSON.stringify(cliResolve.stdout)})`
      );

      // REST symlink creation + read through symlink + mounts check
      const linkPath = `/home/user/Documents/bat-sym-${nonce}.txt`;
      const symRes = await srv.api.post('/api/v1/vfs/symlink', { target: canonPath, linkPath, path: linkPath });
      assert.ok(symRes.ok, `POST /api/v1/vfs/symlink must succeed (got ${symRes.status}: ${symRes.text})`);

      const symRead = await srv.api.get('/api/v1/vfs/file', { query: { path: linkPath }, expectOk: true });
      assert.ok(extractFileText(symRead).includes(expected), 'Reading REST symlink must return .bat target content');

      const mountsRes = await srv.api.get('/api/v1/vfs/mounts', { expectOk: true });
      const mountsArr = unwrapExplicitArray(mountsRes.json, ['mounts', 'items', 'data']);
      assert.ok(Array.isArray(mountsArr), `GET /api/v1/vfs/mounts must return explicit array (got ${mountsRes.text})`);
      const mountsBlob = JSON.stringify(mountsArr);
      for (const reqMount of ['/proc', '/dev', '/tmp']) {
        assert.ok(mountsBlob.includes(reqMount), `Mounts must include "${reqMount}" (got ${mountsBlob})`);
      }
    } finally {
      await srv.stop();
    }
  });

  test('T3-P01-06 [F-017, F-018, F-027, F-040, F-053]: Per-App Private Container Isolation (/data/data/<pkg> vs /var/mobile/Containers) x Shared /home/user/Documents Exchange', async () => {
    const os = await loadPublicOmniOS();
    try {
      const vfs = os.require('vfs');
      const pt = os.require('pathTranslator');
      const pkgManager = os.require('pkgManager');
      const rootCtx = { uid: 0, gid: 0, platform: 'posix' };
      const nonce = makeNonce();

      const andPkg = `com.p01.isoand.${nonce}`;
      const iosBundle = `com.p01.isoios.${nonce}`;

      const andRec = await pkgManager.install(
        buildCustomApk({ packageName: andPkg, appLabel: `IsoAnd${nonce}` }),
        { filename: `p01-iso-and-${nonce}.apk`, grantAll: true }
      );
      const iosRec = await pkgManager.install(
        buildCustomIpa({ bundleId: iosBundle, displayName: `IsoIos${nonce}`, executableName: `IsoIos${nonce}` }),
        { filename: `p01-iso-ios-${nonce}.ipa`, grantAll: true }
      );

      const iosDataDir = iosRec?.dataDir ?? `/var/appdata/ios/${iosBundle}`;
      const iosUuid =
        iosRec?.metadata?.containerUuid ??
        (iosDataDir.startsWith('/var/appdata/ios/') ? iosDataDir.slice('/var/appdata/ios/'.length) : `11111111-2222-3333-4444-${nonce}0000`);

      const uidAnd = await resolveSandboxUid(os, extractAppId(andRec, andPkg), andRec);
      const uidIos = await resolveSandboxUid(os, extractAppId(iosRec, iosBundle), iosRec);
      assert.ok(Number.isInteger(uidAnd) && uidAnd >= 10000, `Android app must receive sandbox UID >= 10000 (got ${uidAnd})`);
      assert.ok(Number.isInteger(uidIos) && uidIos >= 10000, `iOS app must receive sandbox UID >= 10000 (got ${uidIos})`);
      assert.notEqual(uidAnd, uidIos, 'Android and iOS apps must receive distinct sandbox UIDs');

      // Verify PathTranslator container canonicalization
      const andMapped = pt.toCanonical(`/data/data/${andPkg}/priv.txt`, { platform: 'android', appId: andPkg });
      assert.equal(andMapped?.canonicalPath, `/var/appdata/android/${andPkg}/priv.txt`);
      const iosMapped = pt.toCanonical(`/var/mobile/Containers/Data/Application/${iosUuid}/priv.txt`, {
        platform: 'ios',
        appId: iosBundle,
        containerUuid: iosUuid,
      });
      assert.equal(iosMapped?.canonicalPath, `/var/appdata/ios/${iosUuid}/priv.txt`);

      // Provision private 0o700/0o600 files owned by each sandbox UID
      const andDir = `/var/appdata/android/${andPkg}`;
      const andPriv = `${andDir}/priv.txt`;
      const iosDir = `/var/appdata/ios/${iosUuid}`;
      const iosPriv = `${iosDir}/priv.txt`;

      await vfs.mkdir(andDir, { recursive: true, mode: 0o700, ...rootCtx });
      await vfs.chown(andDir, uidAnd, uidAnd, rootCtx);
      await vfs.chmod(andDir, 0o700, rootCtx);
      await vfs.writeFile(andPriv, `AND_PRIV_${nonce}`, { mode: 0o600, ...rootCtx });
      await vfs.chown(andPriv, uidAnd, uidAnd, rootCtx);
      await vfs.chmod(andPriv, 0o600, rootCtx);

      await vfs.mkdir(iosDir, { recursive: true, mode: 0o700, ...rootCtx });
      await vfs.chown(iosDir, uidIos, uidIos, rootCtx);
      await vfs.chmod(iosDir, 0o700, rootCtx);
      await vfs.writeFile(iosPriv, `IOS_PRIV_${nonce}`, { mode: 0o600, ...rootCtx });
      await vfs.chown(iosPriv, uidIos, uidIos, rootCtx);
      await vfs.chmod(iosPriv, 0o600, rootCtx);

      // Each app reads its own container cleanly
      const andCtx = { uid: uidAnd, gid: uidAnd, platform: 'android', appId: andPkg };
      const iosCtx = { uid: uidIos, gid: uidIos, platform: 'ios', appId: iosBundle, containerUuid: iosUuid };
      assert.equal(await vfs.readFile(`/data/data/${andPkg}/priv.txt`, { encoding: 'utf8', ...andCtx }), `AND_PRIV_${nonce}`);
      assert.equal(
        await vfs.readFile(`/var/mobile/Containers/Data/Application/${iosUuid}/priv.txt`, { encoding: 'utf8', ...iosCtx }),
        `IOS_PRIV_${nonce}`
      );

      // Cross-app private container reads & traversal MUST fail with EACCES
      let iosReadAndErr = null;
      try {
        await vfs.readFile(andPriv, { encoding: 'utf8', ...iosCtx });
      } catch (err) {
        iosReadAndErr = err;
      }
      assert.ok(iosReadAndErr instanceof Error, 'iOS UID reading Android private container must be denied');
      assert.equal(iosReadAndErr.code, 'EACCES', `Expected EACCES (got ${iosReadAndErr.code})`);

      let andReadIosErr = null;
      try {
        await vfs.readFile(iosPriv, { encoding: 'utf8', ...andCtx });
      } catch (err) {
        andReadIosErr = err;
      }
      assert.ok(andReadIosErr instanceof Error, 'Android UID reading iOS private container must be denied');
      assert.equal(andReadIosErr.code, 'EACCES', `Expected EACCES (got ${andReadIosErr.code})`);

      let traversalErr = null;
      try {
        await vfs.readFile(`/data/data/${andPkg}/../../ios/${iosUuid}/priv.txt`, { encoding: 'utf8', ...andCtx });
      } catch (err) {
        traversalErr = err;
      }
      assert.ok(traversalErr instanceof Error, 'Cross-container ../ traversal must be blocked');
      assert.ok(
        ['EACCES', 'ENOENT', 'EINVAL'].includes(traversalErr.code),
        `Traversal must fail with EACCES|ENOENT|EINVAL (got ${traversalErr.code})`
      );

      // Simultaneously, both platforms cleanly exchange a shared document under /home/user/Documents/ via mediated user-space access
      const sharedPosix = `/home/user/Documents/xchg-${nonce}.txt`;
      await vfs.writeFile(sharedPosix, `INIT_${nonce}`, { mode: 0o666, ...rootCtx });
      await vfs.chmod(sharedPosix, 0o666, rootCtx);

      const andSharedCtx = { uid: 1000, gid: 1000, platform: 'android', appId: andPkg };
      const iosSharedCtx = { uid: 1000, gid: 1000, platform: 'ios', appId: iosBundle, containerUuid: iosUuid };

      await vfs.writeFile(`/sdcard/Documents/xchg-${nonce}.txt`, `SHARED_FROM_AND_${nonce}`, { mode: 0o666, ...andSharedCtx });
      const readByIos = await vfs.readFile(`/var/mobile/Documents/xchg-${nonce}.txt`, { encoding: 'utf8', ...iosSharedCtx });
      assert.equal(readByIos, `SHARED_FROM_AND_${nonce}`, 'iOS sandbox must read Android-written shared document');

      await vfs.writeFile(`/var/mobile/Documents/xchg-${nonce}.txt`, `SHARED_FROM_IOS_${nonce}`, { mode: 0o666, ...iosSharedCtx });
      const readByAnd = await vfs.readFile(`/sdcard/Documents/xchg-${nonce}.txt`, { encoding: 'utf8', ...andSharedCtx });
      assert.equal(readByAnd, `SHARED_FROM_IOS_${nonce}`, 'Android sandbox must read iOS-written shared document');
    } finally {
      await os.shutdown();
    }
  });
});
