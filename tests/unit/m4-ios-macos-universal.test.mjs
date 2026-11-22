/**
 * OmniOS Milestone M4 Comprehensive Unit, External-Oracle & Multi-Platform Integration Test Suite
 *
 * Covers ALL 13 M4 features (`F-048` through `F-060`), ALL 10 M4 authoritative edge cases
 * (`#19`–`#27`, `#29`), real external toolchain cross-verification (`llvm-mc`, `clang`,
 * `llvm-objdump`, `python3` `zipfile` + `plistlib`, `WebAssembly.validate()`), anti-hardcoding
 * dynamic runtime-nonce binaries, and simultaneous 3-platform (`iOS` + `macOS` + `Universal WASM`)
 * execution + fault isolation under a live M1+M2 `OmniKernel`.
 *
 * Constraints:
 * - Zero external npm dependencies
 * - Zero skipped / todo tests
 * - Zero static imports of M3 modules (M3-parallel safe)
 * - Deterministic cleanup of all temporary directories in `after()`
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// M1 Core Imports
import {
  ERROR_CODES,
  DARWIN_ERRNO,
  WASI_ERRNO,
  FormatError,
  MemoryFaultError,
  IllegalInstructionError,
  QuotaExceededError,
} from '../../os/common/errors.mjs';
import {
  AddressSpace,
  PROT_NONE,
  PROT_READ,
  PROT_WRITE,
  PROT_EXEC,
} from '../../os/kernel/vmm.mjs';
import { CpuRegistry } from '../../os/cpu/registry.mjs';
import { PROCESS_STATES } from '../../os/kernel/process.mjs';
import { OmniKernel, KERNEL_STATES } from '../../os/kernel/kernel.mjs';

// M2 Service Imports
import { UserManager } from '../../os/security/users.mjs';
import {
  PermissionBroker,
  registerSecurityService,
} from '../../os/security/permissions.mjs';
import {
  VFS,
  OPEN_FLAGS,
  registerVfsService,
} from '../../os/vfs/vfs.mjs';
import {
  UnifiedConfigStore,
  registerConfigService,
} from '../../os/store/unified-config.mjs';
import { IPCManager } from '../../os/ipc/ipc.mjs';
import { IntentRouter } from '../../os/ipc/router.mjs';
import { SharedClipboard } from '../../os/ipc/clipboard.mjs';
import {
  NotificationCenter,
  registerIpcBrokerService,
} from '../../os/ipc/notifications.mjs';
import {
  Compositor,
  registerCompositorService,
} from '../../os/compositor/compositor.mjs';
import { readZip, createZip } from '../../os/pkg/zip.mjs';
import { FormatDetector, PACKAGE_FORMATS } from '../../os/pkg/format-detector.mjs';
import {
  PackageManager,
  registerPackageService,
} from '../../os/pkg/package-manager.mjs';

// M4 Stage 1A — Apple Core Engine
import {
  ARM64_RET_OPCODE,
  ARM64_NOP_OPCODE,
  ARM64Cpu,
  createArm64Cpu,
  registerArm64Cpu,
} from '../../os/cpu/arm64.mjs';
import {
  MACHO_CONSTANTS,
  APPLE_THUNK_BASE,
  APPLE_STACK_BASE,
  parseFatMachO,
  parseMachO,
  loadMachOIntoAddressSpace,
} from '../../os/runtimes/apple/macho-parser.mjs';
import {
  CF_EPOCH_MS,
  PlistUID,
  isBinaryPlist,
  parseBinaryPlist,
  writeBinaryPlist,
  parseXmlPlist,
  writeXmlPlist,
  parsePlist,
} from '../../os/runtimes/apple/plist-parser.mjs';
import {
  DARWIN_SYSCALLS,
  MACH_TRAPS,
  DARWIN_O_FLAGS,
  translateDarwinOpenFlags,
  createDarwinSyscalls,
} from '../../os/runtimes/apple/darwin-syscalls.mjs';
import { createObjCRuntime } from '../../os/runtimes/apple/objc-runtime.mjs';

// M4 Stage 1B — Universal WASM/WASI Runtime & SDK
import {
  WASI_CONSTANTS,
  WasiExitSignal,
  createWasiBridge,
} from '../../os/runtimes/universal/wasi-bridge.mjs';
import {
  UniversalWasmRuntime,
  createUniversalRuntime,
  registerWasmCpu,
  parseWasmBinary,
} from '../../os/runtimes/universal/wasm-runtime.mjs';
import {
  WASM_TYPES,
  WasmCodeBuilder,
  WasmModuleBuilder,
  buildUniversalWasm,
  buildUniversalUapp,
} from '../../sdk/universal-builder.mjs';

// M4 Stage 2A — iOS Runtime & SDK
import { parseIpa } from '../../os/runtimes/ios/ipa-parser.mjs';
import {
  createIOSRuntime,
  deriveIosContainerUuid,
} from '../../os/runtimes/ios/ios-runtime.mjs';
import {
  Arm64Assembler,
  buildMachOArm64,
  buildIosIpa,
} from '../../sdk/ios-builder.mjs';

// M4 Stage 2B — macOS Runtime & SDK
import {
  parseCpioArchive,
  parseMacDmg,
  parseMacPkg,
  parseMacPackage,
} from '../../os/runtimes/macos/app-bundle-parser.mjs';
import { createMacOSRuntime } from '../../os/runtimes/macos/macos-runtime.mjs';
import {
  buildMachOArm64Mac,
  buildMachOX86_64Mac,
  buildUniversalFatMachO,
  buildMacAppZip,
  buildTestDmg,
  buildTestPkg,
} from '../../sdk/macos-builder.mjs';

// M4 Stage 3 — Deterministic Sample Build Pipeline
import { buildAllSamples } from '../../sdk/build-samples.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../..');
const PACKAGES_DIR = path.join(REPO_ROOT, 'packages');
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8');

// ============================================================================
// Shared Temp-Dir & Full M1+M2+M4 Stack Harness (Strict Cleanup in `after()`)
// ============================================================================

const createdTempDirs = [];
const bootedStacks = [];

function makeTempDir(prefix = 'omnios-m4-test-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  createdTempDirs.push(dir);
  return dir;
}

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function runPython(script, input = null, args = []) {
  const opts = {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  };
  if (input !== null) {
    opts.input = typeof input === 'string' ? input : JSON.stringify(input);
  }
  return execFileSync('python3', ['-c', script, ...args], opts);
}

function findUiNode(node, predicate) {
  if (!node || typeof node !== 'object') return null;
  if (predicate(node)) return node;
  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      const hit = findUiNode(child, predicate);
      if (hit) return hit;
    }
  }
  return null;
}

function collectUiNodes(node, out = []) {
  if (!node || typeof node !== 'object') return out;
  out.push(node);
  if (Array.isArray(node.children)) {
    for (const child of node.children) collectUiNodes(child, out);
  }
  return out;
}

async function bootFullM4Stack(prefix = 'omnios-m4-stack-') {
  const dir = makeTempDir(prefix);
  const dbPath = path.join(dir, 'omnios.sqlite');

  const kernel = new OmniKernel({ dbPath });
  registerArm64Cpu(kernel.cpuRegistry);
  registerWasmCpu(kernel.cpuRegistry);

  const users = new UserManager({ kernel });
  const permissions = new PermissionBroker({ kernel, userManager: users });
  const vfs = new VFS({ kernel, userManager: users });
  const configStore = new UnifiedConfigStore({ kernel });
  const ipc = new IPCManager({ eventBus: kernel.eventBus, processManager: kernel.processManager });
  const intentRouter = new IntentRouter({
    eventBus: kernel.eventBus,
    processManager: kernel.processManager,
    configStore,
  });
  const clipboard = new SharedClipboard({ eventBus: kernel.eventBus });
  const notifications = new NotificationCenter({
    eventBus: kernel.eventBus,
    configStore,
    processManager: kernel.processManager,
  });
  const compositor = new Compositor({ kernel, configStore });
  const pkgManager = new PackageManager({
    kernel,
    vfs,
    configStore,
    ipc,
    intentRouter,
    clipboard,
    notifications,
    users,
    permissions,
    compositor,
  });

  pkgManager.registerRuntime('ios', createIOSRuntime());
  pkgManager.registerRuntime('macos', createMacOSRuntime());
  pkgManager.registerRuntime('universal', createUniversalRuntime());

  intentRouter.setLauncher((appId, { intent }) => pkgManager.launch(appId, { intent }));

  registerSecurityService(kernel.serviceManager, { userManager: users, permissionBroker: permissions, kernel, deps: [] });
  registerVfsService(kernel.serviceManager, vfs, { kernel, deps: ['securityd'] });
  registerConfigService(kernel.serviceManager, configStore, { kernel, deps: [] });
  registerIpcBrokerService(kernel.serviceManager, { ipc, router: intentRouter, clipboard, notifications, deps: ['configd'] });
  registerCompositorService(kernel.serviceManager, compositor, { deps: ['configd'] });
  registerPackageService(kernel.serviceManager, pkgManager, {
    deps: ['securityd', 'vfsd', 'ipc-brokerd', 'compositord'],
  });

  const bootReport = await kernel.boot();
  assert.equal(bootReport.status, KERNEL_STATES.RUNNING);

  const stack = {
    dir,
    dbPath,
    kernel,
    users,
    permissions,
    vfs,
    configStore,
    ipc,
    intentRouter,
    clipboard,
    notifications,
    compositor,
    pkgManager,
    closed: false,
    async shutdown() {
      if (this.closed) return;
      this.closed = true;
      try {
        await this.kernel.shutdown();
      } catch {
        // Ignore double shutdown
      }
    },
  };
  bootedStacks.push(stack);
  return stack;
}

after(async () => {
  for (const stack of bootedStacks) {
    await stack.shutdown();
  }
  bootedStacks.length = 0;

  for (const dir of createdTempDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup race
    }
  }
  createdTempDirs.length = 0;
});

// ============================================================================
// Helper: Build custom synthetic Mach-O 64 with LC_DYLD_CHAINED_FIXUPS & LC_RPATH
// ============================================================================

function buildSyntheticChainedFixupsMachO({ encrypt = false } = {}) {
  const PAGE = 0x4000;
  const TEXT_VMADDR = 0x100000000n;
  const DATA_VMADDR = 0x100004000n;
  const LINKEDIT_VMADDR = 0x100008000n;

  // Code: MOVZ X0, #42; RET (8 bytes) at __text offset 0x1000
  const codeOff = 0x1000;
  const code = new Uint8Array(8);
  const codeDv = new DataView(code.buffer);
  codeDv.setUint32(0, 0xd2800540, true); // MOVZ X0, #42
  codeDv.setUint32(4, ARM64_RET_OPCODE, true); // RET

  // __DATA page:
  // +0x00: chained ptr64 BIND (ordinal 0 = "_demo_ext_sym", nextDelta = 2 -> +0x08)
  // +0x08: chained ptr64 REBASE (target = 0x100001000, nextDelta = 0 -> end)
  const dataPage = new Uint8Array(PAGE);
  const dataDv = new DataView(dataPage.buffer);
  const bindPtr = (1n << 63n) | (2n << 51n) | 0n; // isBind=1, next=2 (2*4=8 bytes), ordinal=0
  const rebasePtr = (0n << 63n) | (0n << 51n) | (TEXT_VMADDR + BigInt(codeOff));
  dataDv.setBigUint64(0, bindPtr, true);
  dataDv.setBigUint64(8, rebasePtr, true);

  // Build LC_DYLD_CHAINED_FIXUPS payload in __LINKEDIT
  // dyld_chained_fixups_header (28 bytes)
  // starts_in_image: seg_count(4) + seg_info_offset[3](12) = 16 bytes
  // starts_in_segment for __DATA (seg index 2): 24 bytes (size, page_size, ptr_format, seg_offset, max_valid_ptr, page_count=1, page_start[0]=0)
  // imports: 1 x dyld_chained_import (4 bytes)
  // symbols: "\0_demo_ext_sym\0"
  const symStr = TEXT_ENCODER.encode('\0_demo_ext_sym\0');
  const headerLen = 28;
  const startsOff = 32;
  const startsInImageLen = 4 + 3 * 4; // 16
  const segStartRel = startsInImageLen; // 16
  const segStartLen = 24; // 22 + 2 bytes for 1 page_start
  const importsOff = startsOff + startsInImageLen + segStartLen; // 72
  const importsLen = 4;
  const symbolsOff = importsOff + importsLen; // 76
  const cfTotal = symbolsOff + symStr.byteLength;
  const cfBuf = new Uint8Array(cfTotal);
  const cfDv = new DataView(cfBuf.buffer);
  cfDv.setUint32(0, 0, true); // fixups_version = 0
  cfDv.setUint32(4, startsOff, true);
  cfDv.setUint32(8, importsOff, true);
  cfDv.setUint32(12, symbolsOff, true);
  cfDv.setUint32(16, 1, true); // imports_count = 1
  cfDv.setUint32(20, 1, true); // DYLD_CHAINED_IMPORT = 1
  cfDv.setUint32(24, 0, true); // symbols_format = 0 (uncompressed)

  // dyld_chained_starts_in_image
  cfDv.setUint32(startsOff + 0, 3, true); // seg_count = 3 (__PAGEZERO, __TEXT, __DATA)
  cfDv.setUint32(startsOff + 4, 0, true); // __PAGEZERO
  cfDv.setUint32(startsOff + 8, 0, true); // __TEXT
  cfDv.setUint32(startsOff + 12, segStartRel, true); // __DATA

  // dyld_chained_starts_in_segment
  const sBase = startsOff + segStartRel;
  cfDv.setUint32(sBase + 0, segStartLen, true); // size
  cfDv.setUint16(sBase + 4, PAGE, true); // page_size
  cfDv.setUint16(sBase + 6, MACHO_CONSTANTS.DYLD_CHAINED_PTR_64, true); // pointer_format = 2
  cfDv.setBigUint64(sBase + 8, BigInt(PAGE), true); // segment_offset
  cfDv.setUint32(sBase + 16, 0, true); // max_valid_pointer
  cfDv.setUint16(sBase + 20, 1, true); // page_count = 1
  cfDv.setUint16(sBase + 22, 0, true); // page_start[0] = 0

  // dyld_chained_import: lib_ordinal(bits 0..7)=1, weak_import(bit 8)=0, name_offset(bits 9..31)=1
  const importWord = (1 & 0xff) | (0 << 8) | (1 << 9);
  cfDv.setUint32(importsOff, importWord >>> 0, true);
  cfBuf.set(symStr, symbolsOff);

  // Code signature SuperBlob with XML entitlements (0xFADE7171)
  const entXml = TEXT_ENCODER.encode(
    writeXmlPlist({
      'com.apple.security.app-sandbox': true,
      'com.omnios.test.chained': 'verified',
    })
  );
  const entBlobLen = 8 + entXml.byteLength;
  const superBlobLen = 12 + 8 + entBlobLen;
  const csBuf = new Uint8Array(superBlobLen);
  const csDv = new DataView(csBuf.buffer);
  csDv.setUint32(0, 0xfade0cc0, false); // CSMAGIC_EMBEDDED_SIGNATURE
  csDv.setUint32(4, superBlobLen, false);
  csDv.setUint32(8, 1, false); // count = 1
  csDv.setUint32(12, 5, false); // CSSLOT_ENTITLEMENTS
  csDv.setUint32(16, 20, false); // blob offset
  csDv.setUint32(20, 0xfade7171, false); // CSMAGIC_EMBEDDED_ENTITLEMENTS
  csDv.setUint32(24, entBlobLen, false);
  csBuf.set(entXml, 28);

  const linkeditOff = 2 * PAGE;
  const cfFileOff = linkeditOff;
  const csFileOff = linkeditOff + ((cfTotal + 15) & ~15);
  const linkeditSize = (csFileOff - linkeditOff) + csBuf.byteLength;
  const fileSize = linkeditOff + Math.max(PAGE, ((linkeditSize + 15) & ~15));

  const out = new Uint8Array(fileSize);
  const dv = new DataView(out.buffer);

  const writeStr = (buf, off, s, max) => {
    const b = TEXT_ENCODER.encode(s);
    buf.set(b.subarray(0, Math.min(b.length, max)), off);
  };

  const cmds = [];
  const makeSeg64 = (name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, sections = []) => {
    const cmdSize = 72 + sections.length * 80;
    const buf = new Uint8Array(cmdSize);
    const sdv = new DataView(buf.buffer);
    sdv.setUint32(0, MACHO_CONSTANTS.LC_SEGMENT_64, true);
    sdv.setUint32(4, cmdSize, true);
    writeStr(buf, 8, name, 16);
    sdv.setBigUint64(24, BigInt(vmaddr), true);
    sdv.setBigUint64(32, BigInt(vmsize), true);
    sdv.setBigUint64(40, BigInt(fileoff), true);
    sdv.setBigUint64(48, BigInt(filesize), true);
    sdv.setUint32(56, maxprot, true);
    sdv.setUint32(60, initprot, true);
    sdv.setUint32(64, sections.length, true);
    sdv.setUint32(68, 0, true);
    for (let i = 0; i < sections.length; i++) {
      const s = sections[i];
      const base = 72 + i * 80;
      writeStr(buf, base, s.sectname, 16);
      writeStr(buf, base + 16, name, 16);
      sdv.setBigUint64(base + 32, BigInt(s.addr), true);
      sdv.setBigUint64(base + 40, BigInt(s.size), true);
      sdv.setUint32(base + 48, s.offset, true);
      sdv.setUint32(base + 52, s.align ?? 2, true);
      sdv.setUint32(base + 64, s.flags ?? 0, true);
    }
    return buf;
  };

  cmds.push(makeSeg64('__PAGEZERO', 0n, 0x100000000n, 0n, 0n, 0, 0));
  cmds.push(
    makeSeg64('__TEXT', TEXT_VMADDR, BigInt(PAGE), 0n, BigInt(PAGE), 5, 5, [
      { sectname: '__text', addr: TEXT_VMADDR + BigInt(codeOff), size: code.byteLength, offset: codeOff, flags: 0x80000400 },
    ])
  );
  cmds.push(
    makeSeg64('__DATA', DATA_VMADDR, BigInt(PAGE), BigInt(PAGE), BigInt(PAGE), 3, 3, [
      { sectname: '__data', addr: DATA_VMADDR, size: 16, offset: PAGE, flags: 0 },
    ])
  );
  cmds.push(makeSeg64('__LINKEDIT', LINKEDIT_VMADDR, BigInt(PAGE), BigInt(linkeditOff), BigInt(linkeditSize), 1, 1));

  // LC_MAIN
  {
    const b = new Uint8Array(24);
    const d = new DataView(b.buffer);
    d.setUint32(0, MACHO_CONSTANTS.LC_MAIN, true);
    d.setUint32(4, 24, true);
    d.setBigUint64(8, BigInt(codeOff), true); // entryoff = 0x1000
    d.setBigUint64(16, 0n, true);
    cmds.push(b);
  }
  // LC_LOAD_DYLIB
  {
    const dylib = TEXT_ENCODER.encode('/usr/lib/libSystem.B.dylib\0');
    const cmdSize = (24 + dylib.byteLength + 7) & ~7;
    const b = new Uint8Array(cmdSize);
    const d = new DataView(b.buffer);
    d.setUint32(0, MACHO_CONSTANTS.LC_LOAD_DYLIB, true);
    d.setUint32(4, cmdSize, true);
    d.setUint32(8, 24, true);
    b.set(dylib, 24);
    cmds.push(b);
  }
  // LC_RPATH
  {
    const rpath = TEXT_ENCODER.encode('@executable_path/../Frameworks\0');
    const cmdSize = (12 + rpath.byteLength + 7) & ~7;
    const b = new Uint8Array(cmdSize);
    const d = new DataView(b.buffer);
    d.setUint32(0, MACHO_CONSTANTS.LC_RPATH, true);
    d.setUint32(4, cmdSize, true);
    d.setUint32(8, 12, true);
    b.set(rpath, 12);
    cmds.push(b);
  }
  // LC_BUILD_VERSION
  {
    const b = new Uint8Array(24);
    const d = new DataView(b.buffer);
    d.setUint32(0, MACHO_CONSTANTS.LC_BUILD_VERSION, true);
    d.setUint32(4, 24, true);
    d.setUint32(8, 1, true); // macOS
    d.setUint32(12, 0x000e0000, true); // 14.0.0
    d.setUint32(16, 0x000e0000, true);
    cmds.push(b);
  }
  // LC_DYLD_CHAINED_FIXUPS
  {
    const b = new Uint8Array(16);
    const d = new DataView(b.buffer);
    d.setUint32(0, MACHO_CONSTANTS.LC_DYLD_CHAINED_FIXUPS, true);
    d.setUint32(4, 16, true);
    d.setUint32(8, cfFileOff, true);
    d.setUint32(12, cfTotal, true);
    cmds.push(b);
  }
  // LC_CODE_SIGNATURE
  {
    const b = new Uint8Array(16);
    const d = new DataView(b.buffer);
    d.setUint32(0, MACHO_CONSTANTS.LC_CODE_SIGNATURE, true);
    d.setUint32(4, 16, true);
    d.setUint32(8, csFileOff, true);
    d.setUint32(12, csBuf.byteLength, true);
    cmds.push(b);
  }
  if (encrypt) {
    const b = new Uint8Array(24);
    const d = new DataView(b.buffer);
    d.setUint32(0, MACHO_CONSTANTS.LC_ENCRYPTION_INFO_64, true);
    d.setUint32(4, 24, true);
    d.setUint32(8, codeOff, true);
    d.setUint32(12, 8, true);
    d.setUint32(16, 1, true); // cryptid = 1
    cmds.push(b);
  }

  let sizeofcmds = 0;
  for (const c of cmds) sizeofcmds += c.byteLength;

  // mach_header_64 (32 bytes)
  dv.setUint32(0, MACHO_CONSTANTS.MH_MAGIC_64, true);
  dv.setUint32(4, MACHO_CONSTANTS.CPU_TYPE_ARM64, true);
  dv.setUint32(8, 0, true);
  dv.setUint32(12, MACHO_CONSTANTS.MH_EXECUTE, true);
  dv.setUint32(16, cmds.length, true);
  dv.setUint32(20, sizeofcmds, true);
  dv.setUint32(24, 0x00200085, true); // MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE
  dv.setUint32(28, 0, true);

  let pos = 32;
  for (const c of cmds) {
    out.set(c, pos);
    pos += c.byteLength;
  }

  out.set(code, codeOff);
  out.set(dataPage, PAGE);
  out.set(cfBuf, cfFileOff);
  out.set(csBuf, csFileOff);
  return out;
}

// ============================================================================
// SUITE 1 (`F-050`, Edge Cases `#23`, `#24`): ARM64 CPU Emulator & Apple ABI
// ============================================================================

describe('Suite 1 (F-050, Edge Cases #23, #24): ARM64 CPU Emulator & Apple ABI', () => {
  it('registers arm64 in CpuRegistry and resolves aarch64 / arm64e aliases', () => {
    const reg = new CpuRegistry();
    registerArm64Cpu(reg);
    assert.equal(reg.has('arm64'), true);
    assert.equal(reg.has('aarch64'), true);
    assert.equal(reg.has('arm64e'), true);

    const as = new AddressSpace({ pid: 101 });
    const cpu = reg.create('aarch64', { addressSpace: as, pid: 101 });
    assert.ok(cpu instanceof ARM64Cpu);
    assert.equal(cpu.getDebugState().arch, 'arm64');
    cpu.dispose();
  });

  it('executes real llvm-mc --triple=aarch64-apple-darwin assembled machine code covering ALU, shifts, bitfields, MUL/DIV, CSEL, LDP/STP, LDR/STR, FP, branches & Reg-31 SP vs XZR (Edge Case #23)', () => {
    const dir = makeTempDir('omnios-m4-arm64-');
    const objPath = path.join(dir, 'isa_oracle.o');

    const asmSource = `
.text
.globl _test_entry
_test_entry:
  // Preserve LR & FP via STP pre-index + explicit ADD/SUB SP immediate (Reg 31 == SP!)
  stp x29, x30, [sp, #-32]!
  mov x29, sp
  sub sp, sp, #16
  add sp, sp, #16

  // Edge Case #23: Reg 31 == XZR for MOVZ/ORR/ADDS destination (must discard writes, never corrupt SP!)
  movz xzr, #0x1234
  orr xzr, x0, x1
  movz x1, #0x55
  adds xzr, x1, #0           // CMP-style flag update into XZR

  // 32-bit W write MUST zero-extend upper 32 bits
  movn x2, #0                // X2 = 0xFFFFFFFFFFFFFFFF
  movz w2, #0x42             // W2 = 0x42 -> X2 MUST become 0x0000000000000042

  // MOVZ / MOVK / MOVN 64-bit construction
  movz x3, #0xbeef
  movk x3, #0xdead, lsl #16  // X3 = 0x00000000deadbeef

  // DecodeBitMasks logical immediate (AND/ORR/EOR imm — 64-bit repeating & 32-bit patterns)
  and x4, x3, #0x00ff00ff00ff00ff // 0x00ad00ef
  orr w4, w4, #0x0000ff00         // 0x00adffef

  // Shifts & bitfields (LSL / LSR / ASR / ROR / SXTW / UBFX)
  movz x5, #0x1234
  lsl x5, x5, #4             // 0x12340
  lsr x5, x5, #2             // 0x48d0
  movn w6, #9                // w6 = -10 (0xFFFFFFF6)
  sxtw x6, w6                // X6 = -10 (sign-extended to 64-bit)

  // MUL / MADD / UDIV / SDIV incl. div-by-0 -> 0 and INT64_MIN / -1 wrap
  movz x7, #7
  movz x8, #6
  madd x9, x7, x8, x2        // 7*6 + 0x42 (66) = 108
  movz x10, #0
  udiv x11, x9, x10          // div-by-0 -> 0
  sdiv x12, x9, x10          // div-by-0 -> 0
  movz x13, #0x8000, lsl #48 // INT64_MIN
  movn x14, #0               // -1
  sdiv x15, x13, x14         // INT64_MIN / -1 -> INT64_MIN (wrap, no crash)

  // CSEL / CSINC
  cmp x7, x8                 // 7 > 6 -> GT
  csel x16, x7, x8, gt       // X16 = 7
  csinc x17, x8, x8, lt      // cond LT false -> X8 + 1 = 7

  // Stack LDP / STP + LDRB / LDRSB / LDUR / STUR
  str x9, [sp, #16]
  ldur x19, [sp, #16]        // X19 = 108
  movz w20, #0xfe
  strb w20, [sp, #24]
  ldrsb x21, [sp, #24]       // X21 = -2 (sign-extended)
  ldrb w22, [sp, #24]        // X22 = 254 (zero-extended)

  // Scalar FP: SCVTF / FADD / FMUL / FDIV / FCMP / FCVTZS
  movz x23, #12
  scvtf d0, x23              // d0 = 12.0
  movz x24, #3
  scvtf d1, x24              // d1 = 3.0
  fadd d2, d0, d1            // d2 = 15.0
  fmul d2, d2, d1            // d2 = 45.0
  fdiv d2, d2, d1            // d2 = 15.0
  fcmp d2, d0                // 15.0 > 12.0
  fcvtzs x25, d2             // X25 = 15

  // BL / RET / CBZ / CBNZ / TBZ / TBNZ / B.cond
  cmp x7, x8                 // 7 > 6
  b.gt L_gt_taken
  movz x26, #777             // skipped
L_gt_taken:
  cbz x10, L_after_cbz
  movz x26, #999             // skipped
L_after_cbz:
  cbnz x7, L_call_helper
  movz x26, #888             // skipped
L_call_helper:
  mov x0, x19                // 108
  bl L_add_ten               // returns 118 in X0
  tbnz x0, #1, L_bit1_set    // 118 = 0b1110110 -> bit 1 is 1
  movz x0, #0
L_bit1_set:
  tbz x0, #0, L_done         // bit 0 is 0
  movz x0, #0
L_done:
  ldp x29, x30, [sp], #32
  ret

L_add_ten:
  add x0, x0, #10
  ret
`;

    execFileSync(
      'llvm-mc',
      ['--triple=aarch64-apple-darwin', '--filetype=obj', '-o', objPath],
      { input: asmSource, stdio: ['pipe', 'pipe', 'pipe'] }
    );

    const objBytes = fs.readFileSync(objPath);
    const parsed = parseMachO(objBytes);
    const textSect = parsed.sections.find((s) => s.sectname === '__text');
    assert.ok(textSect && textSect.size > 0n);

    const codeBytes = objBytes.subarray(textSect.offset, textSect.offset + Number(textSect.size));
    const as = new AddressSpace({ pid: 102 });
    const CODE_VA = 0x100004000;
    const STACK_VA = 0x7fff00000000;
    const SENTINEL_VA = 0x7ffe00000000;
    as.mmap(CODE_VA, 0x4000, PROT_READ | PROT_WRITE, 'text');
    as.write(CODE_VA, codeBytes);
    as.mprotect(CODE_VA, 0x4000, PROT_READ | PROT_EXEC);
    as.mmap(STACK_VA, 0x10000, PROT_READ | PROT_WRITE, 'stack');
    as.mmap(SENTINEL_VA, 0x1000, PROT_READ | PROT_EXEC, 'sentinel');

    const initSP = BigInt(STACK_VA + 0x8000);
    const cpu = createArm64Cpu({ addressSpace: as, pid: 102, exitSentinelVA: SENTINEL_VA });
    cpu.setPC(CODE_VA);
    cpu.setSP(initSP);
    cpu.setLR(SENTINEL_VA);

    const res = cpu.step(2000);
    assert.equal(res.status, 'EXITED');
    assert.equal(cpu.getSP(), initSP, 'SP must be restored cleanly and never corrupted by XZR ops');
    assert.equal(cpu.getReg(2), 0x42n, '32-bit W write must zero-extend upper 32 bits');
    assert.equal(cpu.getReg(3), 0xdeadbeefn);
    assert.equal(cpu.getReg(4), 0x00adffefn, 'DecodeBitMasks logical imm');
    assert.equal(cpu.getReg(5), 0x48d0n);
    assert.equal(BigInt.asIntN(64, cpu.getReg(6)), -10n);
    assert.equal(cpu.getReg(9), 108n);
    assert.equal(cpu.getReg(11), 0n, 'UDIV by 0 must return 0');
    assert.equal(cpu.getReg(12), 0n, 'SDIV by 0 must return 0');
    assert.equal(cpu.getReg(15), 0x8000000000000000n, 'SDIV INT64_MIN/-1 must wrap to INT64_MIN');
    assert.equal(cpu.getReg(16), 7n);
    assert.equal(cpu.getReg(17), 7n);
    assert.equal(cpu.getReg(19), 108n);
    assert.equal(BigInt.asIntN(64, cpu.getReg(21)), -2n);
    assert.equal(cpu.getReg(22), 254n);
    assert.equal(cpu.getReg(25), 15n, 'Scalar FP SCVTF/FADD/FMUL/FDIV/FCVTZS');
    assert.equal(cpu.getReg(0), 118n, 'BL/RET/CBZ/CBNZ/TBZ/TBNZ flow');
    cpu.dispose();
  });

  it('enforces Apple ARM64 ABI (X18 preservation across thunks & syscalls, 16B SP alignment, stack-slot variadics ignoring X1..X7 — Edge Case #24)', () => {
    const as = new AddressSpace({ pid: 103 });
    const CODE_VA = 0x100004000;
    const THUNK_VA = APPLE_THUNK_BASE + 16;
    const SENTINEL_VA = APPLE_THUNK_BASE;
    const STACK_VA = APPLE_STACK_BASE;

    as.mmap(CODE_VA, 0x4000, PROT_READ | PROT_WRITE, 'text');
    as.mmap(APPLE_THUNK_BASE, 0x4000, PROT_READ | PROT_WRITE, 'thunks');
    as.writeU32(SENTINEL_VA, ARM64_RET_OPCODE, true);
    as.writeU32(THUNK_VA, ARM64_RET_OPCODE, true);
    as.mprotect(APPLE_THUNK_BASE, 0x4000, PROT_READ | PROT_EXEC);
    as.mmap(STACK_VA, 0x10000, PROT_READ | PROT_WRITE, 'stack');

    const asm = new Arm64Assembler();
    asm.stpPre64(29, 30, 31, -16); // Save FP & LR (16B aligned)
    asm.movReg(29, 31);
    asm.subImm(31, 31, 16); // Outgoing Apple ARM64 variadic stack frame (16B aligned)
    asm.movImm64(18, 0x18181818abcdef01n); // Platform register X18 sentinel
    asm.movImm64(10, 1337n);
    asm.strUImm64(10, 31, 0); // Stack slot 0 = 1337
    asm.movImm64(11, 9001n);
    asm.strUImm64(11, 31, 8); // Stack slot 1 = 9001
    asm.movImm64(1, 0xbad0001n); // Decoy X1 (must NOT be read by variadics!)
    asm.movImm64(2, 0xbad0002n); // Decoy X2
    asm.movImm64(3, 0xbad0003n); // Decoy X3
    asm.movImm64(9, THUNK_VA);
    asm.blr(9); // Call host thunk (attempts to clobber X18!)
    asm.addImm(31, 31, 16);
    asm.svc(0x80); // Call syscall (attempts to clobber X18!)
    asm.ldpPost64(29, 30, 31, 16);
    asm.ret();

    as.write(CODE_VA, asm.finalize(CODE_VA, new Map()));
    as.mprotect(CODE_VA, 0x4000, PROT_READ | PROT_EXEC);

    const sp = BigInt(STACK_VA + 0x8000);
    assert.equal(sp % 16n, 0n);

    let capturedVariadics = null;
    const cpu = createArm64Cpu({
      addressSpace: as,
      pid: 103,
      thunkStart: APPLE_THUNK_BASE,
      thunkEnd: APPLE_THUNK_BASE + 0x4000,
      exitSentinelVA: SENTINEL_VA,
      onThunk(pc, c) {
        assert.equal(Number(pc), THUNK_VA);
        capturedVariadics = c.readVariadicArgs(1, 2);
        // Hostile thunk tries to clobber X18 — CPU MUST restore X18!
        c.setReg(18, 0xdeaddeaddeaddeadn);
        c.setReg(0, 77n);
        return true;
      },
      onSyscall(c) {
        // Hostile syscall tries to clobber X18 — CPU MUST restore X18!
        c.setReg(18, 0x0n);
        c.setReg(0, 88n);
      },
    });
    cpu.setPC(CODE_VA);
    cpu.setSP(sp);
    cpu.setLR(SENTINEL_VA);

    const res = cpu.step(100);
    assert.equal(res.status, 'EXITED');
    assert.deepEqual(capturedVariadics, [1337n, 9001n], 'Apple ARM64 variadics must read strictly from [SP + i*8], ignoring decoy X1..X7');
    assert.equal(cpu.getReg(18), 0x18181818abcdef01n, 'X18 must be preserved across both host thunks and SVC syscalls');
    assert.equal(cpu.getReg(0), 88n);
    cpu.dispose();
  });

  it('enforces VMM __PAGEZERO SIGSEGV, NX_EXEC_VIOLATION, step budget SIGXCPU/E_CPU_QUOTA, and illegal opcode SIGILL', () => {
    const as = new AddressSpace({ pid: 104 });
    as.reserveGuard(0, 0x100000000, '__PAGEZERO');
    const CODE_VA = 0x100004000;
    const RW_VA = 0x100008000;
    as.mmap(CODE_VA, 0x4000, PROT_READ | PROT_WRITE, 'code');
    as.mmap(RW_VA, 0x4000, PROT_READ | PROT_WRITE, 'rw-data');
    as.writeU32(RW_VA, ARM64_NOP_OPCODE, true);

    // 1. __PAGEZERO read / write / fetch -> MemoryFaultError(SIGSEGV)
    assert.throws(
      () => as.read(0x100, 8),
      (err) => err instanceof MemoryFaultError && err.signal === 'SIGSEGV'
    );
    assert.throws(
      () => as.write(0x100, new Uint8Array(8)),
      (err) => err instanceof MemoryFaultError && err.signal === 'SIGSEGV'
    );
    const cpuGuard = createArm64Cpu({ addressSpace: as, pid: 104 });
    cpuGuard.setPC(0x100n);
    assert.throws(
      () => cpuGuard.step(10),
      (err) => err instanceof MemoryFaultError && err.signal === 'SIGSEGV'
    );
    cpuGuard.dispose();

    // 2. NX_EXEC_VIOLATION on RW (non-EXEC) page
    const cpuNx = createArm64Cpu({ addressSpace: as, pid: 104 });
    cpuNx.setPC(RW_VA);
    assert.throws(
      () => cpuNx.step(10),
      (err) => err instanceof MemoryFaultError && err.faultType === 'NX_EXEC_VIOLATION' && err.signal === 'SIGSEGV'
    );
    cpuNx.dispose();

    // 3. Infinite loop exceeds maxInstructions -> QuotaExceededError (E_CPU_QUOTA / SIGXCPU)
    as.writeU32(CODE_VA, 0x14000000, true); // B #0 (self-branch)
    as.mprotect(CODE_VA, 0x4000, PROT_READ | PROT_EXEC);
    const cpuLoop = createArm64Cpu({ addressSpace: as, pid: 104, maxInstructions: 25 });
    cpuLoop.setPC(CODE_VA);
    assert.throws(
      () => cpuLoop.step(100),
      (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.E_CPU_QUOTA
    );
    cpuLoop.dispose();

    // 4. Illegal opcode (0x00000000 UDF #0) -> IllegalInstructionError (SIGILL)
    as.mprotect(CODE_VA, 0x4000, PROT_READ | PROT_WRITE);
    as.writeU32(CODE_VA, 0x00000000, true);
    as.mprotect(CODE_VA, 0x4000, PROT_READ | PROT_EXEC);
    const cpuIll = createArm64Cpu({ addressSpace: as, pid: 104 });
    cpuIll.setPC(CODE_VA);
    assert.throws(
      () => cpuIll.step(10),
      (err) => err instanceof IllegalInstructionError && err.signal === 'SIGILL'
    );
    cpuIll.dispose();
  });
});

// ============================================================================
// SUITE 2 (`F-048`, Edge Cases `#19`–`#22`): Mach-O 64-bit & Universal Fat Loader
// ============================================================================

describe('Suite 2 (F-048, Edge Cases #19-#22): Mach-O 64-bit & Universal Fat Loader', () => {
  it('cross-checks real clang --target=aarch64-apple-darwin compiled Mach-O against llvm-objdump --macho --private-headers', () => {
    const dir = makeTempDir('omnios-m4-macho-');
    const cPath = path.join(dir, 'sample.c');
    const oPath = path.join(dir, 'sample.o');
    fs.writeFileSync(
      cPath,
      'long compute_sum(long a, long b) { return a * 3 + b + 7; }\n'
    );

    execFileSync('clang', ['--target=aarch64-apple-darwin', '-O2', '-c', cPath, '-o', oPath]);
    const objdumpOut = execFileSync('llvm-objdump', ['--macho', '--private-headers', oPath], {
      encoding: 'utf8',
    });
    assert.match(objdumpOut, /MH_MAGIC_64/);
    assert.match(objdumpOut, /ARM64/);

    const objBytes = fs.readFileSync(oPath);
    const parsed = parseMachO(objBytes);
    assert.equal(parsed.arch, 'arm64');
    assert.equal(parsed.header.magic, MACHO_CONSTANTS.MH_MAGIC_64);
    assert.equal(parsed.header.filetype, MACHO_CONSTANTS.MH_OBJECT);
    assert.ok(parsed.symbolsByName.has('_compute_sum'));
    assert.ok(parsed.sections.some((s) => s.sectname === '__text'));
  });

  it('Edge Case #19: rejects Java .class (0xCAFEBABE, version 52) with E_INVALID_FAT while parsing genuine 32-bit & 64-bit Universal Fat ARM64 + x86-64 binaries', () => {
    // Java 8 .class header: CAFEBABE 0000 0034 (minor=0, major=52 -> looks like nfat_arch=52 > 32)
    const javaClass8 = new Uint8Array(64);
    const jdv = new DataView(javaClass8.buffer);
    jdv.setUint32(0, 0xcafebabe, false);
    jdv.setUint16(4, 0, false);
    jdv.setUint16(6, 52, false);
    assert.throws(
      () => parseFatMachO(javaClass8),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_FAT
    );

    // Crafted Java-like CAFEBABE with nfat_arch=1 but invalid cputype=0x000A0001
    const fakeFat = new Uint8Array(48);
    const fdv = new DataView(fakeFat.buffer);
    fdv.setUint32(0, 0xcafebabe, false);
    fdv.setUint32(4, 1, false);
    fdv.setUint32(8, 0x000a0001, false);
    assert.throws(
      () => parseFatMachO(fakeFat),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_FAT
    );

    // Genuine Universal Fat (0xCAFEBABE) containing ARM64 + x86-64 Mach-O slices
    const armSlice = buildMachOArm64Mac({ appName: 'FatTest', universal: false });
    const x64Slice = buildMachOX86_64Mac({ appName: 'FatTest', universal: false });
    const fat32 = buildUniversalFatMachO([armSlice, x64Slice]);
    const parsedFat32 = parseFatMachO(fat32);
    assert.equal(parsedFat32.slices.length, 2);
    assert.deepEqual(
      parsedFat32.slices.map((s) => s.arch).sort(),
      ['arm64', 'x86_64']
    );

    const selArm = parseMachO(fat32, { preferredArch: 'arm64' });
    const selX64 = parseMachO(fat32, { preferredArch: 'x86_64' });
    assert.equal(selArm.arch, 'arm64');
    assert.equal(selX64.arch, 'x86_64');

    // Genuine 64-bit Universal Fat (0xCAFEBABF) with 32-byte fat_arch_64 descriptor
    const fat64Off = 0x4000;
    const fat64 = new Uint8Array(fat64Off + armSlice.byteLength);
    const d64 = new DataView(fat64.buffer);
    d64.setUint32(0, MACHO_CONSTANTS.FAT_MAGIC_64, false);
    d64.setUint32(4, 1, false);
    d64.setUint32(8, MACHO_CONSTANTS.CPU_TYPE_ARM64, false);
    d64.setUint32(12, 0, false);
    d64.setBigUint64(16, BigInt(fat64Off), false);
    d64.setBigUint64(24, BigInt(armSlice.byteLength), false);
    d64.setUint32(32, 14, false);
    d64.setUint32(36, 0, false);
    fat64.set(armSlice, fat64Off);

    const fat64Info = parseFatMachO(fat64);
    assert.equal(fat64Info.isFat64, true);
    const parsedFat64 = parseMachO(fat64, { preferredArch: 'arm64' });
    assert.equal(parsedFat64.arch, 'arm64');
    assert.equal(parsedFat64.isFat, true);
  });

  it('Edge Cases #20, #21, #22 + Chained Fixups, Dyld Info, RPATH, Build Version & Code Signature Entitlements', () => {
    // Edge Case #20: FairPlay cryptid = 1 MUST reject with FormatError(E_ENCRYPTED_BINARY)
    const encryptedBytes = buildSyntheticChainedFixupsMachO({ encrypt: true });
    assert.throws(
      () => parseMachO(encryptedBytes),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_ENCRYPTED_BINARY
    );
    const metaOnly = parseMachO(encryptedBytes, { allowEncrypted: true });
    assert.equal(metaOnly.encryptionInfo.cryptid, 1);
    const asEnc = new AddressSpace({ pid: 201 });
    assert.throws(
      () => loadMachOIntoAddressSpace(metaOnly, asEnc),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_ENCRYPTED_BINARY
    );

    // Unencrypted Mach-O with __PAGEZERO, LC_MAIN, LC_DYLD_CHAINED_FIXUPS, LC_CODE_SIGNATURE, LC_RPATH, LC_BUILD_VERSION
    const machoBytes = buildSyntheticChainedFixupsMachO({ encrypt: false });
    const parsed = parseMachO(machoBytes);
    assert.equal(parsed.dylibs.length, 1);
    assert.equal(parsed.dylibs[0].name, '/usr/lib/libSystem.B.dylib');
    assert.deepEqual(parsed.rpaths, ['@executable_path/../Frameworks']);
    assert.equal(parsed.buildVersion.platform, 'macos');
    assert.equal(parsed.entitlements['com.omnios.test.chained'], 'verified');

    // Load with non-zero ASLR slide = 0x100000
    const SLIDE = 0x100000;
    const as = new AddressSpace({ pid: 202 });
    const loaded = loadMachOIntoAddressSpace(parsed, as, { slide: SLIDE });

    // Edge Case #21: __PAGEZERO occupies 0 mapped pages / 0 bytes RAM and faults with SIGSEGV
    const pzSeg = loaded.segments.find((s) => s.segname === '__PAGEZERO');
    assert.equal(pzSeg.isGuard, true);
    assert.ok(as.getStats().usedBytes < 1024 * 1024, '__PAGEZERO must NOT allocate 4 GiB RAM');
    assert.throws(
      () => as.read(0x1000, 8),
      (err) => err instanceof MemoryFaultError && err.signal === 'SIGSEGV'
    );

    // Edge Case #22: LC_MAIN entry VA == __TEXT.vmaddr + slide + entryoff
    assert.equal(loaded.entryVA, 0x100000000 + SLIDE + 0x1000);

    // Chained fixups verified in loaded __DATA memory (bind + rebase with ASLR slide)
    const dataVA = BigInt(0x100004000 + SLIDE);
    const boundSlot = as.readU64(dataVA, true);
    const rebasedSlot = as.readU64(dataVA + 8n, true);
    assert.equal(loaded.thunkTable.get(Number(boundSlot))?.symbol, '_demo_ext_sym');
    assert.equal(rebasedSlot, BigInt(0x100001000 + SLIDE));

    // Also verify LC_DYLD_INFO_ONLY rebases & binds from SDK ARM64 Mach-O
    const iosMachO = buildMachOArm64({ bundleId: 'com.test.dyld', appName: 'DyldCheck' });
    const parsedIos = parseMachO(iosMachO);
    assert.ok(parsedIos.rebases.length > 0, 'LC_DYLD_INFO_ONLY rebases parsed');
    assert.ok(parsedIos.binds.length > 0, 'LC_DYLD_INFO_ONLY binds parsed');
    assert.ok(parsedIos.symbols.length > 0, 'LC_SYMTAB symbols parsed');
    assert.ok(parsedIos.indirectSymtab.length > 0, 'LC_DYSYMTAB indirect symtab parsed');
  });
});

// ============================================================================
// SUITE 3 (`F-049`, Edge Case `#27`): Apple `bplist00` & XML 1.0 Plist Codec
// ============================================================================

describe('Suite 3 (F-049, Edge Case #27): Apple bplist00 & XML 1.0 Plist Codec', () => {
  it('round-trips complex payloads bidirectionally with host Python 3 plistlib (FMT_BINARY & FMT_XML) and honors CF epoch, signed 8B ints, UTF-16BE, data, PlistUID & extended containers', () => {
    const cfEpochDate = new Date(CF_EPOCH_MS); // 2001-01-01T00:00:00.000Z
    const modernDate = new Date(Date.UTC(2026, 10, 21, 12, 30, 0));
    const preEpochDate = new Date(Date.UTC(1995, 5, 15, 0, 0, 0));
    const extendedArray = Array.from({ length: 20 }, (_, i) => `item-${i}`);
    const payload = {
      ascii: 'OmniOS Apple Plist',
      unicode: 'Weather ☀️ 東京 🚀 & <xml>',
      negOne: -1,
      negLarge: -900719925474099,
      uint1: 200,
      uint2: 60000,
      uint4: 3000000000,
      flt: 3.1415926535,
      flagT: true,
      flagF: false,
      cfEpoch: cfEpochDate,
      modernDate,
      preEpochDate,
      rawBytes: new Uint8Array([0x00, 0xde, 0xad, 0xbe, 0xef, 0xff]),
      uidVal: new PlistUID(42),
      extendedArray,
      nested: { a: 'shared-dag-str', b: 'shared-dag-str' },
    };

    const binBuf = writeBinaryPlist(payload);
    assert.equal(isBinaryPlist(binBuf), true);
    const decodedLocal = parseBinaryPlist(binBuf);
    assert.equal(decodedLocal.ascii, payload.ascii);
    assert.equal(decodedLocal.unicode, payload.unicode);
    assert.equal(decodedLocal.negOne, -1);
    assert.equal(decodedLocal.negLarge, -900719925474099);
    assert.equal(decodedLocal.uint1, 200);
    assert.equal(decodedLocal.uint2, 60000);
    assert.equal(decodedLocal.uint4, 3000000000);
    assert.equal(decodedLocal.cfEpoch.toISOString(), '2001-01-01T00:00:00.000Z');
    assert.equal(decodedLocal.modernDate.toISOString(), modernDate.toISOString());
    assert.equal(decodedLocal.preEpochDate.toISOString(), preEpochDate.toISOString());
    assert.deepEqual(Array.from(decodedLocal.rawBytes), [0x00, 0xde, 0xad, 0xbe, 0xef, 0xff]);
    assert.ok(decodedLocal.uidVal instanceof PlistUID && decodedLocal.uidVal.value === 42);
    assert.equal(decodedLocal.extendedArray.length, 20);

    // Host Python 3 `plistlib` bidirectional binary & XML oracle
    const pyResult = JSON.parse(
      runPython(
        `
import sys, json, base64, plistlib, datetime
raw_bplist = base64.b64decode(sys.stdin.read())
obj = plistlib.loads(raw_bplist)
assert obj['ascii'] == 'OmniOS Apple Plist'
assert obj['unicode'] == 'Weather ☀️ 東京 🚀 & <xml>'
assert obj['negOne'] == -1
assert obj['negLarge'] == -900719925474099
assert obj['uint4'] == 3000000000
assert obj['cfEpoch'].isoformat() == '2001-01-01T00:00:00'
assert obj['rawBytes'] == bytes([0x00, 0xde, 0xad, 0xbe, 0xef, 0xff])
assert isinstance(obj['uidVal'], plistlib.UID) and obj['uidVal'].data == 42
assert len(obj['extendedArray']) == 20

# Re-emit from Python in both FMT_BINARY and FMT_XML for OmniOS to parse
py_payload = {
    'fromPython': 'こんにちは 🌍',
    'neg64': -900719925474099,
    'epoch': datetime.datetime(2001, 1, 1, 0, 0, 0),
    'blob': b'\\x01\\x02\\x03\\x04',
    'list20': list(range(20)),
}
out_bin = plistlib.dumps(py_payload, fmt=plistlib.FMT_BINARY)
out_xml = plistlib.dumps(py_payload, fmt=plistlib.FMT_XML)
print(json.dumps({
    'bin_b64': base64.b64encode(out_bin).decode('ascii'),
    'xml': out_xml.decode('utf-8'),
}))
`,
        Buffer.from(binBuf).toString('base64')
      )
    );

    const parsedPyBin = parsePlist(Buffer.from(pyResult.bin_b64, 'base64'));
    assert.equal(parsedPyBin.fromPython, 'こんにちは 🌍');
    assert.equal(parsedPyBin.neg64, -900719925474099);
    assert.equal(parsedPyBin.epoch.toISOString(), '2001-01-01T00:00:00.000Z');
    assert.deepEqual(Array.from(parsedPyBin.blob), [1, 2, 3, 4]);
    assert.equal(parsedPyBin.list20.length, 20);

    const parsedPyXml = parsePlist(pyResult.xml);
    assert.equal(parsedPyXml.fromPython, 'こんにちは 🌍');
    assert.equal(parsedPyXml.neg64, -900719925474099);

    // XML write -> parse round-trip
    const xmlStr = writeXmlPlist({ greeting: 'Hi & <Bye>', nums: [-1, 0, 42], when: cfEpochDate });
    const xmlBack = parseXmlPlist(xmlStr);
    assert.equal(xmlBack.greeting, 'Hi & <Bye>');
    assert.deepEqual(xmlBack.nums, [-1, 0, 42]);
    assert.equal(xmlBack.when.toISOString(), '2001-01-01T00:00:00.000Z');
  });

  it('Edge Case #27: rejects cyclic bplist00 (A -> B -> A) with E_CYCLIC_PLIST while allowing non-cyclic DAG shared refs', () => {
    // Hand-craft binary bplist00 with 2 objects: Obj 0 = Array[1] -> Obj 1, Obj 1 = Array[1] -> Obj 0
    // Header(8) + Obj0(2: 0xA1, 0x01) + Obj1(2: 0xA1, 0x00) + OffsetTable(2: 8, 10) + Trailer(32)
    const cyclic = new Uint8Array(8 + 2 + 2 + 2 + 32);
    cyclic.set(TEXT_ENCODER.encode('bplist00'), 0);
    cyclic[8] = 0xa1;
    cyclic[9] = 1; // A -> B
    cyclic[10] = 0xa1;
    cyclic[11] = 0; // B -> A
    cyclic[12] = 8; // offset of Obj 0
    cyclic[13] = 10; // offset of Obj 1
    const tdv = new DataView(cyclic.buffer, 14, 32);
    tdv.setUint8(6, 1); // offsetIntSize = 1
    tdv.setUint8(7, 1); // objectRefSize = 1
    tdv.setBigUint64(8, 2n, false); // numObjects = 2
    tdv.setBigUint64(16, 0n, false); // topObject = 0
    tdv.setBigUint64(24, 12n, false); // offsetTableOffset = 12

    assert.throws(
      () => parseBinaryPlist(cyclic),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_CYCLIC_PLIST
    );

    // Non-cyclic DAG: Obj 0 = Array[2] -> [Obj 1, Obj 1], Obj 1 = ASCII string "dag"
    const dag = new Uint8Array(8 + 3 + 4 + 2 + 32);
    dag.set(TEXT_ENCODER.encode('bplist00'), 0);
    dag[8] = 0xa2;
    dag[9] = 1;
    dag[10] = 1;
    dag[11] = 0x53; // ASCII string len 3
    dag.set(TEXT_ENCODER.encode('dag'), 12);
    dag[15] = 8;
    dag[16] = 11;
    const ddv = new DataView(dag.buffer, 17, 32);
    ddv.setUint8(6, 1);
    ddv.setUint8(7, 1);
    ddv.setBigUint64(8, 2n, false);
    ddv.setBigUint64(16, 0n, false);
    ddv.setBigUint64(24, 15n, false);

    assert.deepEqual(parseBinaryPlist(dag), ['dag', 'dag']);
  });
});

// ============================================================================
// SUITE 4 (`F-051`, Edge Case `#25`): Darwin / XNU BSD Syscalls & Mach Traps
// ============================================================================

describe('Suite 4 (F-051, Edge Case #25): Darwin / XNU BSD Syscalls & Mach Traps', () => {
  it('translates Darwin O_* flags, executes ARM64 SVC #0x80 & x86-64 SYSCALL Carry-flag error semantics, live VFS ops, stat64 S_IF* bits, sysctl/getentropy & Mach traps', async () => {
    // 1. Verify Darwin O_* flag translation
    const linuxFlags = translateDarwinOpenFlags(
      DARWIN_O_FLAGS.O_RDWR |
        DARWIN_O_FLAGS.O_CREAT |
        DARWIN_O_FLAGS.O_TRUNC |
        DARWIN_O_FLAGS.O_APPEND |
        DARWIN_O_FLAGS.O_EXCL |
        DARWIN_O_FLAGS.O_DIRECTORY
    );
    assert.ok((linuxFlags & OPEN_FLAGS.O_CREAT) !== 0);
    assert.ok((linuxFlags & OPEN_FLAGS.O_TRUNC) !== 0);
    assert.ok((linuxFlags & OPEN_FLAGS.O_APPEND) !== 0);
    assert.ok((linuxFlags & OPEN_FLAGS.O_EXCL) !== 0);
    assert.ok((linuxFlags & OPEN_FLAGS.O_DIRECTORY) !== 0);

    const stack = await bootFullM4Stack('omnios-m4-darwin-');
    const as = new AddressSpace({ pid: 301 });
    const DATA_VA = 0x100010000;
    as.mmap(DATA_VA, 0x10000, PROT_READ | PROT_WRITE, 'darwin-scratch');

    const pcb = {
      pid: 301,
      ppid: 1,
      uid: 1000,
      gid: 1000,
      cwd: '/home/user',
      fdTable: new Map(),
      addressSpace: as,
    };

    const syscalls = createDarwinSyscalls({
      pcb,
      addressSpace: as,
      vfs: stack.vfs,
      processManager: stack.kernel.processManager,
      platform: 'macos',
      arch: 'arm64',
      appId: 'com.test.darwin',
      cwd: '/home/user',
      sandboxRoot: '/home/user',
      pid: 301,
      uid: 1000,
      gid: 1000,
    });

    const armCpu = createArm64Cpu({ addressSpace: as, pid: 301 });
    const writeCStr = (va, str) => {
      const b = TEXT_ENCODER.encode(`${str}\0`);
      as.write(va, b);
      return BigInt(va);
    };

    // Edge Case #25 (ARM64): ENOENT sets PSTATE.C = 1 + positive DARWIN_ERRNO.ENOENT (2) in X0
    const missingPtr = writeCStr(DATA_VA + 0x0, '/home/user/does-not-exist.txt');
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_open));
    armCpu.setReg(0, missingPtr);
    armCpu.setReg(1, BigInt(DARWIN_O_FLAGS.O_RDONLY));
    armCpu.setReg(2, 0o644n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 1, 'ARM64 Darwin BSD error MUST set PSTATE.C = 1');
    assert.equal(armCpu.getReg(0), BigInt(DARWIN_ERRNO.ENOENT));

    // Edge Case #25 (x86-64): 0x2000000 + SYS_open on missing file sets RFLAGS.CF = 1 + positive ENOENT in RAX
    const x64Cpu = {
      regs: { rax: 0n, rdi: 0n, rsi: 0n, rdx: 0n, r10: 0n, r8: 0n, r9: 0n },
      flags: { CF: 0 },
      getReg(n) { return this.regs[n] ?? 0n; },
      setReg(n, v) { this.regs[n] = BigInt.asUintN(64, v); },
      setFlag(f, b) { this.flags[f] = b ? 1 : 0; },
    };
    x64Cpu.setReg('rax', BigInt(0x2000000 + DARWIN_SYSCALLS.SYS_open));
    x64Cpu.setReg('rdi', missingPtr);
    x64Cpu.setReg('rsi', BigInt(DARWIN_O_FLAGS.O_RDONLY));
    x64Cpu.setReg('rdx', 0o644n);
    syscalls.handleX86_64Syscall(x64Cpu);
    assert.equal(x64Cpu.flags.CF, 1, 'x86-64 Darwin BSD error MUST set RFLAGS.CF = 1');
    assert.equal(x64Cpu.getReg('rax'), BigInt(DARWIN_ERRNO.ENOENT));

    // x86-64 success clears RFLAGS.CF = 0 (SYS_getpid)
    x64Cpu.setReg('rax', BigInt(0x2000000 + DARWIN_SYSCALLS.SYS_getpid));
    syscalls.handleX86_64Syscall(x64Cpu);
    assert.equal(x64Cpu.flags.CF, 0);
    assert.equal(x64Cpu.getReg('rax'), 301n);

    // Live VFS cycle via ARM64 Darwin syscalls: mkdir -> chdir -> open_nocancel -> write_nocancel -> lseek -> read_nocancel -> stat64 -> close_nocancel -> unlink
    const dirPtr = writeCStr(DATA_VA + 0x100, '/home/user/darwin-dir');
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_mkdir));
    armCpu.setReg(0, dirPtr);
    armCpu.setReg(1, 0o755n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);

    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_chdir));
    armCpu.setReg(0, dirPtr);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);

    const filePtr = writeCStr(DATA_VA + 0x200, 'hello.txt');
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_open_nocancel));
    armCpu.setReg(0, filePtr);
    armCpu.setReg(1, BigInt(DARWIN_O_FLAGS.O_RDWR | DARWIN_O_FLAGS.O_CREAT | DARWIN_O_FLAGS.O_TRUNC));
    armCpu.setReg(2, 0o644n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    const fd = armCpu.getReg(0);
    assert.ok(fd >= 3n);

    const msgBytes = TEXT_ENCODER.encode('Darwin-XNU-Live-VFS');
    as.write(DATA_VA + 0x300, msgBytes);
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_write_nocancel));
    armCpu.setReg(0, fd);
    armCpu.setReg(1, BigInt(DATA_VA + 0x300));
    armCpu.setReg(2, BigInt(msgBytes.byteLength));
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    assert.equal(armCpu.getReg(0), BigInt(msgBytes.byteLength));

    // lseek to 0
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_lseek));
    armCpu.setReg(0, fd);
    armCpu.setReg(1, 0n);
    armCpu.setReg(2, 0n); // SEEK_SET
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    assert.equal(armCpu.getReg(0), 0n);

    // read_nocancel back
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_read_nocancel));
    armCpu.setReg(0, fd);
    armCpu.setReg(1, BigInt(DATA_VA + 0x400));
    armCpu.setReg(2, 64n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    assert.equal(
      TEXT_DECODER.decode(as.read(DATA_VA + 0x400, Number(armCpu.getReg(0)))),
      'Darwin-XNU-Live-VFS'
    );

    // stat64 on file (verify S_IFREG = 0o100000) & dir (verify S_IFDIR = 0o040000)
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_stat64));
    armCpu.setReg(0, filePtr);
    armCpu.setReg(1, BigInt(DATA_VA + 0x500));
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    const fileMode = as.readU16(DATA_VA + 0x504, true);
    assert.equal(fileMode & 0o170000, 0o100000, 'stat64 must OR S_IFREG into st_mode');

    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_stat64));
    armCpu.setReg(0, dirPtr);
    armCpu.setReg(1, BigInt(DATA_VA + 0x600));
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    const dirMode = as.readU16(DATA_VA + 0x604, true);
    assert.equal(dirMode & 0o170000, 0o040000, 'stat64 must OR S_IFDIR into st_mode');

    // close_nocancel + unlink
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_close_nocancel));
    armCpu.setReg(0, fd);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);

    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_unlink));
    armCpu.setReg(0, filePtr);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);

    // getuid, gettimeofday, mmap/munmap, sysctl, sysctlbyname, getentropy
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_getuid));
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.getReg(0), 1000n);

    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_gettimeofday));
    armCpu.setReg(0, BigInt(DATA_VA + 0x700));
    armCpu.setReg(1, 0n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    assert.ok(as.readU64(DATA_VA + 0x700, true) > 1_700_000_000n);

    // mmap anon + munmap
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_mmap));
    armCpu.setReg(0, 0n);
    armCpu.setReg(1, 0x2000n);
    armCpu.setReg(2, BigInt(PROT_READ | PROT_WRITE));
    armCpu.setReg(3, 0x1002n); // MAP_PRIVATE | MAP_ANON
    armCpu.setReg(4, BigInt.asUintN(64, -1n));
    armCpu.setReg(5, 0n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    const mappedVA = armCpu.getReg(0);
    assert.ok(mappedVA > 0n);
    as.writeU32(mappedVA, 0xcafef00d, true);
    assert.equal(as.readU32(mappedVA, true), 0xcafef00d);

    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_munmap));
    armCpu.setReg(0, mappedVA);
    armCpu.setReg(1, 0x2000n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);

    // sysctlbyname("kern.ostype") -> "Darwin"
    const sysNamePtr = writeCStr(DATA_VA + 0x800, 'kern.ostype');
    as.writeU64(DATA_VA + 0x840, 32n, true);
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_sysctlbyname));
    armCpu.setReg(0, sysNamePtr);
    armCpu.setReg(1, BigInt('kern.ostype'.length));
    armCpu.setReg(2, BigInt(DATA_VA + 0x880));
    armCpu.setReg(3, BigInt(DATA_VA + 0x840));
    armCpu.setReg(4, 0n);
    armCpu.setReg(5, 0n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    assert.equal(as.readCString(DATA_VA + 0x880, 32), 'Darwin');

    // sysctl([CTL_KERN=1, KERN_OSTYPE=1]) -> "Darwin"
    as.writeU32(DATA_VA + 0x900, 1, true);
    as.writeU32(DATA_VA + 0x904, 1, true);
    as.writeU64(DATA_VA + 0x920, 32n, true);
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_sysctl));
    armCpu.setReg(0, BigInt(DATA_VA + 0x900));
    armCpu.setReg(1, 2n);
    armCpu.setReg(2, BigInt(DATA_VA + 0x940));
    armCpu.setReg(3, BigInt(DATA_VA + 0x920));
    armCpu.setReg(4, 0n);
    armCpu.setReg(5, 0n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    assert.equal(as.readCString(DATA_VA + 0x940, 32), 'Darwin');

    // getentropy
    armCpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_getentropy));
    armCpu.setReg(0, BigInt(DATA_VA + 0xa00));
    armCpu.setReg(1, 32n);
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.pstate.C, 0);
    const entropy = as.read(DATA_VA + 0xa00, 32);
    assert.ok(entropy.some((b) => b !== 0));

    // Mach Traps: task_self_trap (-28), mach_timebase_info_trap (-89), mach_absolute_time (-3)
    armCpu.setReg(16, BigInt.asUintN(64, BigInt(MACH_TRAPS.task_self_trap)));
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.ok(armCpu.getReg(0) > 0n);

    armCpu.setReg(16, BigInt.asUintN(64, BigInt(MACH_TRAPS.mach_timebase_info_trap)));
    armCpu.setReg(0, BigInt(DATA_VA + 0xb00));
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.equal(armCpu.getReg(0), 0n);
    assert.equal(as.readU32(DATA_VA + 0xb00, true), 1);
    assert.equal(as.readU32(DATA_VA + 0xb04, true), 1);

    armCpu.setReg(16, BigInt.asUintN(64, BigInt(MACH_TRAPS.mach_absolute_time)));
    syscalls.handleArm64Svc(armCpu, 0x80);
    assert.ok(armCpu.getReg(0) > 0n);

    syscalls.dispose();
    armCpu.dispose();
  });
});

// ============================================================================
// SUITE 5 (`F-052`, Edge Case `#26`): Objective-C ABI2 & Swift Runtime
// ============================================================================

describe('Suite 5 (F-052, Edge Case #26): Objective-C ABI2 & Swift Runtime', () => {
  it('enforces nil-safe objc_msgSend / objc_msgSendSuper2 (Edge Case #26), ARC VMM heap freeing, free(0n), Foundation + live ConfigStore/VFS, stack-slot NSLog, App IMP dispatch & Swift swiftcall', async () => {
    const stack = await bootFullM4Stack('omnios-m4-objc-');
    const pcb = stack.kernel.processManager.spawn({
      name: 'objc-unit-proc',
      appId: 'com.omnios.test.objc',
      platform: 'macos',
      arch: 'arm64',
      uid: 1000,
      gid: 1000,
      cwd: '/home/user',
      autoReady: false,
    });
    const as = pcb.addressSpace;
    as.reserveGuard(0, 0x100000000, '__PAGEZERO');
    const STACK_VA = APPLE_STACK_BASE;
    const SENTINEL_VA = APPLE_THUNK_BASE;
    as.mmap(STACK_VA, 0x10000, PROT_READ | PROT_WRITE, 'stack');
    as.mmap(SENTINEL_VA, 0x1000, PROT_READ | PROT_EXEC, 'sentinel');

    const rt = createObjCRuntime({
      addressSpace: as,
      vfs: stack.vfs,
      configStore: stack.configStore,
      processManager: stack.kernel.processManager,
      pcb,
      platform: 'macos',
      appId: 'com.omnios.test.objc',
      sandboxRoot: '/home/user',
      cwd: '/home/user',
      uid: 1000,
      gid: 1000,
    });

    const cpu = createArm64Cpu({ addressSpace: as, pid: pcb.pid, exitSentinelVA: SENTINEL_VA });
    const sp = BigInt(STACK_VA + 0x8000);
    cpu.setSP(sp);
    cpu.setLR(SENTINEL_VA);

    // Edge Case #26: objc_msgSend(0n, ...) and objc_msgSendSuper2 with nil receiver return 0n without faulting
    const anySel = rt.selRegisterName('doSomethingDangerous:');
    assert.equal(rt.msgSend(cpu, 0n, anySel, [123n]), 0n);

    const superStructVA = BigInt(as.alloc(16));
    as.writeU64(superStructVA, 0n, true); // receiver = nil
    as.writeU64(superStructVA + 8n, rt.getClass('NSObject'), true);
    cpu.setReg(0, superStructVA);
    cpu.setReg(1, anySel);
    rt.handleThunk('_objc_msgSendSuper2', cpu);
    assert.equal(cpu.getReg(0), 0n, 'objc_msgSendSuper2 with nil receiver MUST return 0n');

    // ARC refcounting + autorelease pool + real VMM heap free + free(0n) safety
    const objCls = rt.getClass('NSObject');
    const objPtr = rt.msgSend(cpu, rt.msgSend(cpu, objCls, 'alloc', []), 'init', []);
    assert.ok(objPtr > 0n);
    assert.equal(rt.getRetainCount(objPtr), 1);
    rt.retain(objPtr);
    assert.equal(rt.getRetainCount(objPtr), 2);

    const poolTok = rt.autoreleasePoolPush();
    rt.autorelease(objPtr);
    rt.release(objPtr, cpu); // refcount -> 1 (still alive until pool pop)
    assert.equal(rt.getRetainCount(objPtr), 1);
    rt.autoreleasePoolPop(poolTok, cpu); // refcount -> 0 -> freed from VMM heap
    assert.equal(rt.getRetainCount(objPtr), 0);

    // free(0n) MUST be a safe no-op
    cpu.setReg(0, 0n);
    rt.handleThunk('_free', cpu);

    // Foundation: NSString, NSArray, NSDictionary, NSUserDefaults (incl. remove()), NSFileManager
    const nsStr = rt.createNSString('Hello-ObjC');
    assert.equal(rt.readNSString(nsStr), 'Hello-ObjC');
    assert.equal(rt.msgSend(cpu, nsStr, 'length', []), 10n);

    const arr = rt.createNSArray([nsStr, rt.createNSString('Second')]);
    assert.equal(rt.msgSend(cpu, arr, 'count', []), 2n);
    assert.equal(rt.readNSString(rt.msgSend(cpu, arr, 'objectAtIndex:', [1n])), 'Second');

    const dict = rt.createNSDictionary([['alpha', rt.createNSString('beta')]]);
    const alphaVal = rt.msgSend(cpu, dict, 'objectForKey:', [rt.createNSString('alpha')]);
    assert.equal(rt.readNSString(alphaVal), 'beta');

    // NSUserDefaults live UnifiedConfigStore sync including removeObjectForKey -> defaults.remove()
    const defaultsCls = rt.getClass('NSUserDefaults');
    const stdDefaults = rt.msgSend(cpu, defaultsCls, 'standardUserDefaults', []);
    const keyPtr = rt.createNSString('objc.test.key');
    const valPtr = rt.createNSString('persisted-value');
    rt.msgSend(cpu, stdDefaults, 'setObject:forKey:', [valPtr, keyPtr]);
    assert.equal(
      stack.configStore.defaults.get('com.omnios.test.objc', 'objc.test.key'),
      'persisted-value'
    );
    assert.equal(
      rt.readNSString(rt.msgSend(cpu, stdDefaults, 'stringForKey:', [keyPtr])),
      'persisted-value'
    );
    rt.msgSend(cpu, stdDefaults, 'removeObjectForKey:', [keyPtr]);
    assert.equal(stack.configStore.defaults.get('com.omnios.test.objc', 'objc.test.key'), null);

    // NSFileManager backed live by VFS
    const fmCls = rt.getClass('NSFileManager');
    const fm = rt.msgSend(cpu, fmCls, 'defaultManager', []);
    const fmPath = rt.createNSString('/home/user/objc-fm-test.txt');
    const fmData = rt.createNSData(TEXT_ENCODER.encode('ObjC-VFS-Content'));
    const created = rt.msgSend(cpu, fm, 'createFileAtPath:contents:attributes:', [fmPath, fmData, 0n]);
    assert.equal(created, 1n);
    assert.equal(rt.msgSend(cpu, fm, 'fileExistsAtPath:', [fmPath]), 1n);
    assert.equal(stack.vfs.readFile('/home/user/objc-fm-test.txt', { encoding: 'utf8', uid: 0, gid: 0 }), 'ObjC-VFS-Content');

    // NSLog Apple ARM64 stack-slot variadics (ignores decoy X1..X7!)
    const fmtStr = rt.createNSString('TAG=%@ NUM=%lld');
    const tagStr = rt.createNSString('REAL_STACK');
    const decoyStr = rt.createNSString('DECOY_REG');
    as.writeU64(sp + 0n, tagStr, true);
    as.writeU64(sp + 8n, 4242n, true);
    cpu.setReg(0, fmtStr);
    cpu.setReg(1, decoyStr);
    cpu.setReg(2, 99999n);
    rt.handleThunk('_NSLog', cpu);
    const logged = stack.kernel.processManager.readStderr(pcb.pid);
    assert.match(logged, /TAG=REAL_STACK NUM=4242/);
    assert.doesNotMatch(logged, /DECOY_REG/);

    // Real ARM64 App IMP loaded via loadMachOObjC (`__objc_classlist` + `__objc_selrefs` + `__objc_methname`) + superclass fallback
    const appMachO = buildMachOArm64({ bundleId: 'com.test.imp', appName: 'ImpTest', delegateClassName: 'CustomImpDelegate' });
    const parsedApp = parseMachO(appMachO);
    const as2 = new AddressSpace({ pid: 402 });
    let rt2 = null;
    const ensureRt2 = () => {
      if (!rt2) {
        rt2 = createObjCRuntime({ addressSpace: as2, vfs: stack.vfs, configStore: stack.configStore, appId: 'com.test.imp' });
      }
      return rt2;
    };
    const loaded2 = loadMachOIntoAddressSpace(parsedApp, as2, {
      resolveSymbol: (sym) => ensureRt2().resolveMachOSymbol(sym),
    });
    const objcInfo = ensureRt2().loadMachOObjC(loaded2);
    assert.ok(objcInfo.classes.includes('CustomImpDelegate'));
    assert.ok(objcInfo.selectors.length > 0);
    // Superclass fallback: CustomImpDelegate inherits NSObject's `isEqual:` / `class`
    const cpu2 = createArm64Cpu({ addressSpace: as2, pid: 402, exitSentinelVA: loaded2.exitSentinelVA });
    cpu2.setSP(loaded2.initialSP);
    cpu2.setLR(loaded2.exitSentinelVA);
    const delCls = rt2.getClass('CustomImpDelegate');
    const delInst = rt2.msgSend(cpu2, rt2.msgSend(cpu2, delCls, 'alloc', []), 'init', []);
    assert.equal(rt2.msgSend(cpu2, delInst, 'isEqual:', [delInst]), 1n, 'Superclass NSObject fallback works');
    // Direct ARM64 App IMP execution via ObjC dispatch (`invokeAppImp` on real ARM64 code)
    const APP_IMP_VA = 0x100040000;
    as2.mmap(APP_IMP_VA, 0x4000, PROT_READ | PROT_WRITE, 'app-imp');
    const impAsm = new Arm64Assembler();
    impAsm.addReg(0, 2, 3); // return arg1 (X2) + arg2 (X3)
    impAsm.ret();
    as2.write(APP_IMP_VA, impAsm.finalize(APP_IMP_VA, new Map()));
    as2.mprotect(APP_IMP_VA, 0x4000, PROT_READ | PROT_EXEC);
    const addSel = rt2.selRegisterName('addA:toB:');
    assert.equal(
      rt2.invokeAppImp(cpu2, BigInt(APP_IMP_VA), delInst, addSel, [19n, 23n]),
      42n,
      'Real ARM64 App IMP dispatch must execute guest A64 instructions and return 42n'
    );
    rt2.dispose();
    cpu2.dispose();

    // Swift `swiftcall` (`X20` self, `swift_allocObject`/`swift_retain`/`swift_release`)
    const SWIFT_VA = 0x100020000;
    as.mmap(SWIFT_VA, 0x4000, PROT_READ | PROT_WRITE, 'swift-text');
    const sAsm = new Arm64Assembler();
    // Swift method: load i64 field at [X20 + 16], add X0 (arg0), return in X0
    sAsm.ldrUImm64(9, 20, 16);
    sAsm.addReg(0, 9, 0);
    sAsm.ret();
    as.write(SWIFT_VA, sAsm.finalize(SWIFT_VA, new Map()));
    as.mprotect(SWIFT_VA, 0x4000, PROT_READ | PROT_EXEC);

    cpu.setReg(0, 0x11223344n); // metadataPtr
    cpu.setReg(1, 32n); // requiredSize
    rt.handleThunk('_swift_allocObject', cpu);
    const swiftObj = cpu.getReg(0);
    assert.ok(swiftObj > 0n);
    as.writeU64(swiftObj + 16n, 500n, true);

    const swiftResult = rt.invokeSwiftMethod(cpu, BigInt(SWIFT_VA), swiftObj, [42n]);
    assert.equal(swiftResult.result, 542n, 'Swift swiftcall passes self in X20');
    assert.equal(swiftResult.swiftError, 0n);
    assert.equal(swiftResult.instructionsExecuted, 3);

    cpu.setReg(0, swiftObj);
    rt.handleThunk('_swift_retain', cpu);
    assert.equal(as.readU64(swiftObj + 8n, true), 2n);
    cpu.setReg(0, swiftObj);
    rt.handleThunk('_swift_release', cpu);
    assert.equal(as.readU64(swiftObj + 8n, true), 1n);
    cpu.setReg(0, swiftObj);
    rt.handleThunk('_swift_release', cpu);

    rt.dispose();
    cpu.dispose();
  });
});

// ============================================================================
// SUITE 6 (`F-053`, `F-057`): iOS Runtime, `.ipa`, UIKit, Dynamic Island & SpringBoard Sandbox
// ============================================================================

describe('Suite 6 (F-053, F-057): iOS Runtime, .ipa, UIKit, Dynamic Island & SpringBoard Sandbox', () => {
  it('passes external Python 3 zipfile + plistlib + llvm-objdump oracles on packages/ios-weather-island.ipa', () => {
    const ipaPath = path.join(PACKAGES_DIR, 'ios-weather-island.ipa');
    assert.ok(fs.existsSync(ipaPath), 'packages/ios-weather-island.ipa must exist');

    const tmpDir = makeTempDir('omnios-m4-ios-oracle-');
    const binOut = path.join(tmpDir, 'WeatherIsland');
    const pyCheck = JSON.parse(
      runPython(
        `
import sys, json, zipfile, plistlib
ipa_path, bin_out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(ipa_path, 'r') as zf:
    assert zf.testzip() is None, 'ZIP CRC check failed'
    names = zf.namelist()
    plist_raw = zf.read('Payload/WeatherIsland.app/Info.plist')
    assert plist_raw[:8] == b'bplist00', 'Info.plist must be binary bplist00'
    info = plistlib.loads(plist_raw)
    exec_name = info['CFBundleExecutable']
    macho = zf.read(f'Payload/WeatherIsland.app/{exec_name}')
    with open(bin_out, 'wb') as f:
        f.write(macho)
print(json.dumps({
    'bundleId': info['CFBundleIdentifier'],
    'displayName': info['CFBundleDisplayName'],
    'liveActivities': info.get('NSSupportsLiveActivities'),
    'urlSchemes': info['CFBundleURLTypes'][0]['CFBundleURLSchemes'],
    'machoBytes': len(macho),
    'entries': names,
}))
`,
        null,
        [ipaPath, binOut]
      )
    );

    assert.equal(pyCheck.bundleId, 'com.omnios.ios.weather-island');
    assert.equal(pyCheck.displayName, 'Weather Island');
    assert.equal(pyCheck.liveActivities, true);
    assert.ok(pyCheck.urlSchemes.includes('omniweather'));
    assert.ok(pyCheck.machoBytes > 16384);

    const objdumpHdr = execFileSync('llvm-objdump', ['--macho', '--private-headers', binOut], {
      encoding: 'utf8',
    });
    assert.match(objdumpHdr, /MH_MAGIC_64/);
    assert.match(objdumpHdr, /ARM64/);
    assert.match(objdumpHdr, /__PAGEZERO/);
    assert.match(objdumpHdr, /LC_MAIN/);
    assert.match(objdumpHdr, /LC_DYLD_INFO_ONLY/);
    assert.match(objdumpHdr, /LC_CODE_SIGNATURE/);

    const objdumpObjc = execFileSync('llvm-objdump', ['--macho', '--objc-meta-data', binOut], {
      encoding: 'utf8',
    });
    assert.match(objdumpObjc, /WeatherAppDelegate/);
    assert.match(objdumpObjc, /refreshWeather:/);
  });

  it('executes packages/ios-weather-island.ipa end-to-end on M1+M2+M4 (UUID container, UIKit 390x844, ARM64 button IMP, Dynamic Island, NSUserDefaults, UIPasteboard, URL scheme, SpringBoard suspend/resume & clean close)', async () => {
    const stack = await bootFullM4Stack('omnios-m4-ios-live-');
    const ipaBytes = fs.readFileSync(path.join(PACKAGES_DIR, 'ios-weather-island.ipa'));

    const det = new FormatDetector().detect(ipaBytes, 'ios-weather-island.ipa');
    assert.equal(det.format, PACKAGE_FORMATS.IOS_IPA);
    assert.equal(det.platform, 'ios');

    const insp = await stack.pkgManager.inspect(ipaBytes, 'ios-weather-island.ipa');
    assert.equal(insp.appId, 'com.omnios.ios.weather-island');
    assert.equal(insp.platform, 'ios');
    assert.equal(insp.arch, 'arm64');
    assert.ok(Array.isArray(insp.intents) && insp.intents.length >= 1);

    const installed = await stack.pkgManager.install(ipaBytes, { filename: 'ios-weather-island.ipa' });
    const expectedUuid = deriveIosContainerUuid('com.omnios.ios.weather-island');
    assert.equal(installed.dataDir, `/var/appdata/ios/${expectedUuid}`);
    assert.equal(installed.metadata.containerUuid, expectedUuid);

    const launch = await stack.pkgManager.launch(installed.appId);
    const pid = launch.pid;
    stack.kernel.scheduler.runUntilIdle(pid, 500);

    const pcb = stack.kernel.processManager.get(pid);
    assert.equal(pcb.state, PROCESS_STATES.BLOCKED);
    assert.equal(pcb.threads.get(1).waitReason, 'ui_event');

    // Compositor 390x844 iOS window
    const wins = stack.compositor.listWindows({ pid });
    assert.equal(wins.length, 1);
    const win = wins[0];
    assert.equal(win.platform, 'ios');
    assert.equal(win.chromeStyle, 'ios');
    assert.equal(win.bounds.width, 390);
    assert.equal(win.bounds.height, 844);

    const initialLabel = findUiNode(win.surface.uiTree, (n) => typeof n.text === 'string' && n.text.includes('72°F'));
    assert.ok(initialLabel, 'Initial ARM64-rendered label should display 72°F');

    // Dynamic Island Live Activity started
    const activeLas = stack.notifications.getLiveActivities();
    assert.equal(activeLas.length, 1);
    assert.equal(activeLas[0].compactLeading, '72°F');
    assert.equal(activeLas[0].progress, 0.6);

    // NSUserDefaults & container VFS written by real ARM64 code
    assert.equal(stack.configStore.defaults.get(installed.appId, 'weather_city'), 'Cupertino, CA');
    assert.equal(stack.configStore.defaults.get(installed.appId, 'computed_value'), 72);
    const forecastTxt = stack.vfs.readFile(`${installed.dataDir}/Documents/forecast.txt`, {
      encoding: 'utf8',
      uid: 0,
      gid: 0,
    });
    assert.match(forecastTxt, /72F/);

    // Tap Refresh Weather button -> executes real ARM64 refreshWeather: IMP
    const refreshBtn = findUiNode(
      win.surface.uiTree,
      (n) => n.type === 'button' && String(n.text ?? n.label ?? '').includes('Refresh')
    );
    assert.ok(refreshBtn);
    stack.compositor.dispatchInput(win.windowId, {
      type: 'click',
      nodeId: refreshBtn.id,
      label: 'Refresh Weather',
    });
    stack.kernel.scheduler.runUntilIdle(pid, 500);

    const winAfterTap = stack.compositor.getWindow(win.windowId);
    assert.ok(
      findUiNode(winAfterTap.surface.uiTree, (n) => typeof n.text === 'string' && n.text.includes('75°F')),
      'ARM64 refreshWeather: IMP must update label to 75°F'
    );
    const updatedLa = stack.notifications.getLiveActivities()[0];
    assert.equal(updatedLa.compactLeading, '75°F');
    assert.equal(updatedLa.progress, 0.9);
    assert.equal(stack.configStore.defaults.get(installed.appId, 'computed_value'), 75);
    assert.equal(stack.configStore.defaults.get(installed.appId, 'refresh_count'), 1);
    assert.match(stack.clipboard.get().text ?? '', /75°F/);

    // URL scheme omniweather://city/Tokyo via IntentRouter -> ARM64 application:openURL:options:
    const intentRes = stack.intentRouter.dispatch({
      action: 'view',
      uri: 'omniweather://city/Tokyo',
    });
    assert.equal(intentRes.status, 'DELIVERED');
    assert.equal(intentRes.targetAppId, installed.appId);
    stack.kernel.scheduler.runUntilIdle(pid, 500);
    const winAfterUrl = stack.compositor.getWindow(win.windowId);
    assert.ok(
      findUiNode(winAfterUrl.surface.uiTree, (n) => typeof n.text === 'string' && n.text.includes('Tokyo')),
      'URL scheme openURL IMP should update UI with Tokyo'
    );

    // SpringBoard Suspend -> ignores clicks while suspended -> Resume
    pcb.executionContext.deliverEvent({ type: 'lifecycle', state: 'background' });
    stack.kernel.processManager.wake(pid);
    stack.kernel.scheduler.runUntilIdle(pid, 200);
    assert.equal(stack.kernel.processManager.get(pid).threads.get(1).waitReason, 'suspended');

    const prevRefreshCount = stack.configStore.defaults.get(installed.appId, 'refresh_count');
    stack.compositor.dispatchInput(win.windowId, { type: 'click', nodeId: refreshBtn.id });
    stack.kernel.scheduler.runUntilIdle(pid, 200);
    assert.equal(
      stack.configStore.defaults.get(installed.appId, 'refresh_count'),
      prevRefreshCount,
      'Suspended iOS app must ignore clicks'
    );

    pcb.executionContext.deliverEvent({ type: 'lifecycle', state: 'foreground' });
    stack.kernel.processManager.wake(pid);
    stack.kernel.scheduler.runUntilIdle(pid, 200);
    assert.equal(stack.kernel.processManager.get(pid).threads.get(1).waitReason, 'ui_event');

    // Close window -> applicationWillTerminate: ends Live Activity & exits cleanly
    stack.compositor.closeWindow(win.windowId);
    stack.kernel.scheduler.runUntilIdle(pid, 300);
    const finalPcb = stack.kernel.processManager.get(pid);
    assert.ok(finalPcb.state === PROCESS_STATES.ZOMBIE || finalPcb.state === PROCESS_STATES.TERMINATED);
    assert.equal(finalPcb.stats.exitCode, 0);
    assert.equal(stack.notifications.getLiveActivities().length, 0);
  });

  it('runs a dynamic runtime-nonce custom .ipa (anti-hardcoding), enforces sandbox EACCES + PermissionBroker shared Documents, and rejects FairPlay DRM (Edge Case #20)', async () => {
    const stack = await bootFullM4Stack('omnios-m4-ios-custom-');

    // 1. Dynamic runtime-nonce custom IPA with real ARM64 MUL (17 * 29 = 493, tap +13 = 506)
    const runtimeNonce = `IOS-NONCE-${crypto.randomBytes(4).toString('hex')}`;
    const builtCustom = buildIosIpa({
      bundleId: 'com.omnios.ios.dynamic-nonce',
      appName: 'DynamicNonceApp',
      title: `NonceApp ${runtimeNonce}`,
      nonce: runtimeNonce,
      operands: [17, 29],
      arithmeticOp: 'mul',
      tapStep: 13,
      initialLabelText: `Start ${runtimeNonce}`,
      buttonLabel: 'Compute Next',
      buttonResultText: `Tapped ${runtimeNonce}`,
      defaultsKey: 'runtime_nonce_key',
      defaultsValue: runtimeNonce,
      documentFile: 'nonce.txt',
      documentContent: `Payload:${runtimeNonce}`,
      liveActivity: {
        title: `LA ${runtimeNonce}`,
        subtitle: 'Live Check',
        leading: '493',
        trailing: runtimeNonce,
        body: `Body ${runtimeNonce}`,
        progress: 40,
        updatedTitle: `LA ${runtimeNonce}`,
        updatedSubtitle: 'Updated',
        updatedLeading: '506',
        updatedTrailing: runtimeNonce,
        updatedBody: `Updated ${runtimeNonce}`,
        updatedProgress: 80,
      },
    });

    const installed = await stack.pkgManager.install(builtCustom.ipaBytes, { filename: 'dynamic.ipa' });
    const { pid } = await stack.pkgManager.launch(installed.appId);
    stack.kernel.scheduler.runUntilIdle(pid, 500);

    assert.equal(stack.configStore.defaults.get(installed.appId, 'runtime_nonce_key'), runtimeNonce);
    assert.equal(stack.configStore.defaults.get(installed.appId, 'computed_value'), 493);
    assert.equal(
      stack.vfs.readFile(`${installed.dataDir}/Documents/nonce.txt`, { encoding: 'utf8', uid: 0, gid: 0 }),
      `Payload:${runtimeNonce}`
    );
    assert.equal(stack.notifications.getLiveActivities()[0].compactTrailing, runtimeNonce);

    const win = stack.compositor.listWindows({ pid })[0];
    stack.compositor.dispatchInput(win.windowId, { type: 'click', label: 'Compute Next' });
    stack.kernel.scheduler.runUntilIdle(pid, 500);
    assert.equal(stack.configStore.defaults.get(installed.appId, 'computed_value'), 506);
    assert.equal(stack.notifications.getLiveActivities()[0].compactLeading, '506');
    stack.compositor.closeWindow(win.windowId);
    stack.kernel.scheduler.runUntilIdle(pid, 300);

    // 2. Sandbox escape EACCES + PermissionBroker shared /var/mobile/Documents/ brokering
    stack.vfs.writeFile('/home/user/Documents/ios-shared.txt', 'SharedFromUser', { uid: 1000, gid: 1000 });
    const buildProbeIpa = (probePath, bundleId) =>
      buildIosIpa({
        bundleId,
        appName: 'SandboxProbe',
        customCode(asm, ctx) {
          ctx.internCString(probePath);
          // SYS_open(probePath, O_RDONLY=0, 0) via SVC #0x80
          asm.loadAddr(0, { kind: 'cstring', key: probePath });
          asm.movz(1, 0);
          asm.movz(2, 0);
          asm.movz(16, DARWIN_SYSCALLS.SYS_open);
          asm.svc(0x80);
          // If C==1 (error), X0 holds positive errno -> exit(X0); on success exit(0)
          asm.bCond(3, 'L_ok'); // B.CC (Carry Clear = success)
          asm.movz(16, DARWIN_SYSCALLS.SYS_exit);
          asm.svc(0x80);
          asm.label('L_ok');
          asm.movz(0, 0);
          asm.movz(16, DARWIN_SYSCALLS.SYS_exit);
          asm.svc(0x80);
        },
      });

    // Escape attempt to /etc/passwd -> Darwin EACCES (13)
    const escApp = await stack.pkgManager.install(
      buildProbeIpa('/etc/passwd', 'com.omnios.ios.escape-probe').ipaBytes,
      { filename: 'escape.ipa' }
    );
    const escLaunch = await stack.pkgManager.launch(escApp.appId);
    stack.kernel.scheduler.runUntilIdle(escLaunch.pid, 200);
    assert.equal(stack.kernel.processManager.get(escLaunch.pid).stats.exitCode, DARWIN_ERRNO.EACCES);

    // Shared /var/mobile/Documents/ios-shared.txt denied before grant -> allowed (exit 0) after grant
    const sharedApp = await stack.pkgManager.install(
      buildProbeIpa('/var/mobile/Documents/ios-shared.txt', 'com.omnios.ios.shared-probe').ipaBytes,
      { filename: 'shared.ipa' }
    );
    const deniedRun = await stack.pkgManager.launch(sharedApp.appId);
    stack.kernel.scheduler.runUntilIdle(deniedRun.pid, 200);
    assert.equal(stack.kernel.processManager.get(deniedRun.pid).stats.exitCode, DARWIN_ERRNO.EACCES);

    stack.permissions.setGrant(sharedApp.appId, 'fs.read.user', 'allow');
    const allowedRun = await stack.pkgManager.launch(sharedApp.appId);
    stack.kernel.scheduler.runUntilIdle(allowedRun.pid, 200);
    assert.equal(stack.kernel.processManager.get(allowedRun.pid).stats.exitCode, 0);

    // 3. FairPlay DRM encrypted IPA MUST reject with FormatError(E_ENCRYPTED_BINARY)
    const fairplayIpa = buildIosIpa({
      bundleId: 'com.omnios.ios.fairplay',
      appName: 'FairPlayApp',
      encryptFairPlay: true,
    });
    assert.throws(
      () => parseIpa(fairplayIpa.ipaBytes),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_ENCRYPTED_BINARY
    );
    await assert.rejects(
      () => stack.pkgManager.install(fairplayIpa.ipaBytes, { filename: 'fairplay.ipa' }),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_ENCRYPTED_BINARY
    );
  });
});

// ============================================================================
// SUITE 7 (`F-054`, `F-055`, `F-058`): macOS Runtime, `.app.zip`, `.dmg`, `.pkg`, AppKit & Global Menu Bar
// ============================================================================

describe('Suite 7 (F-054, F-055, F-058): macOS Runtime, .app.zip, .dmg, .pkg, AppKit & Global Menu Bar', () => {
  it('passes external Python 3 zipfile + plistlib + llvm-objdump Universal Fat (ARM64 + x86-64) oracles on packages/macos-studio.app.zip', () => {
    const appZipPath = path.join(PACKAGES_DIR, 'macos-studio.app.zip');
    assert.ok(fs.existsSync(appZipPath), 'packages/macos-studio.app.zip must exist');

    const tmpDir = makeTempDir('omnios-m4-macos-oracle-');
    const binOut = path.join(tmpDir, 'OmniStudio');
    const pyCheck = JSON.parse(
      runPython(
        `
import sys, json, zipfile, plistlib
zip_path, bin_out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path, 'r') as zf:
    assert zf.testzip() is None, 'ZIP CRC check failed'
    info = plistlib.loads(zf.read('OmniStudio.app/Contents/Info.plist'))
    macho = zf.read(f"OmniStudio.app/Contents/MacOS/{info['CFBundleExecutable']}")
    with open(bin_out, 'wb') as f:
        f.write(macho)
print(json.dumps({
    'bundleId': info['CFBundleIdentifier'],
    'name': info['CFBundleName'],
    'executable': info['CFBundleExecutable'],
    'machoBytes': len(macho),
}))
`,
        null,
        [appZipPath, binOut]
      )
    );

    assert.equal(pyCheck.bundleId, 'com.omnios.macos.studio');
    assert.equal(pyCheck.name, 'OmniStudio');
    assert.equal(pyCheck.executable, 'OmniStudio');

    const uniHdr = execFileSync(
      'llvm-objdump',
      ['--macho', '--universal-headers', '--private-headers', binOut],
      { encoding: 'utf8' }
    );
    assert.match(uniHdr, /nfat_arch 2/);
    assert.match(uniHdr, /ARM64/);
    assert.match(uniHdr, /X86_64/);
    assert.match(uniHdr, /__PAGEZERO/);
    assert.match(uniHdr, /LC_MAIN/);
    assert.match(uniHdr, /LC_DYLD_INFO_ONLY/);
    assert.match(uniHdr, /LC_CODE_SIGNATURE/);
  });

  it('executes packages/macos-studio.app.zip end-to-end (Spotlight, Global Menu Bar IMPs, NSTextField/NSButton/NSAlert/NSUserDefaults/NSPasteboard/NSWorkspace, /Users/user/Documents brokering & non-suspending lifecycle)', async () => {
    const stack = await bootFullM4Stack('omnios-m4-macos-live-');
    const zipBytes = fs.readFileSync(path.join(PACKAGES_DIR, 'macos-studio.app.zip'));

    const det = new FormatDetector().detect(zipBytes, 'macos-studio.app.zip');
    assert.equal(det.format, PACKAGE_FORMATS.MACOS_APP);
    assert.equal(det.platform, 'macos');

    const spotlightEvents = [];
    stack.kernel.eventBus.on('spotlight:indexed', (evt) => spotlightEvents.push(evt));

    const installed = await stack.pkgManager.install(zipBytes, { filename: 'macos-studio.app.zip' });
    assert.equal(installed.appId, 'com.omnios.macos.studio');
    assert.ok(installed.metadata.spotlight?.kMDItemDisplayName);
    assert.equal(spotlightEvents.length, 1);
    const xattrDisplayName = stack.vfs.getXattr(
      installed.installDir,
      'com.apple.metadata:kMDItemDisplayName',
      { uid: 0, gid: 0 }
    );
    assert.ok(xattrDisplayName && TEXT_DECODER.decode(xattrDisplayName).includes('OmniStudio'));

    const { pid } = await stack.pkgManager.launch(installed.appId);
    stack.kernel.scheduler.runUntilIdle(pid, 500);

    const wins = stack.compositor.listWindows({ pid });
    assert.equal(wins.length, 1);
    const win = wins[0];
    assert.equal(win.platform, 'macos');
    stack.compositor.focusWindow(win.windowId);

    // Live Global Top Menu Bar
    const snap = stack.compositor.getSnapshot();
    const menuLabels = snap.activeMenuBar.map((m) => m.label);
    assert.ok(menuLabels.includes('OmniStudio'));
    assert.ok(menuLabels.includes('File'));
    assert.ok(menuLabels.includes('Edit'));

    // NSUserDefaults written on launch
    assert.equal(stack.configStore.defaults.get(installed.appId, 'studio.theme'), 'graphite-pro');

    // Menu action -> File > New Document executes real ARM64 menu IMP
    const revBeforeNew = stack.compositor.getWindow(win.windowId).surfaceRevision;
    stack.compositor.dispatchInput(win.windowId, { type: 'menu_action', label: 'New Document' });
    stack.kernel.scheduler.runUntilIdle(pid, 500);
    const winAfterNew = stack.compositor.getWindow(win.windowId);
    assert.ok(winAfterNew.surfaceRevision > revBeforeNew);

    // NSTextField input + Edit > Copy -> NSPasteboard -> SharedClipboard
    const textField = findUiNode(winAfterNew.surface.uiTree, (n) => n.type === 'input' || n.type === 'textarea');
    assert.ok(textField);
    stack.compositor.dispatchInput(win.windowId, {
      type: 'input',
      nodeId: textField.id,
      value: 'Typed-In-OmniStudio',
    });
    stack.kernel.scheduler.runUntilIdle(pid, 300);

    stack.compositor.dispatchInput(win.windowId, { type: 'menu_action', label: 'Copy' });
    stack.kernel.scheduler.runUntilIdle(pid, 300);
    assert.equal(stack.clipboard.get().text, 'Typed-In-OmniStudio');

    // External clipboard change -> Edit > Paste updates NSTextField
    stack.clipboard.set({ text: 'Pasted-From-CrossPlatform', sourceAppId: 'test.peer' });
    stack.compositor.dispatchInput(win.windowId, { type: 'menu_action', label: 'Paste' });
    stack.kernel.scheduler.runUntilIdle(pid, 300);
    const pastedField = findUiNode(
      stack.compositor.getWindow(win.windowId).surface.uiTree,
      (n) => n.id === textField.id
    );
    assert.equal(pastedField.value ?? pastedField.text, 'Pasted-From-CrossPlatform');

    // NSButton click + NSAlert (About OmniStudio) -> posts notification
    const notifsBefore = stack.notifications.list().length;
    stack.compositor.dispatchInput(win.windowId, { type: 'menu_action', label: 'About OmniStudio' });
    stack.kernel.scheduler.runUntilIdle(pid, 300);
    assert.ok(stack.notifications.list().length > notifsBefore, 'NSAlert should post to NotificationCenter');

    const actionBtn = findUiNode(winAfterNew.surface.uiTree, (n) => n.type === 'button');
    assert.ok(actionBtn);
    stack.compositor.dispatchInput(win.windowId, { type: 'click', nodeId: actionBtn.id });
    stack.kernel.scheduler.runUntilIdle(pid, 300);

    // /Users/user/Documents/omnistudio-note.txt: fail-closed BEFORE fs.write.user grant, succeeds AFTER grant
    stack.compositor.dispatchInput(win.windowId, { type: 'menu_action', label: 'Save to Documents' });
    stack.kernel.scheduler.runUntilIdle(pid, 300);
    assert.throws(
      () => stack.vfs.stat('/home/user/Documents/omnistudio-note.txt', { uid: 0, gid: 0 }),
      'Must fail-closed without fs.write.user grant'
    );

    stack.permissions.setGrant(installed.appId, 'fs.write.user', 'allow');
    stack.compositor.dispatchInput(win.windowId, { type: 'menu_action', label: 'Save to Documents' });
    stack.kernel.scheduler.runUntilIdle(pid, 300);
    const savedDoc = stack.vfs.readFile('/home/user/Documents/omnistudio-note.txt', {
      encoding: 'utf8',
      uid: 0,
      gid: 0,
    });
    assert.equal(savedDoc, 'Pasted-From-CrossPlatform');

    // IntentRouter omnistudio:// URL scheme dispatch
    const routeRes = stack.intentRouter.dispatch({ action: 'view', uri: 'omnistudio://open/readme.md' });
    assert.equal(routeRes.status, 'DELIVERED');
    assert.equal(routeRes.targetAppId, installed.appId);
    stack.kernel.scheduler.runUntilIdle(pid, 300);

    // Non-suspending desktop lifecycle: blur/background does NOT freeze macOS app
    stack.compositor.dispatchInput(win.windowId, { type: 'blur' });
    stack.compositor.dispatchInput(win.windowId, { type: 'background' });
    stack.kernel.scheduler.runUntilIdle(pid, 200);
    assert.equal(stack.kernel.processManager.get(pid).threads.get(1).waitReason, 'ui_event');

    // Clean close -> terminate
    stack.compositor.closeWindow(win.windowId);
    stack.kernel.scheduler.runUntilIdle(pid, 300);
    const finalPcb = stack.kernel.processManager.get(pid);
    assert.ok(finalPcb.state === PROCESS_STATES.ZOMBIE || finalPcb.state === PROCESS_STATES.TERMINATED);
    assert.equal(finalPcb.stats.exitCode, 0);
  });

  it('runs dynamic runtime-nonce bplist00 .app.zip, synthetic .dmg (koly+blkx/mish), synthetic .pkg (xar!+CPIO odc & newc), raw Mach-O, and rejects malformed DMG/PKG/CPIO traversal', async () => {
    const stack = await bootFullM4Stack('omnios-m4-macos-formats-');

    // 1. Dynamic runtime-nonce bplist00 .app.zip with custom Tools -> Stamp Nonce menu IMP
    const nonce = `MAC-NONCE-${crypto.randomBytes(4).toString('hex')}`;
    const customZip = buildMacAppZip({
      bundleId: 'com.omnios.macos.dynamic',
      appName: 'DynamicMac',
      executableName: 'DynamicMac',
      nonce,
      plistFormat: 'binary',
      universal: false,
      menuItems: [
        {
          menu: 'Tools',
          label: 'Stamp Nonce',
          selector: 'onStampNonce:',
          keyEquivalent: 't',
          windowTitle: `Stamped ${nonce}`,
          copyText: `CLIP-${nonce}`,
        },
      ],
    });
    const customApp = await stack.pkgManager.install(customZip, { filename: 'DynamicMac.app.zip' });
    const { pid: cPid } = await stack.pkgManager.launch(customApp.appId);
    stack.kernel.scheduler.runUntilIdle(cPid, 500);
    const cWin = stack.compositor.listWindows({ pid: cPid })[0];
    stack.compositor.focusWindow(cWin.windowId);
    assert.ok(stack.compositor.getSnapshot().activeMenuBar.some((m) => m.label === 'Tools'));
    stack.compositor.dispatchInput(cWin.windowId, { type: 'menu_action', label: 'Stamp Nonce' });
    stack.kernel.scheduler.runUntilIdle(cPid, 500);
    assert.equal(stack.compositor.getWindow(cWin.windowId).title, `Stamped ${nonce}`);
    assert.equal(stack.clipboard.get().text, `CLIP-${nonce}`);
    stack.compositor.closeWindow(cWin.windowId);
    stack.kernel.scheduler.runUntilIdle(cPid, 300);

    // 2. Synthetic UDIF .dmg (koly + blkx/mish zlib) -> inspect -> install -> launch
    const dmgBytes = buildTestDmg({
      bundleId: 'com.omnios.macos.dmgapp',
      appName: 'DmgTester',
      executableName: 'DmgTester',
      nonce: `DMG-${nonce}`,
      universal: false,
    });
    assert.equal(new FormatDetector().detect(dmgBytes, 'DmgTester.dmg').format, PACKAGE_FORMATS.MACOS_DMG);
    const dmgApp = await stack.pkgManager.install(dmgBytes, { filename: 'DmgTester.dmg' });
    const { pid: dPid } = await stack.pkgManager.launch(dmgApp.appId);
    stack.kernel.scheduler.runUntilIdle(dPid, 500);
    const dWin = stack.compositor.listWindows({ pid: dPid })[0];
    assert.ok(dWin && dWin.title.includes(`DMG-${nonce}`));
    stack.compositor.closeWindow(dWin.windowId);
    stack.kernel.scheduler.runUntilIdle(dPid, 300);

    // 3. Synthetic Flat Installer .pkg (xar! + gzipped CPIO odc) -> inspect -> install -> launch
    const pkgBytes = buildTestPkg({
      bundleId: 'com.omnios.macos.pkgapp',
      appName: 'PkgTester',
      executableName: 'PkgTester',
      nonce: `PKG-${nonce}`,
      universal: false,
    });
    assert.equal(new FormatDetector().detect(pkgBytes, 'PkgTester.pkg').format, PACKAGE_FORMATS.MACOS_PKG);
    const pkgApp = await stack.pkgManager.install(pkgBytes, { filename: 'PkgTester.pkg' });
    const { pid: pPid } = await stack.pkgManager.launch(pkgApp.appId);
    stack.kernel.scheduler.runUntilIdle(pPid, 500);
    const pWin = stack.compositor.listWindows({ pid: pPid })[0];
    assert.ok(pWin && pWin.title.includes(`PKG-${nonce}`));
    stack.compositor.closeWindow(pWin.windowId);
    stack.kernel.scheduler.runUntilIdle(pPid, 300);

    // 4. SVR4 newc (`070701`) CPIO format parser verification
    const buildNewcCpio = (name, content) => {
      const hex8 = (n) => (n >>> 0).toString(16).padStart(8, '0');
      const pad4 = (len) => (4 - (len % 4)) % 4;
      const mkEntry = (n, data) => {
        const nb = TEXT_ENCODER.encode(`${n}\0`);
        const hdr = TEXT_ENCODER.encode(
          '070701' +
            hex8(1) + hex8(0o100644) + hex8(0) + hex8(0) + hex8(1) + hex8(0) +
            hex8(data.byteLength) + hex8(0) + hex8(0) + hex8(0) + hex8(0) +
            hex8(nb.byteLength) + hex8(0)
        );
        const hPad = new Uint8Array(pad4(hdr.byteLength + nb.byteLength));
        const dPad = new Uint8Array(pad4(data.byteLength));
        const out = new Uint8Array(hdr.byteLength + nb.byteLength + hPad.byteLength + data.byteLength + dPad.byteLength);
        let o = 0;
        for (const p of [hdr, nb, hPad, data, dPad]) { out.set(p, o); o += p.byteLength; }
        return out;
      };
      const e1 = mkEntry(name, TEXT_ENCODER.encode(content));
      const tr = mkEntry('TRAILER!!!', new Uint8Array(0));
      const all = new Uint8Array(e1.byteLength + tr.byteLength);
      all.set(e1, 0);
      all.set(tr, e1.byteLength);
      return all;
    };
    const newcParsed = parseCpioArchive(buildNewcCpio('./hello-newc.txt', 'SVR4-NEWC-OK'));
    assert.equal(newcParsed.entries.length, 1);
    assert.equal(TEXT_DECODER.decode(newcParsed.files.get('hello-newc.txt')), 'SVR4-NEWC-OK');

    // 5. Raw Mach-O (macos-macho) direct execution
    const rawMachO = buildMachOArm64Mac({
      bundleId: 'com.omnios.macos.rawmacho',
      appName: 'RawMachO',
      nonce: `RAW-${nonce}`,
      universal: false,
    });
    assert.equal(new FormatDetector().detect(rawMachO, 'rawmacho').format, PACKAGE_FORMATS.MACOS_MACHO);
    const rawApp = await stack.pkgManager.install(rawMachO, { filename: 'rawmacho' });
    const { pid: rPid } = await stack.pkgManager.launch(rawApp.appId);
    stack.kernel.scheduler.runUntilIdle(rPid, 500);
    const rWin = stack.compositor.listWindows({ pid: rPid })[0];
    assert.ok(rWin && rWin.title.includes(`RAW-${nonce}`));
    stack.compositor.closeWindow(rWin.windowId);
    stack.kernel.scheduler.runUntilIdle(rPid, 300);

    // 6. Malformed DMG, truncated PKG, and CPIO path traversal rejection
    assert.throws(() => parseMacDmg(new Uint8Array(256)), (err) => err instanceof FormatError);
    assert.throws(() => parseMacPkg(new Uint8Array(16)), (err) => err instanceof FormatError);
    const evilPkg = buildTestPkg({
      bundleId: 'com.evil.pkg',
      appName: 'EvilPkg',
      cpioFiles: [{ name: '../../etc/evil.txt', data: TEXT_ENCODER.encode('pwn') }],
    });
    assert.throws(
      () => parseMacPkg(evilPkg),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
    );
  });
});

// ============================================================================
// SUITE 8 (`F-056`, `F-059`, Edge Case `#29`): Universal WASM/WASI Runtime & `.uapp` SDK
// ============================================================================

describe('Suite 8 (F-056, F-059, Edge Case #29): Universal WASM/WASI Runtime & .uapp SDK', () => {
  it('passes external Python 3 zipfile + WebAssembly.validate() oracles and runs packages/universal-canvas.uapp with live Compositor DrawOps redraw', async () => {
    const uappPath = path.join(PACKAGES_DIR, 'universal-canvas.uapp');
    assert.ok(fs.existsSync(uappPath), 'packages/universal-canvas.uapp must exist');

    const pyInfo = JSON.parse(
      runPython(
        `
import sys, json, zipfile
with zipfile.ZipFile(sys.argv[1], 'r') as zf:
    assert zf.testzip() is None
    names = zf.namelist()
    assert 'omnios.manifest.json' in names
    manifest = json.loads(zf.read('omnios.manifest.json').decode('utf-8'))
    wasm = zf.read(manifest['wasmEntry'])
print(json.dumps({'names': names, 'manifest': manifest, 'wasmLen': len(wasm)}))
`,
        null,
        [uappPath]
      )
    );
    assert.equal(pyInfo.manifest.appId, 'com.omnios.universal.canvas');
    assert.equal(pyInfo.manifest.name, 'OmniCanvas Studio');

    const uappBytes = fs.readFileSync(uappPath);
    const entries = readZip(uappBytes);
    const wasmBytes = entries.get('app.wasm').data;
    assert.equal(WebAssembly.validate(wasmBytes), true);
    const parsedWasm = parseWasmBinary(wasmBytes);
    assert.ok(parsedWasm.exports.some((e) => e.name === '_start'));
    assert.ok(parsedWasm.exports.some((e) => e.name === 'omni_on_event'));

    const stack = await bootFullM4Stack('omnios-m4-wasm-canvas-');
    assert.equal(
      new FormatDetector().detect(uappBytes, 'universal-canvas.uapp').format,
      PACKAGE_FORMATS.UNIVERSAL_UAPP
    );

    const installed = await stack.pkgManager.install(uappBytes, { filename: 'universal-canvas.uapp' });
    const { pid } = await stack.pkgManager.launch(installed.appId);
    stack.kernel.scheduler.runUntilIdle(pid, 100);

    const wins = stack.compositor.listWindows({ pid });
    assert.equal(wins.length, 1);
    const win = wins[0];
    const rev1 = win.surfaceRevision;
    const ops1 = win.surface.drawOps.length;
    assert.ok(ops1 >= 8, 'OmniCanvas Studio must commit initial vector DrawOps');

    // Interactive canvas pointer_down -> WASM omni_on_event plots new vector node & increments surfaceRevision
    stack.compositor.dispatchInput(win.windowId, { type: 'pointer_down', x: 240, y: 180 });
    stack.kernel.scheduler.runUntilIdle(pid, 100);
    const win2 = stack.compositor.getWindow(win.windowId);
    assert.ok(win2.surfaceRevision > rev1, 'Live WASM redraw must increment surfaceRevision');
    assert.ok(win2.surface.drawOps.length > ops1, 'Pointer event must append new DrawOps');

    // Clean window close -> exitCode 0
    stack.compositor.closeWindow(win.windowId);
    stack.kernel.scheduler.runUntilIdle(pid, 100);
    const finalPcb = stack.kernel.processManager.get(pid);
    assert.ok(finalPcb.state === PROCESS_STATES.ZOMBIE || finalPcb.state === PROCESS_STATES.TERMINATED);
    assert.equal(finalPcb.stats.exitCode, 0);
  });

  it('executes a dynamic runtime-nonce custom .uapp (WASM ALU, WASI stdout/clock/preopen VFS, omni_os_v1 Clipboard/Notifications/IPC, proc_exit), raw .wasm, and isolates WASM traps', async () => {
    const stack = await bootFullM4Stack('omnios-m4-wasm-dynamic-');

    const nonce = `WASM-${crypto.randomBytes(4).toString('hex')}`;
    const a = 37;
    const b = 19;
    const c = 11;
    const expectedAlu = a * b + c; // 714

    const ipcReceived = [];
    stack.ipc.createChannel('wasm.telemetry', 1);
    stack.ipc.subscribe('wasm.telemetry', (msg) => ipcReceived.push(msg));

    const customUapp = buildUniversalUapp({
      appId: 'com.omnios.universal.dynamic',
      name: 'DynamicWasmApp',
      stdoutMessage: `HELLO:${nonce}\n`,
      readClock: true,
      clockPrefix: 'CLK=',
      arithmetic: { a, b, op: 'mul', c, label: 'ALU=' },
      writeFile: { path: 'wasm-out.txt', content: `VFS:${nonce}` },
      clipboardSet: `CLIP:${nonce}`,
      notification: { title: `Notif ${nonce}`, body: `Body ${nonce}` },
      ipcSend: { channel: 'wasm.telemetry', message: `IPC:${nonce}` },
      exitCode: 7,
    });

    const installed = await stack.pkgManager.install(customUapp.bytes, { filename: 'dynamic.uapp' });
    const { pid } = await stack.pkgManager.launch(installed.appId);
    stack.kernel.scheduler.runUntilIdle(pid, 100);

    const pcb = stack.kernel.processManager.get(pid);
    assert.equal(pcb.stats.exitCode, 7, 'WASI proc_exit(7) must propagate exact exitCode');
    const stdout = stack.kernel.processManager.readStdout(pid);
    assert.match(stdout, new RegExp(`HELLO:${nonce}`));
    assert.match(stdout, new RegExp(`ALU=${expectedAlu}`));
    assert.match(stdout, /CLK=\d+/);
    assert.equal(
      stack.vfs.readFile(`${installed.dataDir}/wasm-out.txt`, { encoding: 'utf8', uid: 0, gid: 0 }),
      `VFS:${nonce}`
    );
    assert.equal(stack.clipboard.get().text, `CLIP:${nonce}`);
    assert.ok(stack.notifications.list().some((n) => n.title === `Notif ${nonce}`));
    assert.ok(ipcReceived.some((m) => String(m.payload ?? m).includes(`IPC:${nonce}`)));

    // Raw `.wasm` direct install & run
    const rawWasm = buildUniversalWasm({
      stdoutMessage: `RAW-WASM:${nonce}\n`,
      exitCode: 0,
    });
    assert.equal(new FormatDetector().detect(rawWasm, 'hello.wasm').format, PACKAGE_FORMATS.UNIVERSAL_WASM);
    const rawInstalled = await stack.pkgManager.install(rawWasm, { filename: 'hello.wasm' });
    const { pid: rawPid } = await stack.pkgManager.launch(rawInstalled.appId);
    stack.kernel.scheduler.runUntilIdle(rawPid, 100);
    assert.equal(stack.kernel.processManager.get(rawPid).stats.exitCode, 0);
    assert.match(stack.kernel.processManager.readStdout(rawPid), new RegExp(`RAW-WASM:${nonce}`));

    // WASM `unreachable` trap fault isolation (kernel stays RUNNING)
    const trapBuilder = new WasmModuleBuilder();
    trapBuilder.setMemory(1, 2, 'memory');
    trapBuilder.addFunction({
      name: '_start',
      params: [],
      results: [],
      body: new WasmCodeBuilder().unreachable(),
      exportName: '_start',
    });
    const trapWasm = trapBuilder.emit({ validate: true });
    const trapApp = await stack.pkgManager.install(trapWasm, { filename: 'trap.wasm' });
    const { pid: trapPid } = await stack.pkgManager.launch(trapApp.appId);
    stack.kernel.scheduler.runUntilIdle(trapPid, 100);
    const trapPcb = stack.kernel.processManager.get(trapPid);
    assert.ok(trapPcb.state === PROCESS_STATES.ZOMBIE || trapPcb.state === PROCESS_STATES.TERMINATED);
    assert.notEqual(trapPcb.stats.exitCode, 0);
    assert.equal(stack.kernel.state, KERNEL_STATES.RUNNING);
  });

  it('Edge Case #29: WasiBridge enforces iovs_len > 1024 (WASI_EINVAL=28), linear-memory OOB & 0xFFFFFFFC+8 wraparound (WASI_EFAULT=21), preopen traversal & rights escalation (WASI_ENOTCAPABLE=76), random_get & memory.grow() view refresh', async () => {
    const stack = await bootFullM4Stack('omnios-m4-wasi-sec-');
    const preopenDir = '/var/appdata/universal/wasi-sec';
    stack.vfs.mkdir(preopenDir, { recursive: true, uid: 0, gid: 0 });
    stack.vfs.chown(preopenDir, 1000, 1000, { uid: 0, gid: 0 });

    const memory = new WebAssembly.Memory({ initial: 1, maximum: 4 }); // 64 KiB
    const bridge = createWasiBridge({
      services: { vfs: stack.vfs },
      appRecord: {
        appId: 'com.test.wasi.sec',
        dataDir: preopenDir,
        uid: 1000,
        gid: 1000,
      },
    });
    bridge.setMemory(memory);
    assert.equal(bridge._vfs, stack.vfs, 'WasiBridge must bind live VFS instance via services.vfs');
    const wasi = bridge.getImportObject().wasi_snapshot_preview1;

    // 1. iovs_len > 1024 -> WASI_EINVAL (28)
    assert.equal(wasi.fd_write(1, 0, 1025, 16), WASI_ERRNO.WASI_EINVAL);
    assert.equal(wasi.fd_read(0, 0, 2000, 16), WASI_ERRNO.WASI_EINVAL);

    // 2. Linear-memory OOB & 32-bit wraparound (0xFFFFFFFC + 8) -> WASI_EFAULT (21), NEVER RangeError
    assert.equal(wasi.random_get(65530, 16), WASI_ERRNO.WASI_EFAULT);
    assert.equal(wasi.random_get(0xfffffffc, 8), WASI_ERRNO.WASI_EFAULT);
    assert.equal(wasi.fd_write(1, 0xfffffffc, 1, 16), WASI_ERRNO.WASI_EFAULT);

    // 3. Valid random_get fills non-zero entropy
    assert.equal(wasi.random_get(128, 32), WASI_ERRNO.WASI_ESUCCESS);
    const randSlice = new Uint8Array(memory.buffer, 128, 32);
    assert.ok(randSlice.some((b) => b !== 0));

    // 4. Preopen path traversal `../escape` & absolute `/etc/passwd` -> WASI_ENOTCAPABLE (76)
    const writePathMem = (off, str) => {
      const b = TEXT_ENCODER.encode(str);
      new Uint8Array(memory.buffer).set(b, off);
      return { ptr: off, len: b.byteLength };
    };
    const trav = writePathMem(256, '../escape.txt');
    assert.equal(
      wasi.path_open(3, 1, trav.ptr, trav.len, 0, WASI_CONSTANTS.RIGHTS_SETS.FILE_READ, 0n, 0, 512),
      WASI_ERRNO.WASI_ENOTCAPABLE
    );
    const abs = writePathMem(300, '/etc/passwd');
    assert.equal(
      wasi.path_open(3, 1, abs.ptr, abs.len, 0, WASI_CONSTANTS.RIGHTS_SETS.FILE_READ, 0n, 0, 512),
      WASI_ERRNO.WASI_ENOTCAPABLE
    );

    // 5. Rights attenuation succeeds, but attempting to re-escalate rights returns WASI_ENOTCAPABLE (76)
    assert.equal(
      wasi.fd_fdstat_set_rights(3, WASI_CONSTANTS.RIGHTS_SETS.DIR_READ, WASI_CONSTANTS.RIGHTS_SETS.FILE_READ),
      WASI_ERRNO.WASI_ESUCCESS
    );
    assert.equal(
      wasi.fd_fdstat_set_rights(3, WASI_CONSTANTS.RIGHTS_SETS.DIR_ALL, WASI_CONSTANTS.RIGHTS_SETS.FILE_ALL),
      WASI_ERRNO.WASI_ENOTCAPABLE
    );

    // 6. memory.grow(1) transparently refreshes views (accessing page 1 at 0x10000 succeeds)
    memory.grow(1); // now 128 KiB
    assert.equal(wasi.random_get(0x10000, 16), WASI_ERRNO.WASI_ESUCCESS);
    const grownSlice = new Uint8Array(memory.buffer, 0x10000, 16);
    assert.ok(grownSlice.some((b) => b !== 0));

    // 7. proc_exit throws WasiExitSignal
    assert.throws(
      () => wasi.proc_exit(42),
      (err) => err instanceof WasiExitSignal && err.exitCode === 42
    );

    bridge.dispose();
  });
});

// ============================================================================
// SUITE 9 (`F-060` + 3-Platform Concurrent M4 Interop & Fault Isolation)
// ============================================================================

describe('Suite 9 (F-060 + 3-Platform Concurrent M4 Interop & Fault Isolation)', () => {
  it('sdk/build-samples.mjs builds iOS, macOS, and Universal samples deterministically with identical SHA-256 across repeated runs and CLI --json', async () => {
    const out1 = makeTempDir('omnios-m4-build1-');
    const out2 = makeTempDir('omnios-m4-build2-');
    const out3 = makeTempDir('omnios-m4-build3-');

    const m1 = await buildAllSamples({ outputDir: out1, platforms: ['ios', 'macos', 'universal'], quiet: true });
    const m2 = await buildAllSamples({ outputDir: out2, platforms: ['ios', 'macos', 'universal'], quiet: true });

    assert.equal(m1.ok, true);
    assert.equal(m1.packages.length, 3);
    assert.equal(m2.packages.length, 3);
    assert.deepEqual(
      m1.packages.map((p) => ({ platform: p.platform, filename: p.filename, bytes: p.bytes, sha256: p.sha256 })),
      m2.packages.map((p) => ({ platform: p.platform, filename: p.filename, bytes: p.bytes, sha256: p.sha256 })),
      'Repeated sdk/build-samples.mjs runs MUST be byte-for-byte deterministic'
    );

    // Verify CLI entrypoint with --output-dir, --platforms, --json
    const cliOut = execFileSync(
      process.execPath,
      [
        path.join(REPO_ROOT, 'sdk/build-samples.mjs'),
        '--output-dir',
        out3,
        '--platforms',
        'ios,macos,universal',
        '--json',
      ],
      { encoding: 'utf8' }
    );
    const cliManifest = JSON.parse(cliOut);
    assert.equal(cliManifest.ok, true);
    assert.deepEqual(
      cliManifest.packages.map((p) => p.sha256),
      m1.packages.map((p) => p.sha256)
    );

    // Verify committed packages/ match build-samples output byte-for-byte
    for (const pkg of m1.packages) {
      const repoBytes = fs.readFileSync(path.join(PACKAGES_DIR, pkg.filename));
      assert.equal(sha256Hex(repoBytes), pkg.sha256, `Repo packages/${pkg.filename} must match deterministic build`);
    }

    // Invalid platform rejects cleanly
    await assert.rejects(
      () => buildAllSamples({ outputDir: out1, platforms: ['bogus-os'] }),
      RangeError
    );
  });

  it('runs iOS (.ipa) + macOS (.app.zip) + Universal WASM (.uapp) concurrently with live cross-platform Clipboard, shared /home/user/Documents VFS, Dynamic Island + Global Menu Bar + Canvas windows, and isolates faulting __PAGEZERO / infinite-loop PIDs', async () => {
    const stack = await bootFullM4Stack('omnios-m4-concurrent-');

    const iosBytes = fs.readFileSync(path.join(PACKAGES_DIR, 'ios-weather-island.ipa'));
    const macBytes = fs.readFileSync(path.join(PACKAGES_DIR, 'macos-studio.app.zip'));
    const wasmBytes = fs.readFileSync(path.join(PACKAGES_DIR, 'universal-canvas.uapp'));

    const iosApp = await stack.pkgManager.install(iosBytes, { filename: 'ios-weather-island.ipa' });
    const macApp = await stack.pkgManager.install(macBytes, { filename: 'macos-studio.app.zip' });
    const wasmApp = await stack.pkgManager.install(wasmBytes, { filename: 'universal-canvas.uapp' });

    const { pid: iosPid } = await stack.pkgManager.launch(iosApp.appId);
    const { pid: macPid } = await stack.pkgManager.launch(macApp.appId);
    const { pid: wasmPid } = await stack.pkgManager.launch(wasmApp.appId);

    // Run all 3 platforms cooperatively under the ONE Kernel Scheduler
    stack.kernel.scheduler.runUntilIdle(iosPid, 500);
    stack.kernel.scheduler.runUntilIdle(macPid, 500);
    stack.kernel.scheduler.runUntilIdle(wasmPid, 200);

    const iosWin = stack.compositor.listWindows({ pid: iosPid })[0];
    const macWin = stack.compositor.listWindows({ pid: macPid })[0];
    const wasmWin = stack.compositor.listWindows({ pid: wasmPid })[0];
    assert.ok(iosWin && macWin && wasmWin, 'All 3 platform windows must coexist in Compositor');
    assert.equal(stack.compositor.listWindows().length, 3);

    // Dynamic Island Live Activity (iOS) + Global Top Menu Bar (macOS) + Canvas DrawOps (WASM) coexist!
    stack.compositor.focusWindow(macWin.windowId);
    assert.equal(stack.notifications.getLiveActivities().length, 1);
    assert.ok(stack.compositor.getSnapshot().activeMenuBar.some((m) => m.label === 'OmniStudio'));
    assert.ok(wasmWin.surface.drawOps.length >= 8);

    // Cross-platform Clipboard exchange: iOS ARM64 tap -> SharedClipboard -> macOS ARM64 Edit > Paste
    const refreshBtn = findUiNode(
      iosWin.surface.uiTree,
      (n) => n.type === 'button' && String(n.text ?? n.label ?? '').includes('Refresh')
    );
    stack.compositor.dispatchInput(iosWin.windowId, { type: 'click', nodeId: refreshBtn.id });
    stack.kernel.scheduler.runUntilIdle(iosPid, 500);
    const clipFromIos = stack.clipboard.get().text;
    assert.match(clipFromIos, /75°F/);

    stack.compositor.dispatchInput(macWin.windowId, { type: 'menu_action', label: 'Paste' });
    stack.kernel.scheduler.runUntilIdle(macPid, 500);
    const macTextField = findUiNode(
      stack.compositor.getWindow(macWin.windowId).surface.uiTree,
      (n) => n.type === 'input' || n.type === 'textarea'
    );
    assert.equal(macTextField.value ?? macTextField.text, clipFromIos, 'macOS app must paste live iOS clipboard text');

    // Shared /home/user/Documents/ VFS visibility across macOS -> iOS
    stack.permissions.setGrant(macApp.appId, 'fs.write.user', 'allow');
    stack.compositor.dispatchInput(macWin.windowId, { type: 'menu_action', label: 'Save to Documents' });
    stack.kernel.scheduler.runUntilIdle(macPid, 500);
    const viaIosPath = stack.vfs.readFile('/var/mobile/Documents/omnistudio-note.txt', {
      encoding: 'utf8',
      platform: 'ios',
      uid: 1000,
      gid: 1000,
    });
    // macOS Save to Documents persisted the live pasted iOS text, readable via iOS /var/mobile/Documents!
    assert.equal(viaIosPath, clipFromIos);

    // Fault Isolation: launch a 4th __PAGEZERO faulting binary (SIGSEGV) AND a 5th infinite-loop binary (SIGXCPU)
    const segvIpa = buildIosIpa({
      bundleId: 'com.omnios.ios.fault-segv',
      appName: 'FaultSegv',
      customCode(asm) {
        asm.movz(9, 0x100);
        asm.ldrUImm64(0, 9, 0); // Read inside __PAGEZERO -> SIGSEGV
        asm.ret();
      },
    });
    const segvApp = await stack.pkgManager.install(segvIpa.ipaBytes, { filename: 'fault-segv.ipa' });
    const { pid: segvPid } = await stack.pkgManager.launch(segvApp.appId);
    stack.kernel.scheduler.runUntilIdle(segvPid, 200);
    const segvPcb = stack.kernel.processManager.get(segvPid);
    assert.ok(segvPcb.state === PROCESS_STATES.ZOMBIE || segvPcb.state === PROCESS_STATES.TERMINATED);
    assert.equal(segvPcb.stats.exitSignal, 'SIGSEGV');

    const loopIpa = buildIosIpa({
      bundleId: 'com.omnios.ios.fault-loop',
      appName: 'FaultLoop',
      customCode(asm) {
        asm.label('L_spin');
        asm.b('L_spin'); // Infinite ARM64 self-loop -> SIGXCPU / quota exceeded
      },
    });
    const loopApp = await stack.pkgManager.install(loopIpa.ipaBytes, { filename: 'fault-loop.ipa' });
    const { pid: loopPid } = await stack.pkgManager.launch(loopApp.appId, {
      quotas: { maxTotalInstructions: 250 },
    });
    stack.kernel.scheduler.runUntilIdle(loopPid, 200);
    const loopPcb = stack.kernel.processManager.get(loopPid);
    assert.ok(loopPcb.state === PROCESS_STATES.ZOMBIE || loopPcb.state === PROCESS_STATES.TERMINATED);
    assert.ok(
      loopPcb.stats.exitSignal === 'SIGXCPU' || loopPcb.stats.exitCode !== 0,
      'Infinite loop process must be killed by CPU quota'
    );

    // ALL 3 healthy apps MUST still be alive, responsive, and unharmed!
    assert.equal(stack.kernel.state, KERNEL_STATES.RUNNING);
    assert.equal(stack.kernel.processManager.get(iosPid).state, PROCESS_STATES.BLOCKED);
    assert.equal(stack.kernel.processManager.get(macPid).state, PROCESS_STATES.BLOCKED);
    assert.equal(stack.kernel.processManager.get(wasmPid).state, PROCESS_STATES.BLOCKED);

    const wasmRevBefore = stack.compositor.getWindow(wasmWin.windowId).surfaceRevision;
    stack.compositor.dispatchInput(wasmWin.windowId, { type: 'pointer_down', x: 320, y: 220 });
    stack.kernel.scheduler.runUntilIdle(wasmPid, 100);
    assert.ok(
      stack.compositor.getWindow(wasmWin.windowId).surfaceRevision > wasmRevBefore,
      'Healthy WASM app must remain interactive after sibling PIDs fault'
    );

    // Clean close of all 3 healthy apps
    stack.compositor.closeWindow(iosWin.windowId);
    stack.compositor.closeWindow(macWin.windowId);
    stack.compositor.closeWindow(wasmWin.windowId);
    stack.kernel.scheduler.runUntilIdle(iosPid, 300);
    stack.kernel.scheduler.runUntilIdle(macPid, 300);
    stack.kernel.scheduler.runUntilIdle(wasmPid, 100);
    assert.equal(stack.compositor.listWindows().length, 0);
  });
});

// ============================================================================
// SUITE 10: Wave 1 Hardening Regressions (Items 1-20 — Security, Fault Isolation, ISA/ABI)
// ============================================================================

describe('Suite 10 (Wave 1 Hardening Regressions — Items 1-20)', () => {
  /**
   * Builds a minimal valid 64-bit little-endian ARM64 Mach-O with customizable load commands
   * and payload bytes for Mach-O parser/loader security regression tests.
   */
  function buildCustomMachO64({
    textVmAddr = 0x100000000n,
    textVmSize = 0x4000n,
    textFileSize = 0x4000n,
    extraCmds = [],
    extraTail = new Uint8Array(0),
    lcMainEntryOff = 0x1000n,
    includeLcMain = true,
    includeTextSegment = true,
  } = {}) {
    const cmds = [];

    if (includeTextSegment) {
      const segBuf = new Uint8Array(72);
      const dv = new DataView(segBuf.buffer);
      dv.setUint32(0, MACHO_CONSTANTS.LC_SEGMENT_64, true);
      dv.setUint32(4, 72, true);
      segBuf.set(TEXT_ENCODER.encode('__TEXT'), 8);
      dv.setBigUint64(24, textVmAddr, true);
      dv.setBigUint64(32, textVmSize, true);
      dv.setBigUint64(40, 0n, true);
      dv.setBigUint64(48, textFileSize, true);
      dv.setUint32(56, 7, true);
      dv.setUint32(60, 5, true);
      cmds.push(segBuf);
    }

    if (includeLcMain) {
      const mainBuf = new Uint8Array(24);
      const dv = new DataView(mainBuf.buffer);
      dv.setUint32(0, MACHO_CONSTANTS.LC_MAIN, true);
      dv.setUint32(4, 24, true);
      dv.setBigUint64(8, lcMainEntryOff, true);
      dv.setBigUint64(16, 0n, true);
      cmds.push(mainBuf);
    }

    for (const c of extraCmds) cmds.push(c);

    const sizeofcmds = cmds.reduce((acc, c) => acc + c.byteLength, 0);
    const minFileLen = Math.max(
      includeTextSegment ? Number(textFileSize) : 0x4000,
      32 + sizeofcmds + extraTail.byteLength
    );
    const out = new Uint8Array(minFileLen);
    const hdr = new DataView(out.buffer);
    hdr.setUint32(0, MACHO_CONSTANTS.MH_MAGIC_64, true);
    hdr.setUint32(4, MACHO_CONSTANTS.CPU_TYPE_ARM64, true);
    hdr.setUint32(8, 0, true);
    hdr.setUint32(12, MACHO_CONSTANTS.MH_EXECUTE, true);
    hdr.setUint32(16, cmds.length, true);
    hdr.setUint32(20, sizeofcmds, true);
    hdr.setUint32(24, 0x200085, true);
    hdr.setUint32(28, 0, true);

    let pos = 32;
    for (const c of cmds) {
      out.set(c, pos);
      pos += c.byteLength;
    }
    if (extraTail.byteLength > 0) {
      out.set(extraTail, minFileLen - extraTail.byteLength);
    }
    return { bytes: out, tailOffset: minFileLen - extraTail.byteLength };
  }

  function makeEncCmd(cryptid) {
    const b = new Uint8Array(24);
    const dv = new DataView(b.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.LC_ENCRYPTION_INFO_64, true);
    dv.setUint32(4, 24, true);
    dv.setUint32(8, 0x1000, true);
    dv.setUint32(12, 0x1000, true);
    dv.setUint32(16, cryptid, true);
    return b;
  }

  function buildRawFat(slices, totalLen = 0x4000) {
    const out = new Uint8Array(totalLen);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.FAT_MAGIC, false);
    dv.setUint32(4, slices.length, false);
    for (let i = 0; i < slices.length; i++) {
      const base = 8 + i * 20;
      dv.setUint32(base + 0, slices[i].cputype ?? MACHO_CONSTANTS.CPU_TYPE_ARM64, false);
      dv.setUint32(base + 4, 0, false);
      dv.setUint32(base + 8, slices[i].offset, false);
      dv.setUint32(base + 12, slices[i].size, false);
      dv.setUint32(base + 16, 12, false);
      if (slices[i].payload) {
        out.set(slices[i].payload, slices[i].offset);
      }
    }
    return out;
  }

  it('Items 1-5: Mach-O sticky FairPlay DRM, nested/overlapping Fat rejection, LC_MAIN OOB validation, dyld cumulative cap & strict chained fixups, STAB filter, unsigned chained addend', () => {
    // Item 1: Double LC_ENCRYPTION_INFO_64 (cryptid=1 followed by cryptid=0) MUST NOT bypass FairPlay!
    const { bytes: doubleEnc } = buildCustomMachO64({
      extraCmds: [makeEncCmd(1), makeEncCmd(0)],
    });
    assert.throws(
      () => parseMachO(doubleEnc),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_ENCRYPTED_BINARY
    );
    const inspected = parseMachO(doubleEnc, { allowEncrypted: true });
    assert.equal(inspected.hasEncryptedSegment, true);
    assert.equal(inspected.encryptionInfo.cryptid, 1);
    const asEnc = new AddressSpace({ pid: 901 });
    assert.throws(
      () => loadMachOIntoAddressSpace(inspected, asEnc),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_ENCRYPTED_BINARY
    );

    // Reverse order (0 then 1) must also remain sticky
    const { bytes: revEnc } = buildCustomMachO64({
      extraCmds: [makeEncCmd(0), makeEncCmd(1)],
    });
    const revParsed = parseMachO(revEnc, { allowEncrypted: true });
    assert.equal(revParsed.hasEncryptedSegment, true);
    assert.equal(revParsed.encryptionInfo.cryptid, 1);
    assert.throws(
      () => loadMachOIntoAddressSpace(revParsed, asEnc),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_ENCRYPTED_BINARY
    );

    // Item 2a: Nested Fat Mach-O MUST throw FormatError(E_INVALID_FAT) instead of RangeError stack overflow
    const innerFat = buildRawFat([{ offset: 0x100, size: 0x100 }], 0x400);
    const nestedFat = buildRawFat([{ offset: 0x1000, size: innerFat.byteLength, payload: innerFat }], 0x2000);
    assert.throws(
      () => parseMachO(nestedFat),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_FAT
    );

    // Item 2b: Overlapping Fat slices (partial, identical, contained) MUST all throw E_INVALID_FAT
    const partialOverlap = buildRawFat([
      { cputype: MACHO_CONSTANTS.CPU_TYPE_ARM64, offset: 0x1000, size: 0x1000 },
      { cputype: MACHO_CONSTANTS.CPU_TYPE_X86_64, offset: 0x1800, size: 0x1000 },
    ]);
    const identicalOverlap = buildRawFat([
      { cputype: MACHO_CONSTANTS.CPU_TYPE_ARM64, offset: 0x1000, size: 0x1000 },
      { cputype: MACHO_CONSTANTS.CPU_TYPE_X86_64, offset: 0x1000, size: 0x1000 },
    ]);
    const containedOverlap = buildRawFat([
      { cputype: MACHO_CONSTANTS.CPU_TYPE_ARM64, offset: 0x1000, size: 0x2000 },
      { cputype: MACHO_CONSTANTS.CPU_TYPE_X86_64, offset: 0x1400, size: 0x1000 },
    ]);
    for (const badFat of [partialOverlap, identicalOverlap, containedOverlap]) {
      assert.throws(
        () => parseFatMachO(badFat),
        (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_FAT
      );
    }

    // Item 3: LC_MAIN OOB entryoff (exceeds __TEXT vmsize / filesize / uint64 overflow / missing __TEXT)
    const { bytes: oobEntry } = buildCustomMachO64({ textVmSize: 0x4000n, lcMainEntryOff: 0x8000n });
    assert.throws(
      () => parseMachO(oobEntry),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MACHO
    );
    const { bytes: maxEntry } = buildCustomMachO64({ textVmSize: 0x4000n, lcMainEntryOff: 0xffffffffffffffffn });
    assert.throws(
      () => parseMachO(maxEntry),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MACHO
    );
    const { bytes: noTextEntry } = buildCustomMachO64({ includeTextSegment: false, lcMainEntryOff: 0x100n });
    assert.throws(
      () => parseMachO(noTextEntry),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MACHO
    );
    // Also check loadMachOIntoAddressSpace rejects mutated OOB entryoff or overflow slide
    const { bytes: validMacho } = buildCustomMachO64();
    const validParsed = parseMachO(validMacho);
    assert.throws(
      () =>
        loadMachOIntoAddressSpace(
          { ...validParsed, lcMain: { entryoff: 0x9000n, stacksize: 0n } },
          new AddressSpace({ pid: 902 })
        ),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MACHO
    );

    // Item 4a: Dyld rebase cumulative cap (> 200,000 across multiple opcodes)
    const rebaseBomb = [];
    // REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(seg=0, off=0)
    rebaseBomb.push(0x20, 0x00);
    // 3x REBASE_OPCODE_DO_REBASE_ULEB_TIMES(100_000) -> 300_000 > 200_000! (100_000 in ULEB128 = 0xa0, 0x8d, 0x06)
    for (let i = 0; i < 3; i++) {
      rebaseBomb.push(0x60, 0xa0, 0x8d, 0x06);
    }
    rebaseBomb.push(0x00);
    const dyldCmd = new Uint8Array(48);
    const dyldDv = new DataView(dyldCmd.buffer);
    dyldDv.setUint32(0, MACHO_CONSTANTS.LC_DYLD_INFO_ONLY, true);
    dyldDv.setUint32(4, 48, true);
    const rebaseBytes = Uint8Array.from(rebaseBomb);
    const { bytes: rebaseBombMacho, tailOffset: rebaseTail } = buildCustomMachO64({
      extraCmds: [dyldCmd],
      extraTail: rebaseBytes,
    });
    const rdv = new DataView(rebaseBombMacho.buffer);
    // Patch rebaseOff / rebaseSize inside LC_DYLD_INFO_ONLY (32 + 72 + 24 = 128)
    rdv.setUint32(128 + 8, rebaseTail, true);
    rdv.setUint32(128 + 12, rebaseBytes.byteLength, true);
    assert.throws(
      () => parseMachO(rebaseBombMacho),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MACHO
    );

    // Item 4b: Dyld bind cumulative cap (> 200,000 across multiple opcodes)
    const bindBomb = [0x20, 0x00, 0x40, 0x5f, 0x78, 0x00, 0x70, 0x00]; // SET_SEG(0,0), SYM("_x"), ...
    // Actually: SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40, "_x\0", SET_SEGMENT_AND_OFFSET_ULEB = 0x70, 0x00
    for (let i = 0; i < 3; i++) {
      bindBomb.push(0xc0, 0xa0, 0x8d, 0x06, 0x00); // BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB(100000, 0)
    }
    bindBomb.push(0x00);
    const bindBytes = Uint8Array.from(bindBomb);
    const { bytes: bindBombMacho, tailOffset: bindTail } = buildCustomMachO64({
      extraCmds: [dyldCmd],
      extraTail: bindBytes,
    });
    const bdv = new DataView(bindBombMacho.buffer);
    bdv.setUint32(128 + 16, bindTail, true);
    bdv.setUint32(128 + 20, bindBytes.byteLength, true);
    assert.throws(
      () => parseMachO(bindBombMacho),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MACHO
    );

    // Item 4c: Strict LC_DYLD_CHAINED_FIXUPS validation (truncated imports & OOB startsOffset & unknown format)
    function makeChainedFixupsBinary(payload) {
      const cfCmd = new Uint8Array(16);
      const dv = new DataView(cfCmd.buffer);
      dv.setUint32(0, MACHO_CONSTANTS.LC_DYLD_CHAINED_FIXUPS, true);
      dv.setUint32(4, 16, true);
      const { bytes: m, tailOffset } = buildCustomMachO64({
        extraCmds: [cfCmd],
        extraTail: payload,
      });
      const mdv = new DataView(m.buffer);
      mdv.setUint32(128 + 8, tailOffset, true);
      mdv.setUint32(128 + 12, payload.byteLength, true);
      return m;
    }

    // Truncated importsCount=500 in 32-byte payload + OOB startsOffset=0xFFFF
    const truncCf = new Uint8Array(32);
    const tcfDv = new DataView(truncCf.buffer);
    tcfDv.setUint32(4, 0xffff, true); // startsOffset OOB
    tcfDv.setUint32(8, 28, true); // importsOffset
    tcfDv.setUint32(12, 28, true); // symbolsOffset
    tcfDv.setUint32(16, 500, true); // importsCount = 500
    tcfDv.setUint32(20, MACHO_CONSTANTS.DYLD_CHAINED_IMPORT, true);
    assert.throws(
      () => parseMachO(makeChainedFixupsBinary(truncCf)),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MACHO
    );

    // Unknown importsFormat=99 with importsCount=1
    const badFmtCf = new Uint8Array(40);
    const bfDv = new DataView(badFmtCf.buffer);
    bfDv.setUint32(4, 0, true);
    bfDv.setUint32(8, 28, true);
    bfDv.setUint32(12, 36, true);
    bfDv.setUint32(16, 1, true);
    bfDv.setUint32(20, 99, true);
    assert.throws(
      () => parseMachO(makeChainedFixupsBinary(badFmtCf)),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MACHO
    );

    // Truncated pageStarts inside starts_in_image
    const truncPageCf = new Uint8Array(64);
    const tpDv = new DataView(truncPageCf.buffer);
    tpDv.setUint32(4, 28, true); // startsOffset = 28
    tpDv.setUint32(8, 60, true);
    tpDv.setUint32(12, 60, true);
    tpDv.setUint32(16, 0, true);
    tpDv.setUint32(20, MACHO_CONSTANTS.DYLD_CHAINED_IMPORT, true);
    tpDv.setUint32(28, 1, true); // segCount = 1
    tpDv.setUint32(32, 8, true); // segInfoOffset = 8 -> pos 36
    tpDv.setUint16(36 + 20, 100, true); // pageCount = 100 (requires 200B, only 6B left!)
    assert.throws(
      () => parseMachO(makeChainedFixupsBinary(truncPageCf)),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_INVALID_MACHO
    );

    // Item 5a: STAB debug symbol (nType=0x20 N_GSYM) must NOT overwrite real symbol or be marked isUndefined
    const strtab = TEXT_ENCODER.encode('\0_realFn\0');
    const symtab = new Uint8Array(32 + strtab.byteLength);
    const sdv = new DataView(symtab.buffer);
    // Entry 0: real defined external symbol _realFn at 0x100001000n (nType = 0x0f: N_SECT | N_EXT)
    sdv.setUint32(0, 1, true);
    symtab[4] = 0x0f;
    symtab[5] = 1;
    sdv.setBigUint64(8, 0x100001000n, true);
    // Entry 1: STAB debug entry with same name _realFn (nType = 0x20: N_GSYM) and value 0
    sdv.setUint32(16, 1, true);
    symtab[20] = 0x20;
    sdv.setBigUint64(24, 0n, true);
    symtab.set(strtab, 32);

    const symCmd = new Uint8Array(24);
    const scDv = new DataView(symCmd.buffer);
    scDv.setUint32(0, MACHO_CONSTANTS.LC_SYMTAB, true);
    scDv.setUint32(4, 24, true);
    const { bytes: stabMacho, tailOffset: symTail } = buildCustomMachO64({
      extraCmds: [symCmd],
      extraTail: symtab,
    });
    const stabDv = new DataView(stabMacho.buffer);
    stabDv.setUint32(128 + 8, symTail, true); // symoff
    stabDv.setUint32(128 + 12, 2, true); // nsyms
    stabDv.setUint32(128 + 16, symTail + 32, true); // stroff
    stabDv.setUint32(128 + 20, strtab.byteLength, true); // strsize
    const stabParsed = parseMachO(stabMacho);
    assert.equal(stabParsed.symbols[1].isStab, true);
    assert.equal(stabParsed.symbols[1].isUndefined, false);
    assert.equal(stabParsed.symbolsByName.get('_realFn').value, 0x100001000n);

    // Item 5b: DYLD_CHAINED_PTR_64 bind fixup 8-bit addend is UNSIGNED (0x80 = +128, not -128)
    const dataSeg = new Uint8Array(72);
    const dsdv = new DataView(dataSeg.buffer);
    dsdv.setUint32(0, MACHO_CONSTANTS.LC_SEGMENT_64, true);
    dsdv.setUint32(4, 72, true);
    dataSeg.set(TEXT_ENCODER.encode('__DATA'), 8);
    dsdv.setBigUint64(24, 0x100004000n, true);
    dsdv.setBigUint64(32, 0x1000n, true);
    dsdv.setBigUint64(40, 0x4000n, true);
    dsdv.setBigUint64(48, 0x1000n, true);
    dsdv.setUint32(56, 3, true);
    dsdv.setUint32(60, 3, true);

    // Chained fixups payload: 1 import "_extSym", starts_in_image for segIndex=1 (__DATA), page 0 offset 0
    const symNameBytes = TEXT_ENCODER.encode('_extSym\0');
    const cfBuf = new Uint8Array(28 + 12 + 24 + 4 + symNameBytes.byteLength);
    const cfdv = new DataView(cfBuf.buffer);
    const startsOff = 28;
    const impOff = 28 + 12 + 24;
    const symsOff = impOff + 4;
    cfdv.setUint32(0, 0, true); // version
    cfdv.setUint32(4, startsOff, true);
    cfdv.setUint32(8, impOff, true);
    cfdv.setUint32(12, symsOff, true);
    cfdv.setUint32(16, 1, true); // importsCount
    cfdv.setUint32(20, MACHO_CONSTANTS.DYLD_CHAINED_IMPORT, true);
    cfdv.setUint32(24, 0, true); // symbolsFormat = uncompressed
    // starts_in_image at 28: segCount=2, seg[0]=0, seg[1]=12
    cfdv.setUint32(startsOff + 0, 2, true);
    cfdv.setUint32(startsOff + 4, 0, true);
    cfdv.setUint32(startsOff + 8, 12, true);
    // segInfo at 40: size=24, pageSize=4096, pointerFormat=DYLD_CHAINED_PTR_64 (2), segOff=0x4000, maxValid=0, pageCount=1, pageStart[0]=0
    cfdv.setUint32(startsOff + 12 + 0, 24, true);
    cfdv.setUint16(startsOff + 12 + 4, 4096, true);
    cfdv.setUint16(startsOff + 12 + 6, MACHO_CONSTANTS.DYLD_CHAINED_PTR_64, true);
    cfdv.setBigUint64(startsOff + 12 + 8, 0x4000n, true);
    cfdv.setUint32(startsOff + 12 + 16, 0, true);
    cfdv.setUint16(startsOff + 12 + 20, 1, true);
    cfdv.setUint16(startsOff + 12 + 22, 0, true);
    // import[0] at impOff: libOrdinal=1, weak=0, nameOffset=0 -> 1
    cfdv.setUint32(impOff, 1, true);
    cfBuf.set(symNameBytes, symsOff);

    const cfCmd = new Uint8Array(16);
    const cfCmdDv = new DataView(cfCmd.buffer);
    cfCmdDv.setUint32(0, MACHO_CONSTANTS.LC_DYLD_CHAINED_FIXUPS, true);
    cfCmdDv.setUint32(4, 16, true);
    // Build file with 0x5000 bytes (0x4000 __TEXT + 0x1000 __DATA) + cfBuf
    const dataPayload = new Uint8Array(0x1000 + cfBuf.byteLength);
    // At __DATA+0 write DYLD_CHAINED_PTR_64 bind entry: bit63=1 (bind), ordinal=0, addend=0x80 (bits 24..31), next=0
    const bindRaw = (1n << 63n) | (0x80n << 24n) | 0n;
    new DataView(dataPayload.buffer).setBigUint64(0, bindRaw, true);
    dataPayload.set(cfBuf, 0x1000);

    const { bytes: cfMacho, tailOffset: dataTail } = buildCustomMachO64({
      extraCmds: [dataSeg, cfCmd],
      extraTail: dataPayload,
    });
    const mfdv = new DataView(cfMacho.buffer);
    // Patch __DATA fileoff (at 128 + 40) and LC_DYLD_CHAINED_FIXUPS dataoff/datasize (at 128 + 72 + 8)
    mfdv.setBigUint64(128 + 40, BigInt(dataTail), true);
    mfdv.setUint32(128 + 72 + 8, dataTail + 0x1000, true);
    mfdv.setUint32(128 + 72 + 12, cfBuf.byteLength, true);

    const cfParsed = parseMachO(cfMacho);
    const asCf = new AddressSpace({ pid: 903 });
    loadMachOIntoAddressSpace(cfParsed, asCf, {
      resolveSymbol: (sym) => (sym === '_extSym' ? 0x123456000 : null),
    });
    assert.equal(
      asCf.readU64(0x100004000n, true),
      0x123456000n + 0x80n,
      'DYLD_CHAINED_PTR_64 bind addend 0x80 must decode as unsigned +128 (NOT signed -128)'
    );
  });

  it('Items 6-9: ARM64 SIMD in-place ORR/EOR & MOVI Vd.2D, illegal 32-bit bitfield immr/imms>=32, IEEE-754 FRINTN ties-to-even, and callFunctionSync X21 swiftError capture', () => {
    const as = new AddressSpace({ pid: 910 });
    as.mmap(0x10000, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, 'code');
    as.mmap(0x20000, 0x4000, PROT_READ | PROT_WRITE, 'stack');

    const cpu = createArm64Cpu({ addressSpace: as, pid: 910 });
    cpu.setSP(0x23f00n);

    // Item 6: SIMD in-place ORR (MOV V0.16B, V0.16B), EOR V1.16B, V1.16B, V2.16B, MOVI V3.2D, #0 & MOVI V4.2D, #0xff000000000000ff
    cpu.v[0].fill(0xaa);
    cpu.v[1].fill(0xaa);
    cpu.v[2].fill(0x55);
    cpu.v[3].fill(0xde);
    cpu.v[4].fill(0x77);
    const simdInsns = [
      0x4ea01c00, // ORR V0.16B, V0.16B, V0.16B (MOV V0.16B, V0.16B)
      0x6e221c21, // EOR V1.16B, V1.16B, V2.16B
      0x6f00e403, // MOVI V3.2D, #0
      0x6f04e424, // MOVI V4.2D, #0xff000000000000ff (imm8 = 0x81 -> a=4, b=1)
      ARM64_RET_OPCODE,
    ];
    for (let i = 0; i < simdInsns.length; i++) {
      as.writeU32(0x10000n + BigInt(i * 4), simdInsns[i], true);
    }
    cpu.callFunctionSync(0x10000n, []);
    // Note: callFunctionSync restores V regs; verify via direct step!
    cpu.setPC(0x10000n);
    cpu.setLR(0x10010n);
    cpu.step(4);
    assert.ok(cpu.v[0].every((b) => b === 0xaa), 'MOV V0.16B, V0.16B must preserve V0');
    assert.ok(cpu.v[1].every((b) => b === 0xff), 'EOR V1.16B, V1.16B, V2.16B must compute 0xaa ^ 0x55 = 0xff');
    assert.ok(cpu.v[3].every((b) => b === 0x00), 'MOVI V3.2D, #0 must zero all 16 bytes');
    assert.deepEqual(
      Array.from(cpu.v[4]),
      [0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0xff],
      'MOVI V4.2D, #imm8 must expand each bit to 0xFF/0x00 across both 64-bit lanes'
    );

    // Item 7: Unallocated 32-bit bitfield encodings (immr>=32 or imms>=32) -> SIGILL
    as.writeU32(0x10100n, 0x53203c20, true); // 32-bit UBFM with immr=32
    cpu.setPC(0x10100n);
    assert.throws(
      () => cpu.step(1),
      (err) => err instanceof IllegalInstructionError && err.signal === 'SIGILL'
    );
    as.writeU32(0x10104n, 0x53008020, true); // 32-bit UBFM with imms=32
    cpu.setPC(0x10104n);
    assert.throws(
      () => cpu.step(1),
      (err) => err instanceof IllegalInstructionError && err.signal === 'SIGILL'
    );

    // Item 8: IEEE-754 FRINTN ties-to-even (frintn d0, d0 = 0x1e644000)
    as.writeU32(0x10200n, 0x1e644000, true);
    const cases = [
      [2.5, 2.0],
      [3.5, 4.0],
      [-2.5, -2.0],
      [-3.5, -4.0],
      [0.5, 0.0],
      [-0.5, -0.0],
      [Infinity, Infinity],
      [-Infinity, -Infinity],
    ];
    for (const [input, expected] of cases) {
      cpu.setDReg(0, input);
      cpu.setPC(0x10200n);
      cpu.step(1);
      const got = cpu.getDReg(0);
      assert.ok(Object.is(got, expected), `FRINTN(${input}) expected ${expected}, got ${got}`);
    }
    cpu.setDReg(0, Number.NaN);
    cpu.setPC(0x10200n);
    cpu.step(1);
    assert.ok(Number.isNaN(cpu.getDReg(0)), 'FRINTN(NaN) must preserve NaN');

    // Item 9: callFunctionSync captures X21 (swiftError) before finally restore
    const asm = new Arm64Assembler();
    asm.movz(0, 0x1234);
    asm.movz(21, 0xbeef);
    asm.ret();
    const swiftFnCode = asm.finalize(0x10300n, () => 0n);
    as.write(0x10300n, swiftFnCode);
    cpu.setReg(21, 0x7777n);
    const callRes = cpu.callFunctionSync(0x10300n, []);
    assert.equal(callRes.result, 0x1234n);
    assert.equal(callRes.x21, 0xbeefn);
    assert.equal(callRes.swiftError, 0xbeefn);
    assert.equal(cpu.getReg(21), 0x7777n, 'Outer X21 must remain restored after callFunctionSync');
  });

  it('Items 10-12: Darwin mach_timebase_info_trap OOB guard, dual-path SYS_rename PermissionBroker check, and direct M3 X86_64Cpu compatibility', async () => {
    const stack = await bootFullM4Stack('omnios-m4-darwin-hard-');
    const appDir = '/var/appdata/macos/com.test.rename';
    const appIdentity = stack.users.allocateAppUid('com.test.rename', {
      platform: 'macos',
      sandboxRoot: appDir,
    });
    stack.vfs.mkdir(appDir, { recursive: true, uid: 0, gid: 0 });
    stack.vfs.chown(appDir, appIdentity.uid, appIdentity.gid, { uid: 0, gid: 0 });
    stack.vfs.mkdir('/home/user/Desktop', { recursive: true, uid: 0, gid: 0 });
    stack.vfs.chown('/home/user/Desktop', 1000, 1000, { uid: 0, gid: 0 });
    stack.vfs.writeFile('/home/user/Desktop/secret.txt', 'TOP-SECRET', { uid: 1000, gid: 1000 });
    stack.vfs.writeFile('/home/user/Documents/allowed-src.txt', 'OK-DATA', { uid: 1000, gid: 1000 });

    const brokerCheckedPaths = [];
    const as = new AddressSpace({ pid: 920 });
    as.reserveGuard(0, 0x100000000, '__PAGEZERO');
    as.mmap(0x100000000, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, '__TEXT');
    as.mmap(0x100004000, 0x4000, PROT_READ | PROT_WRITE, '__DATA');

    const syscalls = createDarwinSyscalls({
      addressSpace: as,
      vfs: stack.vfs,
      platform: 'macos',
      appId: 'com.test.rename',
      sandboxRoot: appDir,
      cwd: appDir,
      pid: 920,
      uid: appIdentity.uid,
      gid: appIdentity.gid,
      permissionBroker: (req) => {
        brokerCheckedPaths.push(req.canonicalPath);
        // Only authorize /home/user/Documents/* (DENY /home/user/Desktop/*)
        const ok = req.canonicalPath.startsWith('/home/user/Documents/');
        return { allowed: ok };
      },
    });

    const cpu = createArm64Cpu({
      addressSpace: as,
      pid: 920,
      onSyscall: (c, imm) => syscalls.handleArm64Svc(c, imm),
    });

    // Item 10: mach_timebase_info_trap (-89) with __PAGEZERO OOB pointer returns KERN_INVALID_ADDRESS (1n), never throws
    cpu.setReg(16, BigInt.asUintN(64, BigInt(MACH_TRAPS.mach_timebase_info_trap)));
    cpu.setReg(0, 0x100n);
    assert.doesNotThrow(() => syscalls.handleArm64Svc(cpu, 0x80));
    assert.equal(cpu.getReg(0), 1n, 'mach_timebase_info_trap OOB ptr must return KERN_INVALID_ADDRESS (1n)');

    // Item 11: SYS_rename checks BOTH oldPath and newPath via PermissionBroker
    const writeCStr = (va, str) => {
      const enc = TEXT_ENCODER.encode(`${str}\0`);
      as.write(va, enc);
      return va;
    };
    const secretPtr = writeCStr(0x100004000n, '/home/user/Desktop/secret.txt');
    const lootPtr = writeCStr(0x100004100n, '/home/user/Documents/loot.txt');
    cpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_rename));
    cpu.setReg(0, secretPtr);
    cpu.setReg(1, lootPtr);
    syscalls.handleArm64Svc(cpu, 0x80);
    assert.equal(cpu.pstate.C, 1, 'SYS_rename with denied source path MUST fail with Carry=1');
    assert.equal(cpu.getReg(0), BigInt(DARWIN_ERRNO.EACCES));
    assert.ok(brokerCheckedPaths.includes('/home/user/Desktop/secret.txt'), 'Broker must inspect oldPath');
    assert.ok(brokerCheckedPaths.includes('/home/user/Documents/loot.txt'), 'Broker must inspect newPath');
    assert.equal(
      stack.vfs.readFile('/home/user/Desktop/secret.txt', { encoding: 'utf8', uid: 1000, gid: 1000 }),
      'TOP-SECRET'
    );

    // Authorized dual-Documents rename succeeds!
    const okSrcPtr = writeCStr(0x100004200n, '/home/user/Documents/allowed-src.txt');
    const okDstPtr = writeCStr(0x100004300n, '/home/user/Documents/allowed-dst.txt');
    cpu.setReg(16, BigInt(DARWIN_SYSCALLS.SYS_rename));
    cpu.setReg(0, okSrcPtr);
    cpu.setReg(1, okDstPtr);
    syscalls.handleArm64Svc(cpu, 0x80);
    assert.equal(cpu.pstate.C, 0, 'SYS_rename with BOTH paths authorized must succeed');
    assert.equal(
      stack.vfs.readFile('/home/user/Documents/allowed-dst.txt', { encoding: 'utf8', uid: 1000, gid: 1000 }),
      'OK-DATA'
    );

    // Item 12: Direct M3 X86_64Cpu compatibility (getReg64/setReg64 + BigInt rflags)
    const strictM3LikeX64 = {
      addressSpace: as,
      rflags: 0x202n,
      exited: false,
      exitCode: 0,
      _map: new Map(),
      getReg64(name) {
        return this._map.get(name) ?? 0n;
      },
      setReg64(name, val) {
        this._map.set(name, BigInt.asUintN(64, val));
      },
      // Simulate real M3 X86_64Cpu numeric-only getReg/setReg/setFlag that fail on string names!
      getReg(idx) {
        if (typeof idx !== 'number') throw new TypeError('numeric idx expected');
        return 0n;
      },
      setReg(idx) {
        if (typeof idx !== 'number') throw new TypeError('numeric idx expected');
      },
      setFlag(mask) {
        if (typeof mask !== 'number') throw new SyntaxError('Cannot convert CF to a BigInt');
      },
    };
    strictM3LikeX64.setReg64('rax', BigInt(0x02000000 | DARWIN_SYSCALLS.SYS_getpid));
    syscalls.handleX86_64Syscall(strictM3LikeX64);
    assert.equal(strictM3LikeX64.getReg64('rax'), 920n);
    assert.equal(strictM3LikeX64.rflags & 1n, 0n);

    const badPathPtr = writeCStr(0x100004400n, `${appDir}/does-not-exist.txt`);
    strictM3LikeX64.setReg64('rax', BigInt(0x02000000 | DARWIN_SYSCALLS.SYS_open));
    strictM3LikeX64.setReg64('rdi', badPathPtr);
    strictM3LikeX64.setReg64('rsi', 0n);
    strictM3LikeX64.setReg64('rdx', 0n);
    syscalls.handleX86_64Syscall(strictM3LikeX64);
    assert.equal(strictM3LikeX64.rflags & 1n, 1n, 'Direct M3 X86_64Cpu must set RFLAGS.CF=1 on BSD error');
    assert.equal(strictM3LikeX64.getReg64('rax'), BigInt(DARWIN_ERRNO.ENOENT));

    // Also test dynamically against real M3 X86_64Cpu when present on disk (zero static M3 import!)
    const x64ModulePath = path.join(REPO_ROOT, 'os/cpu/x86_64.mjs');
    if (fs.existsSync(x64ModulePath)) {
      const { X86_64Cpu } = await import(`file://${x64ModulePath}`);
      const realX64 = new X86_64Cpu({ addressSpace: as, mode: 'x86_64', pid: 920 });
      realX64.setReg64('rax', BigInt(0x02000000 | DARWIN_SYSCALLS.SYS_getpid));
      syscalls.handleX86_64Syscall(realX64);
      assert.equal(realX64.getReg64('rax'), 920n);
      assert.equal(realX64.rflags & 1n, 0n);

      realX64.setReg64('rax', BigInt(0x02000000 | DARWIN_SYSCALLS.SYS_open));
      realX64.setReg64('rdi', badPathPtr);
      realX64.setReg64('rsi', 0n);
      realX64.setReg64('rdx', 0n);
      syscalls.handleX86_64Syscall(realX64);
      assert.equal(realX64.rflags & 1n, 1n);
      assert.equal(realX64.getReg64('rax'), BigInt(DARWIN_ERRNO.ENOENT));
    }
  });

  it('Items 13-16: ObjC 64-bit heap/memset safety, Swift swifterror & App IMP _exit propagation, cyclic containers, NSFileManager rename/chdir, ARC re-entrancy, _formatString %%, NSNumber S0 float & small_method_t fallback', () => {
    const as = new AddressSpace({ pid: 930, maxMemoryBytes: 8 * 1024 * 1024 });
    as.reserveGuard(0, 0x100000000, '__PAGEZERO');
    as.mmap(0x100000000, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, '__TEXT');
    as.mmap(0x100004000, 0x4000, PROT_READ | PROT_WRITE, '__DATA');
    as.mmap(APPLE_THUNK_BASE, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, 'thunks');
    as.mmap(APPLE_STACK_BASE, 0x10000, PROT_READ | PROT_WRITE, 'stack');

    const exitThunkVA = BigInt(APPLE_THUNK_BASE + 0x10);
    as.writeU32(exitThunkVA, ARM64_RET_OPCODE, true);

    const stackPromise = bootFullM4Stack('omnios-m4-objc-hard-');
    return stackPromise.then((stack) => {
      const appDir = '/var/appdata/macos/com.test.objc-hard';
      const objcId = stack.users.allocateAppUid('com.test.objc-hard', {
        platform: 'macos',
        sandboxRoot: appDir,
      });
      stack.vfs.mkdir(`${appDir}/sub`, { recursive: true, uid: 0, gid: 0 });
      stack.vfs.chown(appDir, objcId.uid, objcId.gid, { uid: 0, gid: 0 });
      stack.vfs.chown(`${appDir}/sub`, objcId.uid, objcId.gid, { uid: 0, gid: 0 });
      stack.vfs.mkdir('/home/user/Desktop', { recursive: true, uid: 0, gid: 0 });
      stack.vfs.chown('/home/user/Desktop', 1000, 1000, { uid: 0, gid: 0 });
      stack.vfs.writeFile('/home/user/Desktop/objc-secret.txt', 'KEEP-SAFE', { uid: 1000, gid: 1000 });

      const rt = createObjCRuntime({
        addressSpace: as,
        vfs: stack.vfs,
        platform: 'macos',
        appId: 'com.test.objc-hard',
        sandboxRoot: appDir,
        cwd: appDir,
        uid: objcId.uid,
        gid: objcId.gid,
        permissionBroker: (req) => ({
          allowed: req.canonicalPath.startsWith('/home/user/Documents/'),
        }),
      });

      const cpu = createArm64Cpu({
        addressSpace: as,
        pid: 930,
        thunkStart: APPLE_THUNK_BASE,
        thunkEnd: APPLE_THUNK_BASE + 0x4000,
        onThunk: (pc, c) => (pc === exitThunkVA ? rt.handleThunk('__exit', c) : false),
      });
      cpu.setSP(BigInt(APPLE_STACK_BASE + 0xf000));

      // Item 13: malloc/calloc/realloc/swift_allocObject 64-bit bounds + bounded memset/memmove
      for (const huge of [0x80000000n, 0x100000000n, 0x100000010n, 0xffffffffffffffffn]) {
        cpu.setReg(0, huge);
        rt.handleThunk('_malloc', cpu);
        assert.equal(cpu.getReg(0), 0n, `malloc(0x${huge.toString(16)}) MUST return 0n`);
      }
      cpu.setReg(0, 0x100000001n);
      cpu.setReg(1, 0x100000001n);
      rt.handleThunk('_calloc', cpu);
      assert.equal(cpu.getReg(0), 0n, 'Overflowing calloc MUST return 0n');

      cpu.setReg(0, 0n);
      cpu.setReg(1, 100_000_000n);
      assert.doesNotThrow(() => rt.handleThunk('_realloc', cpu));
      assert.equal(cpu.getReg(0), 0n, 'realloc(0, 100MB) MUST return 0n without throwing');

      cpu.setReg(0, 0x1000n);
      cpu.setReg(1, 0x100000000n);
      rt.handleThunk('_swift_allocObject', cpu);
      assert.equal(cpu.getReg(0), 0n, 'swift_allocObject(4 GiB) MUST return 0n');

      // memset(-1) MUST throw MemoryFaultError(EFAULT), NEVER host RangeError
      cpu.setReg(0, 64n);
      rt.handleThunk('_malloc', cpu);
      const validBuf = cpu.getReg(0);
      assert.notEqual(validBuf, 0n);
      cpu.setReg(0, validBuf);
      cpu.setReg(1, 0n);
      cpu.setReg(2, 0xffffffffffffffffn);
      assert.throws(
        () => rt.handleThunk('_memset', cpu),
        (err) => err instanceof MemoryFaultError && err.code === ERROR_CODES.EFAULT
      );

      // Overlapping memmove forward & backward
      as.write(validBuf, TEXT_ENCODER.encode('ABCDEFGH'));
      cpu.setReg(0, validBuf + 2n);
      cpu.setReg(1, validBuf);
      cpu.setReg(2, 6n);
      rt.handleThunk('_memmove', cpu);
      assert.equal(TEXT_DECODER.decode(as.read(validBuf, 8)), 'ABABCDEF');

      // Item 14a: Swift invokeSwiftMethod propagates X21 swifterror on ARM64
      const swAsm = new Arm64Assembler();
      swAsm.movz(0, 0x42);
      swAsm.movz(21, 0xbeef);
      swAsm.ret();
      as.write(0x100000000n, swAsm.finalize(0x100000000n, () => 0n));
      const swRes = rt.invokeSwiftMethod(cpu, 0x100000000n, 0x5555n, []);
      assert.equal(swRes.result, 0x42n);
      assert.equal(swRes.swiftError, 0xbeefn, 'ARM64 invokeSwiftMethod must return X21 swifterror');

      // Item 14b: x86-64 invokeSwiftMethod saves/restores r13 & r12 and returns r12 swiftError
      const mockX64 = {
        arch: 'x86_64',
        regs: { r13: 0x1111n, r12: 0x2222n, rax: 0n },
        getReg(n) {
          return this.regs[n] ?? 0n;
        },
        setReg(n, v) {
          this.regs[n] = v;
        },
        callFunctionSync() {
          assert.equal(this.regs.r13, 0x9999n);
          assert.equal(this.regs.r12, 0n);
          return { result: 77n, r12: 0xcafen, swiftError: 0xcafen, instructionsExecuted: 3, halted: false, exitCode: 0 };
        },
      };
      const swX64Res = rt.invokeSwiftMethod(mockX64, 0x1000n, 0x9999n, []);
      assert.equal(swX64Res.swiftError, 0xcafen);
      assert.equal(mockX64.regs.r13, 0x1111n);
      assert.equal(mockX64.regs.r12, 0x2222n);

      // Item 14c: App IMP calling _exit(7) propagates cpu.halted & cpu.exitCode
      const impAsm = new Arm64Assembler();
      impAsm.movz(0, 7);
      impAsm.movz(9, Number(exitThunkVA & 0xffffn), 0);
      impAsm.movk(9, Number((exitThunkVA >> 16n) & 0xffffn), 16);
      impAsm.movk(9, Number((exitThunkVA >> 32n) & 0xffffn), 32);
      impAsm.blr(9);
      impAsm.ret();
      as.write(0x100000100n, impAsm.finalize(0x100000100n, () => 0n));
      cpu.halted = false;
      cpu.exitCode = 0;
      rt.invokeAppImp(cpu, 0x100000100n, 0x1n, 'onQuit:', []);
      assert.equal(cpu.halted, true, 'App IMP calling _exit(7) must propagate cpu.halted=true');
      assert.equal(cpu.exitCode, 7);
      cpu.halted = false;
      cpu.exitCode = 0;

      // Item 15a: Cyclic NSMutableArray & NSMutableDictionary do NOT stack-overflow describeObject / objcToJs / jsToObjC
      const arr = rt.createNSArray([], true);
      rt.msgSend(cpu, arr, 'addObject:', [arr]);
      assert.equal(rt.describeObject(arr), '((...))');
      assert.deepEqual(rt.objcToJs(arr), [null]);

      const dict = rt.createNSDictionary([], true);
      const selfKey = rt.createNSString('self');
      rt.msgSend(cpu, dict, 'setObject:forKey:', [dict, selfKey]);
      assert.equal(rt.describeObject(dict), '{self = {...}}');
      assert.deepEqual(rt.objcToJs(dict), { self: null });

      const cyclicJs = { a: 1 };
      cyclicJs.self = cyclicJs;
      const converted = rt.jsToObjC(cyclicJs);
      assert.notEqual(converted, 0n);

      // Item 15b: NSFileManager moveItemAtPath checks BOTH src & dst; changeCurrentDirectoryPath validates dir/sandbox
      const fm = rt.msgSend(cpu, rt.getClass('NSFileManager'), 'defaultManager', []);
      const moveOk = rt.msgSend(cpu, fm, 'moveItemAtPath:toPath:error:', [
        rt.createNSString('/home/user/Desktop/objc-secret.txt'),
        rt.createNSString('/home/user/Documents/stolen.txt'),
        0n,
      ]);
      assert.equal(moveOk, 0n, 'NSFileManager moveItemAtPath must fail closed when source is unauthorized');
      assert.equal(
        stack.vfs.readFile('/home/user/Desktop/objc-secret.txt', { encoding: 'utf8', uid: 1000, gid: 1000 }),
        'KEEP-SAFE'
      );

      assert.equal(
        rt.msgSend(cpu, fm, 'changeCurrentDirectoryPath:', [rt.createNSString('/nonexistent/outside')]),
        0n
      );
      assert.equal(rt.cwd, appDir);
      assert.equal(
        rt.msgSend(cpu, fm, 'changeCurrentDirectoryPath:', [rt.createNSString(`${appDir}/sub`)]),
        1n
      );
      assert.equal(rt.cwd, `${appDir}/sub`);

      // Item 15c: ARC re-entrant dealloc guard + container child release + NSMutableArray subscript bounds
      let deallocCalls = 0;
      rt.registerHostClass('ReentrantDeallocObj', 'NSObject', {
        instanceMethods: {
          dealloc: (self) => {
            deallocCalls++;
            rt.release(self, cpu); // Re-entrant release(self) must be a no-op!
            return 0n;
          },
        },
      });
      const reObj = rt.allocObject('ReentrantDeallocObj');
      rt.release(reObj, cpu);
      assert.equal(deallocCalls, 1, 'Re-entrant dealloc must run exactly once');

      const childStr = rt.createNSString('child-item'); // rc=1
      const holder = rt.createNSArray([childStr]); // child rc=2
      rt.release(childStr, cpu); // child rc=1 (owned solely by holder)
      assert.equal(rt.getRetainCount(childStr), 1);
      rt.release(holder, cpu); // releasing holder must release childStr -> rc=0!
      assert.equal(rt.getRetainCount(childStr), 0, 'Releasing NSArray must release retained children');

      const boundedArr = rt.createNSArray([], true);
      const itemA = rt.createNSString('A');
      rt.msgSend(cpu, boundedArr, 'setObject:atIndexedSubscript:', [itemA, BigInt.asUintN(64, -1n)]);
      rt.msgSend(cpu, boundedArr, 'setObject:atIndexedSubscript:', [itemA, 999999n]);
      assert.equal(rt.msgSend(cpu, boundedArr, 'count', []), 0n, 'Out-of-bounds subscript must not corrupt array');
      rt.msgSend(cpu, boundedArr, 'setObject:atIndexedSubscript:', [itemA, 0n]);
      assert.equal(rt.msgSend(cpu, boundedArr, 'count', []), 1n);

      // Item 16a: _formatString preserves literal %% inside %@ / %s arguments
      const fmtRes = rt._formatString('100%% %@ %%', [rt.createNSString('50%% off')]);
      assert.equal(fmtRes, '100% 50%% off %');

      // Item 16b: NSNumber numberWithFloat: / floatValue uses ARM64 S0 (not D0)
      cpu.setDReg(0, 0.0);
      cpu.setSReg(0, 1.5);
      const numPtr = rt.msgSend(cpu, rt.getClass('NSNumber'), 'numberWithFloat:', []);
      assert.equal(rt.getHostObject(numPtr).value, 1.5);
      cpu.setDReg(0, 0.0);
      rt.msgSend(cpu, numPtr, 'floatValue', []);
      assert.equal(cpu.getSReg(0), 1.5, '-[NSNumber floatValue] must populate ARM64 S0');

      // Item 16c: _parseMethodList relative small_method_t direct C-string fallback
      const mlBase = 0x100004800n;
      const directSelVA = 0x100004900n;
      const typesVA = 0x100004940n;
      const impVA = 0x100000200n;
      as.write(directSelVA, TEXT_ENCODER.encode('directSmallSel:\0'));
      as.write(typesVA, TEXT_ENCODER.encode('v24@0:8@16\0'));
      as.writeU32(mlBase, 0x8000000c, true); // isRelative | entsize=12
      as.writeU32(mlBase + 4n, 1, true); // count=1
      const entryVA = mlBase + 8n;
      as.writeU32(entryVA + 0n, Number(directSelVA - entryVA) >>> 0, true);
      as.writeU32(entryVA + 4n, Number(typesVA - (entryVA + 4n)) >>> 0, true);
      as.writeU32(entryVA + 8n, Number(impVA - (entryVA + 8n)) >>> 0, true);
      const parsedMethods = new Map();
      rt._parseMethodList(mlBase, parsedMethods);
      assert.ok(parsedMethods.has('directSmallSel:'), 'small_method_t direct C-string fallback must resolve');
      assert.equal(parsedMethods.get('directSmallSel:').impVA, impVA);
    });
  });

  it('Items 17-18: WASI untrusted manifest.preopens capability/sandbox enforcement & path_open rightsBase attenuation integrity', async () => {
    const stack = await bootFullM4Stack('omnios-m4-wasi-hard-');
    const appData = '/var/appdata/universal/com.evil.uapp';
    const evilId = stack.users.allocateAppUid('com.evil.uapp', {
      platform: 'universal',
      sandboxRoot: appData,
    });
    const sysId = stack.users.allocateAppUid('com.sysread.uapp', {
      platform: 'universal',
      sandboxRoot: appData,
    });
    stack.vfs.mkdir(appData, { recursive: true, uid: 0, gid: 0 });
    stack.vfs.chown(appData, evilId.uid, evilId.gid, { uid: 0, gid: 0 });
    stack.vfs.writeFile(`${appData}/ok.txt`, 'hello', { uid: 0, gid: 0 });
    stack.vfs.chown(`${appData}/ok.txt`, evilId.uid, evilId.gid, { uid: 0, gid: 0 });
    stack.vfs.writeFile('/home/user/Documents/private.txt', 'USER-SECRET', { uid: 1000, gid: 1000, mode: 0o600 });
    stack.vfs.mkdir('/etc', { recursive: true, uid: 0, gid: 0 });
    stack.vfs.writeFile('/etc/test.conf', 'SYS-DATA', { uid: 0, gid: 0, mode: 0o644 });

    // Item 17a: App granted ONLY ui.window MUST NOT mount preopens by forging spec.capability="ui.window"!
    stack.permissions.setGrant('com.evil.uapp', 'ui.window', 'allow');
    const evilBridge = createWasiBridge({
      services: { vfs: stack.vfs, permissions: stack.permissions },
      appRecord: {
        appId: 'com.evil.uapp',
        dataDir: appData,
        uid: evilId.uid,
        gid: evilId.gid,
        metadata: {
          manifest: {
            preopens: [
              { virtualName: 'pwn-user', hostPath: '/home/user', writable: true, capability: 'ui.window' },
              { virtualName: 'pwn-etc', hostPath: '/etc', writable: false, capability: 'ui.window' },
            ],
          },
        },
      },
      memory: new WebAssembly.Memory({ initial: 1, maximum: 2 }),
    });
    const evilWasi = evilBridge.getImportObject().wasi_snapshot_preview1;
    assert.equal(evilWasi.fd_prestat_get(4, 0), WASI_ERRNO.WASI_EBADF, 'Forged spec.capability preopens must be rejected');

    // Item 17b: App granted ONLY fs.read.user rejects /etc, /root, /var/appdata/*, /home/user/../etc, /home/user2, writable /home/user/Documents,
    // and ONLY mounts read-only /home/user/Documents
    stack.permissions.setGrant('com.readuser.uapp', 'fs.read.user', 'allow');
    const ruMem = new WebAssembly.Memory({ initial: 1, maximum: 2 });
    const ruBridge = createWasiBridge({
      services: { vfs: stack.vfs, permissions: stack.permissions },
      appRecord: {
        appId: 'com.readuser.uapp',
        dataDir: appData,
        uid: evilId.uid,
        gid: evilId.gid,
        metadata: {
          manifest: {
            preopens: [
              { virtualName: 'etc', hostPath: '/etc' },
              { virtualName: 'root', hostPath: '/root' },
              { virtualName: 'cross', hostPath: '/var/appdata/other' },
              { virtualName: 'trav', hostPath: '/home/user/../etc' },
              { virtualName: 'rel', hostPath: 'home/user' },
              { virtualName: 'nul', hostPath: '/home/user\0/Documents' },
              { virtualName: 'user2', hostPath: '/home/user2' },
              { virtualName: 'docs-rw', hostPath: '/home/user/Documents', writable: true },
              { virtualName: 'docs-ro', hostPath: '/home/user/Documents', writable: false },
            ],
          },
        },
      },
      memory: ruMem,
    });
    const ruWasi = ruBridge.getImportObject().wasi_snapshot_preview1;
    assert.equal(ruWasi.fd_prestat_get(4, 0), WASI_ERRNO.WASI_ESUCCESS);
    assert.equal(ruWasi.fd_prestat_get(5, 0), WASI_ERRNO.WASI_EBADF, 'Only the single authorized docs-ro preopen may mount');
    const nameLen = new DataView(ruMem.buffer).getUint32(4, true);
    assert.equal(ruWasi.fd_prestat_dir_name(4, 64, nameLen), WASI_ERRNO.WASI_ESUCCESS);
    assert.equal(TEXT_DECODER.decode(new Uint8Array(ruMem.buffer, 64, nameLen)), 'docs-ro');

    // Item 17c: App granted fs.read.system can mount /etc read-only with app UID (no UID 1000 escalation),
    // while /root and /var/appdata/* remain unconditionally rejected!
    stack.permissions.setGrant('com.sysread.uapp', 'fs.read.system', 'allow');
    const sysBridge = createWasiBridge({
      services: { vfs: stack.vfs, permissions: stack.permissions },
      appRecord: {
        appId: 'com.sysread.uapp',
        dataDir: appData,
        uid: sysId.uid,
        gid: sysId.gid,
        metadata: {
          manifest: {
            preopens: [
              { virtualName: 'root-bad', hostPath: '/root' },
              { virtualName: 'appdata-bad', hostPath: '/var/appdata/victim' },
              { virtualName: 'etc-ro', hostPath: '/etc', writable: false },
            ],
          },
        },
      },
      memory: new WebAssembly.Memory({ initial: 1, maximum: 2 }),
    });
    const sysEntry = sysBridge._fds.get(4);
    assert.ok(sysEntry && sysEntry.virtualName === 'etc-ro');
    assert.equal(sysEntry.actorUid, sysId.uid, 'System preopen must NOT escalate to UID 1000');
    assert.equal(sysBridge._fds.has(5), false);

    // Item 18: path_open MUST preserve effectiveBase === 0n (NEVER re-grant rights!)
    const attMem = new WebAssembly.Memory({ initial: 1, maximum: 2 });
    const attBridge = createWasiBridge({
      services: { vfs: stack.vfs },
      appRecord: { appId: 'com.evil.uapp', dataDir: appData, uid: evilId.uid, gid: evilId.gid },
      memory: attMem,
    });
    const attWasi = attBridge.getImportObject().wasi_snapshot_preview1;
    const writeMem = (off, s) => {
      const b = TEXT_ENCODER.encode(s);
      new Uint8Array(attMem.buffer).set(b, off);
      return { ptr: off, len: b.byteLength };
    };
    const fileP = writeMem(256, 'ok.txt');
    // Case A: Explicit reqBase = 0n -> opened FD MUST have rightsBase === 0n
    assert.equal(
      attWasi.path_open(3, 1, fileP.ptr, fileP.len, 0, 0n, 0n, 0, 512),
      WASI_ERRNO.WASI_ESUCCESS
    );
    const fdZero = new DataView(attMem.buffer).getUint32(512, true);
    assert.equal(attWasi.fd_fdstat_get(fdZero, 600), WASI_ERRNO.WASI_ESUCCESS);
    assert.equal(
      new DataView(attMem.buffer).getBigUint64(600 + 8, true),
      0n,
      'path_open with reqBase=0n must yield rightsBase=0n'
    );

    // Case B: Attenuating dir FD rightsInheriting to 0n -> child dir FD MUST have rightsBase === 0n
    const R = WASI_CONSTANTS.RIGHTS;
    assert.equal(
      attWasi.fd_fdstat_set_rights(3, R.PATH_OPEN | R.PATH_UNLINK_FILE, 0n),
      WASI_ERRNO.WASI_ESUCCESS
    );
    const dotP = writeMem(300, '.');
    assert.equal(
      attWasi.path_open(3, 0, dotP.ptr, dotP.len, WASI_CONSTANTS.OFLAGS.DIRECTORY, 0n, 0n, 0, 520),
      WASI_ERRNO.WASI_ESUCCESS
    );
    const childDirFd = new DataView(attMem.buffer).getUint32(520, true);
    assert.equal(attWasi.fd_fdstat_get(childDirFd, 640), WASI_ERRNO.WASI_ESUCCESS);
    assert.equal(
      new DataView(attMem.buffer).getBigUint64(640 + 8, true),
      0n,
      'path_open on dir with rightsInheriting=0n must NOT re-grant parent dir rights'
    );

    evilBridge.dispose();
    ruBridge.dispose();
    sysBridge.dispose();
    attBridge.dispose();
  });

  it('Items 19-20: macOS per-tick budget clamping & deliverEvent wake, iOS FAULT/halted handling, .pkg shared bomb budget & nested absolute XAR <name>, and macos-macho basename sanitization', async () => {
    const stack = await bootFullM4Stack('omnios-m4-mac-hard-');

    // Item 19a: macOS step(budget) clamps event drain to maxInstructionsPerTick (NEVER killed with SIGXCPU!)
    const macZipBytes = buildMacAppZip({
      appName: 'BudgetMac',
      bundleId: 'com.omnios.macos.budget-test',
    });
    const macApp = await stack.pkgManager.install(macZipBytes, { filename: 'BudgetMac.app.zip' });
    const { pid: macPid } = await stack.pkgManager.launch(macApp.appId, {
      quotas: { maxInstructionsPerTick: 200, maxTotalInstructions: 500_000 },
    });
    stack.kernel.scheduler.runUntilIdle(macPid, 500);
    const macWin = stack.compositor.listWindows({ pid: macPid })[0];
    assert.ok(macWin, 'BudgetMac window must open');

    // Queue 6 menu actions simultaneously so total instructions exceed a single 200-insn tick!
    for (let i = 0; i < 6; i++) {
      stack.compositor.dispatchInput(macWin.windowId, { type: 'menu_action', label: 'New Document' });
    }
    stack.kernel.scheduler.runUntilIdle(macPid, 500);
    const macPcb = stack.kernel.processManager.get(macPid);
    assert.equal(
      macPcb.state,
      PROCESS_STATES.BLOCKED,
      `Healthy macOS app must NOT be killed with SIGXCPU under tight per-tick budget (got ${macPcb.state}, fault=${macPcb.lastFault?.message})`
    );
    assert.equal(macPcb.stats.exitSignal, null);

    // Item 19b: Direct execCtx.deliverEvent() wakes a BLOCKED macOS PCB
    assert.equal(macPcb.state, PROCESS_STATES.BLOCKED);
    macPcb.executionContext.deliverEvent({ type: 'menu_action', label: 'New Document' });
    assert.equal(macPcb.state, PROCESS_STATES.READY, 'macOS deliverEvent must wake BLOCKED PCB');
    stack.kernel.scheduler.runUntilIdle(macPid, 200);
    assert.equal(macPcb.state, PROCESS_STATES.BLOCKED);

    // Item 19c: iOS step() propagates cpu.step FAULT cleanly
    const faultStack = await bootFullM4Stack('omnios-m4-ios-fault-ret-');
    const realCreateArm = createArm64Cpu;
    let triggerFaultReturn = false;
    faultStack.kernel.cpuRegistry.register('arm64', (opts) => {
      const inner = realCreateArm(opts);
      const origStep = inner.step.bind(inner);
      inner.step = (b) => {
        if (triggerFaultReturn) {
          return {
            status: 'FAULT',
            instructionsExecuted: 1,
            fault: new IllegalInstructionError('Injected FAULT status', { code: ERROR_CODES.E_ILLEGAL_INSTRUCTION }),
          };
        }
        return origStep(b);
      };
      return inner;
    });
    const iosDummy = buildIosIpa({ bundleId: 'com.omnios.ios.faultret', appName: 'FaultRet' });
    const iosInstalled = await faultStack.pkgManager.install(iosDummy.ipaBytes, { filename: 'FaultRet.ipa' });
    triggerFaultReturn = true;
    const { pid: fPid } = await faultStack.pkgManager.launch(iosInstalled.appId);
    faultStack.kernel.scheduler.runUntilIdle(fPid, 100);
    const fPcb = faultStack.kernel.processManager.get(fPid);
    assert.ok(fPcb.state === PROCESS_STATES.ZOMBIE || fPcb.state === PROCESS_STATES.TERMINATED);
    assert.equal(fPcb.stats.exitSignal, 'SIGILL');

    // Item 20a: macOS .pkg shared decrementing bomb budget across multiple aliased Payload entries
    function makeRawXarPkg(tocXml, heapBytes) {
      const tocRaw = TEXT_ENCODER.encode(tocXml);
      const tocComp = zlib.deflateSync(tocRaw);
      const header = new Uint8Array(28);
      const dv = new DataView(header.buffer);
      dv.setUint32(0, 0x78617221, false); // 'xar!'
      dv.setUint16(4, 28, false);
      dv.setUint16(6, 1, false);
      dv.setBigUint64(8, BigInt(tocComp.byteLength), false);
      dv.setBigUint64(16, BigInt(tocRaw.byteLength), false);
      dv.setUint32(24, 1, false);
      const out = new Uint8Array(28 + tocComp.byteLength + heapBytes.byteLength);
      out.set(header, 0);
      out.set(tocComp, 28);
      out.set(heapBytes, 28 + tocComp.byteLength);
      return out;
    }

    // Build a valid tiny CPIO (odc) containing an ~80 KiB non-zero file, gzipped once, aliased 4x in XAR TOC
    const fileData = new Uint8Array(80 * 1024);
    for (let i = 0; i < fileData.length; i++) fileData[i] = (i * 131 + 17) & 0xff;
    const fname = 'data.bin\0';
    const hdr1 = `07070700000000000110064400000000000000000100000000000000000${fname.length.toString(8).padStart(6, '0')}${fileData.byteLength.toString(8).padStart(11, '0')}`;
    const trailer = '0707070000000000000000000000000000000000010000000000000000000001300000000000TRAILER!!!\0';
    const cpioRaw = new Uint8Array(hdr1.length + fname.length + fileData.byteLength + trailer.length);
    let cp = 0;
    cpioRaw.set(TEXT_ENCODER.encode(hdr1), cp); cp += hdr1.length;
    cpioRaw.set(TEXT_ENCODER.encode(fname), cp); cp += fname.length;
    cpioRaw.set(fileData, cp); cp += fileData.byteLength;
    cpioRaw.set(TEXT_ENCODER.encode(trailer), cp);
    const gzPayload = zlib.gzipSync(cpioRaw);

    const aliasedToc = `<?xml version="1.0" encoding="UTF-8"?><xar><toc>${[1, 2, 3, 4]
      .map(
        (id) =>
          `<file id="${id}"><name>part${id}.pkg</name><type>directory</type><file id="${id * 10}"><name>Payload</name><type>file</type><data><offset>0</offset><length>${gzPayload.byteLength}</length><size>${gzPayload.byteLength}</size><encoding style="application/octet-stream"/></data></file></file>`
      )
      .join('')}</toc></xar>`;
    const aliasedPkg = makeRawXarPkg(aliasedToc, gzPayload);
    assert.throws(
      () => parseMacPkg(aliasedPkg, { maxOutputBytes: 180_000 }),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_ARCHIVE_BOMB,
      'Aliased multi-Payload .pkg must enforce shared decrementing bomb budget'
    );

    // Item 20b: Nested absolute XAR <name>/etc/passwd</name> MUST throw E_PATH_TRAVERSAL
    const nestedAbsToc = `<?xml version="1.0" encoding="UTF-8"?><xar><toc><file id="1"><name>dir</name><type>directory</type><file id="2"><name>/etc/passwd</name><type>file</type></file></file></toc></xar>`;
    const nestedAbsPkg = makeRawXarPkg(nestedAbsToc, new Uint8Array(0));
    assert.throws(
      () => parseMacPkg(nestedAbsPkg),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.E_PATH_TRAVERSAL,
      'Nested absolute XAR <name>/etc/passwd</name> must throw E_PATH_TRAVERSAL'
    );

    // Item 20c: parseMacPackage macos-macho branch sanitizes executableRelPath basename strictly
    const rawMacho = buildMachOArm64Mac({ appName: 'SafeBin' });
    for (const hostileHint of ['../../..', 'a/..', 'a/.', 'evil\\..\\pwn', 'foo\0bar']) {
      const parsed = parseMacPackage(rawMacho, hostileHint, { format: PACKAGE_FORMATS.MACOS_MACHO });
      assert.ok(
        parsed.executableRelPath.length > 0 &&
          parsed.executableRelPath !== '.' &&
          parsed.executableRelPath !== '..' &&
          !parsed.executableRelPath.includes('/') &&
          !parsed.executableRelPath.includes('\\') &&
          !parsed.executableRelPath.includes('\0'),
        `Hostile hint "${hostileHint}" yielded unsafe executableRelPath="${parsed.executableRelPath}"`
      );
    }
  });

  it('Item 21 (Iter 3): live ARM64 iOS & macOS App IMP _exit(9) propagation (zero post-exit callbacks/intents/windows/flushes) & WASI parent-dir preopen rejection', async () => {
    const stack = await bootFullM4Stack('omnios-m4-iter3-exit9-');
    const PAGE = 0x4000;
    const alignUp = (n, a) => Math.ceil(n / a) * a;
    const uleb = (v) => {
      let x = BigInt(v);
      const out = [];
      do {
        let b = Number(x & 0x7fn);
        x >>= 7n;
        if (x !== 0n) b |= 0x80;
        out.push(b);
      } while (x !== 0n);
      return out;
    };
    const writeFixed = (buf, off, str, max) => {
      const enc = TEXT_ENCODER.encode(str);
      buf.set(enc.subarray(0, Math.min(enc.length, max)), off);
    };

    /**
     * Synthesize a genuine ARM64 Mach-O 64 executable with real ObjC ABI2 class/method_list_t,
     * real __got dyld binds (including `__exit`, `_objc_msgSend`, `_UIApplicationMain`/`_NSApplicationMain`),
     * and real `Arm64Assembler` machine code in every delegate IMP.
     */
    function buildLiveExitArm64MachO({ platform, delegateClassName, buildImps }) {
      const cstrMap = new Map();
      const cstrChunks = [];
      let cstrLen = 0;
      const internCStr = (s) => {
        const k = String(s);
        if (cstrMap.has(k)) return cstrMap.get(k);
        const b = TEXT_ENCODER.encode(`${k}\0`);
        const rec = { offset: cstrLen, byteLength: b.length - 1 };
        cstrChunks.push(b);
        cstrLen += b.length;
        cstrMap.set(k, rec);
        return rec;
      };

      const methMap = new Map();
      const methChunks = [];
      let methLen = 0;
      const internMeth = (sel) => {
        const k = String(sel);
        if (methMap.has(k)) return methMap.get(k);
        const b = TEXT_ENCODER.encode(`${k}\0`);
        const off = methLen;
        methChunks.push(b);
        methLen += b.length;
        methMap.set(k, off);
        return off;
      };

      const gotList = [];
      const gotIdx = new Map();
      const internGot = (sym) => {
        if (gotIdx.has(sym)) return gotIdx.get(sym);
        const idx = gotList.length;
        gotList.push(sym);
        gotIdx.set(sym, idx);
        return idx;
      };

      const selList = [];
      const selIdx = new Map();
      const internSel = (sel) => {
        if (selIdx.has(sel)) return selIdx.get(sel);
        internMeth(sel);
        const idx = selList.length;
        selList.push(sel);
        selIdx.set(sel, idx);
        return idx;
      };

      const cfList = [];
      const cfIdx = new Map();
      const internCF = (s) => {
        const k = String(s);
        if (cfIdx.has(k)) return cfIdx.get(k);
        const cs = internCStr(k);
        const idx = cfList.length;
        cfList.push({ value: k, cstrOffset: cs.offset, byteLength: cs.byteLength });
        cfIdx.set(k, idx);
        return idx;
      };

      const asm = new Arm64Assembler();
      const loadClass = (clsName) => {
        const sym = `_OBJC_CLASS_$_${clsName}`;
        internGot(sym);
        return (r) => asm.loadPtr(r, { kind: 'got', key: sym });
      };
      const loadCF = (s) => {
        internCF(s);
        return (r) => asm.loadAddr(r, { kind: 'cfstring', key: String(s) });
      };
      const loadSel = (sel) => {
        internSel(sel);
        return (r) => asm.loadPtr(r, { kind: 'selref', key: sel });
      };
      const loadReg = (src) => (dst) => {
        if (dst !== src) asm.movReg(dst, src);
      };
      const loadImm = (v) => (r) => asm.movImm64(r, v);
      const emitMsg = (recvFn, sel, argFns = []) => {
        internGot('_objc_msgSend');
        internSel(sel);
        for (let i = 0; i < argFns.length; i++) argFns[i](2 + i);
        recvFn(0);
        asm.loadPtr(1, { kind: 'selref', key: sel });
        asm.callGot('_objc_msgSend');
      };
      const emitLibcExit = (code) => {
        internGot('__exit');
        asm.movz(0, code);
        asm.callGot('__exit');
        asm.ret();
      };
      const emitWriteDefault = (key, val) => {
        emitMsg(loadClass('NSUserDefaults'), 'standardUserDefaults');
        emitMsg(loadReg(0), 'setObject:forKey:', [loadCF(val), loadCF(key)]);
      };

      // Entry point `_main` -> `_UIApplicationMain` or `_NSApplicationMain`
      asm.label('_main');
      asm.stpPre64(29, 30, 31, -16);
      asm.movReg(29, 31);
      if (platform === 'ios') {
        internGot('_UIApplicationMain');
        internCF(delegateClassName);
        asm.movz(2, 0);
        asm.loadAddr(3, { kind: 'cfstring', key: delegateClassName });
        asm.callGot('_UIApplicationMain');
      } else {
        internGot('_NSApplicationMain');
        asm.callGot('_NSApplicationMain');
      }
      asm.ldpPost64(29, 30, 31, 16);
      asm.ret();

      const methods = buildImps(asm, {
        emitMsg,
        emitLibcExit,
        emitWriteDefault,
        loadClass,
        loadCF,
        loadSel,
        loadReg,
        loadImm,
        internGot,
        internSel,
        internCF,
      });

      const classNameCstr = internCStr(delegateClassName);
      const typeStr = internCStr('v24@0:8@16');
      for (const m of methods) internMeth(m.sel);
      if (selList.length === 0) internSel('init');
      if (cfList.length === 0) internCF(delegateClassName);

      // Load command layout
      const dylibName = '/usr/lib/libSystem.B.dylib';
      const dylibCmdSize = alignUp(24 + dylibName.length + 1, 8);
      const segTextSizeCmd = 72 + 3 * 80;
      const segDataSizeCmd = 72 + 6 * 80;
      const sizeofcmds = 72 + segTextSizeCmd + segDataSizeCmd + 72 + 48 + 24 + dylibCmdSize;
      const ncmds = 7;

      // __TEXT layout
      const textVm = 0x100000000;
      const codeOff = alignUp(32 + sizeofcmds, 16);
      const codeSize = Math.max(4, asm.byteLength);
      const cstrOff = alignUp(codeOff + codeSize, 8);
      const methOff = alignUp(cstrOff + Math.max(1, cstrLen), 8);
      const textSegSize = alignUp(methOff + Math.max(1, methLen), PAGE);

      // __DATA layout
      const dataFileOff = textSegSize;
      const dataVm = textVm + textSegSize;
      let dCur = 0;
      const gotRel = dCur;
      dCur = alignUp(dCur + gotList.length * 8, 8);
      const selRel = dCur;
      dCur = alignUp(dCur + selList.length * 8, 8);
      const clsListRel = dCur;
      dCur = alignUp(dCur + 8, 8);
      const objcConstRel = dCur;
      const mlRel = dCur;
      const mlSize = 8 + methods.length * 24;
      const clsRoRel = alignUp(mlRel + mlSize, 8);
      const metaRoRel = clsRoRel + 72;
      const objcConstSize = metaRoRel + 72 - objcConstRel;
      dCur = alignUp(objcConstRel + objcConstSize, 8);
      const objcDataRel = dCur;
      const clsRel = dCur;
      const metaRel = clsRel + 40;
      const objcDataSize = 80;
      dCur = alignUp(objcDataRel + objcDataSize, 8);
      const cfRel = dCur;
      const cfSize = cfList.length * 32;
      dCur = alignUp(cfRel + cfSize, 8);
      const dataSegSize = alignUp(Math.max(8, dCur), PAGE);

      const codeVA = textVm + codeOff;
      const cstrBaseVA = textVm + cstrOff;
      const methBaseVA = textVm + methOff;

      const codeBytes = asm.finalize(codeVA, (t) => {
        if (t.kind === 'got') return BigInt(dataVm + gotRel + gotIdx.get(t.key) * 8);
        if (t.kind === 'selref') return BigInt(dataVm + selRel + selIdx.get(t.key) * 8);
        if (t.kind === 'cfstring') return BigInt(dataVm + cfRel + cfIdx.get(t.key) * 32);
        throw new Error(`Unknown reloc target: ${JSON.stringify(t)}`);
      });

      const dataBuf = new Uint8Array(dataSegSize);
      const dataDv = new DataView(dataBuf.buffer);
      const rebaseOffs = [];
      const binds = [];

      for (let i = 0; i < gotList.length; i++) {
        binds.push({ off: gotRel + i * 8, sym: gotList[i] });
      }
      for (let i = 0; i < selList.length; i++) {
        dataDv.setBigUint64(selRel + i * 8, BigInt(methBaseVA + methMap.get(selList[i])), true);
        rebaseOffs.push(selRel + i * 8);
      }

      const clsVA = BigInt(dataVm + clsRel);
      const metaVA = BigInt(dataVm + metaRel);
      const clsRoVA = BigInt(dataVm + clsRoRel);
      const metaRoVA = BigInt(dataVm + metaRoRel);
      const mlVA = BigInt(dataVm + mlRel);
      const clsNameVA = BigInt(cstrBaseVA + classNameCstr.offset);
      const typesVA = BigInt(cstrBaseVA + typeStr.offset);

      dataDv.setBigUint64(clsListRel, clsVA, true);
      rebaseOffs.push(clsListRel);

      dataDv.setUint32(mlRel, 24, true);
      dataDv.setUint32(mlRel + 4, methods.length, true);
      for (let i = 0; i < methods.length; i++) {
        const m = methods[i];
        const mOff = mlRel + 8 + i * 24;
        const impOff = asm._labels.get(m.label);
        if (impOff === undefined) throw new Error(`Missing IMP label: ${m.label}`);
        dataDv.setBigUint64(mOff, BigInt(methBaseVA + methMap.get(m.sel)), true);
        dataDv.setBigUint64(mOff + 8, typesVA, true);
        dataDv.setBigUint64(mOff + 16, BigInt(codeVA + impOff), true);
        rebaseOffs.push(mOff, mOff + 8, mOff + 16);
      }

      dataDv.setUint32(clsRoRel + 4, 8, true);
      dataDv.setUint32(clsRoRel + 8, 32, true);
      dataDv.setBigUint64(clsRoRel + 24, clsNameVA, true);
      dataDv.setBigUint64(clsRoRel + 32, mlVA, true);
      rebaseOffs.push(clsRoRel + 24, clsRoRel + 32);

      dataDv.setUint32(metaRoRel, 1, true);
      dataDv.setUint32(metaRoRel + 4, 40, true);
      dataDv.setUint32(metaRoRel + 8, 40, true);
      dataDv.setBigUint64(metaRoRel + 24, clsNameVA, true);
      rebaseOffs.push(metaRoRel + 24);

      dataDv.setBigUint64(clsRel, metaVA, true);
      binds.push({ off: clsRel + 8, sym: '_OBJC_CLASS_$_NSObject' });
      dataDv.setBigUint64(clsRel + 32, clsRoVA, true);
      rebaseOffs.push(clsRel, clsRel + 32);

      binds.push({ off: metaRel, sym: '_OBJC_METACLASS_$_NSObject' });
      binds.push({ off: metaRel + 8, sym: '_OBJC_METACLASS_$_NSObject' });
      dataDv.setBigUint64(metaRel + 32, metaRoVA, true);
      rebaseOffs.push(metaRel + 32);

      for (let i = 0; i < cfList.length; i++) {
        const cf = cfList[i];
        const o = cfRel + i * 32;
        binds.push({ off: o, sym: '___CFConstantStringClassReference' });
        dataDv.setBigUint64(o + 8, 0x7c8n, true);
        dataDv.setBigUint64(o + 16, BigInt(cstrBaseVA + cf.cstrOffset), true);
        dataDv.setBigUint64(o + 24, BigInt(cf.byteLength), true);
        rebaseOffs.push(o + 16);
      }

      const rebOps = [MACHO_CONSTANTS.REBASE_OPCODE_SET_TYPE_IMM | 1];
      for (const o of rebaseOffs) {
        rebOps.push(
          MACHO_CONSTANTS.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2,
          ...uleb(o),
          MACHO_CONSTANTS.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1
        );
      }
      rebOps.push(MACHO_CONSTANTS.REBASE_OPCODE_DONE);
      const rebBuf = Uint8Array.from(rebOps);

      const bindOps = [MACHO_CONSTANTS.BIND_OPCODE_SET_TYPE_IMM | 1];
      for (const b of binds) {
        bindOps.push(
          MACHO_CONSTANTS.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
          MACHO_CONSTANTS.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
          ...TEXT_ENCODER.encode(b.sym),
          0,
          MACHO_CONSTANTS.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2,
          ...uleb(b.off),
          MACHO_CONSTANTS.BIND_OPCODE_DO_BIND
        );
      }
      bindOps.push(MACHO_CONSTANTS.BIND_OPCODE_DONE);
      const bindBuf = Uint8Array.from(bindOps);

      const leFileOff = dataFileOff + dataSegSize;
      const leVm = dataVm + dataSegSize;
      const bindRel = alignUp(rebBuf.length, 8);
      const leFileSize = alignUp(bindRel + bindBuf.length, 16);
      const leVmSize = alignUp(leFileSize, PAGE);

      const out = new Uint8Array(leFileOff + leFileSize);
      const dv = new DataView(out.buffer);
      dv.setUint32(0, MACHO_CONSTANTS.MH_MAGIC_64, true);
      dv.setUint32(4, MACHO_CONSTANTS.CPU_TYPE_ARM64, true);
      dv.setUint32(8, 0, true);
      dv.setUint32(12, MACHO_CONSTANTS.MH_EXECUTE, true);
      dv.setUint32(16, ncmds, true);
      dv.setUint32(20, sizeofcmds, true);
      dv.setUint32(24, 0x00200085, true);

      let p = 32;
      const writeSeg = (name, vm, vsz, foff, fsz, maxp, initp, sects) => {
        const csz = 72 + sects.length * 80;
        dv.setUint32(p, MACHO_CONSTANTS.LC_SEGMENT_64, true);
        dv.setUint32(p + 4, csz, true);
        writeFixed(out, p + 8, name, 16);
        dv.setBigUint64(p + 24, BigInt(vm), true);
        dv.setBigUint64(p + 32, BigInt(vsz), true);
        dv.setBigUint64(p + 40, BigInt(foff), true);
        dv.setBigUint64(p + 48, BigInt(fsz), true);
        dv.setUint32(p + 56, maxp, true);
        dv.setUint32(p + 60, initp, true);
        dv.setUint32(p + 64, sects.length, true);
        let sp = p + 72;
        for (const s of sects) {
          writeFixed(out, sp, s.sect, 16);
          writeFixed(out, sp + 16, name, 16);
          dv.setBigUint64(sp + 32, BigInt(s.addr), true);
          dv.setBigUint64(sp + 40, BigInt(s.size), true);
          dv.setUint32(sp + 48, s.off, true);
          dv.setUint32(sp + 52, s.align ?? 3, true);
          dv.setUint32(sp + 64, s.flags ?? 0, true);
          sp += 80;
        }
        p += csz;
      };

      writeSeg('__PAGEZERO', 0, 0x100000000, 0, 0, 0, 0, []);
      writeSeg('__TEXT', textVm, textSegSize, 0, textSegSize, 5, 5, [
        { sect: '__text', addr: codeVA, size: codeSize, off: codeOff, align: 2, flags: 0x80000400 },
        { sect: '__cstring', addr: cstrBaseVA, size: Math.max(1, cstrLen), off: cstrOff, align: 0, flags: MACHO_CONSTANTS.S_CSTRING_LITERALS },
        { sect: '__objc_methname', addr: methBaseVA, size: Math.max(1, methLen), off: methOff, align: 0, flags: MACHO_CONSTANTS.S_CSTRING_LITERALS },
      ]);
      writeSeg('__DATA', dataVm, dataSegSize, dataFileOff, dataSegSize, 3, 3, [
        { sect: '__got', addr: dataVm + gotRel, size: gotList.length * 8, off: dataFileOff + gotRel, flags: MACHO_CONSTANTS.S_NON_LAZY_SYMBOL_POINTERS },
        { sect: '__objc_selrefs', addr: dataVm + selRel, size: selList.length * 8, off: dataFileOff + selRel, flags: 0x10000005 },
        { sect: '__objc_classlist', addr: dataVm + clsListRel, size: 8, off: dataFileOff + clsListRel },
        { sect: '__objc_const', addr: dataVm + objcConstRel, size: objcConstSize, off: dataFileOff + objcConstRel },
        { sect: '__objc_data', addr: dataVm + objcDataRel, size: objcDataSize, off: dataFileOff + objcDataRel },
        { sect: '__cfstring', addr: dataVm + cfRel, size: cfSize, off: dataFileOff + cfRel },
      ]);
      writeSeg('__LINKEDIT', leVm, leVmSize, leFileOff, leFileSize, 1, 1, []);

      // LC_DYLD_INFO_ONLY
      dv.setUint32(p, MACHO_CONSTANTS.LC_DYLD_INFO_ONLY, true);
      dv.setUint32(p + 4, 48, true);
      dv.setUint32(p + 8, leFileOff, true);
      dv.setUint32(p + 12, rebBuf.length, true);
      dv.setUint32(p + 16, leFileOff + bindRel, true);
      dv.setUint32(p + 20, bindBuf.length, true);
      p += 48;

      // LC_MAIN
      dv.setUint32(p, MACHO_CONSTANTS.LC_MAIN, true);
      dv.setUint32(p + 4, 24, true);
      dv.setBigUint64(p + 8, BigInt(codeOff + asm._labels.get('_main')), true);
      p += 24;

      // LC_LOAD_DYLIB
      dv.setUint32(p, MACHO_CONSTANTS.LC_LOAD_DYLIB, true);
      dv.setUint32(p + 4, dylibCmdSize, true);
      dv.setUint32(p + 8, 24, true);
      dv.setUint32(p + 16, 0x00010000, true);
      dv.setUint32(p + 20, 0x00010000, true);
      out.set(TEXT_ENCODER.encode(`${dylibName}\0`), p + 24);

      out.set(codeBytes, codeOff);
      let cp = cstrOff;
      for (const ch of cstrChunks) { out.set(ch, cp); cp += ch.length; }
      let mp = methOff;
      for (const ch of methChunks) { out.set(ch, mp); mp += ch.length; }
      out.set(dataBuf, dataFileOff);
      out.set(rebBuf, leFileOff);
      out.set(bindBuf, leFileOff + bindRel);
      return out;
    }

    function wrapIosIpa({ bundleId, appName, urlSchemes = [], machoBytes }) {
      const exec = appName.replace(/[^A-Za-z0-9_-]/g, '');
      const plist = {
        CFBundleIdentifier: bundleId,
        CFBundleDisplayName: appName,
        CFBundleName: exec,
        CFBundleExecutable: exec,
        CFBundlePackageType: 'APPL',
        CFBundleShortVersionString: '1.0.0',
        CFBundleVersion: '1',
        LSRequiresIPhoneOS: true,
        MinimumOSVersion: '17.0',
      };
      if (urlSchemes.length > 0) {
        plist.CFBundleURLTypes = [{ CFBundleTypeRole: 'Viewer', CFBundleURLName: bundleId, CFBundleURLSchemes: urlSchemes }];
      }
      return createZip([
        { name: `Payload/${exec}.app/Info.plist`, data: writeBinaryPlist(plist) },
        { name: `Payload/${exec}.app/${exec}`, data: machoBytes },
      ]);
    }

    function wrapMacAppZip({ bundleId, appName, urlSchemes = [], machoBytes }) {
      const exec = appName.replace(/[^A-Za-z0-9_-]/g, '');
      const plist = {
        CFBundleIdentifier: bundleId,
        CFBundleDisplayName: appName,
        CFBundleName: exec,
        CFBundleExecutable: exec,
        CFBundlePackageType: 'APPL',
        CFBundleShortVersionString: '1.0.0',
        CFBundleVersion: '1',
      };
      if (urlSchemes.length > 0) {
        plist.CFBundleURLTypes = [{ CFBundleTypeRole: 'Viewer', CFBundleURLName: bundleId, CFBundleURLSchemes: urlSchemes }];
      }
      return createZip([
        { name: `${exec}.app/Contents/Info.plist`, data: TEXT_ENCODER.encode(writeXmlPlist(plist)) },
        { name: `${exec}.app/Contents/MacOS/${exec}`, data: machoBytes },
      ]);
    }

    // -----------------------------------------------------------------------
    // (a) Live ARM64 iOS event IMPs calling libc _exit(9): click, intent,
    //     lifecycle (applicationWillResignActive -> no didEnterBackground),
    //     window_close & terminate (applicationWillTerminate -> exitCode 9)
    // -----------------------------------------------------------------------
    const iosEventBundleId = 'com.omnios.ios.exit9-events';
    const iosEventMachO = buildLiveExitArm64MachO({
      platform: 'ios',
      delegateClassName: 'Exit9IosEventDelegate',
      buildImps(asm, c) {
        // Launch builds a UIWindow + UIViewController + UIButton(id="quit_btn", action=onQuitTap:)
        asm.label('imp_launch');
        asm.stpPre64(29, 30, 31, -48);
        asm.movReg(29, 31);
        asm.stpSigned64(19, 20, 31, 16);
        asm.stpSigned64(21, 22, 31, 32);
        asm.movReg(19, 0); // self

        c.emitMsg(c.loadClass('UIWindow'), 'alloc');
        c.emitMsg(c.loadReg(0), 'initWithFrame:');
        asm.movReg(20, 0);

        c.emitMsg(c.loadClass('UIViewController'), 'alloc');
        c.emitMsg(c.loadReg(0), 'init');
        asm.movReg(21, 0);
        c.emitMsg(c.loadReg(21), 'view');
        asm.movReg(22, 0);

        c.emitMsg(c.loadClass('UIButton'), 'buttonWithType:', [c.loadImm(1)]);
        asm.movReg(23, 0);
        c.emitMsg(c.loadReg(23), 'setTitle:forState:', [c.loadCF('Quit 9'), c.loadImm(0)]);
        c.emitMsg(c.loadReg(23), 'setAccessibilityIdentifier:', [c.loadCF('quit_btn')]);
        c.emitMsg(c.loadReg(23), 'addTarget:action:forControlEvents:', [
          c.loadReg(19),
          c.loadSel('onQuitTap:'),
          c.loadImm(0x40),
        ]);
        c.emitMsg(c.loadReg(22), 'addSubview:', [c.loadReg(23)]);
        c.emitMsg(c.loadReg(20), 'setRootViewController:', [c.loadReg(21)]);
        c.emitMsg(c.loadReg(20), 'makeKeyAndVisible');

        asm.movz(0, 1);
        asm.ldpSigned64(21, 22, 31, 32);
        asm.ldpSigned64(19, 20, 31, 16);
        asm.ldpPost64(29, 30, 31, 48);
        asm.ret();

        // Click IMP -> libc _exit(9)
        asm.label('imp_quit_tap');
        c.emitLibcExit(9);

        // URL-scheme intent IMP -> libc _exit(9)
        asm.label('imp_open_url');
        c.emitLibcExit(9);

        // applicationWillResignActive: -> libc _exit(9)
        asm.label('imp_resign_active');
        c.emitLibcExit(9);

        // applicationDidEnterBackground: -> MUST NOT RUN after applicationWillResignActive: calls _exit(9)!
        asm.label('imp_did_bg');
        asm.stpPre64(29, 30, 31, -16);
        asm.movReg(29, 31);
        c.emitWriteDefault('leaked_bg', 'POST_EXIT_BG_RAN');
        asm.movz(0, 0);
        asm.ldpPost64(29, 30, 31, 16);
        asm.ret();

        // applicationWillTerminate: -> libc _exit(9)
        asm.label('imp_will_term');
        c.emitLibcExit(9);

        return [
          { sel: 'application:didFinishLaunchingWithOptions:', label: 'imp_launch' },
          { sel: 'onQuitTap:', label: 'imp_quit_tap' },
          { sel: 'application:openURL:options:', label: 'imp_open_url' },
          { sel: 'applicationWillResignActive:', label: 'imp_resign_active' },
          { sel: 'applicationDidEnterBackground:', label: 'imp_did_bg' },
          { sel: 'applicationWillTerminate:', label: 'imp_will_term' },
        ];
      },
    });
    const iosEventIpa = wrapIosIpa({
      bundleId: iosEventBundleId,
      appName: 'IosExit9Events',
      urlSchemes: ['exitios'],
      machoBytes: iosEventMachO,
    });
    const iosEventApp = await stack.pkgManager.install(iosEventIpa, { filename: 'IosExit9Events.ipa' });

    const runIosEventExit9Scenario = async (label, triggerFn) => {
      const { pid } = await stack.pkgManager.launch(iosEventApp.appId);
      stack.kernel.scheduler.runUntilIdle(pid, 200);
      const pcb = stack.kernel.processManager.get(pid);
      assert.equal(pcb.state, PROCESS_STATES.BLOCKED, `${label}: must reach BLOCKED`);
      const win = stack.compositor.listWindows({ pid })[0];
      assert.ok(win, `${label}: window must exist`);

      let surfaceFlushesAfterTrigger = 0;
      const unsub = stack.kernel.eventBus.on('compositor:surface_updated', (ev) => {
        if (ev?.windowId === win.windowId) surfaceFlushesAfterTrigger++;
      });
      try {
        triggerFn(pcb, win);
        stack.kernel.scheduler.runUntilIdle(pid, 200);
      } finally {
        unsub();
      }
      assert.equal(pcb.state, PROCESS_STATES.ZOMBIE, `${label}: must exit to ZOMBIE`);
      assert.equal(pcb.stats.exitCode, 9, `${label}: pcb.stats.exitCode must be 9 (got ${pcb.stats.exitCode})`);
      assert.equal(pcb.stats.exitSignal, null, `${label}: clean _exit(9) must not set exitSignal`);
      assert.equal(pcb.executionContext.uikitBridge.shouldExit, true, `${label}: uikitBridge.shouldExit must be true`);
      assert.equal(pcb.executionContext.uikitBridge.exitCode, 9, `${label}: uikitBridge.exitCode must be 9`);
      assert.equal(surfaceFlushesAfterTrigger, 0, `${label}: zero post-exit flushToCompositor calls allowed`);
    };

    await runIosEventExit9Scenario('iOS click IMP _exit(9)', (_pcb, win) => {
      stack.compositor.dispatchInput(win.windowId, { type: 'click', nodeId: 'quit_btn' });
    });
    await runIosEventExit9Scenario('iOS intent IMP _exit(9)', (pcb) => {
      pcb.executionContext.deliverEvent({ type: 'intent', uri: 'exitios://quit-now' });
    });
    await runIosEventExit9Scenario('iOS lifecycle willResignActive _exit(9)', (pcb) => {
      pcb.executionContext.deliverEvent({ type: 'lifecycle', state: 'background' });
    });
    assert.equal(
      stack.configStore.defaults.get(iosEventBundleId, 'leaked_bg'),
      null,
      'iOS applicationDidEnterBackground: MUST NOT run after applicationWillResignActive: called _exit(9)'
    );
    await runIosEventExit9Scenario('iOS window_close applicationWillTerminate _exit(9)', (pcb) => {
      pcb.executionContext.deliverEvent({ type: 'window_close' });
    });
    await runIosEventExit9Scenario('iOS lifecycle:terminate applicationWillTerminate _exit(9)', (pcb) => {
      pcb.executionContext.deliverEvent({ type: 'lifecycle', state: 'terminate' });
    });

    // -----------------------------------------------------------------------
    // (b) Live ARM64 iOS launch IMP (`application:didFinishLaunchingWithOptions:`)
    //     calling `_exit(9)` -> exitCode === 9, zero post-exit URL delivery / stray windows
    // -----------------------------------------------------------------------
    const iosLaunchBundleId = 'com.omnios.ios.exit9-launch';
    const iosLaunchMachO = buildLiveExitArm64MachO({
      platform: 'ios',
      delegateClassName: 'Exit9IosLaunchDelegate',
      buildImps(asm, c) {
        asm.label('imp_launch_exit9');
        c.emitLibcExit(9);

        asm.label('imp_became_active');
        asm.stpPre64(29, 30, 31, -16);
        asm.movReg(29, 31);
        c.emitWriteDefault('leaked_active', 'BAD_ACTIVE');
        asm.movz(0, 0);
        asm.ldpPost64(29, 30, 31, 16);
        asm.ret();

        asm.label('imp_open_url');
        asm.stpPre64(29, 30, 31, -16);
        asm.movReg(29, 31);
        c.emitWriteDefault('leaked_launch_url', 'BAD_URL');
        asm.movz(0, 1);
        asm.ldpPost64(29, 30, 31, 16);
        asm.ret();

        return [
          { sel: 'application:didFinishLaunchingWithOptions:', label: 'imp_launch_exit9' },
          { sel: 'applicationDidBecomeActive:', label: 'imp_became_active' },
          { sel: 'application:openURL:options:', label: 'imp_open_url' },
        ];
      },
    });
    const iosLaunchApp = await stack.pkgManager.install(
      wrapIosIpa({ bundleId: iosLaunchBundleId, appName: 'IosExit9Launch', urlSchemes: ['ioslaunch'], machoBytes: iosLaunchMachO }),
      { filename: 'IosExit9Launch.ipa' }
    );
    const { pid: iosLaunchPid } = await stack.pkgManager.launch(iosLaunchApp.appId, {
      intent: { action: 'view', uri: 'ioslaunch://must-not-deliver' },
    });
    stack.kernel.scheduler.runUntilIdle(iosLaunchPid, 200);
    const iosLaunchPcb = stack.kernel.processManager.get(iosLaunchPid);
    assert.equal(iosLaunchPcb.state, PROCESS_STATES.ZOMBIE);
    assert.equal(iosLaunchPcb.stats.exitCode, 9, 'iOS launch IMP _exit(9) must propagate exitCode === 9');
    assert.equal(stack.compositor.listWindows({ pid: iosLaunchPid }).length, 0, 'Zero stray iOS windows allowed after launch _exit(9)');
    assert.equal(stack.configStore.defaults.get(iosLaunchBundleId, 'leaked_active'), null);
    assert.equal(stack.configStore.defaults.get(iosLaunchBundleId, 'leaked_launch_url'), null);
    assert.equal(iosLaunchPcb.executionContext.uikitBridge.openedUrls.length, 0);
    assert.equal(iosLaunchPcb.executionContext.uikitBridge.runLoopActive, false);

    // -----------------------------------------------------------------------
    // (c1) Live ARM64 macOS `applicationWillFinishLaunching:` calling `_exit(9)`
    //      while `applicationDidFinishLaunching:` would write defaults AND `_exit(0)`
    // -----------------------------------------------------------------------
    const macWillBundleId = 'com.omnios.macos.exit9-will-launch';
    const macWillMachO = buildLiveExitArm64MachO({
      platform: 'macos',
      delegateClassName: 'Exit9MacWillDelegate',
      buildImps(asm, c) {
        asm.label('imp_will_launch');
        c.emitLibcExit(9);

        asm.label('imp_did_launch_clobber');
        asm.stpPre64(29, 30, 31, -16);
        asm.movReg(29, 31);
        c.emitWriteDefault('leaked_did_launch', 'SHOULD_NEVER_WRITE');
        c.emitLibcExit(0);

        asm.label('imp_open_urls');
        asm.stpPre64(29, 30, 31, -16);
        asm.movReg(29, 31);
        c.emitWriteDefault('leaked_will_intent', 'SHOULD_NEVER_DELIVER');
        asm.movz(0, 0);
        asm.ldpPost64(29, 30, 31, 16);
        asm.ret();

        return [
          { sel: 'applicationWillFinishLaunching:', label: 'imp_will_launch' },
          { sel: 'applicationDidFinishLaunching:', label: 'imp_did_launch_clobber' },
          { sel: 'application:openURLs:', label: 'imp_open_urls' },
        ];
      },
    });
    const macWillApp = await stack.pkgManager.install(
      wrapMacAppZip({ bundleId: macWillBundleId, appName: 'MacExit9Will', urlSchemes: ['macwill'], machoBytes: macWillMachO }),
      { filename: 'MacExit9Will.app.zip' }
    );
    let macWillWindowsCreated = 0;
    const unsubMacWill = stack.kernel.eventBus.on('compositor:window_created', (ev) => {
      if (ev?.appId === macWillBundleId) macWillWindowsCreated++;
    });
    const { pid: macWillPid } = await stack.pkgManager.launch(macWillApp.appId, {
      intent: { action: 'view', uri: 'macwill://no-delivery' },
    });
    try {
      stack.kernel.scheduler.runUntilIdle(macWillPid, 200);
    } finally {
      unsubMacWill();
    }
    const macWillPcb = stack.kernel.processManager.get(macWillPid);
    assert.equal(macWillPcb.state, PROCESS_STATES.ZOMBIE);
    assert.equal(macWillPcb.stats.exitCode, 9, 'macOS applicationWillFinishLaunching: _exit(9) must NOT be clobbered by didFinishLaunching');
    assert.equal(stack.configStore.defaults.get(macWillBundleId, 'leaked_did_launch'), null, 'applicationDidFinishLaunching: MUST NOT run after applicationWillFinishLaunching: _exit(9)');
    assert.equal(stack.configStore.defaults.get(macWillBundleId, 'leaked_will_intent'), null, 'launchIntent MUST NOT be delivered after _exit(9)');
    assert.equal(macWillWindowsCreated, 0, 'Zero spurious macOS windows may be created after applicationWillFinishLaunching: _exit(9)');
    assert.equal(macWillPcb.executionContext.appKitBridge.awaitingEvents, false);
    assert.equal(macWillPcb.executionContext.appKitBridge.exitCode, 9);

    // -----------------------------------------------------------------------
    // (c2) Live ARM64 macOS `applicationDidFinishLaunching:` calling `_exit(9)`
    //      -> zero launchIntent delivered, 0 spurious windows, awaitingEvents === false, exitCode === 9
    // -----------------------------------------------------------------------
    const macDidBundleId = 'com.omnios.macos.exit9-did-launch';
    const macDidMachO = buildLiveExitArm64MachO({
      platform: 'macos',
      delegateClassName: 'Exit9MacDidDelegate',
      buildImps(asm, c) {
        asm.label('imp_did_launch_exit9');
        c.emitLibcExit(9);

        asm.label('imp_open_urls');
        asm.stpPre64(29, 30, 31, -16);
        asm.movReg(29, 31);
        c.emitWriteDefault('leaked_did_intent', 'SHOULD_NEVER_DELIVER');
        asm.movz(0, 0);
        asm.ldpPost64(29, 30, 31, 16);
        asm.ret();

        return [
          { sel: 'applicationDidFinishLaunching:', label: 'imp_did_launch_exit9' },
          { sel: 'application:openURLs:', label: 'imp_open_urls' },
        ];
      },
    });
    const macDidApp = await stack.pkgManager.install(
      wrapMacAppZip({ bundleId: macDidBundleId, appName: 'MacExit9Did', urlSchemes: ['macdid'], machoBytes: macDidMachO }),
      { filename: 'MacExit9Did.app.zip' }
    );
    let macDidWindowsCreated = 0;
    const unsubMacDid = stack.kernel.eventBus.on('compositor:window_created', (ev) => {
      if (ev?.appId === macDidBundleId) macDidWindowsCreated++;
    });
    const { pid: macDidPid } = await stack.pkgManager.launch(macDidApp.appId, {
      intent: { action: 'view', uri: 'macdid://must-not-deliver' },
    });
    try {
      stack.kernel.scheduler.runUntilIdle(macDidPid, 200);
    } finally {
      unsubMacDid();
    }
    const macDidPcb = stack.kernel.processManager.get(macDidPid);
    assert.equal(macDidPcb.state, PROCESS_STATES.ZOMBIE);
    assert.equal(macDidPcb.stats.exitCode, 9, 'macOS applicationDidFinishLaunching: _exit(9) must propagate exitCode === 9');
    assert.equal(macDidWindowsCreated, 0, 'Zero spurious default NSWindow may be created after applicationDidFinishLaunching: _exit(9)');
    assert.equal(stack.compositor.listWindows({ pid: macDidPid }).length, 0);
    assert.equal(stack.configStore.defaults.get(macDidBundleId, 'leaked_did_intent'), null, 'launchIntent MUST NOT be delivered after applicationDidFinishLaunching: _exit(9)');
    assert.equal(macDidPcb.executionContext.appKitBridge.awaitingEvents, false);
    assert.equal(macDidPcb.executionContext.appKitBridge.exitCode, 9);

    // -----------------------------------------------------------------------
    // (c3) Live ARM64 macOS event IMPs calling `_exit(9)`: menu_action & window_close (`applicationWillTerminate:`)
    // -----------------------------------------------------------------------
    const macEvtBundleId = 'com.omnios.macos.exit9-events';
    const macEvtMachO = buildLiveExitArm64MachO({
      platform: 'macos',
      delegateClassName: 'Exit9MacEventDelegate',
      buildImps(asm, c) {
        asm.label('imp_did_launch');
        asm.stpPre64(29, 30, 31, -32);
        asm.movReg(29, 31);
        asm.stpSigned64(19, 20, 31, 16);
        asm.movReg(19, 0); // self

        c.emitMsg(c.loadClass('NSWindow'), 'alloc');
        c.emitMsg(c.loadReg(0), 'init');
        asm.movReg(20, 0);
        c.emitMsg(c.loadReg(20), 'setTitle:', [c.loadCF('MacExit9 Events')]);
        c.emitMsg(c.loadReg(20), 'makeKeyAndOrderFront:', [c.loadReg(19)]);

        asm.movz(0, 0);
        asm.ldpSigned64(19, 20, 31, 16);
        asm.ldpPost64(29, 30, 31, 32);
        asm.ret();

        asm.label('imp_menu_exit9');
        c.emitLibcExit(9);

        asm.label('imp_will_term_exit9');
        c.emitLibcExit(9);

        return [
          { sel: 'applicationDidFinishLaunching:', label: 'imp_did_launch' },
          { sel: 'onQuitMenu:', label: 'imp_menu_exit9' },
          { sel: 'applicationWillTerminate:', label: 'imp_will_term_exit9' },
        ];
      },
    });
    const macEvtApp = await stack.pkgManager.install(
      wrapMacAppZip({ bundleId: macEvtBundleId, appName: 'MacExit9Events', machoBytes: macEvtMachO }),
      { filename: 'MacExit9Events.app.zip' }
    );

    const runMacEventExit9Scenario = async (label, triggerFn) => {
      const { pid } = await stack.pkgManager.launch(macEvtApp.appId);
      stack.kernel.scheduler.runUntilIdle(pid, 200);
      const pcb = stack.kernel.processManager.get(pid);
      assert.equal(pcb.state, PROCESS_STATES.BLOCKED, `${label}: must reach BLOCKED`);
      const win = stack.compositor.listWindows({ pid })[0];
      assert.ok(win, `${label}: window must exist`);

      let surfaceFlushesAfterTrigger = 0;
      const unsub = stack.kernel.eventBus.on('compositor:surface_updated', (ev) => {
        if (ev?.windowId === win.windowId) surfaceFlushesAfterTrigger++;
      });
      try {
        triggerFn(pcb, win);
        stack.kernel.scheduler.runUntilIdle(pid, 200);
      } finally {
        unsub();
      }
      assert.equal(pcb.state, PROCESS_STATES.ZOMBIE, `${label}: must exit to ZOMBIE`);
      assert.equal(pcb.stats.exitCode, 9, `${label}: pcb.stats.exitCode must be 9 (got ${pcb.stats.exitCode})`);
      assert.equal(pcb.executionContext.appKitBridge.exitCode, 9, `${label}: appKitBridge.exitCode must be 9`);
      assert.equal(surfaceFlushesAfterTrigger, 0, `${label}: zero post-exit _flushWindowSurface calls allowed`);
    };

    await runMacEventExit9Scenario('macOS menu_action IMP _exit(9)', (_pcb, win) => {
      stack.compositor.dispatchInput(win.windowId, { type: 'menu_action', action: 'onQuitMenu:' });
    });
    await runMacEventExit9Scenario('macOS window_close applicationWillTerminate: _exit(9)', (pcb, win) => {
      pcb.executionContext.deliverEvent({ type: 'window_close', windowId: win.windowId });
    });

    // -----------------------------------------------------------------------
    // (d) WASI `manifest.preopens` rejects '/', '/home', '/var' even under `fs.read.system: 'allow'`
    //     so world-readable `/home/user/Documents/*` files cannot be read without `fs.read.user`!
    // -----------------------------------------------------------------------
    const wasiAppId = 'com.omnios.universal.sys-parent-reject';
    const wasiDataDir = `/var/appdata/universal/${wasiAppId}`;
    const wasiId = stack.users.allocateAppUid(wasiAppId, {
      platform: 'universal',
      sandboxRoot: wasiDataDir,
    });
    stack.vfs.mkdir(wasiDataDir, { recursive: true, uid: 0, gid: 0 });
    stack.vfs.chown(wasiDataDir, wasiId.uid, wasiId.gid, { uid: 0, gid: 0 });
    stack.vfs.mkdir('/etc', { recursive: true, uid: 0, gid: 0 });
    stack.vfs.writeFile('/etc/public.conf', 'ETC-OK', { uid: 0, gid: 0, mode: 0o644 });
    stack.vfs.writeFile('/home/user/Documents/world-readable-user-doc.txt', 'USER-DOC-SECRET-WITHOUT-GRANT', {
      uid: 1000,
      gid: 1000,
      mode: 0o644,
    });

    // Grant ONLY fs.read.system (explicitly NO fs.read.user!)
    stack.permissions.setGrant(wasiAppId, 'fs.read.system', 'allow');
    const parentRejectMem = new WebAssembly.Memory({ initial: 1, maximum: 2 });
    const parentRejectBridge = createWasiBridge({
      services: { vfs: stack.vfs, permissions: stack.permissions },
      appRecord: {
        appId: wasiAppId,
        dataDir: wasiDataDir,
        uid: wasiId.uid,
        gid: wasiId.gid,
        metadata: {
          manifest: {
            preopens: [
              { virtualName: 'root-slash', hostPath: '/' },
              { virtualName: 'root-multi', hostPath: '///' },
              { virtualName: 'home-dir', hostPath: '/home' },
              { virtualName: 'home-slash', hostPath: '/home/' },
              { virtualName: 'var-dir', hostPath: '/var' },
              { virtualName: 'var-slash', hostPath: '/var/' },
              { virtualName: 'etc-ok', hostPath: '/etc', writable: false },
            ],
          },
        },
      },
      memory: parentRejectMem,
    });
    const prWasi = parentRejectBridge.getImportObject().wasi_snapshot_preview1;
    assert.equal(prWasi.fd_prestat_get(4, 0), WASI_ERRNO.WASI_ESUCCESS, 'Only /etc may mount at FD 4');
    assert.equal(prWasi.fd_prestat_get(5, 0), WASI_ERRNO.WASI_EBADF, 'Parent dirs /, /home, /var MUST be rejected even with fs.read.system');
    const preNameLen = new DataView(parentRejectMem.buffer).getUint32(4, true);
    assert.equal(prWasi.fd_prestat_dir_name(4, 64, preNameLen), WASI_ERRNO.WASI_ESUCCESS);
    assert.equal(TEXT_DECODER.decode(new Uint8Array(parentRejectMem.buffer, 64, preNameLen)), 'etc-ok');

    // Confirm /home/user/Documents/world-readable-user-doc.txt cannot be reached via FD 4 (/etc)
    const escPath = TEXT_ENCODER.encode('../home/user/Documents/world-readable-user-doc.txt');
    new Uint8Array(parentRejectMem.buffer).set(escPath, 256);
    assert.equal(
      prWasi.path_open(4, 0, 256, escPath.byteLength, 0, WASI_CONSTANTS.RIGHTS.FD_READ, 0n, 0, 512),
      WASI_ERRNO.WASI_ENOTCAPABLE,
      'Traversal from /etc to /home/user/Documents must return WASI_ENOTCAPABLE'
    );
    parentRejectBridge.dispose();
  });
});



