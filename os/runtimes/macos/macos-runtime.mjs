/**
 * OmniOS macOS Platform Runtime (`F-054`, `F-055`)
 * Implements Contract 5 `IPlatformRuntime` (`platform = 'macos'`).
 * Zero external dependencies, zero `node:fs` imports.
 *
 * Capabilities:
 *  - Inspects & installs all 4 macOS package formats: `.app.zip`, raw Mach-O/Fat, `.dmg`, `.pkg`.
 *  - Indexes Apple Spotlight metadata (`rawMetadata.spotlight`, VFS xattrs, `spotlight:indexed` event).
 *  - Universal Fat architecture slice selection via `services.cpuRegistry` (`arm64` default,
 *    automatic `x86_64` fallback or explicit `launchOptions.arch`).
 *  - Full real CPU execution (ARM64 + x86-64) through Mach-O loader (`__PAGEZERO` guard, fixups,
 *    ObjC ABI2), `DarwinSyscallLayer` (synchronous `permissionBroker` for `/Users/user/*`),
 *    `ObjCRuntime`, and `AppKitBridge` (live Global Top Menu Bar, non-suspending desktop lifecycle).
 */

import { FormatError, OmniOSError, ERROR_CODES } from '../../common/errors.mjs';
import { PACKAGE_FORMATS } from '../../pkg/format-detector.mjs';
import { createArm64Cpu } from '../../cpu/arm64.mjs';
import {
  parseMachO,
  parseFatMachO,
  loadMachOIntoAddressSpace,
  MACHO_CONSTANTS,
} from '../apple/macho-parser.mjs';
import { createDarwinSyscalls } from '../apple/darwin-syscalls.mjs';
import { createObjCRuntime } from '../apple/objc-runtime.mjs';
import {
  parseMacPackage,
  parseMacDmg,
  parseMacPkg,
} from './app-bundle-parser.mjs';
import { createAppKitBridge } from './appkit-bridge.mjs';

const ROOT_VFS_CTX = Object.freeze({ uid: 0, gid: 0 });
const TEXT_ENCODER = new TextEncoder();

const X64_FLAG_MASKS = Object.freeze({
  CF: 1 << 0,
  PF: 1 << 2,
  AF: 1 << 4,
  ZF: 1 << 6,
  SF: 1 << 7,
  DF: 1 << 10,
  OF: 1 << 11,
});

function normalizeArch(arch) {
  if (!arch) return null;
  const low = String(arch).trim().toLowerCase();
  if (low === 'aarch64' || low === 'arm64e') return 'arm64';
  if (low === 'amd64' || low === 'x86-64' || low === 'x64') return 'x86_64';
  return low;
}

function sanitizeAppId(raw, fallback = 'com.omnios.macos.app') {
  if (typeof raw !== 'string') return fallback;
  const cleaned = raw.trim().replace(/[^A-Za-z0-9._-]+/g, '.').replace(/^\.+|\.+$/g, '');
  if (!cleaned || cleaned === '__proto__' || cleaned === 'constructor' || cleaned === 'prototype') {
    return fallback;
  }
  return cleaned.slice(0, 128);
}

function dirnamePosix(p) {
  const idx = p.lastIndexOf('/');
  if (idx <= 0) return '/';
  return p.slice(0, idx);
}

function isFatHeader(bytes) {
  if (!bytes || bytes.byteLength < 8) return false;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magicBE = dv.getUint32(0, false);
  return magicBE === MACHO_CONSTANTS.FAT_MAGIC || magicBE === MACHO_CONSTANTS.FAT_MAGIC_64;
}

function summarizeMachO(macho) {
  if (!macho) {
    return { sectionsOrClasses: [], importsOrMethods: [], dylibs: [], buildVersion: null };
  }
  const sectionsOrClasses = [];
  for (const seg of macho.segments ?? []) {
    sectionsOrClasses.push({
      segment: seg.segname,
      vmaddr: `0x${seg.vmaddr.toString(16)}`,
      vmsize: Number(seg.vmsize),
      sections: (seg.sections ?? []).map((s) => `${s.segname},${s.sectname}`),
    });
  }
  const importSet = new Set();
  for (const b of macho.binds ?? []) {
    if (b?.symbol) importSet.add(b.symbol);
  }
  for (const b of macho.lazyBinds ?? []) {
    if (b?.symbol) importSet.add(b.symbol);
  }
  for (const b of macho.weakBinds ?? []) {
    if (b?.symbol) importSet.add(b.symbol);
  }
  for (const imp of macho.chainedFixups?.imports ?? []) {
    if (imp?.name) importSet.add(imp.name);
  }
  for (const sym of macho.symbols ?? []) {
    if (sym?.isUndefined && sym.name) importSet.add(sym.name);
  }
  for (const cls of macho.objcClasses ?? []) {
    if (cls) sectionsOrClasses.push(cls);
  }
  for (const sel of macho.objcSelectors ?? []) {
    if (sel) importSet.add(sel);
  }
  return {
    sectionsOrClasses,
    importsOrMethods: Array.from(importSet),
    objcClasses: macho.objcClasses ?? [],
    dylibs: (macho.dylibs ?? []).map((d) => (typeof d === 'string' ? d : d.name)),
    buildVersion: macho.buildVersion ?? null,
  };
}

/**
 * Wraps M3's `X86_64Cpu` (whose `getReg(idx, size)` & `setFlag(mask, bool)` use numeric args
 * and whose re-entrant entry is `callFunction(..., { abi: 'sysv64' })`) into the Apple runtime
 * adapter interface expected by `DarwinSyscallLayer` & `ObjCRuntime`.
 */
function createAppleX64CpuAdapter(rawCpu) {
  return {
    arch: 'x86_64',
    rawCpu,
    get addressSpace() {
      return rawCpu.addressSpace;
    },
    get halted() {
      return rawCpu.exited;
    },
    set halted(v) {
      rawCpu.exited = Boolean(v);
    },
    get exitCode() {
      return rawCpu.exitCode;
    },
    set exitCode(v) {
      rawCpu.exitCode = Number(v) | 0;
    },
    getReg(name) {
      const k = String(name).toLowerCase();
      if (k === 'rip' || k === 'pc') return rawCpu.rip;
      return rawCpu.getReg64(k);
    },
    setReg(name, val) {
      const k = String(name).toLowerCase();
      const big = BigInt.asUintN(64, typeof val === 'bigint' ? val : BigInt(Math.trunc(val ?? 0)));
      if (k === 'rip' || k === 'pc') {
        rawCpu.rip = big;
        return;
      }
      rawCpu.setReg64(k, big);
    },
    setFlag(nameOrMask, bit) {
      const mask =
        typeof nameOrMask === 'number'
          ? nameOrMask
          : (X64_FLAG_MASKS[String(nameOrMask).toUpperCase()] ?? 1);
      rawCpu.setFlag(mask, Boolean(bit));
    },
    getXmmDouble(idx) {
      return rawCpu.getXmmF64(idx);
    },
    setXmmDouble(idx, val) {
      rawCpu.setXmmF64(idx, val, false);
    },
    getDReg(idx) {
      return rawCpu.getXmmF64(idx);
    },
    setDReg(idx, val) {
      rawCpu.setXmmF64(idx, val, false);
    },
    getSReg(idx) {
      return rawCpu.getXmmF32(idx);
    },
    setSReg(idx, val) {
      rawCpu.setXmmF32(idx, Math.fround(val), false);
    },
    callFunctionSync(va, args = [], { maxSteps = 100_000, captureSwiftError = false } = {}) {
      if (captureSwiftError && typeof rawCpu.step === 'function' && rawCpu.regs instanceof BigUint64Array) {
        const savedRegs = new BigUint64Array(rawCpu.regs);
        const savedRip = rawCpu.rip;
        const savedRflags = rawCpu.rflags;
        const savedXmm = rawCpu.xmm ? rawCpu.xmm.map((b) => b.slice()) : null;
        const savedExited = rawCpu.exited;
        const savedExitCode = rawCpu.exitCode;
        const savedSentinel = rawCpu.entryReturnSentinel;
        const callSentinel =
          typeof savedSentinel === 'bigint' &&
          savedSentinel >= 0x7fffffffe000n &&
          savedSentinel < 0x7ffffffff000n
            ? savedSentinel + 0x10n
            : 0x7fffffffe000n;
        try {
          let sp = (rawCpu.regs[4] - 0x40n) & ~0xfn;
          const bigArgs = args.map((a) =>
            BigInt.asUintN(64, typeof a === 'bigint' ? a : BigInt(Math.trunc(a ?? 0)))
          );
          const extraArgs = bigArgs.length > 6 ? bigArgs.slice(6) : [];
          if ((extraArgs.length & 1) === 1) sp -= 8n;
          for (let i = extraArgs.length - 1; i >= 0; i--) {
            sp -= 8n;
            rawCpu.addressSpace.writeU64(sp, extraArgs[i], true);
          }
          sp -= 8n;
          rawCpu.addressSpace.writeU64(sp, callSentinel, true);
          rawCpu.setReg64('rsp', sp);
          rawCpu.setReg64('rdi', bigArgs[0] ?? 0n);
          rawCpu.setReg64('rsi', bigArgs[1] ?? 0n);
          rawCpu.setReg64('rdx', bigArgs[2] ?? 0n);
          rawCpu.setReg64('rcx', bigArgs[3] ?? 0n);
          rawCpu.setReg64('r8', bigArgs[4] ?? 0n);
          rawCpu.setReg64('r9', bigArgs[5] ?? 0n);
          rawCpu.rip = BigInt.asUintN(64, typeof va === 'bigint' ? va : BigInt(va));
          rawCpu.exited = false;
          rawCpu.entryReturnSentinel = callSentinel;

          let totalExec = 0;
          let halted = false;
          let exitCode = 0;
          while (totalExec < maxSteps) {
            const stepRes = rawCpu.step(maxSteps - totalExec);
            totalExec += stepRes.instructionsExecuted ?? 0;
            if (rawCpu.rip === callSentinel) {
              break;
            }
            if (stepRes.status === 'EXITED') {
              halted = true;
              exitCode = stepRes.exitCode ?? rawCpu.exitCode ?? 0;
              break;
            }
            if (stepRes.status === 'FAULT') throw stepRes.fault;
            if (stepRes.status === 'RETURNED' || stepRes.status === 'BLOCKED') break;
            if ((stepRes.instructionsExecuted ?? 0) === 0) break;
          }
          const result = rawCpu.getReg64('rax');
          const r12 = rawCpu.getReg64('r12');
          return {
            result,
            r12,
            swiftError: r12,
            instructionsExecuted: totalExec,
            halted,
            exitCode,
          };
        } finally {
          rawCpu.regs.set(savedRegs);
          rawCpu.rip = savedRip;
          rawCpu.rflags = savedRflags;
          if (savedXmm && rawCpu.xmm) {
            for (let i = 0; i < savedXmm.length; i++) rawCpu.xmm[i].set(savedXmm[i]);
          }
          rawCpu.exited = savedExited;
          rawCpu.exitCode = savedExitCode;
          rawCpu.entryReturnSentinel = savedSentinel;
        }
      }
      const res = rawCpu.callFunction(va, args, { abi: 'sysv64', maxInstructions: maxSteps });
      return {
        result: res.returnValue,
        r12: 0n,
        swiftError: 0n,
        instructionsExecuted: res.instructionsExecuted,
        halted: res.exited,
        exitCode: res.exitCode,
      };
    },
    invokeSubroutine(va, args = [], opts = {}) {
      const maxSteps = typeof opts === 'number' ? opts : (opts?.maxSteps ?? 100_000);
      return this.callFunctionSync(va, args, { maxSteps });
    },
    getInstructionsExecuted() {
      return rawCpu.totalInstructions ?? 0;
    },
  };
}

function getCpuTotalInstructions(cpu, isArm64) {
  if (!cpu) return 0;
  return isArm64 ? (cpu.instructionsExecuted ?? 0) : (cpu.totalInstructions ?? 0);
}

function writeGuestArgv(addressSpace, args) {
  const argvList = Array.isArray(args) && args.length > 0 ? args.map(String) : ['macos-app'];
  const strPtrs = [];
  for (const arg of argvList) {
    const encoded = TEXT_ENCODER.encode(arg);
    const ptr = BigInt(addressSpace.alloc(encoded.byteLength + 1));
    const buf = new Uint8Array(encoded.byteLength + 1);
    buf.set(encoded, 0);
    buf[encoded.byteLength] = 0;
    addressSpace.write(ptr, buf);
    strPtrs.push(ptr);
  }
  const tablePtr = BigInt(addressSpace.alloc((strPtrs.length + 1) * 8));
  for (let i = 0; i < strPtrs.length; i++) {
    addressSpace.writeU64(tablePtr + BigInt(i * 8), strPtrs[i], true);
  }
  addressSpace.writeU64(tablePtr + BigInt(strPtrs.length * 8), 0n, true);
  return { argc: strPtrs.length, argvPtr: tablePtr };
}

export class MacOSRuntime {
  constructor(opts = {}) {
    this.platform = 'macos';
    this.options = { ...opts };
  }

  // =========================================================================
  // Contract 5: inspectPackage(bytes, filenameHint, detection)
  // =========================================================================

  inspectPackage(bytes, filenameHint = '', detection = null) {
    const parsed = parseMacPackage(bytes, filenameHint, detection, {
      preferredArch: 'arm64',
      allowEncrypted: false,
    });

    const plist = parsed.infoPlist ?? {};
    const fallbackBase = (parsed.bundleName || 'macos-app')
      .replace(/\.app$/i, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-');

    const appId = sanitizeAppId(
      plist.CFBundleIdentifier ??
        parsed.packageInfo?.identifier ??
        parsed.spotlight?.kMDItemCFBundleIdentifier ??
        `com.omnios.macos.${fallbackBase}`
    );

    const name = String(
      plist.CFBundleDisplayName ??
        plist.CFBundleName ??
        parsed.distribution?.title ??
        parsed.spotlight?.kMDItemDisplayName ??
        parsed.bundleName ??
        appId
    );

    const version = String(
      plist.CFBundleShortVersionString ??
        plist.CFBundleVersion ??
        parsed.packageInfo?.version ??
        '1.0.0'
    );

    const architectures =
      Array.isArray(parsed.architectures) && parsed.architectures.length > 0
        ? parsed.architectures
        : [parsed.macho?.arch ?? 'arm64'];
    const primaryArch = architectures.includes('arm64') ? 'arm64' : architectures[0];

    const machoSummary = summarizeMachO(parsed.macho);

    // Build compact JSON-safe container metadata (no raw binary buffers!)
    let containerMeta;
    if (parsed.format === PACKAGE_FORMATS.MACOS_DMG) {
      containerMeta = {
        type: 'udif-dmg',
        koly: parsed.koly,
        blkx: parsed.blkx,
        partitions: (parsed.partitions ?? []).map((p) => ({
          id: p.id,
          name: p.name,
          decompressedBytes: p.decompressedBytes,
        })),
        bundleRoot: parsed.bundleRoot,
      };
    } else if (parsed.format === PACKAGE_FORMATS.MACOS_PKG) {
      containerMeta = {
        type: 'xar-pkg',
        xar: {
          magic: parsed.xar.magic,
          headerSize: parsed.xar.headerSize,
          version: parsed.xar.version,
          tocLengthCompressed: parsed.xar.tocLengthCompressed,
          tocLengthUncompressed: parsed.xar.tocLengthUncompressed,
          cksumAlg: parsed.xar.cksumAlg,
          fileCount: parsed.xar.files.length,
          files: parsed.xar.files.map((f) => ({ name: f.name, type: f.type })),
        },
        packageInfo: parsed.packageInfo,
        distribution: parsed.distribution,
        cpioEntryCount: parsed.cpioEntries?.length ?? 0,
        bundleRoot: parsed.bundleRoot,
      };
    } else if (parsed.format === PACKAGE_FORMATS.MACOS_APP) {
      containerMeta = {
        type: 'app-bundle',
        bundleRoot: parsed.bundleRoot,
        bundleName: parsed.bundleName,
        infoPlistPath: parsed.infoPlistPath,
        entryCount: parsed.entries?.length ?? 0,
      };
    } else {
      containerMeta = {
        type: 'raw-macho',
        isUniversal: Boolean(parsed.isUniversal),
      };
    }

    const spotlight = {
      ...parsed.spotlight,
      kMDItemCFBundleIdentifier: appId,
      kMDItemDisplayName: name,
      kMDItemVersion: version,
      kMDItemExecutableArchitectures: architectures,
    };

    const entryPoint = parsed.executableRelPath || parsed.executableName || '';

    return {
      format: parsed.format,
      platform: 'macos',
      arch: primaryArch,
      appId,
      name,
      version,
      entryPoint,
      permissions: Array.isArray(parsed.permissions) ? parsed.permissions : [],
      intents: Array.isArray(parsed.intents) ? parsed.intents : [],
      sectionsOrClasses: machoSummary.sectionsOrClasses,
      importsOrMethods: machoSummary.importsOrMethods,
      rawMetadata: {
        spotlight,
        infoPlist: plist,
        architectures,
        isUniversal: Boolean(parsed.isUniversal || architectures.length > 1),
        container: containerMeta,
        entitlements: parsed.entitlements ?? null,
        dylibs: machoSummary.dylibs,
        buildVersion: machoSummary.buildVersion,
        executableRelPath: entryPoint,
        executableName: parsed.executableName || '',
        bundleRoot: parsed.bundleRoot || '',
        bundleName: parsed.bundleName || '',
      },
    };
  }

  // =========================================================================
  // Contract 5: installPackage(inspection, bytes, services)
  // =========================================================================

  async installPackage(inspection, bytes, services = {}) {
    const vfs = services?.vfs ?? null;
    const eventBus = services?.eventBus ?? null;
    const installDir = inspection.installDir;
    const dataDir = inspection.dataDir;
    const uid = inspection.uid ?? 10000;
    const gid = inspection.gid ?? uid;
    const format = inspection.format;

    let entryPoint = inspection.entryPoint || inspection.rawMetadata?.executableRelPath || '';
    const extraMeta = {};

    // 1. Extract `.dmg` / `.pkg` discovered `.app` bundle or Mach-O into installDir (root ctx)
    if (vfs && installDir) {
      if (format === PACKAGE_FORMATS.MACOS_DMG || format === PACKAGE_FORMATS.MACOS_PKG) {
        const parsed =
          format === PACKAGE_FORMATS.MACOS_DMG
            ? parseMacDmg(bytes, { allowEncrypted: false })
            : parseMacPkg(bytes, { allowEncrypted: false });

        if (parsed.extractedFiles && parsed.extractedFiles.size > 0) {
          for (const [relPath, fileBytes] of parsed.extractedFiles.entries()) {
            if (!relPath || relPath === '.') continue;
            const destPath = `${installDir}/${relPath}`;
            const parent = dirnamePosix(destPath);
            if (parent && parent !== installDir) {
              await vfs.mkdir(parent, { recursive: true, mode: 0o755, ...ROOT_VFS_CTX });
            }
            const isExec = relPath === parsed.executableRelPath;
            await vfs.writeFile(destPath, fileBytes, {
              mode: isExec ? 0o755 : 0o644,
              ...ROOT_VFS_CTX,
            });
          }
          if (parsed.executableRelPath) {
            entryPoint = parsed.executableRelPath;
          }
          extraMeta.extractedFileCount = parsed.extractedFiles.size;
        }
      } else if (format === PACKAGE_FORMATS.MACOS_MACHO && entryPoint) {
        const targetPath = `${installDir}/${entryPoint}`;
        let exists = false;
        try {
          await vfs.stat(targetPath, { ...ROOT_VFS_CTX });
          exists = true;
        } catch {
          exists = false;
        }
        if (!exists) {
          await vfs.writeFile(targetPath, bytes, { mode: 0o755, ...ROOT_VFS_CTX });
        }
      }
    }

    // 2. Provision macOS Library/Preferences, Library/Application Support, Library/Caches, Documents
    if (vfs && dataDir) {
      const subdirs = [
        `${dataDir}/Library`,
        `${dataDir}/Library/Preferences`,
        `${dataDir}/Library/Application Support`,
        `${dataDir}/Library/Caches`,
        `${dataDir}/Documents`,
      ];
      for (const dir of subdirs) {
        await vfs.mkdir(dir, { recursive: true, mode: 0o700, ...ROOT_VFS_CTX });
        if (typeof vfs.chown === 'function') {
          try {
            await vfs.chown(dir, uid, gid, { ...ROOT_VFS_CTX });
          } catch {
            // Ignore if chown unsupported on VFS stub
          }
        }
      }
    }

    // 3. Persist Spotlight extended attributes on installDir & emit 'spotlight:indexed'
    const spotlight = {
      ...(inspection.rawMetadata?.spotlight ?? {}),
      kMDItemDisplayName: inspection.rawMetadata?.spotlight?.kMDItemDisplayName ?? inspection.name,
      kMDItemCFBundleIdentifier: inspection.appId,
      kMDItemPath: installDir || inspection.rawMetadata?.spotlight?.kMDItemPath || `/Applications/${inspection.name}.app`,
      indexedAt: new Date().toISOString(),
    };

    if (vfs && installDir && typeof vfs.setXattr === 'function') {
      try {
        vfs.setXattr(
          installDir,
          'com.apple.metadata:kMDItemDisplayName',
          spotlight.kMDItemDisplayName,
          { ...ROOT_VFS_CTX }
        );
        vfs.setXattr(
          installDir,
          'com.apple.metadata:kMDItemCFBundleIdentifier',
          spotlight.kMDItemCFBundleIdentifier,
          { ...ROOT_VFS_CTX }
        );
        vfs.setXattr(
          installDir,
          'com.apple.metadata:kMDItemContentType',
          spotlight.kMDItemContentType ?? 'com.apple.application-bundle',
          { ...ROOT_VFS_CTX }
        );
        vfs.setXattr(
          installDir,
          'com.apple.metadata:omni_spotlight_json',
          JSON.stringify(spotlight),
          { ...ROOT_VFS_CTX }
        );
      } catch {
        // Isolate xattr failures on virtual/read-only mounts
      }
    }

    if (eventBus && typeof eventBus.emit === 'function') {
      try {
        eventBus.emit('spotlight:indexed', {
          appId: inspection.appId,
          platform: 'macos',
          installDir,
          spotlight,
        });
      } catch {
        // Isolate eventBus errors
      }
    }

    return {
      entryPoint,
      arch: inspection.arch,
      permissions: inspection.permissions,
      intents: inspection.intents,
      metadata: {
        ...extraMeta,
        spotlight,
        executableRelPath: entryPoint,
      },
    };
  }

  // =========================================================================
  // Executable Reading & Universal Slice Selection Helpers
  // =========================================================================

  async _readExecutableBytes(appRecord, services) {
    const vfs = services?.vfs;
    if (!vfs || typeof vfs.readFile !== 'function') {
      throw new OmniOSError('MacOSRuntime requires VFS to load executable binary', {
        code: ERROR_CODES.EINVAL,
      });
    }

    const candidates = [];
    if (appRecord.entryPoint) {
      candidates.push(`${appRecord.installDir}/${appRecord.entryPoint}`);
    }
    const metaExec = appRecord.metadata?.executableRelPath;
    if (metaExec && metaExec !== appRecord.entryPoint) {
      candidates.push(`${appRecord.installDir}/${metaExec}`);
    }
    if (appRecord.format === PACKAGE_FORMATS.MACOS_MACHO) {
      candidates.push(`${appRecord.installDir}/.package.bin`);
    }

    for (const fullPath of candidates) {
      try {
        const data = await vfs.readFile(fullPath, { ...ROOT_VFS_CTX });
        if (data instanceof Uint8Array && data.byteLength >= 32) {
          return { execBytes: data, execPath: fullPath };
        }
      } catch {
        // Try next candidate
      }
    }

    throw new FormatError(
      `Unable to locate macOS Mach-O executable for ${appRecord.appId} in ${appRecord.installDir}`,
      {
        code: ERROR_CODES.ENOENT,
        format: appRecord.format,
      }
    );
  }

  _selectArchSlice(execBytes, services, launchOptions = {}) {
    const cpuRegistry = services?.cpuRegistry ?? null;
    const hasArchEngine = (arch) => {
      if (cpuRegistry && typeof cpuRegistry.has === 'function' && cpuRegistry.has(arch)) {
        return true;
      }
      return arch === 'arm64'; // built-in ARM64 fallback
    };

    const requestedArch = normalizeArch(launchOptions?.arch);

    if (isFatHeader(execBytes)) {
      const fat = parseFatMachO(execBytes);
      const avail = fat.slices.map((s) => normalizeArch(s.arch));

      if (requestedArch) {
        if (!avail.includes(requestedArch)) {
          throw new FormatError(
            `Requested macOS architecture "${requestedArch}" not found in Universal binary (available: ${avail.join(', ')})`,
            { code: ERROR_CODES.ENOTSUP, format: 'macho' }
          );
        }
        if (!hasArchEngine(requestedArch)) {
          throw new FormatError(
            `No CPU engine registered in CpuRegistry for architecture "${requestedArch}"`,
            { code: ERROR_CODES.ENOTSUP, format: 'macho' }
          );
        }
        return { selectedArch: requestedArch, availableArchs: avail };
      }

      // Default preference: arm64 first, fallback to x86_64 if registered in CpuRegistry
      if (avail.includes('arm64') && hasArchEngine('arm64')) {
        return { selectedArch: 'arm64', availableArchs: avail };
      }
      if (avail.includes('x86_64') && hasArchEngine('x86_64')) {
        return { selectedArch: 'x86_64', availableArchs: avail };
      }

      throw new FormatError(
        `No supported CPU engine registered for Universal Mach-O slices [${avail.join(', ')}]`,
        { code: ERROR_CODES.ENOTSUP, format: 'macho' }
      );
    }

    // Thin Mach-O binary
    const peek = parseMachO(execBytes, { allowEncrypted: false });
    const thinArch = normalizeArch(peek.arch);
    if (requestedArch && requestedArch !== thinArch) {
      throw new FormatError(
        `Requested architecture "${requestedArch}" does not match thin Mach-O architecture "${thinArch}"`,
        { code: ERROR_CODES.ENOTSUP, format: 'macho' }
      );
    }
    if (!hasArchEngine(thinArch)) {
      throw new FormatError(
        `No CPU engine registered in CpuRegistry for macOS Mach-O architecture "${thinArch}"`,
        { code: ERROR_CODES.ENOTSUP, format: 'macho' }
      );
    }
    return { selectedArch: thinArch, availableArchs: [thinArch] };
  }

  // =========================================================================
  // Contract 5: createExecutionContext(pcb, appRecord, services, launchOptions)
  // =========================================================================

  async createExecutionContext(pcb, appRecord, services = {}, launchOptions = {}) {
    if (!pcb || !pcb.addressSpace) {
      throw new OmniOSError('MacOSRuntime requires a valid PCB with an AddressSpace', {
        code: ERROR_CODES.EINVAL,
      });
    }

    const { execBytes, execPath } = await this._readExecutableBytes(appRecord, services);
    const { selectedArch, availableArchs } = this._selectArchSlice(execBytes, services, launchOptions);

    // Parse chosen Mach-O slice strictly (Edge Case #20: FairPlay DRM always rejected!)
    const parsedMachO = parseMachO(execBytes, {
      preferredArch: selectedArch,
      allowEncrypted: false,
    });

    const addressSpace = pcb.addressSpace;
    const infoPlist = appRecord.metadata?.infoPlist ?? {};
    const appId = appRecord.appId || pcb.appId || 'com.omnios.macos.app';
    const appName = appRecord.name || infoPlist.CFBundleDisplayName || infoPlist.CFBundleName || appId;
    const bundleRoot = appRecord.metadata?.bundleRoot
      ? `${appRecord.installDir}/${appRecord.metadata.bundleRoot}`
      : appRecord.installDir;

    // Synchronous PermissionBroker callback for shared `/Users/user/*` -> `/home/user/*`
    const permissionBroker = ({ capability, canonicalPath }) => {
      const isSharedUser =
        canonicalPath === '/home/user' || canonicalPath.startsWith('/home/user/');
      if (!isSharedUser) return { allowed: false };
      if (!services.permissions || typeof services.permissions.getGrant !== 'function') {
        return { allowed: false };
      }
      try {
        const grant = services.permissions.getGrant(appId, capability);
        if (grant && grant.state === 'allow') {
          return {
            allowed: true,
            effectiveCtx: {
              uid: 1000,
              gid: 1000,
              sandboxRoot: '/home/user',
            },
          };
        }
      } catch {
        // Fail closed
      }
      return { allowed: false };
    };

    // 1. Lazily construct ObjCRuntime & AppKitBridge on first symbol resolution (strictly AFTER
    //    Step 1 of `loadMachOIntoAddressSpace` reserves `__PAGEZERO` 0..0x100000000, so VMM heap
    //    allocations land cleanly at `HIGH_VA_HEAP_BASE` = 0x200000000 with zero guard overlap!).
    let objcRuntime = null;
    let appKitBridge = null;
    const ensureAppleRuntime = () => {
      if (objcRuntime) return;
      objcRuntime = createObjCRuntime({
        addressSpace,
        vfs: services.vfs ?? null,
        configStore: services.configStore ?? null,
        processManager: services.processManager ?? null,
        pcb,
        platform: 'macos',
        appId,
        bundleInfo: infoPlist,
        bundlePath: bundleRoot,
        sandboxRoot: appRecord.dataDir,
        cwd: pcb.cwd || appRecord.dataDir,
        uid: pcb.uid,
        gid: pcb.gid,
        permissionBroker,
      });

      appKitBridge = createAppKitBridge({
        objcRuntime,
        pcb,
        services,
        appId,
        appName,
        infoPlist,
        launchIntent: launchOptions?.intent ?? null,
      });
    };

    // 2. Load Mach-O into VMM AddressSpace (`__PAGEZERO` guard, segments, fixups, thunks, stack)
    const loaded = loadMachOIntoAddressSpace(parsedMachO, addressSpace, {
      slide: launchOptions?.slide ?? 0,
      resolveSymbol: (sym) => {
        ensureAppleRuntime();
        return objcRuntime.resolveMachOSymbol(sym);
      },
      stackSize: 0x40000,
    });
    ensureAppleRuntime();

    if (loaded.entryVA === null || loaded.entryVA === undefined) {
      throw new FormatError(`Mach-O binary for ${appId} has no valid LC_MAIN / entry VA`, {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
      });
    }

    // 3. Load app-defined ObjC ABI2 classes, selectors & static CFStrings from Mach-O sections
    objcRuntime.loadMachOObjC(loaded);

    // 4. Create Darwin XNU BSD Syscall & Mach Trap Layer
    const userRec =
      services.users && typeof services.users.getUserByUid === 'function'
        ? services.users.getUserByUid(pcb.uid)
        : null;
    const macSandboxRoot = userRec?.strictSandbox === true ? appRecord.dataDir : null;
    const darwinSyscalls = createDarwinSyscalls({
      pcb,
      addressSpace,
      vfs: services.vfs ?? null,
      processManager: services.processManager ?? null,
      platform: 'macos',
      arch: selectedArch,
      appId,
      sandboxRoot: macSandboxRoot,
      cwd: pcb.cwd || appRecord.dataDir,
      pid: pcb.pid,
      ppid: pcb.ppid ?? 1,
      uid: pcb.uid,
      gid: pcb.gid,
      entitlementsXml: loaded.codeSignature?.entitlementsXml ?? null,
      permissionBroker,
    });

    // 5. Prepare guest (argc, argv)
    const guestArgvList = [execPath, ...(Array.isArray(launchOptions?.args) ? launchOptions.args : [])];
    const { argc, argvPtr } = writeGuestArgv(addressSpace, guestArgvList);

    // 6. Instantiate real CPU engine via `CpuRegistry` (ARM64 or x86-64)
    const isArm64 = selectedArch === 'arm64';
    const cpuRegistry = services?.cpuRegistry ?? null;
    let rawCpu;
    let cpuForApple;

    if (isArm64) {
      const armOpts = {
        addressSpace,
        pid: pcb.pid,
        maxInstructions: pcb.quotas?.maxTotalInstructions ?? 10_000_000,
        thunkStart: loaded.thunkBase,
        thunkEnd: loaded.thunkBase + loaded.thunkSize,
        exitSentinelVA: loaded.exitSentinelVA,
        onSyscall: (cpu, imm16) => darwinSyscalls.handleArm64Svc(cpu, imm16),
        onThunk: (pc, cpu) => {
          const entry = loaded.thunkTable.get(Number(pc));
          if (!entry) return false;
          const res = objcRuntime.handleThunk(entry.symbol, cpu);
          const ctrl = appKitBridge.consumePendingControl();
          if (ctrl) return ctrl;
          return res;
        },
      };
      rawCpu =
        cpuRegistry && typeof cpuRegistry.has === 'function' && cpuRegistry.has('arm64')
          ? cpuRegistry.create('arm64', armOpts)
          : createArm64Cpu(armOpts);

      rawCpu.setPC(BigInt(loaded.entryVA));
      rawCpu.setSP(BigInt(loaded.initialSP));
      rawCpu.setLR(BigInt(loaded.exitSentinelVA));
      rawCpu.setReg(0, BigInt(argc));
      rawCpu.setReg(1, argvPtr);
      cpuForApple = rawCpu;
    } else {
      // x86-64 Mach-O slice via M3 `X86_64Cpu` registered in `CpuRegistry`
      const x64Opts = {
        addressSpace,
        mode: 'x86_64',
        pid: pcb.pid,
        thunkRange: {
          start: loaded.thunkBase,
          end: loaded.thunkBase + loaded.thunkSize - 1,
        },
        entryReturnSentinel: loaded.exitSentinelVA,
        onSyscall: () => darwinSyscalls.handleX86_64Syscall(cpuForApple),
        onThunk: (curRip) => {
          const entry = loaded.thunkTable.get(Number(curRip));
          if (!entry) {
            return {
              status: 'FAULT',
              fault: new OmniOSError(`Unresolved macOS x86-64 thunk at 0x${curRip.toString(16)}`, {
                code: ERROR_CODES.E_UNIMPLEMENTED_API,
              }),
            };
          }
          const prevRip = rawCpu.rip;
          const res = objcRuntime.handleThunk(entry.symbol, cpuForApple);
          const ctrl = appKitBridge.consumePendingControl();
          if (ctrl) return ctrl;
          if (res && typeof res === 'object' && res.status) {
            return res;
          }
          // If objc_msgSend tail-jumped RIP to an app IMP, preserve RIP & stack return address!
          if (rawCpu.rip !== prevRip) {
            return { status: 'JUMPED' };
          }
          return { status: 'CONTINUE' };
        },
      };

      rawCpu = cpuRegistry.create('x86_64', x64Opts);
      cpuForApple = createAppleX64CpuAdapter(rawCpu);

      // macOS x86-64 LC_MAIN entry: push exit sentinel return address onto 16B-aligned stack
      const spAfterPush = BigInt(loaded.initialSP) - 8n;
      addressSpace.writeU64(spAfterPush, BigInt(loaded.exitSentinelVA), true);
      rawCpu.rip = BigInt(loaded.entryVA);
      rawCpu.setReg64('rsp', spAfterPush);
      rawCpu.setReg64('rdi', BigInt(argc));
      rawCpu.setReg64('rsi', argvPtr);
    }

    // Update PCB arch to accurately reflect chosen slice (e.g., arm64 vs x86_64)
    pcb.arch = selectedArch;

    // 7. Build strictly SYNCHRONOUS Contract 5 `IExecutionContext`
    const pendingEvents = [];
    let disposed = false;

    const execCtx = {
      platform: 'macos',
      arch: selectedArch,
      availableArchs,
      appId,
      cpu: rawCpu,
      objcRuntime,
      darwinSyscalls,
      appKitBridge,
      loadedMachO: loaded,

      step(budget = 1000) {
        if (disposed) {
          return { status: 'EXITED', instructionsExecuted: 0, exitCode: appKitBridge.exitCode };
        }
        if (darwinSyscalls.hasExited) {
          return { status: 'EXITED', instructionsExecuted: 0, exitCode: darwinSyscalls.exitCode };
        }
        if (appKitBridge.terminated) {
          return { status: 'EXITED', instructionsExecuted: 0, exitCode: appKitBridge.exitCode };
        }
        if (cpuForApple.halted) {
          return { status: 'EXITED', instructionsExecuted: 0, exitCode: cpuForApple.exitCode ?? 0 };
        }

        const effectiveBudget =
          typeof budget === 'number' && Number.isFinite(budget) && budget >= 1
            ? Math.floor(budget)
            : 1;

        const startInsns = getCpuTotalInstructions(rawCpu, isArm64);

        // Drain queued UI / Global Menu Bar / Intent / Window events synchronously on real CPU,
        // strictly bounded by per-tick `effectiveBudget`!
        if (pendingEvents.length > 0) {
          let executed = 0;
          while (
            pendingEvents.length > 0 &&
            executed < effectiveBudget &&
            !appKitBridge.terminated &&
            !darwinSyscalls.hasExited &&
            !cpuForApple.halted
          ) {
            const ev = pendingEvents.shift();
            const before = getCpuTotalInstructions(rawCpu, isArm64);
            try {
              appKitBridge.handleEvent(cpuForApple, ev);
            } catch (err) {
              const delta = Math.max(1, getCpuTotalInstructions(rawCpu, isArm64) - startInsns);
              return {
                status: 'FAULT',
                instructionsExecuted: Math.min(delta, effectiveBudget),
                fault: err,
              };
            }
            const stepDelta = Math.max(1, getCpuTotalInstructions(rawCpu, isArm64) - before);
            executed += stepDelta;
          }
          const clampedExec = Math.min(executed, effectiveBudget);
          if (darwinSyscalls.hasExited) {
            return { status: 'EXITED', instructionsExecuted: clampedExec, exitCode: darwinSyscalls.exitCode };
          }
          if (appKitBridge.terminated) {
            return { status: 'EXITED', instructionsExecuted: clampedExec, exitCode: appKitBridge.exitCode };
          }
          if (cpuForApple.halted) {
            return { status: 'EXITED', instructionsExecuted: clampedExec, exitCode: cpuForApple.exitCode ?? 0 };
          }
          if (pendingEvents.length > 0) {
            return { status: 'YIELD', instructionsExecuted: clampedExec };
          }
          if (appKitBridge.awaitingEvents) {
            return { status: 'BLOCKED', instructionsExecuted: clampedExec, waitReason: 'ui_event' };
          }
        }

        // Non-suspending macOS desktop event loop idle wait
        if (appKitBridge.awaitingEvents) {
          return { status: 'BLOCKED', instructionsExecuted: 0, waitReason: 'ui_event' };
        }

        // Execute real native CPU instructions bounded strictly by `effectiveBudget`
        try {
          const res = rawCpu.step(effectiveBudget);
          const clampedExec = Math.min(res.instructionsExecuted ?? 0, effectiveBudget);
          if (res.status === 'FAULT') {
            return { status: 'FAULT', instructionsExecuted: clampedExec, fault: res.fault };
          }
          const ctrl = appKitBridge.consumePendingControl();
          if (ctrl) {
            return {
              ...ctrl,
              instructionsExecuted: clampedExec,
            };
          }
          if (darwinSyscalls.hasExited) {
            return {
              status: 'EXITED',
              instructionsExecuted: clampedExec,
              exitCode: darwinSyscalls.exitCode,
            };
          }
          if (appKitBridge.terminated) {
            return {
              status: 'EXITED',
              instructionsExecuted: clampedExec,
              exitCode: appKitBridge.exitCode,
            };
          }
          if (cpuForApple.halted || res.status === 'EXITED') {
            return {
              status: 'EXITED',
              instructionsExecuted: clampedExec,
              exitCode: res.exitCode ?? cpuForApple.exitCode ?? 0,
            };
          }
          return { ...res, instructionsExecuted: clampedExec };
        } catch (err) {
          const delta = Math.max(0, getCpuTotalInstructions(rawCpu, isArm64) - startInsns);
          return {
            status: 'FAULT',
            instructionsExecuted: Math.min(delta, effectiveBudget),
            fault: err,
          };
        }
      },

      deliverEvent(event) {
        if (disposed || appKitBridge.terminated || darwinSyscalls.hasExited || cpuForApple.halted) return;
        pendingEvents.push(event);
        const pm = services?.processManager;
        if (pm && pcb && pcb.state === 'BLOCKED' && typeof pm.wake === 'function') {
          try {
            pm.wake(pcb.pid);
          } catch {
            // Ignore if already awake or terminated
          }
        }
      },

      getDebugState() {
        const base = typeof rawCpu.getDebugState === 'function' ? rawCpu.getDebugState() : {};
        return {
          ...base,
          arch: selectedArch,
          availableArchs,
          platform: 'macos',
          appId,
          windows: appKitBridge.getWindowIds(),
          menuBar: appKitBridge.getMenuBar(),
          lastSyscall: darwinSyscalls.lastSyscall ?? base.lastSyscall ?? null,
          syscallCount: darwinSyscalls.syscallCount,
          spotlight: appRecord.metadata?.spotlight ?? null,
        };
      },

      dispose() {
        if (disposed) return;
        disposed = true;
        pendingEvents.length = 0;
        try {
          appKitBridge.dispose();
        } catch {
          // Ignore
        }
        try {
          objcRuntime.dispose();
        } catch {
          // Ignore
        }
        try {
          darwinSyscalls.dispose();
        } catch {
          // Ignore
        }
        try {
          if (typeof rawCpu.dispose === 'function') rawCpu.dispose();
        } catch {
          // Ignore
        }
      },
    };

    return execCtx;
  }
}

export function createMacOSRuntime(opts = {}) {
  return new MacOSRuntime(opts);
}
