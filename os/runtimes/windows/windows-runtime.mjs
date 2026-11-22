/**
 * OmniOS Windows Platform Runtime (`os/runtimes/windows/windows-runtime.mjs`)
 * Implements Contract 5 (`IPlatformRuntime`) for `platform = 'windows'`:
 * - Registers `'x86_64'` and `'x86'` in `CpuRegistry`
 * - Inspects, installs, and executes `.exe`/`.dll` (PE32/PE32+), `.msix`/`.appx`, `.msi`, and `.bat`/`.cmd`
 * - Reads `${appRecord.installDir}/.package.bin` with root VFS context (`{ uid: 0, gid: 0 }`) per Landmine #2
 * - Produces strictly synchronous `IExecutionContext` instances driven by M1 Scheduler
 */

import crypto from 'node:crypto';
import { detectFormat, PACKAGE_FORMATS } from '../../pkg/format-detector.mjs';
import { FormatError, OmniOSError, QuotaExceededError, ERROR_CODES } from '../../common/errors.mjs';
import { PROT_READ, PROT_WRITE } from '../../kernel/vmm.mjs';
import {
  createX86_64Cpu,
  createX86Cpu,
  registerX86Cpu,
} from '../../cpu/x86_64.mjs';
import { parsePe, mapPeIntoAddressSpace } from './pe-parser.mjs';
import { parseMsix, parseMsi } from './win-pkg-parser.mjs';
import { Win32Bridge } from './win32-bridge.mjs';
import { createBatchExecutionContext } from './batch-runner.mjs';

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const DEFAULT_WIN_STACK_SIZE = 64 * 1024; // 64 KiB
const MAX_INSPECT_IMPORTS = 4096;
const MAX_INSPECT_IMPORT_CHARS = 256 * 1024;

const DEFAULT_PE_PERMISSIONS = Object.freeze([
  'asInvoker',
  'documentsLibrary',
  'documentsLibraryWrite',
  'clipboardRead',
  'clipboardWrite',
  'toastNotifications',
]);

function toBytes(input) {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new FormatError('WindowsRuntime expected binary Uint8Array/Buffer input', {
    code: ERROR_CODES.EINVAL,
    format: 'windows',
  });
}

function sanitizeIdPart(raw) {
  return String(raw || '')
    .trim()
    .replace(/^.*[/\\]/, '')
    .replace(/\.(exe|dll|msix|appx|msi|bat|cmd)$/i, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

function deriveWinAppId(kind, filenameHint, bytes) {
  const stem = sanitizeIdPart(filenameHint);
  if (stem.length > 0) {
    if (kind === 'bat' || kind === 'cmd') {
      return `win.${stem.toLowerCase()}.${kind}`;
    }
    return `win.${stem.toLowerCase()}`;
  }
  const hash8 = crypto.createHash('sha256').update(bytes).digest('hex').slice(0, 8);
  return `win.${kind}.${hash8}`;
}

function deriveDisplayName(filenameHint, fallback) {
  const base = String(filenameHint || '').trim().replace(/^.*[/\\]/, '');
  if (base) return base;
  return fallback;
}

function buildPeExecutionContext({ pe, pcb, appRecord, services, launchOptions }) {
  const addrSpace = pcb.addressSpace;
  const bridge = new Win32Bridge({ pcb, appRecord, pe, services, launchOptions });

  const mapped = mapPeIntoAddressSpace(pe, addrSpace, {
    reserveNullGuard: true,
    resolveImport: (imp) => bridge.registerImport(imp.dll, imp.name, imp.ordinal),
  });

  // Allocate 64 KiB process stack
  const stackBase = BigInt(addrSpace.mmap(0, DEFAULT_WIN_STACK_SIZE, PROT_READ | PROT_WRITE, 'win:stack'));
  const stackTop = stackBase + BigInt(DEFAULT_WIN_STACK_SIZE);

  // Allocate 4 KiB Thread Environment Block (TEB) page (GS:[0x30] on x64, FS:[0x18] on x86)
  const tebBase = BigInt(addrSpace.mmap(0, 4096, PROT_READ | PROT_WRITE, 'win:teb'));
  const tebBuf = new Uint8Array(64);
  const tebDv = new DataView(tebBuf.buffer);
  if (pe.is64) {
    tebDv.setBigUint64(0x08, stackTop, true);  // StackBase
    tebDv.setBigUint64(0x10, stackBase, true); // StackLimit
    tebDv.setBigUint64(0x30, tebBase, true);   // Self pointer (NtCurrentTeb)
  } else {
    tebDv.setUint32(0x04, Number(stackTop & 0xffffffffn), true);
    tebDv.setUint32(0x08, Number(stackBase & 0xffffffffn), true);
    tebDv.setUint32(0x18, Number(tebBase & 0xffffffffn), true);
  }
  addrSpace.write(tebBase, tebBuf);

  const getNestedInstructionCap = (stepExecuted, stepBudget) => {
    const q = pcb?.quotas;
    const maxPerTick =
      Number.isFinite(q?.maxInstructionsPerTick) && q.maxInstructionsPerTick > 0
        ? Math.floor(q.maxInstructionsPerTick)
        : Infinity;
    let maxTotal =
      Number.isFinite(q?.maxTotalInstructions) && q.maxTotalInstructions > 0
        ? Math.floor(q.maxTotalInstructions)
        : Infinity;
    if (Number.isFinite(q?.maxCpuSteps) && q.maxCpuSteps > 0) {
      maxTotal = Math.min(maxTotal, Math.floor(q.maxCpuSteps));
    }
    const already = pcb?.stats?.instructionsExecuted ?? 0;
    const remTotal = maxTotal === Infinity ? Infinity : Math.max(0, maxTotal - already - stepExecuted);
    const remPerTick = maxPerTick === Infinity ? Infinity : Math.max(0, maxPerTick - stepExecuted);
    const remSlice =
      Number.isFinite(stepBudget) && stepBudget >= 0
        ? Math.max(0, Math.floor(stepBudget) - stepExecuted)
        : Infinity;
    return Math.min(100000, remTotal, Math.max(remPerTick, remSlice));
  };

  const cpuOpts = {
    addressSpace: addrSpace,
    mode: pe.arch,
    pid: pcb.pid,
    thunkRange: bridge.thunkRange,
    getNestedInstructionCap,
    onThunk: (va, cpu) => bridge.handleThunk(va, cpu),
    onInt: (vec, cpu) => {
      void cpu;
      if (vec === 3) {
        return { status: 'CONTINUE' };
      }
      return { status: 'CONTINUE' };
    },
  };

  let cpu;
  if (services.cpuRegistry && typeof services.cpuRegistry.has === 'function' && services.cpuRegistry.has(pe.arch)) {
    cpu = services.cpuRegistry.create(pe.arch, cpuOpts);
  } else {
    cpu = pe.is64 ? createX86_64Cpu(cpuOpts) : createX86Cpu(cpuOpts);
  }

  bridge.attachCpu(cpu, mapped);

  // Initialize RIP/EIP, RSP/ESP, TEB segment base, and return sentinel at [RSP]
  cpu.rip = mapped.entryVa;
  if (pe.is64) {
    // Win64 ABI: RSP % 16 === 8 upon entry (return address sits at [RSP], 32B shadow above)
    const initRsp = stackTop - 0x28n;
    cpu.writeMem(initRsp, 8, cpu.entryReturnSentinel);
    cpu.regs[4] = initRsp;
    cpu.regs[5] = initRsp; // RBP
    cpu.gsBase = tebBase;
  } else {
    const initEsp = (stackTop - 0x10n) & 0xffffffffn;
    cpu.writeMem(initEsp, 4, cpu.entryReturnSentinel & 0xffffffffn);
    cpu.regs[4] = initEsp;
    cpu.regs[5] = initEsp; // EBP
    cpu.fsBase = tebBase & 0xffffffffn;
  }

  let disposed = false;

  return {
    arch: pe.arch,
    cpu,
    bridge,
    mapped,

    step(budget) {
      if (disposed) {
        return { status: 'EXITED', exitCode: cpu.exitCode ?? 0, instructionsExecuted: 0 };
      }
      const q = pcb?.quotas;
      const maxCpuSteps =
        Number.isFinite(q?.maxCpuSteps) && q.maxCpuSteps > 0
          ? Math.floor(q.maxCpuSteps)
          : Infinity;
      let effBudget = Math.max(0, Math.trunc(budget));
      if (maxCpuSteps !== Infinity) {
        const already = pcb?.stats?.instructionsExecuted ?? cpu.totalInstructions;
        const remCpuSteps = Math.max(0, maxCpuSteps - already);
        if (remCpuSteps <= 0) {
          return {
            status: 'FAULT',
            fault: new QuotaExceededError(
              `PID ${pcb?.pid ?? 0} exhausted maxCpuSteps (${maxCpuSteps})`,
              {
                code: ERROR_CODES.E_CPU_QUOTA,
                quotaType: 'cpu',
                limit: maxCpuSteps,
                actual: already,
                pid: pcb?.pid ?? null,
                signal: 'SIGXCPU',
              }
            ),
            instructionsExecuted: 0,
          };
        }
        effBudget = Math.min(effBudget, remCpuSteps);
      }

      let res;
      try {
        res = cpu.step(effBudget);
      } finally {
        bridge.flushCompositorSurfacesIfDirty();
      }
      if (res.status === 'RETURNED') {
        return {
          status: 'EXITED',
          exitCode: Number(cpu.regs[0] & 0xffffffffn) | 0,
          instructionsExecuted: res.instructionsExecuted,
        };
      }
      if (maxCpuSteps !== Infinity && res.status !== 'EXITED' && res.status !== 'FAULT') {
        const afterTotal =
          (pcb?.stats?.instructionsExecuted ?? 0) + (res.instructionsExecuted ?? 0);
        if (afterTotal >= maxCpuSteps) {
          return {
            status: 'FAULT',
            fault: new QuotaExceededError(
              `PID ${pcb?.pid ?? 0} exceeded maxCpuSteps (${afterTotal}/${maxCpuSteps})`,
              {
                code: ERROR_CODES.E_CPU_QUOTA,
                quotaType: 'cpu',
                limit: maxCpuSteps,
                actual: afterTotal,
                pid: pcb?.pid ?? null,
                signal: 'SIGXCPU',
              }
            ),
            instructionsExecuted: res.instructionsExecuted,
          };
        }
      }
      return res;
    },

    deliverEvent(event) {
      if (disposed) return;
      bridge.deliverEvent(event);
    },

    getDebugState() {
      const base = cpu.getDebugState();
      return {
        ...base,
        loadBase: `0x${mapped.loadBase.toString(16)}`,
        entryVa: `0x${mapped.entryVa.toString(16)}`,
        peType: pe.peType,
        subsystem: pe.optionalHeader.subsystemName,
        lastError: bridge.lastError,
      };
    },

    dispose() {
      if (disposed) return;
      disposed = true;
      bridge.dispose();
    },
  };
}

export class WindowsRuntime {
  constructor({ cpuRegistry = null } = {}) {
    this.platform = 'windows';
    this._cpuRegistry = cpuRegistry;
    if (cpuRegistry && typeof cpuRegistry.register === 'function') {
      registerX86Cpu(cpuRegistry);
    }
  }

  _ensureCpuRegistered(cpuRegistry) {
    const reg = cpuRegistry ?? this._cpuRegistry;
    if (!reg || typeof reg.register !== 'function') return;
    if (!reg.has?.('x86_64') || !reg.has?.('x86')) {
      registerX86Cpu(reg);
    }
  }

  inspectPackage(buffer, filenameHint = '') {
    const bytes = toBytes(buffer);
    const detection = detectFormat(bytes, filenameHint);
    const fmt = detection.format;

    // 1. PE32 / PE32+ (.exe / .dll)
    if (fmt === PACKAGE_FORMATS.WINDOWS_PE) {
      const pe = parsePe(bytes);
      const appId = deriveWinAppId('pe', filenameHint, bytes);
      const importsFlat = [];
      const seenImportKeys = new Set();
      let totalImportChars = 0;
      outerImports: for (const desc of pe.imports) {
        for (const entry of desc.entries) {
          const sym = `${desc.dll}!${entry.byOrdinal ? `#${entry.ordinal}` : entry.name}`;
          if (seenImportKeys.has(sym)) continue;
          if (
            importsFlat.length >= MAX_INSPECT_IMPORTS ||
            totalImportChars + sym.length > MAX_INSPECT_IMPORT_CHARS
          ) {
            break outerImports;
          }
          seenImportKeys.add(sym);
          importsFlat.push(sym);
          totalImportChars += sym.length;
        }
      }
      return {
        format: PACKAGE_FORMATS.WINDOWS_PE,
        platform: 'windows',
        arch: pe.arch,
        appId,
        name: deriveDisplayName(filenameHint, appId),
        version: pe.optionalHeader.imageVersion || '1.0.0',
        entryPoint: `0x${pe.optionalHeader.addressOfEntryPoint.toString(16)}`,
        permissions: [...DEFAULT_PE_PERMISSIONS],
        intents: [],
        sectionsOrClasses: pe.sections.map((s) => ({
          name: s.name,
          virtualAddress: `0x${s.virtualAddress.toString(16)}`,
          virtualSize: s.virtualSize,
          sizeOfRawData: s.sizeOfRawData,
          characteristics: `0x${s.characteristics.toString(16)}`,
        })),
        importsOrMethods: importsFlat,
        rawMetadata: {
          peType: pe.peType,
          machine: `0x${pe.coffHeader.machine.toString(16)}`,
          isDll: pe.isDll,
          subsystem: pe.optionalHeader.subsystem,
          subsystemName: pe.optionalHeader.subsystemName,
          imageBase: `0x${pe.optionalHeader.imageBase.toString(16)}`,
          addressOfEntryPoint: `0x${pe.optionalHeader.addressOfEntryPoint.toString(16)}`,
          sizeOfImage: pe.optionalHeader.sizeOfImage,
          exportsCount: pe.exports.entries.length,
          relocationBlocks: pe.relocations.length,
          certificateTable: pe.certificateTable,
        },
      };
    }

    // 2. MSIX / APPX
    if (fmt === PACKAGE_FORMATS.WINDOWS_MSIX) {
      const msix = parseMsix(bytes);
      const safeId = sanitizeIdPart(msix.identity.name) || deriveWinAppId('msix', filenameHint, bytes);
      return {
        format: PACKAGE_FORMATS.WINDOWS_MSIX,
        platform: 'windows',
        arch: msix.arch,
        appId: safeId,
        name: msix.displayName || safeId,
        version: msix.version || '1.0.0',
        entryPoint: msix.executable || '',
        permissions: msix.capabilities.length > 0 ? [...msix.capabilities] : [...DEFAULT_PE_PERMISSIONS],
        intents: msix.intents, // Already flat IntentRouter descriptors!
        sectionsOrClasses: msix.fileNames,
        importsOrMethods: msix.applications.map((a) => a.executable || a.entryPoint).filter(Boolean),
        rawMetadata: {
          identity: msix.identity,
          publisher: msix.publisher,
          description: msix.description,
          executable: msix.executable,
          entryPoint: msix.entryPoint,
          blockMapVerified: msix.blockMapVerified,
          blockMapFileCount: msix.blockMapFileCount,
        },
      };
    }

    // 3. MSI (OLE CFBF)
    if (fmt === PACKAGE_FORMATS.WINDOWS_MSI) {
      const msi = parseMsi(bytes);
      const appId = deriveWinAppId('msi', msi.summaryInfo.title || filenameHint, bytes);
      const template = String(msi.summaryInfo.template || '').toLowerCase();
      const arch = template.includes('x64') || template.includes('amd64') ? 'x86_64' : 'x86';
      return {
        format: PACKAGE_FORMATS.WINDOWS_MSI,
        platform: 'windows',
        arch,
        appId,
        name: msi.summaryInfo.title || deriveDisplayName(filenameHint, appId),
        version: '1.0.0',
        entryPoint: '',
        permissions: [],
        intents: [],
        sectionsOrClasses: msi.streamNames,
        importsOrMethods: [],
        rawMetadata: {
          cfbfVersion: msi.version,
          sectorSize: msi.sectorSize,
          miniSectorSize: msi.miniSectorSize,
          entryCount: msi.entries.length,
          summaryInfo: msi.summaryInfo,
        },
      };
    }

    // 4. Batch Script (.bat / .cmd)
    if (fmt === PACKAGE_FORMATS.WINDOWS_BAT) {
      const hintLower = String(filenameHint || '').trim().toLowerCase();
      const scriptKind = hintLower.endsWith('.cmd') ? 'cmd' : (detection.details?.scriptKind ?? 'bat');
      const text = UTF8_DECODER.decode(bytes);
      const appId = deriveWinAppId(scriptKind, filenameHint, bytes);
      const entryName = deriveDisplayName(filenameHint, `${appId}.${scriptKind}`);
      return {
        format: PACKAGE_FORMATS.WINDOWS_BAT,
        platform: 'windows',
        arch: 'batch',
        appId,
        name: entryName,
        version: '1.0.0',
        entryPoint: entryName,
        permissions: ['documentsLibrary', 'documentsLibraryWrite'],
        intents: [],
        sectionsOrClasses: [],
        importsOrMethods: [],
        rawMetadata: {
          scriptKind,
          lineCount: text.split(/\r?\n/).length,
        },
      };
    }

    // Fallback: if buffer starts with MZ (corrupt PE) or OLE CFBF (corrupt MSI), parse to throw specific FormatError!
    if (bytes.byteLength >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
      parsePe(bytes);
    }
    if (bytes.byteLength >= 8 && bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0) {
      parseMsi(bytes);
    }

    throw new FormatError(`Unsupported Windows package format: "${fmt}"`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format: fmt,
    });
  }

  installPackage(inspection, buffer, services) {
    void buffer;
    this._ensureCpuRegistered(services?.cpuRegistry);
    return {
      appId: inspection.appId,
      name: inspection.name,
      platform: 'windows',
      format: inspection.format,
      arch: inspection.arch,
      version: inspection.version,
      entryPoint: inspection.entryPoint,
      permissions: inspection.permissions ?? [],
      intents: inspection.intents ?? [],
      metadata: {
        ...(inspection.rawMetadata ?? {}),
      },
    };
  }

  createExecutionContext(pcb, appRecord, services = {}, launchOptions = {}) {
    this._ensureCpuRegistered(services.cpuRegistry);

    let packageBytes = null;
    if (launchOptions?.packageBytes instanceof Uint8Array) {
      packageBytes = launchOptions.packageBytes;
    } else if (services.vfs && appRecord?.installDir) {
      // CRITICAL Landmine #2: Read .package.bin as root ({ uid: 0, gid: 0 })!
      const pkgPath = `${appRecord.installDir}/.package.bin`;
      const raw = services.vfs.readFile(pkgPath, { uid: 0, gid: 0 });
      packageBytes = toBytes(raw);
    }

    if (!packageBytes) {
      throw new OmniOSError(`Cannot load Windows package bytes for ${appRecord?.appId ?? pcb?.name}`, {
        code: ERROR_CODES.ENOENT,
      });
    }

    const fmt = appRecord?.format ?? detectFormat(packageBytes, appRecord?.entryPoint || '').format;

    // 1. Batch script (.bat / .cmd)
    if (fmt === PACKAGE_FORMATS.WINDOWS_BAT) {
      const scriptText = UTF8_DECODER.decode(packageBytes);
      const entry = appRecord?.entryPoint || appRecord?.name || 'script.bat';
      const scriptKind =
        appRecord?.metadata?.scriptKind ??
        (String(entry).toLowerCase().endsWith('.cmd') ? 'cmd' : 'bat');
      return createBatchExecutionContext({
        scriptText,
        scriptKind,
        scriptName: entry,
        pcb,
        appRecord,
        services,
        args: launchOptions?.args ?? pcb?.args ?? [],
        env: launchOptions?.env ?? pcb?.env ?? {},
      });
    }

    // 2. MSIX / APPX -> extract inner executable (.exe or .bat/.cmd) and execute genuinely!
    if (fmt === PACKAGE_FORMATS.WINDOWS_MSIX) {
      const msix = parseMsix(packageBytes);
      const targetExe = (appRecord?.entryPoint || msix.executable || '').replace(/\\/g, '/').replace(/^\/+/, '');
      let entryBytes = null;
      let resolvedName = targetExe;
      for (const [name, data] of msix.files.entries()) {
        if (name.toLowerCase() === targetExe.toLowerCase()) {
          entryBytes = data;
          resolvedName = name;
          break;
        }
      }
      if (!entryBytes) {
        // Fallback: find first .exe inside package
        for (const [name, data] of msix.files.entries()) {
          if (name.toLowerCase().endsWith('.exe')) {
            entryBytes = data;
            resolvedName = name;
            break;
          }
        }
      }
      if (!entryBytes) {
        throw new FormatError(`MSIX executable "${targetExe}" not found inside package`, {
          code: ERROR_CODES.E_INVALID_MSIX,
          format: 'windows-msix',
        });
      }
      if (/\.(bat|cmd)$/i.test(resolvedName)) {
        return createBatchExecutionContext({
          scriptText: UTF8_DECODER.decode(entryBytes),
          scriptKind: resolvedName.toLowerCase().endsWith('.cmd') ? 'cmd' : 'bat',
          scriptName: resolvedName,
          pcb,
          appRecord,
          services,
          args: launchOptions?.args ?? pcb?.args ?? [],
          env: launchOptions?.env ?? pcb?.env ?? {},
        });
      }
      const pe = parsePe(entryBytes);
      return buildPeExecutionContext({ pe, pcb, appRecord, services, launchOptions });
    }

    // 3. PE32 / PE32+ (.exe / .dll)
    if (fmt === PACKAGE_FORMATS.WINDOWS_PE) {
      const pe = parsePe(packageBytes);
      return buildPeExecutionContext({ pe, pcb, appRecord, services, launchOptions });
    }

    // 4. MSI OLE CFBF package -> inspect streams & emit installer metadata summary synchronously
    if (fmt === PACKAGE_FORMATS.WINDOWS_MSI) {
      const msi = parseMsi(packageBytes);
      let done = false;
      return {
        arch: appRecord?.arch ?? 'x86_64',
        step() {
          if (done) return { status: 'EXITED', exitCode: 0, instructionsExecuted: 0 };
          done = true;
          const summary = JSON.stringify({
            format: 'windows-msi',
            cfbfVersion: msi.version,
            summaryInfo: msi.summaryInfo,
            streams: msi.streamNames,
          });
          services.processManager?.writeStdout?.(pcb.pid, `${summary}\n`);
          return { status: 'EXITED', exitCode: 0, instructionsExecuted: 1 };
        },
        deliverEvent() {
          // MSI inspection runner has no interactive UI events
        },
        getDebugState() {
          return {
            arch: 'msi',
            pc: done ? 'done' : 'start',
            sp: '0x0',
            registers: {},
            instructionsExecuted: done ? 1 : 0,
            lastSyscall: 'msi_inspect',
            stackTop: [],
          };
        },
        dispose() {
          done = true;
        },
      };
    }

    throw new FormatError(`WindowsRuntime cannot execute format "${fmt}"`, {
      code: ERROR_CODES.ENOTSUP,
      format: fmt,
    });
  }
}

export function createWindowsRuntime(opts = {}) {
  return new WindowsRuntime(opts);
}
