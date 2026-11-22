/**
 * OmniOS iOS Platform Runtime (`IOSRuntime`, `F-053`)
 * Zero external dependencies, zero `node:fs` imports.
 *
 * Implements Contract 5 `IPlatformRuntime` (`platform = 'ios'`, `arch = 'arm64'`):
 * - `inspectPackage`: parses `.ipa` ZIP, `Info.plist`, Mach-O (FairPlay rejected), TCC perms & flat intents
 * - `installPackage`: provisions deterministic RFC 4122 UUID sandbox container `/var/appdata/ios/<UUID>`
 *   with `Documents`, `Library`, `Library/Preferences`, `Library/Caches`, `tmp`
 * - `createExecutionContext`: loads ARM64 Mach-O into M1 VMM (`__PAGEZERO` guard, dyld binds, ObjC ABI2),
 *   wires `ARM64Cpu`, `DarwinSyscallLayer` (jailed + sync `PermissionBroker`), `ObjCRuntime`, and `UIKitBridge`
 *   into a strictly synchronous `IExecutionContext`.
 */

import crypto from 'node:crypto';
import { FormatError, OmniOSError, ERROR_CODES } from '../../common/errors.mjs';
import { createArm64Cpu } from '../../cpu/arm64.mjs';
import { parseMachO, loadMachOIntoAddressSpace } from '../apple/macho-parser.mjs';
import { createDarwinSyscalls } from '../apple/darwin-syscalls.mjs';
import { createObjCRuntime } from '../apple/objc-runtime.mjs';
import { parseIpa } from './ipa-parser.mjs';
import { createUIKitBridge } from './uikit-bridge.mjs';

const ROOT_VFS_CTX = Object.freeze({ uid: 0, gid: 0 });
const TEXT_ENCODER = new TextEncoder();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Derive a deterministic RFC 4122 v5-format uppercase UUID from an iOS bundle identifier.
 */
export function deriveIosContainerUuid(appId) {
  const hash = crypto.createHash('sha256').update(`omnios:ios:container:${String(appId)}`).digest();
  const bytes = Uint8Array.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant 1
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function writeGuestCStringOnStack(addressSpace, sp, str) {
  const encoded = TEXT_ENCODER.encode(String(str ?? ''));
  const len = encoded.byteLength + 1;
  const nextSp = sp - BigInt(len);
  const buf = new Uint8Array(len);
  buf.set(encoded, 0);
  buf[len - 1] = 0;
  addressSpace.write(nextSp, buf);
  return nextSp;
}

/**
 * Populate guest stack with Darwin ARM64 `argc`, `argv`, `envp` keeping SP 16-byte aligned.
 */
function setupGuestMainArgs(addressSpace, initialSP, executableName, args = [], env = {}) {
  let sp = BigInt(initialSP);
  const argvList = [executableName || 'app', ...args.map((a) => String(a))];
  const envList = Object.entries(env || {}).map(([k, v]) => `${k}=${v}`);

  const argvPtrs = [];
  for (let i = argvList.length - 1; i >= 0; i--) {
    sp = writeGuestCStringOnStack(addressSpace, sp, argvList[i]);
    argvPtrs.unshift(sp);
  }

  const envPtrs = [];
  for (let i = envList.length - 1; i >= 0; i--) {
    sp = writeGuestCStringOnStack(addressSpace, sp, envList[i]);
    envPtrs.unshift(sp);
  }

  // Align down to 16 bytes before pushing pointer arrays
  sp = sp - (sp % 16n);

  const totalPtrSlots = argvPtrs.length + 1 + envPtrs.length + 1;
  const tableBytes = BigInt(((totalPtrSlots * 8 + 15) & ~15));
  sp -= tableBytes;

  const argvAddr = sp;
  let cursor = sp;
  for (const p of argvPtrs) {
    addressSpace.writeU64(cursor, p, true);
    cursor += 8n;
  }
  addressSpace.writeU64(cursor, 0n, true);
  cursor += 8n;

  const envpAddr = cursor;
  for (const p of envPtrs) {
    addressSpace.writeU64(cursor, p, true);
    cursor += 8n;
  }
  addressSpace.writeU64(cursor, 0n, true);

  return {
    sp,
    argc: BigInt(argvPtrs.length),
    argv: argvAddr,
    envp: envpAddr,
  };
}

class IOSExecutionContext {
  constructor({
    pcb,
    appRecord,
    services,
    cpu,
    loadedMachO,
    darwinSyscalls,
    objcRuntime,
    uikitBridge,
    containerUuid,
    sandboxRoot,
  }) {
    this.pcb = pcb;
    this.appRecord = appRecord;
    this.services = services;
    this.cpu = cpu;
    this.loadedMachO = loadedMachO;
    this.darwinSyscalls = darwinSyscalls;
    this.objcRuntime = objcRuntime;
    this.uikitBridge = uikitBridge;
    this.containerUuid = containerUuid;
    this.sandboxRoot = sandboxRoot;

    this._eventQueue = [];
    this._exited = false;
    this._exitCode = 0;
    this._disposed = false;
  }

  /**
   * Strictly SYNCHRONOUS step(budget) per M1 Scheduler Contract 5.
   * Never returns a Promise and never reports instructionsExecuted > budget.
   */
  step(budget = 4096) {
    if (this._disposed || this._exited) {
      return { status: 'EXITED', instructionsExecuted: 0, exitCode: this._exitCode };
    }
    if (this.darwinSyscalls.hasExited) {
      this._exited = true;
      this._exitCode = this.darwinSyscalls.exitCode;
      return { status: 'EXITED', instructionsExecuted: 0, exitCode: this._exitCode };
    }
    if (this.cpu.halted) {
      this._exited = true;
      this._exitCode = this.cpu.exitCode ?? 0;
      return { status: 'EXITED', instructionsExecuted: 0, exitCode: this._exitCode };
    }
    if (this.uikitBridge.shouldExit) {
      this._exited = true;
      this._exitCode = this.uikitBridge.exitCode;
      return { status: 'EXITED', instructionsExecuted: 0, exitCode: this._exitCode };
    }

    const effectiveBudget =
      typeof budget === 'number' && Number.isFinite(budget) && budget >= 1
        ? Math.floor(budget)
        : 1;

    // Case 1: UIKit event loop is active
    if (this.uikitBridge.runLoopActive) {
      if (this._eventQueue.length === 0) {
        return {
          status: 'BLOCKED',
          instructionsExecuted: 0,
          waitReason: this.uikitBridge.isSuspended ? 'suspended' : 'ui_event',
        };
      }

      let executed = 0;
      while (this._eventQueue.length > 0 && executed < effectiveBudget) {
        const ev = this._eventQueue.shift();
        const before = this.cpu.instructionsExecuted;
        const outcome = this.uikitBridge.handleEvent(this.cpu, ev);
        const delta = Math.max(1, this.cpu.instructionsExecuted - before);
        executed += delta;

        if (
          outcome?.exited ||
          this.uikitBridge.shouldExit ||
          this.darwinSyscalls.hasExited ||
          this.cpu.halted
        ) {
          this._exited = true;
          this._exitCode = this.darwinSyscalls.hasExited
            ? this.darwinSyscalls.exitCode
            : this.cpu.halted
              ? (this.cpu.exitCode ?? 0)
              : this.uikitBridge.shouldExit
                ? this.uikitBridge.exitCode
                : (outcome?.exitCode ?? 0);
          return {
            status: 'EXITED',
            instructionsExecuted: Math.min(executed, effectiveBudget),
            exitCode: this._exitCode,
          };
        }
      }

      const clampedExec = Math.min(executed, effectiveBudget);
      if (this._eventQueue.length > 0) {
        return { status: 'YIELD', instructionsExecuted: clampedExec };
      }
      return {
        status: 'BLOCKED',
        instructionsExecuted: clampedExec,
        waitReason: this.uikitBridge.isSuspended ? 'suspended' : 'ui_event',
      };
    }

    // Case 2: Executing guest ARM64 code from entryVA (e.g., _main -> _UIApplicationMain or CLI binary)
    const res = this.cpu.step(effectiveBudget);
    const executed = Math.min(res.instructionsExecuted ?? 0, effectiveBudget);

    if (res.status === 'FAULT') {
      return { status: 'FAULT', instructionsExecuted: executed, fault: res.fault };
    }

    if (
      this.darwinSyscalls.hasExited ||
      this.uikitBridge.shouldExit ||
      res.status === 'EXITED' ||
      this.cpu.halted
    ) {
      this._exited = true;
      this._exitCode = this.darwinSyscalls.hasExited
        ? this.darwinSyscalls.exitCode
        : this.cpu.halted
          ? (this.cpu.exitCode ?? 0)
          : this.uikitBridge.shouldExit
            ? this.uikitBridge.exitCode
            : (res.exitCode ?? 0);
      return {
        status: 'EXITED',
        instructionsExecuted: executed,
        exitCode: this._exitCode,
      };
    }

    if (res.status === 'BLOCKED' || this.uikitBridge.runLoopActive) {
      if (this._eventQueue.length > 0) {
        return { status: 'YIELD', instructionsExecuted: executed };
      }
      return {
        status: 'BLOCKED',
        instructionsExecuted: executed,
        waitReason: this.uikitBridge.isSuspended ? 'suspended' : (res.waitReason ?? 'ui_event'),
      };
    }

    return { status: 'YIELD', instructionsExecuted: executed };
  }

  deliverEvent(event) {
    if (
      this._disposed ||
      this._exited ||
      this.darwinSyscalls.hasExited ||
      this.uikitBridge.shouldExit ||
      this.cpu.halted ||
      !event ||
      typeof event !== 'object'
    ) {
      return;
    }
    this._eventQueue.push(event);

    // Ensure process wakes when events (such as SpringBoard lifecycle events) are delivered directly
    const pm = this.services?.processManager;
    if (pm && this.pcb && this.pcb.state === 'BLOCKED' && typeof pm.wake === 'function') {
      try {
        pm.wake(this.pcb.pid);
      } catch {
        // Ignore if already awake or terminated
      }
    }
  }

  getDebugState() {
    const cpuState = typeof this.cpu.getDebugState === 'function' ? this.cpu.getDebugState() : {};
    return {
      ...cpuState,
      arch: 'arm64',
      platform: 'ios',
      appId: this.appRecord?.appId ?? this.pcb?.appId ?? null,
      containerUuid: this.containerUuid,
      sandboxRoot: this.sandboxRoot,
      windowId: this.uikitBridge.windowId,
      lifecycleState: this.uikitBridge.lifecycleState,
      isSuspended: this.uikitBridge.isSuspended,
      runLoopActive: this.uikitBridge.runLoopActive,
      queuedEvents: this._eventQueue.length,
      lastSyscall: this.darwinSyscalls.lastSyscall,
      syscallCount: this.darwinSyscalls.syscallCount,
      logs: this.objcRuntime.logs.slice(-20),
      liveActivities: Array.from(this.uikitBridge.liveActivities.values()),
    };
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    this._eventQueue.length = 0;
    try {
      this.uikitBridge.dispose();
    } catch {
      // Isolate disposal errors
    }
    try {
      this.objcRuntime.dispose();
    } catch {
      // Isolate disposal errors
    }
    try {
      this.darwinSyscalls.dispose();
    } catch {
      // Isolate disposal errors
    }
    try {
      this.cpu.dispose();
    } catch {
      // Isolate disposal errors
    }
  }
}

export class IOSRuntime {
  constructor(opts = {}) {
    this.platform = 'ios';
    this.arch = 'arm64';
    this._opts = opts;
  }

  /**
   * Contract 5: Inspect an iOS `.ipa` package and return exact `PackageManager` inspection metadata.
   */
  inspectPackage(bytes, _filenameHint = '', _detection = null) {
    const parsed = parseIpa(bytes);
    return {
      format: 'ios-ipa',
      platform: 'ios',
      arch: parsed.arch || 'arm64',
      appId: parsed.bundleId,
      name: parsed.name,
      version: parsed.version,
      entryPoint: parsed.executableName,
      permissions: parsed.permissions,
      intents: parsed.intents,
      sectionsOrClasses: parsed.sectionsOrClasses,
      importsOrMethods: parsed.importsOrMethods,
      rawMetadata: {
        infoPlist: parsed.infoPlist,
        bundleName: parsed.bundleName,
        bundleDir: parsed.bundleDir,
        executableName: parsed.executableName,
        executablePath: parsed.executablePath,
        infoPlistPath: parsed.infoPlistPath,
        buildVersion: parsed.buildVersion,
        entitlements: parsed.entitlements,
        urlSchemes: parsed.urlSchemes,
        documentTypes: parsed.documentTypes,
        supportsLiveActivities: parsed.supportsLiveActivities,
        dylibs: parsed.macho.dylibs.map((d) => d.name),
      },
    };
  }

  /**
   * Contract 5: Provision iOS UUID sandbox container (`/var/appdata/ios/<UUID>`) and subdirs.
   */
  async installPackage(inspection, _bytes, services = {}) {
    const appId = inspection.appId;
    const vfs = services?.vfs ?? null;

    // Preserve existing containerUuid on upgrade if present, otherwise derive deterministic RFC 4122 UUID
    let containerUuid = null;
    const rawUuid = inspection.rawMetadata?.containerUuid;
    if (typeof rawUuid === 'string' && UUID_RE.test(rawUuid)) {
      containerUuid = rawUuid.toUpperCase();
    } else if (services?.pkgManager && typeof services.pkgManager.get === 'function') {
      try {
        const existing = services.pkgManager.get(appId);
        const existingUuid = existing?.metadata?.containerUuid;
        if (typeof existingUuid === 'string' && UUID_RE.test(existingUuid)) {
          containerUuid = existingUuid.toUpperCase();
        }
      } catch {
        // Ignore lookup error on fresh install
      }
    }
    if (!containerUuid) {
      containerUuid = deriveIosContainerUuid(appId);
    }

    const dataDir = `/var/appdata/ios/${containerUuid}`;
    const uid = typeof inspection.uid === 'number' ? inspection.uid : 10000;
    const gid = typeof inspection.gid === 'number' ? inspection.gid : uid;

    if (vfs) {
      await vfs.mkdir('/var/appdata/ios', { recursive: true, mode: 0o755, ...ROOT_VFS_CTX });
      await vfs.mkdir(dataDir, { recursive: true, mode: 0o700, ...ROOT_VFS_CTX });
      if (typeof vfs.chown === 'function') {
        await vfs.chown(dataDir, uid, gid, { ...ROOT_VFS_CTX });
      }

      const subdirs = [
        `${dataDir}/Documents`,
        `${dataDir}/Library`,
        `${dataDir}/Library/Preferences`,
        `${dataDir}/Library/Caches`,
        `${dataDir}/tmp`,
      ];
      for (const dir of subdirs) {
        await vfs.mkdir(dir, { recursive: true, mode: 0o755, ...ROOT_VFS_CTX });
        if (typeof vfs.chown === 'function') {
          await vfs.chown(dir, uid, gid, { ...ROOT_VFS_CTX });
        }
      }
    }

    return {
      ...inspection,
      dataDir,
      metadata: {
        ...(inspection.rawMetadata ?? {}),
        containerUuid,
        iosContainerPath: `/var/mobile/Containers/Data/Application/${containerUuid}`,
      },
    };
  }

  /**
   * Contract 5: Load ARM64 Mach-O binary into PCB VMM and create synchronous `IOSExecutionContext`.
   */
  async createExecutionContext(pcb, appRecord, services = {}, launchOptions = {}) {
    const vfs = services?.vfs ?? null;
    if (!vfs) {
      throw new OmniOSError('IOSRuntime requires VFS service to load installed IPA executable', {
        code: ERROR_CODES.EINVAL,
      });
    }

    const meta = appRecord.metadata ?? {};
    const executablePath =
      meta.executablePath ||
      (meta.bundleDir && appRecord.entryPoint ? `${meta.bundleDir}/${appRecord.entryPoint}` : null);
    if (!executablePath) {
      throw new FormatError(`iOS app "${appRecord.appId}" is missing metadata.executablePath`, {
        code: ERROR_CODES.ENOENT,
        format: 'ios-ipa',
      });
    }

    const fullExecVfsPath = `${appRecord.installDir}/${executablePath}`;
    // CRITICAL: Must read from installDir using root VFS context `{ uid: 0, gid: 0 }`
    // because strictSandbox confines the app's own UID strictly to its UUID dataDir!
    const execBytes = await vfs.readFile(fullExecVfsPath, { ...ROOT_VFS_CTX });

    // Parse Mach-O (enforces FairPlay cryptid === 0 -> E_ENCRYPTED_BINARY!)
    const parsedMachO = parseMachO(execBytes, { preferredArch: 'arm64', allowEncrypted: false });
    if (parsedMachO.arch !== 'arm64' && parsedMachO.arch !== 'arm64_32') {
      throw new FormatError(`iOS runtime requires ARM64 Mach-O binary, found arch="${parsedMachO.arch}"`, {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'ios-ipa',
      });
    }

    const containerUuid =
      (typeof meta.containerUuid === 'string' && meta.containerUuid.length > 0
        ? meta.containerUuid
        : null) ||
      (typeof appRecord.dataDir === 'string' && appRecord.dataDir.startsWith('/var/appdata/ios/')
        ? appRecord.dataDir.slice('/var/appdata/ios/'.length).split('/')[0]
        : null) ||
      deriveIosContainerUuid(appRecord.appId);

    const sandboxRoot = appRecord.dataDir || `/var/appdata/ios/${containerUuid}`;
    if (!pcb.cwd || !pcb.cwd.startsWith(sandboxRoot)) {
      pcb.cwd = sandboxRoot;
    }

    // Strictly SYNCHRONOUS permission broker for shared /var/mobile/Documents -> /home/user/Documents
    // ONLY allows access under UID 1000 when PermissionBroker has an explicit 'allow' grant!
    const permissionBroker = (req) => {
      if (!services?.permissions || typeof services.permissions.getGrant !== 'function') {
        return { allowed: false };
      }
      const canonical = String(req?.canonicalPath ?? '');
      const isSharedDocs =
        canonical === '/home/user/Documents' || canonical.startsWith('/home/user/Documents/');
      if (!isSharedDocs) {
        return { allowed: false };
      }
      try {
        const grant = services.permissions.getGrant(appRecord.appId, req.capability);
        if (grant && grant.state === 'allow') {
          return {
            allowed: true,
            effectiveCtx: {
              uid: 1000,
              gid: 1000,
              sandboxRoot: '/home/user/Documents',
            },
          };
        }
      } catch {
        // Fail closed on any broker error
      }
      return { allowed: false };
    };

    const bundleDir = meta.bundleDir || `Payload/${meta.bundleName || 'App'}.app`;
    const bundlePath = `${appRecord.installDir}/${bundleDir}`;

    // 1. Lazily create ObjCRuntime & UIKitBridge on the first symbol bind (AFTER Step 1 of
    //    `loadMachOIntoAddressSpace` has reserved `__PAGEZERO` 0..0x100000000 so `AddressSpace.alloc()`
    //    places the ObjC heap cleanly at HIGH_VA_HEAP_BASE = 0x200000000 above __PAGEZERO!).
    let objcRuntime = null;
    let uikitBridge = null;
    const ensureObjCAndUIKit = () => {
      if (objcRuntime) return objcRuntime;
      objcRuntime = createObjCRuntime({
        addressSpace: pcb.addressSpace,
        vfs,
        configStore: services.configStore ?? null,
        processManager: services.processManager ?? null,
        pcb,
        platform: 'ios',
        appId: appRecord.appId,
        bundleInfo: meta.infoPlist ?? { CFBundleIdentifier: appRecord.appId },
        bundlePath,
        containerUuid,
        sandboxRoot,
        cwd: pcb.cwd,
        uid: pcb.uid,
        gid: pcb.gid,
        permissionBroker,
      });

      uikitBridge = createUIKitBridge({
        objcRuntime,
        addressSpace: pcb.addressSpace,
        compositor: services.compositor ?? null,
        notifications: services.notifications ?? null,
        clipboard: services.clipboard ?? null,
        intentRouter: services.intentRouter ?? null,
        configStore: services.configStore ?? null,
        vfs,
        permissions: services.permissions ?? null,
        processManager: services.processManager ?? null,
        pcb,
        appRecord,
        infoPlist: meta.infoPlist ?? {},
        launchOptions,
      });
      return objcRuntime;
    };

    // 2. Load Mach-O into M1 VMM (Step 1 reserves __PAGEZERO guard, then Step 4 binds ObjC classes & thunks)
    const loadedMachO = loadMachOIntoAddressSpace(parsedMachO, pcb.addressSpace, {
      slide: 0,
      resolveSymbol: (symbolName) => ensureObjCAndUIKit().resolveMachOSymbol(symbolName),
    });

    ensureObjCAndUIKit();

    if (loadedMachO.entryVA === null || loadedMachO.entryVA === undefined) {
      throw new FormatError(`iOS Mach-O executable "${executablePath}" has no LC_MAIN or _main entry point`, {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'ios-ipa',
      });
    }

    // 3. Parse Mach-O ObjC ABI2 sections (__objc_classlist, __objc_selrefs, __cfstring)
    objcRuntime.loadMachOObjC(loadedMachO);

    // 4. Create Darwin/XNU BSD syscall layer strictly jailed to UUID sandboxRoot
    const darwinSyscalls = createDarwinSyscalls({
      pcb,
      addressSpace: pcb.addressSpace,
      vfs,
      processManager: services.processManager ?? null,
      platform: 'ios',
      arch: 'arm64',
      appId: appRecord.appId,
      containerUuid,
      sandboxRoot,
      cwd: pcb.cwd,
      pid: pcb.pid,
      ppid: pcb.ppid ?? 1,
      uid: pcb.uid,
      gid: pcb.gid,
      permissionBroker,
    });

    // 5. Instantiate ARM64 CPU via CpuRegistry when registered, otherwise createArm64Cpu
    const cpuOpts = {
      addressSpace: pcb.addressSpace,
      pid: pcb.pid,
      maxInstructions: pcb.quotas?.maxTotalInstructions ?? Infinity,
      thunkStart: loadedMachO.thunkBase,
      thunkEnd: loadedMachO.thunkBase + loadedMachO.thunkSize,
      exitSentinelVA: loadedMachO.exitSentinelVA,
      onSyscall: (cpuInst, imm16) => darwinSyscalls.handleArm64Svc(cpuInst, imm16),
      onThunk: (pc, cpuInst) => {
        const entry = loadedMachO.thunkTable.get(Number(pc));
        if (!entry) return false;
        const handled = objcRuntime.handleThunk(entry.symbol, cpuInst);
        if (handled) return handled;
        // Unknown optional framework stub returns 0n cleanly without crashing
        cpuInst.setReg(0, 0n);
        return true;
      },
    };

    const cpu =
      services?.cpuRegistry && typeof services.cpuRegistry.has === 'function' && services.cpuRegistry.has('arm64')
        ? services.cpuRegistry.create('arm64', cpuOpts)
        : createArm64Cpu(cpuOpts);

    // 6. Initialize ARM64 entry state (16-byte aligned SP with argc/argv/envp, LR = exitSentinelVA)
    const stackArgs = setupGuestMainArgs(
      pcb.addressSpace,
      loadedMachO.initialSP,
      appRecord.entryPoint || meta.executableName || 'app',
      launchOptions?.args ?? pcb.args ?? [],
      launchOptions?.env ?? pcb.env ?? {}
    );

    cpu.setSP(stackArgs.sp);
    cpu.setPC(loadedMachO.entryVA);
    cpu.setLR(loadedMachO.exitSentinelVA);
    cpu.setReg(0, stackArgs.argc);
    cpu.setReg(1, stackArgs.argv);
    cpu.setReg(2, stackArgs.envp);

    uikitBridge.setCpu(cpu);
    if (typeof uikitBridge.setDarwinSyscalls === 'function') {
      uikitBridge.setDarwinSyscalls(darwinSyscalls);
    }

    return new IOSExecutionContext({
      pcb,
      appRecord,
      services,
      cpu,
      loadedMachO,
      darwinSyscalls,
      objcRuntime,
      uikitBridge,
      containerUuid,
      sandboxRoot,
    });
  }
}

export function createIOSRuntime(opts = {}) {
  return new IOSRuntime(opts);
}
