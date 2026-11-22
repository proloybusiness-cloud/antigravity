/**
 * OmniOS Objective-C ABI2 & Swift Runtime Bridge (`F-052`, Edge Cases `#24`, `#26`)
 * Shared across iOS & macOS runtimes — zero external dependencies, zero `node:fs` imports.
 *
 * Key Guarantees:
 * - Parses real Mach-O ObjC ABI2 sections (`__objc_classlist`, `__objc_selrefs`, `__objc_classrefs`,
 *   `__objc_superrefs`, `__objc_methname`, `__objc_const`, `__objc_data`, `__cfstring`).
 * - Edge Case #26: `objc_msgSend(0n, ...)` and `objc_msgSendSuper2` with `nil` receiver ALWAYS
 *   return `0n` safely without faulting or invoking any method.
 * - Real ARC refcounting (`objc_retain`/`release`/`autorelease`/`autoreleasePoolPush`/`Pop`/
 *   `objc_storeStrong`/`objc_alloc`/`objc_alloc_init`/`objc_opt_new`) with real VMM heap
 *   allocation and freeing on refcount 0 (`free(0n)` strictly guarded as a safe no-op!).
 * - Foundation classes (`NSObject`, `NSString`/`NSMutableString`, `NSNumber`, `NSArray`/`NSMutableArray`,
 *   `NSDictionary`/`NSMutableDictionary`, `NSData`/`NSMutableData`, `NSUserDefaults` backed live by
 *   `configStore.defaults`, `NSFileManager` backed live by `vfs`, `NSURL`, `NSBundle`, `NSProcessInfo`).
 * - Apple ARM64 ABI variadics (`NSLog`, `printf`, `snprintf`, `+[NSString stringWithFormat:]`)
 *   read strictly from 8-byte stack slots `[SP + i * 8]` via `cpu.readVariadicArgs()` (Edge Case #24).
 * - Swift runtime & `swiftcall` (`X20`/`R13` self, `X21`/`R12` swifterror, `swift_allocObject`,
 *   `swift_retain`, `swift_release`, `swift_bridgeObjectRetain`, `swift_bridgeObjectRelease`).
 */

import { MemoryFaultError, ERROR_CODES } from '../../common/errors.mjs';

const TEXT_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const UTF16LE_DECODER = new TextDecoder('utf-16le', { fatal: false });

const MEM_CHUNK_BYTES = 65536;
const ZERO_CHUNK = new Uint8Array(MEM_CHUNK_BYTES);
const MAX_MARSHAL_DEPTH = 64;

const F64_BUF = new ArrayBuffer(8);
const F64_VIEW = new DataView(F64_BUF);

function bitsToF64(u64) {
  F64_VIEW.setBigUint64(0, BigInt.asUintN(64, u64), true);
  return F64_VIEW.getFloat64(0, true);
}

function f64ToBits(f) {
  F64_VIEW.setFloat64(0, f, true);
  return F64_VIEW.getBigUint64(0, true);
}

function f32ToBits(f) {
  F64_VIEW.setFloat32(0, Math.fround(f), true);
  return BigInt(F64_VIEW.getUint32(0, true));
}

function toBigIntPtr(val) {
  if (val === null || val === undefined) return 0n;
  if (typeof val === 'bigint') return BigInt.asUintN(64, val);
  if (typeof val === 'number') return BigInt.asUintN(64, BigInt(Math.trunc(val)));
  return 0n;
}

function stripLeadingUnderscore(sym) {
  const s = String(sym ?? '');
  return s.startsWith('_') ? s.slice(1) : s;
}

function countSelectorArgs(selName) {
  let count = 0;
  for (let i = 0; i < selName.length; i++) {
    if (selName.charCodeAt(i) === 58) count++; // ':'
  }
  return count;
}

function isArm64Cpu(cpu) {
  if (!cpu) return true;
  return cpu.arch === 'arm64' || typeof cpu.readVariadicArgs === 'function';
}

function getX64NamedReg(cpu, name) {
  if (!cpu) return 0n;
  if (typeof cpu.getReg64 === 'function') {
    return BigInt.asUintN(64, BigInt(cpu.getReg64(name)));
  }
  if (typeof cpu.getReg === 'function') {
    return BigInt.asUintN(64, BigInt(cpu.getReg(name)));
  }
  if (cpu.regs && name in cpu.regs) {
    return BigInt.asUintN(64, BigInt(cpu.regs[name]));
  }
  if (name in cpu) {
    return BigInt.asUintN(64, BigInt(cpu[name]));
  }
  return 0n;
}

function setX64NamedReg(cpu, name, val) {
  if (!cpu) return;
  const v = BigInt.asUintN(64, typeof val === 'bigint' ? val : BigInt(Math.trunc(val ?? 0)));
  if (typeof cpu.setReg64 === 'function') {
    cpu.setReg64(name, v);
  } else if (typeof cpu.setReg === 'function') {
    cpu.setReg(name, v);
  } else if (cpu.regs && name in cpu.regs) {
    cpu.regs[name] = v;
  } else if (name in cpu) {
    cpu[name] = v;
  }
}

function getCpuArg(cpu, addrSpace, index) {
  if (isArm64Cpu(cpu)) {
    if (index < 8) return cpu.getReg(index);
    return addrSpace.readU64(cpu.getSP() + BigInt((index - 8) * 8), true);
  }
  const sysvRegs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'];
  if (index < 6) {
    return getX64NamedReg(cpu, sysvRegs[index]);
  }
  const rsp = getX64NamedReg(cpu, 'rsp');
  return addrSpace.readU64(rsp + BigInt(8 + (index - 6) * 8), true);
}

function setCpuReturn(cpu, value) {
  if (!cpu) return;
  const v = BigInt.asUintN(64, typeof value === 'bigint' ? value : BigInt(Math.trunc(value ?? 0)));
  if (isArm64Cpu(cpu)) {
    cpu.setReg(0, v);
  } else {
    setX64NamedReg(cpu, 'rax', v);
  }
}

function setCpuFloatReturn(cpu, val) {
  if (!cpu) return;
  if (isArm64Cpu(cpu) && typeof cpu.setDReg === 'function') {
    cpu.setDReg(0, val);
  } else if (typeof cpu.setXmmDouble === 'function') {
    cpu.setXmmDouble(0, val);
  } else if (typeof cpu.setXmmF64 === 'function') {
    cpu.setXmmF64(0, val, false);
  }
}

function getCpuFloatArg(cpu, index) {
  if (!cpu) return 0;
  if (isArm64Cpu(cpu) && typeof cpu.getDReg === 'function') {
    return cpu.getDReg(index);
  }
  if (typeof cpu.getXmmDouble === 'function') {
    return cpu.getXmmDouble(index);
  }
  if (typeof cpu.getXmmF64 === 'function') {
    return cpu.getXmmF64(index);
  }
  return 0;
}

function setCpuSingleFloatReturn(cpu, val) {
  if (!cpu) return;
  const f32 = Math.fround(val);
  if (typeof cpu.setSReg === 'function') {
    cpu.setSReg(0, f32);
  } else if (typeof cpu.setXmmF32 === 'function') {
    cpu.setXmmF32(0, f32, false);
  } else {
    setCpuFloatReturn(cpu, f32);
  }
}

function getCpuSingleFloatArg(cpu, index) {
  if (!cpu) return 0;
  if (typeof cpu.getSReg === 'function') {
    return cpu.getSReg(index);
  }
  if (typeof cpu.getXmmF32 === 'function') {
    return cpu.getXmmF32(index);
  }
  return Math.fround(getCpuFloatArg(cpu, index));
}

function readCpuVariadicArgs(cpu, addrSpace, fixedCount, count) {
  if (count <= 0) return [];
  if (isArm64Cpu(cpu)) {
    // Edge Case #24: Apple ARM64 ABI — read variadic args STRICTLY from [SP + i * 8]!
    return cpu.readVariadicArgs(fixedCount, count);
  }
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push(getCpuArg(cpu, addrSpace, fixedCount + i));
  }
  return out;
}

function countFormatSpecifiers(fmt) {
  const specs = [];
  for (let i = 0; i < fmt.length; i++) {
    if (fmt[i] !== '%') continue;
    if (i + 1 < fmt.length && fmt[i + 1] === '%') {
      i++;
      continue;
    }
    let j = i + 1;
    // Flags
    while (j < fmt.length && '-+ #0'.includes(fmt[j])) j++;
    // Width
    if (j < fmt.length && fmt[j] === '*') {
      specs.push({ kind: 'width' });
      j++;
    } else {
      while (j < fmt.length && fmt[j] >= '0' && fmt[j] <= '9') j++;
    }
    // Precision
    if (j < fmt.length && fmt[j] === '.') {
      j++;
      if (j < fmt.length && fmt[j] === '*') {
        specs.push({ kind: 'prec' });
        j++;
      } else {
        while (j < fmt.length && fmt[j] >= '0' && fmt[j] <= '9') j++;
      }
    }
    // Length modifiers
    let length = '';
    while (j < fmt.length && 'lhztjq'.includes(fmt[j])) {
      length += fmt[j++];
    }
    if (j < fmt.length) {
      specs.push({ kind: fmt[j], length, start: i, end: j + 1 });
      i = j;
    }
  }
  return specs;
}

export class ObjCRuntime {
  constructor({
    addressSpace,
    vfs = null,
    configStore = null,
    processManager = null,
    pcb = null,
    platform = 'macos',
    appId = 'com.omnios.app',
    bundleInfo = null,
    bundlePath = '/',
    containerUuid = '',
    sandboxRoot = null,
    cwd = '/home/user',
    uid = null,
    gid = null,
    permissionBroker = null,
    onLog = null,
    onStdout = null,
    onStderr = null,
  } = {}) {
    if (!addressSpace) {
      throw new TypeError('ObjCRuntime requires an M1 AddressSpace instance');
    }
    this.addressSpace = addressSpace;
    this.vfs = vfs;
    this.configStore = configStore;
    this.processManager = processManager;
    this.pcb = pcb;
    this.platform = platform;
    this.appId = appId || pcb?.appId || 'com.omnios.app';
    this.bundleInfo = bundleInfo ? { ...bundleInfo } : { CFBundleIdentifier: this.appId };
    this.bundlePath = bundlePath;
    this.containerUuid = containerUuid;
    this.sandboxRoot = sandboxRoot;
    this.cwd = cwd || pcb?.cwd || '/home/user';
    this.uid = uid ?? pcb?.uid ?? 1000;
    this.gid = gid ?? pcb?.gid ?? 1000;
    this.permissionBroker = typeof permissionBroker === 'function' ? permissionBroker : null;
    this.onLog = typeof onLog === 'function' ? onLog : null;
    this.onStdout = typeof onStdout === 'function' ? onStdout : null;
    this.onStderr = typeof onStderr === 'function' ? onStderr : null;

    this._selByName = new Map(); // string -> BigInt VA
    this._selByAddr = new Map(); // BigInt VA -> string
    this._classesByName = new Map(); // string -> ClassRecord
    this._classesByPtr = new Map(); // BigInt VA -> ClassRecord
    this._objects = new Map(); // BigInt VA -> ObjectRecord
    this._swiftObjects = new Map(); // BigInt VA -> SwiftObjectRecord
    this._heapAllocs = new Set(); // BigInt VA allocated via addressSpace.alloc
    this._cFunctions = new Map(); // normalized symbol -> fn(cpu, rt)
    this._autoreleasePools = [[]];
    this._fallbackDefaults = new Map(); // domain -> Map<key, value>
    this._singletons = new Map();
    this._loadedMachO = null;
    this.logs = [];
    this.stdoutLines = [];
    this._disposed = false;

    this._registerBuiltInFoundationClasses();
    this._registerBuiltInCFunctions();
  }

  _maxMemoryBytes() {
    const limit = this.addressSpace?.maxMemoryBytes;
    return typeof limit === 'number' && Number.isSafeInteger(limit) && limit >= 0
      ? limit
      : 64 * 1024 * 1024;
  }

  _validateAllocSize(rawSize) {
    const maxBytes = this._maxMemoryBytes();
    if (typeof rawSize === 'bigint') {
      if (rawSize < 0n || rawSize > BigInt(Number.MAX_SAFE_INTEGER) || rawSize > BigInt(maxBytes)) {
        return null;
      }
      return Number(rawSize);
    }
    if (typeof rawSize === 'number') {
      if (!Number.isFinite(rawSize) || !Number.isSafeInteger(rawSize) || rawSize < 0 || rawSize > maxBytes) {
        return null;
      }
      return rawSize;
    }
    return null;
  }

  _validateMemOpLength(rawN, opName, addr = 0n) {
    const maxBig = BigInt(this._maxMemoryBytes());
    if (rawN < 0n || rawN > maxBig) {
      throw new MemoryFaultError(`${opName} length 0x${rawN.toString(16)} exceeds VMM memory bounds`, {
        code: ERROR_CODES.EFAULT,
        signal: 'SIGSEGV',
        faultType: 'INVALID_SIZE',
        address: addr,
        pid: this.pcb?.pid ?? null,
      });
    }
    return Number(rawN);
  }

  _allocHeap(size, zero = true) {
    const validated = this._validateAllocSize(size);
    if (validated === null) {
      throw new MemoryFaultError(`Invalid or oversized heap allocation size: ${size}`, {
        code: ERROR_CODES.ENOMEM,
        signal: 'SIGSEGV',
        faultType: 'OUT_OF_MEMORY',
        pid: this.pcb?.pid ?? null,
      });
    }
    const sz = Math.max(16, validated);
    if (sz > this._maxMemoryBytes()) {
      throw new MemoryFaultError(
        `Heap allocation (${sz}) exceeds maxMemoryBytes (${this._maxMemoryBytes()})`,
        {
          code: ERROR_CODES.ENOMEM,
          signal: 'SIGSEGV',
          faultType: 'OUT_OF_MEMORY',
          pid: this.pcb?.pid ?? null,
        }
      );
    }
    const ptr = BigInt(this.addressSpace.alloc(sz));
    if (zero) {
      let offset = 0;
      while (offset < sz) {
        const chunkLen = Math.min(MEM_CHUNK_BYTES, sz - offset);
        this.addressSpace.write(
          ptr + BigInt(offset),
          chunkLen === MEM_CHUNK_BYTES ? ZERO_CHUNK : ZERO_CHUNK.subarray(0, chunkLen)
        );
        offset += chunkLen;
      }
    }
    this._heapAllocs.add(ptr);
    return ptr;
  }

  _freeHeap(ptr) {
    const p = toBigIntPtr(ptr);
    if (p === 0n) return;
    if (!this._heapAllocs.has(p)) return;
    this._heapAllocs.delete(p);
    try {
      this.addressSpace.free(Number(p));
    } catch {
      // Guard against teardown or double-free edge cases
    }
  }

  _allocCString(str) {
    const encoded = TEXT_ENCODER.encode(String(str ?? ''));
    const ptr = this._allocHeap(encoded.byteLength + 1, false);
    const buf = new Uint8Array(encoded.byteLength + 1);
    buf.set(encoded, 0);
    buf[encoded.byteLength] = 0;
    this.addressSpace.write(ptr, buf);
    return ptr;
  }

  _vfsCtx() {
    const ctx = {
      pid: this.pcb ? this.pcb.pid : null,
      uid: this.pcb?.uid ?? this.uid,
      gid: this.pcb?.gid ?? this.gid,
      cwd: this.pcb?.cwd ?? this.cwd,
      platform: this.platform,
      appId: this.appId,
      containerUuid: this.containerUuid,
    };
    if (this.sandboxRoot !== null && this.sandboxRoot !== undefined) {
      ctx.sandboxRoot = this.sandboxRoot;
    }
    return ctx;
  }

  _resolveVfsCtxForPath(rawPath, wantWrite = false) {
    const base = this._vfsCtx();
    if (!this.permissionBroker || !this.vfs?.pathTranslator) return base;
    try {
      const translated = this.vfs.pathTranslator.toCanonical(rawPath, {
        platform: base.platform,
        cwd: base.cwd,
        appId: base.appId,
        containerUuid: base.containerUuid,
      });
      const canonical = translated.canonicalPath;
      if (canonical === '/home/user' || canonical.startsWith('/home/user/')) {
        if (
          !base.sandboxRoot ||
          !(canonical === base.sandboxRoot || canonical.startsWith(`${base.sandboxRoot}/`))
        ) {
          const decision = this.permissionBroker({
            action: wantWrite ? 'write' : 'read',
            capability: wantWrite ? 'fs.write.user' : 'fs.read.user',
            rawPath,
            canonicalPath: canonical,
            appId: base.appId,
            pid: this.pcb?.pid ?? null,
            platform: base.platform,
          });
          if (decision && decision.allowed === true) {
            return {
              ...base,
              uid: 1000,
              gid: 1000,
              sandboxRoot: this.platform === 'ios' ? '/home/user/Documents' : '/home/user',
              ...(decision.effectiveCtx ?? {}),
            };
          }
        }
      }
    } catch {
      // Strictly keep sandbox ctx on error
    }
    return base;
  }

  _pathWithinRoot(canonicalPath, root) {
    if (!root || root === '/') return true;
    const cleanRoot = root.length > 1 && root.endsWith('/') ? root.slice(0, -1) : root;
    return canonicalPath === cleanRoot || canonicalPath.startsWith(`${cleanRoot}/`);
  }

  _resolveRenameVfsCtx(srcPath, dstPath) {
    const srcCtx = this._resolveVfsCtxForPath(srcPath, true);
    const dstCtx = this._resolveVfsCtxForPath(dstPath, true);
    if (srcCtx.uid !== dstCtx.uid || srcCtx.gid !== dstCtx.gid) {
      return null;
    }
    const srcRoot = srcCtx.sandboxRoot ?? null;
    const dstRoot = dstCtx.sandboxRoot ?? null;
    if (srcRoot !== dstRoot) {
      return null;
    }
    if (srcRoot !== null && this.vfs?.pathTranslator) {
      try {
        const srcCan = this.vfs.pathTranslator.toCanonical(srcPath, {
          platform: srcCtx.platform,
          cwd: srcCtx.cwd,
          appId: srcCtx.appId,
          containerUuid: srcCtx.containerUuid,
        }).canonicalPath;
        const dstCan = this.vfs.pathTranslator.toCanonical(dstPath, {
          platform: dstCtx.platform,
          cwd: dstCtx.cwd,
          appId: dstCtx.appId,
          containerUuid: dstCtx.containerUuid,
        }).canonicalPath;
        if (!this._pathWithinRoot(srcCan, srcRoot) || !this._pathWithinRoot(dstCan, dstRoot)) {
          return null;
        }
      } catch {
        return null;
      }
    }
    return srcCtx;
  }

  // =========================================================================
  // Selectors & Classes Registration
  // =========================================================================

  selRegisterName(name) {
    if (name === null || name === undefined) return 0n;
    const str = String(name);
    if (this._selByName.has(str)) {
      return this._selByName.get(str);
    }
    const ptr = this._allocCString(str);
    this._selByName.set(str, ptr);
    this._selByAddr.set(ptr, str);
    return ptr;
  }

  selGetName(selAddr) {
    const ptr = toBigIntPtr(selAddr);
    if (ptr === 0n) return '';
    if (this._selByAddr.has(ptr)) {
      return this._selByAddr.get(ptr);
    }
    try {
      const str = this.addressSpace.readCString(ptr, 512);
      this._selByAddr.set(ptr, str);
      if (!this._selByName.has(str)) {
        this._selByName.set(str, ptr);
      }
      return str;
    } catch {
      return '';
    }
  }

  registerHostClass(name, superName = 'NSObject', { classMethods = {}, instanceMethods = {}, instanceSize = 32 } = {}) {
    const existing = this._classesByName.get(name);
    if (existing) {
      if (superName && !existing.superName) existing.superName = superName;
      for (const [sel, fn] of Object.entries(classMethods)) {
        existing.classMethods.set(sel, { kind: 'host', fn });
      }
      for (const [sel, fn] of Object.entries(instanceMethods)) {
        existing.instanceMethods.set(sel, { kind: 'host', fn });
      }
      return existing.ptr;
    }

    const ptr = this._allocHeap(64, true);
    const superRec = superName ? this._classesByName.get(superName) : null;
    // Write class_t header: isa=self (metaclass placeholder), superclass=superPtr
    this.addressSpace.writeU64(ptr, ptr, true);
    this.addressSpace.writeU64(ptr + 8n, superRec ? superRec.ptr : 0n, true);

    const record = {
      name,
      ptr,
      superName: superName ?? null,
      superPtr: superRec ? superRec.ptr : 0n,
      instanceSize: Math.max(16, instanceSize),
      classMethods: new Map(),
      instanceMethods: new Map(),
      ivars: new Map(),
      isAppClass: false,
    };

    for (const [sel, fn] of Object.entries(classMethods)) {
      record.classMethods.set(sel, { kind: 'host', fn });
    }
    for (const [sel, fn] of Object.entries(instanceMethods)) {
      record.instanceMethods.set(sel, { kind: 'host', fn });
    }

    this._classesByName.set(name, record);
    this._classesByPtr.set(ptr, record);
    return ptr;
  }

  registerCFunction(symbolName, fn) {
    if (typeof fn !== 'function') {
      throw new TypeError(`registerCFunction(${symbolName}) expects a function`);
    }
    const clean = stripLeadingUnderscore(symbolName);
    this._cFunctions.set(clean, fn);
    this._cFunctions.set(`_${clean}`, fn);
  }

  getClass(name) {
    const rec = this._classesByName.get(String(name));
    return rec ? rec.ptr : 0n;
  }

  getClassRecord(nameOrPtr) {
    if (typeof nameOrPtr === 'string') {
      return this._classesByName.get(nameOrPtr) ?? null;
    }
    const ptr = toBigIntPtr(nameOrPtr);
    return this._classesByPtr.get(ptr) ?? null;
  }

  /**
   * Symbol resolver callback suitable for passing to `loadMachOIntoAddressSpace(..., { resolveSymbol })`
   * so `_OBJC_CLASS_$_<Name>` and `___CFConstantStringClassReference` bind to real guest Class VAs.
   */
  resolveMachOSymbol(symbolName) {
    const s = String(symbolName ?? '');
    if (s.startsWith('_OBJC_CLASS_$_')) {
      const clsName = s.slice('_OBJC_CLASS_$_'.length);
      let ptr = this.getClass(clsName);
      if (ptr === 0n) {
        ptr = this.registerHostClass(clsName, 'NSObject');
      }
      return Number(ptr);
    }
    if (s.startsWith('_OBJC_METACLASS_$_')) {
      const clsName = s.slice('_OBJC_METACLASS_$_'.length);
      let ptr = this.getClass(clsName);
      if (ptr === 0n) {
        ptr = this.registerHostClass(clsName, 'NSObject');
      }
      return Number(ptr);
    }
    if (s === '___CFConstantStringClassReference') {
      return Number(this.getClass('NSString'));
    }
    return null;
  }

  // =========================================================================
  // Mach-O ObjC ABI2 Metadata Loader (`__objc_classlist`, `__objc_selrefs`, `__cfstring`)
  // =========================================================================

  loadMachOObjC(loadedMachO) {
    if (!loadedMachO || typeof loadedMachO !== 'object') return { classes: [], selectors: [], cfStrings: 0 };
    this._loadedMachO = loadedMachO;
    const sections = loadedMachO.objcSections ?? {};
    const discoveredClasses = [];
    const discoveredSelectors = [];
    let cfStringCount = 0;

    // 1. Intern selector references from `__objc_selrefs`
    if (sections.__objc_selrefs && sections.__objc_selrefs.size >= 8) {
      const { addr, size } = sections.__objc_selrefs;
      const count = Math.floor(size / 8);
      for (let i = 0; i < count; i++) {
        const slotVA = BigInt(addr + i * 8);
        try {
          const strPtr = this.addressSpace.readU64(slotVA, true);
          if (strPtr === 0n) continue;
          const name = this.addressSpace.readCString(strPtr, 512);
          if (!name) continue;
          if (!this._selByName.has(name)) {
            this._selByName.set(name, strPtr);
            this._selByAddr.set(strPtr, name);
          } else {
            this._selByAddr.set(strPtr, name);
          }
          discoveredSelectors.push(name);
        } catch {
          // Skip unreadable slots
        }
      }
    }

    // 2. Register static constant strings from `__cfstring` (32 bytes each)
    if (sections.__cfstring && sections.__cfstring.size >= 32) {
      const { addr, size } = sections.__cfstring;
      const count = Math.floor(size / 32);
      const nsStringPtr = this.getClass('NSString');
      for (let i = 0; i < count; i++) {
        const entryVA = BigInt(addr + i * 32);
        try {
          const flags = this.addressSpace.readU64(entryVA + 8n, true);
          const strPtr = this.addressSpace.readU64(entryVA + 16n, true);
          const strLen = Number(this.addressSpace.readU64(entryVA + 24n, true));
          if (strPtr === 0n || strLen < 0 || strLen > 1_048_576) continue;
          let text;
          if ((flags & 0x10n) !== 0n) {
            const raw = this.addressSpace.read(strPtr, strLen * 2);
            text = UTF16LE_DECODER.decode(raw);
          } else {
            const raw = this.addressSpace.read(strPtr, strLen);
            text = UTF8_DECODER.decode(raw);
          }
          this._objects.set(entryVA, {
            ptr: entryVA,
            className: 'NSString',
            classPtr: nsStringPtr,
            refCount: Number.POSITIVE_INFINITY,
            immortal: true,
            isStatic: true,
            hostData: { value: text },
          });
          cfStringCount++;
        } catch {
          // Skip malformed cfstring entry
        }
      }
    }

    // 3. Parse App-defined classes from `__objc_classlist`
    if (sections.__objc_classlist && sections.__objc_classlist.size >= 8) {
      const { addr, size } = sections.__objc_classlist;
      const count = Math.floor(size / 8);
      for (let i = 0; i < count; i++) {
        const slotVA = BigInt(addr + i * 8);
        try {
          const classPtr = this.addressSpace.readU64(slotVA, true);
          if (classPtr === 0n) continue;
          const rec = this._parseMachOClass(classPtr);
          if (rec) discoveredClasses.push(rec.name);
        } catch {
          // Skip malformed classlist entry
        }
      }
    }

    // 4. Link `__objc_classrefs` entries to known class pointers if pointing to class name/symbol
    if (sections.__objc_classrefs && sections.__objc_classrefs.size >= 8) {
      const { addr, size } = sections.__objc_classrefs;
      const count = Math.floor(size / 8);
      for (let i = 0; i < count; i++) {
        const slotVA = BigInt(addr + i * 8);
        try {
          const ptr = this.addressSpace.readU64(slotVA, true);
          if (ptr !== 0n && !this._classesByPtr.has(ptr)) {
            // Check if ptr points to a class_t not listed in classlist
            const maybeName = this._tryReadClassNameFromClassT(ptr);
            if (maybeName && this._classesByName.has(maybeName)) {
              const cls = this._classesByName.get(maybeName);
              this._classesByPtr.set(ptr, cls);
            }
          }
        } catch {
          // Ignore
        }
      }
    }

    return {
      classes: discoveredClasses,
      selectors: discoveredSelectors,
      cfStrings: cfStringCount,
    };
  }

  _tryReadClassNameFromClassT(classPtr) {
    try {
      const bits = this.addressSpace.readU64(classPtr + 32n, true);
      const roPtr = bits & ~0x7n;
      if (roPtr === 0n) return null;
      const namePtr = this.addressSpace.readU64(roPtr + 24n, true);
      if (namePtr === 0n) return null;
      return this.addressSpace.readCString(namePtr, 256);
    } catch {
      return null;
    }
  }

  _parseMethodList(methodListPtr, targetMap) {
    if (methodListPtr === 0n) return;
    const entsizeAndFlags = this.addressSpace.readU32(methodListPtr, true);
    const count = this.addressSpace.readU32(methodListPtr + 4n, true);
    if (count === 0 || count > 4096) return;

    const isRelative = (entsizeAndFlags & 0x80000000) !== 0;
    const entsize = entsizeAndFlags & 0x0000ffff;
    const stride = entsize >= 12 ? entsize : isRelative ? 12 : 24;
    let cur = methodListPtr + 8n;

    for (let i = 0; i < count; i++) {
      if (isRelative) {
        const nameRel = BigInt.asIntN(32, BigInt(this.addressSpace.readU32(cur, true)));
        const typesRel = BigInt.asIntN(32, BigInt(this.addressSpace.readU32(cur + 4n, true)));
        const impRel = BigInt.asIntN(32, BigInt(this.addressSpace.readU32(cur + 8n, true)));
        const selRefVA = BigInt.asUintN(64, cur + nameRel);
        let selName = '';
        try {
          // On Apple ABI2 small_method_t, nameRel points either to selref (ptr to char*) or direct char*
          const indirect = this.addressSpace.readU64(selRefVA, true);
          selName = this.selGetName(indirect);
        } catch {
          selName = '';
        }
        if (!selName) {
          selName = this.selGetName(selRefVA);
        }
        const typesVA = BigInt.asUintN(64, cur + 4n + typesRel);
        const impVA = BigInt.asUintN(64, cur + 8n + impRel);
        let types = '';
        try {
          types = this.addressSpace.readCString(typesVA, 128);
        } catch {
          types = '';
        }
        if (selName && impVA !== 0n) {
          targetMap.set(selName, { kind: 'imp', impVA, types });
        }
      } else {
        const namePtr = this.addressSpace.readU64(cur, true);
        const typesPtr = this.addressSpace.readU64(cur + 8n, true);
        const impVA = this.addressSpace.readU64(cur + 16n, true);
        const selName = this.selGetName(namePtr);
        let types = '';
        if (typesPtr !== 0n) {
          try {
            types = this.addressSpace.readCString(typesPtr, 128);
          } catch {
            types = '';
          }
        }
        if (selName && impVA !== 0n) {
          targetMap.set(selName, { kind: 'imp', impVA, types });
        }
      }
      cur += BigInt(stride);
    }
  }

  _parseMachOClass(classPtr) {
    const isaPtr = this.addressSpace.readU64(classPtr + 0n, true);
    const superPtr = this.addressSpace.readU64(classPtr + 8n, true);
    const bits = this.addressSpace.readU64(classPtr + 32n, true);
    const roPtr = bits & ~0x7n;
    if (roPtr === 0n) return null;

    const instanceSize = this.addressSpace.readU32(roPtr + 8n, true);
    const namePtr = this.addressSpace.readU64(roPtr + 24n, true);
    const baseMethodsPtr = this.addressSpace.readU64(roPtr + 32n, true);
    const ivarsPtr = this.addressSpace.readU64(roPtr + 48n, true);

    const name = this.addressSpace.readCString(namePtr, 256);
    if (!name) return null;

    let superName = 'NSObject';
    const existingSuper = superPtr !== 0n ? this._classesByPtr.get(superPtr) : null;
    if (existingSuper) {
      superName = existingSuper.name;
    } else if (superPtr !== 0n) {
      const sName = this._tryReadClassNameFromClassT(superPtr);
      if (sName) superName = sName;
    } else if (name === 'NSObject') {
      superName = null;
    }

    const existing = this._classesByName.get(name);
    const record = {
      name,
      ptr: classPtr,
      superName,
      superPtr: existingSuper ? existingSuper.ptr : superPtr,
      instanceSize: Math.max(16, instanceSize || 16),
      classMethods: existing ? new Map(existing.classMethods) : new Map(),
      instanceMethods: existing ? new Map(existing.instanceMethods) : new Map(),
      ivars: new Map(),
      isAppClass: true,
    };

    // Parse instance methods
    if (baseMethodsPtr !== 0n) {
      this._parseMethodList(baseMethodsPtr, record.instanceMethods);
    }

    // Parse class methods from metaclass (`class_t.isa`)
    if (isaPtr !== 0n && isaPtr !== classPtr) {
      try {
        const metaBits = this.addressSpace.readU64(isaPtr + 32n, true);
        const metaRoPtr = metaBits & ~0x7n;
        if (metaRoPtr !== 0n) {
          const metaMethodsPtr = this.addressSpace.readU64(metaRoPtr + 32n, true);
          if (metaMethodsPtr !== 0n) {
            this._parseMethodList(metaMethodsPtr, record.classMethods);
          }
        }
      } catch {
        // Metaclass may be external or absent in minimal Mach-O
      }
    }

    // Parse ivars
    if (ivarsPtr !== 0n) {
      try {
        const ivEntsize = this.addressSpace.readU32(ivarsPtr, true);
        const ivCount = this.addressSpace.readU32(ivarsPtr + 4n, true);
        let cur = ivarsPtr + 8n;
        const stride = ivEntsize >= 32 ? ivEntsize : 32;
        for (let i = 0; i < Math.min(ivCount, 512); i++) {
          const offPtr = this.addressSpace.readU64(cur, true);
          const ivNamePtr = this.addressSpace.readU64(cur + 8n, true);
          const ivTypePtr = this.addressSpace.readU64(cur + 16n, true);
          const ivName = ivNamePtr !== 0n ? this.addressSpace.readCString(ivNamePtr, 128) : '';
          const ivType = ivTypePtr !== 0n ? this.addressSpace.readCString(ivTypePtr, 128) : '';
          const offset = offPtr !== 0n ? this.addressSpace.readU32(offPtr, true) : 8 + i * 8;
          if (ivName) {
            record.ivars.set(ivName, { offset, type: ivType });
          }
          cur += BigInt(stride);
        }
      } catch {
        // Ignore ivar parse failures
      }
    }

    this._classesByName.set(name, record);
    this._classesByPtr.set(classPtr, record);
    return record;
  }

  // =========================================================================
  // Object Allocation, ARC Refcounting & Host Marshaling
  // =========================================================================

  allocObject(classNameOrPtr, hostProps = {}) {
    const classRec =
      typeof classNameOrPtr === 'string'
        ? this._classesByName.get(classNameOrPtr)
        : this._classesByPtr.get(toBigIntPtr(classNameOrPtr));

    if (!classRec) {
      return 0n;
    }

    const ptr = this._allocHeap(Math.max(16, classRec.instanceSize), true);
    this.addressSpace.writeU64(ptr, classRec.ptr, true);

    this._objects.set(ptr, {
      ptr,
      className: classRec.name,
      classPtr: classRec.ptr,
      refCount: 1,
      immortal: false,
      isStatic: false,
      hostData: { ...hostProps },
    });
    return ptr;
  }

  getHostObject(ptr) {
    const p = toBigIntPtr(ptr);
    if (p === 0n) return null;
    const rec = this._objects.get(p);
    return rec ? rec.hostData : null;
  }

  getObjectRecord(ptr) {
    const p = toBigIntPtr(ptr);
    if (p === 0n) return null;
    return this._objects.get(p) ?? null;
  }

  retain(ptr) {
    const p = toBigIntPtr(ptr);
    if (p === 0n) return 0n;
    const rec = this._objects.get(p);
    if (rec && !rec.immortal) {
      rec.refCount += 1;
    }
    return p;
  }

  release(ptr, cpu = null) {
    const p = toBigIntPtr(ptr);
    if (p === 0n) return;
    const rec = this._objects.get(p);
    if (!rec || rec.immortal) return;
    if (rec.deallocating) return;
    rec.refCount -= 1;
    if (rec.refCount <= 0) {
      rec.deallocating = true;
      // Invoke custom dealloc if defined on subclass
      const cls = this._classesByName.get(rec.className);
      if (cls && cls.instanceMethods.has('dealloc') && cls.name !== 'NSObject') {
        try {
          this.msgSend(cpu, p, 'dealloc', []);
        } catch {
          // Isolate dealloc errors
        }
      }
      // Release retained child items on NSArray / NSDictionary deallocation
      if (
        (rec.className === 'NSArray' || rec.className === 'NSMutableArray') &&
        Array.isArray(rec.hostData?.items)
      ) {
        const items = rec.hostData.items;
        rec.hostData.items = [];
        for (const itemPtr of items) {
          this.release(itemPtr, cpu);
        }
      } else if (
        (rec.className === 'NSDictionary' || rec.className === 'NSMutableDictionary') &&
        rec.hostData?.map instanceof Map
      ) {
        const values = Array.from(rec.hostData.map.values());
        rec.hostData.map.clear();
        for (const valPtr of values) {
          this.release(valPtr, cpu);
        }
      }
      if (rec.hostData?._utf8CachePtr) {
        this._freeHeap(rec.hostData._utf8CachePtr);
      }
      if (rec.hostData?._bytesCachePtr) {
        this._freeHeap(rec.hostData._bytesCachePtr);
      }
      this._objects.delete(p);
      if (!rec.isStatic) {
        this._freeHeap(p);
      }
    }
  }

  autorelease(ptr) {
    const p = toBigIntPtr(ptr);
    if (p === 0n) return 0n;
    const top = this._autoreleasePools[this._autoreleasePools.length - 1];
    if (top) {
      top.push(p);
    }
    return p;
  }

  autoreleasePoolPush() {
    this._autoreleasePools.push([]);
    return BigInt(this._autoreleasePools.length);
  }

  autoreleasePoolPop(token, cpu = null) {
    const targetDepth = Math.max(1, Number(toBigIntPtr(token)));
    while (this._autoreleasePools.length >= targetDepth && this._autoreleasePools.length > 1) {
      const frame = this._autoreleasePools.pop();
      for (let i = frame.length - 1; i >= 0; i--) {
        this.release(frame[i], cpu);
      }
    }
  }

  getRetainCount(ptr) {
    const p = toBigIntPtr(ptr);
    if (p === 0n) return 0;
    const rec = this._objects.get(p);
    if (!rec) return 0;
    return rec.immortal ? 0x7fffffff : rec.refCount;
  }

  // ---- Convenience Foundation Constructors ----

  createNSString(str, mutable = false) {
    return this.allocObject(mutable ? 'NSMutableString' : 'NSString', {
      value: String(str ?? ''),
      _utf8CachePtr: 0n,
    });
  }

  readNSString(ptr) {
    const p = toBigIntPtr(ptr);
    if (p === 0n) return null;
    const rec = this._objects.get(p);
    if (rec) {
      if (typeof rec.hostData?.value === 'string') return rec.hostData.value;
      if (rec.className === 'NSURL' && typeof rec.hostData?.absoluteString === 'string') {
        return rec.hostData.absoluteString;
      }
      if (rec.className === 'NSNumber') return String(rec.hostData.value);
    }
    // Check if it is an unregistered static __cfstring in guest memory
    try {
      const flags = this.addressSpace.readU64(p + 8n, true);
      const strPtr = this.addressSpace.readU64(p + 16n, true);
      const strLen = Number(this.addressSpace.readU64(p + 24n, true));
      if (strPtr > 0x1000n && strLen >= 0 && strLen <= 65536 && (flags & 0xff0n) === 0x7c0n) {
        const raw = this.addressSpace.read(strPtr, strLen);
        return UTF8_DECODER.decode(raw);
      }
    } catch {
      // Fall back to reading as plain C string
    }
    try {
      return this.addressSpace.readCString(p, 4096);
    } catch {
      return null;
    }
  }

  createNSNumber(val, kind = 'double') {
    return this.allocObject('NSNumber', { value: val, kind });
  }

  createNSArray(items = [], mutable = false) {
    const arr = items.map((p) => toBigIntPtr(p));
    for (const p of arr) this.retain(p);
    return this.allocObject(mutable ? 'NSMutableArray' : 'NSArray', { items: arr });
  }

  createNSDictionary(entries = [], mutable = false) {
    const map = new Map();
    for (const [k, v] of entries) {
      const keyStr = typeof k === 'string' ? k : (this.readNSString(k) ?? String(k));
      const valPtr = toBigIntPtr(v);
      this.retain(valPtr);
      map.set(keyStr, valPtr);
    }
    return this.allocObject(mutable ? 'NSMutableDictionary' : 'NSDictionary', { map });
  }

  createNSData(bytes, mutable = false) {
    const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes ?? 0);
    return this.allocObject(mutable ? 'NSMutableData' : 'NSData', {
      bytes: copy,
      _bytesCachePtr: 0n,
    });
  }

  jsToObjC(val, seen = new Set(), depth = 0) {
    if (val === null || val === undefined || depth > MAX_MARSHAL_DEPTH) return 0n;
    if (typeof val === 'string') return this.createNSString(val);
    if (typeof val === 'boolean') return this.createNSNumber(val ? 1 : 0, 'bool');
    if (typeof val === 'number') {
      return this.createNSNumber(val, Number.isInteger(val) ? 'int' : 'double');
    }
    if (typeof val === 'bigint') return this.createNSNumber(Number(val), 'int');
    if (val instanceof Uint8Array) return this.createNSData(val);
    if (Array.isArray(val)) {
      if (seen.has(val)) return 0n;
      seen.add(val);
      try {
        const ptrs = val.map((item) => this.jsToObjC(item, seen, depth + 1));
        return this.allocObject('NSArray', { items: ptrs });
      } finally {
        seen.delete(val);
      }
    }
    if (typeof val === 'object') {
      if (seen.has(val)) return 0n;
      seen.add(val);
      try {
        const map = new Map();
        for (const [k, v] of Object.entries(val)) {
          map.set(k, this.jsToObjC(v, seen, depth + 1));
        }
        return this.allocObject('NSDictionary', { map });
      } finally {
        seen.delete(val);
      }
    }
    return this.createNSString(String(val));
  }

  objcToJs(ptr, seen = new Set(), depth = 0) {
    const p = toBigIntPtr(ptr);
    if (p === 0n || depth > MAX_MARSHAL_DEPTH) return null;
    const rec = this._objects.get(p);
    if (!rec) return this.readNSString(p);
    switch (rec.className) {
      case 'NSString':
      case 'NSMutableString':
        return rec.hostData.value;
      case 'NSNumber':
        return rec.hostData.kind === 'bool' ? Boolean(rec.hostData.value) : rec.hostData.value;
      case 'NSArray':
      case 'NSMutableArray': {
        if (seen.has(p)) return null;
        seen.add(p);
        try {
          return (rec.hostData.items ?? []).map((itemPtr) =>
            this.objcToJs(itemPtr, seen, depth + 1)
          );
        } finally {
          seen.delete(p);
        }
      }
      case 'NSDictionary':
      case 'NSMutableDictionary': {
        if (seen.has(p)) return null;
        seen.add(p);
        try {
          const out = {};
          for (const [k, vPtr] of (rec.hostData.map ?? new Map()).entries()) {
            Object.defineProperty(out, k, {
              value: this.objcToJs(vPtr, seen, depth + 1),
              enumerable: true,
              writable: true,
              configurable: true,
            });
          }
          return out;
        } finally {
          seen.delete(p);
        }
      }
      case 'NSData':
      case 'NSMutableData':
        return rec.hostData.bytes.slice();
      case 'NSURL':
        return rec.hostData.absoluteString;
      default:
        return `<${rec.className}: 0x${p.toString(16)}>`;
    }
  }

  describeObject(ptr, seen = new Set(), depth = 0) {
    const p = toBigIntPtr(ptr);
    if (p === 0n) return '(null)';
    if (depth > MAX_MARSHAL_DEPTH) return '(...)';
    const cls = this._classesByPtr.get(p);
    if (cls) return cls.name;
    const rec = this._objects.get(p);
    if (!rec) {
      const maybeStr = this.readNSString(p);
      return maybeStr ?? `<id: 0x${p.toString(16)}>`;
    }
    if (rec.className === 'NSString' || rec.className === 'NSMutableString') {
      return rec.hostData.value;
    }
    if (rec.className === 'NSNumber') {
      return rec.hostData.kind === 'bool'
        ? (rec.hostData.value ? '1' : '0')
        : String(rec.hostData.value);
    }
    if (rec.className === 'NSURL') {
      return rec.hostData.absoluteString;
    }
    if (rec.className === 'NSArray' || rec.className === 'NSMutableArray') {
      if (seen.has(p)) return '(...)';
      seen.add(p);
      try {
        return `(${(rec.hostData.items ?? []).map((it) => this.describeObject(it, seen, depth + 1)).join(', ')})`;
      } finally {
        seen.delete(p);
      }
    }
    if (rec.className === 'NSDictionary' || rec.className === 'NSMutableDictionary') {
      if (seen.has(p)) return '{...}';
      seen.add(p);
      try {
        const parts = [];
        for (const [k, v] of (rec.hostData.map ?? new Map()).entries()) {
          parts.push(`${k} = ${this.describeObject(v, seen, depth + 1)}`);
        }
        return `{${parts.join('; ')}}`;
      } finally {
        seen.delete(p);
      }
    }
    return `<${rec.className}: 0x${p.toString(16)}>`;
  }

  // =========================================================================
  // Method Lookup & Nil-Safe Message Dispatch (Edge Case #26)
  // =========================================================================

  _isSubclassOf(childName, ancestorName) {
    let cur = this._classesByName.get(childName);
    let depth = 0;
    while (cur && depth++ < 64) {
      if (cur.name === ancestorName) return true;
      cur = cur.superName ? this._classesByName.get(cur.superName) : null;
    }
    return false;
  }

  _lookupMethod(startClassRec, selName, isClassMethod) {
    let cur = startClassRec;
    let depth = 0;
    while (cur && depth++ < 64) {
      const table = isClassMethod ? cur.classMethods : cur.instanceMethods;
      if (table.has(selName)) {
        return { method: table.get(selName), ownerClass: cur };
      }
      cur = cur.superName ? this._classesByName.get(cur.superName) : null;
    }
    // ObjC spec: class objects inherit root NSObject instance methods if no class method matches
    if (isClassMethod) {
      const root = this._classesByName.get('NSObject');
      if (root && root.instanceMethods.has(selName)) {
        return { method: root.instanceMethods.get(selName), ownerClass: root };
      }
    }
    return null;
  }

  _resolveReceiverClass(selfPtr) {
    const cls = this._classesByPtr.get(selfPtr);
    if (cls) {
      return { classRec: cls, isClassMethod: true };
    }
    const obj = this._objects.get(selfPtr);
    if (obj) {
      const objCls = this._classesByName.get(obj.className) ?? this._classesByPtr.get(obj.classPtr);
      return objCls ? { classRec: objCls, isClassMethod: false } : null;
    }
    // Check raw guest isa pointer for static/app-allocated objects
    try {
      const isa = this.addressSpace.readU64(selfPtr, true);
      const isaCls = this._classesByPtr.get(isa);
      if (isaCls) {
        return { classRec: isaCls, isClassMethod: false };
      }
    } catch {
      // Ignore
    }
    return null;
  }

  invokeAppImp(cpu, impVA, selfPtr, selPtr, args = [], { maxSteps = 100_000 } = {}) {
    if (!cpu) return 0n;
    const sel = typeof selPtr === 'string' ? this.selRegisterName(selPtr) : toBigIntPtr(selPtr);
    const fullArgs = [toBigIntPtr(selfPtr), sel, ...args.map((a) => toBigIntPtr(a))];
    if (typeof cpu.callFunctionSync === 'function') {
      const res = cpu.callFunctionSync(impVA, fullArgs, { maxSteps });
      if (res?.halted) {
        cpu.halted = true;
        cpu.exitCode = res.exitCode ?? 0;
      }
      return res.result;
    }
    if (typeof cpu.invokeSubroutine === 'function') {
      const res = cpu.invokeSubroutine(impVA, fullArgs, { maxSteps });
      if (res?.halted) {
        cpu.halted = true;
        cpu.exitCode = res.exitCode ?? 0;
      }
      return res.result;
    }
    return 0n;
  }

  /**
   * Swift `swiftcall` invocation helper (`X20`/`R13` = self, `X21`/`R12` = swifterror).
   */
  invokeSwiftMethod(cpu, fnVA, selfPtr, args = [], { maxSteps = 100_000 } = {}) {
    if (!cpu) return { result: 0n, swiftError: 0n };
    const arm64 = isArm64Cpu(cpu);
    const savedSelf = arm64 ? cpu.getReg(20) : getX64NamedReg(cpu, 'r13');
    const savedErr = arm64 ? cpu.getReg(21) : getX64NamedReg(cpu, 'r12');
    try {
      if (arm64) {
        cpu.setReg(20, toBigIntPtr(selfPtr));
        cpu.setReg(21, 0n);
      } else {
        setX64NamedReg(cpu, 'r13', toBigIntPtr(selfPtr));
        setX64NamedReg(cpu, 'r12', 0n);
      }
      const res = cpu.callFunctionSync(
        fnVA,
        args.map((a) => toBigIntPtr(a)),
        { maxSteps, captureSwiftError: true }
      );
      if (res?.halted) {
        cpu.halted = true;
        cpu.exitCode = res.exitCode ?? 0;
      }
      const rawSwiftError = arm64
        ? (res.swiftError ?? res.x21 ?? 0n)
        : (res.swiftError ?? res.r12 ?? getX64NamedReg(cpu, 'r12'));
      return {
        result: res.result,
        swiftError: toBigIntPtr(rawSwiftError),
        instructionsExecuted: res.instructionsExecuted,
        halted: Boolean(res?.halted),
        exitCode: res?.exitCode ?? 0,
      };
    } finally {
      if (arm64) {
        cpu.setReg(20, savedSelf);
        cpu.setReg(21, savedErr);
      } else {
        setX64NamedReg(cpu, 'r13', savedSelf);
        setX64NamedReg(cpu, 'r12', savedErr);
      }
    }
  }

  /**
   * Nil-safe Objective-C message send (Edge Case #26).
   */
  msgSend(cpu, selfPtr, selPtr, args = [], { superClass = null } = {}) {
    const self = toBigIntPtr(selfPtr);
    // Edge Case #26: Messaging nil MUST ALWAYS return 0n safely without faulting!
    if (self === 0n) {
      return 0n;
    }

    const selName = typeof selPtr === 'string' ? selPtr : this.selGetName(selPtr);
    if (!selName) return 0n;

    let classRec;
    let isClassMethod = false;

    if (superClass) {
      classRec = superClass;
      isClassMethod = this._classesByPtr.has(self);
    } else {
      const resolved = this._resolveReceiverClass(self);
      if (!resolved) return 0n;
      classRec = resolved.classRec;
      isClassMethod = resolved.isClassMethod;
    }

    const found = this._lookupMethod(classRec, selName, isClassMethod);
    if (!found) {
      return 0n;
    }

    if (found.method.kind === 'host') {
      const out = found.method.fn(self, args, {
        cpu,
        runtime: this,
        selName,
        classRec,
        ownerClass: found.ownerClass,
        isClassMethod,
      });
      if (out === undefined || out === null) return 0n;
      if (typeof out === 'bigint') return BigInt.asUintN(64, out);
      if (typeof out === 'boolean') return out ? 1n : 0n;
      if (typeof out === 'number') return BigInt.asUintN(64, BigInt(Math.trunc(out)));
      return 0n;
    }

    // Native ARM64 / x86-64 App IMP
    return this.invokeAppImp(cpu, found.method.impVA, self, selPtr, args);
  }

  // =========================================================================
  // Thunk Dispatcher (Called by ARM64/x86-64 CPU `onThunk`)
  // =========================================================================

  handleThunk(symbolName, cpu) {
    const clean = stripLeadingUnderscore(symbolName);

    // Fast path for objc_msgSend / objc_msgSendSuper2 with native App IMP tail-jump!
    if (clean === 'objc_msgSend' || clean === 'objc_msgSend_stret' || clean === 'objc_msgSend_fpret') {
      const selfPtr = getCpuArg(cpu, this.addressSpace, 0);
      // Edge Case #26: nil receiver -> return 0n (and 0.0 in D0) cleanly!
      if (selfPtr === 0n) {
        setCpuReturn(cpu, 0n);
        setCpuFloatReturn(cpu, 0.0);
        return true;
      }
      const selPtr = getCpuArg(cpu, this.addressSpace, 1);
      const selName = this.selGetName(selPtr);
      const resolved = this._resolveReceiverClass(selfPtr);
      if (!resolved) {
        setCpuReturn(cpu, 0n);
        return true;
      }
      const found = this._lookupMethod(resolved.classRec, selName, resolved.isClassMethod);
      if (!found) {
        setCpuReturn(cpu, 0n);
        return true;
      }
      if (found.method.kind === 'imp') {
        // Tail-jump directly to native IMP! Leaves X0..X7, stack args, and X30 (LR) untouched!
        if (isArm64Cpu(cpu)) {
          cpu.setPC(found.method.impVA);
        } else if (typeof cpu.setReg === 'function') {
          cpu.setReg('rip', found.method.impVA);
        }
        return true;
      }

      // Host method: gather arguments according to selector colon count
      const argCount = countSelectorArgs(selName);
      const args = new Array(argCount);
      for (let i = 0; i < argCount; i++) {
        args[i] = getCpuArg(cpu, this.addressSpace, 2 + i);
      }
      const ret = this.msgSend(cpu, selfPtr, selName, args);
      setCpuReturn(cpu, ret);
      return true;
    }

    if (clean === 'objc_msgSendSuper2' || clean === 'objc_msgSendSuper') {
      const superPtr = getCpuArg(cpu, this.addressSpace, 0);
      const selPtr = getCpuArg(cpu, this.addressSpace, 1);
      if (superPtr === 0n) {
        setCpuReturn(cpu, 0n);
        setCpuFloatReturn(cpu, 0.0);
        return true;
      }
      const receiver = this.addressSpace.readU64(superPtr, true);
      // Edge Case #26: nil receiver inside objc_super -> return 0n cleanly!
      if (receiver === 0n) {
        setCpuReturn(cpu, 0n);
        setCpuFloatReturn(cpu, 0.0);
        return true;
      }
      const clsPtr = this.addressSpace.readU64(superPtr + 8n, true);
      let startCls = this._classesByPtr.get(clsPtr) ?? null;
      if (clean === 'objc_msgSendSuper2' && startCls) {
        startCls = startCls.superName ? this._classesByName.get(startCls.superName) : null;
      }
      if (!startCls) {
        setCpuReturn(cpu, 0n);
        return true;
      }
      const selName = this.selGetName(selPtr);
      const isClassMethod = this._classesByPtr.has(receiver);
      const found = this._lookupMethod(startCls, selName, isClassMethod);
      if (!found) {
        setCpuReturn(cpu, 0n);
        return true;
      }
      if (found.method.kind === 'imp') {
        if (isArm64Cpu(cpu)) {
          cpu.setReg(0, receiver);
          cpu.setPC(found.method.impVA);
        } else if (typeof cpu.setReg === 'function') {
          cpu.setReg('rdi', receiver);
          cpu.setReg('rip', found.method.impVA);
        }
        return true;
      }
      const argCount = countSelectorArgs(selName);
      const args = new Array(argCount);
      for (let i = 0; i < argCount; i++) {
        args[i] = getCpuArg(cpu, this.addressSpace, 2 + i);
      }
      const ret = this.msgSend(cpu, receiver, selName, args, { superClass: startCls });
      setCpuReturn(cpu, ret);
      return true;
    }

    const fn = this._cFunctions.get(clean) ?? this._cFunctions.get(symbolName);
    if (!fn) {
      return false;
    }
    const res = fn(cpu, this);
    if (res && typeof res === 'object' && res.status) {
      return res;
    }
    if (res !== undefined) {
      setCpuReturn(cpu, res);
    }
    return true;
  }

  // =========================================================================
  // Format Engine (`NSLog`, `printf`, `snprintf`, `+[NSString stringWithFormat:]`)
  // =========================================================================

  _formatString(fmt, rawArgs) {
    const specs = countFormatSpecifiers(fmt);
    let argIdx = 0;
    let out = '';
    let cursor = 0;

    for (let i = 0; i < specs.length; i++) {
      const sp = specs[i];
      if (sp.kind === 'width' || sp.kind === 'prec') {
        argIdx++;
        continue;
      }
      out += fmt.slice(cursor, sp.start).replace(/%%/g, '%');
      cursor = sp.end;
      const arg = rawArgs[argIdx++] ?? 0n;
      const isLong = sp.length.includes('l') || sp.length.includes('z') || sp.length.includes('q');

      switch (sp.kind) {
        case '@':
          out += this.describeObject(arg);
          break;
        case 's':
          out += arg === 0n ? '(null)' : this.addressSpace.readCString(arg, 4096);
          break;
        case 'd':
        case 'i':
          out += isLong ? BigInt.asIntN(64, arg).toString(10) : BigInt.asIntN(32, arg).toString(10);
          break;
        case 'u':
          out += isLong ? BigInt.asUintN(64, arg).toString(10) : BigInt.asUintN(32, arg).toString(10);
          break;
        case 'x':
          out += isLong ? BigInt.asUintN(64, arg).toString(16) : BigInt.asUintN(32, arg).toString(16);
          break;
        case 'X':
          out += (isLong ? BigInt.asUintN(64, arg).toString(16) : BigInt.asUintN(32, arg).toString(16)).toUpperCase();
          break;
        case 'p':
          out += `0x${BigInt.asUintN(64, arg).toString(16)}`;
          break;
        case 'c':
          out += String.fromCharCode(Number(arg & 0xffn));
          break;
        case 'f':
        case 'F':
        case 'g':
        case 'G':
        case 'e':
        case 'E': {
          const num = bitsToF64(arg);
          out += sp.kind === 'f' || sp.kind === 'F' ? num.toFixed(6) : String(num);
          break;
        }
        default:
          out += fmt.slice(sp.start, sp.end);
      }
    }
    out += fmt.slice(cursor).replace(/%%/g, '%');
    return out;
  }

  _emitStdout(text) {
    this.stdoutLines.push(text);
    const bytes = TEXT_ENCODER.encode(text);
    if (this.onStdout) this.onStdout(bytes);
    if (this.processManager && this.pcb) {
      this.processManager.writeStdout(this.pcb.pid, bytes);
    } else if (this.pcb?.streams?.stdout) {
      this.pcb.streams.stdout.write(bytes);
    }
  }

  _emitLog(text) {
    this.logs.push(text);
    const line = `${text}\n`;
    const bytes = TEXT_ENCODER.encode(line);
    if (this.onLog) this.onLog(text);
    if (this.onStderr) this.onStderr(bytes);
    if (this.processManager && this.pcb) {
      this.processManager.writeStderr(this.pcb.pid, bytes);
    } else if (this.pcb?.streams?.stderr) {
      this.pcb.streams.stderr.write(bytes);
    }
  }

  // =========================================================================
  // Built-in Foundation Classes
  // =========================================================================

  _registerBuiltInFoundationClasses() {
    // ---- NSObject ----
    this.registerHostClass('NSObject', null, {
      classMethods: {
        alloc: (clsPtr) => this.allocObject(clsPtr),
        allocWithZone_: (clsPtr) => this.allocObject(clsPtr),
        'allocWithZone:': (clsPtr) => this.allocObject(clsPtr),
        new: (clsPtr, _args, { cpu }) => {
          const obj = this.allocObject(clsPtr);
          return this.msgSend(cpu, obj, 'init', []);
        },
        class: (clsPtr) => clsPtr,
        superclass: (clsPtr) => {
          const rec = this._classesByPtr.get(clsPtr);
          return rec?.superName ? this.getClass(rec.superName) : 0n;
        },
        'isSubclassOfClass:': (clsPtr, [otherPtr]) => {
          const rec = this._classesByPtr.get(clsPtr);
          const other = this._classesByPtr.get(toBigIntPtr(otherPtr));
          if (!rec || !other) return 0n;
          return this._isSubclassOf(rec.name, other.name) ? 1n : 0n;
        },
        'instancesRespondToSelector:': (clsPtr, [selPtr]) => {
          const rec = this._classesByPtr.get(clsPtr);
          if (!rec) return 0n;
          return this._lookupMethod(rec, this.selGetName(selPtr), false) ? 1n : 0n;
        },
      },
      instanceMethods: {
        init: (self) => self,
        self: (self) => self,
        retain: (self) => this.retain(self),
        release: (self, _args, { cpu }) => {
          this.release(self, cpu);
          return 0n;
        },
        autorelease: (self) => this.autorelease(self),
        retainCount: (self) => BigInt(this.getRetainCount(self)),
        dealloc: () => 0n,
        class: (self) => {
          const resolved = this._resolveReceiverClass(self);
          return resolved ? resolved.classRec.ptr : 0n;
        },
        'isKindOfClass:': (self, [clsPtr]) => {
          const resolved = this._resolveReceiverClass(self);
          const target = this._classesByPtr.get(toBigIntPtr(clsPtr));
          if (!resolved || !target) return 0n;
          return this._isSubclassOf(resolved.classRec.name, target.name) ? 1n : 0n;
        },
        'isMemberOfClass:': (self, [clsPtr]) => {
          const resolved = this._resolveReceiverClass(self);
          const target = this._classesByPtr.get(toBigIntPtr(clsPtr));
          if (!resolved || !target) return 0n;
          return resolved.classRec.name === target.name ? 1n : 0n;
        },
        'respondsToSelector:': (self, [selPtr]) => {
          const resolved = this._resolveReceiverClass(self);
          if (!resolved) return 0n;
          const selName = this.selGetName(selPtr);
          return this._lookupMethod(resolved.classRec, selName, resolved.isClassMethod) ? 1n : 0n;
        },
        'performSelector:': (self, [selPtr], { cpu }) => this.msgSend(cpu, self, selPtr, []),
        'performSelector:withObject:': (self, [selPtr, obj], { cpu }) =>
          this.msgSend(cpu, self, selPtr, [obj]),
        'isEqual:': (self, [other]) => (self === toBigIntPtr(other) ? 1n : 0n),
        hash: (self) => self,
        description: (self) => this.createNSString(this.describeObject(self)),
      },
    });

    // ---- NSString ----
    this.registerHostClass('NSString', 'NSObject', {
      classMethods: {
        string: () => this.createNSString(''),
        'stringWithUTF8String:': (_cls, [cstrPtr]) => {
          const s = cstrPtr === 0n ? '' : this.addressSpace.readCString(cstrPtr, 65536);
          return this.createNSString(s);
        },
        'stringWithCString:encoding:': (_cls, [cstrPtr]) => {
          const s = cstrPtr === 0n ? '' : this.addressSpace.readCString(cstrPtr, 65536);
          return this.createNSString(s);
        },
        'stringWithString:': (_cls, [strPtr]) => {
          return this.createNSString(this.readNSString(strPtr) ?? '');
        },
        'stringWithFormat:': (_cls, [fmtPtr], { cpu }) => {
          const fmt = this.readNSString(fmtPtr) ?? '';
          const specs = countFormatSpecifiers(fmt);
          const rawArgs = cpu
            ? readCpuVariadicArgs(cpu, this.addressSpace, 3, specs.length)
            : [];
          return this.createNSString(this._formatString(fmt, rawArgs));
        },
        'stringWithContentsOfFile:encoding:error:': (_cls, [pathPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, false);
            const content = this.vfs.readFile(path, { ...ctx, encoding: 'utf8' });
            return this.createNSString(content);
          } catch {
            return 0n;
          }
        },
      },
      instanceMethods: {
        init: (self) => {
          const data = this.getHostObject(self);
          if (data && data.value === undefined) data.value = '';
          return self;
        },
        'initWithUTF8String:': (self, [cstrPtr]) => {
          const data = this.getHostObject(self);
          if (data) {
            data.value = cstrPtr === 0n ? '' : this.addressSpace.readCString(cstrPtr, 65536);
          }
          return self;
        },
        'initWithString:': (self, [strPtr]) => {
          const data = this.getHostObject(self);
          if (data) data.value = this.readNSString(strPtr) ?? '';
          return self;
        },
        UTF8String: (self) => {
          const rec = this.getObjectRecord(self);
          const str = this.readNSString(self) ?? '';
          if (rec && rec.hostData._utf8CachePtr) {
            const existing = this.addressSpace.readCString(rec.hostData._utf8CachePtr, 65536);
            if (existing === str) return rec.hostData._utf8CachePtr;
            this._freeHeap(rec.hostData._utf8CachePtr);
          }
          const cstrPtr = this._allocCString(str);
          if (rec) rec.hostData._utf8CachePtr = cstrPtr;
          return cstrPtr;
        },
        length: (self) => BigInt((this.readNSString(self) ?? '').length),
        'characterAtIndex:': (self, [idx]) => {
          const s = this.readNSString(self) ?? '';
          const i = Number(idx);
          return i >= 0 && i < s.length ? BigInt(s.charCodeAt(i)) : 0n;
        },
        'isEqualToString:': (self, [other]) => {
          return (this.readNSString(self) ?? '') === (this.readNSString(other) ?? '') ? 1n : 0n;
        },
        'isEqual:': (self, [other]) => {
          if (self === toBigIntPtr(other)) return 1n;
          const otherRec = this.getObjectRecord(other);
          if (otherRec && (otherRec.className === 'NSString' || otherRec.className === 'NSMutableString')) {
            return (this.readNSString(self) ?? '') === otherRec.hostData.value ? 1n : 0n;
          }
          return 0n;
        },
        'stringByAppendingString:': (self, [other]) => {
          return this.createNSString((this.readNSString(self) ?? '') + (this.readNSString(other) ?? ''));
        },
        'stringByAppendingPathComponent:': (self, [comp]) => {
          const base = (this.readNSString(self) ?? '').replace(/\/+$/, '');
          const child = (this.readNSString(comp) ?? '').replace(/^\/+/, '');
          return this.createNSString(`${base}/${child}`);
        },
        'hasPrefix:': (self, [pref]) =>
          (this.readNSString(self) ?? '').startsWith(this.readNSString(pref) ?? '') ? 1n : 0n,
        'hasSuffix:': (self, [suf]) =>
          (this.readNSString(self) ?? '').endsWith(this.readNSString(suf) ?? '') ? 1n : 0n,
        'containsString:': (self, [sub]) =>
          (this.readNSString(self) ?? '').includes(this.readNSString(sub) ?? '') ? 1n : 0n,
        lowercaseString: (self) => this.createNSString((this.readNSString(self) ?? '').toLowerCase()),
        uppercaseString: (self) => this.createNSString((this.readNSString(self) ?? '').toUpperCase()),
        intValue: (self) => BigInt.asUintN(64, BigInt(Number.parseInt(this.readNSString(self) ?? '0', 10) || 0)),
        integerValue: (self) => BigInt.asUintN(64, BigInt(Number.parseInt(this.readNSString(self) ?? '0', 10) || 0)),
        doubleValue: (self, _args, { cpu }) => {
          const v = Number.parseFloat(this.readNSString(self) ?? '0') || 0;
          setCpuFloatReturn(cpu, v);
          return f64ToBits(v);
        },
        boolValue: (self) => {
          const s = (this.readNSString(self) ?? '').trim().toLowerCase();
          return s.startsWith('y') || s.startsWith('t') || /^[1-9]/.test(s) ? 1n : 0n;
        },
        'dataUsingEncoding:': (self) => {
          return this.createNSData(TEXT_ENCODER.encode(this.readNSString(self) ?? ''));
        },
        'writeToFile:atomically:encoding:error:': (self, [pathPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, true);
            this.vfs.writeFile(path, this.readNSString(self) ?? '', ctx);
            return 1n;
          } catch {
            return 0n;
          }
        },
        description: (self) => self,
      },
    });

    // ---- NSMutableString ----
    this.registerHostClass('NSMutableString', 'NSString', {
      classMethods: {
        string: () => this.createNSString('', true),
        'stringWithCapacity:': () => this.createNSString('', true),
        'stringWithString:': (_cls, [strPtr]) => this.createNSString(this.readNSString(strPtr) ?? '', true),
      },
      instanceMethods: {
        'appendString:': (self, [other]) => {
          const data = this.getHostObject(self);
          if (data) data.value = (data.value ?? '') + (this.readNSString(other) ?? '');
          return 0n;
        },
        'setString:': (self, [other]) => {
          const data = this.getHostObject(self);
          if (data) data.value = this.readNSString(other) ?? '';
          return 0n;
        },
      },
    });

    // ---- NSNumber ----
    this.registerHostClass('NSNumber', 'NSObject', {
      classMethods: {
        'numberWithInt:': (_cls, [v]) => this.createNSNumber(Number(BigInt.asIntN(32, v)), 'int'),
        'numberWithInteger:': (_cls, [v]) => this.createNSNumber(Number(BigInt.asIntN(64, v)), 'int'),
        'numberWithLongLong:': (_cls, [v]) => this.createNSNumber(Number(BigInt.asIntN(64, v)), 'int'),
        'numberWithUnsignedInteger:': (_cls, [v]) => this.createNSNumber(Number(v), 'uint'),
        'numberWithBool:': (_cls, [v]) => this.createNSNumber(v !== 0n ? 1 : 0, 'bool'),
        'numberWithDouble:': (_cls, _args, { cpu }) => this.createNSNumber(getCpuFloatArg(cpu, 0), 'double'),
        'numberWithFloat:': (_cls, _args, { cpu }) => this.createNSNumber(getCpuSingleFloatArg(cpu, 0), 'float'),
      },
      instanceMethods: {
        intValue: (self) => BigInt.asUintN(64, BigInt(Math.trunc(Number(this.getHostObject(self)?.value ?? 0)))),
        integerValue: (self) => BigInt.asUintN(64, BigInt(Math.trunc(Number(this.getHostObject(self)?.value ?? 0)))),
        longLongValue: (self) => BigInt.asUintN(64, BigInt(Math.trunc(Number(this.getHostObject(self)?.value ?? 0)))),
        boolValue: (self) => (this.getHostObject(self)?.value ? 1n : 0n),
        doubleValue: (self, _args, { cpu }) => {
          const v = Number(this.getHostObject(self)?.value ?? 0);
          setCpuFloatReturn(cpu, v);
          return f64ToBits(v);
        },
        floatValue: (self, _args, { cpu }) => {
          const v = Math.fround(Number(this.getHostObject(self)?.value ?? 0));
          setCpuSingleFloatReturn(cpu, v);
          return f32ToBits(v);
        },
        stringValue: (self) => this.createNSString(String(this.getHostObject(self)?.value ?? 0)),
        'isEqualToNumber:': (self, [other]) => {
          const a = this.getHostObject(self)?.value;
          const b = this.getHostObject(other)?.value;
          return a === b ? 1n : 0n;
        },
      },
    });

    // ---- NSArray & NSMutableArray ----
    this.registerHostClass('NSArray', 'NSObject', {
      classMethods: {
        array: () => this.createNSArray([]),
        'arrayWithObject:': (_cls, [obj]) => this.createNSArray([obj]),
        'arrayWithObjects:count:': (_cls, [objsPtr, count]) => {
          const n = Math.min(Number(count), 65536);
          const items = [];
          for (let i = 0; i < n; i++) {
            items.push(this.addressSpace.readU64(objsPtr + BigInt(i * 8), true));
          }
          return this.createNSArray(items);
        },
      },
      instanceMethods: {
        init: (self) => {
          const data = this.getHostObject(self);
          if (data && !Array.isArray(data.items)) data.items = [];
          return self;
        },
        count: (self) => BigInt(this.getHostObject(self)?.items?.length ?? 0),
        'objectAtIndex:': (self, [idx]) => {
          const items = this.getHostObject(self)?.items ?? [];
          const i = Number(idx);
          return i >= 0 && i < items.length ? items[i] : 0n;
        },
        'objectAtIndexedSubscript:': (self, [idx]) => {
          const items = this.getHostObject(self)?.items ?? [];
          const i = Number(idx);
          return i >= 0 && i < items.length ? items[i] : 0n;
        },
        firstObject: (self) => {
          const items = this.getHostObject(self)?.items ?? [];
          return items.length > 0 ? items[0] : 0n;
        },
        lastObject: (self) => {
          const items = this.getHostObject(self)?.items ?? [];
          return items.length > 0 ? items[items.length - 1] : 0n;
        },
        'containsObject:': (self, [obj], { cpu }) => {
          const items = this.getHostObject(self)?.items ?? [];
          for (const it of items) {
            if (it === obj || this.msgSend(cpu, it, 'isEqual:', [obj]) !== 0n) return 1n;
          }
          return 0n;
        },
        'componentsJoinedByString:': (self, [sepPtr]) => {
          const items = this.getHostObject(self)?.items ?? [];
          const sep = this.readNSString(sepPtr) ?? '';
          return this.createNSString(items.map((it) => this.describeObject(it)).join(sep));
        },
      },
    });

    this.registerHostClass('NSMutableArray', 'NSArray', {
      classMethods: {
        array: () => this.createNSArray([], true),
        'arrayWithCapacity:': () => this.createNSArray([], true),
      },
      instanceMethods: {
        'addObject:': (self, [obj]) => {
          const data = this.getHostObject(self);
          if (data && obj !== 0n) {
            if (!data.items) data.items = [];
            this.retain(obj);
            data.items.push(toBigIntPtr(obj));
          }
          return 0n;
        },
        'insertObject:atIndex:': (self, [obj, idx]) => {
          const data = this.getHostObject(self);
          if (data && obj !== 0n) {
            if (!data.items) data.items = [];
            const i = Number(BigInt.asIntN(64, idx));
            if (Number.isSafeInteger(i) && i >= 0 && i <= data.items.length) {
              this.retain(obj);
              data.items.splice(i, 0, toBigIntPtr(obj));
            }
          }
          return 0n;
        },
        removeLastObject: (self, _args, { cpu }) => {
          const data = this.getHostObject(self);
          if (data?.items?.length) {
            const removed = data.items.pop();
            this.release(removed, cpu);
          }
          return 0n;
        },
        'removeObjectAtIndex:': (self, [idx], { cpu }) => {
          const data = this.getHostObject(self);
          const i = Number(idx);
          if (data?.items && i >= 0 && i < data.items.length) {
            const [removed] = data.items.splice(i, 1);
            this.release(removed, cpu);
          }
          return 0n;
        },
        removeAllObjects: (self, _args, { cpu }) => {
          const data = this.getHostObject(self);
          if (data?.items) {
            for (const p of data.items) this.release(p, cpu);
            data.items = [];
          }
          return 0n;
        },
        'setObject:atIndexedSubscript:': (self, [obj, idx], { cpu }) => {
          const data = this.getHostObject(self);
          if (data && obj !== 0n) {
            if (!data.items) data.items = [];
            const i = Number(BigInt.asIntN(64, idx));
            if (!Number.isSafeInteger(i) || i < 0 || i > data.items.length) {
              return 0n;
            }
            if (i < data.items.length) this.release(data.items[i], cpu);
            this.retain(obj);
            data.items[i] = toBigIntPtr(obj);
          }
          return 0n;
        },
      },
    });

    // ---- NSDictionary & NSMutableDictionary ----
    this.registerHostClass('NSDictionary', 'NSObject', {
      classMethods: {
        dictionary: () => this.createNSDictionary([]),
        'dictionaryWithObject:forKey:': (_cls, [obj, key]) => this.createNSDictionary([[key, obj]]),
        'dictionaryWithObjects:forKeys:count:': (_cls, [objsPtr, keysPtr, count]) => {
          const n = Math.min(Number(count), 65536);
          const entries = [];
          for (let i = 0; i < n; i++) {
            const v = this.addressSpace.readU64(objsPtr + BigInt(i * 8), true);
            const k = this.addressSpace.readU64(keysPtr + BigInt(i * 8), true);
            entries.push([k, v]);
          }
          return this.createNSDictionary(entries);
        },
      },
      instanceMethods: {
        init: (self) => {
          const data = this.getHostObject(self);
          if (data && !(data.map instanceof Map)) data.map = new Map();
          return self;
        },
        count: (self) => BigInt(this.getHostObject(self)?.map?.size ?? 0),
        'objectForKey:': (self, [keyPtr]) => {
          const map = this.getHostObject(self)?.map;
          const k = this.readNSString(keyPtr);
          return map && k !== null ? (map.get(k) ?? 0n) : 0n;
        },
        'objectForKeyedSubscript:': (self, [keyPtr]) => {
          const map = this.getHostObject(self)?.map;
          const k = this.readNSString(keyPtr);
          return map && k !== null ? (map.get(k) ?? 0n) : 0n;
        },
        allKeys: (self) => {
          const map = this.getHostObject(self)?.map ?? new Map();
          return this.createNSArray(Array.from(map.keys()).map((k) => this.createNSString(k)));
        },
        allValues: (self) => {
          const map = this.getHostObject(self)?.map ?? new Map();
          return this.createNSArray(Array.from(map.values()));
        },
      },
    });

    this.registerHostClass('NSMutableDictionary', 'NSDictionary', {
      classMethods: {
        dictionary: () => this.createNSDictionary([], true),
        'dictionaryWithCapacity:': () => this.createNSDictionary([], true),
      },
      instanceMethods: {
        'setObject:forKey:': (self, [obj, keyPtr], { cpu }) => {
          const data = this.getHostObject(self);
          const k = this.readNSString(keyPtr);
          if (data && k !== null) {
            if (!data.map) data.map = new Map();
            const prev = data.map.get(k);
            if (prev) this.release(prev, cpu);
            this.retain(obj);
            data.map.set(k, toBigIntPtr(obj));
          }
          return 0n;
        },
        'setObject:forKeyedSubscript:': (self, [obj, keyPtr], { cpu }) => {
          const data = this.getHostObject(self);
          const k = this.readNSString(keyPtr);
          if (data && k !== null) {
            if (!data.map) data.map = new Map();
            const prev = data.map.get(k);
            if (prev) this.release(prev, cpu);
            if (obj === 0n) {
              data.map.delete(k);
            } else {
              this.retain(obj);
              data.map.set(k, toBigIntPtr(obj));
            }
          }
          return 0n;
        },
        'removeObjectForKey:': (self, [keyPtr], { cpu }) => {
          const data = this.getHostObject(self);
          const k = this.readNSString(keyPtr);
          if (data?.map && k !== null && data.map.has(k)) {
            this.release(data.map.get(k), cpu);
            data.map.delete(k);
          }
          return 0n;
        },
        removeAllObjects: (self, _args, { cpu }) => {
          const data = this.getHostObject(self);
          if (data?.map) {
            for (const p of data.map.values()) this.release(p, cpu);
            data.map.clear();
          }
          return 0n;
        },
      },
    });

    // ---- NSData & NSMutableData ----
    this.registerHostClass('NSData', 'NSObject', {
      classMethods: {
        data: () => this.createNSData(new Uint8Array(0)),
        'dataWithBytes:length:': (_cls, [bytesPtr, len]) => {
          const n = Math.max(0, Number(len));
          const raw = n > 0 && bytesPtr !== 0n ? this.addressSpace.read(bytesPtr, n) : new Uint8Array(0);
          return this.createNSData(raw);
        },
        'dataWithContentsOfFile:': (_cls, [pathPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, false);
            const raw = this.vfs.readFile(path, ctx);
            return this.createNSData(raw);
          } catch {
            return 0n;
          }
        },
      },
      instanceMethods: {
        'initWithBytes:length:': (self, [bytesPtr, len]) => {
          const data = this.getHostObject(self);
          const n = Math.max(0, Number(len));
          if (data) {
            data.bytes =
              n > 0 && bytesPtr !== 0n
                ? this.addressSpace.read(bytesPtr, n).slice()
                : new Uint8Array(0);
          }
          return self;
        },
        length: (self) => BigInt(this.getHostObject(self)?.bytes?.byteLength ?? 0),
        bytes: (self) => {
          const data = this.getHostObject(self);
          if (!data || !data.bytes || data.bytes.byteLength === 0) return 0n;
          if (data._bytesCachePtr) {
            this._freeHeap(data._bytesCachePtr);
          }
          const bufPtr = this._allocHeap(data.bytes.byteLength, false);
          this.addressSpace.write(bufPtr, data.bytes);
          data._bytesCachePtr = bufPtr;
          return bufPtr;
        },
        'writeToFile:atomically:': (self, [pathPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          const data = this.getHostObject(self);
          if (!path || !data) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, true);
            this.vfs.writeFile(path, data.bytes ?? new Uint8Array(0), ctx);
            return 1n;
          } catch {
            return 0n;
          }
        },
      },
    });

    this.registerHostClass('NSMutableData', 'NSData', {
      classMethods: {
        data: () => this.createNSData(new Uint8Array(0), true),
        'dataWithCapacity:': () => this.createNSData(new Uint8Array(0), true),
      },
      instanceMethods: {
        'appendBytes:length:': (self, [bytesPtr, len]) => {
          const data = this.getHostObject(self);
          const n = Math.max(0, Number(len));
          if (data && n > 0 && bytesPtr !== 0n) {
            const extra = this.addressSpace.read(bytesPtr, n);
            const prev = data.bytes ?? new Uint8Array(0);
            const next = new Uint8Array(prev.byteLength + extra.byteLength);
            next.set(prev, 0);
            next.set(extra, prev.byteLength);
            data.bytes = next;
          }
          return 0n;
        },
      },
    });

    // ---- NSUserDefaults (Live-backed by UnifiedConfigStore `configStore.defaults`) ----
    const defaultsGet = (domain, key) => {
      if (this.configStore?.defaults) {
        const val = this.configStore.defaults.get(domain, key);
        if (val !== null && val !== undefined) return val;
        if (domain !== 'NSGlobalDomain') {
          return this.configStore.defaults.get('NSGlobalDomain', key);
        }
        return null;
      }
      const d = this._fallbackDefaults.get(domain);
      if (d && d.has(key)) return d.get(key);
      return this._fallbackDefaults.get('NSGlobalDomain')?.get(key) ?? null;
    };

    const defaultsSet = (domain, key, val) => {
      if (this.configStore?.defaults) {
        this.configStore.defaults.set(domain, key, val);
        return;
      }
      if (!this._fallbackDefaults.has(domain)) {
        this._fallbackDefaults.set(domain, new Map());
      }
      this._fallbackDefaults.get(domain).set(key, val);
    };

    const defaultsRemove = (domain, key) => {
      if (this.configStore?.defaults) {
        // Contract: configStore.defaults.remove() (NOT .delete()!)
        this.configStore.defaults.remove(domain, key);
        return;
      }
      this._fallbackDefaults.get(domain)?.delete(key);
    };

    this.registerHostClass('NSUserDefaults', 'NSObject', {
      classMethods: {
        standardUserDefaults: () => {
          if (!this._singletons.has('NSUserDefaults')) {
            const ptr = this.allocObject('NSUserDefaults', { domain: this.appId });
            const rec = this._objects.get(ptr);
            if (rec) rec.immortal = true;
            this._singletons.set('NSUserDefaults', ptr);
          }
          return this._singletons.get('NSUserDefaults');
        },
      },
      instanceMethods: {
        'initWithSuiteName:': (self, [suitePtr]) => {
          const data = this.getHostObject(self);
          if (data) {
            data.domain = this.readNSString(suitePtr) || this.appId;
          }
          return self;
        },
        'setObject:forKey:': (self, [valPtr, keyPtr]) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          if (!key) return 0n;
          if (valPtr === 0n) {
            defaultsRemove(domain, key);
          } else {
            defaultsSet(domain, key, this.objcToJs(valPtr));
          }
          return 0n;
        },
        'setInteger:forKey:': (self, [intVal, keyPtr]) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          if (key) defaultsSet(domain, key, Number(BigInt.asIntN(64, intVal)));
          return 0n;
        },
        'setBool:forKey:': (self, [boolVal, keyPtr]) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          if (key) defaultsSet(domain, key, boolVal !== 0n);
          return 0n;
        },
        'setDouble:forKey:': (self, [keyPtr], { cpu }) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          if (key) defaultsSet(domain, key, getCpuFloatArg(cpu, 0));
          return 0n;
        },
        'objectForKey:': (self, [keyPtr]) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          if (!key) return 0n;
          const val = defaultsGet(domain, key);
          return val === null || val === undefined ? 0n : this.jsToObjC(val);
        },
        'stringForKey:': (self, [keyPtr]) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          if (!key) return 0n;
          const val = defaultsGet(domain, key);
          return val === null || val === undefined ? 0n : this.createNSString(String(val));
        },
        'integerForKey:': (self, [keyPtr]) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          if (!key) return 0n;
          const val = defaultsGet(domain, key);
          return BigInt.asUintN(64, BigInt(Math.trunc(Number(val ?? 0)) || 0));
        },
        'boolForKey:': (self, [keyPtr]) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          if (!key) return 0n;
          return defaultsGet(domain, key) ? 1n : 0n;
        },
        'doubleForKey:': (self, [keyPtr], { cpu }) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          const v = key ? Number(defaultsGet(domain, key) ?? 0) || 0 : 0;
          setCpuFloatReturn(cpu, v);
          return f64ToBits(v);
        },
        'removeObjectForKey:': (self, [keyPtr]) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          const key = this.readNSString(keyPtr);
          if (key) defaultsRemove(domain, key);
          return 0n;
        },
        dictionaryRepresentation: (self) => {
          const domain = this.getHostObject(self)?.domain || this.appId;
          if (this.configStore?.defaults) {
            return this.jsToObjC(this.configStore.defaults.readDomain(domain));
          }
          const m = this._fallbackDefaults.get(domain);
          return this.jsToObjC(m ? Object.fromEntries(m.entries()) : {});
        },
        synchronize: () => 1n,
      },
    });

    // ---- NSFileManager (Live-backed by OmniOS VFS with Sandbox Context) ----
    this.registerHostClass('NSFileManager', 'NSObject', {
      classMethods: {
        defaultManager: () => {
          if (!this._singletons.has('NSFileManager')) {
            const ptr = this.allocObject('NSFileManager', {});
            const rec = this._objects.get(ptr);
            if (rec) rec.immortal = true;
            this._singletons.set('NSFileManager', ptr);
          }
          return this._singletons.get('NSFileManager');
        },
      },
      instanceMethods: {
        'fileExistsAtPath:': (_self, [pathPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, false);
            this.vfs.stat(path, ctx);
            return 1n;
          } catch {
            return 0n;
          }
        },
        'fileExistsAtPath:isDirectory:': (_self, [pathPtr, isDirOutPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, false);
            const st = this.vfs.stat(path, ctx);
            if (isDirOutPtr !== 0n) {
              this.addressSpace.writeU8(isDirOutPtr, st.type === 'dir' ? 1 : 0);
            }
            return 1n;
          } catch {
            if (isDirOutPtr !== 0n) this.addressSpace.writeU8(isDirOutPtr, 0);
            return 0n;
          }
        },
        'createDirectoryAtPath:withIntermediateDirectories:attributes:error:': (
          _self,
          [pathPtr, recursiveFlag]
        ) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, true);
            this.vfs.mkdir(path, { ...ctx, recursive: recursiveFlag !== 0n });
            return 1n;
          } catch {
            return 0n;
          }
        },
        'createFileAtPath:contents:attributes:': (_self, [pathPtr, dataPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          const bytes =
            dataPtr !== 0n ? (this.getHostObject(dataPtr)?.bytes ?? new Uint8Array(0)) : new Uint8Array(0);
          try {
            const ctx = this._resolveVfsCtxForPath(path, true);
            this.vfs.writeFile(path, bytes, ctx);
            return 1n;
          } catch {
            return 0n;
          }
        },
        'contentsAtPath:': (_self, [pathPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, false);
            const raw = this.vfs.readFile(path, ctx);
            return this.createNSData(raw);
          } catch {
            return 0n;
          }
        },
        'contentsOfDirectoryAtPath:error:': (_self, [pathPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, false);
            const entries = this.vfs.readdir(path, ctx);
            return this.createNSArray(entries.map((e) => this.createNSString(e.name)));
          } catch {
            return 0n;
          }
        },
        'removeItemAtPath:error:': (_self, [pathPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, true);
            const st = this.vfs.lstat(path, ctx);
            if (st.type === 'dir') this.vfs.rmdir(path, ctx);
            else this.vfs.unlink(path, ctx);
            return 1n;
          } catch {
            return 0n;
          }
        },
        'moveItemAtPath:toPath:error:': (_self, [srcPtr, dstPtr]) => {
          if (!this.vfs) return 0n;
          const src = this.readNSString(srcPtr);
          const dst = this.readNSString(dstPtr);
          if (!src || !dst) return 0n;
          try {
            const ctx = this._resolveRenameVfsCtx(src, dst);
            if (!ctx) return 0n;
            this.vfs.rename(src, dst, ctx);
            return 1n;
          } catch {
            return 0n;
          }
        },
        'copyItemAtPath:toPath:error:': (_self, [srcPtr, dstPtr]) => {
          if (!this.vfs) return 0n;
          const src = this.readNSString(srcPtr);
          const dst = this.readNSString(dstPtr);
          if (!src || !dst) return 0n;
          try {
            const rCtx = this._resolveVfsCtxForPath(src, false);
            const wCtx = this._resolveVfsCtxForPath(dst, true);
            const data = this.vfs.readFile(src, rCtx);
            this.vfs.writeFile(dst, data, wCtx);
            return 1n;
          } catch {
            return 0n;
          }
        },
        currentDirectoryPath: () => this.createNSString(this.pcb?.cwd ?? this.cwd),
        'changeCurrentDirectoryPath:': (_self, [pathPtr]) => {
          if (!this.vfs) return 0n;
          const path = this.readNSString(pathPtr);
          if (!path) return 0n;
          try {
            const ctx = this._resolveVfsCtxForPath(path, false);
            const st = this.vfs.stat(path, ctx);
            if (st.type !== 'dir') return 0n;
            const canonical = this.vfs.pathTranslator
              ? this.vfs.pathTranslator.toCanonical(path, {
                  platform: ctx.platform,
                  cwd: ctx.cwd,
                  appId: ctx.appId,
                  containerUuid: ctx.containerUuid,
                }).canonicalPath
              : path;
            this.cwd = canonical;
            if (this.pcb) this.pcb.cwd = canonical;
            return 1n;
          } catch {
            return 0n;
          }
        },
        'URLsForDirectory:inDomains:': (_self, [dirEnum]) => {
          const d = Number(dirEnum);
          let targetPath;
          if (this.platform === 'ios' && this.containerUuid) {
            targetPath =
              d === 13 // NSCachesDirectory
                ? `/var/mobile/Containers/Data/Application/${this.containerUuid}/Library/Caches`
                : `/var/mobile/Containers/Data/Application/${this.containerUuid}/Documents`;
          } else {
            targetPath = d === 13 ? '/Users/user/Library/Caches' : '/Users/user/Documents';
          }
          const url = this.allocObject('NSURL', {
            absoluteString: `file://${targetPath}`,
            path: targetPath,
            scheme: 'file',
            host: '',
          });
          return this.createNSArray([url]);
        },
      },
    });

    // ---- NSURL ----
    const parseUrlProps = (rawStr, isFilePath = false) => {
      const s = String(rawStr ?? '');
      if (isFilePath) {
        return { absoluteString: `file://${s}`, path: s, scheme: 'file', host: '' };
      }
      try {
        const u = new URL(s);
        return {
          absoluteString: u.href,
          path: u.pathname,
          scheme: u.protocol.replace(/:$/, ''),
          host: u.hostname,
        };
      } catch {
        return { absoluteString: s, path: s, scheme: '', host: '' };
      }
    };

    this.registerHostClass('NSURL', 'NSObject', {
      classMethods: {
        'URLWithString:': (_cls, [strPtr]) =>
          this.allocObject('NSURL', parseUrlProps(this.readNSString(strPtr) ?? '', false)),
        'fileURLWithPath:': (_cls, [pathPtr]) =>
          this.allocObject('NSURL', parseUrlProps(this.readNSString(pathPtr) ?? '', true)),
      },
      instanceMethods: {
        'initWithString:': (self, [strPtr]) => {
          Object.assign(this.getHostObject(self), parseUrlProps(this.readNSString(strPtr) ?? '', false));
          return self;
        },
        'initFileURLWithPath:': (self, [pathPtr]) => {
          Object.assign(this.getHostObject(self), parseUrlProps(this.readNSString(pathPtr) ?? '', true));
          return self;
        },
        absoluteString: (self) => this.createNSString(this.getHostObject(self)?.absoluteString ?? ''),
        path: (self) => this.createNSString(this.getHostObject(self)?.path ?? ''),
        scheme: (self) => this.createNSString(this.getHostObject(self)?.scheme ?? ''),
        host: (self) => this.createNSString(this.getHostObject(self)?.host ?? ''),
        lastPathComponent: (self) => {
          const p = (this.getHostObject(self)?.path ?? '').replace(/\/+$/, '');
          const idx = p.lastIndexOf('/');
          return this.createNSString(idx >= 0 ? p.slice(idx + 1) : p);
        },
        'URLByAppendingPathComponent:': (self, [compPtr]) => {
          const base = (this.getHostObject(self)?.path ?? '').replace(/\/+$/, '');
          const child = (this.readNSString(compPtr) ?? '').replace(/^\/+/, '');
          return this.allocObject('NSURL', parseUrlProps(`${base}/${child}`, true));
        },
      },
    });

    // ---- NSBundle ----
    this.registerHostClass('NSBundle', 'NSObject', {
      classMethods: {
        mainBundle: () => {
          if (!this._singletons.has('NSBundle')) {
            const ptr = this.allocObject('NSBundle', {
              bundleId: this.bundleInfo.CFBundleIdentifier ?? this.appId,
              bundlePath: this.bundlePath,
              info: this.bundleInfo,
            });
            const rec = this._objects.get(ptr);
            if (rec) rec.immortal = true;
            this._singletons.set('NSBundle', ptr);
          }
          return this._singletons.get('NSBundle');
        },
      },
      instanceMethods: {
        bundleIdentifier: (self) => this.createNSString(this.getHostObject(self)?.bundleId ?? this.appId),
        bundlePath: (self) => this.createNSString(this.getHostObject(self)?.bundlePath ?? this.bundlePath),
        resourcePath: (self) => this.createNSString(this.getHostObject(self)?.bundlePath ?? this.bundlePath),
        infoDictionary: (self) => this.jsToObjC(this.getHostObject(self)?.info ?? this.bundleInfo),
        'objectForInfoDictionaryKey:': (self, [keyPtr]) => {
          const key = this.readNSString(keyPtr);
          const info = this.getHostObject(self)?.info ?? this.bundleInfo;
          if (!key || !(key in info)) return 0n;
          return this.jsToObjC(info[key]);
        },
        'pathForResource:ofType:': (self, [namePtr, extPtr]) => {
          const name = this.readNSString(namePtr) ?? '';
          const ext = this.readNSString(extPtr) ?? '';
          const base = (this.getHostObject(self)?.bundlePath ?? this.bundlePath).replace(/\/+$/, '');
          return this.createNSString(ext ? `${base}/${name}.${ext}` : `${base}/${name}`);
        },
      },
    });

    // ---- NSProcessInfo ----
    this.registerHostClass('NSProcessInfo', 'NSObject', {
      classMethods: {
        processInfo: () => {
          if (!this._singletons.has('NSProcessInfo')) {
            const ptr = this.allocObject('NSProcessInfo', {});
            const rec = this._objects.get(ptr);
            if (rec) rec.immortal = true;
            this._singletons.set('NSProcessInfo', ptr);
          }
          return this._singletons.get('NSProcessInfo');
        },
      },
      instanceMethods: {
        processName: () => this.createNSString(this.pcb?.name ?? this.appId),
        processIdentifier: () => BigInt(this.pcb?.pid ?? 1),
        operatingSystemVersionString: () =>
          this.createNSString(
            this.platform === 'ios' ? 'Version 18.0 (OmniOS iOS)' : 'Version 15.0 (OmniOS macOS)'
          ),
        environment: () => this.jsToObjC(this.pcb?.env ?? {}),
        arguments: () => this.jsToObjC(this.pcb?.args ?? [this.appId]),
      },
    });
  }

  // =========================================================================
  // Built-in C, Libc, ObjC Runtime & Swift Thunks
  // =========================================================================

  _registerBuiltInCFunctions() {
    // ---- ObjC Runtime C API ----
    this.registerCFunction('objc_getClass', (cpu) => {
      const namePtr = getCpuArg(cpu, this.addressSpace, 0);
      if (namePtr === 0n) return 0n;
      return this.getClass(this.addressSpace.readCString(namePtr, 256));
    });
    this.registerCFunction('objc_lookUpClass', (cpu) => {
      const namePtr = getCpuArg(cpu, this.addressSpace, 0);
      if (namePtr === 0n) return 0n;
      return this.getClass(this.addressSpace.readCString(namePtr, 256));
    });
    this.registerCFunction('objc_getMetaClass', (cpu) => {
      const namePtr = getCpuArg(cpu, this.addressSpace, 0);
      if (namePtr === 0n) return 0n;
      return this.getClass(this.addressSpace.readCString(namePtr, 256));
    });
    this.registerCFunction('object_getClass', (cpu) => {
      const obj = getCpuArg(cpu, this.addressSpace, 0);
      if (obj === 0n) return 0n;
      const res = this._resolveReceiverClass(obj);
      return res ? res.classRec.ptr : 0n;
    });
    this.registerCFunction('class_getName', (cpu) => {
      const clsPtr = getCpuArg(cpu, this.addressSpace, 0);
      const rec = this._classesByPtr.get(clsPtr);
      return this._allocCString(rec ? rec.name : 'nil');
    });
    this.registerCFunction('class_getSuperclass', (cpu) => {
      const clsPtr = getCpuArg(cpu, this.addressSpace, 0);
      const rec = this._classesByPtr.get(clsPtr);
      return rec?.superName ? this.getClass(rec.superName) : 0n;
    });
    this.registerCFunction('sel_registerName', (cpu) => {
      const namePtr = getCpuArg(cpu, this.addressSpace, 0);
      if (namePtr === 0n) return 0n;
      return this.selRegisterName(this.addressSpace.readCString(namePtr, 256));
    });
    this.registerCFunction('sel_getName', (cpu) => {
      const selPtr = getCpuArg(cpu, this.addressSpace, 0);
      if (selPtr === 0n) return this._allocCString('<null selector>');
      return selPtr;
    });
    this.registerCFunction('NSClassFromString', (cpu) => {
      const strPtr = getCpuArg(cpu, this.addressSpace, 0);
      const name = this.readNSString(strPtr);
      return name ? this.getClass(name) : 0n;
    });
    this.registerCFunction('NSStringFromClass', (cpu) => {
      const clsPtr = getCpuArg(cpu, this.addressSpace, 0);
      const rec = this._classesByPtr.get(clsPtr);
      return rec ? this.createNSString(rec.name) : 0n;
    });
    this.registerCFunction('NSSelectorFromString', (cpu) => {
      const strPtr = getCpuArg(cpu, this.addressSpace, 0);
      const name = this.readNSString(strPtr);
      return name ? this.selRegisterName(name) : 0n;
    });
    this.registerCFunction('NSStringFromSelector', (cpu) => {
      const selPtr = getCpuArg(cpu, this.addressSpace, 0);
      return this.createNSString(this.selGetName(selPtr));
    });

    // ---- ARC Runtime Functions ----
    this.registerCFunction('objc_retain', (cpu) => this.retain(getCpuArg(cpu, this.addressSpace, 0)));
    this.registerCFunction('objc_release', (cpu) => {
      this.release(getCpuArg(cpu, this.addressSpace, 0), cpu);
      return 0n;
    });
    this.registerCFunction('objc_autorelease', (cpu) =>
      this.autorelease(getCpuArg(cpu, this.addressSpace, 0))
    );
    this.registerCFunction('objc_autoreleaseReturnValue', (cpu) =>
      this.autorelease(getCpuArg(cpu, this.addressSpace, 0))
    );
    this.registerCFunction('objc_retainAutoreleasedReturnValue', (cpu) =>
      this.retain(getCpuArg(cpu, this.addressSpace, 0))
    );
    this.registerCFunction('objc_claimAutoreleasedReturnValue', (cpu) =>
      this.retain(getCpuArg(cpu, this.addressSpace, 0))
    );
    this.registerCFunction('objc_autoreleasePoolPush', () => this.autoreleasePoolPush());
    this.registerCFunction('objc_autoreleasePoolPop', (cpu) => {
      this.autoreleasePoolPop(getCpuArg(cpu, this.addressSpace, 0), cpu);
      return 0n;
    });
    this.registerCFunction('objc_storeStrong', (cpu) => {
      const locPtr = getCpuArg(cpu, this.addressSpace, 0);
      const newObj = getCpuArg(cpu, this.addressSpace, 1);
      if (locPtr === 0n) return 0n;
      const oldObj = this.addressSpace.readU64(locPtr, true);
      if (oldObj === newObj) return 0n;
      this.retain(newObj);
      this.addressSpace.writeU64(locPtr, newObj, true);
      this.release(oldObj, cpu);
      return 0n;
    });
    this.registerCFunction('objc_alloc', (cpu) => this.allocObject(getCpuArg(cpu, this.addressSpace, 0)));
    this.registerCFunction('objc_alloc_init', (cpu) => {
      const clsPtr = getCpuArg(cpu, this.addressSpace, 0);
      const obj = this.allocObject(clsPtr);
      return this.msgSend(cpu, obj, 'init', []);
    });
    this.registerCFunction('objc_opt_new', (cpu) => {
      const clsPtr = getCpuArg(cpu, this.addressSpace, 0);
      return this.msgSend(cpu, clsPtr, 'new', []);
    });
    this.registerCFunction('objc_opt_self', (cpu) => getCpuArg(cpu, this.addressSpace, 0));
    this.registerCFunction('objc_opt_class', (cpu) => {
      const obj = getCpuArg(cpu, this.addressSpace, 0);
      if (obj === 0n) return 0n;
      const res = this._resolveReceiverClass(obj);
      return res ? res.classRec.ptr : 0n;
    });
    this.registerCFunction('objc_opt_isKindOfClass', (cpu) => {
      const obj = getCpuArg(cpu, this.addressSpace, 0);
      const clsPtr = getCpuArg(cpu, this.addressSpace, 1);
      return this.msgSend(cpu, obj, 'isKindOfClass:', [clsPtr]);
    });
    this.registerCFunction('objc_opt_respondsToSelector', (cpu) => {
      const obj = getCpuArg(cpu, this.addressSpace, 0);
      const selPtr = getCpuArg(cpu, this.addressSpace, 1);
      return this.msgSend(cpu, obj, 'respondsToSelector:', [selPtr]);
    });

    // ---- NSLog & Libc Formatted I/O (Edge Case #24: Apple ARM64 stack variadics!) ----
    this.registerCFunction('NSLog', (cpu) => {
      const fmtPtr = getCpuArg(cpu, this.addressSpace, 0);
      const fmt = this.readNSString(fmtPtr) ?? '';
      const specs = countFormatSpecifiers(fmt);
      const varArgs = readCpuVariadicArgs(cpu, this.addressSpace, 1, specs.length);
      const formatted = this._formatString(fmt, varArgs);
      this._emitLog(formatted);
      return 0n;
    });

    this.registerCFunction('printf', (cpu) => {
      const fmtPtr = getCpuArg(cpu, this.addressSpace, 0);
      const fmt = fmtPtr === 0n ? '' : this.addressSpace.readCString(fmtPtr, 65536);
      const specs = countFormatSpecifiers(fmt);
      const varArgs = readCpuVariadicArgs(cpu, this.addressSpace, 1, specs.length);
      const formatted = this._formatString(fmt, varArgs);
      this._emitStdout(formatted);
      return BigInt(TEXT_ENCODER.encode(formatted).byteLength);
    });

    this.registerCFunction('puts', (cpu) => {
      const strPtr = getCpuArg(cpu, this.addressSpace, 0);
      const s = strPtr === 0n ? '(null)' : this.addressSpace.readCString(strPtr, 65536);
      this._emitStdout(`${s}\n`);
      return BigInt(s.length + 1);
    });

    this.registerCFunction('putchar', (cpu) => {
      const ch = Number(getCpuArg(cpu, this.addressSpace, 0) & 0xffn);
      this._emitStdout(String.fromCharCode(ch));
      return BigInt(ch);
    });

    this.registerCFunction('snprintf', (cpu) => {
      const dstPtr = getCpuArg(cpu, this.addressSpace, 0);
      const maxSize = Number(getCpuArg(cpu, this.addressSpace, 1));
      const fmtPtr = getCpuArg(cpu, this.addressSpace, 2);
      const fmt = fmtPtr === 0n ? '' : this.addressSpace.readCString(fmtPtr, 65536);
      const specs = countFormatSpecifiers(fmt);
      const varArgs = readCpuVariadicArgs(cpu, this.addressSpace, 3, specs.length);
      const formatted = this._formatString(fmt, varArgs);
      const encoded = TEXT_ENCODER.encode(formatted);
      if (dstPtr !== 0n && maxSize > 0) {
        const writeLen = Math.min(encoded.byteLength, maxSize - 1);
        const outBuf = new Uint8Array(writeLen + 1);
        outBuf.set(encoded.subarray(0, writeLen), 0);
        outBuf[writeLen] = 0;
        this.addressSpace.write(dstPtr, outBuf);
      }
      return BigInt(encoded.byteLength);
    });

    // ---- Libc Heap & Memory Functions (`free(0n)` strictly guarded!) ----
    this.registerCFunction('malloc', (cpu) => {
      const rawSz = getCpuArg(cpu, this.addressSpace, 0);
      const validated = this._validateAllocSize(rawSz);
      if (validated === null) return 0n;
      try {
        return this._allocHeap(Math.max(1, validated), false);
      } catch {
        return 0n;
      }
    });
    this.registerCFunction('calloc', (cpu) => {
      const rawNmemb = getCpuArg(cpu, this.addressSpace, 0);
      const rawSize = getCpuArg(cpu, this.addressSpace, 1);
      const maxBig = BigInt(this._maxMemoryBytes());
      if (rawNmemb !== 0n && rawSize !== 0n && (rawNmemb > maxBig || rawSize > maxBig)) {
        return 0n;
      }
      const totalBig = rawNmemb * rawSize;
      const validated = this._validateAllocSize(totalBig);
      if (validated === null) return 0n;
      try {
        return this._allocHeap(Math.max(1, validated), true);
      } catch {
        return 0n;
      }
    });
    this.registerCFunction('realloc', (cpu) => {
      const ptr = getCpuArg(cpu, this.addressSpace, 0);
      const rawSize = getCpuArg(cpu, this.addressSpace, 1);
      if (rawSize === 0n) {
        if (ptr !== 0n) this._freeHeap(ptr);
        return 0n;
      }
      const validated = this._validateAllocSize(rawSize);
      if (validated === null) return 0n;
      try {
        if (ptr === 0n) {
          return this._allocHeap(validated, false);
        }
        const nextPtr = BigInt(this.addressSpace.realloc(Number(ptr), validated));
        this._heapAllocs.delete(ptr);
        this._heapAllocs.add(nextPtr);
        return nextPtr;
      } catch {
        return 0n;
      }
    });
    this.registerCFunction('free', (cpu) => {
      const ptr = getCpuArg(cpu, this.addressSpace, 0);
      if (ptr === 0n) return 0n; // Safe no-op (AddressSpace.free(0) throws SIGSEGV!)
      this._freeHeap(ptr);
      return 0n;
    });

    // ---- Libc String & Memory Operations ----
    this.registerCFunction('strlen', (cpu) => {
      const sPtr = getCpuArg(cpu, this.addressSpace, 0);
      if (sPtr === 0n) return 0n;
      const str = this.addressSpace.readCString(sPtr, 1_048_576);
      return BigInt(TEXT_ENCODER.encode(str).byteLength);
    });
    this.registerCFunction('strcmp', (cpu) => {
      const aPtr = getCpuArg(cpu, this.addressSpace, 0);
      const bPtr = getCpuArg(cpu, this.addressSpace, 1);
      const a = TEXT_ENCODER.encode(this.addressSpace.readCString(aPtr, 65536));
      const b = TEXT_ENCODER.encode(this.addressSpace.readCString(bPtr, 65536));
      const n = Math.min(a.length, b.length);
      for (let i = 0; i < n; i++) {
        if (a[i] !== b[i]) return BigInt.asUintN(64, BigInt(a[i] - b[i]));
      }
      return BigInt.asUintN(64, BigInt(a.length - b.length));
    });
    this.registerCFunction('strncmp', (cpu) => {
      const aPtr = getCpuArg(cpu, this.addressSpace, 0);
      const bPtr = getCpuArg(cpu, this.addressSpace, 1);
      const rawMaxN = getCpuArg(cpu, this.addressSpace, 2);
      if (rawMaxN === 0n) return 0n;
      const maxN = rawMaxN > 1_048_576n ? 1_048_576 : Number(rawMaxN);
      const a = TEXT_ENCODER.encode(this.addressSpace.readCString(aPtr, maxN));
      const b = TEXT_ENCODER.encode(this.addressSpace.readCString(bPtr, maxN));
      const n = Math.min(maxN, a.length, b.length);
      for (let i = 0; i < n; i++) {
        if (a[i] !== b[i]) return BigInt.asUintN(64, BigInt(a[i] - b[i]));
      }
      if (n < maxN && a.length !== b.length) {
        return BigInt.asUintN(64, BigInt((a[n] ?? 0) - (b[n] ?? 0)));
      }
      return 0n;
    });
    this.registerCFunction('memcpy', (cpu) => {
      const dst = getCpuArg(cpu, this.addressSpace, 0);
      const src = getCpuArg(cpu, this.addressSpace, 1);
      const rawN = getCpuArg(cpu, this.addressSpace, 2);
      if (rawN === 0n) return dst;
      const n = this._validateMemOpLength(rawN, 'memcpy', dst);
      let copied = 0;
      while (copied < n) {
        const len = Math.min(MEM_CHUNK_BYTES, n - copied);
        const off = BigInt(copied);
        const data = this.addressSpace.read(src + off, len);
        this.addressSpace.write(dst + off, data);
        copied += len;
      }
      return dst;
    });
    this.registerCFunction('memmove', (cpu) => {
      const dst = getCpuArg(cpu, this.addressSpace, 0);
      const src = getCpuArg(cpu, this.addressSpace, 1);
      const rawN = getCpuArg(cpu, this.addressSpace, 2);
      if (rawN === 0n || dst === src) return dst;
      const n = this._validateMemOpLength(rawN, 'memmove', dst);
      if (dst > src && dst < src + BigInt(n)) {
        let remaining = n;
        while (remaining > 0) {
          const len = Math.min(MEM_CHUNK_BYTES, remaining);
          const off = BigInt(remaining - len);
          const data = this.addressSpace.read(src + off, len).slice();
          this.addressSpace.write(dst + off, data);
          remaining -= len;
        }
      } else {
        let copied = 0;
        while (copied < n) {
          const len = Math.min(MEM_CHUNK_BYTES, n - copied);
          const off = BigInt(copied);
          const data = this.addressSpace.read(src + off, len).slice();
          this.addressSpace.write(dst + off, data);
          copied += len;
        }
      }
      return dst;
    });
    this.registerCFunction('memset', (cpu) => {
      const dst = getCpuArg(cpu, this.addressSpace, 0);
      const val = Number(getCpuArg(cpu, this.addressSpace, 1) & 0xffn);
      const rawN = getCpuArg(cpu, this.addressSpace, 2);
      if (rawN === 0n) return dst;
      const n = this._validateMemOpLength(rawN, 'memset', dst);
      const chunkSize = Math.min(MEM_CHUNK_BYTES, n);
      const chunk = val === 0 ? ZERO_CHUNK : new Uint8Array(chunkSize);
      if (val !== 0) chunk.fill(val);
      let written = 0;
      while (written < n) {
        const len = Math.min(chunkSize, n - written);
        this.addressSpace.write(
          dst + BigInt(written),
          len === chunk.byteLength ? chunk : chunk.subarray(0, len)
        );
        written += len;
      }
      return dst;
    });
    this.registerCFunction('memcmp', (cpu) => {
      const aPtr = getCpuArg(cpu, this.addressSpace, 0);
      const bPtr = getCpuArg(cpu, this.addressSpace, 1);
      const rawN = getCpuArg(cpu, this.addressSpace, 2);
      if (rawN === 0n) return 0n;
      const n = this._validateMemOpLength(rawN, 'memcmp', aPtr);
      let checked = 0;
      while (checked < n) {
        const len = Math.min(MEM_CHUNK_BYTES, n - checked);
        const off = BigInt(checked);
        const a = this.addressSpace.read(aPtr + off, len);
        const b = this.addressSpace.read(bPtr + off, len);
        for (let i = 0; i < len; i++) {
          if (a[i] !== b[i]) return BigInt.asUintN(64, BigInt(a[i] - b[i]));
        }
        checked += len;
      }
      return 0n;
    });
    this.registerCFunction('exit', (cpu) => {
      const code = Number(BigInt.asIntN(32, getCpuArg(cpu, this.addressSpace, 0))) & 0xff;
      return { status: 'EXITED', exitCode: code };
    });
    this.registerCFunction('_exit', (cpu) => {
      const code = Number(BigInt.asIntN(32, getCpuArg(cpu, this.addressSpace, 0))) & 0xff;
      return { status: 'EXITED', exitCode: code };
    });

    // ---- Swift Runtime (`swiftcall` & ARC) ----
    this.registerCFunction('swift_allocObject', (cpu) => {
      const metadataPtr = getCpuArg(cpu, this.addressSpace, 0);
      const rawSize = getCpuArg(cpu, this.addressSpace, 1);
      const validated = this._validateAllocSize(rawSize);
      if (validated === null) return 0n;
      const requiredSize = Math.max(16, validated);
      try {
        const ptr = this._allocHeap(requiredSize, true);
        this.addressSpace.writeU64(ptr, metadataPtr, true);
        this.addressSpace.writeU64(ptr + 8n, 1n, true); // inline refcount
        this._swiftObjects.set(ptr, { ptr, metadataPtr, size: requiredSize, refCount: 1 });
        return ptr;
      } catch {
        return 0n;
      }
    });
    this.registerCFunction('swift_retain', (cpu) => {
      const ptr = getCpuArg(cpu, this.addressSpace, 0);
      if (ptr === 0n) return 0n;
      const sw = this._swiftObjects.get(ptr);
      if (sw) {
        sw.refCount += 1;
        this.addressSpace.writeU64(ptr + 8n, BigInt(sw.refCount), true);
      } else {
        this.retain(ptr);
      }
      return ptr;
    });
    this.registerCFunction('swift_release', (cpu) => {
      const ptr = getCpuArg(cpu, this.addressSpace, 0);
      if (ptr === 0n) return 0n;
      const sw = this._swiftObjects.get(ptr);
      if (sw) {
        sw.refCount -= 1;
        if (sw.refCount <= 0) {
          this._swiftObjects.delete(ptr);
          this._freeHeap(ptr);
        } else {
          this.addressSpace.writeU64(ptr + 8n, BigInt(sw.refCount), true);
        }
      } else {
        this.release(ptr, cpu);
      }
      return 0n;
    });
    this.registerCFunction('swift_bridgeObjectRetain', (cpu) => {
      const bits = getCpuArg(cpu, this.addressSpace, 0);
      if (bits === 0n) return 0n;
      // Tagged Swift bridge objects have high tag bits set; extract lower 48-bit pointer if untagged
      if ((bits >> 56n) === 0n) {
        if (this._swiftObjects.has(bits)) {
          const sw = this._swiftObjects.get(bits);
          sw.refCount += 1;
        } else if (this._objects.has(bits)) {
          this.retain(bits);
        }
      }
      return bits;
    });
    this.registerCFunction('swift_bridgeObjectRelease', (cpu) => {
      const bits = getCpuArg(cpu, this.addressSpace, 0);
      if (bits === 0n) return 0n;
      if ((bits >> 56n) === 0n) {
        if (this._swiftObjects.has(bits)) {
          const sw = this._swiftObjects.get(bits);
          sw.refCount -= 1;
          if (sw.refCount <= 0) {
            this._swiftObjects.delete(bits);
            this._freeHeap(bits);
          }
        } else if (this._objects.has(bits)) {
          this.release(bits, cpu);
        }
      }
      return 0n;
    });
    this.registerCFunction('swift_beginAccess', () => 0n);
    this.registerCFunction('swift_endAccess', () => 0n);
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    this._autoreleasePools = [];
    this._objects.clear();
    this._swiftObjects.clear();
    this._classesByName.clear();
    this._classesByPtr.clear();
    this._selByName.clear();
    this._selByAddr.clear();
    this._cFunctions.clear();
    this._singletons.clear();
    this._heapAllocs.clear();
  }
}

export function createObjCRuntime(opts = {}) {
  return new ObjCRuntime(opts);
}
