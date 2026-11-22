/**
 * Dynamic, Standards-Compliant Apple (Mach-O 64-bit ARM64/x86-64, Universal Fat,
 * ObjC ABI2, iOS .ipa, macOS .app.zip, UDIF .dmg koly, XAR .pkg) and Universal
 * WebAssembly (.wasm / .uapp) Binary Fixture Builders.
 *
 * Acyclic Dependency: imports ONLY Node 24 built-in (`node:zlib`)
 * + `./binary-utils.mjs` (reuses `buildBinaryPlist`, `buildXmlPlist`, `buildZip`, etc.
 * without duplication).
 */

import zlib from 'node:zlib';
import {
  BinaryWriter,
  alignUp,
  concatBytes,
  crc32,
  sha1,
  sha1Hex,
  sha256,
  encodeUleb128,
  encodeSleb128,
  escapeXml,
  buildZip,
  buildBinaryPlist,
  buildXmlPlist,
} from './binary-utils.mjs';

export { buildBinaryPlist, buildXmlPlist };

const textEncoder = new TextEncoder();

// ============================================================================
// 1. ARM64 (AArch64) & x86-64 Darwin Instruction Encoders
// ============================================================================

export const ARM64_SVC_80 = 0xd4001001;
export const ARM64_RET = 0xd65f03c0;
export const ARM64_NOP = 0xd503201f;

export function arm64Movz(rd, imm16, hw = 0) {
  return (0xd2800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0;
}

export function arm64Movk(rd, imm16, hw = 0) {
  return (0xf2800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0;
}

export function arm64MovReg(rd, rm) {
  // ORR Xd, XZR, Xm
  return (0xaa0003e0 | ((rm & 31) << 16) | (rd & 31)) >>> 0;
}

export function arm64AddImm(rd, rn, imm12) {
  return (0x91000000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0;
}

export function arm64SubImm(rd, rn, imm12) {
  return (0xd1000000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0;
}

export function arm64SubsImm(rd, rn, imm12) {
  return (0xf1000000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0;
}

export function arm64AddReg(rd, rn, rm) {
  return (0x8b000000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0;
}

export function arm64SubReg(rd, rn, rm) {
  return (0xcb000000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0;
}

export function arm64Adr(rd, byteDelta) {
  const imm = byteDelta & 0x1fffff;
  return (0x10000000 | ((imm & 3) << 29) | (((imm >>> 2) & 0x7ffff) << 5) | (rd & 31)) >>> 0;
}

/**
 * ARM64 ADRP uses 4 KiB (~0xFFF) page masking (NOT 16 KiB!).
 */
export function arm64Adrp(rd, pcVa, targetVa) {
  const pcPage = Number((BigInt(pcVa) & ~0xfffn) >> 12n);
  const tgtPage = Number((BigInt(targetVa) & ~0xfffn) >> 12n);
  const imm = (tgtPage - pcPage) & 0x1fffff;
  return (0x90000000 | ((imm & 3) << 29) | (((imm >>> 2) & 0x7ffff) << 5) | (rd & 31)) >>> 0;
}

export function arm64Ldr64(rt, rn, byteOff = 0) {
  return (0xf9400000 | (((byteOff >>> 3) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0;
}

export function arm64Str64(rt, rn, byteOff = 0) {
  return (0xf9000000 | (((byteOff >>> 3) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0;
}

export function arm64Blr(rn) {
  return (0xd63f0000 | ((rn & 31) << 5)) >>> 0;
}

export function arm64Cbz(rt, byteDelta) {
  return (0xb4000000 | ((((byteDelta >> 2) & 0x7ffff) << 5)) | (rt & 31)) >>> 0;
}

export function arm64Cbnz(rt, byteDelta) {
  return (0xb5000000 | ((((byteDelta >> 2) & 0x7ffff) << 5)) | (rt & 31)) >>> 0;
}

export function arm64BCond(cond, byteDelta) {
  // cond: 0x0=EQ, 0x1=NE, 0x2=CS/HS, 0x3=CC/LO
  return (0x54000000 | ((((byteDelta >> 2) & 0x7ffff) << 5)) | (cond & 0x0f)) >>> 0;
}

export function packArm64Insns(insns) {
  const w = new BinaryWriter(insns.length * 4);
  for (const insn of insns) w.u32le(insn >>> 0);
  return w.toUint8Array();
}

export function encodeArm64WriteExit({ message = 'OmniOS ARM64\n', exitCode = 0, textOff = 0x1000, cstringOff = null } = {}) {
  const msgBytes = textEncoder.encode(String(message));
  const cstringBytes = concatBytes(msgBytes, [0]);
  const codeLen = 8 * 4; // 32 bytes
  const strOff = cstringOff ?? alignUp(textOff + codeLen, 16);

  const codeBytes = packArm64Insns([
    arm64Adr(1, strOff - textOff), // adr x1, msg
    arm64Movz(0, 1), // stdout = 1
    arm64Movz(2, msgBytes.length & 0xffff), // len
    arm64Movz(16, 4), // SYS_write
    ARM64_SVC_80,
    arm64Movz(0, exitCode & 0xffff),
    arm64Movz(16, 1), // SYS_exit
    ARM64_SVC_80,
  ]);

  return { codeBytes, cstringBytes, cstringOff: strOff };
}

/**
 * Darwin ARM64 file write using BSD flags: O_WRONLY|O_CREAT|O_TRUNC = 0x0601, mode = 0o644 = 0x1A4.
 */
export function encodeArm64FileWriteExit({
  filePath,
  content = '',
  exitCode = 0,
  textOff = 0x1000,
  cstringOff = null,
} = {}) {
  const pathZ = concatBytes(textEncoder.encode(String(filePath)), [0]);
  const contentBytes = textEncoder.encode(String(content));
  const cstringBytes = concatBytes(pathZ, contentBytes, [0]);
  const codeLen = 17 * 4; // 68 bytes
  const strOff = cstringOff ?? alignUp(textOff + codeLen, 16);
  const pathOff = strOff;
  const contentOff = strOff + pathZ.length;

  const codeBytes = packArm64Insns([
    arm64Adr(0, pathOff - (textOff + 0)), // adr x0, path
    arm64Movz(1, 0x0601), // O_WRONLY|O_CREAT|O_TRUNC (Darwin)
    arm64Movz(2, 0x01a4), // 0o644
    arm64Movz(16, 5), // SYS_open
    ARM64_SVC_80,
    arm64MovReg(19, 0), // save fd in x19
    arm64MovReg(0, 19), // fd
    arm64Adr(1, contentOff - (textOff + 28)), // adr x1, content
    arm64Movz(2, contentBytes.length & 0xffff),
    arm64Movz(16, 4), // SYS_write
    ARM64_SVC_80,
    arm64MovReg(0, 19),
    arm64Movz(16, 6), // SYS_close
    ARM64_SVC_80,
    arm64Movz(0, exitCode & 0xffff),
    arm64Movz(16, 1), // SYS_exit
    ARM64_SVC_80,
  ]);

  return { codeBytes, cstringBytes, cstringOff: strOff };
}

export function encodeX64DarwinWriteExit({ message = 'OmniOS x64\n', exitCode = 0, textOff = 0x1000, cstringOff = null } = {}) {
  const msgBytes = textEncoder.encode(String(message));
  const cstringBytes = concatBytes(msgBytes, [0]);
  const codeLen = 36;
  const strOff = cstringOff ?? alignUp(textOff + codeLen, 16);
  const disp32 = strOff - (textOff + 17); // lea rsi, [rip + disp32] is at +10, length 7

  const w = new BinaryWriter(codeLen);
  w.u8(0xb8).u32le(0x02000004) // mov eax, 0x2000004 (BSD write)
    .u8(0xbf).u32le(1) // mov edi, 1 (stdout)
    .bytes([0x48, 0x8d, 0x35]).i32le(disp32) // lea rsi, [rip + disp32]
    .u8(0xba).u32le(msgBytes.length) // mov edx, len
    .bytes([0x0f, 0x05]) // syscall
    .u8(0xb8).u32le(0x02000001) // mov eax, 0x2000001 (BSD exit)
    .u8(0xbf).u32le(exitCode >>> 0) // mov edi, exitCode
    .bytes([0x0f, 0x05]); // syscall

  return { codeBytes: w.toUint8Array(), cstringBytes, cstringOff: strOff };
}

/**
 * Darwin x86-64 file write using BSD syscalls:
 * SYS_open (0x2000005, flags=0x0601 [O_WRONLY|O_CREAT|O_TRUNC], mode=0o644 [0x01a4]),
 * SYS_write (0x2000004), SYS_close (0x2000006), SYS_exit (0x2000001).
 */
export function encodeX64DarwinFileWriteExit({
  filePath,
  content = '',
  exitCode = 0,
  textOff = 0x1000,
  cstringOff = null,
} = {}) {
  const pathZ = concatBytes(textEncoder.encode(String(filePath)), [0]);
  const contentBytes = textEncoder.encode(String(content));
  const cstringBytes = concatBytes(pathZ, contentBytes, [0]);
  const codeLen = 68;
  const strOff = cstringOff ?? alignUp(textOff + codeLen, 16);
  const pathOff = strOff;
  const contentOff = strOff + pathZ.length;
  const pathDisp32 = pathOff - (textOff + 12); // lea rdi, [rip + disp32] at +5, len 7
  const contentDisp32 = contentOff - (textOff + 40); // lea rsi, [rip + disp32] at +33, len 7

  const w = new BinaryWriter(codeLen);
  w.u8(0xb8).u32le(0x02000005) // +0  mov eax, 0x2000005 (BSD open)
    .bytes([0x48, 0x8d, 0x3d]).i32le(pathDisp32) // +5  lea rdi, [rip + pathDisp32]
    .u8(0xbe).u32le(0x0601) // +12 mov esi, 0x0601 (O_WRONLY|O_CREAT|O_TRUNC)
    .u8(0xba).u32le(0x01a4) // +17 mov edx, 0x01a4 (0o644)
    .bytes([0x0f, 0x05]) // +22 syscall -> rax = fd
    .bytes([0x89, 0xc3]) // +24 mov ebx, eax (save fd in callee-saved ebx)
    .u8(0xb8).u32le(0x02000004) // +26 mov eax, 0x2000004 (BSD write)
    .bytes([0x89, 0xdf]) // +31 mov edi, ebx (fd)
    .bytes([0x48, 0x8d, 0x35]).i32le(contentDisp32) // +33 lea rsi, [rip + contentDisp32]
    .u8(0xba).u32le(contentBytes.length) // +40 mov edx, contentLen
    .bytes([0x0f, 0x05]) // +45 syscall
    .u8(0xb8).u32le(0x02000006) // +47 mov eax, 0x2000006 (BSD close)
    .bytes([0x89, 0xdf]) // +52 mov edi, ebx (fd)
    .bytes([0x0f, 0x05]) // +54 syscall
    .u8(0xb8).u32le(0x02000001) // +56 mov eax, 0x2000001 (BSD exit)
    .u8(0xbf).u32le(exitCode >>> 0) // +61 mov edi, exitCode
    .bytes([0x0f, 0x05]); // +66 syscall

  return { codeBytes: w.toUint8Array(), cstringBytes, cstringOff: strOff };
}

// ============================================================================
// 2. Mach-O 64-bit (`0xFEEDFACF`) & Universal Fat (`0xCAFEBABE`) Builders
// ============================================================================

const PAGE_SIZE = 0x4000; // 16 KiB (valid on both ARM64 and x86-64 Darwin)
const TEXT_BASE = 0x100000000n;

function buildCodeSignatureSuperBlob(ident, entitlementsXml, codeLimit, filePrefixBytes) {
  const identZ = concatBytes(textEncoder.encode(ident), [0]);
  const pageSize = 4096;
  const nCodeSlots = Math.ceil(codeLimit / pageSize);
  const hasEnt = Boolean(entitlementsXml);
  const nSpecialSlots = hasEnt ? 5 : 0;

  let entBlob = null;
  if (hasEnt) {
    const xmlBytes = textEncoder.encode(String(entitlementsXml));
    const ew = new BinaryWriter(8 + xmlBytes.length);
    ew.u32be(0xfade7171) // CSMAGIC_EMBEDDED_ENTITLEMENTS
      .u32be(8 + xmlBytes.length)
      .bytes(xmlBytes);
    entBlob = ew.toUint8Array();
  }

  // CS_CodeDirectory (version 0x00020001, exact 44B fixed header matching identOffset = 44)
  const identOffset = 44;
  const hashOffset = identOffset + identZ.length + nSpecialSlots * 32;
  const cdLen = hashOffset + nCodeSlots * 32;
  const cd = new BinaryWriter(cdLen);
  cd.u32be(0xfade0c02) // CSMAGIC_CODEDIRECTORY
    .u32be(cdLen)
    .u32be(0x00020001) // version (44-byte CS_CodeDirectory header)
    .u32be(0x00000002) // CS_ADHOC
    .u32be(hashOffset)
    .u32be(identOffset)
    .u32be(nSpecialSlots)
    .u32be(nCodeSlots)
    .u32be(codeLimit)
    .u8(32) // hashSize (SHA-256)
    .u8(2) // hashType (SHA-256)
    .u8(0) // platform
    .u8(12) // pageSize = 2^12 = 4096
    .u32be(0) // spare2
    .bytes(identZ);

  if (hasEnt) {
    // Special slots stored from -nSpecialSlots .. -1; slot -5 is entitlements
    cd.bytes(sha256(entBlob)); // slot -5
    cd.zeros(4 * 32); // slots -4, -3, -2, -1
  }

  for (let i = 0; i < nCodeSlots; i++) {
    const start = i * pageSize;
    const end = Math.min(start + pageSize, codeLimit);
    cd.bytes(sha256(filePrefixBytes.subarray(start, end)));
  }
  const cdBytes = cd.toUint8Array();

  const blobs = [{ type: 0, bytes: cdBytes }];
  if (entBlob) blobs.push({ type: 5, bytes: entBlob });

  const headerLen = 12 + blobs.length * 8;
  let totalLen = headerLen;
  const offsets = [];
  for (const b of blobs) {
    offsets.push(totalLen);
    totalLen += b.bytes.length;
  }

  const sb = new BinaryWriter(totalLen);
  sb.u32be(0xfade0cc0) // CSMAGIC_EMBEDDED_SIGNATURE
    .u32be(totalLen)
    .u32be(blobs.length);
  for (let i = 0; i < blobs.length; i++) {
    sb.u32be(blobs[i].type).u32be(offsets[i]);
  }
  for (const b of blobs) sb.bytes(b.bytes);
  return sb.toUint8Array();
}

/**
 * Builds a complete, llvm-objdump-verified 64-bit Mach-O executable and returns
 * `{ buffer, layout }` so 2-pass callers (ADRP/GOT/ObjC) can resolve exact VAs.
 */
export function buildMachO64WithLayout({
  arch = 'arm64',
  platform = 2, // 2 = iOS, 1 = macOS
  codeBytes = null,
  message = 'OmniOS MachO\n',
  exitCode = 0,
  fileWrite = null,
  cstringBytes = null,
  dataBytes = null,
  dylibs = ['/usr/lib/libSystem.B.dylib'],
  gotSymbols = [],
  symbols = [],
  objcClasses = [],
  objcSelectors = [],
  entitlementsXml = null,
  cryptid = null,
  includePageZero = true,
  entryOffset = 0x1000,
  textOffset = 0x1000,
  codeSignIdent = 'com.omnios.macho',
} = {}) {
  const isArm64 = arch === 'arm64';
  const cpuType = isArm64 ? 0x0100000c : 0x01000007;
  const cpuSubtype = isArm64 ? 0 : 3;

  // Normalize GOT symbols
  const normGot = gotSymbols.map((item) =>
    typeof item === 'string'
      ? { name: item, dylibOrdinal: 1 }
      : { name: item.name, dylibOrdinal: item.dylibOrdinal ?? 1 }
  );

  // Auto-generate machine code if codeBytes not explicitly passed
  let finalCode = codeBytes;
  let finalCstring = cstringBytes;
  let cstringOff;
  if (!finalCode) {
    if (fileWrite && isArm64) {
      const built = encodeArm64FileWriteExit({
        filePath: fileWrite.path,
        content: fileWrite.content ?? '',
        exitCode,
        textOff: textOffset,
      });
      finalCode = built.codeBytes;
      finalCstring = finalCstring ?? built.cstringBytes;
      cstringOff = built.cstringOff;
    } else if (fileWrite) {
      const built = encodeX64DarwinFileWriteExit({
        filePath: fileWrite.path,
        content: fileWrite.content ?? '',
        exitCode,
        textOff: textOffset,
      });
      finalCode = built.codeBytes;
      finalCstring = finalCstring ?? built.cstringBytes;
      cstringOff = built.cstringOff;
    } else if (isArm64) {
      const built = encodeArm64WriteExit({ message, exitCode, textOff: textOffset });
      finalCode = built.codeBytes;
      finalCstring = finalCstring ?? built.cstringBytes;
      cstringOff = built.cstringOff;
    } else {
      const built = encodeX64DarwinWriteExit({ message, exitCode, textOff: textOffset });
      finalCode = built.codeBytes;
      finalCstring = finalCstring ?? built.cstringBytes;
      cstringOff = built.cstringOff;
    }
  } else {
    cstringOff = alignUp(textOffset + finalCode.length, 16);
  }

  // ---- Build __TEXT sections ----
  const textSections = [];
  const textEnd = textOffset + finalCode.length;
  textSections.push({
    sectname: '__text',
    segname: '__TEXT',
    offset: textOffset,
    addr: TEXT_BASE + BigInt(textOffset),
    bytes: finalCode,
    align: isArm64 ? 2 : 4,
    flags: 0x80000400, // S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
  });

  let textCursor = textEnd;
  let actualCstringOff = cstringOff;
  if (finalCstring && finalCstring.length > 0) {
    actualCstringOff = Math.max(cstringOff, alignUp(textCursor, 16));
    textSections.push({
      sectname: '__cstring',
      segname: '__TEXT',
      offset: actualCstringOff,
      addr: TEXT_BASE + BigInt(actualCstringOff),
      bytes: finalCstring,
      align: 0,
      flags: 0x02, // S_CSTRING_LITERALS
    });
    textCursor = actualCstringOff + finalCstring.length;
  }

  // Optional ObjC string sections inside __TEXT
  const hasObjc = objcClasses.length > 0 || objcSelectors.length > 0;
  const objcClassNameVa = new Map();
  const objcMethNameVa = new Map();
  const objcMethTypeVa = new Map();

  if (hasObjc) {
    const allClassNames = objcClasses.map((c) => c.name);
    const allMethNameSet = new Set(objcSelectors);
    const allMethTypeSet = new Set();
    for (const c of objcClasses) {
      for (const m of c.methods ?? []) {
        allMethNameSet.add(m.name);
        allMethTypeSet.add(m.types ?? 'v16@0:8');
      }
    }
    const allMethNames = Array.from(allMethNameSet);
    const allMethTypes = Array.from(allMethTypeSet);

    if (allClassNames.length > 0) {
      const secOff = alignUp(textCursor, 4);
      const sw = new BinaryWriter(64);
      for (const name of allClassNames) {
        objcClassNameVa.set(name, TEXT_BASE + BigInt(secOff + sw.pos));
        sw.utf8Z(name);
      }
      const bytes = sw.toUint8Array();
      textSections.push({
        sectname: '__objc_classname',
        segname: '__TEXT',
        offset: secOff,
        addr: TEXT_BASE + BigInt(secOff),
        bytes,
        align: 0,
        flags: 0x02,
      });
      textCursor = secOff + bytes.length;
    }

    if (allMethNames.length > 0) {
      const secOff = alignUp(textCursor, 4);
      const sw = new BinaryWriter(64);
      for (const name of allMethNames) {
        objcMethNameVa.set(name, TEXT_BASE + BigInt(secOff + sw.pos));
        sw.utf8Z(name);
      }
      const bytes = sw.toUint8Array();
      textSections.push({
        sectname: '__objc_methname',
        segname: '__TEXT',
        offset: secOff,
        addr: TEXT_BASE + BigInt(secOff),
        bytes,
        align: 0,
        flags: 0x02,
      });
      textCursor = secOff + bytes.length;
    }

    if (allMethTypes.length > 0) {
      const secOff = alignUp(textCursor, 4);
      const sw = new BinaryWriter(64);
      for (const t of allMethTypes) {
        objcMethTypeVa.set(t, TEXT_BASE + BigInt(secOff + sw.pos));
        sw.utf8Z(t);
      }
      const bytes = sw.toUint8Array();
      textSections.push({
        sectname: '__objc_methtype',
        segname: '__TEXT',
        offset: secOff,
        addr: TEXT_BASE + BigInt(secOff),
        bytes,
        align: 0,
        flags: 0x02,
      });
      textCursor = secOff + bytes.length;
    }
  }

  const textSegSize = alignUp(Math.max(textCursor, textOffset + 16), PAGE_SIZE);
  let nextFileOff = textSegSize;
  let nextVmAddr = TEXT_BASE + BigInt(textSegSize);

  // ---- Optional __DATA_CONST & __DATA segments ----
  const needDataConst = normGot.length > 0 || hasObjc;
  const needData = Boolean((dataBytes && dataBytes.length > 0) || objcClasses.length > 0);

  const dataConstFileOff = needDataConst ? nextFileOff : 0;
  const dataConstVmAddr = needDataConst ? nextVmAddr : 0n;
  const dataConstSections = [];
  let dataConstSegSize = 0;

  // Pre-compute __DATA addresses first if objcClasses exist (needed by __objc_classlist in __DATA_CONST)
  if (needDataConst) {
    // Estimate __DATA_CONST size (always fits cleanly in 1 page for E2E fixtures; alignUp to PAGE_SIZE)
    const dcEstBytes = normGot.length * 8 + objcClasses.length * 8 + objcMethNameVa.size * 8 + 64;
    dataConstSegSize = alignUp(Math.max(dcEstBytes, 16), PAGE_SIZE);
    nextFileOff += dataConstSegSize;
    nextVmAddr += BigInt(dataConstSegSize);
  }

  const dataFileOff = needData ? nextFileOff : 0;
  const dataVmAddr = needData ? nextVmAddr : 0n;
  const dataSections = [];
  const objcClassPtrVas = [];
  let dataSegSize = 0;

  if (needData) {
    let dCursor = 0;
    if (dataBytes && dataBytes.length > 0) {
      dataSections.push({
        sectname: '__data',
        segname: '__DATA',
        offset: dataFileOff + dCursor,
        addr: dataVmAddr + BigInt(dCursor),
        bytes: dataBytes,
        align: 3,
        flags: 0x00,
      });
      dCursor = alignUp(dCursor + dataBytes.length, 8);
    }

    if (objcClasses.length > 0) {
      // __objc_const: method_list_t + class_ro_t + meta_ro_t
      const constSecRel = alignUp(dCursor, 8);
      const constBaseVa = dataVmAddr + BigInt(constSecRel);
      const cw = new BinaryWriter(256);
      const classRoVas = [];
      const metaRoVas = [];

      for (const cls of objcClasses) {
        let methodListVa = 0n;
        const methods = cls.methods ?? [];
        if (methods.length > 0) {
          cw.align(8);
          methodListVa = constBaseVa + BigInt(cw.pos);
          cw.u32le(24).u32le(methods.length);
          for (const m of methods) {
            const mNameVa = objcMethNameVa.get(m.name) ?? 0n;
            const mTypeVa = objcMethTypeVa.get(m.types ?? 'v16@0:8') ?? 0n;
            const impVa = TEXT_BASE + BigInt(textOffset + (m.impOffset ?? 0));
            cw.u64le(mNameVa).u64le(mTypeVa).u64le(impVa);
          }
        }

        // class_ro_t (72 bytes)
        cw.align(8);
        const classRoVa = constBaseVa + BigInt(cw.pos);
        classRoVas.push(classRoVa);
        cw.u32le(0) // flags
          .u32le(8) // instanceStart
          .u32le(8) // instanceSize
          .u32le(0) // reserved
          .u64le(0n) // ivarLayout
          .u64le(objcClassNameVa.get(cls.name) ?? 0n) // name
          .u64le(methodListVa) // baseMethods
          .u64le(0n) // baseProtocols
          .u64le(0n) // ivars
          .u64le(0n) // weakIvarLayout
          .u64le(0n); // baseProperties

        // meta_ro_t (72 bytes)
        cw.align(8);
        const metaRoVa = constBaseVa + BigInt(cw.pos);
        metaRoVas.push(metaRoVa);
        cw.u32le(1) // RO_META
          .u32le(40)
          .u32le(40)
          .u32le(0)
          .u64le(0n)
          .u64le(objcClassNameVa.get(cls.name) ?? 0n)
          .u64le(0n)
          .u64le(0n)
          .u64le(0n)
          .u64le(0n)
          .u64le(0n);
      }

      const constBytes = cw.toUint8Array();
      dataSections.push({
        sectname: '__objc_const',
        segname: '__DATA',
        offset: dataFileOff + constSecRel,
        addr: constBaseVa,
        bytes: constBytes,
        align: 3,
        flags: 0x00,
      });
      dCursor = alignUp(constSecRel + constBytes.length, 8);

      // __objc_data: objc_class (40B) + metaclass (40B) per class
      const objcDataRel = dCursor;
      const objcDataBaseVa = dataVmAddr + BigInt(objcDataRel);
      const dw = new BinaryWriter(objcClasses.length * 80);
      for (let i = 0; i < objcClasses.length; i++) {
        const clsVa = objcDataBaseVa + BigInt(dw.pos);
        const metaVa = clsVa + 40n;
        objcClassPtrVas.push(clsVa);
        // class
        dw.u64le(metaVa).u64le(0n).u64le(0n).u64le(0n).u64le(classRoVas[i]);
        // metaclass
        dw.u64le(metaVa).u64le(0n).u64le(0n).u64le(0n).u64le(metaRoVas[i]);
      }
      const objcDataBytes = dw.toUint8Array();
      dataSections.push({
        sectname: '__objc_data',
        segname: '__DATA',
        offset: dataFileOff + objcDataRel,
        addr: objcDataBaseVa,
        bytes: objcDataBytes,
        align: 3,
        flags: 0x00,
      });
      dCursor = objcDataRel + objcDataBytes.length;
    }

    dataSegSize = alignUp(Math.max(dCursor, 16), PAGE_SIZE);
    nextFileOff += dataSegSize;
    nextVmAddr += BigInt(dataSegSize);
  }

  // Populate __DATA_CONST sections now that __objc_data VAs are known
  let gotVmAddr = 0n;
  let selRefsVmAddr = 0n;
  if (needDataConst) {
    let dcCursor = 0;
    if (normGot.length > 0) {
      gotVmAddr = dataConstVmAddr + BigInt(dcCursor);
      const gotBytes = new Uint8Array(normGot.length * 8);
      dataConstSections.push({
        sectname: '__got',
        segname: '__DATA_CONST',
        offset: dataConstFileOff + dcCursor,
        addr: gotVmAddr,
        bytes: gotBytes,
        align: 3,
        flags: 0x06, // S_NON_LAZY_SYMBOL_POINTERS
        reserved1: 0,
      });
      dcCursor = alignUp(dcCursor + gotBytes.length, 8);
    }

    if (objcClassPtrVas.length > 0) {
      const clw = new BinaryWriter(objcClassPtrVas.length * 8);
      for (const va of objcClassPtrVas) clw.u64le(va);
      const clBytes = clw.toUint8Array();
      dataConstSections.push({
        sectname: '__objc_classlist',
        segname: '__DATA_CONST',
        offset: dataConstFileOff + dcCursor,
        addr: dataConstVmAddr + BigInt(dcCursor),
        bytes: clBytes,
        align: 3,
        flags: 0x10000000, // S_ATTR_NO_DEAD_STRIP
      });
      dcCursor = alignUp(dcCursor + clBytes.length, 8);
    }

    if (objcMethNameVa.size > 0) {
      selRefsVmAddr = dataConstVmAddr + BigInt(dcCursor);
      const srw = new BinaryWriter(objcMethNameVa.size * 8);
      for (const va of objcMethNameVa.values()) srw.u64le(va);
      const srBytes = srw.toUint8Array();
      dataConstSections.push({
        sectname: '__objc_selrefs',
        segname: '__DATA_CONST',
        offset: dataConstFileOff + dcCursor,
        addr: selRefsVmAddr,
        bytes: srBytes,
        align: 3,
        flags: 0x10000005, // S_ATTR_NO_DEAD_STRIP | S_LITERAL_POINTERS
      });
      dcCursor = alignUp(dcCursor + srBytes.length, 8);
    }
  }

  // ---- Build __LINKEDIT contents ----
  const linkeditFileOff = nextFileOff;
  const linkeditVmAddr = nextVmAddr;
  const linkedit = new BinaryWriter(512);

  // 1. LC_DYLD_INFO_ONLY bind bytecode
  const dataConstSegIndex = includePageZero ? 2 : 1;
  let bindOff = 0;
  let bindSize = 0;
  if (normGot.length > 0) {
    bindOff = linkeditFileOff + linkedit.pos;
    for (let i = 0; i < normGot.length; i++) {
      const g = normGot[i];
      linkedit
        .u8(0x10 | (g.dylibOrdinal & 0x0f)) // BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
        .u8(0x40) // BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
        .utf8Z(g.name)
        .u8(0x51) // BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER
        .u8(0x70 | (dataConstSegIndex & 0x0f)) // BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
        .uleb128(i * 8)
        .u8(0x90); // BIND_OPCODE_DO_BIND
    }
    linkedit.u8(0x00); // BIND_OPCODE_DONE
    linkedit.align(8);
    bindSize = (linkeditFileOff + linkedit.pos) - bindOff;
  }

  // 2. Build string table & nlist_64 entries
  const strtab = new BinaryWriter(256);
  strtab.u8(0x20).u8(0x00); // standard Mach-O strtab prefix
  function internSym(name) {
    const off = strtab.pos;
    strtab.utf8Z(name);
    return off;
  }

  const definedSyms = [{ name: '_main', value: TEXT_BASE + BigInt(entryOffset) }];
  for (const s of symbols) {
    definedSyms.push({ name: s.name, value: TEXT_BASE + BigInt(s.offset) });
  }

  const symOff = linkeditFileOff + linkedit.pos;
  for (const s of definedSyms) {
    linkedit
      .u32le(internSym(s.name))
      .u8(0x0f) // N_SECT | N_EXT
      .u8(1) // __TEXT,__text is section 1
      .u16le(0)
      .u64le(s.value);
  }
  for (const g of normGot) {
    linkedit
      .u32le(internSym(g.name))
      .u8(0x01) // N_UNDF | N_EXT
      .u8(0)
      .u16le((g.dylibOrdinal & 0xff) << 8)
      .u64le(0n);
  }
  const nsyms = definedSyms.length + normGot.length;

  // 3. Indirect symbol table (maps __got entries to nlist_64 indices)
  let indirectSymOff = 0;
  if (normGot.length > 0) {
    indirectSymOff = linkeditFileOff + linkedit.pos;
    for (let i = 0; i < normGot.length; i++) {
      linkedit.u32le(definedSyms.length + i);
    }
    linkedit.align(8);
  }

  // 4. String table
  strtab.align(8);
  const strOff = linkeditFileOff + linkedit.pos;
  const strtabBytes = strtab.toUint8Array();
  linkedit.bytes(strtabBytes);
  const strSize = strtabBytes.length;

  // 5. Optional LC_CODE_SIGNATURE placeholder sizing
  let csDataOff = 0;
  let csDataSize = 0;
  if (entitlementsXml) {
    linkedit.align(16);
    csDataOff = linkeditFileOff + linkedit.pos;
    // Compute exact deterministic size of CS_SuperBlob using dummy prefix of length csDataOff
    const dummySb = buildCodeSignatureSuperBlob(codeSignIdent, entitlementsXml, csDataOff, new Uint8Array(csDataOff));
    csDataSize = dummySb.length;
  }

  const linkeditPreCsBytes = linkedit.toUint8Array();
  const linkeditFileSize = linkeditPreCsBytes.length + csDataSize;
  const linkeditVmSize = alignUp(Math.max(linkeditFileSize, 16), PAGE_SIZE);

  // ---- Build Load Commands ----
  const cmds = [];

  function writeSegment64(segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, sects = []) {
    const cw = new BinaryWriter(72 + sects.length * 80);
    cw.u32le(0x19) // LC_SEGMENT_64
      .u32le(72 + sects.length * 80)
      .fixedAscii(segname, 16)
      .u64le(BigInt(vmaddr))
      .u64le(BigInt(vmsize))
      .u64le(BigInt(fileoff))
      .u64le(BigInt(filesize))
      .u32le(maxprot)
      .u32le(initprot)
      .u32le(sects.length)
      .u32le(0); // flags

    for (const s of sects) {
      cw.fixedAscii(s.sectname, 16)
        .fixedAscii(s.segname, 16)
        .u64le(BigInt(s.addr))
        .u64le(BigInt(s.bytes.length))
        .u32le(s.offset)
        .u32le(s.align ?? 0)
        .u32le(0) // reloff
        .u32le(0) // nreloc
        .u32le(s.flags ?? 0)
        .u32le(s.reserved1 ?? 0)
        .u32le(0)
        .u32le(0);
    }
    cmds.push(cw.toUint8Array());
  }

  if (includePageZero) {
    writeSegment64('__PAGEZERO', 0n, 0x100000000n, 0n, 0n, 0, 0, []);
  }
  writeSegment64('__TEXT', TEXT_BASE, BigInt(textSegSize), 0n, BigInt(textSegSize), 5, 5, textSections);
  if (needDataConst) {
    writeSegment64('__DATA_CONST', dataConstVmAddr, BigInt(dataConstSegSize), BigInt(dataConstFileOff), BigInt(dataConstSegSize), 3, 3, dataConstSections);
  }
  if (needData) {
    writeSegment64('__DATA', dataVmAddr, BigInt(dataSegSize), BigInt(dataFileOff), BigInt(dataSegSize), 3, 3, dataSections);
  }
  writeSegment64('__LINKEDIT', linkeditVmAddr, BigInt(linkeditVmSize), BigInt(linkeditFileOff), BigInt(linkeditFileSize), 1, 1, []);

  // LC_DYLD_INFO_ONLY (0x80000022)
  if (normGot.length > 0) {
    const cw = new BinaryWriter(48);
    cw.u32le(0x80000022)
      .u32le(48)
      .u32le(0).u32le(0) // rebase
      .u32le(bindOff).u32le(bindSize) // bind
      .u32le(0).u32le(0) // weak_bind
      .u32le(0).u32le(0) // lazy_bind
      .u32le(0).u32le(0); // export
    cmds.push(cw.toUint8Array());
  }

  // LC_SYMTAB (0x02)
  {
    const cw = new BinaryWriter(24);
    cw.u32le(0x02).u32le(24).u32le(symOff).u32le(nsyms).u32le(strOff).u32le(strSize);
    cmds.push(cw.toUint8Array());
  }

  // LC_DYSYMTAB (0x0B)
  {
    const cw = new BinaryWriter(80);
    cw.u32le(0x0b)
      .u32le(80)
      .u32le(0).u32le(0) // local
      .u32le(0).u32le(definedSyms.length) // extdef
      .u32le(definedSyms.length).u32le(normGot.length) // undef
      .u32le(0).u32le(0) // toc
      .u32le(0).u32le(0) // modtab
      .u32le(0).u32le(0) // extref
      .u32le(indirectSymOff).u32le(normGot.length) // indirectsym
      .u32le(0).u32le(0) // extrel
      .u32le(0).u32le(0); // locrel
    cmds.push(cw.toUint8Array());
  }

  // LC_LOAD_DYLINKER (0x0E)
  {
    const pathZ = textEncoder.encode('/usr/lib/dyld\0');
    const cmdSize = alignUp(12 + pathZ.length, 8);
    const cw = new BinaryWriter(cmdSize);
    cw.u32le(0x0e).u32le(cmdSize).u32le(12).bytes(pathZ).zeros(cmdSize - 12 - pathZ.length);
    cmds.push(cw.toUint8Array());
  }

  // LC_UUID (0x1B) — deterministic from code + message
  {
    const uuidDigest = sha256(concatBytes(finalCode, finalCstring ?? new Uint8Array(0))).subarray(0, 16);
    const cw = new BinaryWriter(24);
    cw.u32le(0x1b).u32le(24).bytes(uuidDigest);
    cmds.push(cw.toUint8Array());
  }

  // LC_BUILD_VERSION (0x32)
  {
    const minos = platform === 2 ? 0x000f0000 : 0x000d0000; // iOS 15.0 / macOS 13.0
    const cw = new BinaryWriter(24);
    cw.u32le(0x32).u32le(24).u32le(platform).u32le(minos).u32le(minos).u32le(0);
    cmds.push(cw.toUint8Array());
  }

  // LC_MAIN (0x80000028)
  {
    const cw = new BinaryWriter(24);
    cw.u32le(0x80000028).u32le(24).u64le(BigInt(entryOffset)).u64le(0n);
    cmds.push(cw.toUint8Array());
  }

  // LC_LOAD_DYLIB (0x0C)
  for (const dylib of dylibs) {
    const pBytes = textEncoder.encode(`${dylib}\0`);
    const cmdSize = alignUp(24 + pBytes.length, 8);
    const cw = new BinaryWriter(cmdSize);
    cw.u32le(0x0c)
      .u32le(cmdSize)
      .u32le(24) // name offset
      .u32le(2) // timestamp
      .u32le(0x00010000) // current_version
      .u32le(0x00010000) // compatibility_version
      .bytes(pBytes)
      .zeros(cmdSize - 24 - pBytes.length);
    cmds.push(cw.toUint8Array());
  }

  // Optional LC_ENCRYPTION_INFO_64 (0x2C)
  if (cryptid !== null && cryptid !== undefined) {
    const cw = new BinaryWriter(24);
    cw.u32le(0x2c)
      .u32le(24)
      .u32le(textOffset) // cryptoff
      .u32le(alignUp(finalCode.length, 16)) // cryptsize
      .u32le(cryptid >>> 0)
      .u32le(0); // pad
    cmds.push(cw.toUint8Array());
  }

  // Optional LC_CODE_SIGNATURE (0x1D)
  if (entitlementsXml) {
    const cw = new BinaryWriter(16);
    cw.u32le(0x1d).u32le(16).u32le(csDataOff).u32le(csDataSize);
    cmds.push(cw.toUint8Array());
  }

  const allCmds = concatBytes(...cmds);
  if (32 + allCmds.length > textOffset) {
    throw new Error(`Mach-O load commands (${32 + allCmds.length}B) exceeded textOffset (${textOffset}B)`);
  }

  // ---- Assemble Final Mach-O Image ----
  const totalSize = linkeditFileOff + linkeditFileSize;
  const out = new Uint8Array(totalSize);
  const view = new DataView(out.buffer);

  // mach_header_64 (32 bytes)
  view.setUint32(0x00, 0xfeedfacf, true); // MH_MAGIC_64
  view.setUint32(0x04, cpuType, true);
  view.setUint32(0x08, cpuSubtype, true);
  view.setUint32(0x0c, 2, true); // MH_EXECUTE
  view.setUint32(0x10, cmds.length, true);
  view.setUint32(0x14, allCmds.length, true);
  view.setUint32(0x18, 0x00200085, true); // NOUNDEFS | DYLDLINK | TWOLEVEL | PIE
  view.setUint32(0x1c, 0, true);

  out.set(allCmds, 32);

  for (const s of textSections) out.set(s.bytes, s.offset);
  for (const s of dataConstSections) out.set(s.bytes, s.offset);
  for (const s of dataSections) out.set(s.bytes, s.offset);
  out.set(linkeditPreCsBytes, linkeditFileOff);

  // Compute genuine SHA-256 page hashes for CS_SuperBlob over actual binary prefix
  if (entitlementsXml) {
    const realSb = buildCodeSignatureSuperBlob(codeSignIdent, entitlementsXml, csDataOff, out.subarray(0, csDataOff));
    out.set(realSb, csDataOff);
  }

  return {
    buffer: out,
    layout: {
      textBase: TEXT_BASE,
      textOff: textOffset,
      cstringOff: actualCstringOff,
      cstringVa: TEXT_BASE + BigInt(actualCstringOff),
      dataConstVmAddr,
      gotVmAddr,
      selRefsVmAddr,
      dataVmAddr,
      entryOff: entryOffset,
      objcMethNameVa,
    },
  };
}

export function buildMachO64(options = {}) {
  return buildMachO64WithLayout(options).buffer;
}

/**
 * Builds a Universal Fat Mach-O (`0xCAFEBABE` Big-Endian) with monotonic aligned slices.
 */
export function buildUniversalFatMachO({ slices = [] } = {}) {
  if (slices.length === 0) {
    throw new Error('buildUniversalFatMachO requires at least one slice');
  }

  const laidOut = [];
  let cursor = 8 + slices.length * 20;

  for (const sl of slices) {
    const alignPow = sl.align ?? (sl.cputype === 0x0100000c ? 14 : 12);
    const alignBytes = 1 << alignPow;
    cursor = alignUp(Math.max(cursor, alignBytes), alignBytes);
    laidOut.push({
      cputype: sl.cputype,
      cpusubtype: sl.cpusubtype ?? 0,
      offset: cursor,
      size: sl.bytes.length,
      align: alignPow,
      bytes: sl.bytes,
    });
    cursor += sl.bytes.length;
  }

  const w = new BinaryWriter(cursor);
  w.u32be(0xcafebabe).u32be(laidOut.length);
  for (const sl of laidOut) {
    w.u32be(sl.cputype)
      .u32be(sl.cpusubtype)
      .u32be(sl.offset)
      .u32be(sl.size)
      .u32be(sl.align);
  }
  for (const sl of laidOut) {
    if (w.pos < sl.offset) w.zeros(sl.offset - w.pos);
    w.bytes(sl.bytes);
  }
  return w.toUint8Array();
}

export function buildUniversalMachO({
  message = 'OmniOS Universal\n',
  exitCode = 0,
  platform = 1,
  fileWrite = null,
  entitlementsXml = null,
  objcClasses = [],
} = {}) {
  const x64Bytes = buildMachO64({ arch: 'x86_64', platform, message, exitCode, fileWrite, entitlementsXml });
  const arm64Bytes = buildMachO64({ arch: 'arm64', platform, message, exitCode, fileWrite, entitlementsXml, objcClasses });
  return buildUniversalFatMachO({
    slices: [
      { cputype: 0x01000007, cpusubtype: 3, align: 14, bytes: x64Bytes },
      { cputype: 0x0100000c, cpusubtype: 0, align: 14, bytes: arm64Bytes },
    ],
  });
}

// ============================================================================
// 3. Apple Containers: iOS .ipa, macOS .app.zip, UDIF .dmg (koly), XAR .pkg
// ============================================================================

export function buildCustomIpa({
  bundleId = 'com.omnios.ios.dynamic',
  displayName = 'OmniIOSDynamic',
  executableName = 'OmniIOSDynamic',
  version = '1.0.0',
  urlScheme = null,
  plistFormat = 'bplist00',
  message = 'Hello OmniOS iOS\n',
  exitCode = 0,
  fileWrite = null,
  entitlementsXml = null,
  cryptid = null,
  extraPlistKeys = {},
  objcClasses = [],
  machoBytes = null,
} = {}) {
  const plistObj = {
    CFBundleIdentifier: bundleId,
    CFBundleExecutable: executableName,
    CFBundleDisplayName: displayName,
    CFBundleName: displayName,
    CFBundleShortVersionString: version,
    CFBundleVersion: '1',
    CFBundlePackageType: 'APPL',
    LSRequiresIPhoneOS: true,
    ...extraPlistKeys,
  };
  if (urlScheme) {
    plistObj.CFBundleURLTypes = [
      {
        CFBundleURLName: bundleId,
        CFBundleURLSchemes: [urlScheme],
      },
    ];
  }

  const plistBytes = plistFormat === 'xml'
    ? textEncoder.encode(buildXmlPlist(plistObj))
    : buildBinaryPlist(plistObj);

  const execBytes = machoBytes ?? buildMachO64({
    arch: 'arm64',
    platform: 2, // iOS
    message,
    exitCode,
    fileWrite,
    entitlementsXml,
    cryptid,
    objcClasses,
    codeSignIdent: bundleId,
  });

  const appDir = `Payload/${displayName}.app`;
  return buildZip([
    { name: `${appDir}/Info.plist`, data: plistBytes, method: 8 },
    { name: `${appDir}/${executableName}`, data: execBytes, method: 8, externalAttr: 0x81ed0000 },
  ]);
}

export function buildCustomMacAppZip({
  bundleId = 'com.omnios.macos.dynamic',
  appName = 'OmniMacDynamic',
  executableName = 'OmniMacDynamic',
  version = '1.0.0',
  arch = 'universal', // 'universal' | 'arm64' | 'x86_64'
  plistFormat = 'xml', // 'xml' | 'bplist00'
  urlScheme = null,
  documentExtensions = [],
  message = 'Hello OmniOS macOS\n',
  exitCode = 0,
  fileWrite = null,
  entitlementsXml = null,
  objcClasses = [],
  extraPlistKeys = {},
  machoBytes = null,
} = {}) {
  const plistObj = {
    CFBundleIdentifier: bundleId,
    CFBundleExecutable: executableName,
    CFBundleName: appName,
    CFBundleDisplayName: appName,
    CFBundleShortVersionString: version,
    CFBundleVersion: '1',
    CFBundlePackageType: 'APPL',
    LSMinimumSystemVersion: '13.0',
    ...extraPlistKeys,
  };
  if (urlScheme) {
    plistObj.CFBundleURLTypes = [
      {
        CFBundleURLName: bundleId,
        CFBundleURLSchemes: [urlScheme],
      },
    ];
  }
  if (documentExtensions.length > 0) {
    plistObj.CFBundleDocumentTypes = [
      {
        CFBundleTypeName: `${appName} Document`,
        CFBundleTypeRole: 'Editor',
        CFBundleTypeExtensions: documentExtensions,
      },
    ];
  }

  const plistBytes = plistFormat === 'bplist00'
    ? buildBinaryPlist(plistObj)
    : textEncoder.encode(buildXmlPlist(plistObj));

  let execBytes = machoBytes;
  if (!execBytes) {
    if (arch === 'universal') {
      const x64 = buildMachO64({ arch: 'x86_64', platform: 1, message, exitCode, fileWrite, entitlementsXml, codeSignIdent: bundleId });
      const arm64 = buildMachO64({ arch: 'arm64', platform: 1, message, exitCode, fileWrite, entitlementsXml, objcClasses, codeSignIdent: bundleId });
      execBytes = buildUniversalFatMachO({
        slices: [
          { cputype: 0x01000007, cpusubtype: 3, align: 14, bytes: x64 },
          { cputype: 0x0100000c, cpusubtype: 0, align: 14, bytes: arm64 },
        ],
      });
    } else {
      execBytes = buildMachO64({
        arch,
        platform: 1,
        message,
        exitCode,
        fileWrite,
        entitlementsXml,
        objcClasses,
        codeSignIdent: bundleId,
      });
    }
  }

  const root = `${appName}.app/Contents`;
  return buildZip([
    { name: `${root}/Info.plist`, data: plistBytes, method: 8 },
    { name: `${root}/MacOS/${executableName}`, data: execBytes, method: 8, externalAttr: 0x81ed0000 },
  ]);
}

/**
 * Builds a valid Apple UDIF .dmg disk image with exact 512-byte BE `koly` trailer
 * (XMLOffset at exact offset 0x0D8 [216], XMLLength at 0x0E0 [224]).
 */
export function buildCustomDmg({
  volumeName = 'OmniOSDisk',
  appName = 'OmniMacApp',
  bundleId = 'com.omnios.macos.dmgapp',
  executableName = 'OmniMacApp',
  message = 'Hello DMG\n',
  exitCode = 0,
  corruptKoly = false,
} = {}) {
  const embeddedAppZip = buildCustomMacAppZip({
    bundleId,
    appName,
    executableName,
    arch: 'arm64',
    message,
    exitCode,
  });

  // Pad payload to 512-byte sector boundary & compress with standard zlib
  const rawSectorBytes = alignUp(Math.max(embeddedAppZip.length, 512), 512);
  const rawPayload = new Uint8Array(rawSectorBytes);
  rawPayload.set(embeddedAppZip, 0);
  const sectorCount = rawSectorBytes / 512;

  const compressedBuf = zlib.deflateSync(rawPayload);
  const dataFork = new Uint8Array(compressedBuf.buffer, compressedBuf.byteOffset, compressedBuf.byteLength);
  const dataCrc = crc32(dataFork);

  // Build 204-byte BE mish header + 2 × 40-byte chunk entries (zlib 0x80000005 + terminator 0xFFFFFFFF)
  const mish = new BinaryWriter(204 + 80);
  mish
    .ascii('mish') // Signature
    .u32be(1) // Version
    .u64be(0n) // SectorNumber
    .u64be(BigInt(sectorCount)) // SectorCount
    .u64be(0n) // DataOffset
    .u32be(2) // BuffersNeeded
    .u32be(0) // BlockDescriptors
    .zeros(24) // Reserved
    .u32be(2) // ChecksumType (CRC-32)
    .u32be(32) // ChecksumSize
    .u32be(dataCrc)
    .zeros(124) // Checksum[31]
    .u32be(2); // NumberOfBlockChunks

  // Chunk 0: zlib compressed data
  mish
    .u32be(0x80000005) // UDBZ/UDZO zlib
    .u32be(0) // Comment
    .u64be(0n) // SectorNumber
    .u64be(BigInt(sectorCount)) // SectorCount
    .u64be(0n) // CompressedOffset
    .u64be(BigInt(dataFork.length)); // CompressedLength

  // Chunk 1: end terminator
  mish
    .u32be(0xffffffff)
    .u32be(0)
    .u64be(BigInt(sectorCount))
    .u64be(0n)
    .u64be(BigInt(dataFork.length))
    .u64be(0n);

  const blkxPlistObj = {
    'resource-fork': {
      blkx: [
        {
          Attributes: '0x0050',
          Data: mish.toUint8Array(),
          ID: '0',
          Name: `${volumeName} (Apple_HFS : 0)`,
        },
      ],
    },
  };
  const xmlBytes = textEncoder.encode(buildXmlPlist(blkxPlistObj));
  const xmlOffset = dataFork.length;
  const masterCrc = crc32(xmlBytes);

  // Exact 512-byte Big-Endian `koly` trailer
  const koly = new BinaryWriter(512);
  koly
    .ascii(corruptKoly ? 'BAD!' : 'koly') // 0x000
    .u32be(4) // 0x004 Version
    .u32be(512) // 0x008 HeaderSize
    .u32be(1) // 0x00C Flags
    .u64be(0n) // 0x010 RunningDataForkOffset
    .u64be(0n) // 0x018 DataForkOffset
    .u64be(BigInt(dataFork.length)) // 0x020 DataForkLength
    .u64be(0n) // 0x028 RsrcForkOffset
    .u64be(0n) // 0x030 RsrcForkLength
    .u32be(1) // 0x038 SegmentNumber
    .u32be(1) // 0x03C SegmentCount
    .bytes(sha256(textEncoder.encode(volumeName)).subarray(0, 16)) // 0x040 SegmentID (16B)
    .u32be(2) // 0x050 DataChecksumType
    .u32be(32) // 0x054 DataChecksumSize
    .u32be(dataCrc) // 0x058 DataChecksum[0]
    .zeros(124) // 0x05C..0x0D7
    .u64be(corruptKoly ? 0x7fffffffn : BigInt(xmlOffset)) // 0x0D8 (216) XMLOffset!
    .u64be(BigInt(xmlBytes.length)) // 0x0E0 (224) XMLLength!
    .zeros(120) // 0x0E8..0x15F
    .u32be(2) // 0x160 MasterChecksumType
    .u32be(32) // 0x164 MasterChecksumSize
    .u32be(masterCrc) // 0x168 MasterChecksum[0]
    .zeros(124) // 0x16C..0x1E7
    .u32be(1) // 0x1E8 ImageVariant
    .u64be(BigInt(sectorCount)) // 0x1EC SectorCount
    .zeros(12); // 0x1F4..0x1FF (total = 512 bytes)

  if (koly.length !== 512) {
    throw new Error(`UDIF koly trailer size must be 512 bytes, got ${koly.length}`);
  }

  return concatBytes(dataFork, xmlBytes, koly.toUint8Array());
}

function buildCpioOdc(entries) {
  const oct = (val, width) => Math.max(0, val).toString(8).padStart(width, '0').slice(-width);
  const chunks = [];
  let ino = 1;

  for (const e of entries) {
    const nameBytes = concatBytes(textEncoder.encode(e.name), [0]);
    const dataBytes = e.data ?? new Uint8Array(0);
    const mode = e.mode ?? 0o100644;
    const header =
      '070707' +
      oct(0, 6) + // dev
      oct(ino++, 6) + // ino
      oct(mode, 6) + // mode
      oct(0, 6) + // uid
      oct(0, 6) + // gid
      oct(1, 6) + // nlink
      oct(0, 6) + // rdev
      oct(0, 11) + // mtime
      oct(nameBytes.length, 6) + // namesize
      oct(dataBytes.length, 11); // filesize
    chunks.push(textEncoder.encode(header), nameBytes, dataBytes);
  }

  const trailerName = textEncoder.encode('TRAILER!!!\0');
  const trailerHeader =
    '070707' +
    oct(0, 6) + oct(0, 6) + oct(0, 6) + oct(0, 6) + oct(0, 6) + oct(1, 6) + oct(0, 6) + oct(0, 11) +
    oct(trailerName.length, 6) + oct(0, 11);
  chunks.push(textEncoder.encode(trailerHeader), trailerName);
  return concatBytes(...chunks);
}

/**
 * Builds a valid macOS Flat Installer `.pkg` (XAR container with zlib TOC + SHA-1 + gzip CPIO payload).
 */
export function buildCustomPkg({
  bundleId = 'com.omnios.macos.pkgapp',
  appName = 'OmniPkgApp',
  executableName = 'OmniPkgApp',
  version = '1.0.0',
  message = 'Hello PKG\n',
  exitCode = 0,
  corruptXar = false,
} = {}) {
  const plistBytes = textEncoder.encode(
    buildXmlPlist({
      CFBundleIdentifier: bundleId,
      CFBundleExecutable: executableName,
      CFBundleName: appName,
      CFBundleShortVersionString: version,
      CFBundlePackageType: 'APPL',
    })
  );

  const execBytes = buildMachO64({
    arch: 'arm64',
    platform: 1,
    message,
    exitCode,
    codeSignIdent: bundleId,
  });

  const cpioRaw = buildCpioOdc([
    { name: `./${appName}.app/Contents/Info.plist`, data: plistBytes, mode: 0o100644 },
    { name: `./${appName}.app/Contents/MacOS/${executableName}`, data: execBytes, mode: 0o100755 },
  ]);

  const payloadGzipBuf = zlib.gzipSync(cpioRaw);
  const payloadGzip = new Uint8Array(payloadGzipBuf.buffer, payloadGzipBuf.byteOffset, payloadGzipBuf.byteLength);

  const pkgInfoXml = textEncoder.encode(
    `<?xml version="1.0" encoding="utf-8"?>\n<pkg-info format-version="2" identifier="${escapeXml(bundleId)}" version="${escapeXml(version)}" install-location="/Applications" auth="root"><payload numberOfFiles="2" installKBytes="${Math.ceil(cpioRaw.length / 1024)}"/></pkg-info>\n`
  );

  // Heap layout: [0..19] = TOC SHA-1, [20..] = PackageInfo, then Payload
  const pkgInfoOffset = 20;
  const payloadOffset = pkgInfoOffset + pkgInfoXml.length;

  const tocXml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<xar>',
    ' <toc>',
    '  <creation-time>2026-11-20T22:00:00Z</creation-time>',
    '  <checksum style="sha1">',
    '   <offset>0</offset>',
    '   <size>20</size>',
    '  </checksum>',
    '  <file id="1">',
    '   <name>PackageInfo</name>',
    '   <type>file</type>',
    '   <data>',
    `    <offset>${pkgInfoOffset}</offset>`,
    `    <length>${pkgInfoXml.length}</length>`,
    `    <size>${pkgInfoXml.length}</size>`,
    '    <encoding style="application/octet-stream"/>',
    `    <archived-checksum style="sha1">${sha1Hex(pkgInfoXml)}</archived-checksum>`,
    `    <extracted-checksum style="sha1">${sha1Hex(pkgInfoXml)}</extracted-checksum>`,
    '   </data>',
    '  </file>',
    '  <file id="2">',
    '   <name>Payload</name>',
    '   <type>file</type>',
    '   <data>',
    `    <offset>${payloadOffset}</offset>`,
    `    <length>${payloadGzip.length}</length>`,
    `    <size>${payloadGzip.length}</size>`,
    '    <encoding style="application/octet-stream"/>',
    `    <archived-checksum style="sha1">${sha1Hex(payloadGzip)}</archived-checksum>`,
    `    <extracted-checksum style="sha1">${sha1Hex(payloadGzip)}</extracted-checksum>`,
    '   </data>',
    '  </file>',
    ' </toc>',
    '</xar>',
    '',
  ].join('\n');

  const tocXmlBytes = textEncoder.encode(tocXml);
  const tocCompBuf = zlib.deflateSync(tocXmlBytes);
  const tocComp = corruptXar
    ? new Uint8Array([0xff, 0x00, 0xde, 0xad, 0xbe, 0xef])
    : new Uint8Array(tocCompBuf.buffer, tocCompBuf.byteOffset, tocCompBuf.byteLength);
  const tocSha1 = sha1(tocComp);

  // 28-byte BE XAR header
  const header = new BinaryWriter(28);
  header
    .u32be(corruptXar ? 0x42414421 : 0x78617221) // "xar!"
    .u16be(28) // size
    .u16be(1) // version
    .u64be(BigInt(tocComp.length)) // toc_length_compressed
    .u64be(BigInt(tocXmlBytes.length)) // toc_length_uncompressed
    .u32be(1); // cksum_alg = SHA-1

  return concatBytes(header.toUint8Array(), tocComp, tocSha1, pkgInfoXml, payloadGzip);
}

// ============================================================================
// 4. Universal WebAssembly (`\0asm` v1 + WASI Preview 1) & `.uapp` Builders
// ============================================================================

function wasmSection(id, payloadBytes) {
  return concatBytes([id], encodeUleb128(payloadBytes.length), payloadBytes);
}

function wasmStr(str) {
  const b = textEncoder.encode(str);
  return concatBytes(encodeUleb128(b.length), b);
}

function wasmVec(items) {
  return concatBytes(encodeUleb128(items.length), ...items);
}

/**
 * Builds a valid WebAssembly v1 (`\0asm`) WASI Preview 1 module verifiable via WebAssembly.validate().
 */
export function buildCustomWasm({
  message = 'Hello OmniOS WASM\n',
  exitCode = 0,
  useOmniOsImport = false,
  invalidIovsLen = null,
  oobPointer = null,
  ungrantedFd = null,
  returnFdWriteErrno = false,
} = {}) {
  const msgBytes = textEncoder.encode(String(message));

  const omniSpec = useOmniOsImport
    ? (typeof useOmniOsImport === 'object'
        ? {
            module: useOmniOsImport.module ?? 'omni_os_v1',
            name: useOmniOsImport.name ?? 'window_create',
            params: useOmniOsImport.params ?? [0x7f, 0x7f],
            results: useOmniOsImport.results ?? [0x7f],
            args: useOmniOsImport.args ?? [640, 480],
          }
        : {
            module: 'omni_os_v1',
            name: 'window_create',
            params: [0x7f, 0x7f],
            results: [0x7f],
            args: [640, 480],
          })
    : null;

  // 1. Type Section (ID 1)
  const types = [
    // type 0: (i32, i32, i32, i32) -> (i32)  [fd_write]
    Uint8Array.from([0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]),
    // type 1: (i32) -> ()  [proc_exit]
    Uint8Array.from([0x60, 1, 0x7f, 0]),
    // type 2: () -> ()  [_start]
    Uint8Array.from([0x60, 0, 0]),
  ];
  if (omniSpec) {
    types.push(
      concatBytes([0x60], encodeUleb128(omniSpec.params.length), omniSpec.params, encodeUleb128(omniSpec.results.length), omniSpec.results)
    );
  }
  const typeSec = wasmSection(1, wasmVec(types));

  // 2. Import Section (ID 2)
  const imports = [
    concatBytes(wasmStr('wasi_snapshot_preview1'), wasmStr('fd_write'), [0x00], encodeUleb128(0)),
    concatBytes(wasmStr('wasi_snapshot_preview1'), wasmStr('proc_exit'), [0x00], encodeUleb128(1)),
  ];
  if (omniSpec) {
    imports.push(concatBytes(wasmStr(omniSpec.module), wasmStr(omniSpec.name), [0x00], encodeUleb128(3)));
  }
  const importSec = wasmSection(2, wasmVec(imports));
  const startFuncIdx = imports.length;

  // 3. Function Section (ID 3): 1 defined function (_start, type 2)
  const funcSec = wasmSection(3, wasmVec([encodeUleb128(2)]));

  // 5. Memory Section (ID 5): auto-sized minimum 64KiB pages for message payload at 0x0100
  const minPages = Math.max(1, Math.ceil((0x0100 + msgBytes.length) / 65536));
  const maxPages = Math.max(16, minPages);
  const memSec = wasmSection(5, wasmVec([concatBytes([0x01], encodeUleb128(minPages), encodeUleb128(maxPages))]));

  // 7. Export Section (ID 7): "memory" & "_start"
  const exportSec = wasmSection(
    7,
    wasmVec([
      concatBytes(wasmStr('memory'), [0x02], encodeUleb128(0)),
      concatBytes(wasmStr('_start'), [0x00], encodeUleb128(startFuncIdx)),
    ])
  );

  // 10. Code Section (ID 10): body of _start
  const fdArg = ungrantedFd ?? 1;
  const iovsPtrArg = oobPointer ?? 0;
  const iovsLenArg = invalidIovsLen ?? 1;
  const probeErrno = returnFdWriteErrno || invalidIovsLen !== null || oobPointer !== null || ungrantedFd !== null;

  const body = new BinaryWriter(64);
  body.u8(0); // 0 local declarations

  if (omniSpec) {
    for (const argVal of omniSpec.args) {
      body.u8(0x41).sleb128(argVal | 0); // i32.const arg (signed 32-bit LEB128)
    }
    body.u8(0x10).uleb128(2); // call omni_os_v1 import (func index 2)
    for (let r = 0; r < omniSpec.results.length; r++) {
      body.u8(0x1a); // drop
    }
  }

  // call fd_write(fd, iovsPtr, iovsLen, nwrittenPtr=8)
  body
    .u8(0x41).sleb128(fdArg | 0)
    .u8(0x41).sleb128(iovsPtrArg | 0)
    .u8(0x41).sleb128(iovsLenArg | 0)
    .u8(0x41).sleb128(8)
    .u8(0x10).uleb128(0); // call fd_write

  if (probeErrno) {
    // Pass fd_write's returned WASI errno directly to proc_exit(errno)
    body.u8(0x10).uleb128(1); // call proc_exit
  } else {
    body
      .u8(0x1a) // drop fd_write result
      .u8(0x41).sleb128(exitCode | 0)
      .u8(0x10).uleb128(1); // call proc_exit
  }
  body.u8(0x0b); // end

  const bodyBytes = body.toUint8Array();
  const codeEntry = concatBytes(encodeUleb128(bodyBytes.length), bodyBytes);
  const codeSec = wasmSection(10, wasmVec([codeEntry]));

  // 11. Data Section (ID 11): iov struct at 0x0000 + message bytes at 0x0100
  const iov = new BinaryWriter(8);
  iov.u32le(0x0100).u32le(msgBytes.length);
  const iovBytes = iov.toUint8Array();

  const seg0 = concatBytes([0x00, 0x41], encodeSleb128(0), [0x0b], encodeUleb128(iovBytes.length), iovBytes);
  const seg1 = concatBytes([0x00, 0x41], encodeSleb128(0x0100), [0x0b], encodeUleb128(msgBytes.length), msgBytes);
  const dataSec = wasmSection(11, wasmVec([seg0, seg1]));

  return concatBytes(
    Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    typeSec,
    importSec,
    funcSec,
    memSec,
    exportSec,
    codeSec,
    dataSec
  );
}

/**
 * Builds a valid `.uapp` Universal WebAssembly ZIP container (`manifest.json` + `app.wasm`).
 */
export function buildCustomUapp({
  appId = 'com.omnios.uapp.dynamic',
  name = 'OmniUniversalDynamic',
  version = '1.0.0',
  message = 'Hello OmniOS UAPP\n',
  exitCode = 0,
  useOmniOsImport = false,
  permissions = [],
  urlSchemes = [],
  fileTypes = [],
  wasmBytes = null,
} = {}) {
  const finalWasm = wasmBytes ?? buildCustomWasm({ message, exitCode, useOmniOsImport });
  const manifest = {
    id: appId,
    appId,
    name,
    version,
    platform: 'universal',
    entry: 'app.wasm',
    permissions,
    urlSchemes,
    fileTypes,
  };

  return buildZip([
    { name: 'manifest.json', data: textEncoder.encode(JSON.stringify(manifest, null, 2)), method: 8 },
    { name: 'app.wasm', data: finalWasm, method: 8 },
  ]);
}
