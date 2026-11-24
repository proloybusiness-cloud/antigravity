/**
 * OmniOS Mach-O 64-bit & Universal Fat Binary Parser & VMM Loader (`F-048`, Edge Cases `#19`–`#22`)
 * Zero-dependency Node.js 24 ESM implementation — zero `node:fs` imports.
 *
 * Authoritative Edge Cases Enforced:
 * - #19 (Fat vs Java `.class`): Validates `1 <= nfat_arch <= 32`, full table bounds, AND every slice
 *   `cputype` in Apple Mach-O CPU types; rejects Java `.class` files with `E_INVALID_FAT`.
 * - #20 (FairPlay DRM): Rejects `LC_ENCRYPTION_INFO (0x21)` / `LC_ENCRYPTION_INFO_64 (0x2C)` with
 *   `cryptid !== 0` throwing `FormatError(..., { code: ERROR_CODES.E_ENCRYPTED_BINARY })` unless
 *   `allowEncrypted: true` metadata inspection is explicitly requested (loading ALWAYS rejects!).
 * - #21 (`__PAGEZERO` Guard): Reserves `__PAGEZERO` via `addressSpace.reserveGuard()` with 0 bytes RAM.
 * - #22 (`LC_MAIN` Entry VA): Computes `entryVA = __TEXT.vmaddr + slide + lcMain.entryoff`
 *   (with `LC_UNIXTHREAD` PC + slide fallback).
 */

import { FormatError, ERROR_CODES } from '../../common/errors.mjs';
import {
  PAGE_SIZE,
  PROT_READ,
  PROT_WRITE,
  PROT_EXEC,
  MAX_VA,
  alignDown,
  alignUp,
} from '../../kernel/vmm.mjs';
import { parseXmlPlist } from './plist-parser.mjs';

export const APPLE_THUNK_BASE = 0x7ffe00000000;
export const APPLE_THUNK_STRIDE = 16;
export const APPLE_STACK_BASE = 0x7fff00000000;

const MAX_VA_BIG = BigInt(MAX_VA);
const MAX_DYLD_FIXUPS = 200_000;
const MAX_CHAINED_SEGMENTS = 1024;

export const MACHO_CONSTANTS = Object.freeze({
  // Magics
  MH_MAGIC: 0xfeedface,
  MH_CIGAM: 0xcefaedfe,
  MH_MAGIC_64: 0xfeedfacf,
  MH_CIGAM_64: 0xcffaedfe,
  FAT_MAGIC: 0xcafebabe,
  FAT_CIGAM: 0xbebafeca,
  FAT_MAGIC_64: 0xcafebabf,
  FAT_CIGAM_64: 0xbfbafeca,

  // CPU Types
  CPU_ARCH_ABI64: 0x01000000,
  CPU_ARCH_ABI64_32: 0x02000000,
  CPU_TYPE_X86: 0x00000007,
  CPU_TYPE_X86_64: 0x01000007,
  CPU_TYPE_ARM: 0x0000000c,
  CPU_TYPE_ARM64: 0x0100000c,
  CPU_TYPE_ARM64_32: 0x0200000c,
  CPU_TYPE_POWERPC: 0x00000012,
  CPU_TYPE_POWERPC64: 0x01000012,

  // File Types
  MH_OBJECT: 0x1,
  MH_EXECUTE: 0x2,
  MH_FVMLIB: 0x3,
  MH_CORE: 0x4,
  MH_PRELOAD: 0x5,
  MH_DYLIB: 0x6,
  MH_DYLINKER: 0x7,
  MH_BUNDLE: 0x8,
  MH_DSYM: 0xa,

  // Load Commands
  LC_REQ_DYLD: 0x80000000,
  LC_SEGMENT: 0x1,
  LC_SYMTAB: 0x2,
  LC_UNIXTHREAD: 0x5,
  LC_DYSYMTAB: 0xb,
  LC_LOAD_DYLIB: 0xc,
  LC_ID_DYLIB: 0xd,
  LC_LOAD_DYLINKER: 0xe,
  LC_LOAD_WEAK_DYLIB: 0x80000018,
  LC_SEGMENT_64: 0x19,
  LC_UUID: 0x1b,
  LC_RPATH: 0x8000001c,
  LC_CODE_SIGNATURE: 0x1d,
  LC_REEXPORT_DYLIB: 0x8000001f,
  LC_ENCRYPTION_INFO: 0x21,
  LC_DYLD_INFO: 0x22,
  LC_DYLD_INFO_ONLY: 0x80000022,
  LC_LOAD_UPWARD_DYLIB: 0x80000023,
  LC_VERSION_MIN_MACOSX: 0x24,
  LC_VERSION_MIN_IPHONEOS: 0x25,
  LC_FUNCTION_STARTS: 0x26,
  LC_MAIN: 0x80000028,
  LC_DATA_IN_CODE: 0x29,
  LC_SOURCE_VERSION: 0x2a,
  LC_ENCRYPTION_INFO_64: 0x2c,
  LC_VERSION_MIN_TVOS: 0x2f,
  LC_VERSION_MIN_WATCHOS: 0x30,
  LC_BUILD_VERSION: 0x32,
  LC_DYLD_EXPORTS_TRIE: 0x80000033,
  LC_DYLD_CHAINED_FIXUPS: 0x80000034,

  // Section Types (flags & 0xFF)
  SECTION_TYPE_MASK: 0xff,
  S_REGULAR: 0x0,
  S_ZEROFILL: 0x1,
  S_CSTRING_LITERALS: 0x2,
  S_NON_LAZY_SYMBOL_POINTERS: 0x6,
  S_LAZY_SYMBOL_POINTERS: 0x7,
  S_SYMBOL_STUBS: 0x8,

  // VM Protections
  VM_PROT_NONE: 0x0,
  VM_PROT_READ: 0x1,
  VM_PROT_WRITE: 0x2,
  VM_PROT_EXECUTE: 0x4,

  // Dyld Rebase Opcodes
  REBASE_OPCODE_MASK: 0xf0,
  REBASE_IMMEDIATE_MASK: 0x0f,
  REBASE_OPCODE_DONE: 0x00,
  REBASE_OPCODE_SET_TYPE_IMM: 0x10,
  REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: 0x20,
  REBASE_OPCODE_ADD_ADDR_ULEB: 0x30,
  REBASE_OPCODE_ADD_ADDR_IMM_SCALED: 0x40,
  REBASE_OPCODE_DO_REBASE_IMM_TIMES: 0x50,
  REBASE_OPCODE_DO_REBASE_ULEB_TIMES: 0x60,
  REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: 0x70,
  REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: 0x80,

  // Dyld Bind Opcodes
  BIND_OPCODE_MASK: 0xf0,
  BIND_IMMEDIATE_MASK: 0x0f,
  BIND_OPCODE_DONE: 0x00,
  BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: 0x10,
  BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: 0x20,
  BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: 0x30,
  BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: 0x40,
  BIND_OPCODE_SET_TYPE_IMM: 0x50,
  BIND_OPCODE_SET_ADDEND_SLEB: 0x60,
  BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: 0x70,
  BIND_OPCODE_ADD_ADDR_ULEB: 0x80,
  BIND_OPCODE_DO_BIND: 0x90,
  BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: 0xa0,
  BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: 0xb0,
  BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: 0xc0,
  BIND_OPCODE_THREADED: 0xd0,

  // Chained Fixups
  DYLD_CHAINED_IMPORT: 1,
  DYLD_CHAINED_IMPORT_ADDEND: 2,
  DYLD_CHAINED_IMPORT_ADDEND64: 3,
  DYLD_CHAINED_PTR_ARM64E: 1,
  DYLD_CHAINED_PTR_64: 2,
  DYLD_CHAINED_PTR_32: 3,
  DYLD_CHAINED_PTR_64_OFFSET: 6,
  DYLD_CHAINED_PTR_ARM64E_KERNEL: 7,
  DYLD_CHAINED_PTR_ARM64E_USERLAND: 9,
  DYLD_CHAINED_PTR_ARM64E_USERLAND24: 12,
  DYLD_CHAINED_PTR_START_NONE: 0xffff,

  // Code Signature SuperBlob Magics (Big-Endian)
  CSMAGIC_EMBEDDED_SIGNATURE: 0xfade0cc0,
  CSMAGIC_CODEDIRECTORY: 0xfade0c02,
  CSMAGIC_REQUIREMENTS: 0xfade0c01,
  CSMAGIC_EMBEDDED_ENTITLEMENTS: 0xfade7171,
  CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: 0xfade7172,
  CSMAGIC_BLOBWRAPPER: 0xfade0b01,

  // Platforms (LC_BUILD_VERSION)
  PLATFORM_MACOS: 1,
  PLATFORM_IOS: 2,
  PLATFORM_TVOS: 3,
  PLATFORM_WATCHOS: 4,
  PLATFORM_BRIDGEOS: 5,
  PLATFORM_MACCATALYST: 6,
  PLATFORM_IOSSIMULATOR: 7,
});

const VALID_MACHO_CPUTYPES = new Set([
  MACHO_CONSTANTS.CPU_TYPE_X86,
  MACHO_CONSTANTS.CPU_TYPE_X86_64,
  MACHO_CONSTANTS.CPU_TYPE_ARM,
  MACHO_CONSTANTS.CPU_TYPE_ARM64,
  MACHO_CONSTANTS.CPU_TYPE_ARM64_32,
  MACHO_CONSTANTS.CPU_TYPE_POWERPC,
  MACHO_CONSTANTS.CPU_TYPE_POWERPC64,
]);

const CPUTYPE_TO_ARCH = Object.freeze({
  [MACHO_CONSTANTS.CPU_TYPE_X86]: 'x86',
  [MACHO_CONSTANTS.CPU_TYPE_X86_64]: 'x86_64',
  [MACHO_CONSTANTS.CPU_TYPE_ARM]: 'arm',
  [MACHO_CONSTANTS.CPU_TYPE_ARM64]: 'arm64',
  [MACHO_CONSTANTS.CPU_TYPE_ARM64_32]: 'arm64_32',
  [MACHO_CONSTANTS.CPU_TYPE_POWERPC]: 'ppc',
  [MACHO_CONSTANTS.CPU_TYPE_POWERPC64]: 'ppc64',
});

const PLATFORM_NAMES = Object.freeze({
  1: 'macos',
  2: 'ios',
  3: 'tvos',
  4: 'watchos',
  5: 'bridgeos',
  6: 'maccatalyst',
  7: 'iossimulator',
});

const OBJC_SECTION_NAMES = new Set([
  '__objc_classlist',
  '__objc_nlclslist',
  '__objc_catlist',
  '__objc_protolist',
  '__objc_selrefs',
  '__objc_classrefs',
  '__objc_superrefs',
  '__objc_methname',
  '__objc_classname',
  '__objc_methtype',
  '__objc_const',
  '__objc_data',
  '__objc_ivar',
  '__cfstring',
  '__cstring',
  '__ustring',
]);

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });

function toUint8Array(input) {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new FormatError('Mach-O parser expects Uint8Array, ArrayBuffer, or ArrayBufferView', {
    code: ERROR_CODES.E_INVALID_MACHO,
    format: 'macho',
  });
}

function readFixedString(bytes, offset, maxLen) {
  const end = Math.min(bytes.byteLength, offset + maxLen);
  let nul = end;
  for (let i = offset; i < end; i++) {
    if (bytes[i] === 0) {
      nul = i;
      break;
    }
  }
  return UTF8_DECODER.decode(bytes.subarray(offset, nul));
}

function readCString(bytes, offset, limit = bytes.byteLength) {
  if (offset < 0 || offset >= limit) return '';
  let end = offset;
  while (end < limit && bytes[end] !== 0) {
    end++;
  }
  return UTF8_DECODER.decode(bytes.subarray(offset, end));
}

function decodePackedVersion(val) {
  const major = (val >>> 16) & 0xffff;
  const minor = (val >>> 8) & 0xff;
  const patch = val & 0xff;
  return `${major}.${minor}.${patch}`;
}

function normalizeArchName(arch) {
  if (!arch) return 'arm64';
  const low = String(arch).trim().toLowerCase();
  if (low === 'aarch64' || low === 'arm64e') return 'arm64';
  if (low === 'amd64' || low === 'x86-64' || low === 'x64') return 'x86_64';
  return low;
}

// ============================================================================
// 64-bit BigInt LEB128 (Max 10 bytes — independent of 32-bit DEX LEB128!)
// ============================================================================

export function readUleb128_64(bytes, offset, end = bytes.byteLength) {
  let result = 0n;
  let shift = 0n;
  let pos = offset;
  for (let i = 0; i < 10; i++) {
    if (pos >= end) {
      throw new FormatError('Truncated 64-bit ULEB128 sequence in Mach-O dyld info', {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: pos,
      });
    }
    const byte = bytes[pos++];
    if (i === 9 && (byte & 0xfe) !== 0) {
      throw new FormatError('64-bit ULEB128 overflow in Mach-O dyld info', {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: pos - 1,
      });
    }
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value: result, nextOffset: pos };
    }
    shift += 7n;
  }
  throw new FormatError('64-bit ULEB128 exceeds 10 bytes', {
    code: ERROR_CODES.E_INVALID_MACHO,
    format: 'macho',
    offset,
  });
}

export function readSleb128_64(bytes, offset, end = bytes.byteLength) {
  let result = 0n;
  let shift = 0n;
  let pos = offset;
  for (let i = 0; i < 10; i++) {
    if (pos >= end) {
      throw new FormatError('Truncated 64-bit SLEB128 sequence in Mach-O dyld info', {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: pos,
      });
    }
    const byte = bytes[pos++];
    result |= BigInt(byte & 0x7f) << shift;
    shift += 7n;
    if ((byte & 0x80) === 0) {
      if (shift < 64n && (byte & 0x40) !== 0) {
        result |= -(1n << shift);
      }
      return { value: BigInt.asIntN(64, result), nextOffset: pos };
    }
  }
  throw new FormatError('64-bit SLEB128 exceeds 10 bytes', {
    code: ERROR_CODES.E_INVALID_MACHO,
    format: 'macho',
    offset,
  });
}

// ============================================================================
// Universal Fat Mach-O Parser (Edge Case #19: Java .class Guard!)
// ============================================================================

export function parseFatMachO(buffer) {
  const bytes = toUint8Array(buffer);
  if (bytes.byteLength < 8) {
    throw new FormatError('Truncated Fat Mach-O header (< 8 bytes)', {
      code: ERROR_CODES.E_INVALID_FAT,
      format: 'macho-fat',
      offset: 0,
    });
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magicBE = view.getUint32(0, false);
  if (magicBE !== MACHO_CONSTANTS.FAT_MAGIC && magicBE !== MACHO_CONSTANTS.FAT_MAGIC_64) {
    throw new FormatError(`Invalid Fat Mach-O magic: 0x${magicBE.toString(16)}`, {
      code: ERROR_CODES.E_INVALID_FAT,
      format: 'macho-fat',
      offset: 0,
    });
  }

  const isFat64 = magicBE === MACHO_CONSTANTS.FAT_MAGIC_64;
  const entrySize = isFat64 ? 32 : 20;
  const nfatArch = view.getUint32(4, false);

  // Edge Case #19: Java .class files start with 0xCAFEBABE + minor(u16) + major(u16 >= 45)
  if (nfatArch < 1 || nfatArch > 32) {
    throw new FormatError(
      `Invalid Fat Mach-O nfat_arch=${nfatArch} (must be 1..32; rejects Java .class)`,
      {
        code: ERROR_CODES.E_INVALID_FAT,
        format: 'macho-fat',
        offset: 4,
        details: { nfatArch },
      }
    );
  }

  const tableEnd = 8 + nfatArch * entrySize;
  if (tableEnd > bytes.byteLength) {
    throw new FormatError(
      `Fat Mach-O slice table out of bounds (${tableEnd} > ${bytes.byteLength})`,
      {
        code: ERROR_CODES.E_INVALID_FAT,
        format: 'macho-fat',
        offset: 8,
      }
    );
  }

  const slices = [];
  for (let i = 0; i < nfatArch; i++) {
    const base = 8 + i * entrySize;
    const cputype = view.getUint32(base, false);
    const cpusubtype = view.getUint32(base + 4, false);

    if (!VALID_MACHO_CPUTYPES.has(cputype)) {
      throw new FormatError(
        `Invalid Fat Mach-O slice #${i} cputype: 0x${cputype.toString(16)} (not a Mach-O CPU type)`,
        {
          code: ERROR_CODES.E_INVALID_FAT,
          format: 'macho-fat',
          offset: base,
          details: { sliceIndex: i, cputype },
        }
      );
    }

    let offset;
    let size;
    let align;
    if (isFat64) {
      const offBig = view.getBigUint64(base + 8, false);
      const sizeBig = view.getBigUint64(base + 16, false);
      align = view.getUint32(base + 24, false);
      if (offBig > BigInt(bytes.byteLength) || sizeBig > BigInt(bytes.byteLength)) {
        throw new FormatError(`Fat64 slice #${i} offset/size out of bounds`, {
          code: ERROR_CODES.E_INVALID_FAT,
          format: 'macho-fat',
          offset: base + 8,
        });
      }
      offset = Number(offBig);
      size = Number(sizeBig);
    } else {
      offset = view.getUint32(base + 8, false);
      size = view.getUint32(base + 12, false);
      align = view.getUint32(base + 16, false);
    }

    if (offset < tableEnd || size < 28 || offset + size > bytes.byteLength) {
      throw new FormatError(
        `Fat Mach-O slice #${i} bounds invalid (offset=${offset}, size=${size}, total=${bytes.byteLength})`,
        {
          code: ERROR_CODES.E_INVALID_FAT,
          format: 'macho-fat',
          offset: base + 8,
        }
      );
    }

    slices.push({
      cputype,
      cpusubtype,
      arch: CPUTYPE_TO_ARCH[cputype] ?? 'unknown',
      offset,
      size,
      align,
      data: bytes.subarray(offset, offset + size),
    });
  }

  // Reject any overlapping Fat slices (partial, identical, or contained intervals)
  const sortedSlices = [...slices].sort((a, b) => a.offset - b.offset || a.size - b.size);
  for (let i = 1; i < sortedSlices.length; i++) {
    const prev = sortedSlices[i - 1];
    const cur = sortedSlices[i];
    if (prev.offset + prev.size > cur.offset) {
      throw new FormatError(
        `Overlapping Fat Mach-O slices ([${prev.offset}..${prev.offset + prev.size}) overlaps [${cur.offset}..${cur.offset + cur.size}))`,
        {
          code: ERROR_CODES.E_INVALID_FAT,
          format: 'macho-fat',
          offset: cur.offset,
          details: {
            prev: { arch: prev.arch, offset: prev.offset, size: prev.size },
            cur: { arch: cur.arch, offset: cur.offset, size: cur.size },
          },
        }
      );
    }
  }

  return {
    isFat: true,
    isFat64,
    nfatArch,
    slices,
  };
}

// ============================================================================
// Dyld Info (`LC_DYLD_INFO_ONLY`) Parsers
// ============================================================================

function consumeFixupBudget(budget, amount, label, offset) {
  const remaining = BigInt(budget.limit - budget.count);
  const req = typeof amount === 'bigint' ? amount : BigInt(amount);
  if (req < 0n || req > remaining) {
    throw new FormatError(
      `${label} exceeds cumulative dyld fixup cap (${budget.limit})`,
      {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset,
      }
    );
  }
  budget.count += Number(req);
}

function parseDyldRebaseOpcodes(bytes, off, size, segments, budget = { count: 0, limit: MAX_DYLD_FIXUPS }) {
  if (size === 0) return [];
  if (off + size > bytes.byteLength) {
    throw new FormatError('LC_DYLD_INFO rebase table out of bounds', {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: off,
    });
  }

  const end = off + size;
  let pos = off;
  let type = 1; // REBASE_TYPE_POINTER
  let segIndex = 0;
  let segOffset = 0n;
  const rebases = [];
  let guard = 0;

  while (pos < end) {
    if (++guard > MAX_DYLD_FIXUPS * 2) {
      throw new FormatError('LC_DYLD_INFO rebase opcode stream exceeds iteration limit', {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: pos,
      });
    }
    const byte = bytes[pos++];
    const opcode = byte & MACHO_CONSTANTS.REBASE_OPCODE_MASK;
    const imm = byte & MACHO_CONSTANTS.REBASE_IMMEDIATE_MASK;

    switch (opcode) {
      case MACHO_CONSTANTS.REBASE_OPCODE_DONE:
        return rebases;
      case MACHO_CONSTANTS.REBASE_OPCODE_SET_TYPE_IMM:
        type = imm;
        break;
      case MACHO_CONSTANTS.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
        segIndex = imm;
        const r = readUleb128_64(bytes, pos, end);
        segOffset = r.value;
        pos = r.nextOffset;
        break;
      }
      case MACHO_CONSTANTS.REBASE_OPCODE_ADD_ADDR_ULEB: {
        const r = readUleb128_64(bytes, pos, end);
        segOffset = BigInt.asUintN(64, segOffset + r.value);
        pos = r.nextOffset;
        break;
      }
      case MACHO_CONSTANTS.REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        segOffset = BigInt.asUintN(64, segOffset + BigInt(imm * 8));
        break;
      case MACHO_CONSTANTS.REBASE_OPCODE_DO_REBASE_IMM_TIMES:
        consumeFixupBudget(budget, imm, 'LC_DYLD_INFO rebase table', pos - 1);
        for (let i = 0; i < imm; i++) {
          if (segIndex < segments.length) {
            rebases.push({
              segIndex,
              segOffset,
              vmaddr: segments[segIndex].vmaddr + segOffset,
              type,
            });
          }
          segOffset += 8n;
        }
        break;
      case MACHO_CONSTANTS.REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
        const opOff = pos - 1;
        const r = readUleb128_64(bytes, pos, end);
        pos = r.nextOffset;
        consumeFixupBudget(budget, r.value, 'LC_DYLD_INFO rebase table', opOff);
        const count = Number(r.value);
        for (let i = 0; i < count; i++) {
          if (segIndex < segments.length) {
            rebases.push({
              segIndex,
              segOffset,
              vmaddr: segments[segIndex].vmaddr + segOffset,
              type,
            });
          }
          segOffset += 8n;
        }
        break;
      }
      case MACHO_CONSTANTS.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
        consumeFixupBudget(budget, 1, 'LC_DYLD_INFO rebase table', pos - 1);
        if (segIndex < segments.length) {
          rebases.push({
            segIndex,
            segOffset,
            vmaddr: segments[segIndex].vmaddr + segOffset,
            type,
          });
        }
        const r = readUleb128_64(bytes, pos, end);
        pos = r.nextOffset;
        segOffset = BigInt.asUintN(64, segOffset + 8n + r.value);
        break;
      }
      case MACHO_CONSTANTS.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
        const opOff = pos - 1;
        const c = readUleb128_64(bytes, pos, end);
        pos = c.nextOffset;
        const s = readUleb128_64(bytes, pos, end);
        pos = s.nextOffset;
        consumeFixupBudget(budget, c.value, 'LC_DYLD_INFO rebase table', opOff);
        const count = Number(c.value);
        for (let i = 0; i < count; i++) {
          if (segIndex < segments.length) {
            rebases.push({
              segIndex,
              segOffset,
              vmaddr: segments[segIndex].vmaddr + segOffset,
              type,
            });
          }
          segOffset = BigInt.asUintN(64, segOffset + 8n + s.value);
        }
        break;
      }
      default:
        throw new FormatError(`Unknown dyld rebase opcode: 0x${byte.toString(16)}`, {
          code: ERROR_CODES.E_INVALID_MACHO,
          format: 'macho',
          offset: pos - 1,
        });
    }
  }
  return rebases;
}

function parseDyldBindOpcodes(
  bytes,
  off,
  size,
  segments,
  isLazy = false,
  budget = { count: 0, limit: MAX_DYLD_FIXUPS }
) {
  if (size === 0) return [];
  if (off + size > bytes.byteLength) {
    throw new FormatError('LC_DYLD_INFO bind table out of bounds', {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: off,
    });
  }

  const end = off + size;
  let pos = off;
  let libOrdinal = 0;
  let symbol = '';
  let symbolFlags = 0;
  let type = 1; // BIND_TYPE_POINTER
  let addend = 0n;
  let segIndex = 0;
  let segOffset = 0n;
  const binds = [];
  let guard = 0;

  while (pos < end) {
    if (++guard > MAX_DYLD_FIXUPS * 2) {
      throw new FormatError('LC_DYLD_INFO bind opcode stream exceeds iteration limit', {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: pos,
      });
    }
    const byte = bytes[pos++];
    const opcode = byte & MACHO_CONSTANTS.BIND_OPCODE_MASK;
    const imm = byte & MACHO_CONSTANTS.BIND_IMMEDIATE_MASK;

    switch (opcode) {
      case MACHO_CONSTANTS.BIND_OPCODE_DONE:
        if (!isLazy) return binds;
        // In lazy bind stream, DONE marks end of one lazy symbol record; continue until end!
        break;
      case MACHO_CONSTANTS.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        libOrdinal = imm;
        break;
      case MACHO_CONSTANTS.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
        const r = readUleb128_64(bytes, pos, end);
        libOrdinal = Number(r.value);
        pos = r.nextOffset;
        break;
      }
      case MACHO_CONSTANTS.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        libOrdinal = imm === 0 ? 0 : (imm | 0xf0) - 256; // sign-extended 4-bit negative special ordinal
        break;
      case MACHO_CONSTANTS.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
        symbolFlags = imm;
        const start = pos;
        while (pos < end && bytes[pos] !== 0) pos++;
        symbol = UTF8_DECODER.decode(bytes.subarray(start, pos));
        if (pos < end) pos++; // skip NUL
        break;
      }
      case MACHO_CONSTANTS.BIND_OPCODE_SET_TYPE_IMM:
        type = imm;
        break;
      case MACHO_CONSTANTS.BIND_OPCODE_SET_ADDEND_SLEB: {
        const r = readSleb128_64(bytes, pos, end);
        addend = r.value;
        pos = r.nextOffset;
        break;
      }
      case MACHO_CONSTANTS.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
        segIndex = imm;
        const r = readUleb128_64(bytes, pos, end);
        segOffset = r.value;
        pos = r.nextOffset;
        break;
      }
      case MACHO_CONSTANTS.BIND_OPCODE_ADD_ADDR_ULEB: {
        const r = readUleb128_64(bytes, pos, end);
        segOffset = BigInt.asUintN(64, segOffset + r.value);
        pos = r.nextOffset;
        break;
      }
      case MACHO_CONSTANTS.BIND_OPCODE_DO_BIND:
        consumeFixupBudget(budget, 1, 'LC_DYLD_INFO bind table', pos - 1);
        if (segIndex < segments.length) {
          binds.push({
            segIndex,
            segOffset,
            vmaddr: segments[segIndex].vmaddr + segOffset,
            symbol,
            libOrdinal,
            addend,
            type,
            symbolFlags,
            isLazy,
          });
        }
        segOffset += 8n;
        break;
      case MACHO_CONSTANTS.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
        consumeFixupBudget(budget, 1, 'LC_DYLD_INFO bind table', pos - 1);
        if (segIndex < segments.length) {
          binds.push({
            segIndex,
            segOffset,
            vmaddr: segments[segIndex].vmaddr + segOffset,
            symbol,
            libOrdinal,
            addend,
            type,
            symbolFlags,
            isLazy,
          });
        }
        const r = readUleb128_64(bytes, pos, end);
        pos = r.nextOffset;
        segOffset = BigInt.asUintN(64, segOffset + 8n + r.value);
        break;
      }
      case MACHO_CONSTANTS.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        consumeFixupBudget(budget, 1, 'LC_DYLD_INFO bind table', pos - 1);
        if (segIndex < segments.length) {
          binds.push({
            segIndex,
            segOffset,
            vmaddr: segments[segIndex].vmaddr + segOffset,
            symbol,
            libOrdinal,
            addend,
            type,
            symbolFlags,
            isLazy,
          });
        }
        segOffset = BigInt.asUintN(64, segOffset + 8n + BigInt(imm * 8));
        break;
      case MACHO_CONSTANTS.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
        const opOff = pos - 1;
        const c = readUleb128_64(bytes, pos, end);
        pos = c.nextOffset;
        const s = readUleb128_64(bytes, pos, end);
        pos = s.nextOffset;
        consumeFixupBudget(budget, c.value, 'LC_DYLD_INFO bind table', opOff);
        const count = Number(c.value);
        for (let i = 0; i < count; i++) {
          if (segIndex < segments.length) {
            binds.push({
              segIndex,
              segOffset,
              vmaddr: segments[segIndex].vmaddr + segOffset,
              symbol,
              libOrdinal,
              addend,
              type,
              symbolFlags,
              isLazy,
            });
          }
          segOffset = BigInt.asUintN(64, segOffset + 8n + s.value);
        }
        break;
      }
      case MACHO_CONSTANTS.BIND_OPCODE_THREADED: {
        if (imm === 0) {
          // BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB
          const r = readUleb128_64(bytes, pos, end);
          pos = r.nextOffset;
        }
        break;
      }
      default:
        throw new FormatError(`Unknown dyld bind opcode: 0x${byte.toString(16)}`, {
          code: ERROR_CODES.E_INVALID_MACHO,
          format: 'macho',
          offset: pos - 1,
        });
    }
  }
  return binds;
}

function parseDyldExportTrie(bytes, off, size) {
  if (size === 0) return [];
  if (off + size > bytes.byteLength) return [];
  const end = off + size;
  const exports = [];
  const visited = new Set();

  function walk(relOff, prefix, depth) {
    if (depth > 128 || exports.length > 50_000) return;
    const pos = off + relOff;
    if (pos >= end || visited.has(pos)) return;
    visited.add(pos);

    const termInfo = readUleb128_64(bytes, pos, end);
    let cur = termInfo.nextOffset;
    const termSize = Number(termInfo.value);
    if (termSize > 0 && cur + termSize <= end) {
      const flagsRes = readUleb128_64(bytes, cur, cur + termSize);
      const flags = Number(flagsRes.value);
      const addrRes = readUleb128_64(bytes, flagsRes.nextOffset, cur + termSize);
      exports.push({
        name: prefix,
        flags,
        offset: addrRes.value,
      });
      cur += termSize;
    }

    if (cur >= end) return;
    const childCount = bytes[cur++];
    for (let i = 0; i < childCount; i++) {
      const strStart = cur;
      while (cur < end && bytes[cur] !== 0) cur++;
      const edge = UTF8_DECODER.decode(bytes.subarray(strStart, cur));
      if (cur < end) cur++; // NUL
      const nextNode = readUleb128_64(bytes, cur, end);
      cur = nextNode.nextOffset;
      walk(Number(nextNode.value), prefix + edge, depth + 1);
    }
  }

  walk(0, '', 0);
  return exports;
}

// ============================================================================
// Chained Fixups (`LC_DYLD_CHAINED_FIXUPS`) Parser
// ============================================================================

function parseChainedFixups(bytes, dataoff, datasize, le) {
  if (datasize < 28 || dataoff + datasize > bytes.byteLength) {
    throw new FormatError('LC_DYLD_CHAINED_FIXUPS data out of bounds', {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: dataoff,
    });
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fixupsVersion = view.getUint32(dataoff + 0, le);
  const startsOffset = view.getUint32(dataoff + 4, le);
  const importsOffset = view.getUint32(dataoff + 8, le);
  const symbolsOffset = view.getUint32(dataoff + 12, le);
  const importsCount = view.getUint32(dataoff + 16, le);
  const importsFormat = view.getUint32(dataoff + 20, le);
  const symbolsFormat = view.getUint32(dataoff + 24, le);

  const limit = dataoff + datasize;

  if (startsOffset > datasize) {
    throw new FormatError(`LC_DYLD_CHAINED_FIXUPS startsOffset (${startsOffset}) exceeds datasize (${datasize})`, {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: dataoff + 4,
    });
  }
  if (importsOffset > datasize) {
    throw new FormatError(`LC_DYLD_CHAINED_FIXUPS importsOffset (${importsOffset}) exceeds datasize (${datasize})`, {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: dataoff + 8,
    });
  }
  if (symbolsOffset > datasize) {
    throw new FormatError(`LC_DYLD_CHAINED_FIXUPS symbolsOffset (${symbolsOffset}) exceeds datasize (${datasize})`, {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: dataoff + 12,
    });
  }
  if (importsCount > MAX_DYLD_FIXUPS) {
    throw new FormatError(`LC_DYLD_CHAINED_FIXUPS importsCount (${importsCount}) exceeds cap (${MAX_DYLD_FIXUPS})`, {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: dataoff + 16,
    });
  }

  const symbolsBase = dataoff + symbolsOffset;

  // Parse imports with strict format & bounds validation
  const imports = [];
  if (importsCount > 0) {
    let entrySize;
    if (importsFormat === MACHO_CONSTANTS.DYLD_CHAINED_IMPORT) {
      entrySize = 4;
    } else if (importsFormat === MACHO_CONSTANTS.DYLD_CHAINED_IMPORT_ADDEND) {
      entrySize = 8;
    } else if (importsFormat === MACHO_CONSTANTS.DYLD_CHAINED_IMPORT_ADDEND64) {
      entrySize = 16;
    } else {
      throw new FormatError(`Unknown LC_DYLD_CHAINED_FIXUPS importsFormat: ${importsFormat}`, {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: dataoff + 20,
      });
    }

    const totalImportBytes = BigInt(importsOffset) + BigInt(importsCount) * BigInt(entrySize);
    if (totalImportBytes > BigInt(datasize)) {
      throw new FormatError(
        `Truncated LC_DYLD_CHAINED_FIXUPS imports table (${importsCount} entries of ${entrySize}B exceed datasize=${datasize})`,
        {
          code: ERROR_CODES.E_INVALID_MACHO,
          format: 'macho',
          offset: dataoff + importsOffset,
        }
      );
    }

    let impPos = dataoff + importsOffset;
    for (let i = 0; i < importsCount; i++) {
      let libOrdinal = 0;
      let weakImport = false;
      let nameOffset = 0;
      let addend = 0n;

      if (importsFormat === MACHO_CONSTANTS.DYLD_CHAINED_IMPORT) {
        const word = view.getUint32(impPos, le);
        impPos += 4;
        libOrdinal = word & 0xff;
        if (libOrdinal >= 0xf0) libOrdinal -= 256;
        weakImport = ((word >>> 8) & 1) === 1;
        nameOffset = (word >>> 9) & 0x7fffff;
      } else if (importsFormat === MACHO_CONSTANTS.DYLD_CHAINED_IMPORT_ADDEND) {
        const word = view.getUint32(impPos, le);
        addend = BigInt(view.getInt32(impPos + 4, le));
        impPos += 8;
        libOrdinal = word & 0xff;
        if (libOrdinal >= 0xf0) libOrdinal -= 256;
        weakImport = ((word >>> 8) & 1) === 1;
        nameOffset = (word >>> 9) & 0x7fffff;
      } else {
        const qword = view.getBigUint64(impPos, le);
        addend = view.getBigInt64(impPos + 8, le);
        impPos += 16;
        libOrdinal = Number(qword & 0xffffn);
        if (libOrdinal >= 0xfff0) libOrdinal -= 65536;
        weakImport = ((qword >> 16n) & 1n) === 1n;
        nameOffset = Number((qword >> 32n) & 0xffffffffn);
      }

      let name = '';
      if (symbolsFormat === 0) {
        if (symbolsBase + nameOffset >= limit) {
          throw new FormatError(
            `LC_DYLD_CHAINED_FIXUPS import #${i} symbol nameOffset (${nameOffset}) out of bounds`,
            {
              code: ERROR_CODES.E_INVALID_MACHO,
              format: 'macho',
              offset: symbolsBase,
            }
          );
        }
        name = readCString(bytes, symbolsBase + nameOffset, limit);
      }
      imports.push({ libOrdinal, weakImport, name, addend });
    }
  }

  // Parse starts_in_image with strict bounds & cumulative pageStarts cap
  const segmentStarts = [];
  if (startsOffset > 0) {
    const startsBase = dataoff + startsOffset;
    if (startsBase + 4 > limit) {
      throw new FormatError('Truncated LC_DYLD_CHAINED_FIXUPS starts_in_image header', {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: startsBase,
      });
    }
    const segCount = view.getUint32(startsBase, le);
    if (segCount > MAX_CHAINED_SEGMENTS) {
      throw new FormatError(
        `LC_DYLD_CHAINED_FIXUPS segCount (${segCount}) exceeds maximum (${MAX_CHAINED_SEGMENTS})`,
        {
          code: ERROR_CODES.E_INVALID_MACHO,
          format: 'macho',
          offset: startsBase,
        }
      );
    }
    if (BigInt(startsBase) + 4n + BigInt(segCount) * 4n > BigInt(limit)) {
      throw new FormatError('Truncated LC_DYLD_CHAINED_FIXUPS seg_info_offset table', {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: startsBase + 4,
      });
    }

    let totalPageStarts = 0;
    for (let s = 0; s < segCount; s++) {
      const segInfoOffset = view.getUint32(startsBase + 4 + s * 4, le);
      if (segInfoOffset === 0) {
        segmentStarts.push(null);
        continue;
      }
      const segInfoPos = startsBase + segInfoOffset;
      if (segInfoPos < startsBase || segInfoPos + 22 > limit) {
        throw new FormatError(
          `LC_DYLD_CHAINED_FIXUPS segInfo #${s} out of bounds (offset=${segInfoOffset})`,
          {
            code: ERROR_CODES.E_INVALID_MACHO,
            format: 'macho',
            offset: startsBase + 4 + s * 4,
          }
        );
      }
      const size = view.getUint32(segInfoPos + 0, le);
      const pageSize = view.getUint16(segInfoPos + 4, le);
      const pointerFormat = view.getUint16(segInfoPos + 6, le);
      const segmentOffset = view.getBigUint64(segInfoPos + 8, le);
      const maxValidPointer = view.getUint32(segInfoPos + 16, le);
      const pageCount = view.getUint16(segInfoPos + 20, le);
      if (segInfoPos + 22 + pageCount * 2 > limit) {
        throw new FormatError(
          `Truncated LC_DYLD_CHAINED_FIXUPS pageStarts for segment #${s} (pageCount=${pageCount})`,
          {
            code: ERROR_CODES.E_INVALID_MACHO,
            format: 'macho',
            offset: segInfoPos + 20,
          }
        );
      }
      totalPageStarts += pageCount;
      if (totalPageStarts > MAX_DYLD_FIXUPS) {
        throw new FormatError(
          `LC_DYLD_CHAINED_FIXUPS cumulative pageStarts (${totalPageStarts}) exceeds cap (${MAX_DYLD_FIXUPS})`,
          {
            code: ERROR_CODES.E_INVALID_MACHO,
            format: 'macho',
            offset: segInfoPos + 20,
          }
        );
      }
      const pageStarts = [];
      for (let p = 0; p < pageCount; p++) {
        const pPos = segInfoPos + 22 + p * 2;
        pageStarts.push(view.getUint16(pPos, le));
      }
      segmentStarts.push({
        segIndex: s,
        size,
        pageSize,
        pointerFormat,
        segmentOffset,
        maxValidPointer,
        pageStarts,
      });
    }
  }

  return {
    fixupsVersion,
    importsFormat,
    symbolsFormat,
    imports,
    segmentStarts,
  };
}

// ============================================================================
// Code Signature (`LC_CODE_SIGNATURE`) Parser
// ============================================================================

function parseCodeSignature(bytes, dataoff, datasize) {
  if (datasize < 12 || dataoff + datasize > bytes.byteLength) {
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = view.getUint32(dataoff, false); // SuperBlob is ALWAYS Big-Endian
  if (magic !== MACHO_CONSTANTS.CSMAGIC_EMBEDDED_SIGNATURE) {
    return null;
  }
  const length = view.getUint32(dataoff + 4, false);
  const count = view.getUint32(dataoff + 8, false);
  const limit = Math.min(bytes.byteLength, dataoff + Math.min(datasize, length));

  const result = {
    magic,
    length,
    blobCount: count,
    codeDirectory: null,
    entitlementsXml: null,
    entitlements: null,
  };

  for (let i = 0; i < count; i++) {
    const idxPos = dataoff + 12 + i * 8;
    if (idxPos + 8 > limit) break;
    const blobType = view.getUint32(idxPos, false);
    const blobRelOff = view.getUint32(idxPos + 4, false);
    const blobPos = dataoff + blobRelOff;
    if (blobPos + 8 > limit) continue;
    const blobMagic = view.getUint32(blobPos, false);
    const blobLen = view.getUint32(blobPos + 4, false);
    if (blobLen < 8 || blobPos + blobLen > limit) continue;

    if (blobMagic === MACHO_CONSTANTS.CSMAGIC_CODEDIRECTORY && blobLen >= 44) {
      const version = view.getUint32(blobPos + 8, false);
      const flags = view.getUint32(blobPos + 12, false);
      const hashOffset = view.getUint32(blobPos + 16, false);
      const identOffset = view.getUint32(blobPos + 20, false);
      const nSpecialSlots = view.getUint32(blobPos + 24, false);
      const nCodeSlots = view.getUint32(blobPos + 28, false);
      const codeLimit = view.getUint32(blobPos + 32, false);
      const hashSize = bytes[blobPos + 36];
      const hashType = bytes[blobPos + 37];
      const identifier =
        identOffset > 0 && blobPos + identOffset < blobPos + blobLen
          ? readCString(bytes, blobPos + identOffset, blobPos + blobLen)
          : '';
      result.codeDirectory = {
        blobType,
        version,
        flags,
        hashOffset,
        identifier,
        nSpecialSlots,
        nCodeSlots,
        codeLimit,
        hashSize,
        hashType,
      };
    } else if (blobMagic === MACHO_CONSTANTS.CSMAGIC_EMBEDDED_ENTITLEMENTS) {
      const xmlBytes = bytes.subarray(blobPos + 8, blobPos + blobLen);
      const xmlStr = UTF8_DECODER.decode(xmlBytes).replace(/\0+$/, '').trim();
      result.entitlementsXml = xmlStr;
      if (xmlStr.length > 0) {
        try {
          result.entitlements = parseXmlPlist(xmlStr);
        } catch {
          result.entitlements = null;
        }
      }
    }
  }

  return result;
}

// ============================================================================
// Main Mach-O 64 Parser
// ============================================================================

function validateLcMainEntry(lcMain, textSeg, slideBig = 0n) {
  if (!textSeg) {
    throw new FormatError('LC_MAIN present without __TEXT segment', {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
    });
  }
  const entryoff = typeof lcMain.entryoff === 'bigint' ? lcMain.entryoff : BigInt(lcMain.entryoff ?? 0);
  if (entryoff >= textSeg.vmsize) {
    throw new FormatError(
      `LC_MAIN entryoff (0x${entryoff.toString(16)}) out of __TEXT vmsize (0x${textSeg.vmsize.toString(16)})`,
      {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        details: { entryoff: entryoff.toString(), vmsize: textSeg.vmsize.toString() },
      }
    );
  }
  if (textSeg.filesize > 0n && entryoff >= textSeg.filesize) {
    throw new FormatError(
      `LC_MAIN entryoff (0x${entryoff.toString(16)}) out of __TEXT filesize (0x${textSeg.filesize.toString(16)})`,
      {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        details: { entryoff: entryoff.toString(), filesize: textSeg.filesize.toString() },
      }
    );
  }
  const slidTextStart = textSeg.vmaddr + slideBig;
  const slidTextEnd = slidTextStart + textSeg.vmsize;
  const entryVABig = slidTextStart + entryoff;
  if (
    slidTextStart < 0n ||
    entryVABig < slidTextStart ||
    entryVABig >= slidTextEnd ||
    entryVABig > MAX_VA_BIG
  ) {
    throw new FormatError(
      `LC_MAIN entryVA (0x${entryVABig.toString(16)}) exceeds valid address space bounds`,
      {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
      }
    );
  }
  return Number(entryVABig);
}

export function parseMachO(buffer, { preferredArch = 'arm64', allowEncrypted = false, _fromFat = false } = {}) {
  const bytes = toUint8Array(buffer);
  if (bytes.byteLength < 8) {
    throw new FormatError('Truncated Mach-O binary (< 8 bytes)', {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: 0,
    });
  }

  const probeView = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magicBE = probeView.getUint32(0, false);

  // Handle Universal Fat Mach-O (with strict Java .class rejection — Edge Case #19, and no nested Fat!)
  if (magicBE === MACHO_CONSTANTS.FAT_MAGIC || magicBE === MACHO_CONSTANTS.FAT_MAGIC_64) {
    if (_fromFat) {
      throw new FormatError('Nested Fat Mach-O binary inside Fat slice is forbidden', {
        code: ERROR_CODES.E_INVALID_FAT,
        format: 'macho-fat',
        offset: 0,
      });
    }
    const fat = parseFatMachO(bytes);
    const wantArch = normalizeArchName(preferredArch);
    const chosen =
      fat.slices.find((s) => s.arch === wantArch) ??
      fat.slices.find((s) => s.arch === 'arm64') ??
      fat.slices.find((s) => s.arch === 'x86_64') ??
      fat.slices[0];

    const parsedSlice = parseMachO(chosen.data, { preferredArch, allowEncrypted, _fromFat: true });
    parsedSlice.isFat = true;
    parsedSlice.fatSlices = fat.slices.map(({ data: _omit, ...meta }) => meta);
    return parsedSlice;
  }

  if (bytes.byteLength < 32) {
    throw new FormatError('Truncated Mach-O 64-bit header (< 32 bytes)', {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: 0,
    });
  }

  const magicLE = probeView.getUint32(0, true);
  let le = true;
  if (magicLE === MACHO_CONSTANTS.MH_MAGIC_64) {
    le = true;
  } else if (magicBE === MACHO_CONSTANTS.MH_MAGIC_64) {
    le = false;
  } else if (magicLE === MACHO_CONSTANTS.MH_MAGIC || magicBE === MACHO_CONSTANTS.MH_MAGIC) {
    throw new FormatError('32-bit Mach-O binaries are not supported (require 64-bit Mach-O)', {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: 0,
    });
  } else {
    throw new FormatError(`Invalid Mach-O magic: 0x${magicLE.toString(16)}`, {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
      offset: 0,
    });
  }

  const view = probeView;
  const cputype = view.getUint32(4, le);
  const cpusubtype = view.getUint32(8, le);
  const filetype = view.getUint32(12, le);
  const ncmds = view.getUint32(16, le);
  const sizeofcmds = view.getUint32(20, le);
  const flags = view.getUint32(24, le);
  const reserved = view.getUint32(28, le);

  if (ncmds > 4096 || 32 + sizeofcmds > bytes.byteLength) {
    throw new FormatError(
      `Mach-O load commands exceed file size (ncmds=${ncmds}, sizeofcmds=${sizeofcmds}, len=${bytes.byteLength})`,
      {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: 16,
      }
    );
  }

  const arch = CPUTYPE_TO_ARCH[cputype] ?? 'unknown';
  const segments = [];
  const allSections = [];
  const dylibs = [];
  let idDylib = null;
  const rpaths = [];
  let uuid = null;
  let buildVersion = null;
  let versionMin = null;
  let lcMain = null;
  let unixThread = null;
  let symtabCmd = null;
  let dysymtabCmd = null;
  let dyldInfoCmd = null;
  let chainedFixupsCmd = null;
  let exportsTrieCmd = null;
  let codeSignatureCmd = null;
  let encryptionInfo = null;
  let hasEncryptedSegment = false;
  const loadCommands = [];

  let pos = 32;
  const cmdsEnd = 32 + sizeofcmds;

  for (let i = 0; i < ncmds; i++) {
    if (pos + 8 > cmdsEnd) {
      throw new FormatError(`Truncated Mach-O load command #${i} at offset ${pos}`, {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: pos,
      });
    }
    const cmd = view.getUint32(pos, le);
    const cmdsize = view.getUint32(pos + 4, le);
    if (cmdsize < 8 || pos + cmdsize > cmdsEnd) {
      throw new FormatError(`Invalid Mach-O load command #${i} cmdsize=${cmdsize} at offset ${pos}`, {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macho',
        offset: pos,
      });
    }

    loadCommands.push({ cmd, cmdsize, offset: pos });

    switch (cmd) {
      case MACHO_CONSTANTS.LC_SEGMENT_64: {
        if (cmdsize < 72) {
          throw new FormatError('Truncated LC_SEGMENT_64 command', {
            code: ERROR_CODES.E_INVALID_MACHO,
            format: 'macho',
            offset: pos,
          });
        }
        const segname = readFixedString(bytes, pos + 8, 16);
        const vmaddr = view.getBigUint64(pos + 24, le);
        const vmsize = view.getBigUint64(pos + 32, le);
        const fileoff = view.getBigUint64(pos + 40, le);
        const filesize = view.getBigUint64(pos + 48, le);
        const maxprot = view.getUint32(pos + 56, le);
        const initprot = view.getUint32(pos + 60, le);
        const nsects = view.getUint32(pos + 64, le);
        const segFlags = view.getUint32(pos + 68, le);

        if (filesize > 0n && fileoff + filesize > BigInt(bytes.byteLength)) {
          throw new FormatError(
            `LC_SEGMENT_64 '${segname}' file range out of bounds (${fileoff}+${filesize} > ${bytes.byteLength})`,
            {
              code: ERROR_CODES.E_INVALID_MACHO,
              format: 'macho',
              offset: pos,
            }
          );
        }
        if (72 + nsects * 80 > cmdsize) {
          throw new FormatError(`LC_SEGMENT_64 '${segname}' nsects=${nsects} exceeds cmdsize=${cmdsize}`, {
            code: ERROR_CODES.E_INVALID_MACHO,
            format: 'macho',
            offset: pos + 64,
          });
        }

        const sections = [];
        let sPos = pos + 72;
        for (let s = 0; s < nsects; s++) {
          const sectname = readFixedString(bytes, sPos + 0, 16);
          const sectSegname = readFixedString(bytes, sPos + 16, 16);
          const addr = view.getBigUint64(sPos + 32, le);
          const size = view.getBigUint64(sPos + 40, le);
          const offset = view.getUint32(sPos + 48, le);
          const align = view.getUint32(sPos + 52, le);
          const reloff = view.getUint32(sPos + 56, le);
          const nreloc = view.getUint32(sPos + 60, le);
          const sFlags = view.getUint32(sPos + 64, le);
          const reserved1 = view.getUint32(sPos + 68, le);
          const reserved2 = view.getUint32(sPos + 72, le);
          const reserved3 = view.getUint32(sPos + 76, le);
          const sect = {
            sectname,
            segname: sectSegname,
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags: sFlags,
            type: sFlags & 0xff,
            reserved1,
            reserved2,
            reserved3,
          };
          sections.push(sect);
          allSections.push(sect);
          sPos += 80;
        }

        segments.push({
          segname,
          vmaddr,
          vmsize,
          fileoff,
          filesize,
          maxprot,
          initprot,
          nsects,
          flags: segFlags,
          sections,
        });
        break;
      }

      case MACHO_CONSTANTS.LC_MAIN: {
        if (cmdsize < 24) {
          throw new FormatError('Truncated LC_MAIN command', {
            code: ERROR_CODES.E_INVALID_MACHO,
            format: 'macho',
            offset: pos,
          });
        }
        lcMain = {
          entryoff: view.getBigUint64(pos + 8, le),
          stacksize: view.getBigUint64(pos + 16, le),
        };
        break;
      }

      case MACHO_CONSTANTS.LC_UNIXTHREAD: {
        if (cmdsize >= 16) {
          const flavor = view.getUint32(pos + 8, le);
          const count = view.getUint32(pos + 12, le);
          const stateOff = pos + 16;
          let pc = null;
          if (flavor === 6 && stateOff + 264 <= pos + cmdsize) {
            // ARM_THREAD_STATE64: X0..X28 (29), FP (29), LR (30), SP (31), PC (32) -> offset 32*8 = 256
            pc = view.getBigUint64(stateOff + 256, le);
          } else if (flavor === 4 && stateOff + 136 <= pos + cmdsize) {
            // x86_THREAD_STATE64: RIP at index 16 -> offset 128
            pc = view.getBigUint64(stateOff + 128, le);
          }
          unixThread = { flavor, count, pc };
        }
        break;
      }

      case MACHO_CONSTANTS.LC_ENCRYPTION_INFO:
      case MACHO_CONSTANTS.LC_ENCRYPTION_INFO_64: {
        if (cmdsize < 20) {
          throw new FormatError('Truncated LC_ENCRYPTION_INFO command', {
            code: ERROR_CODES.E_INVALID_MACHO,
            format: 'macho',
            offset: pos,
          });
        }
        const cryptoff = view.getUint32(pos + 8, le);
        const cryptsize = view.getUint32(pos + 12, le);
        const cryptid = view.getUint32(pos + 16, le);
        const encRec = { cmd, cryptoff, cryptsize, cryptid };
        // Sticky FairPlay guard: NEVER let a subsequent cryptid===0 overwrite an earlier cryptid!==0!
        if (cryptid !== 0) {
          hasEncryptedSegment = true;
          if (!encryptionInfo || encryptionInfo.cryptid === 0) {
            encryptionInfo = encRec;
          }
        } else if (!encryptionInfo) {
          encryptionInfo = encRec;
        }
        // Edge Case #20: FairPlay DRM rejection
        if (cryptid !== 0 && !allowEncrypted) {
          throw new FormatError(
            `Mach-O binary is encrypted with FairPlay DRM (cryptid=${cryptid})`,
            {
              code: ERROR_CODES.E_ENCRYPTED_BINARY,
              format: 'macho',
              offset: pos,
              details: { cryptid, cryptoff, cryptsize },
            }
          );
        }
        break;
      }

      case MACHO_CONSTANTS.LC_SYMTAB: {
        if (cmdsize >= 24) {
          symtabCmd = {
            symoff: view.getUint32(pos + 8, le),
            nsyms: view.getUint32(pos + 12, le),
            stroff: view.getUint32(pos + 16, le),
            strsize: view.getUint32(pos + 20, le),
          };
        }
        break;
      }

      case MACHO_CONSTANTS.LC_DYSYMTAB: {
        if (cmdsize >= 80) {
          dysymtabCmd = {
            ilocalsym: view.getUint32(pos + 8, le),
            nlocalsym: view.getUint32(pos + 12, le),
            iextdefsym: view.getUint32(pos + 16, le),
            nextdefsym: view.getUint32(pos + 20, le),
            iundefsym: view.getUint32(pos + 24, le),
            nundefsym: view.getUint32(pos + 28, le),
            indirectsymoff: view.getUint32(pos + 56, le),
            nindirectsyms: view.getUint32(pos + 60, le),
          };
        }
        break;
      }

      case MACHO_CONSTANTS.LC_LOAD_DYLIB:
      case MACHO_CONSTANTS.LC_LOAD_WEAK_DYLIB:
      case MACHO_CONSTANTS.LC_REEXPORT_DYLIB:
      case MACHO_CONSTANTS.LC_LOAD_UPWARD_DYLIB:
      case MACHO_CONSTANTS.LC_ID_DYLIB: {
        if (cmdsize >= 24) {
          const nameOffset = view.getUint32(pos + 8, le);
          const timestamp = view.getUint32(pos + 12, le);
          const currentVersion = view.getUint32(pos + 16, le);
          const compatVersion = view.getUint32(pos + 20, le);
          const name =
            nameOffset >= 24 && nameOffset < cmdsize
              ? readCString(bytes, pos + nameOffset, pos + cmdsize)
              : '';
          const entry = {
            cmd,
            name,
            timestamp,
            currentVersion: decodePackedVersion(currentVersion),
            compatVersion: decodePackedVersion(compatVersion),
            weak: cmd === MACHO_CONSTANTS.LC_LOAD_WEAK_DYLIB,
            reexport: cmd === MACHO_CONSTANTS.LC_REEXPORT_DYLIB,
          };
          if (cmd === MACHO_CONSTANTS.LC_ID_DYLIB) {
            idDylib = entry;
          } else {
            dylibs.push(entry);
          }
        }
        break;
      }

      case MACHO_CONSTANTS.LC_RPATH: {
        if (cmdsize >= 12) {
          const pathOffset = view.getUint32(pos + 8, le);
          if (pathOffset >= 12 && pathOffset < cmdsize) {
            rpaths.push(readCString(bytes, pos + pathOffset, pos + cmdsize));
          }
        }
        break;
      }

      case MACHO_CONSTANTS.LC_UUID: {
        if (cmdsize >= 24) {
          const hex = [];
          for (let b = 0; b < 16; b++) {
            hex.push(bytes[pos + 8 + b].toString(16).padStart(2, '0'));
          }
          uuid = `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10, 16).join('')}`.toUpperCase();
        }
        break;
      }

      case MACHO_CONSTANTS.LC_BUILD_VERSION: {
        if (cmdsize >= 24) {
          const platformId = view.getUint32(pos + 8, le);
          const minos = view.getUint32(pos + 12, le);
          const sdk = view.getUint32(pos + 16, le);
          const ntools = view.getUint32(pos + 20, le);
          buildVersion = {
            platformId,
            platform: PLATFORM_NAMES[platformId] ?? `platform_${platformId}`,
            minos: decodePackedVersion(minos),
            sdk: decodePackedVersion(sdk),
            ntools,
          };
        }
        break;
      }

      case MACHO_CONSTANTS.LC_VERSION_MIN_MACOSX:
      case MACHO_CONSTANTS.LC_VERSION_MIN_IPHONEOS:
      case MACHO_CONSTANTS.LC_VERSION_MIN_TVOS:
      case MACHO_CONSTANTS.LC_VERSION_MIN_WATCHOS: {
        if (cmdsize >= 16) {
          const platform =
            cmd === MACHO_CONSTANTS.LC_VERSION_MIN_MACOSX
              ? 'macos'
              : cmd === MACHO_CONSTANTS.LC_VERSION_MIN_IPHONEOS
                ? 'ios'
                : cmd === MACHO_CONSTANTS.LC_VERSION_MIN_TVOS
                  ? 'tvos'
                  : 'watchos';
          versionMin = {
            platform,
            version: decodePackedVersion(view.getUint32(pos + 8, le)),
            sdk: decodePackedVersion(view.getUint32(pos + 12, le)),
          };
          if (!buildVersion) {
            buildVersion = {
              platformId: platform === 'macos' ? 1 : platform === 'ios' ? 2 : 0,
              platform,
              minos: versionMin.version,
              sdk: versionMin.sdk,
              ntools: 0,
            };
          }
        }
        break;
      }

      case MACHO_CONSTANTS.LC_DYLD_INFO:
      case MACHO_CONSTANTS.LC_DYLD_INFO_ONLY: {
        if (cmdsize >= 48) {
          dyldInfoCmd = {
            rebaseOff: view.getUint32(pos + 8, le),
            rebaseSize: view.getUint32(pos + 12, le),
            bindOff: view.getUint32(pos + 16, le),
            bindSize: view.getUint32(pos + 20, le),
            weakBindOff: view.getUint32(pos + 24, le),
            weakBindSize: view.getUint32(pos + 28, le),
            lazyBindOff: view.getUint32(pos + 32, le),
            lazyBindSize: view.getUint32(pos + 36, le),
            exportOff: view.getUint32(pos + 40, le),
            exportSize: view.getUint32(pos + 44, le),
          };
        }
        break;
      }

      case MACHO_CONSTANTS.LC_DYLD_CHAINED_FIXUPS: {
        if (cmdsize >= 16) {
          chainedFixupsCmd = {
            dataoff: view.getUint32(pos + 8, le),
            datasize: view.getUint32(pos + 12, le),
          };
        }
        break;
      }

      case MACHO_CONSTANTS.LC_DYLD_EXPORTS_TRIE: {
        if (cmdsize >= 16) {
          exportsTrieCmd = {
            dataoff: view.getUint32(pos + 8, le),
            datasize: view.getUint32(pos + 12, le),
          };
        }
        break;
      }

      case MACHO_CONSTANTS.LC_CODE_SIGNATURE: {
        if (cmdsize >= 16) {
          codeSignatureCmd = {
            dataoff: view.getUint32(pos + 8, le),
            datasize: view.getUint32(pos + 12, le),
          };
        }
        break;
      }

      default:
        break;
    }

    pos += cmdsize;
  }

  // Parse symbol table (`LC_SYMTAB`)
  const symbols = [];
  const symbolsByName = new Map();
  if (symtabCmd && symtabCmd.nsyms > 0) {
    const symEnd = symtabCmd.symoff + symtabCmd.nsyms * 16;
    const strEnd = Math.min(bytes.byteLength, symtabCmd.stroff + symtabCmd.strsize);
    if (symEnd <= bytes.byteLength && symtabCmd.stroff <= bytes.byteLength) {
      for (let i = 0; i < symtabCmd.nsyms; i++) {
        const sOff = symtabCmd.symoff + i * 16;
        const nStrx = view.getUint32(sOff, le);
        const nType = bytes[sOff + 4];
        const nSect = bytes[sOff + 5];
        const nDesc = view.getUint16(sOff + 6, le);
        const nValue = view.getBigUint64(sOff + 8, le);
        const name =
          nStrx < symtabCmd.strsize
            ? readCString(bytes, symtabCmd.stroff + nStrx, strEnd)
            : '';
        const isStab = (nType & 0xe0) !== 0;
        const sym = {
          index: i,
          name,
          type: nType,
          sect: nSect,
          desc: nDesc,
          value: nValue,
          isStab,
          isExternal: !isStab && (nType & 0x01) !== 0,
          isUndefined: !isStab && (nType & 0x0e) === 0x00,
          libOrdinal: (nDesc >>> 8) & 0xff,
        };
        symbols.push(sym);
        if (name && !isStab) {
          symbolsByName.set(name, sym);
        }
      }
    }
  }

  // Parse indirect symbol table (`LC_DYSYMTAB`)
  let indirectSymtab = new Uint32Array(0);
  if (dysymtabCmd && dysymtabCmd.nindirectsyms > 0) {
    const indEnd = dysymtabCmd.indirectsymoff + dysymtabCmd.nindirectsyms * 4;
    if (indEnd <= bytes.byteLength) {
      indirectSymtab = new Uint32Array(dysymtabCmd.nindirectsyms);
      for (let i = 0; i < dysymtabCmd.nindirectsyms; i++) {
        indirectSymtab[i] = view.getUint32(dysymtabCmd.indirectsymoff + i * 4, le);
      }
    }
  }

  // Parse `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`
  let rebases = [];
  let binds = [];
  let weakBinds = [];
  let lazyBinds = [];
  let exports = [];
  if (dyldInfoCmd) {
    const fixupBudget = { count: 0, limit: MAX_DYLD_FIXUPS };
    rebases = parseDyldRebaseOpcodes(
      bytes,
      dyldInfoCmd.rebaseOff,
      dyldInfoCmd.rebaseSize,
      segments,
      fixupBudget
    );
    binds = parseDyldBindOpcodes(
      bytes,
      dyldInfoCmd.bindOff,
      dyldInfoCmd.bindSize,
      segments,
      false,
      fixupBudget
    );
    weakBinds = parseDyldBindOpcodes(
      bytes,
      dyldInfoCmd.weakBindOff,
      dyldInfoCmd.weakBindSize,
      segments,
      false,
      fixupBudget
    );
    lazyBinds = parseDyldBindOpcodes(
      bytes,
      dyldInfoCmd.lazyBindOff,
      dyldInfoCmd.lazyBindSize,
      segments,
      true,
      fixupBudget
    );
    exports = parseDyldExportTrie(bytes, dyldInfoCmd.exportOff, dyldInfoCmd.exportSize);
  }
  if (exportsTrieCmd && exports.length === 0) {
    exports = parseDyldExportTrie(bytes, exportsTrieCmd.dataoff, exportsTrieCmd.datasize);
  }

  // Parse `LC_DYLD_CHAINED_FIXUPS`
  let chainedFixups = null;
  if (chainedFixupsCmd) {
    chainedFixups = parseChainedFixups(bytes, chainedFixupsCmd.dataoff, chainedFixupsCmd.datasize, le);
  }

  // Parse `LC_CODE_SIGNATURE`
  let codeSignature = null;
  if (codeSignatureCmd) {
    codeSignature = parseCodeSignature(bytes, codeSignatureCmd.dataoff, codeSignatureCmd.datasize);
  }

  // Compute & validate unslid entryVA preview
  const textSeg = segments.find((s) => s.segname === '__TEXT') ?? null;
  let entryVA = null;
  if (lcMain) {
    entryVA = validateLcMainEntry(lcMain, textSeg, 0n);
  } else if (unixThread && unixThread.pc !== null) {
    entryVA = Number(unixThread.pc);
  }

  const extractSectionCStrings = (sectName) => {
    const out = [];
    const seen = new Set();
    for (const s of allSections) {
      if (!s || s.sectname !== sectName) continue;
      const startOff = Number(s.offset);
      const secSize = Number(s.size);
      if (!Number.isFinite(startOff) || !Number.isFinite(secSize) || startOff <= 0 || secSize <= 0) {
        continue;
      }
      if (startOff >= bytes.byteLength) continue;
      const endOff = Math.min(bytes.byteLength, startOff + Math.min(secSize, 1024 * 1024));
      let cursor = startOff;
      while (cursor < endOff && out.length < 4096) {
        if (bytes[cursor] === 0) {
          cursor += 1;
          continue;
        }
        let nul = cursor;
        while (nul < endOff && bytes[nul] !== 0) nul += 1;
        const str = readCString(bytes, cursor, endOff);
        if (str && !seen.has(str)) {
          seen.add(str);
          out.push(str);
        }
        cursor = nul + 1;
      }
    }
    return out;
  };
  const objcClasses = extractSectionCStrings('__objc_classname');
  const objcSelectors = extractSectionCStrings('__objc_methname');

  return {
    isFat: false,
    littleEndian: le,
    header: {
      magic: le ? magicLE : magicBE,
      cputype,
      cpusubtype,
      arch,
      filetype,
      ncmds,
      sizeofcmds,
      flags,
      reserved,
    },
    arch,
    cputype,
    cpusubtype,
    filetype,
    segments,
    sections: allSections,
    loadCommands,
    lcMain,
    unixThread,
    entryVA,
    symbols,
    symbolsByName,
    indirectSymtab,
    dylibs,
    idDylib,
    rpaths,
    uuid,
    buildVersion,
    versionMin,
    encryptionInfo,
    hasEncryptedSegment,
    rebases,
    binds,
    weakBinds,
    lazyBinds,
    exports,
    chainedFixups,
    codeSignature,
    entitlements: codeSignature?.entitlements ?? null,
    objcClasses,
    objcSelectors,
    rawBytes: bytes,
  };
}

// ============================================================================
// VMM AddressSpace Loader (Edge Cases #20, #21, #22)
// ============================================================================

function writeThunkSlotRet(buf, offset, arch) {
  if (arch === 'x86_64' || arch === 'x86') {
    buf[offset] = 0xc3; // RET
    for (let i = 1; i < APPLE_THUNK_STRIDE; i++) buf[offset + i] = 0x90; // NOP
  } else {
    // ARM64 RET (0xD65F03C0 LE) + 3x NOP (0xD503201F LE)
    const dv = new DataView(buf.buffer, buf.byteOffset + offset, APPLE_THUNK_STRIDE);
    dv.setUint32(0, 0xd65f03c0, true);
    dv.setUint32(4, 0xd503201f, true);
    dv.setUint32(8, 0xd503201f, true);
    dv.setUint32(12, 0xd503201f, true);
  }
}

export function loadMachOIntoAddressSpace(
  parsed,
  addressSpace,
  {
    slide = 0,
    resolveSymbol = null,
    stackSize = 0x40000,
    thunkBase = APPLE_THUNK_BASE,
    thunkSize = 0x10000,
    stackBase = APPLE_STACK_BASE,
  } = {}
) {
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.segments)) {
    throw new FormatError('Invalid parsed Mach-O object passed to loadMachOIntoAddressSpace', {
      code: ERROR_CODES.E_INVALID_MACHO,
      format: 'macho',
    });
  }
  if (!addressSpace || typeof addressSpace.mmap !== 'function') {
    throw new FormatError('loadMachOIntoAddressSpace requires a valid M1 AddressSpace', {
      code: ERROR_CODES.EINVAL,
      format: 'macho',
    });
  }

  // Edge Case #20: Never load an encrypted FairPlay binary into memory even if parsed with allowEncrypted!
  if (
    parsed.hasEncryptedSegment === true ||
    (parsed.encryptionInfo && parsed.encryptionInfo.cryptid !== 0)
  ) {
    throw new FormatError(
      `Refusing to load encrypted Mach-O binary (FairPlay cryptid=${parsed.encryptionInfo?.cryptid ?? 1})`,
      {
        code: ERROR_CODES.E_ENCRYPTED_BINARY,
        format: 'macho',
        details: parsed.encryptionInfo ?? { hasEncryptedSegment: true },
      }
    );
  }

  const slideNum = typeof slide === 'bigint' ? Number(slide) : Number(slide || 0);
  const slideBig = BigInt(slideNum);
  const le = parsed.littleEndian !== false;
  const rawBytes = parsed.rawBytes;

  // Validate LC_MAIN entryoff & slid entryVA BEFORE mapping pages into AddressSpace
  const preTextSeg = parsed.segments.find((s) => s.segname === '__TEXT') ?? null;
  const validatedMainEntryVA = parsed.lcMain
    ? validateLcMainEntry(parsed.lcMain, preTextSeg, slideBig)
    : null;

  const mappedSegments = [];
  let textSeg = null;

  // Step 1: Reserve __PAGEZERO guard (0 bytes RAM!) and map all real segments RW
  for (const seg of parsed.segments) {
    if (seg.segname === '__TEXT') {
      textSeg = seg;
    }

    // Edge Case #21: Reserve __PAGEZERO via reserveGuard (NEVER allocate 4 GiB!)
    const isPageZero =
      seg.segname === '__PAGEZERO' ||
      (seg.vmaddr === 0n && seg.initprot === 0 && seg.filesize === 0n && seg.vmsize > 0n);

    if (isPageZero) {
      if (seg.vmsize > 0n) {
        addressSpace.reserveGuard(Number(seg.vmaddr), Number(seg.vmsize), seg.segname || '__PAGEZERO');
      }
      mappedSegments.push({
        ...seg,
        mappedBase: Number(seg.vmaddr),
        mappedSize: Number(seg.vmsize),
        isGuard: true,
      });
      continue;
    }

    if (seg.vmsize === 0n) continue;

    const targetStart = Number(seg.vmaddr) + slideNum;
    const alignedBase = alignDown(targetStart, PAGE_SIZE);
    const alignedSize = alignUp((targetStart - alignedBase) + Number(seg.vmsize), PAGE_SIZE);

    addressSpace.mmap(alignedBase, alignedSize, PROT_READ | PROT_WRITE, seg.segname || 'segment');

    if (seg.filesize > 0n && rawBytes) {
      const copyLen = Math.min(Number(seg.filesize), Number(seg.vmsize));
      const fOff = Number(seg.fileoff);
      if (copyLen > 0 && fOff + copyLen <= rawBytes.byteLength) {
        addressSpace.write(targetStart, rawBytes.subarray(fOff, fOff + copyLen));
      }
    }

    mappedSegments.push({
      ...seg,
      mappedBase: alignedBase,
      mappedSize: alignedSize,
      targetStart,
      isGuard: false,
    });
  }

  // Step 2: Allocate executable thunk table page at APPLE_THUNK_BASE
  const alignedThunkSize = alignUp(thunkSize, PAGE_SIZE);
  addressSpace.mmap(thunkBase, alignedThunkSize, PROT_READ | PROT_WRITE, 'apple-thunks');
  const thunkPageBuf = new Uint8Array(alignedThunkSize);
  const maxThunkSlots = Math.floor(alignedThunkSize / APPLE_THUNK_STRIDE);
  for (let i = 0; i < maxThunkSlots; i++) {
    writeThunkSlotRet(thunkPageBuf, i * APPLE_THUNK_STRIDE, parsed.arch);
  }
  addressSpace.write(thunkBase, thunkPageBuf);
  addressSpace.mprotect(thunkBase, alignedThunkSize, PROT_READ | PROT_EXEC);

  const exitSentinelVA = thunkBase; // Slot 0 = exit sentinel
  const thunkTable = new Map();
  const thunkBySymbol = new Map();
  let nextThunkIndex = 1;

  function allocateOrResolveSymbol(symbolName, libOrdinal = 0) {
    if (typeof resolveSymbol === 'function') {
      const externalVA = resolveSymbol(symbolName, libOrdinal);
      if (externalVA !== null && externalVA !== undefined) {
        return typeof externalVA === 'bigint' ? externalVA : BigInt(externalVA);
      }
    }
    if (thunkBySymbol.has(symbolName)) {
      return BigInt(thunkBySymbol.get(symbolName));
    }
    if (nextThunkIndex >= maxThunkSlots) {
      throw new FormatError(`Exhausted Apple thunk table slots (${maxThunkSlots})`, {
        code: ERROR_CODES.ENOMEM,
        format: 'macho',
      });
    }
    const idx = nextThunkIndex++;
    const va = thunkBase + idx * APPLE_THUNK_STRIDE;
    thunkTable.set(va, { symbol: symbolName, libOrdinal, index: idx, va });
    thunkBySymbol.set(symbolName, va);
    return BigInt(va);
  }

  // Step 3: Apply dyld rebases
  for (const rb of parsed.rebases) {
    const addr = rb.vmaddr + slideBig;
    const orig = addressSpace.readU64(addr, le);
    addressSpace.writeU64(addr, BigInt.asUintN(64, orig + slideBig), le);
  }

  // Step 4: Apply dyld binds (normal, weak, lazy)
  const boundAddresses = new Set();
  for (const bindList of [parsed.binds, parsed.weakBinds, parsed.lazyBinds]) {
    for (const b of bindList) {
      const addr = b.vmaddr + slideBig;
      const targetVA = allocateOrResolveSymbol(b.symbol, b.libOrdinal);
      addressSpace.writeU64(addr, BigInt.asUintN(64, targetVA + b.addend), le);
      boundAddresses.add(addr);
    }
  }

  // Step 5: Apply LC_DYLD_CHAINED_FIXUPS pointer chains
  if (parsed.chainedFixups) {
    const cf = parsed.chainedFixups;
    const textVmAddrBig = textSeg ? textSeg.vmaddr : 0x100000000n;

    for (const segStart of cf.segmentStarts) {
      if (!segStart) continue;
      const seg = parsed.segments[segStart.segIndex];
      if (!seg || seg.segname === '__PAGEZERO') continue;
      const ptrFormat = segStart.pointerFormat;
      const stride =
        ptrFormat === MACHO_CONSTANTS.DYLD_CHAINED_PTR_ARM64E ||
        ptrFormat === MACHO_CONSTANTS.DYLD_CHAINED_PTR_ARM64E_USERLAND ||
        ptrFormat === MACHO_CONSTANTS.DYLD_CHAINED_PTR_ARM64E_USERLAND24
          ? 8n
          : 4n;

      for (let p = 0; p < segStart.pageStarts.length; p++) {
        const pageStartOff = segStart.pageStarts[p];
        if (pageStartOff === MACHO_CONSTANTS.DYLD_CHAINED_PTR_START_NONE) continue;

        let curAddr =
          seg.vmaddr +
          slideBig +
          BigInt(p * segStart.pageSize) +
          BigInt(pageStartOff);

        let chainGuard = 0;
        while (chainGuard++ < 4096) {
          const raw = addressSpace.readU64(curAddr, le);
          const isBind = ((raw >> 63n) & 1n) === 1n;
          let nextDelta = 0n;
          let resolved = 0n;

          if (
            ptrFormat === MACHO_CONSTANTS.DYLD_CHAINED_PTR_64 ||
            ptrFormat === MACHO_CONSTANTS.DYLD_CHAINED_PTR_64_OFFSET
          ) {
            nextDelta = (raw >> 51n) & 0xfffn;
            if (isBind) {
              const ordinal = Number(raw & 0xffffffn);
              // Per Apple <mach-o/fixup-chains.h>, dyld_chained_ptr_64_bind.addend is unsigned 8-bit
              const addend = (raw >> 24n) & 0xffn;
              const imp = cf.imports[ordinal];
              if (imp) {
                const symVA = allocateOrResolveSymbol(imp.name, imp.libOrdinal);
                resolved = BigInt.asUintN(64, symVA + imp.addend + addend);
              }
            } else {
              const target = raw & 0xfffffffffn; // 36-bit target
              const high8 = (raw >> 36n) & 0xffn;
              if (ptrFormat === MACHO_CONSTANTS.DYLD_CHAINED_PTR_64_OFFSET) {
                resolved = BigInt.asUintN(64, textVmAddrBig + slideBig + target);
              } else {
                resolved = BigInt.asUintN(64, (high8 << 56n) | (target + slideBig));
              }
            }
          } else {
            // ARM64E chained pointer formats
            const auth = ((raw >> 63n) & 1n) === 1n;
            const bindBit = ((raw >> 62n) & 1n) === 1n;
            nextDelta = (raw >> 51n) & 0x7ffn;
            if (bindBit) {
              const ordMask =
                ptrFormat === MACHO_CONSTANTS.DYLD_CHAINED_PTR_ARM64E_USERLAND24
                  ? 0xffffffn
                  : 0xffffn;
              const ordinal = Number(raw & ordMask);
              const imp = cf.imports[ordinal];
              if (imp) {
                const symVA = allocateOrResolveSymbol(imp.name, imp.libOrdinal);
                resolved = BigInt.asUintN(64, symVA + imp.addend);
              }
            } else if (auth) {
              const target = raw & 0xffffffffn;
              resolved = BigInt.asUintN(64, textVmAddrBig + slideBig + target);
            } else {
              const target = raw & 0x7ffffffffffn; // 43-bit target
              if (
                ptrFormat === MACHO_CONSTANTS.DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                ptrFormat === MACHO_CONSTANTS.DYLD_CHAINED_PTR_ARM64E_USERLAND24
              ) {
                resolved = BigInt.asUintN(64, textVmAddrBig + slideBig + target);
              } else {
                resolved = BigInt.asUintN(64, target + slideBig);
              }
            }
          }

          addressSpace.writeU64(curAddr, resolved, le);
          boundAddresses.add(curAddr);

          if (nextDelta === 0n) break;
          curAddr += nextDelta * stride;
        }
      }
    }
  }

  // Step 6: Bind indirect symbol pointers (__got / __la_symbol_ptr) not already bound
  if (parsed.indirectSymtab.length > 0 && parsed.symbols.length > 0) {
    for (const sect of parsed.sections) {
      if (
        sect.type !== MACHO_CONSTANTS.S_NON_LAZY_SYMBOL_POINTERS &&
        sect.type !== MACHO_CONSTANTS.S_LAZY_SYMBOL_POINTERS
      ) {
        continue;
      }
      const entryCount = Number(sect.size / 8n);
      const startIdx = sect.reserved1;
      for (let i = 0; i < entryCount; i++) {
        const ptrVA = sect.addr + slideBig + BigInt(i * 8);
        if (boundAddresses.has(ptrVA)) continue;
        const indIdx = startIdx + i;
        if (indIdx >= parsed.indirectSymtab.length) break;
        const symIdx = parsed.indirectSymtab[indIdx];
        if (symIdx >= parsed.symbols.length) continue;
        const sym = parsed.symbols[symIdx];
        if (!sym || !sym.name) continue;
        const targetVA = allocateOrResolveSymbol(sym.name, sym.libOrdinal);
        addressSpace.writeU64(ptrVA, targetVA, le);
        boundAddresses.add(ptrVA);
      }
    }
  }

  // Step 7: Finalize segment protections via mprotect(initprot & 7)
  for (const seg of mappedSegments) {
    if (seg.isGuard) continue;
    addressSpace.mprotect(seg.mappedBase, seg.mappedSize, seg.initprot & 7);
  }

  // Step 8: Allocate 16-byte aligned stack at APPLE_STACK_BASE
  const alignedStackSize = alignUp(Math.max(stackSize, PAGE_SIZE), PAGE_SIZE);
  addressSpace.mmap(stackBase, alignedStackSize, PROT_READ | PROT_WRITE, 'apple-stack');
  const rawSp = stackBase + alignedStackSize - 0x100;
  // Safe 53-bit alignment (NEVER 32-bit bitwise ops on >32-bit addresses!)
  const initialSP = rawSp - (rawSp % 16);

  // Step 9: Compute final Entry VA (Edge Case #22: __TEXT.vmaddr + slide + entryoff)
  const textVmAddr = textSeg ? Number(textSeg.vmaddr) : 0x100000000;
  let entryVA = null;
  if (validatedMainEntryVA !== null) {
    entryVA = validatedMainEntryVA;
  } else if (parsed.unixThread && parsed.unixThread.pc !== null) {
    entryVA = Number(parsed.unixThread.pc) + slideNum;
  } else if (parsed.symbolsByName.has('_main')) {
    const mainSym = parsed.symbolsByName.get('_main');
    if (!mainSym.isUndefined) {
      entryVA = Number(mainSym.value) + slideNum;
    }
  }

  // Step 10: Expose ObjC and string sections with slid VAs
  const objcSections = {};
  for (const sect of parsed.sections) {
    if (OBJC_SECTION_NAMES.has(sect.sectname)) {
      objcSections[sect.sectname] = {
        sectname: sect.sectname,
        segname: sect.segname,
        addr: Number(sect.addr) + slideNum,
        size: Number(sect.size),
        fileOffset: sect.offset,
        flags: sect.flags,
      };
    }
  }

  // Build slid symbolsByName map
  const slidSymbolsByName = new Map();
  for (const [name, sym] of parsed.symbolsByName.entries()) {
    slidSymbolsByName.set(name, {
      ...sym,
      va: sym.isUndefined ? null : Number(sym.value) + slideNum,
    });
  }

  return {
    arch: parsed.arch,
    entryVA,
    textVmAddr,
    slide: slideNum,
    stackBase,
    stackSize: alignedStackSize,
    initialSP,
    thunkBase,
    thunkSize: alignedThunkSize,
    exitSentinelVA,
    thunkTable,
    thunkBySymbol,
    symbolsByName: slidSymbolsByName,
    objcSections,
    segments: mappedSegments,
    dylibs: parsed.dylibs,
    rpaths: parsed.rpaths,
    entitlements: parsed.entitlements,
    codeSignature: parsed.codeSignature,
    buildVersion: parsed.buildVersion,
    uuid: parsed.uuid,
  };
}
