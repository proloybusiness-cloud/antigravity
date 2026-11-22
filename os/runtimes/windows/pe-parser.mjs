/**
 * OmniOS Windows PE32 (0x10B) & PE32+ (0x20B) Binary Loader (`os/runtimes/windows/pe-parser.mjs`)
 * - Strict validation of DOS MZ, e_lfanew >= 64 & bounds, PE\0\0, COFF (NumberOfSections <= 96),
 *   Optional Header (PE32/PE32+), and clamped Data Directories (<= 16 & <= SizeOfOptionalHeader) (Edge Case #12)
 * - Section mapping copies min(SizeOfRawData, VirtualSize) & zero-fills .bss remainder (Edge Case #13)
 * - Import resolution supports both ILT (OriginalFirstThunk) and FirstThunk fallback when OFT == 0 (Edge Case #14)
 * - CERTIFICATE_TABLE (DataDir[4]) strictly treated as raw file offset, never RVA (Edge Case #15)
 * - Base relocations (ABSOLUTE=0, HIGHLOW=3, DIR64=10), Exports, and M1 VMM hardware mprotect locking
 */

import { FormatError, ERROR_CODES } from '../../common/errors.mjs';
import {
  PAGE_SIZE,
  PROT_NONE,
  PROT_READ,
  PROT_WRITE,
  PROT_EXEC,
  alignUp,
} from '../../kernel/vmm.mjs';

export const PE_CONSTANTS = Object.freeze({
  DOS_MAGIC: 0x5a4d, // 'MZ'
  PE_SIGNATURE: 0x00004550, // 'PE\0\0'
  MACHINE_I386: 0x014c,
  MACHINE_AMD64: 0x8664,
  MACHINE_ARM64: 0xaa64,
  OPT_MAGIC_PE32: 0x010b,
  OPT_MAGIC_PE32_PLUS: 0x020b,
  SUBSYSTEM_UNKNOWN: 0,
  SUBSYSTEM_NATIVE: 1,
  SUBSYSTEM_WINDOWS_GUI: 2,
  SUBSYSTEM_WINDOWS_CUI: 3,
  CHAR_RELOCS_STRIPPED: 0x0001,
  CHAR_EXECUTABLE_IMAGE: 0x0002,
  CHAR_LARGE_ADDRESS_AWARE: 0x0020,
  CHAR_32BIT_MACHINE: 0x0100,
  CHAR_DLL: 0x2000,
  DLL_CHAR_DYNAMIC_BASE: 0x0040,
  DLL_CHAR_NX_COMPAT: 0x0100,
  SCN_CNT_CODE: 0x00000020,
  SCN_CNT_INITIALIZED_DATA: 0x00000040,
  SCN_CNT_UNINITIALIZED_DATA: 0x00000080,
  SCN_MEM_DISCARDABLE: 0x02000000,
  SCN_MEM_EXECUTE: 0x20000000,
  SCN_MEM_READ: 0x40000000,
  SCN_MEM_WRITE: 0x80000000,
  MAX_SECTIONS: 96,
  MAX_DATA_DIRS: 16,
  DIR_EXPORT_TABLE: 0,
  DIR_IMPORT_TABLE: 1,
  DIR_RESOURCE_TABLE: 2,
  DIR_EXCEPTION_TABLE: 3,
  DIR_CERTIFICATE_TABLE: 4,
  DIR_BASE_RELOCATION_TABLE: 5,
  DIR_DEBUG_DIRECTORY: 6,
  DIR_ARCHITECTURE: 7,
  DIR_GLOBAL_PTR: 8,
  DIR_TLS_TABLE: 9,
  DIR_LOAD_CONFIG_TABLE: 10,
  DIR_BOUND_IMPORT: 11,
  DIR_IAT: 12,
  DIR_DELAY_IMPORT_DESCRIPTOR: 13,
  DIR_CLR_RUNTIME_HEADER: 14,
  DIR_RESERVED: 15,
  RELOC_ABSOLUTE: 0,
  RELOC_HIGHLOW: 3,
  RELOC_DIR64: 10,
  DATA_DIR_NAMES: Object.freeze([
    'EXPORT_TABLE',
    'IMPORT_TABLE',
    'RESOURCE_TABLE',
    'EXCEPTION_TABLE',
    'CERTIFICATE_TABLE',
    'BASE_RELOCATION_TABLE',
    'DEBUG_DIRECTORY',
    'ARCHITECTURE',
    'GLOBAL_PTR',
    'TLS_TABLE',
    'LOAD_CONFIG_TABLE',
    'BOUND_IMPORT',
    'IAT',
    'DELAY_IMPORT_DESCRIPTOR',
    'CLR_RUNTIME_HEADER',
    'RESERVED',
  ]),
});

const SUBSYSTEM_NAMES = Object.freeze({
  0: 'UNKNOWN',
  1: 'NATIVE',
  2: 'WINDOWS_GUI',
  3: 'WINDOWS_CUI',
});

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
  throw new FormatError('PE input must be a Uint8Array, Buffer, or ArrayBuffer', {
    code: ERROR_CODES.E_INVALID_PE,
    format: 'windows-pe',
  });
}

function peErr(message, offset = null, details = null) {
  return new FormatError(message, {
    code: ERROR_CODES.E_INVALID_PE,
    format: 'windows-pe',
    offset,
    details,
  });
}

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const MAX_PE_UNIQUE_STRING_BYTES = 8 * 1024 * 1024; // 8 MiB hard cap on unique decoded PE strings
const MAX_EXPORT_ENTRIES = 65536;
const MAX_RELOC_BLOCKS = 4096;
const MAX_TOTAL_RELOCATIONS = 65536;

function createStringContext(bytes) {
  return {
    cache: new Map(),
    decodedBytes: 0,
    maxUniqueBytes: Math.min(MAX_PE_UNIQUE_STRING_BYTES, Math.max(bytes.byteLength * 2, 65536)),
  };
}

function readAsciiZ(bytes, offset, strCtx = null, maxLen = 1024) {
  if (offset === null || offset < 0 || offset >= bytes.byteLength) return null;
  if (strCtx && strCtx.cache.has(offset)) {
    return strCtx.cache.get(offset);
  }
  const limit = Math.min(bytes.byteLength, offset + maxLen);
  const slice = bytes.subarray(offset, limit);
  const nulRel = slice.indexOf(0);
  if (nulRel === -1 && limit >= bytes.byteLength) return null;
  const byteLen = nulRel === -1 ? slice.byteLength : nulRel;
  if (strCtx) {
    strCtx.decodedBytes += byteLen + 1;
    if (strCtx.decodedBytes > strCtx.maxUniqueBytes) {
      throw peErr(
        `PE decoded string budget exceeded (${strCtx.decodedBytes} > ${strCtx.maxUniqueBytes} bytes)`,
        offset
      );
    }
  }
  const s = byteLen === 0 ? '' : UTF8_DECODER.decode(slice.subarray(0, byteLen));
  if (strCtx) {
    strCtx.cache.set(offset, s);
  }
  return s;
}

function sectionPermsFromCharacteristics(characteristics) {
  let perms = PROT_NONE;
  if ((characteristics & PE_CONSTANTS.SCN_MEM_READ) !== 0) perms |= PROT_READ;
  if ((characteristics & PE_CONSTANTS.SCN_MEM_WRITE) !== 0) perms |= PROT_WRITE;
  if ((characteristics & PE_CONSTANTS.SCN_MEM_EXECUTE) !== 0) perms |= PROT_EXEC;
  // Standard Windows executable sections always allow at least read if executable
  if ((perms & PROT_EXEC) !== 0) perms |= PROT_READ;
  if (perms === PROT_NONE) perms = PROT_READ;
  return perms;
}

/**
 * Translate a Relative Virtual Address (RVA) to a raw PE file offset.
 * Returns `null` if the RVA falls in uninitialized (.bss) padding or outside all sections/headers.
 * NEVER call this on DataDirectory[4] (CERTIFICATE_TABLE), which stores a raw file offset directly!
 */
export function rvaToFileOffset(rva, sections, sizeOfHeaders = 0) {
  const numRva = typeof rva === 'bigint' ? Number(rva) : rva;
  if (!Number.isSafeInteger(numRva) || numRva < 0) return null;
  if (numRva < sizeOfHeaders) {
    return numRva;
  }
  for (let i = 0; i < sections.length; i++) {
    const sec = sections[i];
    const span = Math.max(sec.virtualSize, sec.sizeOfRawData);
    if (numRva >= sec.virtualAddress && numRva < sec.virtualAddress + span) {
      const delta = numRva - sec.virtualAddress;
      if (delta >= sec.sizeOfRawData) {
        return null; // Inside zero-filled .bss tail, not backed by file bytes
      }
      return sec.pointerToRawData + delta;
    }
  }
  return null;
}

function parseExports(bytes, view, dir, sections, sizeOfHeaders, strCtx) {
  if (!dir || dir.virtualAddress === 0 || dir.size === 0) return { dllName: null, ordinalBase: 1, entries: [] };
  const dirOff = rvaToFileOffset(dir.virtualAddress, sections, sizeOfHeaders);
  if (dirOff === null || dirOff + 40 > bytes.byteLength) {
    return { dllName: null, ordinalBase: 1, entries: [] };
  }

  const nameRva = view.getUint32(dirOff + 12, true);
  const ordinalBase = view.getUint32(dirOff + 16, true);
  const numberOfFunctions = view.getUint32(dirOff + 20, true);
  const numberOfNames = view.getUint32(dirOff + 24, true);
  const addrOfFuncsRva = view.getUint32(dirOff + 28, true);
  const addrOfNamesRva = view.getUint32(dirOff + 32, true);
  const addrOfOrdinalsRva = view.getUint32(dirOff + 36, true);

  const maxFuncsByFile = Math.min(MAX_EXPORT_ENTRIES, Math.floor(bytes.byteLength / 4));
  const maxNamesByFile = Math.min(MAX_EXPORT_ENTRIES, Math.floor(bytes.byteLength / 6));
  if (
    numberOfFunctions > MAX_EXPORT_ENTRIES ||
    numberOfNames > MAX_EXPORT_ENTRIES ||
    numberOfFunctions > maxFuncsByFile ||
    numberOfNames > maxNamesByFile
  ) {
    throw peErr('Export table function/name count exceeds safe bounds', dirOff);
  }

  const dllNameOff = rvaToFileOffset(nameRva, sections, sizeOfHeaders);
  const dllName = dllNameOff !== null ? readAsciiZ(bytes, dllNameOff, strCtx) : null;

  const funcsOff = rvaToFileOffset(addrOfFuncsRva, sections, sizeOfHeaders);
  const namesOff = rvaToFileOffset(addrOfNamesRva, sections, sizeOfHeaders);
  const ordsOff = rvaToFileOffset(addrOfOrdinalsRva, sections, sizeOfHeaders);
  if (funcsOff === null) return { dllName, ordinalBase, entries: [] };

  if (numberOfFunctions > 0 && funcsOff + numberOfFunctions * 4 > bytes.byteLength) {
    throw peErr('Export AddressOfFunctions table exceeds file bounds', dirOff);
  }
  if (numberOfNames > 0) {
    if (
      namesOff === null ||
      ordsOff === null ||
      namesOff + numberOfNames * 4 > bytes.byteLength ||
      ordsOff + numberOfNames * 2 > bytes.byteLength
    ) {
      throw peErr('Export AddressOfNames/Ordinals table exceeds file bounds', dirOff);
    }
  }

  const maxRefStringBytes = Math.min(
    MAX_PE_UNIQUE_STRING_BYTES,
    Math.max(bytes.byteLength * 4, 262144)
  );
  let totalRefStringBytes = 0;

  const namesByFuncIdx = new Map();
  const seenNameOffsets = new Set();
  if (namesOff !== null && ordsOff !== null && numberOfNames > 0) {
    for (let i = 0; i < numberOfNames; i++) {
      const fnNameRva = view.getUint32(namesOff + i * 4, true);
      const ordIdx = view.getUint16(ordsOff + i * 2, true);
      const fnNameOff = rvaToFileOffset(fnNameRva, sections, sizeOfHeaders);
      if (fnNameOff !== null) {
        if (seenNameOffsets.has(fnNameOff)) {
          throw peErr(
            `Aliased duplicate PE export name offset 0x${fnNameOff.toString(16)}`,
            namesOff + i * 4
          );
        }
        seenNameOffsets.add(fnNameOff);
        const fnName = readAsciiZ(bytes, fnNameOff, strCtx);
        if (fnName !== null) {
          totalRefStringBytes += fnName.length + 1;
          if (totalRefStringBytes > maxRefStringBytes) {
            throw peErr('PE export name table amplification exceeds safe bounds', namesOff + i * 4);
          }
          if (!namesByFuncIdx.has(ordIdx)) {
            namesByFuncIdx.set(ordIdx, fnName);
          }
        }
      }
    }
  }

  const entries = [];
  const forwarderRefCounts = new Map();
  for (let i = 0; i < numberOfFunctions; i++) {
    const fnRva = view.getUint32(funcsOff + i * 4, true);
    if (fnRva === 0) continue;
    const isForwarder = fnRva >= dir.virtualAddress && fnRva < dir.virtualAddress + dir.size;
    let forwardedTo = null;
    if (isForwarder) {
      const fwdOff = rvaToFileOffset(fnRva, sections, sizeOfHeaders);
      if (fwdOff !== null) {
        const refCount = (forwarderRefCounts.get(fwdOff) ?? 0) + 1;
        if (refCount > 64) {
          throw peErr(
            `Aliased PE export forwarder offset 0x${fwdOff.toString(16)} exceeds safe bounds`,
            funcsOff + i * 4
          );
        }
        forwarderRefCounts.set(fwdOff, refCount);
        forwardedTo = readAsciiZ(bytes, fwdOff, strCtx);
        if (forwardedTo !== null) {
          totalRefStringBytes += forwardedTo.length + 1;
          if (totalRefStringBytes > maxRefStringBytes) {
            throw peErr('PE export forwarder amplification exceeds safe bounds', funcsOff + i * 4);
          }
        }
      }
    }
    entries.push({
      name: namesByFuncIdx.get(i) ?? null,
      ordinal: ordinalBase + i,
      rva: fnRva,
      forwardedTo,
    });
  }

  return { dllName, ordinalBase, entries };
}

const MAX_IMPORT_DESCRIPTORS = 4096;
const MAX_TOTAL_IMPORTS = 65536;

function parseImports(bytes, view, dir, sections, sizeOfHeaders, is64, strCtx) {
  if (!dir || dir.virtualAddress === 0 || dir.size === 0) return [];
  const dirOff = rvaToFileOffset(dir.virtualAddress, sections, sizeOfHeaders);
  if (dirOff === null) return [];

  const ptrSize = is64 ? 8 : 4;
  const ordinalFlag = is64 ? 0x8000000000000000n : 0x80000000n;
  const descriptors = [];
  const dirMaxDescriptors = Math.floor(dir.size / 20);
  const maxDescriptors = Math.min(MAX_IMPORT_DESCRIPTORS, dirMaxDescriptors);
  const maxPhysicalImports = Math.min(MAX_TOTAL_IMPORTS, Math.floor(bytes.byteLength / ptrSize));
  const maxRefStringBytes = Math.min(
    MAX_PE_UNIQUE_STRING_BYTES,
    Math.max(bytes.byteLength * 4, 262144)
  );
  let totalImports = 0;
  let totalRefStringBytes = 0;

  const seenLookupOffsets = new Set();
  const seenOrigFirstThunks = new Set();
  const seenFirstThunks = new Set();
  const seenThunkBuckets = new Set();

  for (let idx = 0; idx < maxDescriptors; idx++) {
    const off = dirOff + idx * 20;
    if (off + 20 > bytes.byteLength) break;

    const originalFirstThunk = view.getUint32(off, true);
    const timeDateStamp = view.getUint32(off + 4, true);
    const forwarderChain = view.getUint32(off + 8, true);
    const nameRva = view.getUint32(off + 12, true);
    const firstThunk = view.getUint32(off + 16, true);

    if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) {
      break;
    }

    if (originalFirstThunk !== 0) {
      if (seenOrigFirstThunks.has(originalFirstThunk)) {
        throw peErr(
          `Aliased PE import OriginalFirstThunk RVA 0x${originalFirstThunk.toString(16)}`,
          off
        );
      }
      seenOrigFirstThunks.add(originalFirstThunk);
    }
    if (firstThunk !== 0) {
      if (seenFirstThunks.has(firstThunk)) {
        throw peErr(`Aliased PE import FirstThunk RVA 0x${firstThunk.toString(16)}`, off);
      }
      seenFirstThunks.add(firstThunk);
    }

    const nameOff = rvaToFileOffset(nameRva, sections, sizeOfHeaders);
    const dll = nameOff !== null ? readAsciiZ(bytes, nameOff, strCtx) : null;
    if (!dll) {
      throw peErr(`Invalid import DLL name RVA 0x${nameRva.toString(16)}`, off);
    }
    totalRefStringBytes += dll.length + 1;
    if (totalRefStringBytes > maxRefStringBytes) {
      throw peErr('PE import metadata string amplification exceeds safe bounds', off);
    }

    // CRITICAL Edge Case #14: Fallback to FirstThunk (IAT) when OriginalFirstThunk === 0!
    const lookupRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
    const lookupOff = rvaToFileOffset(lookupRva, sections, sizeOfHeaders);
    const usedFallbackIat = originalFirstThunk === 0;
    const entries = [];

    if (lookupOff !== null) {
      if (seenLookupOffsets.has(lookupOff)) {
        throw peErr(
          `Aliased PE import thunk lookup table at file offset 0x${lookupOff.toString(16)}`,
          off
        );
      }
      seenLookupOffsets.add(lookupOff);

      for (let t = 0; t <= maxPhysicalImports; t++) {
        const thunkFileOff = lookupOff + t * ptrSize;
        if (thunkFileOff + ptrSize > bytes.byteLength) break;
        const rawThunk = is64
          ? view.getBigUint64(thunkFileOff, true)
          : BigInt(view.getUint32(thunkFileOff, true));
        if (rawThunk === 0n) break;

        const thunkBucket = Math.floor(thunkFileOff / ptrSize);
        if (seenThunkBuckets.has(thunkBucket)) {
          throw peErr(
            `Overlapping or aliased PE import thunk entry at file offset 0x${thunkFileOff.toString(16)}`,
            thunkFileOff
          );
        }
        seenThunkBuckets.add(thunkBucket);

        totalImports += 1;
        if (totalImports > maxPhysicalImports) {
          throw peErr(
            `PE import entry count exceeds maximum (${maxPhysicalImports})`,
            thunkFileOff
          );
        }

        const iatRva = firstThunk + t * ptrSize;
        if ((rawThunk & ordinalFlag) !== 0n) {
          entries.push({
            byOrdinal: true,
            ordinal: Number(rawThunk & 0xffffn),
            hint: 0,
            name: null,
            iatRva,
          });
        } else {
          const hintNameRva = Number(rawThunk & 0x7fffffffn);
          const hintNameOff = rvaToFileOffset(hintNameRva, sections, sizeOfHeaders);
          if (hintNameOff === null || hintNameOff + 2 > bytes.byteLength) {
            throw peErr(`Invalid IMAGE_IMPORT_BY_NAME RVA 0x${hintNameRva.toString(16)}`, thunkFileOff);
          }
          const hint = view.getUint16(hintNameOff, true);
          const fnName = readAsciiZ(bytes, hintNameOff + 2, strCtx);
          if (!fnName) {
            throw peErr(`Unterminated import symbol name at offset 0x${(hintNameOff + 2).toString(16)}`, hintNameOff);
          }
          totalRefStringBytes += fnName.length + 1;
          if (totalRefStringBytes > maxRefStringBytes) {
            throw peErr('PE import symbol string amplification exceeds safe bounds', thunkFileOff);
          }
          entries.push({
            byOrdinal: false,
            ordinal: null,
            hint,
            name: fnName,
            iatRva,
          });
        }
      }
    }

    descriptors.push({
      dll,
      dllLower: dll.toLowerCase(),
      originalFirstThunk,
      firstThunk,
      timeDateStamp,
      forwarderChain,
      usedFallbackIat,
      entries,
    });
  }

  if (descriptors.length === MAX_IMPORT_DESCRIPTORS && dirMaxDescriptors > MAX_IMPORT_DESCRIPTORS) {
    const nextOff = dirOff + MAX_IMPORT_DESCRIPTORS * 20;
    if (nextOff + 20 <= bytes.byteLength) {
      const oft = view.getUint32(nextOff, true);
      const nrva = view.getUint32(nextOff + 12, true);
      const ft = view.getUint32(nextOff + 16, true);
      if (oft !== 0 || nrva !== 0 || ft !== 0) {
        throw peErr(`PE import descriptor count exceeds maximum (${MAX_IMPORT_DESCRIPTORS})`, nextOff);
      }
    }
  }

  return descriptors;
}

function parseBaseRelocations(bytes, view, dir, sections, sizeOfHeaders) {
  if (!dir || dir.virtualAddress === 0 || dir.size === 0) return [];
  const startOff = rvaToFileOffset(dir.virtualAddress, sections, sizeOfHeaders);
  if (startOff === null) return [];
  const endOff = Math.min(bytes.byteLength, startOff + dir.size);
  const blocks = [];
  let pos = startOff;
  let totalRelocs = 0;

  while (pos + 8 <= endOff) {
    const pageRva = view.getUint32(pos, true);
    const blockSize = view.getUint32(pos + 4, true);
    if (blockSize === 0) break;
    if (blockSize < 8 || pos + blockSize > endOff) {
      throw peErr(`Malformed base relocation block (size=${blockSize})`, pos);
    }
    if (blocks.length >= MAX_RELOC_BLOCKS) {
      throw peErr(`PE base relocation block count exceeds maximum (${MAX_RELOC_BLOCKS})`, pos);
    }
    const entryCount = Math.floor((blockSize - 8) / 2);
    totalRelocs += entryCount;
    if (totalRelocs > MAX_TOTAL_RELOCATIONS) {
      throw peErr(
        `PE base relocation entry count exceeds maximum (${MAX_TOTAL_RELOCATIONS})`,
        pos
      );
    }
    const entries = [];
    for (let i = 0; i < entryCount; i++) {
      const word = view.getUint16(pos + 8 + i * 2, true);
      const type = (word >>> 12) & 0x0f;
      const offset = word & 0x0fff;
      entries.push({
        type,
        offset,
        rva: pageRva + offset,
      });
    }
    blocks.push({ pageRva, blockSize, entries });
    pos += blockSize;
  }

  return blocks;
}

/**
 * Parse a Windows PE32 (`0x10B`) or PE32+ (`0x20B`) binary buffer.
 */
export function parsePe(buffer) {
  const bytes = toBytes(buffer);
  if (bytes.byteLength < 64) {
    throw peErr(`PE buffer too small (${bytes.byteLength} bytes, minimum 64)`, 0);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // 1. MS-DOS Header (Edge Case #12)
  const dosMagic = view.getUint16(0, true);
  if (dosMagic !== PE_CONSTANTS.DOS_MAGIC) {
    throw peErr(`Invalid DOS magic 0x${dosMagic.toString(16)} (expected 0x5A4D 'MZ')`, 0);
  }
  const eLfanew = view.getUint32(0x3c, true);
  if (eLfanew < 64 || eLfanew + 24 > bytes.byteLength) {
    throw peErr(`Invalid e_lfanew offset 0x${eLfanew.toString(16)} (fileSize=${bytes.byteLength})`, 0x3c);
  }

  // 2. PE\0\0 Signature
  const peSig = view.getUint32(eLfanew, true);
  if (peSig !== PE_CONSTANTS.PE_SIGNATURE) {
    throw peErr(`Invalid PE signature 0x${peSig.toString(16)} at 0x${eLfanew.toString(16)}`, eLfanew);
  }

  // 3. COFF File Header (20 bytes)
  const coffOff = eLfanew + 4;
  const machine = view.getUint16(coffOff, true);
  const numberOfSections = view.getUint16(coffOff + 2, true);
  const timeDateStamp = view.getUint32(coffOff + 4, true);
  const pointerToSymbolTable = view.getUint32(coffOff + 8, true);
  const numberOfSymbols = view.getUint32(coffOff + 12, true);
  const sizeOfOptionalHeader = view.getUint16(coffOff + 16, true);
  const characteristics = view.getUint16(coffOff + 18, true);

  // Edge Case #12: Windows loader enforces NumberOfSections <= 96
  if (numberOfSections > PE_CONSTANTS.MAX_SECTIONS) {
    throw peErr(
      `PE NumberOfSections (${numberOfSections}) exceeds maximum (${PE_CONSTANTS.MAX_SECTIONS})`,
      coffOff + 2
    );
  }

  const optOff = coffOff + 20;
  if (sizeOfOptionalHeader < 2 || optOff + sizeOfOptionalHeader > bytes.byteLength) {
    throw peErr(
      `PE Optional Header out of bounds (optOff=0x${optOff.toString(16)}, size=${sizeOfOptionalHeader})`,
      optOff
    );
  }

  const sectionTableOff = optOff + sizeOfOptionalHeader;
  if (sectionTableOff + numberOfSections * 40 > bytes.byteLength) {
    throw peErr('PE Section Table exceeds file length', sectionTableOff);
  }

  // 4. Optional Header (PE32 vs PE32+)
  const optMagic = view.getUint16(optOff, true);
  let is64;
  let fixedOptSize;
  if (optMagic === PE_CONSTANTS.OPT_MAGIC_PE32) {
    is64 = false;
    fixedOptSize = 96;
  } else if (optMagic === PE_CONSTANTS.OPT_MAGIC_PE32_PLUS) {
    is64 = true;
    fixedOptSize = 112;
  } else {
    throw peErr(`Unsupported PE Optional Header magic: 0x${optMagic.toString(16)}`, optOff);
  }

  if (sizeOfOptionalHeader < fixedOptSize) {
    throw peErr(
      `PE Optional Header size (${sizeOfOptionalHeader}) smaller than required minimum (${fixedOptSize})`,
      optOff
    );
  }

  const majorLinkerVersion = view.getUint8(optOff + 2);
  const minorLinkerVersion = view.getUint8(optOff + 3);
  const sizeOfCode = view.getUint32(optOff + 4, true);
  const sizeOfInitializedData = view.getUint32(optOff + 8, true);
  const sizeOfUninitializedData = view.getUint32(optOff + 12, true);
  const addressOfEntryPoint = view.getUint32(optOff + 16, true);
  const baseOfCode = view.getUint32(optOff + 20, true);
  const baseOfData = is64 ? null : view.getUint32(optOff + 24, true);
  const imageBase = is64
    ? view.getBigUint64(optOff + 24, true)
    : BigInt(view.getUint32(optOff + 28, true));

  const sectionAlignment = view.getUint32(optOff + 32, true);
  const fileAlignment = view.getUint32(optOff + 36, true);
  const majorOsVersion = view.getUint16(optOff + 40, true);
  const minorOsVersion = view.getUint16(optOff + 42, true);
  const majorImageVersion = view.getUint16(optOff + 44, true);
  const minorImageVersion = view.getUint16(optOff + 46, true);
  const majorSubsystemVersion = view.getUint16(optOff + 48, true);
  const minorSubsystemVersion = view.getUint16(optOff + 50, true);
  const sizeOfImage = view.getUint32(optOff + 56, true);
  const sizeOfHeaders = view.getUint32(optOff + 60, true);
  const checkSum = view.getUint32(optOff + 64, true);
  const subsystem = view.getUint16(optOff + 68, true);
  const dllCharacteristics = view.getUint16(optOff + 70, true);

  let sizeOfStackReserve;
  let sizeOfStackCommit;
  let sizeOfHeapReserve;
  let sizeOfHeapCommit;
  let loaderFlags;
  let rawNumberOfRvaAndSizes;

  if (is64) {
    sizeOfStackReserve = view.getBigUint64(optOff + 72, true);
    sizeOfStackCommit = view.getBigUint64(optOff + 80, true);
    sizeOfHeapReserve = view.getBigUint64(optOff + 88, true);
    sizeOfHeapCommit = view.getBigUint64(optOff + 96, true);
    loaderFlags = view.getUint32(optOff + 104, true);
    rawNumberOfRvaAndSizes = view.getUint32(optOff + 108, true);
  } else {
    sizeOfStackReserve = BigInt(view.getUint32(optOff + 72, true));
    sizeOfStackCommit = BigInt(view.getUint32(optOff + 76, true));
    sizeOfHeapReserve = BigInt(view.getUint32(optOff + 80, true));
    sizeOfHeapCommit = BigInt(view.getUint32(optOff + 84, true));
    loaderFlags = view.getUint32(optOff + 88, true);
    rawNumberOfRvaAndSizes = view.getUint32(optOff + 92, true);
  }

  if (sectionAlignment === 0 || sizeOfImage === 0) {
    throw peErr('PE SectionAlignment and SizeOfImage must be non-zero', optOff + 32);
  }
  if (sizeOfHeaders > bytes.byteLength) {
    throw peErr(
      `PE SizeOfHeaders (${sizeOfHeaders}) exceeds file length (${bytes.byteLength})`,
      optOff + 60
    );
  }

  // Edge Case #12: Clamp NumberOfRvaAndSizes to <= 16 AND within SizeOfOptionalHeader!
  const maxDirsByHeader = Math.floor((sizeOfOptionalHeader - fixedOptSize) / 8);
  const numberOfRvaAndSizes = Math.min(rawNumberOfRvaAndSizes, PE_CONSTANTS.MAX_DATA_DIRS, maxDirsByHeader);

  const dataDirectories = [];
  for (let i = 0; i < PE_CONSTANTS.MAX_DATA_DIRS; i++) {
    const isCertTable = i === PE_CONSTANTS.DIR_CERTIFICATE_TABLE;
    let va = 0;
    let sz = 0;
    if (i < numberOfRvaAndSizes) {
      const dOff = optOff + fixedOptSize + i * 8;
      va = view.getUint32(dOff, true);
      sz = view.getUint32(dOff + 4, true);
    }
    // CRITICAL Edge Case #15: Index 4 (CERTIFICATE_TABLE) stores a RAW FILE OFFSET, NOT an RVA!
    dataDirectories.push({
      index: i,
      name: PE_CONSTANTS.DATA_DIR_NAMES[i],
      virtualAddress: va,
      size: sz,
      isFileOffset: isCertTable,
      fileOffset: isCertTable ? va : null,
    });
  }

  const certDir = dataDirectories[PE_CONSTANTS.DIR_CERTIFICATE_TABLE];
  const certificateTable = {
    present: certDir.fileOffset !== 0 && certDir.size !== 0,
    fileOffset: certDir.fileOffset,
    size: certDir.size,
    validBounds:
      certDir.fileOffset === 0 || certDir.size === 0
        ? true
        : certDir.fileOffset + certDir.size <= bytes.byteLength,
  };

  // 5. Section Table (40 bytes each)
  const sections = [];
  for (let i = 0; i < numberOfSections; i++) {
    const sOff = sectionTableOff + i * 40;
    let secName = '';
    for (let j = 0; j < 8; j++) {
      const ch = bytes[sOff + j];
      if (ch === 0) break;
      secName += String.fromCharCode(ch);
    }
    const virtualSize = view.getUint32(sOff + 8, true);
    const virtualAddress = view.getUint32(sOff + 12, true);
    const sizeOfRawData = view.getUint32(sOff + 16, true);
    const pointerToRawData = view.getUint32(sOff + 20, true);
    const secChars = view.getUint32(sOff + 36, true);

    if (sizeOfRawData > 0 && pointerToRawData + sizeOfRawData > bytes.byteLength) {
      throw peErr(
        `Section "${secName}" raw data [0x${pointerToRawData.toString(16)}..+0x${sizeOfRawData.toString(16)}] exceeds file length (${bytes.byteLength})`,
        sOff
      );
    }

    sections.push({
      index: i,
      name: secName,
      virtualSize,
      virtualAddress,
      sizeOfRawData,
      pointerToRawData,
      characteristics: secChars,
      perms: sectionPermsFromCharacteristics(secChars),
    });
  }

  // 6. Parse Exports, Imports, and Base Relocations
  const strCtx = createStringContext(bytes);
  const exports = parseExports(
    bytes,
    view,
    dataDirectories[PE_CONSTANTS.DIR_EXPORT_TABLE],
    sections,
    sizeOfHeaders,
    strCtx
  );
  const imports = parseImports(
    bytes,
    view,
    dataDirectories[PE_CONSTANTS.DIR_IMPORT_TABLE],
    sections,
    sizeOfHeaders,
    is64,
    strCtx
  );
  const relocations = parseBaseRelocations(
    bytes,
    view,
    dataDirectories[PE_CONSTANTS.DIR_BASE_RELOCATION_TABLE],
    sections,
    sizeOfHeaders
  );

  let arch = is64 ? 'x86_64' : 'x86';
  if (machine === PE_CONSTANTS.MACHINE_AMD64) arch = 'x86_64';
  else if (machine === PE_CONSTANTS.MACHINE_I386) arch = 'x86';
  else if (machine === PE_CONSTANTS.MACHINE_ARM64) arch = 'arm64';

  const result = {
    peType: is64 ? 'PE32+' : 'PE32',
    is64,
    arch,
    isDll: (characteristics & PE_CONSTANTS.CHAR_DLL) !== 0,
    dosHeader: {
      eMagic: dosMagic,
      eLfanew,
    },
    coffHeader: {
      machine,
      numberOfSections,
      timeDateStamp,
      pointerToSymbolTable,
      numberOfSymbols,
      sizeOfOptionalHeader,
      characteristics,
    },
    optionalHeader: {
      magic: optMagic,
      majorLinkerVersion,
      minorLinkerVersion,
      sizeOfCode,
      sizeOfInitializedData,
      sizeOfUninitializedData,
      addressOfEntryPoint,
      baseOfCode,
      baseOfData,
      imageBase,
      sectionAlignment,
      fileAlignment,
      osVersion: `${majorOsVersion}.${minorOsVersion}`,
      imageVersion: `${majorImageVersion}.${minorImageVersion}`,
      subsystemVersion: `${majorSubsystemVersion}.${minorSubsystemVersion}`,
      sizeOfImage,
      sizeOfHeaders,
      checkSum,
      subsystem,
      subsystemName: SUBSYSTEM_NAMES[subsystem] ?? `SUBSYSTEM_${subsystem}`,
      dllCharacteristics,
      sizeOfStackReserve,
      sizeOfStackCommit,
      sizeOfHeapReserve,
      sizeOfHeapCommit,
      loaderFlags,
      numberOfRvaAndSizes,
      rawNumberOfRvaAndSizes,
    },
    dataDirectories,
    certificateTable,
    sections,
    exports,
    imports,
    relocations,
  };

  // Attach non-enumerable raw bytes slice so mapPeIntoAddressSpace can copy directly without extra args
  Object.defineProperty(result, '_rawBytes', {
    value: bytes,
    enumerable: false,
    writable: false,
    configurable: false,
  });

  return result;
}

/**
 * Map a parsed PE32 / PE32+ image into an M1 `AddressSpace`:
 * 1. Reserves 64 KiB null-pointer guard (`0..0x10000`)
 * 2. Maps image temporarily RW, copies headers & `min(SizeOfRawData, VirtualSize)` per section (zeroing `.bss`)
 * 3. Applies base relocations (`ABSOLUTE=0`, `HIGHLOW=3`, `DIR64=10`) if `loadBase !== imageBase`
 * 4. Resolves & patches IAT entries via `resolveImport`
 * 5. Locks final hardware R/W/X section permissions via `addressSpace.mprotect()`
 */
export function mapPeIntoAddressSpace(pe, addressSpace, options = {}) {
  if (!pe || !pe.optionalHeader || !Array.isArray(pe.sections)) {
    throw peErr('mapPeIntoAddressSpace requires a parsed PE object');
  }
  if (!addressSpace || typeof addressSpace.mmap !== 'function') {
    throw peErr('mapPeIntoAddressSpace requires a valid M1 AddressSpace');
  }

  const rawBytes = options.rawBytes ? toBytes(options.rawBytes) : pe._rawBytes;
  if (!rawBytes) {
    throw peErr('mapPeIntoAddressSpace requires raw PE bytes (missing pe._rawBytes / options.rawBytes)');
  }

  const reserveNullGuard = options.reserveNullGuard !== false;
  if (reserveNullGuard) {
    try {
      addressSpace.reserveGuard(0, 0x10000, 'WIN_NULL_GUARD');
    } catch (err) {
      // Allow reuse if null guard was already reserved on this AddressSpace
      if (err?.code !== ERROR_CODES.EEXIST) {
        throw err;
      }
    }
  }

  const preferredBase = pe.optionalHeader.imageBase;
  const loadBase = options.loadBase !== undefined && options.loadBase !== null
    ? BigInt(options.loadBase)
    : preferredBase;
  const alignedImageSize = alignUp(pe.optionalHeader.sizeOfImage, PAGE_SIZE);
  const ptrSize = pe.is64 ? 8 : 4;

  // Pre-validate all section, base relocation, and IAT RVAs before mapping or writing VMM pages
  for (const sec of pe.sections) {
    const virtSpan = sec.virtualSize > 0 ? sec.virtualSize : sec.sizeOfRawData;
    if (
      !Number.isSafeInteger(sec.virtualAddress) ||
      sec.virtualAddress < 0 ||
      sec.virtualAddress + virtSpan > alignedImageSize
    ) {
      throw peErr(
        `Section "${sec.name}" virtual range [0x${sec.virtualAddress.toString(16)}..+0x${virtSpan.toString(16)}] exceeds SizeOfImage (0x${alignedImageSize.toString(16)})`
      );
    }
  }
  for (const block of pe.relocations) {
    for (const entry of block.entries) {
      if (entry.type === PE_CONSTANTS.RELOC_ABSOLUTE) {
        continue;
      }
      const patchSize =
        entry.type === PE_CONSTANTS.RELOC_HIGHLOW
          ? 4
          : entry.type === PE_CONSTANTS.RELOC_DIR64
            ? 8
            : 0;
      if (patchSize === 0) continue;
      if (
        !Number.isSafeInteger(entry.rva) ||
        entry.rva < 0 ||
        entry.rva + patchSize > alignedImageSize
      ) {
        throw peErr(
          `Base relocation RVA 0x${Number(entry.rva).toString(16)} (size ${patchSize}) exceeds SizeOfImage (0x${alignedImageSize.toString(16)})`
        );
      }
    }
  }
  for (const desc of pe.imports) {
    for (const imp of desc.entries) {
      if (
        !Number.isSafeInteger(imp.iatRva) ||
        imp.iatRva < 0 ||
        imp.iatRva + ptrSize > alignedImageSize
      ) {
        throw peErr(
          `Import IAT RVA 0x${Number(imp.iatRva).toString(16)} (size ${ptrSize}) exceeds SizeOfImage (0x${alignedImageSize.toString(16)})`
        );
      }
    }
  }

  // Map whole image temporarily RW for loading, relocations, and IAT patching
  const mappedBaseNum = addressSpace.mmap(loadBase, alignedImageSize, PROT_READ | PROT_WRITE, 'pe:image');
  const mappedBase = BigInt(mappedBaseNum);

  // 1. Copy PE Headers
  const hdrCopyLen = Math.min(pe.optionalHeader.sizeOfHeaders, rawBytes.byteLength, alignedImageSize);
  if (hdrCopyLen > 0) {
    addressSpace.write(mappedBase, rawBytes.subarray(0, hdrCopyLen));
  }

  // 2. Copy Sections (Edge Case #13: copy min(SizeOfRawData, VirtualSize) and zero-fill .bss remainder!)
  const sectionMappings = [];
  for (const sec of pe.sections) {
    const virtSpan = sec.virtualSize > 0 ? sec.virtualSize : sec.sizeOfRawData;
    const copyLen = Math.min(sec.sizeOfRawData, virtSpan);
    const secVa = mappedBase + BigInt(sec.virtualAddress);

    if (copyLen > 0) {
      addressSpace.write(secVa, rawBytes.subarray(sec.pointerToRawData, sec.pointerToRawData + copyLen));
    }
    // Explicitly zero-fill .bss tail (VirtualSize > SizeOfRawData)
    if (virtSpan > copyLen) {
      const zeroTail = virtSpan - copyLen;
      const chunk = new Uint8Array(Math.min(zeroTail, 65536));
      let remaining = zeroTail;
      let cursor = secVa + BigInt(copyLen);
      while (remaining > 0) {
        const n = Math.min(remaining, chunk.byteLength);
        addressSpace.write(cursor, n === chunk.byteLength ? chunk : chunk.subarray(0, n));
        cursor += BigInt(n);
        remaining -= n;
      }
    }

    sectionMappings.push({
      name: sec.name,
      va: secVa,
      virtualAddress: sec.virtualAddress,
      virtualSize: virtSpan,
      copiedBytes: copyLen,
      bssZeroedBytes: Math.max(0, virtSpan - copyLen),
      perms: sec.perms,
    });
  }

  // 3. Apply Base Relocations if loadBase !== imageBase (all RVAs already bounds-checked above)
  let relocationsApplied = 0;
  const delta = mappedBase - preferredBase;
  if (delta !== 0n && pe.relocations.length > 0) {
    const tmp = new Uint8Array(8);
    const tmpDv = new DataView(tmp.buffer);
    for (const block of pe.relocations) {
      for (const entry of block.entries) {
        if (entry.type === PE_CONSTANTS.RELOC_ABSOLUTE) {
          continue;
        }
        const targetVa = mappedBase + BigInt(entry.rva);
        if (entry.type === PE_CONSTANTS.RELOC_HIGHLOW) {
          const cur = addressSpace.read(targetVa, 4);
          const curVal = new DataView(cur.buffer, cur.byteOffset, 4).getUint32(0, true);
          const nextVal = Number((BigInt(curVal) + delta) & 0xffffffffn);
          tmpDv.setUint32(0, nextVal, true);
          addressSpace.write(targetVa, tmp.subarray(0, 4));
          relocationsApplied += 1;
        } else if (entry.type === PE_CONSTANTS.RELOC_DIR64) {
          const cur = addressSpace.read(targetVa, 8);
          const curVal = new DataView(cur.buffer, cur.byteOffset, 8).getBigUint64(0, true);
          const nextVal = BigInt.asUintN(64, curVal + delta);
          tmpDv.setBigUint64(0, nextVal, true);
          addressSpace.write(targetVa, tmp);
          relocationsApplied += 1;
        }
      }
    }
  }

  // 4. Patch Import Address Table (IAT) using resolveImport callback (all iatRvas bounds-checked above)
  const patchedImports = [];
  const slotBuf = new Uint8Array(8);
  const slotView = new DataView(slotBuf.buffer);

  if (typeof options.resolveImport === 'function') {
    for (const desc of pe.imports) {
      for (const imp of desc.entries) {
        const iatVa = mappedBase + BigInt(imp.iatRva);
        const resolved = options.resolveImport({
          dll: desc.dll,
          dllLower: desc.dllLower,
          name: imp.name,
          ordinal: imp.ordinal,
          byOrdinal: imp.byOrdinal,
          hint: imp.hint,
          iatRva: imp.iatRva,
          iatVa,
        });
        const resolvedVa = typeof resolved === 'bigint' ? resolved : BigInt(resolved ?? 0);
        if (pe.is64) {
          slotView.setBigUint64(0, resolvedVa, true);
          addressSpace.write(iatVa, slotBuf);
        } else {
          slotView.setUint32(0, Number(resolvedVa & 0xffffffffn), true);
          addressSpace.write(iatVa, slotBuf.subarray(0, 4));
        }
        patchedImports.push({
          dll: desc.dll,
          name: imp.name,
          ordinal: imp.ordinal,
          iatVa,
          thunkVa: resolvedVa,
        });
      }
    }
  }

  // 5. Lock final hardware R/W/X page permissions via mprotect()
  const totalPages = alignedImageSize / PAGE_SIZE;
  const pagePerms = new Uint8Array(totalPages);
  // Default headers pages to PROT_READ
  const headerPages = Math.max(1, Math.ceil(pe.optionalHeader.sizeOfHeaders / PAGE_SIZE));
  for (let p = 0; p < Math.min(headerPages, totalPages); p++) {
    pagePerms[p] = PROT_READ;
  }
  // Apply section permissions (OR together if two sections ever share a 4KB page)
  for (const sm of sectionMappings) {
    if (sm.virtualSize === 0) continue;
    const firstPage = Math.floor(sm.virtualAddress / PAGE_SIZE);
    const lastPage = Math.floor((sm.virtualAddress + sm.virtualSize - 1) / PAGE_SIZE);
    for (let p = firstPage; p <= lastPage && p < totalPages; p++) {
      pagePerms[p] |= sm.perms;
    }
  }
  // Ensure any untouched pages between sections stay PROT_READ
  for (let p = 0; p < totalPages; p++) {
    if (pagePerms[p] === 0) pagePerms[p] = PROT_READ;
  }

  // Coalesce contiguous runs with identical permissions into clean mprotect() calls
  let runStart = 0;
  while (runStart < totalPages) {
    const perm = pagePerms[runStart];
    let runEnd = runStart + 1;
    while (runEnd < totalPages && pagePerms[runEnd] === perm) {
      runEnd += 1;
    }
    addressSpace.mprotect(
      mappedBase + BigInt(runStart * PAGE_SIZE),
      (runEnd - runStart) * PAGE_SIZE,
      perm
    );
    runStart = runEnd;
  }

  return {
    loadBase: mappedBase,
    preferredBase,
    imageSize: alignedImageSize,
    entryVa: mappedBase + BigInt(pe.optionalHeader.addressOfEntryPoint),
    relocationsApplied,
    patchedImports,
    sectionMappings,
  };
}
