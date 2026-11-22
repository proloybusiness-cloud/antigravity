/**
 * OmniOS Pure Byte-Level Package & Binary Format Auto-Detector (`os/pkg/format-detector.mjs`)
 * Detects all 12 supported cross-platform package/binary formats plus `unknown` purely from bytes:
 *  - `android-apk`, `windows-pe`, `windows-msix`, `windows-msi` (OLE CFBF), `windows-bat`
 *  - `ios-ipa`, `macos-app`, `macos-macho` (64/32/Fat with strict Java `.class` guard on `0xCAFEBABE`),
 *    `macos-dmg` (512B BE `koly` at EOF-512), `macos-pkg` (XAR `0x78617221`)
 *  - `universal-uapp`, `universal-wasm` (`\0asm` v1), `unknown`
 * Fault-isolated: never crashes on truncated, corrupt, empty, or random bytes.
 */

import { types } from 'node:util';
import { listZipEntries } from './zip.mjs';
import { ERROR_CODES } from '../common/errors.mjs';

const AB_BYTE_LENGTH = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const AB_DETACHED = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'detached')?.get ?? null;
const TYPED_ARRAY_CTOR = Object.getPrototypeOf(Uint8Array);
const TYPED_ARRAY_PROTO = TYPED_ARRAY_CTOR.prototype;
const TA_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'buffer').get;
const TA_BYTE_OFFSET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteOffset').get;
const TA_BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteLength').get;
const DV_BUFFER = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
const DV_BYTE_OFFSET = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get;
const DV_BYTE_LENGTH = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;

function extractGenuineBytes(val) {
  if (val === null || val === undefined || typeof val !== 'object') {
    return { ok: false, detached: false };
  }
  try {
    if (types.isTypedArray(val) && !types.isProxy(val)) {
      const buf = TA_BUFFER.call(val);
      if (types.isArrayBuffer(buf) && AB_DETACHED && AB_DETACHED.call(buf)) {
        return { ok: false, detached: true };
      }
      const byteOffset = TA_BYTE_OFFSET.call(val);
      const byteLength = TA_BYTE_LENGTH.call(val);
      return { ok: true, bytes: new Uint8Array(buf, byteOffset, byteLength) };
    }
    if (types.isDataView(val) && !types.isProxy(val)) {
      const buf = DV_BUFFER.call(val);
      if (types.isArrayBuffer(buf) && AB_DETACHED && AB_DETACHED.call(buf)) {
        return { ok: false, detached: true };
      }
      const byteOffset = DV_BYTE_OFFSET.call(val);
      const byteLength = DV_BYTE_LENGTH.call(val);
      return { ok: true, bytes: new Uint8Array(buf, byteOffset, byteLength) };
    }
    if (types.isArrayBuffer(val) && !types.isProxy(val)) {
      if (AB_DETACHED && AB_DETACHED.call(val)) {
        return { ok: false, detached: true };
      }
      const byteLength = AB_BYTE_LENGTH.call(val);
      return { ok: true, bytes: new Uint8Array(val, 0, byteLength) };
    }
  } catch {
    return { ok: false, detached: false };
  }
  return { ok: false, detached: false };
}

export const PACKAGE_FORMATS = Object.freeze({
  ANDROID_APK: 'android-apk',
  WINDOWS_PE: 'windows-pe',
  WINDOWS_MSIX: 'windows-msix',
  WINDOWS_MSI: 'windows-msi',
  WINDOWS_BAT: 'windows-bat',
  IOS_IPA: 'ios-ipa',
  MACOS_APP: 'macos-app',
  MACOS_MACHO: 'macos-macho',
  MACOS_DMG: 'macos-dmg',
  MACOS_PKG: 'macos-pkg',
  UNIVERSAL_UAPP: 'universal-uapp',
  UNIVERSAL_WASM: 'universal-wasm',
  UNKNOWN: 'unknown',
});

// Valid Apple Mach-O CPU types for Fat binary guard against Java .class files
const VALID_MACHO_CPUTYPES = new Set([
  0x00000007, // CPU_TYPE_X86
  0x01000007, // CPU_TYPE_X86_64
  0x0000000c, // CPU_TYPE_ARM
  0x0100000c, // CPU_TYPE_ARM64
  0x0200000c, // CPU_TYPE_ARM64_32
  0x00000012, // CPU_TYPE_POWERPC
  0x01000012, // CPU_TYPE_POWERPC64
]);

const MACHO_CPUTYPE_NAMES = Object.freeze({
  0x00000007: 'x86',
  0x01000007: 'x86_64',
  0x0000000c: 'arm',
  0x0100000c: 'arm64',
  0x0200000c: 'arm64_32',
  0x00000012: 'ppc',
  0x01000012: 'ppc64',
});

const PE_MACHINE_ARCH = Object.freeze({
  0x014c: 'x86',
  0x8664: 'x86_64',
  0xaa64: 'arm64',
  0x01c4: 'arm',
});

const OLE_CFBF_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const UTF8_DECODER_FATAL = new TextDecoder('utf-8', { fatal: true });
const TEXT_ENCODER = new TextEncoder();

const BATCH_STRONG_PATTERNS = [
  /^[ \t]*@echo[ \t]+(?:off|on)\b/im,
  /^[ \t]*echo[ \t]+(?:off|on)\b/im,
  /^[ \t]*(?:setlocal|endlocal)\b/im,
  /^[ \t]*set[ \t]+\/a\b/im,
  /^[ \t]*goto[ \t]+:?\w+/im,
  /%ERRORLEVEL%/i,
  /^[ \t]*rem[ \t]+/im,
];

function toBytesSafe(input) {
  if (input === null || input === undefined) return null;
  if (typeof input === 'string') {
    return TEXT_ENCODER.encode(input);
  }
  const bin = extractGenuineBytes(input);
  if (bin.ok) {
    return bin.bytes;
  }
  return null;
}

function bytesToMagicHex(bytes, maxLen = 16) {
  const n = Math.min(maxLen, bytes.byteLength);
  let out = '';
  for (let i = 0; i < n; i++) {
    out += bytes[i].toString(16).padStart(2, '0').toUpperCase();
  }
  return out;
}

function matchesPrefix(bytes, pattern) {
  if (bytes.byteLength < pattern.length) return false;
  for (let i = 0; i < pattern.length; i++) {
    if (bytes[i] !== pattern[i]) return false;
  }
  return true;
}

function detectWasm(bytes, view) {
  if (bytes.byteLength < 8) return null;
  if (bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) return null;
  const version = view.getUint32(4, true);
  if (version !== 1) return null;
  return {
    format: PACKAGE_FORMATS.UNIVERSAL_WASM,
    platform: 'universal',
    details: { version, arch: 'wasm' },
  };
}

function detectMsi(bytes) {
  if (!matchesPrefix(bytes, OLE_CFBF_MAGIC)) return null;
  return {
    format: PACKAGE_FORMATS.WINDOWS_MSI,
    platform: 'windows',
    details: { container: 'ole-cfbf' },
  };
}

function detectPe(bytes, view) {
  if (bytes.byteLength < 64) return null;
  if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) return null; // 'MZ'

  const peOffset = view.getUint32(0x3c, true);
  if (peOffset < 64 || peOffset + 24 > bytes.byteLength) return null;
  if (
    bytes[peOffset] !== 0x50 ||
    bytes[peOffset + 1] !== 0x45 ||
    bytes[peOffset + 2] !== 0x00 ||
    bytes[peOffset + 3] !== 0x00
  ) {
    return null;
  }

  const machine = view.getUint16(peOffset + 4, true);
  const numberOfSections = view.getUint16(peOffset + 6, true);
  const sizeOfOptionalHeader = view.getUint16(peOffset + 20, true);
  const characteristics = view.getUint16(peOffset + 22, true);

  // Spec Invariant #4: NumberOfSections <= 96
  if (numberOfSections > 96) return null;
  if (sizeOfOptionalHeader === 1) return null;

  let peType = 'COFF';
  let optMagic = null;
  if (sizeOfOptionalHeader >= 2) {
    // Reject PE if declared Optional Header is truncated before its 2-byte magic
    if (peOffset + 24 + 2 > bytes.byteLength) return null;
    optMagic = view.getUint16(peOffset + 24, true);
    if (optMagic === 0x010b) peType = 'PE32';
    else if (optMagic === 0x020b) peType = 'PE32+';
    else return null; // Invalid PE optional header magic
  }

  const isDll = (characteristics & 0x2000) !== 0;
  return {
    format: PACKAGE_FORMATS.WINDOWS_PE,
    platform: 'windows',
    details: {
      peType,
      optMagic,
      peOffset,
      machine,
      arch: PE_MACHINE_ARCH[machine] ?? (peType === 'PE32+' ? 'x86_64' : 'x86'),
      numberOfSections,
      characteristics,
      isDll,
    },
  };
}

function detectMacosPkg(bytes, view) {
  if (bytes.byteLength < 28) return null;
  // XAR magic 'xar!' = 0x78617221 (big-endian)
  if (view.getUint32(0, false) !== 0x78617221) return null;
  const headerSize = view.getUint16(4, false);
  const version = view.getUint16(6, false);
  if (headerSize < 28 || headerSize > bytes.byteLength) return null;
  return {
    format: PACKAGE_FORMATS.MACOS_PKG,
    platform: 'macos',
    details: { container: 'xar', headerSize, version },
  };
}

function detectMachO(bytes, view) {
  if (bytes.byteLength < 28) return null;
  const magicLE = view.getUint32(0, true);
  const magicBE = view.getUint32(0, false);

  // 1. 64-bit Mach-O (LE: 0xFEEDFACF or BE: 0xFEEDFACF)
  if (bytes.byteLength >= 32 && (magicLE === 0xfeedfacf || magicBE === 0xfeedfacf)) {
    const le = magicLE === 0xfeedfacf;
    const cputype = view.getUint32(4, le);
    const cpusubtype = view.getUint32(8, le);
    const filetype = view.getUint32(12, le);
    const ncmds = view.getUint32(16, le);
    if (filetype >= 1 && filetype <= 12) {
      return {
        format: PACKAGE_FORMATS.MACOS_MACHO,
        platform: 'macos',
        details: {
          kind: 'macho64',
          littleEndian: le,
          cputype,
          cpusubtype,
          arch: MACHO_CPUTYPE_NAMES[cputype] ?? 'arm64',
          filetype,
          ncmds,
        },
      };
    }
  }

  // 2. 32-bit Mach-O (LE: 0xFEEDFACE or BE: 0xFEEDFACE)
  if (magicLE === 0xfeedface || magicBE === 0xfeedface) {
    const le = magicLE === 0xfeedface;
    const cputype = view.getUint32(4, le);
    const cpusubtype = view.getUint32(8, le);
    const filetype = view.getUint32(12, le);
    const ncmds = view.getUint32(16, le);
    if (filetype >= 1 && filetype <= 12) {
      return {
        format: PACKAGE_FORMATS.MACOS_MACHO,
        platform: 'macos',
        details: {
          kind: 'macho32',
          littleEndian: le,
          cputype,
          cpusubtype,
          arch: MACHO_CPUTYPE_NAMES[cputype] ?? 'x86',
          filetype,
          ncmds,
        },
      };
    }
  }

  // 3. Universal Fat Mach-O (0xCAFEBABE = 32-bit fat, 0xCAFEBABF = 64-bit fat)
  // CRITICAL JAVA .class GUARD:
  // Java .class starts with 0xCAFEBABE followed by minor_version(u16) + major_version(u16 >= 45),
  // making u32be(4) >= 45 (or huge if minor_version != 0).
  // Require 1 <= nfat_arch <= 32, full slice table in bounds, AND every slice cputype in VALID_MACHO_CPUTYPES!
  if (magicBE === 0xcafebabe || magicBE === 0xcafebabf) {
    const isFat64 = magicBE === 0xcafebabf;
    const entrySize = isFat64 ? 32 : 20;
    const nfatArch = view.getUint32(4, false);
    if (nfatArch < 1 || nfatArch > 32) return null;
    if (8 + nfatArch * entrySize > bytes.byteLength) return null;

    const slices = [];
    for (let i = 0; i < nfatArch; i++) {
      const base = 8 + i * entrySize;
      const cputype = view.getUint32(base, false);
      const cpusubtype = view.getUint32(base + 4, false);
      if (!VALID_MACHO_CPUTYPES.has(cputype)) {
        return null;
      }
      slices.push({
        cputype,
        cpusubtype,
        arch: MACHO_CPUTYPE_NAMES[cputype] ?? 'unknown',
      });
    }

    return {
      format: PACKAGE_FORMATS.MACOS_MACHO,
      platform: 'macos',
      details: {
        kind: isFat64 ? 'fat64' : 'fat32',
        nfatArch,
        slices,
        arch: slices[0]?.arch ?? 'arm64',
      },
    };
  }

  return null;
}

function detectMacosDmg(bytes, view) {
  if (bytes.byteLength < 512) return null;
  const tail = bytes.byteLength - 512;
  // UDIF trailer magic 'koly' = 0x6B6F6C79 (big-endian) and HeaderSize == 512 at offset +8
  if (view.getUint32(tail, false) !== 0x6b6f6c79) return null;
  const version = view.getUint32(tail + 4, false);
  const headerSize = view.getUint32(tail + 8, false);
  if (headerSize !== 512) return null;

  // Apple 512-byte big-endian UDIF koly trailer: XMLOffset at +0xD8, XMLLength at +0xE0
  const xmlOffset = Number(view.getBigUint64(tail + 0xd8, false));
  const xmlLength = Number(view.getBigUint64(tail + 0xe0, false));

  return {
    format: PACKAGE_FORMATS.MACOS_DMG,
    platform: 'macos',
    details: {
      container: 'udif-koly',
      version,
      headerSize,
      xmlOffset,
      xmlLength,
    },
  };
}

function detectZipContainer(bytes, opts) {
  if (bytes.byteLength < 22) return { match: null, zipError: null };

  let zipLimits;
  let strictZip = false;
  if (opts && typeof opts === 'object') {
    try {
      zipLimits = opts.zipLimits;
      strictZip = opts.strictZip === true;
    } catch {
      zipLimits = undefined;
      strictZip = false;
    }
  }

  // Quick check: starts with PK signature or contains EOCD near tail
  let index;
  try {
    index = listZipEntries(bytes, zipLimits);
  } catch (err) {
    const code = err?.code;
    const isSecurityErr =
      code === ERROR_CODES.E_PATH_TRAVERSAL ||
      code === ERROR_CODES.E_ARCHIVE_BOMB ||
      code === ERROR_CODES.E_ENCRYPTED_BINARY;
    if (strictZip && isSecurityErr) {
      throw err;
    }
    return {
      match: null,
      zipError: isSecurityErr ? { errorCode: code, errorMessage: err.message } : null,
    };
  }

  const names = index.entryList.map((e) => e.name);
  const lowerSet = new Set(names.map((n) => n.toLowerCase()));

  // 7a. Android APK
  const hasAndroidManifest = names.includes('AndroidManifest.xml');
  const hasDex = names.some((n) => /^classes\d*\.dex$/.test(n));
  if (hasAndroidManifest || hasDex) {
    return {
      match: {
        format: PACKAGE_FORMATS.ANDROID_APK,
        platform: 'android',
        details: {
          entryCount: names.length,
          hasAndroidManifest,
          hasDex,
          hasApkSigningBlock: index.hasApkSigningBlock,
          isZip64: index.isZip64,
        },
      },
      zipError: null,
    };
  }

  // 7b. Windows MSIX / APPX
  if (lowerSet.has('appxmanifest.xml')) {
    return {
      match: {
        format: PACKAGE_FORMATS.WINDOWS_MSIX,
        platform: 'windows',
        details: {
          entryCount: names.length,
          hasBlockMap: lowerSet.has('appxblockmap.xml'),
          isZip64: index.isZip64,
        },
      },
      zipError: null,
    };
  }

  // 7c. iOS IPA
  const ipaPlist = names.find((n) => /^Payload\/[^/]+\.app\/Info\.plist$/i.test(n));
  if (ipaPlist) {
    return {
      match: {
        format: PACKAGE_FORMATS.IOS_IPA,
        platform: 'ios',
        details: {
          entryCount: names.length,
          infoPlistPath: ipaPlist,
          isZip64: index.isZip64,
        },
      },
      zipError: null,
    };
  }

  // 7d. macOS .app bundle ZIP
  const macosPlist = names.find((n) => /^(?:[^/]+\/)?[^/]+\.app\/Contents\/Info\.plist$/i.test(n));
  if (macosPlist) {
    return {
      match: {
        format: PACKAGE_FORMATS.MACOS_APP,
        platform: 'macos',
        details: {
          entryCount: names.length,
          infoPlistPath: macosPlist,
          isZip64: index.isZip64,
        },
      },
      zipError: null,
    };
  }

  // 7e. OmniOS Universal .uapp
  if (names.includes('omnios.manifest.json')) {
    return {
      match: {
        format: PACKAGE_FORMATS.UNIVERSAL_UAPP,
        platform: 'universal',
        details: {
          entryCount: names.length,
          hasWasm: names.some((n) => n.toLowerCase().endsWith('.wasm')),
          isZip64: index.isZip64,
        },
      },
      zipError: null,
    };
  }

  return {
    match: null,
    zipError: { container: 'zip', entryCount: names.length },
  };
}

function detectWindowsBat(bytes, filenameHint) {
  if (bytes.byteLength === 0 || bytes.byteLength > 2 * 1024 * 1024) return null;

  // Reject any NUL bytes or non-whitespace binary control chars
  let sampleLen = Math.min(bytes.byteLength, 8192);
  if (bytes.byteLength > sampleLen) {
    // Avoid splitting a multi-byte UTF-8 character straddling the 8,192-byte boundary
    // while still fatally validating all bytes (including malformed/invalid sequences across the cut).
    const minLead = Math.max(0, sampleLen - 4);
    let lead = sampleLen - 1;
    while (lead > minLead && (bytes[lead] & 0xc0) === 0x80) {
      lead -= 1;
    }
    const leadByte = bytes[lead];
    let seqLen = 0;
    if (leadByte >= 0xc2 && leadByte <= 0xdf) seqLen = 2;
    else if (leadByte >= 0xe0 && leadByte <= 0xef) seqLen = 3;
    else if (leadByte >= 0xf0 && leadByte <= 0xf4) seqLen = 4;
    if (seqLen > 0 && lead + seqLen > sampleLen && lead + seqLen <= bytes.byteLength) {
      sampleLen = lead + seqLen;
    }
  }
  for (let i = 0; i < sampleLen; i++) {
    const b = bytes[i];
    if (b === 0x00) return null;
    if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d && b !== 0x0c) return null;
  }

  let text;
  try {
    text = UTF8_DECODER_FATAL.decode(bytes.subarray(0, sampleLen));
  } catch {
    return null;
  }
  if (text.trim().length === 0) return null;

  const hint = typeof filenameHint === 'string' ? filenameHint.trim().toLowerCase() : '';
  const hasBatExt = hint.endsWith('.bat') || hint.endsWith('.cmd');
  const matchedSyntax = BATCH_STRONG_PATTERNS.some((re) => re.test(text));

  if (!hasBatExt && !matchedSyntax) return null;

  return {
    format: PACKAGE_FORMATS.WINDOWS_BAT,
    platform: 'windows',
    details: {
      scriptKind: hint.endsWith('.cmd') ? 'cmd' : 'bat',
      matchedByExtension: hasBatExt,
      matchedBySyntax: matchedSyntax,
    },
  };
}

export class FormatDetector {
  detect(buffer, filenameHint = '', opts = {}) {
    const bytes = toBytesSafe(buffer);
    if (!bytes || bytes.byteLength === 0) {
      return {
        format: PACKAGE_FORMATS.UNKNOWN,
        platform: 'unknown',
        magicHex: '',
        details: { reason: bytes === null ? 'invalid_buffer' : 'empty_buffer' },
      };
    }

    const magicHex = bytesToMagicHex(bytes, 16);

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    // 1. Universal WebAssembly (\0asm v1)
    const wasm = detectWasm(bytes, view);
    if (wasm) return { ...wasm, magicHex };

    // 2. Windows MSI (OLE CFBF)
    const msi = detectMsi(bytes);
    if (msi) return { ...msi, magicHex };

    // 3. Windows PE32 / PE32+
    const pe = detectPe(bytes, view);
    if (pe) return { ...pe, magicHex };

    // 4. macOS .pkg (XAR)
    const pkg = detectMacosPkg(bytes, view);
    if (pkg) return { ...pkg, magicHex };

    // 5. macOS Mach-O (64 / 32 / Universal Fat with Java .class guard)
    const macho = detectMachO(bytes, view);
    if (macho) return { ...macho, magicHex };

    // 6. macOS .dmg (UDIF koly trailer at EOF-512)
    const dmg = detectMacosDmg(bytes, view);
    if (dmg) return { ...dmg, magicHex };

    // 7. ZIP-based packages (APK, MSIX, IPA, macOS .app, Universal .uapp)
    const { match: zipMatch, zipError } = detectZipContainer(bytes, opts);
    if (zipMatch) return { ...zipMatch, magicHex };

    // 8. Windows .bat / .cmd script
    if (!zipError) {
      const bat = detectWindowsBat(bytes, filenameHint);
      if (bat) return { ...bat, magicHex };
    }

    // 9. Unknown
    return {
      format: PACKAGE_FORMATS.UNKNOWN,
      platform: 'unknown',
      magicHex,
      details: zipError ? { ...zipError } : { byteLength: bytes.byteLength },
    };
  }
}

const DEFAULT_DETECTOR = new FormatDetector();

export function detectFormat(buffer, filenameHint = '', opts = {}) {
  return DEFAULT_DETECTOR.detect(buffer, filenameHint, opts);
}
