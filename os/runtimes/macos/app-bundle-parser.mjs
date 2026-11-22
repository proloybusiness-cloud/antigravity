/**
 * OmniOS macOS Package & Bundle Parser (`F-054`)
 * Zero external dependencies, zero `node:fs` imports.
 *
 * Supports all 4 macOS package/binary formats:
 *  1. `macos-app`   — `.app.zip` (`<Name>.app/Contents/Info.plist` + `Contents/MacOS/<Exec>`)
 *  2. `macos-macho` — Raw 64-bit Mach-O or Universal Fat binary (ARM64 / x86-64)
 *  3. `macos-dmg`   — Apple UDIF disk image (512B BE `koly` trailer + XML `blkx`/`mish` runs)
 *  4. `macos-pkg`   — Apple Flat Installer XAR (`0x78617221`) TOC + POSIX `odc`/`newc` CPIO Payload
 *
 * Security Invariants:
 *  - Rejects path traversal (`..`, leading `/`, backslashes, drive letters, NUL -> `E_PATH_TRAVERSAL`)
 *    across ZIP, XAR TOC, CPIO Payload, and embedded TAR streams.
 *  - Enforces strict decompression caps & ratio guards (`E_ARCHIVE_BOMB`) on DMG `blkx` zlib runs,
 *    XAR TOC/heap streams, and gzipped CPIO payloads via `node:zlib` `{ maxOutputLength }`.
 *  - Propagates FairPlay DRM (`E_ENCRYPTED_BINARY`) and Fat Java `.class` guard (`E_INVALID_FAT`).
 */

import zlib from 'node:zlib';
import { FormatError, ERROR_CODES } from '../../common/errors.mjs';
import { readZip } from '../../pkg/zip.mjs';
import { PACKAGE_FORMATS } from '../../pkg/format-detector.mjs';
import { UTI_TYPE_MAP } from '../../ipc/router.mjs';
import {
  MACOS_ENTITLEMENT_MAP,
  IOS_TCC_PERMISSION_MAP,
  CAPABILITIES,
} from '../../security/permissions.mjs';
import { parsePlist, parseXmlPlist } from '../apple/plist-parser.mjs';
import { parseMachO, parseFatMachO, MACHO_CONSTANTS } from '../apple/macho-parser.mjs';

export const KOLY_MAGIC = 0x6b6f6c79; // 'koly'
export const MISH_MAGIC = 0x6d697368; // 'mish'
export const XAR_MAGIC = 0x78617221; // 'xar!'

export const DMG_CHUNK_TYPES = Object.freeze({
  ZERO_FILL: 0x00000000,
  RAW: 0x00000001,
  IGNORE: 0x00000002,
  ADC: 0x80000004,
  ZLIB: 0x80000005,
  BZ2: 0x80000006,
  LZFSE: 0x80000007,
  COMMENT: 0x7ffffffe,
  END: 0xffffffff,
});

const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024; // 64 MiB
const DEFAULT_MAX_TOC_BYTES = 16 * 1024 * 1024; // 16 MiB
const DEFAULT_MAX_ENTRIES = 10_000;
const DEFAULT_MAX_RATIO = 120;
const SECTOR_SIZE = 512;

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const ASCII_DECODER = new TextDecoder('latin1');

const EXTRA_APPLE_UTI_MAP = Object.freeze({
  'public.source-code': { extensions: ['.c', '.h', '.m', '.swift', '.js', '.mjs', '.py'], mimeTypes: ['text/plain'] },
  'public.c-source': { extensions: ['.c'], mimeTypes: ['text/x-c'] },
  'public.swift-source': { extensions: ['.swift'], mimeTypes: ['text/x-swift'] },
  'public.rtf': { extensions: ['.rtf'], mimeTypes: ['application/rtf'] },
  'public.data': { extensions: ['.bin', '.dat'], mimeTypes: ['application/octet-stream'] },
  'public.content': { extensions: ['.txt'], mimeTypes: ['text/plain'] },
  'public.image': { extensions: ['.png', '.jpg', '.jpeg'], mimeTypes: ['image/png', 'image/jpeg'] },
  'public.audio': { extensions: ['.mp3', '.wav', '.m4a'], mimeTypes: ['audio/mpeg'] },
  'public.movie': { extensions: ['.mp4', '.mov'], mimeTypes: ['video/mp4'] },
  'public.script': { extensions: ['.sh', '.py', '.js'], mimeTypes: ['text/plain'] },
  'com.apple.property-list': { extensions: ['.plist'], mimeTypes: ['application/xml'] },
});

const MACOS_USAGE_DESCRIPTION_MAP = Object.freeze({
  ...IOS_TCC_PERMISSION_MAP,
  NSAppleEventsUsageDescription: CAPABILITIES.IPC_BROADCAST,
  NSSystemAdministrationUsageDescription: CAPABILITIES.FS_WRITE_SYSTEM,
  NSMicrophoneUsageDescription: CAPABILITIES.CAMERA_DEVICE,
  NSRemovableVolumesUsageDescription: CAPABILITIES.FS_READ_USER,
  NSNetworkVolumesUsageDescription: CAPABILITIES.NETWORK_OUTBOUND,
});

const CANONICAL_CAPABILITY_SET = new Set(Object.values(CAPABILITIES));

// ============================================================================
// Byte & Security Validation Helpers
// ============================================================================

function toUint8Array(input, format = 'macos') {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new FormatError('Expected Uint8Array, ArrayBuffer, or ArrayBufferView', {
    code: ERROR_CODES.EINVAL,
    format,
  });
}

function safeBigToNum(val, label, format, offset = 0) {
  if (val > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new FormatError(`${label} exceeds safe integer bounds`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
      offset,
    });
  }
  return Number(val);
}

function isFatMagic(bytes) {
  if (!bytes || bytes.byteLength < 8) return false;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magicBE = dv.getUint32(0, false);
  return magicBE === MACHO_CONSTANTS.FAT_MAGIC || magicBE === MACHO_CONSTANTS.FAT_MAGIC_64;
}

function isMachOMagic(bytes) {
  if (!bytes || bytes.byteLength < 32) return false;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magicLE = dv.getUint32(0, true);
  const magicBE = dv.getUint32(0, false);
  return (
    magicLE === MACHO_CONSTANTS.MH_MAGIC_64 ||
    magicBE === MACHO_CONSTANTS.MH_MAGIC_64 ||
    magicLE === MACHO_CONSTANTS.MH_MAGIC ||
    magicBE === MACHO_CONSTANTS.MH_MAGIC
  );
}

/**
 * Validates and normalizes an archive entry path against directory traversal (`E_PATH_TRAVERSAL`).
 * Allows benign leading `./` prefix used by CPIO/tar archives, while strictly rejecting:
 *  - NUL bytes
 *  - Backslashes (`\`)
 *  - Leading `/` (absolute paths)
 *  - Windows drive letters (`C:...`)
 *  - Any `..` path component
 */
export function assertSafeArchivePath(rawPath, format = 'macos') {
  if (typeof rawPath !== 'string' || rawPath.length === 0 || rawPath.length > 4096) {
    throw new FormatError('Invalid or overly long archive entry path', {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      format,
    });
  }
  if (rawPath.includes('\0') || rawPath.includes('\\')) {
    throw new FormatError(`Illegal character in archive entry path: ${rawPath}`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      format,
    });
  }
  if (rawPath.startsWith('/')) {
    throw new FormatError(`Absolute path forbidden in archive: ${rawPath}`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      format,
    });
  }
  if (/^[A-Za-z]:/.test(rawPath)) {
    throw new FormatError(`Drive-letter path forbidden in archive: ${rawPath}`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      format,
    });
  }

  let cleaned = rawPath;
  while (cleaned.startsWith('./')) {
    cleaned = cleaned.slice(2);
  }
  while (cleaned.endsWith('/') && cleaned.length > 1) {
    cleaned = cleaned.slice(0, -1);
  }

  if (cleaned === '.' || cleaned === '') {
    return '.';
  }
  if (cleaned.startsWith('/')) {
    throw new FormatError(`Absolute path forbidden in archive: ${rawPath}`, {
      code: ERROR_CODES.E_PATH_TRAVERSAL,
      format,
    });
  }

  const parts = cleaned.split('/');
  const safeParts = [];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      throw new FormatError(`Path traversal ("..") forbidden in archive: ${rawPath}`, {
        code: ERROR_CODES.E_PATH_TRAVERSAL,
        format,
      });
    }
    safeParts.push(part);
  }
  if (safeParts.length === 0) return '.';
  return safeParts.join('/');
}

function safeInflate(data, { maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES, format = 'macos', mode = 'zlib', maxRatio = DEFAULT_MAX_RATIO } = {}) {
  const inputLen = data.byteLength;
  try {
    const outBuf =
      mode === 'gzip'
        ? zlib.gunzipSync(data, { maxOutputLength: maxOutputBytes })
        : mode === 'raw'
          ? zlib.inflateRawSync(data, { maxOutputLength: maxOutputBytes })
          : zlib.inflateSync(data, { maxOutputLength: maxOutputBytes });
    const out = new Uint8Array(outBuf.buffer, outBuf.byteOffset, outBuf.byteLength);
    if (out.byteLength > maxOutputBytes) {
      throw new FormatError(`Decompressed stream exceeds limit (${maxOutputBytes} bytes)`, {
        code: ERROR_CODES.E_ARCHIVE_BOMB,
        format,
      });
    }
    if (out.byteLength > 1024 && out.byteLength / Math.max(1, inputLen) > maxRatio) {
      throw new FormatError(
        `Suspicious compression ratio (${(out.byteLength / Math.max(1, inputLen)).toFixed(1)}x > ${maxRatio}x)`,
        {
          code: ERROR_CODES.E_ARCHIVE_BOMB,
          format,
        }
      );
    }
    return out;
  } catch (err) {
    if (err instanceof FormatError) throw err;
    if (err?.code === 'ERR_BUFFER_TOO_LARGE' || err instanceof RangeError) {
      throw new FormatError(`Decompressed stream exceeds maximum allowed size (${maxOutputBytes} bytes)`, {
        code: ERROR_CODES.E_ARCHIVE_BOMB,
        format,
        cause: err,
      });
    }
    throw new FormatError(`Failed to decompress ${mode} stream: ${err?.message ?? String(err)}`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
      cause: err,
    });
  }
}

function sanitizeBundleId(raw, fallback = 'com.omnios.macos.app') {
  if (typeof raw !== 'string') return fallback;
  const cleaned = raw.trim().replace(/[^A-Za-z0-9._-]+/g, '.').replace(/^\.+|\.+$/g, '');
  if (!cleaned || cleaned === '__proto__' || cleaned === 'constructor' || cleaned === 'prototype') {
    return fallback;
  }
  return cleaned.slice(0, 128);
}

function stripExt(filename) {
  if (typeof filename !== 'string' || !filename) return 'MacApp';
  const base = filename.split('/').pop() || filename;
  return base.replace(/\.(app\.zip|app|dmg|pkg|zip|macho|bin)$/i, '') || 'MacApp';
}

function parseMachOOrFat(execBytes, opts = {}) {
  let fat = null;
  let architectures = [];
  if (isFatMagic(execBytes)) {
    fat = parseFatMachO(execBytes);
    architectures = fat.slices.map((s) => s.arch);
  }
  const macho = parseMachO(execBytes, {
    preferredArch: opts.preferredArch ?? 'arm64',
    allowEncrypted: opts.allowEncrypted === true,
  });
  if (architectures.length === 0 && macho.arch) {
    architectures = [macho.arch];
  }
  return { macho, fat, architectures };
}

// ============================================================================
// Spotlight Metadata, Permissions & Intents Extraction
// ============================================================================

/**
 * Builds an Apple Spotlight (`MDItem`) metadata dictionary for an inspected/installed macOS app.
 */
export function buildSpotlightMetadata(infoPlist = {}, details = {}) {
  const plist = infoPlist && typeof infoPlist === 'object' ? infoPlist : {};
  const displayName = String(
    plist.CFBundleDisplayName ??
      plist.CFBundleName ??
      details.displayName ??
      details.name ??
      details.bundleName ??
      'macOS Application'
  );
  const bundleId = String(
    plist.CFBundleIdentifier ?? details.bundleId ?? details.appId ?? 'com.omnios.macos.app'
  );
  const version = String(
    plist.CFBundleShortVersionString ??
      plist.CFBundleVersion ??
      details.version ??
      '1.0.0'
  );
  const category = String(
    plist.LSApplicationCategoryType ??
      details.category ??
      'public.app-category.utilities'
  );
  const description = String(
    plist.NSHumanReadableCopyright ??
      plist.CFBundleGetInfoString ??
      details.description ??
      `${displayName} (${bundleId})`
  );
  const architectures = Array.isArray(details.architectures) && details.architectures.length > 0
    ? [...new Set(details.architectures.map(String))]
    : [String(details.arch ?? 'arm64')];

  const bundleName = details.bundleName
    ? (details.bundleName.endsWith('.app') ? details.bundleName : `${details.bundleName}.app`)
    : `${displayName.replace(/[^\w.-]+/g, '') || 'App'}.app`;

  const keywordSet = new Set();
  const addKw = (val) => {
    if (typeof val === 'string') {
      const t = val.trim();
      if (t.length > 0 && t.length <= 128) keywordSet.add(t);
    }
  };
  addKw(displayName);
  addKw(plist.CFBundleName);
  addKw(plist.CFBundleExecutable);
  addKw(bundleId);
  addKw(category.split('.').pop());
  addKw('macos');
  if (architectures.length > 1) addKw('universal');
  for (const a of architectures) addKw(a);

  if (Array.isArray(plist.MDItemKeywords)) {
    for (const kw of plist.MDItemKeywords) addKw(kw);
  }
  if (Array.isArray(details.keywords)) {
    for (const kw of details.keywords) addKw(kw);
  }
  if (Array.isArray(plist.CFBundleURLTypes)) {
    for (const ut of plist.CFBundleURLTypes) {
      if (Array.isArray(ut?.CFBundleURLSchemes)) {
        for (const s of ut.CFBundleURLSchemes) addKw(s);
      }
    }
  }
  if (Array.isArray(plist.CFBundleDocumentTypes)) {
    for (const dt of plist.CFBundleDocumentTypes) {
      addKw(dt?.CFBundleTypeName);
      if (Array.isArray(dt?.CFBundleTypeExtensions)) {
        for (const ext of dt.CFBundleTypeExtensions) addKw(ext);
      }
    }
  }

  return {
    kMDItemDisplayName: displayName,
    kMDItemCFBundleIdentifier: bundleId,
    kMDItemVersion: version,
    kMDItemKind: String(details.kind ?? 'Application'),
    kMDItemContentType: String(details.contentType ?? 'com.apple.application-bundle'),
    kMDItemCategory: category,
    kMDItemKeywords: Array.from(keywordSet),
    kMDItemDescription: description,
    kMDItemExecutableArchitectures: architectures,
    kMDItemPath: String(details.path ?? `/Applications/${bundleName}`),
    indexedAt: details.indexedAt ?? new Date().toISOString(),
  };
}

/**
 * Extracts canonical OmniOS permission capabilities from macOS entitlements (`com.apple.security.*`)
 * and `Info.plist` `NS*UsageDescription` declarations.
 */
export function extractMacPermissions(infoPlist = {}, entitlements = null) {
  const perms = new Set();
  // macOS desktop apps can create AppKit windows
  perms.add(CAPABILITIES.UI_WINDOW);

  if (entitlements && typeof entitlements === 'object') {
    for (const [key, val] of Object.entries(entitlements)) {
      if (!val) continue;
      if (Object.prototype.hasOwnProperty.call(MACOS_ENTITLEMENT_MAP, key)) {
        const cap = MACOS_ENTITLEMENT_MAP[key];
        perms.add(cap);
        // read-write entitlements also imply read capability
        if (cap === CAPABILITIES.FS_WRITE_USER) {
          perms.add(CAPABILITIES.FS_READ_USER);
        }
        if (cap === CAPABILITIES.FS_WRITE_SYSTEM) {
          perms.add(CAPABILITIES.FS_READ_SYSTEM);
        }
      } else if (CANONICAL_CAPABILITY_SET.has(key)) {
        perms.add(key);
      }
    }
  }

  if (infoPlist && typeof infoPlist === 'object') {
    for (const [key, val] of Object.entries(infoPlist)) {
      if (!val) continue;
      if (Object.prototype.hasOwnProperty.call(MACOS_USAGE_DESCRIPTION_MAP, key)) {
        perms.add(MACOS_USAGE_DESCRIPTION_MAP[key]);
      } else if (Object.prototype.hasOwnProperty.call(MACOS_ENTITLEMENT_MAP, key)) {
        perms.add(MACOS_ENTITLEMENT_MAP[key]);
      }
    }
  }

  return Array.from(perms);
}

/**
 * Converts Apple `CFBundleURLTypes` & `CFBundleDocumentTypes` (with UTI resolution) into
 * a flat `Array<FlatIntentDescriptor>` compatible with `PackageManager` and `IntentRouter`.
 */
export function extractMacIntents(infoPlist = {}, opts = {}) {
  const plist = infoPlist && typeof infoPlist === 'object' ? infoPlist : {};
  const defaultLabel = String(
    plist.CFBundleDisplayName ?? plist.CFBundleName ?? opts.label ?? 'macOS App'
  );
  const descriptors = [];

  // 1. CFBundleURLTypes -> URL scheme handlers
  if (Array.isArray(plist.CFBundleURLTypes)) {
    for (const urlType of plist.CFBundleURLTypes) {
      if (!urlType || typeof urlType !== 'object') continue;
      const rawSchemes = Array.isArray(urlType.CFBundleURLSchemes)
        ? urlType.CFBundleURLSchemes
        : typeof urlType.CFBundleURLSchemes === 'string'
          ? [urlType.CFBundleURLSchemes]
          : [];
      const schemes = [];
      for (const s of rawSchemes) {
        if (typeof s === 'string') {
          const norm = s.trim().toLowerCase().replace(/:$/, '');
          if (norm) schemes.push(norm);
        }
      }
      if (schemes.length > 0) {
        descriptors.push({
          actions: ['view'],
          schemes: Array.from(new Set(schemes)),
          label: String(urlType.CFBundleURLName ?? defaultLabel),
          platform: 'macos',
          priority: typeof urlType.priority === 'number' ? urlType.priority : 10,
        });
      }
    }
  }

  // 2. CFBundleDocumentTypes -> File extension, MIME & UTI handlers
  if (Array.isArray(plist.CFBundleDocumentTypes)) {
    for (const docType of plist.CFBundleDocumentTypes) {
      if (!docType || typeof docType !== 'object') continue;
      const extSet = new Set();
      const mimeSet = new Set();

      const addExt = (ext) => {
        if (typeof ext !== 'string') return;
        const t = ext.trim().toLowerCase();
        if (!t || t === '*') return;
        extSet.add(t.startsWith('.') ? t : `.${t}`);
      };
      const addMime = (mime) => {
        if (typeof mime !== 'string') return;
        const t = mime.trim().toLowerCase();
        if (t && t.includes('/')) mimeSet.add(t);
      };

      if (Array.isArray(docType.CFBundleTypeExtensions)) {
        for (const ext of docType.CFBundleTypeExtensions) addExt(ext);
      }
      if (Array.isArray(docType.CFBundleTypeMIMETypes)) {
        for (const mime of docType.CFBundleTypeMIMETypes) addMime(mime);
      }
      if (Array.isArray(docType.LSItemContentTypes)) {
        for (const uti of docType.LSItemContentTypes) {
          if (typeof uti !== 'string') continue;
          const key = uti.trim().toLowerCase();
          const mapped = UTI_TYPE_MAP[key] ?? EXTRA_APPLE_UTI_MAP[key] ?? null;
          if (mapped) {
            for (const ext of mapped.extensions) addExt(ext);
            for (const mime of mapped.mimeTypes) addMime(mime);
          }
        }
      }

      if (extSet.size > 0 || mimeSet.size > 0) {
        const role = String(docType.CFBundleTypeRole ?? 'Editor').toLowerCase();
        const actions = role === 'viewer' ? ['view'] : ['view', 'edit'];
        descriptors.push({
          actions,
          extensions: Array.from(extSet),
          mimeTypes: Array.from(mimeSet),
          label: String(docType.CFBundleTypeName ?? defaultLabel),
          platform: 'macos',
          priority: role === 'editor' ? 15 : 10,
        });
      }
    }
  }

  return descriptors;
}

// ============================================================================
// 1. macOS `.app.zip` Bundle Parser
// ============================================================================

export function parseMacAppZip(buffer, opts = {}) {
  const bytes = toUint8Array(buffer, 'macos-app');
  const archive = readZip(bytes, opts.zipLimits);

  const infoEntry = archive.entryList.find(
    (e) => !e.isDirectory && /^(?:[^/]+\/)?[^/]+\.app\/Contents\/Info\.plist$/i.test(e.name)
  );
  if (!infoEntry) {
    throw new FormatError('macOS .app bundle is missing Contents/Info.plist', {
      code: ERROR_CODES.E_MALFORMED_ZIP,
      format: 'macos-app',
    });
  }

  const infoPlistPath = infoEntry.name;
  const bundleRoot = infoPlistPath.slice(0, infoPlistPath.length - '/Contents/Info.plist'.length);
  const bundleName = bundleRoot.split('/').pop() || bundleRoot;

  const plistBytes = archive.readBytes(infoPlistPath);
  const infoPlist = parsePlist(plistBytes);
  if (!infoPlist || typeof infoPlist !== 'object' || Array.isArray(infoPlist)) {
    throw new FormatError('macOS Contents/Info.plist root must be a dictionary', {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'macos-app',
    });
  }

  const declaredExec = typeof infoPlist.CFBundleExecutable === 'string'
    ? infoPlist.CFBundleExecutable.trim()
    : '';
  const macosDirPrefix = `${bundleRoot}/Contents/MacOS/`;
  const macosDirLower = macosDirPrefix.toLowerCase();

  let execEntry = null;
  if (declaredExec) {
    const exactTarget = `${macosDirPrefix}${declaredExec}`;
    execEntry =
      archive.entryList.find((e) => !e.isDirectory && e.name === exactTarget) ??
      archive.entryList.find((e) => !e.isDirectory && e.name.toLowerCase() === exactTarget.toLowerCase()) ??
      null;
  }
  if (!execEntry) {
    execEntry =
      archive.entryList.find(
        (e) => !e.isDirectory && e.name.toLowerCase().startsWith(macosDirLower)
      ) ?? null;
  }
  if (!execEntry) {
    throw new FormatError(
      `macOS .app bundle executable not found under ${macosDirPrefix}${declaredExec || '<CFBundleExecutable>'}`,
      {
        code: ERROR_CODES.E_INVALID_MACHO,
        format: 'macos-app',
      }
    );
  }

  const executableRelPath = execEntry.name;
  const executableName = declaredExec || executableRelPath.split('/').pop();
  const executableBytes = archive.readBytes(executableRelPath);

  const { macho, fat, architectures } = parseMachOOrFat(executableBytes, opts);

  // Merge entitlements from Mach-O LC_CODE_SIGNATURE + optional bundle entitlements.plist
  let entitlements = macho.entitlements ? { ...macho.entitlements } : null;
  const entEntry = archive.entryList.find(
    (e) =>
      !e.isDirectory &&
      e.name.toLowerCase() === `${bundleRoot.toLowerCase()}/contents/entitlements.plist`
  );
  if (entEntry) {
    try {
      const parsedEnt = parsePlist(archive.readBytes(entEntry.name));
      if (parsedEnt && typeof parsedEnt === 'object' && !Array.isArray(parsedEnt)) {
        entitlements = { ...(entitlements ?? {}), ...parsedEnt };
      }
    } catch {
      // Ignore malformed optional entitlements file
    }
  }

  const spotlight = buildSpotlightMetadata(infoPlist, {
    bundleName,
    architectures,
    arch: macho.arch,
    path: `/Applications/${bundleName}`,
  });

  return {
    format: PACKAGE_FORMATS.MACOS_APP,
    bundleRoot,
    bundleName,
    infoPlistPath,
    infoPlist,
    executableName,
    executableRelPath,
    executableBytes,
    macho,
    fat,
    architectures,
    isUniversal: Boolean(fat && fat.slices.length > 1),
    entitlements,
    entries: archive.entryList.map((e) => ({
      name: e.name,
      size: e.uncompSize,
      isDirectory: e.isDirectory,
    })),
    spotlight,
    permissions: extractMacPermissions(infoPlist, entitlements),
    intents: extractMacIntents(infoPlist),
  };
}

// ============================================================================
// Helper: Parse Extracted Virtual File Map (from CPIO or TAR) for `.app`/Mach-O
// ============================================================================

function inspectExtractedFileMap(fileMap, containerFormat, opts = {}) {
  const names = Array.from(fileMap.keys());
  const infoPath = names.find((n) => /^(?:[^/]+\/)*[^/]+\.app\/Contents\/Info\.plist$/i.test(n));

  if (infoPath) {
    const bundleRoot = infoPath.slice(0, infoPath.length - '/Contents/Info.plist'.length);
    const bundleName = bundleRoot.split('/').pop() || bundleRoot;
    const infoPlist = parsePlist(fileMap.get(infoPath));
    const declaredExec = typeof infoPlist?.CFBundleExecutable === 'string'
      ? infoPlist.CFBundleExecutable.trim()
      : '';
    const macosDirPrefix = `${bundleRoot}/Contents/MacOS/`;
    const macosDirLower = macosDirPrefix.toLowerCase();

    let execPath = null;
    if (declaredExec) {
      const target = `${macosDirPrefix}${declaredExec}`;
      execPath =
        names.find((n) => n === target) ??
        names.find((n) => n.toLowerCase() === target.toLowerCase()) ??
        null;
    }
    if (!execPath) {
      execPath = names.find((n) => n.toLowerCase().startsWith(macosDirLower)) ?? null;
    }

    let macho = null;
    let fat = null;
    let architectures = [];
    let executableBytes = null;
    if (execPath) {
      executableBytes = fileMap.get(execPath);
      if (executableBytes && (isMachOMagic(executableBytes) || isFatMagic(executableBytes))) {
        const parsed = parseMachOOrFat(executableBytes, opts);
        macho = parsed.macho;
        fat = parsed.fat;
        architectures = parsed.architectures;
      }
    }

    const entitlements = macho?.entitlements ? { ...macho.entitlements } : null;
    return {
      foundApp: true,
      bundleRoot,
      bundleName,
      infoPlistPath: infoPath,
      infoPlist,
      executableName: declaredExec || (execPath ? execPath.split('/').pop() : ''),
      executableRelPath: execPath ?? '',
      executableBytes,
      macho,
      fat,
      architectures,
      entitlements,
    };
  }

  // Fallback: discover any standalone Mach-O / Fat binary in extracted map
  for (const name of names) {
    const fileBytes = fileMap.get(name);
    if (fileBytes && (isMachOMagic(fileBytes) || isFatMagic(fileBytes))) {
      const parsed = parseMachOOrFat(fileBytes, opts);
      return {
        foundApp: false,
        bundleRoot: '',
        bundleName: stripExt(name),
        infoPlistPath: null,
        infoPlist: null,
        executableName: name.split('/').pop(),
        executableRelPath: name,
        executableBytes: fileBytes,
        macho: parsed.macho,
        fat: parsed.fat,
        architectures: parsed.architectures,
        entitlements: parsed.macho?.entitlements ?? null,
      };
    }
  }

  return null;
}

// ============================================================================
// Helper: POSIX `odc` ('070707') & SVR4 `newc` ('070701'/'070702') CPIO Parser
// ============================================================================

export function parseCpioArchive(buffer, opts = {}) {
  const bytes = toUint8Array(buffer, 'macos-pkg');
  const maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const maxOutputBytes = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;

  const entries = [];
  const files = new Map();
  let offset = 0;
  let totalBytes = 0;

  while (offset + 6 <= bytes.byteLength) {
    const magic = ASCII_DECODER.decode(bytes.subarray(offset, offset + 6));

    if (magic === '070707') {
      // POSIX.1 odc format (76-byte ASCII octal header)
      if (offset + 76 > bytes.byteLength) {
        throw new FormatError('Truncated POSIX odc CPIO header', {
          code: ERROR_CODES.E_MALFORMED_BINARY,
          format: 'macos-pkg',
          offset,
        });
      }
      const mode = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 18, offset + 24)), 8);
      const uid = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 24, offset + 30)), 8);
      const gid = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 30, offset + 36)), 8);
      const mtime = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 48, offset + 59)), 8);
      const nameSize = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 59, offset + 65)), 8);
      const fileSize = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 65, offset + 76)), 8);

      if (
        !Number.isSafeInteger(nameSize) ||
        nameSize <= 0 ||
        nameSize > 4096 ||
        !Number.isSafeInteger(fileSize) ||
        fileSize < 0
      ) {
        throw new FormatError('Invalid POSIX odc CPIO header sizes', {
          code: ERROR_CODES.E_MALFORMED_BINARY,
          format: 'macos-pkg',
          offset,
        });
      }

      const nameStart = offset + 76;
      const dataStart = nameStart + nameSize;
      const dataEnd = dataStart + fileSize;
      if (dataEnd > bytes.byteLength) {
        throw new FormatError('Truncated POSIX odc CPIO entry payload', {
          code: ERROR_CODES.E_MALFORMED_BINARY,
          format: 'macos-pkg',
          offset,
        });
      }

      const rawNameBytes = bytes.subarray(nameStart, nameStart + nameSize);
      const nulIdx = rawNameBytes.indexOf(0);
      const rawName = UTF8_DECODER.decode(nulIdx >= 0 ? rawNameBytes.subarray(0, nulIdx) : rawNameBytes);

      offset = dataEnd;

      if (rawName === 'TRAILER!!!') {
        break;
      }

      if (entries.length >= maxEntries) {
        throw new FormatError(`CPIO entry count exceeds limit (${maxEntries})`, {
          code: ERROR_CODES.E_ARCHIVE_BOMB,
          format: 'macos-pkg',
        });
      }
      totalBytes += fileSize;
      if (totalBytes > maxOutputBytes) {
        throw new FormatError(`CPIO extracted size exceeds limit (${maxOutputBytes} bytes)`, {
          code: ERROR_CODES.E_ARCHIVE_BOMB,
          format: 'macos-pkg',
        });
      }

      const safePath = assertSafeArchivePath(rawName, 'macos-pkg');
      const isDir = (mode & 0o170000) === 0o040000;
      const isSymlink = (mode & 0o170000) === 0o120000;
      const data = bytes.subarray(dataStart, dataEnd).slice();

      entries.push({
        name: safePath,
        mode,
        uid,
        gid,
        mtime,
        size: fileSize,
        isDirectory: isDir,
        isSymlink,
      });
      if (!isDir && !isSymlink && safePath !== '.') {
        files.set(safePath, data);
      }
    } else if (magic === '070701' || magic === '070702') {
      // SVR4 newc / crc format (110-byte ASCII hex header + 4-byte alignment)
      if (offset + 110 > bytes.byteLength) {
        throw new FormatError('Truncated SVR4 newc CPIO header', {
          code: ERROR_CODES.E_MALFORMED_BINARY,
          format: 'macos-pkg',
          offset,
        });
      }
      const mode = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 14, offset + 22)), 16);
      const uid = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 22, offset + 30)), 16);
      const gid = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 30, offset + 38)), 16);
      const mtime = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 46, offset + 54)), 16);
      const fileSize = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 54, offset + 62)), 16);
      const nameSize = Number.parseInt(ASCII_DECODER.decode(bytes.subarray(offset + 94, offset + 102)), 16);

      if (
        !Number.isSafeInteger(nameSize) ||
        nameSize <= 0 ||
        nameSize > 4096 ||
        !Number.isSafeInteger(fileSize) ||
        fileSize < 0
      ) {
        throw new FormatError('Invalid SVR4 newc CPIO header sizes', {
          code: ERROR_CODES.E_MALFORMED_BINARY,
          format: 'macos-pkg',
          offset,
        });
      }

      const nameStart = offset + 110;
      const nameEnd = nameStart + nameSize;
      const namePad = (4 - ((110 + nameSize) & 3)) & 3;
      const dataStart = nameEnd + namePad;
      const dataEnd = dataStart + fileSize;
      const dataPad = (4 - (fileSize & 3)) & 3;

      if (dataEnd > bytes.byteLength) {
        throw new FormatError('Truncated SVR4 newc CPIO entry payload', {
          code: ERROR_CODES.E_MALFORMED_BINARY,
          format: 'macos-pkg',
          offset,
        });
      }

      const rawNameBytes = bytes.subarray(nameStart, nameEnd);
      const nulIdx = rawNameBytes.indexOf(0);
      const rawName = UTF8_DECODER.decode(nulIdx >= 0 ? rawNameBytes.subarray(0, nulIdx) : rawNameBytes);

      offset = dataEnd + dataPad;

      if (rawName === 'TRAILER!!!') {
        break;
      }

      if (entries.length >= maxEntries) {
        throw new FormatError(`CPIO entry count exceeds limit (${maxEntries})`, {
          code: ERROR_CODES.E_ARCHIVE_BOMB,
          format: 'macos-pkg',
        });
      }
      totalBytes += fileSize;
      if (totalBytes > maxOutputBytes) {
        throw new FormatError(`CPIO extracted size exceeds limit (${maxOutputBytes} bytes)`, {
          code: ERROR_CODES.E_ARCHIVE_BOMB,
          format: 'macos-pkg',
        });
      }

      const safePath = assertSafeArchivePath(rawName, 'macos-pkg');
      const isDir = (mode & 0o170000) === 0o040000;
      const isSymlink = (mode & 0o170000) === 0o120000;
      const data = bytes.subarray(dataStart, dataEnd).slice();

      entries.push({
        name: safePath,
        mode,
        uid,
        gid,
        mtime,
        size: fileSize,
        isDirectory: isDir,
        isSymlink,
      });
      if (!isDir && !isSymlink && safePath !== '.') {
        files.set(safePath, data);
      }
    } else if (bytes[offset] === 0) {
      // Trailing NUL padding at end of CPIO archive
      break;
    } else {
      throw new FormatError(`Unrecognized CPIO magic "${magic}" at offset ${offset}`, {
        code: ERROR_CODES.E_MALFORMED_BINARY,
        format: 'macos-pkg',
        offset,
      });
    }
  }

  return { entries, files };
}

// ============================================================================
// Helper: USTAR TAR Parser (for DMG payloads containing a TAR archive)
// ============================================================================

function tryParseTarArchive(bytes, format = 'macos-dmg', opts = {}) {
  if (bytes.byteLength < 512) return null;
  const ustar = ASCII_DECODER.decode(bytes.subarray(257, 262));
  if (ustar !== 'ustar') return null;

  const maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const maxOutputBytes = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const files = new Map();
  let offset = 0;
  let totalBytes = 0;
  let count = 0;

  while (offset + 512 <= bytes.byteLength) {
    let allZero = true;
    for (let i = 0; i < 512; i++) {
      if (bytes[offset + i] !== 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) break;

    const nameRaw = ASCII_DECODER.decode(bytes.subarray(offset, offset + 100)).replace(/\0.*$/, '');
    const prefixRaw = ASCII_DECODER.decode(bytes.subarray(offset + 345, offset + 500)).replace(/\0.*$/, '');
    const fullName = prefixRaw ? `${prefixRaw}/${nameRaw}` : nameRaw;
    const sizeStr = ASCII_DECODER.decode(bytes.subarray(offset + 124, offset + 136)).replace(/\0.*$/, '').trim();
    const size = sizeStr ? Number.parseInt(sizeStr, 8) : 0;
    const typeFlag = bytes[offset + 156];

    if (!Number.isSafeInteger(size) || size < 0 || offset + 512 + size > bytes.byteLength) {
      throw new FormatError('Truncated or invalid USTAR TAR entry', {
        code: ERROR_CODES.E_MALFORMED_BINARY,
        format,
        offset,
      });
    }
    if (++count > maxEntries || (totalBytes += size) > maxOutputBytes) {
      throw new FormatError('TAR archive exceeds safety limits', {
        code: ERROR_CODES.E_ARCHIVE_BOMB,
        format,
      });
    }

    const safePath = assertSafeArchivePath(fullName, format);
    if ((typeFlag === 0 || typeFlag === 48 /* '0' */) && safePath !== '.') {
      files.set(safePath, bytes.subarray(offset + 512, offset + 512 + size).slice());
    }
    const blocks = Math.ceil(size / 512);
    offset += 512 + blocks * 512;
  }

  return files;
}

// ============================================================================
// 2. macOS `.dmg` (Apple UDIF `koly` + XML `blkx`/`mish`) Parser
// ============================================================================

function concatChunks(chunks, totalLen) {
  const out = new Uint8Array(totalLen);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }
  return out;
}

function decodeMishRuns(mishBytes, dmgBytes, dataForkOffset, dataForkEnd, opts = {}) {
  const format = 'macos-dmg';
  const maxOutputBytes = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const maxRatio = opts.maxRatio ?? DEFAULT_MAX_RATIO;

  if (!(mishBytes instanceof Uint8Array) || mishBytes.byteLength < 204) {
    throw new FormatError('Truncated DMG blkx mish block (< 204 bytes)', {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
    });
  }
  const dv = new DataView(mishBytes.buffer, mishBytes.byteOffset, mishBytes.byteLength);
  const sig = dv.getUint32(0, false);
  if (sig !== MISH_MAGIC) {
    throw new FormatError(`Invalid DMG mish signature: 0x${sig.toString(16)}`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
    });
  }

  const version = dv.getUint32(4, false);
  const sectorNumber = safeBigToNum(dv.getBigUint64(8, false), 'mish.sectorNumber', format);
  const sectorCount = safeBigToNum(dv.getBigUint64(16, false), 'mish.sectorCount', format);
  const dataOffset = safeBigToNum(dv.getBigUint64(24, false), 'mish.dataOffset', format);
  const buffersNeeded = dv.getUint32(32, false);
  const blockDescriptors = dv.getUint32(36, false);
  const runCount = dv.getUint32(200, false);

  if (runCount > 65536 || 204 + runCount * 40 > mishBytes.byteLength) {
    throw new FormatError(`Invalid DMG mish runCount (${runCount}) for ${mishBytes.byteLength}B block`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
    });
  }

  const runs = [];
  const outputChunks = [];
  let totalOutBytes = 0;

  for (let i = 0; i < runCount; i++) {
    const off = 204 + i * 40;
    const entryType = dv.getUint32(off, false);
    const comment = dv.getUint32(off + 4, false);
    const runSectorNum = safeBigToNum(dv.getBigUint64(off + 8, false), 'run.sectorNumber', format);
    const runSectorCount = safeBigToNum(dv.getBigUint64(off + 16, false), 'run.sectorCount', format);
    const compOffset = safeBigToNum(dv.getBigUint64(off + 24, false), 'run.compressedOffset', format);
    const compLength = safeBigToNum(dv.getBigUint64(off + 32, false), 'run.compressedLength', format);

    runs.push({
      entryType,
      entryTypeHex: `0x${entryType.toString(16).padStart(8, '0')}`,
      comment,
      sectorNumber: runSectorNum,
      sectorCount: runSectorCount,
      compressedOffset: compOffset,
      compressedLength: compLength,
    });

    if (entryType === DMG_CHUNK_TYPES.END) {
      break;
    }
    if (entryType === DMG_CHUNK_TYPES.COMMENT) {
      continue;
    }

    if (entryType === DMG_CHUNK_TYPES.ZERO_FILL || entryType === DMG_CHUNK_TYPES.IGNORE) {
      const zeroBytes = runSectorCount * SECTOR_SIZE;
      if (zeroBytes > maxOutputBytes - totalOutBytes) {
        throw new FormatError(`DMG zero-fill run exceeds output cap (${maxOutputBytes} bytes)`, {
          code: ERROR_CODES.E_ARCHIVE_BOMB,
          format,
        });
      }
      if (zeroBytes > 0) {
        outputChunks.push(new Uint8Array(zeroBytes));
        totalOutBytes += zeroBytes;
      }
      continue;
    }

    if (entryType === DMG_CHUNK_TYPES.RAW) {
      const absStart = dataForkOffset + dataOffset + compOffset;
      const absEnd = absStart + compLength;
      if (absStart < dataForkOffset || absEnd > dataForkEnd || absEnd > dmgBytes.byteLength) {
        throw new FormatError('DMG raw blkx run out of data fork bounds', {
          code: ERROR_CODES.E_MALFORMED_BINARY,
          format,
          offset: absStart,
        });
      }
      if (compLength > maxOutputBytes - totalOutBytes) {
        throw new FormatError(`DMG raw run exceeds output cap (${maxOutputBytes} bytes)`, {
          code: ERROR_CODES.E_ARCHIVE_BOMB,
          format,
        });
      }
      if (compLength > 0) {
        outputChunks.push(dmgBytes.subarray(absStart, absEnd));
        totalOutBytes += compLength;
      }
      continue;
    }

    if (entryType === DMG_CHUNK_TYPES.ZLIB) {
      const absStart = dataForkOffset + dataOffset + compOffset;
      const absEnd = absStart + compLength;
      if (absStart < dataForkOffset || absEnd > dataForkEnd || absEnd > dmgBytes.byteLength) {
        throw new FormatError('DMG zlib blkx run out of data fork bounds', {
          code: ERROR_CODES.E_MALFORMED_BINARY,
          format,
          offset: absStart,
        });
      }
      const remaining = maxOutputBytes - totalOutBytes;
      const inflated = safeInflate(dmgBytes.subarray(absStart, absEnd), {
        maxOutputBytes: remaining,
        format,
        mode: 'zlib',
        maxRatio,
      });
      if (inflated.byteLength > 0) {
        outputChunks.push(inflated);
        totalOutBytes += inflated.byteLength;
      }
      continue;
    }

    // Other Apple codecs (ADC/BZ2/LZFSE): record run metadata safely without crashing
  }

  const data = concatChunks(outputChunks, totalOutBytes);
  return {
    version,
    sectorNumber,
    sectorCount,
    dataOffset,
    buffersNeeded,
    blockDescriptors,
    runCount,
    runs,
    decompressedBytes: totalOutBytes,
    data,
  };
}

function findZipEndOffset(bytes, startOffset) {
  // Scan backward for PK\x05\x06 EOCD so trailing zero-padded sector bytes after an embedded ZIP are trimmed cleanly
  const minPos = Math.max(startOffset, bytes.byteLength - 65557);
  for (let i = bytes.byteLength - 22; i >= minPos; i--) {
    if (
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x05 &&
      bytes[i + 3] === 0x06
    ) {
      const commentLen = bytes[i + 20] | (bytes[i + 21] << 8);
      const endPos = i + 22 + commentLen;
      if (endPos <= bytes.byteLength) {
        return endPos;
      }
    }
  }
  return bytes.byteLength;
}

export function parseMacDmg(buffer, opts = {}) {
  const format = PACKAGE_FORMATS.MACOS_DMG;
  const bytes = toUint8Array(buffer, format);
  if (bytes.byteLength < 512) {
    throw new FormatError('Truncated macOS DMG image (< 512 bytes for koly trailer)', {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
    });
  }

  const tail = bytes.byteLength - 512;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const signature = dv.getUint32(tail, false);
  if (signature !== KOLY_MAGIC) {
    throw new FormatError(`Invalid DMG koly trailer signature: 0x${signature.toString(16)}`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
      offset: tail,
    });
  }

  const version = dv.getUint32(tail + 4, false);
  const headerSize = dv.getUint32(tail + 8, false);
  if (headerSize !== 512) {
    throw new FormatError(`Invalid DMG koly headerSize (${headerSize}, expected 512)`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
      offset: tail + 8,
    });
  }

  const flags = dv.getUint32(tail + 12, false);
  const runningDataForkOffset = safeBigToNum(dv.getBigUint64(tail + 0x10, false), 'koly.runningDataForkOffset', format, tail + 0x10);
  const dataForkOffset = safeBigToNum(dv.getBigUint64(tail + 0x18, false), 'koly.dataForkOffset', format, tail + 0x18);
  const dataForkLength = safeBigToNum(dv.getBigUint64(tail + 0x20, false), 'koly.dataForkLength', format, tail + 0x20);
  const rsrcForkOffset = safeBigToNum(dv.getBigUint64(tail + 0x28, false), 'koly.rsrcForkOffset', format, tail + 0x28);
  const rsrcForkLength = safeBigToNum(dv.getBigUint64(tail + 0x30, false), 'koly.rsrcForkLength', format, tail + 0x30);
  const segmentNumber = dv.getUint32(tail + 0x38, false);
  const segmentCount = dv.getUint32(tail + 0x3c, false);
  const xmlOffset = safeBigToNum(dv.getBigUint64(tail + 0xd8, false), 'koly.xmlOffset', format, tail + 0xd8);
  const xmlLength = safeBigToNum(dv.getBigUint64(tail + 0xe0, false), 'koly.xmlLength', format, tail + 0xe0);
  const imageVariant = dv.getUint32(tail + 0x1ec, false);
  const sectorCount = safeBigToNum(dv.getBigUint64(tail + 0x1f0, false), 'koly.sectorCount', format, tail + 0x1f0);

  if (dataForkOffset + dataForkLength > tail) {
    throw new FormatError('DMG koly dataForkOffset + dataForkLength exceeds trailer boundary', {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
      offset: tail + 0x18,
    });
  }
  if (xmlLength === 0 || xmlOffset + xmlLength > tail) {
    throw new FormatError('DMG koly xmlOffset + xmlLength out of bounds', {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
      offset: tail + 0xd8,
    });
  }

  const xmlBytes = bytes.subarray(xmlOffset, xmlOffset + xmlLength);
  const xmlPlist = parseXmlPlist(xmlBytes);
  const resourceFork = xmlPlist?.['resource-fork'] ?? {};
  const rawBlkx = Array.isArray(resourceFork.blkx) ? resourceFork.blkx : [];

  const maxTotalBytes = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  let remainingBudget = maxTotalBytes;
  const partitions = [];
  const blkxMeta = [];

  for (let i = 0; i < rawBlkx.length; i++) {
    const entry = rawBlkx[i];
    if (!entry || typeof entry !== 'object') continue;
    const mishBytes = entry.Data;
    const decoded = decodeMishRuns(mishBytes, bytes, dataForkOffset, dataForkOffset + dataForkLength, {
      ...opts,
      maxOutputBytes: remainingBudget,
    });
    remainingBudget = Math.max(0, remainingBudget - decoded.decompressedBytes);

    blkxMeta.push({
      index: i,
      id: entry.ID ?? String(i),
      name: entry.Name ?? entry.CFName ?? `partition-${i}`,
      attributes: entry.Attributes ?? null,
      sectorNumber: decoded.sectorNumber,
      sectorCount: decoded.sectorCount,
      runCount: decoded.runCount,
      decompressedBytes: decoded.decompressedBytes,
      runs: decoded.runs,
    });
    partitions.push({
      id: entry.ID ?? String(i),
      name: entry.Name ?? entry.CFName ?? `partition-${i}`,
      decompressedBytes: decoded.decompressedBytes,
      data: decoded.data,
    });
  }

  const koly = {
    signature: 'koly',
    version,
    headerSize,
    flags,
    runningDataForkOffset,
    dataForkOffset,
    dataForkLength,
    rsrcForkOffset,
    rsrcForkLength,
    segmentNumber,
    segmentCount,
    xmlOffset,
    xmlLength,
    imageVariant,
    sectorCount,
  };

  // Discover embedded `.app` ZIP, TAR, CPIO, or raw Mach-O across decompressed partitions
  let embeddedApp = null;
  let extractedFiles = new Map();
  let embeddedZipBytes = null;

  for (const part of partitions) {
    const pData = part.data;
    if (!pData || pData.byteLength < 8) continue;

    // 1. Embedded PKZIP (`.app.zip`)
    if (pData[0] === 0x50 && pData[1] === 0x4b && pData[2] === 0x03 && pData[3] === 0x04) {
      const zipEnd = findZipEndOffset(pData, 0);
      const zipSlice = pData.subarray(0, zipEnd);
      embeddedApp = parseMacAppZip(zipSlice, opts);
      embeddedZipBytes = zipSlice;
      const z = readZip(zipSlice, opts.zipLimits);
      for (const e of z.entryList) {
        if (!e.isDirectory) {
          extractedFiles.set(e.name, z.readBytes(e.name));
        }
      }
      break;
    }

    // 2. Embedded CPIO (gzipped or raw)
    if (
      (pData[0] === 0x1f && pData[1] === 0x8b) ||
      ASCII_DECODER.decode(pData.subarray(0, 6)) === '070707' ||
      ASCII_DECODER.decode(pData.subarray(0, 6)) === '070701'
    ) {
      const cpioBytes =
        pData[0] === 0x1f && pData[1] === 0x8b
          ? safeInflate(pData, { maxOutputBytes: maxTotalBytes, format, mode: 'gzip' })
          : pData;
      const cpio = parseCpioArchive(cpioBytes, opts);
      extractedFiles = cpio.files;
      embeddedApp = inspectExtractedFileMap(cpio.files, format, opts);
      if (embeddedApp) break;
    }

    // 3. Embedded USTAR TAR
    const tarFiles = tryParseTarArchive(pData, format, opts);
    if (tarFiles && tarFiles.size > 0) {
      extractedFiles = tarFiles;
      embeddedApp = inspectExtractedFileMap(tarFiles, format, opts);
      if (embeddedApp) break;
    }

    // 4. Embedded raw Mach-O / Universal Fat binary
    if (isMachOMagic(pData) || isFatMagic(pData)) {
      const parsed = parseMachOOrFat(pData, opts);
      const execName = stripExt(part.name) || 'dmg-binary';
      extractedFiles.set(execName, pData);
      embeddedApp = {
        foundApp: false,
        bundleRoot: '',
        bundleName: execName,
        infoPlistPath: null,
        infoPlist: null,
        executableName: execName,
        executableRelPath: execName,
        executableBytes: pData,
        macho: parsed.macho,
        fat: parsed.fat,
        architectures: parsed.architectures,
        entitlements: parsed.macho?.entitlements ?? null,
      };
      break;
    }
  }

  const infoPlist = embeddedApp?.infoPlist ?? {};
  const entitlements = embeddedApp?.entitlements ?? null;
  const architectures = embeddedApp?.architectures ?? [];
  const bundleName = embeddedApp?.bundleName ?? stripExt(opts.filenameHint || 'DiskImage');
  const spotlight = buildSpotlightMetadata(infoPlist, {
    bundleName,
    architectures: architectures.length > 0 ? architectures : ['arm64'],
    kind: embeddedApp?.infoPlist ? 'Application' : 'Disk Image',
    contentType: embeddedApp?.infoPlist ? 'com.apple.application-bundle' : 'com.apple.disk-image-udif',
    path: `/Applications/${bundleName}`,
  });

  return {
    format,
    koly,
    blkx: blkxMeta,
    partitions: partitions.map((p) => ({
      id: p.id,
      name: p.name,
      decompressedBytes: p.decompressedBytes,
      data: p.data,
    })),
    bundleRoot: embeddedApp?.bundleRoot ?? '',
    bundleName,
    infoPlistPath: embeddedApp?.infoPlistPath ?? null,
    infoPlist: embeddedApp?.infoPlist ?? null,
    executableName: embeddedApp?.executableName ?? '',
    executableRelPath: embeddedApp?.executableRelPath ?? '',
    executableBytes: embeddedApp?.executableBytes ?? null,
    macho: embeddedApp?.macho ?? null,
    fat: embeddedApp?.fat ?? null,
    architectures,
    isUniversal: Boolean(embeddedApp?.fat && embeddedApp.fat.slices.length > 1),
    entitlements,
    embeddedZipBytes,
    extractedFiles,
    spotlight,
    permissions: extractMacPermissions(infoPlist, entitlements),
    intents: extractMacIntents(infoPlist),
  };
}

// ============================================================================
// 3. macOS `.pkg` (Flat Installer XAR + CPIO Payload) Parser
// ============================================================================

function unescapeXml(str) {
  return String(str ?? '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function parseXmlAttrs(attrStr) {
  const attrs = {};
  if (!attrStr) return attrs;
  const re = /([A-Za-z0-9_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(attrStr)) !== null) {
    attrs[m[1]] = unescapeXml(m[2] ?? m[3] ?? '');
  }
  return attrs;
}

/**
 * Lightweight, zero-dependency, stack-based XML element parser for XAR TOC, PackageInfo & Distribution.
 */
function parseSimpleXml(xmlText, format = 'macos-pkg') {
  const root = { tag: '#root', attrs: {}, children: [], text: '' };
  const stack = [root];
  const tokenRe = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[\s\S]*?>|<!\[CDATA\[([\s\S]*?)\]\]>|<\/([A-Za-z0-9_:-]+)\s*>|<([A-Za-z0-9_:-]+)((?:\s+[^<>]*?)?)(\/?)>|([^<]+)/g;
  let m;
  let nodeCount = 0;

  while ((m = tokenRe.exec(xmlText)) !== null) {
    if (m[1] !== undefined) {
      stack[stack.length - 1].text += m[1];
      continue;
    }
    if (m[2] !== undefined) {
      const closeTag = m[2];
      if (stack.length > 1 && stack[stack.length - 1].tag === closeTag) {
        stack.pop();
      }
      continue;
    }
    if (m[3] !== undefined) {
      if (++nodeCount > 200_000) {
        throw new FormatError('XML exceeds maximum node limit', {
          code: ERROR_CODES.E_ARCHIVE_BOMB,
          format,
        });
      }
      const tag = m[3];
      const attrs = parseXmlAttrs(m[4]);
      const selfClosing = m[5] === '/';
      const node = { tag, attrs, children: [], text: '' };
      stack[stack.length - 1].children.push(node);
      if (!selfClosing) {
        if (stack.length > 128) {
          throw new FormatError('XML exceeds maximum nesting depth', {
            code: ERROR_CODES.E_ARCHIVE_BOMB,
            format,
          });
        }
        stack.push(node);
      }
      continue;
    }
    if (m[6] !== undefined) {
      const txt = m[6];
      if (txt.trim().length > 0) {
        stack[stack.length - 1].text += unescapeXml(txt);
      }
    }
  }
  return root;
}

function getChildText(node, tagName) {
  const child = node?.children?.find((c) => c.tag === tagName);
  return child ? child.text.trim() : null;
}

function collectXarFiles(parentNode, prefix, out, format, maxEntries = DEFAULT_MAX_ENTRIES) {
  for (const child of parentNode.children ?? []) {
    if (child.tag !== 'file') continue;
    const rawName = getChildText(child, 'name');
    if (!rawName) continue;
    // Validate rawName BEFORE prefixing so nested absolute <name>/etc/passwd</name> is rejected!
    const safeRawName = assertSafeArchivePath(rawName, format);
    const fullRaw = prefix ? `${prefix}/${safeRawName}` : safeRawName;
    const safePath = assertSafeArchivePath(fullRaw, format);
    if (out.length >= maxEntries) {
      throw new FormatError(`XAR TOC file count exceeds limit (${maxEntries})`, {
        code: ERROR_CODES.E_ARCHIVE_BOMB,
        format,
      });
    }
    const type = (getChildText(child, 'type') ?? 'file').toLowerCase();
    const dataNode = child.children.find((c) => c.tag === 'data') ?? null;

    let dataInfo = null;
    if (dataNode) {
      const encNode = dataNode.children.find((c) => c.tag === 'encoding');
      dataInfo = {
        offset: Number.parseInt(getChildText(dataNode, 'offset') ?? '0', 10),
        length: Number.parseInt(getChildText(dataNode, 'length') ?? '0', 10),
        size: Number.parseInt(getChildText(dataNode, 'size') ?? '0', 10),
        encoding: encNode?.attrs?.style ?? 'application/octet-stream',
      };
    }

    out.push({
      id: child.attrs.id ?? null,
      name: safePath,
      type,
      data: dataInfo,
    });

    if (type === 'directory') {
      collectXarFiles(child, safePath, out, format, maxEntries);
    }
  }
}

export function parseMacPkg(buffer, opts = {}) {
  const format = PACKAGE_FORMATS.MACOS_PKG;
  const bytes = toUint8Array(buffer, format);
  if (bytes.byteLength < 28) {
    throw new FormatError('Truncated macOS XAR .pkg header (< 28 bytes)', {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
    });
  }

  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = dv.getUint32(0, false);
  if (magic !== XAR_MAGIC) {
    throw new FormatError(`Invalid XAR magic: 0x${magic.toString(16)}`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
      offset: 0,
    });
  }

  const headerSize = dv.getUint16(4, false);
  const version = dv.getUint16(6, false);
  if (headerSize < 28 || headerSize > bytes.byteLength) {
    throw new FormatError(`Invalid XAR headerSize (${headerSize})`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
      offset: 4,
    });
  }

  const tocLengthCompressed = safeBigToNum(dv.getBigUint64(8, false), 'xar.tocLengthCompressed', format, 8);
  const tocLengthUncompressed = safeBigToNum(dv.getBigUint64(16, false), 'xar.tocLengthUncompressed', format, 16);
  const cksumAlg = dv.getUint32(24, false);

  const maxTocBytes = opts.maxTocBytes ?? DEFAULT_MAX_TOC_BYTES;
  const maxOutputBytes = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;

  if (tocLengthCompressed === 0 || headerSize + tocLengthCompressed > bytes.byteLength) {
    throw new FormatError('XAR TOC compressed range exceeds archive bounds', {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
      offset: 8,
    });
  }
  if (tocLengthUncompressed > maxTocBytes) {
    throw new FormatError(`XAR TOC uncompressed size (${tocLengthUncompressed}) exceeds limit (${maxTocBytes})`, {
      code: ERROR_CODES.E_ARCHIVE_BOMB,
      format,
      offset: 16,
    });
  }

  const tocCompressed = bytes.subarray(headerSize, headerSize + tocLengthCompressed);
  const tocBytes = safeInflate(tocCompressed, {
    maxOutputBytes: Math.min(maxTocBytes, Math.max(tocLengthUncompressed + 1024, 65536)),
    format,
    mode: 'zlib',
    maxRatio: opts.maxRatio ?? DEFAULT_MAX_RATIO,
  });
  if (tocLengthUncompressed > 0 && tocBytes.byteLength !== tocLengthUncompressed) {
    throw new FormatError(
      `XAR TOC decompressed size mismatch (expected ${tocLengthUncompressed}, got ${tocBytes.byteLength})`,
      {
        code: ERROR_CODES.E_MALFORMED_BINARY,
        format,
      }
    );
  }

  const tocXmlStr = UTF8_DECODER.decode(tocBytes);
  const tocDom = parseSimpleXml(tocXmlStr, format);
  const xarNode = tocDom.children.find((c) => c.tag === 'xar');
  const tocNode = xarNode?.children?.find((c) => c.tag === 'toc');
  if (!tocNode) {
    throw new FormatError('XAR XML TOC missing <xar><toc> root', {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format,
    });
  }

  const maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const maxRatio = opts.maxRatio ?? DEFAULT_MAX_RATIO;
  const xarFiles = [];
  collectXarFiles(tocNode, '', xarFiles, format, maxEntries);

  // Shared decrementing bomb budget across ALL XAR heap reads + CPIO Payload inflations/extractions
  let remainingBudget = maxOutputBytes;
  let remainingEntries = maxEntries;

  const heapBase = headerSize + tocLengthCompressed;
  const readXarFileBytes = (entry, { deferRawBudget = false } = {}) => {
    if (!entry?.data) return new Uint8Array(0);
    const { offset, length, size, encoding } = entry.data;
    if (
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      !Number.isSafeInteger(length) ||
      length < 0 ||
      heapBase + offset + length > bytes.byteLength
    ) {
      throw new FormatError(`XAR heap entry "${entry.name}" out of bounds`, {
        code: ERROR_CODES.E_MALFORMED_BINARY,
        format,
        offset: heapBase + offset,
      });
    }
    const enc = String(encoding ?? '').toLowerCase();
    const isCompressed = enc === 'application/x-gzip' || enc === 'application/x-zlib' || enc === 'application/zlib';
    if (remainingBudget <= 0 || (!deferRawBudget && size > remainingBudget) || (isCompressed && size > remainingBudget)) {
      throw new FormatError(
        `XAR entry "${entry.name}" exceeds remaining decompression budget (${remainingBudget} bytes)`,
        {
          code: ERROR_CODES.E_ARCHIVE_BOMB,
          format,
        }
      );
    }
    const rawSlice = bytes.subarray(heapBase + offset, heapBase + offset + length);
    if (enc === 'application/x-gzip') {
      const out = safeInflate(rawSlice, { maxOutputBytes: remainingBudget, format, mode: 'gzip', maxRatio });
      remainingBudget -= out.byteLength;
      return out;
    }
    if (enc === 'application/x-zlib' || enc === 'application/zlib') {
      const out = safeInflate(rawSlice, { maxOutputBytes: remainingBudget, format, mode: 'zlib', maxRatio });
      remainingBudget -= out.byteLength;
      return out;
    }
    if (!deferRawBudget) {
      if (rawSlice.byteLength > remainingBudget) {
        throw new FormatError(
          `XAR entry "${entry.name}" exceeds remaining extraction budget (${remainingBudget} bytes)`,
          {
            code: ERROR_CODES.E_ARCHIVE_BOMB,
            format,
          }
        );
      }
      remainingBudget -= rawSlice.byteLength;
    }
    return rawSlice.slice();
  };

  // Extract PackageInfo & Distribution XML metadata
  let packageInfo = null;
  let distribution = null;

  const pkgInfoEntry = xarFiles.find(
    (f) => f.type === 'file' && /(?:^|\/)PackageInfo$/i.test(f.name)
  );
  if (pkgInfoEntry) {
    const xmlStr = UTF8_DECODER.decode(readXarFileBytes(pkgInfoEntry));
    const dom = parseSimpleXml(xmlStr, format);
    const piNode = dom.children.find((c) => c.tag === 'pkg-info');
    if (piNode) {
      const bundles = [];
      const walkBundles = (n) => {
        for (const ch of n.children ?? []) {
          if (ch.tag === 'bundle') bundles.push({ ...ch.attrs });
          walkBundles(ch);
        }
      };
      walkBundles(piNode);
      packageInfo = {
        identifier: piNode.attrs.identifier ?? null,
        version: piNode.attrs.version ?? null,
        installLocation: piNode.attrs['install-location'] ?? '/',
        auth: piNode.attrs.auth ?? null,
        bundles,
      };
    }
  }

  const distEntry = xarFiles.find(
    (f) => f.type === 'file' && /(?:^|\/)Distribution$/i.test(f.name)
  );
  if (distEntry) {
    const xmlStr = UTF8_DECODER.decode(readXarFileBytes(distEntry));
    const dom = parseSimpleXml(xmlStr, format);
    const scriptNode = dom.children.find((c) => c.tag === 'installer-gui-script');
    if (scriptNode) {
      const titleNode = scriptNode.children.find((c) => c.tag === 'title');
      const pkgRefs = scriptNode.children
        .filter((c) => c.tag === 'pkg-ref')
        .map((r) => ({ ...r.attrs, text: r.text.trim() }));
      distribution = {
        title: titleNode ? titleNode.text.trim() : null,
        pkgRefs,
      };
    }
  }

  // Extract CPIO Payload(s) under the shared decrementing remainingBudget & remainingEntries
  const payloadEntries = xarFiles.filter(
    (f) => f.type === 'file' && /(?:^|\/)Payload$/i.test(f.name)
  );
  const cpioEntries = [];
  const extractedFiles = new Map();

  for (const pEntry of payloadEntries) {
    const enc = String(pEntry.data?.encoding ?? '').toLowerCase();
    const xarCompressed =
      enc === 'application/x-gzip' || enc === 'application/x-zlib' || enc === 'application/zlib';
    const rawPayload = readXarFileBytes(pEntry, { deferRawBudget: !xarCompressed });
    if (rawPayload.byteLength === 0) continue;

    let cpioStream;
    if (rawPayload.byteLength >= 2 && rawPayload[0] === 0x1f && rawPayload[1] === 0x8b) {
      if (remainingBudget <= 0) {
        throw new FormatError(
          `macOS .pkg cumulative payload size exceeds limit (${maxOutputBytes} bytes)`,
          {
            code: ERROR_CODES.E_ARCHIVE_BOMB,
            format,
          }
        );
      }
      cpioStream = safeInflate(rawPayload, {
        maxOutputBytes: remainingBudget,
        format,
        mode: 'gzip',
        maxRatio,
      });
      remainingBudget -= cpioStream.byteLength;
    } else {
      if (!xarCompressed) {
        if (rawPayload.byteLength > remainingBudget) {
          throw new FormatError(
            `macOS .pkg cumulative payload size exceeds limit (${maxOutputBytes} bytes)`,
            {
              code: ERROR_CODES.E_ARCHIVE_BOMB,
              format,
            }
          );
        }
        remainingBudget -= rawPayload.byteLength;
      }
      cpioStream = rawPayload;
    }

    if (remainingEntries <= 0) {
      throw new FormatError(`macOS .pkg cumulative CPIO entries exceed limit (${maxEntries})`, {
        code: ERROR_CODES.E_ARCHIVE_BOMB,
        format,
      });
    }

    const parsedCpio = parseCpioArchive(cpioStream, {
      maxOutputBytes: cpioStream.byteLength,
      maxEntries: remainingEntries,
    });
    remainingEntries -= parsedCpio.entries.length;
    for (const ce of parsedCpio.entries) cpioEntries.push(ce);
    for (const [k, v] of parsedCpio.files.entries()) {
      extractedFiles.set(k, v);
    }
  }

  const embeddedApp = inspectExtractedFileMap(extractedFiles, format, opts);
  const infoPlist = embeddedApp?.infoPlist ?? {};
  const entitlements = embeddedApp?.entitlements ?? null;
  const architectures = embeddedApp?.architectures ?? [];

  const fallbackName =
    distribution?.title ??
    embeddedApp?.bundleName ??
    packageInfo?.identifier?.split('.').pop() ??
    stripExt(opts.filenameHint || 'Installer');

  const spotlight = buildSpotlightMetadata(infoPlist, {
    displayName: infoPlist.CFBundleDisplayName ?? infoPlist.CFBundleName ?? fallbackName,
    bundleId: infoPlist.CFBundleIdentifier ?? packageInfo?.identifier ?? undefined,
    version: infoPlist.CFBundleShortVersionString ?? packageInfo?.version ?? '1.0.0',
    bundleName: embeddedApp?.bundleName ?? `${fallbackName}.app`,
    architectures: architectures.length > 0 ? architectures : ['arm64'],
    kind: embeddedApp?.infoPlist ? 'Application' : 'Installer Package',
    contentType: embeddedApp?.infoPlist ? 'com.apple.application-bundle' : 'com.apple.installer-package-archive',
  });

  return {
    format,
    xar: {
      magic: 'xar!',
      headerSize,
      version,
      tocLengthCompressed,
      tocLengthUncompressed,
      cksumAlg,
      heapBase,
      files: xarFiles,
    },
    packageInfo,
    distribution,
    cpioEntries,
    extractedFiles,
    bundleRoot: embeddedApp?.bundleRoot ?? '',
    bundleName: embeddedApp?.bundleName ?? fallbackName,
    infoPlistPath: embeddedApp?.infoPlistPath ?? null,
    infoPlist: embeddedApp?.infoPlist ?? null,
    executableName: embeddedApp?.executableName ?? '',
    executableRelPath: embeddedApp?.executableRelPath ?? '',
    executableBytes: embeddedApp?.executableBytes ?? null,
    macho: embeddedApp?.macho ?? null,
    fat: embeddedApp?.fat ?? null,
    architectures,
    isUniversal: Boolean(embeddedApp?.fat && embeddedApp.fat.slices.length > 1),
    entitlements,
    spotlight,
    permissions: extractMacPermissions(infoPlist, entitlements),
    intents: extractMacIntents(infoPlist, { label: fallbackName }),
  };
}

// ============================================================================
// 4. Unified macOS Package Dispatcher (`macos-app`, `macos-macho`, `macos-dmg`, `macos-pkg`)
// ============================================================================

export function parseMacPackage(buffer, filenameHint = '', detection = null, opts = {}) {
  const bytes = toUint8Array(buffer, 'macos');
  let format = detection?.format ?? null;

  if (!format) {
    if (bytes.byteLength >= 28) {
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      if (dv.getUint32(0, false) === XAR_MAGIC) {
        format = PACKAGE_FORMATS.MACOS_PKG;
      } else if (bytes.byteLength >= 512 && dv.getUint32(bytes.byteLength - 512, false) === KOLY_MAGIC) {
        format = PACKAGE_FORMATS.MACOS_DMG;
      } else if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
        format = PACKAGE_FORMATS.MACOS_APP;
      } else if (isMachOMagic(bytes) || isFatMagic(bytes)) {
        format = PACKAGE_FORMATS.MACOS_MACHO;
      }
    }
  }

  if (format === PACKAGE_FORMATS.MACOS_APP) {
    return parseMacAppZip(bytes, { ...opts, filenameHint });
  }
  if (format === PACKAGE_FORMATS.MACOS_DMG) {
    return parseMacDmg(bytes, { ...opts, filenameHint });
  }
  if (format === PACKAGE_FORMATS.MACOS_PKG) {
    return parseMacPkg(bytes, { ...opts, filenameHint });
  }
  if (format === PACKAGE_FORMATS.MACOS_MACHO) {
    const { macho, fat, architectures } = parseMachOOrFat(bytes, opts);
    const rawBase = stripExt(filenameHint || 'macho-app')
      .replace(/[^\w.-]+/g, '_')
      .replace(/^\.+/, '');
    const baseName =
      rawBase && rawBase !== '.' && rawBase !== '..' && !rawBase.includes('/') && !rawBase.includes('\\')
        ? rawBase.slice(0, 128)
        : 'macho-app';

    let executableRelPath = `${baseName}.macho`;
    if (typeof filenameHint === 'string' && filenameHint.length > 0) {
      const hasUnsafeHint =
        filenameHint.includes('\0') ||
        filenameHint.includes('\\') ||
        /^[A-Za-z]:/.test(filenameHint);
      if (!hasUnsafeHint) {
        const candidate = filenameHint.split('/').pop() ?? '';
        if (
          candidate.length > 0 &&
          candidate.length <= 255 &&
          candidate !== '.' &&
          candidate !== '..' &&
          !candidate.includes('/') &&
          !candidate.includes('\\') &&
          !candidate.includes('\0')
        ) {
          executableRelPath = candidate;
        }
      }
    }

    const appId = sanitizeBundleId(
      macho.entitlements?.['application-identifier'] ??
        macho.codeSignature?.codeDirectory?.identifier ??
        `com.omnios.macos.${baseName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
    );
    const infoPlist = {
      CFBundleIdentifier: appId,
      CFBundleName: baseName,
      CFBundleExecutable: baseName,
      CFBundleShortVersionString: '1.0.0',
    };
    const entitlements = macho.entitlements ?? null;
    const spotlight = buildSpotlightMetadata(infoPlist, {
      displayName: baseName,
      bundleId: appId,
      bundleName: baseName,
      architectures,
      kind: 'Mach-O Executable',
      contentType: 'public.unix-executable',
      path: `/Applications/${baseName}`,
    });
    return {
      format: PACKAGE_FORMATS.MACOS_MACHO,
      bundleRoot: '',
      bundleName: baseName,
      infoPlistPath: null,
      infoPlist,
      executableName: baseName,
      executableRelPath,
      executableBytes: bytes,
      macho,
      fat,
      architectures,
      isUniversal: Boolean(fat && fat.slices.length > 1),
      entitlements,
      spotlight,
      permissions: extractMacPermissions(infoPlist, entitlements),
      intents: [],
    };
  }

  throw new FormatError(`Unsupported macOS package format: ${format ?? 'unknown'}`, {
    code: ERROR_CODES.ENOTSUP,
    format: format ?? 'unknown',
  });
}
