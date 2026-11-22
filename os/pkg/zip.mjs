/**
 * OmniOS Zero-Dependency PKZIP & ZIP64 Reader/Writer (`os/pkg/zip.mjs`)
 * - Backward EOCD scan with exact comment-length verification (tolerates APK Signing Block v2/v3 & fake EOCDs)
 * - Full ZIP64 EOCD Record, Locator, and Extra Field `0x0001` compliant with PKWARE APPNOTE & Python 3 `zipfile`
 * - Central Directory authority for Data Descriptor Bit 3 (`0x0008`), UTF-8 Bit 11 (`0x0800`) + CP437 fallback
 * - STORE (0) and DEFLATE (8) via `node:zlib` with strict IEEE CRC-32 validation (`E_CRC_MISMATCH`)
 * - Comprehensive security defenses: ZIP-slip (`E_PATH_TRAVERSAL`), ZIP-bomb (`E_ARCHIVE_BOMB` via
 *   maxEntries, maxEntryBytes, maxUncompressedBytes, maxCompressionRatio, overlapping ranges,
 *   and `inflateRawSync(..., { maxOutputLength })`), and duplicate/conflicting Central Directory names
 */

import zlib from 'node:zlib';
import { isAscii } from 'node:buffer';
import { types } from 'node:util';
import { BinaryReader, BinaryWriter, crc32 } from '../common/binary.mjs';
import { FormatError, ERROR_CODES } from '../common/errors.mjs';

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
const SYMBOL_DESCRIPTION_GET = Object.getOwnPropertyDescriptor(Symbol.prototype, 'description')?.get ?? null;

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

export const ZIP_SIGNATURES = Object.freeze({
  LOCAL_FILE_HEADER: 0x04034b50,
  DATA_DESCRIPTOR: 0x08074b50,
  CENTRAL_DIR_HEADER: 0x02014b50,
  EOCD: 0x06054b50,
  ZIP64_EOCD: 0x06064b50,
  ZIP64_EOCD_LOCATOR: 0x07064b50,
});

export const ZIP_METHODS = Object.freeze({
  STORE: 0,
  DEFLATE: 8,
});

export const ZIP_FLAGS = Object.freeze({
  ENCRYPTED: 0x0001,
  DATA_DESCRIPTOR: 0x0008,
  UTF8: 0x0800,
});

export const ZIP_ERROR_CODES = Object.freeze({
  E_CRC_MISMATCH: 'E_CRC_MISMATCH',
  E_PATH_TRAVERSAL: ERROR_CODES.E_PATH_TRAVERSAL,
  E_ARCHIVE_BOMB: ERROR_CODES.E_ARCHIVE_BOMB,
  E_MALFORMED_ZIP: ERROR_CODES.E_MALFORMED_ZIP,
  E_ENCRYPTED_BINARY: ERROR_CODES.E_ENCRYPTED_BINARY,
});

export const DEFAULT_ZIP_LIMITS = Object.freeze({
  maxEntries: 10_000,
  maxUncompressedBytes: 64 * 1024 * 1024, // 64 MiB
  maxEntryBytes: 64 * 1024 * 1024, // 64 MiB
  maxCompressionRatio: 100,
  ratioFloorBytes: 1024,
});

const TEXT_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const APK_SIG_BLOCK_MAGIC = TEXT_ENCODER.encode('APK Sig Block 42');
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const DETERMINISTIC_DEFAULT_MTIME = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));

// Code Page 437 Unicode table for high bytes 0x80..0xFF (PKWARE default when UTF-8 bit 11 is 0)
const CP437_HIGH =
  '\u00C7\u00FC\u00E9\u00E2\u00E4\u00E0\u00E5\u00E7\u00EA\u00EB\u00E8\u00EF\u00EE\u00EC\u00C4\u00C5' +
  '\u00C9\u00E6\u00C6\u00F4\u00F6\u00F2\u00FB\u00F9\u00FF\u00D6\u00DC\u00A2\u00A3\u00A5\u20A7\u0192' +
  '\u00E1\u00ED\u00F3\u00FA\u00F1\u00D1\u00AA\u00BA\u00BF\u2310\u00AC\u00BD\u00BC\u00A1\u00AB\u00BB' +
  '\u2591\u2592\u2593\u2502\u2524\u2561\u2562\u2556\u2555\u2563\u2551\u2557\u255D\u255C\u255B\u2510' +
  '\u2514\u2534\u252C\u251C\u2500\u253C\u255E\u255F\u255A\u2554\u2569\u2566\u2560\u2550\u256C\u2567' +
  '\u2568\u2564\u2565\u2559\u2558\u2552\u2553\u256B\u256A\u2518\u250C\u2588\u2584\u258C\u2590\u2580' +
  '\u03B1\u00DF\u0393\u03C0\u03A3\u03C3\u00B5\u03C4\u03A6\u0398\u03A9\u03B4\u221E\u03C6\u03B5\u2229' +
  '\u2261\u00B1\u2265\u2264\u2320\u2321\u00F7\u2248\u00B0\u2219\u00B7\u221A\u207F\u00B2\u25A0\u00A0';

function decodeCp437(bytes) {
  const len = bytes.byteLength;
  if (len === 0) return '';
  if (isAscii(bytes)) {
    return Buffer.from(bytes.buffer, bytes.byteOffset, len).toString('latin1');
  }
  const chars = new Array(len);
  for (let i = 0; i < len; i++) {
    const b = bytes[i];
    chars[i] = b < 0x80 ? String.fromCharCode(b) : CP437_HIGH[b - 0x80];
  }
  return chars.join('');
}

function decodeZipString(bytes, flags) {
  if (bytes.byteLength === 0) return '';
  if ((flags & ZIP_FLAGS.UTF8) !== 0) {
    return UTF8_DECODER.decode(bytes);
  }
  return decodeCp437(bytes);
}

function toZipBytes(input) {
  const bin = extractGenuineBytes(input);
  if (bin.detached) {
    throw new FormatError('ZIP input is unreadable or malformed (detached buffer)', {
      code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
      format: 'zip',
    });
  }
  if (bin.ok) {
    return bin.bytes;
  }
  throw new FormatError('ZIP input must be a Uint8Array, Buffer, ArrayBuffer, or ArrayBufferView', {
    code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
    format: 'zip',
  });
}

function safeBigIntToNumber(val, label, offset = null) {
  if (val < 0n || val > MAX_SAFE_BIGINT) {
    throw new FormatError(`ZIP64 field "${label}" exceeds safe integer range`, {
      code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
      format: 'zip',
      offset,
    });
  }
  return Number(val);
}

function isErrorInstance(err) {
  try {
    return err instanceof Error;
  } catch {
    return false;
  }
}

const MAX_CLONE_BIGINT_ABS = 1n << 4096n;
const MAX_DISPLAY_LENGTH = 256;
export const MAX_ZIP_PATH_DEPTH = 256;

function capDisplayString(str) {
  if (str.length > 65_536) return `[String(${str.length})]`;
  return str.length > MAX_DISPLAY_LENGTH ? `${str.slice(0, MAX_DISPLAY_LENGTH)}...` : str;
}

function safeDisplayValue(val) {
  if (val === null) return 'null';
  if (val === undefined) return 'undefined';
  const t = typeof val;
  if (t === 'string') return capDisplayString(val);
  if (t === 'number' || t === 'boolean') return String(val);
  if (t === 'bigint') {
    if (val > MAX_CLONE_BIGINT_ABS || val < -MAX_CLONE_BIGINT_ABS) {
      return '[BigInt(out-of-range)]';
    }
    return capDisplayString(val.toString(10));
  }
  if (t === 'symbol') {
    try {
      const desc = SYMBOL_DESCRIPTION_GET ? SYMBOL_DESCRIPTION_GET.call(val) : val.description;
      return desc === undefined ? 'Symbol()' : `Symbol(${capDisplayString(desc)})`;
    } catch {
      return 'Symbol()';
    }
  }
  if (t === 'function') return '[Function]';
  try {
    return Array.isArray(val) ? '[Array]' : '[Object]';
  } catch {
    return '[Unreadable]';
  }
}

function safeGetProp(obj, key, label) {
  try {
    return obj[key];
  } catch (err) {
    throw new FormatError(`Unreadable ${label} property "${key}"`, {
      code: ERROR_CODES.EINVAL,
      format: 'zip',
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
}

function normalizeReadableOptions(options, label) {
  if (options === undefined || options === null) return {};
  let isArr = false;
  try {
    isArr = Array.isArray(options);
  } catch (err) {
    throw new FormatError(`${label} must be a readable plain object`, {
      code: ERROR_CODES.EINVAL,
      format: 'zip',
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (typeof options !== 'object' || isArr) {
    throw new FormatError(`${label} must be a plain object`, {
      code: ERROR_CODES.EINVAL,
      format: 'zip',
    });
  }
  return options;
}

function resolveLimits(options = {}) {
  const opts = normalizeReadableOptions(options, 'ZIP options');
  const maxEntries = safeGetProp(opts, 'maxEntries', 'ZIP options');
  const maxUncompressedBytes = safeGetProp(opts, 'maxUncompressedBytes', 'ZIP options');
  const maxEntryBytes = safeGetProp(opts, 'maxEntryBytes', 'ZIP options');
  const maxCompressionRatio = safeGetProp(opts, 'maxCompressionRatio', 'ZIP options');
  const ratioFloorBytes = safeGetProp(opts, 'ratioFloorBytes', 'ZIP options');
  return {
    maxEntries:
      Number.isSafeInteger(maxEntries) && maxEntries >= 0
        ? maxEntries
        : DEFAULT_ZIP_LIMITS.maxEntries,
    maxUncompressedBytes:
      Number.isSafeInteger(maxUncompressedBytes) && maxUncompressedBytes >= 0
        ? maxUncompressedBytes
        : DEFAULT_ZIP_LIMITS.maxUncompressedBytes,
    maxEntryBytes:
      Number.isSafeInteger(maxEntryBytes) && maxEntryBytes >= 0
        ? maxEntryBytes
        : DEFAULT_ZIP_LIMITS.maxEntryBytes,
    maxCompressionRatio:
      typeof maxCompressionRatio === 'number' &&
      Number.isFinite(maxCompressionRatio) &&
      maxCompressionRatio > 0
        ? maxCompressionRatio
        : DEFAULT_ZIP_LIMITS.maxCompressionRatio,
    ratioFloorBytes:
      Number.isSafeInteger(ratioFloorBytes) && ratioFloorBytes >= 0
        ? ratioFloorBytes
        : DEFAULT_ZIP_LIMITS.ratioFloorBytes,
  };
}

function encodeDosDateTime(date) {
  let d = DETERMINISTIC_DEFAULT_MTIME;
  if (types.isDate(date) && !types.isProxy(date)) {
    try {
      const ms = Date.prototype.getTime.call(date);
      if (Number.isFinite(ms)) {
        d = new Date(ms);
      }
    } catch {
      d = DETERMINISTIC_DEFAULT_MTIME;
    }
  }
  const year = Math.max(1980, Math.min(2107, d.getUTCFullYear()));
  const month = d.getUTCMonth() + 1;
  const day = d.getUTCDate();
  const hours = d.getUTCHours();
  const minutes = d.getUTCMinutes();
  const seconds = Math.floor(d.getUTCSeconds() / 2);

  const dosDate = ((year - 1980) << 9) | (month << 5) | day;
  const dosTime = (hours << 11) | (minutes << 5) | seconds;
  return { dosDate: dosDate & 0xffff, dosTime: dosTime & 0xffff };
}

function decodeDosDateTime(dosDate, dosTime) {
  const year = ((dosDate >>> 9) & 0x7f) + 1980;
  const month = Math.max(1, Math.min(12, (dosDate >>> 5) & 0x0f));
  const day = Math.max(1, Math.min(31, dosDate & 0x1f));
  const hours = Math.min(23, (dosTime >>> 11) & 0x1f);
  const minutes = Math.min(59, (dosTime >>> 5) & 0x3f);
  const seconds = Math.min(59, (dosTime & 0x1f) * 2);
  return new Date(Date.UTC(year, month - 1, day, hours, minutes, seconds));
}

function hasApkSigningBlockAt(bytes, cdOffset) {
  if (cdOffset < APK_SIG_BLOCK_MAGIC.byteLength) return false;
  const start = cdOffset - APK_SIG_BLOCK_MAGIC.byteLength;
  for (let i = 0; i < APK_SIG_BLOCK_MAGIC.byteLength; i++) {
    if (bytes[start + i] !== APK_SIG_BLOCK_MAGIC[i]) return false;
  }
  return true;
}

/**
 * Validates and normalizes a ZIP entry path against ZIP-slip / path-traversal attacks.
 * Rejects `..`, leading `/` or `\`, Windows drive prefixes (`C:`), NUL, and control chars.
 */
function validateZipEntryNameInternal(name) {
  if (typeof name !== 'string' || name.length === 0) {
    throw new FormatError('ZIP entry name must be a non-empty string', {
      code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
      format: 'zip',
      details: { name: safeDisplayValue(name) },
    });
  }

  if (name.length > 0xffff) {
    const safeName = safeDisplayValue(name);
    throw new FormatError(`ZIP entry name exceeds 65535 characters: ${safeName}`, {
      code: ERROR_CODES.EINVAL,
      format: 'zip',
      details: { name: safeName, length: name.length },
    });
  }

  // Single-pass scan for control chars, backslashes, path segments, and segment depth (zero .split() allocation)
  const nameLen = name.length;
  let hasBackslash = false;
  let hasEmptySeg = false;
  let segStart = 0;
  let depth = 0;

  if (name.charCodeAt(0) === 0x2f || name.charCodeAt(0) === 0x5c) {
    // Preserve exact precedence: check for control characters first
    for (let i = 0; i < nameLen; i++) {
      const c = name.charCodeAt(i);
      if (c <= 0x1f || c === 0x7f) {
        const preview = capDisplayString(name);
        throw new FormatError(`ZIP entry name contains illegal control character: ${JSON.stringify(preview)}`, {
          code: ZIP_ERROR_CODES.E_PATH_TRAVERSAL,
          format: 'zip',
          details: { name: preview },
        });
      }
    }
    const safeName = safeDisplayValue(name);
    throw new FormatError(`ZIP entry name cannot be an absolute path: ${safeName}`, {
      code: ZIP_ERROR_CODES.E_PATH_TRAVERSAL,
      format: 'zip',
      details: { name: safeName },
    });
  }

  if (nameLen >= 2 && name.charCodeAt(1) === 0x3a) {
    const c0 = name.charCodeAt(0);
    if ((c0 >= 0x41 && c0 <= 0x5a) || (c0 >= 0x61 && c0 <= 0x7a)) {
      for (let i = 0; i < nameLen; i++) {
        const c = name.charCodeAt(i);
        if (c <= 0x1f || c === 0x7f) {
          const preview = capDisplayString(name);
          throw new FormatError(`ZIP entry name contains illegal control character: ${JSON.stringify(preview)}`, {
            code: ZIP_ERROR_CODES.E_PATH_TRAVERSAL,
            format: 'zip',
            details: { name: preview },
          });
        }
      }
      const safeName = safeDisplayValue(name);
      throw new FormatError(`ZIP entry name cannot contain a drive letter: ${safeName}`, {
        code: ZIP_ERROR_CODES.E_PATH_TRAVERSAL,
        format: 'zip',
        details: { name: safeName },
      });
    }
  }

  for (let i = 0; i <= nameLen; i++) {
    const ch = i < nameLen ? name.charCodeAt(i) : 0x2f;
    if (i < nameLen && (ch <= 0x1f || ch === 0x7f)) {
      const preview = capDisplayString(name);
      throw new FormatError(`ZIP entry name contains illegal control character: ${JSON.stringify(preview)}`, {
        code: ZIP_ERROR_CODES.E_PATH_TRAVERSAL,
        format: 'zip',
        details: { name: preview },
      });
    }
    if (ch === 0x2f || ch === 0x5c) {
      if (ch === 0x5c) hasBackslash = true;
      const segLen = i - segStart;
      if (segLen === 2 && name.charCodeAt(segStart) === 0x2e && name.charCodeAt(segStart + 1) === 0x2e) {
        const safeName = safeDisplayValue(name);
        throw new FormatError(`ZIP entry name contains parent directory traversal: ${safeName}`, {
          code: ZIP_ERROR_CODES.E_PATH_TRAVERSAL,
          format: 'zip',
          details: { name: safeName },
        });
      }
      if (segLen === 1 && name.charCodeAt(segStart) === 0x2e) {
        const safeName = safeDisplayValue(name);
        throw new FormatError(`ZIP entry name contains ambiguous dot segment: ${safeName}`, {
          code: ZIP_ERROR_CODES.E_PATH_TRAVERSAL,
          format: 'zip',
          details: { name: safeName },
        });
      }
      if (segLen === 0 && i < nameLen) {
        hasEmptySeg = true;
      } else if (segLen > 0) {
        depth += 1;
      }
      segStart = i + 1;
    }
  }

  if (hasEmptySeg) {
    const safeName = safeDisplayValue(name);
    throw new FormatError(`ZIP entry name contains empty path segment: ${safeName}`, {
      code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
      format: 'zip',
      details: { name: safeName },
    });
  }

  // Normalize safe path separators to POSIX '/'
  const normalized = hasBackslash ? name.replace(/\\/g, '/') : name;
  if (normalized === '/' || normalized.length === 0) {
    const safeName = safeDisplayValue(name);
    throw new FormatError(`Invalid ZIP entry name: ${safeName}`, {
      code: ZIP_ERROR_CODES.E_PATH_TRAVERSAL,
      format: 'zip',
      details: { name: safeName },
    });
  }
  return { normalized, depth };
}

export function validateZipEntryName(name) {
  return validateZipEntryNameInternal(name).normalized;
}

function parseZip64ExtraField(extraBytes, { needUncomp, needComp, needLfhOffset, needDiskStart }, offset) {
  const result = {
    uncompressedSize: null,
    compressedSize: null,
    localHeaderOffset: null,
    diskStart: null,
    found: false,
  };

  const reader = new BinaryReader(extraBytes, { littleEndian: true });
  while (reader.remaining >= 4) {
    const tag = reader.u16le();
    const fieldSize = reader.u16le();
    if (fieldSize > reader.remaining) {
      throw new FormatError('Truncated ZIP extra field', {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset,
      });
    }
    const fieldData = reader.bytes(fieldSize);
    if (tag === 0x0001) {
      result.found = true;
      const fr = new BinaryReader(fieldData, { littleEndian: true });
      if (needUncomp) {
        if (fr.remaining < 8) {
          throw new FormatError('Truncated ZIP64 extra field (uncompressedSize)', {
            code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
            format: 'zip',
            offset,
          });
        }
        result.uncompressedSize = safeBigIntToNumber(fr.u64le(), 'uncompressedSize', offset);
      }
      if (needComp) {
        if (fr.remaining < 8) {
          throw new FormatError('Truncated ZIP64 extra field (compressedSize)', {
            code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
            format: 'zip',
            offset,
          });
        }
        result.compressedSize = safeBigIntToNumber(fr.u64le(), 'compressedSize', offset);
      }
      if (needLfhOffset) {
        if (fr.remaining < 8) {
          throw new FormatError('Truncated ZIP64 extra field (localHeaderOffset)', {
            code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
            format: 'zip',
            offset,
          });
        }
        result.localHeaderOffset = safeBigIntToNumber(fr.u64le(), 'localHeaderOffset', offset);
      }
      if (needDiskStart) {
        if (fr.remaining < 4) {
          throw new FormatError('Truncated ZIP64 extra field (diskStart)', {
            code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
            format: 'zip',
            offset,
          });
        }
        result.diskStart = fr.u32le();
      }
      return result;
    }
  }

  return result;
}

function hasZip64ExtraTag(bytes, start, length) {
  let pos = start;
  const end = start + length;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  while (pos + 4 <= end) {
    const tag = view.getUint16(pos, true);
    const sz = view.getUint16(pos + 2, true);
    if (pos + 4 + sz > end) break;
    if (tag === 0x0001) return true;
    pos += 4 + sz;
  }
  return false;
}

function findEocd(bytes) {
  const len = bytes.byteLength;
  if (len < 22) {
    throw new FormatError('ZIP archive truncated: smaller than 22-byte EOCD', {
      code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
      format: 'zip',
      offset: 0,
    });
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const minPos = Math.max(0, len - 65557);

  for (let pos = len - 22; pos >= minPos; pos--) {
    if (
      bytes[pos] === 0x50 &&
      bytes[pos + 1] === 0x4b &&
      bytes[pos + 2] === 0x05 &&
      bytes[pos + 3] === 0x06
    ) {
      const commentLen = view.getUint16(pos + 20, true);
      if (pos + 22 + commentLen === len) {
        return {
          eocdOffset: pos,
          diskNumber: view.getUint16(pos + 4, true),
          cdStartDisk: view.getUint16(pos + 6, true),
          entriesOnDisk: view.getUint16(pos + 8, true),
          totalEntries: view.getUint16(pos + 10, true),
          cdSize: view.getUint32(pos + 12, true),
          cdOffset: view.getUint32(pos + 16, true),
          commentLen,
          comment: UTF8_DECODER.decode(bytes.subarray(pos + 22, pos + 22 + commentLen)),
        };
      }
    }
  }

  throw new FormatError('ZIP End of Central Directory (EOCD) signature not found', {
    code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
    format: 'zip',
    offset: Math.max(0, len - 22),
  });
}

function assertZipPathDepth(normalizedName, depth) {
  if (depth > MAX_ZIP_PATH_DEPTH) {
    const safeName = safeDisplayValue(normalizedName);
    throw new FormatError(
      `ZIP entry "${safeName}" exceeds maximum path depth (${MAX_ZIP_PATH_DEPTH})`,
      {
        code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
        format: 'zip',
        details: { name: safeName, maxDepth: MAX_ZIP_PATH_DEPTH },
      }
    );
  }
}

function compareZipStrippedPaths(a, b) {
  const sa = a.stripped;
  const sb = b.stripped;
  const len = sa.length < sb.length ? sa.length : sb.length;
  for (let i = 0; i < len; i += 1) {
    const ca = sa.charCodeAt(i);
    const cb = sb.charCodeAt(i);
    if (ca !== cb) {
      return (ca === 0x2f ? -1 : ca) - (cb === 0x2f ? -1 : cb);
    }
  }
  return sa.length - sb.length;
}

function checkNameCollisions(nameEntries) {
  if (nameEntries.length < 2) return;
  nameEntries.sort(compareZipStrippedPaths);
  for (let i = 1; i < nameEntries.length; i += 1) {
    const prev = nameEntries[i - 1];
    const cur = nameEntries[i];
    if (prev.stripped === cur.stripped) {
      const safeName = safeDisplayValue(cur.normalizedName);
      throw new FormatError(`Duplicate or conflicting ZIP entry name: ${safeName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        details: { name: safeName },
      });
    }
    if (
      !prev.isDirectory &&
      cur.stripped.length > prev.stripped.length &&
      cur.stripped.charCodeAt(prev.stripped.length) === 0x2f &&
      cur.stripped.startsWith(prev.stripped)
    ) {
      const safeName = safeDisplayValue(cur.normalizedName);
      const safeConflict = safeDisplayValue(prev.normalizedName);
      throw new FormatError(`Conflicting ZIP file and directory path: ${safeName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        details: { name: safeName, conflict: safeConflict },
      });
    }
  }
}

export function listZipEntries(buffer, options = {}) {
  const bytes = toZipBytes(buffer);
  const limits = resolveLimits(options);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const eocd = findEocd(bytes);
  let totalEntries = eocd.totalEntries;
  let cdSize = eocd.cdSize;
  let cdOffset = eocd.cdOffset;
  let diskNumber = eocd.diskNumber;
  let cdStartDisk = eocd.cdStartDisk;
  let eocdBoundary = eocd.eocdOffset;
  let isZip64 = false;

  // Check for ZIP64 EOCD Locator immediately before EOCD
  if (eocd.eocdOffset >= 20) {
    const locOffset = eocd.eocdOffset - 20;
    if (view.getUint32(locOffset, true) === ZIP_SIGNATURES.ZIP64_EOCD_LOCATOR) {
      const z64Disk = view.getUint32(locOffset + 4, true);
      const z64EocdOffsetBig = view.getBigUint64(locOffset + 8, true);
      const totalDisks = view.getUint32(locOffset + 16, true);

      if (z64Disk !== 0 || totalDisks > 1) {
        throw new FormatError('Multi-disk ZIP64 archives are not supported', {
          code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          format: 'zip',
          offset: locOffset,
        });
      }

      const z64EocdOffset = safeBigIntToNumber(z64EocdOffsetBig, 'zip64EocdOffset', locOffset);
      if (z64EocdOffset + 56 > locOffset) {
        throw new FormatError('ZIP64 EOCD record offset out of bounds', {
          code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          format: 'zip',
          offset: locOffset,
        });
      }
      if (view.getUint32(z64EocdOffset, true) !== ZIP_SIGNATURES.ZIP64_EOCD) {
        throw new FormatError('Invalid ZIP64 EOCD record signature', {
          code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          format: 'zip',
          offset: z64EocdOffset,
        });
      }

      const recSize = view.getBigUint64(z64EocdOffset + 4, true);
      if (recSize < 44n || BigInt(z64EocdOffset) + 12n + recSize > BigInt(locOffset)) {
        throw new FormatError('Invalid ZIP64 EOCD record size', {
          code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          format: 'zip',
          offset: z64EocdOffset,
        });
      }

      diskNumber = view.getUint32(z64EocdOffset + 16, true);
      cdStartDisk = view.getUint32(z64EocdOffset + 20, true);
      const entriesOnDisk64 = safeBigIntToNumber(view.getBigUint64(z64EocdOffset + 24, true), 'entriesOnDisk', z64EocdOffset);
      totalEntries = safeBigIntToNumber(view.getBigUint64(z64EocdOffset + 32, true), 'totalEntries', z64EocdOffset);
      cdSize = safeBigIntToNumber(view.getBigUint64(z64EocdOffset + 40, true), 'cdSize', z64EocdOffset);
      cdOffset = safeBigIntToNumber(view.getBigUint64(z64EocdOffset + 48, true), 'cdOffset', z64EocdOffset);

      if (entriesOnDisk64 !== totalEntries) {
        throw new FormatError('Multi-disk ZIP64 entry count mismatch', {
          code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          format: 'zip',
          offset: z64EocdOffset,
        });
      }
      eocdBoundary = z64EocdOffset;
      isZip64 = true;
    }
  }

  if (!isZip64) {
    if (eocd.cdSize === 0xffffffff || eocd.cdOffset === 0xffffffff || eocd.totalEntries === 0xffff) {
      throw new FormatError('ZIP64 sentinel in EOCD without valid ZIP64 EOCD locator', {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: eocd.eocdOffset,
      });
    }
    if (eocd.entriesOnDisk !== eocd.totalEntries) {
      throw new FormatError('Multi-disk ZIP archives are not supported', {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: eocd.eocdOffset,
      });
    }
  }

  if (diskNumber !== 0 || cdStartDisk !== 0) {
    throw new FormatError('Multi-disk ZIP archives are not supported', {
      code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
      format: 'zip',
      offset: eocd.eocdOffset,
    });
  }

  if (cdOffset < 0 || cdSize < 0 || cdOffset + cdSize > eocdBoundary) {
    throw new FormatError('ZIP Central Directory bounds exceed archive size', {
      code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
      format: 'zip',
      offset: cdOffset,
      details: { cdOffset, cdSize, eocdBoundary },
    });
  }

  if (totalEntries > limits.maxEntries) {
    throw new FormatError(`ZIP archive entry count (${totalEntries}) exceeds maxEntries (${limits.maxEntries})`, {
      code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
      format: 'zip',
      details: { totalEntries, maxEntries: limits.maxEntries },
    });
  }

  const hasApkSigningBlock = hasApkSigningBlockAt(bytes, cdOffset);
  const cdEnd = cdOffset + cdSize;
  let cursor = cdOffset;

  const zipBuf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entryList = [];
  const entriesByName = new Map();
  const nameEntries = [];
  let totalDeclaredUncompressed = 0;

  for (let i = 0; i < totalEntries; i++) {
    if (cursor + 46 > cdEnd) {
      throw new FormatError(`Truncated Central Directory header at entry #${i}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: cursor,
      });
    }
    if (view.getUint32(cursor, true) !== ZIP_SIGNATURES.CENTRAL_DIR_HEADER) {
      throw new FormatError(`Invalid Central Directory header signature at entry #${i}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: cursor,
      });
    }

    const versionMadeBy = view.getUint16(cursor + 4, true);
    const versionNeeded = view.getUint16(cursor + 6, true);
    const flags = view.getUint16(cursor + 8, true);
    const method = view.getUint16(cursor + 10, true);
    const dosTime = view.getUint16(cursor + 12, true);
    const dosDate = view.getUint16(cursor + 14, true);
    const entryCrc = view.getUint32(cursor + 16, true);
    const compSize32 = view.getUint32(cursor + 20, true);
    const uncompSize32 = view.getUint32(cursor + 24, true);
    const nameLen = view.getUint16(cursor + 28, true);
    const extraLen = view.getUint16(cursor + 30, true);
    const commentLen = view.getUint16(cursor + 32, true);
    const diskStart16 = view.getUint16(cursor + 34, true);
    const internalAttr = view.getUint16(cursor + 36, true);
    const externalAttr = view.getUint32(cursor + 38, true);
    const lfhOffset32 = view.getUint32(cursor + 42, true);

    const recordEnd = cursor + 46 + nameLen + extraLen + commentLen;
    if (recordEnd > cdEnd) {
      throw new FormatError(`Central Directory entry #${i} overflows Central Directory bounds`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: cursor,
      });
    }

    const nameBytes = bytes.subarray(cursor + 46, cursor + 46 + nameLen);
    const extraBytes = bytes.subarray(cursor + 46 + nameLen, cursor + 46 + nameLen + extraLen);

    const rawName = decodeZipString(nameBytes, flags);
    const { normalized: normalizedName, depth: pathDepth } = validateZipEntryNameInternal(rawName);
    const comment =
      commentLen === 0
        ? ''
        : decodeZipString(bytes.subarray(cursor + 46 + nameLen + extraLen, recordEnd), flags);

    if ((flags & ZIP_FLAGS.ENCRYPTED) !== 0) {
      throw new FormatError(`Encrypted ZIP entry is not supported: ${normalizedName}`, {
        code: ZIP_ERROR_CODES.E_ENCRYPTED_BINARY,
        format: 'zip',
        offset: cursor,
        details: { name: normalizedName },
      });
    }

    if (method !== ZIP_METHODS.STORE && method !== ZIP_METHODS.DEFLATE) {
      throw new FormatError(`Unsupported ZIP compression method ${method} for entry: ${normalizedName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: cursor,
        details: { name: normalizedName, method },
      });
    }

    let compressedSize = compSize32;
    let uncompressedSize = uncompSize32;
    let localHeaderOffset = lfhOffset32;
    let diskStart = diskStart16;

    const needUncomp = uncompSize32 === 0xffffffff;
    const needComp = compSize32 === 0xffffffff;
    const needLfhOffset = lfhOffset32 === 0xffffffff;
    const needDiskStart = diskStart16 === 0xffff;

    if (needUncomp || needComp || needLfhOffset || needDiskStart) {
      const z64 = parseZip64ExtraField(
        extraBytes,
        { needUncomp, needComp, needLfhOffset, needDiskStart },
        cursor
      );
      if (!z64.found) {
        throw new FormatError(`Missing ZIP64 extra field (0x0001) for entry: ${normalizedName}`, {
          code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          format: 'zip',
          offset: cursor,
          details: { name: normalizedName },
        });
      }
      if (needUncomp) uncompressedSize = z64.uncompressedSize;
      if (needComp) compressedSize = z64.compressedSize;
      if (needLfhOffset) localHeaderOffset = z64.localHeaderOffset;
      if (needDiskStart) diskStart = z64.diskStart;
      isZip64 = true;
    }

    if (diskStart !== 0) {
      throw new FormatError(`Multi-disk ZIP entry not supported: ${normalizedName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: cursor,
      });
    }

    if (method === ZIP_METHODS.STORE && compressedSize !== uncompressedSize) {
      throw new FormatError(
        `STORE entry size mismatch for ${normalizedName}: compressed=${compressedSize}, uncompressed=${uncompressedSize}`,
        {
          code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          format: 'zip',
          offset: cursor,
        }
      );
    }

    // Validate Local File Header (LFH)
    if (localHeaderOffset < 0 || localHeaderOffset + 30 > cdOffset) {
      throw new FormatError(`Local File Header offset out of bounds for ${normalizedName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: localHeaderOffset,
      });
    }
    if (view.getUint32(localHeaderOffset, true) !== ZIP_SIGNATURES.LOCAL_FILE_HEADER) {
      throw new FormatError(`Invalid Local File Header signature for ${normalizedName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: localHeaderOffset,
      });
    }

    const lfhFlags = view.getUint16(localHeaderOffset + 6, true);
    const lfhMethod = view.getUint16(localHeaderOffset + 8, true);
    const lfhComp32 = view.getUint32(localHeaderOffset + 18, true);
    const lfhUncomp32 = view.getUint32(localHeaderOffset + 22, true);
    const lfhNameLen = view.getUint16(localHeaderOffset + 26, true);
    const lfhExtraLen = view.getUint16(localHeaderOffset + 28, true);

    if (((flags | lfhFlags) & ZIP_FLAGS.ENCRYPTED) !== 0) {
      throw new FormatError(`Encrypted ZIP entry is not supported: ${normalizedName}`, {
        code: ZIP_ERROR_CODES.E_ENCRYPTED_BINARY,
        format: 'zip',
        offset: localHeaderOffset,
        details: { name: normalizedName },
      });
    }

    if (lfhMethod !== method) {
      throw new FormatError(`LFH/CDFH compression method mismatch for ${normalizedName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: localHeaderOffset,
      });
    }

    const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
    if (dataStart > cdOffset) {
      throw new FormatError(`Local File Header variable fields exceed Central Directory offset for ${normalizedName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: localHeaderOffset,
      });
    }

    if (
      (lfhComp32 === 0xffffffff && lfhUncomp32 === 0xffffffff) ||
      (lfhExtraLen >= 4 && hasZip64ExtraTag(bytes, localHeaderOffset + 30 + lfhNameLen, lfhExtraLen)) ||
      (extraLen >= 4 && hasZip64ExtraTag(bytes, cursor + 46 + nameLen, extraLen))
    ) {
      isZip64 = true;
    }

    const lfhNameStart = localHeaderOffset + 30;
    const lfhBytesMatch =
      lfhNameLen === nameLen &&
      ((lfhFlags ^ flags) & ZIP_FLAGS.UTF8) === 0 &&
      zipBuf.compare(zipBuf, lfhNameStart, lfhNameStart + nameLen, cursor + 46, cursor + 46 + nameLen) === 0;
    if (!lfhBytesMatch) {
      const lfhRawName = decodeZipString(
        bytes.subarray(lfhNameStart, lfhNameStart + lfhNameLen),
        lfhFlags
      );
      const lfhNormName = validateZipEntryName(lfhRawName);
      if (lfhNormName !== normalizedName) {
        throw new FormatError(
          `LFH/CDFH filename mismatch: LFH="${safeDisplayValue(lfhNormName)}", CDFH="${safeDisplayValue(normalizedName)}"`,
          {
            code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
            format: 'zip',
            offset: localHeaderOffset,
          }
        );
      }
    }

    const dataEnd = dataStart + compressedSize;
    if (dataEnd > cdOffset) {
      throw new FormatError(`Compressed entry data exceeds Central Directory offset for ${normalizedName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        offset: dataStart,
        details: { name: normalizedName, dataStart, compressedSize, cdOffset },
      });
    }

    const isDirectory = normalizedName.endsWith('/');
    assertZipPathDepth(normalizedName, pathDepth);
    if (entriesByName.has(normalizedName)) {
      const safeName = safeDisplayValue(normalizedName);
      throw new FormatError(`Duplicate or conflicting ZIP entry name: ${safeName}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        details: { name: safeName },
      });
    }
    nameEntries.push({
      stripped: isDirectory ? normalizedName.slice(0, -1) : normalizedName,
      normalizedName,
      isDirectory,
    });

    // Declared ZIP-bomb defenses enforced eagerly during directory listing (before extraction)
    if (uncompressedSize > limits.maxEntryBytes) {
      throw new FormatError(
        `ZIP entry "${normalizedName}" size (${uncompressedSize}) exceeds maxEntryBytes (${limits.maxEntryBytes})`,
        {
          code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
          format: 'zip',
          offset: cursor,
          details: { name: normalizedName, uncompressedSize, maxEntryBytes: limits.maxEntryBytes },
        }
      );
    }
    if (uncompressedSize > limits.maxUncompressedBytes - totalDeclaredUncompressed) {
      throw new FormatError(
        `ZIP archive total uncompressed size exceeds maxUncompressedBytes (${limits.maxUncompressedBytes})`,
        {
          code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
          format: 'zip',
          offset: cursor,
          details: {
            name: normalizedName,
            totalDeclaredUncompressed: totalDeclaredUncompressed + uncompressedSize,
            maxUncompressedBytes: limits.maxUncompressedBytes,
          },
        }
      );
    }
    totalDeclaredUncompressed += uncompressedSize;

    if (method === ZIP_METHODS.DEFLATE && uncompressedSize > limits.ratioFloorBytes) {
      if (compressedSize === 0 || uncompressedSize / compressedSize > limits.maxCompressionRatio) {
        throw new FormatError(
          `ZIP entry "${normalizedName}" exceeds maxCompressionRatio (${limits.maxCompressionRatio}:1)`,
          {
            code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
            format: 'zip',
            offset: cursor,
            details: {
              name: normalizedName,
              compressedSize,
              uncompressedSize,
              maxCompressionRatio: limits.maxCompressionRatio,
            },
          }
        );
      }
    }

    const meta = {
      name: normalizedName,
      rawName,
      isDirectory,
      method,
      flags,
      hasDataDescriptor: ((flags | lfhFlags) & ZIP_FLAGS.DATA_DESCRIPTOR) !== 0,
      isUtf8: (flags & ZIP_FLAGS.UTF8) !== 0,
      crc32: entryCrc >>> 0,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
      dataStart,
      dataEnd,
      versionMadeBy,
      versionNeeded,
      internalAttr,
      externalAttr,
      mtime: decodeDosDateTime(dosDate, dosTime),
      comment,
    };

    entryList.push(meta);
    entriesByName.set(normalizedName, meta);
    cursor = recordEnd;
  }

  // Zero-Trie O(N log N) sorted-adjacent duplicate and file/directory collision check
  checkNameCollisions(nameEntries);

  // Overlapping entry byte range defense (classic ZIP-bomb / quine technique)
  const byOffset = [...entryList].sort((a, b) => a.localHeaderOffset - b.localHeaderOffset);
  for (let i = 1; i < byOffset.length; i++) {
    if (byOffset[i].localHeaderOffset < byOffset[i - 1].dataEnd) {
      throw new FormatError(
        `Overlapping ZIP entry byte ranges detected between "${byOffset[i - 1].name}" and "${byOffset[i].name}"`,
        {
          code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
          format: 'zip',
          offset: byOffset[i].localHeaderOffset,
        }
      );
    }
  }

  return {
    entries: entriesByName,
    entryList,
    comment: eocd.comment,
    isZip64,
    hasApkSigningBlock,
    centralDirOffset: cdOffset,
    centralDirSize: cdSize,
    eocdOffset: eocd.eocdOffset,
  };
}

function extractEntryInternal(bytes, entry, limits, remainingBudget) {
  if (entry.isDirectory) {
    if (entry.uncompressedSize !== 0) {
      throw new FormatError(`Directory ZIP entry "${safeDisplayValue(entry.name)}" has non-zero size`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
      });
    }
    return new Uint8Array(0);
  }

  if (entry.uncompressedSize > limits.maxEntryBytes) {
    const safeName = safeDisplayValue(entry.name);
    throw new FormatError(
      `ZIP entry "${safeName}" size (${entry.uncompressedSize}) exceeds maxEntryBytes (${limits.maxEntryBytes})`,
      {
        code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
        format: 'zip',
        details: { name: safeName, uncompressedSize: entry.uncompressedSize, maxEntryBytes: limits.maxEntryBytes },
      }
    );
  }

  if (entry.uncompressedSize > remainingBudget) {
    const safeName = safeDisplayValue(entry.name);
    throw new FormatError(
      `ZIP archive total uncompressed size exceeds maxUncompressedBytes (${limits.maxUncompressedBytes})`,
      {
        code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
        format: 'zip',
        details: { name: safeName, maxUncompressedBytes: limits.maxUncompressedBytes },
      }
    );
  }

  if (entry.method === ZIP_METHODS.DEFLATE && entry.uncompressedSize > limits.ratioFloorBytes) {
    if (entry.compressedSize === 0 || entry.uncompressedSize / entry.compressedSize > limits.maxCompressionRatio) {
      const safeName = safeDisplayValue(entry.name);
      throw new FormatError(
        `ZIP entry "${safeName}" exceeds maxCompressionRatio (${limits.maxCompressionRatio}:1)`,
        {
          code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
          format: 'zip',
          details: {
            name: safeName,
            compressedSize: entry.compressedSize,
            uncompressedSize: entry.uncompressedSize,
            maxCompressionRatio: limits.maxCompressionRatio,
          },
        }
      );
    }
  }

  const compressedSlice = bytes.subarray(entry.dataStart, entry.dataEnd);
  let out;

  if (entry.method === ZIP_METHODS.STORE) {
    out = compressedSlice.slice();
    if (out.byteLength !== entry.uncompressedSize) {
      throw new FormatError(`STORE entry "${safeDisplayValue(entry.name)}" length mismatch`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
      });
    }
  } else if (entry.method === ZIP_METHODS.DEFLATE) {
    const ratioCap =
      entry.compressedSize === 0
        ? limits.ratioFloorBytes
        : Math.max(limits.ratioFloorBytes, Math.floor(entry.compressedSize * limits.maxCompressionRatio));
    const hardCap = Math.min(limits.maxEntryBytes, remainingBudget, ratioCap);

    // Node 24 requires maxOutputLength >= 1
    const maxOutputLength = Math.max(1, hardCap);
    let inflated;
    try {
      inflated = zlib.inflateRawSync(compressedSlice, { maxOutputLength });
    } catch (err) {
      const safeName = safeDisplayValue(entry.name);
      if (err?.code === 'ERR_BUFFER_TOO_LARGE') {
        throw new FormatError(
          `ZIP entry "${safeName}" decompressed stream exceeded safe memory/ratio cap (${hardCap} bytes)`,
          {
            code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
            format: 'zip',
            details: { name: safeName, cap: hardCap },
            cause: err,
          }
        );
      }
      throw new FormatError(`Failed to inflate ZIP entry "${safeName}": ${safeDisplayValue(err?.message ?? err)}`, {
        code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
        format: 'zip',
        details: { name: safeName },
        cause: err,
      });
    }

    if (inflated.byteLength > entry.uncompressedSize) {
      const safeName = safeDisplayValue(entry.name);
      throw new FormatError(
        `ZIP entry "${safeName}" decompressed to ${inflated.byteLength} bytes, exceeding declared ${entry.uncompressedSize} bytes`,
        {
          code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
          format: 'zip',
          details: { name: safeName, declared: entry.uncompressedSize, actual: inflated.byteLength },
        }
      );
    }
    if (inflated.byteLength < entry.uncompressedSize) {
      const safeName = safeDisplayValue(entry.name);
      throw new FormatError(
        `ZIP entry "${safeName}" truncated: decompressed ${inflated.byteLength} < declared ${entry.uncompressedSize} bytes`,
        {
          code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          format: 'zip',
          details: { name: safeName, declared: entry.uncompressedSize, actual: inflated.byteLength },
        }
      );
    }
    if (inflated.byteLength > hardCap) {
      throw new FormatError(`ZIP entry "${safeDisplayValue(entry.name)}" exceeded decompressed cap (${hardCap})`, {
        code: ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
        format: 'zip',
      });
    }
    out = new Uint8Array(inflated.buffer, inflated.byteOffset, inflated.byteLength).slice();
  } else {
    throw new FormatError(`Unsupported ZIP compression method: ${safeDisplayValue(entry.method)}`, {
      code: ZIP_ERROR_CODES.E_MALFORMED_ZIP,
      format: 'zip',
    });
  }

  // Strict IEEE CRC-32 validation
  const actualCrc = crc32(out);
  if (actualCrc !== entry.crc32) {
    const safeName = safeDisplayValue(entry.name);
    const expectedHex =
      typeof entry.crc32 === 'number' && Number.isFinite(entry.crc32)
        ? (entry.crc32 >>> 0).toString(16).padStart(8, '0')
        : safeDisplayValue(entry.crc32);
    throw new FormatError(
      `CRC-32 mismatch for ZIP entry "${safeName}": expected 0x${expectedHex}, actual 0x${actualCrc.toString(16).padStart(8, '0')}`,
      {
        code: ZIP_ERROR_CODES.E_CRC_MISMATCH,
        format: 'zip',
        details: { name: safeName, expected: entry.crc32, actual: actualCrc },
      }
    );
  }

  return out;
}

export function extractZipEntry(buffer, entryOrName, options = {}) {
  const bytes = toZipBytes(buffer);
  const limits = resolveLimits(options);
  let entry = entryOrName;

  if (typeof entryOrName === 'string') {
    const index = listZipEntries(bytes, limits);
    const normalized = validateZipEntryName(entryOrName);
    entry = index.entries.get(normalized);
    if (!entry) {
      const safeName = safeDisplayValue(entryOrName);
      throw new FormatError(`ZIP entry not found: ${safeName}`, {
        code: ERROR_CODES.ENOENT,
        format: 'zip',
        details: { name: safeName },
      });
    }
  } else {
    let entryIsArr = false;
    try {
      entryIsArr = Array.isArray(entry);
    } catch (err) {
      throw new FormatError('extractZipEntry received an unreadable ZipEntryMeta object', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (!entry || typeof entry !== 'object' || entryIsArr) {
      throw new FormatError('extractZipEntry requires an entry name or ZipEntryMeta object', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }
    const name = safeGetProp(entry, 'name', 'ZipEntryMeta');
    if (typeof name !== 'string' || name.length === 0) {
      throw new FormatError('extractZipEntry requires an entry name or ZipEntryMeta object', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }
    const isDirectory = Boolean(safeGetProp(entry, 'isDirectory', 'ZipEntryMeta'));
    const uncompressedSize = safeGetProp(entry, 'uncompressedSize', 'ZipEntryMeta');
    const compressedSize = safeGetProp(entry, 'compressedSize', 'ZipEntryMeta');
    const method = safeGetProp(entry, 'method', 'ZipEntryMeta');
    const dataStart = safeGetProp(entry, 'dataStart', 'ZipEntryMeta');
    const dataEnd = safeGetProp(entry, 'dataEnd', 'ZipEntryMeta');
    const entryCrc = safeGetProp(entry, 'crc32', 'ZipEntryMeta');
    if (
      !Number.isSafeInteger(uncompressedSize) ||
      uncompressedSize < 0 ||
      (!isDirectory &&
        (!Number.isSafeInteger(compressedSize) ||
          compressedSize < 0 ||
          !Number.isSafeInteger(dataStart) ||
          dataStart < 0 ||
          !Number.isSafeInteger(dataEnd) ||
          dataEnd < dataStart ||
          dataEnd > bytes.byteLength))
    ) {
      throw new FormatError('Invalid ZipEntryMeta bounds or sizes', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }
    entry = {
      name,
      isDirectory,
      uncompressedSize,
      compressedSize,
      method,
      dataStart,
      dataEnd,
      crc32: entryCrc,
    };
  }

  return extractEntryInternal(bytes, entry, limits, limits.maxUncompressedBytes);
}

export function readZip(buffer, options = {}) {
  const bytes = toZipBytes(buffer);
  const limits = resolveLimits(options);
  const index = listZipEntries(bytes, limits);

  const entries = new Map();
  let totalUncompressedBytes = 0;

  for (const meta of index.entryList) {
    const remainingBudget = limits.maxUncompressedBytes - totalUncompressedBytes;
    const data = extractEntryInternal(bytes, meta, limits, remainingBudget);
    totalUncompressedBytes += data.byteLength;
    entries.set(meta.name, { ...meta, data });
  }

  return {
    entries,
    entryList: index.entryList,
    comment: index.comment,
    isZip64: index.isZip64,
    hasApkSigningBlock: index.hasApkSigningBlock,
    totalUncompressedBytes,
    get(name) {
      const rec = entries.get(name);
      return rec ? { ...rec, data: rec.data.slice() } : null;
    },
    has(name) {
      return entries.has(name);
    },
    readBytes(name) {
      const rec = entries.get(name);
      return rec ? rec.data.slice() : null;
    },
    readText(name) {
      const rec = entries.get(name);
      return rec ? UTF8_DECODER.decode(rec.data) : null;
    },
  };
}

function normalizeCreateEntries(entries) {
  let isArr = false;
  try {
    isArr = Array.isArray(entries);
  } catch (err) {
    throw new FormatError('createZip entries object is unreadable', {
      code: ERROR_CODES.EINVAL,
      format: 'zip',
      cause: isErrorInstance(err) ? err : undefined,
    });
  }
  if (isArr) {
    let len;
    try {
      len = entries.length;
    } catch (err) {
      throw new FormatError('createZip entries array length is unreadable', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (
      typeof len !== 'number' ||
      !Number.isSafeInteger(len) ||
      len < 0 ||
      len > 0xffffffff ||
      len > 100_000
    ) {
      throw new FormatError('Invalid createZip entries array length', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }
    const out = [];
    for (let i = 0; i < len; i++) {
      let elem;
      try {
        elem = entries[i];
      } catch (err) {
        throw new FormatError(`Unreadable createZip entry at index ${i}`, {
          code: ERROR_CODES.EINVAL,
          format: 'zip',
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
      out.push(elem);
    }
    return out;
  }
  if (entries && typeof entries === 'object') {
    if (
      types.isProxy(entries) ||
      types.isBoxedPrimitive(entries) ||
      types.isTypedArray(entries) ||
      types.isArrayBuffer(entries) ||
      types.isDataView(entries) ||
      types.isSharedArrayBuffer?.(entries) ||
      types.isDate(entries)
    ) {
      throw new FormatError('createZip entries must be an Array or plain Object', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }
    let keys;
    try {
      keys = Object.keys(entries);
    } catch (err) {
      throw new FormatError('createZip entries object is unreadable', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (keys.length > 100_000) {
      throw new FormatError('createZip entries object exceeds maximum entry count', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }
    const out = [];
    for (const name of keys) {
      let data;
      try {
        data = entries[name];
      } catch (err) {
        throw new FormatError(`Unreadable createZip entry "${safeDisplayValue(name)}"`, {
          code: ERROR_CODES.EINVAL,
          format: 'zip',
          cause: isErrorInstance(err) ? err : undefined,
        });
      }
      out.push({ name, data });
    }
    return out;
  }
  throw new FormatError('createZip entries must be an Array or plain Object', {
    code: ERROR_CODES.EINVAL,
    format: 'zip',
  });
}

function toEntryRawBytes(data) {
  if (data === null || data === undefined) return new Uint8Array(0);
  if (typeof data === 'string') return TEXT_ENCODER.encode(data);
  const bin = extractGenuineBytes(data);
  if (bin.detached) {
    throw new FormatError('ZIP entry data is unreadable (detached buffer)', {
      code: ERROR_CODES.EINVAL,
      format: 'zip',
    });
  }
  if (bin.ok) return bin.bytes;
  throw new FormatError('ZIP entry data must be a string, Uint8Array, Buffer, ArrayBuffer, or null', {
    code: ERROR_CODES.EINVAL,
    format: 'zip',
  });
}

function toCommentBytes(comment, label) {
  if (comment === null || comment === undefined) return new Uint8Array(0);
  let out = null;
  if (typeof comment === 'string') {
    if (comment.length > 0xffff) {
      throw new FormatError(`${label} exceeds 65535 bytes`, {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }
    out = comment.length > 0 ? TEXT_ENCODER.encode(comment) : new Uint8Array(0);
  } else {
    const bin = extractGenuineBytes(comment);
    if (bin.detached) {
      throw new FormatError(`${label} is unreadable (detached buffer)`, {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }
    if (bin.ok) {
      out = bin.bytes;
    }
  }
  if (!out) {
    throw new FormatError(`${label} must be a string, Uint8Array, ArrayBuffer, or ArrayBufferView`, {
      code: ERROR_CODES.EINVAL,
      format: 'zip',
    });
  }
  if (out.byteLength > 0xffff) {
    throw new FormatError(`${label} exceeds 65535 bytes`, {
      code: ERROR_CODES.EINVAL,
      format: 'zip',
    });
  }
  return out;
}

export function createZip(entries, options = {}) {
  const rawList = normalizeCreateEntries(entries);
  const optsObj = normalizeReadableOptions(options, 'createZip options');
  const forceZip64 = Boolean(safeGetProp(optsObj, 'zip64', 'createZip options'));
  const rawArchiveComment = safeGetProp(optsObj, 'comment', 'createZip options');
  const rawLevel = safeGetProp(optsObj, 'level', 'createZip options');
  const archiveCommentBytes = toCommentBytes(rawArchiveComment, 'ZIP archive comment');
  let compressionLevel = zlib.constants.Z_DEFAULT_COMPRESSION;
  if (rawLevel !== undefined && rawLevel !== null) {
    if (typeof rawLevel !== 'number' || !Number.isSafeInteger(rawLevel) || rawLevel < -1 || rawLevel > 9) {
      throw new FormatError(`Invalid ZIP compression level: ${safeDisplayValue(rawLevel)}`, {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }
    compressionLevel = rawLevel;
  }

  const writer = new BinaryWriter({ initialCapacity: 4096, littleEndian: true });
  const records = [];
  const nameEntries = [];
  const stagedEntries = [];

  for (const item of rawList) {
    let itemIsArr = false;
    try {
      itemIsArr = Array.isArray(item);
    } catch (err) {
      throw new FormatError('Each ZIP entry must be a readable object with { name, data }', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
        cause: isErrorInstance(err) ? err : undefined,
      });
    }
    if (!item || typeof item !== 'object' || itemIsArr) {
      throw new FormatError('Each ZIP entry must be an object with { name, data }', {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }

    const rawName = safeGetProp(item, 'name', 'ZIP entry');
    const rawIsDirectory = safeGetProp(item, 'isDirectory', 'ZIP entry');
    const rawComment = safeGetProp(item, 'comment', 'ZIP entry');
    const rawData = safeGetProp(item, 'data', 'ZIP entry');
    const rawMethod = safeGetProp(item, 'method', 'ZIP entry');
    const rawCompress = safeGetProp(item, 'compress', 'ZIP entry');
    const rawMtime = safeGetProp(item, 'mtime', 'ZIP entry');

    const parsedName = validateZipEntryNameInternal(rawName);
    let normalizedName = parsedName.normalized;
    const isDirectory = Boolean(rawIsDirectory) || normalizedName.endsWith('/');
    if (isDirectory && !normalizedName.endsWith('/')) {
      normalizedName = `${normalizedName}/`;
    }
    assertZipPathDepth(normalizedName, parsedName.depth);
    nameEntries.push({
      stripped: isDirectory ? normalizedName.slice(0, -1) : normalizedName,
      normalizedName,
      isDirectory,
    });
    stagedEntries.push({
      normalizedName,
      isDirectory,
      rawComment,
      rawData,
      rawMethod,
      rawCompress,
      rawMtime,
    });
  }

  checkNameCollisions(nameEntries);

  for (const staged of stagedEntries) {
    const {
      normalizedName,
      isDirectory,
      rawComment,
      rawData,
      rawMethod,
      rawCompress,
      rawMtime,
    } = staged;

    const nameBytes = TEXT_ENCODER.encode(normalizedName);
    if (nameBytes.byteLength > 0xffff) {
      throw new FormatError(`ZIP entry name exceeds 65535 bytes: ${safeDisplayValue(normalizedName)}`, {
        code: ERROR_CODES.EINVAL,
        format: 'zip',
      });
    }

    const entryCommentBytes = toCommentBytes(rawComment, `ZIP entry comment for "${safeDisplayValue(normalizedName)}"`);

    const rawBytes = isDirectory ? new Uint8Array(0) : toEntryRawBytes(rawData);
    let method;
    if (isDirectory) {
      method = ZIP_METHODS.STORE;
    } else if (rawMethod !== undefined && rawMethod !== null) {
      if (rawMethod !== ZIP_METHODS.STORE && rawMethod !== ZIP_METHODS.DEFLATE) {
        throw new FormatError(`Unsupported ZIP compression method: ${safeDisplayValue(rawMethod)}`, {
          code: ERROR_CODES.EINVAL,
          format: 'zip',
        });
      }
      method = rawMethod;
    } else if (rawCompress === false || rawBytes.byteLength === 0) {
      method = ZIP_METHODS.STORE;
    } else {
      method = ZIP_METHODS.DEFLATE;
    }

    const payloadBytes =
      method === ZIP_METHODS.DEFLATE
        ? zlib.deflateRawSync(rawBytes, { level: compressionLevel })
        : rawBytes;
    const entryCrc = crc32(rawBytes);
    const flags = ZIP_FLAGS.UTF8;
    const { dosDate, dosTime } = encodeDosDateTime(rawMtime);

    const lfhOffset = writer.length;
    const uncompSize = rawBytes.byteLength;
    const compSize = payloadBytes.byteLength;

    const needLfhZip64 = forceZip64 || uncompSize >= 0xffffffff || compSize >= 0xffffffff;
    const needCdZip64 = needLfhZip64 || lfhOffset >= 0xffffffff;

    let lfhExtra = new Uint8Array(0);
    if (needLfhZip64) {
      const ew = new BinaryWriter({ initialCapacity: 20, littleEndian: true });
      ew.u16le(0x0001).u16le(16).u64le(BigInt(uncompSize)).u64le(BigInt(compSize));
      lfhExtra = ew.toUint8Array();
    }

    // Local File Header (30 bytes + name + extra)
    writer
      .u32le(ZIP_SIGNATURES.LOCAL_FILE_HEADER)
      .u16le(needLfhZip64 ? 45 : 20)
      .u16le(flags)
      .u16le(method)
      .u16le(dosTime)
      .u16le(dosDate)
      .u32le(entryCrc)
      .u32le(needLfhZip64 ? 0xffffffff : compSize)
      .u32le(needLfhZip64 ? 0xffffffff : uncompSize)
      .u16le(nameBytes.byteLength)
      .u16le(lfhExtra.byteLength)
      .bytes(nameBytes)
      .bytes(lfhExtra)
      .bytes(payloadBytes);

    const externalAttr = isDirectory
      ? ((0o040755 << 16) | 0x10) >>> 0
      : ((0o100644 << 16) >>> 0);

    records.push({
      nameBytes,
      entryCommentBytes,
      flags,
      method,
      dosTime,
      dosDate,
      entryCrc,
      compSize,
      uncompSize,
      lfhOffset,
      needCdZip64,
      externalAttr,
    });
  }

  // Central Directory
  const cdOffset = writer.length;
  for (const rec of records) {
    const useZ64Uncomp = forceZip64 || rec.uncompSize >= 0xffffffff;
    const useZ64Comp = forceZip64 || rec.compSize >= 0xffffffff;
    const useZ64Offset = forceZip64 || rec.lfhOffset >= 0xffffffff;

    let cdExtra = new Uint8Array(0);
    if (useZ64Uncomp || useZ64Comp || useZ64Offset) {
      const payloadSize = (useZ64Uncomp ? 8 : 0) + (useZ64Comp ? 8 : 0) + (useZ64Offset ? 8 : 0);
      const ew = new BinaryWriter({ initialCapacity: 4 + payloadSize, littleEndian: true });
      ew.u16le(0x0001).u16le(payloadSize);
      if (useZ64Uncomp) ew.u64le(BigInt(rec.uncompSize));
      if (useZ64Comp) ew.u64le(BigInt(rec.compSize));
      if (useZ64Offset) ew.u64le(BigInt(rec.lfhOffset));
      cdExtra = ew.toUint8Array();
    }

    const verNeeded = rec.needCdZip64 ? 45 : 20;
    const verMadeBy = (3 << 8) | verNeeded; // UNIX creator

    writer
      .u32le(ZIP_SIGNATURES.CENTRAL_DIR_HEADER)
      .u16le(verMadeBy)
      .u16le(verNeeded)
      .u16le(rec.flags)
      .u16le(rec.method)
      .u16le(rec.dosTime)
      .u16le(rec.dosDate)
      .u32le(rec.entryCrc)
      .u32le(useZ64Comp ? 0xffffffff : rec.compSize)
      .u32le(useZ64Uncomp ? 0xffffffff : rec.uncompSize)
      .u16le(rec.nameBytes.byteLength)
      .u16le(cdExtra.byteLength)
      .u16le(rec.entryCommentBytes.byteLength)
      .u16le(0) // disk number start
      .u16le(0) // internal file attributes
      .u32le(rec.externalAttr)
      .u32le(useZ64Offset ? 0xffffffff : rec.lfhOffset)
      .bytes(rec.nameBytes)
      .bytes(cdExtra)
      .bytes(rec.entryCommentBytes);
  }

  const cdSize = writer.length - cdOffset;
  const needEocdZip64 =
    forceZip64 || records.length >= 0xffff || cdSize >= 0xffffffff || cdOffset >= 0xffffffff;

  if (needEocdZip64) {
    const zip64EocdOffset = writer.length;
    // ZIP64 End of Central Directory Record (56 bytes; size of remaining record = 44n)
    writer
      .u32le(ZIP_SIGNATURES.ZIP64_EOCD)
      .u64le(44n)
      .u16le((3 << 8) | 45)
      .u16le(45)
      .u32le(0)
      .u32le(0)
      .u64le(BigInt(records.length))
      .u64le(BigInt(records.length))
      .u64le(BigInt(cdSize))
      .u64le(BigInt(cdOffset));

    // ZIP64 End of Central Directory Locator (20 bytes)
    writer
      .u32le(ZIP_SIGNATURES.ZIP64_EOCD_LOCATOR)
      .u32le(0)
      .u64le(BigInt(zip64EocdOffset))
      .u32le(1);
  }

  // Classic End of Central Directory Record (22 bytes + archive comment)
  writer
    .u32le(ZIP_SIGNATURES.EOCD)
    .u16le(0)
    .u16le(0)
    .u16le(needEocdZip64 ? 0xffff : records.length)
    .u16le(needEocdZip64 ? 0xffff : records.length)
    .u32le(needEocdZip64 ? 0xffffffff : cdSize)
    .u32le(needEocdZip64 ? 0xffffffff : cdOffset)
    .u16le(archiveCommentBytes.byteLength)
    .bytes(archiveCommentBytes);

  return writer.toUint8Array();
}
