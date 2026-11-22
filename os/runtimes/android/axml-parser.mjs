/**
 * OmniOS Android Binary XML (AXML) Parser, Encoder & Plain XML Fallback (F-037)
 * Compliant with AOSP `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h`.
 * - Enforces strict chunk DoS guards (size === 0, size < headerSize, OOB, depth > 256)
 * - Supports UTF-8 (`UTF8_FLAG = 0x0100`) and UTF-16LE `ResStringPool`
 * - Supports `RESOURCE_MAP`, namespaces, nested elements, CDATA, and typed `Res_value`
 * - Zero external dependencies; pure in-memory parser/encoder without host filesystem access.
 */

import { BinaryWriter } from '../../common/binary.mjs';
import { FormatError, ERROR_CODES } from '../../common/errors.mjs';

const TEXT_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const UTF16LE_DECODER = new TextDecoder('utf-16le');

export const UTF8_FLAG = 0x0100;
export const SORTED_FLAG = 0x0001;
export const MAX_AXML_DEPTH = 256;
export const MAX_PLAIN_XML_BYTES = 2 * 1024 * 1024;
export const MAX_AXML_BYTES = 4 * 1024 * 1024;
export const MAX_XML_ELEMENTS = 16384;
export const MAX_XML_ATTRIBUTES = 65536;
export const MAX_XML_TEXT_BYTES = 2 * 1024 * 1024;
export const MAX_AXML_CHUNKS = 65536;
export const MAX_XML_NODES = 65536;
export const MAX_STRING_POOL_DECODED_BYTES = 8 * 1024 * 1024;

export const RES_CHUNK_TYPES = Object.freeze({
  RES_NULL_TYPE: 0x0000,
  RES_STRING_POOL_TYPE: 0x0001,
  RES_TABLE_TYPE: 0x0002,
  RES_XML_TYPE: 0x0003,
  RES_XML_START_NAMESPACE_TYPE: 0x0100,
  RES_XML_END_NAMESPACE_TYPE: 0x0101,
  RES_XML_START_ELEMENT_TYPE: 0x0102,
  RES_XML_END_ELEMENT_TYPE: 0x0103,
  RES_XML_CDATA_TYPE: 0x0104,
  RES_XML_RESOURCE_MAP_TYPE: 0x0180,
  RES_TABLE_PACKAGE_TYPE: 0x0200,
  RES_TABLE_TYPE_TYPE: 0x0201,
  RES_TABLE_TYPE_SPEC_TYPE: 0x0202,
  RES_TABLE_LIBRARY_TYPE: 0x0203,
  RES_TABLE_OVERLAYABLE_TYPE: 0x0204,
  RES_TABLE_STAGED_ALIAS_TYPE: 0x0206,
});

export const RES_VALUE_TYPES = Object.freeze({
  TYPE_NULL: 0x00,
  TYPE_REFERENCE: 0x01,
  TYPE_ATTRIBUTE: 0x02,
  TYPE_STRING: 0x03,
  TYPE_FLOAT: 0x04,
  TYPE_DIMENSION: 0x05,
  TYPE_FRACTION: 0x06,
  TYPE_DYNAMIC_REFERENCE: 0x07,
  TYPE_DYNAMIC_ATTRIBUTE: 0x08,
  TYPE_INT_DEC: 0x10,
  TYPE_INT_HEX: 0x11,
  TYPE_INT_BOOLEAN: 0x12,
  TYPE_INT_COLOR_ARGB8: 0x1c,
  TYPE_INT_COLOR_RGB8: 0x1d,
  TYPE_INT_COLOR_ARGB4: 0x1e,
  TYPE_INT_COLOR_RGB4: 0x1f,
});

export const ANDROID_XML_NS = 'http://schemas.android.com/apk/res/android';

export const ANDROID_ATTR_IDS = Object.freeze({
  theme: 0x01010000,
  label: 0x01010001,
  icon: 0x01010002,
  name: 0x01010003,
  enabled: 0x0101000e,
  exported: 0x01010010,
  priority: 0x0101001c,
  mimeType: 0x01010026,
  scheme: 0x01010027,
  host: 0x01010028,
  port: 0x01010029,
  path: 0x0101002a,
  pathPrefix: 0x0101002b,
  pathPattern: 0x0101002c,
  textSize: 0x01010095,
  textColor: 0x01010098,
  gravity: 0x010100af,
  orientation: 0x010100c4,
  id: 0x010100d0,
  tag: 0x010100d1,
  background: 0x010100d4,
  padding: 0x010100d5,
  visibility: 0x010100dc,
  layout_width: 0x010100f4,
  layout_height: 0x010100f5,
  src: 0x01010119,
  text: 0x0101014f,
  hint: 0x01010150,
  minSdkVersion: 0x0101020c,
  versionCode: 0x0101021b,
  versionName: 0x0101021c,
  inputType: 0x01010220,
  onClick: 0x0101026f,
  targetSdkVersion: 0x01010270,
  contentDescription: 0x01010273,
});

const ATTR_ID_TO_NAME = Object.freeze(
  Object.fromEntries(Object.entries(ANDROID_ATTR_IDS).map(([k, v]) => [v, k]))
);

const DIMENSION_UNITS = Object.freeze(['px', 'dp', 'sp', 'pt', 'in', 'mm']);
const FRACTION_UNITS = Object.freeze(['%', '%p']);
const RADIX_MULTS = Object.freeze([1.0, 1.0 / 128.0, 1.0 / 32768.0, 1.0 / 8388608.0]);

function toBytes(input, { errorCode = ERROR_CODES.E_MALFORMED_AXML, format = 'axml' } = {}) {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new FormatError('Expected binary Uint8Array/ArrayBuffer input', {
    code: errorCode,
    format,
    offset: 0,
  });
}

function complexToFloat(complex) {
  const mantissa = (complex & 0xffffff00) | 0;
  const radix = (complex >>> 4) & 0x03;
  return (mantissa / 256.0) * RADIX_MULTS[radix];
}

export function decodeResValue(dataType, data, strings = null, resources = null) {
  switch (dataType) {
    case RES_VALUE_TYPES.TYPE_NULL:
      return data === 1 ? '@empty' : null;
    case RES_VALUE_TYPES.TYPE_REFERENCE:
    case RES_VALUE_TYPES.TYPE_DYNAMIC_REFERENCE: {
      if (data === 0) return null;
      if (resources && typeof resources.resolve === 'function') {
        const resolved = resources.resolve(data >>> 0);
        if (resolved && resolved.value !== undefined && resolved.value !== null) {
          return resolved.value;
        }
      }
      return `@0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    }
    case RES_VALUE_TYPES.TYPE_ATTRIBUTE:
    case RES_VALUE_TYPES.TYPE_DYNAMIC_ATTRIBUTE:
      return `?0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    case RES_VALUE_TYPES.TYPE_STRING: {
      if (Array.isArray(strings) && data >= 0 && data < strings.length) {
        return strings[data];
      }
      return '';
    }
    case RES_VALUE_TYPES.TYPE_FLOAT: {
      const buf = new ArrayBuffer(4);
      const dv = new DataView(buf);
      dv.setUint32(0, data >>> 0, true);
      return dv.getFloat32(0, true);
    }
    case RES_VALUE_TYPES.TYPE_DIMENSION: {
      const val = complexToFloat(data);
      const unit = DIMENSION_UNITS[data & 0x0f] ?? 'px';
      return `${Number(val.toFixed(4))}${unit}`;
    }
    case RES_VALUE_TYPES.TYPE_FRACTION: {
      const val = complexToFloat(data) * 100;
      const unit = FRACTION_UNITS[data & 0x0f] ?? '%';
      return `${Number(val.toFixed(4))}${unit}`;
    }
    case RES_VALUE_TYPES.TYPE_INT_DEC:
      return data | 0;
    case RES_VALUE_TYPES.TYPE_INT_HEX:
      return `0x${(data >>> 0).toString(16)}`;
    case RES_VALUE_TYPES.TYPE_INT_BOOLEAN:
      return data !== 0;
    case RES_VALUE_TYPES.TYPE_INT_COLOR_ARGB8:
    case RES_VALUE_TYPES.TYPE_INT_COLOR_RGB8:
    case RES_VALUE_TYPES.TYPE_INT_COLOR_ARGB4:
    case RES_VALUE_TYPES.TYPE_INT_COLOR_RGB4:
      return `#${(data >>> 0).toString(16).padStart(8, '0')}`;
    default:
      return data >>> 0;
  }
}

/**
 * Reads and strictly validates an 8-byte `ResChunk_header`.
 * Defends against zero-size infinite-loop DoS, size < headerSize, and out-of-bounds chunks (Edge Case #5).
 */
export function readChunkHeader(
  bytes,
  offset = 0,
  end = bytes?.byteLength ?? 0,
  { errorCode = ERROR_CODES.E_MALFORMED_AXML, format = 'axml' } = {}
) {
  const buf = toBytes(bytes, { errorCode, format });
  const limit = Math.min(end, buf.byteLength);
  if (!Number.isInteger(offset) || offset < 0 || offset + 8 > limit) {
    throw new FormatError(`Truncated ${format.toUpperCase()} chunk header at offset ${offset}`, {
      code: errorCode,
      format,
      offset,
    });
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const type = view.getUint16(offset, true);
  const headerSize = view.getUint16(offset + 2, true);
  const size = view.getUint32(offset + 4, true);

  if (headerSize < 8) {
    throw new FormatError(
      `Invalid ${format.toUpperCase()} chunk headerSize (${headerSize} < 8) at offset ${offset}`,
      { code: errorCode, format, offset, details: { type, headerSize, size } }
    );
  }
  if (size === 0 || size < headerSize) {
    throw new FormatError(
      `Invalid ${format.toUpperCase()} chunk size (${size}) < headerSize (${headerSize}) at offset ${offset}`,
      { code: errorCode, format, offset, details: { type, headerSize, size } }
    );
  }
  if (offset + size > limit) {
    throw new FormatError(
      `${format.toUpperCase()} chunk exceeds buffer bounds (${offset} + ${size} > ${limit})`,
      { code: errorCode, format, offset, details: { type, headerSize, size, limit } }
    );
  }

  return {
    type,
    headerSize,
    size,
    offset,
    end: offset + size,
  };
}

function readUtf8PoolVarint(bytes, pos, end, { errorCode, format }) {
  if (pos >= end) {
    throw new FormatError('Truncated UTF-8 ResStringPool length varint', {
      code: errorCode,
      format,
      offset: pos,
    });
  }
  const b0 = bytes[pos];
  if ((b0 & 0x80) !== 0) {
    if (pos + 1 >= end) {
      throw new FormatError('Truncated 2-byte UTF-8 ResStringPool length varint', {
        code: errorCode,
        format,
        offset: pos,
      });
    }
    return {
      value: ((b0 & 0x7f) << 8) | bytes[pos + 1],
      nextPos: pos + 2,
    };
  }
  return { value: b0, nextPos: pos + 1 };
}

function readUtf16PoolLength(bytes, view, pos, end, { errorCode, format }) {
  if (pos + 2 > end) {
    throw new FormatError('Truncated UTF-16 ResStringPool length', {
      code: errorCode,
      format,
      offset: pos,
    });
  }
  const u0 = view.getUint16(pos, true);
  if ((u0 & 0x8000) !== 0) {
    if (pos + 4 > end) {
      throw new FormatError('Truncated 4-byte UTF-16 ResStringPool length', {
        code: errorCode,
        format,
        offset: pos,
      });
    }
    const u1 = view.getUint16(pos + 2, true);
    return {
      value: (((u0 & 0x7fff) << 16) | u1) >>> 0,
      nextPos: pos + 4,
    };
  }
  return { value: u0, nextPos: pos + 2 };
}

/**
 * Parses an Android `ResStringPool` chunk (`0x0001`), supporting both UTF-8 and UTF-16LE encodings.
 */
export function parseResStringPool(
  bytes,
  offset = 0,
  end = bytes?.byteLength ?? 0,
  { errorCode = ERROR_CODES.E_MALFORMED_AXML, format = 'axml', decodedStringBudget = null } = {}
) {
  const buf = toBytes(bytes, { errorCode, format });
  const chunk = readChunkHeader(buf, offset, end, { errorCode, format });
  if (chunk.type !== RES_CHUNK_TYPES.RES_STRING_POOL_TYPE) {
    throw new FormatError(
      `Expected RES_STRING_POOL_TYPE (0x0001), got 0x${chunk.type.toString(16)}`,
      { code: errorCode, format, offset }
    );
  }
  if (chunk.headerSize < 28) {
    throw new FormatError(`ResStringPool headerSize too small (${chunk.headerSize} < 28)`, {
      code: errorCode,
      format,
      offset,
    });
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const stringCount = view.getUint32(offset + 8, true);
  const styleCount = view.getUint32(offset + 12, true);
  const flags = view.getUint32(offset + 16, true);
  const stringsStart = view.getUint32(offset + 20, true);
  const stylesStart = view.getUint32(offset + 24, true);

  const isUtf8 = (flags & UTF8_FLAG) !== 0;
  const offsetsTableStart = offset + chunk.headerSize;
  const offsetsTableEnd = offsetsTableStart + stringCount * 4;
  const fullOffsetsTableEnd = offsetsTableEnd + styleCount * 4;
  if (stringCount > 1_000_000 || styleCount > 1_000_000 || fullOffsetsTableEnd > chunk.end) {
    throw new FormatError(
      `ResStringPool offset table out of bounds (strings=${stringCount}, styles=${styleCount})`,
      {
        code: errorCode,
        format,
        offset: offsetsTableStart,
      }
    );
  }

  const stringsDataBase = offset + stringsStart;
  if (stringCount > 0 && (stringsStart < chunk.headerSize || stringsDataBase > chunk.end)) {
    throw new FormatError(`ResStringPool stringsStart out of bounds (${stringsStart})`, {
      code: errorCode,
      format,
      offset: offset + 20,
    });
  }
  if (styleCount > 0 && (stylesStart < chunk.headerSize || offset + stylesStart > chunk.end)) {
    throw new FormatError(`ResStringPool stylesStart out of bounds (${stylesStart})`, {
      code: errorCode,
      format,
      offset: offset + 24,
    });
  }

  const decodedByOff = new Map();
  const budget = decodedStringBudget ?? {
    decodedBytes: 0,
    maxDecodedBytes: Math.min(Math.max(chunk.size * 4, 64 * 1024), MAX_STRING_POOL_DECODED_BYTES),
  };
  const strings = new Array(stringCount);
  for (let i = 0; i < stringCount; i++) {
    const relOff = view.getUint32(offsetsTableStart + i * 4, true);
    const strPos = stringsDataBase + relOff;
    if (strPos < stringsDataBase || strPos >= chunk.end) {
      throw new FormatError(`ResStringPool string #${i} offset out of bounds (${relOff})`, {
        code: errorCode,
        format,
        offset: offsetsTableStart + i * 4,
      });
    }

    if (decodedByOff.has(strPos)) {
      strings[i] = decodedByOff.get(strPos);
      continue;
    }

    let decoded;
    if (isUtf8) {
      const charLenInfo = readUtf8PoolVarint(buf, strPos, chunk.end, { errorCode, format });
      const byteLenInfo = readUtf8PoolVarint(buf, charLenInfo.nextPos, chunk.end, { errorCode, format });
      const dataStart = byteLenInfo.nextPos;
      const byteLen = byteLenInfo.value;
      const dataEnd = dataStart + byteLen;
      if (dataEnd > chunk.end) {
        throw new FormatError(`ResStringPool UTF-8 string #${i} exceeds chunk bounds`, {
          code: errorCode,
          format,
          offset: dataStart,
        });
      }
      if (budget.decodedBytes + byteLen > budget.maxDecodedBytes) {
        throw new FormatError(
          `ResStringPool decoded string bytes (${budget.decodedBytes + byteLen}) exceeds budget (${budget.maxDecodedBytes})`,
          { code: errorCode, format, offset: strPos }
        );
      }
      decoded = UTF8_DECODER.decode(buf.subarray(dataStart, dataEnd));
      const chargeBytes = Math.max(byteLen, decoded.length * 2);
      budget.decodedBytes += chargeBytes;
      if (budget.decodedBytes > budget.maxDecodedBytes) {
        throw new FormatError(
          `ResStringPool decoded string bytes (${budget.decodedBytes}) exceeds budget (${budget.maxDecodedBytes})`,
          { code: errorCode, format, offset: strPos }
        );
      }
    } else {
      const lenInfo = readUtf16PoolLength(buf, view, strPos, chunk.end, { errorCode, format });
      const dataStart = lenInfo.nextPos;
      const byteLen = lenInfo.value * 2;
      const dataEnd = dataStart + byteLen;
      if (dataEnd > chunk.end) {
        throw new FormatError(`ResStringPool UTF-16 string #${i} exceeds chunk bounds`, {
          code: errorCode,
          format,
          offset: dataStart,
        });
      }
      if (budget.decodedBytes + byteLen > budget.maxDecodedBytes) {
        throw new FormatError(
          `ResStringPool decoded string bytes (${budget.decodedBytes + byteLen}) exceeds budget (${budget.maxDecodedBytes})`,
          { code: errorCode, format, offset: strPos }
        );
      }
      decoded = UTF16LE_DECODER.decode(buf.subarray(dataStart, dataEnd));
      const chargeBytes = Math.max(byteLen, decoded.length * 2);
      budget.decodedBytes += chargeBytes;
      if (budget.decodedBytes > budget.maxDecodedBytes) {
        throw new FormatError(
          `ResStringPool decoded string bytes (${budget.decodedBytes}) exceeds budget (${budget.maxDecodedBytes})`,
          { code: errorCode, format, offset: strPos }
        );
      }
    }
    decodedByOff.set(strPos, decoded);
    strings[i] = decoded;
  }

  return {
    strings,
    stringCount,
    styleCount,
    flags,
    isUtf8,
    stringsStart,
    stylesStart,
    chunk,
  };
}

function writeUtf8PoolVarint(writer, len) {
  if (len > 0x7f) {
    writer.u8(0x80 | ((len >>> 8) & 0x7f));
    writer.u8(len & 0xff);
  } else {
    writer.u8(len & 0x7f);
  }
}

function writeUtf16PoolLength(writer, len) {
  if (len > 0x7fff) {
    writer.u16le(0x8000 | ((len >>> 16) & 0x7fff));
    writer.u16le(len & 0xffff);
  } else {
    writer.u16le(len & 0xffff);
  }
}

/**
 * Encodes an array of JS strings into a compliant Android `ResStringPool` chunk (`0x0001`).
 */
export function encodeResStringPool(strings, { utf8 = true } = {}) {
  const list = Array.isArray(strings) ? strings.map((s) => String(s ?? '')) : [];
  const count = list.length;
  const headerSize = 28;
  const offsetsSize = count * 4;
  const stringsStart = headerSize + offsetsSize;

  const dataWriter = new BinaryWriter({ initialCapacity: Math.max(64, count * 16), littleEndian: true });
  const offsets = new Uint32Array(count);

  for (let i = 0; i < count; i++) {
    offsets[i] = dataWriter.length;
    const str = list[i];
    if (utf8) {
      const encoded = TEXT_ENCODER.encode(str);
      writeUtf8PoolVarint(dataWriter, str.length);
      writeUtf8PoolVarint(dataWriter, encoded.byteLength);
      dataWriter.bytes(encoded);
      dataWriter.u8(0);
    } else {
      writeUtf16PoolLength(dataWriter, str.length);
      for (let j = 0; j < str.length; j++) {
        dataWriter.u16le(str.charCodeAt(j));
      }
      dataWriter.u16le(0);
    }
  }
  dataWriter.align(4, 0);
  const dataBytes = dataWriter.toUint8Array();

  const totalSize = stringsStart + dataBytes.byteLength;
  const out = new BinaryWriter({ initialCapacity: totalSize, littleEndian: true });
  out.u16le(RES_CHUNK_TYPES.RES_STRING_POOL_TYPE);
  out.u16le(headerSize);
  out.u32le(totalSize);
  out.u32le(count);
  out.u32le(0); // styleCount
  out.u32le(utf8 ? UTF8_FLAG : 0);
  out.u32le(count > 0 ? stringsStart : 0);
  out.u32le(0); // stylesStart
  for (let i = 0; i < count; i++) {
    out.u32le(offsets[i]);
  }
  out.bytes(dataBytes);
  return out.toUint8Array();
}

function getPoolString(strings, idx) {
  if (idx === 0xffffffff || idx < 0) return null;
  if (idx >= strings.length) return null;
  return strings[idx];
}

/**
 * Parses Android Binary XML (AXML, `RES_XML_TYPE = 0x0003`) into a normalized XML DOM.
 */
export function parseAxml(
  buffer,
  {
    resources = null,
    maxDepth = MAX_AXML_DEPTH,
    maxInputBytes = MAX_AXML_BYTES,
    maxElements = MAX_XML_ELEMENTS,
    maxAttributes = MAX_XML_ATTRIBUTES,
    maxTextBytes = MAX_XML_TEXT_BYTES,
    maxChunks = undefined,
  } = {}
) {
  const buf = toBytes(buffer, { errorCode: ERROR_CODES.E_MALFORMED_AXML, format: 'axml' });
  if (buf.byteLength > maxInputBytes) {
    throw new FormatError(
      `AXML input size (${buf.byteLength} bytes) exceeds maximum (${maxInputBytes} bytes)`,
      { code: ERROR_CODES.E_MALFORMED_AXML, format: 'axml', offset: 0 }
    );
  }
  const outer = readChunkHeader(buf, 0, buf.byteLength, {
    errorCode: ERROR_CODES.E_MALFORMED_AXML,
    format: 'axml',
  });

  if (outer.type !== RES_CHUNK_TYPES.RES_XML_TYPE) {
    throw new FormatError(`Expected RES_XML_TYPE (0x0003), got 0x${outer.type.toString(16)}`, {
      code: ERROR_CODES.E_MALFORMED_AXML,
      format: 'axml',
      offset: 0,
    });
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let strings = [];
  let resourceMap = [];
  const namespaces = Object.create(null);
  const uriToPrefix = new Map();
  const stack = [];
  let root = null;
  let totalDerivedChars = 0;
  const maxDerivedChars = Math.min(Math.max(buf.byteLength * 4, 256 * 1024), Math.max(maxTextBytes, 256 * 1024));
  let totalElements = 0;
  let totalAttributes = 0;
  let totalTextBytes = 0;
  let totalChunks = 0;
  let totalNamespaces = 0;
  const effectiveMaxChunks = maxChunks ?? Math.min(MAX_AXML_CHUNKS, Math.max(maxElements * 4 + 64, 256));
  const maxNamespaces = Math.min(maxAttributes, 4096);
  const decodedStringBudget = {
    decodedBytes: 0,
    maxDecodedBytes: Math.min(Math.max(buf.byteLength * 4, 64 * 1024), MAX_STRING_POOL_DECODED_BYTES),
  };

  let cursor = outer.headerSize;
  while (cursor < outer.end) {
    totalChunks += 1;
    if (totalChunks > effectiveMaxChunks) {
      throw new FormatError(
        `AXML chunk count (${totalChunks}) exceeds maximum (${effectiveMaxChunks})`,
        { code: ERROR_CODES.E_MALFORMED_AXML, format: 'axml', offset: cursor }
      );
    }
    const sub = readChunkHeader(buf, cursor, outer.end, {
      errorCode: ERROR_CODES.E_MALFORMED_AXML,
      format: 'axml',
    });

    switch (sub.type) {
      case RES_CHUNK_TYPES.RES_STRING_POOL_TYPE: {
        const pool = parseResStringPool(buf, sub.offset, sub.end, {
          errorCode: ERROR_CODES.E_MALFORMED_AXML,
          format: 'axml',
          decodedStringBudget,
        });
        strings = pool.strings;
        break;
      }

      case RES_CHUNK_TYPES.RES_XML_RESOURCE_MAP_TYPE: {
        const payloadBytes = sub.size - sub.headerSize;
        const count = Math.floor(payloadBytes / 4);
        resourceMap = new Array(count);
        for (let i = 0; i < count; i++) {
          resourceMap[i] = view.getUint32(sub.offset + sub.headerSize + i * 4, true);
        }
        break;
      }

      case RES_CHUNK_TYPES.RES_XML_START_NAMESPACE_TYPE: {
        if (sub.size - sub.headerSize < 8) {
          throw new FormatError('Truncated RES_XML_START_NAMESPACE chunk', {
            code: ERROR_CODES.E_MALFORMED_AXML,
            format: 'axml',
            offset: sub.offset,
          });
        }
        totalNamespaces += 1;
        if (totalNamespaces > maxNamespaces) {
          throw new FormatError(
            `AXML namespace count (${totalNamespaces}) exceeds maximum (${maxNamespaces})`,
            { code: ERROR_CODES.E_MALFORMED_AXML, format: 'axml', offset: sub.offset }
          );
        }
        const prefixIdx = view.getUint32(sub.offset + sub.headerSize, true);
        const uriIdx = view.getUint32(sub.offset + sub.headerSize + 4, true);
        const prefix = getPoolString(strings, prefixIdx) ?? '';
        const uri = getPoolString(strings, uriIdx) ?? '';
        if (prefix) namespaces[prefix] = uri;
        if (uri) uriToPrefix.set(uri, prefix);
        break;
      }

      case RES_CHUNK_TYPES.RES_XML_END_NAMESPACE_TYPE: {
        // Namespace scope ends cleanly; keep prefix map for metadata inspection.
        break;
      }

      case RES_CHUNK_TYPES.RES_XML_START_ELEMENT_TYPE: {
        if (sub.headerSize < 16 || sub.size - sub.headerSize < 20) {
          throw new FormatError('Truncated RES_XML_START_ELEMENT chunk', {
            code: ERROR_CODES.E_MALFORMED_AXML,
            format: 'axml',
            offset: sub.offset,
          });
        }
        totalElements += 1;
        if (totalElements > maxElements) {
          throw new FormatError(
            `AXML element count (${totalElements}) exceeds maximum (${maxElements})`,
            { code: ERROR_CODES.E_MALFORMED_AXML, format: 'axml', offset: sub.offset }
          );
        }
        if (stack.length >= maxDepth) {
          throw new FormatError(`AXML nesting depth exceeds maximum (${maxDepth})`, {
            code: ERROR_CODES.E_MALFORMED_AXML,
            format: 'axml',
            offset: sub.offset,
            details: { depth: stack.length + 1, maxDepth },
          });
        }

        const lineNumber = view.getUint32(sub.offset + 8, true);
        const extBase = sub.offset + sub.headerSize;
        const nsIdx = view.getUint32(extBase, true);
        const nameIdx = view.getUint32(extBase + 4, true);
        const attributeStart = view.getUint16(extBase + 8, true);
        const attributeSize = view.getUint16(extBase + 10, true);
        const attributeCount = view.getUint16(extBase + 12, true);

        if (totalAttributes + attributeCount > maxAttributes) {
          throw new FormatError(
            `AXML attribute count (${totalAttributes + attributeCount}) exceeds maximum (${maxAttributes})`,
            { code: ERROR_CODES.E_MALFORMED_AXML, format: 'axml', offset: extBase + 12 }
          );
        }
        totalAttributes += attributeCount;

        const nsUri = getPoolString(strings, nsIdx);
        const tag = getPoolString(strings, nameIdx);
        if (!tag) {
          throw new FormatError(`Invalid element name string index ${nameIdx}`, {
            code: ERROR_CODES.E_MALFORMED_AXML,
            format: 'axml',
            offset: extBase + 4,
          });
        }

        const attrs = Object.create(null);
        const typedAttrs = [];

        if (attributeCount > 0) {
          if (attributeSize < 20) {
            throw new FormatError(`Invalid AXML attributeSize (${attributeSize} < 20)`, {
              code: ERROR_CODES.E_MALFORMED_AXML,
              format: 'axml',
              offset: extBase + 10,
            });
          }
          const attrTableStart = extBase + attributeStart;
          const attrTableEnd = attrTableStart + attributeCount * attributeSize;
          if (attrTableStart < extBase || attrTableEnd > sub.end) {
            throw new FormatError('AXML attribute table exceeds element chunk bounds', {
              code: ERROR_CODES.E_MALFORMED_AXML,
              format: 'axml',
              offset: attrTableStart,
            });
          }

          for (let i = 0; i < attributeCount; i++) {
            const aOff = attrTableStart + i * attributeSize;
            const aNsIdx = view.getUint32(aOff, true);
            const aNameIdx = view.getUint32(aOff + 4, true);
            const aRawValueIdx = view.getUint32(aOff + 8, true);
            const valType = buf[aOff + 15];
            const valData = view.getUint32(aOff + 16, true);

            const aNs = getPoolString(strings, aNsIdx);
            const resourceId = aNameIdx < resourceMap.length ? resourceMap[aNameIdx] : null;
            let aName = getPoolString(strings, aNameIdx);
            if (!aName && resourceId !== null && ATTR_ID_TO_NAME[resourceId]) {
              aName = ATTR_ID_TO_NAME[resourceId];
            }
            if (!aName) {
              aName = `attr_${i}`;
            }

            const rawValue = getPoolString(strings, aRawValueIdx);
            const value =
              valType === RES_VALUE_TYPES.TYPE_STRING && rawValue !== null
                ? rawValue
                : decodeResValue(valType, valData, strings, resources);

            const prefix = aNs ? (uriToPrefix.get(aNs) ?? (aNs === ANDROID_XML_NS ? 'android' : '')) : '';
            let qualifiedName = aName;
            if (prefix) {
              totalDerivedChars += prefix.length + 1 + aName.length;
              if (totalDerivedChars > maxDerivedChars) {
                throw new FormatError(
                  `AXML derived attribute name expansion exceeds budget (${totalDerivedChars} > ${maxDerivedChars})`,
                  { code: ERROR_CODES.E_MALFORMED_AXML, format: 'axml', offset: aOff }
                );
              }
              qualifiedName = `${prefix}:${aName}`;
            }

            attrs[qualifiedName] = value;
            if (prefix && attrs[aName] === undefined) {
              attrs[aName] = value;
            }

            typedAttrs.push({
              name: aName,
              qualifiedName,
              prefix: prefix || null,
              ns: aNs,
              resourceId,
              rawValue,
              dataType: valType,
              data: valData >>> 0,
              value,
            });
          }
        }

        const node = {
          tag,
          ns: nsUri,
          prefix: nsUri ? (uriToPrefix.get(nsUri) ?? null) : null,
          attrs,
          typedAttrs,
          children: [],
          text: '',
          lineNumber,
        };

        if (stack.length > 0) {
          stack[stack.length - 1].children.push(node);
        } else if (!root) {
          root = node;
        }
        stack.push(node);
        break;
      }

      case RES_CHUNK_TYPES.RES_XML_END_ELEMENT_TYPE: {
        if (sub.size - sub.headerSize < 8) {
          throw new FormatError('Truncated RES_XML_END_ELEMENT chunk', {
            code: ERROR_CODES.E_MALFORMED_AXML,
            format: 'axml',
            offset: sub.offset,
          });
        }
        if (stack.length === 0) {
          throw new FormatError('Unmatched RES_XML_END_ELEMENT chunk on empty element stack', {
            code: ERROR_CODES.E_MALFORMED_AXML,
            format: 'axml',
            offset: sub.offset,
          });
        }
        const endNameIdx = view.getUint32(sub.offset + sub.headerSize + 4, true);
        const endTag = getPoolString(strings, endNameIdx);
        const openNode = stack[stack.length - 1];
        if (!endTag || endTag !== openNode.tag) {
          throw new FormatError(
            `Mismatched AXML closing element </${endTag ?? `#${endNameIdx}`}> for open <${openNode.tag}>`,
            {
              code: ERROR_CODES.E_MALFORMED_AXML,
              format: 'axml',
              offset: sub.offset + sub.headerSize + 4,
            }
          );
        }
        stack.pop();
        break;
      }

      case RES_CHUNK_TYPES.RES_XML_CDATA_TYPE: {
        if (sub.size - sub.headerSize < 12) {
          throw new FormatError('Truncated RES_XML_CDATA chunk', {
            code: ERROR_CODES.E_MALFORMED_AXML,
            format: 'axml',
            offset: sub.offset,
          });
        }
        const dataIdx = view.getUint32(sub.offset + sub.headerSize, true);
        const text = getPoolString(strings, dataIdx) ?? '';
        if (stack.length > 0 && text.length > 0) {
          totalDerivedChars += text.length;
          totalTextBytes += text.length * 2;
          if (totalDerivedChars > maxDerivedChars || totalTextBytes > maxTextBytes) {
            throw new FormatError(
              `AXML CDATA text expansion exceeds budget (${totalTextBytes} > ${maxTextBytes} bytes)`,
              { code: ERROR_CODES.E_MALFORMED_AXML, format: 'axml', offset: sub.offset }
            );
          }
          stack[stack.length - 1].text += text;
        }
        break;
      }

      default:
        // Safely skip unknown future chunks using validated sub.end.
        break;
    }

    cursor = sub.end;
  }

  if (stack.length > 0) {
    throw new FormatError(`Unclosed AXML element <${stack[stack.length - 1].tag}>`, {
      code: ERROR_CODES.E_MALFORMED_AXML,
      format: 'axml',
      offset: outer.end,
    });
  }

  if (!root) {
    throw new FormatError('AXML document contains no root element', {
      code: ERROR_CODES.E_MALFORMED_AXML,
      format: 'axml',
      offset: 0,
    });
  }

  return {
    format: 'axml',
    root,
    strings,
    resourceMap,
    namespaces,
  };
}

function unescapeXmlEntities(str) {
  return str.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g, (_m, ent) => {
    if (ent === 'amp') return '&';
    if (ent === 'lt') return '<';
    if (ent === 'gt') return '>';
    if (ent === 'quot') return '"';
    if (ent === 'apos') return "'";
    if (ent.startsWith('#x')) {
      const code = Number.parseInt(ent.slice(2), 16);
      if (!Number.isSafeInteger(code) || code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
        throw new FormatError(`Invalid XML numeric character reference: &${ent};`, {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
        });
      }
      return String.fromCodePoint(code);
    }
    if (ent.startsWith('#')) {
      const code = Number.parseInt(ent.slice(1), 10);
      if (!Number.isSafeInteger(code) || code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
        throw new FormatError(`Invalid XML numeric character reference: &${ent};`, {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
        });
      }
      return String.fromCodePoint(code);
    }
    return '';
  });
}

function resolvePlainXmlAttrValue(rawStr, resources) {
  if (resources && typeof resources.resolve === 'function' && rawStr.startsWith('@')) {
    const resolved = resources.resolve(rawStr);
    if (resolved && resolved.value !== undefined && resolved.value !== null) {
      return { value: resolved.value, dataType: RES_VALUE_TYPES.TYPE_REFERENCE, data: resolved.id >>> 0 };
    }
  }
  return { value: rawStr, dataType: RES_VALUE_TYPES.TYPE_STRING, data: 0 };
}

function utf8ByteLength(str) {
  let bytes = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code <= 0x7f) {
      bytes += 1;
    } else if (code <= 0x7ff) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const next = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

/**
 * Plain UTF-8 XML fallback parser (used for developer/test manifests & layouts).
 */
export function parsePlainXml(
  input,
  {
    resources = null,
    maxDepth = MAX_AXML_DEPTH,
    maxInputBytes = MAX_PLAIN_XML_BYTES,
    maxElements = MAX_XML_ELEMENTS,
    maxAttributes = MAX_XML_ATTRIBUTES,
    maxTextBytes = MAX_XML_TEXT_BYTES,
    maxNodes = undefined,
  } = {}
) {
  let xml;
  if (typeof input === 'string') {
    if (input.length > maxInputBytes || (input.length * 3 > maxInputBytes && utf8ByteLength(input) > maxInputBytes)) {
      throw new FormatError(
        `Plain XML input size exceeds maximum (${maxInputBytes} bytes)`,
        { code: ERROR_CODES.E_MALFORMED_AXML, format: 'xml', offset: 0 }
      );
    }
    xml = input;
  } else {
    const rawBuf = toBytes(input, { errorCode: ERROR_CODES.E_MALFORMED_AXML, format: 'xml' });
    if (rawBuf.byteLength > maxInputBytes) {
      throw new FormatError(
        `Plain XML input size (${rawBuf.byteLength} bytes) exceeds maximum (${maxInputBytes} bytes)`,
        { code: ERROR_CODES.E_MALFORMED_AXML, format: 'xml', offset: 0 }
      );
    }
    xml = UTF8_DECODER.decode(rawBuf);
  }

  const len = xml.length;
  let i = 0;
  let line = 1;
  const stack = [];
  const namespaces = Object.create(null);
  let root = null;
  let totalElements = 0;
  let totalAttributes = 0;
  let totalTextBytes = 0;
  let totalNodes = 0;
  let totalNamespaces = 0;
  const effectiveMaxNodes = maxNodes ?? Math.min(MAX_XML_NODES, Math.max(maxElements * 4 + 64, 256));
  const maxNamespaces = Math.min(maxAttributes, 4096);

  const chargeNode = (offset) => {
    totalNodes += 1;
    if (totalNodes > effectiveMaxNodes) {
      throw new FormatError(
        `XML node/token count (${totalNodes}) exceeds maximum (${effectiveMaxNodes})`,
        { code: ERROR_CODES.E_MALFORMED_AXML, format: 'xml', offset }
      );
    }
  };

  const chargeText = (str, offset) => {
    const byteCost = str.length * 2;
    totalTextBytes += byteCost;
    if (totalTextBytes > maxTextBytes) {
      throw new FormatError(
        `XML text content (${totalTextBytes} bytes) exceeds maximum (${maxTextBytes} bytes)`,
        { code: ERROR_CODES.E_MALFORMED_AXML, format: 'xml', offset }
      );
    }
  };

  const advance = (n) => {
    for (let k = 0; k < n && i < len; k++, i++) {
      if (xml.charCodeAt(i) === 10) line += 1;
    }
  };

  while (i < len) {
    const lt = xml.indexOf('<', i);
    if (lt === -1) {
      const tail = unescapeXmlEntities(xml.slice(i));
      if (stack.length > 0 && tail.trim().length > 0) {
        chargeText(tail, i);
        stack[stack.length - 1].text += tail;
      }
      break;
    }
    if (lt > i) {
      const txt = unescapeXmlEntities(xml.slice(i, lt));
      if (stack.length > 0 && txt.length > 0) {
        chargeText(txt, i);
        stack[stack.length - 1].text += txt;
      }
      advance(lt - i);
    }

    if (xml.startsWith('<!--', i)) {
      chargeNode(i);
      const endComment = xml.indexOf('-->', i + 4);
      if (endComment === -1) {
        throw new FormatError('Unterminated XML comment', {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
          offset: i,
        });
      }
      advance(endComment + 3 - i);
      continue;
    }

    if (xml.startsWith('<![CDATA[', i)) {
      chargeNode(i);
      const endCdata = xml.indexOf(']]>', i + 9);
      if (endCdata === -1) {
        throw new FormatError('Unterminated XML CDATA section', {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
          offset: i,
        });
      }
      const cdataText = xml.slice(i + 9, endCdata);
      if (stack.length > 0 && cdataText.length > 0) {
        chargeText(cdataText, i + 9);
        stack[stack.length - 1].text += cdataText;
      }
      advance(endCdata + 3 - i);
      continue;
    }

    if (xml.startsWith('<?', i)) {
      chargeNode(i);
      const endPi = xml.indexOf('?>', i + 2);
      if (endPi === -1) {
        throw new FormatError('Unterminated XML processing instruction', {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
          offset: i,
        });
      }
      advance(endPi + 2 - i);
      continue;
    }

    if (xml.startsWith('<!', i)) {
      chargeNode(i);
      const endDecl = xml.indexOf('>', i + 2);
      if (endDecl === -1) {
        throw new FormatError('Unterminated XML declaration', {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
          offset: i,
        });
      }
      advance(endDecl + 1 - i);
      continue;
    }

    if (xml.startsWith('</', i)) {
      chargeNode(i);
      const closeGt = xml.indexOf('>', i + 2);
      if (closeGt === -1) {
        throw new FormatError('Unterminated XML closing tag', {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
          offset: i,
        });
      }
      const closeName = xml.slice(i + 2, closeGt).trim();
      const top = stack.pop();
      if (!top || (top.tag !== closeName && `${top.prefix ? `${top.prefix}:` : ''}${top.tag}` !== closeName)) {
        throw new FormatError(`Mismatched XML closing tag </${closeName}>`, {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
          offset: i,
        });
      }
      advance(closeGt + 1 - i);
      continue;
    }

    // Start tag
    const tagStartOffset = i;
    chargeNode(tagStartOffset);
    totalElements += 1;
    if (totalElements > maxElements) {
      throw new FormatError(
        `XML element count (${totalElements}) exceeds maximum (${maxElements})`,
        { code: ERROR_CODES.E_MALFORMED_AXML, format: 'xml', offset: tagStartOffset }
      );
    }

    const tagLine = line;
    advance(1); // '<'
    while (i < len && /\s/.test(xml[i])) advance(1);

    const nameStart = i;
    while (i < len && !/[\s/>]/.test(xml[i])) advance(1);
    const rawTagName = xml.slice(nameStart, i);
    if (!rawTagName) {
      throw new FormatError('Empty XML tag name', {
        code: ERROR_CODES.E_MALFORMED_AXML,
        format: 'xml',
        offset: tagStartOffset,
      });
    }

    if (stack.length >= maxDepth) {
      throw new FormatError(`XML nesting depth exceeds maximum (${maxDepth})`, {
        code: ERROR_CODES.E_MALFORMED_AXML,
        format: 'xml',
        offset: tagStartOffset,
      });
    }

    const colon = rawTagName.indexOf(':');
    const tagPrefix = colon >= 0 ? rawTagName.slice(0, colon) : null;
    const tag = colon >= 0 ? rawTagName.slice(colon + 1) : rawTagName;
    const attrs = Object.create(null);
    const typedAttrs = [];
    let selfClosing = false;

    while (i < len) {
      while (i < len && /\s/.test(xml[i])) advance(1);
      if (i >= len) {
        throw new FormatError(`Unterminated XML start tag <${rawTagName}>`, {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
          offset: tagStartOffset,
        });
      }
      if (xml.startsWith('/>', i)) {
        selfClosing = true;
        advance(2);
        break;
      }
      if (xml[i] === '>') {
        advance(1);
        break;
      }

      const attrNameStart = i;
      totalAttributes += 1;
      if (totalAttributes > maxAttributes) {
        throw new FormatError(
          `XML attribute count (${totalAttributes}) exceeds maximum (${maxAttributes})`,
          { code: ERROR_CODES.E_MALFORMED_AXML, format: 'xml', offset: attrNameStart }
        );
      }

      while (i < len && !/[\s=/>]/.test(xml[i])) advance(1);
      const qualifiedAttr = xml.slice(attrNameStart, i);
      if (!qualifiedAttr) {
        throw new FormatError('Malformed XML attribute', {
          code: ERROR_CODES.E_MALFORMED_AXML,
          format: 'xml',
          offset: i,
        });
      }
      while (i < len && /\s/.test(xml[i])) advance(1);
      let rawAttrVal = '';
      if (xml[i] === '=') {
        advance(1);
        while (i < len && /\s/.test(xml[i])) advance(1);
        const quote = xml[i];
        if (quote !== '"' && quote !== "'") {
          throw new FormatError(`Expected quoted attribute value for ${qualifiedAttr}`, {
            code: ERROR_CODES.E_MALFORMED_AXML,
            format: 'xml',
            offset: i,
          });
        }
        advance(1);
        const valStart = i;
        const valEnd = xml.indexOf(quote, i);
        if (valEnd === -1) {
          throw new FormatError(`Unterminated attribute value for ${qualifiedAttr}`, {
            code: ERROR_CODES.E_MALFORMED_AXML,
            format: 'xml',
            offset: valStart,
          });
        }
        rawAttrVal = unescapeXmlEntities(xml.slice(valStart, valEnd));
        advance(valEnd - i + 1);
      }

      if (qualifiedAttr.startsWith('xmlns:')) {
        totalNamespaces += 1;
        if (totalNamespaces > maxNamespaces) {
          throw new FormatError(
            `XML namespace count (${totalNamespaces}) exceeds maximum (${maxNamespaces})`,
            { code: ERROR_CODES.E_MALFORMED_AXML, format: 'xml', offset: attrNameStart }
          );
        }
        const nsPrefix = qualifiedAttr.slice(6);
        namespaces[nsPrefix] = rawAttrVal;
        continue;
      }
      if (qualifiedAttr === 'xmlns') {
        totalNamespaces += 1;
        if (totalNamespaces > maxNamespaces) {
          throw new FormatError(
            `XML namespace count (${totalNamespaces}) exceeds maximum (${maxNamespaces})`,
            { code: ERROR_CODES.E_MALFORMED_AXML, format: 'xml', offset: attrNameStart }
          );
        }
        namespaces[''] = rawAttrVal;
        continue;
      }

      const aColon = qualifiedAttr.indexOf(':');
      const aPrefix = aColon >= 0 ? qualifiedAttr.slice(0, aColon) : null;
      const aLocal = aColon >= 0 ? qualifiedAttr.slice(aColon + 1) : qualifiedAttr;
      const resolved = resolvePlainXmlAttrValue(rawAttrVal, resources);

      attrs[qualifiedAttr] = resolved.value;
      if (aPrefix && attrs[aLocal] === undefined) {
        attrs[aLocal] = resolved.value;
      }
      typedAttrs.push({
        name: aLocal,
        qualifiedName: qualifiedAttr,
        prefix: aPrefix,
        ns: aPrefix ? (namespaces[aPrefix] ?? null) : null,
        resourceId: aPrefix === 'android' ? (ANDROID_ATTR_IDS[aLocal] ?? null) : null,
        rawValue: rawAttrVal,
        dataType: resolved.dataType,
        data: resolved.data,
        value: resolved.value,
      });
    }

    const node = {
      tag,
      ns: tagPrefix ? (namespaces[tagPrefix] ?? null) : null,
      prefix: tagPrefix,
      attrs,
      typedAttrs,
      children: [],
      text: '',
      lineNumber: tagLine,
    };

    if (stack.length > 0) {
      stack[stack.length - 1].children.push(node);
    } else if (!root) {
      root = node;
    }

    if (!selfClosing) {
      stack.push(node);
    }
  }

  if (stack.length > 0) {
    throw new FormatError(`Unclosed XML element <${stack[stack.length - 1].tag}>`, {
      code: ERROR_CODES.E_MALFORMED_AXML,
      format: 'xml',
      offset: len,
    });
  }
  if (!root) {
    throw new FormatError('XML document contains no root element', {
      code: ERROR_CODES.E_MALFORMED_AXML,
      format: 'xml',
      offset: 0,
    });
  }

  return {
    format: 'xml',
    root,
    strings: [],
    resourceMap: [],
    namespaces,
  };
}

/**
 * Automatically detects and parses either Binary AXML (`0x0003`) or plain UTF-8 XML.
 */
export function parseXmlOrAxml(input, opts = {}) {
  const {
    resources = null,
    maxDepth = MAX_AXML_DEPTH,
    maxInputBytes = undefined,
    maxElements = MAX_XML_ELEMENTS,
    maxAttributes = MAX_XML_ATTRIBUTES,
    maxTextBytes = MAX_XML_TEXT_BYTES,
    maxChunks = undefined,
    maxNodes = undefined,
  } = opts ?? {};

  const forwarded = {
    resources,
    maxDepth,
    maxElements,
    maxAttributes,
    maxTextBytes,
    ...(maxInputBytes !== undefined ? { maxInputBytes } : {}),
    ...(maxChunks !== undefined ? { maxChunks } : {}),
    ...(maxNodes !== undefined ? { maxNodes } : {}),
  };

  if (typeof input === 'string') {
    return parsePlainXml(input, forwarded);
  }
  const buf = toBytes(input, { errorCode: ERROR_CODES.E_MALFORMED_AXML, format: 'axml' });
  if (buf.byteLength >= 8) {
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const type = view.getUint16(0, true);
    if (type === RES_CHUNK_TYPES.RES_XML_TYPE) {
      return parseAxml(buf, forwarded);
    }
  }
  const plainMaxBytes = maxInputBytes ?? MAX_PLAIN_XML_BYTES;
  if (buf.byteLength > plainMaxBytes) {
    throw new FormatError(
      `XML input size (${buf.byteLength} bytes) exceeds maximum (${plainMaxBytes} bytes)`,
      { code: ERROR_CODES.E_MALFORMED_AXML, format: 'xml', offset: 0 }
    );
  }
  // Check if starts with optional UTF-8 BOM + whitespace + '<'
  let start = 0;
  if (buf.byteLength >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    start = 3;
  }
  while (start < buf.byteLength && (buf[start] === 0x20 || buf[start] === 0x09 || buf[start] === 0x0a || buf[start] === 0x0d)) {
    start += 1;
  }
  if (start < buf.byteLength && buf[start] === 0x3c /* '<' */) {
    return parsePlainXml(buf.subarray(start), forwarded);
  }
  // Otherwise treat as AXML so malformed binary headers raise E_MALFORMED_AXML
  return parseAxml(buf, forwarded);
}

function classifyAttrValue(val) {
  if (val !== null && typeof val === 'object' && typeof val.dataType === 'number') {
    return {
      dataType: val.dataType,
      data: (val.data ?? 0) >>> 0,
      rawString: val.rawValue !== undefined ? String(val.rawValue) : null,
    };
  }
  if (val !== null && typeof val === 'object' && val.type === 'reference') {
    return {
      dataType: RES_VALUE_TYPES.TYPE_REFERENCE,
      data: (val.value ?? val.id ?? 0) >>> 0,
      rawString: null,
    };
  }
  if (typeof val === 'boolean') {
    return {
      dataType: RES_VALUE_TYPES.TYPE_INT_BOOLEAN,
      data: val ? 0xffffffff : 0,
      rawString: null,
    };
  }
  if (typeof val === 'number' && Number.isInteger(val)) {
    return {
      dataType: RES_VALUE_TYPES.TYPE_INT_DEC,
      data: val >>> 0,
      rawString: null,
    };
  }
  if (typeof val === 'string') {
    const refMatch = /^@0x([0-9a-fA-F]{8})$/.exec(val);
    if (refMatch) {
      return {
        dataType: RES_VALUE_TYPES.TYPE_REFERENCE,
        data: Number.parseInt(refMatch[1], 16) >>> 0,
        rawString: null,
      };
    }
    return {
      dataType: RES_VALUE_TYPES.TYPE_STRING,
      data: 0,
      rawString: val,
    };
  }
  return {
    dataType: RES_VALUE_TYPES.TYPE_STRING,
    data: 0,
    rawString: String(val ?? ''),
  };
}

/**
 * Encodes an XML element tree into a compliant Android Binary XML (`RES_XML_TYPE = 0x0003`) buffer.
 * Supports `android:*` attribute resource IDs (`RES_XML_RESOURCE_MAP_TYPE`), namespaces, typed values, and CDATA.
 */
export function encodeAxml(
  rootNode,
  {
    utf8 = true,
    namespaces = { android: ANDROID_XML_NS },
  } = {}
) {
  if (!rootNode || typeof rootNode !== 'object' || typeof rootNode.tag !== 'string') {
    throw new FormatError('encodeAxml requires a root node with a string tag', {
      code: ERROR_CODES.E_MALFORMED_AXML,
      format: 'axml',
    });
  }

  // Collect strings: place known Android attribute names first so RESOURCE_MAP indices align 0..K-1.
  const androidAttrNames = [];
  const androidAttrSet = new Set();
  const otherStrings = [];
  const otherSet = new Set();

  const registerAndroidAttr = (localName) => {
    if (Object.prototype.hasOwnProperty.call(ANDROID_ATTR_IDS, localName) && !androidAttrSet.has(localName)) {
      androidAttrSet.add(localName);
      androidAttrNames.push(localName);
    }
  };
  const registerString = (s) => {
    if (s === null || s === undefined) return;
    const str = String(s);
    if (!androidAttrSet.has(str) && !otherSet.has(str)) {
      otherSet.add(str);
      otherStrings.push(str);
    }
  };

  // Pass 1: discover all android attributes first so they occupy indices 0..K-1
  const discoverAttrs = (node) => {
    const attrObj = node.attrs ?? {};
    for (const key of Object.keys(attrObj)) {
      const colon = key.indexOf(':');
      if (colon >= 0) {
        const prefix = key.slice(0, colon);
        const local = key.slice(colon + 1);
        if (prefix === 'android') registerAndroidAttr(local);
      }
    }
    if (Array.isArray(node.children)) {
      for (const child of node.children) discoverAttrs(child);
    }
  };
  discoverAttrs(rootNode);

  // Pass 2: discover all remaining strings
  for (const [prefix, uri] of Object.entries(namespaces)) {
    registerString(prefix);
    registerString(uri);
  }
  const discoverStrings = (node) => {
    registerString(node.tag);
    if (node.ns) registerString(node.ns);
    const attrObj = node.attrs ?? {};
    for (const [key, val] of Object.entries(attrObj)) {
      const colon = key.indexOf(':');
      const local = colon >= 0 ? key.slice(colon + 1) : key;
      registerString(local);
      const classified = classifyAttrValue(val);
      if (classified.rawString !== null) {
        registerString(classified.rawString);
      }
    }
    if (typeof node.text === 'string' && node.text.length > 0) {
      registerString(node.text);
    }
    if (Array.isArray(node.children)) {
      for (const child of node.children) discoverStrings(child);
    }
  };
  discoverStrings(rootNode);

  const allStrings = [...androidAttrNames, ...otherStrings];
  const strIndex = new Map();
  for (let i = 0; i < allStrings.length; i++) {
    strIndex.set(allStrings[i], i);
  }
  const idxOf = (s) => (s !== null && s !== undefined && strIndex.has(s) ? strIndex.get(s) : 0xffffffff);

  const stringPoolChunk = encodeResStringPool(allStrings, { utf8 });

  // Resource map chunk (0x0180)
  let resMapChunk = new Uint8Array(0);
  if (androidAttrNames.length > 0) {
    const rmSize = 8 + androidAttrNames.length * 4;
    const rm = new BinaryWriter({ initialCapacity: rmSize, littleEndian: true });
    rm.u16le(RES_CHUNK_TYPES.RES_XML_RESOURCE_MAP_TYPE);
    rm.u16le(8);
    rm.u32le(rmSize);
    for (const name of androidAttrNames) {
      rm.u32le(ANDROID_ATTR_IDS[name]);
    }
    resMapChunk = rm.toUint8Array();
  }

  // Emit XML node chunks
  const body = new BinaryWriter({ initialCapacity: 512, littleEndian: true });
  let lineCounter = 1;

  const nsEntries = Object.entries(namespaces);
  for (const [prefix, uri] of nsEntries) {
    body.u16le(RES_CHUNK_TYPES.RES_XML_START_NAMESPACE_TYPE);
    body.u16le(16);
    body.u32le(24);
    body.u32le(lineCounter++);
    body.u32le(0xffffffff);
    body.u32le(idxOf(prefix));
    body.u32le(idxOf(uri));
  }

  const emitNode = (node) => {
    const lineNo = node.lineNumber ?? lineCounter++;
    const rawAttrs = Object.entries(node.attrs ?? {});
    const encodedAttrs = rawAttrs.map(([key, val]) => {
      const colon = key.indexOf(':');
      const prefix = colon >= 0 ? key.slice(0, colon) : null;
      const local = colon >= 0 ? key.slice(colon + 1) : key;
      const nsUri = prefix ? (namespaces[prefix] ?? null) : null;
      const classified = classifyAttrValue(val);
      const rawIdx = classified.rawString !== null ? idxOf(classified.rawString) : 0xffffffff;
      const dataVal =
        classified.dataType === RES_VALUE_TYPES.TYPE_STRING ? rawIdx : classified.data;
      return {
        nsIdx: idxOf(nsUri),
        nameIdx: idxOf(local),
        rawIdx,
        dataType: classified.dataType,
        data: dataVal,
      };
    });

    const startSize = 16 + 20 + encodedAttrs.length * 20;
    body.u16le(RES_CHUNK_TYPES.RES_XML_START_ELEMENT_TYPE);
    body.u16le(16);
    body.u32le(startSize);
    body.u32le(lineNo);
    body.u32le(0xffffffff); // comment
    body.u32le(idxOf(node.ns ?? null));
    body.u32le(idxOf(node.tag));
    body.u16le(20); // attributeStart
    body.u16le(20); // attributeSize
    body.u16le(encodedAttrs.length);
    body.u16le(0); // idIndex
    body.u16le(0); // classIndex
    body.u16le(0); // styleIndex

    for (const a of encodedAttrs) {
      body.u32le(a.nsIdx);
      body.u32le(a.nameIdx);
      body.u32le(a.rawIdx);
      body.u16le(8); // Res_value.size
      body.u8(0); // res0
      body.u8(a.dataType);
      body.u32le(a.data >>> 0);
    }

    if (typeof node.text === 'string' && node.text.length > 0) {
      body.u16le(RES_CHUNK_TYPES.RES_XML_CDATA_TYPE);
      body.u16le(16);
      body.u32le(28);
      body.u32le(lineCounter++);
      body.u32le(0xffffffff);
      body.u32le(idxOf(node.text));
      body.u16le(8);
      body.u8(0);
      body.u8(RES_VALUE_TYPES.TYPE_NULL);
      body.u32le(0);
    }

    if (Array.isArray(node.children)) {
      for (const child of node.children) {
        emitNode(child);
      }
    }

    body.u16le(RES_CHUNK_TYPES.RES_XML_END_ELEMENT_TYPE);
    body.u16le(16);
    body.u32le(24);
    body.u32le(lineCounter++);
    body.u32le(0xffffffff);
    body.u32le(idxOf(node.ns ?? null));
    body.u32le(idxOf(node.tag));
  };

  emitNode(rootNode);

  for (let i = nsEntries.length - 1; i >= 0; i--) {
    const [prefix, uri] = nsEntries[i];
    body.u16le(RES_CHUNK_TYPES.RES_XML_END_NAMESPACE_TYPE);
    body.u16le(16);
    body.u32le(24);
    body.u32le(lineCounter++);
    body.u32le(0xffffffff);
    body.u32le(idxOf(prefix));
    body.u32le(idxOf(uri));
  }

  const bodyBytes = body.toUint8Array();
  const totalSize = 8 + stringPoolChunk.byteLength + resMapChunk.byteLength + bodyBytes.byteLength;
  const out = new BinaryWriter({ initialCapacity: totalSize, littleEndian: true });
  out.u16le(RES_CHUNK_TYPES.RES_XML_TYPE);
  out.u16le(8);
  out.u32le(totalSize);
  out.bytes(stringPoolChunk);
  if (resMapChunk.byteLength > 0) out.bytes(resMapChunk);
  out.bytes(bodyBytes);
  return out.toUint8Array();
}
