/**
 * OmniOS Apple Binary Plist (`bplist00`) & XML 1.0 Plist Codec (`F-049`, Edge Case `#27`)
 * Zero-dependency Node.js 24 ESM implementation with full Python `plistlib` round-trip fidelity.
 *
 * Security & Spec Guarantees (Edge Case #27):
 * - Tracks active recursion stack (`visiting` Set) to reject cycles with `E_CYCLIC_PLIST`,
 *   while allowing shared non-cyclic DAG references (common for deduplicated keys/strings).
 * - Enforces `maxDepth = 128` and `maxNodes = 100_000` to defeat DAG expansion / nesting bombs.
 * - Decodes `0x10..0x12` (1/2/4B) as unsigned BE and `0x13`/`0x14` (8/16B) as SIGNED two's complement BE.
 * - Encodes negative integers as `0x13` (8B signed BE) / `0x14` (16B signed BE) per Apple spec.
 * - Decodes/encodes `0x33` dates as float64 BE seconds relative to `2001-01-01T00:00:00.000Z` (`CF_EPOCH_MS`).
 */

import { FormatError, ERROR_CODES } from '../../common/errors.mjs';

export const CF_EPOCH_MS = 978307200000; // Date.UTC(2001, 0, 1, 0, 0, 0)

const BPLIST_MAGIC = [0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30]; // 'bplist00'
const TEXT_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const UTF16BE_DECODER = new TextDecoder('utf-16be', { fatal: false });

const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE_BIGINT = BigInt(Number.MIN_SAFE_INTEGER);
const INT64_MIN = -0x8000000000000000n;
const INT64_MAX = 0x7fffffffffffffffn;
const INT128_MIN = -(1n << 127n);
const INT128_MAX = (1n << 127n) - 1n;

export class PlistUID {
  constructor(value) {
    if (typeof value === 'bigint') {
      if (value < 0n) {
        throw new FormatError(`PlistUID value must be non-negative: ${value}`, {
          code: ERROR_CODES.E_MALFORMED_PLIST,
          format: 'bplist00',
        });
      }
      this.value = value <= MAX_SAFE_BIGINT ? Number(value) : value;
    } else if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
      this.value = value;
    } else {
      throw new FormatError(`Invalid PlistUID value: ${value}`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
      });
    }
  }
}

function toBytes(input, format = 'plist') {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (typeof input === 'string') {
    return TEXT_ENCODER.encode(input);
  }
  throw new FormatError('Expected Uint8Array, ArrayBuffer, or string input for plist', {
    code: ERROR_CODES.E_MALFORMED_PLIST,
    format,
  });
}

function defineSafeProp(obj, key, value) {
  Object.defineProperty(obj, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

function bigIntToJsNumberIfSafe(v) {
  if (v >= MIN_SAFE_BIGINT && v <= MAX_SAFE_BIGINT) {
    return Number(v);
  }
  return v;
}

/**
 * Returns true if buffer begins with the 8-byte `'bplist00'` header.
 */
export function isBinaryPlist(input) {
  if (!input) return false;
  let bytes;
  if (input instanceof Uint8Array) {
    bytes = input;
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else if (ArrayBuffer.isView(input)) {
    bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  } else if (typeof input === 'string') {
    return input.startsWith('bplist00');
  } else {
    return false;
  }
  if (bytes.byteLength < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== BPLIST_MAGIC[i]) return false;
  }
  return true;
}

// ============================================================================
// Binary Plist (`bplist00`) Reader
// ============================================================================

function readUintBE(bytes, offset, size) {
  if (offset < 0 || offset + size > bytes.byteLength) {
    throw new FormatError(`bplist00 read out of bounds at offset ${offset} (size=${size})`, {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'bplist00',
      offset,
    });
  }
  let val = 0n;
  for (let i = 0; i < size; i++) {
    val = (val << 8n) | BigInt(bytes[offset + i]);
  }
  return val;
}

function readSignedBE(bytes, offset, size) {
  const unsigned = readUintBE(bytes, offset, size);
  return BigInt.asIntN(size * 8, unsigned);
}

/**
 * Parse an Apple Binary Plist (`bplist00`) buffer into native JS values.
 */
export function parseBinaryPlist(input, { maxDepth = 128, maxNodes = 100_000 } = {}) {
  const bytes = toBytes(input, 'bplist00');
  if (bytes.byteLength < 40 || !isBinaryPlist(bytes)) {
    throw new FormatError('Invalid bplist00 header or truncated file (< 40 bytes)', {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'bplist00',
      offset: 0,
    });
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const trailerOffset = bytes.byteLength - 32;
  const offsetIntSize = bytes[trailerOffset + 6];
  const objectRefSize = bytes[trailerOffset + 7];
  const numObjectsBig = view.getBigUint64(trailerOffset + 8, false);
  const topObjectBig = view.getBigUint64(trailerOffset + 16, false);
  const offsetTableOffsetBig = view.getBigUint64(trailerOffset + 24, false);

  if (![1, 2, 4, 8].includes(offsetIntSize)) {
    throw new FormatError(`Invalid bplist00 offsetIntSize: ${offsetIntSize}`, {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'bplist00',
      offset: trailerOffset + 6,
    });
  }
  if (![1, 2, 4, 8].includes(objectRefSize)) {
    throw new FormatError(`Invalid bplist00 objectRefSize: ${objectRefSize}`, {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'bplist00',
      offset: trailerOffset + 7,
    });
  }
  if (numObjectsBig === 0n || numObjectsBig > BigInt(Math.max(maxNodes, 1_000_000))) {
    throw new FormatError(`Invalid bplist00 numObjects: ${numObjectsBig}`, {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'bplist00',
      offset: trailerOffset + 8,
    });
  }
  if (topObjectBig >= numObjectsBig) {
    throw new FormatError(`bplist00 topObject (${topObjectBig}) >= numObjects (${numObjectsBig})`, {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'bplist00',
      offset: trailerOffset + 16,
    });
  }

  const numObjects = Number(numObjectsBig);
  const topObject = Number(topObjectBig);
  const offsetTableBytes = numObjectsBig * BigInt(offsetIntSize);

  if (
    offsetTableOffsetBig < 8n ||
    offsetTableOffsetBig > BigInt(trailerOffset) ||
    offsetTableOffsetBig + offsetTableBytes > BigInt(trailerOffset)
  ) {
    throw new FormatError('bplist00 offset table out of bounds', {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'bplist00',
      offset: trailerOffset + 24,
    });
  }

  const offsetTableOffset = Number(offsetTableOffsetBig);
  const offsets = new Array(numObjects);
  for (let i = 0; i < numObjects; i++) {
    const offBig = readUintBE(bytes, offsetTableOffset + i * offsetIntSize, offsetIntSize);
    if (offBig < 8n || offBig >= offsetTableOffsetBig) {
      throw new FormatError(`bplist00 object #${i} offset out of bounds: ${offBig}`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
        offset: offsetTableOffset + i * offsetIntSize,
      });
    }
    offsets[i] = Number(offBig);
  }

  const visiting = new Set();
  let visitedNodes = 0;

  function requirePayloadRange(pos, len) {
    if (!Number.isSafeInteger(len) || len < 0 || pos + len > offsetTableOffset) {
      throw new FormatError(
        `bplist00 payload out of bounds at offset ${pos} (len=${len}, limit=${offsetTableOffset})`,
        {
          code: ERROR_CODES.E_MALFORMED_PLIST,
          format: 'bplist00',
          offset: pos,
        }
      );
    }
  }

  function readLength(lowNibble, pos) {
    if (lowNibble < 0x0f) {
      return { length: lowNibble, nextPos: pos };
    }
    requirePayloadRange(pos, 1);
    const intMarker = bytes[pos];
    if ((intMarker & 0xf0) !== 0x10) {
      throw new FormatError(
        `bplist00 extended length must be integer marker (0x1n), got 0x${intMarker.toString(16)}`,
        {
          code: ERROR_CODES.E_MALFORMED_PLIST,
          format: 'bplist00',
          offset: pos,
        }
      );
    }
    const sizeLog2 = intMarker & 0x0f;
    if (sizeLog2 > 3) {
      throw new FormatError(`bplist00 extended length integer too large (2^${sizeLog2} bytes)`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
        offset: pos,
      });
    }
    const byteCount = 1 << sizeLog2;
    requirePayloadRange(pos + 1, byteCount);
    const lenBig =
      byteCount === 8
        ? readSignedBE(bytes, pos + 1, 8)
        : readUintBE(bytes, pos + 1, byteCount);
    if (lenBig < 0n || lenBig > BigInt(offsetTableOffset)) {
      throw new FormatError(`bplist00 extended length out of bounds: ${lenBig}`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
        offset: pos,
      });
    }
    return { length: Number(lenBig), nextPos: pos + 1 + byteCount };
  }

  function readObjRef(pos) {
    requirePayloadRange(pos, objectRefSize);
    const refBig = readUintBE(bytes, pos, objectRefSize);
    if (refBig >= numObjectsBig) {
      throw new FormatError(`bplist00 object reference out of bounds: ${refBig} >= ${numObjects}`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
        offset: pos,
      });
    }
    return Number(refBig);
  }

  function decodeObject(objIdx, depth) {
    if (objIdx < 0 || objIdx >= numObjects) {
      throw new FormatError(`bplist00 object index out of range: ${objIdx}`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
      });
    }

    const pos = offsets[objIdx];

    // Edge Case #27: Active recursion stack cycle detection (allows non-cyclic shared DAG refs!)
    if (visiting.has(objIdx)) {
      throw new FormatError(`Cyclic object reference detected in bplist00 at object #${objIdx}`, {
        code: ERROR_CODES.E_CYCLIC_PLIST,
        format: 'bplist00',
        offset: pos,
        details: { objectIndex: objIdx },
      });
    }
    if (depth > maxDepth) {
      throw new FormatError(`bplist00 maximum nesting depth (${maxDepth}) exceeded`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
        offset: pos,
        details: { maxDepth },
      });
    }
    visitedNodes += 1;
    if (visitedNodes > maxNodes) {
      throw new FormatError(`bplist00 maximum node count (${maxNodes}) exceeded`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
        offset: pos,
        details: { maxNodes },
      });
    }

    visiting.add(objIdx);
    try {
      requirePayloadRange(pos, 1);
      const marker = bytes[pos];
      const high = marker & 0xf0;
      const low = marker & 0x0f;

      // Singleton primitives: 0x00 (null), 0x08 (false), 0x09 (true)
      if (high === 0x00) {
        if (low === 0x00) return null;
        if (low === 0x08) return false;
        if (low === 0x09) return true;
        throw new FormatError(`Unsupported bplist00 primitive marker: 0x${marker.toString(16)}`, {
          code: ERROR_CODES.E_MALFORMED_PLIST,
          format: 'bplist00',
          offset: pos,
        });
      }

      // Integer: 0x1n (size = 2^n bytes)
      // Edge Case #27: 0x10..0x12 (1,2,4B) = UNSIGNED BE; 0x13 (8B) & 0x14 (16B) = SIGNED BE!
      if (high === 0x10) {
        if (low > 4) {
          throw new FormatError(`Unsupported bplist00 integer byte-width 2^${low}`, {
            code: ERROR_CODES.E_MALFORMED_PLIST,
            format: 'bplist00',
            offset: pos,
          });
        }
        const byteCount = 1 << low;
        requirePayloadRange(pos + 1, byteCount);
        if (byteCount <= 4) {
          return Number(readUintBE(bytes, pos + 1, byteCount));
        }
        // 8-byte (0x13) and 16-byte (0x14): signed two's complement big-endian!
        return bigIntToJsNumberIfSafe(readSignedBE(bytes, pos + 1, byteCount));
      }

      // Real: 0x22 (float32 BE) / 0x23 (float64 BE)
      if (high === 0x20) {
        if (low === 2) {
          requirePayloadRange(pos + 1, 4);
          return view.getFloat32(pos + 1, false);
        }
        if (low === 3) {
          requirePayloadRange(pos + 1, 8);
          return view.getFloat64(pos + 1, false);
        }
        throw new FormatError(`Unsupported bplist00 real marker: 0x${marker.toString(16)}`, {
          code: ERROR_CODES.E_MALFORMED_PLIST,
          format: 'bplist00',
          offset: pos,
        });
      }

      // Date: 0x33 (float64 BE seconds since 2001-01-01T00:00:00.000Z)
      if (marker === 0x33) {
        requirePayloadRange(pos + 1, 8);
        const seconds = view.getFloat64(pos + 1, false);
        return new Date(Math.round(CF_EPOCH_MS + seconds * 1000));
      }

      // Data: 0x4n
      if (high === 0x40) {
        const { length, nextPos } = readLength(low, pos + 1);
        requirePayloadRange(nextPos, length);
        return bytes.slice(nextPos, nextPos + length);
      }

      // ASCII string: 0x5n
      if (high === 0x50) {
        const { length, nextPos } = readLength(low, pos + 1);
        requirePayloadRange(nextPos, length);
        let out = '';
        for (let i = 0; i < length; i++) {
          out += String.fromCharCode(bytes[nextPos + i]);
        }
        return out;
      }

      // UTF-16BE string: 0x6n (length = UTF-16 code unit count -> length * 2 bytes)
      if (high === 0x60) {
        const { length, nextPos } = readLength(low, pos + 1);
        const byteLen = length * 2;
        requirePayloadRange(nextPos, byteLen);
        return UTF16BE_DECODER.decode(bytes.subarray(nextPos, nextPos + byteLen));
      }

      // UID: 0x8n (size = low + 1 bytes unsigned BE)
      if (high === 0x80) {
        const byteCount = low + 1;
        requirePayloadRange(pos + 1, byteCount);
        const uidVal = readUintBE(bytes, pos + 1, byteCount);
        return new PlistUID(uidVal);
      }

      // Array (0xAn) / Set (0xCn)
      if (high === 0xa0 || high === 0xc0) {
        const { length, nextPos } = readLength(low, pos + 1);
        requirePayloadRange(nextPos, length * objectRefSize);
        const arr = new Array(length);
        for (let i = 0; i < length; i++) {
          const ref = readObjRef(nextPos + i * objectRefSize);
          arr[i] = decodeObject(ref, depth + 1);
        }
        return arr;
      }

      // Dictionary: 0xDn (count key refs followed by count value refs)
      if (high === 0xd0) {
        const { length, nextPos } = readLength(low, pos + 1);
        requirePayloadRange(nextPos, length * 2 * objectRefSize);
        const dict = {};
        const valRefsStart = nextPos + length * objectRefSize;
        for (let i = 0; i < length; i++) {
          const keyRef = readObjRef(nextPos + i * objectRefSize);
          const valRef = readObjRef(valRefsStart + i * objectRefSize);
          const key = decodeObject(keyRef, depth + 1);
          if (typeof key !== 'string') {
            throw new FormatError(`bplist00 dictionary key must be string, got ${typeof key}`, {
              code: ERROR_CODES.E_MALFORMED_PLIST,
              format: 'bplist00',
              offset: pos,
            });
          }
          const val = decodeObject(valRef, depth + 1);
          defineSafeProp(dict, key, val);
        }
        return dict;
      }

      throw new FormatError(`Unknown bplist00 marker byte: 0x${marker.toString(16)}`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
        offset: pos,
      });
    } finally {
      visiting.delete(objIdx);
    }
  }

  return decodeObject(topObject, 0);
}

// ============================================================================
// Binary Plist (`bplist00`) Writer
// ============================================================================

function writeUintBEInto(arr, value, byteSize) {
  const big = typeof value === 'bigint' ? value : BigInt(value);
  for (let i = byteSize - 1; i >= 0; i--) {
    arr.push(Number((big >> BigInt(i * 8)) & 0xffn));
  }
}

function writeLengthHeader(out, highNibble, length) {
  if (length < 0x0f) {
    out.push(highNibble | length);
  } else {
    out.push(highNibble | 0x0f);
    if (length <= 0xff) {
      out.push(0x10, length & 0xff);
    } else if (length <= 0xffff) {
      out.push(0x11, (length >>> 8) & 0xff, length & 0xff);
    } else if (length <= 0xffffffff) {
      out.push(
        0x12,
        (length >>> 24) & 0xff,
        (length >>> 16) & 0xff,
        (length >>> 8) & 0xff,
        length & 0xff
      );
    } else {
      out.push(0x13);
      writeUintBEInto(out, BigInt(length), 8);
    }
  }
}

function isAsciiString(str) {
  for (let i = 0; i < str.length; i++) {
    if (str.charCodeAt(i) > 0x7f) return false;
  }
  return true;
}

function encodeIntegerBytes(val) {
  const big = typeof val === 'bigint' ? val : BigInt(val);
  const out = [];
  if (big < 0n) {
    // Edge Case #27: Negative integers MUST be 8B signed (0x13) or 16B signed (0x14)
    if (big >= INT64_MIN) {
      out.push(0x13);
      writeUintBEInto(out, BigInt.asUintN(64, big), 8);
    } else if (big >= INT128_MIN) {
      out.push(0x14);
      writeUintBEInto(out, BigInt.asUintN(128, big), 16);
    } else {
      throw new FormatError(`Integer out of 128-bit signed range for bplist00: ${big}`, {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
      });
    }
  } else if (big <= 0xffn) {
    out.push(0x10, Number(big));
  } else if (big <= 0xffffn) {
    out.push(0x11);
    writeUintBEInto(out, big, 2);
  } else if (big <= 0xffffffffn) {
    out.push(0x12);
    writeUintBEInto(out, big, 4);
  } else if (big <= INT64_MAX) {
    out.push(0x13);
    writeUintBEInto(out, big, 8);
  } else if (big <= INT128_MAX) {
    out.push(0x14);
    writeUintBEInto(out, big, 16);
  } else {
    throw new FormatError(`Integer out of 128-bit range for bplist00: ${big}`, {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'bplist00',
    });
  }
  return out;
}

/**
 * Encode a JS value into Apple Binary Plist (`bplist00`) format (`Uint8Array`).
 * Compatible with host Python 3 `plistlib.loads()` and Apple `CFBinaryPList`.
 */
export function writeBinaryPlist(value) {
  const objects = []; // Array<{ kind, payload, keyRefs?, valRefs?, elemRefs? }>
  const primCache = new Map();
  const visiting = new Set();

  function internPrimitive(cacheKey, node) {
    const existing = primCache.get(cacheKey);
    if (existing !== undefined) return existing;
    const idx = objects.length;
    objects.push(node);
    primCache.set(cacheKey, idx);
    return idx;
  }

  function flatten(val, depth) {
    if (depth > 128) {
      throw new FormatError('Maximum plist nesting depth (128) exceeded during encoding', {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'bplist00',
      });
    }
    if (val === null || val === undefined) {
      return internPrimitive('null', { kind: 'null' });
    }
    if (typeof val === 'boolean') {
      return internPrimitive(val ? 'bool:true' : 'bool:false', { kind: 'bool', value: val });
    }
    if (typeof val === 'bigint') {
      return internPrimitive(`int:${val.toString(10)}`, { kind: 'int', value: val });
    }
    if (typeof val === 'number') {
      if (Number.isInteger(val) && !Object.is(val, -0) && Number.isSafeInteger(val)) {
        return internPrimitive(`int:${val}`, { kind: 'int', value: BigInt(val) });
      }
      const fBuf = new ArrayBuffer(8);
      const dv = new DataView(fBuf);
      dv.setFloat64(0, val, false);
      const hex = dv.getBigUint64(0, false).toString(16);
      return internPrimitive(`real:${hex}`, { kind: 'real', value: val });
    }
    if (typeof val === 'string') {
      return internPrimitive(`str:${val}`, { kind: 'string', value: val });
    }
    if (val instanceof Date) {
      const ms = val.getTime();
      if (Number.isNaN(ms)) {
        throw new FormatError('Cannot encode Invalid Date into bplist00', {
          code: ERROR_CODES.E_MALFORMED_PLIST,
          format: 'bplist00',
        });
      }
      const secs = (ms - CF_EPOCH_MS) / 1000;
      const fBuf = new ArrayBuffer(8);
      const dv = new DataView(fBuf);
      dv.setFloat64(0, secs, false);
      const hex = dv.getBigUint64(0, false).toString(16);
      return internPrimitive(`date:${hex}`, { kind: 'date', value: secs });
    }
    if (val instanceof PlistUID) {
      return internPrimitive(`uid:${val.value}`, { kind: 'uid', value: BigInt(val.value) });
    }
    if (val instanceof Uint8Array || val instanceof ArrayBuffer || ArrayBuffer.isView(val)) {
      const u8 =
        val instanceof Uint8Array
          ? val
          : val instanceof ArrayBuffer
            ? new Uint8Array(val)
            : new Uint8Array(val.buffer, val.byteOffset, val.byteLength);
      let keyHex = 'data:';
      for (let i = 0; i < Math.min(u8.byteLength, 32); i++) {
        keyHex += u8[i].toString(16).padStart(2, '0');
      }
      if (u8.byteLength <= 32) {
        return internPrimitive(keyHex, { kind: 'data', value: u8 });
      }
      const idx = objects.length;
      objects.push({ kind: 'data', value: u8 });
      return idx;
    }

    if (typeof val === 'object') {
      if (visiting.has(val)) {
        throw new FormatError('Cyclic object reference detected while encoding bplist00', {
          code: ERROR_CODES.E_CYCLIC_PLIST,
          format: 'bplist00',
        });
      }
      visiting.add(val);
      try {
        if (Array.isArray(val)) {
          const idx = objects.length;
          const node = { kind: 'array', elemRefs: [] };
          objects.push(node);
          for (let i = 0; i < val.length; i++) {
            node.elemRefs.push(flatten(val[i], depth + 1));
          }
          return idx;
        }

        const idx = objects.length;
        const node = { kind: 'dict', keyRefs: [], valRefs: [] };
        objects.push(node);
        const entries = val instanceof Map ? Array.from(val.entries()) : Object.entries(val);
        for (const [k, v] of entries) {
          if (v === undefined) continue;
          node.keyRefs.push(flatten(String(k), depth + 1));
          node.valRefs.push(flatten(v, depth + 1));
        }
        return idx;
      } finally {
        visiting.delete(val);
      }
    }

    throw new FormatError(`Unsupported value type for bplist00: ${typeof val}`, {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'bplist00',
    });
  }

  const topIndex = flatten(value, 0);
  const numObjects = objects.length;
  const objectRefSize = numObjects < 256 ? 1 : numObjects < 65536 ? 2 : 4;

  const body = [...BPLIST_MAGIC];
  const offsets = new Array(numObjects);

  for (let i = 0; i < numObjects; i++) {
    offsets[i] = body.length;
    const node = objects[i];

    switch (node.kind) {
      case 'null':
        body.push(0x00);
        break;
      case 'bool':
        body.push(node.value ? 0x09 : 0x08);
        break;
      case 'int': {
        const enc = encodeIntegerBytes(node.value);
        for (let j = 0; j < enc.length; j++) body.push(enc[j]);
        break;
      }
      case 'real': {
        body.push(0x23);
        const fBuf = new Uint8Array(8);
        new DataView(fBuf.buffer).setFloat64(0, node.value, false);
        for (let j = 0; j < 8; j++) body.push(fBuf[j]);
        break;
      }
      case 'date': {
        body.push(0x33);
        const fBuf = new Uint8Array(8);
        new DataView(fBuf.buffer).setFloat64(0, node.value, false);
        for (let j = 0; j < 8; j++) body.push(fBuf[j]);
        break;
      }
      case 'data': {
        const u8 = node.value;
        writeLengthHeader(body, 0x40, u8.byteLength);
        for (let j = 0; j < u8.byteLength; j++) body.push(u8[j]);
        break;
      }
      case 'string': {
        const s = node.value;
        if (isAsciiString(s)) {
          writeLengthHeader(body, 0x50, s.length);
          for (let j = 0; j < s.length; j++) body.push(s.charCodeAt(j) & 0x7f);
        } else {
          writeLengthHeader(body, 0x60, s.length);
          for (let j = 0; j < s.length; j++) {
            const cu = s.charCodeAt(j);
            body.push((cu >>> 8) & 0xff, cu & 0xff);
          }
        }
        break;
      }
      case 'uid': {
        const v = node.value;
        let byteSize = 1;
        if (v > 0xffffffffn) byteSize = 8;
        else if (v > 0xffffn) byteSize = 4;
        else if (v > 0xffn) byteSize = 2;
        body.push(0x80 | (byteSize - 1));
        writeUintBEInto(body, v, byteSize);
        break;
      }
      case 'array': {
        writeLengthHeader(body, 0xa0, node.elemRefs.length);
        for (let j = 0; j < node.elemRefs.length; j++) {
          writeUintBEInto(body, node.elemRefs[j], objectRefSize);
        }
        break;
      }
      case 'dict': {
        writeLengthHeader(body, 0xd0, node.keyRefs.length);
        for (let j = 0; j < node.keyRefs.length; j++) {
          writeUintBEInto(body, node.keyRefs[j], objectRefSize);
        }
        for (let j = 0; j < node.valRefs.length; j++) {
          writeUintBEInto(body, node.valRefs[j], objectRefSize);
        }
        break;
      }
    }
  }

  const offsetTableOffset = body.length;
  const offsetIntSize =
    offsetTableOffset < 256
      ? 1
      : offsetTableOffset < 65536
        ? 2
        : offsetTableOffset < 0x100000000
          ? 4
          : 8;

  for (let i = 0; i < numObjects; i++) {
    writeUintBEInto(body, offsets[i], offsetIntSize);
  }

  // 32-byte Trailer
  body.push(0, 0, 0, 0, 0, 0); // 6 unused bytes
  body.push(offsetIntSize);
  body.push(objectRefSize);
  writeUintBEInto(body, BigInt(numObjects), 8);
  writeUintBEInto(body, BigInt(topIndex), 8);
  writeUintBEInto(body, BigInt(offsetTableOffset), 8);

  return Uint8Array.from(body);
}

export const encodeBinaryPlist = writeBinaryPlist;

// ============================================================================
// XML 1.0 Plist Parser
// ============================================================================

function decodeXmlEntities(text) {
  return text.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g, (_match, entity) => {
    switch (entity) {
      case 'amp': return '&';
      case 'lt': return '<';
      case 'gt': return '>';
      case 'quot': return '"';
      case 'apos': return "'";
      default: {
        let code;
        if (entity.startsWith('#x') || entity.startsWith('#X')) {
          code = Number.parseInt(entity.slice(2), 16);
        } else {
          code = Number.parseInt(entity.slice(1), 10);
        }
        if (!Number.isInteger(code) || code < 0 || code > 0x10ffff) {
          throw new FormatError(`Invalid XML character reference: &${entity};`, {
            code: ERROR_CODES.E_MALFORMED_PLIST,
            format: 'xml-plist',
          });
        }
        return String.fromCodePoint(code);
      }
    }
  });
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function decodeBase64Strict(raw) {
  const clean = raw.replace(/\s+/g, '');
  if (clean.length === 0) return new Uint8Array(0);
  if (clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new FormatError('Invalid base64 data inside XML plist <data>', {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'xml-plist',
    });
  }
  const buf = Buffer.from(clean, 'base64');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).slice();
}

function encodeBase64(bytes) {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
}

/**
 * Parse an Apple XML 1.0 plist string or UTF-8 buffer into native JS values.
 */
export function parseXmlPlist(input, { maxDepth = 128, maxNodes = 100_000 } = {}) {
  const xml =
    typeof input === 'string'
      ? input
      : UTF8_DECODER.decode(toBytes(input, 'xml-plist'));

  const len = xml.length;
  let pos = 0;
  let nodeCount = 0;

  function fail(msg) {
    throw new FormatError(msg, {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'xml-plist',
      offset: pos,
    });
  }

  function skipWsAndComments() {
    while (pos < len) {
      // Skip whitespace
      while (pos < len && (xml[pos] === ' ' || xml[pos] === '\t' || xml[pos] === '\r' || xml[pos] === '\n')) {
        pos++;
      }
      // XML processing instruction <?...?>
      if (xml.startsWith('<?', pos)) {
        const end = xml.indexOf('?>', pos + 2);
        if (end === -1) fail('Unterminated XML processing instruction');
        pos = end + 2;
        continue;
      }
      // XML comment <!-- ... -->
      if (xml.startsWith('<!--', pos)) {
        const end = xml.indexOf('-->', pos + 4);
        if (end === -1) fail('Unterminated XML comment');
        pos = end + 3;
        continue;
      }
      // DOCTYPE declaration <!DOCTYPE ...>
      if (xml.startsWith('<!DOCTYPE', pos) || xml.startsWith('<!doctype', pos)) {
        let depth = 0;
        let inQuote = null;
        pos += 9;
        while (pos < len) {
          const ch = xml[pos++];
          if (inQuote) {
            if (ch === inQuote) inQuote = null;
          } else if (ch === '"' || ch === "'") {
            inQuote = ch;
          } else if (ch === '[') {
            depth++;
          } else if (ch === ']') {
            depth--;
          } else if (ch === '>' && depth <= 0) {
            break;
          }
        }
        continue;
      }
      break;
    }
  }

  function readTag() {
    skipWsAndComments();
    if (pos >= len || xml[pos] !== '<') {
      fail('Expected XML tag');
    }
    const start = pos;
    pos++; // consume '<'
    let closing = false;
    if (pos < len && xml[pos] === '/') {
      closing = true;
      pos++;
    }
    const nameStart = pos;
    while (pos < len && /[A-Za-z0-9_:-]/.test(xml[pos])) {
      pos++;
    }
    const name = xml.slice(nameStart, pos);
    if (!name) fail('Empty XML tag name');

    // Scan to '>' respecting quoted attribute values
    let selfClosing = false;
    let inQuote = null;
    while (pos < len) {
      const ch = xml[pos++];
      if (inQuote) {
        if (ch === inQuote) inQuote = null;
      } else if (ch === '"' || ch === "'") {
        inQuote = ch;
      } else if (ch === '>') {
        // Check if preceding non-ws char was '/'
        let j = pos - 2;
        while (j > nameStart && (xml[j] === ' ' || xml[j] === '\t' || xml[j] === '\r' || xml[j] === '\n')) {
          j--;
        }
        if (xml[j] === '/') selfClosing = true;
        return { name, closing, selfClosing, start };
      }
    }
    fail(`Unterminated XML tag <${name}>`);
  }

  function readTextUntilClose(expectedTag) {
    let out = '';
    while (pos < len) {
      if (xml.startsWith('<![CDATA[', pos)) {
        const end = xml.indexOf(']]>', pos + 9);
        if (end === -1) fail('Unterminated CDATA section');
        out += xml.slice(pos + 9, end);
        pos = end + 3;
        continue;
      }
      if (xml.startsWith('<!--', pos)) {
        const end = xml.indexOf('-->', pos + 4);
        if (end === -1) fail('Unterminated XML comment');
        pos = end + 3;
        continue;
      }
      if (xml[pos] === '<') {
        const tag = readTag();
        if (!tag.closing || tag.name !== expectedTag) {
          fail(`Expected </${expectedTag}>, found <${tag.closing ? '/' : ''}${tag.name}>`);
        }
        return out;
      }
      const nextLt = xml.indexOf('<', pos);
      if (nextLt === -1) {
        fail(`Unexpected EOF before </${expectedTag}>`);
      }
      out += decodeXmlEntities(xml.slice(pos, nextLt));
      pos = nextLt;
    }
    fail(`Unexpected EOF before </${expectedTag}>`);
  }

  function parseValue(depth) {
    if (depth > maxDepth) {
      fail(`XML plist maximum nesting depth (${maxDepth}) exceeded`);
    }
    nodeCount += 1;
    if (nodeCount > maxNodes) {
      fail(`XML plist maximum node count (${maxNodes}) exceeded`);
    }
    const tag = readTag();
    if (tag.closing) {
      fail(`Unexpected closing tag </${tag.name}>`);
    }
    return parseElement(tag, depth);
  }

  function parseElement(tag, depth) {
    switch (tag.name) {
      case 'true':
        if (!tag.selfClosing) {
          const close = readTag();
          if (!close.closing || close.name !== 'true') fail('Expected </true>');
        }
        return true;

      case 'false':
        if (!tag.selfClosing) {
          const close = readTag();
          if (!close.closing || close.name !== 'false') fail('Expected </false>');
        }
        return false;

      case 'string':
        return tag.selfClosing ? '' : readTextUntilClose('string');

      case 'integer': {
        const raw = (tag.selfClosing ? '' : readTextUntilClose('integer')).trim();
        if (!/^[+-]?(0x[0-9a-fA-F]+|[0-9]+)$/.test(raw)) {
          fail(`Invalid <integer> value: "${raw}"`);
        }
        const neg = raw.startsWith('-');
        const body = neg || raw.startsWith('+') ? raw.slice(1) : raw;
        const big = neg ? -BigInt(body) : BigInt(body);
        return bigIntToJsNumberIfSafe(big);
      }

      case 'real': {
        const raw = (tag.selfClosing ? '' : readTextUntilClose('real')).trim();
        const lower = raw.toLowerCase();
        if (lower === 'nan') return Number.NaN;
        if (lower === 'inf' || lower === '+inf' || lower === 'infinity' || lower === '+infinity') {
          return Number.POSITIVE_INFINITY;
        }
        if (lower === '-inf' || lower === '-infinity') {
          return Number.NEGATIVE_INFINITY;
        }
        const num = Number(raw);
        if (raw.length === 0 || Number.isNaN(num)) {
          fail(`Invalid <real> value: "${raw}"`);
        }
        return num;
      }

      case 'date': {
        const raw = (tag.selfClosing ? '' : readTextUntilClose('date')).trim();
        const ms = Date.parse(raw);
        if (Number.isNaN(ms)) {
          fail(`Invalid ISO-8601 <date> value: "${raw}"`);
        }
        return new Date(ms);
      }

      case 'data': {
        const raw = tag.selfClosing ? '' : readTextUntilClose('data');
        return decodeBase64Strict(raw);
      }

      case 'array': {
        const arr = [];
        if (tag.selfClosing) return arr;
        while (true) {
          skipWsAndComments();
          if (pos >= len) fail('Unterminated <array>');
          const next = readTag();
          if (next.closing) {
            if (next.name !== 'array') fail(`Expected </array>, found </${next.name}>`);
            return arr;
          }
          if (depth + 1 > maxDepth) fail(`XML plist maximum nesting depth (${maxDepth}) exceeded`);
          nodeCount += 1;
          if (nodeCount > maxNodes) fail(`XML plist maximum node count (${maxNodes}) exceeded`);
          arr.push(parseElement(next, depth + 1));
        }
      }

      case 'dict': {
        const dict = {};
        if (tag.selfClosing) return dict;
        while (true) {
          skipWsAndComments();
          if (pos >= len) fail('Unterminated <dict>');
          const keyTag = readTag();
          if (keyTag.closing) {
            if (keyTag.name !== 'dict') fail(`Expected </dict>, found </${keyTag.name}>`);
            return dict;
          }
          if (keyTag.name !== 'key') {
            fail(`Expected <key> inside <dict>, found <${keyTag.name}>`);
          }
          const key = keyTag.selfClosing ? '' : readTextUntilClose('key');
          const val = parseValue(depth + 1);
          defineSafeProp(dict, key, val);
        }
      }

      default:
        fail(`Unknown XML plist element <${tag.name}>`);
    }
  }

  // Strip UTF-8 BOM if present
  if (xml.charCodeAt(0) === 0xfeff) {
    pos = 1;
  }

  const rootTag = readTag();
  if (rootTag.closing || rootTag.name !== 'plist') {
    fail(`Expected root <plist> tag, found <${rootTag.closing ? '/' : ''}${rootTag.name}>`);
  }
  if (rootTag.selfClosing) {
    return null;
  }

  skipWsAndComments();
  if (xml.startsWith('</plist', pos)) {
    readTag();
    return null;
  }

  const result = parseValue(0);
  const endTag = readTag();
  if (!endTag.closing || endTag.name !== 'plist') {
    fail(`Expected </plist>, found <${endTag.closing ? '/' : ''}${endTag.name}>`);
  }
  return result;
}

// ============================================================================
// XML 1.0 Plist Writer
// ============================================================================

function formatIsoUtcDate(date) {
  const ms = date.getTime();
  if (Number.isNaN(ms)) {
    throw new FormatError('Cannot encode Invalid Date into XML plist', {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'xml-plist',
    });
  }
  // Apple & Python plistlib expect YYYY-MM-DDTHH:MM:SSZ (no fractional ms)
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Encode a JS value into an Apple XML 1.0 plist string.
 */
export function writeXmlPlist(value) {
  const visiting = new Set();

  function render(val, indent, depth) {
    if (depth > 128) {
      throw new FormatError('Maximum plist nesting depth (128) exceeded during XML encoding', {
        code: ERROR_CODES.E_MALFORMED_PLIST,
        format: 'xml-plist',
      });
    }
    const pad = '\t'.repeat(indent);

    if (typeof val === 'boolean') {
      return `${pad}${val ? '<true/>' : '<false/>'}`;
    }
    if (typeof val === 'bigint') {
      return `${pad}<integer>${val.toString(10)}</integer>`;
    }
    if (typeof val === 'number') {
      if (Number.isInteger(val) && !Object.is(val, -0) && Number.isSafeInteger(val)) {
        return `${pad}<integer>${val}</integer>`;
      }
      if (Number.isNaN(val)) return `${pad}<real>nan</real>`;
      if (val === Number.POSITIVE_INFINITY) return `${pad}<real>inf</real>`;
      if (val === Number.NEGATIVE_INFINITY) return `${pad}<real>-inf</real>`;
      return `${pad}<real>${val}</real>`;
    }
    if (typeof val === 'string') {
      return `${pad}<string>${escapeXml(val)}</string>`;
    }
    if (val instanceof Date) {
      return `${pad}<date>${formatIsoUtcDate(val)}</date>`;
    }
    if (val instanceof PlistUID) {
      return `${pad}<dict>\n${pad}\t<key>CF$UID</key>\n${pad}\t<integer>${val.value}</integer>\n${pad}</dict>`;
    }
    if (val instanceof Uint8Array || val instanceof ArrayBuffer || ArrayBuffer.isView(val)) {
      const u8 =
        val instanceof Uint8Array
          ? val
          : val instanceof ArrayBuffer
            ? new Uint8Array(val)
            : new Uint8Array(val.buffer, val.byteOffset, val.byteLength);
      const b64 = encodeBase64(u8);
      if (b64.length === 0) return `${pad}<data></data>`;
      return `${pad}<data>${b64}</data>`;
    }
    if (val === null || val === undefined) {
      return `${pad}<string></string>`;
    }
    if (typeof val === 'object') {
      if (visiting.has(val)) {
        throw new FormatError('Cyclic object reference detected while encoding XML plist', {
          code: ERROR_CODES.E_CYCLIC_PLIST,
          format: 'xml-plist',
        });
      }
      visiting.add(val);
      try {
        if (Array.isArray(val)) {
          if (val.length === 0) return `${pad}<array/>`;
          const items = val.map((item) => render(item, indent + 1, depth + 1));
          return `${pad}<array>\n${items.join('\n')}\n${pad}</array>`;
        }
        const entries = (val instanceof Map ? Array.from(val.entries()) : Object.entries(val)).filter(
          ([, v]) => v !== undefined
        );
        if (entries.length === 0) return `${pad}<dict/>`;
        const lines = [];
        const innerPad = '\t'.repeat(indent + 1);
        for (const [k, v] of entries) {
          lines.push(`${innerPad}<key>${escapeXml(k)}</key>`);
          lines.push(render(v, indent + 1, depth + 1));
        }
        return `${pad}<dict>\n${lines.join('\n')}\n${pad}</dict>`;
      } finally {
        visiting.delete(val);
      }
    }

    throw new FormatError(`Unsupported value type for XML plist: ${typeof val}`, {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'xml-plist',
    });
  }

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    render(value, 0, 0),
    '</plist>',
    '',
  ].join('\n');
}

export const encodeXmlPlist = writeXmlPlist;

/**
 * Auto-detect binary (`bplist00`) vs XML 1.0 plist and parse cleanly.
 */
export function parsePlist(input, opts = {}) {
  if (isBinaryPlist(input)) {
    return parseBinaryPlist(input, opts);
  }
  return parseXmlPlist(input, opts);
}
