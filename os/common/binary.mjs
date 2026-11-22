/**
 * OmniOS Zero-Dependency Binary Codecs:
 * BinaryReader, BinaryWriter, IEEE CRC-32, RFC 1950 Adler-32,
 * DEX 32-bit LEB128 (ULEB128, SLEB128, ULEB128p1), and DEX Modified UTF-8 (MUTF-8).
 */

import { FormatError, ERROR_CODES } from './errors.mjs';

const TEXT_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const UTF8_DECODER_FATAL = new TextDecoder('utf-8', { fatal: true });
const UTF16LE_DECODER = new TextDecoder('utf-16le');
const UTF16BE_DECODER = new TextDecoder('utf-16be');

// Precomputed IEEE 802.3 CRC-32 table (reflected polynomial 0xEDB88320).
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let bit = 0; bit < 8; bit++) {
    c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC32_TABLE[i] = c >>> 0;
}

const MOD_ADLER = 65521;
const ADLER_NMAX = 5552;
const MAX_U64 = 0xffffffffffffffffn;
const MIN_I64 = -0x8000000000000000n;
const MAX_I64 = 0x7fffffffffffffffn;

function toUint8Array(input, { allowString = false } = {}) {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (allowString && typeof input === 'string') {
    return TEXT_ENCODER.encode(input);
  }
  throw new TypeError('Expected Uint8Array, ArrayBuffer, or ArrayBufferView');
}

function resolveSliceBounds(bufLength, offset, length) {
  if (!Number.isInteger(offset) || offset < 0 || offset > bufLength) {
    throw new FormatError(`Offset out of bounds: ${offset} (length=${bufLength})`, {
      code: ERROR_CODES.ERANGE,
      offset,
    });
  }
  const len = length === undefined ? bufLength - offset : length;
  if (!Number.isInteger(len) || len < 0 || offset + len > bufLength) {
    throw new FormatError(`Length out of bounds: offset=${offset}, length=${len}, total=${bufLength}`, {
      code: ERROR_CODES.ERANGE,
      offset,
    });
  }
  return { start: offset, end: offset + len };
}

function codeUnitsToString(units) {
  const CHUNK = 4096;
  if (units.length <= CHUNK) {
    return String.fromCharCode(...units);
  }
  let out = '';
  for (let i = 0; i < units.length; i += CHUNK) {
    out += String.fromCharCode(...units.slice(i, i + CHUNK));
  }
  return out;
}

function normalizeU64(value, offset) {
  if (typeof value === 'bigint') {
    if (value < 0n || value > MAX_U64) {
      throw new FormatError(`u64 out of range: ${value}`, { code: ERROR_CODES.ERANGE, offset });
    }
    return value;
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value);
  }
  throw new FormatError(`Invalid u64 value: ${value}`, { code: ERROR_CODES.ERANGE, offset });
}

function normalizeI64(value, offset) {
  if (typeof value === 'bigint') {
    if (value < MIN_I64 || value > MAX_I64) {
      throw new FormatError(`i64 out of range: ${value}`, { code: ERROR_CODES.ERANGE, offset });
    }
    return value;
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  throw new FormatError(`Invalid i64 value: ${value}`, { code: ERROR_CODES.ERANGE, offset });
}

function checkIntRange(value, min, max, label, offset) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new FormatError(`${label} out of range [${min}, ${max}]: ${value}`, {
      code: ERROR_CODES.ERANGE,
      offset,
    });
  }
}

function checkFloat(value, label, offset) {
  if (typeof value !== 'number') {
    throw new FormatError(`Invalid ${label} value: ${value}`, {
      code: ERROR_CODES.ERANGE,
      offset,
    });
  }
}

/**
 * IEEE 802.3 CRC-32 checksum.
 */
export function crc32(bytes, seed = 0, offset = 0, length = undefined) {
  const buf = toUint8Array(bytes, { allowString: true });
  const { start, end } = resolveSliceBounds(buf.byteLength, offset, length);
  let crc = ((seed >>> 0) ^ 0xffffffff) >>> 0;
  for (let i = start; i < end; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * RFC 1950 Adler-32 checksum (used in DEX header_item and zlib streams).
 */
export function adler32(bytes, offset = 0, length = undefined, seed = 1) {
  const buf = toUint8Array(bytes, { allowString: true });
  const { start, end } = resolveSliceBounds(buf.byteLength, offset, length);
  let s1 = (seed >>> 0) & 0xffff;
  let s2 = ((seed >>> 0) >>> 16) & 0xffff;

  let i = start;
  while (i < end) {
    const chunkEnd = Math.min(end, i + ADLER_NMAX);
    while (i < chunkEnd) {
      s1 += buf[i++];
      s2 += s1;
    }
    s1 %= MOD_ADLER;
    s2 %= MOD_ADLER;
  }

  return (((s2 << 16) | s1) >>> 0);
}

/**
 * DEX 32-bit unsigned LEB128 encoder (1..5 bytes).
 */
export function encodeUleb128(value) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new FormatError(`ULEB128 value out of uint32 range: ${value}`, {
      code: ERROR_CODES.E_INVALID_LEB128,
      format: 'leb128',
    });
  }
  const out = [];
  let v = value >>> 0;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v !== 0) byte |= 0x80;
    out.push(byte);
  } while (v !== 0);
  return new Uint8Array(out);
}

/**
 * DEX 32-bit unsigned LEB128 decoder (strictly rejects >5-byte and uint32 overflow encodings).
 */
export function decodeUleb128(bytes, offset = 0) {
  const buf = toUint8Array(bytes);
  if (!Number.isInteger(offset) || offset < 0 || offset >= buf.byteLength) {
    throw new FormatError(`ULEB128 offset out of bounds: ${offset}`, {
      code: ERROR_CODES.E_INVALID_LEB128,
      format: 'leb128',
      offset,
    });
  }

  let result = 0;
  for (let i = 0; i < 5; i++) {
    const pos = offset + i;
    if (pos >= buf.byteLength) {
      throw new FormatError('Truncated ULEB128 sequence', {
        code: ERROR_CODES.E_INVALID_LEB128,
        format: 'leb128',
        offset: pos,
      });
    }
    const byte = buf[pos];
    if (i === 4) {
      if ((byte & 0x80) !== 0) {
        throw new FormatError('ULEB128 exceeds maximum 5-byte 32-bit length', {
          code: ERROR_CODES.E_INVALID_LEB128,
          format: 'leb128',
          offset: pos,
        });
      }
      if ((byte & 0xf0) !== 0) {
        throw new FormatError('ULEB128 5th byte overflows uint32', {
          code: ERROR_CODES.E_INVALID_LEB128,
          format: 'leb128',
          offset: pos,
        });
      }
    }
    result |= (byte & 0x7f) << (i * 7);
    if ((byte & 0x80) === 0) {
      return { value: result >>> 0, bytesRead: i + 1, nextOffset: pos + 1 };
    }
  }

  throw new FormatError('ULEB128 exceeds maximum 5-byte 32-bit length', {
    code: ERROR_CODES.E_INVALID_LEB128,
    format: 'leb128',
    offset,
  });
}

/**
 * DEX 32-bit signed LEB128 encoder (1..5 bytes).
 */
export function encodeSleb128(value) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < -2147483648 || value > 2147483647) {
    throw new FormatError(`SLEB128 value out of int32 range: ${value}`, {
      code: ERROR_CODES.E_INVALID_LEB128,
      format: 'leb128',
    });
  }
  const out = [];
  let v = value | 0;
  let more = true;
  while (more) {
    let byte = v & 0x7f;
    v >>= 7;
    if ((v === 0 && (byte & 0x40) === 0) || (v === -1 && (byte & 0x40) !== 0)) {
      more = false;
    } else {
      byte |= 0x80;
    }
    out.push(byte);
  }
  return new Uint8Array(out);
}

/**
 * DEX 32-bit signed LEB128 decoder (strictly rejects >5-byte and int32 overflow encodings).
 */
export function decodeSleb128(bytes, offset = 0) {
  const buf = toUint8Array(bytes);
  if (!Number.isInteger(offset) || offset < 0 || offset >= buf.byteLength) {
    throw new FormatError(`SLEB128 offset out of bounds: ${offset}`, {
      code: ERROR_CODES.E_INVALID_LEB128,
      format: 'leb128',
      offset,
    });
  }

  let result = 0;
  for (let i = 0; i < 5; i++) {
    const pos = offset + i;
    if (pos >= buf.byteLength) {
      throw new FormatError('Truncated SLEB128 sequence', {
        code: ERROR_CODES.E_INVALID_LEB128,
        format: 'leb128',
        offset: pos,
      });
    }
    const byte = buf[pos];
    const shift = i * 7;
    if (i === 4) {
      if ((byte & 0x80) !== 0) {
        throw new FormatError('SLEB128 exceeds maximum 5-byte 32-bit length', {
          code: ERROR_CODES.E_INVALID_LEB128,
          format: 'leb128',
          offset: pos,
        });
      }
      const signBit = (byte & 0x08) !== 0;
      const upper = byte & 0x70;
      if ((!signBit && upper !== 0x00) || (signBit && upper !== 0x70)) {
        throw new FormatError('SLEB128 5th byte overflows int32', {
          code: ERROR_CODES.E_INVALID_LEB128,
          format: 'leb128',
          offset: pos,
        });
      }
      result |= (byte & 0x0f) << 28;
      return { value: result | 0, bytesRead: 5, nextOffset: pos + 1 };
    }

    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      const nextShift = shift + 7;
      if (nextShift < 32 && (byte & 0x40) !== 0) {
        result |= ~0 << nextShift;
      }
      return { value: result | 0, bytesRead: i + 1, nextOffset: pos + 1 };
    }
  }

  throw new FormatError('SLEB128 exceeds maximum 5-byte 32-bit length', {
    code: ERROR_CODES.E_INVALID_LEB128,
    format: 'leb128',
    offset,
  });
}

/**
 * DEX ULEB128p1 encoder (-1 .. 0xFFFFFFFE encoded as value + 1).
 */
export function encodeUleb128p1(value) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < -1 || value > 0xfffffffe) {
    throw new FormatError(`ULEB128p1 value out of range [-1, 0xFFFFFFFE]: ${value}`, {
      code: ERROR_CODES.E_INVALID_LEB128,
      format: 'leb128',
    });
  }
  return encodeUleb128(value + 1);
}

/**
 * DEX ULEB128p1 decoder.
 */
export function decodeUleb128p1(bytes, offset = 0) {
  const decoded = decodeUleb128(bytes, offset);
  return {
    value: decoded.value - 1,
    bytesRead: decoded.bytesRead,
    nextOffset: decoded.nextOffset,
  };
}

/**
 * DEX Modified UTF-8 encoder (NUL -> 0xC0 0x80, UTF-16 surrogates as 3-byte sequences).
 */
export function encodeMutf8(str, { nullTerminate = false } = {}) {
  if (typeof str !== 'string') {
    throw new FormatError('encodeMutf8 expects a string', {
      code: ERROR_CODES.E_INVALID_MUTF8,
      format: 'mutf8',
    });
  }
  const out = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c === 0x0000) {
      out.push(0xc0, 0x80);
    } else if (c <= 0x007f) {
      out.push(c);
    } else if (c <= 0x07ff) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  if (nullTerminate) {
    out.push(0x00);
  }
  return new Uint8Array(out);
}

/**
 * DEX Modified UTF-8 decoder (strictly rejects raw NUL, 4-byte UTF-8, overlongs, bad continuations).
 */
export function decodeMutf8(bytes, offset = 0, byteLength = undefined) {
  const buf = toUint8Array(bytes);
  const { start, end } = resolveSliceBounds(buf.byteLength, offset, byteLength);
  const units = [];

  let i = start;
  while (i < end) {
    const b1 = buf[i];
    if (b1 === 0x00) {
      throw new FormatError('Raw NUL byte forbidden in MUTF-8 payload', {
        code: ERROR_CODES.E_INVALID_MUTF8,
        format: 'mutf8',
        offset: i,
      });
    }
    if (b1 <= 0x7f) {
      units.push(b1);
      i += 1;
      continue;
    }
    if (b1 >= 0xc0 && b1 <= 0xdf) {
      if (i + 1 >= end) {
        throw new FormatError('Truncated 2-byte MUTF-8 sequence', {
          code: ERROR_CODES.E_INVALID_MUTF8,
          format: 'mutf8',
          offset: i,
        });
      }
      const b2 = buf[i + 1];
      if ((b2 & 0xc0) !== 0x80) {
        throw new FormatError('Invalid MUTF-8 continuation byte', {
          code: ERROR_CODES.E_INVALID_MUTF8,
          format: 'mutf8',
          offset: i + 1,
        });
      }
      if (b1 === 0xc0) {
        if (b2 !== 0x80) {
          throw new FormatError('Overlong 2-byte MUTF-8 sequence', {
            code: ERROR_CODES.E_INVALID_MUTF8,
            format: 'mutf8',
            offset: i,
          });
        }
        units.push(0x0000);
      } else if (b1 === 0xc1) {
        throw new FormatError('Overlong 2-byte MUTF-8 sequence', {
          code: ERROR_CODES.E_INVALID_MUTF8,
          format: 'mutf8',
          offset: i,
        });
      } else {
        units.push(((b1 & 0x1f) << 6) | (b2 & 0x3f));
      }
      i += 2;
      continue;
    }
    if (b1 >= 0xe0 && b1 <= 0xef) {
      if (i + 2 >= end) {
        throw new FormatError('Truncated 3-byte MUTF-8 sequence', {
          code: ERROR_CODES.E_INVALID_MUTF8,
          format: 'mutf8',
          offset: i,
        });
      }
      const b2 = buf[i + 1];
      const b3 = buf[i + 2];
      if ((b2 & 0xc0) !== 0x80 || (b3 & 0xc0) !== 0x80) {
        throw new FormatError('Invalid 3-byte MUTF-8 continuation byte', {
          code: ERROR_CODES.E_INVALID_MUTF8,
          format: 'mutf8',
          offset: i,
        });
      }
      if (b1 === 0xe0 && b2 < 0xa0) {
        throw new FormatError('Overlong 3-byte MUTF-8 sequence', {
          code: ERROR_CODES.E_INVALID_MUTF8,
          format: 'mutf8',
          offset: i,
        });
      }
      units.push(((b1 & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f));
      i += 3;
      continue;
    }
    throw new FormatError(`Invalid MUTF-8 lead byte: 0x${b1.toString(16)}`, {
      code: ERROR_CODES.E_INVALID_MUTF8,
      format: 'mutf8',
      offset: i,
    });
  }

  return codeUnitsToString(units);
}

/**
 * Decode a NUL-terminated MUTF-8 string starting at `offset`.
 */
export function decodeMutf8Z(bytes, offset = 0, { expectedUtf16Length = undefined } = {}) {
  const buf = toUint8Array(bytes);
  if (!Number.isInteger(offset) || offset < 0 || offset >= buf.byteLength) {
    throw new FormatError(`MUTF-8 offset out of bounds: ${offset}`, {
      code: ERROR_CODES.E_INVALID_MUTF8,
      format: 'mutf8',
      offset,
    });
  }

  let nulPos = -1;
  for (let i = offset; i < buf.byteLength; i++) {
    if (buf[i] === 0x00) {
      nulPos = i;
      break;
    }
  }
  if (nulPos === -1) {
    throw new FormatError('Unterminated MUTF-8 string (missing 0x00 terminator)', {
      code: ERROR_CODES.E_INVALID_MUTF8,
      format: 'mutf8',
      offset,
    });
  }

  const value = decodeMutf8(buf, offset, nulPos - offset);
  if (expectedUtf16Length !== undefined && value.length !== expectedUtf16Length) {
    throw new FormatError(
      `MUTF-8 UTF-16 length mismatch: expected ${expectedUtf16Length}, got ${value.length}`,
      {
        code: ERROR_CODES.E_INVALID_MUTF8,
        format: 'mutf8',
        offset,
        details: { expectedUtf16Length, actualUtf16Length: value.length },
      }
    );
  }

  return {
    value,
    bytesRead: nulPos - offset + 1,
    nextOffset: nulPos + 1,
  };
}

/**
 * Bounds-checked LE/BE BinaryReader over Uint8Array / ArrayBuffer / ArrayBufferView.
 */
export class BinaryReader {
  constructor(input, { littleEndian = true, offset = 0, byteLength = undefined } = {}) {
    const base = toUint8Array(input);
    const { start, end } = resolveSliceBounds(base.byteLength, offset, byteLength);
    this._bytes = base.subarray(start, end);
    this._view = new DataView(this._bytes.buffer, this._bytes.byteOffset, this._bytes.byteLength);
    this._offset = 0;
    this._le = Boolean(littleEndian);
  }

  get offset() {
    return this._offset;
  }

  get length() {
    return this._bytes.byteLength;
  }

  get byteLength() {
    return this._bytes.byteLength;
  }

  get remaining() {
    return this._bytes.byteLength - this._offset;
  }

  get eof() {
    return this._offset >= this._bytes.byteLength;
  }

  get littleEndian() {
    return this._le;
  }

  set littleEndian(val) {
    this._le = Boolean(val);
  }

  get buffer() {
    return this._bytes;
  }

  _requireBytes(n) {
    if (!Number.isInteger(n) || n < 0) {
      throw new FormatError(`Invalid read length: ${n}`, {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    if (this._offset + n > this._bytes.byteLength) {
      throw new FormatError(`Unexpected EOF: needed ${n} bytes, remaining ${this.remaining}`, {
        code: ERROR_CODES.E_EOF,
        offset: this._offset,
        details: { needed: n, remaining: this.remaining },
      });
    }
  }

  tell() {
    return this._offset;
  }

  seek(pos) {
    if (!Number.isInteger(pos) || pos < 0 || pos > this._bytes.byteLength) {
      throw new FormatError(`Seek position out of range: ${pos} (length=${this._bytes.byteLength})`, {
        code: ERROR_CODES.ERANGE,
        offset: this._offset,
      });
    }
    this._offset = pos;
    return this;
  }

  skip(n) {
    if (!Number.isInteger(n) || n < 0) {
      throw new FormatError(`Invalid skip distance: ${n}`, {
        code: ERROR_CODES.ERANGE,
        offset: this._offset,
      });
    }
    if (this._offset + n > this._bytes.byteLength) {
      throw new FormatError(`Skip past EOF: needed ${n} bytes, remaining ${this.remaining}`, {
        code: ERROR_CODES.E_EOF,
        offset: this._offset,
        details: { needed: n, remaining: this.remaining },
      });
    }
    this._offset += n;
    return this;
  }

  align(alignment) {
    if (!Number.isInteger(alignment) || alignment < 1) {
      throw new FormatError(`Alignment must be a positive integer: ${alignment}`, {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    const pad = (alignment - (this._offset % alignment)) % alignment;
    if (pad > 0) this.skip(pad);
    return this;
  }

  bytes(length, { copy = false } = {}) {
    this._requireBytes(length);
    const slice = this._bytes.subarray(this._offset, this._offset + length);
    this._offset += length;
    return copy ? slice.slice() : slice;
  }

  readBytes(length, opts) {
    return this.bytes(length, opts);
  }

  peekBytes(length, atOffset = this._offset) {
    if (!Number.isInteger(atOffset) || atOffset < 0) {
      throw new FormatError(`Invalid peek offset: ${atOffset}`, {
        code: ERROR_CODES.ERANGE,
        offset: atOffset,
      });
    }
    if (!Number.isInteger(length) || length < 0) {
      throw new FormatError(`Invalid peek length: ${length}`, {
        code: ERROR_CODES.EINVAL,
        offset: atOffset,
      });
    }
    if (atOffset + length > this._bytes.byteLength) {
      throw new FormatError(`Peek out of bounds: offset=${atOffset}, length=${length}`, {
        code: ERROR_CODES.E_EOF,
        offset: atOffset,
      });
    }
    return this._bytes.subarray(atOffset, atOffset + length);
  }

  slice(start = 0, end = this._bytes.byteLength) {
    if (
      !Number.isInteger(start) ||
      !Number.isInteger(end) ||
      start < 0 ||
      end < start ||
      end > this._bytes.byteLength
    ) {
      throw new FormatError(`Invalid slice [${start}, ${end}) (length=${this._bytes.byteLength})`, {
        code: ERROR_CODES.ERANGE,
        offset: start,
      });
    }
    return this._bytes.subarray(start, end);
  }

  subReader(length, { offset = undefined, littleEndian = this._le } = {}) {
    if (offset === undefined) {
      const sub = this.bytes(length);
      return new BinaryReader(sub, { littleEndian });
    }
    const sub = this.peekBytes(length, offset);
    return new BinaryReader(sub, { littleEndian });
  }

  // Primitive readers (default endianness)
  u8() {
    this._requireBytes(1);
    const v = this._view.getUint8(this._offset);
    this._offset += 1;
    return v;
  }

  i8() {
    this._requireBytes(1);
    const v = this._view.getInt8(this._offset);
    this._offset += 1;
    return v;
  }

  u16(le = this._le) {
    this._requireBytes(2);
    const v = this._view.getUint16(this._offset, le);
    this._offset += 2;
    return v;
  }

  i16(le = this._le) {
    this._requireBytes(2);
    const v = this._view.getInt16(this._offset, le);
    this._offset += 2;
    return v;
  }

  u32(le = this._le) {
    this._requireBytes(4);
    const v = this._view.getUint32(this._offset, le);
    this._offset += 4;
    return v;
  }

  i32(le = this._le) {
    this._requireBytes(4);
    const v = this._view.getInt32(this._offset, le);
    this._offset += 4;
    return v;
  }

  u64(le = this._le) {
    this._requireBytes(8);
    const v = this._view.getBigUint64(this._offset, le);
    this._offset += 8;
    return v;
  }

  i64(le = this._le) {
    this._requireBytes(8);
    const v = this._view.getBigInt64(this._offset, le);
    this._offset += 8;
    return v;
  }

  f32(le = this._le) {
    this._requireBytes(4);
    const v = this._view.getFloat32(this._offset, le);
    this._offset += 4;
    return v;
  }

  f64(le = this._le) {
    this._requireBytes(8);
    const v = this._view.getFloat64(this._offset, le);
    this._offset += 8;
    return v;
  }

  // Explicit Little-Endian
  u16le() { return this.u16(true); }
  i16le() { return this.i16(true); }
  u32le() { return this.u32(true); }
  i32le() { return this.i32(true); }
  u64le() { return this.u64(true); }
  i64le() { return this.i64(true); }
  f32le() { return this.f32(true); }
  f64le() { return this.f64(true); }

  // Explicit Big-Endian
  u16be() { return this.u16(false); }
  i16be() { return this.i16(false); }
  u32be() { return this.u32(false); }
  i32be() { return this.i32(false); }
  u64be() { return this.u64(false); }
  i64be() { return this.i64(false); }
  f32be() { return this.f32(false); }
  f64be() { return this.f64(false); }

  // read* aliases
  readU8() { return this.u8(); }
  readI8() { return this.i8(); }
  readU16() { return this.u16(); }
  readI16() { return this.i16(); }
  readU32() { return this.u32(); }
  readI32() { return this.i32(); }
  readU64() { return this.u64(); }
  readI64() { return this.i64(); }
  readF32() { return this.f32(); }
  readF64() { return this.f64(); }
  readU16LE() { return this.u16le(); }
  readI16LE() { return this.i16le(); }
  readU32LE() { return this.u32le(); }
  readI32LE() { return this.i32le(); }
  readU64LE() { return this.u64le(); }
  readI64LE() { return this.i64le(); }
  readF32LE() { return this.f32le(); }
  readF64LE() { return this.f64le(); }
  readU16BE() { return this.u16be(); }
  readI16BE() { return this.i16be(); }
  readU32BE() { return this.u32be(); }
  readI32BE() { return this.i32be(); }
  readU64BE() { return this.u64be(); }
  readI64BE() { return this.i64be(); }
  readF32BE() { return this.f32be(); }
  readF64BE() { return this.f64be(); }

  // String readers
  ascii(length, { trimNull = false } = {}) {
    const raw = this.bytes(length);
    const units = [];
    for (let i = 0; i < raw.length; i++) {
      if (trimNull && raw[i] === 0x00) break;
      units.push(raw[i]);
    }
    return codeUnitsToString(units);
  }

  utf8(length, { fatal = false } = {}) {
    const startOffset = this._offset;
    const raw = this.bytes(length);
    try {
      return (fatal ? UTF8_DECODER_FATAL : UTF8_DECODER).decode(raw);
    } catch (err) {
      throw new FormatError(`Invalid UTF-8 byte sequence: ${err.message}`, {
        code: ERROR_CODES.E_MALFORMED_BINARY,
        format: 'utf8',
        offset: startOffset,
        cause: err,
      });
    }
  }

  cstring({ maxLength = this.remaining, encoding = 'utf8', requireNull = true } = {}) {
    if (!Number.isInteger(maxLength) || maxLength < 0) {
      throw new FormatError(`Invalid cstring maxLength: ${maxLength}`, {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    const start = this._offset;
    const limit = Math.min(this._bytes.byteLength, start + maxLength);
    let nulPos = -1;
    for (let i = start; i < limit; i++) {
      if (this._bytes[i] === 0x00) {
        nulPos = i;
        break;
      }
    }
    if (nulPos === -1) {
      if (requireNull) {
        throw new FormatError('Unterminated C string', {
          code: ERROR_CODES.E_EOF,
          offset: start,
        });
      }
      const raw = this._bytes.subarray(start, limit);
      this._offset = limit;
      return encoding === 'ascii' ? codeUnitsToString(Array.from(raw)) : UTF8_DECODER.decode(raw);
    }
    const raw = this._bytes.subarray(start, nulPos);
    this._offset = nulPos + 1;
    return encoding === 'ascii' ? codeUnitsToString(Array.from(raw)) : UTF8_DECODER.decode(raw);
  }

  utf16le(byteLength) {
    if (!Number.isInteger(byteLength) || byteLength < 0 || byteLength % 2 !== 0) {
      throw new FormatError(`UTF-16LE byteLength must be an even non-negative integer: ${byteLength}`, {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    const raw = this.bytes(byteLength);
    return UTF16LE_DECODER.decode(raw);
  }

  utf16be(byteLength) {
    if (!Number.isInteger(byteLength) || byteLength < 0 || byteLength % 2 !== 0) {
      throw new FormatError(`UTF-16BE byteLength must be an even non-negative integer: ${byteLength}`, {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    const raw = this.bytes(byteLength);
    return UTF16BE_DECODER.decode(raw);
  }

  utf16leUnits(codeUnitCount) {
    if (!Number.isInteger(codeUnitCount) || codeUnitCount < 0) {
      throw new FormatError(`Invalid UTF-16 codeUnitCount: ${codeUnitCount}`, {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    return this.utf16le(codeUnitCount * 2);
  }

  utf16beUnits(codeUnitCount) {
    if (!Number.isInteger(codeUnitCount) || codeUnitCount < 0) {
      throw new FormatError(`Invalid UTF-16 codeUnitCount: ${codeUnitCount}`, {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    return this.utf16be(codeUnitCount * 2);
  }

  // LEB128 & MUTF-8
  uleb128() {
    const res = decodeUleb128(this._bytes, this._offset);
    this._offset = res.nextOffset;
    return res.value;
  }

  sleb128() {
    const res = decodeSleb128(this._bytes, this._offset);
    this._offset = res.nextOffset;
    return res.value;
  }

  uleb128p1() {
    const res = decodeUleb128p1(this._bytes, this._offset);
    this._offset = res.nextOffset;
    return res.value;
  }

  mutf8({ expectedUtf16Length = undefined } = {}) {
    const res = decodeMutf8Z(this._bytes, this._offset, { expectedUtf16Length });
    this._offset = res.nextOffset;
    return res.value;
  }
}

/**
 * Auto-growing LE/BE BinaryWriter with strict range validation and in-place patching.
 */
export class BinaryWriter {
  constructor({ initialCapacity = 256, littleEndian = true } = {}) {
    if (!Number.isInteger(initialCapacity) || initialCapacity < 1) {
      throw new FormatError(`initialCapacity must be a positive integer: ${initialCapacity}`, {
        code: ERROR_CODES.EINVAL,
      });
    }
    this._buf = new Uint8Array(initialCapacity);
    this._view = new DataView(this._buf.buffer);
    this._offset = 0;
    this._length = 0;
    this._le = Boolean(littleEndian);
  }

  get offset() {
    return this._offset;
  }

  get length() {
    return this._length;
  }

  get byteLength() {
    return this._length;
  }

  get capacity() {
    return this._buf.byteLength;
  }

  get littleEndian() {
    return this._le;
  }

  set littleEndian(val) {
    this._le = Boolean(val);
  }

  _ensure(extraBytes) {
    const needed = this._offset + extraBytes;
    if (needed <= this._buf.byteLength) return;
    let newCap = this._buf.byteLength;
    while (newCap < needed) {
      newCap = Math.max(newCap * 2, needed);
    }
    const nextBuf = new Uint8Array(newCap);
    nextBuf.set(this._buf.subarray(0, this._length), 0);
    this._buf = nextBuf;
    this._view = new DataView(this._buf.buffer);
  }

  _advance(n) {
    this._offset += n;
    if (this._offset > this._length) {
      this._length = this._offset;
    }
  }

  _checkPatchBounds(at, width) {
    if (!Number.isInteger(at) || at < 0 || at + width > this._length) {
      throw new FormatError(
        `Patch out of bounds: at=${at}, width=${width}, length=${this._length}`,
        { code: ERROR_CODES.ERANGE, offset: at }
      );
    }
  }

  // Primitive writers
  u8(v) {
    checkIntRange(v, 0, 0xff, 'u8', this._offset);
    this._ensure(1);
    this._view.setUint8(this._offset, v);
    this._advance(1);
    return this;
  }

  i8(v) {
    checkIntRange(v, -128, 127, 'i8', this._offset);
    this._ensure(1);
    this._view.setInt8(this._offset, v);
    this._advance(1);
    return this;
  }

  u16(v, le = this._le) {
    checkIntRange(v, 0, 0xffff, 'u16', this._offset);
    this._ensure(2);
    this._view.setUint16(this._offset, v, le);
    this._advance(2);
    return this;
  }

  i16(v, le = this._le) {
    checkIntRange(v, -32768, 32767, 'i16', this._offset);
    this._ensure(2);
    this._view.setInt16(this._offset, v, le);
    this._advance(2);
    return this;
  }

  u32(v, le = this._le) {
    checkIntRange(v, 0, 0xffffffff, 'u32', this._offset);
    this._ensure(4);
    this._view.setUint32(this._offset, v, le);
    this._advance(4);
    return this;
  }

  i32(v, le = this._le) {
    checkIntRange(v, -2147483648, 2147483647, 'i32', this._offset);
    this._ensure(4);
    this._view.setInt32(this._offset, v, le);
    this._advance(4);
    return this;
  }

  u64(v, le = this._le) {
    const big = normalizeU64(v, this._offset);
    this._ensure(8);
    this._view.setBigUint64(this._offset, big, le);
    this._advance(8);
    return this;
  }

  i64(v, le = this._le) {
    const big = normalizeI64(v, this._offset);
    this._ensure(8);
    this._view.setBigInt64(this._offset, big, le);
    this._advance(8);
    return this;
  }

  f32(v, le = this._le) {
    checkFloat(v, 'f32', this._offset);
    this._ensure(4);
    this._view.setFloat32(this._offset, v, le);
    this._advance(4);
    return this;
  }

  f64(v, le = this._le) {
    checkFloat(v, 'f64', this._offset);
    this._ensure(8);
    this._view.setFloat64(this._offset, v, le);
    this._advance(8);
    return this;
  }

  // Explicit LE
  u16le(v) { return this.u16(v, true); }
  i16le(v) { return this.i16(v, true); }
  u32le(v) { return this.u32(v, true); }
  i32le(v) { return this.i32(v, true); }
  u64le(v) { return this.u64(v, true); }
  i64le(v) { return this.i64(v, true); }
  f32le(v) { return this.f32(v, true); }
  f64le(v) { return this.f64(v, true); }

  // Explicit BE
  u16be(v) { return this.u16(v, false); }
  i16be(v) { return this.i16(v, false); }
  u32be(v) { return this.u32(v, false); }
  i32be(v) { return this.i32(v, false); }
  u64be(v) { return this.u64(v, false); }
  i64be(v) { return this.i64(v, false); }
  f32be(v) { return this.f32(v, false); }
  f64be(v) { return this.f64(v, false); }

  // write* aliases
  writeU8(v) { return this.u8(v); }
  writeI8(v) { return this.i8(v); }
  writeU16(v) { return this.u16(v); }
  writeI16(v) { return this.i16(v); }
  writeU32(v) { return this.u32(v); }
  writeI32(v) { return this.i32(v); }
  writeU64(v) { return this.u64(v); }
  writeI64(v) { return this.i64(v); }
  writeF32(v) { return this.f32(v); }
  writeF64(v) { return this.f64(v); }
  writeU16LE(v) { return this.u16le(v); }
  writeI16LE(v) { return this.i16le(v); }
  writeU32LE(v) { return this.u32le(v); }
  writeI32LE(v) { return this.i32le(v); }
  writeU64LE(v) { return this.u64le(v); }
  writeI64LE(v) { return this.i64le(v); }
  writeF32LE(v) { return this.f32le(v); }
  writeF64LE(v) { return this.f64le(v); }
  writeU16BE(v) { return this.u16be(v); }
  writeI16BE(v) { return this.i16be(v); }
  writeU32BE(v) { return this.u32be(v); }
  writeI32BE(v) { return this.i32be(v); }
  writeU64BE(v) { return this.u64be(v); }
  writeI64BE(v) { return this.i64be(v); }
  writeF32BE(v) { return this.f32be(v); }
  writeF64BE(v) { return this.f64be(v); }

  bytes(input) {
    const raw = Array.isArray(input) ? Uint8Array.from(input) : toUint8Array(input);
    this._ensure(raw.byteLength);
    this._buf.set(raw, this._offset);
    this._advance(raw.byteLength);
    return this;
  }

  writeBytes(input) {
    return this.bytes(input);
  }

  ascii(str, fixedLength = undefined) {
    if (typeof str !== 'string') {
      throw new FormatError('ascii() expects a string', {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    if (fixedLength !== undefined) {
      if (!Number.isInteger(fixedLength) || fixedLength < 0) {
        throw new FormatError(`Invalid fixedLength: ${fixedLength}`, {
          code: ERROR_CODES.EINVAL,
          offset: this._offset,
        });
      }
      if (str.length > fixedLength) {
        throw new FormatError(`ASCII string exceeds fixedLength ${fixedLength} (len=${str.length})`, {
          code: ERROR_CODES.ERANGE,
          offset: this._offset,
        });
      }
    }
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code > 0xff) {
        throw new FormatError(`Non-ASCII/Latin-1 code unit 0x${code.toString(16)} at index ${i}`, {
          code: ERROR_CODES.EINVAL,
          offset: this._offset + i,
        });
      }
    }
    const totalLen = fixedLength !== undefined ? fixedLength : str.length;
    this._ensure(totalLen);
    for (let i = 0; i < str.length; i++) {
      this._buf[this._offset + i] = str.charCodeAt(i);
    }
    for (let i = str.length; i < totalLen; i++) {
      this._buf[this._offset + i] = 0x00;
    }
    this._advance(totalLen);
    return this;
  }

  utf8(str) {
    if (typeof str !== 'string') {
      throw new FormatError('utf8() expects a string', {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    return this.bytes(TEXT_ENCODER.encode(str));
  }

  cstring(str, encoding = 'utf8') {
    if (encoding === 'ascii') {
      this.ascii(str);
    } else {
      this.utf8(str);
    }
    return this.u8(0x00);
  }

  utf16le(str) {
    if (typeof str !== 'string') {
      throw new FormatError('utf16le() expects a string', {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    this._ensure(str.length * 2);
    for (let i = 0; i < str.length; i++) {
      this._view.setUint16(this._offset + i * 2, str.charCodeAt(i), true);
    }
    this._advance(str.length * 2);
    return this;
  }

  utf16be(str) {
    if (typeof str !== 'string') {
      throw new FormatError('utf16be() expects a string', {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    this._ensure(str.length * 2);
    for (let i = 0; i < str.length; i++) {
      this._view.setUint16(this._offset + i * 2, str.charCodeAt(i), false);
    }
    this._advance(str.length * 2);
    return this;
  }

  uleb128(v) {
    return this.bytes(encodeUleb128(v));
  }

  sleb128(v) {
    return this.bytes(encodeSleb128(v));
  }

  uleb128p1(v) {
    return this.bytes(encodeUleb128p1(v));
  }

  mutf8(str, { nullTerminate = true } = {}) {
    return this.bytes(encodeMutf8(str, { nullTerminate }));
  }

  pad(count, fill = 0) {
    if (!Number.isInteger(count) || count < 0) {
      throw new FormatError(`Invalid pad count: ${count}`, {
        code: ERROR_CODES.ERANGE,
        offset: this._offset,
      });
    }
    checkIntRange(fill, 0, 0xff, 'fill', this._offset);
    if (count === 0) return this;
    this._ensure(count);
    this._buf.fill(fill, this._offset, this._offset + count);
    this._advance(count);
    return this;
  }

  skip(count) {
    return this.pad(count, 0);
  }

  align(alignment, fill = 0) {
    if (!Number.isInteger(alignment) || alignment < 1) {
      throw new FormatError(`Alignment must be a positive integer: ${alignment}`, {
        code: ERROR_CODES.EINVAL,
        offset: this._offset,
      });
    }
    const padLen = (alignment - (this._offset % alignment)) % alignment;
    return this.pad(padLen, fill);
  }

  seek(pos) {
    if (!Number.isInteger(pos) || pos < 0 || pos > this._length) {
      throw new FormatError(`Seek position out of range [0, ${this._length}]: ${pos}`, {
        code: ERROR_CODES.ERANGE,
        offset: this._offset,
      });
    }
    this._offset = pos;
    return this;
  }

  // In-place patch helpers (do NOT move cursor)
  patchU8(at, v) {
    checkIntRange(v, 0, 0xff, 'u8', at);
    this._checkPatchBounds(at, 1);
    this._view.setUint8(at, v);
    return this;
  }

  patchU16(at, v, le = this._le) {
    checkIntRange(v, 0, 0xffff, 'u16', at);
    this._checkPatchBounds(at, 2);
    this._view.setUint16(at, v, le);
    return this;
  }

  patchU16LE(at, v) { return this.patchU16(at, v, true); }
  patchU16le(at, v) { return this.patchU16(at, v, true); }
  patchU16BE(at, v) { return this.patchU16(at, v, false); }
  patchU16be(at, v) { return this.patchU16(at, v, false); }

  patchU32(at, v, le = this._le) {
    checkIntRange(v, 0, 0xffffffff, 'u32', at);
    this._checkPatchBounds(at, 4);
    this._view.setUint32(at, v, le);
    return this;
  }

  patchU32LE(at, v) { return this.patchU32(at, v, true); }
  patchU32le(at, v) { return this.patchU32(at, v, true); }
  patchU32BE(at, v) { return this.patchU32(at, v, false); }
  patchU32be(at, v) { return this.patchU32(at, v, false); }

  patchU64(at, v, le = this._le) {
    const big = normalizeU64(v, at);
    this._checkPatchBounds(at, 8);
    this._view.setBigUint64(at, big, le);
    return this;
  }

  patchU64LE(at, v) { return this.patchU64(at, v, true); }
  patchU64BE(at, v) { return this.patchU64(at, v, false); }

  patchBytes(at, input) {
    const raw = Array.isArray(input) ? Uint8Array.from(input) : toUint8Array(input);
    this._checkPatchBounds(at, raw.byteLength);
    this._buf.set(raw, at);
    return this;
  }

  toUint8Array() {
    return this._buf.slice(0, this._length);
  }

  slice(start = 0, end = this._length) {
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || end > this._length) {
      throw new FormatError(`Invalid slice [${start}, ${end}) (length=${this._length})`, {
        code: ERROR_CODES.ERANGE,
        offset: start,
      });
    }
    return this._buf.slice(start, end);
  }
}
