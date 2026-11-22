/**
 * OmniOS Android DEX Binary Parser (`dex\n035\0` – `dex\n041\0`) (F-038)
 * Compliant with AOSP `dex-format` and ART `libdexfile/dex/dex_file.h`.
 * - Validates magic, `header_size` (`0x70` v035–040 / `0x78` v041), `endian_tag` (`0x12345678`),
 *   file/container/table bounds, `type_ids <= 65535`, `proto_ids <= 65535`, Adler-32 & SHA-1 (Edge Case #7)
 * - Decodes MUTF-8 (`0xC0 0x80` -> `\u0000`, surrogate pairs) and strictly wraps >5B LEB128 into
 *   `FormatError(E_MALFORMED_DEX, { details: { subcode: E_INVALID_LEB128 }, cause })` (Edge Case #8)
 * - Skips 2-byte `code_item` alignment padding when `tries_size > 0 && (insns_size & 1) === 1` (Edge Case #9)
 * - Zero external dependencies; pure in-memory parser without host filesystem access.
 */

import crypto from 'node:crypto';
import {
  BinaryReader,
  adler32,
  decodeUleb128,
  decodeSleb128,
  decodeUleb128p1,
  decodeMutf8Z,
} from '../../common/binary.mjs';
import { FormatError, ERROR_CODES } from '../../common/errors.mjs';

export const DEX_SUPPORTED_VERSIONS = Object.freeze(['035', '037', '038', '039', '040', '041']);
const SUPPORTED_VERSION_SET = new Set(DEX_SUPPORTED_VERSIONS);

export const DEX_ENDIAN_CONSTANT = 0x12345678;
export const DEX_REVERSE_ENDIAN_CONSTANT = 0x78563412;
export const DEX_NO_INDEX = 0xffffffff;
export const MAX_CONTAINER_DEX_FILES = 64;

export const DEX_ACCESS_FLAGS = Object.freeze({
  ACC_PUBLIC: 0x0001,
  ACC_PRIVATE: 0x0002,
  ACC_PROTECTED: 0x0004,
  ACC_STATIC: 0x0008,
  ACC_FINAL: 0x0010,
  ACC_SYNCHRONIZED: 0x0020,
  ACC_VOLATILE: 0x0040,
  ACC_BRIDGE: 0x0040,
  ACC_TRANSIENT: 0x0080,
  ACC_VARARGS: 0x0080,
  ACC_NATIVE: 0x0100,
  ACC_INTERFACE: 0x0200,
  ACC_ABSTRACT: 0x0400,
  ACC_STRICT: 0x0800,
  ACC_SYNTHETIC: 0x1000,
  ACC_ANNOTATION: 0x2000,
  ACC_ENUM: 0x4000,
  ACC_CONSTRUCTOR: 0x10000,
  ACC_DECLARED_SYNCHRONIZED: 0x20000,
});

export const DEX_VALUE_TYPES = Object.freeze({
  VALUE_BYTE: 0x00,
  VALUE_SHORT: 0x02,
  VALUE_CHAR: 0x03,
  VALUE_INT: 0x04,
  VALUE_LONG: 0x06,
  VALUE_FLOAT: 0x10,
  VALUE_DOUBLE: 0x11,
  VALUE_METHOD_TYPE: 0x15,
  VALUE_METHOD_HANDLE: 0x16,
  VALUE_STRING: 0x17,
  VALUE_TYPE: 0x18,
  VALUE_FIELD: 0x19,
  VALUE_METHOD: 0x1a,
  VALUE_ENUM: 0x1b,
  VALUE_ARRAY: 0x1c,
  VALUE_ANNOTATION: 0x1d,
  VALUE_NULL: 0x1e,
  VALUE_BOOLEAN: 0x1f,
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
  throw new FormatError('DEX input must be a Uint8Array, ArrayBuffer, or ArrayBufferView', {
    code: ERROR_CODES.E_MALFORMED_DEX,
    format: 'dex',
    offset: 0,
  });
}

function wrapLeb128(fn, offset) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof FormatError) {
      const subcode = err.code;
      throw new FormatError(err.message, {
        code: ERROR_CODES.E_MALFORMED_DEX,
        format: 'dex',
        offset: err.offset ?? offset,
        details: { subcode },
        cause: err,
      });
    }
    throw err;
  }
}

function wrapMutf8(fn, offset) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof FormatError) {
      throw new FormatError(err.message, {
        code: ERROR_CODES.E_MALFORMED_DEX,
        format: 'dex',
        offset: err.offset ?? offset,
        details: { subcode: err.code },
        cause: err,
      });
    }
    throw err;
  }
}

function assertRange(bytesLen, offset, sizeBytes, label) {
  if (offset < 0 || sizeBytes < 0 || offset + sizeBytes > bytesLen) {
    throw new FormatError(
      `DEX ${label} exceeds bounds (offset=0x${offset.toString(16)}, size=${sizeBytes}, limit=${bytesLen})`,
      {
        code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
        format: 'dex',
        offset,
        details: { label, offset, sizeBytes, limit: bytesLen },
      }
    );
  }
}

function assertIndex(idx, length, label, offset) {
  if (!Number.isInteger(idx) || idx < 0 || idx >= length) {
    throw new FormatError(`DEX ${label} index out of bounds: ${idx} (count=${length})`, {
      code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
      format: 'dex',
      offset,
      details: { label, index: idx, count: length },
    });
  }
}

function readSignedIntBytes(bytes, offset, count) {
  let val = 0n;
  for (let i = 0; i < count; i++) {
    val |= BigInt(bytes[offset + i]) << BigInt(i * 8);
  }
  const bits = BigInt(count * 8);
  const signBit = 1n << (bits - 1n);
  if ((val & signBit) !== 0n) {
    val -= 1n << bits;
  }
  return val;
}

function readUnsignedIntBytes(bytes, offset, count) {
  let val = 0n;
  for (let i = 0; i < count; i++) {
    val |= BigInt(bytes[offset + i]) << BigInt(i * 8);
  }
  return val;
}

function readFloatRightZeroExtended(bytes, offset, count, totalBytes) {
  const tmp = new Uint8Array(totalBytes);
  const start = totalBytes - count;
  for (let i = 0; i < count; i++) {
    tmp[start + i] = bytes[offset + i];
  }
  const dv = new DataView(tmp.buffer);
  return totalBytes === 4 ? dv.getFloat32(0, true) : dv.getFloat64(0, true);
}

function decodeEncodedValue(bytes, pos, limit, ctx, depth = 0) {
  if (depth > 32) {
    throw new FormatError('DEX encoded_value nesting depth exceeded', {
      code: ERROR_CODES.E_MALFORMED_DEX,
      format: 'dex',
      offset: pos,
    });
  }
  if (pos >= limit) {
    throw new FormatError('Truncated DEX encoded_value', {
      code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
      format: 'dex',
      offset: pos,
    });
  }
  if (ctx.budget) {
    ctx.budget.encodedValues += 1;
    if (ctx.budget.encodedValues > ctx.budget.maxEncodedValues) {
      throw new FormatError(
        `DEX encoded_value count (${ctx.budget.encodedValues}) exceeds budget (${ctx.budget.maxEncodedValues})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: pos }
      );
    }
  }
  const header = bytes[pos++];
  const valueArg = (header >>> 5) & 0x07;
  const valueType = header & 0x1f;
  const byteCount = valueArg + 1;

  switch (valueType) {
    case DEX_VALUE_TYPES.VALUE_BYTE: {
      assertRange(limit, pos, 1, 'VALUE_BYTE');
      const v = (bytes[pos] << 24) >> 24;
      return { value: v, type: valueType, nextOffset: pos + 1 };
    }
    case DEX_VALUE_TYPES.VALUE_SHORT:
    case DEX_VALUE_TYPES.VALUE_INT: {
      assertRange(limit, pos, byteCount, 'VALUE_INT');
      const v = Number(readSignedIntBytes(bytes, pos, byteCount)) | 0;
      return { value: v, type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_CHAR: {
      assertRange(limit, pos, byteCount, 'VALUE_CHAR');
      const v = Number(readUnsignedIntBytes(bytes, pos, byteCount)) & 0xffff;
      return { value: v, type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_LONG: {
      assertRange(limit, pos, byteCount, 'VALUE_LONG');
      const v = BigInt.asIntN(64, readSignedIntBytes(bytes, pos, byteCount));
      return { value: v, type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_FLOAT: {
      assertRange(limit, pos, byteCount, 'VALUE_FLOAT');
      const v = readFloatRightZeroExtended(bytes, pos, Math.min(byteCount, 4), 4);
      return { value: v, type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_DOUBLE: {
      assertRange(limit, pos, byteCount, 'VALUE_DOUBLE');
      const v = readFloatRightZeroExtended(bytes, pos, Math.min(byteCount, 8), 8);
      return { value: v, type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_STRING: {
      assertRange(limit, pos, byteCount, 'VALUE_STRING');
      const idx = Number(readUnsignedIntBytes(bytes, pos, byteCount));
      assertIndex(idx, ctx.strings.length, 'encoded_value string', pos);
      return { value: ctx.strings[idx], type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_TYPE: {
      assertRange(limit, pos, byteCount, 'VALUE_TYPE');
      const idx = Number(readUnsignedIntBytes(bytes, pos, byteCount));
      assertIndex(idx, ctx.types.length, 'encoded_value type', pos);
      return { value: ctx.types[idx], type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_FIELD:
    case DEX_VALUE_TYPES.VALUE_ENUM: {
      assertRange(limit, pos, byteCount, 'VALUE_FIELD');
      const idx = Number(readUnsignedIntBytes(bytes, pos, byteCount));
      assertIndex(idx, ctx.fields.length, 'encoded_value field', pos);
      return { value: ctx.fields[idx], type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_METHOD: {
      assertRange(limit, pos, byteCount, 'VALUE_METHOD');
      const idx = Number(readUnsignedIntBytes(bytes, pos, byteCount));
      assertIndex(idx, ctx.methods.length, 'encoded_value method', pos);
      return { value: ctx.methods[idx], type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_METHOD_TYPE:
    case DEX_VALUE_TYPES.VALUE_METHOD_HANDLE: {
      assertRange(limit, pos, byteCount, 'VALUE_METHOD_HANDLE');
      const idx = Number(readUnsignedIntBytes(bytes, pos, byteCount));
      return { value: idx, type: valueType, nextOffset: pos + byteCount };
    }
    case DEX_VALUE_TYPES.VALUE_ARRAY: {
      const lenDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
      pos = lenDec.nextOffset;
      if (lenDec.value > limit - pos) {
        throw new FormatError(
          `DEX encoded_array length (${lenDec.value}) exceeds remaining bytes (${limit - pos})`,
          { code: ERROR_CODES.E_INVALID_DEX_BOUNDS, format: 'dex', offset: pos }
        );
      }
      if (ctx.budget && ctx.budget.encodedValues + lenDec.value > ctx.budget.maxEncodedValues) {
        throw new FormatError(
          `DEX encoded_array expansion (${ctx.budget.encodedValues + lenDec.value}) exceeds budget (${ctx.budget.maxEncodedValues})`,
          { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: pos }
        );
      }
      const arr = new Array(lenDec.value);
      for (let i = 0; i < lenDec.value; i++) {
        const elem = decodeEncodedValue(bytes, pos, limit, ctx, depth + 1);
        arr[i] = elem.value;
        pos = elem.nextOffset;
      }
      return { value: arr, type: valueType, nextOffset: pos };
    }
    case DEX_VALUE_TYPES.VALUE_ANNOTATION: {
      const typeDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
      pos = typeDec.nextOffset;
      const sizeDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
      pos = sizeDec.nextOffset;
      if (sizeDec.value * 2 > limit - pos) {
        throw new FormatError(
          `DEX encoded_annotation size (${sizeDec.value}) exceeds remaining bytes (${limit - pos})`,
          { code: ERROR_CODES.E_INVALID_DEX_BOUNDS, format: 'dex', offset: pos }
        );
      }
      const fields = Object.create(null);
      for (let i = 0; i < sizeDec.value; i++) {
        const nameDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
        pos = nameDec.nextOffset;
        assertIndex(nameDec.value, ctx.strings.length, 'annotation element name', pos);
        const elem = decodeEncodedValue(bytes, pos, limit, ctx, depth + 1);
        fields[ctx.strings[nameDec.value]] = elem.value;
        pos = elem.nextOffset;
      }
      return { value: { typeIdx: typeDec.value, fields }, type: valueType, nextOffset: pos };
    }
    case DEX_VALUE_TYPES.VALUE_NULL:
      return { value: null, type: valueType, nextOffset: pos };
    case DEX_VALUE_TYPES.VALUE_BOOLEAN:
      return { value: valueArg !== 0, type: valueType, nextOffset: pos };
    default:
      throw new FormatError(`Unknown DEX encoded_value type 0x${valueType.toString(16)}`, {
        code: ERROR_CODES.E_MALFORMED_DEX,
        format: 'dex',
        offset: pos - 1,
      });
  }
}

const EMPTY_ARRAY = Object.freeze([]);
const EMPTY_METHOD_MAP = new Map();
const EMPTY_TYPE_LIST_ENTRY = Object.freeze({ list: EMPTY_ARRAY, joined: '' });

export function createDexParseBudget(totalBytes) {
  const size = Number.isFinite(totalBytes) && totalBytes > 0 ? Math.trunc(totalBytes) : 0;
  return {
    decodedStringBytes: 0,
    maxDecodedStringBytes: Math.min(Math.max(size * 4, 32 * 1024), 16 * 1024 * 1024),
    derivedChars: 0,
    maxDerivedChars: Math.min(Math.max(size * 16, 256 * 1024), 16 * 1024 * 1024),
    typeListItems: 0,
    maxTypeListItems: Math.min(Math.max(Math.ceil(size / 2), 8192), 262144),
    codeBytes: 0,
    maxCodeBytes: Math.min(Math.max(size * 4, 64 * 1024), 16 * 1024 * 1024),
    encodedValues: 0,
    maxEncodedValues: Math.min(Math.max(size, 8192), 262144),
    classDataMembers: 0,
    maxClassDataMembers: Math.min(Math.max(Math.ceil(size / 2), 8192), 262144),
    mapListItems: 0,
    maxMapListItems: Math.min(Math.max(Math.ceil(size / 8), 4096), 131072),
    tableSlots: 0,
    maxTableSlots: Math.min(Math.max(Math.ceil(size / 2), 65536), 262144),
    heavyTableSlots: 0,
    maxHeavyTableSlots: Math.min(Math.max(Math.ceil(size / 4), 16384), 131072),
  };
}

function parseTypeList(bytes, view, offset, limit, types, cache = null, budget = null, cacheKeyPrefix = null) {
  if (offset === 0) return EMPTY_TYPE_LIST_ENTRY;
  const cacheKey = cacheKeyPrefix !== null ? `${cacheKeyPrefix}:${offset}` : offset;
  if (cache && cache.has(cacheKey)) {
    return cache.get(cacheKey);
  }
  assertRange(limit, offset, 4, 'type_list header');
  const size = view.getUint32(offset, true);
  assertRange(limit, offset + 4, size * 2, 'type_list items');
  if (budget) {
    budget.typeListItems += size;
    if (budget.typeListItems > budget.maxTypeListItems) {
      throw new FormatError(
        `DEX type_list items (${budget.typeListItems}) exceeds budget (${budget.maxTypeListItems})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset }
      );
    }
  }
  const list = new Array(size);
  let joinedLen = 0;
  for (let i = 0; i < size; i++) {
    const typeIdx = view.getUint16(offset + 4 + i * 2, true);
    assertIndex(typeIdx, types.length, 'type_list item', offset + 4 + i * 2);
    const t = types[typeIdx];
    list[i] = t;
    joinedLen += t.length;
  }
  if (budget && joinedLen > 0) {
    budget.derivedChars += joinedLen;
    if (budget.derivedChars > budget.maxDerivedChars) {
      throw new FormatError(
        `DEX type_list string expansion (${budget.derivedChars}) exceeds budget (${budget.maxDerivedChars})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset }
      );
    }
  }
  const entry = Object.freeze({ list: Object.freeze(list), joined: list.join('') });
  if (cache) cache.set(cacheKey, entry);
  return entry;
}

function parseCodeItem(bytes, view, codeOff, limit, types, codeCache = null, budget = null, cacheKeyPrefix = null) {
  const cacheKey = cacheKeyPrefix !== null ? `${cacheKeyPrefix}:${codeOff}` : codeOff;
  if (codeCache && codeCache.has(cacheKey)) {
    return codeCache.get(cacheKey);
  }
  assertRange(limit, codeOff, 16, 'code_item header');
  const registersSize = view.getUint16(codeOff, true);
  const insSize = view.getUint16(codeOff + 2, true);
  const outsSize = view.getUint16(codeOff + 4, true);
  const triesSize = view.getUint16(codeOff + 6, true);
  const debugInfoOff = view.getUint32(codeOff + 8, true);
  const insnsSize = view.getUint32(codeOff + 12, true);

  if (insSize > registersSize) {
    throw new FormatError(
      `DEX code_item insSize (${insSize}) exceeds registersSize (${registersSize})`,
      { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: codeOff }
    );
  }

  const insnsStart = codeOff + 16;
  const insnsByteLen = insnsSize * 2;
  assertRange(limit, insnsStart, insnsByteLen, 'code_item insns');

  if (budget) {
    budget.codeBytes += insnsByteLen + triesSize * 32;
    if (budget.codeBytes > budget.maxCodeBytes) {
      throw new FormatError(
        `DEX decoded code_item bytes (${budget.codeBytes}) exceeds budget (${budget.maxCodeBytes})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: codeOff }
      );
    }
  }

  const insns = new Uint16Array(insnsSize);
  for (let i = 0; i < insnsSize; i++) {
    insns[i] = view.getUint16(insnsStart + i * 2, true);
  }

  let pos = insnsStart + insnsByteLen;
  const tries = [];
  const catchHandlers = new Map();

  if (triesSize > 0) {
    // CRITICAL Edge Case #9: skip 2-byte alignment padding when tries_size > 0 && (insns_size & 1) === 1
    if ((insnsSize & 1) === 1) {
      assertRange(limit, pos, 2, 'code_item try alignment padding');
      pos += 2;
    }

    assertRange(limit, pos, triesSize * 8, 'code_item try_item table');
    const rawTries = new Array(triesSize);
    for (let i = 0; i < triesSize; i++) {
      const tOff = pos + i * 8;
      const startAddr = view.getUint32(tOff, true);
      const insnCount = view.getUint16(tOff + 4, true);
      const handlerOff = view.getUint16(tOff + 6, true);
      const endAddr = startAddr + insnCount;
      if (startAddr >= insnsSize || endAddr > insnsSize) {
        throw new FormatError(
          `DEX try_item range [${startAddr}, ${endAddr}) exceeds insns_size (${insnsSize})`,
          {
            code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
            format: 'dex',
            offset: tOff,
            details: { startAddr, insnCount, endAddr, insnsSize },
          }
        );
      }
      rawTries[i] = { startAddr, insnCount, endAddr, handlerOff, tOff };
    }
    pos += triesSize * 8;

    // Parse encoded_catch_handler_list keyed by relative byte offset from handlerListStart
    const handlerListStart = pos;
    assertRange(limit, pos, 1, 'encoded_catch_handler_list');
    const listSizeDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
    pos = listSizeDec.nextOffset;
    if (listSizeDec.value > limit - pos) {
      throw new FormatError(
        `DEX encoded_catch_handler_list size (${listSizeDec.value}) exceeds remaining bytes (${limit - pos})`,
        { code: ERROR_CODES.E_INVALID_DEX_BOUNDS, format: 'dex', offset: pos }
      );
    }

    for (let i = 0; i < listSizeDec.value; i++) {
      assertRange(limit, pos, 1, 'encoded_catch_handler');
      const relOff = pos - handlerListStart;
      const sizeDec = wrapLeb128(() => decodeSleb128(bytes, pos), pos);
      pos = sizeDec.nextOffset;
      const count = Math.abs(sizeDec.value);
      if (count * 2 > limit - pos) {
        throw new FormatError(
          `DEX encoded_catch_handler count (${count}) exceeds remaining bytes (${limit - pos})`,
          { code: ERROR_CODES.E_INVALID_DEX_BOUNDS, format: 'dex', offset: pos }
        );
      }
      if (budget) {
        budget.codeBytes += (count + 1) * 24;
        if (budget.codeBytes > budget.maxCodeBytes) {
          throw new FormatError(
            `DEX catch handler bytes (${budget.codeBytes}) exceeds budget (${budget.maxCodeBytes})`,
            { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: pos }
          );
        }
      }
      const typedHandlers = new Array(count);
      for (let h = 0; h < count; h++) {
        const typeDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
        pos = typeDec.nextOffset;
        assertIndex(typeDec.value, types.length, 'catch handler type', pos);
        const addrOff = pos;
        const addrDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
        pos = addrDec.nextOffset;
        if (addrDec.value >= insnsSize) {
          throw new FormatError(
            `DEX catch handler addr (${addrDec.value}) exceeds insns_size (${insnsSize})`,
            {
              code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
              format: 'dex',
              offset: addrOff,
              details: { addr: addrDec.value, insnsSize },
            }
          );
        }
        typedHandlers[h] = {
          typeIdx: typeDec.value,
          type: types[typeDec.value],
          addr: addrDec.value,
        };
      }
      let catchAllAddr = null;
      if (sizeDec.value <= 0) {
        const catchAllOff = pos;
        const catchAllDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
        pos = catchAllDec.nextOffset;
        if (catchAllDec.value >= insnsSize) {
          throw new FormatError(
            `DEX catch_all_addr (${catchAllDec.value}) exceeds insns_size (${insnsSize})`,
            {
              code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
              format: 'dex',
              offset: catchAllOff,
              details: { catchAllAddr: catchAllDec.value, insnsSize },
            }
          );
        }
        catchAllAddr = catchAllDec.value;
      }
      catchHandlers.set(relOff, { handlers: typedHandlers, catchAllAddr });
    }

    for (const rt of rawTries) {
      if (handlerListStart + rt.handlerOff >= limit) {
        throw new FormatError(
          `DEX try_item handler_off (${rt.handlerOff}) exceeds DEX bounds (base=${handlerListStart}, limit=${limit})`,
          {
            code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
            format: 'dex',
            offset: rt.tOff + 6,
            details: { handlerOff: rt.handlerOff, handlerListStart, limit },
          }
        );
      }
      const resolved = catchHandlers.get(rt.handlerOff);
      if (!resolved) {
        throw new FormatError(
          `DEX try_item handler_off (${rt.handlerOff}) does not reference a valid encoded_catch_handler`,
          {
            code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
            format: 'dex',
            offset: rt.tOff + 6,
            details: { handlerOff: rt.handlerOff, handlerListStart },
          }
        );
      }

      tries.push({
        startAddr: rt.startAddr,
        insnCount: rt.insnCount,
        endAddr: rt.endAddr,
        handlerOff: rt.handlerOff,
        handlers: resolved.handlers,
        catchAllAddr: resolved.catchAllAddr,
      });
    }
  }

  const codeObj = {
    registersSize,
    insSize,
    outsSize,
    triesSize,
    debugInfoOff,
    insnsSize,
    insns,
    tries,
  };
  if (codeCache) codeCache.set(cacheKey, codeObj);
  return codeObj;
}

/**
 * Parses a single DEX file (`035`–`041`) starting at `baseOffset` (default 0).
 */
export function parseDex(
  buffer,
  {
    verifyChecksum = true,
    verifySignature = true,
    baseOffset = 0,
    sharedBudget = null,
    _sharedState = null,
    _expectedContainer = null,
  } = {}
) {
  const fullBytes = toBytes(buffer);
  if (baseOffset < 0 || baseOffset + 0x70 > fullBytes.byteLength) {
    throw new FormatError(
      `Truncated DEX file: size ${fullBytes.byteLength - baseOffset} < minimum 112-byte header`,
      { code: ERROR_CODES.E_INVALID_DEX_BOUNDS, format: 'dex', offset: baseOffset }
    );
  }

  const reader = new BinaryReader(fullBytes, {
    littleEndian: true,
    offset: baseOffset,
    byteLength: fullBytes.byteLength - baseOffset,
  });

  // 1. Validate 8-byte magic: "dex\n035\0" .. "dex\n041\0"
  const magicBytes = reader.bytes(8);
  if (
    magicBytes[0] !== 0x64 || // 'd'
    magicBytes[1] !== 0x65 || // 'e'
    magicBytes[2] !== 0x78 || // 'x'
    magicBytes[3] !== 0x0a || // '\n'
    magicBytes[7] !== 0x00
  ) {
    throw new FormatError('Invalid DEX magic bytes', {
      code: ERROR_CODES.E_INVALID_DEX_MAGIC,
      format: 'dex',
      offset: baseOffset,
    });
  }
  const version = String.fromCharCode(magicBytes[4], magicBytes[5], magicBytes[6]);
  if (!SUPPORTED_VERSION_SET.has(version)) {
    throw new FormatError(`Unsupported DEX version: "${version}"`, {
      code: ERROR_CODES.E_INVALID_DEX_MAGIC,
      format: 'dex',
      offset: baseOffset + 4,
      details: { version, supported: DEX_SUPPORTED_VERSIONS },
    });
  }

  if (_expectedContainer && version !== _expectedContainer.version) {
    throw new FormatError(
      `DEX v${_expectedContainer.version} container sub-DEX has incompatible version "${version}"`,
      {
        code: ERROR_CODES.E_MALFORMED_DEX,
        format: 'dex',
        offset: baseOffset + 4,
        details: { expectedVersion: _expectedContainer.version, version },
      }
    );
  }

  const isV41 = version === '041';
  const expectedHeaderSize = isV41 ? 0x78 : 0x70;

  // Read fixed 112-byte header fields
  const checksum = reader.u32le();
  const signatureBytes = reader.bytes(20, { copy: true });
  const fileSize = reader.u32le();
  const headerSize = reader.u32le();
  const endianTag = reader.u32le();
  const linkSize = reader.u32le();
  const linkOff = reader.u32le();
  const mapOff = reader.u32le();
  const stringIdsSize = reader.u32le();
  const stringIdsOff = reader.u32le();
  const typeIdsSize = reader.u32le();
  const typeIdsOff = reader.u32le();
  const protoIdsSize = reader.u32le();
  const protoIdsOff = reader.u32le();
  const fieldIdsSize = reader.u32le();
  const fieldIdsOff = reader.u32le();
  const methodIdsSize = reader.u32le();
  const methodIdsOff = reader.u32le();
  const classDefsSize = reader.u32le();
  const classDefsOff = reader.u32le();
  const dataSize = reader.u32le();
  const dataOff = reader.u32le();

  // 2. Validate endian_tag BEFORE trusting header values further (Edge Case #7)
  if (endianTag === DEX_REVERSE_ENDIAN_CONSTANT) {
    throw new FormatError('Reverse-endian DEX files (0x78563412) are not supported', {
      code: ERROR_CODES.E_INVALID_DEX_HEADER,
      format: 'dex',
      offset: baseOffset + 0x28,
      details: { endianTag },
    });
  }
  if (endianTag !== DEX_ENDIAN_CONSTANT) {
    throw new FormatError(
      `Invalid DEX endian_tag: 0x${endianTag.toString(16)} (expected 0x12345678)`,
      {
        code: ERROR_CODES.E_INVALID_DEX_HEADER,
        format: 'dex',
        offset: baseOffset + 0x28,
        details: { endianTag },
      }
    );
  }

  // 3. Validate header_size (0x70 for v035–040, 0x78 for v041)
  if (headerSize !== expectedHeaderSize) {
    throw new FormatError(
      `Invalid DEX v${version} header_size: 0x${headerSize.toString(16)} (expected 0x${expectedHeaderSize.toString(16)})`,
      {
        code: ERROR_CODES.E_INVALID_DEX_HEADER,
        format: 'dex',
        offset: baseOffset + 0x24,
        details: { version, headerSize, expectedHeaderSize },
      }
    );
  }

  let containerSize = fileSize;
  let headerOff = baseOffset;
  if (isV41) {
    if (baseOffset + 0x78 > fullBytes.byteLength) {
      throw new FormatError('Truncated DEX v041 120-byte header', {
        code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
        format: 'dex',
        offset: baseOffset + 0x70,
      });
    }
    containerSize = reader.u32le();
    headerOff = reader.u32le();
    if (_expectedContainer && containerSize !== _expectedContainer.containerSize) {
      throw new FormatError(
        `DEX v041 container sub-DEX container_size (${containerSize}) does not match container (${_expectedContainer.containerSize})`,
        {
          code: ERROR_CODES.E_MALFORMED_DEX,
          format: 'dex',
          offset: baseOffset + 0x70,
          details: { expectedContainerSize: _expectedContainer.containerSize, containerSize },
        }
      );
    }
  }

  // 4. Validate file_size & container bounds
  const logicalLimit = isV41 ? containerSize : fileSize;
  if (fileSize < expectedHeaderSize) {
    throw new FormatError(`Invalid DEX file_size (${fileSize} < ${expectedHeaderSize})`, {
      code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
      format: 'dex',
      offset: baseOffset + 0x20,
    });
  }
  if (!isV41) {
    if (baseOffset + fileSize > fullBytes.byteLength || (baseOffset === 0 && fileSize !== fullBytes.byteLength)) {
      throw new FormatError(
        `DEX file_size (${fileSize}) does not match buffer length (${fullBytes.byteLength - baseOffset})`,
        {
          code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
          format: 'dex',
          offset: baseOffset + 0x20,
          details: { fileSize, bufferLength: fullBytes.byteLength - baseOffset },
        }
      );
    }
  } else {
    if (
      containerSize < expectedHeaderSize ||
      containerSize > fullBytes.byteLength ||
      headerOff !== baseOffset ||
      baseOffset + fileSize > containerSize
    ) {
      throw new FormatError(
        `Invalid DEX v041 container bounds (fileSize=${fileSize}, containerSize=${containerSize}, headerOff=${headerOff})`,
        {
          code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
          format: 'dex',
          offset: baseOffset + 0x70,
        }
      );
    }
  }

  // Slice representing the address space for DEX offsets
  // For v<=040, offsets are relative to DEX start (baseOffset); for v041, offsets are physical container offsets.
  const bytes = isV41
    ? fullBytes.subarray(0, containerSize)
    : fullBytes.subarray(baseOffset, baseOffset + fileSize);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const dexStartInSlice = isV41 ? headerOff : 0;
  const checksumSpanEnd = isV41 ? containerSize : fileSize;

  // 5. Verify Adler-32 checksum over bytes[0x0c .. checksumSpanEnd)
  if (verifyChecksum) {
    const adlerStart = dexStartInSlice + 0x0c;
    const computedAdler = adler32(bytes, adlerStart, checksumSpanEnd - adlerStart);
    if (computedAdler !== checksum) {
      throw new FormatError(
        `DEX Adler-32 checksum mismatch: header=0x${checksum.toString(16).padStart(8, '0')}, computed=0x${computedAdler.toString(16).padStart(8, '0')}`,
        {
          code: ERROR_CODES.E_INVALID_DEX_CHECKSUM,
          format: 'dex',
          offset: baseOffset + 0x08,
          details: { expected: checksum, computed: computedAdler },
        }
      );
    }
  }

  // 6. Verify SHA-1 signature over bytes[0x20 .. checksumSpanEnd)
  const signatureHex = Buffer.from(signatureBytes).toString('hex');
  if (verifySignature) {
    const sha1Start = dexStartInSlice + 0x20;
    const computedSha1 = crypto
      .createHash('sha1')
      .update(bytes.subarray(sha1Start, checksumSpanEnd))
      .digest();
    let match = computedSha1.byteLength === 20;
    for (let i = 0; match && i < 20; i++) {
      if (computedSha1[i] !== signatureBytes[i]) match = false;
    }
    if (!match) {
      throw new FormatError(
        `DEX SHA-1 signature mismatch: header=${signatureHex}, computed=${computedSha1.toString('hex')}`,
        {
          code: ERROR_CODES.E_INVALID_DEX_CHECKSUM,
          format: 'dex',
          offset: baseOffset + 0x0c,
          details: { expected: signatureHex, computed: computedSha1.toString('hex') },
        }
      );
    }
  }

  // 7. Enforce DEX spec u16 limits on type_ids & proto_ids (Edge Case #7)
  if (typeIdsSize > 65535) {
    throw new FormatError(`DEX type_ids_size (${typeIdsSize}) exceeds maximum 65535`, {
      code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
      format: 'dex',
      offset: baseOffset + 0x40,
      details: { typeIdsSize },
    });
  }
  if (protoIdsSize > 65535) {
    throw new FormatError(`DEX proto_ids_size (${protoIdsSize}) exceeds maximum 65535`, {
      code: ERROR_CODES.E_INVALID_DEX_BOUNDS,
      format: 'dex',
      offset: baseOffset + 0x48,
      details: { protoIdsSize },
    });
  }

  const limit = bytes.byteLength;
  if (stringIdsSize > 0) assertRange(limit, stringIdsOff, stringIdsSize * 4, 'string_ids');
  if (typeIdsSize > 0) assertRange(limit, typeIdsOff, typeIdsSize * 4, 'type_ids');
  if (protoIdsSize > 0) assertRange(limit, protoIdsOff, protoIdsSize * 12, 'proto_ids');
  if (fieldIdsSize > 0) assertRange(limit, fieldIdsOff, fieldIdsSize * 8, 'field_ids');
  if (methodIdsSize > 0) assertRange(limit, methodIdsOff, methodIdsSize * 8, 'method_ids');
  if (classDefsSize > 0) assertRange(limit, classDefsOff, classDefsSize * 32, 'class_defs');
  if (!isV41 && dataSize > 0) assertRange(limit, dataOff, dataSize, 'data');

  // Shared budgets & offset-aliasing memoization caches (prevents offset-aliasing amplification bombs)
  const budget = sharedBudget ?? _sharedState?.budget ?? createDexParseBudget(bytes.byteLength);
  if (typeof budget.mapListItems !== 'number') {
    budget.mapListItems = 0;
    budget.maxMapListItems = Math.min(Math.max(Math.ceil(bytes.byteLength / 8), 4096), 131072);
  }
  if (typeof budget.tableSlots !== 'number') {
    budget.tableSlots = 0;
    budget.maxTableSlots = Math.min(Math.max(Math.ceil(bytes.byteLength / 2), 65536), 262144);
  }
  if (typeof budget.heavyTableSlots !== 'number') {
    budget.heavyTableSlots = 0;
    budget.maxHeavyTableSlots = Math.min(Math.max(Math.ceil(bytes.byteLength / 4), 16384), 131072);
  }

  // Enforce cross-sub-DEX / multi-DEX cumulative table-slot budgets BEFORE allocating table arrays
  const subTableSlots =
    stringIdsSize + typeIdsSize + protoIdsSize + fieldIdsSize + methodIdsSize + classDefsSize;
  const subHeavySlots = protoIdsSize + fieldIdsSize + methodIdsSize + classDefsSize * 2;
  budget.tableSlots += subTableSlots;
  if (budget.tableSlots > budget.maxTableSlots) {
    throw new FormatError(
      `DEX cumulative table slots (${budget.tableSlots}) exceeds budget (${budget.maxTableSlots})`,
      { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: baseOffset }
    );
  }
  budget.heavyTableSlots += subHeavySlots;
  if (budget.heavyTableSlots > budget.maxHeavyTableSlots) {
    throw new FormatError(
      `DEX cumulative structured table slots (${budget.heavyTableSlots}) exceeds budget (${budget.maxHeavyTableSlots})`,
      { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: baseOffset }
    );
  }

  const strCache = _sharedState?.strCache ?? new Map();
  const typeListCache = _sharedState?.typeListCache ?? new Map();
  const codeCache = _sharedState?.codeCache ?? new Map();
  const staticValuesCache = _sharedState?.staticValuesCache ?? new Map();
  const mapListCache = _sharedState?.mapListCache ?? new Map();
  const classDataCache = new Map();
  const boundStaticFieldsCache = new Map();
  const typeTableCachePrefix = _sharedState ? `${stringIdsOff}:${stringIdsSize}:${typeIdsOff}:${typeIdsSize}` : null;
  const staticValCachePrefix = _sharedState
    ? `${stringIdsOff}:${stringIdsSize}:${typeIdsOff}:${typeIdsSize}:${protoIdsOff}:${protoIdsSize}:${fieldIdsOff}:${fieldIdsSize}:${methodIdsOff}:${methodIdsSize}`
    : null;

  // 8. Parse string_ids -> MUTF-8 strings (memoized by strDataOff + unique decoded byte budget)
  const strings = new Array(stringIdsSize);
  for (let i = 0; i < stringIdsSize; i++) {
    const strDataOff = view.getUint32(stringIdsOff + i * 4, true);
    assertRange(limit, strDataOff, 1, `string_data_item[${i}]`);
    if (strCache.has(strDataOff)) {
      strings[i] = strCache.get(strDataOff);
      continue;
    }
    const utf16LenDec = wrapLeb128(() => decodeUleb128(bytes, strDataOff), strDataOff);
    if (budget.decodedStringBytes + utf16LenDec.value * 2 > budget.maxDecodedStringBytes) {
      throw new FormatError(
        `DEX decoded string bytes (${budget.decodedStringBytes + utf16LenDec.value * 2}) exceeds budget (${budget.maxDecodedStringBytes})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: strDataOff }
      );
    }
    const decoded = wrapMutf8(
      () => decodeMutf8Z(bytes, utf16LenDec.nextOffset, { expectedUtf16Length: utf16LenDec.value }),
      utf16LenDec.nextOffset
    );
    const decodedBytes = Math.max(decoded.value.length * 2, decoded.nextOffset - strDataOff);
    budget.decodedStringBytes += decodedBytes;
    if (budget.decodedStringBytes > budget.maxDecodedStringBytes) {
      throw new FormatError(
        `DEX decoded string bytes (${budget.decodedStringBytes}) exceeds budget (${budget.maxDecodedStringBytes})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: strDataOff }
      );
    }
    strCache.set(strDataOff, decoded.value);
    strings[i] = decoded.value;
  }

  // 9. Parse type_ids
  const types = new Array(typeIdsSize);
  for (let i = 0; i < typeIdsSize; i++) {
    const descIdx = view.getUint32(typeIdsOff + i * 4, true);
    assertIndex(descIdx, strings.length, 'type_id descriptor', typeIdsOff + i * 4);
    types[i] = strings[descIdx];
  }

  // 10. Parse proto_ids (memoized type_list + derived descriptor budget)
  const protos = new Array(protoIdsSize);
  for (let i = 0; i < protoIdsSize; i++) {
    const pOff = protoIdsOff + i * 12;
    const shortyIdx = view.getUint32(pOff, true);
    const returnTypeIdx = view.getUint32(pOff + 4, true);
    const parametersOff = view.getUint32(pOff + 8, true);
    assertIndex(shortyIdx, strings.length, 'proto shorty', pOff);
    assertIndex(returnTypeIdx, types.length, 'proto return_type', pOff + 4);
    const paramEntry = parseTypeList(
      bytes,
      view,
      parametersOff,
      limit,
      types,
      typeListCache,
      budget,
      typeTableCachePrefix
    );
    const returnType = types[returnTypeIdx];
    const descLen = 2 + paramEntry.joined.length + returnType.length;
    budget.derivedChars += descLen;
    if (budget.derivedChars > budget.maxDerivedChars) {
      throw new FormatError(
        `DEX proto descriptor expansion (${budget.derivedChars}) exceeds budget (${budget.maxDerivedChars})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: pOff }
      );
    }
    protos[i] = {
      index: i,
      shorty: strings[shortyIdx],
      returnType,
      params: paramEntry.list,
      descriptor: `(${paramEntry.joined})${returnType}`,
    };
  }

  // 11. Parse field_ids
  const fields = new Array(fieldIdsSize);
  for (let i = 0; i < fieldIdsSize; i++) {
    const fOff = fieldIdsOff + i * 8;
    const classIdx = view.getUint16(fOff, true);
    const typeIdx = view.getUint16(fOff + 2, true);
    const nameIdx = view.getUint32(fOff + 4, true);
    assertIndex(classIdx, types.length, 'field class_idx', fOff);
    assertIndex(typeIdx, types.length, 'field type_idx', fOff + 2);
    assertIndex(nameIdx, strings.length, 'field name_idx', fOff + 4);
    const classType = types[classIdx];
    const type = types[typeIdx];
    const name = strings[nameIdx];
    budget.derivedChars += classType.length + 2 + name.length + 1 + type.length;
    if (budget.derivedChars > budget.maxDerivedChars) {
      throw new FormatError(
        `DEX field key expansion (${budget.derivedChars}) exceeds budget (${budget.maxDerivedChars})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: fOff }
      );
    }
    fields[i] = {
      index: i,
      classIdx,
      typeIdx,
      nameIdx,
      classType,
      type,
      name,
      key: `${classType}->${name}:${type}`,
    };
  }

  // 12. Parse method_ids
  const methods = new Array(methodIdsSize);
  for (let i = 0; i < methodIdsSize; i++) {
    const mOff = methodIdsOff + i * 8;
    const classIdx = view.getUint16(mOff, true);
    const protoIdx = view.getUint16(mOff + 2, true);
    const nameIdx = view.getUint32(mOff + 4, true);
    assertIndex(classIdx, types.length, 'method class_idx', mOff);
    assertIndex(protoIdx, protos.length, 'method proto_idx', mOff + 2);
    assertIndex(nameIdx, strings.length, 'method name_idx', mOff + 4);
    const classType = types[classIdx];
    const proto = protos[protoIdx];
    const name = strings[nameIdx];
    const sigLen = name.length + proto.descriptor.length;
    budget.derivedChars += sigLen + classType.length + 2 + sigLen;
    if (budget.derivedChars > budget.maxDerivedChars) {
      throw new FormatError(
        `DEX method signature expansion (${budget.derivedChars}) exceeds budget (${budget.maxDerivedChars})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: mOff }
      );
    }
    const signature = `${name}${proto.descriptor}`;
    methods[i] = {
      index: i,
      classIdx,
      protoIdx,
      nameIdx,
      classType,
      proto,
      name,
      descriptor: proto.descriptor,
      signature,
      key: `${classType}->${signature}`,
    };
  }

  // 13. Parse class_defs + class_data_item + static_values + code_item
  const decodeCtx = { strings, types, fields, methods, budget };
  const classDefs = new Array(classDefsSize);
  const classesByName = new Map();

  for (let i = 0; i < classDefsSize; i++) {
    const cOff = classDefsOff + i * 32;
    const classIdx = view.getUint32(cOff, true);
    const accessFlags = view.getUint32(cOff + 4, true);
    const superclassIdx = view.getUint32(cOff + 8, true);
    const interfacesOff = view.getUint32(cOff + 12, true);
    const sourceFileIdx = view.getUint32(cOff + 16, true);
    const annotationsOff = view.getUint32(cOff + 20, true);
    const classDataOff = view.getUint32(cOff + 24, true);
    const staticValuesOff = view.getUint32(cOff + 28, true);

    assertIndex(classIdx, types.length, 'class_def class_idx', cOff);
    const classType = types[classIdx];
    let superclassType = null;
    if (superclassIdx !== DEX_NO_INDEX) {
      assertIndex(superclassIdx, types.length, 'class_def superclass_idx', cOff + 8);
      superclassType = types[superclassIdx];
    }
    const interfaces = parseTypeList(
      bytes,
      view,
      interfacesOff,
      limit,
      types,
      typeListCache,
      budget,
      typeTableCachePrefix
    ).list;
    let sourceFile = null;
    if (sourceFileIdx !== DEX_NO_INDEX) {
      assertIndex(sourceFileIdx, strings.length, 'class_def source_file_idx', cOff + 16);
      sourceFile = strings[sourceFileIdx];
    }

    let staticValues = EMPTY_ARRAY;
    if (staticValuesOff !== 0) {
      const svCacheKey = staticValCachePrefix !== null ? `${staticValCachePrefix}:${staticValuesOff}` : staticValuesOff;
      if (staticValuesCache.has(svCacheKey)) {
        staticValues = staticValuesCache.get(svCacheKey);
      } else {
        assertRange(limit, staticValuesOff, 1, 'static_values_off');
        let svPos = staticValuesOff;
        const svLenDec = wrapLeb128(() => decodeUleb128(bytes, svPos), svPos);
        svPos = svLenDec.nextOffset;
        if (svLenDec.value > limit - svPos) {
          throw new FormatError(
            `DEX static_values length (${svLenDec.value}) exceeds remaining bytes (${limit - svPos})`,
            { code: ERROR_CODES.E_INVALID_DEX_BOUNDS, format: 'dex', offset: svPos }
          );
        }
        if (svLenDec.value === 0) {
          staticValues = EMPTY_ARRAY;
        } else {
          if (budget.encodedValues + svLenDec.value > budget.maxEncodedValues) {
            throw new FormatError(
              `DEX static_values expansion (${budget.encodedValues + svLenDec.value}) exceeds budget (${budget.maxEncodedValues})`,
              { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: svPos }
            );
          }
          staticValues = new Array(svLenDec.value);
          for (let s = 0; s < svLenDec.value; s++) {
            const decodedVal = decodeEncodedValue(bytes, svPos, limit, decodeCtx, 0);
            staticValues[s] = decodedVal.value;
            svPos = decodedVal.nextOffset;
          }
          Object.freeze(staticValues);
          staticValuesCache.set(svCacheKey, staticValues);
        }
      }
    }

    let staticFields = EMPTY_ARRAY;
    let instanceFields = EMPTY_ARRAY;
    let directMethods = EMPTY_ARRAY;
    let virtualMethods = EMPTY_ARRAY;
    let methodMap = EMPTY_METHOD_MAP;

    if (classDataOff !== 0) {
      let cachedCd = classDataCache.get(classDataOff);
      if (!cachedCd) {
        assertRange(limit, classDataOff, 1, 'class_data_item');
        let pos = classDataOff;
        const sfDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
        pos = sfDec.nextOffset;
        const ifDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
        pos = ifDec.nextOffset;
        const dmDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
        pos = dmDec.nextOffset;
        const vmDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
        pos = vmDec.nextOffset;
        const minClassDataBytes = (sfDec.value + ifDec.value) * 2 + (dmDec.value + vmDec.value) * 3;
        if (minClassDataBytes > limit - pos) {
          throw new FormatError(
            `DEX class_data_item item counts exceed remaining bytes (${minClassDataBytes} > ${limit - pos})`,
            { code: ERROR_CODES.E_INVALID_DEX_BOUNDS, format: 'dex', offset: pos }
          );
        }
        const totalMembers = sfDec.value + ifDec.value + dmDec.value + vmDec.value;
        budget.classDataMembers += totalMembers;
        if (budget.classDataMembers > budget.maxClassDataMembers) {
          throw new FormatError(
            `DEX class_data_item member count (${budget.classDataMembers}) exceeds budget (${budget.maxClassDataMembers})`,
            { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: classDataOff }
          );
        }

        const baseStaticFields = sfDec.value > 0 ? new Array(sfDec.value) : EMPTY_ARRAY;
        let fieldIdx = 0;
        for (let f = 0; f < sfDec.value; f++) {
          const diffDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = diffDec.nextOffset;
          const accDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = accDec.nextOffset;
          fieldIdx += diffDec.value;
          assertIndex(fieldIdx, fields.length, 'static field', pos);
          const fieldRef = fields[fieldIdx];
          baseStaticFields[f] = Object.freeze({
            ...fieldRef,
            accessFlags: accDec.value,
            initialValue: undefined,
          });
        }
        if (sfDec.value > 0) Object.freeze(baseStaticFields);

        const parsedInstanceFields = ifDec.value > 0 ? new Array(ifDec.value) : EMPTY_ARRAY;
        fieldIdx = 0;
        for (let f = 0; f < ifDec.value; f++) {
          const diffDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = diffDec.nextOffset;
          const accDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = accDec.nextOffset;
          fieldIdx += diffDec.value;
          assertIndex(fieldIdx, fields.length, 'instance field', pos);
          parsedInstanceFields[f] = Object.freeze({
            ...fields[fieldIdx],
            accessFlags: accDec.value,
          });
        }
        if (ifDec.value > 0) Object.freeze(parsedInstanceFields);

        const parsedDirectMethods = dmDec.value > 0 ? new Array(dmDec.value) : EMPTY_ARRAY;
        const parsedVirtualMethods = vmDec.value > 0 ? new Array(vmDec.value) : EMPTY_ARRAY;
        const parsedMethodMap = dmDec.value + vmDec.value > 0 ? new Map() : EMPTY_METHOD_MAP;

        let methodIdx = 0;
        for (let m = 0; m < dmDec.value; m++) {
          const diffDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = diffDec.nextOffset;
          const accDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = accDec.nextOffset;
          const codeOffDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = codeOffDec.nextOffset;
          methodIdx += diffDec.value;
          assertIndex(methodIdx, methods.length, 'direct method', pos);
          const methodRef = methods[methodIdx];
          const code =
            codeOffDec.value !== 0
              ? parseCodeItem(
                  bytes,
                  view,
                  codeOffDec.value,
                  limit,
                  types,
                  codeCache,
                  budget,
                  typeTableCachePrefix
                )
              : null;
          const entry = {
            ...methodRef,
            accessFlags: accDec.value,
            codeOff: codeOffDec.value,
            code,
            isDirect: true,
            isStatic: (accDec.value & DEX_ACCESS_FLAGS.ACC_STATIC) !== 0,
          };
          parsedDirectMethods[m] = entry;
          parsedMethodMap.set(entry.signature, entry);
        }
        if (dmDec.value > 0) Object.freeze(parsedDirectMethods);

        methodIdx = 0;
        for (let m = 0; m < vmDec.value; m++) {
          const diffDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = diffDec.nextOffset;
          const accDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = accDec.nextOffset;
          const codeOffDec = wrapLeb128(() => decodeUleb128(bytes, pos), pos);
          pos = codeOffDec.nextOffset;
          methodIdx += diffDec.value;
          assertIndex(methodIdx, methods.length, 'virtual method', pos);
          const methodRef = methods[methodIdx];
          const code =
            codeOffDec.value !== 0
              ? parseCodeItem(
                  bytes,
                  view,
                  codeOffDec.value,
                  limit,
                  types,
                  codeCache,
                  budget,
                  typeTableCachePrefix
                )
              : null;
          const entry = {
            ...methodRef,
            accessFlags: accDec.value,
            codeOff: codeOffDec.value,
            code,
            isDirect: false,
            isStatic: (accDec.value & DEX_ACCESS_FLAGS.ACC_STATIC) !== 0,
          };
          parsedVirtualMethods[m] = entry;
          parsedMethodMap.set(entry.signature, entry);
        }
        if (vmDec.value > 0) Object.freeze(parsedVirtualMethods);

        cachedCd = Object.freeze({
          staticFields: baseStaticFields,
          instanceFields: parsedInstanceFields,
          directMethods: parsedDirectMethods,
          virtualMethods: parsedVirtualMethods,
          methodMap: parsedMethodMap,
        });
        classDataCache.set(classDataOff, cachedCd);
      }

      instanceFields = cachedCd.instanceFields;
      directMethods = cachedCd.directMethods;
      virtualMethods = cachedCd.virtualMethods;
      methodMap = cachedCd.methodMap;

      if (staticValues.length > 0 && cachedCd.staticFields.length > 0) {
        const boundKey = `${classDataOff}:${staticValuesOff}`;
        const cachedBound = boundStaticFieldsCache.get(boundKey);
        if (cachedBound) {
          staticFields = cachedBound;
        } else {
          budget.classDataMembers += cachedCd.staticFields.length;
          if (budget.classDataMembers > budget.maxClassDataMembers) {
            throw new FormatError(
              `DEX class_data_item static field binding (${budget.classDataMembers}) exceeds budget (${budget.maxClassDataMembers})`,
              { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: classDataOff }
            );
          }
          const bound = new Array(cachedCd.staticFields.length);
          for (let f = 0; f < cachedCd.staticFields.length; f++) {
            const sf = cachedCd.staticFields[f];
            bound[f] = f < staticValues.length ? Object.freeze({ ...sf, initialValue: staticValues[f] }) : sf;
          }
          Object.freeze(bound);
          boundStaticFieldsCache.set(boundKey, bound);
          staticFields = bound;
        }
      } else {
        staticFields = cachedCd.staticFields;
      }
    }

    const classDef = {
      index: i,
      classType,
      accessFlags,
      superclassType,
      interfaces,
      sourceFile,
      annotationsOff,
      classDataOff,
      staticValuesOff,
      staticValues,
      staticFields,
      instanceFields,
      directMethods,
      virtualMethods,
      methods: methodMap,
    };
    classDefs[i] = classDef;
    classesByName.set(classType, classDef);
  }

  // Also parse optional map_list for diagnostics (memoized by mapOff & budgeted against mapListItems)
  let mapList = EMPTY_ARRAY;
  if (mapOff !== 0) {
    if (mapListCache.has(mapOff)) {
      mapList = mapListCache.get(mapOff);
    } else {
      assertRange(limit, mapOff, 4, 'map_list header');
      const mapSize = view.getUint32(mapOff, true);
      assertRange(limit, mapOff + 4, mapSize * 12, 'map_list items');
      budget.mapListItems += mapSize;
      if (budget.mapListItems > budget.maxMapListItems) {
        throw new FormatError(
          `DEX map_list item count (${budget.mapListItems}) exceeds budget (${budget.maxMapListItems})`,
          { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: mapOff }
        );
      }
      const parsedMapList = mapSize > 0 ? new Array(mapSize) : EMPTY_ARRAY;
      for (let i = 0; i < mapSize; i++) {
        const mOff = mapOff + 4 + i * 12;
        parsedMapList[i] = Object.freeze({
          type: view.getUint16(mOff, true),
          size: view.getUint32(mOff + 4, true),
          offset: view.getUint32(mOff + 8, true),
        });
      }
      if (mapSize > 0) Object.freeze(parsedMapList);
      mapListCache.set(mapOff, parsedMapList);
      mapList = parsedMapList;
    }
  }

  const dexFile = {
    version,
    header: {
      version,
      checksum,
      signature: signatureHex,
      fileSize,
      headerSize,
      endianTag,
      linkSize,
      linkOff,
      mapOff,
      stringIdsSize,
      stringIdsOff,
      typeIdsSize,
      typeIdsOff,
      protoIdsSize,
      protoIdsOff,
      fieldIdsSize,
      fieldIdsOff,
      methodIdsSize,
      methodIdsOff,
      classDefsSize,
      classDefsOff,
      dataSize,
      dataOff,
      containerSize,
      headerOff,
    },
    strings,
    types,
    protos,
    fields,
    methods,
    classDefs,
    classesByName,
    mapList,
    logicalLimit,
    decodeUleb128p1: (off) => wrapLeb128(() => decodeUleb128p1(bytes, off), off),
  };

  // Back-reference owning dexFile on each class & method for multidex VM lookup (deduplicated)
  const taggedMethodArrays = new Set();
  for (const cls of classDefs) {
    cls.dex = dexFile;
    if (!taggedMethodArrays.has(cls.directMethods)) {
      taggedMethodArrays.add(cls.directMethods);
      for (const m of cls.directMethods) m.dex = dexFile;
    }
    if (!taggedMethodArrays.has(cls.virtualMethods)) {
      taggedMethodArrays.add(cls.virtualMethods);
      for (const m of cls.virtualMethods) m.dex = dexFile;
    }
  }

  return dexFile;
}

/**
 * Parses a DEX v041 multi-DEX container (or single DEX v035–v041) into an array of DexFile objects.
 */
export function parseDexContainer(buffer, opts = {}) {
  const bytes = toBytes(buffer);
  const maxContainerDexFiles =
    Number.isInteger(opts.maxContainerDexFiles) && opts.maxContainerDexFiles > 0
      ? opts.maxContainerDexFiles
      : MAX_CONTAINER_DEX_FILES;
  const sharedState = {
    budget: opts.sharedBudget ?? createDexParseBudget(bytes.byteLength),
    strCache: new Map(),
    typeListCache: new Map(),
    codeCache: new Map(),
    staticValuesCache: new Map(),
    mapListCache: new Map(),
  };
  const first = parseDex(bytes, { ...opts, baseOffset: 0, _sharedState: sharedState });
  const results = [first];
  if (first.version === '041' && first.header.fileSize < first.header.containerSize) {
    const expectedContainer = { version: '041', containerSize: first.header.containerSize };
    let nextOff = first.header.fileSize;
    while (nextOff + 0x78 <= first.header.containerSize) {
      if (results.length >= maxContainerDexFiles) {
        throw new FormatError(
          `DEX v041 container sub-DEX count (${results.length + 1}) exceeds maximum (${maxContainerDexFiles})`,
          { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: nextOff }
        );
      }
      const sub = parseDex(bytes, {
        ...opts,
        baseOffset: nextOff,
        _sharedState: sharedState,
        _expectedContainer: expectedContainer,
      });
      if (sub.version !== '041' || sub.header.containerSize !== first.header.containerSize) {
        throw new FormatError(
          `DEX v041 container sub-DEX at offset ${nextOff} has incompatible version (${sub.version}) or container_size (${sub.header.containerSize} !== ${first.header.containerSize})`,
          { code: ERROR_CODES.E_MALFORMED_DEX, format: 'dex', offset: nextOff }
        );
      }
      results.push(sub);
      if (sub.header.fileSize <= 0) break;
      nextOff += sub.header.fileSize;
    }
  }
  return results;
}
