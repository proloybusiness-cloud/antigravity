/**
 * OmniOS Android Resource Table (`resources.arsc`) Parser & Encoder (F-037)
 * Compliant with AOSP `ResourceTypes.h` (`ResTable`, `ResTable_package`, `ResTable_typeSpec`, `ResTable_type`).
 * - Supports standard 32-bit entry offsets, Android O+ `FLAG_OFFSET16 (0x02)` (`off16 * 4`, `0xFFFF == NO_ENTRY`),
 *   AND `FLAG_SPARSE (0x01)` (`(u16 idx, u16 off16)` pairs, `off16 * 4`) (Edge Case #6)
 * - Supports simple entries, complex bags (`FLAG_COMPLEX`), compact entries (`FLAG_COMPACT`), and unknown chunk skipping
 * - Strict chunk DoS guards rejecting zero/truncated/OOB chunks with `FormatError(E_MALFORMED_ARSC)`
 * - Zero external dependencies; pure in-memory parser/encoder without host filesystem access.
 */

import { BinaryWriter } from '../../common/binary.mjs';
import { FormatError, ERROR_CODES } from '../../common/errors.mjs';
import {
  RES_CHUNK_TYPES,
  RES_VALUE_TYPES,
  readChunkHeader,
  parseResStringPool,
  encodeResStringPool,
  decodeResValue,
} from './axml-parser.mjs';

const UTF16LE_DECODER = new TextDecoder('utf-16le');

export const ARSC_TYPE_FLAGS = Object.freeze({
  FLAG_SPARSE: 0x01,
  FLAG_OFFSET16: 0x02,
});

export const ARSC_ENTRY_FLAGS = Object.freeze({
  FLAG_COMPLEX: 0x0001,
  FLAG_PUBLIC: 0x0002,
  FLAG_WEAK: 0x0004,
  FLAG_COMPACT: 0x0008,
});

export const NO_ENTRY_32 = 0xffffffff;
export const NO_ENTRY_16 = 0xffff;
export const MAX_ARSC_BYTES = 16 * 1024 * 1024;
export const MAX_ARSC_ENTRIES = 65536;
export const MAX_ARSC_PACKAGES = 64;
export const MAX_ARSC_CHUNKS = 4096;
export const MAX_ARSC_DECODED_STRING_BYTES = 8 * 1024 * 1024;

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
  throw new FormatError('Expected binary buffer for resources.arsc', {
    code: ERROR_CODES.E_MALFORMED_ARSC,
    format: 'arsc',
    offset: 0,
  });
}

function readUtf16FixedString(buf, offset, maxCodeUnits) {
  const byteLen = maxCodeUnits * 2;
  let end = offset;
  const limit = Math.min(buf.byteLength, offset + byteLen);
  while (end + 1 < limit) {
    if (buf[end] === 0 && buf[end + 1] === 0) break;
    end += 2;
  }
  return UTF16LE_DECODER.decode(buf.subarray(offset, end));
}

function parseEntryAt(buf, view, entryPos, chunkEnd, keyStrings, globalStrings, arscBudget = null) {
  if (entryPos < 0 || entryPos + 8 > chunkEnd) {
    throw new FormatError(`Truncated ResTable_entry at offset ${entryPos}`, {
      code: ERROR_CODES.E_MALFORMED_ARSC,
      format: 'arsc',
      offset: entryPos,
    });
  }

  const first = view.getUint16(entryPos, true);
  const flags = view.getUint16(entryPos + 2, true);

  // Android 14+ compact entry (8 bytes total)
  if ((flags & ARSC_ENTRY_FLAGS.FLAG_COMPACT) !== 0) {
    const keyIndex = first;
    const dataType = (flags >>> 8) & 0xff;
    const data = view.getUint32(entryPos + 4, true);
    const keyName = keyIndex < keyStrings.length ? keyStrings[keyIndex] : `entry_${keyIndex}`;
    return {
      flags,
      keyIndex,
      keyName,
      dataType,
      data,
      value: decodeResValue(dataType, data, globalStrings, null),
      bag: null,
    };
  }

  const entrySize = first;
  if (entrySize < 8 || entryPos + entrySize > chunkEnd) {
    throw new FormatError(`Invalid ResTable_entry size (${entrySize}) at offset ${entryPos}`, {
      code: ERROR_CODES.E_MALFORMED_ARSC,
      format: 'arsc',
      offset: entryPos,
    });
  }

  const keyIndex = view.getUint32(entryPos + 4, true);
  const keyName = keyIndex < keyStrings.length ? keyStrings[keyIndex] : `entry_${keyIndex}`;

  if ((flags & ARSC_ENTRY_FLAGS.FLAG_COMPLEX) !== 0) {
    if (entrySize < 16 || entryPos + 16 > chunkEnd) {
      throw new FormatError(`Truncated ResTable_map_entry at offset ${entryPos}`, {
        code: ERROR_CODES.E_MALFORMED_ARSC,
        format: 'arsc',
        offset: entryPos,
      });
    }
    const parentId = view.getUint32(entryPos + 8, true);
    const mapCount = view.getUint32(entryPos + 12, true);
    const mapStart = entryPos + entrySize;
    if (mapCount > 100_000 || mapStart + mapCount * 12 > chunkEnd) {
      throw new FormatError(`ResTable_map_entry bag exceeds chunk bounds (count=${mapCount})`, {
        code: ERROR_CODES.E_MALFORMED_ARSC,
        format: 'arsc',
        offset: mapStart,
      });
    }
    if (arscBudget) {
      arscBudget.totalUniqueBagItems += mapCount;
      if (arscBudget.totalUniqueBagItems > arscBudget.maxUniqueBagItems) {
        throw new FormatError(
          `ARSC cumulative unique bag items (${arscBudget.totalUniqueBagItems}) exceeds budget (${arscBudget.maxUniqueBagItems})`,
          { code: ERROR_CODES.E_MALFORMED_ARSC, format: 'arsc', offset: mapStart }
        );
      }
    }

    const bag = new Array(mapCount);
    for (let m = 0; m < mapCount; m++) {
      const mOff = mapStart + m * 12;
      const itemName = view.getUint32(mOff, true);
      const valType = buf[mOff + 7];
      const valData = view.getUint32(mOff + 8, true);
      bag[m] = {
        name: itemName,
        dataType: valType,
        data: valData,
        value: decodeResValue(valType, valData, globalStrings, null),
      };
    }

    return {
      flags,
      keyIndex,
      keyName,
      parentId,
      dataType: RES_VALUE_TYPES.TYPE_NULL,
      data: 0,
      value: bag,
      bag,
    };
  }

  // Standard simple entry: followed immediately by 8-byte Res_value
  const valPos = entryPos + entrySize;
  if (valPos + 8 > chunkEnd) {
    throw new FormatError(`Truncated Res_value in ResTable_entry at offset ${valPos}`, {
      code: ERROR_CODES.E_MALFORMED_ARSC,
      format: 'arsc',
      offset: valPos,
    });
  }
  const dataType = buf[valPos + 3];
  const data = view.getUint32(valPos + 4, true);

  return {
    flags,
    keyIndex,
    keyName,
    dataType,
    data,
    value: decodeResValue(dataType, data, globalStrings, null),
    bag: null,
  };
}

function parsePackageChunk(buf, view, pkgChunk, globalStrings, entriesMap, byNameMap, arscBudget = null) {
  const offset = pkgChunk.offset;
  if (pkgChunk.headerSize < 284) {
    throw new FormatError(`ResTable_package headerSize too small (${pkgChunk.headerSize} < 284)`, {
      code: ERROR_CODES.E_MALFORMED_ARSC,
      format: 'arsc',
      offset,
    });
  }

  const pkgId = view.getUint32(offset + 8, true) & 0xff;
  const name = readUtf16FixedString(buf, offset + 12, 128);
  const typeStringsOff = view.getUint32(offset + 268, true);
  const keyStringsOff = view.getUint32(offset + 276, true);
  const typeIdOffset = pkgChunk.headerSize >= 288 ? view.getUint32(offset + 284, true) : 0;

  let typeStrings = [];
  let keyStrings = [];

  const parsePool = (poolOffset, poolLimit) => {
    if (arscBudget && typeof arscBudget.getStringPool === 'function') {
      return arscBudget.getStringPool(poolOffset, poolLimit);
    }
    return parseResStringPool(buf, poolOffset, poolLimit, {
      errorCode: ERROR_CODES.E_MALFORMED_ARSC,
      format: 'arsc',
      decodedStringBudget: arscBudget?.decodedStringBudget ?? null,
    });
  };

  if (typeStringsOff > 0) {
    const absOff = offset + typeStringsOff;
    if (absOff < offset + pkgChunk.headerSize || absOff >= pkgChunk.end) {
      throw new FormatError(`ResTable_package typeStrings offset out of bounds (${typeStringsOff})`, {
        code: ERROR_CODES.E_MALFORMED_ARSC,
        format: 'arsc',
        offset: offset + 268,
      });
    }
    typeStrings = parsePool(absOff, pkgChunk.end).strings;
  }

  if (keyStringsOff > 0) {
    const absOff = offset + keyStringsOff;
    if (absOff < offset + pkgChunk.headerSize || absOff >= pkgChunk.end) {
      throw new FormatError(`ResTable_package keyStrings offset out of bounds (${keyStringsOff})`, {
        code: ERROR_CODES.E_MALFORMED_ARSC,
        format: 'arsc',
        offset: offset + 276,
      });
    }
    keyStrings = parsePool(absOff, pkgChunk.end).strings;
  }

  const types = [];
  const typeSpecs = [];
  let cursor = offset + pkgChunk.headerSize;

  while (cursor < pkgChunk.end) {
    if (arscBudget) {
      arscBudget.totalChunks += 1;
      if (arscBudget.totalChunks > arscBudget.maxChunks) {
        throw new FormatError(
          `ARSC chunk count (${arscBudget.totalChunks}) exceeds maximum (${arscBudget.maxChunks})`,
          { code: ERROR_CODES.E_MALFORMED_ARSC, format: 'arsc', offset: cursor }
        );
      }
    }
    const sub = readChunkHeader(buf, cursor, pkgChunk.end, {
      errorCode: ERROR_CODES.E_MALFORMED_ARSC,
      format: 'arsc',
    });

    if (sub.type === RES_CHUNK_TYPES.RES_STRING_POOL_TYPE) {
      // Already parsed via typeStringsOff / keyStringsOff; if offsets were 0, populate in order.
      if (typeStrings.length === 0 && sub.offset === offset + typeStringsOff) {
        typeStrings = parsePool(sub.offset, sub.end).strings;
      } else if (keyStrings.length === 0 && sub.offset === offset + keyStringsOff) {
        keyStrings = parsePool(sub.offset, sub.end).strings;
      }
    } else if (sub.type === RES_CHUNK_TYPES.RES_TABLE_TYPE_SPEC_TYPE) {
      if (sub.headerSize < 16) {
        throw new FormatError(`ResTable_typeSpec headerSize too small (${sub.headerSize})`, {
          code: ERROR_CODES.E_MALFORMED_ARSC,
          format: 'arsc',
          offset: sub.offset,
        });
      }
      const specId = buf[sub.offset + 8];
      const entryCount = view.getUint32(sub.offset + 12, true);
      if (sub.offset + sub.headerSize + entryCount * 4 > sub.end) {
        throw new FormatError(`ResTable_typeSpec exceeds chunk bounds (entryCount=${entryCount})`, {
          code: ERROR_CODES.E_MALFORMED_ARSC,
          format: 'arsc',
          offset: sub.offset,
        });
      }
      typeSpecs.push({ id: specId, entryCount });
    } else if (sub.type === RES_CHUNK_TYPES.RES_TABLE_TYPE_TYPE) {
      if (sub.headerSize < 20) {
        throw new FormatError(`ResTable_type headerSize too small (${sub.headerSize})`, {
          code: ERROR_CODES.E_MALFORMED_ARSC,
          format: 'arsc',
          offset: sub.offset,
        });
      }
      const typeId = buf[sub.offset + 8];
      const flags = buf[sub.offset + 9];
      const entryCount = view.getUint32(sub.offset + 12, true);
      const entriesStart = view.getUint32(sub.offset + 16, true);

      if (entryCount > 65536) {
        throw new FormatError(`ResTable_type entryCount (${entryCount}) exceeds 65536`, {
          code: ERROR_CODES.E_MALFORMED_ARSC,
          format: 'arsc',
          offset: sub.offset + 12,
        });
      }
      if (entryCount > 0 && (entriesStart < sub.headerSize || sub.offset + entriesStart > sub.end)) {
        throw new FormatError(`ResTable_type entriesStart (${entriesStart}) out of bounds`, {
          code: ERROR_CODES.E_MALFORMED_ARSC,
          format: 'arsc',
          offset: sub.offset + 16,
        });
      }

      const typeNameIdx = typeId - 1 - typeIdOffset;
      const typeName =
        typeNameIdx >= 0 && typeNameIdx < typeStrings.length
          ? typeStrings[typeNameIdx]
          : `type_${typeId}`;

      const tableStart = sub.offset + sub.headerSize;
      const entriesBase = sub.offset + entriesStart;
      const isSparse = (flags & ARSC_TYPE_FLAGS.FLAG_SPARSE) !== 0;
      const isOffset16 = (flags & ARSC_TYPE_FLAGS.FLAG_OFFSET16) !== 0;
      const typeEntries = [];
      const entryCache = new Map();

      const addEntryAt = (idx, entryPos) => {
        if (entryPos < entriesBase || entryPos + 8 > sub.end) {
          throw new FormatError(`ResTable_entry offset (${entryPos}) out of chunk bounds`, {
            code: ERROR_CODES.E_MALFORMED_ARSC,
            format: 'arsc',
            offset: entryPos,
          });
        }
        if (arscBudget) {
          arscBudget.totalEntries += 1;
          if (arscBudget.totalEntries > arscBudget.maxEntries) {
            throw new FormatError(
              `ARSC total materialized entries (${arscBudget.totalEntries}) exceeds maximum (${arscBudget.maxEntries})`,
              { code: ERROR_CODES.E_MALFORMED_ARSC, format: 'arsc', offset: entryPos }
            );
          }
        }
        let cached = entryCache.get(entryPos);
        if (!cached) {
          const parsed = parseEntryAt(buf, view, entryPos, sub.end, keyStrings, globalStrings, arscBudget);
          const shortName = `@${typeName}/${parsed.keyName}`;
          const fullName = `@${name}:${typeName}/${parsed.keyName}`;
          if (arscBudget) {
            arscBudget.totalDerivedNameChars += shortName.length + fullName.length;
            if (arscBudget.totalDerivedNameChars > arscBudget.maxDerivedNameChars) {
              throw new FormatError(
                `ARSC resource name expansion (${arscBudget.totalDerivedNameChars}) exceeds budget (${arscBudget.maxDerivedNameChars})`,
                { code: ERROR_CODES.E_MALFORMED_ARSC, format: 'arsc', offset: entryPos }
              );
            }
          }
          cached = { parsed, shortName, fullName };
          entryCache.set(entryPos, cached);
        }
        const p = cached.parsed;
        const resId = (((pkgId & 0xff) << 24) | ((typeId & 0xff) << 16) | (idx & 0xffff)) >>> 0;
        const record = {
          id: resId,
          packageId: pkgId,
          packageName: name,
          typeId,
          typeName,
          entryIndex: idx,
          flags: p.flags,
          keyIndex: p.keyIndex,
          keyName: p.keyName,
          dataType: p.dataType,
          data: p.data,
          value: p.value,
          bag: p.bag,
        };
        if (p.parentId !== undefined) {
          record.parentId = p.parentId;
        }
        typeEntries.push(record);
        if (!entriesMap.has(resId)) entriesMap.set(resId, record);
        byNameMap.set(cached.shortName, resId);
        byNameMap.set(cached.fullName, resId);
      };

      if (isSparse) {
        // FLAG_SPARSE (0x01): entryCount pairs of (uint16 idx, uint16 off16), real_offset = off16 * 4
        const tableEnd = tableStart + entryCount * 4;
        if (tableEnd > sub.end) {
          throw new FormatError('ResTable_type FLAG_SPARSE offset table exceeds chunk bounds', {
            code: ERROR_CODES.E_MALFORMED_ARSC,
            format: 'arsc',
            offset: tableStart,
          });
        }
        for (let i = 0; i < entryCount; i++) {
          const idx = view.getUint16(tableStart + i * 4, true);
          const off16 = view.getUint16(tableStart + i * 4 + 2, true);
          if (off16 === NO_ENTRY_16) continue;
          addEntryAt(idx, entriesBase + off16 * 4);
        }
      } else if (isOffset16) {
        // FLAG_OFFSET16 (0x02): entryCount uint16 offsets, real_offset = off16 * 4, 0xFFFF == NO_ENTRY
        const tableEnd = tableStart + entryCount * 2;
        if (tableEnd > sub.end) {
          throw new FormatError('ResTable_type FLAG_OFFSET16 offset table exceeds chunk bounds', {
            code: ERROR_CODES.E_MALFORMED_ARSC,
            format: 'arsc',
            offset: tableStart,
          });
        }
        for (let idx = 0; idx < entryCount; idx++) {
          const off16 = view.getUint16(tableStart + idx * 2, true);
          if (off16 === NO_ENTRY_16) continue;
          addEntryAt(idx, entriesBase + off16 * 4);
        }
      } else {
        // Standard 32-bit entry offset table
        const tableEnd = tableStart + entryCount * 4;
        if (tableEnd > sub.end) {
          throw new FormatError('ResTable_type offset table exceeds chunk bounds', {
            code: ERROR_CODES.E_MALFORMED_ARSC,
            format: 'arsc',
            offset: tableStart,
          });
        }
        for (let idx = 0; idx < entryCount; idx++) {
          const off32 = view.getUint32(tableStart + idx * 4, true);
          if (off32 === NO_ENTRY_32) continue;
          addEntryAt(idx, entriesBase + off32);
        }
      }

      types.push({ id: typeId, name: typeName, flags, entryCount, entries: typeEntries });
    }
    // Unknown chunks (RES_TABLE_LIBRARY_TYPE, OVERLAYABLE, STAGED_ALIAS, etc.) are safely skipped via sub.end

    cursor = sub.end;
  }

  return {
    id: pkgId,
    name,
    typeStrings,
    keyStrings,
    typeSpecs,
    types,
  };
}

/**
 * Parses an Android `resources.arsc` binary table (`RES_TABLE_TYPE = 0x0002`).
 */
export function parseResourcesArsc(
  buffer,
  {
    maxInputBytes = MAX_ARSC_BYTES,
    maxEntries = MAX_ARSC_ENTRIES,
    maxPackages = MAX_ARSC_PACKAGES,
    maxChunks = MAX_ARSC_CHUNKS,
  } = {}
) {
  const buf = toBytes(buffer);
  if (buf.byteLength > maxInputBytes) {
    throw new FormatError(
      `ARSC input size (${buf.byteLength} bytes) exceeds maximum (${maxInputBytes} bytes)`,
      { code: ERROR_CODES.E_MALFORMED_ARSC, format: 'arsc', offset: 0 }
    );
  }
  const outer = readChunkHeader(buf, 0, buf.byteLength, {
    errorCode: ERROR_CODES.E_MALFORMED_ARSC,
    format: 'arsc',
  });

  if (outer.type !== RES_CHUNK_TYPES.RES_TABLE_TYPE) {
    throw new FormatError(
      `Expected RES_TABLE_TYPE (0x0002), got 0x${outer.type.toString(16)}`,
      { code: ERROR_CODES.E_MALFORMED_ARSC, format: 'arsc', offset: 0 }
    );
  }
  if (outer.headerSize < 12) {
    throw new FormatError(`ResTable headerSize too small (${outer.headerSize} < 12)`, {
      code: ERROR_CODES.E_MALFORMED_ARSC,
      format: 'arsc',
      offset: 0,
    });
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const packageCount = view.getUint32(8, true);

  let globalStrings = [];
  const packages = [];
  const entries = new Map();
  const byName = new Map();
  const decodedStringBudget = {
    decodedBytes: 0,
    maxDecodedBytes: Math.min(Math.max(buf.byteLength * 4, 64 * 1024), MAX_ARSC_DECODED_STRING_BYTES),
  };
  const stringPoolCache = new Map();
  const getStringPool = (poolOffset, poolLimit) => {
    const cached = stringPoolCache.get(poolOffset);
    if (cached) {
      if (cached.chunk.end > poolLimit) {
        throw new FormatError(
          `ARSC ResStringPool chunk exceeds bounds (${cached.chunk.offset} + ${cached.chunk.size} > ${poolLimit})`,
          { code: ERROR_CODES.E_MALFORMED_ARSC, format: 'arsc', offset: poolOffset }
        );
      }
      return cached;
    }
    const parsed = parseResStringPool(buf, poolOffset, poolLimit, {
      errorCode: ERROR_CODES.E_MALFORMED_ARSC,
      format: 'arsc',
      decodedStringBudget,
    });
    Object.freeze(parsed.strings);
    Object.freeze(parsed);
    stringPoolCache.set(poolOffset, parsed);
    return parsed;
  };
  const arscBudget = {
    totalEntries: 0,
    maxEntries,
    totalPackages: 0,
    maxPackages,
    totalChunks: 0,
    maxChunks,
    totalUniqueBagItems: 0,
    maxUniqueBagItems: Math.min(Math.max(Math.ceil(buf.byteLength / 4), 16384), 262144),
    totalDerivedNameChars: 0,
    maxDerivedNameChars: Math.min(Math.max(buf.byteLength * 8, 2 * 1024 * 1024), 16 * 1024 * 1024),
    decodedStringBudget,
    getStringPool,
  };

  let cursor = outer.headerSize;
  while (cursor < outer.end) {
    arscBudget.totalChunks += 1;
    if (arscBudget.totalChunks > arscBudget.maxChunks) {
      throw new FormatError(
        `ARSC chunk count (${arscBudget.totalChunks}) exceeds maximum (${arscBudget.maxChunks})`,
        { code: ERROR_CODES.E_MALFORMED_ARSC, format: 'arsc', offset: cursor }
      );
    }
    const sub = readChunkHeader(buf, cursor, outer.end, {
      errorCode: ERROR_CODES.E_MALFORMED_ARSC,
      format: 'arsc',
    });

    if (sub.type === RES_CHUNK_TYPES.RES_STRING_POOL_TYPE) {
      globalStrings = getStringPool(sub.offset, sub.end).strings;
    } else if (sub.type === RES_CHUNK_TYPES.RES_TABLE_PACKAGE_TYPE) {
      arscBudget.totalPackages += 1;
      if (arscBudget.totalPackages > arscBudget.maxPackages) {
        throw new FormatError(
          `ARSC package count (${arscBudget.totalPackages}) exceeds maximum (${arscBudget.maxPackages})`,
          { code: ERROR_CODES.E_MALFORMED_ARSC, format: 'arsc', offset: sub.offset }
        );
      }
      packages.push(parsePackageChunk(buf, view, sub, globalStrings, entries, byName, arscBudget));
    }
    // Unknown top-level chunks skipped cleanly via sub.end

    cursor = sub.end;
  }

  const resolve = (idOrRef) => {
    let id = null;
    if (typeof idOrRef === 'number' && Number.isInteger(idOrRef)) {
      id = idOrRef >>> 0;
    } else if (typeof idOrRef === 'string') {
      const trimmed = idOrRef.trim();
      const hexMatch = /^@?(?:0x)?([0-9a-fA-F]{8})$/.exec(trimmed);
      if (hexMatch && (trimmed.startsWith('@0x') || trimmed.startsWith('0x'))) {
        id = Number.parseInt(hexMatch[1], 16) >>> 0;
      } else if (byName.has(trimmed)) {
        id = byName.get(trimmed);
      } else if (!trimmed.startsWith('@') && byName.has(`@${trimmed}`)) {
        id = byName.get(`@${trimmed}`);
      }
    }
    if (id === null) return null;

    // Follow TYPE_REFERENCE chains with cycle protection (max 16 hops)
    let current = entries.get(id) ?? null;
    const seen = new Set([id]);
    for (let hop = 0; hop < 16 && current; hop++) {
      if (
        (current.dataType === RES_VALUE_TYPES.TYPE_REFERENCE ||
          current.dataType === RES_VALUE_TYPES.TYPE_DYNAMIC_REFERENCE) &&
        current.data !== 0 &&
        !seen.has(current.data >>> 0) &&
        entries.has(current.data >>> 0)
      ) {
        const nextId = current.data >>> 0;
        seen.add(nextId);
        current = entries.get(nextId);
      } else {
        break;
      }
    }
    return current;
  };

  const getString = (idOrRef) => {
    const entry = resolve(idOrRef);
    if (!entry) return null;
    if (typeof entry.value === 'string') return entry.value;
    if (entry.value !== null && entry.value !== undefined) return String(entry.value);
    return null;
  };

  const getLayoutPath = (idOrRef) => {
    const entry = resolve(idOrRef);
    if (!entry) return null;
    if (typeof entry.value === 'string' && entry.value.length > 0) return entry.value;
    if (entry.typeName === 'layout' && entry.keyName) {
      return `res/layout/${entry.keyName}.xml`;
    }
    return null;
  };

  const getIdByName = (refName) => {
    if (typeof refName !== 'string') return null;
    const trimmed = refName.trim();
    if (byName.has(trimmed)) return byName.get(trimmed);
    if (!trimmed.startsWith('@') && byName.has(`@${trimmed}`)) return byName.get(`@${trimmed}`);
    return null;
  };

  return {
    packageCount,
    globalStrings,
    packages,
    entries,
    byName,
    resolve,
    getString,
    getLayoutPath,
    getIdByName,
  };
}

/**
 * Encodes a specification into a valid binary `resources.arsc` (`RES_TABLE_TYPE = 0x0002`).
 * Supports standard u32 offsets, `FLAG_OFFSET16`, and `FLAG_SPARSE` per type!
 */
export function encodeResourcesArsc({
  packageId = 0x7f,
  packageName = 'com.omnios.app',
  types = [],
  utf8 = true,
} = {}) {
  const globalStringList = [];
  const globalStringIdx = new Map();
  const internGlobal = (str) => {
    const s = String(str);
    if (globalStringIdx.has(s)) return globalStringIdx.get(s);
    const idx = globalStringList.length;
    globalStringList.push(s);
    globalStringIdx.set(s, idx);
    return idx;
  };

  const keyStringList = [];
  const keyStringIdx = new Map();
  const internKey = (str) => {
    const s = String(str);
    if (keyStringIdx.has(s)) return keyStringIdx.get(s);
    const idx = keyStringList.length;
    keyStringList.push(s);
    keyStringIdx.set(s, idx);
    return idx;
  };

  // Sort types by 1-based id
  const sortedTypes = [...types].sort((a, b) => a.id - b.id);
  const maxTypeId = sortedTypes.reduce((m, t) => Math.max(m, t.id), 0);
  const typeStringList = new Array(maxTypeId).fill('unknown');
  for (const t of sortedTypes) {
    typeStringList[t.id - 1] = t.name;
    for (const e of t.entries ?? []) {
      internKey(e.name);
      const dataType = e.dataType ?? (typeof e.value === 'string' ? RES_VALUE_TYPES.TYPE_STRING : RES_VALUE_TYPES.TYPE_INT_DEC);
      if (dataType === RES_VALUE_TYPES.TYPE_STRING) {
        internGlobal(e.value ?? '');
      }
    }
  }

  const globalPoolBytes = encodeResStringPool(globalStringList, { utf8 });
  const typePoolBytes = encodeResStringPool(typeStringList, { utf8 });
  const keyPoolBytes = encodeResStringPool(keyStringList, { utf8 });

  const typeChunks = [];
  for (const t of sortedTypes) {
    const flags = t.flags ?? 0;
    const isSparse = (flags & ARSC_TYPE_FLAGS.FLAG_SPARSE) !== 0;
    const isOffset16 = (flags & ARSC_TYPE_FLAGS.FLAG_OFFSET16) !== 0;
    const rawEntries = [...(t.entries ?? [])].sort((a, b) => a.id - b.id);
    const maxEntryIdx = rawEntries.reduce((m, e) => Math.max(m, e.id), -1);
    const denseCount = maxEntryIdx + 1;

    // ResTable_typeSpec (0x0202)
    const specSize = 16 + denseCount * 4;
    const specW = new BinaryWriter({ initialCapacity: specSize, littleEndian: true });
    specW.u16le(RES_CHUNK_TYPES.RES_TABLE_TYPE_SPEC_TYPE);
    specW.u16le(16);
    specW.u32le(specSize);
    specW.u8(t.id & 0xff);
    specW.u8(0);
    specW.u16le(0);
    specW.u32le(denseCount);
    for (let i = 0; i < denseCount; i++) specW.u32le(0);
    typeChunks.push(specW.toUint8Array());

    // Build serialized entries payload (each simple entry is 16 bytes -> naturally 4-byte aligned!)
    const entryByIdx = new Map();
    const payloadW = new BinaryWriter({ initialCapacity: Math.max(32, rawEntries.length * 16), littleEndian: true });
    const entryOffsetByIdx = new Map();

    for (const e of rawEntries) {
      payloadW.align(4, 0);
      entryOffsetByIdx.set(e.id, payloadW.length);
      entryByIdx.set(e.id, e);

      const dataType =
        e.dataType ??
        (typeof e.value === 'string'
          ? RES_VALUE_TYPES.TYPE_STRING
          : typeof e.value === 'boolean'
            ? RES_VALUE_TYPES.TYPE_INT_BOOLEAN
            : RES_VALUE_TYPES.TYPE_INT_DEC);

      let dataVal;
      if (dataType === RES_VALUE_TYPES.TYPE_STRING) {
        dataVal = internGlobal(e.value ?? '');
      } else if (dataType === RES_VALUE_TYPES.TYPE_INT_BOOLEAN) {
        dataVal = e.value ? 0xffffffff : 0;
      } else {
        dataVal = (e.data ?? e.value ?? 0) >>> 0;
      }

      // ResTable_entry (8B) + Res_value (8B) = 16B
      payloadW.u16le(8); // size
      payloadW.u16le(e.flags ?? 0);
      payloadW.u32le(internKey(e.name));
      payloadW.u16le(8); // Res_value.size
      payloadW.u8(0);
      payloadW.u8(dataType);
      payloadW.u32le(dataVal >>> 0);
    }
    payloadW.align(4, 0);
    const payloadBytes = payloadW.toUint8Array();

    // ResTable_type header: 20B + 48B ResTable_config = 68B (4-byte aligned)
    const configSize = 48;
    const typeHeaderSize = 20 + configSize;
    const offsetTableW = new BinaryWriter({ initialCapacity: 64, littleEndian: true });
    let headerEntryCount;

    if (isSparse) {
      headerEntryCount = rawEntries.length;
      for (const e of rawEntries) {
        const byteOff = entryOffsetByIdx.get(e.id);
        offsetTableW.u16le(e.id & 0xffff);
        offsetTableW.u16le((byteOff >>> 2) & 0xffff);
      }
    } else if (isOffset16) {
      headerEntryCount = denseCount;
      for (let i = 0; i < denseCount; i++) {
        if (entryOffsetByIdx.has(i)) {
          offsetTableW.u16le((entryOffsetByIdx.get(i) >>> 2) & 0xffff);
        } else {
          offsetTableW.u16le(NO_ENTRY_16);
        }
      }
      offsetTableW.align(4, 0);
    } else {
      headerEntryCount = denseCount;
      for (let i = 0; i < denseCount; i++) {
        if (entryOffsetByIdx.has(i)) {
          offsetTableW.u32le(entryOffsetByIdx.get(i));
        } else {
          offsetTableW.u32le(NO_ENTRY_32);
        }
      }
    }

    const offsetTableBytes = offsetTableW.toUint8Array();
    const entriesStart = typeHeaderSize + offsetTableBytes.byteLength;
    const totalTypeSize = entriesStart + payloadBytes.byteLength;

    const tw = new BinaryWriter({ initialCapacity: totalTypeSize, littleEndian: true });
    tw.u16le(RES_CHUNK_TYPES.RES_TABLE_TYPE_TYPE);
    tw.u16le(typeHeaderSize);
    tw.u32le(totalTypeSize);
    tw.u8(t.id & 0xff);
    tw.u8(flags & 0xff);
    tw.u16le(0);
    tw.u32le(headerEntryCount);
    tw.u32le(entriesStart);
    // ResTable_config (48 bytes: size=48 followed by 44 zero bytes)
    tw.u32le(configSize);
    tw.pad(configSize - 4, 0);
    tw.bytes(offsetTableBytes);
    tw.bytes(payloadBytes);
    typeChunks.push(tw.toUint8Array());
  }

  // ResTable_package (headerSize = 288)
  const pkgHeaderSize = 288;
  const typeStringsOff = pkgHeaderSize;
  const keyStringsOff = pkgHeaderSize + typePoolBytes.byteLength;
  const typeChunksTotal = typeChunks.reduce((sum, c) => sum + c.byteLength, 0);
  const pkgTotalSize = keyStringsOff + keyPoolBytes.byteLength + typeChunksTotal;

  const pkgW = new BinaryWriter({ initialCapacity: pkgTotalSize, littleEndian: true });
  pkgW.u16le(RES_CHUNK_TYPES.RES_TABLE_PACKAGE_TYPE);
  pkgW.u16le(pkgHeaderSize);
  pkgW.u32le(pkgTotalSize);
  pkgW.u32le(packageId & 0xff);

  // uint16 name[128] (256 bytes UTF-16LE NUL-padded)
  for (let i = 0; i < 128; i++) {
    pkgW.u16le(i < packageName.length ? packageName.charCodeAt(i) : 0);
  }
  pkgW.u32le(typeStringsOff);
  pkgW.u32le(typeStringList.length);
  pkgW.u32le(keyStringsOff);
  pkgW.u32le(keyStringList.length);
  pkgW.u32le(0); // typeIdOffset
  pkgW.bytes(typePoolBytes);
  pkgW.bytes(keyPoolBytes);
  for (const tc of typeChunks) {
    pkgW.bytes(tc);
  }
  const pkgBytes = pkgW.toUint8Array();

  // Outer ResTable (headerSize = 12)
  const tableTotalSize = 12 + globalPoolBytes.byteLength + pkgBytes.byteLength;
  const tableW = new BinaryWriter({ initialCapacity: tableTotalSize, littleEndian: true });
  tableW.u16le(RES_CHUNK_TYPES.RES_TABLE_TYPE);
  tableW.u16le(12);
  tableW.u32le(tableTotalSize);
  tableW.u32le(1); // packageCount
  tableW.bytes(globalPoolBytes);
  tableW.bytes(pkgBytes);
  return tableW.toUint8Array();
}
