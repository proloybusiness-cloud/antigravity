/**
 * Pure-JS Binary Utilities, Checksums, LEB128/MUTF-8, PKZIP, Android AXML/ARSC,
 * and Apple bplist00 / XML Plist Builders (Zero External Dependencies).
 *
 * Acyclic Leaf Module: imports ONLY Node 24 built-ins (`node:crypto`, `node:zlib`).
 */

import crypto from 'node:crypto';
import zlib from 'node:zlib';

const textEncoder = new TextEncoder();

// ============================================================================
// 1. BinaryWriter, concatBytes & alignUp
// ============================================================================

export function alignUp(value, alignment) {
  if (typeof value === 'bigint') {
    const a = BigInt(alignment);
    if (a <= 1n) return value;
    const rem = value % a;
    return rem === 0n ? value : value + (a - rem);
  }
  if (alignment <= 1) return value;
  const rem = value % alignment;
  return rem === 0 ? value : value + (alignment - rem);
}

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof BinaryWriter) return input.toUint8Array();
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (Array.isArray(input)) return Uint8Array.from(input);
  if (typeof input === 'string') return textEncoder.encode(input);
  throw new TypeError(`Unsupported byte input type: ${typeof input}`);
}

export function concatBytes(...chunks) {
  const normalized = [];
  let total = 0;
  for (const chunk of chunks) {
    if (chunk === null || chunk === undefined) continue;
    const arr = toBytes(chunk);
    normalized.push(arr);
    total += arr.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const arr of normalized) {
    out.set(arr, off);
    off += arr.length;
  }
  return out;
}

export class BinaryWriter {
  constructor(initialCapacity = 256) {
    this._buf = new Uint8Array(Math.max(16, initialCapacity));
    this._view = new DataView(this._buf.buffer);
    this.pos = 0;
    this.length = 0;
  }

  _ensure(extra) {
    const required = this.pos + extra;
    if (required <= this._buf.length) return;
    let nextCap = this._buf.length * 2;
    while (nextCap < required) nextCap *= 2;
    const next = new Uint8Array(nextCap);
    next.set(this._buf.subarray(0, this.length));
    this._buf = next;
    this._view = new DataView(this._buf.buffer);
  }

  _advance(n) {
    this.pos += n;
    if (this.pos > this.length) this.length = this.pos;
    return this;
  }

  _checkPatchRange(offset, size) {
    if (offset < 0 || offset + size > this.length) {
      throw new RangeError(`Patch offset ${offset}..${offset + size} out of bounds (length=${this.length})`);
    }
  }

  u8(v) {
    this._ensure(1);
    this._view.setUint8(this.pos, v & 0xff);
    return this._advance(1);
  }

  i8(v) {
    this._ensure(1);
    this._view.setInt8(this.pos, v);
    return this._advance(1);
  }

  u16le(v) {
    this._ensure(2);
    this._view.setUint16(this.pos, v & 0xffff, true);
    return this._advance(2);
  }

  i16le(v) {
    this._ensure(2);
    this._view.setInt16(this.pos, v, true);
    return this._advance(2);
  }

  u16be(v) {
    this._ensure(2);
    this._view.setUint16(this.pos, v & 0xffff, false);
    return this._advance(2);
  }

  i16be(v) {
    this._ensure(2);
    this._view.setInt16(this.pos, v, false);
    return this._advance(2);
  }

  u32le(v) {
    this._ensure(4);
    this._view.setUint32(this.pos, v >>> 0, true);
    return this._advance(4);
  }

  i32le(v) {
    this._ensure(4);
    this._view.setInt32(this.pos, v | 0, true);
    return this._advance(4);
  }

  u32be(v) {
    this._ensure(4);
    this._view.setUint32(this.pos, v >>> 0, false);
    return this._advance(4);
  }

  i32be(v) {
    this._ensure(4);
    this._view.setInt32(this.pos, v | 0, false);
    return this._advance(4);
  }

  u64le(v) {
    this._ensure(8);
    this._view.setBigUint64(this.pos, BigInt.asUintN(64, BigInt(v)), true);
    return this._advance(8);
  }

  i64le(v) {
    this._ensure(8);
    this._view.setBigInt64(this.pos, BigInt.asIntN(64, BigInt(v)), true);
    return this._advance(8);
  }

  u64be(v) {
    this._ensure(8);
    this._view.setBigUint64(this.pos, BigInt.asUintN(64, BigInt(v)), false);
    return this._advance(8);
  }

  i64be(v) {
    this._ensure(8);
    this._view.setBigInt64(this.pos, BigInt.asIntN(64, BigInt(v)), false);
    return this._advance(8);
  }

  f32le(v) {
    this._ensure(4);
    this._view.setFloat32(this.pos, v, true);
    return this._advance(4);
  }

  f32be(v) {
    this._ensure(4);
    this._view.setFloat32(this.pos, v, false);
    return this._advance(4);
  }

  f64le(v) {
    this._ensure(8);
    this._view.setFloat64(this.pos, v, true);
    return this._advance(8);
  }

  f64be(v) {
    this._ensure(8);
    this._view.setFloat64(this.pos, v, false);
    return this._advance(8);
  }

  bytes(arr) {
    const src = toBytes(arr);
    if (src.length === 0) return this;
    this._ensure(src.length);
    this._buf.set(src, this.pos);
    return this._advance(src.length);
  }

  zeros(count) {
    if (count <= 0) return this;
    this._ensure(count);
    this._buf.fill(0, this.pos, this.pos + count);
    return this._advance(count);
  }

  ascii(str) {
    this._ensure(str.length);
    for (let i = 0; i < str.length; i++) {
      this._buf[this.pos + i] = str.charCodeAt(i) & 0xff;
    }
    return this._advance(str.length);
  }

  asciiZ(str) {
    return this.ascii(str).u8(0);
  }

  fixedAscii(str, len) {
    this._ensure(len);
    this._buf.fill(0, this.pos, this.pos + len);
    const n = Math.min(str.length, len);
    for (let i = 0; i < n; i++) {
      this._buf[this.pos + i] = str.charCodeAt(i) & 0xff;
    }
    return this._advance(len);
  }

  utf8(str) {
    return this.bytes(textEncoder.encode(str));
  }

  utf8Z(str) {
    return this.utf8(str).u8(0);
  }

  utf16le(str) {
    this._ensure(str.length * 2);
    for (let i = 0; i < str.length; i++) {
      this._view.setUint16(this.pos + i * 2, str.charCodeAt(i), true);
    }
    return this._advance(str.length * 2);
  }

  utf16leZ(str) {
    return this.utf16le(str).u16le(0);
  }

  utf16be(str) {
    this._ensure(str.length * 2);
    for (let i = 0; i < str.length; i++) {
      this._view.setUint16(this.pos + i * 2, str.charCodeAt(i), false);
    }
    return this._advance(str.length * 2);
  }

  fixedUtf16le(str, codeUnits) {
    const byteLen = codeUnits * 2;
    this._ensure(byteLen);
    this._buf.fill(0, this.pos, this.pos + byteLen);
    const n = Math.min(str.length, codeUnits);
    for (let i = 0; i < n; i++) {
      this._view.setUint16(this.pos + i * 2, str.charCodeAt(i), true);
    }
    return this._advance(byteLen);
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

  align(alignment, padByte = 0) {
    if (alignment <= 1) return this;
    const pad = (alignment - (this.pos % alignment)) % alignment;
    if (pad === 0) return this;
    this._ensure(pad);
    this._buf.fill(padByte & 0xff, this.pos, this.pos + pad);
    return this._advance(pad);
  }

  patchU8(off, v) {
    this._checkPatchRange(off, 1);
    this._view.setUint8(off, v & 0xff);
    return this;
  }

  patchU16le(off, v) {
    this._checkPatchRange(off, 2);
    this._view.setUint16(off, v & 0xffff, true);
    return this;
  }

  patchU16be(off, v) {
    this._checkPatchRange(off, 2);
    this._view.setUint16(off, v & 0xffff, false);
    return this;
  }

  patchU32le(off, v) {
    this._checkPatchRange(off, 4);
    this._view.setUint32(off, v >>> 0, true);
    return this;
  }

  patchU32be(off, v) {
    this._checkPatchRange(off, 4);
    this._view.setUint32(off, v >>> 0, false);
    return this;
  }

  patchI32le(off, v) {
    this._checkPatchRange(off, 4);
    this._view.setInt32(off, v | 0, true);
    return this;
  }

  patchU64le(off, v) {
    this._checkPatchRange(off, 8);
    this._view.setBigUint64(off, BigInt.asUintN(64, BigInt(v)), true);
    return this;
  }

  patchU64be(off, v) {
    this._checkPatchRange(off, 8);
    this._view.setBigUint64(off, BigInt.asUintN(64, BigInt(v)), false);
    return this;
  }

  patchBytes(off, arr) {
    const src = toBytes(arr);
    this._checkPatchRange(off, src.length);
    this._buf.set(src, off);
    return this;
  }

  toUint8Array() {
    return this._buf.slice(0, this.length);
  }
}

// ============================================================================
// 2. Checksums & Cryptographic Hashes
// ============================================================================

const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC32_TABLE[i] = c >>> 0;
}

export function crc32(input) {
  const bytes = toBytes(input);
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function adler32(input) {
  const bytes = toBytes(input);
  const MOD = 65521;
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i++) {
    a = (a + bytes[i]) % MOD;
    b = (b + a) % MOD;
  }
  return ((b << 16) | a) >>> 0;
}

export function sha1(input) {
  const digest = crypto.createHash('sha1').update(toBytes(input)).digest();
  return new Uint8Array(digest.buffer, digest.byteOffset, digest.byteLength);
}

export function sha1Hex(input) {
  return crypto.createHash('sha1').update(toBytes(input)).digest('hex');
}

export function sha256(input) {
  const digest = crypto.createHash('sha256').update(toBytes(input)).digest();
  return new Uint8Array(digest.buffer, digest.byteOffset, digest.byteLength);
}

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(toBytes(input)).digest('hex');
}

export function sha256Base64(input) {
  return crypto.createHash('sha256').update(toBytes(input)).digest('base64');
}

// ============================================================================
// 3. LEB128 & MUTF-8 Codecs
// ============================================================================

export function encodeUleb128(value) {
  let val;
  if (typeof value === 'bigint') {
    if (value < 0n) {
      throw new RangeError(`encodeUleb128 requires non-negative value, got ${value}`);
    }
    val = value;
  } else {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw new RangeError(`encodeUleb128 requires non-negative integer, got ${value}`);
    }
    val = BigInt(value);
  }
  const out = [];
  do {
    let byte = Number(val & 0x7fn);
    val >>= 7n;
    if (val !== 0n) byte |= 0x80;
    out.push(byte);
  } while (val !== 0n);
  return Uint8Array.from(out);
}

export function encodeSleb128(value) {
  let val = typeof value === 'bigint' ? value : BigInt(Math.trunc(value));
  const out = [];
  while (true) {
    const byte = Number(val & 0x7fn);
    val >>= 7n;
    const done = (val === 0n && (byte & 0x40) === 0) || (val === -1n && (byte & 0x40) !== 0);
    out.push(done ? byte : (byte | 0x80));
    if (done) break;
  }
  return Uint8Array.from(out);
}

export function encodeUleb128p1(value) {
  return encodeUleb128((value + 1) >>> 0);
}

export function encodeMutf8(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c !== 0 && c <= 0x7f) {
      out.push(c);
    } else if (c <= 0x7ff) {
      out.push(0xc0 | ((c >> 6) & 0x1f));
      out.push(0x80 | (c & 0x3f));
    } else {
      out.push(0xe0 | ((c >> 12) & 0x0f));
      out.push(0x80 | ((c >> 6) & 0x3f));
      out.push(0x80 | (c & 0x3f));
    }
  }
  return Uint8Array.from(out);
}

export function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ============================================================================
// 4. PKZIP Builder (STORE/DEFLATE, Data Descriptor Bit 3, UTF-8 Bit 11, APK v2 Sig Block)
// ============================================================================

export function buildZip(entries = [], options = {}) {
  const {
    apkV2SigBlock = false,
    useDataDescriptor = false,
    utf8Flag = undefined,
    comment = '',
  } = options;

  const w = new BinaryWriter(1024);
  const records = [];

  for (const entry of entries) {
    const nameStr = String(entry.name);
    const nameBytes = textEncoder.encode(nameStr);
    const commentStr = entry.comment ?? '';
    const commentBytes = textEncoder.encode(commentStr);
    const method = entry.method ?? 8;
    const modTime = entry.modTime ?? 0;
    const modDate = entry.modDate ?? 0x5421;
    const entryUtf8 = entry.utf8 ?? utf8Flag ?? /[^\x00-\x7f]/.test(nameStr + commentStr);
    const entryDD = entry.useDataDescriptor ?? useDataDescriptor ?? false;
    const flags = (entryDD ? 0x0008 : 0) | (entryUtf8 ? 0x0800 : 0);

    let rawCrc;
    let uncompSize;
    let compData;

    if (entry.rawCompData) {
      compData = toBytes(entry.rawCompData);
      rawCrc = entry.overrideCrc32 ?? 0;
      uncompSize = entry.overrideUncompSize ?? compData.length;
    } else {
      const rawData = toBytes(entry.data ?? new Uint8Array(0));
      rawCrc = entry.overrideCrc32 ?? crc32(rawData);
      uncompSize = entry.overrideUncompSize ?? rawData.length;
      if (method === 8) {
        const deflated = zlib.deflateRawSync(rawData);
        compData = new Uint8Array(deflated.buffer, deflated.byteOffset, deflated.byteLength);
      } else {
        compData = rawData;
      }
    }

    const compSize = entry.overrideCompSize ?? compData.length;
    const lfhOffset = w.pos;

    let lfhExtra = entry.extra ? toBytes(entry.extra) : new Uint8Array(0);
    const alignDataTo = entry.alignDataTo ?? 0;
    if (alignDataTo > 1 && !entry.extra) {
      const dataPos = lfhOffset + 30 + nameBytes.length;
      const pad = (alignDataTo - (dataPos % alignDataTo)) % alignDataTo;
      if (pad > 0) {
        lfhExtra = new Uint8Array(pad);
      }
    }

    // Local File Header (30 bytes)
    w.u32le(0x04034b50)
      .u16le(20) // version needed to extract
      .u16le(flags)
      .u16le(method)
      .u16le(modTime)
      .u16le(modDate)
      .u32le(entryDD ? 0 : rawCrc)
      .u32le(entryDD ? 0 : compSize)
      .u32le(entryDD ? 0 : uncompSize)
      .u16le(nameBytes.length)
      .u16le(lfhExtra.length)
      .bytes(nameBytes)
      .bytes(lfhExtra)
      .bytes(compData);

    if (entryDD) {
      // 16-byte Data Descriptor
      w.u32le(0x08074b50)
        .u32le(rawCrc)
        .u32le(compSize)
        .u32le(uncompSize);
    }

    const externalAttr = entry.externalAttr ?? (nameStr.endsWith('/') ? 0x41ed0010 : 0x81a40000);
    records.push({
      nameBytes,
      commentBytes,
      method,
      flags,
      modTime,
      modDate,
      rawCrc,
      compSize,
      uncompSize,
      lfhOffset,
      externalAttr,
    });
  }

  // Optional APK Signing Block v2/v3 placed directly before Central Directory
  if (apkV2SigBlock) {
    const pairs = typeof apkV2SigBlock === 'object' && Array.isArray(apkV2SigBlock.pairs)
      ? apkV2SigBlock.pairs
      : [{ id: 0x7109871a, data: textEncoder.encode('OMNIOS_APK_SIG_V2_BLOCK') }];

    const pairsWriter = new BinaryWriter(64);
    for (const pair of pairs) {
      const dataBytes = toBytes(pair.data ?? new Uint8Array(0));
      pairsWriter.u64le(BigInt(4 + dataBytes.length)).u32le(pair.id >>> 0).bytes(dataBytes);
    }
    const pairsBytes = pairsWriter.toUint8Array();
    const blockSize = BigInt(pairsBytes.length + 8 + 16);
    w.u64le(blockSize)
      .bytes(pairsBytes)
      .u64le(blockSize)
      .ascii('APK Sig Block 42');
  }

  const cdOffset = w.pos;
  for (const rec of records) {
    // Central Directory File Header (46 bytes)
    w.u32le(0x02014b50)
      .u16le(0x0314) // version made by: Unix, 2.0
      .u16le(20) // version needed
      .u16le(rec.flags)
      .u16le(rec.method)
      .u16le(rec.modTime)
      .u16le(rec.modDate)
      .u32le(rec.rawCrc)
      .u32le(rec.compSize)
      .u32le(rec.uncompSize)
      .u16le(rec.nameBytes.length)
      .u16le(0) // extra length in CD
      .u16le(rec.commentBytes.length)
      .u16le(0) // disk number start
      .u16le(0) // internal file attributes
      .u32le(rec.externalAttr)
      .u32le(rec.lfhOffset)
      .bytes(rec.nameBytes)
      .bytes(rec.commentBytes);
  }

  const cdSize = w.pos - cdOffset;
  const eocdComment = textEncoder.encode(comment);

  // End of Central Directory (22 bytes)
  w.u32le(0x06054b50)
    .u16le(0)
    .u16le(0)
    .u16le(records.length)
    .u16le(records.length)
    .u32le(cdSize)
    .u32le(cdOffset)
    .u16le(eocdComment.length)
    .bytes(eocdComment);

  return w.toUint8Array();
}

// ============================================================================
// 5. Android Binary XML (AXML) & resources.arsc Builders
// ============================================================================

export function buildResStringPool(strings = [], { utf8 = false } = {}) {
  const encodedOffsets = [];
  const dataWriter = new BinaryWriter(256);

  for (const rawStr of strings) {
    const s = String(rawStr);
    encodedOffsets.push(dataWriter.pos);
    if (utf8) {
      const charLen = s.length;
      if (charLen <= 0x7f) {
        dataWriter.u8(charLen);
      } else {
        dataWriter.u8(0x80 | ((charLen >> 8) & 0x7f)).u8(charLen & 0xff);
      }
      const u8 = textEncoder.encode(s);
      const byteLen = u8.length;
      if (byteLen <= 0x7f) {
        dataWriter.u8(byteLen);
      } else {
        dataWriter.u8(0x80 | ((byteLen >> 8) & 0x7f)).u8(byteLen & 0xff);
      }
      dataWriter.bytes(u8).u8(0);
    } else {
      const charLen = s.length;
      if (charLen <= 0x7fff) {
        dataWriter.u16le(charLen);
      } else {
        dataWriter.u16le(0x8000 | ((charLen >> 16) & 0x7fff)).u16le(charLen & 0xffff);
      }
      dataWriter.utf16le(s).u16le(0);
    }
  }

  const headerSize = 28;
  const stringsStart = headerSize + strings.length * 4;
  const w = new BinaryWriter(stringsStart + dataWriter.length + 4);
  w.u16le(0x0001) // RES_STRING_POOL_TYPE
    .u16le(headerSize)
    .u32le(0) // total size patched below
    .u32le(strings.length)
    .u32le(0) // styleCount
    .u32le(utf8 ? 0x00000100 : 0) // flags: UTF8_FLAG = 1 << 8
    .u32le(strings.length > 0 ? stringsStart : 0)
    .u32le(0); // stylesStart

  for (const off of encodedOffsets) {
    w.u32le(off);
  }
  w.bytes(dataWriter.toUint8Array());
  w.align(4);
  w.patchU32le(4, w.length);
  return w.toUint8Array();
}

const ANDROID_ATTR_RES_IDS = Object.freeze({
  theme: 0x01010000,
  label: 0x01010001,
  icon: 0x01010002,
  name: 0x01010003,
  exported: 0x01010010,
  value: 0x01010024,
  mimeType: 0x01010026,
  scheme: 0x01010027,
  host: 0x01010028,
  pathPrefix: 0x0101002b,
  minSdkVersion: 0x0101020c,
  versionCode: 0x0101021b,
  versionName: 0x0101021c,
  targetSdkVersion: 0x01010270,
});

const ANDROID_NS = 'http://schemas.android.com/apk/res/android';

export function buildAxmlManifest({
  packageName = 'com.omnios.app',
  versionCode = 1,
  versionName = '1.0',
  label = 'OmniApp',
  labelResId = null,
  mainActivity = '.MainActivity',
  permissions = [],
  intentFilters = [],
  minSdkVersion = 26,
  targetSdkVersion = 34,
  utf8Pool = false,
} = {}) {
  // Build declarative XML tree first so all mapped attr names occupy indices 0..resIds.length-1
  const filterNodes = [
    {
      tag: 'intent-filter',
      attrs: [],
      children: [
        { tag: 'action', attrs: [{ ns: ANDROID_NS, name: 'name', type: 0x03, value: 'android.intent.action.MAIN' }], children: [] },
        { tag: 'category', attrs: [{ ns: ANDROID_NS, name: 'name', type: 0x03, value: 'android.intent.category.LAUNCHER' }], children: [] },
      ],
    },
  ];

  for (const filter of intentFilters) {
    const children = [];
    for (const action of filter.actions ?? []) {
      children.push({ tag: 'action', attrs: [{ ns: ANDROID_NS, name: 'name', type: 0x03, value: String(action) }], children: [] });
    }
    for (const category of filter.categories ?? []) {
      children.push({ tag: 'category', attrs: [{ ns: ANDROID_NS, name: 'name', type: 0x03, value: String(category) }], children: [] });
    }
    for (const d of filter.data ?? []) {
      const dataAttrs = [];
      if (d.scheme) dataAttrs.push({ ns: ANDROID_NS, name: 'scheme', type: 0x03, value: String(d.scheme) });
      if (d.host) dataAttrs.push({ ns: ANDROID_NS, name: 'host', type: 0x03, value: String(d.host) });
      if (d.mimeType) dataAttrs.push({ ns: ANDROID_NS, name: 'mimeType', type: 0x03, value: String(d.mimeType) });
      if (d.pathPrefix) dataAttrs.push({ ns: ANDROID_NS, name: 'pathPrefix', type: 0x03, value: String(d.pathPrefix) });
      children.push({ tag: 'data', attrs: dataAttrs, children: [] });
    }
    filterNodes.push({ tag: 'intent-filter', attrs: [], children });
  }

  const root = {
    tag: 'manifest',
    attrs: [
      { ns: null, name: 'package', type: 0x03, value: String(packageName) },
      { ns: ANDROID_NS, name: 'versionCode', type: 0x10, value: Number(versionCode) | 0 },
      { ns: ANDROID_NS, name: 'versionName', type: 0x03, value: String(versionName) },
    ],
    children: [
      {
        tag: 'uses-sdk',
        attrs: [
          { ns: ANDROID_NS, name: 'minSdkVersion', type: 0x10, value: Number(minSdkVersion) | 0 },
          { ns: ANDROID_NS, name: 'targetSdkVersion', type: 0x10, value: Number(targetSdkVersion) | 0 },
        ],
        children: [],
      },
      ...permissions.map((perm) => ({
        tag: 'uses-permission',
        attrs: [{ ns: ANDROID_NS, name: 'name', type: 0x03, value: String(perm) }],
        children: [],
      })),
      {
        tag: 'application',
        attrs: [
          labelResId != null
            ? { ns: ANDROID_NS, name: 'label', type: 0x01, value: labelResId >>> 0 }
            : { ns: ANDROID_NS, name: 'label', type: 0x03, value: String(label) },
        ],
        children: [
          {
            tag: 'activity',
            attrs: [
              { ns: ANDROID_NS, name: 'name', type: 0x03, value: String(mainActivity) },
              { ns: ANDROID_NS, name: 'exported', type: 0x12, value: 0xffffffff },
            ],
            children: filterNodes,
          },
        ],
      },
    ],
  };

  // Pass 1: Collect mapped android:* attribute names first (strict 1:1 with RES_XML_RESOURCE_MAP)
  const usedMappedAttrs = new Set();
  const otherStrings = [];
  function collectNode(node) {
    otherStrings.push(node.tag);
    for (const a of node.attrs) {
      if (a.ns === ANDROID_NS && Object.prototype.hasOwnProperty.call(ANDROID_ATTR_RES_IDS, a.name)) {
        usedMappedAttrs.add(a.name);
      } else {
        otherStrings.push(a.name);
      }
      if (a.type === 0x03) {
        otherStrings.push(String(a.value));
      }
    }
    for (const child of node.children) collectNode(child);
  }
  collectNode(root);

  const stringPool = [];
  const stringMap = new Map();
  const resIds = [];

  function intern(s) {
    if (stringMap.has(s)) return stringMap.get(s);
    const idx = stringPool.length;
    stringPool.push(s);
    stringMap.set(s, idx);
    return idx;
  }

  // Mapped attribute names occupy 0 .. resIds.length - 1
  for (const attrName of usedMappedAttrs) {
    intern(attrName);
    resIds.push(ANDROID_ATTR_RES_IDS[attrName]);
  }

  // Namespace prefix/URI + remaining tags/attr names/values
  const androidPrefixIdx = intern('android');
  const androidNsIdx = intern(ANDROID_NS);
  for (const s of otherStrings) intern(s);

  const w = new BinaryWriter(512);
  // Top-level RES_XML_TYPE (0x0003)
  w.u16le(0x0003).u16le(8).u32le(0);

  // 1. String Pool
  w.bytes(buildResStringPool(stringPool, { utf8: utf8Pool }));

  // 2. Resource Map
  w.u16le(0x0180).u16le(8).u32le(8 + resIds.length * 4);
  for (const id of resIds) w.u32le(id);

  // 3. Start Namespace
  let lineNumber = 1;
  w.u16le(0x0100)
    .u16le(16)
    .u32le(24)
    .u32le(lineNumber++)
    .i32le(-1)
    .u32le(androidPrefixIdx)
    .u32le(androidNsIdx);

  function emitNode(node) {
    const startLine = lineNumber++;
    const nameIdx = intern(node.tag);
    const attrCount = node.attrs.length;
    const chunkSize = 36 + attrCount * 20;

    // RES_XML_START_ELEMENT_TYPE (0x0102)
    w.u16le(0x0102)
      .u16le(16)
      .u32le(chunkSize)
      .u32le(startLine)
      .i32le(-1)
      .i32le(-1) // element namespace
      .u32le(nameIdx)
      .u16le(20) // attributeStart
      .u16le(20) // attributeSize
      .u16le(attrCount)
      .u16le(0) // idIndex
      .u16le(0) // classIndex
      .u16le(0); // styleIndex

    for (const attr of node.attrs) {
      const aNsIdx = attr.ns === ANDROID_NS ? androidNsIdx : -1;
      const aNameIdx = intern(attr.name);
      const rawValIdx = attr.type === 0x03 ? intern(String(attr.value)) : -1;
      const typedData = attr.type === 0x03 ? rawValIdx : (attr.value >>> 0);

      w.i32le(aNsIdx)
        .u32le(aNameIdx)
        .i32le(rawValIdx)
        .u16le(8) // Res_value.size
        .u8(0) // res0
        .u8(attr.type)
        .u32le(typedData);
    }

    for (const child of node.children) emitNode(child);

    // RES_XML_END_ELEMENT_TYPE (0x0103)
    w.u16le(0x0103)
      .u16le(16)
      .u32le(24)
      .u32le(lineNumber++)
      .i32le(-1)
      .i32le(-1)
      .u32le(nameIdx);
  }

  emitNode(root);

  // 4. End Namespace
  w.u16le(0x0101)
    .u16le(16)
    .u32le(24)
    .u32le(lineNumber++)
    .i32le(-1)
    .u32le(androidPrefixIdx)
    .u32le(androidNsIdx);

  w.patchU32le(4, w.length);
  return w.toUint8Array();
}

export function buildResourcesArsc({
  packageId = 0x7f,
  packageName = 'com.omnios.app',
  strings = { app_name: 'OmniApp' },
  mode = 'standard', // 'standard' | 'offset16' | 'sparse'
  sparse = false,
  offset16 = false,
  utf8Pool = false,
} = {}) {
  const useSparse = Boolean(sparse || mode === 'sparse');
  const useOffset16 = !useSparse && Boolean(offset16 || mode === 'offset16');

  let entries;
  if (Array.isArray(strings)) {
    entries = strings
      .map((item, idx) => ({
        id: item.id ?? idx,
        name: String(item.name),
        value: String(item.value),
      }))
      .sort((a, b) => a.id - b.id);
  } else {
    entries = Object.entries(strings).map(([name, value], idx) => ({
      id: idx,
      name: String(name),
      value: String(value),
    }));
  }

  const globalValuePool = buildResStringPool(entries.map((e) => e.value), { utf8: utf8Pool });
  const typePool = buildResStringPool(['string'], { utf8: utf8Pool });
  const keyPool = buildResStringPool(entries.map((e) => e.name), { utf8: utf8Pool });

  const maxSlots = entries.length === 0 ? 0 : (entries[entries.length - 1].id + 1);

  // Build ResTable_typeSpec (0x0202)
  const typeSpec = new BinaryWriter(16 + maxSlots * 4);
  typeSpec
    .u16le(0x0202)
    .u16le(16)
    .u32le(16 + maxSlots * 4)
    .u8(1) // type id = 1 ("string")
    .u8(0) // res0
    .u16le(0) // res1
    .u32le(maxSlots);
  for (let i = 0; i < maxSlots; i++) typeSpec.u32le(0);

  // Build entry payloads (16 bytes each: 8B ResTable_entry + 8B Res_value)
  const entryById = new Map();
  const payloadWriter = new BinaryWriter(entries.length * 16);
  for (let i = 0; i < entries.length; i++) {
    const byteOffset = i * 16;
    entryById.set(entries[i].id, { index: i, byteOffset });
    payloadWriter
      .u16le(8) // ResTable_entry.size
      .u16le(0) // flags (simple entry)
      .u32le(i) // key string pool index
      .u16le(8) // Res_value.size
      .u8(0) // res0
      .u8(0x03) // TYPE_STRING
      .u32le(i); // global string pool index
  }
  const entryPayloads = payloadWriter.toUint8Array();

  // Build ResTable_type (0x0201)
  const typeHeaderSize = 84; // 20B fixed + 64B ResTable_config
  const offsetsWriter = new BinaryWriter(maxSlots * 4 + 4);
  let flags = 0x00;
  let typeEntryCount = maxSlots;

  if (useSparse) {
    flags = 0x01; // FLAG_SPARSE
    typeEntryCount = entries.length;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      offsetsWriter.u16le(e.id).u16le((i * 16) >>> 2);
    }
  } else if (useOffset16) {
    flags = 0x02; // FLAG_OFFSET16
    typeEntryCount = maxSlots;
    for (let slot = 0; slot < maxSlots; slot++) {
      const hit = entryById.get(slot);
      offsetsWriter.u16le(hit ? (hit.byteOffset >>> 2) : 0xffff);
    }
    offsetsWriter.align(4);
  } else {
    flags = 0x00;
    typeEntryCount = maxSlots;
    for (let slot = 0; slot < maxSlots; slot++) {
      const hit = entryById.get(slot);
      offsetsWriter.u32le(hit ? hit.byteOffset : 0xffffffff);
    }
  }

  const offsetBytes = offsetsWriter.toUint8Array();
  const entriesStart = typeHeaderSize + offsetBytes.length;
  const typeChunk = new BinaryWriter(entriesStart + entryPayloads.length);
  typeChunk
    .u16le(0x0201)
    .u16le(typeHeaderSize)
    .u32le(entriesStart + entryPayloads.length)
    .u8(1) // id = 1
    .u8(flags)
    .u16le(0) // reserved
    .u32le(typeEntryCount)
    .u32le(entriesStart)
    .u32le(64) // ResTable_config.size
    .zeros(60)
    .bytes(offsetBytes)
    .bytes(entryPayloads);

  // Build ResTable_package (0x0200, headerSize = 288)
  const pkgHeaderSize = 288;
  const pkgBody = concatBytes(typePool, keyPool, typeSpec, typeChunk);
  const pkgChunk = new BinaryWriter(pkgHeaderSize + pkgBody.length);
  pkgChunk
    .u16le(0x0200)
    .u16le(pkgHeaderSize)
    .u32le(pkgHeaderSize + pkgBody.length)
    .u32le(packageId >>> 0)
    .fixedUtf16le(packageName, 128)
    .u32le(pkgHeaderSize) // typeStrings offset
    .u32le(1) // lastPublicType
    .u32le(pkgHeaderSize + typePool.length) // keyStrings offset
    .u32le(entries.length) // lastPublicKey
    .u32le(0) // typeIdOffset
    .bytes(pkgBody);

  // Wrap in ResTable_header (0x0002, headerSize = 12)
  const totalSize = 12 + globalValuePool.length + pkgChunk.length;
  const table = new BinaryWriter(totalSize);
  table
    .u16le(0x0002)
    .u16le(12)
    .u32le(totalSize)
    .u32le(1) // packageCount
    .bytes(globalValuePool)
    .bytes(pkgChunk.toUint8Array());

  return table.toUint8Array();
}

// ============================================================================
// 6. Apple Binary Plist (bplist00) & XML 1.0 Plist Builders
// ============================================================================

const CF_EPOCH_MS = Date.UTC(2001, 0, 1, 0, 0, 0, 0); // 978307200000

export function plistFloat(value) {
  return { __plistType: 'float', value: Number(value) };
}

function isPlistFloat(val) {
  return val !== null && typeof val === 'object' && val.__plistType === 'float';
}

function countToByteSize(count) {
  if (count < 0x100) return 1;
  if (count < 0x10000) return 2;
  if (count < 0x100000000) return 4;
  return 8;
}

function writeUintBe(w, size, value) {
  if (size === 1) w.u8(value);
  else if (size === 2) w.u16be(value);
  else if (size === 4) w.u32be(value);
  else w.u64be(BigInt(value));
}

function writeBplistMarkerAndSize(w, highNibble, length) {
  if (length < 15) {
    w.u8(highNibble | length);
  } else if (length < 0x100) {
    w.u8(highNibble | 0x0f).u8(0x10).u8(length);
  } else if (length < 0x10000) {
    w.u8(highNibble | 0x0f).u8(0x11).u16be(length);
  } else {
    w.u8(highNibble | 0x0f).u8(0x12).u32be(length);
  }
}

export function buildBinaryPlist(rootObj, { sortKeys = true } = {}) {
  const objects = [];
  const scalarDedup = new Map();
  const activeContainers = new Set();

  function flatten(val) {
    if (val === null || val === undefined) {
      const k = 'null';
      if (scalarDedup.has(k)) return scalarDedup.get(k);
      const idx = objects.length;
      objects.push({ kind: 'null' });
      scalarDedup.set(k, idx);
      return idx;
    }

    if (typeof val === 'boolean') {
      const k = `bool:${val}`;
      if (scalarDedup.has(k)) return scalarDedup.get(k);
      const idx = objects.length;
      objects.push({ kind: 'bool', value: val });
      scalarDedup.set(k, idx);
      return idx;
    }

    if (isPlistFloat(val)) {
      const num = Number(val.value);
      const k = `float:${Object.is(num, -0) ? '-0' : String(num)}`;
      if (scalarDedup.has(k)) return scalarDedup.get(k);
      const idx = objects.length;
      objects.push({ kind: 'float', value: num });
      scalarDedup.set(k, idx);
      return idx;
    }

    if (typeof val === 'bigint') {
      const k = `int:${val.toString()}`;
      if (scalarDedup.has(k)) return scalarDedup.get(k);
      const idx = objects.length;
      objects.push({ kind: 'int', value: val });
      scalarDedup.set(k, idx);
      return idx;
    }

    if (typeof val === 'number') {
      if (Number.isInteger(val) && Number.isSafeInteger(val) && !Object.is(val, -0)) {
        const bi = BigInt(val);
        const k = `int:${bi.toString()}`;
        if (scalarDedup.has(k)) return scalarDedup.get(k);
        const idx = objects.length;
        objects.push({ kind: 'int', value: bi });
        scalarDedup.set(k, idx);
        return idx;
      }
      const k = `float:${Object.is(val, -0) ? '-0' : String(val)}`;
      if (scalarDedup.has(k)) return scalarDedup.get(k);
      const idx = objects.length;
      objects.push({ kind: 'float', value: val });
      scalarDedup.set(k, idx);
      return idx;
    }

    if (typeof val === 'string') {
      const k = `str:${val}`;
      if (scalarDedup.has(k)) return scalarDedup.get(k);
      const idx = objects.length;
      objects.push({ kind: 'string', value: val });
      scalarDedup.set(k, idx);
      return idx;
    }

    if (val instanceof Date) {
      const ms = val.getTime();
      const k = `date:${ms}`;
      if (scalarDedup.has(k)) return scalarDedup.get(k);
      const idx = objects.length;
      objects.push({ kind: 'date', value: val });
      scalarDedup.set(k, idx);
      return idx;
    }

    if (val instanceof Uint8Array || Buffer.isBuffer(val)) {
      const idx = objects.length;
      objects.push({ kind: 'data', value: toBytes(val) });
      return idx;
    }

    if (Array.isArray(val)) {
      if (activeContainers.has(val)) {
        throw new Error('Cycle detected while encoding bplist00 array');
      }
      activeContainers.add(val);
      const idx = objects.length;
      const entry = { kind: 'array', refs: [] };
      objects.push(entry);
      for (const item of val) {
        entry.refs.push(flatten(item));
      }
      activeContainers.delete(val);
      return idx;
    }

    if (typeof val === 'object') {
      if (activeContainers.has(val)) {
        throw new Error('Cycle detected while encoding bplist00 dict');
      }
      activeContainers.add(val);
      const idx = objects.length;
      const entry = { kind: 'dict', keyRefs: [], valRefs: [] };
      objects.push(entry);
      const keys = Object.keys(val);
      if (sortKeys) keys.sort();
      for (const k of keys) {
        entry.keyRefs.push(flatten(k));
      }
      for (const k of keys) {
        entry.valRefs.push(flatten(val[k]));
      }
      activeContainers.delete(val);
      return idx;
    }

    throw new TypeError(`Unsupported bplist00 value type: ${typeof val}`);
  }

  flatten(rootObj);

  const objectRefSize = countToByteSize(objects.length);
  const w = new BinaryWriter(256);
  w.ascii('bplist00');

  const offsets = new Array(objects.length);

  for (let i = 0; i < objects.length; i++) {
    offsets[i] = w.pos;
    const obj = objects[i];

    switch (obj.kind) {
      case 'null':
        w.u8(0x00);
        break;
      case 'bool':
        w.u8(obj.value ? 0x09 : 0x08);
        break;
      case 'int': {
        const v = obj.value;
        if (v < 0n) {
          // Negative integers MUST be encoded as 8-byte signed BE (marker 0x13)
          w.u8(0x13).i64be(v);
        } else if (v < 0x100n) {
          w.u8(0x10).u8(Number(v));
        } else if (v < 0x10000n) {
          w.u8(0x11).u16be(Number(v));
        } else if (v < 0x100000000n) {
          w.u8(0x12).u32be(Number(v));
        } else if (v < (1n << 63n)) {
          w.u8(0x13).u64be(v);
        } else {
          w.u8(0x14).u64be(0n).u64be(v);
        }
        break;
      }
      case 'float':
        w.u8(0x23).f64be(obj.value);
        break;
      case 'date':
        w.u8(0x33).f64be((obj.value.getTime() - CF_EPOCH_MS) / 1000);
        break;
      case 'data':
        writeBplistMarkerAndSize(w, 0x40, obj.value.length);
        w.bytes(obj.value);
        break;
      case 'string': {
        const s = obj.value;
        if (!/[^\x00-\x7f]/.test(s)) {
          writeBplistMarkerAndSize(w, 0x50, s.length);
          w.ascii(s);
        } else {
          // UTF-16BE string length count is UTF-16 code units (s.length), NOT byte length!
          writeBplistMarkerAndSize(w, 0x60, s.length);
          w.utf16be(s);
        }
        break;
      }
      case 'array':
        writeBplistMarkerAndSize(w, 0xa0, obj.refs.length);
        for (const ref of obj.refs) writeUintBe(w, objectRefSize, ref);
        break;
      case 'dict':
        writeBplistMarkerAndSize(w, 0xd0, obj.keyRefs.length);
        for (const ref of obj.keyRefs) writeUintBe(w, objectRefSize, ref);
        for (const ref of obj.valRefs) writeUintBe(w, objectRefSize, ref);
        break;
      default:
        throw new Error(`Unknown bplist object kind: ${obj.kind}`);
    }
  }

  const offsetTableOffset = w.pos;
  const offsetIntSize = countToByteSize(offsetTableOffset);
  for (const off of offsets) {
    writeUintBe(w, offsetIntSize, off);
  }

  // Exact 32-byte BE Trailer (>5xBBBQQQ)
  w.zeros(5)
    .u8(0) // sortVersion
    .u8(offsetIntSize)
    .u8(objectRefSize)
    .u64be(BigInt(objects.length))
    .u64be(0n) // topObject = 0
    .u64be(BigInt(offsetTableOffset));

  return w.toUint8Array();
}

export function buildXmlPlist(rootObj, { sortKeys = true } = {}) {
  function render(val, indent) {
    const pad = '  '.repeat(indent);
    if (val === null || val === undefined) {
      return `${pad}<string></string>`;
    }
    if (typeof val === 'boolean') {
      return `${pad}${val ? '<true/>' : '<false/>'}`;
    }
    if (isPlistFloat(val)) {
      return `${pad}<real>${Number(val.value)}</real>`;
    }
    if (typeof val === 'bigint') {
      return `${pad}<integer>${val.toString()}</integer>`;
    }
    if (typeof val === 'number') {
      if (Number.isInteger(val) && Number.isSafeInteger(val) && !Object.is(val, -0)) {
        return `${pad}<integer>${val}</integer>`;
      }
      return `${pad}<real>${val}</real>`;
    }
    if (typeof val === 'string') {
      return `${pad}<string>${escapeXml(val)}</string>`;
    }
    if (val instanceof Date) {
      const isoNoMs = val.toISOString().replace(/\.\d{3}Z$/, 'Z');
      return `${pad}<date>${isoNoMs}</date>`;
    }
    if (val instanceof Uint8Array || Buffer.isBuffer(val)) {
      const b64 = Buffer.from(toBytes(val)).toString('base64');
      return `${pad}<data>${b64}</data>`;
    }
    if (Array.isArray(val)) {
      if (val.length === 0) return `${pad}<array/>`;
      const inner = val.map((item) => render(item, indent + 1)).join('\n');
      return `${pad}<array>\n${inner}\n${pad}</array>`;
    }
    if (typeof val === 'object') {
      const keys = Object.keys(val);
      if (sortKeys) keys.sort();
      if (keys.length === 0) return `${pad}<dict/>`;
      const inner = keys
        .map((k) => `${'  '.repeat(indent + 1)}<key>${escapeXml(k)}</key>\n${render(val[k], indent + 1)}`)
        .join('\n');
      return `${pad}<dict>\n${inner}\n${pad}</dict>`;
    }
    throw new TypeError(`Unsupported XML plist value type: ${typeof val}`);
  }

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    render(rootObj, 0),
    '</plist>',
    '',
  ].join('\n');
}
