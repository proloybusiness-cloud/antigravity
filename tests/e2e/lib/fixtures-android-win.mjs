/**
 * Dynamic, Standards-Compliant Android (.apk / DEX / AXML / ARSC) and Windows
 * (PE32+ / PE32 .exe, .msix, .msi OLE CFBF, .bat / .cmd) Binary Fixture Builders.
 *
 * Acyclic Dependency: imports ONLY Node 24 built-ins + `./binary-utils.mjs`.
 * Zero hardcoded app outputs — every fixture accepts runtime nonces, operands,
 * paths, Registry/SharedPrefs keys, and window titles.
 */

import {
  BinaryWriter,
  alignUp,
  concatBytes,
  adler32,
  sha1,
  sha256Base64,
  encodeUleb128,
  encodeSleb128,
  encodeMutf8,
  escapeXml,
  buildZip,
  buildAxmlManifest,
  buildResourcesArsc,
} from './binary-utils.mjs';

const textEncoder = new TextEncoder();

// ============================================================================
// 1. Dalvik Bytecode Encoders & Canonical Two-Pass DEX Assembler
// ============================================================================

export const DALVIK = Object.freeze({
  OP_ADD_INT: 0x90,
  OP_SUB_INT: 0x91,
  OP_MUL_INT: 0x92,
  OP_DIV_INT: 0x93,
  OP_REM_INT: 0x94,
  OP_INVOKE_VIRTUAL: 0x6e,
  OP_INVOKE_SUPER: 0x6f,
  OP_INVOKE_DIRECT: 0x70,
  OP_INVOKE_STATIC: 0x71,
  OP_INVOKE_INTERFACE: 0x72,

  nop: () => [0x0000],
  returnVoid: () => [0x000e],
  returnReg: (vAA) => [(((vAA & 0xff) << 8) | 0x0f) & 0xffff],
  returnObj: (vAA) => [(((vAA & 0xff) << 8) | 0x11) & 0xffff],
  moveResult: (vAA) => [(((vAA & 0xff) << 8) | 0x0a) & 0xffff],
  moveResultObj: (vAA) => [(((vAA & 0xff) << 8) | 0x0c) & 0xffff],
  moveException: (vAA) => [(((vAA & 0xff) << 8) | 0x0d) & 0xffff],
  const4: (vA, s4) => [((((s4 & 0x0f) << 12) | ((vA & 0x0f) << 8) | 0x12) & 0xffff)],
  const16: (vAA, s16) => [(((vAA & 0xff) << 8) | 0x13) & 0xffff, s16 & 0xffff],
  const32: (vAA, i32) => [
    (((vAA & 0xff) << 8) | 0x14) & 0xffff,
    i32 & 0xffff,
    (i32 >>> 16) & 0xffff,
  ],
  constHigh16: (vAA, hi16) => [(((vAA & 0xff) << 8) | 0x15) & 0xffff, hi16 & 0xffff],
  constString: (vAA, strIdx) => [(((vAA & 0xff) << 8) | 0x1a) & 0xffff, strIdx & 0xffff],
  newInstance: (vAA, typeIdx) => [(((vAA & 0xff) << 8) | 0x22) & 0xffff, typeIdx & 0xffff],
  goto8: (rel8) => [(((rel8 & 0xff) << 8) | 0x28) & 0xffff],
  binop: (op, vAA, vBB, vCC) => [
    (((vAA & 0xff) << 8) | (op & 0xff)) & 0xffff,
    (((vCC & 0xff) << 8) | (vBB & 0xff)) & 0xffff,
  ],
  invoke35c: (op, regs, methodIdx) => {
    if (regs.length > 5) throw new RangeError(`invoke35c supports at most 5 registers, got ${regs.length}`);
    const a = regs.length & 0x0f;
    const c = (regs[0] ?? 0) & 0x0f;
    const d = (regs[1] ?? 0) & 0x0f;
    const e = (regs[2] ?? 0) & 0x0f;
    const f = (regs[3] ?? 0) & 0x0f;
    const g = (regs[4] ?? 0) & 0x0f;
    return [
      (((a << 12) | (g << 8) | (op & 0xff)) & 0xffff),
      methodIdx & 0xffff,
      (((f << 12) | (e << 8) | (d << 4) | c) & 0xffff),
    ];
  },
});

function compareUtf16(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const diff = a.charCodeAt(i) - b.charCodeAt(i);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

function shortyChar(typeDesc) {
  if (!typeDesc) return 'V';
  const ch = typeDesc[0];
  if (ch === 'L' || ch === '[') return 'L';
  return ch;
}

function protoKey(returnType, params) {
  return `${returnType}|${params.join(',')}`;
}

function fieldKey(cls, name, type) {
  return `${cls}|${name}|${type}`;
}

function methodKey(cls, name, returnType, params) {
  return `${cls}|${name}|${protoKey(returnType, params)}`;
}

/**
 * Canonical two-pass DEX assembler (versions 035..041) with strict UTF-16/index sorting,
 * 4-byte alignment, odd-insns_size try_item padding, map_list, SHA-1, and Adler-32.
 */
export function buildDex({ dexVersion = '035', classes = [], extraStrings = [] } = {}) {
  const stringSet = new Set();
  const typeSet = new Set();
  const protoMap = new Map();
  const fieldMap = new Map();
  const methodMap = new Map();

  function addString(s) {
    stringSet.add(String(s));
    return 0;
  }

  function addType(t) {
    const ts = String(t);
    addString(ts);
    typeSet.add(ts);
    return 0;
  }

  function addProto(ret, params = []) {
    const retStr = String(ret);
    const paramList = params.map(String);
    addType(retStr);
    for (const p of paramList) addType(p);
    const shorty = shortyChar(retStr) + paramList.map(shortyChar).join('');
    addString(shorty);
    const key = protoKey(retStr, paramList);
    if (!protoMap.has(key)) {
      protoMap.set(key, { key, shorty, returnType: retStr, params: paramList });
    }
    return 0;
  }

  function addField(cls, name, type) {
    const c = String(cls);
    const n = String(name);
    const t = String(type);
    addType(c);
    addString(n);
    addType(t);
    const key = fieldKey(c, n, t);
    if (!fieldMap.has(key)) {
      fieldMap.set(key, { key, cls: c, name: n, type: t });
    }
    return 0;
  }

  function addMethod(cls, name, ret, params = []) {
    const c = String(cls);
    const n = String(name);
    const r = String(ret);
    const p = params.map(String);
    addType(c);
    addString(n);
    addProto(r, p);
    const key = methodKey(c, n, r, p);
    if (!methodMap.has(key)) {
      methodMap.set(key, { key, cls: c, name: n, returnType: r, params: p });
    }
    return 0;
  }

  for (const s of extraStrings) addString(s);

  const collectCtx = {
    str: addString,
    type: addType,
    proto: addProto,
    field: addField,
    method: addMethod,
    DALVIK,
  };

  // Pass 1: collect all symbolic references from class definitions and method builders
  for (const cls of classes) {
    addType(cls.descriptor);
    if (cls.superclass) addType(cls.superclass);
    if (cls.sourceFile) addString(cls.sourceFile);
    for (const f of [...(cls.staticFields ?? []), ...(cls.instanceFields ?? [])]) {
      addField(cls.descriptor, f.name, f.type);
    }
    for (const m of [...(cls.directMethods ?? []), ...(cls.virtualMethods ?? [])]) {
      addMethod(cls.descriptor, m.name, m.returnType ?? 'V', m.params ?? []);
      let tries = m.tries ?? [];
      if (typeof m.buildInsns === 'function') {
        const res = m.buildInsns(collectCtx);
        if (!Array.isArray(res) && res?.tries) {
          tries = res.tries;
        }
      }
      for (const tr of tries) {
        for (const h of tr.handlers ?? []) {
          if (h.type) addType(h.type);
        }
      }
    }
  }

  // Pass 2: Canonical DEX table sorting
  const strings = Array.from(stringSet).sort(compareUtf16);
  const strIndex = new Map(strings.map((s, i) => [s, i]));

  const types = Array.from(typeSet).sort((a, b) => strIndex.get(a) - strIndex.get(b));
  const typeIndex = new Map(types.map((t, i) => [t, i]));

  const protos = Array.from(protoMap.values()).sort((a, b) => {
    const retDiff = typeIndex.get(a.returnType) - typeIndex.get(b.returnType);
    if (retDiff !== 0) return retDiff;
    const minLen = Math.min(a.params.length, b.params.length);
    for (let i = 0; i < minLen; i++) {
      const pDiff = typeIndex.get(a.params[i]) - typeIndex.get(b.params[i]);
      if (pDiff !== 0) return pDiff;
    }
    return a.params.length - b.params.length;
  });
  const protoIndex = new Map(protos.map((p, i) => [p.key, i]));

  // DEX spec: field_ids sorted by (class_idx, name_idx, type_idx) — name_idx BEFORE type_idx!
  const fields = Array.from(fieldMap.values()).sort((a, b) => {
    return (
      (typeIndex.get(a.cls) - typeIndex.get(b.cls)) ||
      (strIndex.get(a.name) - strIndex.get(b.name)) ||
      (typeIndex.get(a.type) - typeIndex.get(b.type))
    );
  });
  const fieldIndex = new Map(fields.map((f, i) => [f.key, i]));

  // DEX spec: method_ids sorted by (class_idx, name_idx, proto_idx) — name_idx BEFORE proto_idx!
  const methods = Array.from(methodMap.values()).sort((a, b) => {
    return (
      (typeIndex.get(a.cls) - typeIndex.get(b.cls)) ||
      (strIndex.get(a.name) - strIndex.get(b.name)) ||
      (protoIndex.get(protoKey(a.returnType, a.params)) - protoIndex.get(protoKey(b.returnType, b.params)))
    );
  });
  const methodIndex = new Map(methods.map((m, i) => [m.key, i]));

  const resolveCtx = {
    str: (s) => strIndex.get(String(s)),
    type: (t) => typeIndex.get(String(t)),
    proto: (ret, params = []) => protoIndex.get(protoKey(String(ret), params.map(String))),
    field: (cls, name, type) => fieldIndex.get(fieldKey(String(cls), String(name), String(type))),
    method: (cls, name, ret, params = []) =>
      methodIndex.get(methodKey(String(cls), String(name), String(ret), params.map(String))),
    DALVIK,
  };

  // Resolve final method code units & try blocks
  const resolvedClasses = classes.map((cls) => {
    const resolveMethod = (m) => {
      const mIdx = resolveCtx.method(cls.descriptor, m.name, m.returnType ?? 'V', m.params ?? []);
      let codeUnits = m.codeUnits ?? null;
      let tries = m.tries ?? [];
      if (typeof m.buildInsns === 'function') {
        const res = m.buildInsns(resolveCtx);
        if (Array.isArray(res)) {
          codeUnits = res;
        } else {
          codeUnits = res.codeUnits;
          tries = res.tries ?? tries;
        }
      }
      return {
        methodIdx: mIdx,
        accessFlags: m.accessFlags ?? 0x0001,
        registersSize: m.registersSize ?? 4,
        insSize: m.insSize ?? 1,
        outsSize: m.outsSize ?? 2,
        codeUnits,
        tries,
      };
    };

    const resolveField = (f) => ({
      fieldIdx: resolveCtx.field(cls.descriptor, f.name, f.type),
      accessFlags: f.accessFlags ?? 0x0001,
    });

    return {
      descriptor: cls.descriptor,
      classIdx: typeIndex.get(cls.descriptor),
      accessFlags: cls.accessFlags ?? 0x0001,
      superclassIdx: cls.superclass ? typeIndex.get(cls.superclass) : 0xffffffff,
      sourceFileIdx: cls.sourceFile ? strIndex.get(cls.sourceFile) : 0xffffffff,
      staticFields: (cls.staticFields ?? []).map(resolveField).sort((a, b) => a.fieldIdx - b.fieldIdx),
      instanceFields: (cls.instanceFields ?? []).map(resolveField).sort((a, b) => a.fieldIdx - b.fieldIdx),
      directMethods: (cls.directMethods ?? []).map(resolveMethod).sort((a, b) => a.methodIdx - b.methodIdx),
      virtualMethods: (cls.virtualMethods ?? []).map(resolveMethod).sort((a, b) => a.methodIdx - b.methodIdx),
    };
  });

  // Pass 3: Binary layout
  const isV041 = String(dexVersion) === '041';
  const headerSize = isV041 ? 0x78 : 0x70;
  const w = new BinaryWriter(2048);

  // Reserve header
  w.zeros(headerSize);

  const mapItems = [{ type: 0x0000, size: 1, offset: 0 }];

  const stringIdsOff = strings.length > 0 ? w.pos : 0;
  if (strings.length > 0) {
    mapItems.push({ type: 0x0001, size: strings.length, offset: stringIdsOff });
    w.zeros(strings.length * 4);
  }

  const typeIdsOff = types.length > 0 ? w.pos : 0;
  if (types.length > 0) {
    mapItems.push({ type: 0x0002, size: types.length, offset: typeIdsOff });
    for (const t of types) w.u32le(strIndex.get(t));
  }

  const protoIdsOff = protos.length > 0 ? w.pos : 0;
  if (protos.length > 0) {
    mapItems.push({ type: 0x0003, size: protos.length, offset: protoIdsOff });
    for (const p of protos) {
      w.u32le(strIndex.get(p.shorty))
        .u32le(typeIndex.get(p.returnType))
        .u32le(0); // parameters_off patched below
    }
  }

  const fieldIdsOff = fields.length > 0 ? w.pos : 0;
  if (fields.length > 0) {
    mapItems.push({ type: 0x0004, size: fields.length, offset: fieldIdsOff });
    for (const f of fields) {
      w.u16le(typeIndex.get(f.cls))
        .u16le(typeIndex.get(f.type))
        .u32le(strIndex.get(f.name));
    }
  }

  const methodIdsOff = methods.length > 0 ? w.pos : 0;
  if (methods.length > 0) {
    mapItems.push({ type: 0x0005, size: methods.length, offset: methodIdsOff });
    for (const m of methods) {
      w.u16le(typeIndex.get(m.cls))
        .u16le(protoIndex.get(protoKey(m.returnType, m.params)))
        .u32le(strIndex.get(m.name));
    }
  }

  const classDefsOff = resolvedClasses.length > 0 ? w.pos : 0;
  if (resolvedClasses.length > 0) {
    mapItems.push({ type: 0x0006, size: resolvedClasses.length, offset: classDefsOff });
    for (const c of resolvedClasses) {
      w.u32le(c.classIdx)
        .u32le(c.accessFlags)
        .u32le(c.superclassIdx)
        .u32le(0) // interfaces_off
        .u32le(c.sourceFileIdx)
        .u32le(0) // annotations_off
        .u32le(0) // class_data_off patched below
        .u32le(0); // static_values_off
    }
  }

  const dataOff = w.pos;

  // 3a. type_list (0x1001, 4-byte aligned)
  const typeListOffsets = new Map();
  let typeListFirstOff = 0;
  let typeListCount = 0;
  for (let i = 0; i < protos.length; i++) {
    const p = protos[i];
    if (p.params.length === 0) continue;
    const pKey = p.params.join(',');
    let off = typeListOffsets.get(pKey);
    if (off === undefined) {
      w.align(4);
      off = w.pos;
      if (typeListCount === 0) typeListFirstOff = off;
      typeListCount++;
      w.u32le(p.params.length);
      for (const paramType of p.params) {
        w.u16le(typeIndex.get(paramType));
      }
      w.align(4);
      typeListOffsets.set(pKey, off);
    }
    w.patchU32le(protoIdsOff + i * 12 + 8, off);
  }
  if (typeListCount > 0) {
    mapItems.push({ type: 0x1001, size: typeListCount, offset: typeListFirstOff });
  }

  // 3b. code_item (0x2001, 4-byte aligned)
  let codeItemFirstOff = 0;
  let codeItemCount = 0;
  for (const c of resolvedClasses) {
    for (const m of [...c.directMethods, ...c.virtualMethods]) {
      if (!m.codeUnits) {
        m.codeOff = 0;
        continue;
      }
      w.align(4);
      const off = w.pos;
      if (codeItemCount === 0) codeItemFirstOff = off;
      codeItemCount++;
      m.codeOff = off;

      const tries = m.tries ?? [];
      w.u16le(m.registersSize)
        .u16le(m.insSize)
        .u16le(m.outsSize)
        .u16le(tries.length)
        .u32le(0) // debug_info_off
        .u32le(m.codeUnits.length);

      for (const cu of m.codeUnits) {
        w.u16le(cu);
      }

      if (tries.length > 0) {
        // Edge Case #9: 2-byte zero pad required when tries_size > 0 && insns_size is odd
        if ((m.codeUnits.length & 1) === 1) {
          w.u16le(0);
        }

        const handlerList = new BinaryWriter(32);
        handlerList.uleb128(tries.length);
        const handlerOffsets = [];

        for (const tr of tries) {
          handlerOffsets.push(handlerList.pos);
          const handlers = tr.handlers ?? [];
          const hasCatchAll = tr.catchAllAddr !== undefined && tr.catchAllAddr !== null;
          const sizeVal = hasCatchAll ? -handlers.length : handlers.length;
          handlerList.sleb128(sizeVal);
          for (const h of handlers) {
            handlerList.uleb128(typeIndex.get(h.type)).uleb128(h.addr);
          }
          if (hasCatchAll) {
            handlerList.uleb128(tr.catchAllAddr);
          }
        }

        for (let ti = 0; ti < tries.length; ti++) {
          const tr = tries[ti];
          w.u32le(tr.startAddr).u16le(tr.insnCount).u16le(handlerOffsets[ti]);
        }
        w.bytes(handlerList.toUint8Array());
      }
    }
  }
  if (codeItemCount > 0) {
    mapItems.push({ type: 0x2001, size: codeItemCount, offset: codeItemFirstOff });
  }

  // 3c. string_data_item (0x2002, 1-byte aligned)
  if (strings.length > 0) {
    const firstStrDataOff = w.pos;
    for (let i = 0; i < strings.length; i++) {
      const s = strings[i];
      const off = w.pos;
      w.patchU32le(stringIdsOff + i * 4, off);
      w.uleb128(s.length).bytes(encodeMutf8(s)).u8(0);
    }
    mapItems.push({ type: 0x2002, size: strings.length, offset: firstStrDataOff });
  }

  // 3d. class_data_item (0x2000, 1-byte aligned)
  let classDataFirstOff = 0;
  let classDataCount = 0;
  for (let i = 0; i < resolvedClasses.length; i++) {
    const c = resolvedClasses[i];
    const hasData =
      c.staticFields.length > 0 ||
      c.instanceFields.length > 0 ||
      c.directMethods.length > 0 ||
      c.virtualMethods.length > 0;
    if (!hasData) continue;

    const off = w.pos;
    if (classDataCount === 0) classDataFirstOff = off;
    classDataCount++;
    w.patchU32le(classDefsOff + i * 32 + 24, off);

    w.uleb128(c.staticFields.length)
      .uleb128(c.instanceFields.length)
      .uleb128(c.directMethods.length)
      .uleb128(c.virtualMethods.length);

    let prev = 0;
    for (const f of c.staticFields) {
      w.uleb128(f.fieldIdx - prev).uleb128(f.accessFlags);
      prev = f.fieldIdx;
    }
    prev = 0;
    for (const f of c.instanceFields) {
      w.uleb128(f.fieldIdx - prev).uleb128(f.accessFlags);
      prev = f.fieldIdx;
    }
    prev = 0;
    for (const m of c.directMethods) {
      w.uleb128(m.methodIdx - prev).uleb128(m.accessFlags).uleb128(m.codeOff);
      prev = m.methodIdx;
    }
    prev = 0;
    for (const m of c.virtualMethods) {
      w.uleb128(m.methodIdx - prev).uleb128(m.accessFlags).uleb128(m.codeOff);
      prev = m.methodIdx;
    }
  }
  if (classDataCount > 0) {
    mapItems.push({ type: 0x2000, size: classDataCount, offset: classDataFirstOff });
  }

  // 3e. map_list (0x1000, 4-byte aligned)
  w.align(4);
  const mapOff = w.pos;
  mapItems.push({ type: 0x1000, size: 1, offset: mapOff });
  w.u32le(mapItems.length);
  for (const item of mapItems) {
    w.u16le(item.type).u16le(0).u32le(item.size).u32le(item.offset);
  }

  const fileSize = w.length;
  const dataSize = fileSize - dataOff;

  // Finalize DEX header fields
  const magic = `dex\n${String(dexVersion).padStart(3, '0')}\0`;
  w.patchBytes(0x00, textEncoder.encode(magic));
  w.patchU32le(0x20, fileSize);
  w.patchU32le(0x24, headerSize);
  w.patchU32le(0x28, 0x12345678); // ENDIAN_CONSTANT
  w.patchU32le(0x2c, 0); // link_size
  w.patchU32le(0x30, 0); // link_off
  w.patchU32le(0x34, mapOff);
  w.patchU32le(0x38, strings.length);
  w.patchU32le(0x3c, stringIdsOff);
  w.patchU32le(0x40, types.length);
  w.patchU32le(0x44, typeIdsOff);
  w.patchU32le(0x48, protos.length);
  w.patchU32le(0x4c, protoIdsOff);
  w.patchU32le(0x50, fields.length);
  w.patchU32le(0x54, fieldIdsOff);
  w.patchU32le(0x58, methods.length);
  w.patchU32le(0x5c, methodIdsOff);
  w.patchU32le(0x60, resolvedClasses.length);
  w.patchU32le(0x64, classDefsOff);
  w.patchU32le(0x68, dataSize);
  w.patchU32le(0x6c, dataOff);
  if (isV041) {
    w.patchU32le(0x70, fileSize); // container_size
    w.patchU32le(0x74, 0); // header_offset
  }

  // Compute SHA-1 ([0x20..]) first, THEN Adler-32 ([0x0C..]) last!
  const bytes = w.toUint8Array();
  const digest = sha1(bytes.subarray(0x20));
  bytes.set(digest, 0x0c);
  const checksum = adler32(bytes.subarray(0x0c));
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(0x08, checksum, true);
  return bytes;
}

/**
 * Builds a complete, valid, dynamically parameterized Android .apk archive.
 */
export function buildCustomApk({
  packageName = 'com.omnios.dynamic',
  appLabel = 'OmniDynamic',
  activityClass = '.MainActivity',
  computeA,
  computeB,
  computeOp = 'add',
  outputFile,
  outputContent,
  sharedPrefName = 'app_prefs',
  sharedPrefKey,
  sharedPrefVal,
  intentAction,
  intentUri,
  intentMimeType,
  notificationTitle,
  notificationBody,
  logTag = 'OmniDynamic',
  permissions = [],
  intentFilters = [],
  dexVersion = '035',
  includeV2SigBlock = false,
  includeResourcesArsc = true,
  arscSparse = false,
  arscOffset16 = false,
  useDataDescriptor = false,
  rawDexInsns = null,
  extraTries = [],
  extraStrings = [],
  extraClasses = [],
} = {}) {
  const fullClass = activityClass.startsWith('.') ? `${packageName}${activityClass}` : activityClass;
  const classDesc = `L${fullClass.replace(/\./g, '/')};`;

  const opMap = {
    add: DALVIK.OP_ADD_INT,
    sub: DALVIK.OP_SUB_INT,
    mul: DALVIK.OP_MUL_INT,
    div: DALVIK.OP_DIV_INT,
    rem: DALVIK.OP_REM_INT,
  };

  const mainClass = {
    descriptor: classDesc,
    accessFlags: 0x0001,
    superclass: 'Landroid/app/Activity;',
    sourceFile: 'MainActivity.java',
    directMethods: [
      {
        name: '<init>',
        returnType: 'V',
        params: [],
        accessFlags: 0x10001, // PUBLIC | CONSTRUCTOR
        registersSize: 1,
        insSize: 1,
        outsSize: 1,
        buildInsns: (ctx) => [
          ...DALVIK.invoke35c(
            DALVIK.OP_INVOKE_DIRECT,
            [0],
            ctx.method('Landroid/app/Activity;', '<init>', 'V', [])
          ),
          ...DALVIK.returnVoid(),
        ],
      },
    ],
    virtualMethods: [
      {
        name: 'onCreate',
        returnType: 'V',
        params: ['Landroid/os/Bundle;'],
        accessFlags: 0x0001,
        registersSize: 8,
        insSize: 2,
        outsSize: 4,
        buildInsns: (ctx) => {
          // p0 = this = v6, p1 = savedInstanceState = v7
          if (typeof rawDexInsns === 'function') {
            return rawDexInsns(ctx, classDesc);
          }

          const code = [];
          // super.onCreate(savedInstanceState)
          code.push(
            ...DALVIK.invoke35c(
              DALVIK.OP_INVOKE_SUPER,
              [6, 7],
              ctx.method('Landroid/app/Activity;', 'onCreate', 'V', ['Landroid/os/Bundle;'])
            )
          );

          // Arithmetic + Log.i OR static outputContent
          if (computeA !== undefined && computeB !== undefined) {
            const binOp = opMap[computeOp] ?? DALVIK.OP_ADD_INT;
            code.push(...DALVIK.const32(0, computeA | 0));
            code.push(...DALVIK.const32(1, computeB | 0));
            code.push(...DALVIK.binop(binOp, 2, 0, 1));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_STATIC,
                [2],
                ctx.method('Ljava/lang/Integer;', 'toString', 'Ljava/lang/String;', ['I'])
              )
            );
            code.push(...DALVIK.moveResultObj(3));
            code.push(...DALVIK.constString(4, ctx.str(logTag)));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_STATIC,
                [4, 3],
                ctx.method('Landroid/util/Log;', 'i', 'I', ['Ljava/lang/String;', 'Ljava/lang/String;'])
              )
            );
          } else {
            code.push(...DALVIK.constString(3, ctx.str(outputContent ?? appLabel)));
          }

          // TextView UI surface
          code.push(...DALVIK.newInstance(0, ctx.type('Landroid/widget/TextView;')));
          code.push(
            ...DALVIK.invoke35c(
              DALVIK.OP_INVOKE_DIRECT,
              [0, 6],
              ctx.method('Landroid/widget/TextView;', '<init>', 'V', ['Landroid/content/Context;'])
            )
          );
          code.push(
            ...DALVIK.invoke35c(
              DALVIK.OP_INVOKE_VIRTUAL,
              [0, 3],
              ctx.method('Landroid/widget/TextView;', 'setText', 'V', ['Ljava/lang/CharSequence;'])
            )
          );
          code.push(
            ...DALVIK.invoke35c(
              DALVIK.OP_INVOKE_VIRTUAL,
              [6, 0],
              ctx.method('Landroid/app/Activity;', 'setContentView', 'V', ['Landroid/view/View;'])
            )
          );

          // Optional SharedPreferences write
          if (sharedPrefKey !== undefined) {
            code.push(...DALVIK.constString(0, ctx.str(sharedPrefName)));
            code.push(...DALVIK.const4(1, 0));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_VIRTUAL,
                [6, 0, 1],
                ctx.method('Landroid/app/Activity;', 'getSharedPreferences', 'Landroid/content/SharedPreferences;', ['Ljava/lang/String;', 'I'])
              )
            );
            code.push(...DALVIK.moveResultObj(0));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_INTERFACE,
                [0],
                ctx.method('Landroid/content/SharedPreferences;', 'edit', 'Landroid/content/SharedPreferences$Editor;', [])
              )
            );
            code.push(...DALVIK.moveResultObj(0));
            code.push(...DALVIK.constString(1, ctx.str(String(sharedPrefKey))));
            code.push(...DALVIK.constString(2, ctx.str(String(sharedPrefVal ?? ''))));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_INTERFACE,
                [0, 1, 2],
                ctx.method('Landroid/content/SharedPreferences$Editor;', 'putString', 'Landroid/content/SharedPreferences$Editor;', ['Ljava/lang/String;', 'Ljava/lang/String;'])
              )
            );
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_INTERFACE,
                [0],
                ctx.method('Landroid/content/SharedPreferences$Editor;', 'apply', 'V', [])
              )
            );
          }

          // Optional FileOutputStream VFS file write
          if (outputFile) {
            code.push(...DALVIK.newInstance(0, ctx.type('Ljava/io/FileOutputStream;')));
            code.push(...DALVIK.constString(1, ctx.str(outputFile)));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_DIRECT,
                [0, 1],
                ctx.method('Ljava/io/FileOutputStream;', '<init>', 'V', ['Ljava/lang/String;'])
              )
            );
            let contentReg = 3;
            if (outputContent !== undefined) {
              code.push(...DALVIK.constString(2, ctx.str(String(outputContent))));
              contentReg = 2;
            }
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_VIRTUAL,
                [contentReg],
                ctx.method('Ljava/lang/String;', 'getBytes', '[B', [])
              )
            );
            code.push(...DALVIK.moveResultObj(4));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_VIRTUAL,
                [0, 4],
                ctx.method('Ljava/io/FileOutputStream;', 'write', 'V', ['[B'])
              )
            );
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_VIRTUAL,
                [0],
                ctx.method('Ljava/io/FileOutputStream;', 'close', 'V', [])
              )
            );
          }

          // Optional Intent dispatch
          if (intentAction) {
            code.push(...DALVIK.newInstance(0, ctx.type('Landroid/content/Intent;')));
            code.push(...DALVIK.constString(1, ctx.str(intentAction)));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_DIRECT,
                [0, 1],
                ctx.method('Landroid/content/Intent;', '<init>', 'V', ['Ljava/lang/String;'])
              )
            );
            if (intentUri) {
              code.push(...DALVIK.constString(1, ctx.str(intentUri)));
              code.push(
                ...DALVIK.invoke35c(
                  DALVIK.OP_INVOKE_STATIC,
                  [1],
                  ctx.method('Landroid/net/Uri;', 'parse', 'Landroid/net/Uri;', ['Ljava/lang/String;'])
                )
              );
              code.push(...DALVIK.moveResultObj(1));
              code.push(
                ...DALVIK.invoke35c(
                  DALVIK.OP_INVOKE_VIRTUAL,
                  [0, 1],
                  ctx.method('Landroid/content/Intent;', 'setData', 'Landroid/content/Intent;', ['Landroid/net/Uri;'])
                )
              );
            }
            if (intentMimeType) {
              code.push(...DALVIK.constString(1, ctx.str(intentMimeType)));
              code.push(
                ...DALVIK.invoke35c(
                  DALVIK.OP_INVOKE_VIRTUAL,
                  [0, 1],
                  ctx.method('Landroid/content/Intent;', 'setType', 'Landroid/content/Intent;', ['Ljava/lang/String;'])
                )
              );
            }
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_VIRTUAL,
                [6, 0],
                ctx.method('Landroid/app/Activity;', 'startActivity', 'V', ['Landroid/content/Intent;'])
              )
            );
          }

          // Optional Toast notification
          if (notificationTitle) {
            const toastMsg = notificationBody ? `${notificationTitle}: ${notificationBody}` : notificationTitle;
            code.push(...DALVIK.constString(0, ctx.str(toastMsg)));
            code.push(...DALVIK.const4(1, 0));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_STATIC,
                [6, 0, 1],
                ctx.method('Landroid/widget/Toast;', 'makeText', 'Landroid/widget/Toast;', ['Landroid/content/Context;', 'Ljava/lang/CharSequence;', 'I'])
              )
            );
            code.push(...DALVIK.moveResultObj(0));
            code.push(
              ...DALVIK.invoke35c(
                DALVIK.OP_INVOKE_VIRTUAL,
                [0],
                ctx.method('Landroid/widget/Toast;', 'show', 'V', [])
              )
            );
          }

          code.push(...DALVIK.returnVoid());
          return { codeUnits: code, tries: extraTries };
        },
      },
    ],
  };

  const manifestBytes = buildAxmlManifest({
    packageName,
    label: appLabel,
    mainActivity: activityClass,
    permissions,
    intentFilters,
  });

  const dexBytes = buildDex({
    dexVersion,
    classes: [mainClass, ...extraClasses],
    extraStrings,
  });

  const zipEntries = [
    { name: 'AndroidManifest.xml', data: manifestBytes, method: 8 },
    { name: 'classes.dex', data: dexBytes, method: 8 },
  ];

  if (includeResourcesArsc) {
    const arscStrings = (arscSparse || arscOffset16)
      ? [
          { id: 0, name: 'app_name', value: appLabel },
          { id: 5, name: 'app_tag', value: logTag },
        ]
      : { app_name: appLabel };
    const arscBytes = buildResourcesArsc({
      packageName,
      strings: arscStrings,
      sparse: arscSparse,
      offset16: arscOffset16,
    });
    zipEntries.push({ name: 'resources.arsc', data: arscBytes, method: 0, alignDataTo: 4 });
  }

  return buildZip(zipEntries, {
    apkV2SigBlock: includeV2SigBlock,
    useDataDescriptor,
  });
}

// ============================================================================
// 2. x86-64 & x86 Machine Code Helpers + PE32+ / PE32 Executable Builders
// ============================================================================

function le16(v) {
  return [v & 0xff, (v >>> 8) & 0xff];
}

function le32(v) {
  const u = v >>> 0;
  return [u & 0xff, (u >>> 8) & 0xff, (u >>> 16) & 0xff, (u >>> 24) & 0xff];
}

function le64(v) {
  const bi = BigInt.asUintN(64, BigInt(v));
  const out = [];
  for (let i = 0; i < 8; i++) out.push(Number((bi >> BigInt(i * 8)) & 0xffn));
  return out;
}

export const X64 = Object.freeze({
  subRspImm8: (imm8) => [0x48, 0x83, 0xec, imm8 & 0xff],
  addRspImm8: (imm8) => [0x48, 0x83, 0xc4, imm8 & 0xff],
  ret: () => [0xc3],
  movEaxImm32: (imm32) => [0xb8, ...le32(imm32)],
  movEcxImm32: (imm32) => [0xb9, ...le32(imm32)],
  movEdxImm32: (imm32) => [0xba, ...le32(imm32)],
  movR8dImm32: (imm32) => [0x41, 0xb8, ...le32(imm32)],
  movR9dImm32: (imm32) => [0x41, 0xb9, ...le32(imm32)],
  movabsRaxImm64: (imm64) => [0x48, 0xb8, ...le64(imm64)],
  movAxImm16: (imm16) => [0x66, 0xb8, ...le16(imm16)],
  movAlImm8: (imm8) => [0xb0, imm8 & 0xff],
  xorEaxEax: () => [0x31, 0xc0],
  xorEcxEcx: () => [0x31, 0xc9],
  xorEdxEdx: () => [0x31, 0xd2],
  xorR8dR8d: () => [0x45, 0x31, 0xc0],
  xorR9dR9d: () => [0x45, 0x31, 0xc9],
  movRcxRax: () => [0x48, 0x89, 0xc1],
  movEcxEax: () => [0x89, 0xc1],
  addEaxEdx: () => [0x01, 0xd0],
  imulEaxEdx: () => [0x0f, 0xaf, 0xc2],
  leaRaxRip: (instRva, targetRva) => [0x48, 0x8d, 0x05, ...le32(targetRva - (instRva + 7))],
  leaRcxRip: (instRva, targetRva) => [0x48, 0x8d, 0x0d, ...le32(targetRva - (instRva + 7))],
  leaRdxRip: (instRva, targetRva) => [0x48, 0x8d, 0x15, ...le32(targetRva - (instRva + 7))],
  leaR8Rip: (instRva, targetRva) => [0x4c, 0x8d, 0x05, ...le32(targetRva - (instRva + 7))],
  leaR9Rip: (instRva, targetRva) => [0x4c, 0x8d, 0x0d, ...le32(targetRva - (instRva + 7))],
  movMemRipRax: (instRva, targetRva) => [0x48, 0x89, 0x05, ...le32(targetRva - (instRva + 7))],
  movRcxMemRip: (instRva, targetRva) => [0x48, 0x8b, 0x0d, ...le32(targetRva - (instRva + 7))],
  movQwordRspRax: (disp8) => [0x48, 0x89, 0x44, 0x24, disp8 & 0xff],
  movQwordRspImm32: (disp8, imm32) => [0x48, 0xc7, 0x44, 0x24, disp8 & 0xff, ...le32(imm32)],
  callRipIat: (instRva, iatSlotRva) => [0xff, 0x15, ...le32(iatSlotRva - (instRva + 6))],
});

export const X86 = Object.freeze({
  pushImm8: (imm8) => [0x6a, imm8 & 0xff],
  pushImm32: (imm32) => [0x68, ...le32(imm32)],
  pushEax: () => [0x50],
  callAbsIat: (va32) => [0xff, 0x15, ...le32(va32)],
  ret: () => [0xc3],
});

/**
 * Builds an .rdata section containing IAT, Import Descriptors, optional ILT,
 * 2-byte-aligned Hint/Name entries, DLL names, and read-only string payloads.
 */
function buildPeRdata({
  rdataRva,
  is64,
  dllImports, // Array<{ dll: string, funcs: string[] }>
  strings, // Map<key, Uint8Array>
  useOriginalFirstThunkZero = false,
}) {
  const ptrSize = is64 ? 8 : 4;
  const w = new BinaryWriter(1024);

  // 1. Reserve IAT slots
  const iatStartOff = w.pos;
  const dllIatOffs = [];
  const iatRvaByName = new Map();

  for (const imp of dllImports) {
    dllIatOffs.push(w.pos);
    for (const fn of imp.funcs) {
      iatRvaByName.set(fn, rdataRva + w.pos);
      iatRvaByName.set(`${imp.dll}!${fn}`, rdataRva + w.pos);
      w.zeros(ptrSize);
    }
    w.zeros(ptrSize); // null terminator thunk
  }
  const iatSize = w.pos - iatStartOff;

  // 2. Reserve Import Descriptors (20 bytes each + 20-byte null terminator)
  w.align(4);
  const importDirOff = w.pos;
  const importDirSize = (dllImports.length + 1) * 20;
  w.zeros(importDirSize);

  // 3. Optional ILT (omitted when useOriginalFirstThunkZero === true)
  const dllIltOffs = [];
  if (!useOriginalFirstThunkZero) {
    w.align(ptrSize);
    for (const imp of dllImports) {
      dllIltOffs.push(w.pos);
      w.zeros((imp.funcs.length + 1) * ptrSize);
    }
  }

  // 4. Hint/Name entries (2-byte aligned)
  const hintNameRvas = new Map();
  for (const imp of dllImports) {
    for (const fn of imp.funcs) {
      w.align(2);
      const rva = rdataRva + w.pos;
      hintNameRvas.set(`${imp.dll}!${fn}`, rva);
      w.u16le(0).asciiZ(fn);
    }
  }

  // 5. DLL names
  const dllNameRvas = [];
  for (const imp of dllImports) {
    dllNameRvas.push(rdataRva + w.pos);
    w.asciiZ(imp.dll);
  }

  // 6. Read-only strings
  w.align(4);
  const stringRvas = new Map();
  let firstStringRva = rdataRva;
  let idx = 0;
  for (const [key, bytes] of strings.entries()) {
    const rva = rdataRva + w.pos;
    if (idx === 0) firstStringRva = rva;
    idx++;
    stringRvas.set(key, { rva, length: bytes.length });
    w.bytes(bytes);
  }

  // Patch IAT, ILT, and Import Descriptors
  for (let d = 0; d < dllImports.length; d++) {
    const imp = dllImports[d];
    const iatOff = dllIatOffs[d];
    const iltOff = useOriginalFirstThunkZero ? 0 : dllIltOffs[d];

    for (let f = 0; f < imp.funcs.length; f++) {
      const hnRva = hintNameRvas.get(`${imp.dll}!${imp.funcs[f]}`);
      if (is64) {
        w.patchU64le(iatOff + f * 8, BigInt(hnRva));
        if (!useOriginalFirstThunkZero) w.patchU64le(iltOff + f * 8, BigInt(hnRva));
      } else {
        w.patchU32le(iatOff + f * 4, hnRva);
        if (!useOriginalFirstThunkZero) w.patchU32le(iltOff + f * 4, hnRva);
      }
    }

    const descOff = importDirOff + d * 20;
    w.patchU32le(descOff + 0, useOriginalFirstThunkZero ? 0 : (rdataRva + iltOff)); // OriginalFirstThunk
    w.patchU32le(descOff + 4, 0); // TimeDateStamp
    w.patchU32le(descOff + 8, 0); // ForwarderChain
    w.patchU32le(descOff + 12, dllNameRvas[d]); // Name RVA
    w.patchU32le(descOff + 16, rdataRva + iatOff); // FirstThunk
  }

  return {
    bytes: w.toUint8Array(),
    iatRva: rdataRva + iatStartOff,
    iatSize,
    importDirRva: rdataRva + importDirOff,
    importDirSize,
    iatRvaByName,
    stringRvas,
    firstStringRva,
  };
}

function assemblePeFile({
  is64,
  subsystem,
  imageBase,
  sections, // [{ name, rva, virtualSize, rawBytes, characteristics, overrideRawSize? }]
  entryPointRva,
  baseOfCode,
  baseOfData = 0,
  dataDirs, // Map<index, { rva, size }>
  includeReloc = true,
  addCertTableRawOffset = false,
}) {
  const eLfanew = 0x80;
  const optSize = is64 ? 240 : 224;
  const optEnd = eLfanew + 4 + 20 + optSize;
  const sizeOfHeaders = alignUp(optEnd + sections.length * 40, 0x200);

  let nextRawOff = sizeOfHeaders;
  const laidOut = sections.map((sec) => {
    const rawBytes = sec.rawBytes ?? new Uint8Array(0);
    const isUninit = rawBytes.length === 0 && sec.overrideRawSize === 0;
    const rawSize = sec.overrideRawSize !== undefined
      ? sec.overrideRawSize
      : (rawBytes.length === 0 ? 0 : alignUp(rawBytes.length, 0x200));
    const ptrToRaw = (isUninit || rawSize === 0) ? 0 : nextRawOff;
    if (rawSize > 0) nextRawOff += rawSize;
    return {
      ...sec,
      rawBytes,
      rawSize,
      ptrToRaw,
    };
  });

  let certBytes = null;
  let certFileOff = 0;
  if (addCertTableRawOffset) {
    certFileOff = alignUp(nextRawOff, 8);
    const cw = new BinaryWriter(32);
    // WIN_CERTIFICATE (dwLength=32, wRevision=0x0200, wCertificateType=0x0002, payload=24B)
    cw.u32le(32)
      .u16le(0x0200)
      .u16le(0x0002)
      .fixedAscii('OMNIOS_TEST_WIN_CERT_V2', 24);
    certBytes = cw.toUint8Array();
    dataDirs.set(4, { rva: certFileOff, size: certBytes.length });
  }

  let sizeOfImage = alignUp(sizeOfHeaders, 0x1000);
  let sizeOfCode = 0;
  let sizeOfInitData = 0;
  let sizeOfUninitData = 0;
  for (const s of laidOut) {
    const end = alignUp(s.rva + Math.max(s.virtualSize, s.rawSize, 1), 0x1000);
    if (end > sizeOfImage) sizeOfImage = end;
    if (s.characteristics & 0x00000020) sizeOfCode += s.rawSize;
    if (s.characteristics & 0x00000040) sizeOfInitData += s.rawSize;
    if (s.characteristics & 0x00000080) sizeOfUninitData += alignUp(s.virtualSize, 0x200);
  }

  const w = new BinaryWriter(nextRawOff + 64);

  // DOS Header (0x00..0x7F)
  w.ascii('MZ').zeros(0x3a).u32le(eLfanew).zeros(eLfanew - 0x40);

  // PE Signature + COFF Header
  w.ascii('PE\0\0')
    .u16le(is64 ? 0x8664 : 0x014c) // Machine
    .u16le(laidOut.length) // NumberOfSections
    .u32le(0x65000000) // TimeDateStamp
    .u32le(0) // PointerToSymbolTable
    .u32le(0) // NumberOfSymbols
    .u16le(optSize) // SizeOfOptionalHeader
    .u16le(is64 ? 0x0022 : 0x0102); // Characteristics

  // Optional Header
  if (is64) {
    w.u16le(0x020b) // PE32+
      .u8(14)
      .u8(0)
      .u32le(sizeOfCode)
      .u32le(sizeOfInitData)
      .u32le(sizeOfUninitData)
      .u32le(entryPointRva)
      .u32le(baseOfCode)
      .u64le(BigInt(imageBase))
      .u32le(0x1000) // SectionAlignment
      .u32le(0x0200) // FileAlignment
      .u16le(6)
      .u16le(0)
      .u16le(1)
      .u16le(0)
      .u16le(6)
      .u16le(0)
      .u32le(0)
      .u32le(sizeOfImage)
      .u32le(sizeOfHeaders)
      .u32le(0) // CheckSum
      .u16le(subsystem)
      .u16le(includeReloc ? 0x8160 : 0x8100) // DllCharacteristics
      .u64le(0x100000n)
      .u64le(0x1000n)
      .u64le(0x100000n)
      .u64le(0x1000n)
      .u32le(0)
      .u32le(16);
  } else {
    w.u16le(0x010b) // PE32
      .u8(14)
      .u8(0)
      .u32le(sizeOfCode)
      .u32le(sizeOfInitData)
      .u32le(sizeOfUninitData)
      .u32le(entryPointRva)
      .u32le(baseOfCode)
      .u32le(baseOfData)
      .u32le(Number(imageBase) >>> 0)
      .u32le(0x1000)
      .u32le(0x0200)
      .u16le(6)
      .u16le(0)
      .u16le(1)
      .u16le(0)
      .u16le(6)
      .u16le(0)
      .u32le(0)
      .u32le(sizeOfImage)
      .u32le(sizeOfHeaders)
      .u32le(0)
      .u16le(subsystem)
      .u16le(includeReloc ? 0x8140 : 0x8100)
      .u32le(0x100000)
      .u32le(0x1000)
      .u32le(0x100000)
      .u32le(0x1000)
      .u32le(0)
      .u32le(16);
  }

  for (let i = 0; i < 16; i++) {
    const dir = dataDirs.get(i) ?? { rva: 0, size: 0 };
    w.u32le(dir.rva).u32le(dir.size);
  }

  // Section Headers (40 bytes each)
  for (const s of laidOut) {
    w.fixedAscii(s.name, 8)
      .u32le(s.virtualSize)
      .u32le(s.rva)
      .u32le(s.rawSize)
      .u32le(s.ptrToRaw)
      .u32le(0)
      .u32le(0)
      .u16le(0)
      .u16le(0)
      .u32le(s.characteristics);
  }

  // Pad headers to SizeOfHeaders
  if (w.pos > sizeOfHeaders) {
    throw new Error(`PE headers overflowed SizeOfHeaders (${w.pos} > ${sizeOfHeaders})`);
  }
  w.zeros(sizeOfHeaders - w.pos);

  // Section Raw Data
  for (const s of laidOut) {
    if (s.rawSize === 0) continue;
    if (w.pos < s.ptrToRaw) w.zeros(s.ptrToRaw - w.pos);
    w.bytes(s.rawBytes);
    const pad = s.rawSize - s.rawBytes.length;
    if (pad > 0) w.zeros(pad);
  }

  // Optional Certificate Table appended at 8-byte aligned raw file offset
  if (certBytes) {
    if (w.pos < certFileOff) w.zeros(certFileOff - w.pos);
    w.bytes(certBytes);
  }

  return w.toUint8Array();
}

/**
 * Builds a valid, llvm-objdump / llvm-readobj verified PE32+ (x86-64) executable.
 */
export function buildCustomPe64Exe({
  subsystem = 3,
  message = null,
  exitCode = 0,
  computeExitSum = null,
  writeFilePath = null,
  writeFileContent = null,
  regHive = 0x80000001,
  regSubKey = null,
  regValueName = null,
  regValueData = null,
  windowTitle = null,
  messageBoxText = null,
  messageBoxCaption = null,
  useOriginalFirstThunkZero = false,
  addCertTableRawOffset = false,
  includeReloc = true,
  dataVirtualSize = null,
  textVirtualSize = null,
  addBssSection = false,
  bssVirtualSize = 0x1000,
  customCodeBytes = null,
  extraImports = [],
  extraStrings = {},
} = {}) {
  const IMAGE_BASE = 0x140000000n;
  const TEXT_RVA = 0x1000;
  const RDATA_RVA = 0x2000;

  // Collect minimal needed DLL imports
  const dllMap = new Map();
  function addImport(dll, fn) {
    if (!dllMap.has(dll)) dllMap.set(dll, new Set());
    dllMap.get(dll).add(fn);
  }

  addImport('KERNEL32.dll', 'ExitProcess');
  if (message !== null && message !== undefined) {
    addImport('KERNEL32.dll', 'GetStdHandle');
    addImport('KERNEL32.dll', 'WriteFile');
  }
  if (writeFilePath) {
    addImport('KERNEL32.dll', 'CreateFileA');
    addImport('KERNEL32.dll', 'WriteFile');
    addImport('KERNEL32.dll', 'CloseHandle');
  }
  if (regSubKey) {
    addImport('ADVAPI32.dll', 'RegCreateKeyExA');
    addImport('ADVAPI32.dll', 'RegSetValueExA');
    addImport('ADVAPI32.dll', 'RegCloseKey');
  }
  if (windowTitle) {
    addImport('USER32.dll', 'CreateWindowExA');
    addImport('USER32.dll', 'ShowWindow');
  }
  if (messageBoxText) {
    addImport('USER32.dll', 'MessageBoxA');
  }
  for (const extra of extraImports) {
    for (const fn of extra.funcs ?? []) addImport(extra.dll, fn);
  }

  const dllImports = Array.from(dllMap.entries()).map(([dll, fnSet]) => ({
    dll,
    funcs: Array.from(fnSet),
  }));

  // Collect read-only strings into .rdata first so RVAs are fixed before assembling .text
  const roStrings = new Map();
  if (message !== null && message !== undefined) {
    roStrings.set('message', concatBytes(textEncoder.encode(String(message)), [0]));
  }
  if (writeFilePath) {
    roStrings.set('writeFilePath', concatBytes(textEncoder.encode(String(writeFilePath)), [0]));
    roStrings.set('writeFileContent', textEncoder.encode(String(writeFileContent ?? '')));
  }
  if (regSubKey) {
    roStrings.set('regSubKey', concatBytes(textEncoder.encode(String(regSubKey)), [0]));
    roStrings.set('regValueName', concatBytes(textEncoder.encode(String(regValueName ?? 'Value')), [0]));
    roStrings.set('regValueData', concatBytes(textEncoder.encode(String(regValueData ?? '')), [0]));
  }
  if (windowTitle) {
    roStrings.set('winClass', textEncoder.encode('STATIC\0'));
    roStrings.set('windowTitle', concatBytes(textEncoder.encode(String(windowTitle)), [0]));
  }
  if (messageBoxText) {
    roStrings.set('msgBoxText', concatBytes(textEncoder.encode(String(messageBoxText)), [0]));
    roStrings.set('msgBoxCaption', concatBytes(textEncoder.encode(String(messageBoxCaption ?? windowTitle ?? 'OmniOS')), [0]));
  }
  for (const [k, v] of Object.entries(extraStrings)) {
    roStrings.set(k, typeof v === 'string' ? concatBytes(textEncoder.encode(v), [0]) : v);
  }
  if (roStrings.size === 0) {
    roStrings.set('_marker', textEncoder.encode('OmniOS\0'));
  }

  const rdata = buildPeRdata({
    rdataRva: RDATA_RVA,
    is64: true,
    dllImports,
    strings: roStrings,
    useOriginalFirstThunkZero,
  });

  const dataRva = RDATA_RVA + alignUp(Math.max(rdata.bytes.length, 1), 0x1000);
  const dataVSize = dataVirtualSize ?? 0x100;
  let nextRva = dataRva + alignUp(Math.max(dataVSize, 0x200), 0x1000);

  let bssRva = 0;
  if (addBssSection) {
    bssRva = nextRva;
    nextRva = bssRva + alignUp(bssVirtualSize, 0x1000);
  }

  // Assemble .text machine code
  const code = new BinaryWriter(256);
  const emit = (arr) => code.bytes(arr);
  const curRva = () => TEXT_RVA + code.pos;

  if (customCodeBytes) {
    if (typeof customCodeBytes === 'function') {
      const ctx = {
        X64,
        textRva: TEXT_RVA,
        rdataRva: RDATA_RVA,
        dataRva,
        bssRva,
        imageBase: IMAGE_BASE,
        iat: rdata.iatRvaByName,
        strings: rdata.stringRvas,
        code,
        curRva,
        emit,
      };
      const returned = customCodeBytes(ctx);
      if (returned instanceof Uint8Array || Array.isArray(returned)) {
        emit(returned);
      }
    } else {
      emit(customCodeBytes);
    }
  } else {
    // Win64 prologue: align RSP to 16 bytes & reserve 32B shadow + 8 stack arg slots
    emit(X64.subRspImm8(0x68));

    // 1. Console stdout write
    if (message !== null && message !== undefined) {
      const msgInfo = rdata.stringRvas.get('message');
      const msgByteLen = msgInfo.length - 1; // exclude trailing NUL
      emit(X64.movEcxImm32(0xfffffff5)); // STD_OUTPUT_HANDLE (-11)
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('GetStdHandle')));
      emit(X64.movRcxRax()); // hFile
      emit(X64.leaRdxRip(curRva(), msgInfo.rva)); // lpBuffer
      emit(X64.movR8dImm32(msgByteLen)); // nNumberOfBytesToWrite
      emit(X64.leaR9Rip(curRva(), dataRva + 0)); // lpNumberOfBytesWritten
      emit(X64.movQwordRspImm32(0x20, 0)); // lpOverlapped = NULL
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('WriteFile')));
    }

    // 2. Win32 file creation & write
    if (writeFilePath) {
      const pathInfo = rdata.stringRvas.get('writeFilePath');
      const contentInfo = rdata.stringRvas.get('writeFileContent');
      emit(X64.leaRcxRip(curRva(), pathInfo.rva)); // lpFileName
      emit(X64.movEdxImm32(0x40000000)); // GENERIC_WRITE
      emit(X64.xorR8dR8d()); // dwShareMode = 0
      emit(X64.xorR9dR9d()); // lpSecurityAttributes = NULL
      emit(X64.movQwordRspImm32(0x20, 2)); // CREATE_ALWAYS
      emit(X64.movQwordRspImm32(0x28, 0x80)); // FILE_ATTRIBUTE_NORMAL
      emit(X64.movQwordRspImm32(0x30, 0)); // hTemplateFile = NULL
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('CreateFileA')));
      emit(X64.movMemRipRax(curRva(), dataRva + 8)); // save hFile

      emit(X64.movRcxMemRip(curRva(), dataRva + 8)); // hFile
      emit(X64.leaRdxRip(curRva(), contentInfo.rva)); // lpBuffer
      emit(X64.movR8dImm32(contentInfo.length)); // len
      emit(X64.leaR9Rip(curRva(), dataRva + 0)); // &written
      emit(X64.movQwordRspImm32(0x20, 0)); // lpOverlapped = NULL
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('WriteFile')));

      emit(X64.movRcxMemRip(curRva(), dataRva + 8));
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('CloseHandle')));
    }

    // 3. Win32 Registry key/value write
    if (regSubKey) {
      const subKeyInfo = rdata.stringRvas.get('regSubKey');
      const valNameInfo = rdata.stringRvas.get('regValueName');
      const valDataInfo = rdata.stringRvas.get('regValueData');
      emit(X64.movEcxImm32(regHive >>> 0)); // HKEY (zero-extends to 0x0000000080000001)
      emit(X64.leaRdxRip(curRva(), subKeyInfo.rva));
      emit(X64.xorR8dR8d()); // Reserved
      emit(X64.xorR9dR9d()); // lpClass
      emit(X64.movQwordRspImm32(0x20, 0)); // dwOptions
      emit(X64.movQwordRspImm32(0x28, 0x000f003f)); // KEY_ALL_ACCESS
      emit(X64.movQwordRspImm32(0x30, 0)); // lpSecurityAttributes
      emit(X64.leaRaxRip(curRva(), dataRva + 16));
      emit(X64.movQwordRspRax(0x38)); // phkResult
      emit(X64.movQwordRspImm32(0x40, 0)); // lpdwDisposition
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('RegCreateKeyExA')));

      emit(X64.movRcxMemRip(curRva(), dataRva + 16)); // hKey
      emit(X64.leaRdxRip(curRva(), valNameInfo.rva));
      emit(X64.xorR8dR8d()); // Reserved
      emit(X64.movR9dImm32(1)); // REG_SZ
      emit(X64.leaRaxRip(curRva(), valDataInfo.rva));
      emit(X64.movQwordRspRax(0x20)); // lpData
      emit(X64.movQwordRspImm32(0x28, valDataInfo.length)); // cbData (incl. NUL)
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('RegSetValueExA')));

      emit(X64.movRcxMemRip(curRva(), dataRva + 16));
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('RegCloseKey')));
    }

    // 4. Optional GUI Window creation
    if (windowTitle) {
      const clsInfo = rdata.stringRvas.get('winClass');
      const titleInfo = rdata.stringRvas.get('windowTitle');
      emit(X64.xorEcxEcx()); // dwExStyle
      emit(X64.leaRdxRip(curRva(), clsInfo.rva)); // lpClassName
      emit(X64.leaR8Rip(curRva(), titleInfo.rva)); // lpWindowName
      emit(X64.movR9dImm32(0x10cf0000)); // WS_VISIBLE | WS_OVERLAPPEDWINDOW
      emit(X64.movQwordRspImm32(0x20, 100)); // X
      emit(X64.movQwordRspImm32(0x28, 100)); // Y
      emit(X64.movQwordRspImm32(0x30, 480)); // Width
      emit(X64.movQwordRspImm32(0x38, 320)); // Height
      emit(X64.movQwordRspImm32(0x40, 0)); // hWndParent
      emit(X64.movQwordRspImm32(0x48, 0)); // hMenu
      emit(X64.movQwordRspImm32(0x50, 0)); // hInstance
      emit(X64.movQwordRspImm32(0x58, 0)); // lpParam
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('CreateWindowExA')));
      emit(X64.movRcxRax());
      emit(X64.movEdxImm32(5)); // SW_SHOW
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('ShowWindow')));
    }

    // 5. Optional MessageBoxA
    if (messageBoxText) {
      const textInfo = rdata.stringRvas.get('msgBoxText');
      const capInfo = rdata.stringRvas.get('msgBoxCaption');
      emit(X64.xorEcxEcx()); // hWnd = NULL
      emit(X64.leaRdxRip(curRva(), textInfo.rva));
      emit(X64.leaR8Rip(curRva(), capInfo.rva));
      emit(X64.xorR9dR9d()); // MB_OK
      emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('MessageBoxA')));
    }

    // 6. Compute exit code & call ExitProcess
    if (Array.isArray(computeExitSum) && computeExitSum.length === 2) {
      emit(X64.movEaxImm32(computeExitSum[0] | 0));
      emit(X64.movEdxImm32(computeExitSum[1] | 0));
      emit(X64.addEaxEdx());
      emit(X64.movEcxEax());
    } else {
      emit(X64.movEcxImm32(exitCode >>> 0));
    }
    emit(X64.callRipIat(curRva(), rdata.iatRvaByName.get('ExitProcess')));
    emit(X64.addRspImm8(0x68));
    emit(X64.ret());
  }

  const textBytes = code.toUint8Array();

  // .data section (32 bytes initialized scratch; offset +24 holds absolute 64-bit ptr for DIR64 reloc)
  const dataWriter = new BinaryWriter(32);
  dataWriter
    .u64le(0n) // [0] bytesWritten
    .u64le(0n) // [8] hFile
    .u64le(0n) // [16] hKey
    .u64le(IMAGE_BASE + BigInt(rdata.firstStringRva)); // [24] DIR64 relocation target
  const dataBytes = dataWriter.toUint8Array();

  const sections = [
    {
      name: '.text',
      rva: TEXT_RVA,
      virtualSize: textVirtualSize ?? textBytes.length,
      rawBytes: textBytes,
      characteristics: 0x60000020, // CODE | EXECUTE | READ
    },
    {
      name: '.rdata',
      rva: RDATA_RVA,
      virtualSize: rdata.bytes.length,
      rawBytes: rdata.bytes,
      characteristics: 0x40000040, // INITIALIZED_DATA | READ
    },
    {
      name: '.data',
      rva: dataRva,
      virtualSize: dataVSize,
      rawBytes: dataBytes,
      characteristics: 0xc0000040, // INITIALIZED_DATA | READ | WRITE
    },
  ];

  if (addBssSection) {
    sections.push({
      name: '.bss',
      rva: bssRva,
      virtualSize: bssVirtualSize,
      rawBytes: new Uint8Array(0),
      overrideRawSize: 0,
      characteristics: 0xc0000080, // UNINITIALIZED_DATA | READ | WRITE
    });
  }

  const dataDirs = new Map();
  dataDirs.set(1, { rva: rdata.importDirRva, size: rdata.importDirSize });
  dataDirs.set(12, { rva: rdata.iatRva, size: rdata.iatSize });

  if (includeReloc) {
    const relocRva = nextRva;
    const rw = new BinaryWriter(16);
    rw.u32le(dataRva)
      .u32le(12) // BlockSize = 8 + 2*2
      .u16le((10 << 12) | 24) // IMAGE_REL_BASED_DIR64 at data+24
      .u16le(0); // IMAGE_REL_BASED_ABSOLUTE padding
    const relocBytes = rw.toUint8Array();
    sections.push({
      name: '.reloc',
      rva: relocRva,
      virtualSize: relocBytes.length,
      rawBytes: relocBytes,
      characteristics: 0x42000040, // INITIALIZED_DATA | DISCARDABLE | READ
    });
    dataDirs.set(5, { rva: relocRva, size: relocBytes.length });
  }

  return assemblePeFile({
    is64: true,
    subsystem,
    imageBase: IMAGE_BASE,
    sections,
    entryPointRva: TEXT_RVA,
    baseOfCode: TEXT_RVA,
    dataDirs,
    includeReloc,
    addCertTableRawOffset,
  });
}

/**
 * Builds a valid, llvm-objdump / llvm-readobj verified PE32 (32-bit x86) executable
 * with absolute VA32 __stdcall IAT calls and HIGHLOW base relocations.
 */
export function buildCustomPe32Exe({
  subsystem = 3,
  message = 'Hello PE32\n',
  exitCode = 0,
  useOriginalFirstThunkZero = false,
  includeReloc = true,
} = {}) {
  const IMAGE_BASE = 0x00400000;
  const TEXT_RVA = 0x1000;
  const RDATA_RVA = 0x2000;

  const dllImports = [
    {
      dll: 'KERNEL32.dll',
      funcs: message ? ['GetStdHandle', 'WriteFile', 'ExitProcess'] : ['ExitProcess'],
    },
  ];

  const roStrings = new Map();
  if (message) {
    roStrings.set('message', concatBytes(textEncoder.encode(String(message)), [0]));
  } else {
    roStrings.set('_marker', textEncoder.encode('OmniOS32\0'));
  }

  const rdata = buildPeRdata({
    rdataRva: RDATA_RVA,
    is64: false,
    dllImports,
    strings: roStrings,
    useOriginalFirstThunkZero,
  });

  const dataRva = RDATA_RVA + alignUp(Math.max(rdata.bytes.length, 1), 0x1000);
  const relocRva = dataRva + 0x1000;

  const code = new BinaryWriter(128);
  const textRelocOffsets = [];

  function emitPushVa32(rva) {
    code.u8(0x68);
    textRelocOffsets.push(code.pos);
    code.u32le((IMAGE_BASE + rva) >>> 0);
  }

  function emitCallIat32(fnName) {
    const slotRva = rdata.iatRvaByName.get(fnName);
    code.u8(0xff).u8(0x15);
    textRelocOffsets.push(code.pos);
    code.u32le((IMAGE_BASE + slotRva) >>> 0);
  }

  if (message) {
    const msgInfo = rdata.stringRvas.get('message');
    const msgLen = msgInfo.length - 1;
    // GetStdHandle(-11)
    code.bytes(X86.pushImm8(0xf5)); // -11 sign-extended
    emitCallIat32('GetStdHandle');
    // WriteFile(hOut, msgVA, msgLen, &written, 0) — right-to-left __stdcall
    code.bytes(X86.pushImm8(0)); // lpOverlapped = NULL
    emitPushVa32(dataRva + 0); // &written
    code.bytes(X86.pushImm32(msgLen)); // len
    emitPushVa32(msgInfo.rva); // lpBuffer
    code.bytes(X86.pushEax()); // hFile
    emitCallIat32('WriteFile');
  }

  code.bytes(X86.pushImm32(exitCode >>> 0));
  emitCallIat32('ExitProcess');
  code.bytes(X86.ret());

  const textBytes = code.toUint8Array();
  const dataBytes = new Uint8Array(16);

  const sections = [
    {
      name: '.text',
      rva: TEXT_RVA,
      virtualSize: textBytes.length,
      rawBytes: textBytes,
      characteristics: 0x60000020,
    },
    {
      name: '.rdata',
      rva: RDATA_RVA,
      virtualSize: rdata.bytes.length,
      rawBytes: rdata.bytes,
      characteristics: 0x40000040,
    },
    {
      name: '.data',
      rva: dataRva,
      virtualSize: 0x100,
      rawBytes: dataBytes,
      characteristics: 0xc0000040,
    },
  ];

  const dataDirs = new Map();
  dataDirs.set(1, { rva: rdata.importDirRva, size: rdata.importDirSize });
  dataDirs.set(12, { rva: rdata.iatRva, size: rdata.iatSize });

  if (includeReloc) {
    const entries = textRelocOffsets.map((off) => (3 << 12) | (off & 0x0fff)); // IMAGE_REL_BASED_HIGHLOW
    if ((entries.length & 1) === 1) entries.push(0); // 4-byte align block
    const blockSize = 8 + entries.length * 2;
    const rw = new BinaryWriter(blockSize);
    rw.u32le(TEXT_RVA).u32le(blockSize);
    for (const e of entries) rw.u16le(e);
    const relocBytes = rw.toUint8Array();
    sections.push({
      name: '.reloc',
      rva: relocRva,
      virtualSize: relocBytes.length,
      rawBytes: relocBytes,
      characteristics: 0x42000040,
    });
    dataDirs.set(5, { rva: relocRva, size: relocBytes.length });
  }

  return assemblePeFile({
    is64: false,
    subsystem,
    imageBase: IMAGE_BASE,
    sections,
    entryPointRva: TEXT_RVA,
    baseOfCode: TEXT_RVA,
    baseOfData: RDATA_RVA,
    dataDirs,
    includeReloc,
    addCertTableRawOffset: false,
  });
}

// ============================================================================
// 3. Windows .msix Package, .msi OLE CFBF Installer, and .bat / .cmd Scripts
// ============================================================================

export function buildCustomMsix({
  identityName = 'OmniOS.DynamicApp',
  publisher = 'CN=OmniOS',
  version = '1.0.0.0',
  displayName = 'OmniOS MSIX App',
  executable = 'app.exe',
  capabilities = ['runFullTrust'],
  exeBuffer = null,
  exeOptions = null,
} = {}) {
  const exeBytes = exeBuffer ?? buildCustomPe64Exe(exeOptions ?? { message: `${displayName}\n`, exitCode: 0 });

  const capLines = capabilities
    .map((cap) => `    <rescap:Capability Name="${escapeXml(cap)}" />`)
    .join('\n');

  const manifestXml = [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"',
    '         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"',
    '         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">',
    `  <Identity Name="${escapeXml(identityName)}" Publisher="${escapeXml(publisher)}" Version="${escapeXml(version)}" ProcessorArchitecture="x64" />`,
    '  <Properties>',
    `    <DisplayName>${escapeXml(displayName)}</DisplayName>`,
    '    <PublisherDisplayName>OmniOS</PublisherDisplayName>',
    '  </Properties>',
    '  <Dependencies>',
    '    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" />',
    '  </Dependencies>',
    '  <Applications>',
    `    <Application Id="App" Executable="${escapeXml(executable)}" EntryPoint="Windows.FullTrustApplication">`,
    `      <uap:VisualElements DisplayName="${escapeXml(displayName)}" Description="${escapeXml(displayName)}" BackgroundColor="transparent" />`,
    '    </Application>',
    '  </Applications>',
    '  <Capabilities>',
    capLines,
    '  </Capabilities>',
    '</Package>',
    '',
  ].join('\n');

  const manifestBytes = textEncoder.encode(manifestXml);

  const contentTypesXml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
    '  <Default Extension="xml" ContentType="application/vnd.ms-appx.manifest+xml" />',
    '  <Default Extension="exe" ContentType="application/octet-stream" />',
    '</Types>',
    '',
  ].join('\n');

  function renderBlockMapFile(name, dataBytes) {
    const lfhSize = 30 + textEncoder.encode(name).length;
    const blocks = [];
    const chunkSize = 65536;
    for (let off = 0; off < dataBytes.length; off += chunkSize) {
      const slice = dataBytes.subarray(off, Math.min(off + chunkSize, dataBytes.length));
      blocks.push(`    <Block Hash="${sha256Base64(slice)}" />`);
    }
    if (blocks.length === 0) {
      blocks.push(`    <Block Hash="${sha256Base64(new Uint8Array(0))}" />`);
    }
    return [
      `  <File Name="${escapeXml(name)}" Size="${dataBytes.length}" LfhSize="${lfhSize}">`,
      ...blocks,
      '  </File>',
    ].join('\n');
  }

  const blockMapXml = [
    '<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
    '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">',
    renderBlockMapFile('AppxManifest.xml', manifestBytes),
    renderBlockMapFile(executable, exeBytes),
    '</BlockMap>',
    '',
  ].join('\n');

  return buildZip(
    [
      { name: 'AppxManifest.xml', data: manifestBytes, method: 0 },
      { name: executable, data: exeBytes, method: 0 },
      { name: 'AppxBlockMap.xml', data: textEncoder.encode(blockMapXml), method: 0 },
      { name: '[Content_Types].xml', data: textEncoder.encode(contentTypesXml), method: 0 },
    ],
    { utf8Flag: true }
  );
}

function buildOleSummaryInfoStream({ title, subject, author, comments }) {
  const props = [
    { id: 1, type: 0x0002, value: 1252 }, // PIDSI_CODEPAGE (VT_I2)
    { id: 2, type: 0x001e, value: String(title) }, // PIDSI_TITLE (VT_LPSTR)
    { id: 3, type: 0x001e, value: String(subject) }, // PIDSI_SUBJECT
    { id: 4, type: 0x001e, value: String(author) }, // PIDSI_AUTHOR
    { id: 6, type: 0x001e, value: String(comments) }, // PIDSI_COMMENTS
  ];

  // Build PropertySet0 payload
  const propSet = new BinaryWriter(256);
  const headerLen = 8 + props.length * 8;
  propSet.u32le(0).u32le(props.length).zeros(props.length * 8);

  for (let i = 0; i < props.length; i++) {
    const p = props[i];
    const relOff = propSet.pos;
    propSet.patchU32le(8 + i * 8, p.id);
    propSet.patchU32le(8 + i * 8 + 4, relOff);

    if (p.type === 0x0002) {
      propSet.u32le(0x0002).u16le(p.value).u16le(0);
    } else {
      const strBytes = concatBytes(textEncoder.encode(p.value), [0]);
      propSet.u32le(0x001e).u32le(strBytes.length).bytes(strBytes).align(4);
    }
  }
  propSet.patchU32le(0, propSet.length);
  const propSetBytes = propSet.toUint8Array();

  // PropertySetStream header (48B)
  const w = new BinaryWriter(48 + propSetBytes.length);
  w.u16le(0xfffe) // ByteOrder
    .u16le(0x0000) // Version
    .u32le(0x00060002) // SystemIdentifier: Windows 6.0
    .zeros(16) // CLSID
    .u32le(1) // NumPropertySets
    // FMTID_SummaryInformation {F29F85E0-4FF9-1068-AB91-08002B27B3D9}
    .bytes([0xe0, 0x85, 0x9f, 0xf2, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27, 0xb3, 0xd9])
    .u32le(48) // Offset0
    .bytes(propSetBytes);

  return w.toUint8Array();
}

function compareCfbfNames(a, b) {
  if (a.length !== b.length) return a.length - b.length;
  const ua = a.toUpperCase();
  const ub = b.toUpperCase();
  for (let i = 0; i < ua.length; i++) {
    const d = ua.charCodeAt(i) - ub.charCodeAt(i);
    if (d !== 0) return d;
  }
  return 0;
}

/**
 * Builds a valid [MS-CFB] v3 OLE Compound Document .msi installer recognizable by host `file`.
 */
export function buildCustomMsi({
  productName = 'OmniOS Test Installer',
  productVersion = '1.0.0',
  manufacturer = 'OmniOS',
  productCode = '{11111111-2222-3333-4444-555555555555}',
  embeddedExe = null,
  extraStreams = [],
} = {}) {
  const SECTOR_SIZE = 512;
  const ENDOFCHAIN = 0xfffffffe;
  const FREESECT = 0xffffffff;
  const FATSECT = 0xfffffffd;
  const NOSTREAM = 0xffffffff;

  const summaryRaw = buildOleSummaryInfoStream({
    title: productName,
    subject: productVersion,
    author: manufacturer,
    comments: productCode,
  });

  const metaRaw = textEncoder.encode(
    `ProductName=${productName}\nProductVersion=${productVersion}\nManufacturer=${manufacturer}\nProductCode=${productCode}\n`
  );

  // Pad every stream to >= 4096 bytes (MiniStreamCutoffSize) so all streams live in standard FAT sectors
  const streams = [
    { name: '\x05SummaryInformation', raw: summaryRaw },
    { name: 'MsiMetadata', raw: metaRaw },
  ];
  if (embeddedExe) {
    streams.push({ name: 'Payload.exe', raw: embeddedExe instanceof Uint8Array ? embeddedExe : textEncoder.encode(String(embeddedExe)) });
  }
  for (const extra of extraStreams) {
    streams.push({
      name: String(extra.name),
      raw: extra.data instanceof Uint8Array ? extra.data : textEncoder.encode(String(extra.data ?? '')),
    });
  }

  // Sort streams by CFBF Red-Black tree ordering: (length ASC, uppercase UTF-16 ASC)
  streams.sort((a, b) => compareCfbfNames(a.name, b.name));

  // Prepare padded sector buffers (>= 4096 bytes each)
  const prepared = streams.map((st) => {
    const logicalLen = Math.max(st.raw.length, 4096);
    const paddedLen = alignUp(logicalLen, SECTOR_SIZE);
    const padded = new Uint8Array(paddedLen);
    padded.set(st.raw, 0);
    return {
      name: st.name,
      streamSize: logicalLen,
      sectorCount: paddedLen / SECTOR_SIZE,
      padded,
    };
  });

  // Directory sectors: 1 Root Entry + prepared.length stream entries (4 entries per 512B sector)
  const totalDirEntries = 1 + prepared.length;
  const numDirSectors = Math.ceil(totalDirEntries / 4);
  const totalDataSectors = prepared.reduce((acc, s) => acc + s.sectorCount, 0);

  // Iteratively determine FAT sector count (each FAT sector holds 128 sector entries)
  let numFatSectors = 1;
  while ((numFatSectors + numDirSectors + totalDataSectors) > numFatSectors * 128) {
    numFatSectors++;
  }

  const firstDirSector = numFatSectors;
  let nextSector = firstDirSector + numDirSectors;

  // Build FAT table
  const fatEntries = new Uint32Array(numFatSectors * 128);
  fatEntries.fill(FREESECT);

  for (let i = 0; i < numFatSectors; i++) {
    fatEntries[i] = FATSECT;
  }
  for (let i = 0; i < numDirSectors; i++) {
    fatEntries[firstDirSector + i] = i + 1 < numDirSectors ? (firstDirSector + i + 1) : ENDOFCHAIN;
  }

  for (const st of prepared) {
    st.startSector = nextSector;
    for (let i = 0; i < st.sectorCount; i++) {
      fatEntries[nextSector + i] = i + 1 < st.sectorCount ? (nextSector + i + 1) : ENDOFCHAIN;
    }
    nextSector += st.sectorCount;
  }

  // Build balanced binary tree over directory entries 1..prepared.length
  const dirNodes = prepared.map((st, idx) => ({
    did: idx + 1,
    st,
    left: NOSTREAM,
    right: NOSTREAM,
    color: 1, // black default
  }));

  function buildTree(lo, hi, depth) {
    if (lo > hi) return NOSTREAM;
    const mid = (lo + hi) >> 1;
    const node = dirNodes[mid];
    node.color = (depth % 2 === 0) ? 1 : 0;
    node.left = buildTree(lo, mid - 1, depth + 1);
    node.right = buildTree(mid + 1, hi, depth + 1);
    return node.did;
  }
  const rootChildId = buildTree(0, dirNodes.length - 1, 0);

  // Assemble Directory Sectors (128 bytes per entry)
  const dirWriter = new BinaryWriter(numDirSectors * SECTOR_SIZE);
  function writeDirEntry({ name, objType, color, left, right, child, clsid = null, startSec = 0, size = 0 }) {
    const startPos = dirWriter.pos;
    const nameLenBytes = name.length > 0 ? (name.length + 1) * 2 : 0;
    dirWriter.fixedUtf16le(name, 32); // 64 bytes
    dirWriter.u16le(nameLenBytes); // 66
    dirWriter.u8(objType); // 67
    dirWriter.u8(color); // 68
    dirWriter.u32le(left); // 72
    dirWriter.u32le(right); // 76
    dirWriter.u32le(child); // 80
    if (clsid) dirWriter.bytes(clsid);
    else dirWriter.zeros(16); // 96
    dirWriter.u32le(0); // state bits (100)
    dirWriter.zeros(16); // timestamps (116)
    dirWriter.u32le(startSec); // 120
    dirWriter.u64le(BigInt(size)); // 128
    if (dirWriter.pos - startPos !== 128) {
      throw new Error(`CFBF directory entry size mismatch: ${dirWriter.pos - startPos}`);
    }
  }

  // Entry 0: Root Entry with MSI CLSID {000C1084-0000-0000-C000-000000000046}
  const MSI_CLSID = [0x84, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
  writeDirEntry({
    name: 'Root Entry',
    objType: 5, // Root Storage
    color: 1, // Black
    left: NOSTREAM,
    right: NOSTREAM,
    child: rootChildId,
    clsid: MSI_CLSID,
    startSec: ENDOFCHAIN,
    size: 0,
  });

  for (const node of dirNodes) {
    writeDirEntry({
      name: node.st.name,
      objType: 2, // Stream Object
      color: node.color,
      left: node.left,
      right: node.right,
      child: NOSTREAM,
      startSec: node.st.startSector,
      size: node.st.streamSize,
    });
  }
  const remDirBytes = numDirSectors * SECTOR_SIZE - dirWriter.length;
  if (remDirBytes > 0) dirWriter.zeros(remDirBytes);

  // Assemble 512-byte CFBF v3 Header
  const out = new BinaryWriter((1 + nextSector) * SECTOR_SIZE);
  out
    .bytes([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) // Signature
    .zeros(16) // CLSID
    .u16le(0x003e) // MinorVersion
    .u16le(0x0003) // MajorVersion (v3)
    .u16le(0xfffe) // ByteOrder (little-endian)
    .u16le(9) // SectorShift (512B)
    .u16le(6) // MiniSectorShift (64B)
    .zeros(6) // Reserved
    .u32le(0) // NumberOfDirectorySectors (0 for v3)
    .u32le(numFatSectors) // NumberOfFATSectors
    .u32le(firstDirSector) // FirstDirectorySectorLocation
    .u32le(0) // TransactionSignatureNumber
    .u32le(0x1000) // MiniStreamCutoffSize (4096)
    .u32le(ENDOFCHAIN) // FirstMiniFATSectorLocation
    .u32le(0) // NumberOfMiniFATSectors
    .u32le(ENDOFCHAIN) // FirstDIFATSectorLocation
    .u32le(0); // NumberOfDIFATSectors

  // 109 DIFAT entries (436 bytes -> total header = 76 + 436 = 512 bytes)
  for (let i = 0; i < 109; i++) {
    out.u32le(i < numFatSectors ? i : FREESECT);
  }

  // FAT Sectors
  for (let i = 0; i < fatEntries.length; i++) {
    out.u32le(fatEntries[i]);
  }

  // Directory Sectors
  out.bytes(dirWriter.toUint8Array());

  // Stream Data Sectors
  for (const st of prepared) {
    out.bytes(st.padded);
  }

  return out.toUint8Array();
}

export function buildBatScript({
  vars = {},
  computeA,
  computeB,
  computeVar = 'RESULT',
  echoMessage,
  outputFile,
  outputContent,
  lines = [],
  exitCode = 0,
} = {}) {
  const out = ['@ECHO OFF'];
  for (const [k, v] of Object.entries(vars)) {
    out.push(`SET ${k}=${v}`);
  }
  if (computeA !== undefined && computeB !== undefined) {
    out.push(`SET /A ${computeVar}=${Number(computeA)}+${Number(computeB)}`);
    out.push(`ECHO ${computeVar}=%${computeVar}%`);
  }
  if (echoMessage !== undefined) {
    out.push(`ECHO ${echoMessage}`);
  }
  if (outputFile) {
    out.push(`ECHO ${outputContent ?? echoMessage ?? 'OK'}>${outputFile}`);
  }
  for (const line of lines) {
    out.push(String(line));
  }
  out.push(`EXIT /B ${exitCode}`);
  return `${out.join('\r\n')}\r\n`;
}

export function buildCmdScript(options = {}) {
  return buildBatScript(options);
}

/**
 * Edge Case #18: Identical script whose ERRORLEVEL diverges between .bat (preserves failCode)
 * and .cmd (resets ERRORLEVEL to 0 after a successful SET).
 */
export function buildErrorlevelSemanticsScript({
  failCode = 7,
  markerVar = 'OMNI_OK',
  markerVal = '1',
} = {}) {
  return [
    '@ECHO OFF',
    'CALL :SETERR',
    `SET ${markerVar}=${markerVal}`,
    'ECHO EL=%ERRORLEVEL%',
    'EXIT /B %ERRORLEVEL%',
    ':SETERR',
    `EXIT /B ${failCode}`,
    '',
  ].join('\r\n');
}
