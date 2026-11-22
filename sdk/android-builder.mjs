/**
 * OmniOS Pure-JS Android SDK Builder (`sdk/android-builder.mjs`, F-046)
 * Deterministically assembles authentic, externally verifiable `.apk` packages:
 * - Real Dalvik bytecode assembler (`DALVIK_ASM`) & DEX v035–v041 binary emitter (`assembleDex`)
 *   with verified Adler-32 (`bytes[0x0c..]`) and SHA-1 (`bytes[0x20..]`) checksums
 * - Real Binary AXML (`encodeAxml`) manifests & layouts + compiled `resources.arsc` (`encodeResourcesArsc`)
 * - Real ZIP (`createZip`) + APK Signing Block v2/v3 (`appendApkSigningBlock`, `"APK Sig Block 42"`)
 *   passing Python 3 `zipfile.ZipFile.testzip() is None`
 * - Parameterized `buildCustomApk(spec)` for arbitrary dynamic APKs + sample builders:
 *   `packages/android-calc.apk` (`com.omnios.calc`) & `packages/android-notes-sharer.apk` (`com.omnios.notes`).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BinaryWriter,
  adler32,
  encodeUleb128,
  encodeSleb128,
  encodeMutf8,
} from '../os/common/binary.mjs';
import { createZip, listZipEntries, ZIP_SIGNATURES } from '../os/pkg/zip.mjs';
import { encodeAxml, RES_VALUE_TYPES } from '../os/runtimes/android/axml-parser.mjs';
import { encodeResourcesArsc } from '../os/runtimes/android/resources-arsc.mjs';
import { DEX_ACCESS_FLAGS, DEX_ENDIAN_CONSTANT, DEX_NO_INDEX } from '../os/runtimes/android/dex-parser.mjs';
import { APK_SIG_BLOCK_MAGIC, APK_SIG_SCHEME_IDS } from '../os/runtimes/android/apk-parser.mjs';

const TEXT_ENCODER = new TextEncoder();

// =============================================================================
// Dalvik Bytecode Assembler DSL (`DALVIK_ASM`)
// =============================================================================

function parseMethodDescriptor(descriptor) {
  const closeIdx = descriptor.indexOf(')');
  if (!descriptor.startsWith('(') || closeIdx === -1) {
    throw new Error(`Invalid Dalvik method descriptor: ${descriptor}`);
  }
  const paramStr = descriptor.slice(1, closeIdx);
  const returnType = descriptor.slice(closeIdx + 1);
  const params = [];
  let i = 0;
  while (i < paramStr.length) {
    let start = i;
    while (paramStr[i] === '[') i++;
    if (paramStr[i] === 'L') {
      const semi = paramStr.indexOf(';', i);
      if (semi === -1) throw new Error(`Unterminated object type in descriptor: ${descriptor}`);
      i = semi + 1;
    } else {
      i += 1;
    }
    params.push(paramStr.slice(start, i));
  }
  const toShorty = (t) => (t.startsWith('L') || t.startsWith('[') ? 'L' : t);
  const shorty = toShorty(returnType) + params.map(toShorty).join('');
  return { shorty, returnType, params, descriptor };
}

function insn10x(op) { return { fmt: '10x', op, units: 1 }; }
function insn12x(op, a, b) { return { fmt: '12x', op, a, b, units: 1 }; }
function insn11n(op, a, b) { return { fmt: '11n', op, a, b, units: 1 }; }
function insn11x(op, aa) { return { fmt: '11x', op, aa, units: 1 }; }
function insn10t(op, target) { return { fmt: '10t', op, target, units: 1 }; }
function insn20t(op, target) { return { fmt: '20t', op, target, units: 2 }; }
function insn30t(op, target) { return { fmt: '30t', op, target, units: 3 }; }
function insn22x(op, aa, bbbb) { return { fmt: '22x', op, aa, bbbb, units: 2 }; }
function insn21s(op, aa, imm) { return { fmt: '21s', op, aa, imm, units: 2 }; }
function insn21h(op, aa, imm) { return { fmt: '21h', op, aa, imm, units: 2 }; }
function insn31i(op, aa, imm) { return { fmt: '31i', op, aa, imm, units: 3 }; }
function insn51l(op, aa, imm64) { return { fmt: '51l', op, aa, imm64: BigInt(imm64), units: 5 }; }
function insn21t(op, aa, target) { return { fmt: '21t', op, aa, target, units: 2 }; }
function insn22t(op, a, b, target) { return { fmt: '22t', op, a, b, target, units: 2 }; }
function insn23x(op, aa, bb, cc) { return { fmt: '23x', op, aa, bb, cc, units: 2 }; }
function insn22s(op, a, b, lit) { return { fmt: '22s', op, a, b, lit, units: 2 }; }
function insn22b(op, aa, bb, lit) { return { fmt: '22b', op, aa, bb, lit, units: 2 }; }
function insn31t(op, aa, target) { return { fmt: '31t', op, aa, target, units: 3 }; }
function insn21c(op, aa, refKind, ref) { return { fmt: '21c', op, aa, refKind, ref, units: 2 }; }
function insn31c(op, aa, refKind, ref) { return { fmt: '31c', op, aa, refKind, ref, units: 3 }; }
function insn22c(op, a, b, refKind, ref) { return { fmt: '22c', op, a, b, refKind, ref, units: 2 }; }
function insn35c(op, regs, refKind, ref) { return { fmt: '35c', op, regs, refKind, ref, units: 3 }; }
function insn3rc(op, firstReg, count, refKind, ref) { return { fmt: '3rc', op, firstReg, count, refKind, ref, units: 3 }; }

export const DALVIK_ASM = Object.freeze({
  label: (name) => ({ fmt: 'label', name, units: 0 }),
  nop: () => insn10x(0x00),
  move: (a, b) => insn12x(0x01, a, b),
  moveFrom16: (aa, bbbb) => insn22x(0x02, aa, bbbb),
  moveWide: (a, b) => insn12x(0x04, a, b),
  moveWideFrom16: (aa, bbbb) => insn22x(0x05, aa, bbbb),
  moveObject: (a, b) => insn12x(0x07, a, b),
  moveObjectFrom16: (aa, bbbb) => insn22x(0x08, aa, bbbb),
  moveResult: (aa) => insn11x(0x0a, aa),
  moveResultWide: (aa) => insn11x(0x0b, aa),
  moveResultObject: (aa) => insn11x(0x0c, aa),
  moveException: (aa) => insn11x(0x0d, aa),
  returnVoid: () => insn10x(0x0e),
  returnVal: (aa) => insn11x(0x0f, aa),
  returnWide: (aa) => insn11x(0x10, aa),
  returnObject: (aa) => insn11x(0x11, aa),

  const4: (a, imm) => insn11n(0x12, a, imm),
  const16: (aa, imm) => insn21s(0x13, aa, imm),
  const32: (aa, imm) => insn31i(0x14, aa, imm),
  constHigh16: (aa, imm) => insn21h(0x15, aa, imm),
  constWide16: (aa, imm) => insn21s(0x16, aa, imm),
  constWide32: (aa, imm) => insn31i(0x17, aa, imm),
  constWide: (aa, imm64) => insn51l(0x18, aa, imm64),
  constWideHigh16: (aa, imm) => insn21h(0x19, aa, imm),
  constString: (aa, str) => insn21c(0x1a, aa, 'string', String(str)),
  constStringJumbo: (aa, str) => insn31c(0x1b, aa, 'string', String(str)),
  constClass: (aa, typeDesc) => insn21c(0x1c, aa, 'type', typeDesc),

  monitorEnter: (aa) => insn11x(0x1d, aa),
  monitorExit: (aa) => insn11x(0x1e, aa),
  checkCast: (aa, typeDesc) => insn21c(0x1f, aa, 'type', typeDesc),
  instanceOf: (a, b, typeDesc) => insn22c(0x20, a, b, 'type', typeDesc),
  arrayLength: (a, b) => insn12x(0x21, a, b),
  newInstance: (aa, typeDesc) => insn21c(0x22, aa, 'type', typeDesc),
  newArray: (a, b, arrayType) => insn22c(0x23, a, b, 'type', arrayType),
  filledNewArray: (regs, arrayType) => insn35c(0x24, regs, 'type', arrayType),
  filledNewArrayRange: (firstReg, count, arrayType) => insn3rc(0x25, firstReg, count, 'type', arrayType),
  fillArrayData: (aa, payloadLabel) => insn31t(0x26, aa, payloadLabel),
  throwEx: (aa) => insn11x(0x27, aa),

  goto: (target) => insn10t(0x28, target),
  goto16: (target) => insn20t(0x29, target),
  goto32: (target) => insn30t(0x2a, target),
  packedSwitch: (aa, payloadLabel) => insn31t(0x2b, aa, payloadLabel),
  sparseSwitch: (aa, payloadLabel) => insn31t(0x2c, aa, payloadLabel),

  cmplFloat: (aa, bb, cc) => insn23x(0x2d, aa, bb, cc),
  cmpgFloat: (aa, bb, cc) => insn23x(0x2e, aa, bb, cc),
  cmplDouble: (aa, bb, cc) => insn23x(0x2f, aa, bb, cc),
  cmpgDouble: (aa, bb, cc) => insn23x(0x30, aa, bb, cc),
  cmpLong: (aa, bb, cc) => insn23x(0x31, aa, bb, cc),

  ifEq: (a, b, target) => insn22t(0x32, a, b, target),
  ifNe: (a, b, target) => insn22t(0x33, a, b, target),
  ifLt: (a, b, target) => insn22t(0x34, a, b, target),
  ifGe: (a, b, target) => insn22t(0x35, a, b, target),
  ifGt: (a, b, target) => insn22t(0x36, a, b, target),
  ifLe: (a, b, target) => insn22t(0x37, a, b, target),
  ifEqz: (aa, target) => insn21t(0x38, aa, target),
  ifNez: (aa, target) => insn21t(0x39, aa, target),
  ifLtz: (aa, target) => insn21t(0x3a, aa, target),
  ifGez: (aa, target) => insn21t(0x3b, aa, target),
  ifGtz: (aa, target) => insn21t(0x3c, aa, target),
  ifLez: (aa, target) => insn21t(0x3d, aa, target),

  aget: (aa, arr, idx) => insn23x(0x44, aa, arr, idx),
  agetWide: (aa, arr, idx) => insn23x(0x45, aa, arr, idx),
  agetObject: (aa, arr, idx) => insn23x(0x46, aa, arr, idx),
  agetBoolean: (aa, arr, idx) => insn23x(0x47, aa, arr, idx),
  agetByte: (aa, arr, idx) => insn23x(0x48, aa, arr, idx),
  agetChar: (aa, arr, idx) => insn23x(0x49, aa, arr, idx),
  agetShort: (aa, arr, idx) => insn23x(0x4a, aa, arr, idx),
  aput: (aa, arr, idx) => insn23x(0x4b, aa, arr, idx),
  aputWide: (aa, arr, idx) => insn23x(0x4c, aa, arr, idx),
  aputObject: (aa, arr, idx) => insn23x(0x4d, aa, arr, idx),
  aputBoolean: (aa, arr, idx) => insn23x(0x4e, aa, arr, idx),
  aputByte: (aa, arr, idx) => insn23x(0x4f, aa, arr, idx),
  aputChar: (aa, arr, idx) => insn23x(0x50, aa, arr, idx),
  aputShort: (aa, arr, idx) => insn23x(0x51, aa, arr, idx),

  iget: (a, obj, cls, name, type) => insn22c(0x52, a, obj, 'field', { cls, name, type }),
  igetWide: (a, obj, cls, name, type) => insn22c(0x53, a, obj, 'field', { cls, name, type }),
  igetObject: (a, obj, cls, name, type) => insn22c(0x54, a, obj, 'field', { cls, name, type }),
  igetBoolean: (a, obj, cls, name, type) => insn22c(0x55, a, obj, 'field', { cls, name, type }),
  iput: (a, obj, cls, name, type) => insn22c(0x59, a, obj, 'field', { cls, name, type }),
  iputWide: (a, obj, cls, name, type) => insn22c(0x5a, a, obj, 'field', { cls, name, type }),
  iputObject: (a, obj, cls, name, type) => insn22c(0x5b, a, obj, 'field', { cls, name, type }),
  iputBoolean: (a, obj, cls, name, type) => insn22c(0x5c, a, obj, 'field', { cls, name, type }),

  sget: (aa, cls, name, type) => insn21c(0x60, aa, 'field', { cls, name, type }),
  sgetWide: (aa, cls, name, type) => insn21c(0x61, aa, 'field', { cls, name, type }),
  sgetObject: (aa, cls, name, type) => insn21c(0x62, aa, 'field', { cls, name, type }),
  sgetBoolean: (aa, cls, name, type) => insn21c(0x63, aa, 'field', { cls, name, type }),
  sput: (aa, cls, name, type) => insn21c(0x67, aa, 'field', { cls, name, type }),
  sputWide: (aa, cls, name, type) => insn21c(0x68, aa, 'field', { cls, name, type }),
  sputObject: (aa, cls, name, type) => insn21c(0x69, aa, 'field', { cls, name, type }),
  sputBoolean: (aa, cls, name, type) => insn21c(0x6a, aa, 'field', { cls, name, type }),

  invokeVirtual: (regs, cls, name, descriptor) => insn35c(0x6e, regs, 'method', { cls, name, descriptor }),
  invokeSuper: (regs, cls, name, descriptor) => insn35c(0x6f, regs, 'method', { cls, name, descriptor }),
  invokeDirect: (regs, cls, name, descriptor) => insn35c(0x70, regs, 'method', { cls, name, descriptor }),
  invokeStatic: (regs, cls, name, descriptor) => insn35c(0x71, regs, 'method', { cls, name, descriptor }),
  invokeInterface: (regs, cls, name, descriptor) => insn35c(0x72, regs, 'method', { cls, name, descriptor }),
  invokeVirtualRange: (first, count, cls, name, descriptor) => insn3rc(0x74, first, count, 'method', { cls, name, descriptor }),
  invokeSuperRange: (first, count, cls, name, descriptor) => insn3rc(0x75, first, count, 'method', { cls, name, descriptor }),
  invokeDirectRange: (first, count, cls, name, descriptor) => insn3rc(0x76, first, count, 'method', { cls, name, descriptor }),
  invokeStaticRange: (first, count, cls, name, descriptor) => insn3rc(0x77, first, count, 'method', { cls, name, descriptor }),
  invokeInterfaceRange: (first, count, cls, name, descriptor) => insn3rc(0x78, first, count, 'method', { cls, name, descriptor }),

  negInt: (a, b) => insn12x(0x7b, a, b),
  notInt: (a, b) => insn12x(0x7c, a, b),
  negLong: (a, b) => insn12x(0x7d, a, b),
  intToLong: (a, b) => insn12x(0x81, a, b),
  intToFloat: (a, b) => insn12x(0x82, a, b),
  intToDouble: (a, b) => insn12x(0x83, a, b),
  longToInt: (a, b) => insn12x(0x84, a, b),
  floatToInt: (a, b) => insn12x(0x87, a, b),
  doubleToInt: (a, b) => insn12x(0x8a, a, b),

  addInt: (aa, bb, cc) => insn23x(0x90, aa, bb, cc),
  subInt: (aa, bb, cc) => insn23x(0x91, aa, bb, cc),
  mulInt: (aa, bb, cc) => insn23x(0x92, aa, bb, cc),
  divInt: (aa, bb, cc) => insn23x(0x93, aa, bb, cc),
  remInt: (aa, bb, cc) => insn23x(0x94, aa, bb, cc),
  andInt: (aa, bb, cc) => insn23x(0x95, aa, bb, cc),
  orInt: (aa, bb, cc) => insn23x(0x96, aa, bb, cc),
  xorInt: (aa, bb, cc) => insn23x(0x97, aa, bb, cc),
  shlInt: (aa, bb, cc) => insn23x(0x98, aa, bb, cc),
  shrInt: (aa, bb, cc) => insn23x(0x99, aa, bb, cc),
  ushrInt: (aa, bb, cc) => insn23x(0x9a, aa, bb, cc),

  addLong: (aa, bb, cc) => insn23x(0x9b, aa, bb, cc),
  subLong: (aa, bb, cc) => insn23x(0x9c, aa, bb, cc),
  mulLong: (aa, bb, cc) => insn23x(0x9d, aa, bb, cc),
  divLong: (aa, bb, cc) => insn23x(0x9e, aa, bb, cc),
  remLong: (aa, bb, cc) => insn23x(0x9f, aa, bb, cc),

  addFloat: (aa, bb, cc) => insn23x(0xa6, aa, bb, cc),
  subFloat: (aa, bb, cc) => insn23x(0xa7, aa, bb, cc),
  mulFloat: (aa, bb, cc) => insn23x(0xa8, aa, bb, cc),
  divFloat: (aa, bb, cc) => insn23x(0xa9, aa, bb, cc),

  addDouble: (aa, bb, cc) => insn23x(0xab, aa, bb, cc),
  subDouble: (aa, bb, cc) => insn23x(0xac, aa, bb, cc),
  mulDouble: (aa, bb, cc) => insn23x(0xad, aa, bb, cc),
  divDouble: (aa, bb, cc) => insn23x(0xae, aa, bb, cc),

  addInt2Addr: (a, b) => insn12x(0xb0, a, b),
  subInt2Addr: (a, b) => insn12x(0xb1, a, b),
  mulInt2Addr: (a, b) => insn12x(0xb2, a, b),
  divInt2Addr: (a, b) => insn12x(0xb3, a, b),
  remInt2Addr: (a, b) => insn12x(0xb4, a, b),

  addIntLit16: (a, b, lit) => insn22s(0xd0, a, b, lit),
  rsubInt: (a, b, lit) => insn22s(0xd1, a, b, lit),
  mulIntLit16: (a, b, lit) => insn22s(0xd2, a, b, lit),
  divIntLit16: (a, b, lit) => insn22s(0xd3, a, b, lit),
  remIntLit16: (a, b, lit) => insn22s(0xd4, a, b, lit),

  addIntLit8: (aa, bb, lit) => insn22b(0xd8, aa, bb, lit),
  rsubIntLit8: (aa, bb, lit) => insn22b(0xd9, aa, bb, lit),
  mulIntLit8: (aa, bb, lit) => insn22b(0xda, aa, bb, lit),
  divIntLit8: (aa, bb, lit) => insn22b(0xdb, aa, bb, lit),
  remIntLit8: (aa, bb, lit) => insn22b(0xdc, aa, bb, lit),
  andIntLit8: (aa, bb, lit) => insn22b(0xdd, aa, bb, lit),
  orIntLit8: (aa, bb, lit) => insn22b(0xde, aa, bb, lit),
  xorIntLit8: (aa, bb, lit) => insn22b(0xdf, aa, bb, lit),
  shlIntLit8: (aa, bb, lit) => insn22b(0xe0, aa, bb, lit),
  shrIntLit8: (aa, bb, lit) => insn22b(0xe1, aa, bb, lit),
  ushrIntLit8: (aa, bb, lit) => insn22b(0xe2, aa, bb, lit),

  packedSwitchPayload: (labelName, switchLabel, firstKey, targetLabels) => ({
    fmt: 'packed-switch-payload',
    labelName,
    switchLabel,
    firstKey,
    targetLabels,
    units: 4 + targetLabels.length * 2,
  }),
  sparseSwitchPayload: (labelName, switchLabel, entries) => ({
    fmt: 'sparse-switch-payload',
    labelName,
    switchLabel,
    entries: [...entries].sort((a, b) => a[0] - b[0]),
    units: 2 + entries.length * 4,
  }),
  fillArrayDataPayload: (labelName, elementWidth, values) => ({
    fmt: 'fill-array-data-payload',
    labelName,
    elementWidth,
    values,
    units: 4 + Math.ceil((values.length * elementWidth) / 2),
  }),
});

function compareMutf8Bytes(a, b) {
  const ba = encodeMutf8(a);
  const bb = encodeMutf8(b);
  const len = Math.min(ba.byteLength, bb.byteLength);
  for (let i = 0; i < len; i++) {
    if (ba[i] !== bb[i]) return ba[i] - bb[i];
  }
  return ba.byteLength - bb.byteLength;
}

// =============================================================================
// Pure-JS Deterministic DEX Binary Assembler (`assembleDex`)
// =============================================================================

export function assembleDex({ version = '035', classes = [] } = {}) {
  const isV41 = version === '041';
  const headerSize = isV41 ? 0x78 : 0x70;

  const stringSet = new Set();
  const typeSet = new Set();
  const protoMap = new Map(); // descriptor -> parsedProto
  const fieldMap = new Map(); // key -> { cls, name, type }
  const methodMap = new Map(); // key -> { cls, name, descriptor }

  const addString = (s) => stringSet.add(String(s));
  const addType = (t) => { addString(t); typeSet.add(t); };
  const addProto = (desc) => {
    if (protoMap.has(desc)) return protoMap.get(desc);
    const parsed = parseMethodDescriptor(desc);
    addString(parsed.shorty);
    addType(parsed.returnType);
    for (const p of parsed.params) addType(p);
    protoMap.set(desc, parsed);
    return parsed;
  };
  const addField = ({ cls, name, type }) => {
    const key = `${cls}->${name}:${type}`;
    if (!fieldMap.has(key)) {
      addType(cls);
      addType(type);
      addString(name);
      fieldMap.set(key, { cls, name, type, key });
    }
    return key;
  };
  const addMethod = ({ cls, name, descriptor }) => {
    const key = `${cls}->${name}${descriptor}`;
    if (!methodMap.has(key)) {
      addType(cls);
      addString(name);
      addProto(descriptor);
      methodMap.set(key, { cls, name, descriptor, key });
    }
    return key;
  };

  // Pass 1: collect all constant pool references across classes, fields, methods, bytecode, and try/catch
  for (const cls of classes) {
    addType(cls.type);
    if (cls.superclass) addType(cls.superclass);
    for (const iface of cls.interfaces ?? []) addType(iface);
    if (cls.sourceFile) addString(cls.sourceFile);

    for (const sf of cls.staticFields ?? []) addField({ cls: cls.type, name: sf.name, type: sf.type });
    for (const inf of cls.instanceFields ?? []) addField({ cls: cls.type, name: inf.name, type: inf.type });

    const allMethods = [...(cls.directMethods ?? []), ...(cls.virtualMethods ?? [])];
    for (const m of allMethods) {
      addMethod({ cls: cls.type, name: m.name, descriptor: m.descriptor });
      for (const insn of m.insns ?? []) {
        if (insn.refKind === 'string') addString(insn.ref);
        else if (insn.refKind === 'type') addType(insn.ref);
        else if (insn.refKind === 'field') addField(insn.ref);
        else if (insn.refKind === 'method') addMethod(insn.ref);
      }
      for (const t of m.tries ?? []) {
        for (const h of t.handlers ?? []) addType(h.type);
      }
    }
  }

  // Canonical DEX table sorting
  const sortedStrings = Array.from(stringSet).sort(compareMutf8Bytes);
  const strIdxMap = new Map(sortedStrings.map((s, i) => [s, i]));

  const sortedTypes = Array.from(typeSet).sort((a, b) => strIdxMap.get(a) - strIdxMap.get(b));
  const typeIdxMap = new Map(sortedTypes.map((t, i) => [t, i]));

  const sortedProtos = Array.from(protoMap.values()).sort((a, b) => {
    const rDiff = typeIdxMap.get(a.returnType) - typeIdxMap.get(b.returnType);
    if (rDiff !== 0) return rDiff;
    const minLen = Math.min(a.params.length, b.params.length);
    for (let i = 0; i < minLen; i++) {
      const pDiff = typeIdxMap.get(a.params[i]) - typeIdxMap.get(b.params[i]);
      if (pDiff !== 0) return pDiff;
    }
    return a.params.length - b.params.length;
  });
  const protoIdxMap = new Map(sortedProtos.map((p, i) => [p.descriptor, i]));

  const sortedFields = Array.from(fieldMap.values()).sort((a, b) => {
    const cDiff = typeIdxMap.get(a.cls) - typeIdxMap.get(b.cls);
    if (cDiff !== 0) return cDiff;
    const nDiff = strIdxMap.get(a.name) - strIdxMap.get(b.name);
    if (nDiff !== 0) return nDiff;
    return typeIdxMap.get(a.type) - typeIdxMap.get(b.type);
  });
  const fieldIdxMap = new Map(sortedFields.map((f, i) => [f.key, i]));

  const sortedMethods = Array.from(methodMap.values()).sort((a, b) => {
    const cDiff = typeIdxMap.get(a.cls) - typeIdxMap.get(b.cls);
    if (cDiff !== 0) return cDiff;
    const nDiff = strIdxMap.get(a.name) - strIdxMap.get(b.name);
    if (nDiff !== 0) return nDiff;
    return protoIdxMap.get(a.descriptor) - protoIdxMap.get(b.descriptor);
  });
  const methodIdxMap = new Map(sortedMethods.map((m, i) => [m.key, i]));

  // Compute fixed section offsets
  const stringIdsOff = sortedStrings.length > 0 ? headerSize : 0;
  const typeIdsOff = sortedTypes.length > 0 ? headerSize + sortedStrings.length * 4 : 0;
  const protoIdsOff = sortedProtos.length > 0 ? headerSize + sortedStrings.length * 4 + sortedTypes.length * 4 : 0;
  const fieldIdsOff =
    sortedFields.length > 0
      ? headerSize + sortedStrings.length * 4 + sortedTypes.length * 4 + sortedProtos.length * 12
      : 0;
  const methodIdsOff =
    sortedMethods.length > 0
      ? headerSize +
        sortedStrings.length * 4 +
        sortedTypes.length * 4 +
        sortedProtos.length * 12 +
        sortedFields.length * 8
      : 0;
  const classDefsOff =
    classes.length > 0
      ? headerSize +
        sortedStrings.length * 4 +
        sortedTypes.length * 4 +
        sortedProtos.length * 12 +
        sortedFields.length * 8 +
        sortedMethods.length * 8
      : 0;

  const dataOff =
    headerSize +
    sortedStrings.length * 4 +
    sortedTypes.length * 4 +
    sortedProtos.length * 12 +
    sortedFields.length * 8 +
    sortedMethods.length * 8 +
    classes.length * 32;

  const dataW = new BinaryWriter({ initialCapacity: 4096, littleEndian: true });
  const absOff = () => dataOff + dataW.length;

  // 1. Emit type_lists (proto params + class interfaces)
  const typeListCache = new Map();
  let typeListCount = 0;
  const typeListStartOff = absOff();
  const emitTypeList = (typeArray) => {
    if (!typeArray || typeArray.length === 0) return 0;
    const key = typeArray.join(',');
    if (typeListCache.has(key)) return typeListCache.get(key);
    dataW.align(4, 0);
    const off = absOff();
    dataW.u32le(typeArray.length);
    for (const t of typeArray) dataW.u16le(typeIdxMap.get(t));
    typeListCache.set(key, off);
    typeListCount += 1;
    return off;
  };

  const protoParamOffs = sortedProtos.map((p) => emitTypeList(p.params));
  const classInterfaceOffs = classes.map((c) => emitTypeList(c.interfaces ?? []));

  // 2. Emit string_data_items
  const stringDataStartOff = absOff();
  const stringDataOffs = new Uint32Array(sortedStrings.length);
  for (let i = 0; i < sortedStrings.length; i++) {
    stringDataOffs[i] = absOff();
    const str = sortedStrings[i];
    dataW.bytes(encodeUleb128(str.length));
    dataW.bytes(encodeMutf8(str, { nullTerminate: true }));
  }

  // Helper to assemble a method's bytecode instruction stream & code_item
  const encodeMethodCode = (m) => {
    if (!m.insns || m.insns.length === 0) return 0;

    // Pass A: compute label PCs (in 16-bit code units)
    const labels = new Map();
    let totalUnits = 0;
    for (const insn of m.insns) {
      if (insn.fmt === 'label') {
        labels.set(insn.name, totalUnits);
      } else if (insn.labelName) {
        // Align payload to 2-unit (4-byte) boundary if needed
        if ((totalUnits & 1) === 1) {
          totalUnits += 1;
        }
        labels.set(insn.labelName, totalUnits);
        totalUnits += insn.units;
      } else {
        totalUnits += insn.units;
      }
    }

    const resolveTarget = (target, pc) => {
      if (typeof target === 'number') return target;
      if (!labels.has(target)) {
        throw new Error(`Undefined Dalvik branch label "${target}" in ${m.name}`);
      }
      return labels.get(target) - pc;
    };

    const resolveRef = (refKind, ref) => {
      if (refKind === 'string') return strIdxMap.get(ref);
      if (refKind === 'type') return typeIdxMap.get(ref);
      if (refKind === 'field') return fieldIdxMap.get(`${ref.cls}->${ref.name}:${ref.type}`);
      if (refKind === 'method') return methodIdxMap.get(`${ref.cls}->${ref.name}${ref.descriptor}`);
      throw new Error(`Unknown Dalvik refKind: ${refKind}`);
    };

    // Pass B: emit 16-bit code units
    const units = [];
    let pc = 0;
    for (const insn of m.insns) {
      if (insn.fmt === 'label') continue;
      if (insn.labelName && (pc & 1) === 1) {
        units.push(0x0000); // nop padding for 4-byte aligned payload
        pc += 1;
      }
      switch (insn.fmt) {
        case '10x':
          units.push(insn.op & 0xff);
          break;
        case '12x':
          units.push((insn.op & 0xff) | ((insn.a & 0xf) << 8) | ((insn.b & 0xf) << 12));
          break;
        case '11n':
          units.push((insn.op & 0xff) | ((insn.a & 0xf) << 8) | ((insn.b & 0xf) << 12));
          break;
        case '11x':
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8));
          break;
        case '10t': {
          const off = resolveTarget(insn.target, pc);
          units.push((insn.op & 0xff) | ((off & 0xff) << 8));
          break;
        }
        case '20t': {
          const off = resolveTarget(insn.target, pc);
          units.push(insn.op & 0xff, off & 0xffff);
          break;
        }
        case '30t': {
          const off = resolveTarget(insn.target, pc) | 0;
          units.push(insn.op & 0xff, off & 0xffff, (off >>> 16) & 0xffff);
          break;
        }
        case '22x':
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8), insn.bbbb & 0xffff);
          break;
        case '21s':
        case '21h':
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8), insn.imm & 0xffff);
          break;
        case '31i': {
          const v = insn.imm | 0;
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8), v & 0xffff, (v >>> 16) & 0xffff);
          break;
        }
        case '51l': {
          const v = BigInt.asUintN(64, insn.imm64);
          units.push(
            (insn.op & 0xff) | ((insn.aa & 0xff) << 8),
            Number(v & 0xffffn),
            Number((v >> 16n) & 0xffffn),
            Number((v >> 32n) & 0xffffn),
            Number((v >> 48n) & 0xffffn)
          );
          break;
        }
        case '21t': {
          const off = resolveTarget(insn.target, pc);
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8), off & 0xffff);
          break;
        }
        case '22t': {
          const off = resolveTarget(insn.target, pc);
          units.push((insn.op & 0xff) | ((insn.a & 0xf) << 8) | ((insn.b & 0xf) << 12), off & 0xffff);
          break;
        }
        case '23x':
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8), (insn.bb & 0xff) | ((insn.cc & 0xff) << 8));
          break;
        case '22s':
          units.push((insn.op & 0xff) | ((insn.a & 0xf) << 8) | ((insn.b & 0xf) << 12), insn.lit & 0xffff);
          break;
        case '22b':
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8), (insn.bb & 0xff) | ((insn.lit & 0xff) << 8));
          break;
        case '31t': {
          const off = resolveTarget(insn.target, pc) | 0;
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8), off & 0xffff, (off >>> 16) & 0xffff);
          break;
        }
        case '21c': {
          const idx = resolveRef(insn.refKind, insn.ref);
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8), idx & 0xffff);
          break;
        }
        case '31c': {
          const idx = resolveRef(insn.refKind, insn.ref) >>> 0;
          units.push((insn.op & 0xff) | ((insn.aa & 0xff) << 8), idx & 0xffff, (idx >>> 16) & 0xffff);
          break;
        }
        case '22c': {
          const idx = resolveRef(insn.refKind, insn.ref);
          units.push((insn.op & 0xff) | ((insn.a & 0xf) << 8) | ((insn.b & 0xf) << 12), idx & 0xffff);
          break;
        }
        case '35c': {
          const idx = resolveRef(insn.refKind, insn.ref);
          const r = insn.regs ?? [];
          const count = r.length;
          const C = r[0] ?? 0;
          const D = r[1] ?? 0;
          const E = r[2] ?? 0;
          const F = r[3] ?? 0;
          const G = r[4] ?? 0;
          units.push(
            (insn.op & 0xff) | ((G & 0xf) << 8) | ((count & 0xf) << 12),
            idx & 0xffff,
            (C & 0xf) | ((D & 0xf) << 4) | ((E & 0xf) << 8) | ((F & 0xf) << 12)
          );
          break;
        }
        case '3rc': {
          const idx = resolveRef(insn.refKind, insn.ref);
          units.push((insn.op & 0xff) | ((insn.count & 0xff) << 8), idx & 0xffff, insn.firstReg & 0xffff);
          break;
        }
        case 'packed-switch-payload': {
          const swPc = labels.get(insn.switchLabel);
          units.push(0x0100, insn.targetLabels.length & 0xffff);
          const fk = insn.firstKey | 0;
          units.push(fk & 0xffff, (fk >>> 16) & 0xffff);
          for (const tl of insn.targetLabels) {
            const off = (labels.get(tl) - swPc) | 0;
            units.push(off & 0xffff, (off >>> 16) & 0xffff);
          }
          break;
        }
        case 'sparse-switch-payload': {
          const swPc = labels.get(insn.switchLabel);
          units.push(0x0200, insn.entries.length & 0xffff);
          for (const [k] of insn.entries) {
            const ki = k | 0;
            units.push(ki & 0xffff, (ki >>> 16) & 0xffff);
          }
          for (const [, tl] of insn.entries) {
            const off = (labels.get(tl) - swPc) | 0;
            units.push(off & 0xffff, (off >>> 16) & 0xffff);
          }
          break;
        }
        case 'fill-array-data-payload': {
          const ew = insn.elementWidth;
          const sz = insn.values.length;
          units.push(0x0300, ew & 0xffff, sz & 0xffff, (sz >>> 16) & 0xffff);
          const raw = new Uint8Array(Math.ceil((sz * ew) / 2) * 2);
          const dv = new DataView(raw.buffer);
          for (let i = 0; i < sz; i++) {
            const v = insn.values[i];
            if (ew === 1) dv.setInt8(i, v);
            else if (ew === 2) dv.setInt16(i * 2, v, true);
            else if (ew === 4) dv.setInt32(i * 4, v, true);
            else if (ew === 8) dv.setBigInt64(i * 8, BigInt(v), true);
          }
          for (let i = 0; i < raw.byteLength; i += 2) {
            units.push(raw[i] | (raw[i + 1] << 8));
          }
          break;
        }
        default:
          throw new Error(`Unsupported assembler format: ${insn.fmt}`);
      }
      pc += insn.units;
    }

    // Write 4-byte aligned code_item
    dataW.align(4, 0);
    const codeOff = absOff();
    const tries = m.tries ?? [];

    const parsedProto = parseMethodDescriptor(m.descriptor);
    const isStatic = ((m.accessFlags ?? 0) & DEX_ACCESS_FLAGS.ACC_STATIC) !== 0;
    const computedInsSize =
      (isStatic ? 0 : 1) + parsedProto.params.reduce((acc, p) => acc + (p === 'J' || p === 'D' ? 2 : 1), 0);
    const insSize = m.insSize ?? computedInsSize;
    const regsSize = Math.max(m.registers ?? (insSize + 4), insSize);
    const outsSize = m.outsSize ?? 5;

    dataW.u16le(regsSize);
    dataW.u16le(insSize);
    dataW.u16le(outsSize);
    dataW.u16le(tries.length);
    dataW.u32le(0); // debug_info_off
    dataW.u32le(units.length);
    for (const u of units) dataW.u16le(u & 0xffff);

    if (tries.length > 0) {
      // Edge Case #9: emit 2-byte alignment padding when tries_size > 0 && (insns_size & 1) === 1
      if ((units.length & 1) === 1) {
        dataW.u16le(0);
      }

      // Build encoded_catch_handler_list first so we know each handler's exact byte offset
      const handlerW = new BinaryWriter({ initialCapacity: 64, littleEndian: true });
      handlerW.bytes(encodeUleb128(tries.length));
      const handlerOffs = [];
      for (const t of tries) {
        handlerOffs.push(handlerW.length);
        const hList = t.handlers ?? [];
        const hasCatchAll = t.catchAll !== undefined && t.catchAll !== null;
        const sizeVal = hasCatchAll ? -hList.length : hList.length;
        handlerW.bytes(encodeSleb128(sizeVal));
        for (const h of hList) {
          handlerW.bytes(encodeUleb128(typeIdxMap.get(h.type)));
          const addr = typeof h.handler === 'number' ? h.handler : labels.get(h.handler);
          handlerW.bytes(encodeUleb128(addr));
        }
        if (hasCatchAll) {
          const caAddr = typeof t.catchAll === 'number' ? t.catchAll : labels.get(t.catchAll);
          handlerW.bytes(encodeUleb128(caAddr));
        }
      }

      for (let i = 0; i < tries.length; i++) {
        const t = tries[i];
        const startAddr = typeof t.start === 'number' ? t.start : labels.get(t.start);
        const endAddr = typeof t.end === 'number' ? t.end : labels.get(t.end);
        dataW.u32le(startAddr);
        dataW.u16le(endAddr - startAddr);
        dataW.u16le(handlerOffs[i]);
      }
      dataW.bytes(handlerW.toUint8Array());
    }

    return codeOff;
  };

  // 3. Emit code_items
  dataW.align(4, 0);
  const codeItemsStartOff = absOff();
  let codeItemCount = 0;
  const classMethodCodes = classes.map((cls) => {
    const direct = (cls.directMethods ?? []).map((m) => {
      const codeOff = encodeMethodCode(m);
      if (codeOff !== 0) codeItemCount += 1;
      return { ...m, codeOff, idx: methodIdxMap.get(`${cls.type}->${m.name}${m.descriptor}`) };
    });
    const virtual = (cls.virtualMethods ?? []).map((m) => {
      const codeOff = encodeMethodCode(m);
      if (codeOff !== 0) codeItemCount += 1;
      return { ...m, codeOff, idx: methodIdxMap.get(`${cls.type}->${m.name}${m.descriptor}`) };
    });
    return { direct, virtual };
  });

  // 4. Emit class_data_items
  const classDataStartOff = absOff();
  let classDataCount = 0;
  const classDataOffs = classes.map((cls, cIdx) => {
    const sf = (cls.staticFields ?? [])
      .map((f) => ({ ...f, idx: fieldIdxMap.get(`${cls.type}->${f.name}:${f.type}`) }))
      .sort((a, b) => a.idx - b.idx);
    const inf = (cls.instanceFields ?? [])
      .map((f) => ({ ...f, idx: fieldIdxMap.get(`${cls.type}->${f.name}:${f.type}`) }))
      .sort((a, b) => a.idx - b.idx);
    const dm = [...classMethodCodes[cIdx].direct].sort((a, b) => a.idx - b.idx);
    const vm = [...classMethodCodes[cIdx].virtual].sort((a, b) => a.idx - b.idx);

    if (sf.length === 0 && inf.length === 0 && dm.length === 0 && vm.length === 0) return 0;

    const off = absOff();
    classDataCount += 1;
    dataW.bytes(encodeUleb128(sf.length));
    dataW.bytes(encodeUleb128(inf.length));
    dataW.bytes(encodeUleb128(dm.length));
    dataW.bytes(encodeUleb128(vm.length));

    let prev = 0;
    for (const f of sf) {
      dataW.bytes(encodeUleb128(f.idx - prev));
      dataW.bytes(encodeUleb128(f.accessFlags ?? (DEX_ACCESS_FLAGS.ACC_PUBLIC | DEX_ACCESS_FLAGS.ACC_STATIC)));
      prev = f.idx;
    }
    prev = 0;
    for (const f of inf) {
      dataW.bytes(encodeUleb128(f.idx - prev));
      dataW.bytes(encodeUleb128(f.accessFlags ?? DEX_ACCESS_FLAGS.ACC_PUBLIC));
      prev = f.idx;
    }
    prev = 0;
    for (const m of dm) {
      dataW.bytes(encodeUleb128(m.idx - prev));
      dataW.bytes(encodeUleb128(m.accessFlags ?? DEX_ACCESS_FLAGS.ACC_PUBLIC));
      dataW.bytes(encodeUleb128(m.codeOff));
      prev = m.idx;
    }
    prev = 0;
    for (const m of vm) {
      dataW.bytes(encodeUleb128(m.idx - prev));
      dataW.bytes(encodeUleb128(m.accessFlags ?? DEX_ACCESS_FLAGS.ACC_PUBLIC));
      dataW.bytes(encodeUleb128(m.codeOff));
      prev = m.idx;
    }
    return off;
  });

  // 5. Emit map_list (4-byte aligned at end of data section)
  dataW.align(4, 0);
  const mapOff = absOff();
  const mapItems = [
    { type: 0x0000, size: 1, off: 0 }, // HEADER_ITEM
    ...(sortedStrings.length > 0 ? [{ type: 0x0001, size: sortedStrings.length, off: stringIdsOff }] : []),
    ...(sortedTypes.length > 0 ? [{ type: 0x0002, size: sortedTypes.length, off: typeIdsOff }] : []),
    ...(sortedProtos.length > 0 ? [{ type: 0x0003, size: sortedProtos.length, off: protoIdsOff }] : []),
    ...(sortedFields.length > 0 ? [{ type: 0x0004, size: sortedFields.length, off: fieldIdsOff }] : []),
    ...(sortedMethods.length > 0 ? [{ type: 0x0005, size: sortedMethods.length, off: methodIdsOff }] : []),
    ...(classes.length > 0 ? [{ type: 0x0006, size: classes.length, off: classDefsOff }] : []),
    ...(typeListCount > 0 ? [{ type: 0x1001, size: typeListCount, off: typeListStartOff }] : []),
    ...(sortedStrings.length > 0 ? [{ type: 0x2002, size: sortedStrings.length, off: stringDataStartOff }] : []),
    ...(codeItemCount > 0 ? [{ type: 0x2001, size: codeItemCount, off: codeItemsStartOff }] : []),
    ...(classDataCount > 0 ? [{ type: 0x2000, size: classDataCount, off: classDataStartOff }] : []),
    { type: 0x1000, size: 1, off: mapOff }, // MAP_LIST
  ];
  dataW.u32le(mapItems.length);
  for (const mi of mapItems) {
    dataW.u16le(mi.type).u16le(0).u32le(mi.size).u32le(mi.off);
  }
  dataW.align(4, 0);

  const dataBytes = dataW.toUint8Array();
  const fileSize = dataOff + dataBytes.byteLength;

  // Assemble full DEX image
  const out = new BinaryWriter({ initialCapacity: fileSize, littleEndian: true });
  out.bytes(TEXT_ENCODER.encode(`dex\n${version}\0`)); // 0x00..0x07
  out.u32le(0); // 0x08 checksum placeholder
  out.pad(20, 0); // 0x0C..0x1F SHA-1 placeholder
  out.u32le(fileSize); // 0x20
  out.u32le(headerSize); // 0x24
  out.u32le(DEX_ENDIAN_CONSTANT); // 0x28
  out.u32le(0).u32le(0); // link_size, link_off
  out.u32le(mapOff); // 0x34
  out.u32le(sortedStrings.length).u32le(stringIdsOff);
  out.u32le(sortedTypes.length).u32le(typeIdsOff);
  out.u32le(sortedProtos.length).u32le(protoIdsOff);
  out.u32le(sortedFields.length).u32le(fieldIdsOff);
  out.u32le(sortedMethods.length).u32le(methodIdsOff);
  out.u32le(classes.length).u32le(classDefsOff);
  out.u32le(isV41 ? 0 : dataBytes.byteLength).u32le(isV41 ? 0 : dataOff);
  if (isV41) {
    out.u32le(fileSize); // container_size
    out.u32le(0); // header_off
  }

  for (let i = 0; i < sortedStrings.length; i++) out.u32le(stringDataOffs[i]);
  for (const t of sortedTypes) out.u32le(strIdxMap.get(t));
  for (let i = 0; i < sortedProtos.length; i++) {
    const p = sortedProtos[i];
    out.u32le(strIdxMap.get(p.shorty));
    out.u32le(typeIdxMap.get(p.returnType));
    out.u32le(protoParamOffs[i]);
  }
  for (const f of sortedFields) {
    out.u16le(typeIdxMap.get(f.cls));
    out.u16le(typeIdxMap.get(f.type));
    out.u32le(strIdxMap.get(f.name));
  }
  for (const m of sortedMethods) {
    out.u16le(typeIdxMap.get(m.cls));
    out.u16le(protoIdxMap.get(m.descriptor));
    out.u32le(strIdxMap.get(m.name));
  }
  for (let i = 0; i < classes.length; i++) {
    const c = classes[i];
    out.u32le(typeIdxMap.get(c.type));
    out.u32le(c.accessFlags ?? DEX_ACCESS_FLAGS.ACC_PUBLIC);
    out.u32le(c.superclass ? typeIdxMap.get(c.superclass) : DEX_NO_INDEX);
    out.u32le(classInterfaceOffs[i]);
    out.u32le(c.sourceFile ? strIdxMap.get(c.sourceFile) : DEX_NO_INDEX);
    out.u32le(0); // annotations_off
    out.u32le(classDataOffs[i]);
    out.u32le(0); // static_values_off
  }
  out.bytes(dataBytes);

  const bytes = out.toUint8Array();

  // Compute authentic SHA-1 over bytes[0x20..fileSize) and Adler-32 over bytes[0x0c..fileSize)
  const sha1 = crypto.createHash('sha1').update(bytes.subarray(0x20, fileSize)).digest();
  bytes.set(sha1, 0x0c);
  const checksum = adler32(bytes, 0x0c, fileSize - 0x0c);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  dv.setUint32(0x08, checksum >>> 0, true);

  return bytes;
}

// =============================================================================
// APK Signing Block v2/v3 Injector (`appendApkSigningBlock`)
// =============================================================================

export function appendApkSigningBlock(zipBytes, { schemeV2Data = null, schemeV3Data = null } = {}) {
  const bytes = zipBytes instanceof Uint8Array ? zipBytes : new Uint8Array(zipBytes);
  const idx = listZipEntries(bytes);
  const cdOffset = idx.centralDirOffset;
  const eocdOffset = idx.eocdOffset;

  const prefix = bytes.subarray(0, cdOffset);
  const suffix = bytes.subarray(cdOffset).slice(); // Central Directory + EOCD (writable copy)

  const digest = crypto.createHash('sha256').update(prefix).digest();
  const v2Payload = schemeV2Data ?? digest;

  const pairsW = new BinaryWriter({ initialCapacity: 128, littleEndian: true });
  // Pair: u64le(4 + payload.length), u32le(schemeId), payload
  pairsW.u64le(BigInt(4 + v2Payload.byteLength));
  pairsW.u32le(APK_SIG_SCHEME_IDS.V2);
  pairsW.bytes(v2Payload);
  if (schemeV3Data) {
    pairsW.u64le(BigInt(4 + schemeV3Data.byteLength));
    pairsW.u32le(APK_SIG_SCHEME_IDS.V3);
    pairsW.bytes(schemeV3Data);
  }
  const pairsBytes = pairsW.toUint8Array();

  // sizeOfBlock = pairs + 8 (footer size) + 16 (magic)
  const sizeOfBlock = BigInt(pairsBytes.byteLength + 24);
  const blockW = new BinaryWriter({ initialCapacity: pairsBytes.byteLength + 32, littleEndian: true });
  blockW.u64le(sizeOfBlock);
  blockW.bytes(pairsBytes);
  blockW.u64le(sizeOfBlock);
  blockW.bytes(TEXT_ENCODER.encode(APK_SIG_BLOCK_MAGIC));
  const blockBytes = blockW.toUint8Array();

  // Patch EOCD cdOffset in suffix copy
  const relEocd = eocdOffset - cdOffset;
  const sView = new DataView(suffix.buffer, suffix.byteOffset, suffix.byteLength);
  if (sView.getUint32(relEocd, true) === ZIP_SIGNATURES.EOCD) {
    const newCdOffset = cdOffset + blockBytes.byteLength;
    sView.setUint32(relEocd + 16, newCdOffset >>> 0, true);
  }

  const combined = new Uint8Array(prefix.byteLength + blockBytes.byteLength + suffix.byteLength);
  combined.set(prefix, 0);
  combined.set(blockBytes, prefix.byteLength);
  combined.set(suffix, prefix.byteLength + blockBytes.byteLength);
  return combined;
}

// =============================================================================
// General Parameterized APK Builder (`buildCustomApk`)
// =============================================================================

export function buildCustomApk({
  packageName = 'com.omnios.custom',
  label = 'Custom App',
  versionCode = 1,
  versionName = '1.0.0',
  minSdkVersion = 24,
  targetSdkVersion = 34,
  permissions = [],
  launcherActivity = '.MainActivity',
  activities = null,
  intentFilters = [],
  strings = {},
  layouts = {},
  ids = {},
  extraResourceTypes = [],
  classes = [],
  extraDexList = [],
  assets = {},
  dexVersion = '035',
  signV2 = true,
  plainXmlManifest = false,
} = {}) {
  // Build resources.arsc entries
  const stringEntries = [{ id: 0, name: 'app_name', value: label }];
  let nextStrId = 1;
  const stringIdMap = new Map([['app_name', 0x7f010000]]);
  for (const [k, v] of Object.entries(strings)) {
    if (k === 'app_name') {
      stringEntries[0].value = String(v);
      continue;
    }
    const entryId = nextStrId++;
    stringEntries.push({ id: entryId, name: k, value: String(v) });
    stringIdMap.set(k, (0x7f010000 | entryId) >>> 0);
  }

  const layoutEntries = [];
  const layoutFiles = [];
  let nextLayoutId = 0;
  for (const [layoutName, layoutTree] of Object.entries(layouts)) {
    const entryId = nextLayoutId++;
    const filePath = `res/layout/${layoutName}.xml`;
    layoutEntries.push({ id: entryId, name: layoutName, value: filePath });
    const axmlBytes = layoutTree instanceof Uint8Array ? layoutTree : encodeAxml(layoutTree);
    layoutFiles.push({ name: filePath, data: axmlBytes, compress: true });
  }

  const idEntries = [];
  for (const [idName, rawIdVal] of Object.entries(ids)) {
    const entryIdx = rawIdVal & 0xffff;
    idEntries.push({ id: entryIdx, name: idName, dataType: RES_VALUE_TYPES.TYPE_INT_BOOLEAN, value: false });
  }

  const arscTypes = [
    { id: 1, name: 'string', entries: stringEntries },
    ...(layoutEntries.length > 0 ? [{ id: 2, name: 'layout', entries: layoutEntries }] : []),
    ...(idEntries.length > 0 ? [{ id: 3, name: 'id', entries: idEntries }] : []),
    ...extraResourceTypes,
  ];
  const arscBytes = encodeResourcesArsc({ packageId: 0x7f, packageName, types: arscTypes });

  // Build AndroidManifest.xml AST
  const resolvedActivities = activities ?? [
    {
      name: launcherActivity,
      label: '@0x7f010000',
      isLauncher: true,
      intentFilters,
    },
  ];

  const appChildren = resolvedActivities.map((act) => {
    const filters = [];
    if (act.isLauncher !== false) {
      filters.push({
        tag: 'intent-filter',
        attrs: {},
        children: [
          { tag: 'action', attrs: { 'android:name': 'android.intent.action.MAIN' }, children: [] },
          { tag: 'category', attrs: { 'android:name': 'android.intent.category.LAUNCHER' }, children: [] },
        ],
      });
    }
    for (const f of act.intentFilters ?? []) {
      const fChildren = [];
      for (const a of f.actions ?? []) {
        fChildren.push({ tag: 'action', attrs: { 'android:name': a }, children: [] });
      }
      for (const c of f.categories ?? []) {
        fChildren.push({ tag: 'category', attrs: { 'android:name': c }, children: [] });
      }
      for (const d of f.data ?? []) {
        const dAttrs = {};
        if (d.scheme) dAttrs['android:scheme'] = d.scheme;
        if (d.host) dAttrs['android:host'] = d.host;
        if (d.mimeType) dAttrs['android:mimeType'] = d.mimeType;
        if (d.pathPattern) dAttrs['android:pathPattern'] = d.pathPattern;
        fChildren.push({ tag: 'data', attrs: dAttrs, children: [] });
      }
      filters.push({ tag: 'intent-filter', attrs: f.priority ? { 'android:priority': f.priority } : {}, children: fChildren });
    }
    return {
      tag: 'activity',
      attrs: {
        'android:name': act.name,
        'android:exported': true,
      },
      children: filters,
    };
  });

  const manifestNode = {
    tag: 'manifest',
    attrs: {
      package: packageName,
      'android:versionCode': versionCode,
      'android:versionName': versionName,
    },
    children: [
      {
        tag: 'uses-sdk',
        attrs: {
          'android:minSdkVersion': minSdkVersion,
          'android:targetSdkVersion': targetSdkVersion,
        },
        children: [],
      },
      ...permissions.map((p) => ({
        tag: 'uses-permission',
        attrs: { 'android:name': p },
        children: [],
      })),
      {
        tag: 'application',
        attrs: {
          'android:label': '@0x7f010000',
        },
        children: appChildren,
      },
    ],
  };

  let manifestBytes;
  if (plainXmlManifest) {
    const serializePlain = (n) => {
      const attrsStr = Object.entries(n.attrs ?? {})
        .map(([k, v]) => ` ${k}="${String(v)}"`)
        .join('');
      const nsStr = n.tag === 'manifest' ? ' xmlns:android="http://schemas.android.com/apk/res/android"' : '';
      if (!n.children || n.children.length === 0) return `<${n.tag}${nsStr}${attrsStr}/>`;
      return `<${n.tag}${nsStr}${attrsStr}>${n.children.map(serializePlain).join('')}</${n.tag}>`;
    };
    manifestBytes = TEXT_ENCODER.encode(`<?xml version="1.0" encoding="utf-8"?>\n${serializePlain(manifestNode)}\n`);
  } else {
    manifestBytes = encodeAxml(manifestNode);
  }

  // Assemble primary DEX + optional extra multidex files
  const dexBytes = assembleDex({ version: dexVersion, classes });

  const zipEntries = [
    { name: 'AndroidManifest.xml', data: manifestBytes, compress: true },
    { name: 'resources.arsc', data: arscBytes, compress: false }, // Android 11+ uncompressed resources.arsc
    { name: 'classes.dex', data: dexBytes, compress: true },
    ...extraDexList.map((d, i) => ({
      name: `classes${i + 2}.dex`,
      data: d instanceof Uint8Array ? d : assembleDex(d),
      compress: true,
    })),
    ...layoutFiles,
    ...Object.entries(assets).map(([assetPath, data]) => ({
      name: assetPath.startsWith('assets/') ? assetPath : `assets/${assetPath}`,
      data,
      compress: true,
    })),
  ];

  let apkBytes = createZip(zipEntries);
  if (signV2) {
    apkBytes = appendApkSigningBlock(apkBytes);
  }
  return apkBytes;
}

// =============================================================================
// Sample APK 1: `packages/android-calc.apk` (`com.omnios.calc`)
// Real Dalvik ALU + DEX `try/catch ArithmeticException` Interactive Calculator
// =============================================================================

export function buildCalcApk() {
  const A = DALVIK_ASM;
  const MAIN_CLS = 'Lcom/omnios/calc/MainActivity;';
  const LISTENER_CLS = 'Lcom/omnios/calc/CalcClickListener;';
  const ACTIVITY_CLS = 'Landroid/app/Activity;';
  const VIEW_CLS = 'Landroid/view/View;';
  const TV_CLS = 'Landroid/widget/TextView;';
  const ONCLICK_CLS = 'Landroid/view/View$OnClickListener;';

  const ID_DISPLAY = 0x7f030001;
  const ID_BTN_BASE = 0x7f030010; // 0..9 -> 0x7f030010 .. 0x7f030019
  const ID_BTN_ADD = 0x7f030020;
  const ID_BTN_SUB = 0x7f030021;
  const ID_BTN_MUL = 0x7f030022;
  const ID_BTN_DIV = 0x7f030023;
  const ID_BTN_EQ = 0x7f030024;
  const ID_BTN_CLR = 0x7f030025;

  const ids = {
    display: ID_DISPLAY,
    btn_0: ID_BTN_BASE + 0,
    btn_1: ID_BTN_BASE + 1,
    btn_2: ID_BTN_BASE + 2,
    btn_3: ID_BTN_BASE + 3,
    btn_4: ID_BTN_BASE + 4,
    btn_5: ID_BTN_BASE + 5,
    btn_6: ID_BTN_BASE + 6,
    btn_7: ID_BTN_BASE + 7,
    btn_8: ID_BTN_BASE + 8,
    btn_9: ID_BTN_BASE + 9,
    btn_add: ID_BTN_ADD,
    btn_sub: ID_BTN_SUB,
    btn_mul: ID_BTN_MUL,
    btn_div: ID_BTN_DIV,
    btn_eq: ID_BTN_EQ,
    btn_clr: ID_BTN_CLR,
  };

  const makeBtn = (id, label) => ({
    tag: 'Button',
    attrs: {
      'android:id': `@0x${id.toString(16)}`,
      'android:text': label,
    },
    children: [],
  });

  const layoutMain = {
    tag: 'LinearLayout',
    attrs: { 'android:orientation': 1 },
    children: [
      {
        tag: 'TextView',
        attrs: {
          'android:id': `@0x${ID_DISPLAY.toString(16)}`,
          'android:text': '0',
        },
        children: [],
      },
      {
        tag: 'LinearLayout',
        attrs: { 'android:orientation': 0 },
        children: [makeBtn(ID_BTN_BASE + 7, '7'), makeBtn(ID_BTN_BASE + 8, '8'), makeBtn(ID_BTN_BASE + 9, '9'), makeBtn(ID_BTN_DIV, '/')],
      },
      {
        tag: 'LinearLayout',
        attrs: { 'android:orientation': 0 },
        children: [makeBtn(ID_BTN_BASE + 4, '4'), makeBtn(ID_BTN_BASE + 5, '5'), makeBtn(ID_BTN_BASE + 6, '6'), makeBtn(ID_BTN_MUL, '*')],
      },
      {
        tag: 'LinearLayout',
        attrs: { 'android:orientation': 0 },
        children: [makeBtn(ID_BTN_BASE + 1, '1'), makeBtn(ID_BTN_BASE + 2, '2'), makeBtn(ID_BTN_BASE + 3, '3'), makeBtn(ID_BTN_SUB, '-')],
      },
      {
        tag: 'LinearLayout',
        attrs: { 'android:orientation': 0 },
        children: [makeBtn(ID_BTN_BASE + 0, '0'), makeBtn(ID_BTN_CLR, 'C'), makeBtn(ID_BTN_EQ, '='), makeBtn(ID_BTN_ADD, '+')],
      },
    ],
  };

  // Wire all 16 buttons in onCreate(Bundle): p0=v4 (this), p1=v5 (bundle)
  // locals: v0=resId, v1=view, v2=listener, v3=const
  const allButtonIds = [
    ID_BTN_BASE + 0, ID_BTN_BASE + 1, ID_BTN_BASE + 2, ID_BTN_BASE + 3, ID_BTN_BASE + 4,
    ID_BTN_BASE + 5, ID_BTN_BASE + 6, ID_BTN_BASE + 7, ID_BTN_BASE + 8, ID_BTN_BASE + 9,
    ID_BTN_ADD, ID_BTN_SUB, ID_BTN_MUL, ID_BTN_DIV, ID_BTN_EQ, ID_BTN_CLR,
  ];
  const onCreateInsns = [
    A.invokeSuper([4, 5], ACTIVITY_CLS, 'onCreate', '(Landroid/os/Bundle;)V'),
    A.const32(0, 0x7f020000), // R.layout.activity_main
    A.invokeVirtual([4, 0], MAIN_CLS, 'setContentView', '(I)V'),
    A.const32(0, ID_DISPLAY),
    A.invokeVirtual([4, 0], MAIN_CLS, 'findViewById', '(I)Landroid/view/View;'),
    A.moveResultObject(1),
    A.checkCast(1, TV_CLS),
    A.iputObject(1, 4, MAIN_CLS, 'display', TV_CLS),
    A.const4(3, 1),
    A.iput(3, 4, MAIN_CLS, 'enteringNew', 'I'),
    // listener = new CalcClickListener(this)
    A.newInstance(2, LISTENER_CLS),
    A.invokeDirect([2, 4], LISTENER_CLS, '<init>', `(${MAIN_CLS})V`),
  ];
  for (const btnId of allButtonIds) {
    onCreateInsns.push(
      A.const32(0, btnId),
      A.invokeVirtual([4, 0], MAIN_CLS, 'findViewById', '(I)Landroid/view/View;'),
      A.moveResultObject(1),
      A.invokeVirtual([1, 2], VIEW_CLS, 'setOnClickListener', `(${ONCLICK_CLS})V`)
    );
  }
  onCreateInsns.push(
    A.constString(0, 'OmniCalc'),
    A.constString(1, 'Calculator initialized'),
    A.invokeStatic([0, 1], 'Landroid/util/Log;', 'i', '(Ljava/lang/String;Ljava/lang/String;)I'),
    A.returnVoid()
  );

  // MainActivity.onButtonClick(View): p0=v8 (this), p1=v9 (view)
  // locals: v0=id, v1=tmp1, v2=tmp2, v3=acc, v4=cur, v5=op, v6=res/str, v7=display
  const onButtonClickInsns = [
    A.invokeVirtual([9], VIEW_CLS, 'getId', '()I'),
    A.moveResult(0),
    A.igetObject(7, 8, MAIN_CLS, 'display', TV_CLS),

    // Check if digit button: ID_BTN_BASE <= id <= ID_BTN_BASE + 9
    A.const32(1, ID_BTN_BASE),
    A.ifLt(0, 1, 'L_check_ops'),
    A.const32(2, ID_BTN_BASE + 9),
    A.ifGt(0, 2, 'L_check_ops'),
    // Digit = id - ID_BTN_BASE
    A.subInt(1, 0, 1),
    A.iget(2, 8, MAIN_CLS, 'enteringNew', 'I'),
    A.ifEqz(2, 'L_append_digit'),
    // enteringNew != 0 -> current = digit; enteringNew = 0
    A.iput(1, 8, MAIN_CLS, 'current', 'I'),
    A.const4(2, 0),
    A.iput(2, 8, MAIN_CLS, 'enteringNew', 'I'),
    A.goto('L_show_current'),

    A.label('L_append_digit'),
    A.iget(4, 8, MAIN_CLS, 'current', 'I'),
    A.mulIntLit8(4, 4, 10),
    A.addInt(4, 4, 1),
    A.iput(4, 8, MAIN_CLS, 'current', 'I'),

    A.label('L_show_current'),
    A.iget(4, 8, MAIN_CLS, 'current', 'I'),
    A.invokeStatic([4], 'Ljava/lang/Integer;', 'toString', '(I)Ljava/lang/String;'),
    A.moveResultObject(6),
    A.invokeVirtual([7, 6], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.returnVoid(),

    // Operator buttons: +, -, *, /
    A.label('L_check_ops'),
    A.const32(1, ID_BTN_ADD),
    A.ifLt(0, 1, 'L_check_eq'),
    A.const32(2, ID_BTN_DIV),
    A.ifGt(0, 2, 'L_check_eq'),
    // pendingOp = (id - ID_BTN_ADD) + 1  => 1=+, 2=-, 3=*, 4=/
    A.subInt(5, 0, 1),
    A.addIntLit8(5, 5, 1),
    A.iput(5, 8, MAIN_CLS, 'pendingOp', 'I'),
    A.iget(4, 8, MAIN_CLS, 'current', 'I'),
    A.iput(4, 8, MAIN_CLS, 'accumulator', 'I'),
    A.const4(2, 0),
    A.iput(2, 8, MAIN_CLS, 'current', 'I'),
    A.const4(2, 1),
    A.iput(2, 8, MAIN_CLS, 'enteringNew', 'I'),
    A.returnVoid(),

    // Equals button
    A.label('L_check_eq'),
    A.const32(1, ID_BTN_EQ),
    A.ifNe(0, 1, 'L_check_clr'),
    A.iget(3, 8, MAIN_CLS, 'accumulator', 'I'),
    A.iget(4, 8, MAIN_CLS, 'current', 'I'),
    A.iget(5, 8, MAIN_CLS, 'pendingOp', 'I'),

    A.label('L_try_eval_start'),
    A.const4(1, 1),
    A.ifNe(5, 1, 'L_op_sub'),
    A.addInt(6, 3, 4),
    A.goto('L_eval_done'),

    A.label('L_op_sub'),
    A.const4(1, 2),
    A.ifNe(5, 1, 'L_op_mul'),
    A.subInt(6, 3, 4),
    A.goto('L_eval_done'),

    A.label('L_op_mul'),
    A.const4(1, 3),
    A.ifNe(5, 1, 'L_op_div'),
    A.mulInt(6, 3, 4),
    A.goto('L_eval_done'),

    A.label('L_op_div'),
    A.const4(1, 4),
    A.ifNe(5, 1, 'L_op_none'),
    A.divInt(6, 3, 4), // Real Dalvik div-int: throws ArithmeticException when v4 == 0!
    A.goto('L_eval_done'),

    A.label('L_op_none'),
    A.move(6, 4),
    A.label('L_try_eval_end'),

    A.label('L_eval_done'),
    A.iput(6, 8, MAIN_CLS, 'current', 'I'),
    A.iput(6, 8, MAIN_CLS, 'accumulator', 'I'),
    A.const4(2, 0),
    A.iput(2, 8, MAIN_CLS, 'pendingOp', 'I'),
    A.const4(2, 1),
    A.iput(2, 8, MAIN_CLS, 'enteringNew', 'I'),
    A.invokeStatic([6], 'Ljava/lang/Integer;', 'toString', '(I)Ljava/lang/String;'),
    A.moveResultObject(6),
    A.invokeVirtual([7, 6], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.constString(1, 'OmniCalc'),
    A.invokeStatic([1, 6], 'Landroid/util/Log;', 'i', '(Ljava/lang/String;Ljava/lang/String;)I'),
    A.returnVoid(),

    // Real DEX ArithmeticException catch handler!
    A.label('L_catch_arith'),
    A.moveException(1),
    A.const4(2, 0),
    A.iput(2, 8, MAIN_CLS, 'current', 'I'),
    A.iput(2, 8, MAIN_CLS, 'accumulator', 'I'),
    A.iput(2, 8, MAIN_CLS, 'pendingOp', 'I'),
    A.const4(2, 1),
    A.iput(2, 8, MAIN_CLS, 'enteringNew', 'I'),
    A.constString(6, 'Error: / by zero'),
    A.invokeVirtual([7, 6], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.constString(1, 'OmniCalc'),
    A.invokeStatic([1, 6], 'Landroid/util/Log;', 'e', '(Ljava/lang/String;Ljava/lang/String;)I'),
    A.returnVoid(),

    // Clear button
    A.label('L_check_clr'),
    A.const32(1, ID_BTN_CLR),
    A.ifNe(0, 1, 'L_done'),
    A.const4(2, 0),
    A.iput(2, 8, MAIN_CLS, 'accumulator', 'I'),
    A.iput(2, 8, MAIN_CLS, 'current', 'I'),
    A.iput(2, 8, MAIN_CLS, 'pendingOp', 'I'),
    A.const4(2, 1),
    A.iput(2, 8, MAIN_CLS, 'enteringNew', 'I'),
    A.constString(6, '0'),
    A.invokeVirtual([7, 6], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),

    A.label('L_done'),
    A.returnVoid(),
  ];

  const classes = [
    {
      type: MAIN_CLS,
      superclass: ACTIVITY_CLS,
      sourceFile: 'MainActivity.java',
      instanceFields: [
        { name: 'display', type: TV_CLS },
        { name: 'accumulator', type: 'I' },
        { name: 'current', type: 'I' },
        { name: 'pendingOp', type: 'I' },
        { name: 'enteringNew', type: 'I' },
      ],
      directMethods: [
        {
          name: '<init>',
          descriptor: '()V',
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC | DEX_ACCESS_FLAGS.ACC_CONSTRUCTOR,
          registers: 2,
          insns: [
            A.invokeDirect([1], ACTIVITY_CLS, '<init>', '()V'),
            A.returnVoid(),
          ],
        },
      ],
      virtualMethods: [
        {
          name: 'onCreate',
          descriptor: '(Landroid/os/Bundle;)V',
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC,
          registers: 6,
          insns: onCreateInsns,
        },
        {
          name: 'onButtonClick',
          descriptor: `(${VIEW_CLS})V`,
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC,
          registers: 10,
          insns: onButtonClickInsns,
          tries: [
            {
              start: 'L_try_eval_start',
              end: 'L_try_eval_end',
              handlers: [{ type: 'Ljava/lang/ArithmeticException;', handler: 'L_catch_arith' }],
            },
          ],
        },
      ],
    },
    {
      type: LISTENER_CLS,
      superclass: 'Ljava/lang/Object;',
      interfaces: [ONCLICK_CLS],
      sourceFile: 'CalcClickListener.java',
      instanceFields: [{ name: 'activity', type: MAIN_CLS }],
      directMethods: [
        {
          name: '<init>',
          descriptor: `(${MAIN_CLS})V`,
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC | DEX_ACCESS_FLAGS.ACC_CONSTRUCTOR,
          registers: 3,
          insns: [
            A.invokeDirect([1], 'Ljava/lang/Object;', '<init>', '()V'),
            A.iputObject(2, 1, LISTENER_CLS, 'activity', MAIN_CLS),
            A.returnVoid(),
          ],
        },
      ],
      virtualMethods: [
        {
          name: 'onClick',
          descriptor: `(${VIEW_CLS})V`,
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC,
          registers: 3,
          insns: [
            A.igetObject(0, 1, LISTENER_CLS, 'activity', MAIN_CLS),
            A.invokeVirtual([0, 2], MAIN_CLS, 'onButtonClick', `(${VIEW_CLS})V`),
            A.returnVoid(),
          ],
        },
      ],
    },
  ];

  return buildCustomApk({
    packageName: 'com.omnios.calc',
    label: 'OmniCalc',
    versionCode: 1,
    versionName: '1.0.0',
    launcherActivity: '.MainActivity',
    layouts: { activity_main: layoutMain },
    ids,
    classes,
    signV2: true,
  });
}

// =============================================================================
// Sample APK 2: `packages/android-notes-sharer.apk` (`com.omnios.notes`)
// Real Dalvik EditText + /data/data VFS + SharedPreferences + Clipboard + Intent + Toast + /sdcard Export
// =============================================================================

export function buildNotesSharerApk() {
  const A = DALVIK_ASM;
  const MAIN_CLS = 'Lcom/omnios/notes/NotesActivity;';
  const LISTENER_CLS = 'Lcom/omnios/notes/NotesClickListener;';
  const ACTIVITY_CLS = 'Landroid/app/Activity;';
  const VIEW_CLS = 'Landroid/view/View;';
  const TV_CLS = 'Landroid/widget/TextView;';
  const ET_CLS = 'Landroid/widget/EditText;';
  const ONCLICK_CLS = 'Landroid/view/View$OnClickListener;';
  const INTENT_CLS = 'Landroid/content/Intent;';
  const SP_CLS = 'Landroid/content/SharedPreferences;';
  const SP_ED_CLS = 'Landroid/content/SharedPreferences$Editor;';
  const CB_CLS = 'Landroid/content/ClipboardManager;';
  const CLIP_CLS = 'Landroid/content/ClipData;';
  const TOAST_CLS = 'Landroid/widget/Toast;';
  const FILE_CLS = 'Ljava/io/File;';
  const FOS_CLS = 'Ljava/io/FileOutputStream;';
  const FIS_CLS = 'Ljava/io/FileInputStream;';
  const SB_CLS = 'Ljava/lang/StringBuilder;';

  const ID_NOTE_INPUT = 0x7f030001;
  const ID_STATUS = 0x7f030002;
  const ID_BTN_SAVE = 0x7f030010;
  const ID_BTN_LOAD = 0x7f030011;
  const ID_BTN_COPY = 0x7f030012;
  const ID_BTN_SHARE = 0x7f030013;
  const ID_BTN_EXPORT = 0x7f030014;

  const ids = {
    note_input: ID_NOTE_INPUT,
    status_text: ID_STATUS,
    btn_save: ID_BTN_SAVE,
    btn_load: ID_BTN_LOAD,
    btn_copy: ID_BTN_COPY,
    btn_share: ID_BTN_SHARE,
    btn_export: ID_BTN_EXPORT,
  };

  const layoutNotes = {
    tag: 'LinearLayout',
    attrs: { 'android:orientation': 1 },
    children: [
      {
        tag: 'EditText',
        attrs: {
          'android:id': `@0x${ID_NOTE_INPUT.toString(16)}`,
          'android:hint': 'Write a note...',
          'android:text': '',
        },
        children: [],
      },
      {
        tag: 'TextView',
        attrs: {
          'android:id': `@0x${ID_STATUS.toString(16)}`,
          'android:text': 'Ready',
        },
        children: [],
      },
      {
        tag: 'LinearLayout',
        attrs: { 'android:orientation': 0 },
        children: [
          { tag: 'Button', attrs: { 'android:id': `@0x${ID_BTN_SAVE.toString(16)}`, 'android:text': 'Save' }, children: [] },
          { tag: 'Button', attrs: { 'android:id': `@0x${ID_BTN_LOAD.toString(16)}`, 'android:text': 'Load' }, children: [] },
          { tag: 'Button', attrs: { 'android:id': `@0x${ID_BTN_COPY.toString(16)}`, 'android:text': 'Copy' }, children: [] },
          { tag: 'Button', attrs: { 'android:id': `@0x${ID_BTN_SHARE.toString(16)}`, 'android:text': 'Share' }, children: [] },
          { tag: 'Button', attrs: { 'android:id': `@0x${ID_BTN_EXPORT.toString(16)}`, 'android:text': 'Export SD' }, children: [] },
        ],
      },
    ],
  };

  // onCreate(Bundle): p0=v6 (this), p1=v7 (bundle)
  const onCreateInsns = [
    A.invokeSuper([6, 7], ACTIVITY_CLS, 'onCreate', '(Landroid/os/Bundle;)V'),
    A.const32(0, 0x7f020000),
    A.invokeVirtual([6, 0], MAIN_CLS, 'setContentView', '(I)V'),

    // Bind noteInput & statusText
    A.const32(0, ID_NOTE_INPUT),
    A.invokeVirtual([6, 0], MAIN_CLS, 'findViewById', '(I)Landroid/view/View;'),
    A.moveResultObject(1),
    A.checkCast(1, ET_CLS),
    A.iputObject(1, 6, MAIN_CLS, 'noteInput', ET_CLS),

    A.const32(0, ID_STATUS),
    A.invokeVirtual([6, 0], MAIN_CLS, 'findViewById', '(I)Landroid/view/View;'),
    A.moveResultObject(2),
    A.checkCast(2, TV_CLS),
    A.iputObject(2, 6, MAIN_CLS, 'statusText', TV_CLS),

    // Wire click listener onto all 5 buttons
    A.newInstance(3, LISTENER_CLS),
    A.invokeDirect([3, 6], LISTENER_CLS, '<init>', `(${MAIN_CLS})V`),
    ...[ID_BTN_SAVE, ID_BTN_LOAD, ID_BTN_COPY, ID_BTN_SHARE, ID_BTN_EXPORT].flatMap((bid) => [
      A.const32(0, bid),
      A.invokeVirtual([6, 0], MAIN_CLS, 'findViewById', '(I)Landroid/view/View;'),
      A.moveResultObject(4),
      A.invokeVirtual([4, 3], VIEW_CLS, 'setOnClickListener', `(${ONCLICK_CLS})V`),
    ]),

    // Check launch intent EXTRA_TEXT; else load from SharedPreferences("notes_prefs")
    A.invokeVirtual([6], MAIN_CLS, 'getIntent', `()${INTENT_CLS}`),
    A.moveResultObject(4),
    A.ifEqz(4, 'L_check_prefs'),
    A.constString(5, 'android.intent.extra.TEXT'),
    A.invokeVirtual([4, 5], INTENT_CLS, 'getStringExtra', '(Ljava/lang/String;)Ljava/lang/String;'),
    A.moveResultObject(5),
    A.ifEqz(5, 'L_check_prefs'),
    A.invokeVirtual([1, 5], ET_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.newInstance(0, SB_CLS),
    A.constString(4, 'Received: '),
    A.invokeDirect([0, 4], SB_CLS, '<init>', '(Ljava/lang/String;)V'),
    A.invokeVirtual([0, 5], SB_CLS, 'append', `(Ljava/lang/String;)${SB_CLS}`),
    A.invokeVirtual([0], SB_CLS, 'toString', '()Ljava/lang/String;'),
    A.moveResultObject(4),
    A.invokeVirtual([2, 4], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.goto('L_init_done'),

    A.label('L_check_prefs'),
    A.constString(4, 'notes_prefs'),
    A.const4(0, 0),
    A.invokeVirtual([6, 4, 0], MAIN_CLS, 'getSharedPreferences', `(Ljava/lang/String;I)${SP_CLS}`),
    A.moveResultObject(4),
    A.constString(5, 'last_note'),
    A.constString(0, ''),
    A.invokeInterface([4, 5, 0], SP_CLS, 'getString', '(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;'),
    A.moveResultObject(5),
    A.ifEqz(5, 'L_init_done'),
    A.invokeVirtual([1, 5], ET_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),

    A.label('L_init_done'),
    A.constString(0, 'OmniNotes'),
    A.constString(4, 'NotesActivity ready'),
    A.invokeStatic([0, 4], 'Landroid/util/Log;', 'i', '(Ljava/lang/String;Ljava/lang/String;)I'),
    A.returnVoid(),
  ];

  // onNewIntent(Intent): p0=v4 (this), p1=v5 (intent)
  const onNewIntentInsns = [
    A.invokeVirtual([4, 5], MAIN_CLS, 'setIntent', `(${INTENT_CLS})V`),
    A.ifEqz(5, 'L_ni_done'),
    A.constString(0, 'android.intent.extra.TEXT'),
    A.invokeVirtual([5, 0], INTENT_CLS, 'getStringExtra', '(Ljava/lang/String;)Ljava/lang/String;'),
    A.moveResultObject(1),
    A.ifEqz(1, 'L_ni_done'),
    A.igetObject(2, 4, MAIN_CLS, 'noteInput', ET_CLS),
    A.invokeVirtual([2, 1], ET_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.newInstance(3, SB_CLS),
    A.constString(0, 'Received: '),
    A.invokeDirect([3, 0], SB_CLS, '<init>', '(Ljava/lang/String;)V'),
    A.invokeVirtual([3, 1], SB_CLS, 'append', `(Ljava/lang/String;)${SB_CLS}`),
    A.invokeVirtual([3], SB_CLS, 'toString', '()Ljava/lang/String;'),
    A.moveResultObject(0),
    A.igetObject(2, 4, MAIN_CLS, 'statusText', TV_CLS),
    A.invokeVirtual([2, 0], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.label('L_ni_done'),
    A.returnVoid(),
  ];

  // onButtonClick(View): p0=v10 (this), p1=v11 (view)
  // locals: v0=id, v1=tmp, v2=noteText, v3=statusTextView, v4=noteInputView, v5..v9=scratch
  const onButtonClickInsns = [
    A.invokeVirtual([11], VIEW_CLS, 'getId', '()I'),
    A.moveResult(0),
    A.igetObject(4, 10, MAIN_CLS, 'noteInput', ET_CLS),
    A.igetObject(3, 10, MAIN_CLS, 'statusText', TV_CLS),
    A.invokeVirtual([4], ET_CLS, 'getText', '()Ljava/lang/CharSequence;'),
    A.moveResultObject(2),

    // ---- SAVE ----
    A.const32(1, ID_BTN_SAVE),
    A.ifNe(0, 1, 'L_btn_load'),
    // Write /data/data/com.omnios.notes/files/note.txt
    A.constString(5, 'note.txt'),
    A.const4(6, 0),
    A.invokeVirtual([10, 5, 6], MAIN_CLS, 'openFileOutput', `(Ljava/lang/String;I)${FOS_CLS}`),
    A.moveResultObject(7),
    A.invokeVirtual([2], 'Ljava/lang/String;', 'getBytes', '()[B'),
    A.moveResultObject(8),
    A.invokeVirtual([7, 8], FOS_CLS, 'write', '([B)V'),
    A.invokeVirtual([7], FOS_CLS, 'close', '()V'),
    // Persist in SharedPreferences("notes_prefs")
    A.constString(5, 'notes_prefs'),
    A.const4(6, 0),
    A.invokeVirtual([10, 5, 6], MAIN_CLS, 'getSharedPreferences', `(Ljava/lang/String;I)${SP_CLS}`),
    A.moveResultObject(7),
    A.constString(5, 'save_count'),
    A.const4(6, 0),
    A.invokeInterface([7, 5, 6], SP_CLS, 'getInt', '(Ljava/lang/String;I)I'),
    A.moveResult(8),
    A.addIntLit8(8, 8, 1),
    A.invokeInterface([7], SP_CLS, 'edit', `()${SP_ED_CLS}`),
    A.moveResultObject(9),
    A.constString(5, 'last_note'),
    A.invokeInterface([9, 5, 2], SP_ED_CLS, 'putString', `(Ljava/lang/String;Ljava/lang/String;)${SP_ED_CLS}`),
    A.constString(5, 'save_count'),
    A.invokeInterface([9, 5, 8], SP_ED_CLS, 'putInt', `(Ljava/lang/String;I)${SP_ED_CLS}`),
    A.invokeInterface([9], SP_ED_CLS, 'commit', '()Z'),
    // Toast + statusText + Log
    A.constString(5, 'Note saved'),
    A.const4(6, 0),
    A.invokeStatic([10, 5, 6], TOAST_CLS, 'makeText', `(Landroid/content/Context;Ljava/lang/CharSequence;I)${TOAST_CLS}`),
    A.moveResultObject(7),
    A.invokeVirtual([7], TOAST_CLS, 'show', '()V'),
    A.newInstance(7, SB_CLS),
    A.constString(5, 'Saved: '),
    A.invokeDirect([7, 5], SB_CLS, '<init>', '(Ljava/lang/String;)V'),
    A.invokeVirtual([7, 2], SB_CLS, 'append', `(Ljava/lang/String;)${SB_CLS}`),
    A.invokeVirtual([7], SB_CLS, 'toString', '()Ljava/lang/String;'),
    A.moveResultObject(5),
    A.invokeVirtual([3, 5], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.constString(6, 'OmniNotes'),
    A.invokeStatic([6, 5], 'Landroid/util/Log;', 'i', '(Ljava/lang/String;Ljava/lang/String;)I'),
    A.returnVoid(),

    // ---- LOAD ----
    A.label('L_btn_load'),
    A.const32(1, ID_BTN_LOAD),
    A.ifNe(0, 1, 'L_btn_copy'),
    A.label('L_try_load_start'),
    A.constString(5, 'note.txt'),
    A.invokeVirtual([10, 5], MAIN_CLS, 'openFileInput', `(Ljava/lang/String;)${FIS_CLS}`),
    A.moveResultObject(7),
    A.const16(6, 4096),
    A.newArray(8, 6, '[B'),
    A.invokeVirtual([7, 8], FIS_CLS, 'read', '([B)I'),
    A.moveResult(9),
    A.invokeVirtual([7], FIS_CLS, 'close', '()V'),
    A.ifLtz(9, 'L_load_empty'),
    A.newInstance(5, 'Ljava/lang/String;'),
    A.const4(6, 0),
    A.invokeDirect([5, 8, 6, 9], 'Ljava/lang/String;', '<init>', '([BII)V'),
    A.goto('L_load_apply'),
    A.label('L_load_empty'),
    A.constString(5, ''),
    A.label('L_load_apply'),
    A.invokeVirtual([4, 5], ET_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.newInstance(7, SB_CLS),
    A.constString(6, 'Loaded: '),
    A.invokeDirect([7, 6], SB_CLS, '<init>', '(Ljava/lang/String;)V'),
    A.invokeVirtual([7, 5], SB_CLS, 'append', `(Ljava/lang/String;)${SB_CLS}`),
    A.invokeVirtual([7], SB_CLS, 'toString', '()Ljava/lang/String;'),
    A.moveResultObject(6),
    A.invokeVirtual([3, 6], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.label('L_try_load_end'),
    A.returnVoid(),
    A.label('L_catch_load'),
    A.moveException(5),
    A.constString(6, 'Load failed'),
    A.invokeVirtual([3, 6], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.returnVoid(),

    // ---- COPY TO SHARED CLIPBOARD ----
    A.label('L_btn_copy'),
    A.const32(1, ID_BTN_COPY),
    A.ifNe(0, 1, 'L_btn_share'),
    A.constString(5, 'clipboard'),
    A.invokeVirtual([10, 5], MAIN_CLS, 'getSystemService', '(Ljava/lang/String;)Ljava/lang/Object;'),
    A.moveResultObject(7),
    A.checkCast(7, CB_CLS),
    A.constString(5, 'note'),
    A.invokeStatic([5, 2], CLIP_CLS, 'newPlainText', `(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)${CLIP_CLS}`),
    A.moveResultObject(8),
    A.invokeVirtual([7, 8], CB_CLS, 'setPrimaryClip', `(${CLIP_CLS})V`),
    A.constString(5, 'Copied to clipboard'),
    A.const4(6, 0),
    A.invokeStatic([10, 5, 6], TOAST_CLS, 'makeText', `(Landroid/content/Context;Ljava/lang/CharSequence;I)${TOAST_CLS}`),
    A.moveResultObject(7),
    A.invokeVirtual([7], TOAST_CLS, 'show', '()V'),
    A.invokeVirtual([3, 5], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.returnVoid(),

    // ---- SHARE VIA INTENT (ACTION_SEND) ----
    A.label('L_btn_share'),
    A.const32(1, ID_BTN_SHARE),
    A.ifNe(0, 1, 'L_btn_export'),
    A.label('L_try_share_start'),
    A.newInstance(7, INTENT_CLS),
    A.constString(5, 'android.intent.action.SEND'),
    A.invokeDirect([7, 5], INTENT_CLS, '<init>', '(Ljava/lang/String;)V'),
    A.constString(5, 'text/plain'),
    A.invokeVirtual([7, 5], INTENT_CLS, 'setType', `(Ljava/lang/String;)${INTENT_CLS}`),
    A.constString(5, 'android.intent.extra.TEXT'),
    A.invokeVirtual([7, 5, 2], INTENT_CLS, 'putExtra', `(Ljava/lang/String;Ljava/lang/String;)${INTENT_CLS}`),
    A.invokeVirtual([10, 7], MAIN_CLS, 'startActivity', `(${INTENT_CLS})V`),
    A.constString(5, 'Shared note'),
    A.const4(6, 0),
    A.invokeStatic([10, 5, 6], TOAST_CLS, 'makeText', `(Landroid/content/Context;Ljava/lang/CharSequence;I)${TOAST_CLS}`),
    A.moveResultObject(8),
    A.invokeVirtual([8], TOAST_CLS, 'show', '()V'),
    A.invokeVirtual([3, 5], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.label('L_try_share_end'),
    A.returnVoid(),
    A.label('L_catch_share'),
    A.moveException(5),
    A.constString(6, 'No share handler'),
    A.invokeVirtual([3, 6], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.returnVoid(),

    // ---- EXPORT TO /sdcard/Documents/android-note.txt (Permission-gated Shared User Space) ----
    A.label('L_btn_export'),
    A.const32(1, ID_BTN_EXPORT),
    A.ifNe(0, 1, 'L_notes_done'),
    A.label('L_try_export_start'),
    A.invokeStatic([], 'Landroid/os/Environment;', 'getExternalStorageDirectory', `()${FILE_CLS}`),
    A.moveResultObject(5),
    A.newInstance(6, FILE_CLS),
    A.constString(7, 'Documents/android-note.txt'),
    A.invokeDirect([6, 5, 7], FILE_CLS, '<init>', `(${FILE_CLS}Ljava/lang/String;)V`),
    A.newInstance(8, FOS_CLS),
    A.invokeDirect([8, 6], FOS_CLS, '<init>', `(${FILE_CLS})V`),
    A.invokeVirtual([2], 'Ljava/lang/String;', 'getBytes', '()[B'),
    A.moveResultObject(9),
    A.invokeVirtual([8, 9], FOS_CLS, 'write', '([B)V'),
    A.invokeVirtual([8], FOS_CLS, 'close', '()V'),
    A.constString(5, 'Exported to /sdcard/Documents/android-note.txt'),
    A.const4(6, 0),
    A.invokeStatic([10, 5, 6], TOAST_CLS, 'makeText', `(Landroid/content/Context;Ljava/lang/CharSequence;I)${TOAST_CLS}`),
    A.moveResultObject(7),
    A.invokeVirtual([7], TOAST_CLS, 'show', '()V'),
    A.invokeVirtual([3, 5], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.label('L_try_export_end'),
    A.returnVoid(),
    A.label('L_catch_export_sec'),
    A.moveException(5),
    A.constString(6, 'Export denied'),
    A.invokeVirtual([3, 6], TV_CLS, 'setText', '(Ljava/lang/CharSequence;)V'),
    A.constString(7, 'OmniNotes'),
    A.invokeStatic([7, 6], 'Landroid/util/Log;', 'w', '(Ljava/lang/String;Ljava/lang/String;)I'),

    A.label('L_notes_done'),
    A.returnVoid(),
  ];

  const classes = [
    {
      type: MAIN_CLS,
      superclass: ACTIVITY_CLS,
      sourceFile: 'NotesActivity.java',
      instanceFields: [
        { name: 'noteInput', type: ET_CLS },
        { name: 'statusText', type: TV_CLS },
      ],
      directMethods: [
        {
          name: '<init>',
          descriptor: '()V',
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC | DEX_ACCESS_FLAGS.ACC_CONSTRUCTOR,
          registers: 2,
          insns: [
            A.invokeDirect([1], ACTIVITY_CLS, '<init>', '()V'),
            A.returnVoid(),
          ],
        },
      ],
      virtualMethods: [
        {
          name: 'onCreate',
          descriptor: '(Landroid/os/Bundle;)V',
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC,
          registers: 8,
          insns: onCreateInsns,
        },
        {
          name: 'onNewIntent',
          descriptor: `(${INTENT_CLS})V`,
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC,
          registers: 6,
          insns: onNewIntentInsns,
        },
        {
          name: 'onButtonClick',
          descriptor: `(${VIEW_CLS})V`,
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC,
          registers: 12,
          insns: onButtonClickInsns,
          tries: [
            {
              start: 'L_try_load_start',
              end: 'L_try_load_end',
              handlers: [{ type: 'Ljava/lang/Exception;', handler: 'L_catch_load' }],
            },
            {
              start: 'L_try_share_start',
              end: 'L_try_share_end',
              handlers: [{ type: 'Ljava/lang/Exception;', handler: 'L_catch_share' }],
            },
            {
              start: 'L_try_export_start',
              end: 'L_try_export_end',
              handlers: [{ type: 'Ljava/lang/SecurityException;', handler: 'L_catch_export_sec' }],
            },
          ],
        },
      ],
    },
    {
      type: LISTENER_CLS,
      superclass: 'Ljava/lang/Object;',
      interfaces: [ONCLICK_CLS],
      sourceFile: 'NotesClickListener.java',
      instanceFields: [{ name: 'activity', type: MAIN_CLS }],
      directMethods: [
        {
          name: '<init>',
          descriptor: `(${MAIN_CLS})V`,
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC | DEX_ACCESS_FLAGS.ACC_CONSTRUCTOR,
          registers: 3,
          insns: [
            A.invokeDirect([1], 'Ljava/lang/Object;', '<init>', '()V'),
            A.iputObject(2, 1, LISTENER_CLS, 'activity', MAIN_CLS),
            A.returnVoid(),
          ],
        },
      ],
      virtualMethods: [
        {
          name: 'onClick',
          descriptor: `(${VIEW_CLS})V`,
          accessFlags: DEX_ACCESS_FLAGS.ACC_PUBLIC,
          registers: 3,
          insns: [
            A.igetObject(0, 1, LISTENER_CLS, 'activity', MAIN_CLS),
            A.invokeVirtual([0, 2], MAIN_CLS, 'onButtonClick', `(${VIEW_CLS})V`),
            A.returnVoid(),
          ],
        },
      ],
    },
  ];

  return buildCustomApk({
    packageName: 'com.omnios.notes',
    label: 'OmniNotes Android',
    versionCode: 1,
    versionName: '1.0.0',
    permissions: [
      'android.permission.READ_EXTERNAL_STORAGE',
      'android.permission.WRITE_EXTERNAL_STORAGE',
      'android.permission.POST_NOTIFICATIONS',
      'android.permission.READ_CLIPBOARD',
      'android.permission.WRITE_CLIPBOARD',
    ],
    launcherActivity: '.NotesActivity',
    intentFilters: [
      {
        actions: ['android.intent.action.SEND'],
        categories: ['android.intent.category.DEFAULT'],
        data: [{ mimeType: 'text/plain' }],
        priority: 10,
      },
      {
        actions: ['android.intent.action.VIEW'],
        categories: ['android.intent.category.DEFAULT'],
        data: [{ scheme: 'notes' }],
        priority: 10,
      },
    ],
    layouts: { activity_notes: layoutNotes },
    ids,
    classes,
    signV2: true,
  });
}

// =============================================================================
// Deterministic Sample Builder Entrypoint (`buildSampleApks`)
// =============================================================================

export function buildSampleApks(outDir = null) {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const targetDir = outDir || path.resolve(__dirname, '..', 'packages');
  fs.mkdirSync(targetDir, { recursive: true });

  const calcBytes = buildCalcApk();
  const calcPath = path.join(targetDir, 'android-calc.apk');
  fs.writeFileSync(calcPath, calcBytes);

  const notesBytes = buildNotesSharerApk();
  const notesPath = path.join(targetDir, 'android-notes-sharer.apk');
  fs.writeFileSync(notesPath, notesBytes);

  return [
    {
      name: 'android-calc.apk',
      path: calcPath,
      size: calcBytes.byteLength,
      sha256: crypto.createHash('sha256').update(calcBytes).digest('hex'),
    },
    {
      name: 'android-notes-sharer.apk',
      path: notesPath,
      size: notesBytes.byteLength,
      sha256: crypto.createHash('sha256').update(notesBytes).digest('hex'),
    },
  ];
}

// Direct CLI execution: `node sdk/android-builder.mjs`
const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(currentFile)) {
  const built = buildSampleApks();
  for (const item of built) {
    console.log(`[android-builder] Built ${item.name} (${item.size} bytes, sha256=${item.sha256})`);
  }
}
