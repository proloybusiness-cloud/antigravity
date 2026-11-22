/**
 * OmniOS Pure-JS iOS SDK Builder (`F-057`)
 * Zero external npm dependencies (uses only Node.js built-ins + OmniOS `plist-parser.mjs` & `zip.mjs`).
 *
 * Exports:
 * - `Arm64Assembler`: genuine A64 instruction encoder with label resolution & Mach-O page-relative relocations
 * - `buildMachOArm64(spec)`: standards-compliant 64-bit ARM64 Mach-O executable (`0xFEEDFACF`,
 *   `__PAGEZERO`, `__TEXT`, `__DATA`, `__LINKEDIT`, `LC_DYLD_INFO_ONLY`, `LC_SYMTAB`, `LC_DYSYMTAB`,
 *   `LC_LOAD_DYLINKER`, `LC_UUID`, `LC_BUILD_VERSION` [`PLATFORM_IOS = 2`], `LC_MAIN`,
 *   `LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE` with `0xFADE7171` entitlements, optional FairPlay `LC_ENCRYPTION_INFO_64`)
 * - `buildIosIpa(spec)`: fully parameterized `.ipa` builder supporting arbitrary runtime-nonce specs
 * - `buildWeatherIslandSample(outputPath)`: builds deterministic `packages/ios-weather-island.ipa`
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createZip } from '../os/pkg/zip.mjs';
import { writeBinaryPlist, writeXmlPlist } from '../os/runtimes/apple/plist-parser.mjs';
import { MACHO_CONSTANTS } from '../os/runtimes/apple/macho-parser.mjs';

const TEXT_ENCODER = new TextEncoder();
const DETERMINISTIC_MTIME = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));
const MACHO_PAGE_SIZE = 0x4000; // 16 KiB Apple Silicon / iOS page alignment

function alignUp(n, align) {
  return Math.ceil(n / align) * align;
}

function encodeUleb128(val) {
  let v = typeof val === 'bigint' ? val : BigInt(val);
  const out = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    out.push(byte);
  } while (v !== 0n);
  return out;
}

function writeFixedString(buf, offset, str, maxLen) {
  const bytes = TEXT_ENCODER.encode(str);
  const len = Math.min(bytes.length, maxLen);
  buf.set(bytes.subarray(0, len), offset);
}

// ============================================================================
// Pure-JS ARM64 (AArch64) Assembler
// ============================================================================

export class Arm64Assembler {
  constructor() {
    this._insns = []; // Array<number> (32-bit unsigned A64 words)
    this._labels = new Map(); // name -> byteOffset
    this._branchFixups = []; // { insnIndex, label, kind, reg, cond }
    this._addrRelocs = []; // { insnIndex, kind: 'adrp_add'|'adrp_ldr'|'adrp_str', reg, scratchReg, target }
  }

  get byteLength() {
    return this._insns.length * 4;
  }

  emit(word) {
    const idx = this._insns.length;
    this._insns.push(word >>> 0);
    return idx;
  }

  label(name) {
    this._labels.set(name, this.byteLength);
    return this;
  }

  // ---- Basic Control & System ----

  nop() {
    this.emit(0xd503201f);
    return this;
  }

  ret(rn = 30) {
    this.emit((0xd65f0000 | ((rn & 31) << 5)) >>> 0);
    return this;
  }

  br(rn) {
    this.emit((0xd61f0000 | ((rn & 31) << 5)) >>> 0);
    return this;
  }

  blr(rn) {
    this.emit((0xd63f0000 | ((rn & 31) << 5)) >>> 0);
    return this;
  }

  svc(imm16 = 0x80) {
    this.emit((0xd4000001 | ((imm16 & 0xffff) << 5)) >>> 0);
    return this;
  }

  // ---- Move Wide & Register Move ----

  movz(rd, imm16, shift = 0, is64 = true) {
    const sf = is64 ? 1 : 0;
    const hw = ((shift / 16) | 0) & 3;
    this.emit(((sf << 31) | (0b10 << 29) | (0b100101 << 23) | (hw << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0);
    return this;
  }

  movk(rd, imm16, shift = 0, is64 = true) {
    const sf = is64 ? 1 : 0;
    const hw = ((shift / 16) | 0) & 3;
    this.emit(((sf << 31) | (0b11 << 29) | (0b100101 << 23) | (hw << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0);
    return this;
  }

  movn(rd, imm16, shift = 0, is64 = true) {
    const sf = is64 ? 1 : 0;
    const hw = ((shift / 16) | 0) & 3;
    this.emit(((sf << 31) | (0b00 << 29) | (0b100101 << 23) | (hw << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0);
    return this;
  }

  movImm64(rd, value) {
    const v = BigInt.asUintN(64, typeof value === 'bigint' ? value : BigInt(Math.trunc(value)));
    if (v === 0n) {
      return this.movz(rd, 0, 0, true);
    }
    let emitted = false;
    for (let hw = 0; hw < 4; hw++) {
      const part = Number((v >> BigInt(hw * 16)) & 0xffffn);
      if (part !== 0) {
        if (!emitted) {
          this.movz(rd, part, hw * 16, true);
          emitted = true;
        } else {
          this.movk(rd, part, hw * 16, true);
        }
      }
    }
    return this;
  }

  movReg(rd, rm, is64 = true) {
    if (rd === 31 || rm === 31) {
      return this.addImm(rd, rm, 0, is64);
    }
    const sf = is64 ? 1 : 0;
    // ORR Xd, XZR, Xm
    this.emit(((sf << 31) | (0b01 << 29) | (0b01010 << 24) | ((rm & 31) << 16) | (31 << 5) | (rd & 31)) >>> 0);
    return this;
  }

  // ---- ALU Immediate & Register ----

  addImm(rd, rn, imm12, is64 = true, shift12 = false) {
    const sf = is64 ? 1 : 0;
    const sh = shift12 ? 1 : 0;
    this.emit(((sf << 31) | (0b00100010 << 23) | (sh << 22) | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0);
    return this;
  }

  subImm(rd, rn, imm12, is64 = true, shift12 = false) {
    const sf = is64 ? 1 : 0;
    const sh = shift12 ? 1 : 0;
    this.emit(((sf << 31) | (0b10100010 << 23) | (sh << 22) | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0);
    return this;
  }

  subsImm(rd, rn, imm12, is64 = true, shift12 = false) {
    const sf = is64 ? 1 : 0;
    const sh = shift12 ? 1 : 0;
    this.emit(((sf << 31) | (0b11100010 << 23) | (sh << 22) | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0);
    return this;
  }

  cmpImm(rn, imm12, is64 = true) {
    return this.subsImm(31, rn, imm12, is64);
  }

  addReg(rd, rn, rm, is64 = true) {
    const sf = is64 ? 1 : 0;
    this.emit(((sf << 31) | (0b0001011 << 24) | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0);
    return this;
  }

  subReg(rd, rn, rm, is64 = true) {
    const sf = is64 ? 1 : 0;
    this.emit(((sf << 31) | (0b1001011 << 24) | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0);
    return this;
  }

  mul(rd, rn, rm, is64 = true) {
    const sf = is64 ? 1 : 0;
    this.emit(((sf << 31) | (0b0011011000 << 21) | ((rm & 31) << 16) | (31 << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0);
    return this;
  }

  // ---- Load / Store ----

  ldrUImm64(rt, rn, byteOffset = 0) {
    const imm12 = (byteOffset >>> 3) & 0xfff;
    this.emit((0xf9400000 | (imm12 << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0);
    return this;
  }

  strUImm64(rt, rn, byteOffset = 0) {
    const imm12 = (byteOffset >>> 3) & 0xfff;
    this.emit((0xf9000000 | (imm12 << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0);
    return this;
  }

  stpPre64(rt, rt2, rn, byteOffset) {
    const imm7 = (byteOffset >> 3) & 0x7f;
    this.emit((0xa9800000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0);
    return this;
  }

  ldpPost64(rt, rt2, rn, byteOffset) {
    const imm7 = (byteOffset >> 3) & 0x7f;
    this.emit((0xa8c00000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0);
    return this;
  }

  stpSigned64(rt, rt2, rn, byteOffset = 0) {
    const imm7 = (byteOffset >> 3) & 0x7f;
    this.emit((0xa9000000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0);
    return this;
  }

  ldpSigned64(rt, rt2, rn, byteOffset = 0) {
    const imm7 = (byteOffset >> 3) & 0x7f;
    this.emit((0xa9400000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0);
    return this;
  }

  // ---- PC-Relative & Branches ----

  static encodeAdrp(rd, pcVA, targetVA) {
    const pcPage = BigInt(pcVA) & ~0xfffn;
    const targetPage = BigInt(targetVA) & ~0xfffn;
    const deltaPages = Number((targetPage - pcPage) >> 12n);
    const immlo = deltaPages & 0x3;
    const immhi = (deltaPages >> 2) & 0x7ffff;
    return (((1 << 31) | (immlo << 29) | (0b10000 << 24) | (immhi << 5) | (rd & 31)) >>> 0);
  }

  static encodeAdr(rd, byteDelta) {
    const immlo = byteDelta & 0x3;
    const immhi = (byteDelta >> 2) & 0x7ffff;
    return (((immlo << 29) | (0b10000 << 24) | (immhi << 5) | (rd & 31)) >>> 0);
  }

  b(label) {
    const idx = this.emit(0x14000000);
    this._branchFixups.push({ insnIndex: idx, label, kind: 'b' });
    return this;
  }

  bl(label) {
    const idx = this.emit(0x94000000);
    this._branchFixups.push({ insnIndex: idx, label, kind: 'bl' });
    return this;
  }

  cbz(rt, label) {
    const idx = this.emit(0xb4000000);
    this._branchFixups.push({ insnIndex: idx, label, kind: 'cbz', reg: rt });
    return this;
  }

  cbnz(rt, label) {
    const idx = this.emit(0xb5000000);
    this._branchFixups.push({ insnIndex: idx, label, kind: 'cbnz', reg: rt });
    return this;
  }

  bCond(cond, label) {
    const idx = this.emit(0x54000000);
    this._branchFixups.push({ insnIndex: idx, label, kind: 'bcond', cond });
    return this;
  }

  // ---- High-level Mach-O Relocation Helpers (resolved at link time) ----

  /** Emit ADRP + ADD to compute exact VA of `target` (`{ kind, key }`) into `rd`. */
  loadAddr(rd, target) {
    const idx = this.emit(0xd503201f);
    this.emit(0xd503201f);
    this._addrRelocs.push({ insnIndex: idx, kind: 'adrp_add', reg: rd, target });
    return this;
  }

  /** Emit ADRP + LDR [64-bit] to load pointer stored at `target` into `rd`. */
  loadPtr(rd, target) {
    const idx = this.emit(0xd503201f);
    this.emit(0xd503201f);
    this._addrRelocs.push({ insnIndex: idx, kind: 'adrp_ldr', reg: rd, target });
    return this;
  }

  /** Emit ADRP(scratch) + STR(reg, [scratch, #off]) to store 64-bit `reg` into `target`. */
  storePtr(reg, target, scratchReg = 17) {
    const idx = this.emit(0xd503201f);
    this.emit(0xd503201f);
    this._addrRelocs.push({ insnIndex: idx, kind: 'adrp_str', reg, scratchReg, target });
    return this;
  }

  /** Emit GOT call sequence: ADRP X16 + LDR X16 + BLR X16. */
  callGot(symbolName) {
    this.loadPtr(16, { kind: 'got', key: symbolName });
    this.blr(16);
    return this;
  }

  /**
   * Resolve all internal branch fixups and external Mach-O address relocations,
   * returning the finalized little-endian machine code `Uint8Array`.
   */
  finalize(textBaseVA, resolveTargetVA) {
    const words = Uint32Array.from(this._insns);

    for (const fx of this._branchFixups) {
      if (!this._labels.has(fx.label)) {
        throw new Error(`Arm64Assembler: unresolved branch label "${fx.label}"`);
      }
      const pcOff = fx.insnIndex * 4;
      const targetOff = this._labels.get(fx.label);
      const wordDelta = (targetOff - pcOff) >> 2;
      if (fx.kind === 'b') {
        words[fx.insnIndex] = (0x14000000 | (wordDelta & 0x03ffffff)) >>> 0;
      } else if (fx.kind === 'bl') {
        words[fx.insnIndex] = (0x94000000 | (wordDelta & 0x03ffffff)) >>> 0;
      } else if (fx.kind === 'cbz') {
        words[fx.insnIndex] = (0xb4000000 | ((wordDelta & 0x7ffff) << 5) | (fx.reg & 31)) >>> 0;
      } else if (fx.kind === 'cbnz') {
        words[fx.insnIndex] = (0xb5000000 | ((wordDelta & 0x7ffff) << 5) | (fx.reg & 31)) >>> 0;
      } else if (fx.kind === 'bcond') {
        words[fx.insnIndex] = (0x54000000 | ((wordDelta & 0x7ffff) << 5) | (fx.cond & 0xf)) >>> 0;
      }
    }

    for (const rel of this._addrRelocs) {
      const targetVA = BigInt(resolveTargetVA(rel.target));
      const pcVA = BigInt(textBaseVA) + BigInt(rel.insnIndex * 4);
      const pageOff = Number(targetVA & 0xfffn);

      if (rel.kind === 'adrp_add') {
        words[rel.insnIndex] = Arm64Assembler.encodeAdrp(rel.reg, pcVA, targetVA);
        words[rel.insnIndex + 1] =
          ((1 << 31) | (0b00100010 << 23) | ((pageOff & 0xfff) << 10) | ((rel.reg & 31) << 5) | (rel.reg & 31)) >>> 0;
      } else if (rel.kind === 'adrp_ldr') {
        if ((pageOff & 7) !== 0) {
          throw new Error(`Arm64Assembler: adrp_ldr target 0x${targetVA.toString(16)} is not 8-byte aligned`);
        }
        words[rel.insnIndex] = Arm64Assembler.encodeAdrp(rel.reg, pcVA, targetVA);
        words[rel.insnIndex + 1] =
          (0xf9400000 | (((pageOff >>> 3) & 0xfff) << 10) | ((rel.reg & 31) << 5) | (rel.reg & 31)) >>> 0;
      } else if (rel.kind === 'adrp_str') {
        if ((pageOff & 7) !== 0) {
          throw new Error(`Arm64Assembler: adrp_str target 0x${targetVA.toString(16)} is not 8-byte aligned`);
        }
        words[rel.insnIndex] = Arm64Assembler.encodeAdrp(rel.scratchReg, pcVA, targetVA);
        words[rel.insnIndex + 1] =
          (0xf9000000 | (((pageOff >>> 3) & 0xfff) << 10) | ((rel.scratchReg & 31) << 5) | (rel.reg & 31)) >>> 0;
      }
    }

    const out = new Uint8Array(words.length * 4);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < words.length; i++) {
      dv.setUint32(i * 4, words[i], true);
    }
    return out;
  }
}

// ============================================================================
// Standards-Compliant 64-bit ARM64 Mach-O Builder
// ============================================================================

function buildCodeSignatureSuperBlob(identifier, entitlementsObj, codeLimit) {
  const xmlStr = writeXmlPlist(entitlementsObj ?? {});
  const xmlBytes = TEXT_ENCODER.encode(xmlStr);
  const identBytes = TEXT_ENCODER.encode(`${identifier}\0`);

  // CodeDirectory blob: 44-byte header + identifier + 32-byte SHA-256 hash slot
  const identOffset = 44;
  const hashOffset = alignUp(identOffset + identBytes.length, 4);
  const cdLen = hashOffset + 32;
  const cdBuf = new Uint8Array(cdLen);
  const cdView = new DataView(cdBuf.buffer);
  cdView.setUint32(0, MACHO_CONSTANTS.CSMAGIC_CODEDIRECTORY, false);
  cdView.setUint32(4, cdLen, false);
  cdView.setUint32(8, 0x00020400, false); // version
  cdView.setUint32(12, 0x00000002, false); // adhoc flag
  cdView.setUint32(16, hashOffset, false);
  cdView.setUint32(20, identOffset, false);
  cdView.setUint32(24, 0, false); // nSpecialSlots
  cdView.setUint32(28, 1, false); // nCodeSlots
  cdView.setUint32(32, codeLimit >>> 0, false);
  cdBuf[36] = 32; // hashSize (SHA-256)
  cdBuf[37] = 2; // hashType (SHA-256)
  cdBuf[38] = 0; // platform
  cdBuf[39] = 12; // pageSize (log2 4096)
  cdView.setUint32(40, 0, false); // spare2
  cdBuf.set(identBytes, identOffset);
  const digest = crypto.createHash('sha256').update(identifier).update(xmlBytes).digest();
  cdBuf.set(digest, hashOffset);

  // Embedded Entitlements blob (0xFADE7171)
  const entLen = 8 + xmlBytes.length;
  const entBuf = new Uint8Array(entLen);
  const entView = new DataView(entBuf.buffer);
  entView.setUint32(0, MACHO_CONSTANTS.CSMAGIC_EMBEDDED_ENTITLEMENTS, false);
  entView.setUint32(4, entLen, false);
  entBuf.set(xmlBytes, 8);

  // CS_SuperBlob (0xFADE0CC0)
  const headerAndIndex = 12 + 2 * 8; // 28 bytes
  const cdOff = headerAndIndex;
  const entOff = cdOff + cdLen;
  const totalLen = alignUp(entOff + entLen, 16);

  const superBuf = new Uint8Array(totalLen);
  const sv = new DataView(superBuf.buffer);
  sv.setUint32(0, MACHO_CONSTANTS.CSMAGIC_EMBEDDED_SIGNATURE, false);
  sv.setUint32(4, totalLen, false);
  sv.setUint32(8, 2, false); // count = 2 blobs
  // Index 0: CodeDirectory (slot 0)
  sv.setUint32(12, 0, false);
  sv.setUint32(16, cdOff, false);
  // Index 1: Entitlements (slot 5)
  sv.setUint32(20, 5, false);
  sv.setUint32(24, entOff, false);

  superBuf.set(cdBuf, cdOff);
  superBuf.set(entBuf, entOff);
  return superBuf;
}

function buildDylibLoadCommand(dylibPath, cmd = MACHO_CONSTANTS.LC_LOAD_DYLIB) {
  const pathBytes = TEXT_ENCODER.encode(`${dylibPath}\0`);
  const cmdsize = alignUp(24 + pathBytes.length, 8);
  const buf = new Uint8Array(cmdsize);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, cmd, true);
  dv.setUint32(4, cmdsize, true);
  dv.setUint32(8, 24, true); // name offset
  dv.setUint32(12, 2, true); // timestamp
  dv.setUint32(16, 0x00010000, true); // current_version 1.0.0
  dv.setUint32(20, 0x00010000, true); // compatibility_version 1.0.0
  buf.set(pathBytes, 24);
  return buf;
}

function buildDylinkerLoadCommand(dylinkerPath = '/usr/lib/dyld') {
  const pathBytes = TEXT_ENCODER.encode(`${dylinkerPath}\0`);
  const cmdsize = alignUp(12 + pathBytes.length, 8);
  const buf = new Uint8Array(cmdsize);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, MACHO_CONSTANTS.LC_LOAD_DYLINKER, true);
  dv.setUint32(4, cmdsize, true);
  dv.setUint32(8, 12, true);
  buf.set(pathBytes, 12);
  return buf;
}

function buildSegment64Command(seg, sections = []) {
  const cmdsize = 72 + sections.length * 80;
  const buf = new Uint8Array(cmdsize);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, MACHO_CONSTANTS.LC_SEGMENT_64, true);
  dv.setUint32(4, cmdsize, true);
  writeFixedString(buf, 8, seg.segname, 16);
  dv.setBigUint64(24, BigInt(seg.vmaddr), true);
  dv.setBigUint64(32, BigInt(seg.vmsize), true);
  dv.setBigUint64(40, BigInt(seg.fileoff), true);
  dv.setBigUint64(48, BigInt(seg.filesize), true);
  dv.setUint32(56, seg.maxprot >>> 0, true);
  dv.setUint32(60, seg.initprot >>> 0, true);
  dv.setUint32(64, sections.length >>> 0, true);
  dv.setUint32(68, (seg.flags ?? 0) >>> 0, true);

  let pos = 72;
  for (const s of sections) {
    writeFixedString(buf, pos, s.sectname, 16);
    writeFixedString(buf, pos + 16, seg.segname, 16);
    dv.setBigUint64(pos + 32, BigInt(s.addr), true);
    dv.setBigUint64(pos + 40, BigInt(s.size), true);
    dv.setUint32(pos + 48, s.offset >>> 0, true);
    dv.setUint32(pos + 52, (s.align ?? 3) >>> 0, true);
    dv.setUint32(pos + 56, 0, true); // reloff
    dv.setUint32(pos + 60, 0, true); // nreloc
    dv.setUint32(pos + 64, (s.flags ?? 0) >>> 0, true);
    dv.setUint32(pos + 68, (s.reserved1 ?? 0) >>> 0, true);
    dv.setUint32(pos + 72, (s.reserved2 ?? 0) >>> 0, true);
    dv.setUint32(pos + 76, 0, true); // reserved3
    pos += 80;
  }
  return buf;
}

/**
 * Assemble a complete, standards-compliant 64-bit ARM64 Mach-O executable for iOS.
 */
export function buildMachOArm64(spec = {}) {
  const bundleId = spec.bundleId || 'com.omnios.ios.app';
  const delegateClassName = spec.delegateClassName || 'OmniAppDelegate';
  const actionSelector = spec.actionSelector || 'refreshWeather:';
  const title = spec.title ?? spec.appName ?? 'OmniOS iOS App';
  const nonce = spec.nonce !== undefined && spec.nonce !== null ? String(spec.nonce) : '';
  const operands =
    Array.isArray(spec.operands) && spec.operands.length >= 2
      ? [Number(spec.operands[0]) | 0, Number(spec.operands[1]) | 0]
      : [68, 4]; // default 68 + 4 = 72

  const initialLabelText =
    spec.initialLabelText ??
    (nonce ? `${title} | ${nonce}` : `${title} — ${operands[0] + operands[1]}°F Clear`);
  const buttonLabel = spec.buttonLabel ?? 'Refresh Forecast';
  const buttonResultText =
    spec.buttonResultText ??
    (nonce ? `Updated ${nonce}` : `Updated: ${operands[0] + operands[1] + (spec.tapStep ?? 3)}°F Breezy`);
  const defaultsKey = spec.defaultsKey ?? 'weather_status';
  const defaultsValue = spec.defaultsValue ?? (nonce ? `ready:${nonce}` : 'sunny_72F');
  const documentFile = spec.documentFile ?? 'forecast.txt';
  const documentContent =
    spec.documentContent ??
    (nonce ? `iOS Container Payload ${nonce}` : 'OmniOS Weather Island: 72F Clear');

  const laSpec = spec.liveActivity ?? {};
  const laTitle = laSpec.title ?? title;
  const laSubtitle = laSpec.subtitle ?? (nonce ? `Live ${nonce}` : 'Cupertino • Clear');
  const laLeading = laSpec.leading ?? 'SUN';
  const laTrailing = laSpec.trailing ?? `${operands[0] + operands[1]}°F`;
  const laBody = laSpec.body ?? initialLabelText;
  const laProgress = Number.isFinite(laSpec.progress) ? Math.max(0, Math.min(100, Math.round(laSpec.progress))) : 65;

  const laUpdatedTitle = laSpec.updatedTitle ?? laTitle;
  const laUpdatedSubtitle = laSpec.updatedSubtitle ?? (nonce ? `Refreshed ${nonce}` : 'Cupertino • Updated');
  const laUpdatedLeading = laSpec.updatedLeading ?? 'WIND';
  const laUpdatedTrailing =
    laSpec.updatedTrailing ?? `${operands[0] + operands[1] + (spec.tapStep ?? 3)}°F`;
  const laUpdatedBody = laSpec.updatedBody ?? buttonResultText;
  const laUpdatedProgress = Number.isFinite(laSpec.updatedProgress)
    ? Math.max(0, Math.min(100, Math.round(laSpec.updatedProgress)))
    : 90;

  const tapStep = Number.isFinite(spec.tapStep) ? Math.trunc(spec.tapStep) : 3;
  const copyOnTap = spec.copyOnTap !== false;
  const encryptFairPlay = Boolean(spec.encryptFairPlay);
  const entitlements = spec.entitlements ?? {
    'application-identifier': `OMNIOS0001.${bundleId}`,
    'aps-environment': 'development',
    'com.apple.developer.usernotifications': true,
    'com.apple.security.clipboard.write': true,
  };

  // ---- String & Metadata Pools ----
  const cstringMap = new Map();
  const cstringChunks = [];
  let cstringLen = 0;
  function internCString(str) {
    const s = String(str);
    if (cstringMap.has(s)) return cstringMap.get(s);
    const bytes = TEXT_ENCODER.encode(`${s}\0`);
    const off = cstringLen;
    cstringChunks.push(bytes);
    cstringLen += bytes.length;
    const entry = { offset: off, byteLength: bytes.length - 1 };
    cstringMap.set(s, entry);
    return entry;
  }

  const methnameMap = new Map();
  const methnameChunks = [];
  let methnameLen = 0;
  function internMethname(sel) {
    const s = String(sel);
    if (methnameMap.has(s)) return methnameMap.get(s);
    const bytes = TEXT_ENCODER.encode(`${s}\0`);
    const off = methnameLen;
    methnameChunks.push(bytes);
    methnameLen += bytes.length;
    methnameMap.set(s, off);
    return off;
  }

  const gotList = [];
  const gotIndexMap = new Map(); // symbol -> { index, libOrdinal }
  function internGot(symbol, libOrdinal = 1) {
    if (gotIndexMap.has(symbol)) return gotIndexMap.get(symbol).index;
    const index = gotList.length;
    const rec = { symbol, index, libOrdinal };
    gotList.push(rec);
    gotIndexMap.set(symbol, rec);
    return index;
  }

  const selrefList = [];
  const selrefIndexMap = new Map();
  function internSelref(sel) {
    if (selrefIndexMap.has(sel)) return selrefIndexMap.get(sel);
    internMethname(sel);
    const index = selrefList.length;
    selrefList.push(sel);
    selrefIndexMap.set(sel, index);
    return index;
  }

  const cfstringList = [];
  const cfstringIndexMap = new Map();
  function internCFString(str) {
    const s = String(str);
    if (cfstringIndexMap.has(s)) return cfstringIndexMap.get(s);
    const cstr = internCString(s);
    const index = cfstringList.length;
    cfstringList.push({ value: s, cstrOffset: cstr.offset, byteLength: cstr.byteLength });
    cfstringIndexMap.set(s, index);
    return index;
  }

  const globalNames = [
    'g_statusLabel',
    'g_liveActivityId',
    'g_tapCount',
    'g_computedValue',
    'g_window',
    'g_button',
  ];
  const globalIndexMap = new Map(globalNames.map((n, i) => [n, i]));

  // ---- Build ARM64 Machine Code ----
  const asm = new Arm64Assembler();

  // Helper to emit `[receiver selector]` with 0..7 args (handles stack spill for 7th arg!)
  function emitMsgSend(loadReceiverFn, selName, loadArgFns = []) {
    internGot('_objc_msgSend', 3);
    internSelref(selName);
    const hasStackArg = loadArgFns.length > 6;
    if (hasStackArg) {
      asm.subImm(31, 31, 16); // keep SP 16-byte aligned!
      // Evaluate 7th ObjC arg (index 6) into X9 and store at [SP + 0]
      loadArgFns[6](9);
      asm.strUImm64(9, 31, 0);
    }
    const regArgCount = Math.min(6, loadArgFns.length);
    for (let i = 0; i < regArgCount; i++) {
      loadArgFns[i](2 + i);
    }
    loadReceiverFn(0);
    asm.loadPtr(1, { kind: 'selref', key: selName });
    asm.callGot('_objc_msgSend');
    if (hasStackArg) {
      asm.addImm(31, 31, 16);
    }
  }

  function loadClassArg(clsName, libOrdinal = 1) {
    const sym = `_OBJC_CLASS_$_${clsName}`;
    internGot(sym, libOrdinal);
    return (reg) => asm.loadPtr(reg, { kind: 'got', key: sym });
  }

  function loadCFStrArg(str) {
    internCFString(str);
    return (reg) => asm.loadAddr(reg, { kind: 'cfstring', key: String(str) });
  }

  function loadRegArg(srcReg) {
    return (reg) => {
      if (reg !== srcReg) asm.movReg(reg, srcReg);
    };
  }

  function loadImmArg(immVal) {
    return (reg) => asm.movImm64(reg, immVal);
  }

  function loadGlobalArg(globalName) {
    return (reg) => asm.loadPtr(reg, { kind: 'global', key: globalName });
  }

  function loadSelArg(selName) {
    internSelref(selName);
    return (reg) => asm.loadPtr(reg, { kind: 'selref', key: selName });
  }

  let appClassMethods = [];

  if (typeof spec.customCode === 'function') {
    // Allow tests & SDK callers to assemble arbitrary custom ARM64 Mach-O binaries
    const customCtx = {
      internCString,
      internMethname,
      internGot,
      internSelref,
      internCFString,
      emitMsgSend,
      loadClassArg,
      loadCFStrArg,
      loadRegArg,
      loadImmArg,
      loadGlobalArg,
      loadSelArg,
    };
    asm.label('_main');
    spec.customCode(asm, customCtx);
  } else {
    // ---- 1. _main(argc, argv): invoke _UIApplicationMain(argc, argv, nil, @delegateClassName) ----
    internGot('_UIApplicationMain', 1);
    internGot('_NSLog', 2);
    internCFString(delegateClassName);

    asm.label('_main');
    asm.stpPre64(29, 30, 31, -16);
    asm.movReg(29, 31);
    asm.movz(2, 0); // principalClassName = nil -> UIApplication
    asm.loadAddr(3, { kind: 'cfstring', key: delegateClassName });
    asm.callGot('_UIApplicationMain');
    asm.ldpPost64(29, 30, 31, 16);
    asm.ret();

    // ---- 2. -[Delegate application:didFinishLaunchingWithOptions:] ----
    // Callee-saved regs used: X19=self, X20=window, X21=vc, X22=rootView, X23=label, X24=computedVal, X25=defaults
    asm.label('imp_didFinishLaunching');
    asm.stpPre64(29, 30, 31, -80);
    asm.movReg(29, 31);
    asm.stpSigned64(19, 20, 31, 16);
    asm.stpSigned64(21, 22, 31, 32);
    asm.stpSigned64(23, 24, 31, 48);
    asm.stpSigned64(25, 26, 31, 64);

    asm.movReg(19, 0); // X19 = self (AppDelegate)

    // Real ARM64 arithmetic on spec.operands -> X24
    asm.movImm64(9, operands[0]);
    asm.movImm64(10, operands[1]);
    if (spec.arithmeticOp === 'mul') {
      asm.mul(24, 9, 10);
    } else if (spec.arithmeticOp === 'sub') {
      asm.subReg(24, 9, 10);
    } else {
      asm.addReg(24, 9, 10);
    }
    asm.storePtr(24, { kind: 'global', key: 'g_computedValue' });

    // Log via NSLog using Apple ARM64 stack-slot variadics (Edge Case #24!)
    const launchLogFmt = nonce ? `[${title}] launch nonce=%@ val=%lld` : `[${title}] launch val=%lld`;
    internCFString(launchLogFmt);
    if (nonce) {
      internCFString(nonce);
      asm.subImm(31, 31, 16);
      asm.loadAddr(9, { kind: 'cfstring', key: nonce });
      asm.strUImm64(9, 31, 0); // stack slot 0 = %@
      asm.strUImm64(24, 31, 8); // stack slot 1 = %lld
      asm.loadAddr(0, { kind: 'cfstring', key: launchLogFmt });
      asm.callGot('_NSLog');
      asm.addImm(31, 31, 16);
    } else {
      asm.subImm(31, 31, 16);
      asm.strUImm64(24, 31, 0); // stack slot 0 = %lld
      asm.loadAddr(0, { kind: 'cfstring', key: launchLogFmt });
      asm.callGot('_NSLog');
      asm.addImm(31, 31, 16);
    }

    // NSUserDefaults standardUserDefaults -> setObject:defaultsValue forKey:defaultsKey & setInteger:X24 forKey:@"computed_value"
    emitMsgSend(loadClassArg('NSUserDefaults', 2), 'standardUserDefaults');
    asm.movReg(25, 0);
    emitMsgSend(loadRegArg(25), 'setObject:forKey:', [
      loadCFStrArg(defaultsValue),
      loadCFStrArg(defaultsKey),
    ]);
    emitMsgSend(loadRegArg(25), 'setInteger:forKey:', [
      loadRegArg(24),
      loadCFStrArg('computed_value'),
    ]);
    emitMsgSend(loadRegArg(25), 'setObject:forKey:', [
      loadCFStrArg('Active'),
      loadCFStrArg('lifecycle_state'),
    ]);

    // Write file into iOS UUID container Documents directory via NSFileManager + NSString
    emitMsgSend(loadClassArg('NSFileManager', 2), 'defaultManager');
    asm.movReg(26, 0);
    // [fm URLsForDirectory:9 (NSDocumentDirectory) inDomains:1]
    emitMsgSend(loadRegArg(26), 'URLsForDirectory:inDomains:', [loadImmArg(9), loadImmArg(1)]);
    emitMsgSend(loadRegArg(0), 'firstObject');
    emitMsgSend(loadRegArg(0), 'path');
    emitMsgSend(loadRegArg(0), 'stringByAppendingPathComponent:', [loadCFStrArg(documentFile)]);
    asm.movReg(26, 0); // X26 = container Documents file path NSString*
    emitMsgSend(loadCFStrArg(documentContent), 'writeToFile:atomically:encoding:error:', [
      loadRegArg(26),
      loadImmArg(1),
      loadImmArg(4),
      loadImmArg(0),
    ]);

    // Create UIWindow, UIViewController, UILabel, UIButton
    emitMsgSend(loadClassArg('UIWindow', 1), 'alloc');
    emitMsgSend(loadRegArg(0), 'initWithFrame:');
    asm.movReg(20, 0); // X20 = UIWindow
    asm.storePtr(20, { kind: 'global', key: 'g_window' });

    emitMsgSend(loadClassArg('UIViewController', 1), 'alloc');
    emitMsgSend(loadRegArg(0), 'init');
    asm.movReg(21, 0); // X21 = UIViewController
    emitMsgSend(loadRegArg(21), 'setTitle:', [loadCFStrArg(title)]);

    emitMsgSend(loadRegArg(21), 'view');
    asm.movReg(22, 0); // X22 = root UIView

    // UILabel (tag=100, accessibilityIdentifier="status_label")
    emitMsgSend(loadClassArg('UILabel', 1), 'alloc');
    emitMsgSend(loadRegArg(0), 'initWithFrame:');
    asm.movReg(23, 0); // X23 = status UILabel
    asm.storePtr(23, { kind: 'global', key: 'g_statusLabel' });
    emitMsgSend(loadRegArg(23), 'setText:', [loadCFStrArg(initialLabelText)]);
    emitMsgSend(loadRegArg(23), 'setTag:', [loadImmArg(100)]);
    emitMsgSend(loadRegArg(23), 'setAccessibilityIdentifier:', [loadCFStrArg('status_label')]);
    emitMsgSend(loadRegArg(22), 'addSubview:', [loadRegArg(23)]);

    // UIButton (tag=200, accessibilityIdentifier="refresh_btn", target=self, action=actionSelector)
    emitMsgSend(loadClassArg('UIButton', 1), 'buttonWithType:', [loadImmArg(1)]);
    asm.movReg(26, 0); // X26 = UIButton
    asm.storePtr(26, { kind: 'global', key: 'g_button' });
    emitMsgSend(loadRegArg(26), 'setTitle:forState:', [loadCFStrArg(buttonLabel), loadImmArg(0)]);
    emitMsgSend(loadRegArg(26), 'setTag:', [loadImmArg(200)]);
    emitMsgSend(loadRegArg(26), 'setAccessibilityIdentifier:', [loadCFStrArg('refresh_btn')]);
    emitMsgSend(loadRegArg(26), 'addTarget:action:forControlEvents:', [
      loadRegArg(19),
      loadSelArg(actionSelector),
      loadImmArg(0x40), // UIControlEventTouchUpInside
    ]);
    emitMsgSend(loadRegArg(22), 'addSubview:', [loadRegArg(26)]);

    // Mount RootViewController & Make Key And Visible
    emitMsgSend(loadRegArg(20), 'setRootViewController:', [loadRegArg(21)]);
    emitMsgSend(loadRegArg(20), 'makeKeyAndVisible');

    // Start Dynamic Island Live Activity via OmniLiveActivity
    emitMsgSend(
      loadClassArg('OmniLiveActivity', 1),
      'startActivityWithTitle:subtitle:leading:trailing:body:progress:',
      [
        loadCFStrArg(laTitle),
        loadCFStrArg(laSubtitle),
        loadCFStrArg(laLeading),
        loadCFStrArg(laTrailing),
        loadCFStrArg(laBody),
        loadImmArg(laProgress),
      ]
    );
    asm.storePtr(0, { kind: 'global', key: 'g_liveActivityId' });

    // Return YES (1)
    asm.movz(0, 1);
    asm.ldpSigned64(25, 26, 31, 64);
    asm.ldpSigned64(23, 24, 31, 48);
    asm.ldpSigned64(21, 22, 31, 32);
    asm.ldpSigned64(19, 20, 31, 16);
    asm.ldpPost64(29, 30, 31, 80);
    asm.ret();

    // ---- 3. -[Delegate refreshWeather:] (invoked by real UIButton tap!) ----
    asm.label('imp_buttonAction');
    asm.stpPre64(29, 30, 31, -48);
    asm.movReg(29, 31);
    asm.stpSigned64(19, 20, 31, 16);
    asm.stpSigned64(21, 22, 31, 32);

    // Increment g_tapCount and add tapStep to g_computedValue using real ARM64 ALU
    asm.loadPtr(19, { kind: 'global', key: 'g_tapCount' });
    asm.addImm(19, 19, 1);
    asm.storePtr(19, { kind: 'global', key: 'g_tapCount' });

    asm.loadPtr(20, { kind: 'global', key: 'g_computedValue' });
    asm.movImm64(9, tapStep);
    asm.addReg(20, 20, 9);
    asm.storePtr(20, { kind: 'global', key: 'g_computedValue' });

    // Update UILabel text
    asm.loadPtr(21, { kind: 'global', key: 'g_statusLabel' });
    emitMsgSend(loadRegArg(21), 'setText:', [loadCFStrArg(buttonResultText)]);

    // Update Dynamic Island Live Activity (7 args -> 7th arg progress passed on stack!)
    emitMsgSend(
      loadClassArg('OmniLiveActivity', 1),
      'updateActivity:title:subtitle:leading:trailing:body:progress:',
      [
        loadGlobalArg('g_liveActivityId'),
        loadCFStrArg(laUpdatedTitle),
        loadCFStrArg(laUpdatedSubtitle),
        loadCFStrArg(laUpdatedLeading),
        loadCFStrArg(laUpdatedTrailing),
        loadCFStrArg(laUpdatedBody),
        loadImmArg(laUpdatedProgress),
      ]
    );

    // Persist refresh_count and computed_value to NSUserDefaults
    emitMsgSend(loadClassArg('NSUserDefaults', 2), 'standardUserDefaults');
    asm.movReg(22, 0);
    emitMsgSend(loadRegArg(22), 'setInteger:forKey:', [
      loadRegArg(19),
      loadCFStrArg('refresh_count'),
    ]);
    emitMsgSend(loadRegArg(22), 'setInteger:forKey:', [
      loadRegArg(20),
      loadCFStrArg('computed_value'),
    ]);

    if (copyOnTap) {
      // Copy updated result text to UIPasteboard -> live SharedClipboard!
      emitMsgSend(loadClassArg('UIPasteboard', 1), 'generalPasteboard');
      emitMsgSend(loadRegArg(0), 'setString:', [loadCFStrArg(buttonResultText)]);
    }

    // Log refresh via NSLog with Apple ARM64 stack variadics
    const tapLogFmt = `[${title}] tap=%lld val=%lld`;
    internCFString(tapLogFmt);
    asm.subImm(31, 31, 16);
    asm.strUImm64(19, 31, 0);
    asm.strUImm64(20, 31, 8);
    asm.loadAddr(0, { kind: 'cfstring', key: tapLogFmt });
    asm.callGot('_NSLog');
    asm.addImm(31, 31, 16);

    asm.movz(0, 0);
    asm.ldpSigned64(21, 22, 31, 32);
    asm.ldpSigned64(19, 20, 31, 16);
    asm.ldpPost64(29, 30, 31, 48);
    asm.ret();

    // ---- 4. -[Delegate application:openURL:options:] ----
    // Args: X0=self, X1=_cmd, X2=app, X3=NSURL*, X4=options
    asm.label('imp_openURL');
    asm.stpPre64(29, 30, 31, -48);
    asm.movReg(29, 31);
    asm.stpSigned64(19, 20, 31, 16);
    asm.stpSigned64(21, 22, 31, 32);

    asm.movReg(19, 3); // X19 = NSURL*
    emitMsgSend(loadRegArg(19), 'absoluteString');
    asm.movReg(20, 0); // X20 = url NSString*

    // Save last_opened_url into NSUserDefaults
    emitMsgSend(loadClassArg('NSUserDefaults', 2), 'standardUserDefaults');
    emitMsgSend(loadRegArg(0), 'setObject:forKey:', [
      loadRegArg(20),
      loadCFStrArg('last_opened_url'),
    ]);

    // Update status UILabel to "Opened: <url>"
    emitMsgSend(loadCFStrArg('Opened: '), 'stringByAppendingString:', [loadRegArg(20)]);
    asm.movReg(21, 0);
    asm.loadPtr(22, { kind: 'global', key: 'g_statusLabel' });
    emitMsgSend(loadRegArg(22), 'setText:', [loadRegArg(21)]);

    // Log opened URL via NSLog stack variadic
    const urlLogFmt = `[${title}] openURL=%@`;
    internCFString(urlLogFmt);
    asm.subImm(31, 31, 16);
    asm.strUImm64(20, 31, 0);
    asm.loadAddr(0, { kind: 'cfstring', key: urlLogFmt });
    asm.callGot('_NSLog');
    asm.addImm(31, 31, 16);

    asm.movz(0, 1);
    asm.ldpSigned64(21, 22, 31, 32);
    asm.ldpSigned64(19, 20, 31, 16);
    asm.ldpPost64(29, 30, 31, 48);
    asm.ret();

    // ---- 5. -[Delegate applicationDidEnterBackground:] ----
    asm.label('imp_didEnterBackground');
    asm.stpPre64(29, 30, 31, -16);
    asm.movReg(29, 31);
    emitMsgSend(loadClassArg('NSUserDefaults', 2), 'standardUserDefaults');
    emitMsgSend(loadRegArg(0), 'setObject:forKey:', [
      loadCFStrArg('Suspended'),
      loadCFStrArg('lifecycle_state'),
    ]);
    asm.movz(0, 0);
    asm.ldpPost64(29, 30, 31, 16);
    asm.ret();

    // ---- 6. -[Delegate applicationWillEnterForeground:] ----
    asm.label('imp_willEnterForeground');
    asm.stpPre64(29, 30, 31, -16);
    asm.movReg(29, 31);
    emitMsgSend(loadClassArg('NSUserDefaults', 2), 'standardUserDefaults');
    emitMsgSend(loadRegArg(0), 'setObject:forKey:', [
      loadCFStrArg('Active'),
      loadCFStrArg('lifecycle_state'),
    ]);
    asm.movz(0, 0);
    asm.ldpPost64(29, 30, 31, 16);
    asm.ret();

    // ---- 7. -[Delegate applicationWillTerminate:] ----
    asm.label('imp_willTerminate');
    asm.stpPre64(29, 30, 31, -16);
    asm.movReg(29, 31);
    asm.loadPtr(9, { kind: 'global', key: 'g_liveActivityId' });
    asm.cbz(9, 'term_done');
    emitMsgSend(loadClassArg('OmniLiveActivity', 1), 'endActivity:', [
      loadGlobalArg('g_liveActivityId'),
    ]);
    asm.label('term_done');
    asm.movz(0, 0);
    asm.ldpPost64(29, 30, 31, 16);
    asm.ret();

    appClassMethods = [
      { sel: 'application:didFinishLaunchingWithOptions:', types: 'B32@0:8@16@24', label: 'imp_didFinishLaunching' },
      { sel: actionSelector, types: 'v24@0:8@16', label: 'imp_buttonAction' },
      { sel: 'application:openURL:options:', types: 'B40@0:8@16@24@32', label: 'imp_openURL' },
      { sel: 'applicationDidEnterBackground:', types: 'v24@0:8@16', label: 'imp_didEnterBackground' },
      { sel: 'applicationWillEnterForeground:', types: 'v24@0:8@16', label: 'imp_willEnterForeground' },
      { sel: 'applicationWillTerminate:', types: 'v24@0:8@16', label: 'imp_willTerminate' },
    ];
  }

  // Intern class name & method names/types into string pools
  const hasAppClass = appClassMethods.length > 0;
  const classNameCstr = hasAppClass ? internCString(delegateClassName) : null;
  for (const m of appClassMethods) {
    internMethname(m.sel);
    internCString(m.types);
  }

  // Ensure at least one GOT entry & CFString entry exist cleanly
  if (gotList.length === 0) internGot('_exit', 4);
  if (selrefList.length === 0) internSelref('init');
  if (cfstringList.length === 0) internCFString(bundleId);

  // ---- Build Dylib Load Commands (needed to know header + commands size) ----
  const dylibPaths = [
    '/System/Library/Frameworks/UIKit.framework/UIKit',
    '/System/Library/Frameworks/Foundation.framework/Foundation',
    '/usr/lib/libobjc.A.dylib',
    '/usr/lib/libSystem.B.dylib',
  ];
  const dylibCmds = dylibPaths.map((p) => buildDylibLoadCommand(p));
  const dylinkerCmd = buildDylinkerLoadCommand('/usr/lib/dyld');

  const nTextSects = 3; // __text, __cstring, __objc_methname
  const nDataSects = 7; // __got, __objc_selrefs, __objc_classlist, __objc_const, __objc_data, __cfstring, __data
  const segPagezeroSize = 72;
  const segTextCmdSize = 72 + nTextSects * 80;
  const segDataCmdSize = 72 + nDataSects * 80;
  const segLinkeditCmdSize = 72;
  const dyldInfoCmdSize = 48;
  const symtabCmdSize = 24;
  const dysymtabCmdSize = 80;
  const uuidCmdSize = 24;
  const buildVerCmdSize = 24;
  const mainCmdSize = 24;
  const codeSigCmdSize = 16;
  const encInfoCmdSize = encryptFairPlay ? 24 : 0;

  const sizeofcmds =
    segPagezeroSize +
    segTextCmdSize +
    segDataCmdSize +
    segLinkeditCmdSize +
    dyldInfoCmdSize +
    symtabCmdSize +
    dysymtabCmdSize +
    dylinkerCmd.length +
    uuidCmdSize +
    buildVerCmdSize +
    mainCmdSize +
    dylibCmds.reduce((acc, b) => acc + b.length, 0) +
    encInfoCmdSize +
    codeSigCmdSize;

  const ncmds = 12 + dylibCmds.length + (encryptFairPlay ? 1 : 0);

  // ---- Layout __TEXT Segment ----
  const textVmAddr = 0x100000000;
  const textCodeOff = alignUp(32 + sizeofcmds, 16);
  const textCodeSize = Math.max(4, asm.byteLength);
  const cstringOff = alignUp(textCodeOff + textCodeSize, 8);
  const cstringSize = Math.max(1, cstringLen);
  const methnameOff = alignUp(cstringOff + cstringSize, 8);
  const methnameSize = Math.max(1, methnameLen);
  const textSegSize = alignUp(methnameOff + methnameSize, MACHO_PAGE_SIZE);

  // ---- Layout __DATA Segment ----
  const dataFileOff = textSegSize;
  const dataVmAddr = textVmAddr + textSegSize;
  let dCur = 0;

  const gotRelOff = dCur;
  const gotSize = gotList.length * 8;
  dCur = alignUp(dCur + gotSize, 8);

  const selrefsRelOff = dCur;
  const selrefsSize = selrefList.length * 8;
  dCur = alignUp(dCur + selrefsSize, 8);

  const classlistRelOff = dCur;
  const classlistSize = hasAppClass ? 8 : 0;
  dCur = alignUp(dCur + Math.max(8, classlistSize), 8);

  const objcConstRelOff = dCur;
  const methodListRelOff = dCur;
  const methodListSize = hasAppClass ? 8 + appClassMethods.length * 24 : 0;
  const classRoRelOff = alignUp(methodListRelOff + methodListSize, 8);
  const metaclassRoRelOff = classRoRelOff + 72;
  const objcConstSize = hasAppClass ? metaclassRoRelOff + 72 - objcConstRelOff : 8;
  dCur = alignUp(objcConstRelOff + objcConstSize, 8);

  const objcDataRelOff = dCur;
  const metaclassRelOff = dCur;
  const classRelOff = dCur + 40;
  const objcDataSize = hasAppClass ? 80 : 8;
  dCur = alignUp(objcDataRelOff + objcDataSize, 8);

  const cfstringRelOff = dCur;
  const cfstringSize = cfstringList.length * 32;
  dCur = alignUp(dCur + cfstringSize, 8);

  const globalsRelOff = dCur;
  const globalsSize = globalNames.length * 8;
  dCur = alignUp(dCur + globalsSize, 8);

  const dataSegSize = alignUp(dCur, MACHO_PAGE_SIZE);

  // ---- Finalize ARM64 Code with Exact VAs ----
  const textCodeVA = textVmAddr + textCodeOff;
  const cstringBaseVA = textVmAddr + cstringOff;
  const methnameBaseVA = textVmAddr + methnameOff;

  const codeBytes = asm.finalize(textCodeVA, (target) => {
    switch (target.kind) {
      case 'got': {
        const rec = gotIndexMap.get(target.key);
        if (!rec) throw new Error(`buildMachOArm64: unknown GOT symbol "${target.key}"`);
        return dataVmAddr + gotRelOff + rec.index * 8;
      }
      case 'selref': {
        const idx = selrefIndexMap.get(target.key);
        if (idx === undefined) throw new Error(`buildMachOArm64: unknown selref "${target.key}"`);
        return dataVmAddr + selrefsRelOff + idx * 8;
      }
      case 'cfstring': {
        const idx = cfstringIndexMap.get(target.key);
        if (idx === undefined) throw new Error(`buildMachOArm64: unknown cfstring "${target.key}"`);
        return dataVmAddr + cfstringRelOff + idx * 32;
      }
      case 'global': {
        const idx = globalIndexMap.get(target.key);
        if (idx === undefined) throw new Error(`buildMachOArm64: unknown global "${target.key}"`);
        return dataVmAddr + globalsRelOff + idx * 8;
      }
      case 'cstring': {
        const c = cstringMap.get(target.key);
        if (!c) throw new Error(`buildMachOArm64: unknown cstring "${target.key}"`);
        return cstringBaseVA + c.offset;
      }
      default:
        throw new Error(`buildMachOArm64: unknown reloc target kind "${target.kind}"`);
    }
  });

  // ---- Populate __DATA Bytes & Record Dyld Rebases + Binds ----
  const dataBuf = new Uint8Array(dataSegSize);
  const dataView = new DataView(dataBuf.buffer);
  const rebaseOffsets = []; // offsets within __DATA (segIndex = 2)
  const bindRecords = []; // { dataOffset, symbol, libOrdinal }

  // 1. __got binds
  for (const g of gotList) {
    bindRecords.push({
      dataOffset: gotRelOff + g.index * 8,
      symbol: g.symbol,
      libOrdinal: g.libOrdinal,
    });
  }

  // 2. __objc_selrefs
  for (let i = 0; i < selrefList.length; i++) {
    const off = selrefsRelOff + i * 8;
    const strVA = BigInt(methnameBaseVA + methnameMap.get(selrefList[i]));
    dataView.setBigUint64(off, strVA, true);
    rebaseOffsets.push(off);
  }

  // 3. __objc_classlist, __objc_const, __objc_data
  if (hasAppClass) {
    const classVA = BigInt(dataVmAddr + classRelOff);
    const metaclassVA = BigInt(dataVmAddr + metaclassRelOff);
    const methodListVA = BigInt(dataVmAddr + methodListRelOff);
    const classRoVA = BigInt(dataVmAddr + classRoRelOff);
    const metaclassRoVA = BigInt(dataVmAddr + metaclassRoRelOff);
    const classNameVA = BigInt(cstringBaseVA + classNameCstr.offset);

    // __objc_classlist[0] = class_t VA
    dataView.setBigUint64(classlistRelOff, classVA, true);
    rebaseOffsets.push(classlistRelOff);

    // method_list_t in __objc_const
    dataView.setUint32(methodListRelOff, 24, true); // entsize = 24
    dataView.setUint32(methodListRelOff + 4, appClassMethods.length, true);
    for (let i = 0; i < appClassMethods.length; i++) {
      const m = appClassMethods[i];
      const mOff = methodListRelOff + 8 + i * 24;
      const selVA = BigInt(methnameBaseVA + methnameMap.get(m.sel));
      const typesVA = BigInt(cstringBaseVA + cstringMap.get(m.types).offset);
      const impVA = BigInt(textCodeVA + asm._labels.get(m.label));
      dataView.setBigUint64(mOff, selVA, true);
      dataView.setBigUint64(mOff + 8, typesVA, true);
      dataView.setBigUint64(mOff + 16, impVA, true);
      rebaseOffsets.push(mOff, mOff + 8, mOff + 16);
    }

    // class_ro_t
    dataView.setUint32(classRoRelOff + 0, 0, true); // flags
    dataView.setUint32(classRoRelOff + 4, 8, true); // instanceStart
    dataView.setUint32(classRoRelOff + 8, 32, true); // instanceSize
    dataView.setBigUint64(classRoRelOff + 24, classNameVA, true);
    dataView.setBigUint64(classRoRelOff + 32, methodListVA, true);
    rebaseOffsets.push(classRoRelOff + 24, classRoRelOff + 32);

    // metaclass_ro_t
    dataView.setUint32(metaclassRoRelOff + 0, 1, true); // RO_META
    dataView.setUint32(metaclassRoRelOff + 4, 40, true);
    dataView.setUint32(metaclassRoRelOff + 8, 40, true);
    dataView.setBigUint64(metaclassRoRelOff + 24, classNameVA, true);
    rebaseOffsets.push(metaclassRoRelOff + 24);

    // metaclass_t
    bindRecords.push({ dataOffset: metaclassRelOff + 0, symbol: '_OBJC_METACLASS_$_NSObject', libOrdinal: 3 });
    bindRecords.push({ dataOffset: metaclassRelOff + 8, symbol: '_OBJC_METACLASS_$_NSObject', libOrdinal: 3 });
    dataView.setBigUint64(metaclassRelOff + 32, metaclassRoVA, true);
    rebaseOffsets.push(metaclassRelOff + 32);

    // class_t
    dataView.setBigUint64(classRelOff + 0, metaclassVA, true);
    rebaseOffsets.push(classRelOff + 0);
    bindRecords.push({ dataOffset: classRelOff + 8, symbol: '_OBJC_CLASS_$_NSObject', libOrdinal: 3 });
    dataView.setBigUint64(classRelOff + 32, classRoVA, true);
    rebaseOffsets.push(classRelOff + 32);
  }

  // 4. __cfstring (32 bytes each)
  for (let i = 0; i < cfstringList.length; i++) {
    const cf = cfstringList[i];
    const off = cfstringRelOff + i * 32;
    bindRecords.push({
      dataOffset: off,
      symbol: '___CFConstantStringClassReference',
      libOrdinal: 2, // Foundation
    });
    dataView.setBigUint64(off + 8, 0x00000000000007c8n, true); // flags: UTF-8 constant CFString
    dataView.setBigUint64(off + 16, BigInt(cstringBaseVA + cf.cstrOffset), true);
    dataView.setBigUint64(off + 24, BigInt(cf.byteLength), true);
    rebaseOffsets.push(off + 16);
  }

  // ---- Build __LINKEDIT (Dyld Rebase, Dyld Bind, Symtab, Indirect Symtab, Strtab, CodeSignature) ----
  const rebaseBytes = [];
  if (rebaseOffsets.length > 0) {
    rebaseBytes.push(MACHO_CONSTANTS.REBASE_OPCODE_SET_TYPE_IMM | 1); // REBASE_TYPE_POINTER
    for (const off of rebaseOffsets) {
      rebaseBytes.push(MACHO_CONSTANTS.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2); // segIndex 2 = __DATA
      rebaseBytes.push(...encodeUleb128(off));
      rebaseBytes.push(MACHO_CONSTANTS.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1);
    }
    rebaseBytes.push(MACHO_CONSTANTS.REBASE_OPCODE_DONE);
  }
  const rebaseBuf = Uint8Array.from(rebaseBytes);

  const bindBytes = [];
  if (bindRecords.length > 0) {
    bindBytes.push(MACHO_CONSTANTS.BIND_OPCODE_SET_TYPE_IMM | 1); // BIND_TYPE_POINTER
    for (const b of bindRecords) {
      bindBytes.push(MACHO_CONSTANTS.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | (b.libOrdinal & 0x0f));
      bindBytes.push(MACHO_CONSTANTS.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
      for (const byte of TEXT_ENCODER.encode(b.symbol)) bindBytes.push(byte);
      bindBytes.push(0);
      bindBytes.push(MACHO_CONSTANTS.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2); // segIndex 2 = __DATA
      bindBytes.push(...encodeUleb128(b.dataOffset));
      bindBytes.push(MACHO_CONSTANTS.BIND_OPCODE_DO_BIND);
    }
    bindBytes.push(MACHO_CONSTANTS.BIND_OPCODE_DONE);
  }
  const bindBuf = Uint8Array.from(bindBytes);

  // Symbol table: _main (defined ext) + all GOT symbols (undefined ext)
  const strtabParts = [Uint8Array.from([0x20, 0x00])]; // Apple Mach-O strtab starts with " \0"
  let strtabCursor = 2;
  const symEntries = [];

  const addSymStr = (s) => {
    const off = strtabCursor;
    const b = TEXT_ENCODER.encode(`${s}\0`);
    strtabParts.push(b);
    strtabCursor += b.length;
    return off;
  };

  // Defined external symbol 0: _main
  const mainLabelOff = asm._labels.get('_main') ?? 0;
  symEntries.push({
    strx: addSymStr('_main'),
    type: 0x0f, // N_SECT | N_EXT
    sect: 1, // __TEXT.__text
    desc: 0,
    value: BigInt(textCodeVA + mainLabelOff),
  });

  // Undefined external symbols 1..gotList.length
  const indirectSymIndices = [];
  for (const g of gotList) {
    const symIdx = symEntries.length;
    symEntries.push({
      strx: addSymStr(g.symbol),
      type: 0x01, // N_UNDF | N_EXT
      sect: 0,
      desc: (g.libOrdinal & 0xff) << 8,
      value: 0n,
    });
    indirectSymIndices.push(symIdx);
  }

  const symtabBuf = new Uint8Array(symEntries.length * 16);
  const symView = new DataView(symtabBuf.buffer);
  for (let i = 0; i < symEntries.length; i++) {
    const s = symEntries[i];
    const p = i * 16;
    symView.setUint32(p, s.strx, true);
    symtabBuf[p + 4] = s.type;
    symtabBuf[p + 5] = s.sect;
    symView.setUint16(p + 6, s.desc, true);
    symView.setBigUint64(p + 8, s.value, true);
  }

  const indirectBuf = new Uint8Array(indirectSymIndices.length * 4);
  const indView = new DataView(indirectBuf.buffer);
  for (let i = 0; i < indirectSymIndices.length; i++) {
    indView.setUint32(i * 4, indirectSymIndices[i], true);
  }

  const strtabLen = alignUp(strtabCursor, 8);
  const strtabBuf = new Uint8Array(strtabLen);
  let sPos = 0;
  for (const part of strtabParts) {
    strtabBuf.set(part, sPos);
    sPos += part.length;
  }

  // Layout inside __LINKEDIT
  const linkeditFileOff = dataFileOff + dataSegSize;
  const linkeditVmAddr = dataVmAddr + dataSegSize;
  let lCur = 0;

  const rebaseRelOff = lCur;
  lCur = alignUp(lCur + rebaseBuf.length, 8);

  const bindRelOff = lCur;
  lCur = alignUp(lCur + bindBuf.length, 8);

  const symtabRelOff = lCur;
  lCur = alignUp(lCur + symtabBuf.length, 8);

  const indirectRelOff = lCur;
  lCur = alignUp(lCur + indirectBuf.length, 8);

  const strtabRelOff = lCur;
  lCur = alignUp(lCur + strtabBuf.length, 16);

  const codeSigRelOff = lCur;
  const codeSigBuf = buildCodeSignatureSuperBlob(bundleId, entitlements, linkeditFileOff + codeSigRelOff);
  lCur += codeSigBuf.length;

  const linkeditFileSize = lCur;
  const linkeditVmSize = alignUp(linkeditFileSize, MACHO_PAGE_SIZE);
  const totalFileSize = linkeditFileOff + linkeditFileSize;

  // ---- Assemble Final Mach-O File ----
  const fileBuf = new Uint8Array(totalFileSize);
  const fileView = new DataView(fileBuf.buffer);

  // 1. mach_header_64 (32 bytes)
  fileView.setUint32(0, MACHO_CONSTANTS.MH_MAGIC_64, true);
  fileView.setUint32(4, MACHO_CONSTANTS.CPU_TYPE_ARM64, true);
  fileView.setUint32(8, 0, true); // CPU_SUBTYPE_ARM64_ALL
  fileView.setUint32(12, MACHO_CONSTANTS.MH_EXECUTE, true);
  fileView.setUint32(16, ncmds, true);
  fileView.setUint32(20, sizeofcmds, true);
  fileView.setUint32(24, 0x00200085, true); // MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE
  fileView.setUint32(28, 0, true);

  // 2. Load Commands
  let cmdPos = 32;
  const pushCmd = (buf) => {
    fileBuf.set(buf, cmdPos);
    cmdPos += buf.length;
  };

  // LC_SEGMENT_64 __PAGEZERO
  pushCmd(
    buildSegment64Command({
      segname: '__PAGEZERO',
      vmaddr: 0,
      vmsize: 0x100000000,
      fileoff: 0,
      filesize: 0,
      maxprot: 0,
      initprot: 0,
    })
  );

  // LC_SEGMENT_64 __TEXT
  pushCmd(
    buildSegment64Command(
      {
        segname: '__TEXT',
        vmaddr: textVmAddr,
        vmsize: textSegSize,
        fileoff: 0,
        filesize: textSegSize,
        maxprot: 5,
        initprot: 5,
      },
      [
        {
          sectname: '__text',
          addr: textCodeVA,
          size: textCodeSize,
          offset: textCodeOff,
          align: 2,
          flags: 0x80000400, // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
        },
        {
          sectname: '__cstring',
          addr: cstringBaseVA,
          size: cstringSize,
          offset: cstringOff,
          align: 0,
          flags: MACHO_CONSTANTS.S_CSTRING_LITERALS,
        },
        {
          sectname: '__objc_methname',
          addr: methnameBaseVA,
          size: methnameSize,
          offset: methnameOff,
          align: 0,
          flags: MACHO_CONSTANTS.S_CSTRING_LITERALS,
        },
      ]
    )
  );

  // LC_SEGMENT_64 __DATA
  pushCmd(
    buildSegment64Command(
      {
        segname: '__DATA',
        vmaddr: dataVmAddr,
        vmsize: dataSegSize,
        fileoff: dataFileOff,
        filesize: dataSegSize,
        maxprot: 3,
        initprot: 3,
      },
      [
        {
          sectname: '__got',
          addr: dataVmAddr + gotRelOff,
          size: gotSize,
          offset: dataFileOff + gotRelOff,
          align: 3,
          flags: MACHO_CONSTANTS.S_NON_LAZY_SYMBOL_POINTERS,
          reserved1: 0,
        },
        {
          sectname: '__objc_selrefs',
          addr: dataVmAddr + selrefsRelOff,
          size: selrefsSize,
          offset: dataFileOff + selrefsRelOff,
          align: 3,
          flags: 0x10000005, // S_ATTR_NO_DEAD_STRIP | S_LITERAL_POINTERS
        },
        {
          sectname: '__objc_classlist',
          addr: dataVmAddr + classlistRelOff,
          size: classlistSize,
          offset: dataFileOff + classlistRelOff,
          align: 3,
          flags: 0x10000000, // S_ATTR_NO_DEAD_STRIP
        },
        {
          sectname: '__objc_const',
          addr: dataVmAddr + objcConstRelOff,
          size: objcConstSize,
          offset: dataFileOff + objcConstRelOff,
          align: 3,
          flags: 0,
        },
        {
          sectname: '__objc_data',
          addr: dataVmAddr + objcDataRelOff,
          size: objcDataSize,
          offset: dataFileOff + objcDataRelOff,
          align: 3,
          flags: 0,
        },
        {
          sectname: '__cfstring',
          addr: dataVmAddr + cfstringRelOff,
          size: cfstringSize,
          offset: dataFileOff + cfstringRelOff,
          align: 3,
          flags: 0,
        },
        {
          sectname: '__data',
          addr: dataVmAddr + globalsRelOff,
          size: globalsSize,
          offset: dataFileOff + globalsRelOff,
          align: 3,
          flags: 0,
        },
      ]
    )
  );

  // LC_SEGMENT_64 __LINKEDIT
  pushCmd(
    buildSegment64Command({
      segname: '__LINKEDIT',
      vmaddr: linkeditVmAddr,
      vmsize: linkeditVmSize,
      fileoff: linkeditFileOff,
      filesize: linkeditFileSize,
      maxprot: 1,
      initprot: 1,
    })
  );

  // LC_DYLD_INFO_ONLY (48 bytes)
  {
    const buf = new Uint8Array(48);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.LC_DYLD_INFO_ONLY, true);
    dv.setUint32(4, 48, true);
    dv.setUint32(8, rebaseBuf.length > 0 ? linkeditFileOff + rebaseRelOff : 0, true);
    dv.setUint32(12, rebaseBuf.length, true);
    dv.setUint32(16, bindBuf.length > 0 ? linkeditFileOff + bindRelOff : 0, true);
    dv.setUint32(20, bindBuf.length, true);
    pushCmd(buf);
  }

  // LC_SYMTAB (24 bytes)
  {
    const buf = new Uint8Array(24);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.LC_SYMTAB, true);
    dv.setUint32(4, 24, true);
    dv.setUint32(8, linkeditFileOff + symtabRelOff, true);
    dv.setUint32(12, symEntries.length, true);
    dv.setUint32(16, linkeditFileOff + strtabRelOff, true);
    dv.setUint32(20, strtabBuf.length, true);
    pushCmd(buf);
  }

  // LC_DYSYMTAB (80 bytes)
  {
    const buf = new Uint8Array(80);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.LC_DYSYMTAB, true);
    dv.setUint32(4, 80, true);
    dv.setUint32(8, 0, true); // ilocalsym
    dv.setUint32(12, 0, true); // nlocalsym
    dv.setUint32(16, 0, true); // iextdefsym
    dv.setUint32(20, 1, true); // nextdefsym (_main)
    dv.setUint32(24, 1, true); // iundefsym
    dv.setUint32(28, gotList.length, true); // nundefsym
    dv.setUint32(56, linkeditFileOff + indirectRelOff, true);
    dv.setUint32(60, indirectSymIndices.length, true);
    pushCmd(buf);
  }

  // LC_LOAD_DYLINKER
  pushCmd(dylinkerCmd);

  // LC_UUID (24 bytes — deterministic SHA-256 derived)
  {
    const buf = new Uint8Array(24);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.LC_UUID, true);
    dv.setUint32(4, 24, true);
    const uuidHash = crypto.createHash('sha256').update(bundleId).update(codeBytes).digest();
    buf.set(uuidHash.subarray(0, 16), 8);
    pushCmd(buf);
  }

  // LC_BUILD_VERSION (24 bytes — PLATFORM_IOS = 2)
  {
    const buf = new Uint8Array(24);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.LC_BUILD_VERSION, true);
    dv.setUint32(4, 24, true);
    dv.setUint32(8, MACHO_CONSTANTS.PLATFORM_IOS, true); // 2 = iOS
    dv.setUint32(12, 0x00110000, true); // minos 17.0.0
    dv.setUint32(16, 0x00120000, true); // sdk 18.0.0
    dv.setUint32(20, 0, true); // ntools
    pushCmd(buf);
  }

  // LC_MAIN (24 bytes)
  {
    const buf = new Uint8Array(24);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.LC_MAIN, true);
    dv.setUint32(4, 24, true);
    dv.setBigUint64(8, BigInt(textCodeOff + mainLabelOff), true);
    dv.setBigUint64(16, 0n, true);
    pushCmd(buf);
  }

  // LC_LOAD_DYLIB x4
  for (const dc of dylibCmds) pushCmd(dc);

  // Optional LC_ENCRYPTION_INFO_64 (FairPlay DRM test fixture)
  if (encryptFairPlay) {
    const buf = new Uint8Array(24);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.LC_ENCRYPTION_INFO_64, true);
    dv.setUint32(4, 24, true);
    dv.setUint32(8, textCodeOff, true);
    dv.setUint32(12, textCodeSize, true);
    dv.setUint32(16, 1, true); // cryptid = 1 (FairPlay encrypted)
    dv.setUint32(20, 0, true);
    pushCmd(buf);
  }

  // LC_CODE_SIGNATURE (16 bytes)
  {
    const buf = new Uint8Array(16);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, MACHO_CONSTANTS.LC_CODE_SIGNATURE, true);
    dv.setUint32(4, 16, true);
    dv.setUint32(8, linkeditFileOff + codeSigRelOff, true);
    dv.setUint32(12, codeSigBuf.length, true);
    pushCmd(buf);
  }

  // 3. Copy __TEXT sections
  fileBuf.set(codeBytes, textCodeOff);
  let cPos = cstringOff;
  for (const chunk of cstringChunks) {
    fileBuf.set(chunk, cPos);
    cPos += chunk.length;
  }
  let mPos = methnameOff;
  for (const chunk of methnameChunks) {
    fileBuf.set(chunk, mPos);
    mPos += chunk.length;
  }

  // 4. Copy __DATA segment
  fileBuf.set(dataBuf, dataFileOff);

  // 5. Copy __LINKEDIT payloads
  fileBuf.set(rebaseBuf, linkeditFileOff + rebaseRelOff);
  fileBuf.set(bindBuf, linkeditFileOff + bindRelOff);
  fileBuf.set(symtabBuf, linkeditFileOff + symtabRelOff);
  fileBuf.set(indirectBuf, linkeditFileOff + indirectRelOff);
  fileBuf.set(strtabBuf, linkeditFileOff + strtabRelOff);
  fileBuf.set(codeSigBuf, linkeditFileOff + codeSigRelOff);

  return fileBuf;
}

// ============================================================================
// Pure-JS iOS `.ipa` Packager
// ============================================================================

/**
 * Build a complete, externally-verifiable iOS `.ipa` package (`Uint8Array`)
 * containing a real ARM64 Mach-O executable, binary `bplist00` `Info.plist`,
 * and optional `embedded.mobileprovision`.
 */
export function buildIosIpa(spec = {}) {
  const bundleId = spec.bundleId || 'com.omnios.ios.app';
  const appName = spec.appName || spec.title || 'OmniOSApp';
  const bundleName = spec.bundleName || appName.replace(/[^A-Za-z0-9_-]/g, '') || 'OmniOSApp';
  const executableName = spec.executableName || bundleName;
  const version = spec.version || '1.0.0';
  const buildNumber = spec.buildNumber || '100';
  const urlSchemes = Array.isArray(spec.urlSchemes) ? spec.urlSchemes : [];
  const documentTypes = Array.isArray(spec.documentTypes) ? spec.documentTypes : [];
  const supportsLiveActivities = spec.supportsLiveActivities !== false;

  const entitlements = spec.entitlements ?? {
    'application-identifier': `OMNIOS0001.${bundleId}`,
    'aps-environment': 'development',
    'com.apple.developer.usernotifications': true,
    'com.apple.security.clipboard.write': true,
  };

  const infoPlist = {
    CFBundleDevelopmentRegion: 'en',
    CFBundleDisplayName: appName,
    CFBundleExecutable: executableName,
    CFBundleIdentifier: bundleId,
    CFBundleInfoDictionaryVersion: '6.0',
    CFBundleName: bundleName,
    CFBundlePackageType: 'APPL',
    CFBundleShortVersionString: version,
    CFBundleVersion: buildNumber,
    LSRequiresIPhoneOS: true,
    MinimumOSVersion: '17.0',
    UIDeviceFamily: [1, 2],
    UIRequiredDeviceCapabilities: ['arm64'],
    NSSupportsLiveActivities: supportsLiveActivities,
    UIPasteboard: true,
    ...(spec.usageDescriptions ?? {}),
    ...(spec.extraInfoPlist ?? {}),
  };

  if (urlSchemes.length > 0) {
    infoPlist.CFBundleURLTypes = [
      {
        CFBundleTypeRole: 'Viewer',
        CFBundleURLName: bundleId,
        CFBundleURLSchemes: urlSchemes,
      },
    ];
  }

  if (documentTypes.length > 0) {
    infoPlist.CFBundleDocumentTypes = documentTypes;
  }

  const infoPlistBytes = spec.xmlInfoPlist
    ? TEXT_ENCODER.encode(writeXmlPlist(infoPlist))
    : writeBinaryPlist(infoPlist);

  const machoBytes = buildMachOArm64({
    ...spec,
    bundleId,
    appName,
    executableName,
    entitlements,
  });

  const provisionPlistXml = writeXmlPlist({
    AppIDName: appName,
    ApplicationIdentifierPrefix: ['OMNIOS0001'],
    Name: `${appName} Development Profile`,
    Platform: ['iOS'],
    TeamIdentifier: ['OMNIOS0001'],
    Entitlements: entitlements,
  });

  const appPrefix = `Payload/${bundleName}.app`;
  const entries = [
    { name: 'Payload/', isDirectory: true, mtime: DETERMINISTIC_MTIME },
    { name: `${appPrefix}/`, isDirectory: true, mtime: DETERMINISTIC_MTIME },
    { name: `${appPrefix}/Info.plist`, data: infoPlistBytes, mtime: DETERMINISTIC_MTIME },
    { name: `${appPrefix}/${executableName}`, data: machoBytes, mtime: DETERMINISTIC_MTIME },
    {
      name: `${appPrefix}/embedded.mobileprovision`,
      data: TEXT_ENCODER.encode(provisionPlistXml),
      mtime: DETERMINISTIC_MTIME,
    },
  ];

  if (Array.isArray(spec.extraResources)) {
    for (const res of spec.extraResources) {
      if (!res || !res.name) continue;
      entries.push({
        name: `${appPrefix}/${res.name}`,
        data: res.data ?? new Uint8Array(0),
        mtime: DETERMINISTIC_MTIME,
      });
    }
  }

  const ipaBytes = createZip(entries);
  return {
    ipaBytes,
    machoBytes,
    infoPlistBytes,
    infoPlist,
    bundleId,
    bundleName,
    executableName,
    executablePath: `${appPrefix}/${executableName}`,
  };
}

/**
 * Deterministically build the sample `packages/ios-weather-island.ipa` package.
 */
export function buildWeatherIslandSample(outputPath = null) {
  const result = buildIosIpa({
    bundleId: 'com.omnios.ios.weather-island',
    appName: 'Weather Island',
    bundleName: 'WeatherIsland',
    executableName: 'WeatherIsland',
    delegateClassName: 'WeatherAppDelegate',
    actionSelector: 'refreshWeather:',
    version: '1.0.0',
    buildNumber: '101',
    title: 'Weather Island',
    operands: [68, 4], // real ARM64 ADD -> 72
    tapStep: 3, // real ARM64 ADD on tap -> 75
    initialLabelText: 'Cupertino: 72°F Clear',
    buttonLabel: 'Refresh Weather',
    buttonResultText: 'Cupertino: 75°F Sunny & Breezy',
    defaultsKey: 'weather_city',
    defaultsValue: 'Cupertino, CA',
    documentFile: 'forecast.txt',
    documentContent: 'Weather Island Forecast: 72F Clear (ARM64 iOS Container)',
    urlSchemes: ['omniweather'],
    usageDescriptions: {
      NSLocationWhenInUseUsageDescription: 'Weather Island uses your location for local forecasts.',
      NSDocumentsFolderUsageDescription: 'Weather Island can export forecast summaries to Documents.',
    },
    liveActivity: {
      title: 'Weather Island',
      subtitle: 'Cupertino • Clear Sky',
      leading: '72°F',
      trailing: 'UV 3',
      body: 'High 76°F • Low 58°F • Clear',
      progress: 60,
      updatedTitle: 'Weather Island',
      updatedSubtitle: 'Cupertino • Forecast Refreshed',
      updatedLeading: '75°F',
      updatedTrailing: 'Breezy',
      updatedBody: 'Updated: 75°F Sunny & Breezy',
      updatedProgress: 90,
    },
  });

  if (outputPath) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, result.ipaBytes);
  }
  return result;
}

// CLI execution: `node sdk/ios-builder.mjs`
const __filename = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const repoRoot = path.resolve(path.dirname(__filename), '..');
  const outPath = path.join(repoRoot, 'packages', 'ios-weather-island.ipa');
  const built = buildWeatherIslandSample(outPath);
  const sha256 = crypto.createHash('sha256').update(built.ipaBytes).digest('hex');
  console.log(
    JSON.stringify({
      ok: true,
      output: outPath,
      bundleId: built.bundleId,
      executablePath: built.executablePath,
      ipaBytes: built.ipaBytes.byteLength,
      machoBytes: built.machoBytes.byteLength,
      sha256,
    })
  );
}
