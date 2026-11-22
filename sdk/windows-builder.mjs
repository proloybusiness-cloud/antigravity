/**
 * OmniOS Pure-JS Deterministic Windows PE32+ / PE32 SDK Assembler & Linker (`sdk/windows-builder.mjs`)
 * - Zero external dependencies; emits standards-compliant PE32+ (`0x20B`) & PE32 (`0x10B`) executables
 *   verifiable by host `llvm-objdump --private-headers -d` and `llvm-readobj --file-headers --coff-imports`
 * - Exports: `X64Assembler`, `X86Assembler`, `buildPeExecutable`, `buildWinSysinfoExe`,
 *   `buildWinNotepadExe`, `buildWindowsSamples`
 * - Both `buildWinSysinfoExe(opts)` and `buildWinNotepadExe(opts)` support runtime-customizable inputs/nonces
 *   for anti-hardcoding verification
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const UTF8_ENCODER = new TextEncoder();
const DETERMINISTIC_TIMESTAMP = 0x67890000;

export const REG64 = Object.freeze({
  RAX: 0, RCX: 1, RDX: 2, RBX: 3, RSP: 4, RBP: 5, RSI: 6, RDI: 7,
  R8: 8,  R9: 9,  R10: 10, R11: 11, R12: 12, R13: 13, R14: 14, R15: 15,
});

export const REG32 = Object.freeze({
  EAX: 0, ECX: 1, EDX: 2, EBX: 3, ESP: 4, EBP: 5, ESI: 6, EDI: 7,
});

function alignUp(val, align) {
  if (val === 0) return 0;
  const rem = val % align;
  return rem === 0 ? val : val + (align - rem);
}

function encodeAsciiZ(str) {
  const enc = UTF8_ENCODER.encode(String(str));
  const out = new Uint8Array(enc.byteLength + 1);
  out.set(enc, 0);
  return out;
}

function encodeUtf16Z(str) {
  const s = String(str);
  const out = new Uint8Array((s.length + 1) * 2);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < s.length; i++) {
    dv.setUint16(i * 2, s.charCodeAt(i), true);
  }
  return out;
}

function writeU16(arr, off, v) {
  arr[off] = v & 0xff;
  arr[off + 1] = (v >>> 8) & 0xff;
}

function writeU32(arr, off, v) {
  arr[off] = v & 0xff;
  arr[off + 1] = (v >>> 8) & 0xff;
  arr[off + 2] = (v >>> 16) & 0xff;
  arr[off + 3] = (v >>> 24) & 0xff;
}

function writeU64(arr, off, big) {
  const v = BigInt.asUintN(64, BigInt(big));
  writeU32(arr, off, Number(v & 0xffffffffn));
  writeU32(arr, off + 4, Number((v >> 32n) & 0xffffffffn));
}

// ============================================================================
// Pure-JS x86-64 Assembler (with Labels & RIP-Relative Symbol Fixups)
// ============================================================================

export class X64Assembler {
  constructor() {
    this.bytes = [];
    this.labels = new Map();
    this.relFixups = [];    // { patchOff, nextOff, label }
    this.ripRelFixups = []; // { patchOff, nextOff, symbol }
    this.dir64Relocs = [];  // offset in .text for optional 64-bit relocs
  }

  get offset() {
    return this.bytes.length;
  }

  emit(...vals) {
    for (const v of vals) this.bytes.push(v & 0xff);
    return this;
  }

  emitU16(v) {
    this.bytes.push(v & 0xff, (v >>> 8) & 0xff);
    return this;
  }

  emitI32(v) {
    const u = v >>> 0;
    this.bytes.push(u & 0xff, (u >>> 8) & 0xff, (u >>> 16) & 0xff, (u >>> 24) & 0xff);
    return this;
  }

  emitU64(big) {
    const v = BigInt.asUintN(64, BigInt(big));
    this.emitI32(Number(v & 0xffffffffn));
    this.emitI32(Number((v >> 32n) & 0xffffffffn));
    return this;
  }

  label(name) {
    this.labels.set(name, this.bytes.length);
    return this;
  }

  _rex(w, r, x, b) {
    const byte = 0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0);
    if (byte !== 0x40) this.emit(byte);
  }

  nop() { return this.emit(0x90); }
  ret() { return this.emit(0xc3); }
  int3() { return this.emit(0xcc); }
  cld() { return this.emit(0xfc); }
  repMovsb() { return this.emit(0xf3, 0xa4); }
  repStosb() { return this.emit(0xf3, 0xaa); }

  push(reg) {
    if (reg >= 8) this.emit(0x41);
    return this.emit(0x50 | (reg & 7));
  }

  pop(reg) {
    if (reg >= 8) this.emit(0x41);
    return this.emit(0x58 | (reg & 7));
  }

  movRR64(dst, src) {
    this._rex(true, src >= 8, false, dst >= 8);
    return this.emit(0x89, 0xc0 | ((src & 7) << 3) | (dst & 7));
  }

  movRR32(dst, src) {
    this._rex(false, src >= 8, false, dst >= 8);
    return this.emit(0x89, 0xc0 | ((src & 7) << 3) | (dst & 7));
  }

  movRI32(dst, imm32) {
    if (dst >= 8) this.emit(0x41);
    this.emit(0xb8 | (dst & 7));
    return this.emitI32(imm32);
  }

  movRI64(dst, imm64) {
    this._rex(true, false, false, dst >= 8);
    this.emit(0xb8 | (dst & 7));
    return this.emitU64(imm64);
  }

  xorRR32(dst, src) {
    this._rex(false, src >= 8, false, dst >= 8);
    return this.emit(0x31, 0xc0 | ((src & 7) << 3) | (dst & 7));
  }

  xorRR64(dst, src) {
    this._rex(true, src >= 8, false, dst >= 8);
    return this.emit(0x31, 0xc0 | ((src & 7) << 3) | (dst & 7));
  }

  addRI64(dst, imm32) {
    this._rex(true, false, false, dst >= 8);
    this.emit(0x81, 0xc0 | (dst & 7));
    return this.emitI32(imm32);
  }

  subRI64(dst, imm32) {
    this._rex(true, false, false, dst >= 8);
    this.emit(0x81, 0xe8 | (dst & 7));
    return this.emitI32(imm32);
  }

  addRR64(dst, src) {
    this._rex(true, src >= 8, false, dst >= 8);
    return this.emit(0x01, 0xc0 | ((src & 7) << 3) | (dst & 7));
  }

  subRR64(dst, src) {
    this._rex(true, src >= 8, false, dst >= 8);
    return this.emit(0x29, 0xc0 | ((src & 7) << 3) | (dst & 7));
  }

  imulRR32(dst, src) {
    this._rex(false, dst >= 8, false, src >= 8);
    return this.emit(0x0f, 0xaf, 0xc0 | ((dst & 7) << 3) | (src & 7));
  }

  andRI32(dst, imm32) {
    this._rex(false, false, false, dst >= 8);
    this.emit(0x81, 0xe0 | (dst & 7));
    return this.emitI32(imm32);
  }

  cmpRI32(dst, imm32) {
    this._rex(false, false, false, dst >= 8);
    this.emit(0x81, 0xf8 | (dst & 7));
    return this.emitI32(imm32);
  }

  cmpRI64(dst, imm32) {
    this._rex(true, false, false, dst >= 8);
    this.emit(0x81, 0xf8 | (dst & 7));
    return this.emitI32(imm32);
  }

  testRR32(a, b) {
    this._rex(false, b >= 8, false, a >= 8);
    return this.emit(0x85, 0xc0 | ((b & 7) << 3) | (a & 7));
  }

  // [rbp + disp32] helpers
  leaRbpDisp(dst, disp32) {
    this._rex(true, dst >= 8, false, false);
    this.emit(0x8d, 0x85 | ((dst & 7) << 3));
    return this.emitI32(disp32);
  }

  movToRbpDisp64(disp32, src) {
    this._rex(true, src >= 8, false, false);
    this.emit(0x89, 0x85 | ((src & 7) << 3));
    return this.emitI32(disp32);
  }

  movToRbpDisp32(disp32, src) {
    this._rex(false, src >= 8, false, false);
    this.emit(0x89, 0x85 | ((src & 7) << 3));
    return this.emitI32(disp32);
  }

  movFromRbpDisp64(dst, disp32) {
    this._rex(true, dst >= 8, false, false);
    this.emit(0x8b, 0x85 | ((dst & 7) << 3));
    return this.emitI32(disp32);
  }

  movFromRbpDisp32(dst, disp32) {
    this._rex(false, dst >= 8, false, false);
    this.emit(0x8b, 0x85 | ((dst & 7) << 3));
    return this.emitI32(disp32);
  }

  movImm32ToRbpDisp64(disp32, imm32) {
    this.emit(0x48, 0xc7, 0x85);
    this.emitI32(disp32);
    return this.emitI32(imm32);
  }

  movImm32ToRbpDisp32(disp32, imm32) {
    this.emit(0xc7, 0x85);
    this.emitI32(disp32);
    return this.emitI32(imm32);
  }

  // [rsp + disp32] helpers (requires SIB = 0x24)
  leaRspDisp(dst, disp32) {
    this._rex(true, dst >= 8, false, false);
    this.emit(0x8d, 0x84 | ((dst & 7) << 3), 0x24);
    return this.emitI32(disp32);
  }

  movToRspDisp64(disp32, src) {
    this._rex(true, src >= 8, false, false);
    this.emit(0x89, 0x84 | ((src & 7) << 3), 0x24);
    return this.emitI32(disp32);
  }

  movToRspDisp32(disp32, src) {
    this._rex(false, src >= 8, false, false);
    this.emit(0x89, 0x84 | ((src & 7) << 3), 0x24);
    return this.emitI32(disp32);
  }

  movFromRspDisp64(dst, disp32) {
    this._rex(true, dst >= 8, false, false);
    this.emit(0x8b, 0x84 | ((dst & 7) << 3), 0x24);
    return this.emitI32(disp32);
  }

  movImm32ToRspDisp64(disp32, imm32) {
    this.emit(0x48, 0xc7, 0x84, 0x24);
    this.emitI32(disp32);
    return this.emitI32(imm32);
  }

  movImm32ToRspDisp32(disp32, imm32) {
    this.emit(0xc7, 0x84, 0x24);
    this.emitI32(disp32);
    return this.emitI32(imm32);
  }

  // Write NUL byte at [base + index]: `mov byte ptr [rax + rcx], 0` (base!=rbp/r13, idx!=rsp)
  movByteToBaseIdx(base, idx, imm8) {
    this._rex(false, false, idx >= 8, base >= 8);
    const sib = ((idx & 7) << 3) | (base & 7);
    return this.emit(0xc6, 0x04, sib, imm8 & 0xff);
  }

  // RIP-relative external symbol / label references
  leaRipRel(dst, symbol) {
    this._rex(true, dst >= 8, false, false);
    this.emit(0x8d, ((dst & 7) << 3) | 5);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.ripRelFixups.push({ patchOff, nextOff: this.bytes.length, symbol });
    return this;
  }

  movFromRipRel64(dst, symbol) {
    this._rex(true, dst >= 8, false, false);
    this.emit(0x8b, ((dst & 7) << 3) | 5);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.ripRelFixups.push({ patchOff, nextOff: this.bytes.length, symbol });
    return this;
  }

  movToRipRel64(symbol, src) {
    this._rex(true, src >= 8, false, false);
    this.emit(0x89, ((src & 7) << 3) | 5);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.ripRelFixups.push({ patchOff, nextOff: this.bytes.length, symbol });
    return this;
  }

  callIat(symbol) {
    // `call qword ptr [rip + disp32]` (FF 15 disp32)
    this.emit(0xff, 0x15);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.ripRelFixups.push({ patchOff, nextOff: this.bytes.length, symbol });
    return this;
  }

  // Internal relative branches & calls
  call(label) {
    this.emit(0xe8);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.relFixups.push({ patchOff, nextOff: this.bytes.length, label });
    return this;
  }

  jmp(label) {
    this.emit(0xe9);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.relFixups.push({ patchOff, nextOff: this.bytes.length, label });
    return this;
  }

  _jcc(cc, label) {
    this.emit(0x0f, 0x80 | (cc & 0x0f));
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.relFixups.push({ patchOff, nextOff: this.bytes.length, label });
    return this;
  }

  je(label) { return this._jcc(0x4, label); }
  jne(label) { return this._jcc(0x5, label); }
  jl(label) { return this._jcc(0xc, label); }
  jge(label) { return this._jcc(0xd, label); }
  jle(label) { return this._jcc(0xe, label); }
  jg(label) { return this._jcc(0xf, label); }
  jb(label) { return this._jcc(0x2, label); }
  jae(label) { return this._jcc(0x3, label); }

  link(textRva, symbolRvas = {}) {
    const out = new Uint8Array(this.bytes);
    for (const fx of this.relFixups) {
      if (!this.labels.has(fx.label)) {
        throw new Error(`X64Assembler: unresolved label "${fx.label}"`);
      }
      const rel = this.labels.get(fx.label) - fx.nextOff;
      writeU32(out, fx.patchOff, rel >>> 0);
    }
    for (const fx of this.ripRelFixups) {
      let targetRva;
      if (this.labels.has(fx.symbol)) {
        targetRva = textRva + this.labels.get(fx.symbol);
      } else if (Object.prototype.hasOwnProperty.call(symbolRvas, fx.symbol)) {
        targetRva = symbolRvas[fx.symbol];
      } else {
        throw new Error(`X64Assembler: unresolved RIP-relative symbol "${fx.symbol}"`);
      }
      const disp = targetRva - (textRva + fx.nextOff);
      writeU32(out, fx.patchOff, disp >>> 0);
    }
    return { bytes: out, relocs: this.dir64Relocs.map((off) => ({ type: 10, rva: textRva + off })) };
  }
}

// ============================================================================
// Pure-JS 32-bit x86 Assembler (PE32 0x10B with Automatic HIGHLOW Relocs!)
// ============================================================================

export class X86Assembler {
  constructor() {
    this.bytes = [];
    this.labels = new Map();
    this.relFixups = [];
    this.abs32Fixups = []; // { patchOff, symbol } -> patched with imageBase + rva & emitted as HIGHLOW reloc!
  }

  get offset() {
    return this.bytes.length;
  }

  emit(...vals) {
    for (const v of vals) this.bytes.push(v & 0xff);
    return this;
  }

  emitI32(v) {
    const u = v >>> 0;
    this.bytes.push(u & 0xff, (u >>> 8) & 0xff, (u >>> 16) & 0xff, (u >>> 24) & 0xff);
    return this;
  }

  label(name) {
    this.labels.set(name, this.bytes.length);
    return this;
  }

  nop() { return this.emit(0x90); }
  ret(imm16 = 0) {
    if (imm16 > 0) return this.emit(0xc2, imm16 & 0xff, (imm16 >>> 8) & 0xff);
    return this.emit(0xc3);
  }

  push(reg) { return this.emit(0x50 | (reg & 7)); }
  pop(reg) { return this.emit(0x58 | (reg & 7)); }
  pushImm32(imm32) { this.emit(0x68); return this.emitI32(imm32); }

  pushSymVa(symbol) {
    this.emit(0x68);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.abs32Fixups.push({ patchOff, symbol });
    return this;
  }

  movRI32(dst, imm32) { this.emit(0xb8 | (dst & 7)); return this.emitI32(imm32); }
  movRR32(dst, src) { return this.emit(0x89, 0xc0 | ((src & 7) << 3) | (dst & 7)); }
  xorRR32(dst, src) { return this.emit(0x31, 0xc0 | ((src & 7) << 3) | (dst & 7)); }
  addRI32(dst, imm32) { this.emit(0x81, 0xc0 | (dst & 7)); return this.emitI32(imm32); }
  subRI32(dst, imm32) { this.emit(0x81, 0xe8 | (dst & 7)); return this.emitI32(imm32); }
  cmpRI32(dst, imm32) { this.emit(0x81, 0xf8 | (dst & 7)); return this.emitI32(imm32); }
  testRR32(a, b) { return this.emit(0x85, 0xc0 | ((b & 7) << 3) | (a & 7)); }

  leaEbpDisp(dst, disp32) { this.emit(0x8d, 0x85 | ((dst & 7) << 3)); return this.emitI32(disp32); }
  movToEbpDisp32(disp32, src) { this.emit(0x89, 0x85 | ((src & 7) << 3)); return this.emitI32(disp32); }
  movFromEbpDisp32(dst, disp32) { this.emit(0x8b, 0x85 | ((dst & 7) << 3)); return this.emitI32(disp32); }

  callIat(symbol) {
    // `call dword ptr [imm32]` (FF 15 imm32)
    this.emit(0xff, 0x15);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.abs32Fixups.push({ patchOff, symbol });
    return this;
  }

  jmp(label) {
    this.emit(0xe9);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.relFixups.push({ patchOff, nextOff: this.bytes.length, label });
    return this;
  }

  je(label) {
    this.emit(0x0f, 0x84);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.relFixups.push({ patchOff, nextOff: this.bytes.length, label });
    return this;
  }

  jne(label) {
    this.emit(0x0f, 0x85);
    const patchOff = this.bytes.length;
    this.emitI32(0);
    this.relFixups.push({ patchOff, nextOff: this.bytes.length, label });
    return this;
  }

  link(textRva, symbolRvas = {}, imageBase = 0x400000n) {
    const out = new Uint8Array(this.bytes);
    const relocs = [];
    for (const fx of this.relFixups) {
      if (!this.labels.has(fx.label)) throw new Error(`X86Assembler: unresolved label "${fx.label}"`);
      const rel = this.labels.get(fx.label) - fx.nextOff;
      writeU32(out, fx.patchOff, rel >>> 0);
    }
    for (const fx of this.abs32Fixups) {
      let targetRva;
      if (this.labels.has(fx.symbol)) targetRva = textRva + this.labels.get(fx.symbol);
      else if (Object.prototype.hasOwnProperty.call(symbolRvas, fx.symbol)) targetRva = symbolRvas[fx.symbol];
      else throw new Error(`X86Assembler: unresolved symbol "${fx.symbol}"`);
      const va = Number((BigInt(imageBase) + BigInt(targetRva)) & 0xffffffffn);
      writeU32(out, fx.patchOff, va);
      relocs.push({ type: 3, rva: textRva + fx.patchOff }); // IMAGE_REL_BASED_HIGHLOW
    }
    return { bytes: out, relocs };
  }
}

// ============================================================================
// Standards-Compliant PE32+ / PE32 Linker (Verified with llvm-objdump & llvm-readobj)
// ============================================================================

function buildRelocSectionBytes(relocs) {
  if (!relocs || relocs.length === 0) return new Uint8Array(0);
  const byPage = new Map();
  for (const r of relocs) {
    const pageRva = r.rva & ~0xfff;
    if (!byPage.has(pageRva)) byPage.set(pageRva, []);
    byPage.get(pageRva).push(((r.type & 0x0f) << 12) | (r.rva & 0x0fff));
  }
  const pages = Array.from(byPage.keys()).sort((a, b) => a - b);
  const chunks = [];
  let total = 0;
  for (const pageRva of pages) {
    const entries = byPage.get(pageRva);
    if ((entries.length & 1) === 1) entries.push(0); // Pad to 4-byte boundary with RELOC_ABSOLUTE
    const blockSize = 8 + entries.length * 2;
    const block = new Uint8Array(blockSize);
    writeU32(block, 0, pageRva);
    writeU32(block, 4, blockSize);
    for (let i = 0; i < entries.length; i++) {
      writeU16(block, 8 + i * 2, entries[i]);
    }
    chunks.push(block);
    total += blockSize;
  }
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }
  return out;
}

function normalizeRdataValue(val) {
  if (val instanceof Uint8Array) return val;
  if (typeof val === 'string') return encodeAsciiZ(val);
  if (val && typeof val === 'object') {
    if (typeof val.utf16 === 'string') return encodeUtf16Z(val.utf16);
    if (val.bytes instanceof Uint8Array) return val.bytes;
    if (typeof val.ascii === 'string') return UTF8_ENCODER.encode(val.ascii);
  }
  return new Uint8Array(0);
}

/**
 * Assemble and link a deterministic, LLVM-verifiable PE32+ (`x86_64`) or PE32 (`x86`) binary.
 */
export function buildPeExecutable({
  arch = 'x86_64',
  subsystem = 3, // 3 = WINDOWS_CUI, 2 = WINDOWS_GUI
  imageBase = null,
  isDll = false,
  imports = {},
  exports = null,
  rdata = {},
  data = {},
  bss = {},
  code,
  entryLabel = null,
  extraRelocs = [],
  forceOftZero = false,
} = {}) {
  const is64 = arch !== 'x86' && arch !== 'i386';
  const ptrSize = is64 ? 8 : 4;
  const secAlign = 0x1000;
  const fileAlign = 0x200;
  const baseAddr = imageBase !== null ? BigInt(imageBase) : (is64 ? 0x140000000n : 0x00400000n);

  // Build assembler if callback was passed
  let asm = code;
  if (typeof code === 'function') {
    asm = is64 ? new X64Assembler() : new X86Assembler();
    code(asm);
  }
  const rawCodeLen = asm instanceof Uint8Array ? asm.byteLength : asm.bytes.length;
  const textRva = 0x1000;
  const textVirtSize = Math.max(1, rawCodeLen);
  const textRawSize = alignUp(textVirtSize, fileAlign);

  // ---- Build .rdata layout (IAT + Import Directory + ILT + Hint/Names + Exports + Constants) ----
  const rdataRva = alignUp(textRva + textVirtSize, secAlign);
  const symbolRvas = Object.create(null);

  const dllNames = Object.keys(imports);
  const rdataChunks = [];
  let rdataCursor = 0;

  const pushRdata = (bytes, align = 1) => {
    const aligned = alignUp(rdataCursor, align);
    if (aligned > rdataCursor) {
      rdataChunks.push(new Uint8Array(aligned - rdataCursor));
      rdataCursor = aligned;
    }
    const startOff = rdataCursor;
    rdataChunks.push(bytes);
    rdataCursor += bytes.byteLength;
    return startOff;
  };

  // Reserve IAT slots first
  const iatStartOff = 0;
  const dllLayouts = [];
  for (const dllName of dllNames) {
    const funcs = imports[dllName] || [];
    const iatOff = alignUp(rdataCursor, ptrSize);
    if (iatOff > rdataCursor) {
      rdataChunks.push(new Uint8Array(iatOff - rdataCursor));
      rdataCursor = iatOff;
    }
    const iatBuf = new Uint8Array((funcs.length + 1) * ptrSize);
    rdataChunks.push(iatBuf);
    rdataCursor += iatBuf.byteLength;

    const dllLower = dllName.toLowerCase();
    for (let i = 0; i < funcs.length; i++) {
      const fn = funcs[i];
      const slotRva = rdataRva + iatOff + i * ptrSize;
      symbolRvas[`iat:${dllLower}!${fn}`] = slotRva;
      symbolRvas[`iat:${fn}`] = slotRva;
    }
    dllLayouts.push({ dllName, funcs, iatOff, iatBuf, iltOff: 0, iltBuf: null, nameRva: 0, hintNameRvas: [] });
  }
  const iatTotalSize = rdataCursor - iatStartOff;

  // Reserve Import Directory Table (20B per DLL + 20B terminator)
  let importDirRva = 0;
  let importDirSize = 0;
  let importDirBuf = null;
  if (dllLayouts.length > 0) {
    importDirSize = (dllLayouts.length + 1) * 20;
    importDirBuf = new Uint8Array(importDirSize);
    const importDirOff = pushRdata(importDirBuf, 4);
    importDirRva = rdataRva + importDirOff;

    // Reserve ILT tables (unless forceOftZero is enabled for Edge Case #14 testing!)
    if (!forceOftZero) {
      for (const dl of dllLayouts) {
        const iltBuf = new Uint8Array((dl.funcs.length + 1) * ptrSize);
        dl.iltOff = pushRdata(iltBuf, ptrSize);
        dl.iltBuf = iltBuf;
      }
    }

    // Emit Hint/Name entries & DLL name strings, then populate ILT, IAT, and Import Directory Table
    for (let d = 0; d < dllLayouts.length; d++) {
      const dl = dllLayouts[d];
      for (let i = 0; i < dl.funcs.length; i++) {
        const fn = dl.funcs[i];
        const fnBytes = encodeAsciiZ(fn);
        const hn = new Uint8Array(2 + fnBytes.byteLength);
        hn.set(fnBytes, 2); // Hint = 0
        const hnOff = pushRdata(hn, 2);
        const hnRva = rdataRva + hnOff;
        dl.hintNameRvas.push(hnRva);

        if (is64) {
          writeU64(dl.iatBuf, i * 8, BigInt(hnRva));
          if (dl.iltBuf) writeU64(dl.iltBuf, i * 8, BigInt(hnRva));
        } else {
          writeU32(dl.iatBuf, i * 4, hnRva);
          if (dl.iltBuf) writeU32(dl.iltBuf, i * 4, hnRva);
        }
      }
      const dllStrOff = pushRdata(encodeAsciiZ(dl.dllName), 1);
      dl.nameRva = rdataRva + dllStrOff;

      const descOff = d * 20;
      writeU32(importDirBuf, descOff + 0, forceOftZero ? 0 : (rdataRva + dl.iltOff)); // OriginalFirstThunk
      writeU32(importDirBuf, descOff + 4, 0); // TimeDateStamp
      writeU32(importDirBuf, descOff + 8, 0); // ForwarderChain
      writeU32(importDirBuf, descOff + 12, dl.nameRva); // Name RVA
      writeU32(importDirBuf, descOff + 16, rdataRva + dl.iatOff); // FirstThunk (IAT)
    }
  }

  // Optional Export Directory (for DLL / export tests)
  let exportDirRva = 0;
  let exportDirSize = 0;
  if (exports && Array.isArray(exports.symbols) && exports.symbols.length > 0) {
    const syms = [...exports.symbols].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const expStart = alignUp(rdataCursor, 4);
    const expHeader = new Uint8Array(40);
    const expOff = pushRdata(expHeader, 4);
    exportDirRva = rdataRva + expOff;

    const eatBuf = new Uint8Array(syms.length * 4);
    const eatOff = pushRdata(eatBuf, 4);
    const namesBuf = new Uint8Array(syms.length * 4);
    const namesOff = pushRdata(namesBuf, 4);
    const ordsBuf = new Uint8Array(syms.length * 2);
    const ordsOff = pushRdata(ordsBuf, 2);
    const dllNameOff = pushRdata(encodeAsciiZ(exports.dllName || 'module.dll'), 1);

    for (let i = 0; i < syms.length; i++) {
      writeU32(eatBuf, i * 4, textRva + (syms[i].textOffset ?? 0));
      const sOff = pushRdata(encodeAsciiZ(syms[i].name), 1);
      writeU32(namesBuf, i * 4, rdataRva + sOff);
      writeU16(ordsBuf, i * 2, i);
    }

    writeU32(expHeader, 4, DETERMINISTIC_TIMESTAMP);
    writeU32(expHeader, 12, rdataRva + dllNameOff);
    writeU32(expHeader, 16, exports.ordinalBase ?? 1);
    writeU32(expHeader, 20, syms.length);
    writeU32(expHeader, 24, syms.length);
    writeU32(expHeader, 28, rdataRva + eatOff);
    writeU32(expHeader, 32, rdataRva + namesOff);
    writeU32(expHeader, 36, rdataRva + ordsOff);
    exportDirSize = rdataCursor - expStart;
  }

  // Emit user read-only data symbols into .rdata
  for (const [symName, rawVal] of Object.entries(rdata)) {
    const bytes = normalizeRdataValue(rawVal);
    const off = pushRdata(bytes, 8);
    symbolRvas[symName] = rdataRva + off;
  }

  const rdataBytes = new Uint8Array(Math.max(1, rdataCursor));
  {
    let pos = 0;
    for (const c of rdataChunks) {
      rdataBytes.set(c, pos);
      pos += c.byteLength;
    }
  }
  const rdataVirtSize = rdataBytes.byteLength;
  const rdataRawSize = alignUp(rdataVirtSize, fileAlign);

  // ---- Build .data (+ optional .bss tail where VirtualSize > SizeOfRawData!) ----
  const dataEntries = Object.entries(data);
  const bssEntries = Object.entries(bss);
  const hasDataSection = dataEntries.length > 0 || bssEntries.length > 0;
  let dataRva = alignUp(rdataRva + rdataVirtSize, secAlign);
  let dataInitBytes = new Uint8Array(0);
  let dataVirtSize = 0;
  let dataRawSize = 0;

  if (hasDataSection) {
    const initChunks = [];
    let cursor = 0;
    for (const [symName, rawVal] of dataEntries) {
      const aligned = alignUp(cursor, 8);
      if (aligned > cursor) {
        initChunks.push(new Uint8Array(aligned - cursor));
        cursor = aligned;
      }
      const bytes = rawVal instanceof Uint8Array
        ? rawVal
        : (rawVal && typeof rawVal === 'object' && Number.isInteger(rawVal.size)
          ? new Uint8Array(rawVal.size)
          : normalizeRdataValue(rawVal));
      symbolRvas[symName] = dataRva + cursor;
      initChunks.push(bytes);
      cursor += bytes.byteLength;
    }
    dataInitBytes = new Uint8Array(cursor);
    let pos = 0;
    for (const c of initChunks) {
      dataInitBytes.set(c, pos);
      pos += c.byteLength;
    }

    let virtCursor = cursor;
    for (const [symName, bssSize] of bssEntries) {
      virtCursor = alignUp(virtCursor, 8);
      symbolRvas[symName] = dataRva + virtCursor;
      virtCursor += Math.max(1, Number(bssSize));
    }
    dataVirtSize = Math.max(1, virtCursor);
    dataRawSize = dataInitBytes.byteLength > 0 ? alignUp(dataInitBytes.byteLength, fileAlign) : 0;
  }

  // ---- Link .text now that ALL .rdata and .data/.bss RVAs are known! ----
  let textBytes;
  let relocs = [...extraRelocs];
  let entryOffset = 0;
  if (asm instanceof Uint8Array) {
    textBytes = asm;
  } else {
    const linked = is64 ? asm.link(textRva, symbolRvas) : asm.link(textRva, symbolRvas, baseAddr);
    textBytes = linked.bytes;
    relocs.push(...linked.relocs);
    if (entryLabel && asm.labels.has(entryLabel)) {
      entryOffset = asm.labels.get(entryLabel);
    }
  }

  // ---- Build .reloc section if relocations exist ----
  const relocBytes = buildRelocSectionBytes(relocs);
  const hasRelocSection = relocBytes.byteLength > 0;
  const relocRva = hasDataSection
    ? alignUp(dataRva + dataVirtSize, secAlign)
    : alignUp(rdataRva + rdataVirtSize, secAlign);
  const relocVirtSize = relocBytes.byteLength;
  const relocRawSize = hasRelocSection ? alignUp(relocVirtSize, fileAlign) : 0;

  // ---- Assemble Section Descriptors ----
  const sections = [];
  sections.push({
    name: '.text',
    virtualSize: textVirtSize,
    virtualAddress: textRva,
    rawSize: textRawSize,
    data: textBytes,
    characteristics: 0x60000020, // CNT_CODE | MEM_EXECUTE | MEM_READ
  });
  sections.push({
    name: '.rdata',
    virtualSize: rdataVirtSize,
    virtualAddress: rdataRva,
    rawSize: rdataRawSize,
    data: rdataBytes,
    characteristics: 0x40000040, // CNT_INITIALIZED_DATA | MEM_READ
  });
  if (hasDataSection) {
    sections.push({
      name: '.data',
      virtualSize: dataVirtSize,
      virtualAddress: dataRva,
      rawSize: dataRawSize,
      data: dataInitBytes,
      characteristics: dataRawSize > 0 ? 0xc0000040 : 0xc0000080, // READ | WRITE | INIT/UNINIT
    });
  }
  if (hasRelocSection) {
    sections.push({
      name: '.reloc',
      virtualSize: relocVirtSize,
      virtualAddress: relocRva,
      rawSize: relocRawSize,
      data: relocBytes,
      characteristics: 0x42000040, // CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ
    });
  }

  // ---- Header Sizing & File Offsets ----
  const eLfanew = 0x80;
  const sizeOfOptionalHeader = is64 ? 240 : 224;
  const headersEnd = eLfanew + 4 + 20 + sizeOfOptionalHeader + sections.length * 40;
  const sizeOfHeaders = alignUp(headersEnd, fileAlign);

  let rawCursor = sizeOfHeaders;
  for (const sec of sections) {
    if (sec.rawSize > 0) {
      sec.pointerToRawData = rawCursor;
      rawCursor += sec.rawSize;
    } else {
      sec.pointerToRawData = 0;
    }
  }

  const lastSec = sections[sections.length - 1];
  const sizeOfImage = alignUp(lastSec.virtualAddress + lastSec.virtualSize, secAlign);
  const totalFileSize = rawCursor;
  const out = new Uint8Array(totalFileSize);

  // ---- 1. DOS Header (64B) + Minimal DOS Stub ----
  writeU16(out, 0x00, 0x5a4d); // 'MZ'
  writeU16(out, 0x02, 0x0090); // e_cblp
  writeU16(out, 0x04, 0x0003); // e_cp
  writeU16(out, 0x08, 0x0004); // e_cparhdr
  writeU16(out, 0x0c, 0xffff); // e_maxalloc
  writeU16(out, 0x10, 0x00b8); // e_sp
  writeU16(out, 0x18, 0x0040); // e_lfarlc
  writeU32(out, 0x3c, eLfanew);
  const dosMsg = UTF8_ENCODER.encode('This program cannot be run in DOS mode.\r\n$');
  out.set(dosMsg, 0x4e);

  // ---- 2. PE Signature + COFF Header ----
  writeU32(out, eLfanew, 0x00004550); // 'PE\0\0'
  const coffOff = eLfanew + 4;
  writeU16(out, coffOff + 0, is64 ? 0x8664 : 0x014c);
  writeU16(out, coffOff + 2, sections.length);
  writeU32(out, coffOff + 4, DETERMINISTIC_TIMESTAMP);
  writeU32(out, coffOff + 8, 0);
  writeU32(out, coffOff + 12, 0);
  writeU16(out, coffOff + 16, sizeOfOptionalHeader);
  let coffChars = is64 ? 0x0022 : 0x0102; // EXECUTABLE_IMAGE | (LARGE_ADDRESS_AWARE / 32BIT_MACHINE)
  if (isDll) coffChars |= 0x2000;
  writeU16(out, coffOff + 18, coffChars);

  // ---- 3. Optional Header ----
  const optOff = coffOff + 20;
  writeU16(out, optOff + 0, is64 ? 0x020b : 0x010b);
  out[optOff + 2] = 14; // MajorLinkerVersion
  out[optOff + 3] = 0;  // MinorLinkerVersion
  writeU32(out, optOff + 4, textRawSize);
  writeU32(out, optOff + 8, rdataRawSize + dataRawSize + relocRawSize);
  writeU32(out, optOff + 12, hasDataSection ? Math.max(0, dataVirtSize - dataInitBytes.byteLength) : 0);
  writeU32(out, optOff + 16, textRva + entryOffset); // AddressOfEntryPoint
  writeU32(out, optOff + 20, textRva); // BaseOfCode
  if (is64) {
    writeU64(out, optOff + 24, baseAddr);
  } else {
    writeU32(out, optOff + 24, rdataRva); // BaseOfData
    writeU32(out, optOff + 28, Number(baseAddr & 0xffffffffn));
  }
  writeU32(out, optOff + 32, secAlign);
  writeU32(out, optOff + 36, fileAlign);
  writeU16(out, optOff + 40, 6); // MajorOSVersion
  writeU16(out, optOff + 42, 0);
  writeU16(out, optOff + 44, 1); // MajorImageVersion
  writeU16(out, optOff + 46, 0);
  writeU16(out, optOff + 48, 6); // MajorSubsystemVersion
  writeU16(out, optOff + 50, 0);
  writeU32(out, optOff + 56, sizeOfImage);
  writeU32(out, optOff + 60, sizeOfHeaders);
  writeU32(out, optOff + 64, 0); // CheckSum
  writeU16(out, optOff + 68, subsystem);
  const dllChars = 0x0100 | (hasRelocSection ? 0x0040 : 0); // NX_COMPAT | (DYNAMIC_BASE if reloc)
  writeU16(out, optOff + 70, dllChars);

  const dataDirOff = is64 ? optOff + 112 : optOff + 96;
  if (is64) {
    writeU64(out, optOff + 72, 0x100000n); // SizeOfStackReserve
    writeU64(out, optOff + 80, 0x10000n);  // SizeOfStackCommit
    writeU64(out, optOff + 88, 0x100000n); // SizeOfHeapReserve
    writeU64(out, optOff + 96, 0x10000n);  // SizeOfHeapCommit
    writeU32(out, optOff + 104, 0);
    writeU32(out, optOff + 108, 16); // NumberOfRvaAndSizes
  } else {
    writeU32(out, optOff + 72, 0x100000);
    writeU32(out, optOff + 76, 0x10000);
    writeU32(out, optOff + 80, 0x100000);
    writeU32(out, optOff + 84, 0x10000);
    writeU32(out, optOff + 88, 0);
    writeU32(out, optOff + 92, 16);
  }

  // Data Directories
  if (exportDirRva !== 0) {
    writeU32(out, dataDirOff + 0 * 8, exportDirRva);
    writeU32(out, dataDirOff + 0 * 8 + 4, exportDirSize);
  }
  if (importDirRva !== 0) {
    writeU32(out, dataDirOff + 1 * 8, importDirRva);
    writeU32(out, dataDirOff + 1 * 8 + 4, importDirSize);
  }
  if (hasRelocSection) {
    writeU32(out, dataDirOff + 5 * 8, relocRva);
    writeU32(out, dataDirOff + 5 * 8 + 4, relocVirtSize);
  }
  if (iatTotalSize > 0) {
    writeU32(out, dataDirOff + 12 * 8, rdataRva + iatStartOff);
    writeU32(out, dataDirOff + 12 * 8 + 4, iatTotalSize);
  }

  // ---- 4. Section Table & Section Payloads ----
  const secTableOff = optOff + sizeOfOptionalHeader;
  for (let i = 0; i < sections.length; i++) {
    const sec = sections[i];
    const sOff = secTableOff + i * 40;
    const nameEnc = UTF8_ENCODER.encode(sec.name);
    out.set(nameEnc.subarray(0, Math.min(8, nameEnc.byteLength)), sOff);
    writeU32(out, sOff + 8, sec.virtualSize);
    writeU32(out, sOff + 12, sec.virtualAddress);
    writeU32(out, sOff + 16, sec.rawSize);
    writeU32(out, sOff + 20, sec.pointerToRawData);
    writeU32(out, sOff + 36, sec.characteristics);
    if (sec.rawSize > 0 && sec.data.byteLength > 0) {
      out.set(sec.data, sec.pointerToRawData);
    }
  }

  return out;
}

// ============================================================================
// Sample 1: `packages/win-sysinfo.exe` (Real x86-64 CUI PE32+)
// Calls kernel32 Console + VFS File I/O + advapi32 Registry via genuine IAT!
// ============================================================================

export function buildWinSysinfoExe({
  banner = 'OmniOS Windows Subsystem SysInfo v1.0 (x86_64 PE32+)\nStatus: ONLINE\n',
  filePath = 'C:\\Users\\user\\Documents\\win-sysinfo.txt',
  fileContent = 'OmniOS WinSysInfo Report: Architecture=x86_64 Subsystem=CUI\n',
  regSubKey = 'Software\\OmniOS\\WinSysInfo',
  regValueName = 'Status',
  regValueData = 'OmniOS-Win64-OK',
  exitCode = 0,
} = {}) {
  const bannerBytes = UTF8_ENCODER.encode(banner);
  const contentBytes = UTF8_ENCODER.encode(fileContent);
  const regValBytes = encodeAsciiZ(regValueData);

  return buildPeExecutable({
    arch: 'x86_64',
    subsystem: 3, // WINDOWS_CUI
    imports: {
      'kernel32.dll': [
        'GetStdHandle',
        'WriteConsoleA',
        'GetCurrentProcessId',
        'CreateFileA',
        'WriteFile',
        'CloseHandle',
        'ExitProcess',
      ],
      'advapi32.dll': [
        'RegCreateKeyExA',
        'RegSetValueExA',
        'RegCloseKey',
      ],
    },
    rdata: {
      s_banner: { bytes: bannerBytes },
      s_filePath: filePath,
      s_fileContent: { bytes: contentBytes },
      s_regSubKey: regSubKey,
      s_regValName: regValueName,
      s_regValData: { bytes: regValBytes },
    },
    data: {
      g_pid: new Uint8Array(8),
    },
    code: (asm) => {
      const R = REG64;
      // Win64 standard prologue: RSP % 16 === 8 on entry -> push rbp -> RSP % 16 === 0
      asm.push(R.RBP);
      asm.movRR64(R.RBP, R.RSP);
      asm.push(R.RBX);
      asm.push(R.R12);
      // 16B pushed -> RSP % 16 === 0; reserve 0x100 bytes (shadow + stack args + locals)
      asm.subRI64(R.RSP, 0x100);

      // 1. hStdout = GetStdHandle(STD_OUTPUT_HANDLE = -11)
      asm.movRI32(R.RCX, 0xfffffff5);
      asm.callIat('iat:GetStdHandle');
      asm.movRR64(R.RBX, R.RAX);

      // 2. WriteConsoleA(hStdout, s_banner, bannerLen, &written [rbp-0x28], NULL)
      asm.movRR64(R.RCX, R.RBX);
      asm.leaRipRel(R.RDX, 's_banner');
      asm.movRI32(R.R8, bannerBytes.byteLength);
      asm.leaRbpDisp(R.R9, -0x28);
      asm.movImm32ToRspDisp64(0x20, 0);
      asm.callIat('iat:WriteConsoleA');

      // 3. pid = GetCurrentProcessId(); g_pid = pid
      asm.callIat('iat:GetCurrentProcessId');
      asm.movToRipRel64('g_pid', R.RAX);

      // 4. hFile = CreateFileA(s_filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS(2), 0x80, NULL)
      asm.leaRipRel(R.RCX, 's_filePath');
      asm.movRI32(R.RDX, 0x40000000); // GENERIC_WRITE
      asm.xorRR32(R.R8, R.R8);
      asm.xorRR32(R.R9, R.R9);
      asm.movImm32ToRspDisp64(0x20, 2);    // CREATE_ALWAYS
      asm.movImm32ToRspDisp64(0x28, 0x80); // FILE_ATTRIBUTE_NORMAL
      asm.movImm32ToRspDisp64(0x30, 0);    // hTemplateFile = NULL
      asm.callIat('iat:CreateFileA');
      asm.movRR64(R.R12, R.RAX);

      // 5. WriteFile(hFile, s_fileContent, contentLen, &written [rbp-0x28], NULL)
      asm.movRR64(R.RCX, R.R12);
      asm.leaRipRel(R.RDX, 's_fileContent');
      asm.movRI32(R.R8, contentBytes.byteLength);
      asm.leaRbpDisp(R.R9, -0x28);
      asm.movImm32ToRspDisp64(0x20, 0);
      asm.callIat('iat:WriteFile');

      // 6. CloseHandle(hFile)
      asm.movRR64(R.RCX, R.R12);
      asm.callIat('iat:CloseHandle');

      // 7. RegCreateKeyExA(HKEY_CURRENT_USER=0x80000001, s_regSubKey, 0, NULL, 0, 0x20006, NULL, &hKey [rbp-0x38], NULL)
      asm.movRI32(R.RCX, 0x80000001);
      asm.leaRipRel(R.RDX, 's_regSubKey');
      asm.xorRR32(R.R8, R.R8);
      asm.xorRR32(R.R9, R.R9);
      asm.movImm32ToRspDisp64(0x20, 0);       // dwOptions
      asm.movImm32ToRspDisp64(0x28, 0x20006); // KEY_WRITE
      asm.movImm32ToRspDisp64(0x30, 0);       // lpSecurityAttributes
      asm.leaRbpDisp(R.RAX, -0x38);
      asm.movToRspDisp64(0x38, R.RAX);        // phkResult
      asm.movImm32ToRspDisp64(0x40, 0);       // lpdwDisposition
      asm.callIat('iat:RegCreateKeyExA');

      // 8. RegSetValueExA(hKey, s_regValName, 0, REG_SZ(1), s_regValData, regValBytes.length)
      asm.movFromRbpDisp64(R.RCX, -0x38);
      asm.leaRipRel(R.RDX, 's_regValName');
      asm.xorRR32(R.R8, R.R8);
      asm.movRI32(R.R9, 1); // REG_SZ
      asm.leaRipRel(R.RAX, 's_regValData');
      asm.movToRspDisp64(0x20, R.RAX);
      asm.movImm32ToRspDisp64(0x28, regValBytes.byteLength);
      asm.callIat('iat:RegSetValueExA');

      // 9. RegCloseKey(hKey)
      asm.movFromRbpDisp64(R.RCX, -0x38);
      asm.callIat('iat:RegCloseKey');

      // 10. ExitProcess(exitCode)
      asm.movRI32(R.RCX, exitCode >>> 0);
      asm.callIat('iat:ExitProcess');

      asm.leaRbpDisp(R.RSP, -0x10);
      asm.pop(R.R12);
      asm.pop(R.RBX);
      asm.pop(R.RBP);
      asm.ret();
    },
  });
}

// ============================================================================
// Sample 2: `packages/win-notepad.exe` (Real x86-64 GUI PE32+)
// Full WinMain + re-entrant x86-64 WndProc, RegisterClassExA, CreateWindowExA,
// child controls (EDIT/BUTTON/STATIC), GDI WM_PAINT DrawOps, WM_COMMAND Save & Clipboard!
// ============================================================================

export function buildWinNotepadExe({
  windowTitle = 'OmniOS WinNotepad',
  initialText = 'Hello from x86-64 Win32 Notepad!',
  headerText = 'Win32 GDI Notepad Surface',
  savePath = 'C:\\Users\\user\\Documents\\win-notepad.txt',
  savedStatusText = 'Saved to Documents',
  copiedStatusText = 'Copied to Clipboard',
} = {}) {
  const headerBytes = UTF8_ENCODER.encode(headerText);

  return buildPeExecutable({
    arch: 'x86_64',
    subsystem: 2, // WINDOWS_GUI
    imports: {
      'kernel32.dll': [
        'GetModuleHandleA',
        'CreateFileA',
        'WriteFile',
        'CloseHandle',
        'GlobalAlloc',
        'GlobalLock',
        'GlobalUnlock',
        'ExitProcess',
      ],
      'user32.dll': [
        'RegisterClassExA',
        'CreateWindowExA',
        'ShowWindow',
        'UpdateWindow',
        'GetMessageA',
        'TranslateMessage',
        'DispatchMessageA',
        'DefWindowProcA',
        'DestroyWindow',
        'PostQuitMessage',
        'BeginPaint',
        'EndPaint',
        'GetWindowTextA',
        'SetWindowTextA',
        'GetDlgItem',
        'OpenClipboard',
        'EmptyClipboard',
        'SetClipboardData',
        'CloseClipboard',
      ],
      'gdi32.dll': [
        'CreateSolidBrush',
        'SelectObject',
        'Rectangle',
        'SetTextColor',
        'TextOutA',
      ],
    },
    rdata: {
      s_className: 'OmniWinNotepadClass',
      s_windowTitle: windowTitle,
      s_clsEdit: 'EDIT',
      s_clsButton: 'BUTTON',
      s_clsStatic: 'STATIC',
      s_initialText: initialText,
      s_btnSave: 'Save Note',
      s_btnCopy: 'Copy to Clipboard',
      s_statusInit: 'Ready',
      s_statusSaved: savedStatusText,
      s_statusCopied: copiedStatusText,
      s_headerText: { bytes: headerBytes },
      s_savePath: savePath,
    },
    data: {
      g_hInstance: new Uint8Array(8),
      g_hEdit: new Uint8Array(8),
    },
    bss: {
      g_textBuf: 1024,
    },
    entryLabel: 'WinMain',
    code: (asm) => {
      const R = REG64;

      // ====================================================================
      // WinMain (entry point)
      // Locals: [rbp-0x80..rbp-0x31] = WNDCLASSEXA (80 bytes)
      //         [rbp-0xC0..rbp-0x91] = MSG (48 bytes)
      // Outgoing stack args: [rsp+0x20..rsp+0x5F] (frame size 0x160)
      // ====================================================================
      asm.label('WinMain');
      asm.push(R.RBP);
      asm.movRR64(R.RBP, R.RSP);
      asm.push(R.RBX);
      asm.push(R.R12);
      asm.subRI64(R.RSP, 0x160);

      // hInstance = GetModuleHandleA(NULL)
      asm.xorRR32(R.RCX, R.RCX);
      asm.callIat('iat:GetModuleHandleA');
      asm.movRR64(R.R12, R.RAX);
      asm.movToRipRel64('g_hInstance', R.RAX);

      // Zero WNDCLASSEXA (80 bytes at [rbp-0x80]) using rep stosb
      asm.cld();
      asm.leaRbpDisp(R.RDI, -0x80);
      asm.xorRR32(R.RAX, R.RAX);
      asm.movRI32(R.RCX, 80);
      asm.repStosb();

      // Populate WNDCLASSEXA fields
      asm.movImm32ToRbpDisp32(-0x80 + 0, 80);     // cbSize = 80
      asm.movImm32ToRbpDisp32(-0x80 + 4, 0x0003); // style = CS_HREDRAW | CS_VREDRAW
      asm.leaRipRel(R.RAX, 'WndProc');
      asm.movToRbpDisp64(-0x80 + 8, R.RAX);       // lpfnWndProc = &WndProc
      asm.movToRbpDisp64(-0x80 + 24, R.R12);      // hInstance
      asm.leaRipRel(R.RAX, 's_className');
      asm.movToRbpDisp64(-0x80 + 64, R.RAX);      // lpszClassName

      // RegisterClassExA(&wcx)
      asm.leaRbpDisp(R.RCX, -0x80);
      asm.callIat('iat:RegisterClassExA');

      // hwnd = CreateWindowExA(0, s_className, s_windowTitle, WS_OVERLAPPEDWINDOW|WS_VISIBLE,
      //                        100, 80, 640, 440, NULL, NULL, hInstance, NULL)
      asm.xorRR32(R.RCX, R.RCX);                 // dwExStyle = 0
      asm.leaRipRel(R.RDX, 's_className');       // lpClassName
      asm.leaRipRel(R.R8, 's_windowTitle');      // lpWindowName
      asm.movRI32(R.R9, 0x10cf0000);             // WS_OVERLAPPEDWINDOW | WS_VISIBLE
      asm.movImm32ToRspDisp64(0x20, 100);        // X
      asm.movImm32ToRspDisp64(0x28, 80);         // Y
      asm.movImm32ToRspDisp64(0x30, 640);        // Width
      asm.movImm32ToRspDisp64(0x38, 440);        // Height
      asm.movImm32ToRspDisp64(0x40, 0);          // hWndParent = NULL
      asm.movImm32ToRspDisp64(0x48, 0);          // hMenu = NULL
      asm.movToRspDisp64(0x50, R.R12);           // hInstance
      asm.movImm32ToRspDisp64(0x58, 0);          // lpParam = NULL
      asm.callIat('iat:CreateWindowExA');
      asm.movRR64(R.RBX, R.RAX);                 // RBX = hwnd

      // ShowWindow(hwnd, SW_SHOW=5)
      asm.movRR64(R.RCX, R.RBX);
      asm.movRI32(R.RDX, 5);
      asm.callIat('iat:ShowWindow');

      // UpdateWindow(hwnd) -> triggers synchronous WM_PAINT -> initial GDI drawOps!
      asm.movRR64(R.RCX, R.RBX);
      asm.callIat('iat:UpdateWindow');

      // Message Loop: while (GetMessageA(&msg, 0, 0, 0) > 0) { TranslateMessage; DispatchMessageA; }
      asm.label('msg_loop');
      asm.leaRbpDisp(R.RCX, -0xc0);
      asm.xorRR32(R.RDX, R.RDX);
      asm.xorRR32(R.R8, R.R8);
      asm.xorRR32(R.R9, R.R9);
      asm.callIat('iat:GetMessageA');
      asm.testRR32(R.RAX, R.RAX);
      asm.jle('msg_done');

      asm.leaRbpDisp(R.RCX, -0xc0);
      asm.callIat('iat:TranslateMessage');
      asm.leaRbpDisp(R.RCX, -0xc0);
      asm.callIat('iat:DispatchMessageA');
      asm.jmp('msg_loop');

      asm.label('msg_done');
      asm.xorRR32(R.RCX, R.RCX);
      asm.callIat('iat:ExitProcess');

      asm.leaRbpDisp(R.RSP, -0x10);
      asm.pop(R.R12);
      asm.pop(R.RBX);
      asm.pop(R.RBP);
      asm.ret();

      // ====================================================================
      // WndProc(RCX=hwnd, RDX=uMsg, R8=wParam, R9=lParam)
      // Saved regs: RBX=hwnd, R12=uMsg, R13=wParam, R14=lParam (32B at [rbp-0x20])
      // Locals: [rbp-0x90] = PAINTSTRUCT (72B), [rbp-0xA0] = written (4B), [rbp-0xA8] = tmp
      // ====================================================================
      asm.label('WndProc');
      asm.push(R.RBP);
      asm.movRR64(R.RBP, R.RSP);
      asm.push(R.RBX);
      asm.push(R.R12);
      asm.push(R.R13);
      asm.push(R.R14);
      asm.push(R.RDI);
      asm.push(R.RSI);
      asm.subRI64(R.RSP, 0x160);

      asm.movRR64(R.RBX, R.RCX); // hwnd
      asm.movRR64(R.R12, R.RDX); // uMsg
      asm.movRR64(R.R13, R.R8);  // wParam
      asm.movRR64(R.R14, R.R9);  // lParam

      // Dispatch on uMsg
      asm.cmpRI32(R.R12, 0x0001); // WM_CREATE
      asm.je('on_create');
      asm.cmpRI32(R.R12, 0x000f); // WM_PAINT
      asm.je('on_paint');
      asm.cmpRI32(R.R12, 0x0111); // WM_COMMAND
      asm.je('on_command');
      asm.cmpRI32(R.R12, 0x0010); // WM_CLOSE
      asm.je('on_close');
      asm.cmpRI32(R.R12, 0x0002); // WM_DESTROY
      asm.je('on_destroy');

      // Default: DefWindowProcA(hwnd, uMsg, wParam, lParam)
      asm.label('on_default');
      asm.movRR64(R.RCX, R.RBX);
      asm.movRR64(R.RDX, R.R12);
      asm.movRR64(R.R8, R.R13);
      asm.movRR64(R.R9, R.R14);
      asm.callIat('iat:DefWindowProcA');
      asm.jmp('wndproc_ret');

      // ---- WM_CREATE: Create child controls (EDIT 101, BUTTON 102, BUTTON 103, STATIC 104) ----
      asm.label('on_create');
      // 1. EDIT (ID 101)
      asm.xorRR32(R.RCX, R.RCX);
      asm.leaRipRel(R.RDX, 's_clsEdit');
      asm.leaRipRel(R.R8, 's_initialText');
      asm.movRI32(R.R9, 0x50000004); // WS_CHILD | WS_VISIBLE | ES_MULTILINE
      asm.movImm32ToRspDisp64(0x20, 16);
      asm.movImm32ToRspDisp64(0x28, 56);
      asm.movImm32ToRspDisp64(0x30, 608);
      asm.movImm32ToRspDisp64(0x38, 280);
      asm.movToRspDisp64(0x40, R.RBX);
      asm.movImm32ToRspDisp64(0x48, 101);
      asm.movFromRipRel64(R.RAX, 'g_hInstance');
      asm.movToRspDisp64(0x50, R.RAX);
      asm.movImm32ToRspDisp64(0x58, 0);
      asm.callIat('iat:CreateWindowExA');
      asm.movToRipRel64('g_hEdit', R.RAX);

      // 2. BUTTON "Save Note" (ID 102)
      asm.xorRR32(R.RCX, R.RCX);
      asm.leaRipRel(R.RDX, 's_clsButton');
      asm.leaRipRel(R.R8, 's_btnSave');
      asm.movRI32(R.R9, 0x50000000);
      asm.movImm32ToRspDisp64(0x20, 16);
      asm.movImm32ToRspDisp64(0x28, 350);
      asm.movImm32ToRspDisp64(0x30, 140);
      asm.movImm32ToRspDisp64(0x38, 34);
      asm.movToRspDisp64(0x40, R.RBX);
      asm.movImm32ToRspDisp64(0x48, 102);
      asm.movFromRipRel64(R.RAX, 'g_hInstance');
      asm.movToRspDisp64(0x50, R.RAX);
      asm.movImm32ToRspDisp64(0x58, 0);
      asm.callIat('iat:CreateWindowExA');

      // 3. BUTTON "Copy to Clipboard" (ID 103)
      asm.xorRR32(R.RCX, R.RCX);
      asm.leaRipRel(R.RDX, 's_clsButton');
      asm.leaRipRel(R.R8, 's_btnCopy');
      asm.movRI32(R.R9, 0x50000000);
      asm.movImm32ToRspDisp64(0x20, 170);
      asm.movImm32ToRspDisp64(0x28, 350);
      asm.movImm32ToRspDisp64(0x30, 170);
      asm.movImm32ToRspDisp64(0x38, 34);
      asm.movToRspDisp64(0x40, R.RBX);
      asm.movImm32ToRspDisp64(0x48, 103);
      asm.movFromRipRel64(R.RAX, 'g_hInstance');
      asm.movToRspDisp64(0x50, R.RAX);
      asm.movImm32ToRspDisp64(0x58, 0);
      asm.callIat('iat:CreateWindowExA');

      // 4. STATIC status label (ID 104)
      asm.xorRR32(R.RCX, R.RCX);
      asm.leaRipRel(R.RDX, 's_clsStatic');
      asm.leaRipRel(R.R8, 's_statusInit');
      asm.movRI32(R.R9, 0x50000000);
      asm.movImm32ToRspDisp64(0x20, 356);
      asm.movImm32ToRspDisp64(0x28, 358);
      asm.movImm32ToRspDisp64(0x30, 260);
      asm.movImm32ToRspDisp64(0x38, 24);
      asm.movToRspDisp64(0x40, R.RBX);
      asm.movImm32ToRspDisp64(0x48, 104);
      asm.movFromRipRel64(R.RAX, 'g_hInstance');
      asm.movToRspDisp64(0x50, R.RAX);
      asm.movImm32ToRspDisp64(0x58, 0);
      asm.callIat('iat:CreateWindowExA');

      asm.xorRR32(R.RAX, R.RAX);
      asm.jmp('wndproc_ret');

      // ---- WM_PAINT: BeginPaint -> Brush -> Rectangle -> TextOutA -> EndPaint ----
      asm.label('on_paint');
      asm.movRR64(R.RCX, R.RBX);
      asm.leaRbpDisp(R.RDX, -0x90);
      asm.callIat('iat:BeginPaint');
      asm.movRR64(R.R13, R.RAX); // R13 = hdc

      asm.movRI32(R.RCX, 0x00f5f0eb);
      asm.callIat('iat:CreateSolidBrush');
      asm.movRR64(R.RCX, R.R13);
      asm.movRR64(R.RDX, R.RAX);
      asm.callIat('iat:SelectObject');

      // Rectangle(hdc, 0, 0, 640, 44)
      asm.movRR64(R.RCX, R.R13);
      asm.xorRR32(R.RDX, R.RDX);
      asm.xorRR32(R.R8, R.R8);
      asm.movRI32(R.R9, 640);
      asm.movImm32ToRspDisp64(0x20, 44);
      asm.callIat('iat:Rectangle');

      // SetTextColor(hdc, 0x00222222)
      asm.movRR64(R.RCX, R.R13);
      asm.movRI32(R.RDX, 0x00222222);
      asm.callIat('iat:SetTextColor');

      // TextOutA(hdc, 16, 12, s_headerText, headerLen)
      asm.movRR64(R.RCX, R.R13);
      asm.movRI32(R.RDX, 16);
      asm.movRI32(R.R8, 12);
      asm.leaRipRel(R.R9, 's_headerText');
      asm.movImm32ToRspDisp64(0x20, headerBytes.byteLength);
      asm.callIat('iat:TextOutA');

      // EndPaint(hwnd, &ps)
      asm.movRR64(R.RCX, R.RBX);
      asm.leaRbpDisp(R.RDX, -0x90);
      asm.callIat('iat:EndPaint');

      asm.xorRR32(R.RAX, R.RAX);
      asm.jmp('wndproc_ret');

      // ---- WM_COMMAND: Dispatch Save (102) & Copy to Clipboard (103) ----
      asm.label('on_command');
      asm.movRR32(R.RAX, R.R13);
      asm.andRI32(R.RAX, 0xffff);
      asm.cmpRI32(R.RAX, 102);
      asm.je('cmd_save');
      asm.cmpRI32(R.RAX, 103);
      asm.je('cmd_copy');
      asm.xorRR32(R.RAX, R.RAX);
      asm.jmp('wndproc_ret');

      // ID 102: Read Edit text -> Write to VFS savePath -> Update status label
      asm.label('cmd_save');
      asm.movFromRipRel64(R.RCX, 'g_hEdit');
      asm.leaRipRel(R.RDX, 'g_textBuf');
      asm.movRI32(R.R8, 1000);
      asm.callIat('iat:GetWindowTextA');
      asm.movRR64(R.R14, R.RAX); // R14 = text length

      asm.leaRipRel(R.RCX, 's_savePath');
      asm.movRI32(R.RDX, 0x40000000); // GENERIC_WRITE
      asm.xorRR32(R.R8, R.R8);
      asm.xorRR32(R.R9, R.R9);
      asm.movImm32ToRspDisp64(0x20, 2);    // CREATE_ALWAYS
      asm.movImm32ToRspDisp64(0x28, 0x80); // FILE_ATTRIBUTE_NORMAL
      asm.movImm32ToRspDisp64(0x30, 0);
      asm.callIat('iat:CreateFileA');
      asm.movRR64(R.R13, R.RAX); // R13 = hFile

      asm.movRR64(R.RCX, R.R13);
      asm.leaRipRel(R.RDX, 'g_textBuf');
      asm.movRR64(R.R8, R.R14);
      asm.leaRbpDisp(R.R9, -0xa0);
      asm.movImm32ToRspDisp64(0x20, 0);
      asm.callIat('iat:WriteFile');

      asm.movRR64(R.RCX, R.R13);
      asm.callIat('iat:CloseHandle');

      asm.movRR64(R.RCX, R.RBX);
      asm.movRI32(R.RDX, 104);
      asm.callIat('iat:GetDlgItem');
      asm.movRR64(R.RCX, R.RAX);
      asm.leaRipRel(R.RDX, 's_statusSaved');
      asm.callIat('iat:SetWindowTextA');

      asm.xorRR32(R.RAX, R.RAX);
      asm.jmp('wndproc_ret');

      // ID 103: Read Edit text -> GlobalAlloc -> rep movsb -> SetClipboardData(CF_TEXT)
      asm.label('cmd_copy');
      asm.movFromRipRel64(R.RCX, 'g_hEdit');
      asm.leaRipRel(R.RDX, 'g_textBuf');
      asm.movRI32(R.R8, 1000);
      asm.callIat('iat:GetWindowTextA');
      asm.movRR64(R.R14, R.RAX); // R14 = len

      // hMem = GlobalAlloc(GMEM_MOVEABLE|GMEM_ZEROINIT=0x42, len + 1)
      asm.movRI32(R.RCX, 0x0042);
      asm.movRR64(R.RDX, R.R14);
      asm.addRI64(R.RDX, 1);
      asm.callIat('iat:GlobalAlloc');
      asm.movRR64(R.R13, R.RAX); // R13 = hMem

      // pMem = GlobalLock(hMem)
      asm.movRR64(R.RCX, R.R13);
      asm.callIat('iat:GlobalLock');
      // Copy g_textBuf -> pMem via real x86-64 `rep movsb` + NUL terminator!
      asm.movRR64(R.RDI, R.RAX);
      asm.leaRipRel(R.RSI, 'g_textBuf');
      asm.movRR64(R.RCX, R.R14);
      asm.cld();
      asm.repMovsb();
      // Write trailing NUL at [rax + r14]
      asm.movByteToBaseIdx(R.RAX, R.R14, 0);

      asm.movRR64(R.RCX, R.R13);
      asm.callIat('iat:GlobalUnlock');

      asm.movRR64(R.RCX, R.RBX);
      asm.callIat('iat:OpenClipboard');
      asm.callIat('iat:EmptyClipboard');
      asm.movRI32(R.RCX, 1); // CF_TEXT
      asm.movRR64(R.RDX, R.R13);
      asm.callIat('iat:SetClipboardData');
      asm.callIat('iat:CloseClipboard');

      asm.movRR64(R.RCX, R.RBX);
      asm.movRI32(R.RDX, 104);
      asm.callIat('iat:GetDlgItem');
      asm.movRR64(R.RCX, R.RAX);
      asm.leaRipRel(R.RDX, 's_statusCopied');
      asm.callIat('iat:SetWindowTextA');

      asm.xorRR32(R.RAX, R.RAX);
      asm.jmp('wndproc_ret');

      // ---- WM_CLOSE: DestroyWindow(hwnd) ----
      asm.label('on_close');
      asm.movRR64(R.RCX, R.RBX);
      asm.callIat('iat:DestroyWindow');
      asm.xorRR32(R.RAX, R.RAX);
      asm.jmp('wndproc_ret');

      // ---- WM_DESTROY: PostQuitMessage(0) ----
      asm.label('on_destroy');
      asm.xorRR32(R.RCX, R.RCX);
      asm.callIat('iat:PostQuitMessage');
      asm.xorRR32(R.RAX, R.RAX);

      asm.label('wndproc_ret');
      asm.leaRbpDisp(R.RSP, -0x30);
      asm.pop(R.RSI);
      asm.pop(R.RDI);
      asm.pop(R.R14);
      asm.pop(R.R13);
      asm.pop(R.R12);
      asm.pop(R.RBX);
      asm.pop(R.RBP);
      asm.ret();
    },
  });
}

// ============================================================================
// Sample Builder CLI & Export
// ============================================================================

export function buildWindowsSamples({
  outDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'packages'),
} = {}) {
  fs.mkdirSync(outDir, { recursive: true });

  const sysinfoBytes = buildWinSysinfoExe();
  const sysinfoPath = path.join(outDir, 'win-sysinfo.exe');
  fs.writeFileSync(sysinfoPath, sysinfoBytes);

  const notepadBytes = buildWinNotepadExe();
  const notepadPath = path.join(outDir, 'win-notepad.exe');
  fs.writeFileSync(notepadPath, notepadBytes);

  return {
    sysinfo: { path: sysinfoPath, size: sysinfoBytes.byteLength },
    notepad: { path: notepadPath, size: notepadBytes.byteLength },
  };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const res = buildWindowsSamples();
  console.log(
    `Built Windows samples:\n` +
    `  - ${res.sysinfo.path} (${res.sysinfo.size} bytes)\n` +
    `  - ${res.notepad.path} (${res.notepad.size} bytes)`
  );
}
