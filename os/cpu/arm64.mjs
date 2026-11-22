/**
 * OmniOS Real ARM64 (AArch64) CPU Emulator & Apple ARM64 ABI (`F-050`, Edge Cases `#23`, `#24`)
 * Zero-dependency Node.js 24 ESM implementation executing strictly against M1 `AddressSpace`.
 *
 * Key Architectural Guarantees:
 * - Full 64-bit GPR file (`X0..X30` as `BigUint64Array(31)`), 32-bit `W0..W30` views zero-extending
 *   upper 32 bits on write, dedicated `SP`, `PC`, `PSTATE { N, Z, C, V }`, and 32x128-bit `V0..V31`.
 * - Edge Case #23 (Reg 31 semantics): Strictly distinguishes `SP` (load/store base `Rn`, non-flag
 *   `ADD/SUB (imm)` `Rd`/`Rn`, `ADDS/SUBS (imm)` `Rn`, `ADD/SUB (ext)` `Rn`, non-flag logical imm `Rd`)
 *   vs `XZR`/`WZR` (reads `0n`, discards writes).
 * - Edge Case #24 (Apple ARM64 ABI): Reserves `X18`, keeps `SP` 16-byte aligned, and reads variadic
 *   arguments strictly from 8-byte stack slots `[SP + i * 8]` via `readVariadicArgs(fixedCount, count)`.
 */

import {
  IllegalInstructionError,
  UnsupportedOpcodeError,
  MemoryFaultError,
  QuotaExceededError,
  ERROR_CODES,
} from '../common/errors.mjs';

export const ARM64_RET_OPCODE = 0xd65f03c0;
export const ARM64_NOP_OPCODE = 0xd503201f;

export const ARM64_COND = Object.freeze({
  EQ: 0x0,
  NE: 0x1,
  CS: 0x2,
  HS: 0x2,
  CC: 0x3,
  LO: 0x3,
  MI: 0x4,
  PL: 0x5,
  VS: 0x6,
  VC: 0x7,
  HI: 0x8,
  LS: 0x9,
  GE: 0xa,
  LT: 0xb,
  GT: 0xc,
  LE: 0xd,
  AL: 0xe,
  NV: 0xf,
});

const MASK64 = 0xffffffffffffffffn;
const MASK32 = 0xffffffffn;
const SIGN64 = 0x8000000000000000n;
const SIGN32 = 0x80000000n;
const INT64_MIN = -0x8000000000000000n;
const INT64_MAX = 0x7fffffffffffffffn;
const INT32_MIN = -0x80000000n;
const INT32_MAX = 0x7fffffffn;

const F32_BUF = new ArrayBuffer(4);
const F32_VIEW = new DataView(F32_BUF);
const F64_BUF = new ArrayBuffer(8);
const F64_VIEW = new DataView(F64_BUF);

function toU64(val) {
  return BigInt.asUintN(64, typeof val === 'bigint' ? val : BigInt(val));
}

function toS64(val) {
  return BigInt.asIntN(64, val);
}

function toS32(val) {
  return BigInt.asIntN(32, val);
}

function signExtend32(val, bits) {
  const shift = 32 - bits;
  return BigInt((val << shift) >> shift);
}

function f32ToBits(f) {
  F32_VIEW.setFloat32(0, f, true);
  return F32_VIEW.getUint32(0, true);
}

function bitsToF32(u32) {
  F32_VIEW.setUint32(0, u32 >>> 0, true);
  return F32_VIEW.getFloat32(0, true);
}

function f64ToBits(f) {
  F64_VIEW.setFloat64(0, f, true);
  return F64_VIEW.getBigUint64(0, true);
}

function bitsToF64(u64) {
  F64_VIEW.setBigUint64(0, BigInt.asUintN(64, u64), true);
  return F64_VIEW.getFloat64(0, true);
}

function rorBits(val, shift, width) {
  const w = BigInt(width);
  const mask = (1n << w) - 1n;
  const v = val & mask;
  const s = BigInt(((shift % width) + width) % width);
  if (s === 0n) return v;
  return ((v >> s) | (v << (w - s))) & mask;
}

function replicatePattern(pattern, elemSize, totalSize) {
  let out = 0n;
  const e = BigInt(elemSize);
  for (let pos = 0; pos < totalSize; pos += elemSize) {
    out |= pattern << BigInt(pos);
  }
  return out & ((1n << BigInt(totalSize)) - 1n);
}

/**
 * ARMv8-A `DecodeBitMasks(N, imms, immr, immediate, M)` — exact architectural algorithm.
 * Returns `{ wmask, tmask }` or `null` on reserved/illegal encoding.
 */
function decodeBitMasks(N, imms, immr, immediate, regSize) {
  if (regSize === 32 && N === 1) return null;
  const combined = (N << 6) | (~imms & 0x3f);
  let len = -1;
  for (let bit = 6; bit >= 0; bit--) {
    if ((combined & (1 << bit)) !== 0) {
      len = bit;
      break;
    }
  }
  if (len < 1) return null;
  const esize = 1 << len;
  if (esize > regSize) return null;
  const levels = esize - 1;
  if (immediate && (imms & levels) === levels) return null;

  const S = imms & levels;
  const R = immr & levels;
  const diff = (S - R) & levels;

  const welem = (1n << BigInt(S + 1)) - 1n;
  const telem = (1n << BigInt(diff + 1)) - 1n;
  const wmask = replicatePattern(rorBits(welem, R, esize), esize, regSize);
  const tmask = replicatePattern(telem, esize, regSize);
  return { wmask, tmask, S, R, diff };
}

function vfpExpandImm32(imm8) {
  const sign = (imm8 >>> 7) & 1;
  const b = (imm8 >>> 6) & 1;
  const notB = b ^ 1;
  const rep5 = b ? 0x1f : 0x00;
  const cd = (imm8 >>> 4) & 3;
  const frac = imm8 & 0xf;
  const bits = ((sign << 31) | (notB << 30) | (rep5 << 25) | (cd << 23) | (frac << 19)) >>> 0;
  return bitsToF32(bits);
}

function vfpExpandImm64(imm8) {
  const sign = BigInt((imm8 >>> 7) & 1);
  const b = (imm8 >>> 6) & 1;
  const notB = BigInt(b ^ 1);
  const rep8 = b ? 0xffn : 0x00n;
  const cd = BigInt((imm8 >>> 4) & 3);
  const frac = BigInt(imm8 & 0xf);
  const bits = (sign << 63n) | (notB << 62n) | (rep8 << 54n) | (cd << 52n) | (frac << 48n);
  return bitsToF64(bits);
}

function addWithCarry(a, b, carryIn, is64) {
  const mask = is64 ? MASK64 : MASK32;
  const signBit = is64 ? SIGN64 : SIGN32;
  const ua = a & mask;
  const ub = b & mask;
  const cin = carryIn ? 1n : 0n;
  const unsignedSum = ua + ub + cin;
  const result = unsignedSum & mask;
  const sa = is64 ? toS64(ua) : toS32(ua);
  const sb = is64 ? toS64(ub) : toS32(ub);
  const sres = is64 ? toS64(result) : toS32(result);
  const signedSum = sa + sb + cin;

  return {
    result,
    N: (result & signBit) !== 0n ? 1 : 0,
    Z: result === 0n ? 1 : 0,
    C: unsignedSum > mask ? 1 : 0,
    V: sres !== signedSum ? 1 : 0,
  };
}

function roundToNearestEven(v) {
  if (!Number.isFinite(v) || v === 0) return v;
  const fl = Math.floor(v);
  const diff = v - fl;
  if (diff < 0.5) return fl === 0 && v < 0 ? -0 : fl;
  if (diff > 0.5) return fl + 1 === 0 && v < 0 ? -0 : fl + 1;
  // Exact half-way tie: pick even integer (preserving -0 for -0.5)
  const even = fl % 2 === 0 ? fl : fl + 1;
  return even === 0 && v < 0 ? -0 : even;
}

function shiftRegValue(val, shiftType, amount, is64) {
  const width = is64 ? 64 : 32;
  const mask = is64 ? MASK64 : MASK32;
  const v = val & mask;
  const sh = BigInt(amount & (width - 1));
  if (sh === 0n) return v;
  switch (shiftType) {
    case 0: // LSL
      return (v << sh) & mask;
    case 1: // LSR
      return v >> sh;
    case 2: { // ASR
      const signed = is64 ? toS64(v) : toS32(v);
      return (signed >> sh) & mask;
    }
    case 3: // ROR
      return rorBits(v, Number(sh), width);
    default:
      return v;
  }
}

function extendRegValue(val, option, shiftAmount, is64) {
  let extended;
  switch (option & 7) {
    case 0: // UXTB
      extended = val & 0xffn;
      break;
    case 1: // UXTH
      extended = val & 0xffffn;
      break;
    case 2: // UXTW
      extended = val & 0xffffffffn;
      break;
    case 3: // UXTX
      extended = val & MASK64;
      break;
    case 4: // SXTB
      extended = BigInt.asIntN(8, val);
      break;
    case 5: // SXTH
      extended = BigInt.asIntN(16, val);
      break;
    case 6: // SXTW
      extended = BigInt.asIntN(32, val);
      break;
    case 7: // SXTX
      extended = BigInt.asIntN(64, val);
      break;
    default:
      extended = val;
  }
  const mask = is64 ? MASK64 : MASK32;
  return (extended << BigInt(shiftAmount)) & mask;
}

function floatToSignedInt(val, is64) {
  if (Number.isNaN(val)) return 0n;
  const minVal = is64 ? INT64_MIN : INT32_MIN;
  const maxVal = is64 ? INT64_MAX : INT32_MAX;
  const maxFloat = is64 ? 9223372036854775808.0 : 2147483648.0;
  const minFloat = is64 ? -9223372036854775808.0 : -2147483648.0;
  if (val >= maxFloat) return maxVal;
  if (val <= minFloat) return minVal;
  const truncated = Math.trunc(val);
  const big = BigInt(truncated);
  if (big > maxVal) return maxVal;
  if (big < minVal) return minVal;
  return big;
}

function floatToUnsignedInt(val, is64) {
  if (Number.isNaN(val) || val <= 0) return 0n;
  const maxVal = is64 ? MASK64 : MASK32;
  const maxFloat = is64 ? 18446744073709551616.0 : 4294967296.0;
  if (val >= maxFloat) return maxVal;
  const truncated = Math.trunc(val);
  const big = BigInt(truncated);
  return big > maxVal ? maxVal : big;
}

function reverseBits(val, width) {
  let out = 0n;
  let v = val;
  for (let i = 0; i < width; i++) {
    out = (out << 1n) | (v & 1n);
    v >>= 1n;
  }
  return out;
}

function countLeadingZeros(val, width) {
  let count = 0;
  for (let i = width - 1; i >= 0; i--) {
    if (((val >> BigInt(i)) & 1n) !== 0n) break;
    count++;
  }
  return BigInt(count);
}

function countLeadingSignBits(val, width) {
  const sign = (val >> BigInt(width - 1)) & 1n;
  let count = 0;
  for (let i = width - 2; i >= 0; i--) {
    if (((val >> BigInt(i)) & 1n) !== sign) break;
    count++;
  }
  return BigInt(count);
}

export class ARM64Cpu {
  constructor({
    addressSpace = null,
    onSyscall = null,
    onThunk = null,
    onBreak = null,
    pid = null,
    maxInstructions = Infinity,
    thunkStart = null,
    thunkEnd = null,
    exitSentinelVA = null,
  } = {}) {
    this.arch = 'arm64';
    this.addressSpace = addressSpace;
    this.onSyscall = typeof onSyscall === 'function' ? onSyscall : null;
    this.onThunk = typeof onThunk === 'function' ? onThunk : null;
    this.onBreak = typeof onBreak === 'function' ? onBreak : null;
    this.pid = pid;
    this.maxInstructions =
      typeof maxInstructions === 'number' && maxInstructions > 0 ? maxInstructions : Infinity;
    this.thunkStart = thunkStart !== null && thunkStart !== undefined ? toU64(thunkStart) : null;
    this.thunkEnd = thunkEnd !== null && thunkEnd !== undefined ? toU64(thunkEnd) : null;
    this.exitSentinelVA =
      exitSentinelVA !== null && exitSentinelVA !== undefined ? toU64(exitSentinelVA) : null;

    // 31 general-purpose 64-bit registers X0..X30 (X29=FP, X30=LR, X18=Apple reserved)
    this.x = new BigUint64Array(31);
    this.sp = 0n;
    this.pc = 0n;
    this.pstate = { N: 0, Z: 0, C: 0, V: 0 };
    this.tpidrEl0 = 0n;

    // 32 x 128-bit SIMD/FP registers V0..V31
    this.v = Array.from({ length: 32 }, () => new Uint8Array(16));
    this._vViews = this.v.map((buf) => new DataView(buf.buffer, buf.byteOffset, 16));

    this.halted = false;
    this.exitCode = 0;
    this.instructionsExecuted = 0;
    this.lastSyscall = null;
    this._disposed = false;
  }

  reset() {
    this.x.fill(0n);
    this.sp = 0n;
    this.pc = 0n;
    this.pstate = { N: 0, Z: 0, C: 0, V: 0 };
    this.tpidrEl0 = 0n;
    for (let i = 0; i < 32; i++) {
      this.v[i].fill(0);
    }
    this.halted = false;
    this.exitCode = 0;
    this.instructionsExecuted = 0;
    this.lastSyscall = null;
  }

  get nzcv() {
    return (
      ((this.pstate.N & 1) << 31) |
      ((this.pstate.Z & 1) << 30) |
      ((this.pstate.C & 1) << 29) |
      ((this.pstate.V & 1) << 28)
    ) >>> 0;
  }

  set nzcv(bits) {
    const u = Number(typeof bits === 'bigint' ? bits & 0xffffffffn : bits >>> 0);
    this.pstate.N = (u >>> 31) & 1;
    this.pstate.Z = (u >>> 30) & 1;
    this.pstate.C = (u >>> 29) & 1;
    this.pstate.V = (u >>> 28) & 1;
  }

  // ---- Register accessors ----

  getReg(n) {
    if (typeof n === 'string') {
      const k = n.trim().toLowerCase();
      if (k === 'sp') return this.sp;
      if (k === 'pc') return this.pc;
      if (k === 'lr') return this.x[30];
      if (k === 'fp') return this.x[29];
      if (k === 'xzr' || k === 'wzr') return 0n;
      if (k.startsWith('x')) {
        const idx = Number.parseInt(k.slice(1), 10);
        if (idx >= 0 && idx <= 30) return this.x[idx];
        if (idx === 31) return 0n;
      }
      if (k.startsWith('w')) {
        const idx = Number.parseInt(k.slice(1), 10);
        if (idx >= 0 && idx <= 30) return this.x[idx] & MASK32;
        if (idx === 31) return 0n;
      }
      throw new RangeError(`Unknown ARM64 register: ${n}`);
    }
    if (n === 31) return 0n; // XZR
    if (!Number.isInteger(n) || n < 0 || n > 30) {
      throw new RangeError(`ARM64 register index out of range: ${n}`);
    }
    return this.x[n];
  }

  setReg(n, val) {
    const v = toU64(val);
    if (typeof n === 'string') {
      const k = n.trim().toLowerCase();
      if (k === 'sp') {
        this.sp = v;
        return;
      }
      if (k === 'pc') {
        this.pc = v;
        return;
      }
      if (k === 'lr') {
        this.x[30] = v;
        return;
      }
      if (k === 'fp') {
        this.x[29] = v;
        return;
      }
      if (k === 'xzr' || k === 'wzr') return;
      if (k.startsWith('x')) {
        const idx = Number.parseInt(k.slice(1), 10);
        if (idx >= 0 && idx <= 30) {
          this.x[idx] = v;
          return;
        }
        if (idx === 31) return;
      }
      if (k.startsWith('w')) {
        const idx = Number.parseInt(k.slice(1), 10);
        if (idx >= 0 && idx <= 30) {
          this.x[idx] = v & MASK32;
          return;
        }
        if (idx === 31) return;
      }
      throw new RangeError(`Unknown ARM64 register: ${n}`);
    }
    if (n === 31) return; // XZR discards writes
    if (!Number.isInteger(n) || n < 0 || n > 30) {
      throw new RangeError(`ARM64 register index out of range: ${n}`);
    }
    this.x[n] = v;
  }

  getWReg(n) {
    if (n === 31) return 0;
    if (!Number.isInteger(n) || n < 0 || n > 30) {
      throw new RangeError(`ARM64 W register index out of range: ${n}`);
    }
    return Number(this.x[n] & MASK32) >>> 0;
  }

  setWReg(n, val) {
    if (n === 31) return; // WZR discards writes
    if (!Number.isInteger(n) || n < 0 || n > 30) {
      throw new RangeError(`ARM64 W register index out of range: ${n}`);
    }
    // 32-bit W writes ALWAYS zero-extend upper 32 bits of the 64-bit X register!
    const low32 = typeof val === 'bigint' ? val & MASK32 : BigInt(val >>> 0);
    this.x[n] = low32;
  }

  getSP() {
    return this.sp;
  }

  setSP(val) {
    this.sp = toU64(val);
  }

  getPC() {
    return this.pc;
  }

  setPC(val) {
    this.pc = toU64(val);
  }

  getLR() {
    return this.x[30];
  }

  setLR(val) {
    this.x[30] = toU64(val);
  }

  getSReg(n) {
    return this._vViews[n & 31].getFloat32(0, true);
  }

  setSReg(n, val) {
    const idx = n & 31;
    this.v[idx].fill(0);
    this._vViews[idx].setFloat32(0, val, true);
  }

  getSRegBits(n) {
    return this._vViews[n & 31].getUint32(0, true);
  }

  setSRegBits(n, bits) {
    const idx = n & 31;
    this.v[idx].fill(0);
    this._vViews[idx].setUint32(0, bits >>> 0, true);
  }

  getDReg(n) {
    return this._vViews[n & 31].getFloat64(0, true);
  }

  setDReg(n, val) {
    const idx = n & 31;
    this.v[idx].fill(0);
    this._vViews[idx].setFloat64(0, val, true);
  }

  getDRegBits(n) {
    return this._vViews[n & 31].getBigUint64(0, true);
  }

  setDRegBits(n, bits) {
    const idx = n & 31;
    this.v[idx].fill(0);
    this._vViews[idx].setBigUint64(0, toU64(bits), true);
  }

  getVReg(n) {
    return this.v[n & 31].slice();
  }

  setVReg(n, bytes) {
    const idx = n & 31;
    this.v[idx].fill(0);
    const len = Math.min(16, bytes.length);
    for (let i = 0; i < len; i++) {
      this.v[idx][i] = bytes[i];
    }
  }

  // ---- Internal Reg-31 distinction helpers (Edge Case #23) ----

  _readRegOrSp(n, is64 = true) {
    const raw = n === 31 ? this.sp : this.x[n];
    return is64 ? raw : raw & MASK32;
  }

  _writeRegOrSp(n, val, is64 = true) {
    const masked = is64 ? val & MASK64 : val & MASK32;
    if (n === 31) {
      this.sp = masked;
    } else {
      this.x[n] = masked;
    }
  }

  _readRegOrZr(n, is64 = true) {
    if (n === 31) return 0n;
    return is64 ? this.x[n] : this.x[n] & MASK32;
  }

  _writeRegOrZr(n, val, is64 = true) {
    if (n === 31) return; // XZR/WZR discards writes
    this.x[n] = is64 ? val & MASK64 : val & MASK32;
  }

  /**
   * Edge Case #24 (Apple ARM64 ABI):
   * On Apple Darwin ARM64, variadic arguments (`...`) are ALWAYS passed on the stack
   * in 8-byte slots `[SP + (max(0, fixedCount - 8) + i) * 8]` — NEVER in `X1..X7`.
   */
  readVariadicArgs(fixedCount = 1, count = 0) {
    if (!this.addressSpace) {
      throw new MemoryFaultError('Cannot read variadic arguments without an AddressSpace', {
        code: ERROR_CODES.EFAULT,
        pid: this.pid,
      });
    }
    const nArgs = Math.max(0, Number(count) | 0);
    const fixedOnStack = Math.max(0, (Number(fixedCount) | 0) - 8);
    const out = new Array(nArgs);
    for (let i = 0; i < nArgs; i++) {
      const slotAddr = this.sp + BigInt((fixedOnStack + i) * 8);
      out[i] = this.addressSpace.readU64(slotAddr, true);
    }
    return out;
  }

  evalCondition(cond) {
    const { N, Z, C, V } = this.pstate;
    const base = (cond >>> 1) & 0x7;
    let res;
    switch (base) {
      case 0: // EQ / NE
        res = Z === 1;
        break;
      case 1: // CS(HS) / CC(LO)
        res = C === 1;
        break;
      case 2: // MI / PL
        res = N === 1;
        break;
      case 3: // VS / VC
        res = V === 1;
        break;
      case 4: // HI / LS
        res = C === 1 && Z === 0;
        break;
      case 5: // GE / LT
        res = N === V;
        break;
      case 6: // GT / LE
        res = Z === 0 && N === V;
        break;
      case 7: // AL / NV (both always true on ARM64)
        return true;
      default:
        res = false;
    }
    return (cond & 1) === 1 ? !res : res;
  }

  /**
   * Synchronously invoke a native ARM64 subroutine inside the current AddressSpace,
   * preserving callee-saved state, `X18` (Apple reserved), `SP`, `PC`, and `PSTATE`.
   */
  callFunctionSync(va, args = [], { maxSteps = 100_000, returnSentinelVA = null } = {}) {
    if (!this.addressSpace) {
      throw new MemoryFaultError('ARM64Cpu.callFunctionSync requires an AddressSpace', {
        code: ERROR_CODES.EFAULT,
        pid: this.pid,
      });
    }

    const savedX = new BigUint64Array(this.x);
    const savedSP = this.sp;
    const savedPC = this.pc;
    const savedPstate = { ...this.pstate };
    const savedV = this.v.map((buf) => buf.slice());
    const savedHalted = this.halted;
    const savedExitCode = this.exitCode;

    const sentinel = toU64(
      returnSentinelVA !== null && returnSentinelVA !== undefined
        ? returnSentinelVA
        : this.exitSentinelVA !== null
          ? this.exitSentinelVA
          : 0x7ffe00000000n
    );

    try {
      // Ensure 16-byte aligned SP on entry
      let callSP = this.sp - (this.sp % 16n);

      // Push stack args (index >= 8) if present, maintaining 16-byte SP alignment
      if (args.length > 8) {
        const extra = args.length - 8;
        const frameBytes = BigInt(((extra * 8 + 15) & ~15));
        callSP = (callSP - frameBytes) & MASK64;
        for (let i = 0; i < extra; i++) {
          this.addressSpace.writeU64(callSP + BigInt(i * 8), toU64(args[8 + i]), true);
        }
      }

      this.sp = callSP;
      for (let i = 0; i < Math.min(8, args.length); i++) {
        this.x[i] = toU64(args[i]);
      }
      // Note: X18 is explicitly preserved untouched!
      this.x[30] = sentinel;
      this.pc = toU64(va);
      this.halted = false;

      let totalSteps = 0;
      while (totalSteps < maxSteps) {
        if (this.pc === sentinel || this.halted) {
          break;
        }
        const chunk = Math.min(256, maxSteps - totalSteps);
        const res = this._stepInner(chunk, sentinel);
        totalSteps += res.instructionsExecuted;
        if (res.status === 'RETURNED_SENTINEL' || res.status === 'EXITED' || res.status === 'BLOCKED') {
          break;
        }
      }

      if (this.pc !== sentinel && !this.halted && totalSteps >= maxSteps) {
        throw new QuotaExceededError(
          `ARM64 subroutine at 0x${toU64(va).toString(16)} exceeded maxSteps (${maxSteps})`,
          {
            code: ERROR_CODES.E_CPU_QUOTA,
            quotaType: 'cpu',
            limit: maxSteps,
            actual: totalSteps,
            pid: this.pid,
          }
        );
      }

      const result = this.x[0];
      const x21 = this.x[21];
      const d0 = this.getDReg(0);
      const exited = this.halted;
      const exitCode = this.exitCode;

      return {
        result,
        x21,
        swiftError: x21,
        d0,
        instructionsExecuted: totalSteps,
        halted: exited,
        exitCode,
      };
    } finally {
      this.x.set(savedX);
      this.sp = savedSP;
      this.pc = savedPC;
      this.pstate = savedPstate;
      for (let i = 0; i < 32; i++) {
        this.v[i].set(savedV[i]);
      }
      this.halted = savedHalted;
      this.exitCode = savedExitCode;
    }
  }

  invokeSubroutine(va, args = [], opts = {}) {
    const normalizedOpts = typeof opts === 'number' ? { maxSteps: opts } : opts;
    return this.callFunctionSync(va, args, normalizedOpts);
  }

  /**
   * Synchronous, budget-bounded execution step conforming to OmniOS `IExecutionContext.step(budget)`.
   */
  step(budget = 1) {
    if (this._disposed) {
      return { status: 'EXITED', instructionsExecuted: 0, exitCode: this.exitCode };
    }
    if (this.halted) {
      return { status: 'EXITED', instructionsExecuted: 0, exitCode: this.exitCode };
    }
    const maxSteps =
      typeof budget === 'number' && Number.isFinite(budget) && budget >= 1
        ? Math.floor(budget)
        : 1;
    const res = this._stepInner(maxSteps, null);
    if (res.status === 'RETURNED_SENTINEL') {
      return { status: 'EXITED', instructionsExecuted: res.instructionsExecuted, exitCode: this.exitCode };
    }
    return res;
  }

  _stepInner(maxSteps, stopSentinel) {
    if (!this.addressSpace) {
      throw new MemoryFaultError('ARM64Cpu has no attached AddressSpace', {
        code: ERROR_CODES.EFAULT,
        pid: this.pid,
      });
    }

    let executed = 0;

    while (executed < maxSteps) {
      if (this.halted) {
        return { status: 'EXITED', instructionsExecuted: executed, exitCode: this.exitCode };
      }

      const pc = this.pc;
      if (stopSentinel !== null && pc === stopSentinel) {
        return { status: 'RETURNED_SENTINEL', instructionsExecuted: executed };
      }
      if (this.exitSentinelVA !== null && pc === this.exitSentinelVA && stopSentinel === null) {
        this.halted = true;
        this.exitCode = Number(BigInt.asIntN(32, this.x[0]));
        return { status: 'EXITED', instructionsExecuted: executed, exitCode: this.exitCode };
      }

      if (this.instructionsExecuted >= this.maxInstructions) {
        throw new QuotaExceededError(
          `ARM64 CPU exceeded maxInstructions quota (${this.maxInstructions})`,
          {
            code: ERROR_CODES.E_CPU_QUOTA,
            quotaType: 'cpu',
            limit: this.maxInstructions,
            actual: this.instructionsExecuted,
            pid: this.pid,
          }
        );
      }

      if ((pc & 3n) !== 0n) {
        throw new IllegalInstructionError(
          `Unaligned ARM64 instruction fetch at PC=0x${pc.toString(16)}`,
          {
            code: ERROR_CODES.E_MISALIGNED_ACCESS,
            pc,
            arch: 'arm64',
            pid: this.pid,
          }
        );
      }

      // Strictly enforce PROT_EXEC & __PAGEZERO via M1 AddressSpace.fetch()
      const insnBytes = this.addressSpace.fetch(pc, 4);
      const insn =
        (insnBytes[0] | (insnBytes[1] << 8) | (insnBytes[2] << 16) | (insnBytes[3] << 24)) >>> 0;

      // Check thunk dispatch BEFORE decoding when inside thunk range (or any PC if no range filter)
      if (
        this.onThunk &&
        (this.thunkStart === null ||
          this.thunkEnd === null ||
          (pc >= this.thunkStart && pc < this.thunkEnd))
      ) {
        const savedX18 = this.x[18];
        const thunkRes = this.onThunk(pc, this);
        // Apple ARM64 ABI invariant (Edge Case #24): host thunks MUST NEVER clobber X18
        this.x[18] = savedX18;

        if (thunkRes) {
          executed += 1;
          this.instructionsExecuted += 1;

          if (typeof thunkRes === 'object') {
            if (thunkRes.status === 'EXITED') {
              this.halted = true;
              this.exitCode =
                thunkRes.exitCode !== undefined
                  ? Number(thunkRes.exitCode)
                  : Number(BigInt.asIntN(32, this.x[0]));
              return { status: 'EXITED', instructionsExecuted: executed, exitCode: this.exitCode };
            }
            if (thunkRes.status === 'BLOCKED') {
              if (this.pc === pc) {
                this.pc = this.x[30];
              }
              return {
                status: 'BLOCKED',
                instructionsExecuted: executed,
                waitReason: thunkRes.waitReason ?? 'ui_event',
              };
            }
            if (thunkRes.status === 'YIELD') {
              if (this.pc === pc) {
                this.pc = this.x[30];
              }
              return { status: 'YIELD', instructionsExecuted: executed };
            }
          }

          if (this.halted) {
            return { status: 'EXITED', instructionsExecuted: executed, exitCode: this.exitCode };
          }
          // If the thunk did not redirect PC (e.g. tail-call to an app IMP), return via LR (X30)
          if (this.pc === pc) {
            this.pc = this.x[30];
          }
          continue;
        }
      }

      // Advance default PC to next instruction; branches/traps overwrite this.pc as needed.
      this.pc = (pc + 4n) & MASK64;
      const ctrl = this._executeInstruction(insn, pc);
      executed += 1;
      this.instructionsExecuted += 1;

      if (ctrl) {
        if (ctrl.status === 'EXITED') {
          this.halted = true;
          this.exitCode = ctrl.exitCode ?? this.exitCode;
          return { status: 'EXITED', instructionsExecuted: executed, exitCode: this.exitCode };
        }
        if (ctrl.status === 'BLOCKED') {
          return {
            status: 'BLOCKED',
            instructionsExecuted: executed,
            waitReason: ctrl.waitReason ?? 'ui_event',
          };
        }
        if (ctrl.status === 'YIELD') {
          return { status: 'YIELD', instructionsExecuted: executed };
        }
      }
      if (this.halted) {
        return { status: 'EXITED', instructionsExecuted: executed, exitCode: this.exitCode };
      }
    }

    return { status: 'YIELD', instructionsExecuted: executed };
  }

  _unsupported(insn, pc, detail = '') {
    throw new UnsupportedOpcodeError(
      `Unsupported ARM64 opcode 0x${insn.toString(16).padStart(8, '0')} at PC=0x${pc.toString(16)}${detail ? `: ${detail}` : ''}`,
      {
        code: ERROR_CODES.E_UNSUPPORTED_OPCODE,
        pc,
        opcode: insn,
        arch: 'arm64',
        pid: this.pid,
      }
    );
  }

  _illegal(insn, pc, detail = '', signal = 'SIGILL') {
    throw new IllegalInstructionError(
      `Illegal ARM64 instruction 0x${insn.toString(16).padStart(8, '0')} at PC=0x${pc.toString(16)}${detail ? `: ${detail}` : ''}`,
      {
        code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
        pc,
        opcode: insn,
        arch: 'arm64',
        pid: this.pid,
        signal,
      }
    );
  }

  _executeInstruction(insn, pc) {
    if (insn === 0) {
      this._illegal(insn, pc, 'UDF #0');
    }

    const op0 = (insn >>> 25) & 0xf;

    // 100x -> Data Processing — Immediate (bits 28..26 = 100)
    if ((op0 & 0xe) === 0x8) {
      return this._execDataProcImm(insn, pc);
    }

    // 101x -> Branches, Exception Generating and System instructions (bits 28..26 = 101)
    if ((op0 & 0xe) === 0xa) {
      return this._execBranchSystem(insn, pc);
    }

    // x1x0 -> Loads and Stores (bit 27 = 1, bit 25 = 0)
    if ((op0 & 0x5) === 0x4) {
      return this._execLoadStore(insn, pc);
    }

    // x101 -> Data Processing — Register (bits 27..25 = 101)
    if ((op0 & 0x7) === 0x5) {
      return this._execDataProcReg(insn, pc);
    }

    // x111 -> Data Processing — Scalar Floating-Point & SIMD (bits 27..25 = 111)
    if ((op0 & 0x7) === 0x7) {
      return this._execFpSimd(insn, pc);
    }

    this._unsupported(insn, pc, `top-level op0=0b${op0.toString(2).padStart(4, '0')}`);
  }

  // =========================================================================
  // Group 1: Data Processing — Immediate
  // =========================================================================

  _execDataProcImm(insn, pc) {
    const op0 = (insn >>> 23) & 0x7;

    // 000 / 001: PC-rel addressing (ADR / ADRP)
    if ((op0 & 0x6) === 0x0) {
      const isAdrp = ((insn >>> 31) & 1) === 1;
      const immlo = (insn >>> 29) & 0x3;
      const immhi = (insn >>> 5) & 0x7ffff;
      const rd = insn & 0x1f;
      const imm21 = signExtend32((immhi << 2) | immlo, 21);
      const base = isAdrp ? pc & ~0xfffn : pc;
      const offset = isAdrp ? imm21 << 12n : imm21;
      this._writeRegOrZr(rd, (base + offset) & MASK64, true);
      return null;
    }

    // 010: Add/subtract (immediate): ADD, ADDS, SUB, SUBS
    if (op0 === 0x2) {
      const is64 = ((insn >>> 31) & 1) === 1;
      const isSub = ((insn >>> 30) & 1) === 1;
      const setFlags = ((insn >>> 29) & 1) === 1;
      const sh = (insn >>> 22) & 1;
      const imm12 = BigInt((insn >>> 10) & 0xfff);
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;

      const imm = sh ? imm12 << 12n : imm12;
      // Edge Case #23: Rn is ALWAYS SP for ADD/ADDS/SUB/SUBS (imm).
      // Rd is SP when S=0 (ADD/SUB), and XZR/WZR when S=1 (ADDS/SUBS, e.g. CMP/CMN).
      const op1 = this._readRegOrSp(rn, is64);
      const mask = is64 ? MASK64 : MASK32;
      const op2 = isSub ? ~imm & mask : imm;
      const res = addWithCarry(op1, op2, isSub ? 1 : 0, is64);

      if (setFlags) {
        this.pstate.N = res.N;
        this.pstate.Z = res.Z;
        this.pstate.C = res.C;
        this.pstate.V = res.V;
        this._writeRegOrZr(rd, res.result, is64);
      } else {
        this._writeRegOrSp(rd, res.result, is64);
      }
      return null;
    }

    // 100: Logical (immediate): AND, ORR, EOR, ANDS
    if (op0 === 0x4) {
      const is64 = ((insn >>> 31) & 1) === 1;
      const opc = (insn >>> 29) & 0x3;
      const N = (insn >>> 22) & 1;
      const immr = (insn >>> 16) & 0x3f;
      const imms = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;

      const decoded = decodeBitMasks(N, imms, immr, true, is64 ? 64 : 32);
      if (!decoded) {
        this._illegal(insn, pc, 'Invalid logical immediate bitmask');
      }
      const imm = decoded.wmask;
      const op1 = this._readRegOrZr(rn, is64);
      let result;
      switch (opc) {
        case 0: // AND
        case 3: // ANDS (TST)
          result = op1 & imm;
          break;
        case 1: // ORR
          result = op1 | imm;
          break;
        case 2: // EOR
          result = op1 ^ imm;
          break;
        default:
          result = 0n;
      }
      const mask = is64 ? MASK64 : MASK32;
      result &= mask;

      if (opc === 3) {
        this.pstate.N = (result & (is64 ? SIGN64 : SIGN32)) !== 0n ? 1 : 0;
        this.pstate.Z = result === 0n ? 1 : 0;
        this.pstate.C = 0;
        this.pstate.V = 0;
        this._writeRegOrZr(rd, result, is64);
      } else {
        // ARMv8 spec: non-flag logical immediate writes SP if Rd=31 (e.g., AND SP, SP, #-16)
        this._writeRegOrSp(rd, result, is64);
      }
      return null;
    }

    // 101: Move wide (immediate): MOVN, MOVZ, MOVK
    if (op0 === 0x5) {
      const is64 = ((insn >>> 31) & 1) === 1;
      const opc = (insn >>> 29) & 0x3;
      const hw = (insn >>> 21) & 0x3;
      const imm16 = BigInt((insn >>> 5) & 0xffff);
      const rd = insn & 0x1f;

      if (!is64 && hw >= 2) {
        this._illegal(insn, pc, 'Invalid 32-bit move-wide hw >= 2');
      }
      const shift = BigInt(hw * 16);
      const mask = is64 ? MASK64 : MASK32;
      let result;

      if (opc === 0) {
        // MOVN
        result = ~(imm16 << shift) & mask;
      } else if (opc === 2) {
        // MOVZ
        result = (imm16 << shift) & mask;
      } else if (opc === 3) {
        // MOVK
        const cur = this._readRegOrZr(rd, is64);
        const clearMask = ~(0xffffn << shift) & mask;
        result = ((cur & clearMask) | (imm16 << shift)) & mask;
      } else {
        this._illegal(insn, pc, `Reserved move-wide opc=${opc}`);
      }
      this._writeRegOrZr(rd, result, is64);
      return null;
    }

    // 110: Bitfield: SBFM, BFM, UBFM (covers LSL, LSR, ASR, SXTB/H/W, UXTB/H, UBFX, SBFX, BFI)
    if (op0 === 0x6) {
      const is64 = ((insn >>> 31) & 1) === 1;
      const opc = (insn >>> 29) & 0x3;
      const N = (insn >>> 22) & 1;
      const immr = (insn >>> 16) & 0x3f;
      const imms = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;

      if (opc === 3 || N !== (is64 ? 1 : 0) || (!is64 && (immr >= 32 || imms >= 32))) {
        this._illegal(insn, pc, 'Invalid bitfield encoding');
      }
      const regSize = is64 ? 64 : 32;
      const decoded = decodeBitMasks(N, imms, immr, false, regSize);
      if (!decoded) {
        this._illegal(insn, pc, 'Invalid bitfield mask');
      }
      const mask = is64 ? MASK64 : MASK32;
      const src = this._readRegOrZr(rn, is64);
      const dst = opc === 1 ? this._readRegOrZr(rd, is64) : 0n;
      const rotated = rorBits(src, decoded.R, regSize);
      const bot = (dst & ~decoded.wmask) | (rotated & decoded.wmask);
      let top;
      if (opc === 0) {
        // SBFM: replicate bit S of src
        const signBit = (src >> BigInt(decoded.S)) & 1n;
        top = signBit === 1n ? mask : 0n;
      } else {
        top = dst;
      }
      const result = ((top & ~decoded.tmask) | (bot & decoded.tmask)) & mask;
      this._writeRegOrZr(rd, result, is64);
      return null;
    }

    // 111: Extract (EXTR / ROR imm)
    if (op0 === 0x7) {
      const is64 = ((insn >>> 31) & 1) === 1;
      const op21 = (insn >>> 29) & 0x3;
      const N = (insn >>> 22) & 1;
      const o0 = (insn >>> 21) & 1;
      const rm = (insn >>> 16) & 0x1f;
      const imms = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;

      if (op21 !== 0 || o0 !== 0 || N !== (is64 ? 1 : 0) || (!is64 && imms >= 32)) {
        this._illegal(insn, pc, 'Invalid EXTR encoding');
      }
      const width = is64 ? 64 : 32;
      const mask = is64 ? MASK64 : MASK32;
      const hi = this._readRegOrZr(rn, is64);
      const lo = this._readRegOrZr(rm, is64);
      const lsb = BigInt(imms);
      const result =
        lsb === 0n ? lo : (((lo >> lsb) | (hi << (BigInt(width) - lsb))) & mask);
      this._writeRegOrZr(rd, result, is64);
      return null;
    }

    this._unsupported(insn, pc, `data-proc-imm op0=${op0}`);
  }

  // =========================================================================
  // Group 2: Branches, Exception Generating & System
  // =========================================================================

  _execBranchSystem(insn, pc) {
    const op0 = (insn >>> 29) & 0x7;

    // 000 / 100: Unconditional branch (immediate): B, BL
    if (op0 === 0x0 || op0 === 0x4) {
      const isLink = ((insn >>> 31) & 1) === 1;
      const imm26 = signExtend32(insn & 0x03ffffff, 26);
      if (isLink) {
        this.x[30] = (pc + 4n) & MASK64;
      }
      this.pc = (pc + (imm26 << 2n)) & MASK64;
      return null;
    }

    // 001 / 101: CBZ, CBNZ, TBZ, TBNZ
    if (op0 === 0x1 || op0 === 0x5) {
      const isTestBranch = ((insn >>> 25) & 1) === 1;
      const op = (insn >>> 24) & 1;
      const rt = insn & 0x1f;

      if (!isTestBranch) {
        // CBZ / CBNZ
        const is64 = ((insn >>> 31) & 1) === 1;
        const imm19 = signExtend32((insn >>> 5) & 0x7ffff, 19);
        const val = this._readRegOrZr(rt, is64);
        const take = op === 0 ? val === 0n : val !== 0n;
        if (take) {
          this.pc = (pc + (imm19 << 2n)) & MASK64;
        }
      } else {
        // TBZ / TBNZ
        const b5 = (insn >>> 31) & 1;
        const b40 = (insn >>> 19) & 0x1f;
        const bitPos = BigInt((b5 << 5) | b40);
        const imm14 = signExtend32((insn >>> 5) & 0x3fff, 14);
        const bit = (this._readRegOrZr(rt, true) >> bitPos) & 1n;
        const take = op === 0 ? bit === 0n : bit !== 0n;
        if (take) {
          this.pc = (pc + (imm14 << 2n)) & MASK64;
        }
      }
      return null;
    }

    // 010: Conditional branch (immediate): B.cond
    if (op0 === 0x2) {
      const o1 = (insn >>> 24) & 1;
      const o0 = (insn >>> 4) & 1;
      if (o1 !== 0 || o0 !== 0) {
        this._unsupported(insn, pc, 'Unrecognized conditional branch');
      }
      const imm19 = signExtend32((insn >>> 5) & 0x7ffff, 19);
      const cond = insn & 0xf;
      if (this.evalCondition(cond)) {
        this.pc = (pc + (imm19 << 2n)) & MASK64;
      }
      return null;
    }

    // 110: Exception generation, System, Unconditional branch (register)
    if (op0 === 0x6) {
      const bit25 = (insn >>> 25) & 1;

      if (bit25 === 1) {
        // Unconditional branch (register): BR, BLR, RET
        const opc = (insn >>> 21) & 0xf;
        const op2 = (insn >>> 16) & 0x1f;
        const op3 = (insn >>> 10) & 0x3f;
        const rn = (insn >>> 5) & 0x1f;
        const op4 = insn & 0x1f;

        if (op2 === 0x1f && op3 === 0 && op4 === 0) {
          if (opc === 0) {
            // BR Xn
            this.pc = this._readRegOrZr(rn, true);
            return null;
          }
          if (opc === 1) {
            // BLR Xn (read target before clobbering X30)
            const target = this._readRegOrZr(rn, true);
            this.x[30] = (pc + 4n) & MASK64;
            this.pc = target;
            return null;
          }
          if (opc === 2) {
            // RET {Xn}
            this.pc = this._readRegOrZr(rn, true);
            return null;
          }
        }
        // PAC-authenticated RETAB/RETAA (opc=2, op2=0x1F, op3=2|3, rn=0x1F, op4=0x1F)
        if (opc === 2 && op2 === 0x1f && (op3 === 2 || op3 === 3) && rn === 0x1f && op4 === 0x1f) {
          this.pc = this.x[30];
          return null;
        }
        this._unsupported(insn, pc, `branch-reg opc=${opc}`);
      }

      const bit24 = (insn >>> 24) & 1;
      if (bit24 === 0) {
        // Exception generation: SVC, BRK, HLT
        const opc = (insn >>> 21) & 0x7;
        const imm16 = (insn >>> 5) & 0xffff;
        const op2 = (insn >>> 2) & 0x7;
        const ll = insn & 0x3;

        if (opc === 0 && op2 === 0 && ll === 1) {
          // SVC #imm16
          this.lastSyscall = {
            imm16,
            x16: this.x[16],
            x0: this.x[0],
            pc,
          };
          if (!this.onSyscall) {
            this._unsupported(insn, pc, `SVC #0x${imm16.toString(16)} with no onSyscall handler`);
          }
          const savedX18 = this.x[18];
          const sysRes = this.onSyscall(this, imm16);
          // Apple ARM64 ABI: X18 preserved across host syscall handler
          this.x[18] = savedX18;
          if (sysRes && typeof sysRes === 'object') {
            return sysRes;
          }
          return null;
        }

        if (opc === 1 && op2 === 0 && ll === 0) {
          // BRK #imm16
          if (this.onBreak) {
            const brkRes = this.onBreak(this, imm16);
            if (brkRes && typeof brkRes === 'object') return brkRes;
            return null;
          }
          this._illegal(insn, pc, `BRK #0x${imm16.toString(16)}`, 'SIGTRAP');
        }

        if (opc === 2 && op2 === 0 && ll === 0) {
          // HLT #imm16
          this.halted = true;
          this.exitCode = Number(BigInt.asIntN(32, this.x[0]));
          return { status: 'EXITED', exitCode: this.exitCode };
        }

        this._unsupported(insn, pc, `exception opc=${opc}`);
      }

      // System instructions (bits 31..22 = 0b1101010100 = 0x354)
      if ((insn >>> 22) === 0x354) {
        const L = (insn >>> 21) & 1;
        const op0Sys = (insn >>> 19) & 0x3;
        const op1Sys = (insn >>> 16) & 0x7;
        const crn = (insn >>> 12) & 0xf;
        const crm = (insn >>> 8) & 0xf;
        const op2Sys = (insn >>> 5) & 0x7;
        const rt = insn & 0x1f;

        // HINTs (NOP, YIELD, WFE, WFI, SEV, SEVL, PACIASP, AUTIASP, BTI, etc.)
        if (L === 0 && op0Sys === 0 && op1Sys === 3 && crn === 2 && rt === 31) {
          return null;
        }
        // Barriers (CLREX, DSB, DMB, ISB)
        if (L === 0 && op0Sys === 0 && op1Sys === 3 && crn === 3 && rt === 31) {
          return null;
        }
        // MRS Xt, <sysreg>
        if (L === 1 && op0Sys >= 2) {
          let val = 0n;
          if (op0Sys === 3 && op1Sys === 3 && crn === 4 && crm === 2 && op2Sys === 0) {
            val = BigInt(this.nzcv);
          } else if (op0Sys === 3 && op1Sys === 3 && crn === 13 && crm === 0 && (op2Sys === 2 || op2Sys === 3)) {
            val = this.tpidrEl0;
          } else if (op0Sys === 3 && op1Sys === 3 && crn === 14 && crm === 0 && op2Sys === 0) {
            val = 24_000_000n; // CNTFRQ_EL0 (24 MHz Apple Silicon)
          } else if (op0Sys === 3 && op1Sys === 3 && crn === 14 && crm === 0 && op2Sys === 2) {
            val = BigInt(this.instructionsExecuted); // CNTVCT_EL0 deterministic monotonic counter
          } else if (op0Sys === 3 && op1Sys === 3 && crn === 0 && crm === 0 && op2Sys === 1) {
            val = 0x84448004n; // CTR_EL0
          } else if (op0Sys === 3 && op1Sys === 3 && crn === 0 && crm === 0 && op2Sys === 7) {
            val = 0x4n; // DCZID_EL0 (64B cache line)
          }
          this._writeRegOrZr(rt, val, true);
          return null;
        }
        // MSR <sysreg>, Xt
        if (L === 0 && op0Sys >= 2) {
          const val = this._readRegOrZr(rt, true);
          if (op0Sys === 3 && op1Sys === 3 && crn === 4 && crm === 2 && op2Sys === 0) {
            this.nzcv = val;
          } else if (op0Sys === 3 && op1Sys === 3 && crn === 13 && crm === 0 && op2Sys === 2) {
            this.tpidrEl0 = val;
          }
          return null;
        }
      }
    }

    this._unsupported(insn, pc, `branch/system op0=${op0}`);
  }

  // =========================================================================
  // Group 3: Loads and Stores
  // =========================================================================

  _execLoadStore(insn, pc) {
    const bits29_27 = (insn >>> 27) & 0x7;
    const isFp = ((insn >>> 26) & 1) === 1;
    const bits25_24 = (insn >>> 24) & 0x3;

    // 1. Load register (literal): bits 29..27 = 011, bits 25..24 = 00
    if (bits29_27 === 0x3 && bits25_24 === 0x0) {
      const opc = (insn >>> 30) & 0x3;
      const imm19 = signExtend32((insn >>> 5) & 0x7ffff, 19);
      const rt = insn & 0x1f;
      const addr = (pc + (imm19 << 2n)) & MASK64;

      if (!isFp) {
        if (opc === 0) {
          this._writeRegOrZr(rt, BigInt(this.addressSpace.readU32(addr, true)), false);
        } else if (opc === 1) {
          this._writeRegOrZr(rt, this.addressSpace.readU64(addr, true), true);
        } else if (opc === 2) {
          const v = BigInt.asIntN(32, BigInt(this.addressSpace.readU32(addr, true)));
          this._writeRegOrZr(rt, v & MASK64, true);
        } else {
          // PRFM (literal) -> NOP
        }
      } else {
        if (opc === 0) {
          this.setSRegBits(rt, this.addressSpace.readU32(addr, true));
        } else if (opc === 1) {
          this.setDRegBits(rt, this.addressSpace.readU64(addr, true));
        } else if (opc === 2) {
          this.setVReg(rt, this.addressSpace.read(addr, 16));
        } else {
          this._illegal(insn, pc, 'Invalid FP LDR literal opc=3');
        }
      }
      return null;
    }

    // 2. Load/Store Pair (LDP, STP, LDPSW, LDNP, STNP): bits 29..27 = 101 (0x5)
    if (bits29_27 === 0x5) {
      const opc = (insn >>> 30) & 0x3;
      const mode = (insn >>> 23) & 0x7;
      const isLoad = ((insn >>> 22) & 1) === 1;
      const imm7 = signExtend32((insn >>> 15) & 0x7f, 7);
      const rt2 = (insn >>> 10) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const rt = insn & 0x1f;

      if (mode !== 0 && mode !== 1 && mode !== 2 && mode !== 3) {
        this._unsupported(insn, pc, `LDP/STP mode=${mode}`);
      }

      let scale;
      let isSignedW = false;
      if (!isFp) {
        if (opc === 0) {
          scale = 2; // 32-bit W
        } else if (opc === 1 && isLoad) {
          scale = 2; // LDPSW
          isSignedW = true;
        } else if (opc === 2) {
          scale = 3; // 64-bit X
        } else {
          this._illegal(insn, pc, `Invalid GPR LDP/STP opc=${opc}`);
        }
      } else {
        if (opc === 0) scale = 2; // S (4B)
        else if (opc === 1) scale = 3; // D (8B)
        else if (opc === 2) scale = 4; // Q (16B)
        else this._illegal(insn, pc, 'Invalid FP LDP/STP opc=3');
      }

      const dbytes = BigInt(1 << scale);
      const offset = imm7 << BigInt(scale);
      // Edge Case #23: Load/store base Rn=31 is ALWAYS SP!
      const base = this._readRegOrSp(rn, true);
      const postIndex = mode === 1;
      const preIndex = mode === 3;
      const addr = postIndex ? base : (base + offset) & MASK64;
      const addr2 = (addr + dbytes) & MASK64;

      if (isLoad) {
        if (!isFp) {
          if (scale === 2) {
            const v1 = BigInt(this.addressSpace.readU32(addr, true));
            const v2 = BigInt(this.addressSpace.readU32(addr2, true));
            if (isSignedW) {
              this._writeRegOrZr(rt, BigInt.asIntN(32, v1) & MASK64, true);
              this._writeRegOrZr(rt2, BigInt.asIntN(32, v2) & MASK64, true);
            } else {
              this._writeRegOrZr(rt, v1, false);
              this._writeRegOrZr(rt2, v2, false);
            }
          } else {
            const v1 = this.addressSpace.readU64(addr, true);
            const v2 = this.addressSpace.readU64(addr2, true);
            this._writeRegOrZr(rt, v1, true);
            this._writeRegOrZr(rt2, v2, true);
          }
        } else {
          if (scale === 2) {
            const b1 = this.addressSpace.readU32(addr, true);
            const b2 = this.addressSpace.readU32(addr2, true);
            this.setSRegBits(rt, b1);
            this.setSRegBits(rt2, b2);
          } else if (scale === 3) {
            const b1 = this.addressSpace.readU64(addr, true);
            const b2 = this.addressSpace.readU64(addr2, true);
            this.setDRegBits(rt, b1);
            this.setDRegBits(rt2, b2);
          } else {
            const b1 = this.addressSpace.read(addr, 16);
            const b2 = this.addressSpace.read(addr2, 16);
            this.setVReg(rt, b1);
            this.setVReg(rt2, b2);
          }
        }
      } else {
        if (!isFp) {
          if (scale === 2) {
            this.addressSpace.writeU32(addr, Number(this._readRegOrZr(rt, false)), true);
            this.addressSpace.writeU32(addr2, Number(this._readRegOrZr(rt2, false)), true);
          } else {
            this.addressSpace.writeU64(addr, this._readRegOrZr(rt, true), true);
            this.addressSpace.writeU64(addr2, this._readRegOrZr(rt2, true), true);
          }
        } else {
          if (scale === 2) {
            this.addressSpace.writeU32(addr, this.getSRegBits(rt), true);
            this.addressSpace.writeU32(addr2, this.getSRegBits(rt2), true);
          } else if (scale === 3) {
            this.addressSpace.writeU64(addr, this.getDRegBits(rt), true);
            this.addressSpace.writeU64(addr2, this.getDRegBits(rt2), true);
          } else {
            this.addressSpace.write(addr, this.v[rt]);
            this.addressSpace.write(addr2, this.v[rt2]);
          }
        }
      }

      if (preIndex || postIndex) {
        this._writeRegOrSp(rn, (base + offset) & MASK64, true);
      }
      return null;
    }

    // 3. Load/Store Register (unsigned imm, unscaled LDUR/STUR, pre/post-index, reg-offset): bits 29..27 = 111
    if (bits29_27 === 0x7) {
      const size = (insn >>> 30) & 0x3;
      const opc = (insn >>> 22) & 0x3;
      const rn = (insn >>> 5) & 0x1f;
      const rt = insn & 0x1f;

      const scale = isFp ? (((opc & 2) << 1) | size) : size;
      if (scale > 4) {
        this._illegal(insn, pc, 'Invalid FP load/store scale');
      }

      // Edge Case #23: base Rn=31 is ALWAYS SP!
      const base = this._readRegOrSp(rn, true);
      let addr;
      let writeback = false;
      let wbAddr = 0n;

      if ((bits25_24 & 1) === 1) {
        // Unsigned scaled immediate
        const imm12 = BigInt((insn >>> 10) & 0xfff);
        addr = (base + (imm12 << BigInt(scale))) & MASK64;
      } else {
        const bit21 = (insn >>> 21) & 1;
        const bits11_10 = (insn >>> 10) & 0x3;
        if (bit21 === 0) {
          const imm9 = signExtend32((insn >>> 12) & 0x1ff, 9);
          if (bits11_10 === 0x0) {
            // Unscaled (LDUR / STUR)
            addr = (base + imm9) & MASK64;
          } else if (bits11_10 === 0x1) {
            // Post-index
            addr = base;
            writeback = true;
            wbAddr = (base + imm9) & MASK64;
          } else if (bits11_10 === 0x3) {
            // Pre-index
            addr = (base + imm9) & MASK64;
            writeback = true;
            wbAddr = addr;
          } else {
            this._unsupported(insn, pc, 'LDTR/STTR unprivileged load/store');
          }
        } else if (bits11_10 === 0x2) {
          // Register offset
          const rm = (insn >>> 16) & 0x1f;
          const option = (insn >>> 13) & 0x7;
          const S = (insn >>> 12) & 1;
          const shift = S ? scale : 0;
          const offset = extendRegValue(this._readRegOrZr(rm, true), option, shift, true);
          addr = (base + offset) & MASK64;
        } else {
          this._unsupported(insn, pc, `load/store bit21=1 bits11_10=${bits11_10}`);
        }
      }

      if (!isFp) {
        if (opc === 0) {
          // Store: STRB, STRH, STR W, STR X
          const val = this._readRegOrZr(rt, true);
          if (scale === 0) this.addressSpace.writeU8(addr, Number(val & 0xffn));
          else if (scale === 1) this.addressSpace.writeU16(addr, Number(val & 0xffffn), true);
          else if (scale === 2) this.addressSpace.writeU32(addr, Number(val & MASK32), true);
          else this.addressSpace.writeU64(addr, val, true);
        } else if (opc === 1) {
          // Unsigned Load: LDRB, LDRH, LDR W, LDR X
          if (scale === 0) this._writeRegOrZr(rt, BigInt(this.addressSpace.readU8(addr)), false);
          else if (scale === 1) this._writeRegOrZr(rt, BigInt(this.addressSpace.readU16(addr, true)), false);
          else if (scale === 2) this._writeRegOrZr(rt, BigInt(this.addressSpace.readU32(addr, true)), false);
          else this._writeRegOrZr(rt, this.addressSpace.readU64(addr, true), true);
        } else if (opc === 2) {
          // Signed load to 64-bit (LDRSB X, LDRSH X, LDRSW X) or PRFM (scale===3)
          if (scale === 0) {
            const v = BigInt.asIntN(8, BigInt(this.addressSpace.readU8(addr)));
            this._writeRegOrZr(rt, v & MASK64, true);
          } else if (scale === 1) {
            const v = BigInt.asIntN(16, BigInt(this.addressSpace.readU16(addr, true)));
            this._writeRegOrZr(rt, v & MASK64, true);
          } else if (scale === 2) {
            const v = BigInt.asIntN(32, BigInt(this.addressSpace.readU32(addr, true)));
            this._writeRegOrZr(rt, v & MASK64, true);
          } else {
            // PRFM -> NOP
          }
        } else {
          // Signed load to 32-bit (LDRSB W, LDRSH W) -> zero-extended to 64-bit
          if (scale === 0) {
            const v = BigInt.asIntN(8, BigInt(this.addressSpace.readU8(addr)));
            this._writeRegOrZr(rt, v & MASK32, false);
          } else if (scale === 1) {
            const v = BigInt.asIntN(16, BigInt(this.addressSpace.readU16(addr, true)));
            this._writeRegOrZr(rt, v & MASK32, false);
          } else {
            this._illegal(insn, pc, `Invalid signed load scale=${scale} opc=3`);
          }
        }
      } else {
        const isLoad = (opc & 1) === 1;
        if (isLoad) {
          if (scale === 0) {
            this.v[rt].fill(0);
            this.v[rt][0] = this.addressSpace.readU8(addr);
          } else if (scale === 1) {
            this.v[rt].fill(0);
            this._vViews[rt].setUint16(0, this.addressSpace.readU16(addr, true), true);
          } else if (scale === 2) {
            this.setSRegBits(rt, this.addressSpace.readU32(addr, true));
          } else if (scale === 3) {
            this.setDRegBits(rt, this.addressSpace.readU64(addr, true));
          } else {
            this.setVReg(rt, this.addressSpace.read(addr, 16));
          }
        } else {
          if (scale === 0) this.addressSpace.writeU8(addr, this.v[rt][0]);
          else if (scale === 1) this.addressSpace.writeU16(addr, this._vViews[rt].getUint16(0, true), true);
          else if (scale === 2) this.addressSpace.writeU32(addr, this.getSRegBits(rt), true);
          else if (scale === 3) this.addressSpace.writeU64(addr, this.getDRegBits(rt), true);
          else this.addressSpace.write(addr, this.v[rt]);
        }
      }

      if (writeback) {
        this._writeRegOrSp(rn, wbAddr, true);
      }
      return null;
    }

    // 4. Load/Store Exclusive & Load-Acquire/Store-Release (LDXR/STXR/LDAXR/STLXR/LDAR/STLR)
    if (bits29_27 === 0x1 && !isFp && bits25_24 === 0x0) {
      const size = (insn >>> 30) & 0x3;
      const o2 = (insn >>> 23) & 1;
      const L = (insn >>> 22) & 1;
      const o1 = (insn >>> 21) & 1;
      const rs = (insn >>> 16) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const rt = insn & 0x1f;
      const addr = this._readRegOrSp(rn, true);

      if (o1 === 0) {
        if (L === 1) {
          if (size === 0) this._writeRegOrZr(rt, BigInt(this.addressSpace.readU8(addr)), false);
          else if (size === 1) this._writeRegOrZr(rt, BigInt(this.addressSpace.readU16(addr, true)), false);
          else if (size === 2) this._writeRegOrZr(rt, BigInt(this.addressSpace.readU32(addr, true)), false);
          else this._writeRegOrZr(rt, this.addressSpace.readU64(addr, true), true);
        } else {
          const val = this._readRegOrZr(rt, true);
          if (size === 0) this.addressSpace.writeU8(addr, Number(val & 0xffn));
          else if (size === 1) this.addressSpace.writeU16(addr, Number(val & 0xffffn), true);
          else if (size === 2) this.addressSpace.writeU32(addr, Number(val & MASK32), true);
          else this.addressSpace.writeU64(addr, val, true);
          if (o2 === 0) {
            // STXR/STLXR: status 0 = exclusive store succeeded
            this._writeRegOrZr(rs, 0n, false);
          }
        }
        return null;
      }
    }

    this._unsupported(insn, pc, `load/store bits29_27=${bits29_27}`);
  }

  // =========================================================================
  // Group 4: Data Processing — Register
  // =========================================================================

  _execDataProcReg(insn, pc) {
    const is64 = ((insn >>> 31) & 1) === 1;
    const op0 = (insn >>> 30) & 1;
    const op1 = (insn >>> 28) & 1;
    const op2 = (insn >>> 21) & 0xf;
    const rm = (insn >>> 16) & 0x1f;
    const rn = (insn >>> 5) & 0x1f;
    const rd = insn & 0x1f;
    const mask = is64 ? MASK64 : MASK32;

    if (op1 === 0) {
      // Logical (shifted register): bit 24 = 0
      if ((op2 & 0x8) === 0) {
        const opc = (insn >>> 29) & 0x3;
        const shiftType = (insn >>> 22) & 0x3;
        const N = (insn >>> 21) & 1;
        const imm6 = (insn >>> 10) & 0x3f;
        if (!is64 && imm6 >= 32) {
          this._illegal(insn, pc, 'Invalid 32-bit shifted logical imm6 >= 32');
        }
        const op1Val = this._readRegOrZr(rn, is64);
        let op2Val = shiftRegValue(this._readRegOrZr(rm, is64), shiftType, imm6, is64);
        if (N === 1) op2Val = ~op2Val & mask;

        let result;
        if (opc === 0 || opc === 3) result = op1Val & op2Val;
        else if (opc === 1) result = op1Val | op2Val;
        else result = op1Val ^ op2Val;
        result &= mask;

        if (opc === 3) {
          this.pstate.N = (result & (is64 ? SIGN64 : SIGN32)) !== 0n ? 1 : 0;
          this.pstate.Z = result === 0n ? 1 : 0;
          this.pstate.C = 0;
          this.pstate.V = 0;
        }
        this._writeRegOrZr(rd, result, is64);
        return null;
      }

      // Add/subtract (shifted register): bit 24 = 1, bit 21 = 0
      if ((op2 & 0x9) === 0x8) {
        const isSub = op0 === 1;
        const setFlags = ((insn >>> 29) & 1) === 1;
        const shiftType = (insn >>> 22) & 0x3;
        const imm6 = (insn >>> 10) & 0x3f;
        if (shiftType === 3 || (!is64 && imm6 >= 32)) {
          this._illegal(insn, pc, 'Invalid add/sub shifted register encoding');
        }
        // In Add/Sub (shifted reg), Rn, Rm, and Rd ALL decode 31 as XZR/WZR!
        const a = this._readRegOrZr(rn, is64);
        const shifted = shiftRegValue(this._readRegOrZr(rm, is64), shiftType, imm6, is64);
        const b = isSub ? ~shifted & mask : shifted;
        const res = addWithCarry(a, b, isSub ? 1 : 0, is64);

        if (setFlags) {
          this.pstate.N = res.N;
          this.pstate.Z = res.Z;
          this.pstate.C = res.C;
          this.pstate.V = res.V;
        }
        this._writeRegOrZr(rd, res.result, is64);
        return null;
      }

      // Add/subtract (extended register): bit 24 = 1, bit 21 = 1
      if ((op2 & 0x9) === 0x9) {
        const isSub = op0 === 1;
        const setFlags = ((insn >>> 29) & 1) === 1;
        const opt = (insn >>> 22) & 0x3;
        const option = (insn >>> 13) & 0x7;
        const imm3 = (insn >>> 10) & 0x7;
        if (opt !== 0 || imm3 > 4) {
          this._illegal(insn, pc, 'Invalid add/sub extended register encoding');
        }
        // Edge Case #23: Rn is SP; Rd is SP if S=0, XZR/WZR if S=1!
        const a = this._readRegOrSp(rn, is64);
        const ext = extendRegValue(this._readRegOrZr(rm, true), option, imm3, is64);
        const b = isSub ? ~ext & mask : ext;
        const res = addWithCarry(a, b, isSub ? 1 : 0, is64);

        if (setFlags) {
          this.pstate.N = res.N;
          this.pstate.Z = res.Z;
          this.pstate.C = res.C;
          this.pstate.V = res.V;
          this._writeRegOrZr(rd, res.result, is64);
        } else {
          this._writeRegOrSp(rd, res.result, is64);
        }
        return null;
      }
    } else {
      // op1 === 1
      // Add/subtract (with carry): op2 === 0x0
      if (op2 === 0x0 && ((insn >>> 10) & 0x3f) === 0) {
        const isSub = op0 === 1;
        const setFlags = ((insn >>> 29) & 1) === 1;
        const a = this._readRegOrZr(rn, is64);
        const rawB = this._readRegOrZr(rm, is64);
        const b = isSub ? ~rawB & mask : rawB;
        const res = addWithCarry(a, b, this.pstate.C, is64);
        if (setFlags) {
          this.pstate.N = res.N;
          this.pstate.Z = res.Z;
          this.pstate.C = res.C;
          this.pstate.V = res.V;
        }
        this._writeRegOrZr(rd, res.result, is64);
        return null;
      }

      // Conditional compare (register & immediate): op2 === 0x2
      if (op2 === 0x2) {
        const setFlags = ((insn >>> 29) & 1) === 1;
        if (!setFlags || ((insn >>> 10) & 1) !== 0 || ((insn >>> 4) & 1) !== 0) {
          this._illegal(insn, pc, 'Invalid conditional compare');
        }
        const isSub = op0 === 1; // CCMP=1, CCMN=0
        const isImm = ((insn >>> 11) & 1) === 1;
        const cond = (insn >>> 12) & 0xf;
        const nzcv = insn & 0xf;
        if (this.evalCondition(cond)) {
          const a = this._readRegOrZr(rn, is64);
          const rawB = isImm ? BigInt(rm) : this._readRegOrZr(rm, is64);
          const b = isSub ? ~rawB & mask : rawB;
          const res = addWithCarry(a, b, isSub ? 1 : 0, is64);
          this.pstate.N = res.N;
          this.pstate.Z = res.Z;
          this.pstate.C = res.C;
          this.pstate.V = res.V;
        } else {
          this.pstate.N = (nzcv >>> 3) & 1;
          this.pstate.Z = (nzcv >>> 2) & 1;
          this.pstate.C = (nzcv >>> 1) & 1;
          this.pstate.V = nzcv & 1;
        }
        return null;
      }

      // Conditional select (CSEL, CSINC, CSINV, CSNEG): op2 === 0x4
      if (op2 === 0x4) {
        const setFlags = ((insn >>> 29) & 1) === 1;
        const cond = (insn >>> 12) & 0xf;
        const op2Sel = (insn >>> 10) & 0x3;
        if (setFlags || op2Sel > 1) {
          this._illegal(insn, pc, 'Invalid conditional select');
        }
        let result;
        if (this.evalCondition(cond)) {
          result = this._readRegOrZr(rn, is64);
        } else {
          result = this._readRegOrZr(rm, is64);
          if (op0 === 1) result = ~result & mask;
          if (op2Sel === 1) result = (result + 1n) & mask;
        }
        this._writeRegOrZr(rd, result, is64);
        return null;
      }

      // Data-processing (2 source) & (1 source): op2 === 0x6
      if (op2 === 0x6) {
        const setFlags = ((insn >>> 29) & 1) === 1;
        const opcode = (insn >>> 10) & 0x3f;
        if (setFlags) {
          this._illegal(insn, pc, 'Invalid S=1 in data-proc 1/2 source');
        }

        if (op0 === 0) {
          // Data-processing (2 source): UDIV, SDIV, LSLV, LSRV, ASRV, RORV
          const a = this._readRegOrZr(rn, is64);
          const b = this._readRegOrZr(rm, is64);
          let result;
          switch (opcode) {
            case 0x02: // UDIV (ARM64 spec: div-by-0 returns 0)
              result = b === 0n ? 0n : a / b;
              break;
            case 0x03: { // SDIV (ARM64 spec: div-by-0 -> 0; INT_MIN / -1 -> INT_MIN)
              const sa = is64 ? toS64(a) : toS32(a);
              const sb = is64 ? toS64(b) : toS32(b);
              const minVal = is64 ? INT64_MIN : INT32_MIN;
              if (sb === 0n) {
                result = 0n;
              } else if (sa === minVal && sb === -1n) {
                result = minVal & mask;
              } else {
                result = (sa / sb) & mask;
              }
              break;
            }
            case 0x08: // LSLV
              result = shiftRegValue(a, 0, Number(b & 0x3fn), is64);
              break;
            case 0x09: // LSRV
              result = shiftRegValue(a, 1, Number(b & 0x3fn), is64);
              break;
            case 0x0a: // ASRV
              result = shiftRegValue(a, 2, Number(b & 0x3fn), is64);
              break;
            case 0x0b: // RORV
              result = shiftRegValue(a, 3, Number(b & 0x3fn), is64);
              break;
            default:
              this._unsupported(insn, pc, `data-proc 2-src opcode=0x${opcode.toString(16)}`);
          }
          this._writeRegOrZr(rd, result, is64);
          return null;
        }

        // op0 === 1: Data-processing (1 source): RBIT, REV16, REV32, REV, CLZ, CLS
        if (rm === 0) {
          const src = this._readRegOrZr(rn, is64);
          const width = is64 ? 64 : 32;
          let result;
          switch (opcode) {
            case 0x00: // RBIT
              result = reverseBits(src, width);
              break;
            case 0x01: { // REV16
              let out = 0n;
              for (let i = 0; i < width; i += 16) {
                const lo = (src >> BigInt(i)) & 0xffn;
                const hi = (src >> BigInt(i + 8)) & 0xffn;
                out |= (lo << BigInt(i + 8)) | (hi << BigInt(i));
              }
              result = out;
              break;
            }
            case 0x02: { // REV32 (64-bit) or REV (32-bit)
              let out = 0n;
              for (let i = 0; i < width; i += 32) {
                const b0 = (src >> BigInt(i)) & 0xffn;
                const b1 = (src >> BigInt(i + 8)) & 0xffn;
                const b2 = (src >> BigInt(i + 16)) & 0xffn;
                const b3 = (src >> BigInt(i + 24)) & 0xffn;
                out |= (b0 << BigInt(i + 24)) | (b1 << BigInt(i + 16)) | (b2 << BigInt(i + 8)) | (b3 << BigInt(i));
              }
              result = out;
              break;
            }
            case 0x03: { // REV (64-bit)
              if (!is64) this._illegal(insn, pc, 'REV64 with sf=0');
              let out = 0n;
              for (let i = 0; i < 8; i++) {
                out |= ((src >> BigInt(i * 8)) & 0xffn) << BigInt((7 - i) * 8);
              }
              result = out;
              break;
            }
            case 0x04: // CLZ
              result = countLeadingZeros(src, width);
              break;
            case 0x05: // CLS
              result = countLeadingSignBits(src, width);
              break;
            default:
              this._unsupported(insn, pc, `data-proc 1-src opcode=0x${opcode.toString(16)}`);
          }
          this._writeRegOrZr(rd, result, is64);
          return null;
        }
      }

      // Data-processing (3 source): MADD/MUL, MSUB/MNEG, SMADDL/SMULL, SMSUBL, SMULH, UMADDL/UMULL, UMSUBL, UMULH
      if ((op2 & 0x8) === 0x8) {
        const op54 = (insn >>> 29) & 0x3;
        const op31 = op2 & 0x7;
        const o0 = (insn >>> 15) & 1;
        const ra = (insn >>> 10) & 0x1f;
        if (op54 !== 0) {
          this._illegal(insn, pc, 'Invalid 3-src op54');
        }

        if (op31 === 0) {
          // MADD (o0=0, MUL when Ra=31) / MSUB (o0=1, MNEG when Ra=31)
          const a = this._readRegOrZr(ra, is64);
          const n = this._readRegOrZr(rn, is64);
          const m = this._readRegOrZr(rm, is64);
          const prod = (n * m) & mask;
          const result = o0 === 0 ? (a + prod) & mask : (a - prod) & mask;
          this._writeRegOrZr(rd, result, is64);
          return null;
        }

        if (is64 && op31 === 1) {
          // SMADDL (SMULL when Ra=31) / SMSUBL
          const a = this._readRegOrZr(ra, true);
          const n = toS32(this._readRegOrZr(rn, false));
          const m = toS32(this._readRegOrZr(rm, false));
          const prod = n * m;
          const result = o0 === 0 ? (a + prod) & MASK64 : (a - prod) & MASK64;
          this._writeRegOrZr(rd, result, true);
          return null;
        }

        if (is64 && op31 === 2 && o0 === 0) {
          // SMULH
          const n = toS64(this._readRegOrZr(rn, true));
          const m = toS64(this._readRegOrZr(rm, true));
          const result = ((n * m) >> 64n) & MASK64;
          this._writeRegOrZr(rd, result, true);
          return null;
        }

        if (is64 && op31 === 5) {
          // UMADDL (UMULL when Ra=31) / UMSUBL
          const a = this._readRegOrZr(ra, true);
          const n = this._readRegOrZr(rn, false);
          const m = this._readRegOrZr(rm, false);
          const prod = n * m;
          const result = o0 === 0 ? (a + prod) & MASK64 : (a - prod) & MASK64;
          this._writeRegOrZr(rd, result, true);
          return null;
        }

        if (is64 && op31 === 6 && o0 === 0) {
          // UMULH
          const n = this._readRegOrZr(rn, true);
          const m = this._readRegOrZr(rm, true);
          const result = ((n * m) >> 64n) & MASK64;
          this._writeRegOrZr(rd, result, true);
          return null;
        }
      }
    }

    this._unsupported(insn, pc, `data-proc-reg op1=${op1} op2=${op2}`);
  }

  // =========================================================================
  // Group 5: Scalar Floating-Point & Basic SIMD
  // =========================================================================

  _execFpSimd(insn, pc) {
    const sf = (insn >>> 31) & 1;
    const bit30 = (insn >>> 30) & 1;
    const bit29 = (insn >>> 29) & 1;
    const bit28 = (insn >>> 28) & 1;
    const bit24 = (insn >>> 24) & 1;
    const ftype = (insn >>> 22) & 0x3;
    const bit21 = (insn >>> 21) & 1;
    const rn = (insn >>> 5) & 0x1f;
    const rd = insn & 0x1f;

    // Scalar Floating-Point group: bit30=0, bit29=0, bit28=1
    if (bit30 === 0 && bit29 === 0 && bit28 === 1) {
      if (ftype !== 0 && ftype !== 1) {
        this._unsupported(insn, pc, `FP ftype=${ftype}`);
      }
      const isDouble = ftype === 1;
      const readFp = (reg) => (isDouble ? this.getDReg(reg) : this.getSReg(reg));
      const writeFp = (reg, val) => (isDouble ? this.setDReg(reg, val) : this.setSReg(reg, val));

      // Floating-point data-processing (3 source): bit24=1 (FMADD, FMSUB, FNMADD, FNMSUB)
      if (bit24 === 1 && sf === 0) {
        const o1 = bit21;
        const rm = (insn >>> 16) & 0x1f;
        const o0 = (insn >>> 15) & 1;
        const ra = (insn >>> 10) & 0x1f;
        const a = readFp(ra);
        const n = readFp(rn);
        const m = readFp(rm);
        let result;
        if (o1 === 0 && o0 === 0) result = a + n * m; // FMADD
        else if (o1 === 0 && o0 === 1) result = a - n * m; // FMSUB
        else if (o1 === 1 && o0 === 0) result = -a - n * m; // FNMADD
        else result = -a + n * m; // FNMSUB
        writeFp(rd, result);
        return null;
      }

      if (bit24 === 0 && bit21 === 1) {
        const bits15_10 = (insn >>> 10) & 0x3f;

        // Conversion between FP and integer (FMOV GPR<->FP, SCVTF, UCVTF, FCVTZS, FCVTZU)
        if (bits15_10 === 0x00) {
          const is64Int = sf === 1;
          const rmode = (insn >>> 19) & 0x3;
          const opcode = (insn >>> 16) & 0x7;

          if (rmode === 0 && opcode === 2) {
            // SCVTF
            const raw = this._readRegOrZr(rn, is64Int);
            const signed = is64Int ? toS64(raw) : toS32(raw);
            writeFp(rd, Number(signed));
            return null;
          }
          if (rmode === 0 && opcode === 3) {
            // UCVTF
            const raw = this._readRegOrZr(rn, is64Int);
            writeFp(rd, Number(raw));
            return null;
          }
          if (rmode === 3 && opcode === 0) {
            // FCVTZS
            const val = readFp(rn);
            const res = floatToSignedInt(val, is64Int);
            this._writeRegOrZr(rd, res & (is64Int ? MASK64 : MASK32), is64Int);
            return null;
          }
          if (rmode === 3 && opcode === 1) {
            // FCVTZU
            const val = readFp(rn);
            const res = floatToUnsignedInt(val, is64Int);
            this._writeRegOrZr(rd, res & (is64Int ? MASK64 : MASK32), is64Int);
            return null;
          }
          if (rmode === 0 && opcode === 6) {
            // FMOV (FP -> GPR)
            if (!isDouble && !is64Int) {
              this._writeRegOrZr(rd, BigInt(this.getSRegBits(rn)), false);
              return null;
            }
            if (isDouble && is64Int) {
              this._writeRegOrZr(rd, this.getDRegBits(rn), true);
              return null;
            }
          }
          if (rmode === 0 && opcode === 7) {
            // FMOV (GPR -> FP)
            if (!isDouble && !is64Int) {
              this.setSRegBits(rd, Number(this._readRegOrZr(rn, false)));
              return null;
            }
            if (isDouble && is64Int) {
              this.setDRegBits(rd, this._readRegOrZr(rn, true));
              return null;
            }
          }
          this._unsupported(insn, pc, `FP conv rmode=${rmode} opcode=${opcode}`);
        }

        if (sf === 0) {
          const bits11_10 = bits15_10 & 0x3;

          // FP Data-processing (1 source): bits 14..10 = 10000
          if ((bits15_10 & 0x1f) === 0x10) {
            const opcode = (insn >>> 15) & 0x3f;
            if (opcode === 0x00) {
              // FMOV (register)
              if (isDouble) this.setDRegBits(rd, this.getDRegBits(rn));
              else this.setSRegBits(rd, this.getSRegBits(rn));
              return null;
            }
            if (opcode === 0x01) {
              // FABS
              writeFp(rd, Math.abs(readFp(rn)));
              return null;
            }
            if (opcode === 0x02) {
              // FNEG
              writeFp(rd, -readFp(rn));
              return null;
            }
            if (opcode === 0x03) {
              // FSQRT
              writeFp(rd, Math.sqrt(readFp(rn)));
              return null;
            }
            if (opcode === 0x04 && isDouble) {
              // FCVT Sd, Dn (double -> single)
              this.setSReg(rd, this.getDReg(rn));
              return null;
            }
            if (opcode === 0x05 && !isDouble) {
              // FCVT Dd, Sn (single -> double)
              this.setDReg(rd, this.getSReg(rn));
              return null;
            }
            if (opcode === 0x08) {
              // FRINTN (IEEE-754 round to nearest, ties to even)
              writeFp(rd, roundToNearestEven(readFp(rn)));
              return null;
            }
            if (opcode === 0x09) {
              // FRINTP (ceil)
              writeFp(rd, Math.ceil(readFp(rn)));
              return null;
            }
            if (opcode === 0x0a) {
              // FRINTM (floor)
              writeFp(rd, Math.floor(readFp(rn)));
              return null;
            }
            if (opcode === 0x0b) {
              // FRINTZ (trunc)
              writeFp(rd, Math.trunc(readFp(rn)));
              return null;
            }
          }

          // FP Compare (FCMP / FCMPE): bits 13..10 = 1000
          if ((bits15_10 & 0x0f) === 0x08) {
            const rm = (insn >>> 16) & 0x1f;
            const opc2 = insn & 0x1f;
            const a = readFp(rn);
            const b = (opc2 & 0x8) !== 0 ? 0.0 : readFp(rm);
            if (Number.isNaN(a) || Number.isNaN(b)) {
              this.pstate.N = 0;
              this.pstate.Z = 0;
              this.pstate.C = 1;
              this.pstate.V = 1;
            } else if (a === b) {
              this.pstate.N = 0;
              this.pstate.Z = 1;
              this.pstate.C = 1;
              this.pstate.V = 0;
            } else if (a < b) {
              this.pstate.N = 1;
              this.pstate.Z = 0;
              this.pstate.C = 0;
              this.pstate.V = 0;
            } else {
              this.pstate.N = 0;
              this.pstate.Z = 0;
              this.pstate.C = 1;
              this.pstate.V = 0;
            }
            return null;
          }

          // FP Immediate (FMOV Sd/Dd, #imm8): bits 12..10 = 100, rn = 0
          if ((bits15_10 & 0x07) === 0x04 && rn === 0) {
            const imm8 = (insn >>> 13) & 0xff;
            if (isDouble) this.setDReg(rd, vfpExpandImm64(imm8));
            else this.setSReg(rd, vfpExpandImm32(imm8));
            return null;
          }

          // FP Data-processing (2 source): bits 11..10 = 10
          if (bits11_10 === 0x2) {
            const rm = (insn >>> 16) & 0x1f;
            const opcode = (insn >>> 12) & 0xf;
            const a = readFp(rn);
            const b = readFp(rm);
            let result;
            switch (opcode) {
              case 0x0: result = a * b; break; // FMUL
              case 0x1: result = a / b; break; // FDIV
              case 0x2: result = a + b; break; // FADD
              case 0x3: result = a - b; break; // FSUB
              case 0x4: result = Number.isNaN(a) || Number.isNaN(b) ? NaN : Math.max(a, b); break; // FMAX
              case 0x5: result = Number.isNaN(a) || Number.isNaN(b) ? NaN : Math.min(a, b); break; // FMIN
              case 0x6: result = Number.isNaN(a) ? b : (Number.isNaN(b) ? a : Math.max(a, b)); break; // FMAXNM
              case 0x7: result = Number.isNaN(a) ? b : (Number.isNaN(b) ? a : Math.min(a, b)); break; // FMINNM
              case 0x8: result = -(a * b); break; // FNMUL
              default:
                this._unsupported(insn, pc, `FP 2-src opcode=${opcode}`);
            }
            writeFp(rd, result);
            return null;
          }

          // FP Conditional Select (FCSEL): bits 11..10 = 11
          if (bits11_10 === 0x3) {
            const rm = (insn >>> 16) & 0x1f;
            const cond = (insn >>> 12) & 0xf;
            const chosen = this.evalCondition(cond) ? rn : rm;
            if (isDouble) this.setDRegBits(rd, this.getDRegBits(chosen));
            else this.setSRegBits(rd, this.getSRegBits(chosen));
            return null;
          }
        }
      }
    }

    // Basic SIMD vector register move / ORR (ORR Vd.16B, Vn.16B, Vm.16B -> MOV Vd.16B, Vn.16B)
    if ((insn & 0xbfe0fc00) === 0x0ea01c00) {
      const Q = (insn >>> 30) & 1;
      const rm = (insn >>> 16) & 0x1f;
      const bytes = Q ? 16 : 8;
      // Compute active lanes FIRST so rd === rn or rd === rm never wipes source lanes
      for (let i = 0; i < bytes; i++) {
        this.v[rd][i] = this.v[rn][i] | this.v[rm][i];
      }
      for (let i = bytes; i < 16; i++) {
        this.v[rd][i] = 0;
      }
      return null;
    }

    // Basic SIMD EOR Vd, Vn, Vm (used by compilers to zero V registers: EOR V0.16B, V0.16B, V0.16B)
    if ((insn & 0xbfe0fc00) === 0x2e201c00) {
      const Q = (insn >>> 30) & 1;
      const rm = (insn >>> 16) & 0x1f;
      const bytes = Q ? 16 : 8;
      for (let i = 0; i < bytes; i++) {
        this.v[rd][i] = this.v[rn][i] ^ this.v[rm][i];
      }
      for (let i = bytes; i < 16; i++) {
        this.v[rd][i] = 0;
      }
      return null;
    }

    // Basic SIMD MOVI Vd.8B/16B, #imm8 (op=0, cmode=1110 -> 0x0F00E400 / 0x4F00E400)
    if ((insn & 0xbff8fc00) === 0x0f00e400) {
      const Q = (insn >>> 30) & 1;
      const a = (insn >>> 16) & 0x7;
      const b = (insn >>> 5) & 0x1f;
      const imm8 = (a << 5) | b;
      const bytes = Q ? 16 : 8;
      for (let i = 0; i < bytes; i++) {
        this.v[rd][i] = imm8;
      }
      for (let i = bytes; i < 16; i++) {
        this.v[rd][i] = 0;
      }
      return null;
    }

    // Basic SIMD MOVI Dd/Vd.2D, #imm (op=1, cmode=1110 -> 0x2F00E400 / 0x6F00E400; expands each bit to 0xFF/0x00)
    if ((insn & 0xbff8fc00) === 0x2f00e400) {
      const Q = (insn >>> 30) & 1;
      const a = (insn >>> 16) & 0x7;
      const b = (insn >>> 5) & 0x1f;
      const imm8 = (a << 5) | b;
      for (let k = 0; k < 8; k++) {
        const byteVal = ((imm8 >>> k) & 1) !== 0 ? 0xff : 0x00;
        this.v[rd][k] = byteVal;
        this.v[rd][8 + k] = Q ? byteVal : 0x00;
      }
      return null;
    }

    this._unsupported(insn, pc, `fp/simd`);
  }

  getDebugState() {
    const registers = {};
    for (let i = 0; i < 31; i++) {
      registers[`x${i}`] = `0x${this.x[i].toString(16)}`;
    }
    registers.sp = `0x${this.sp.toString(16)}`;
    registers.pc = `0x${this.pc.toString(16)}`;
    registers.pstate = { ...this.pstate };

    const stackTop = [];
    if (this.addressSpace && this.sp > 0n) {
      for (let i = 0; i < 4; i++) {
        try {
          const val = this.addressSpace.readU64(this.sp + BigInt(i * 8), true);
          stackTop.push(`0x${val.toString(16)}`);
        } catch {
          break;
        }
      }
    }

    return {
      arch: 'arm64',
      pc: `0x${this.pc.toString(16)}`,
      sp: `0x${this.sp.toString(16)}`,
      registers,
      pstate: { ...this.pstate },
      instructionsExecuted: this.instructionsExecuted,
      halted: this.halted,
      exitCode: this.exitCode,
      lastSyscall: this.lastSyscall,
      stackTop,
    };
  }

  dispose() {
    this._disposed = true;
    this.halted = true;
    this.onSyscall = null;
    this.onThunk = null;
    this.onBreak = null;
    this.addressSpace = null;
  }
}

export function createArm64Cpu(opts = {}) {
  return new ARM64Cpu(opts);
}

export function registerArm64Cpu(cpuRegistry) {
  if (!cpuRegistry || typeof cpuRegistry.register !== 'function') {
    throw new TypeError('registerArm64Cpu requires a CpuRegistry instance');
  }
  cpuRegistry.register('arm64', createArm64Cpu);
  return cpuRegistry;
}
