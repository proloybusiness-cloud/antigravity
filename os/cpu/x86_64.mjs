/**
 * OmniOS Real x86 (32-bit) & x86-64 (64-bit) CPU Emulator (`os/cpu/x86_64.mjs`)
 * - OS-agnostic engine executing directly against M1 `AddressSpace` (R/W/X hardware page checks)
 * - Pluggable `onThunk`, `onSyscall`, `onInt` hooks (reusable by Windows Win64/Win32 AND macOS SysV x86-64)
 * - Strict x86-64 architectural semantics:
 *   - Edge Case #16: 32-bit GPR writes zero upper 32 bits; 16-bit & 8-bit (`AL`/`AH`) preserve upper bits
 *   - Edge Case #17: RIP-relative `[RIP + disp32]` resolved strictly using next-instruction RIP (after all immediates)
 *   - Safe per-byte instruction fetching (max 15-byte x86 length; never speculatively crosses page boundaries)
 *   - Budget-yielded `REP`/`REPE`/`REPNE` string ops so giant `RCX` trips scheduler CPU quotas cleanly
 *   - Re-entrant `callFunction()` with register preservation and stack-overflow depth guard for Win32 `WNDPROC`
 */

import {
  OmniOSError,
  IllegalInstructionError,
  UnsupportedOpcodeError,
  QuotaExceededError,
  ERROR_CODES,
  WIN32_ERROR,
} from '../common/errors.mjs';

export const RFLAGS = Object.freeze({
  CF: 1 << 0,
  PF: 1 << 2,
  AF: 1 << 4,
  ZF: 1 << 6,
  SF: 1 << 7,
  TF: 1 << 8,
  IF: 1 << 9,
  DF: 1 << 10,
  OF: 1 << 11,
});

export const REG64_NAMES = Object.freeze([
  'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
  'r8',  'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
]);

export const REG32_NAMES = Object.freeze([
  'eax',  'ecx',  'edx',  'ebx',  'esp',  'ebp',  'esi',  'edi',
  'r8d',  'r9d',  'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
]);

const REG_NAME_TO_INDEX = Object.create(null);
for (let i = 0; i < 16; i++) {
  REG_NAME_TO_INDEX[REG64_NAMES[i]] = i;
  REG_NAME_TO_INDEX[REG32_NAMES[i]] = i;
}

const MASK_64 = 0xffffffffffffffffn;
const MASK_32 = 0xffffffffn;
const MASK_16 = 0xffffn;
const MASK_8 = 0xffn;
const MAX_INSN_BYTES = 15;
const DEFAULT_MAX_CALL_DEPTH = 32;
const DEFAULT_MAX_CALLBACK_TREE_CALLS = 512;

// Precomputed 256-entry even-parity lookup table for low byte (PF = 1 if even number of 1-bits)
const PARITY_TABLE = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  let bits = 0;
  let v = i;
  while (v !== 0) {
    bits += v & 1;
    v >>>= 1;
  }
  PARITY_TABLE[i] = (bits & 1) === 0 ? 1 : 0;
}

function sizeMask(size) {
  if (size === 8) return MASK_64;
  if (size === 4) return MASK_32;
  if (size === 2) return MASK_16;
  return MASK_8;
}

function sizeBits(size) {
  return size * 8;
}

function signBit(size) {
  if (size === 8) return 0x8000000000000000n;
  if (size === 4) return 0x80000000n;
  if (size === 2) return 0x8000n;
  return 0x80n;
}

function toSigned(val, size) {
  return BigInt.asIntN(sizeBits(size), val);
}

function toUnsigned(val, size) {
  return BigInt.asUintN(sizeBits(size), val);
}

function toBigIntVal(val) {
  if (typeof val === 'bigint') return BigInt.asUintN(64, val);
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) return 0n;
    return BigInt.asUintN(64, BigInt(Math.trunc(val)));
  }
  return 0n;
}

export class X86_64Cpu {
  constructor({
    addressSpace,
    mode = 'x86_64',
    onThunk = null,
    onSyscall = null,
    onInt = null,
    thunkRange = null,
    entryReturnSentinel = null,
    maxCallDepth = DEFAULT_MAX_CALL_DEPTH,
    getNestedInstructionCap = null,
    pid = null,
  } = {}) {
    if (!addressSpace || typeof addressSpace.read !== 'function' || typeof addressSpace.fetch !== 'function') {
      throw new OmniOSError('X86_64Cpu requires a valid M1 AddressSpace', {
        code: ERROR_CODES.EINVAL,
      });
    }

    const normMode = String(mode || 'x86_64').toLowerCase();
    this.mode = normMode === 'x86' || normMode === 'i386' || normMode === 'ia32' ? 'x86' : 'x86_64';
    this.is64 = this.mode === 'x86_64';
    this.ptrSize = this.is64 ? 8 : 4;
    this.addressSpace = addressSpace;
    this.pid = pid ?? addressSpace.pid ?? null;

    this.regs = new BigUint64Array(16);
    this.rip = 0n;
    this.rflags = BigInt(0x202); // Bit 1 reserved=1, IF=1
    this.fsBase = 0n;
    this.gsBase = 0n;

    this.xmm = Array.from({ length: 16 }, () => new Uint8Array(16));
    this._xmmViews = this.xmm.map((buf) => new DataView(buf.buffer, buf.byteOffset, 16));

    this.onThunk = typeof onThunk === 'function' ? onThunk : null;
    this.onSyscall = typeof onSyscall === 'function' ? onSyscall : null;
    this.onInt = typeof onInt === 'function' ? onInt : null;
    this.getNestedInstructionCap =
      typeof getNestedInstructionCap === 'function' ? getNestedInstructionCap : null;

    if (thunkRange && thunkRange.start !== undefined && thunkRange.end !== undefined) {
      this.thunkStart = toBigIntVal(thunkRange.start);
      this.thunkEnd = toBigIntVal(thunkRange.end);
    } else if (this.is64) {
      this.thunkStart = 0x7fff00000000n;
      this.thunkEnd = 0x7fff00ffffffn;
    } else {
      this.thunkStart = 0x7f000000n;
      this.thunkEnd = 0x7f0fffffn;
    }

    this.entryReturnSentinel =
      entryReturnSentinel !== null && entryReturnSentinel !== undefined
        ? toBigIntVal(entryReturnSentinel)
        : (this.is64 ? 0x7fffffff0000n : 0x7ffff000n);

    this._callReturnSentinels = new Set();
    this._callDepth = 0;
    this.maxCallDepth = maxCallDepth;
    this.maxCallbackTreeCalls = DEFAULT_MAX_CALLBACK_TREE_CALLS;
    this._nestedBudget = null;
    this._topStepState = null;
    this._callbackFrames = [];
    this._callbackReturnSentinels = new Set();
    this._callbackTree = null;

    this.totalInstructions = 0;
    this.lastSyscall = null;
    this.exited = false;
    this.exitCode = 0;
    this.faulted = false;
    this.lastFault = null;
    this._tscCounter = 1000000n;

    // Reusable scratch buffer for small writes
    this._scratch = new Uint8Array(16);
    this._scratchView = new DataView(this._scratch.buffer);
  }

  // ============================================================================
  // Register & Flag Accessors (Strict Edge Case #16 Width Rules!)
  // ============================================================================

  _resolveRegIndex(nameOrIdx) {
    if (typeof nameOrIdx === 'number') {
      if (!Number.isInteger(nameOrIdx) || nameOrIdx < 0 || nameOrIdx > 15) {
        throw new OmniOSError(`Invalid register index: ${nameOrIdx}`, { code: ERROR_CODES.EINVAL });
      }
      return nameOrIdx;
    }
    if (typeof nameOrIdx === 'string') {
      const idx = REG_NAME_TO_INDEX[nameOrIdx.toLowerCase()];
      if (idx !== undefined) return idx;
    }
    throw new OmniOSError(`Unknown register: ${nameOrIdx}`, { code: ERROR_CODES.EINVAL });
  }

  getReg64(nameOrIdx) {
    const idx = this._resolveRegIndex(nameOrIdx);
    return this.is64 ? this.regs[idx] : (this.regs[idx] & MASK_32);
  }

  setReg64(nameOrIdx, value) {
    const idx = this._resolveRegIndex(nameOrIdx);
    const v = toBigIntVal(value);
    this.regs[idx] = this.is64 ? v : (v & MASK_32);
  }

  getReg32(nameOrIdx) {
    const idx = this._resolveRegIndex(nameOrIdx);
    return Number(this.regs[idx] & MASK_32);
  }

  setReg32(nameOrIdx, value) {
    const idx = this._resolveRegIndex(nameOrIdx);
    // Edge Case #16: 32-bit GPR write zeroes upper 32 bits!
    this.regs[idx] = toBigIntVal(value) & MASK_32;
  }

  getReg(idx, size, hasRex = false) {
    if (size === 8) {
      return this.is64 ? this.regs[idx] : (this.regs[idx] & MASK_32);
    }
    if (size === 4) {
      return this.regs[idx] & MASK_32;
    }
    if (size === 2) {
      return this.regs[idx] & MASK_16;
    }
    // size === 1
    if (!hasRex && idx >= 4 && idx <= 7) {
      // AH, CH, DH, BH
      return (this.regs[idx - 4] >> 8n) & MASK_8;
    }
    return this.regs[idx] & MASK_8;
  }

  setReg(idx, size, value, hasRex = false) {
    const v = toBigIntVal(value);
    if (size === 8) {
      this.regs[idx] = this.is64 ? v : (v & MASK_32);
      return;
    }
    if (size === 4) {
      // Edge Case #16: 32-bit write ZEROES upper 32 bits!
      this.regs[idx] = v & MASK_32;
      return;
    }
    if (size === 2) {
      // Edge Case #16: 16-bit write PRESERVES upper 48 bits!
      this.regs[idx] = (this.regs[idx] & ~MASK_16) | (v & MASK_16);
      return;
    }
    // size === 1: 8-bit write PRESERVES upper/other bits!
    if (!hasRex && idx >= 4 && idx <= 7) {
      const target = idx - 4;
      this.regs[target] = (this.regs[target] & ~0xff00n) | ((v & MASK_8) << 8n);
      return;
    }
    this.regs[idx] = (this.regs[idx] & ~MASK_8) | (v & MASK_8);
  }

  getXmmF32(idx) {
    return this._xmmViews[idx & 15].getFloat32(0, true);
  }

  setXmmF32(idx, val, zeroUpper = false) {
    const i = idx & 15;
    if (zeroUpper) this.xmm[i].fill(0);
    this._xmmViews[i].setFloat32(0, val, true);
  }

  getXmmF64(idx) {
    return this._xmmViews[idx & 15].getFloat64(0, true);
  }

  setXmmF64(idx, val, zeroUpper = false) {
    const i = idx & 15;
    if (zeroUpper) this.xmm[i].fill(0);
    this._xmmViews[i].setFloat64(0, val, true);
  }

  getXmmU64(idx, lane = 0) {
    return this._xmmViews[idx & 15].getBigUint64(lane ? 8 : 0, true);
  }

  setXmmU64(idx, lane, val) {
    this._xmmViews[idx & 15].setBigUint64(lane ? 8 : 0, toBigIntVal(val), true);
  }

  getFlag(mask) {
    return (Number(this.rflags) & mask) !== 0;
  }

  setFlag(mask, on) {
    const m = BigInt(mask);
    if (on) {
      this.rflags |= m;
    } else {
      this.rflags &= ~m;
    }
  }

  _setSZP(val, size) {
    const masked = val & sizeMask(size);
    this.setFlag(RFLAGS.ZF, masked === 0n);
    this.setFlag(RFLAGS.SF, (masked & signBit(size)) !== 0n);
    this.setFlag(RFLAGS.PF, PARITY_TABLE[Number(masked & 0xffn)] === 1);
  }

  _evalCond(cc) {
    const cf = this.getFlag(RFLAGS.CF);
    const zf = this.getFlag(RFLAGS.ZF);
    const sf = this.getFlag(RFLAGS.SF);
    const of = this.getFlag(RFLAGS.OF);
    const pf = this.getFlag(RFLAGS.PF);
    switch (cc & 0x0f) {
      case 0x0: return of;                   // O
      case 0x1: return !of;                  // NO
      case 0x2: return cf;                   // B / C / NAE
      case 0x3: return !cf;                  // AE / NB / NC
      case 0x4: return zf;                   // E / Z
      case 0x5: return !zf;                  // NE / NZ
      case 0x6: return cf || zf;             // BE / NA
      case 0x7: return !cf && !zf;           // A / NBE
      case 0x8: return sf;                   // S
      case 0x9: return !sf;                  // NS
      case 0xa: return pf;                   // P / PE
      case 0xb: return !pf;                  // NP / PO
      case 0xc: return sf !== of;            // L / NGE
      case 0xd: return sf === of;            // GE / NL
      case 0xe: return zf || (sf !== of);    // LE / NG
      case 0xf: return !zf && (sf === of);   // G / NLE
      default: return false;
    }
  }

  // ============================================================================
  // Memory & Safe Per-Byte Instruction Fetching (via M1 AddressSpace)
  // ============================================================================

  _maskAddr(addr) {
    return this.is64 ? BigInt.asUintN(64, addr) : (BigInt.asUintN(64, addr) & MASK_32);
  }

  isThunkAddress(va) {
    const a = this._maskAddr(va);
    return a >= this.thunkStart && a <= this.thunkEnd;
  }

  readMem(va, size) {
    const addr = this._maskAddr(va);
    const bytes = this.addressSpace.read(addr, size);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (size === 1) return BigInt(bytes[0]);
    if (size === 2) return BigInt(dv.getUint16(0, true));
    if (size === 4) return BigInt(dv.getUint32(0, true));
    if (size === 8) return dv.getBigUint64(0, true);
    throw new OmniOSError(`Invalid readMem size: ${size}`, { code: ERROR_CODES.EINVAL });
  }

  readMemBytes(va, len) {
    return this.addressSpace.read(this._maskAddr(va), len);
  }

  writeMem(va, size, value) {
    const addr = this._maskAddr(va);
    const v = toBigIntVal(value);
    if (size === 1) {
      this._scratch[0] = Number(v & MASK_8);
    } else if (size === 2) {
      this._scratchView.setUint16(0, Number(v & MASK_16), true);
    } else if (size === 4) {
      this._scratchView.setUint32(0, Number(v & MASK_32), true);
    } else if (size === 8) {
      this._scratchView.setBigUint64(0, v, true);
    } else {
      throw new OmniOSError(`Invalid writeMem size: ${size}`, { code: ERROR_CODES.EINVAL });
    }
    this.addressSpace.write(addr, this._scratch.subarray(0, size));
  }

  writeMemBytes(va, bytes) {
    this.addressSpace.write(this._maskAddr(va), bytes);
  }

  pushStack(value, size = this.ptrSize) {
    const sp = this._maskAddr(this.regs[4] - BigInt(size));
    this.writeMem(sp, size, value);
    this.regs[4] = sp;
  }

  popStack(size = this.ptrSize) {
    const sp = this._maskAddr(this.regs[4]);
    const val = this.readMem(sp, size);
    this.regs[4] = this._maskAddr(sp + BigInt(size));
    return val;
  }

  _fetchU8(ctx) {
    if (ctx.bytesFetched >= MAX_INSN_BYTES) {
      throw new IllegalInstructionError(
        `x86 instruction exceeds maximum 15-byte length at 0x${ctx.startRip.toString(16)}`,
        {
          code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
          pc: `0x${ctx.startRip.toString(16)}`,
          arch: this.mode,
          pid: this.pid,
        }
      );
    }
    const addr = this._maskAddr(this.rip);
    const b = this.addressSpace.fetch(addr, 1)[0];
    this.rip = this._maskAddr(addr + 1n);
    ctx.bytesFetched += 1;
    return b;
  }

  _fetchI8(ctx) {
    const b = this._fetchU8(ctx);
    return b >= 0x80 ? b - 0x100 : b;
  }

  _fetchU16(ctx) {
    const b0 = this._fetchU8(ctx);
    const b1 = this._fetchU8(ctx);
    return b0 | (b1 << 8);
  }

  _fetchI16(ctx) {
    const v = this._fetchU16(ctx);
    return v >= 0x8000 ? v - 0x10000 : v;
  }

  _fetchU32(ctx) {
    const b0 = this._fetchU8(ctx);
    const b1 = this._fetchU8(ctx);
    const b2 = this._fetchU8(ctx);
    const b3 = this._fetchU8(ctx);
    return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
  }

  _fetchI32(ctx) {
    return this._fetchU32(ctx) | 0;
  }

  _fetchU64(ctx) {
    const lo = BigInt(this._fetchU32(ctx));
    const hi = BigInt(this._fetchU32(ctx));
    return lo | (hi << 32n);
  }

  _fetchImmSigned(ctx, size) {
    if (size === 1) return BigInt(this._fetchI8(ctx));
    if (size === 2) return BigInt(this._fetchI16(ctx));
    if (size === 4) return BigInt(this._fetchI32(ctx));
    return this._fetchU64(ctx);
  }

  _fetchImmUnsigned(ctx, size) {
    if (size === 1) return BigInt(this._fetchU8(ctx));
    if (size === 2) return BigInt(this._fetchU16(ctx));
    if (size === 4) return BigInt(this._fetchU32(ctx));
    return this._fetchU64(ctx);
  }

  // ============================================================================
  // ModR/M & SIB Decoding (Deferred RIP-Relative Resolution for Edge Case #17!)
  // ============================================================================

  _decodeModRM(ctx, pfx) {
    const byte = this._fetchU8(ctx);
    const mod = (byte >> 6) & 3;
    const regRaw = (byte >> 3) & 7;
    const rmRaw = byte & 7;
    const reg = regRaw | (pfx.rexR ? 8 : 0);

    if (mod === 3) {
      return {
        mod,
        regRaw,
        reg,
        isReg: true,
        rm: rmRaw | (pfx.rexB ? 8 : 0),
        hasRipRel: false,
        ripDisp: 0,
        addr: 0n,
        seg: pfx.seg,
      };
    }

    const addrSize = pfx.addrSize;
    const addrMask = addrSize === 8 ? MASK_64 : (addrSize === 4 ? MASK_32 : MASK_16);

    if (addrSize === 2) {
      // 16-bit addressing mode (rare, supported cleanly)
      let disp = 0;
      let ea = 0n;
      if (mod === 0 && rmRaw === 6) {
        ea = BigInt(this._fetchU16(ctx));
      } else {
        const bx = this.regs[3] & MASK_16;
        const bp = this.regs[5] & MASK_16;
        const si = this.regs[6] & MASK_16;
        const di = this.regs[7] & MASK_16;
        if (rmRaw === 0) ea = bx + si;
        else if (rmRaw === 1) ea = bx + di;
        else if (rmRaw === 2) ea = bp + si;
        else if (rmRaw === 3) ea = bp + di;
        else if (rmRaw === 4) ea = si;
        else if (rmRaw === 5) ea = di;
        else if (rmRaw === 6) ea = bp;
        else ea = bx;
        if (mod === 1) disp = this._fetchI8(ctx);
        else if (mod === 2) disp = this._fetchI16(ctx);
        ea = (ea + BigInt(disp)) & MASK_16;
      }
      return {
        mod,
        regRaw,
        reg,
        isReg: false,
        rm: rmRaw,
        hasRipRel: false,
        ripDisp: 0,
        addr: ea,
        seg: pfx.seg,
      };
    }

    // 32-bit or 64-bit addressing
    if (rmRaw === 4) {
      // SIB byte follows
      const sib = this._fetchU8(ctx);
      const scaleShift = BigInt((sib >> 6) & 3);
      const indexRaw = (sib >> 3) & 7;
      const baseRaw = sib & 7;
      const indexIdx = indexRaw | (pfx.rexX ? 8 : 0);
      const baseIdx = baseRaw | (pfx.rexB ? 8 : 0);

      let ea = 0n;
      if (indexIdx !== 4) {
        ea += (this.regs[indexIdx] & addrMask) << scaleShift;
      }

      if (mod === 0 && baseRaw === 5) {
        const disp32 = this._fetchI32(ctx);
        ea += BigInt(disp32);
      } else {
        ea += this.regs[baseIdx] & addrMask;
        if (mod === 1) {
          ea += BigInt(this._fetchI8(ctx));
        } else if (mod === 2) {
          ea += BigInt(this._fetchI32(ctx));
        }
      }
      return {
        mod,
        regRaw,
        reg,
        isReg: false,
        rm: rmRaw,
        hasRipRel: false,
        ripDisp: 0,
        addr: ea & addrMask,
        seg: pfx.seg,
      };
    }

    if (mod === 0 && rmRaw === 5) {
      const disp32 = this._fetchI32(ctx);
      if (this.is64) {
        // Edge Case #17: DEFER RIP-relative calculation until ALL immediates are fetched!
        return {
          mod,
          regRaw,
          reg,
          isReg: false,
          rm: rmRaw,
          hasRipRel: true,
          ripDisp: disp32,
          addr: 0n,
          addrMask,
          seg: pfx.seg,
        };
      }
      return {
        mod,
        regRaw,
        reg,
        isReg: false,
        rm: rmRaw,
        hasRipRel: false,
        ripDisp: 0,
        addr: BigInt(disp32 >>> 0),
        seg: pfx.seg,
      };
    }

    const baseIdx = rmRaw | (pfx.rexB ? 8 : 0);
    let ea = this.regs[baseIdx] & addrMask;
    if (mod === 1) {
      ea += BigInt(this._fetchI8(ctx));
    } else if (mod === 2) {
      ea += BigInt(this._fetchI32(ctx));
    }
    return {
      mod,
      regRaw,
      reg,
      isReg: false,
      rm: baseIdx,
      hasRipRel: false,
      ripDisp: 0,
      addr: ea & addrMask,
      seg: pfx.seg,
    };
  }

  _resolveEA(modrm) {
    let ea = modrm.hasRipRel
      ? ((this.rip + BigInt(modrm.ripDisp)) & (modrm.addrMask ?? MASK_64))
      : modrm.addr;
    if (modrm.seg === 0x64) {
      ea = this._maskAddr(ea + this.fsBase);
    } else if (modrm.seg === 0x65) {
      ea = this._maskAddr(ea + this.gsBase);
    }
    return this._maskAddr(ea);
  }

  _readRM(modrm, size, hasRex) {
    if (modrm.isReg) return this.getReg(modrm.rm, size, hasRex);
    return this.readMem(this._resolveEA(modrm), size);
  }

  _writeRM(modrm, size, val, hasRex) {
    if (modrm.isReg) {
      this.setReg(modrm.rm, size, val, hasRex);
    } else {
      this.writeMem(this._resolveEA(modrm), size, val);
    }
  }

  // ============================================================================
  // ALU Operations & Exact Flag Updates
  // ============================================================================

  _aluOp(op, dst, src, size) {
    const mask = sizeMask(size);
    const sb = signBit(size);
    const a = dst & mask;
    const b = src & mask;
    let res = 0n;

    switch (op) {
      case 0: { // ADD
        const full = a + b;
        res = full & mask;
        this.setFlag(RFLAGS.CF, full > mask);
        this.setFlag(RFLAGS.OF, ((~(a ^ b) & (a ^ res)) & sb) !== 0n);
        this.setFlag(RFLAGS.AF, ((a ^ b ^ res) & 0x10n) !== 0n);
        this._setSZP(res, size);
        return res;
      }
      case 1: { // OR
        res = (a | b) & mask;
        this.setFlag(RFLAGS.CF, false);
        this.setFlag(RFLAGS.OF, false);
        this.setFlag(RFLAGS.AF, false);
        this._setSZP(res, size);
        return res;
      }
      case 2: { // ADC
        const carry = this.getFlag(RFLAGS.CF) ? 1n : 0n;
        const full = a + b + carry;
        res = full & mask;
        this.setFlag(RFLAGS.CF, full > mask);
        this.setFlag(RFLAGS.OF, ((~(a ^ b) & (a ^ res)) & sb) !== 0n);
        this.setFlag(RFLAGS.AF, ((a ^ b ^ res) & 0x10n) !== 0n);
        this._setSZP(res, size);
        return res;
      }
      case 3: { // SBB
        const borrow = this.getFlag(RFLAGS.CF) ? 1n : 0n;
        const subtrahend = b + borrow;
        res = (a - subtrahend) & mask;
        this.setFlag(RFLAGS.CF, a < subtrahend);
        this.setFlag(RFLAGS.OF, (((a ^ b) & (a ^ res)) & sb) !== 0n);
        this.setFlag(RFLAGS.AF, ((a ^ b ^ res) & 0x10n) !== 0n);
        this._setSZP(res, size);
        return res;
      }
      case 4: { // AND
        res = (a & b) & mask;
        this.setFlag(RFLAGS.CF, false);
        this.setFlag(RFLAGS.OF, false);
        this.setFlag(RFLAGS.AF, false);
        this._setSZP(res, size);
        return res;
      }
      case 5: // SUB
      case 7: { // CMP
        res = (a - b) & mask;
        this.setFlag(RFLAGS.CF, a < b);
        this.setFlag(RFLAGS.OF, (((a ^ b) & (a ^ res)) & sb) !== 0n);
        this.setFlag(RFLAGS.AF, ((a ^ b ^ res) & 0x10n) !== 0n);
        this._setSZP(res, size);
        return res;
      }
      case 6: { // XOR
        res = (a ^ b) & mask;
        this.setFlag(RFLAGS.CF, false);
        this.setFlag(RFLAGS.OF, false);
        this.setFlag(RFLAGS.AF, false);
        this._setSZP(res, size);
        return res;
      }
      default:
        return a;
    }
  }

  _incDec(val, size, isDec) {
    const mask = sizeMask(size);
    const sb = signBit(size);
    const a = val & mask;
    const res = (isDec ? (a - 1n) : (a + 1n)) & mask;
    // INC/DEC intentionally PRESERVES CF!
    this.setFlag(RFLAGS.OF, isDec ? (a === sb) : (res === sb));
    this.setFlag(RFLAGS.AF, ((a ^ 1n ^ res) & 0x10n) !== 0n);
    this._setSZP(res, size);
    return res;
  }

  _shiftOp(subop, val, rawCount, size) {
    const bits = sizeBits(size);
    const mask = sizeMask(size);
    const sb = signBit(size);
    const countMask = size === 8 ? 0x3f : 0x1f;
    const count = rawCount & countMask;
    const a = val & mask;
    if (count === 0) return a;

    let res = a;
    switch (subop) {
      case 0: { // ROL
        const r = count % bits;
        if (r !== 0) {
          res = ((a << BigInt(r)) | (a >> BigInt(bits - r))) & mask;
        }
        const cf = (res & 1n) !== 0n;
        this.setFlag(RFLAGS.CF, cf);
        if (count === 1) {
          this.setFlag(RFLAGS.OF, ((res & sb) !== 0n) !== cf);
        }
        return res;
      }
      case 1: { // ROR
        const r = count % bits;
        if (r !== 0) {
          res = ((a >> BigInt(r)) | (a << BigInt(bits - r))) & mask;
        }
        const msb = (res & sb) !== 0n;
        this.setFlag(RFLAGS.CF, msb);
        if (count === 1) {
          const prevMsb = (res & (sb >> 1n)) !== 0n;
          this.setFlag(RFLAGS.OF, msb !== prevMsb);
        }
        return res;
      }
      case 2: { // RCL
        const total = bits + 1;
        const r = count % total;
        let cf = this.getFlag(RFLAGS.CF) ? 1n : 0n;
        res = a;
        for (let i = 0; i < r; i++) {
          const nextCf = (res & sb) !== 0n ? 1n : 0n;
          res = ((res << 1n) | cf) & mask;
          cf = nextCf;
        }
        this.setFlag(RFLAGS.CF, cf !== 0n);
        if (count === 1) {
          this.setFlag(RFLAGS.OF, ((res & sb) !== 0n) !== (cf !== 0n));
        }
        return res;
      }
      case 3: { // RCR
        const total = bits + 1;
        const r = count % total;
        let cf = this.getFlag(RFLAGS.CF) ? 1n : 0n;
        res = a;
        if (count === 1) {
          this.setFlag(RFLAGS.OF, ((a & sb) !== 0n) !== (cf !== 0n));
        }
        for (let i = 0; i < r; i++) {
          const nextCf = res & 1n;
          res = ((res >> 1n) | (cf !== 0n ? sb : 0n)) & mask;
          cf = nextCf;
        }
        this.setFlag(RFLAGS.CF, cf !== 0n);
        return res;
      }
      case 4: // SHL / SAL
      case 6: {
        if (count >= bits) {
          res = 0n;
          const cf = count === bits ? ((a & 1n) !== 0n) : false;
          this.setFlag(RFLAGS.CF, cf);
        } else {
          res = (a << BigInt(count)) & mask;
          const cf = ((a >> BigInt(bits - count)) & 1n) !== 0n;
          this.setFlag(RFLAGS.CF, cf);
          if (count === 1) {
            this.setFlag(RFLAGS.OF, ((res & sb) !== 0n) !== cf);
          }
        }
        this._setSZP(res, size);
        return res;
      }
      case 5: { // SHR
        if (count >= bits) {
          res = 0n;
          const cf = count === bits ? ((a & sb) !== 0n) : false;
          this.setFlag(RFLAGS.CF, cf);
        } else {
          const cf = ((a >> BigInt(count - 1)) & 1n) !== 0n;
          res = a >> BigInt(count);
          this.setFlag(RFLAGS.CF, cf);
          if (count === 1) {
            this.setFlag(RFLAGS.OF, (a & sb) !== 0n);
          }
        }
        this._setSZP(res, size);
        return res;
      }
      case 7: { // SAR
        const sa = toSigned(a, size);
        if (count >= bits) {
          const neg = sa < 0n;
          res = neg ? mask : 0n;
          this.setFlag(RFLAGS.CF, neg);
        } else {
          const cf = ((a >> BigInt(count - 1)) & 1n) !== 0n;
          res = (sa >> BigInt(count)) & mask;
          this.setFlag(RFLAGS.CF, cf);
          if (count === 1) {
            this.setFlag(RFLAGS.OF, false);
          }
        }
        this._setSZP(res, size);
        return res;
      }
      default:
        return a;
    }
  }

  _divFault(reason, startRip) {
    return new OmniOSError(reason, {
      code: 'STATUS_INTEGER_DIVIDE_BY_ZERO',
      signal: 'SIGFPE',
      details: {
        pc: `0x${startRip.toString(16)}`,
        arch: this.mode,
        pid: this.pid,
        win32Status: WIN32_ERROR.STATUS_INTEGER_DIVIDE_BY_ZERO,
      },
    });
  }

  _execDiv(isSigned, divisorVal, size, startRip) {
    const bits = BigInt(sizeBits(size));
    const mask = sizeMask(size);

    if ((divisorVal & mask) === 0n) {
      throw this._divFault('x86 integer division by zero', startRip);
    }

    if (size === 1) {
      const dividend = this.regs[0] & MASK_16;
      if (!isSigned) {
        const d = divisorVal & MASK_8;
        const q = dividend / d;
        const r = dividend % d;
        if (q > 0xffn) throw this._divFault('x86 DIV8 quotient overflow', startRip);
        this.setReg(0, 1, q, false);
        this.setReg(4, 1, r, false); // AH
      } else {
        const sDividend = BigInt.asIntN(16, dividend);
        const sDivisor = BigInt.asIntN(8, divisorVal);
        const q = sDividend / sDivisor;
        const r = sDividend % sDivisor;
        if (q < -128n || q > 127n) throw this._divFault('x86 IDIV8 quotient overflow', startRip);
        this.setReg(0, 1, q & MASK_8, false);
        this.setReg(4, 1, r & MASK_8, false); // AH
      }
      return;
    }

    const lo = this.getReg(0, size, true);
    const hi = this.getReg(2, size, true);
    const fullUnsigned = (hi << bits) | lo;

    if (!isSigned) {
      const d = divisorVal & mask;
      const q = fullUnsigned / d;
      const r = fullUnsigned % d;
      if (q > mask) throw this._divFault(`x86 DIV${size * 8} quotient overflow`, startRip);
      this.setReg(0, size, q, true);
      this.setReg(2, size, r, true);
    } else {
      const sDividend = BigInt.asIntN(size * 16, fullUnsigned);
      const sDivisor = toSigned(divisorVal, size);
      const q = sDividend / sDivisor;
      const r = sDividend % sDivisor;
      const minQ = -(1n << (bits - 1n));
      const maxQ = (1n << (bits - 1n)) - 1n;
      if (q < minQ || q > maxQ) {
        throw this._divFault(`x86 IDIV${size * 8} quotient overflow`, startRip);
      }
      this.setReg(0, size, q & mask, true);
      this.setReg(2, size, r & mask, true);
    }
  }

  _execMul(isSigned, srcVal, size) {
    const bits = BigInt(sizeBits(size));
    const mask = sizeMask(size);

    if (size === 1) {
      const al = this.regs[0] & MASK_8;
      if (!isSigned) {
        const prod = al * (srcVal & MASK_8);
        this.setReg(0, 2, prod & MASK_16, true);
        const ovf = (prod >> 8n) !== 0n;
        this.setFlag(RFLAGS.CF, ovf);
        this.setFlag(RFLAGS.OF, ovf);
      } else {
        const prod = BigInt.asIntN(8, al) * BigInt.asIntN(8, srcVal);
        const low16 = prod & MASK_16;
        this.setReg(0, 2, low16, true);
        const ovf = BigInt.asIntN(8, prod) !== prod;
        this.setFlag(RFLAGS.CF, ovf);
        this.setFlag(RFLAGS.OF, ovf);
      }
      return;
    }

    const a = this.getReg(0, size, true);
    if (!isSigned) {
      const prod = a * (srcVal & mask);
      const lo = prod & mask;
      const hi = (prod >> bits) & mask;
      this.setReg(0, size, lo, true);
      this.setReg(2, size, hi, true);
      const ovf = hi !== 0n;
      this.setFlag(RFLAGS.CF, ovf);
      this.setFlag(RFLAGS.OF, ovf);
    } else {
      const prod = toSigned(a, size) * toSigned(srcVal, size);
      const lo = prod & mask;
      const hi = (prod >> bits) & mask;
      this.setReg(0, size, lo, true);
      this.setReg(2, size, hi, true);
      const ovf = toSigned(lo, size) !== prod;
      this.setFlag(RFLAGS.CF, ovf);
      this.setFlag(RFLAGS.OF, ovf);
    }
  }

  _imulTrunc(a, b, size) {
    const mask = sizeMask(size);
    const prod = toSigned(a, size) * toSigned(b, size);
    const res = prod & mask;
    const ovf = toSigned(res, size) !== prod;
    this.setFlag(RFLAGS.CF, ovf);
    this.setFlag(RFLAGS.OF, ovf);
    return res;
  }

  // ============================================================================
  // Step Execution Loop (Strictly Synchronous, Budget-Bounded)
  // ============================================================================

  step(budget = 1000) {
    const maxSteps = Math.max(0, Math.trunc(budget));
    let executed = 0;
    const isTopStep = this._topStepState === null;
    const stepState = isTopStep ? { executed: 0, maxSteps } : null;
    if (isTopStep) {
      this._topStepState = stepState;
    }

    try {
      while (executed < maxSteps) {
        if (this.exited) {
          return {
            status: 'EXITED',
            exitCode: this.exitCode,
            instructionsExecuted: executed,
          };
        }
        if (this.faulted) {
          return {
            status: 'FAULT',
            fault: this.lastFault,
            instructionsExecuted: executed,
          };
        }

        const curRip = this._maskAddr(this.rip);

        // 0. Unwind completed cooperative callback frames BEFORE fetch() or budget check
        if (this._callbackReturnSentinels.has(curRip)) {
          try {
            this._unwindCallbackReturn();
          } catch (err) {
            this.faulted = true;
            this.lastFault = err;
            return { status: 'FAULT', fault: err, instructionsExecuted: executed };
          }
          continue;
        }

        // 1. Intercept re-entrant callFunction return sentinels BEFORE fetch() or budget check
        if (this._callReturnSentinels.has(curRip)) {
          return {
            status: 'RETURNED',
            instructionsExecuted: executed,
          };
        }

        // 2. Intercept top-level entry return sentinel BEFORE fetch()
        if (curRip === this.entryReturnSentinel) {
          this.exited = true;
          this.exitCode = Number(this.regs[0] & MASK_32) | 0;
          return {
            status: 'EXITED',
            exitCode: this.exitCode,
            instructionsExecuted: executed,
          };
        }

        // Enforce shared cumulative nested-call instruction budget if executing inside callFunction()
        let remaining = maxSteps - executed;
        if (this._nestedBudget !== null) {
          const nestedRem =
            this._nestedBudget.limit - (this.totalInstructions - this._nestedBudget.startTotal);
          if (nestedRem <= 0) {
            break;
          }
          if (nestedRem < remaining) {
            remaining = nestedRem;
          }
        }

        // 3. Intercept Win32 / Darwin synthetic Thunk VAs BEFORE fetch()
        if (this.isThunkAddress(curRip)) {
          if (!this.onThunk) {
            const err = new IllegalInstructionError(
              `Unhandled thunk call at 0x${curRip.toString(16)}`,
              { code: ERROR_CODES.E_UNIMPLEMENTED_API, pc: `0x${curRip.toString(16)}`, arch: this.mode, pid: this.pid }
            );
            this.faulted = true;
            this.lastFault = err;
            return { status: 'FAULT', fault: err, instructionsExecuted: executed };
          }

          // Charge the thunk invocation immediately so recursive thunks consume cumulative budget before re-entering
          executed += 1;
          this.totalInstructions += 1;
          if (stepState !== null) stepState.executed = executed;
          const beforeNestedTotal = this.totalInstructions;

          let thunkRes;
          try {
            thunkRes = this.onThunk(curRip, this);
          } catch (err) {
            const deltaNested = this.totalInstructions - beforeNestedTotal;
            executed += deltaNested;
            if (stepState !== null) stepState.executed = executed;
            this.faulted = true;
            this.lastFault = err;
            return { status: 'FAULT', fault: err, instructionsExecuted: executed };
          }

          const deltaNested = this.totalInstructions - beforeNestedTotal;
          executed += deltaNested;
          if (stepState !== null) stepState.executed = executed;

          if (this.faulted) {
            return { status: 'FAULT', fault: this.lastFault, instructionsExecuted: executed };
          }
          if (this.exited) {
            return { status: 'EXITED', exitCode: this.exitCode, instructionsExecuted: executed };
          }

          if (thunkRes && thunkRes.status === 'CALLBACK_REDIRECT') {
            // Cooperative trampoline frame already consumed caller return address & redirected RIP
            continue;
          }

          if (!thunkRes || thunkRes.status === 'CONTINUE') {
            // Pop return address and apply optional __stdcall stack cleanup
            const retAddr = this.popStack(this.ptrSize);
            const cleanup = thunkRes?.stackCleanupBytes ?? 0;
            if (cleanup > 0) {
              this.regs[4] = this._maskAddr(this.regs[4] + BigInt(cleanup));
            }
            this.rip = this._maskAddr(retAddr);
            continue;
          }
          if (thunkRes.status === 'BLOCKED') {
            // Leave RIP at thunk VA & return address on stack so waking retries cleanly!
            return {
              status: 'BLOCKED',
              waitReason: thunkRes.waitReason ?? 'io',
              instructionsExecuted: executed,
            };
          }
          if (thunkRes.status === 'EXITED') {
            this.exited = true;
            this.exitCode = Number.isInteger(thunkRes.exitCode) ? thunkRes.exitCode : 0;
            return {
              status: 'EXITED',
              exitCode: this.exitCode,
              instructionsExecuted: executed,
            };
          }
          if (thunkRes.status === 'FAULT') {
            const fault = thunkRes.fault ?? new IllegalInstructionError(
              `Thunk fault at 0x${curRip.toString(16)}`,
              { code: ERROR_CODES.E_ILLEGAL_INSTRUCTION, pc: `0x${curRip.toString(16)}`, arch: this.mode, pid: this.pid }
            );
            this.faulted = true;
            this.lastFault = fault;
            return {
              status: 'FAULT',
              fault,
              instructionsExecuted: executed,
            };
          }
          if (thunkRes.status === 'YIELD') {
            const retAddr = this.popStack(this.ptrSize);
            const cleanup = thunkRes?.stackCleanupBytes ?? 0;
            if (cleanup > 0) {
              this.regs[4] = this._maskAddr(this.regs[4] + BigInt(cleanup));
            }
            this.rip = this._maskAddr(retAddr);
            return { status: 'YIELD', instructionsExecuted: executed };
          }
          continue;
        }

        // 4. Decode and execute one x86 / x86-64 instruction (or REP batch bounded by remaining budget)
        const startRip = curRip;
        if (stepState !== null) stepState.executed = executed;
        const beforeExecTotal = this.totalInstructions;
        try {
          const outcome = this._executeOne(startRip, remaining);
          const deltaNested = this.totalInstructions - beforeExecTotal;
          executed += deltaNested + outcome.count;
          this.totalInstructions += outcome.count;
          this._tscCounter += BigInt(outcome.count * 4);
          if (stepState !== null) stepState.executed = executed;

          if (outcome.status === 'EXITED') {
            this.exited = true;
            this.exitCode = outcome.exitCode ?? 0;
            return { status: 'EXITED', exitCode: this.exitCode, instructionsExecuted: executed };
          }
          if (outcome.status === 'BLOCKED') {
            return {
              status: 'BLOCKED',
              waitReason: outcome.waitReason ?? 'io',
              instructionsExecuted: executed,
            };
          }
          if (outcome.status === 'FAULT') {
            const fault = outcome.fault ?? new IllegalInstructionError(
              `Instruction fault at 0x${startRip.toString(16)}`,
              { code: ERROR_CODES.E_ILLEGAL_INSTRUCTION, pc: `0x${startRip.toString(16)}`, arch: this.mode, pid: this.pid }
            );
            this.faulted = true;
            this.lastFault = fault;
            return {
              status: 'FAULT',
              fault,
              instructionsExecuted: executed,
            };
          }
          if (outcome.status === 'YIELD') {
            return { status: 'YIELD', instructionsExecuted: executed };
          }
        } catch (err) {
          const deltaNested = this.totalInstructions - beforeExecTotal;
          executed += deltaNested;
          if (stepState !== null) stepState.executed = executed;
          // Restore RIP to faulting instruction start for accurate crash diagnostics
          this.rip = startRip;
          this.faulted = true;
          this.lastFault = err;
          return {
            status: 'FAULT',
            fault: err,
            instructionsExecuted: executed,
          };
        }
      }

      while (this._callbackReturnSentinels.has(this._maskAddr(this.rip))) {
        try {
          this._unwindCallbackReturn();
        } catch (err) {
          this.faulted = true;
          this.lastFault = err;
          return { status: 'FAULT', fault: err, instructionsExecuted: executed };
        }
      }

      if (this._callReturnSentinels.has(this._maskAddr(this.rip))) {
        return {
          status: 'RETURNED',
          instructionsExecuted: executed,
        };
      }

      return {
        status: 'YIELD',
        instructionsExecuted: executed,
      };
    } finally {
      if (isTopStep) {
        this._topStepState = null;
      }
    }
  }

  _executeOne(startRip, remainingBudget) {
    const ctx = { startRip, bytesFetched: 0 };
    const pfx = {
      lock: false,
      rep: 0, // 0, 0xF2, 0xF3
      seg: 0, // 0, 0x64 (FS), 0x65 (GS)
      opSizeOverride: false,
      addrSizeOverride: false,
      hasRex: false,
      rexW: false,
      rexR: false,
      rexX: false,
      rexB: false,
      opSize: 4,
      addrSize: this.is64 ? 8 : 4,
    };

    // Parse legacy prefixes + REX prefix (in 64-bit mode)
    let op = 0;
    while (true) {
      const b = this._fetchU8(ctx);
      if (b === 0xf0) { pfx.lock = true; continue; }
      if (b === 0xf2 || b === 0xf3) { pfx.rep = b; continue; }
      if (b === 0x66) { pfx.opSizeOverride = true; continue; }
      if (b === 0x67) { pfx.addrSizeOverride = true; continue; }
      if (b === 0x26 || b === 0x2e || b === 0x36 || b === 0x3e || b === 0x64 || b === 0x65) {
        pfx.seg = b;
        continue;
      }
      if (this.is64 && b >= 0x40 && b <= 0x4f) {
        pfx.hasRex = true;
        pfx.rexW = (b & 8) !== 0;
        pfx.rexR = (b & 4) !== 0;
        pfx.rexX = (b & 2) !== 0;
        pfx.rexB = (b & 1) !== 0;
        continue;
      }
      op = b;
      break;
    }

    pfx.opSize = pfx.rexW ? 8 : (pfx.opSizeOverride ? 2 : 4);
    if (this.is64) {
      pfx.addrSize = pfx.addrSizeOverride ? 4 : 8;
    } else {
      pfx.addrSize = pfx.addrSizeOverride ? 2 : 4;
    }

    const opSize = pfx.opSize;
    const stackOpSize = this.is64 ? (pfx.opSizeOverride ? 2 : 8) : (pfx.opSizeOverride ? 2 : 4);

    // ---- Two-byte opcode escape (0x0F) ----
    if (op === 0x0f) {
      return this._execute0F(ctx, pfx);
    }

    // ---- Standard ALU 0x00..0x3D (ADD, OR, ADC, SBB, AND, SUB, XOR, CMP) ----
    if ((op & 0xc0) === 0x00 && (op & 0x07) <= 5) {
      const aluKind = (op >> 3) & 7;
      const mode = op & 7;
      if (mode === 0) { // r/m8, r8
        const m = this._decodeModRM(ctx, pfx);
        const dst = this._readRM(m, 1, pfx.hasRex);
        const src = this.getReg(m.reg, 1, pfx.hasRex);
        const res = this._aluOp(aluKind, dst, src, 1);
        if (aluKind !== 7) this._writeRM(m, 1, res, pfx.hasRex);
        return { count: 1 };
      }
      if (mode === 1) { // r/m, r
        const m = this._decodeModRM(ctx, pfx);
        const dst = this._readRM(m, opSize, pfx.hasRex);
        const src = this.getReg(m.reg, opSize, pfx.hasRex);
        const res = this._aluOp(aluKind, dst, src, opSize);
        if (aluKind !== 7) this._writeRM(m, opSize, res, pfx.hasRex);
        return { count: 1 };
      }
      if (mode === 2) { // r8, r/m8
        const m = this._decodeModRM(ctx, pfx);
        const dst = this.getReg(m.reg, 1, pfx.hasRex);
        const src = this._readRM(m, 1, pfx.hasRex);
        const res = this._aluOp(aluKind, dst, src, 1);
        if (aluKind !== 7) this.setReg(m.reg, 1, res, pfx.hasRex);
        return { count: 1 };
      }
      if (mode === 3) { // r, r/m
        const m = this._decodeModRM(ctx, pfx);
        const dst = this.getReg(m.reg, opSize, pfx.hasRex);
        const src = this._readRM(m, opSize, pfx.hasRex);
        const res = this._aluOp(aluKind, dst, src, opSize);
        if (aluKind !== 7) this.setReg(m.reg, opSize, res, pfx.hasRex);
        return { count: 1 };
      }
      if (mode === 4) { // AL, imm8
        const imm = BigInt(this._fetchU8(ctx));
        const res = this._aluOp(aluKind, this.getReg(0, 1, false), imm, 1);
        if (aluKind !== 7) this.setReg(0, 1, res, false);
        return { count: 1 };
      }
      if (mode === 5) { // rAX, imm16/32 (sign-ext for 64)
        const immSize = opSize === 2 ? 2 : 4;
        const imm = this._fetchImmSigned(ctx, immSize);
        const res = this._aluOp(aluKind, this.getReg(0, opSize, true), imm, opSize);
        if (aluKind !== 7) this.setReg(0, opSize, res, true);
        return { count: 1 };
      }
    }

    // ---- 32-bit mode INC / DEC r32 (0x40..0x4F) ----
    if (!this.is64 && op >= 0x40 && op <= 0x4f) {
      const reg = op & 7;
      const isDec = op >= 0x48;
      const res = this._incDec(this.getReg(reg, opSize, false), opSize, isDec);
      this.setReg(reg, opSize, res, false);
      return { count: 1 };
    }

    // ---- PUSH / POP r64/r32/r16 (0x50..0x5F) ----
    if (op >= 0x50 && op <= 0x57) {
      const reg = (op & 7) | (pfx.rexB ? 8 : 0);
      this.pushStack(this.getReg(reg, stackOpSize, true), stackOpSize);
      return { count: 1 };
    }
    if (op >= 0x58 && op <= 0x5f) {
      const reg = (op & 7) | (pfx.rexB ? 8 : 0);
      const val = this.popStack(stackOpSize);
      this.setReg(reg, stackOpSize, val, true);
      return { count: 1 };
    }

    // ---- Jcc rel8 (0x70..0x7F) ----
    if (op >= 0x70 && op <= 0x7f) {
      const rel = this._fetchI8(ctx);
      if (this._evalCond(op & 0x0f)) {
        this.rip = this._maskAddr(this.rip + BigInt(rel));
      }
      return { count: 1 };
    }

    // ---- MOV r8, imm8 (0xB0..0xB7) ----
    if (op >= 0xb0 && op <= 0xb7) {
      const reg = (op & 7) | (pfx.rexB ? 8 : 0);
      const imm = BigInt(this._fetchU8(ctx));
      this.setReg(reg, 1, imm, pfx.hasRex);
      return { count: 1 };
    }

    // ---- MOV r, imm16/32/64 (0xB8..0xBF, movabs when REX.W) ----
    if (op >= 0xb8 && op <= 0xbf) {
      const reg = (op & 7) | (pfx.rexB ? 8 : 0);
      const imm = this._fetchImmUnsigned(ctx, opSize);
      this.setReg(reg, opSize, imm, true);
      return { count: 1 };
    }

    // ---- XCHG rAX, r (0x90..0x97) & NOP ----
    if (op >= 0x90 && op <= 0x97) {
      const reg = (op & 7) | (pfx.rexB ? 8 : 0);
      if (op === 0x90 && reg === 0) {
        // NOP / PAUSE (0x90 or 0xF3 0x90)
        return { count: 1 };
      }
      const a = this.getReg(0, opSize, true);
      const b = this.getReg(reg, opSize, true);
      this.setReg(0, opSize, b, true);
      this.setReg(reg, opSize, a, true);
      return { count: 1 };
    }

    switch (op) {
      case 0x63: { // MOVSXD r, r/m32 (64-bit)
        if (!this.is64) {
          throw this._unsupported(op, startRip);
        }
        const m = this._decodeModRM(ctx, pfx);
        const src32 = this._readRM(m, 4, pfx.hasRex);
        if (opSize === 8) {
          this.setReg(m.reg, 8, BigInt.asIntN(32, src32) & MASK_64, true);
        } else {
          this.setReg(m.reg, opSize, src32, true);
        }
        return { count: 1 };
      }

      case 0x68: { // PUSH imm32/16 (sign-ext to stackOpSize)
        const immSize = pfx.opSizeOverride ? 2 : 4;
        const imm = this._fetchImmSigned(ctx, immSize);
        this.pushStack(imm, stackOpSize);
        return { count: 1 };
      }

      case 0x6a: { // PUSH imm8 (sign-ext)
        const imm = BigInt(this._fetchI8(ctx));
        this.pushStack(imm, stackOpSize);
        return { count: 1 };
      }

      case 0x69: { // IMUL r, r/m, imm32/16
        const m = this._decodeModRM(ctx, pfx);
        const immSize = opSize === 2 ? 2 : 4;
        const imm = this._fetchImmSigned(ctx, immSize);
        const src = this._readRM(m, opSize, pfx.hasRex);
        const res = this._imulTrunc(src, imm, opSize);
        this.setReg(m.reg, opSize, res, true);
        return { count: 1 };
      }

      case 0x6b: { // IMUL r, r/m, imm8
        const m = this._decodeModRM(ctx, pfx);
        const imm = BigInt(this._fetchI8(ctx));
        const src = this._readRM(m, opSize, pfx.hasRex);
        const res = this._imulTrunc(src, imm, opSize);
        this.setReg(m.reg, opSize, res, true);
        return { count: 1 };
      }

      // Group 1 ALU: r/m, imm
      case 0x80:
      case 0x82: {
        const m = this._decodeModRM(ctx, pfx);
        const imm = BigInt(this._fetchU8(ctx));
        const dst = this._readRM(m, 1, pfx.hasRex);
        const res = this._aluOp(m.regRaw, dst, imm, 1);
        if (m.regRaw !== 7) this._writeRM(m, 1, res, pfx.hasRex);
        return { count: 1 };
      }

      case 0x81: {
        const m = this._decodeModRM(ctx, pfx);
        const immSize = opSize === 2 ? 2 : 4;
        const imm = this._fetchImmSigned(ctx, immSize);
        const dst = this._readRM(m, opSize, pfx.hasRex);
        const res = this._aluOp(m.regRaw, dst, imm, opSize);
        if (m.regRaw !== 7) this._writeRM(m, opSize, res, pfx.hasRex);
        return { count: 1 };
      }

      case 0x83: {
        const m = this._decodeModRM(ctx, pfx);
        const imm = BigInt(this._fetchI8(ctx));
        const dst = this._readRM(m, opSize, pfx.hasRex);
        const res = this._aluOp(m.regRaw, dst, imm, opSize);
        if (m.regRaw !== 7) this._writeRM(m, opSize, res, pfx.hasRex);
        return { count: 1 };
      }

      case 0x84: { // TEST r/m8, r8
        const m = this._decodeModRM(ctx, pfx);
        this._aluOp(4, this._readRM(m, 1, pfx.hasRex), this.getReg(m.reg, 1, pfx.hasRex), 1);
        return { count: 1 };
      }

      case 0x85: { // TEST r/m, r
        const m = this._decodeModRM(ctx, pfx);
        this._aluOp(4, this._readRM(m, opSize, pfx.hasRex), this.getReg(m.reg, opSize, pfx.hasRex), opSize);
        return { count: 1 };
      }

      case 0x86: { // XCHG r/m8, r8
        const m = this._decodeModRM(ctx, pfx);
        const a = this._readRM(m, 1, pfx.hasRex);
        const b = this.getReg(m.reg, 1, pfx.hasRex);
        this._writeRM(m, 1, b, pfx.hasRex);
        this.setReg(m.reg, 1, a, pfx.hasRex);
        return { count: 1 };
      }

      case 0x87: { // XCHG r/m, r
        const m = this._decodeModRM(ctx, pfx);
        const a = this._readRM(m, opSize, pfx.hasRex);
        const b = this.getReg(m.reg, opSize, pfx.hasRex);
        this._writeRM(m, opSize, b, pfx.hasRex);
        this.setReg(m.reg, opSize, a, pfx.hasRex);
        return { count: 1 };
      }

      case 0x88: { // MOV r/m8, r8
        const m = this._decodeModRM(ctx, pfx);
        this._writeRM(m, 1, this.getReg(m.reg, 1, pfx.hasRex), pfx.hasRex);
        return { count: 1 };
      }

      case 0x89: { // MOV r/m, r
        const m = this._decodeModRM(ctx, pfx);
        this._writeRM(m, opSize, this.getReg(m.reg, opSize, pfx.hasRex), pfx.hasRex);
        return { count: 1 };
      }

      case 0x8a: { // MOV r8, r/m8
        const m = this._decodeModRM(ctx, pfx);
        this.setReg(m.reg, 1, this._readRM(m, 1, pfx.hasRex), pfx.hasRex);
        return { count: 1 };
      }

      case 0x8b: { // MOV r, r/m
        const m = this._decodeModRM(ctx, pfx);
        this.setReg(m.reg, opSize, this._readRM(m, opSize, pfx.hasRex), pfx.hasRex);
        return { count: 1 };
      }

      case 0x8d: { // LEA r, m
        const m = this._decodeModRM(ctx, pfx);
        if (m.isReg) {
          throw new IllegalInstructionError('LEA requires memory operand', {
            code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
            pc: `0x${startRip.toString(16)}`,
            arch: this.mode,
            pid: this.pid,
          });
        }
        // LEA does NOT apply segment override base in x86-64
        const ea = m.hasRipRel
          ? ((this.rip + BigInt(m.ripDisp)) & (m.addrMask ?? MASK_64))
          : m.addr;
        this.setReg(m.reg, opSize, ea, true);
        return { count: 1 };
      }

      case 0x8f: { // POP r/m
        const m = this._decodeModRM(ctx, pfx);
        if (m.regRaw !== 0) throw this._unsupported(op, startRip);
        const val = this.popStack(stackOpSize);
        this._writeRM(m, stackOpSize, val, pfx.hasRex);
        return { count: 1 };
      }

      case 0x98: { // CBW / CWDE / CDQE
        if (opSize === 2) {
          this.setReg(0, 2, BigInt.asIntN(8, this.regs[0]) & MASK_16, true);
        } else if (opSize === 4) {
          this.setReg(0, 4, BigInt.asIntN(16, this.regs[0]) & MASK_32, true);
        } else {
          this.setReg(0, 8, BigInt.asIntN(32, this.regs[0]) & MASK_64, true);
        }
        return { count: 1 };
      }

      case 0x99: { // CWD / CDQ / CQO
        const s = toSigned(this.getReg(0, opSize, true), opSize);
        this.setReg(2, opSize, s < 0n ? sizeMask(opSize) : 0n, true);
        return { count: 1 };
      }

      case 0x9c: { // PUSHFQ / PUSHFD / PUSHF
        this.pushStack(this.rflags, stackOpSize);
        return { count: 1 };
      }

      case 0x9d: { // POPFQ / POPFD / POPF
        const val = this.popStack(stackOpSize);
        const keepMask = 0x0000000000240dd5n;
        this.rflags = (val & keepMask) | 0x202n;
        return { count: 1 };
      }

      case 0x9e: { // SAHF
        const ah = Number((this.regs[0] >> 8n) & 0xffn);
        this.setFlag(RFLAGS.CF, (ah & 0x01) !== 0);
        this.setFlag(RFLAGS.PF, (ah & 0x04) !== 0);
        this.setFlag(RFLAGS.AF, (ah & 0x10) !== 0);
        this.setFlag(RFLAGS.ZF, (ah & 0x40) !== 0);
        this.setFlag(RFLAGS.SF, (ah & 0x80) !== 0);
        return { count: 1 };
      }

      case 0x9f: { // LAHF
        const flagsLo = (Number(this.rflags) & 0xd5) | 0x02;
        this.setReg(4, 1, BigInt(flagsLo), false);
        return { count: 1 };
      }

      case 0xa0: { // MOV AL, moffs8
        const addr = this._applySeg(this._fetchImmUnsigned(ctx, pfx.addrSize), pfx.seg);
        this.setReg(0, 1, this.readMem(addr, 1), false);
        return { count: 1 };
      }
      case 0xa1: { // MOV rAX, moffs
        const addr = this._applySeg(this._fetchImmUnsigned(ctx, pfx.addrSize), pfx.seg);
        this.setReg(0, opSize, this.readMem(addr, opSize), true);
        return { count: 1 };
      }
      case 0xa2: { // MOV moffs8, AL
        const addr = this._applySeg(this._fetchImmUnsigned(ctx, pfx.addrSize), pfx.seg);
        this.writeMem(addr, 1, this.getReg(0, 1, false));
        return { count: 1 };
      }
      case 0xa3: { // MOV moffs, rAX
        const addr = this._applySeg(this._fetchImmUnsigned(ctx, pfx.addrSize), pfx.seg);
        this.writeMem(addr, opSize, this.getReg(0, opSize, true));
        return { count: 1 };
      }

      // ---- String Ops (MOVS/CMPS/STOS/LODS/SCAS) with Budget-Yielded REP! ----
      case 0xa4: case 0xa5:
      case 0xa6: case 0xa7:
      case 0xaa: case 0xab:
      case 0xac: case 0xad:
      case 0xae: case 0xaf: {
        return this._executeStringOp(op, pfx, startRip, remainingBudget);
      }

      case 0xa8: { // TEST AL, imm8
        const imm = BigInt(this._fetchU8(ctx));
        this._aluOp(4, this.getReg(0, 1, false), imm, 1);
        return { count: 1 };
      }

      case 0xa9: { // TEST rAX, imm32/16
        const immSize = opSize === 2 ? 2 : 4;
        const imm = this._fetchImmSigned(ctx, immSize);
        this._aluOp(4, this.getReg(0, opSize, true), imm, opSize);
        return { count: 1 };
      }

      // ---- Group 2 Shifts & Rotates ----
      case 0xc0: {
        const m = this._decodeModRM(ctx, pfx);
        const cnt = this._fetchU8(ctx);
        const res = this._shiftOp(m.regRaw, this._readRM(m, 1, pfx.hasRex), cnt, 1);
        this._writeRM(m, 1, res, pfx.hasRex);
        return { count: 1 };
      }
      case 0xc1: {
        const m = this._decodeModRM(ctx, pfx);
        const cnt = this._fetchU8(ctx);
        const res = this._shiftOp(m.regRaw, this._readRM(m, opSize, pfx.hasRex), cnt, opSize);
        this._writeRM(m, opSize, res, pfx.hasRex);
        return { count: 1 };
      }
      case 0xd0: {
        const m = this._decodeModRM(ctx, pfx);
        const res = this._shiftOp(m.regRaw, this._readRM(m, 1, pfx.hasRex), 1, 1);
        this._writeRM(m, 1, res, pfx.hasRex);
        return { count: 1 };
      }
      case 0xd1: {
        const m = this._decodeModRM(ctx, pfx);
        const res = this._shiftOp(m.regRaw, this._readRM(m, opSize, pfx.hasRex), 1, opSize);
        this._writeRM(m, opSize, res, pfx.hasRex);
        return { count: 1 };
      }
      case 0xd2: {
        const m = this._decodeModRM(ctx, pfx);
        const cnt = Number(this.regs[1] & MASK_8);
        const res = this._shiftOp(m.regRaw, this._readRM(m, 1, pfx.hasRex), cnt, 1);
        this._writeRM(m, 1, res, pfx.hasRex);
        return { count: 1 };
      }
      case 0xd3: {
        const m = this._decodeModRM(ctx, pfx);
        const cnt = Number(this.regs[1] & MASK_8);
        const res = this._shiftOp(m.regRaw, this._readRM(m, opSize, pfx.hasRex), cnt, opSize);
        this._writeRM(m, opSize, res, pfx.hasRex);
        return { count: 1 };
      }

      case 0xc2: { // RET imm16 (__stdcall)
        const imm16 = this._fetchU16(ctx);
        const retAddr = this.popStack(this.ptrSize);
        this.regs[4] = this._maskAddr(this.regs[4] + BigInt(imm16));
        this.rip = this._maskAddr(retAddr);
        return { count: 1 };
      }

      case 0xc3: { // RET
        const retAddr = this.popStack(this.ptrSize);
        this.rip = this._maskAddr(retAddr);
        return { count: 1 };
      }

      case 0xc6: { // MOV r/m8, imm8
        const m = this._decodeModRM(ctx, pfx);
        if (m.regRaw !== 0) throw this._unsupported(op, startRip);
        const imm = BigInt(this._fetchU8(ctx));
        this._writeRM(m, 1, imm, pfx.hasRex);
        return { count: 1 };
      }

      case 0xc7: { // MOV r/m, imm32/16 (sign-ext to 64 when REX.W)
        const m = this._decodeModRM(ctx, pfx);
        if (m.regRaw !== 0) throw this._unsupported(op, startRip);
        const immSize = opSize === 2 ? 2 : 4;
        const imm = this._fetchImmSigned(ctx, immSize);
        this._writeRM(m, opSize, imm, pfx.hasRex);
        return { count: 1 };
      }

      case 0xc8: { // ENTER imm16, imm8
        const allocSize = BigInt(this._fetchU16(ctx));
        const nestLevel = this._fetchU8(ctx) & 0x1f;
        this.pushStack(this.getReg(5, stackOpSize, true), stackOpSize);
        const frameTemp = this.regs[4];
        if (nestLevel > 0) {
          let bp = this.regs[5];
          for (let i = 1; i < nestLevel; i++) {
            bp = this._maskAddr(bp - BigInt(stackOpSize));
            this.pushStack(this.readMem(bp, stackOpSize), stackOpSize);
          }
          this.pushStack(frameTemp, stackOpSize);
        }
        this.setReg(5, stackOpSize, frameTemp, true);
        this.regs[4] = this._maskAddr(this.regs[4] - allocSize);
        return { count: 1 };
      }

      case 0xc9: { // LEAVE
        this.regs[4] = this._maskAddr(this.regs[5]);
        const bp = this.popStack(stackOpSize);
        this.setReg(5, stackOpSize, bp, true);
        return { count: 1 };
      }

      case 0xcc: { // INT3
        this.lastSyscall = 'int3';
        if (this.onInt) {
          const res = this.onInt(3, this);
          if (res?.status === 'EXITED') return { count: 1, status: 'EXITED', exitCode: res.exitCode ?? 0 };
          if (res?.status === 'BLOCKED') return { count: 1, status: 'BLOCKED', waitReason: res.waitReason };
          if (res?.status === 'FAULT') {
            return {
              count: 1,
              status: 'FAULT',
              fault: res.fault ?? new OmniOSError(`INT3 fault at 0x${startRip.toString(16)}`, {
                code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
                signal: 'SIGTRAP',
                details: { pc: `0x${startRip.toString(16)}`, arch: this.mode },
              }),
            };
          }
          if (res?.status === 'YIELD') return { count: 1, status: 'YIELD' };
          return { count: 1 };
        }
        throw new OmniOSError(`Breakpoint trap (INT3) at 0x${startRip.toString(16)}`, {
          code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
          signal: 'SIGTRAP',
          details: { pc: `0x${startRip.toString(16)}`, arch: this.mode },
        });
      }

      case 0xcd: { // INT imm8
        const vec = this._fetchU8(ctx);
        this.lastSyscall = `int 0x${vec.toString(16)}`;
        if (this.onInt) {
          const res = this.onInt(vec, this);
          if (res?.status === 'EXITED') return { count: 1, status: 'EXITED', exitCode: res.exitCode ?? 0 };
          if (res?.status === 'BLOCKED') return { count: 1, status: 'BLOCKED', waitReason: res.waitReason };
          if (res?.status === 'FAULT') {
            return {
              count: 1,
              status: 'FAULT',
              fault: res.fault ?? new IllegalInstructionError(`INT 0x${vec.toString(16)} fault`, {
                code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
                pc: `0x${startRip.toString(16)}`,
                opcode: `0xcd 0x${vec.toString(16)}`,
                arch: this.mode,
                pid: this.pid,
              }),
            };
          }
          if (res?.status === 'YIELD') return { count: 1, status: 'YIELD' };
          return { count: 1 };
        }
        throw new IllegalInstructionError(`Unhandled software interrupt INT 0x${vec.toString(16)}`, {
          code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
          pc: `0x${startRip.toString(16)}`,
          opcode: `0xcd 0x${vec.toString(16)}`,
          arch: this.mode,
          pid: this.pid,
        });
      }

      case 0xe0: case 0xe1: case 0xe2: { // LOOPNE / LOOPE / LOOP
        const rel = this._fetchI8(ctx);
        const cntSize = pfx.addrSize;
        const cnt = (this.getReg(1, cntSize, true) - 1n) & sizeMask(cntSize);
        this.setReg(1, cntSize, cnt, true);
        const zf = this.getFlag(RFLAGS.ZF);
        const cond = op === 0xe2 ? true : (op === 0xe1 ? zf : !zf);
        if (cnt !== 0n && cond) {
          this.rip = this._maskAddr(this.rip + BigInt(rel));
        }
        return { count: 1 };
      }

      case 0xe3: { // JRCXZ / JECXZ / JCXZ
        const rel = this._fetchI8(ctx);
        const cnt = this.getReg(1, pfx.addrSize, true);
        if (cnt === 0n) {
          this.rip = this._maskAddr(this.rip + BigInt(rel));
        }
        return { count: 1 };
      }

      case 0xe8: { // CALL rel32 / rel16
        const rel = pfx.opSizeOverride ? this._fetchI16(ctx) : this._fetchI32(ctx);
        this.pushStack(this.rip, this.ptrSize);
        this.rip = this._maskAddr(this.rip + BigInt(rel));
        return { count: 1 };
      }

      case 0xe9: { // JMP rel32 / rel16
        const rel = pfx.opSizeOverride ? this._fetchI16(ctx) : this._fetchI32(ctx);
        this.rip = this._maskAddr(this.rip + BigInt(rel));
        return { count: 1 };
      }

      case 0xeb: { // JMP rel8
        const rel = this._fetchI8(ctx);
        this.rip = this._maskAddr(this.rip + BigInt(rel));
        return { count: 1 };
      }

      case 0xf5: this.setFlag(RFLAGS.CF, !this.getFlag(RFLAGS.CF)); return { count: 1 }; // CMC
      case 0xf8: this.setFlag(RFLAGS.CF, false); return { count: 1 }; // CLC
      case 0xf9: this.setFlag(RFLAGS.CF, true); return { count: 1 };  // STC
      case 0xfc: this.setFlag(RFLAGS.DF, false); return { count: 1 }; // CLD
      case 0xfd: this.setFlag(RFLAGS.DF, true); return { count: 1 };  // STD

      case 0xf6:
      case 0xf7: { // Group 3 (TEST/NOT/NEG/MUL/IMUL/DIV/IDIV)
        const sz = op === 0xf6 ? 1 : opSize;
        const m = this._decodeModRM(ctx, pfx);
        const sub = m.regRaw;
        if (sub === 0 || sub === 1) { // TEST r/m, imm
          const immSize = sz === 1 ? 1 : (sz === 2 ? 2 : 4);
          const imm = this._fetchImmSigned(ctx, immSize);
          const lhs = this._readRM(m, sz, pfx.hasRex);
          this._aluOp(4, lhs, imm, sz);
        } else if (sub === 2) { // NOT
          const v = this._readRM(m, sz, pfx.hasRex);
          this._writeRM(m, sz, (~v) & sizeMask(sz), pfx.hasRex);
        } else if (sub === 3) { // NEG
          const v = this._readRM(m, sz, pfx.hasRex);
          const res = this._aluOp(5, 0n, v, sz);
          this.setFlag(RFLAGS.CF, (v & sizeMask(sz)) !== 0n);
          this._writeRM(m, sz, res, pfx.hasRex);
        } else if (sub === 4) { // MUL
          this._execMul(false, this._readRM(m, sz, pfx.hasRex), sz);
        } else if (sub === 5) { // IMUL
          this._execMul(true, this._readRM(m, sz, pfx.hasRex), sz);
        } else if (sub === 6) { // DIV
          this._execDiv(false, this._readRM(m, sz, pfx.hasRex), sz, startRip);
        } else if (sub === 7) { // IDIV
          this._execDiv(true, this._readRM(m, sz, pfx.hasRex), sz, startRip);
        }
        return { count: 1 };
      }

      case 0xfe: { // Group 4 (INC/DEC r/m8)
        const m = this._decodeModRM(ctx, pfx);
        if (m.regRaw === 0 || m.regRaw === 1) {
          const res = this._incDec(this._readRM(m, 1, pfx.hasRex), 1, m.regRaw === 1);
          this._writeRM(m, 1, res, pfx.hasRex);
          return { count: 1 };
        }
        throw this._unsupported(op, startRip);
      }

      case 0xff: { // Group 5 (INC/DEC/CALL/JMP/PUSH)
        const m = this._decodeModRM(ctx, pfx);
        const sub = m.regRaw;
        if (sub === 0 || sub === 1) {
          const res = this._incDec(this._readRM(m, opSize, pfx.hasRex), opSize, sub === 1);
          this._writeRM(m, opSize, res, pfx.hasRex);
          return { count: 1 };
        }
        if (sub === 2) { // CALL r/m (64-bit default in 64-bit mode!)
          const target = this._readRM(m, this.ptrSize, pfx.hasRex);
          this.pushStack(this.rip, this.ptrSize);
          this.rip = this._maskAddr(target);
          return { count: 1 };
        }
        if (sub === 4) { // JMP r/m (64-bit default in 64-bit mode!)
          const target = this._readRM(m, this.ptrSize, pfx.hasRex);
          this.rip = this._maskAddr(target);
          return { count: 1 };
        }
        if (sub === 6) { // PUSH r/m
          const val = this._readRM(m, stackOpSize, pfx.hasRex);
          this.pushStack(val, stackOpSize);
          return { count: 1 };
        }
        throw this._unsupported(op, startRip);
      }

      default:
        throw this._unsupported(op, startRip);
    }
  }

  _applySeg(addr, seg) {
    let ea = addr;
    if (seg === 0x64) ea += this.fsBase;
    else if (seg === 0x65) ea += this.gsBase;
    return this._maskAddr(ea);
  }

  _executeStringOp(op, pfx, startRip, remainingBudget) {
    const isByte = (op & 1) === 0;
    const elemSize = isByte ? 1 : pfx.opSize;
    const addrSize = pfx.addrSize;
    const stepDelta = this.getFlag(RFLAGS.DF) ? -BigInt(elemSize) : BigInt(elemSize);
    const hasRep = pfx.rep === 0xf3 || pfx.rep === 0xf2;
    const isCmpOrScas = op === 0xa6 || op === 0xa7 || op === 0xae || op === 0xaf;

    if (!hasRep) {
      this._doStringStep(op, elemSize, addrSize, stepDelta);
      return { count: 1 };
    }

    let rcx = this.getReg(1, addrSize, true);
    if (rcx === 0n) {
      return { count: 1 };
    }

    const maxIters = Math.max(1, remainingBudget);
    let iters = 0;
    while (rcx > 0n && iters < maxIters) {
      this._doStringStep(op, elemSize, addrSize, stepDelta);
      rcx -= 1n;
      iters += 1;
      this.setReg(1, addrSize, rcx, true);

      if (isCmpOrScas) {
        const zf = this.getFlag(RFLAGS.ZF);
        if (pfx.rep === 0xf3 && !zf) break; // REPE stops on ZF==0
        if (pfx.rep === 0xf2 && zf) break;  // REPNE stops on ZF==1
      }
    }

    // If RCX still > 0, rewind RIP to instruction start and yield cleanly to scheduler!
    if (rcx > 0n) {
      const stoppedEarly = isCmpOrScas && (
        (pfx.rep === 0xf3 && !this.getFlag(RFLAGS.ZF)) ||
        (pfx.rep === 0xf2 && this.getFlag(RFLAGS.ZF))
      );
      if (!stoppedEarly) {
        this.rip = startRip;
        return { count: iters, status: 'YIELD' };
      }
    }
    return { count: iters };
  }

  _doStringStep(op, elemSize, addrSize, stepDelta) {
    const addrMask = sizeMask(addrSize);
    const rsi = this.getReg(6, addrSize, true);
    const rdi = this.getReg(7, addrSize, true);

    if (op === 0xa4 || op === 0xa5) { // MOVS
      const v = this.readMem(rsi, elemSize);
      this.writeMem(rdi, elemSize, v);
      this.setReg(6, addrSize, (rsi + stepDelta) & addrMask, true);
      this.setReg(7, addrSize, (rdi + stepDelta) & addrMask, true);
    } else if (op === 0xa6 || op === 0xa7) { // CMPS
      const a = this.readMem(rsi, elemSize);
      const b = this.readMem(rdi, elemSize);
      this._aluOp(7, a, b, elemSize);
      this.setReg(6, addrSize, (rsi + stepDelta) & addrMask, true);
      this.setReg(7, addrSize, (rdi + stepDelta) & addrMask, true);
    } else if (op === 0xaa || op === 0xab) { // STOS
      const a = this.getReg(0, elemSize, true);
      this.writeMem(rdi, elemSize, a);
      this.setReg(7, addrSize, (rdi + stepDelta) & addrMask, true);
    } else if (op === 0xac || op === 0xad) { // LODS
      const v = this.readMem(rsi, elemSize);
      this.setReg(0, elemSize, v, elemSize > 1);
      this.setReg(6, addrSize, (rsi + stepDelta) & addrMask, true);
    } else if (op === 0xae || op === 0xaf) { // SCAS
      const a = this.getReg(0, elemSize, true);
      const b = this.readMem(rdi, elemSize);
      this._aluOp(7, a, b, elemSize);
      this.setReg(7, addrSize, (rdi + stepDelta) & addrMask, true);
    }
  }

  // ============================================================================
  // Two-Byte Opcodes (0x0F ...) + SSE2 Scalar/Packed
  // ============================================================================

  _execute0F(ctx, pfx) {
    const startRip = ctx.startRip;
    const op2 = this._fetchU8(ctx);
    const opSize = pfx.opSize;

    // Jcc rel32 (0F 80..8F)
    if (op2 >= 0x80 && op2 <= 0x8f) {
      const rel = pfx.opSizeOverride ? this._fetchI16(ctx) : this._fetchI32(ctx);
      if (this._evalCond(op2 & 0x0f)) {
        this.rip = this._maskAddr(this.rip + BigInt(rel));
      }
      return { count: 1 };
    }

    // CMOVcc r, r/m (0F 40..4F)
    if (op2 >= 0x40 && op2 <= 0x4f) {
      const m = this._decodeModRM(ctx, pfx);
      const src = this._readRM(m, opSize, pfx.hasRex);
      if (this._evalCond(op2 & 0x0f)) {
        this.setReg(m.reg, opSize, src, true);
      } else if (opSize === 4 && this.is64) {
        // Real x86-64 hardware zeroes upper 32 bits of 32-bit CMOVcc dest even when condition is false!
        this.regs[m.reg] &= MASK_32;
      }
      return { count: 1 };
    }

    // SETcc r/m8 (0F 90..9F)
    if (op2 >= 0x90 && op2 <= 0x9f) {
      const m = this._decodeModRM(ctx, pfx);
      this._writeRM(m, 1, this._evalCond(op2 & 0x0f) ? 1n : 0n, pfx.hasRex);
      return { count: 1 };
    }

    // BSWAP r32/r64 (0F C8..CF)
    if (op2 >= 0xc8 && op2 <= 0xcf) {
      const reg = (op2 & 7) | (pfx.rexB ? 8 : 0);
      if (opSize === 8) {
        const v = this.regs[reg];
        let out = 0n;
        for (let i = 0; i < 8; i++) {
          out = (out << 8n) | ((v >> BigInt(i * 8)) & 0xffn);
        }
        this.regs[reg] = out;
      } else {
        const v = Number(this.regs[reg] & MASK_32);
        const swapped =
          (((v & 0xff) << 24) |
            ((v & 0xff00) << 8) |
            ((v >>> 8) & 0xff00) |
            ((v >>> 24) & 0xff)) >>> 0;
        this.setReg(reg, 4, BigInt(swapped), true);
      }
      return { count: 1 };
    }

    switch (op2) {
      case 0x05: { // SYSCALL
        this.lastSyscall = `syscall(0x${this.regs[0].toString(16)})`;
        if (this.is64) {
          this.regs[1] = this.rip;    // RCX = next RIP
          this.regs[11] = this.rflags; // R11 = RFLAGS
        }
        if (this.onSyscall) {
          const res = this.onSyscall(this);
          if (res?.status === 'EXITED') return { count: 1, status: 'EXITED', exitCode: res.exitCode ?? 0 };
          if (res?.status === 'BLOCKED') return { count: 1, status: 'BLOCKED', waitReason: res.waitReason };
          if (res?.status === 'FAULT') {
            return {
              count: 1,
              status: 'FAULT',
              fault: res.fault ?? new IllegalInstructionError(`Syscall fault at 0x${startRip.toString(16)}`, {
                code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
                pc: `0x${startRip.toString(16)}`,
                opcode: '0x0f 0x05',
                arch: this.mode,
                pid: this.pid,
              }),
            };
          }
          if (res?.status === 'YIELD') return { count: 1, status: 'YIELD' };
          return { count: 1 };
        }
        throw new IllegalInstructionError('Unhandled SYSCALL (no onSyscall handler configured)', {
          code: ERROR_CODES.ENOSYS,
          pc: `0x${startRip.toString(16)}`,
          opcode: '0x0f 0x05',
          arch: this.mode,
          pid: this.pid,
        });
      }

      case 0x0b: { // UD2
        throw new IllegalInstructionError(`UD2 illegal instruction at 0x${startRip.toString(16)}`, {
          code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
          pc: `0x${startRip.toString(16)}`,
          opcode: '0x0f 0x0b',
          arch: this.mode,
          pid: this.pid,
        });
      }

      case 0x18: case 0x19: case 0x1a: case 0x1b:
      case 0x1c: case 0x1d: case 0x1e: case 0x1f: {
        // Multi-byte NOP / PREFETCH / ENDBR64 (F3 0F 1E FA)
        this._decodeModRM(ctx, pfx);
        return { count: 1 };
      }

      case 0x31: { // RDTSC
        const v = this._tscCounter;
        this.setReg(0, 4, v & MASK_32, true);
        this.setReg(2, 4, (v >> 32n) & MASK_32, true);
        return { count: 1 };
      }

      case 0xa2: { // CPUID
        const leaf = Number(this.regs[0] & MASK_32);
        if (leaf === 0) {
          this.setReg(0, 4, 1n, true);
          this.setReg(3, 4, 0x756e6547n, true); // "Genu"
          this.setReg(2, 4, 0x49656e69n, true); // "ineI"
          this.setReg(1, 4, 0x6c65746en, true); // "ntel"
        } else if (leaf === 1) {
          this.setReg(0, 4, 0x000306c3n, true);
          this.setReg(3, 4, 0x00010800n, true);
          this.setReg(1, 4, 0x00000001n, true); // SSE3
          this.setReg(2, 4, 0x078bfbffn, true); // FPU, CMOV, MMX, SSE, SSE2
        } else {
          this.setReg(0, 4, 0n, true);
          this.setReg(3, 4, 0n, true);
          this.setReg(1, 4, 0n, true);
          this.setReg(2, 4, 0n, true);
        }
        return { count: 1 };
      }

      // Bit test instructions: BT/BTS/BTR/BTC
      case 0xa3: case 0xab: case 0xb3: case 0xbb: {
        const m = this._decodeModRM(ctx, pfx);
        const bitIdxRaw = toSigned(this.getReg(m.reg, opSize, true), opSize);
        const bits = BigInt(sizeBits(opSize));
        let bitPos;
        let targetVal;
        let memAddr = null;
        if (m.isReg) {
          bitPos = ((bitIdxRaw % bits) + bits) % bits;
          targetVal = this.getReg(m.rm, opSize, true);
        } else {
          const byteShift = bitIdxRaw >= 0n
            ? (bitIdxRaw / bits)
            : -((-bitIdxRaw + bits - 1n) / bits);
          bitPos = bitIdxRaw - byteShift * bits;
          memAddr = this._maskAddr(this._resolveEA(m) + byteShift * BigInt(opSize));
          targetVal = this.readMem(memAddr, opSize);
        }
        const bitMask = 1n << bitPos;
        this.setFlag(RFLAGS.CF, (targetVal & bitMask) !== 0n);
        if (op2 !== 0xa3) {
          let nextVal = targetVal;
          if (op2 === 0xab) nextVal = targetVal | bitMask;       // BTS
          else if (op2 === 0xb3) nextVal = targetVal & ~bitMask; // BTR
          else if (op2 === 0xbb) nextVal = targetVal ^ bitMask;  // BTC
          if (m.isReg) this.setReg(m.rm, opSize, nextVal, true);
          else this.writeMem(memAddr, opSize, nextVal);
        }
        return { count: 1 };
      }

      case 0xba: { // BT/BTS/BTR/BTC r/m, imm8
        const m = this._decodeModRM(ctx, pfx);
        const imm8 = this._fetchU8(ctx);
        const bitPos = BigInt(imm8 & (sizeBits(opSize) - 1));
        const val = this._readRM(m, opSize, pfx.hasRex);
        const bitMask = 1n << bitPos;
        this.setFlag(RFLAGS.CF, (val & bitMask) !== 0n);
        if (m.regRaw === 5) this._writeRM(m, opSize, val | bitMask, pfx.hasRex);       // BTS
        else if (m.regRaw === 6) this._writeRM(m, opSize, val & ~bitMask, pfx.hasRex); // BTR
        else if (m.regRaw === 7) this._writeRM(m, opSize, val ^ bitMask, pfx.hasRex);  // BTC
        else if (m.regRaw !== 4) throw this._unsupported(0x0f00 | op2, startRip);
        return { count: 1 };
      }

      // SHLD / SHRD
      case 0xa4: case 0xa5: case 0xac: case 0xad: {
        const m = this._decodeModRM(ctx, pfx);
        const rawCount = (op2 === 0xa4 || op2 === 0xac) ? this._fetchU8(ctx) : Number(this.regs[1] & MASK_8);
        const bits = sizeBits(opSize);
        const count = rawCount & (opSize === 8 ? 0x3f : 0x1f);
        if (count === 0) return { count: 1 };
        const dst = this._readRM(m, opSize, pfx.hasRex);
        const src = this.getReg(m.reg, opSize, true);
        const mask = sizeMask(opSize);
        let res;
        if (op2 === 0xa4 || op2 === 0xa5) { // SHLD
          const eff = count % bits;
          if (count <= bits) {
            const cf = ((dst >> BigInt(bits - count)) & 1n) !== 0n;
            this.setFlag(RFLAGS.CF, cf);
            res = count === bits ? src : (((dst << BigInt(eff)) | (src >> BigInt(bits - eff))) & mask);
          } else {
            res = (src << BigInt(eff)) & mask;
          }
        } else { // SHRD
          const eff = count % bits;
          if (count <= bits) {
            const cf = ((dst >> BigInt(count - 1)) & 1n) !== 0n;
            this.setFlag(RFLAGS.CF, cf);
            res = count === bits ? src : (((dst >> BigInt(eff)) | (src << BigInt(bits - eff))) & mask);
          } else {
            res = (src >> BigInt(eff)) & mask;
          }
        }
        this._setSZP(res, opSize);
        this._writeRM(m, opSize, res, pfx.hasRex);
        return { count: 1 };
      }

      case 0xaf: { // IMUL r, r/m
        const m = this._decodeModRM(ctx, pfx);
        const a = this.getReg(m.reg, opSize, true);
        const b = this._readRM(m, opSize, pfx.hasRex);
        this.setReg(m.reg, opSize, this._imulTrunc(a, b, opSize), true);
        return { count: 1 };
      }

      case 0xb0: case 0xb1: { // CMPXCHG r/m, r
        const sz = op2 === 0xb0 ? 1 : opSize;
        const m = this._decodeModRM(ctx, pfx);
        const acc = this.getReg(0, sz, pfx.hasRex);
        const dst = this._readRM(m, sz, pfx.hasRex);
        this._aluOp(7, acc, dst, sz);
        if (acc === dst) {
          this._writeRM(m, sz, this.getReg(m.reg, sz, pfx.hasRex), pfx.hasRex);
        } else {
          this.setReg(0, sz, dst, pfx.hasRex);
        }
        return { count: 1 };
      }

      case 0xb6: { // MOVZX r, r/m8
        const m = this._decodeModRM(ctx, pfx);
        const val = this._readRM(m, 1, pfx.hasRex) & MASK_8;
        this.setReg(m.reg, opSize, val, true);
        return { count: 1 };
      }

      case 0xb7: { // MOVZX r, r/m16
        const m = this._decodeModRM(ctx, pfx);
        const val = this._readRM(m, 2, pfx.hasRex) & MASK_16;
        this.setReg(m.reg, opSize, val, true);
        return { count: 1 };
      }

      case 0xbc: { // BSF r, r/m
        const m = this._decodeModRM(ctx, pfx);
        const v = this._readRM(m, opSize, pfx.hasRex) & sizeMask(opSize);
        if (v === 0n) {
          this.setFlag(RFLAGS.ZF, true);
        } else {
          this.setFlag(RFLAGS.ZF, false);
          let bit = 0;
          let tmp = v;
          while ((tmp & 1n) === 0n) {
            tmp >>= 1n;
            bit += 1;
          }
          this.setReg(m.reg, opSize, BigInt(bit), true);
        }
        return { count: 1 };
      }

      case 0xbd: { // BSR r, r/m
        const m = this._decodeModRM(ctx, pfx);
        const v = this._readRM(m, opSize, pfx.hasRex) & sizeMask(opSize);
        if (v === 0n) {
          this.setFlag(RFLAGS.ZF, true);
        } else {
          this.setFlag(RFLAGS.ZF, false);
          let bit = sizeBits(opSize) - 1;
          while (bit > 0 && ((v >> BigInt(bit)) & 1n) === 0n) {
            bit -= 1;
          }
          this.setReg(m.reg, opSize, BigInt(bit), true);
        }
        return { count: 1 };
      }

      case 0xbe: { // MOVSX r, r/m8
        const m = this._decodeModRM(ctx, pfx);
        const val = BigInt.asIntN(8, this._readRM(m, 1, pfx.hasRex));
        this.setReg(m.reg, opSize, val & sizeMask(opSize), true);
        return { count: 1 };
      }

      case 0xbf: { // MOVSX r, r/m16
        const m = this._decodeModRM(ctx, pfx);
        const val = BigInt.asIntN(16, this._readRM(m, 2, pfx.hasRex));
        this.setReg(m.reg, opSize, val & sizeMask(opSize), true);
        return { count: 1 };
      }

      case 0xc0: case 0xc1: { // XADD r/m, r
        const sz = op2 === 0xc0 ? 1 : opSize;
        const m = this._decodeModRM(ctx, pfx);
        const dst = this._readRM(m, sz, pfx.hasRex);
        const src = this.getReg(m.reg, sz, pfx.hasRex);
        const sum = this._aluOp(0, dst, src, sz);
        this._writeRM(m, sz, sum, pfx.hasRex);
        this.setReg(m.reg, sz, dst, pfx.hasRex);
        return { count: 1 };
      }

      // ---- SSE2 Scalar & Packed Instructions ----
      case 0x10: // MOVSS/MOVSD/MOVUPS/MOVUPD xmm, xmm/m
      case 0x11: // MOVSS/MOVSD/MOVUPS/MOVUPD xmm/m, xmm
      case 0x28: // MOVAPS/MOVAPD xmm, xmm/m128
      case 0x29: // MOVAPS/MOVAPD xmm/m128, xmm
      case 0x6f: // MOVDQA/MOVDQU xmm, xmm/m128
      case 0x7f: { // MOVDQA/MOVDQU xmm/m128, xmm
        const m = this._decodeModRM(ctx, pfx);
        const isStore = op2 === 0x11 || op2 === 0x29 || op2 === 0x7f;
        if ((op2 === 0x10 || op2 === 0x11) && pfx.rep === 0xf3) { // MOVSS
          if (!isStore) {
            if (m.isReg) {
              this.setXmmF32(m.reg, this.getXmmF32(m.rm), false);
            } else {
              const raw = this.readMemBytes(this._resolveEA(m), 4);
              this.xmm[m.reg].fill(0);
              this.xmm[m.reg].set(raw, 0);
            }
          } else if (m.isReg) {
            this.setXmmF32(m.rm, this.getXmmF32(m.reg), false);
          } else {
            this.writeMemBytes(this._resolveEA(m), this.xmm[m.reg].subarray(0, 4));
          }
          return { count: 1 };
        }
        if ((op2 === 0x10 || op2 === 0x11) && pfx.rep === 0xf2) { // MOVSD
          if (!isStore) {
            if (m.isReg) {
              this.setXmmF64(m.reg, this.getXmmF64(m.rm), false);
            } else {
              const raw = this.readMemBytes(this._resolveEA(m), 8);
              this.xmm[m.reg].fill(0);
              this.xmm[m.reg].set(raw, 0);
            }
          } else if (m.isReg) {
            this.setXmmF64(m.rm, this.getXmmF64(m.reg), false);
          } else {
            this.writeMemBytes(this._resolveEA(m), this.xmm[m.reg].subarray(0, 8));
          }
          return { count: 1 };
        }
        // 128-bit MOVUPS/MOVUPD/MOVAPS/MOVAPD/MOVDQA/MOVDQU
        if (!isStore) {
          if (m.isReg) {
            this.xmm[m.reg].set(this.xmm[m.rm]);
          } else {
            this.xmm[m.reg].set(this.readMemBytes(this._resolveEA(m), 16));
          }
        } else if (m.isReg) {
          this.xmm[m.rm].set(this.xmm[m.reg]);
        } else {
          this.writeMemBytes(this._resolveEA(m), this.xmm[m.reg]);
        }
        return { count: 1 };
      }

      case 0x6e: { // MOVD/MOVQ xmm, r/m32/64
        const m = this._decodeModRM(ctx, pfx);
        const sz = pfx.rexW ? 8 : 4;
        const val = this._readRM(m, sz, pfx.hasRex);
        this.xmm[m.reg].fill(0);
        if (sz === 8) this._xmmViews[m.reg].setBigUint64(0, val, true);
        else this._xmmViews[m.reg].setUint32(0, Number(val & MASK_32), true);
        return { count: 1 };
      }

      case 0x7e: { // 66: MOVD/MOVQ r/m32/64, xmm; F3: MOVQ xmm, xmm/m64
        const m = this._decodeModRM(ctx, pfx);
        if (pfx.rep === 0xf3) {
          const val = m.isReg ? this.getXmmU64(m.rm, 0) : this.readMem(this._resolveEA(m), 8);
          this.xmm[m.reg].fill(0);
          this.setXmmU64(m.reg, 0, val);
        } else {
          const sz = pfx.rexW ? 8 : 4;
          const val = sz === 8 ? this.getXmmU64(m.reg, 0) : BigInt(this._xmmViews[m.reg].getUint32(0, true));
          this._writeRM(m, sz, val, pfx.hasRex);
        }
        return { count: 1 };
      }

      case 0xd6: { // 66 0F D6: MOVQ xmm/m64, xmm
        const m = this._decodeModRM(ctx, pfx);
        const val = this.getXmmU64(m.reg, 0);
        if (m.isReg) {
          this.xmm[m.rm].fill(0);
          this.setXmmU64(m.rm, 0, val);
        } else {
          this.writeMem(this._resolveEA(m), 8, val);
        }
        return { count: 1 };
      }

      case 0x57: // XORPS / XORPD
      case 0xef: { // PXOR
        const m = this._decodeModRM(ctx, pfx);
        const src = m.isReg ? this.xmm[m.rm] : this.readMemBytes(this._resolveEA(m), 16);
        const dst = this.xmm[m.reg];
        for (let i = 0; i < 16; i++) dst[i] ^= src[i];
        return { count: 1 };
      }

      case 0x51: // SQRTSS/SD
      case 0x58: // ADDSS/SD
      case 0x59: // MULSS/SD
      case 0x5c: // SUBSS/SD
      case 0x5d: // MINSS/SD
      case 0x5e: // DIVSS/SD
      case 0x5f: { // MAXSS/SD
        const m = this._decodeModRM(ctx, pfx);
        const isDouble = pfx.rep === 0xf2;
        const isSingle = pfx.rep === 0xf3;
        if (!isDouble && !isSingle) throw this._unsupported(0x0f00 | op2, startRip);
        const a = isDouble ? this.getXmmF64(m.reg) : this.getXmmF32(m.reg);
        let b;
        if (m.isReg) {
          b = isDouble ? this.getXmmF64(m.rm) : this.getXmmF32(m.rm);
        } else {
          const bytes = this.readMemBytes(this._resolveEA(m), isDouble ? 8 : 4);
          const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
          b = isDouble ? dv.getFloat64(0, true) : dv.getFloat32(0, true);
        }
        let res;
        if (op2 === 0x51) res = Math.sqrt(b);
        else if (op2 === 0x58) res = a + b;
        else if (op2 === 0x59) res = a * b;
        else if (op2 === 0x5c) res = a - b;
        else if (op2 === 0x5d) res = (Number.isNaN(a) || Number.isNaN(b)) ? b : (a < b ? a : b);
        else if (op2 === 0x5e) res = a / b;
        else res = (Number.isNaN(a) || Number.isNaN(b)) ? b : (a > b ? a : b);

        if (isDouble) this.setXmmF64(m.reg, res, false);
        else this.setXmmF32(m.reg, Math.fround(res), false);
        return { count: 1 };
      }

      case 0x2a: { // CVTSI2SS (F3) / CVTSI2SD (F2)
        const m = this._decodeModRM(ctx, pfx);
        const sz = pfx.rexW ? 8 : 4;
        const iv = Number(toSigned(this._readRM(m, sz, pfx.hasRex), sz));
        if (pfx.rep === 0xf2) this.setXmmF64(m.reg, iv, false);
        else if (pfx.rep === 0xf3) this.setXmmF32(m.reg, Math.fround(iv), false);
        else throw this._unsupported(0x0f2a, startRip);
        return { count: 1 };
      }

      case 0x2c: // CVTTSS2SI / CVTTSD2SI (truncate)
      case 0x2d: { // CVTSS2SI / CVTSD2SI (round)
        const m = this._decodeModRM(ctx, pfx);
        const isDouble = pfx.rep === 0xf2;
        let fv;
        if (m.isReg) {
          fv = isDouble ? this.getXmmF64(m.rm) : this.getXmmF32(m.rm);
        } else {
          const bytes = this.readMemBytes(this._resolveEA(m), isDouble ? 8 : 4);
          const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
          fv = isDouble ? dv.getFloat64(0, true) : dv.getFloat32(0, true);
        }
        const sz = pfx.rexW ? 8 : 4;
        let iv;
        if (!Number.isFinite(fv)) {
          iv = sz === 8 ? -0x8000000000000000n : -0x80000000n;
        } else {
          const rounded = op2 === 0x2c ? Math.trunc(fv) : Math.round(fv);
          iv = BigInt(rounded);
        }
        this.setReg(m.reg, sz, iv & sizeMask(sz), true);
        return { count: 1 };
      }

      case 0x5a: { // CVTSS2SD (F3) / CVTSD2SS (F2)
        const m = this._decodeModRM(ctx, pfx);
        if (pfx.rep === 0xf3) {
          let fv;
          if (m.isReg) fv = this.getXmmF32(m.rm);
          else {
            const b = this.readMemBytes(this._resolveEA(m), 4);
            fv = new DataView(b.buffer, b.byteOffset, 4).getFloat32(0, true);
          }
          this.setXmmF64(m.reg, fv, false);
        } else if (pfx.rep === 0xf2) {
          let fv;
          if (m.isReg) fv = this.getXmmF64(m.rm);
          else {
            const b = this.readMemBytes(this._resolveEA(m), 8);
            fv = new DataView(b.buffer, b.byteOffset, 8).getFloat64(0, true);
          }
          this.setXmmF32(m.reg, Math.fround(fv), false);
        } else {
          throw this._unsupported(0x0f5a, startRip);
        }
        return { count: 1 };
      }

      case 0x2e: // UCOMISS / UCOMISD
      case 0x2f: { // COMISS / COMISD
        const m = this._decodeModRM(ctx, pfx);
        const isDouble = pfx.opSizeOverride;
        const a = isDouble ? this.getXmmF64(m.reg) : this.getXmmF32(m.reg);
        let b;
        if (m.isReg) {
          b = isDouble ? this.getXmmF64(m.rm) : this.getXmmF32(m.rm);
        } else {
          const bytes = this.readMemBytes(this._resolveEA(m), isDouble ? 8 : 4);
          const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
          b = isDouble ? dv.getFloat64(0, true) : dv.getFloat32(0, true);
        }
        this.setFlag(RFLAGS.OF, false);
        this.setFlag(RFLAGS.SF, false);
        this.setFlag(RFLAGS.AF, false);
        if (Number.isNaN(a) || Number.isNaN(b)) {
          this.setFlag(RFLAGS.ZF, true);
          this.setFlag(RFLAGS.PF, true);
          this.setFlag(RFLAGS.CF, true);
        } else if (a > b) {
          this.setFlag(RFLAGS.ZF, false);
          this.setFlag(RFLAGS.PF, false);
          this.setFlag(RFLAGS.CF, false);
        } else if (a < b) {
          this.setFlag(RFLAGS.ZF, false);
          this.setFlag(RFLAGS.PF, false);
          this.setFlag(RFLAGS.CF, true);
        } else {
          this.setFlag(RFLAGS.ZF, true);
          this.setFlag(RFLAGS.PF, false);
          this.setFlag(RFLAGS.CF, false);
        }
        return { count: 1 };
      }

      default:
        throw this._unsupported(0x0f00 | op2, startRip);
    }
  }

  _unsupported(opcode, pc) {
    return new UnsupportedOpcodeError(
      `Unsupported ${this.mode} opcode 0x${opcode.toString(16)} at 0x${pc.toString(16)}`,
      {
        code: ERROR_CODES.E_UNSUPPORTED_OPCODE,
        pc: `0x${pc.toString(16)}`,
        opcode: `0x${opcode.toString(16)}`,
        arch: this.mode,
        pid: this.pid,
      }
    );
  }

  // ============================================================================
  // Re-entrant Synchronous Callback Invocation (Win32 WNDPROC, etc.)
  // ============================================================================

  isInStep() {
    return this._topStepState !== null;
  }

  enterCooperativeCallback(
    va,
    args = [],
    { abi = null, fromThunk = true, stackCleanupBytes = 0, onReturn = null } = {}
  ) {
    const totalDepth = this._callDepth + this._callbackFrames.length;
    if (totalDepth >= this.maxCallDepth) {
      throw new OmniOSError(
        `Maximum re-entrant call depth (${this.maxCallDepth}) exceeded`,
        {
          code: 'STATUS_STACK_OVERFLOW',
          signal: 'SIGSEGV',
          details: {
            callDepth: totalDepth,
            target: `0x${toBigIntVal(va).toString(16)}`,
            win32Status: WIN32_ERROR.STATUS_STACK_OVERFLOW,
          },
        }
      );
    }

    const nextCalls =
      this._callbackFrames.length === 0 ? 1 : (this._callbackTree?.calls ?? 0) + 1;
    const maxCalls =
      this._callbackFrames.length === 0
        ? this.maxCallbackTreeCalls
        : (this._callbackTree?.maxCalls ?? this.maxCallbackTreeCalls);
    if (nextCalls > maxCalls) {
      throw new QuotaExceededError(
        `Re-entrant callback tree exceeded maximum nested invocations (${maxCalls})`,
        {
          code: ERROR_CODES.E_CPU_QUOTA,
          quotaType: 'cpu',
          limit: maxCalls,
          actual: nextCalls,
          pid: this.pid,
          signal: 'SIGXCPU',
        }
      );
    }

    let callerRip;
    if (fromThunk) {
      callerRip = this._maskAddr(this.popStack(this.ptrSize));
      if (stackCleanupBytes > 0) {
        this.regs[4] = this._maskAddr(this.regs[4] + BigInt(stackCleanupBytes));
      }
    } else {
      callerRip = this._maskAddr(this.rip);
    }

    const savedRegs = new BigUint64Array(this.regs);
    const savedRflags = this.rflags;
    const savedXmm = this.xmm.map((buf) => buf.slice());

    const frameIdx = this._callbackFrames.length + 1;
    const sentinel = this.is64
      ? (0x7fffffffe400n + BigInt(frameIdx * 0x10))
      : (0x7fffe400n + BigInt(frameIdx * 0x10));

    const resolvedAbi = abi ?? (this.is64 ? 'win64' : 'stdcall');
    const bigArgs = args.map((a) => toBigIntVal(a));

    // Reserve 16-byte aligned stack frame below caller RSP/ESP (matches callFunction ABI)
    let sp = this._maskAddr(this.regs[4] - 0x40n);
    sp &= ~0xfn;

    if (resolvedAbi === 'win64') {
      const extraArgs = bigArgs.length > 4 ? bigArgs.slice(4) : [];
      if ((extraArgs.length & 1) === 1) {
        sp = this._maskAddr(sp - 8n);
      }
      for (let i = extraArgs.length - 1; i >= 0; i--) {
        sp = this._maskAddr(sp - 8n);
        this.writeMem(sp, 8, extraArgs[i]);
      }
      // 32-byte mandatory Win64 shadow space
      sp = this._maskAddr(sp - 32n);
      this.writeMemBytes(sp, new Uint8Array(32));
      // Push return sentinel (callee sees RSP % 16 === 8, [RSP] === sentinel)
      sp = this._maskAddr(sp - 8n);
      this.writeMem(sp, 8, sentinel);

      this.regs[4] = sp;
      this.regs[1] = bigArgs[0] ?? 0n; // RCX
      this.regs[2] = bigArgs[1] ?? 0n; // RDX
      this.regs[8] = bigArgs[2] ?? 0n; // R8
      this.regs[9] = bigArgs[3] ?? 0n; // R9
    } else if (resolvedAbi === 'sysv64') {
      const extraArgs = bigArgs.length > 6 ? bigArgs.slice(6) : [];
      if ((extraArgs.length & 1) === 1) {
        sp = this._maskAddr(sp - 8n);
      }
      for (let i = extraArgs.length - 1; i >= 0; i--) {
        sp = this._maskAddr(sp - 8n);
        this.writeMem(sp, 8, extraArgs[i]);
      }
      sp = this._maskAddr(sp - 8n);
      this.writeMem(sp, 8, sentinel);

      this.regs[4] = sp;
      this.regs[7] = bigArgs[0] ?? 0n; // RDI
      this.regs[6] = bigArgs[1] ?? 0n; // RSI
      this.regs[2] = bigArgs[2] ?? 0n; // RDX
      this.regs[1] = bigArgs[3] ?? 0n; // RCX
      this.regs[8] = bigArgs[4] ?? 0n; // R8
      this.regs[9] = bigArgs[5] ?? 0n; // R9
    } else {
      // Win32 x86 __stdcall / __cdecl: push args right-to-left (4B each), then 4B sentinel
      for (let i = bigArgs.length - 1; i >= 0; i--) {
        sp = this._maskAddr(sp - 4n);
        this.writeMem(sp, 4, bigArgs[i] & MASK_32);
      }
      sp = this._maskAddr(sp - 4n);
      this.writeMem(sp, 4, sentinel & MASK_32);
      this.regs[4] = sp;
    }

    const targetVa = this._maskAddr(toBigIntVal(va));
    if (this._callbackFrames.length === 0) {
      this._callbackTree = {
        startTotal: this.totalInstructions,
        calls: 1,
        maxCalls,
        entryVa: targetVa,
      };
    } else if (this._callbackTree !== null) {
      this._callbackTree.calls = nextCalls;
    }

    this._callbackReturnSentinels.add(sentinel);
    this._callbackFrames.push({
      sentinel,
      callerRip,
      savedRegs,
      savedRflags,
      savedXmm,
      onReturn: typeof onReturn === 'function' ? onReturn : null,
      targetVa,
    });

    this.rip = targetVa;
    return { status: 'CALLBACK_REDIRECT' };
  }

  _unwindCallbackReturn() {
    const curRip = this._maskAddr(this.rip);
    if (!this._callbackReturnSentinels.has(curRip)) {
      return false;
    }
    const top =
      this._callbackFrames.length > 0
        ? this._callbackFrames[this._callbackFrames.length - 1]
        : null;
    if (!top || top.sentinel !== curRip) {
      throw new IllegalInstructionError(
        `Mismatched callback return sentinel 0x${curRip.toString(16)}`,
        {
          code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
          pc: `0x${curRip.toString(16)}`,
          arch: this.mode,
          pid: this.pid,
        }
      );
    }

    const retVal = this.is64 ? this.regs[0] : (this.regs[0] & MASK_32);
    this._callbackFrames.pop();
    this._callbackReturnSentinels.delete(top.sentinel);
    if (this._callbackFrames.length === 0) {
      this._callbackTree = null;
    }

    this.regs.set(top.savedRegs);
    this.rip = top.callerRip;
    this.rflags = top.savedRflags;
    for (let i = 0; i < 16; i++) {
      this.xmm[i].set(top.savedXmm[i]);
    }

    if (top.onReturn) {
      const cont = top.onReturn(retVal, this);
      if (cont && typeof cont === 'object' && cont.status === 'CALLBACK_REDIRECT') {
        return true;
      }
      if (cont !== undefined) {
        const finalRet = typeof cont === 'bigint' ? cont : BigInt(Math.trunc(Number(cont)));
        this.setReg64(0, this.is64 ? BigInt.asUintN(64, finalRet) : BigInt.asUintN(32, finalRet));
        return true;
      }
    }

    this.setReg64(0, retVal);
    return true;
  }

  callFunction(va, args = [], { abi = null, maxInstructions = 50000 } = {}) {
    const totalDepth = this._callDepth + this._callbackFrames.length;
    if (totalDepth >= this.maxCallDepth) {
      throw new OmniOSError(
        `Maximum re-entrant call depth (${this.maxCallDepth}) exceeded`,
        {
          code: 'STATUS_STACK_OVERFLOW',
          signal: 'SIGSEGV',
          details: {
            callDepth: totalDepth,
            target: `0x${toBigIntVal(va).toString(16)}`,
            win32Status: WIN32_ERROR.STATUS_STACK_OVERFLOW,
          },
        }
      );
    }

    const isOutermost = this._nestedBudget === null;
    let budgetObj = this._nestedBudget;
    if (isOutermost) {
      let cap = Number.isFinite(maxInstructions) ? Math.max(0, Math.trunc(maxInstructions)) : 50000;
      if (this._topStepState !== null) {
        if (typeof this.getNestedInstructionCap === 'function') {
          const dynCap = this.getNestedInstructionCap(
            this._topStepState.executed,
            this._topStepState.maxSteps
          );
          if (typeof dynCap === 'number' && Number.isFinite(dynCap)) {
            cap = Math.min(cap, Math.max(0, Math.trunc(dynCap)));
          }
        } else {
          const stepRem = Math.max(0, this._topStepState.maxSteps - this._topStepState.executed);
          cap = Math.min(cap, stepRem);
        }
      }
      budgetObj = {
        startTotal: this.totalInstructions,
        limit: cap,
        exhausted: false,
      };
      this._nestedBudget = budgetObj;
    }

    const resolvedAbi = abi ?? (this.is64 ? 'win64' : 'stdcall');
    const savedRegs = new BigUint64Array(this.regs);
    const savedRip = this.rip;
    const savedRflags = this.rflags;
    const savedXmm = this.xmm.map((buf) => buf.slice());
    const savedCallbackFramesLen = this._callbackFrames.length;
    const savedCallbackTree = this._callbackTree;

    this._callDepth += 1;
    const sentinel = this.is64
      ? (0x7fffffffe000n + BigInt(this._callDepth * 0x10))
      : (0x7fffe000n + BigInt(this._callDepth * 0x10));
    this._callReturnSentinels.add(sentinel);

    const bigArgs = args.map((a) => toBigIntVal(a));

    try {
      // Reserve 16-byte aligned stack frame below current RSP/ESP
      let sp = this._maskAddr(this.regs[4] - 0x40n);
      sp &= ~0xfn; // 16-byte align

      if (resolvedAbi === 'win64') {
        const extraArgs = bigArgs.length > 4 ? bigArgs.slice(4) : [];
        // Keep RSP % 16 === 0 before pushing return address (so callee sees RSP % 16 === 8)
        if ((extraArgs.length & 1) === 1) {
          sp = this._maskAddr(sp - 8n);
        }
        for (let i = extraArgs.length - 1; i >= 0; i--) {
          sp = this._maskAddr(sp - 8n);
          this.writeMem(sp, 8, extraArgs[i]);
        }
        // 32-byte mandatory Win64 shadow space
        sp = this._maskAddr(sp - 32n);
        this.writeMemBytes(sp, new Uint8Array(32));
        // Push return sentinel
        sp = this._maskAddr(sp - 8n);
        this.writeMem(sp, 8, sentinel);

        this.regs[4] = sp;
        this.regs[1] = bigArgs[0] ?? 0n; // RCX
        this.regs[2] = bigArgs[1] ?? 0n; // RDX
        this.regs[8] = bigArgs[2] ?? 0n; // R8
        this.regs[9] = bigArgs[3] ?? 0n; // R9
      } else if (resolvedAbi === 'sysv64') {
        const extraArgs = bigArgs.length > 6 ? bigArgs.slice(6) : [];
        if ((extraArgs.length & 1) === 1) {
          sp = this._maskAddr(sp - 8n);
        }
        for (let i = extraArgs.length - 1; i >= 0; i--) {
          sp = this._maskAddr(sp - 8n);
          this.writeMem(sp, 8, extraArgs[i]);
        }
        sp = this._maskAddr(sp - 8n);
        this.writeMem(sp, 8, sentinel);

        this.regs[4] = sp;
        this.regs[7] = bigArgs[0] ?? 0n; // RDI
        this.regs[6] = bigArgs[1] ?? 0n; // RSI
        this.regs[2] = bigArgs[2] ?? 0n; // RDX
        this.regs[1] = bigArgs[3] ?? 0n; // RCX
        this.regs[8] = bigArgs[4] ?? 0n; // R8
        this.regs[9] = bigArgs[5] ?? 0n; // R9
      } else {
        // Win32 x86 __stdcall or __cdecl: push args right-to-left (4 bytes each), then return sentinel
        for (let i = bigArgs.length - 1; i >= 0; i--) {
          sp = this._maskAddr(sp - 4n);
          this.writeMem(sp, 4, bigArgs[i] & MASK_32);
        }
        sp = this._maskAddr(sp - 4n);
        this.writeMem(sp, 4, sentinel & MASK_32);
        this.regs[4] = sp;
      }

      this.rip = this._maskAddr(toBigIntVal(va));

      const callStartTotal = this.totalInstructions;
      while (true) {
        const usedInTree = this.totalInstructions - budgetObj.startTotal;
        const remInTree = budgetObj.limit - usedInTree;
        if (remInTree <= 0) {
          budgetObj.exhausted = true;
          break;
        }

        const res = this.step(remInTree);
        const totalExec = this.totalInstructions - callStartTotal;

        if (res.status === 'RETURNED') {
          const curRip = this._maskAddr(this.rip);
          if (curRip === sentinel) {
            const returnValue = this.is64 ? this.regs[0] : (this.regs[0] & MASK_32);
            return {
              returnValue,
              instructionsExecuted: totalExec,
              exited: false,
              exitCode: 0,
            };
          }
          throw new IllegalInstructionError(
            `Mismatched callFunction return sentinel 0x${curRip.toString(16)} (expected 0x${sentinel.toString(16)})`,
            {
              code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
              pc: `0x${curRip.toString(16)}`,
              arch: this.mode,
              pid: this.pid,
            }
          );
        }
        if (res.status === 'EXITED') {
          return {
            returnValue: this.is64 ? this.regs[0] : (this.regs[0] & MASK_32),
            instructionsExecuted: totalExec,
            exited: true,
            exitCode: res.exitCode ?? 0,
          };
        }
        if (res.status === 'FAULT') {
          throw res.fault;
        }
        if (res.status === 'BLOCKED') {
          break;
        }
        if (res.status === 'YIELD') {
          const curRip = this._maskAddr(this.rip);
          if (curRip === sentinel) {
            const returnValue = this.is64 ? this.regs[0] : (this.regs[0] & MASK_32);
            return {
              returnValue,
              instructionsExecuted: totalExec,
              exited: false,
              exitCode: 0,
            };
          }
          if (this.totalInstructions - budgetObj.startTotal >= budgetObj.limit) {
            budgetObj.exhausted = true;
            break;
          }
          if (res.instructionsExecuted === 0) {
            throw new IllegalInstructionError(
              `Re-entrant callFunction(0x${toBigIntVal(va).toString(16)}) made zero forward progress`,
              {
                code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
                pc: `0x${this._maskAddr(this.rip).toString(16)}`,
                arch: this.mode,
                pid: this.pid,
              }
            );
          }
        }
      }

      if (this._maskAddr(this.rip) === sentinel) {
        const returnValue = this.is64 ? this.regs[0] : (this.regs[0] & MASK_32);
        return {
          returnValue,
          instructionsExecuted: this.totalInstructions - callStartTotal,
          exited: false,
          exitCode: 0,
        };
      }

      budgetObj.exhausted = true;
      throw new QuotaExceededError(
        `Re-entrant callFunction(0x${toBigIntVal(va).toString(16)}) exceeded cumulative instruction budget (${budgetObj.limit})`,
        {
          code: ERROR_CODES.E_CPU_QUOTA,
          quotaType: 'cpu',
          limit: budgetObj.limit,
          actual: this.totalInstructions - budgetObj.startTotal,
          pid: this.pid,
          signal: 'SIGXCPU',
        }
      );
    } finally {
      if (isOutermost) {
        this._nestedBudget = null;
      }
      while (this._callbackFrames.length > savedCallbackFramesLen) {
        const dropped = this._callbackFrames.pop();
        this._callbackReturnSentinels.delete(dropped.sentinel);
      }
      if (this._callbackFrames.length === 0) {
        this._callbackTree = null;
      } else if (savedCallbackTree !== null) {
        this._callbackTree = savedCallbackTree;
      }
      this._callReturnSentinels.delete(sentinel);
      this._callDepth -= 1;
      this.regs.set(savedRegs);
      this.rip = savedRip;
      this.rflags = savedRflags;
      for (let i = 0; i < 16; i++) {
        this.xmm[i].set(savedXmm[i]);
      }
    }
  }

  // ============================================================================
  // Debug Snapshot (Contract 5)
  // ============================================================================

  getDebugState() {
    const registers = {};
    const names = this.is64 ? REG64_NAMES : REG32_NAMES;
    for (let i = 0; i < (this.is64 ? 16 : 8); i++) {
      const v = this.is64 ? this.regs[i] : (this.regs[i] & MASK_32);
      registers[names[i]] = `0x${v.toString(16)}`;
    }
    const sp = this.is64 ? this.regs[4] : (this.regs[4] & MASK_32);
    const stackTop = [];
    for (let i = 0; i < 4; i++) {
      try {
        const val = this.readMem(this._maskAddr(sp + BigInt(i * this.ptrSize)), this.ptrSize);
        stackTop.push(`0x${val.toString(16)}`);
      } catch (err) {
        void err;
        break;
      }
    }
    return {
      arch: this.mode,
      pc: `0x${this._maskAddr(this.rip).toString(16)}`,
      sp: `0x${sp.toString(16)}`,
      registers,
      flags: {
        CF: this.getFlag(RFLAGS.CF),
        PF: this.getFlag(RFLAGS.PF),
        AF: this.getFlag(RFLAGS.AF),
        ZF: this.getFlag(RFLAGS.ZF),
        SF: this.getFlag(RFLAGS.SF),
        OF: this.getFlag(RFLAGS.OF),
        DF: this.getFlag(RFLAGS.DF),
      },
      rflags: `0x${this.rflags.toString(16)}`,
      instructionsExecuted: this.totalInstructions,
      lastSyscall: this.lastSyscall,
      stackTop,
    };
  }
}

export function createX86_64Cpu(opts = {}) {
  return new X86_64Cpu({ ...opts, mode: 'x86_64' });
}

export function createX86Cpu(opts = {}) {
  return new X86_64Cpu({ ...opts, mode: 'x86' });
}

export function registerX86Cpu(registry) {
  if (!registry || typeof registry.register !== 'function') {
    throw new OmniOSError('registerX86Cpu requires a valid CpuRegistry', {
      code: ERROR_CODES.EINVAL,
    });
  }
  registry.register('x86_64', createX86_64Cpu);
  registry.register('x86', createX86Cpu);
  return registry;
}
