/**
 * OmniOS Pure-JS Universal WebAssembly (`\0asm` v1) & `.uapp` SDK Builder (`F-059`)
 * Zero external dependencies. Emits standards-compliant WebAssembly 1.0 MVP bytecode
 * verified via `WebAssembly.validate()` and packages deterministic `.uapp` ZIP archives
 * with exact root `omnios.manifest.json` + `app.wasm`.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BinaryWriter, encodeUleb128, encodeSleb128 } from '../os/common/binary.mjs';
import { FormatError, ERROR_CODES } from '../os/common/errors.mjs';
import { createZip } from '../os/pkg/zip.mjs';
import { hashEventTarget } from '../os/runtimes/universal/wasm-runtime.mjs';

const TEXT_ENCODER = new TextEncoder();

export const WASM_TYPES = Object.freeze({
  i32: 0x7f,
  i64: 0x7e,
  f32: 0x7d,
  f64: 0x7c,
  funcref: 0x70,
  func: 0x60,
  void: 0x40,
});

export const WASM_OPCODES = Object.freeze({
  unreachable: 0x00,
  nop: 0x01,
  block: 0x02,
  loop: 0x03,
  if: 0x04,
  else: 0x05,
  end: 0x0b,
  br: 0x0c,
  br_if: 0x0d,
  return: 0x0f,
  call: 0x10,
  drop: 0x1a,
  select: 0x1b,

  local_get: 0x20,
  local_set: 0x21,
  local_tee: 0x22,
  global_get: 0x23,
  global_set: 0x24,

  i32_load: 0x28,
  i64_load: 0x29,
  i32_load8_s: 0x2c,
  i32_load8_u: 0x2d,
  i32_load16_u: 0x2f,
  i32_store: 0x36,
  i64_store: 0x37,
  i32_store8: 0x3a,
  i32_store16: 0x3b,
  memory_size: 0x3f,
  memory_grow: 0x40,

  i32_const: 0x41,
  i64_const: 0x42,
  f32_const: 0x43,
  f64_const: 0x44,

  i32_eqz: 0x45,
  i32_eq: 0x46,
  i32_ne: 0x47,
  i32_lt_s: 0x48,
  i32_lt_u: 0x49,
  i32_gt_s: 0x4a,
  i32_gt_u: 0x4b,
  i32_le_s: 0x4c,
  i32_le_u: 0x4d,
  i32_ge_s: 0x4e,
  i32_ge_u: 0x4f,

  i64_eqz: 0x50,
  i64_eq: 0x51,
  i64_ne: 0x52,

  i32_add: 0x6a,
  i32_sub: 0x6b,
  i32_mul: 0x6c,
  i32_div_s: 0x6d,
  i32_div_u: 0x6e,
  i32_rem_s: 0x6f,
  i32_rem_u: 0x70,
  i32_and: 0x71,
  i32_or: 0x72,
  i32_xor: 0x73,
  i32_shl: 0x74,
  i32_shr_s: 0x75,
  i32_shr_u: 0x76,

  i64_add: 0x7c,
  i64_sub: 0x7d,
  i64_mul: 0x7e,
  i64_div_u: 0x80,
  i64_rem_u: 0x82,

  i32_wrap_i64: 0xa7,
  i64_extend_i32_s: 0xac,
  i64_extend_i32_u: 0xad,
});

const EXPORT_KIND = Object.freeze({
  func: 0x00,
  table: 0x01,
  memory: 0x02,
  global: 0x03,
});

function encodeSleb128_64(value) {
  let v = typeof value === 'bigint' ? BigInt.asIntN(64, value) : BigInt.asIntN(64, BigInt(Math.trunc(value)));
  const out = [];
  let more = true;
  while (more) {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if ((v === 0n && (byte & 0x40) === 0) || (v === -1n && (byte & 0x40) !== 0)) {
      more = false;
    } else {
      byte |= 0x80;
    }
    out.push(byte);
  }
  return new Uint8Array(out);
}

function encodeName(str) {
  const bytes = TEXT_ENCODER.encode(str);
  const w = new BinaryWriter({ initialCapacity: bytes.byteLength + 5 });
  w.bytes(encodeUleb128(bytes.byteLength)).bytes(bytes);
  return w.toUint8Array();
}

function encodeSection(sectionId, payload) {
  const w = new BinaryWriter({ initialCapacity: payload.byteLength + 8 });
  w.u8(sectionId).bytes(encodeUleb128(payload.byteLength)).bytes(payload);
  return w.toUint8Array();
}

/**
 * Fluent WebAssembly 1.0 MVP instruction sequence builder.
 */
export class WasmCodeBuilder {
  constructor() {
    this._w = new BinaryWriter({ initialCapacity: 128, littleEndian: true });
  }

  raw(bytes) {
    this._w.bytes(bytes);
    return this;
  }

  op(opcode) {
    this._w.u8(opcode);
    return this;
  }

  unreachable() { return this.op(WASM_OPCODES.unreachable); }
  nop() { return this.op(WASM_OPCODES.nop); }
  block(blockType = WASM_TYPES.void) { this._w.u8(WASM_OPCODES.block).u8(blockType); return this; }
  loop(blockType = WASM_TYPES.void) { this._w.u8(WASM_OPCODES.loop).u8(blockType); return this; }
  if_(blockType = WASM_TYPES.void) { this._w.u8(WASM_OPCODES.if).u8(blockType); return this; }
  else_() { return this.op(WASM_OPCODES.else); }
  end() { return this.op(WASM_OPCODES.end); }
  br(depth) { this._w.u8(WASM_OPCODES.br).bytes(encodeUleb128(depth)); return this; }
  brIf(depth) { this._w.u8(WASM_OPCODES.br_if).bytes(encodeUleb128(depth)); return this; }
  ret() { return this.op(WASM_OPCODES.return); }
  call(funcIdx) { this._w.u8(WASM_OPCODES.call).bytes(encodeUleb128(funcIdx)); return this; }
  drop() { return this.op(WASM_OPCODES.drop); }
  select() { return this.op(WASM_OPCODES.select); }

  localGet(idx) { this._w.u8(WASM_OPCODES.local_get).bytes(encodeUleb128(idx)); return this; }
  localSet(idx) { this._w.u8(WASM_OPCODES.local_set).bytes(encodeUleb128(idx)); return this; }
  localTee(idx) { this._w.u8(WASM_OPCODES.local_tee).bytes(encodeUleb128(idx)); return this; }
  globalGet(idx) { this._w.u8(WASM_OPCODES.global_get).bytes(encodeUleb128(idx)); return this; }
  globalSet(idx) { this._w.u8(WASM_OPCODES.global_set).bytes(encodeUleb128(idx)); return this; }

  i32Load(offset = 0, align = 2) {
    this._w.u8(WASM_OPCODES.i32_load).bytes(encodeUleb128(align)).bytes(encodeUleb128(offset));
    return this;
  }
  i64Load(offset = 0, align = 3) {
    this._w.u8(WASM_OPCODES.i64_load).bytes(encodeUleb128(align)).bytes(encodeUleb128(offset));
    return this;
  }
  i32Load8U(offset = 0, align = 0) {
    this._w.u8(WASM_OPCODES.i32_load8_u).bytes(encodeUleb128(align)).bytes(encodeUleb128(offset));
    return this;
  }
  i32Store(offset = 0, align = 2) {
    this._w.u8(WASM_OPCODES.i32_store).bytes(encodeUleb128(align)).bytes(encodeUleb128(offset));
    return this;
  }
  i64Store(offset = 0, align = 3) {
    this._w.u8(WASM_OPCODES.i64_store).bytes(encodeUleb128(align)).bytes(encodeUleb128(offset));
    return this;
  }
  i32Store8(offset = 0, align = 0) {
    this._w.u8(WASM_OPCODES.i32_store8).bytes(encodeUleb128(align)).bytes(encodeUleb128(offset));
    return this;
  }

  i32Const(val) {
    this._w.u8(WASM_OPCODES.i32_const).bytes(encodeSleb128(val | 0));
    return this;
  }
  i64Const(val) {
    this._w.u8(WASM_OPCODES.i64_const).bytes(encodeSleb128_64(val));
    return this;
  }
  f32Const(val) {
    this._w.u8(WASM_OPCODES.f32_const).f32le(val);
    return this;
  }
  f64Const(val) {
    this._w.u8(WASM_OPCODES.f64_const).f64le(val);
    return this;
  }

  i32Eqz() { return this.op(WASM_OPCODES.i32_eqz); }
  i32Eq() { return this.op(WASM_OPCODES.i32_eq); }
  i32Ne() { return this.op(WASM_OPCODES.i32_ne); }
  i32LtS() { return this.op(WASM_OPCODES.i32_lt_s); }
  i32LtU() { return this.op(WASM_OPCODES.i32_lt_u); }
  i32GtS() { return this.op(WASM_OPCODES.i32_gt_s); }
  i32GtU() { return this.op(WASM_OPCODES.i32_gt_u); }
  i32LeS() { return this.op(WASM_OPCODES.i32_le_s); }
  i32LeU() { return this.op(WASM_OPCODES.i32_le_u); }
  i32GeS() { return this.op(WASM_OPCODES.i32_ge_s); }
  i32GeU() { return this.op(WASM_OPCODES.i32_ge_u); }

  i64Eqz() { return this.op(WASM_OPCODES.i64_eqz); }
  i64Eq() { return this.op(WASM_OPCODES.i64_eq); }
  i64Ne() { return this.op(WASM_OPCODES.i64_ne); }

  i32Add() { return this.op(WASM_OPCODES.i32_add); }
  i32Sub() { return this.op(WASM_OPCODES.i32_sub); }
  i32Mul() { return this.op(WASM_OPCODES.i32_mul); }
  i32DivS() { return this.op(WASM_OPCODES.i32_div_s); }
  i32DivU() { return this.op(WASM_OPCODES.i32_div_u); }
  i32RemS() { return this.op(WASM_OPCODES.i32_rem_s); }
  i32RemU() { return this.op(WASM_OPCODES.i32_rem_u); }
  i32And() { return this.op(WASM_OPCODES.i32_and); }
  i32Or() { return this.op(WASM_OPCODES.i32_or); }
  i32Xor() { return this.op(WASM_OPCODES.i32_xor); }
  i32Shl() { return this.op(WASM_OPCODES.i32_shl); }
  i32ShrS() { return this.op(WASM_OPCODES.i32_shr_s); }
  i32ShrU() { return this.op(WASM_OPCODES.i32_shr_u); }

  i64Add() { return this.op(WASM_OPCODES.i64_add); }
  i64Sub() { return this.op(WASM_OPCODES.i64_sub); }
  i64Mul() { return this.op(WASM_OPCODES.i64_mul); }
  i64DivU() { return this.op(WASM_OPCODES.i64_div_u); }
  i64RemU() { return this.op(WASM_OPCODES.i64_rem_u); }

  i32WrapI64() { return this.op(WASM_OPCODES.i32_wrap_i64); }
  i64ExtendI32U() { return this.op(WASM_OPCODES.i64_extend_i32_u); }

  toBytes() {
    return this._w.toUint8Array();
  }
}

/**
 * Pure-JS WebAssembly 1.0 (`\0asm` v1) Module Builder.
 * Emits Type, Import, Function, Memory, Global, Export, Code, Data, and Custom sections.
 */
export class WasmModuleBuilder {
  constructor({ dataBaseOffset = 0x1000 } = {}) {
    this._types = [];
    this._typeKeyToIdx = new Map();
    this._imports = [];
    this._importedFuncCount = 0;
    this._functions = [];
    this._memory = null;
    this._globals = [];
    this._exports = [];
    this._startFunc = null;
    this._dataSegments = [];
    this._customSections = [];
    this._dataCursor = dataBaseOffset;
  }

  addType(params = [], results = []) {
    const key = `${params.join(',')}=>${results.join(',')}`;
    if (this._typeKeyToIdx.has(key)) {
      return this._typeKeyToIdx.get(key);
    }
    const idx = this._types.length;
    this._types.push({ params: [...params], results: [...results] });
    this._typeKeyToIdx.set(key, idx);
    return idx;
  }

  addImportFunc(moduleName, fieldName, params = [], results = []) {
    if (this._functions.length > 0) {
      throw new FormatError('All function imports must be added before defined functions', {
        code: ERROR_CODES.EINVAL,
        format: 'wasm',
      });
    }
    const typeIdx = this.addType(params, results);
    const funcIdx = this._importedFuncCount;
    this._imports.push({
      module: moduleName,
      name: fieldName,
      kind: 0x00,
      typeIdx,
    });
    this._importedFuncCount += 1;
    return funcIdx;
  }

  setMemory(minPages = 1, maxPages = null, exportName = 'memory') {
    this._memory = { min: minPages, max: maxPages };
    if (typeof exportName === 'string' && exportName.length > 0) {
      this._exports = this._exports.filter((e) => !(e.kind === EXPORT_KIND.memory && e.index === 0));
      this._exports.push({ name: exportName, kind: EXPORT_KIND.memory, index: 0 });
    }
    return this;
  }

  addGlobal(valtype, mutable = true, initValue = 0, exportName = null) {
    const idx = this._globals.length;
    this._globals.push({ valtype, mutable: Boolean(mutable), initValue });
    if (typeof exportName === 'string' && exportName.length > 0) {
      this._exports.push({ name: exportName, kind: EXPORT_KIND.global, index: idx });
    }
    return idx;
  }

  addFunction({ name = null, params = [], results = [], locals = [], body = [], exportName = null } = {}) {
    const typeIdx = this.addType(params, results);
    const funcIdx = this._importedFuncCount + this._functions.length;
    const bodyBytes =
      body instanceof WasmCodeBuilder
        ? body.toBytes()
        : body instanceof Uint8Array
          ? body
          : Uint8Array.from(body);
    this._functions.push({
      name,
      typeIdx,
      locals: [...locals],
      body: bodyBytes,
    });
    const exp = exportName ?? null;
    if (typeof exp === 'string' && exp.length > 0) {
      this._exports.push({ name: exp, kind: EXPORT_KIND.func, index: funcIdx });
    }
    return funcIdx;
  }

  addExport(name, kind, index) {
    const k = typeof kind === 'string' ? EXPORT_KIND[kind] : kind;
    this._exports.push({ name, kind: k, index });
    return this;
  }

  setStart(funcIdx) {
    this._startFunc = funcIdx;
    return this;
  }

  addData(offset, data) {
    const bytes = typeof data === 'string' ? TEXT_ENCODER.encode(data) : new Uint8Array(data);
    this._dataSegments.push({ offset, bytes });
    return { ptr: offset, len: bytes.byteLength };
  }

  allocData(data, align = 4) {
    const bytes = typeof data === 'string' ? TEXT_ENCODER.encode(data) : new Uint8Array(data);
    if (align > 1) {
      const rem = this._dataCursor % align;
      if (rem !== 0) this._dataCursor += align - rem;
    }
    const ptr = this._dataCursor;
    this._dataSegments.push({ offset: ptr, bytes });
    this._dataCursor += bytes.byteLength;
    return { ptr, len: bytes.byteLength };
  }

  addCustomSection(name, payload) {
    const data = typeof payload === 'string' ? TEXT_ENCODER.encode(payload) : new Uint8Array(payload);
    this._customSections.push({ name, data });
    return this;
  }

  emit({ validate = true } = {}) {
    const out = new BinaryWriter({ initialCapacity: 1024, littleEndian: true });
    // Magic `\0asm` + version 1
    out.bytes([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

    // Section 1: Type
    if (this._types.length > 0) {
      const s = new BinaryWriter({ initialCapacity: 128 });
      s.bytes(encodeUleb128(this._types.length));
      for (const t of this._types) {
        s.u8(WASM_TYPES.func);
        s.bytes(encodeUleb128(t.params.length));
        for (const p of t.params) s.u8(p);
        s.bytes(encodeUleb128(t.results.length));
        for (const r of t.results) s.u8(r);
      }
      out.bytes(encodeSection(1, s.toUint8Array()));
    }

    // Section 2: Import
    if (this._imports.length > 0) {
      const s = new BinaryWriter({ initialCapacity: 256 });
      s.bytes(encodeUleb128(this._imports.length));
      for (const imp of this._imports) {
        s.bytes(encodeName(imp.module));
        s.bytes(encodeName(imp.name));
        s.u8(imp.kind);
        s.bytes(encodeUleb128(imp.typeIdx));
      }
      out.bytes(encodeSection(2, s.toUint8Array()));
    }

    // Section 3: Function
    if (this._functions.length > 0) {
      const s = new BinaryWriter({ initialCapacity: 64 });
      s.bytes(encodeUleb128(this._functions.length));
      for (const fn of this._functions) {
        s.bytes(encodeUleb128(fn.typeIdx));
      }
      out.bytes(encodeSection(3, s.toUint8Array()));
    }

    // Section 5: Memory
    if (this._memory) {
      const s = new BinaryWriter({ initialCapacity: 16 });
      s.bytes(encodeUleb128(1));
      if (this._memory.max !== null && this._memory.max !== undefined) {
        s.u8(0x01)
          .bytes(encodeUleb128(this._memory.min))
          .bytes(encodeUleb128(this._memory.max));
      } else {
        s.u8(0x00).bytes(encodeUleb128(this._memory.min));
      }
      out.bytes(encodeSection(5, s.toUint8Array()));
    }

    // Section 6: Global
    if (this._globals.length > 0) {
      const s = new BinaryWriter({ initialCapacity: 64 });
      s.bytes(encodeUleb128(this._globals.length));
      for (const g of this._globals) {
        s.u8(g.valtype).u8(g.mutable ? 1 : 0);
        if (g.valtype === WASM_TYPES.i32) {
          s.u8(WASM_OPCODES.i32_const).bytes(encodeSleb128(g.initValue | 0));
        } else if (g.valtype === WASM_TYPES.i64) {
          s.u8(WASM_OPCODES.i64_const).bytes(encodeSleb128_64(g.initValue));
        } else if (g.valtype === WASM_TYPES.f32) {
          s.u8(WASM_OPCODES.f32_const).f32le(g.initValue);
        } else if (g.valtype === WASM_TYPES.f64) {
          s.u8(WASM_OPCODES.f64_const).f64le(g.initValue);
        }
        s.u8(WASM_OPCODES.end);
      }
      out.bytes(encodeSection(6, s.toUint8Array()));
    }

    // Section 7: Export
    if (this._exports.length > 0) {
      const s = new BinaryWriter({ initialCapacity: 128 });
      s.bytes(encodeUleb128(this._exports.length));
      for (const exp of this._exports) {
        s.bytes(encodeName(exp.name)).u8(exp.kind).bytes(encodeUleb128(exp.index));
      }
      out.bytes(encodeSection(7, s.toUint8Array()));
    }

    // Section 8: Start
    if (this._startFunc !== null) {
      const s = new BinaryWriter({ initialCapacity: 8 });
      s.bytes(encodeUleb128(this._startFunc));
      out.bytes(encodeSection(8, s.toUint8Array()));
    }

    // Section 10: Code
    if (this._functions.length > 0) {
      const s = new BinaryWriter({ initialCapacity: 512 });
      s.bytes(encodeUleb128(this._functions.length));
      for (const fn of this._functions) {
        const funcBuf = new BinaryWriter({ initialCapacity: fn.body.byteLength + 32 });
        // Group consecutive locals of identical type
        const groups = [];
        for (const t of fn.locals) {
          if (groups.length > 0 && groups[groups.length - 1].type === t) {
            groups[groups.length - 1].count += 1;
          } else {
            groups.push({ count: 1, type: t });
          }
        }
        funcBuf.bytes(encodeUleb128(groups.length));
        for (const grp of groups) {
          funcBuf.bytes(encodeUleb128(grp.count)).u8(grp.type);
        }
        funcBuf.bytes(fn.body);
        funcBuf.u8(WASM_OPCODES.end);
        const bodyData = funcBuf.toUint8Array();
        s.bytes(encodeUleb128(bodyData.byteLength)).bytes(bodyData);
      }
      out.bytes(encodeSection(10, s.toUint8Array()));
    }

    // Section 11: Data
    if (this._dataSegments.length > 0) {
      const s = new BinaryWriter({ initialCapacity: 512 });
      s.bytes(encodeUleb128(this._dataSegments.length));
      for (const seg of this._dataSegments) {
        s.u8(0x00) // active memory 0
          .u8(WASM_OPCODES.i32_const)
          .bytes(encodeSleb128(seg.offset))
          .u8(WASM_OPCODES.end)
          .bytes(encodeUleb128(seg.bytes.byteLength))
          .bytes(seg.bytes);
      }
      out.bytes(encodeSection(11, s.toUint8Array()));
    }

    // Section 0: Custom sections
    for (const cs of this._customSections) {
      const s = new BinaryWriter({ initialCapacity: cs.data.byteLength + cs.name.length + 8 });
      s.bytes(encodeName(cs.name)).bytes(cs.data);
      out.bytes(encodeSection(0, s.toUint8Array()));
    }

    const wasmBytes = out.toUint8Array();
    if (validate && !WebAssembly.validate(wasmBytes)) {
      let detail = 'Emitted WebAssembly module failed WebAssembly.validate()';
      try {
        new WebAssembly.Module(wasmBytes);
      } catch (vErr) {
        detail = `Emitted WebAssembly module failed validation: ${vErr?.message ?? vErr}`;
      }
      throw new FormatError(detail, {
        code: ERROR_CODES.E_INVALID_WASM,
        format: 'wasm',
      });
    }
    return wasmBytes;
  }
}

/**
 * Adds reusable WASM helper functions to `builder`:
 *  - `fnMemCopy(dst, src, len) -> endPtr`
 *  - `fnWriteI32Dec(val, dstPtr) -> len`
 *  - `fnWriteU64Dec(val, dstPtr) -> len`
 *  - `fnPrintFd(fd, ptr, len) -> void` (requires `impFdWrite`)
 */
function addRuntimeHelpers(builder, impFdWrite) {
  const { i32, i64 } = WASM_TYPES;

  // fnMemCopy(dst: i32, src: i32, len: i32) -> i32 (dst + len)
  // locals: 3 = i
  const cCopy = new WasmCodeBuilder();
  cCopy
    .i32Const(0).localSet(3)
    .block()
      .loop()
        .localGet(3).localGet(2).i32GeU().brIf(1)
        .localGet(0).localGet(3).i32Add()
        .localGet(1).localGet(3).i32Add().i32Load8U()
        .i32Store8()
        .localGet(3).i32Const(1).i32Add().localSet(3)
        .br(0)
      .end()
    .end()
    .localGet(0).localGet(2).i32Add();
  const fnMemCopy = builder.addFunction({
    name: 'mem_copy',
    params: [i32, i32, i32],
    results: [i32],
    locals: [i32],
    body: cCopy,
  });

  // fnWriteI32Dec(val: i32, dstPtr: i32) -> i32 (bytes written)
  // params: 0=val, 1=dstPtr
  // locals: 2=isNeg, 3=count, 4=tmp, 5=i, 6=right
  const cI32 = new WasmCodeBuilder();
  cI32
    .localGet(0).i32Eqz()
    .if_()
      .localGet(1).i32Const(48).i32Store8()
      .i32Const(1).ret()
    .end()
    .i32Const(0).localSet(2)
    .localGet(0).i32Const(0).i32LtS()
    .if_()
      .i32Const(1).localSet(2)
      .i32Const(0).localGet(0).i32Sub().localSet(0)
      .localGet(1).i32Const(45).i32Store8()
      .localGet(1).i32Const(1).i32Add().localSet(1)
    .end()
    .i32Const(0).localSet(3)
    .loop()
      .localGet(1).localGet(3).i32Add()
      .localGet(0).i32Const(10).i32RemU().i32Const(48).i32Add()
      .i32Store8()
      .localGet(3).i32Const(1).i32Add().localSet(3)
      .localGet(0).i32Const(10).i32DivU().localTee(0)
      .i32Const(0).i32Ne().brIf(0)
    .end()
    .i32Const(0).localSet(5)
    .block()
      .loop()
        .localGet(3).i32Const(1).i32Sub().localGet(5).i32Sub().localTee(6)
        .localGet(5).i32LeS().brIf(1)
        .localGet(1).localGet(5).i32Add().i32Load8U().localSet(4)
        .localGet(1).localGet(5).i32Add()
        .localGet(1).localGet(6).i32Add().i32Load8U()
        .i32Store8()
        .localGet(1).localGet(6).i32Add()
        .localGet(4)
        .i32Store8()
        .localGet(5).i32Const(1).i32Add().localSet(5)
        .br(0)
      .end()
    .end()
    .localGet(3).localGet(2).i32Add();
  const fnWriteI32Dec = builder.addFunction({
    name: 'write_i32_dec',
    params: [i32, i32],
    results: [i32],
    locals: [i32, i32, i32, i32, i32],
    body: cI32,
  });

  // fnWriteU64Dec(val: i64, dstPtr: i32) -> i32 (bytes written)
  // params: 0=val(i64), 1=dstPtr(i32)
  // locals: 2=count, 3=tmp, 4=i, 5=right
  const cU64 = new WasmCodeBuilder();
  cU64
    .localGet(0).i64Eqz()
    .if_()
      .localGet(1).i32Const(48).i32Store8()
      .i32Const(1).ret()
    .end()
    .i32Const(0).localSet(2)
    .loop()
      .localGet(1).localGet(2).i32Add()
      .localGet(0).i64Const(10n).i64RemU().i32WrapI64().i32Const(48).i32Add()
      .i32Store8()
      .localGet(2).i32Const(1).i32Add().localSet(2)
      .localGet(0).i64Const(10n).i64DivU().localTee(0)
      .i64Const(0n).i64Ne().brIf(0)
    .end()
    .i32Const(0).localSet(4)
    .block()
      .loop()
        .localGet(2).i32Const(1).i32Sub().localGet(4).i32Sub().localTee(5)
        .localGet(4).i32LeS().brIf(1)
        .localGet(1).localGet(4).i32Add().i32Load8U().localSet(3)
        .localGet(1).localGet(4).i32Add()
        .localGet(1).localGet(5).i32Add().i32Load8U()
        .i32Store8()
        .localGet(1).localGet(5).i32Add()
        .localGet(3)
        .i32Store8()
        .localGet(4).i32Const(1).i32Add().localSet(4)
        .br(0)
      .end()
    .end()
    .localGet(2);
  const fnWriteU64Dec = builder.addFunction({
    name: 'write_u64_dec',
    params: [i64, i32],
    results: [i32],
    locals: [i32, i32, i32, i32],
    body: cU64,
  });

  // fnPrintFd(fd: i32, ptr: i32, len: i32) -> void
  // Scratch iovec at [0..7], nwritten at [8..11]
  const cPrint = new WasmCodeBuilder();
  cPrint
    .i32Const(0).localGet(1).i32Store()
    .i32Const(4).localGet(2).i32Store()
    .localGet(0).i32Const(0).i32Const(1).i32Const(8).call(impFdWrite).drop();
  const fnPrintFd = builder.addFunction({
    name: 'print_fd',
    params: [i32, i32, i32],
    results: [],
    body: cPrint,
  });

  return { fnMemCopy, fnWriteI32Dec, fnWriteU64Dec, fnPrintFd };
}

/**
 * Builds a genuine, spec-driven WebAssembly (`\0asm` v1) binary supporting arbitrary runtime
 * strings, real WASM arithmetic, WASI file I/O, clock reads, Compositor windows/canvas/UI tree,
 * interactive `omni_on_event` redraws, clipboard, notifications, IPC, and exit codes.
 */
export function buildUniversalWasm(spec = {}) {
  const { i32, i64 } = WASM_TYPES;
  const builder = new WasmModuleBuilder({ dataBaseOffset: 0x1000 });

  // Determine required imports dynamically so generated binaries stay minimal and authentic
  const needFdWrite = Boolean(
    spec.stdoutMessage ||
    spec.stderrMessage ||
    spec.arithmetic ||
    spec.readClock ||
    spec.writeFile ||
    (spec.window && spec.window.interactive !== false)
  );
  const needClock = Boolean(spec.readClock);
  const needFileIo = Boolean(spec.writeFile);
  const needExit = spec.exitCode !== undefined && spec.exitCode !== null;
  const needWindow = Boolean(spec.window);
  const needClipboard = typeof spec.clipboardSet === 'string';
  const needNotify = Boolean(spec.notification);
  const needIpc = Boolean(spec.ipcSend);

  let impFdWrite = -1;
  let impClockTimeGet = -1;
  let impPathOpen = -1;
  let impFdClose = -1;
  let impProcExit = -1;
  let impWinCreate = -1;
  let impSurfClear = -1;
  let impRect = -1;
  let impCircle = -1;
  let impLine = -1;
  let impText = -1;
  let impUiTree = -1;
  let impCommit = -1;
  let impClipSet = -1;
  let impNotify = -1;
  let impIpcSend = -1;

  if (needFdWrite) {
    impFdWrite = builder.addImportFunc('wasi_snapshot_preview1', 'fd_write', [i32, i32, i32, i32], [i32]);
  }
  if (needClock) {
    impClockTimeGet = builder.addImportFunc('wasi_snapshot_preview1', 'clock_time_get', [i32, i64, i32], [i32]);
  }
  if (needFileIo) {
    impPathOpen = builder.addImportFunc(
      'wasi_snapshot_preview1',
      'path_open',
      [i32, i32, i32, i32, i32, i64, i64, i32, i32],
      [i32]
    );
    impFdClose = builder.addImportFunc('wasi_snapshot_preview1', 'fd_close', [i32], [i32]);
  }
  if (needExit) {
    impProcExit = builder.addImportFunc('wasi_snapshot_preview1', 'proc_exit', [i32], []);
  }
  if (needWindow) {
    impWinCreate = builder.addImportFunc('omni_os_v1', 'window_create', [i32, i32, i32, i32], [i32]);
    impSurfClear = builder.addImportFunc('omni_os_v1', 'surface_clear', [i32, i32, i32], [i32]);
    impRect = builder.addImportFunc('omni_os_v1', 'canvas_rect', [i32, i32, i32, i32, i32, i32, i32], [i32]);
    impCircle = builder.addImportFunc('omni_os_v1', 'canvas_circle', [i32, i32, i32, i32, i32, i32], [i32]);
    impLine = builder.addImportFunc('omni_os_v1', 'canvas_line', [i32, i32, i32, i32, i32, i32, i32, i32], [i32]);
    impText = builder.addImportFunc('omni_os_v1', 'canvas_text', [i32, i32, i32, i32, i32, i32, i32, i32], [i32]);
    impUiTree = builder.addImportFunc('omni_os_v1', 'ui_set_tree', [i32, i32, i32], [i32]);
    impCommit = builder.addImportFunc('omni_os_v1', 'surface_commit', [i32], [i32]);
  }
  if (needClipboard) {
    impClipSet = builder.addImportFunc('omni_os_v1', 'clipboard_set', [i32, i32], [i32]);
  }
  if (needNotify) {
    impNotify = builder.addImportFunc('omni_os_v1', 'notify_post', [i32, i32, i32, i32], [i32]);
  }
  if (needIpc) {
    impIpcSend = builder.addImportFunc('omni_os_v1', 'ipc_send', [i32, i32, i32, i32], [i32]);
  }

  builder.setMemory(spec.memoryPages ?? 2, 16, 'memory');

  const gWinHandle = builder.addGlobal(i32, true, 0);
  const gEventCount = builder.addGlobal(i32, true, 0);

  let helpers = null;
  if (needFdWrite) {
    helpers = addRuntimeHelpers(builder, impFdWrite);
  }

  // Build `_start()` body
  const start = new WasmCodeBuilder();
  // locals: 0 = scratchPtr / len, 1 = openedFd, 2 = computedVal

  if (spec.stdoutMessage) {
    const seg = builder.allocData(spec.stdoutMessage);
    start.i32Const(1).i32Const(seg.ptr).i32Const(seg.len).call(helpers.fnPrintFd);
  }

  if (spec.stderrMessage) {
    const seg = builder.allocData(spec.stderrMessage);
    start.i32Const(2).i32Const(seg.ptr).i32Const(seg.len).call(helpers.fnPrintFd);
  }

  if (spec.readClock) {
    const clockPrefix = builder.allocData(spec.clockPrefix ?? 'CLOCK_NS=');
    const nl = builder.allocData('\n');
    // clock_time_get(0, 0n, 0x0010)
    start
      .i32Const(0).i64Const(0n).i32Const(0x10).call(impClockTimeGet).drop()
      .i32Const(0x100).i32Const(clockPrefix.ptr).i32Const(clockPrefix.len).call(helpers.fnMemCopy)
      .localSet(0)
      .i32Const(0x10).i64Load().localGet(0).call(helpers.fnWriteU64Dec)
      .localGet(0).i32Add().localSet(0)
      .localGet(0).i32Const(nl.ptr).i32Const(nl.len).call(helpers.fnMemCopy)
      .localSet(0)
      .i32Const(1).i32Const(0x100).localGet(0).i32Const(0x100).i32Sub().call(helpers.fnPrintFd);
  }

  if (spec.arithmetic) {
    const { a = 0, b = 0, op = 'add', c = 0, label = 'RESULT=' } = spec.arithmetic;
    const lblSeg = builder.allocData(label);
    const nl = builder.allocData('\n');

    // Compute in real WASM ALU instructions (zero JS precomputation!)
    start.i32Const(a | 0).i32Const(b | 0);
    if (op === 'mul') start.i32Mul();
    else if (op === 'sub') start.i32Sub();
    else if (op === 'div') start.i32DivS();
    else if (op === 'xor') start.i32Xor();
    else start.i32Add();

    if ((c | 0) !== 0) {
      start.i32Const(c | 0).i32Add();
    }
    start.localSet(2);

    // Format label + decimal(computedVal) + '\n' into scratch 0x100
    start
      .i32Const(0x100).i32Const(lblSeg.ptr).i32Const(lblSeg.len).call(helpers.fnMemCopy)
      .localSet(0)
      .localGet(2).localGet(0).call(helpers.fnWriteI32Dec)
      .localGet(0).i32Add().localSet(0)
      .localGet(0).i32Const(nl.ptr).i32Const(nl.len).call(helpers.fnMemCopy)
      .localSet(0)
      .i32Const(1).i32Const(0x100).localGet(0).i32Const(0x100).i32Sub().call(helpers.fnPrintFd);
  }

  if (needFileIo) {
    const pathSeg = builder.allocData(spec.writeFile.path);
    const contentSeg = builder.allocData(spec.writeFile.content ?? '');
    // path_open(3, 1, pathPtr, pathLen, 9 /* CREAT|TRUNC */, rightsBase, rightsInheriting, 0, 0x18)
    const rwRights = (1n << 1n) | (1n << 2n) | (1n << 5n) | (1n << 6n) | (1n << 21n) | (1n << 22n);
    start
      .i32Const(3)
      .i32Const(1)
      .i32Const(pathSeg.ptr)
      .i32Const(pathSeg.len)
      .i32Const(9)
      .i64Const(rwRights)
      .i64Const(rwRights)
      .i32Const(0)
      .i32Const(0x18)
      .call(impPathOpen)
      .i32Eqz()
      .if_()
        .i32Const(0x18).i32Load().localSet(1)
        .localGet(1).i32Const(contentSeg.ptr).i32Const(contentSeg.len).call(helpers.fnPrintFd)
        .localGet(1).call(impFdClose).drop()
      .end();
  }

  if (needClipboard) {
    const clipSeg = builder.allocData(spec.clipboardSet);
    start.i32Const(clipSeg.ptr).i32Const(clipSeg.len).call(impClipSet).drop();
  }

  if (needNotify) {
    const tSeg = builder.allocData(spec.notification.title ?? 'OmniOS');
    const bSeg = builder.allocData(spec.notification.body ?? '');
    start
      .i32Const(tSeg.ptr).i32Const(tSeg.len)
      .i32Const(bSeg.ptr).i32Const(bSeg.len)
      .call(impNotify).drop();
  }

  if (needIpc) {
    const chSeg = builder.allocData(spec.ipcSend.channel);
    const msgSeg = builder.allocData(spec.ipcSend.message ?? '');
    start
      .i32Const(chSeg.ptr).i32Const(chSeg.len)
      .i32Const(msgSeg.ptr).i32Const(msgSeg.len)
      .call(impIpcSend).drop();
  }

  let baseCanvasDrawFn = -1;
  if (needWindow) {
    const winSpec = spec.window;
    const titleSeg = builder.allocData(winSpec.title ?? spec.name ?? 'Universal App');
    const clearSeg = builder.allocData(winSpec.clearColor ?? '#0f172a');
    const winW = winSpec.width ?? 640;
    const winH = winSpec.height ?? 440;

    // Emit reusable `draw_base_scene()` function so both `_start` and `Clear` button share it!
    const baseCode = new WasmCodeBuilder();
    baseCode
      .globalGet(gWinHandle).i32Const(clearSeg.ptr).i32Const(clearSeg.len).call(impSurfClear).drop();

    const shapes = Array.isArray(winSpec.shapes) ? winSpec.shapes : [];
    for (const sh of shapes) {
      if (!sh || typeof sh !== 'object') continue;
      if (sh.op === 'rect') {
        const col = builder.allocData(sh.color ?? '#1e293b');
        baseCode
          .globalGet(gWinHandle)
          .i32Const(sh.x | 0).i32Const(sh.y | 0).i32Const(sh.w | 0).i32Const(sh.h | 0)
          .i32Const(col.ptr).i32Const(col.len)
          .call(impRect).drop();
      } else if (sh.op === 'circle') {
        const col = builder.allocData(sh.color ?? '#38bdf8');
        baseCode
          .globalGet(gWinHandle)
          .i32Const(sh.cx | 0).i32Const(sh.cy | 0).i32Const(sh.r | 0)
          .i32Const(col.ptr).i32Const(col.len)
          .call(impCircle).drop();
      } else if (sh.op === 'line') {
        const col = builder.allocData(sh.color ?? '#64748b');
        baseCode
          .globalGet(gWinHandle)
          .i32Const(sh.x1 | 0).i32Const(sh.y1 | 0).i32Const(sh.x2 | 0).i32Const(sh.y2 | 0)
          .i32Const((sh.strokeWidth ?? 2) | 0)
          .i32Const(col.ptr).i32Const(col.len)
          .call(impLine).drop();
      } else if (sh.op === 'text') {
        const txt = builder.allocData(sh.text ?? '');
        const col = builder.allocData(sh.color ?? '#f8fafc');
        baseCode
          .globalGet(gWinHandle)
          .i32Const(sh.x | 0).i32Const(sh.y | 0)
          .i32Const(txt.ptr).i32Const(txt.len)
          .i32Const(col.ptr).i32Const(col.len)
          .i32Const((sh.fontSize ?? 14) | 0)
          .call(impText).drop();
      }
    }

    if (winSpec.uiTree) {
      const uiSeg = builder.allocData(JSON.stringify(winSpec.uiTree));
      baseCode.globalGet(gWinHandle).i32Const(uiSeg.ptr).i32Const(uiSeg.len).call(impUiTree).drop();
    }

    baseCode.globalGet(gWinHandle).call(impCommit).drop();

    baseCanvasDrawFn = builder.addFunction({
      name: 'draw_base_scene',
      params: [],
      results: [],
      body: baseCode,
    });

    start
      .i32Const(titleSeg.ptr).i32Const(titleSeg.len)
      .i32Const(winW | 0).i32Const(winH | 0)
      .call(impWinCreate)
      .globalSet(gWinHandle)
      .call(baseCanvasDrawFn);
  }

  if (needExit) {
    start.i32Const(spec.exitCode | 0).call(impProcExit);
  }

  builder.addFunction({
    name: '_start',
    params: [],
    results: [],
    locals: [i32, i32, i32],
    body: start,
    exportName: '_start',
  });

  // Interactive `omni_on_event(typeCode, arg1, arg2)` for windowed apps
  if (needWindow && spec.window.interactive !== false) {
    const winW = spec.window.width ?? 640;
    const winH = spec.window.height ?? 440;
    const clearActionHash = hashEventTarget('btn-clear');
    const col0 = builder.allocData('#38bdf8');
    const col1 = builder.allocData('#f472b6');
    const col2 = builder.allocData('#34d399');
    const col3 = builder.allocData('#fbbf24');
    const lineCol = builder.allocData('#94a3b8');
    const txtCol = builder.allocData('#f8fafc');
    const evPrefix = builder.allocData('Node #');
    const logPrefix = builder.allocData('[OmniCanvas] event #');
    const logSep = builder.allocData(' @ ');
    const logComma = builder.allocData(',');
    const logNl = builder.allocData('\n');

    // params: 0=typeCode, 1=arg1, 2=arg2
    // locals: 3=count, 4=cx, 5=cy, 6=colPtr, 7=colLen, 8=bufEnd
    const ev = new WasmCodeBuilder();
    ev
      // Ignore window_close (10)
      .localGet(0).i32Const(10).i32Eq()
      .if_()
        .ret()
      .end()
      // Check clear button action: typeCode == 2 (ACTION) && arg1 == hash('btn-clear')
      .localGet(0).i32Const(2).i32Eq()
      .localGet(1).i32Const(clearActionHash).i32Eq()
      .i32And()
      .if_()
        .i32Const(0).globalSet(gEventCount)
        .call(baseCanvasDrawFn)
        .ret()
      .end()
      // Increment live event counter
      .globalGet(gEventCount).i32Const(1).i32Add().localTee(3).globalSet(gEventCount)
      // Determine coordinates: use (arg1, arg2) if valid inside window, else compute live spiral/grid position
      .localGet(1).i32Const(0).i32GtS()
      .localGet(1).i32Const(winW).i32LtS()
      .i32And()
      .localGet(2).i32Const(0).i32GtS()
      .localGet(2).i32Const(winH).i32LtS()
      .i32And()
      .i32And()
      .if_()
        .localGet(1).localSet(4)
        .localGet(2).localSet(5)
      .else_()
        .i32Const(110).localGet(3).i32Const(57).i32Mul().i32Const(Math.max(120, winW - 220)).i32RemU().i32Add().localSet(4)
        .i32Const(110).localGet(3).i32Const(41).i32Mul().i32Const(Math.max(100, winH - 180)).i32RemU().i32Add().localSet(5)
      .end()
      // Select palette color based on (count & 3)
      .i32Const(col0.ptr).localSet(6)
      .i32Const(col0.len).localSet(7)
      .localGet(3).i32Const(3).i32And().i32Const(1).i32Eq()
      .if_()
        .i32Const(col1.ptr).localSet(6)
        .i32Const(col1.len).localSet(7)
      .end()
      .localGet(3).i32Const(3).i32And().i32Const(2).i32Eq()
      .if_()
        .i32Const(col2.ptr).localSet(6)
        .i32Const(col2.len).localSet(7)
      .end()
      .localGet(3).i32Const(3).i32And().i32Const(3).i32Eq()
      .if_()
        .i32Const(col3.ptr).localSet(6)
        .i32Const(col3.len).localSet(7)
      .end()
      // Draw connecting guide line from canvas center to (cx, cy)
      .globalGet(gWinHandle)
      .i32Const((winW >> 1) | 0).i32Const((winH >> 1) | 0)
      .localGet(4).localGet(5)
      .i32Const(2)
      .i32Const(lineCol.ptr).i32Const(lineCol.len)
      .call(impLine).drop()
      // Alternate drawing circles (odd) and rectangles (even)
      .localGet(3).i32Const(1).i32And().i32Eqz()
      .if_()
        .globalGet(gWinHandle)
        .localGet(4).i32Const(22).i32Sub()
        .localGet(5).i32Const(16).i32Sub()
        .i32Const(44).i32Const(32)
        .localGet(6).localGet(7)
        .call(impRect).drop()
      .else_()
        .globalGet(gWinHandle)
        .localGet(4).localGet(5)
        .i32Const(18)
        .localGet(6).localGet(7)
        .call(impCircle).drop()
      .end()
      // Format dynamic label "Node #<count>" in scratch memory 0x200
      .i32Const(0x200).i32Const(evPrefix.ptr).i32Const(evPrefix.len).call(helpers.fnMemCopy)
      .localSet(8)
      .localGet(3).localGet(8).call(helpers.fnWriteI32Dec)
      .localGet(8).i32Add().localSet(8)
      .globalGet(gWinHandle)
      .localGet(4).i32Const(22).i32Add()
      .localGet(5).i32Const(4).i32Add()
      .i32Const(0x200).localGet(8).i32Const(0x200).i32Sub()
      .i32Const(txtCol.ptr).i32Const(txtCol.len)
      .i32Const(12)
      .call(impText).drop()
      // Log event to stdout via WASI fd_write
      .i32Const(0x300).i32Const(logPrefix.ptr).i32Const(logPrefix.len).call(helpers.fnMemCopy).localSet(8)
      .localGet(3).localGet(8).call(helpers.fnWriteI32Dec).localGet(8).i32Add().localSet(8)
      .localGet(8).i32Const(logSep.ptr).i32Const(logSep.len).call(helpers.fnMemCopy).localSet(8)
      .localGet(4).localGet(8).call(helpers.fnWriteI32Dec).localGet(8).i32Add().localSet(8)
      .localGet(8).i32Const(logComma.ptr).i32Const(logComma.len).call(helpers.fnMemCopy).localSet(8)
      .localGet(5).localGet(8).call(helpers.fnWriteI32Dec).localGet(8).i32Add().localSet(8)
      .localGet(8).i32Const(logNl.ptr).i32Const(logNl.len).call(helpers.fnMemCopy).localSet(8)
      .i32Const(1).i32Const(0x300).localGet(8).i32Const(0x300).i32Sub().call(helpers.fnPrintFd)
      // Commit updated surface to Compositor
      .globalGet(gWinHandle).call(impCommit).drop();

    builder.addFunction({
      name: 'omni_on_event',
      params: [i32, i32, i32],
      results: [],
      locals: [i32, i32, i32, i32, i32, i32],
      body: ev,
      exportName: 'omni_on_event',
    });

    // Helper getter exports for introspection/testing
    builder.addFunction({
      name: 'get_event_count',
      params: [],
      results: [i32],
      body: new WasmCodeBuilder().globalGet(gEventCount),
      exportName: 'get_event_count',
    });
    builder.addFunction({
      name: 'get_window_handle',
      params: [],
      results: [i32],
      body: new WasmCodeBuilder().globalGet(gWinHandle),
      exportName: 'get_window_handle',
    });
  }

  // Optional custom extra exported functions
  if (Array.isArray(spec.extraExports)) {
    for (const fnSpec of spec.extraExports) {
      builder.addFunction({
        name: fnSpec.name,
        params: fnSpec.params ?? [],
        results: fnSpec.results ?? [],
        locals: fnSpec.locals ?? [],
        body: fnSpec.body,
        exportName: fnSpec.name,
      });
    }
  }

  builder.addCustomSection('omnios.sdk', JSON.stringify({
    generator: 'OmniOS Universal WASM SDK',
    appId: spec.appId ?? 'com.omnios.universal.app',
  }));

  return builder.emit({ validate: true });
}

/**
 * Packages a Universal `.uapp` ZIP archive with exact root `omnios.manifest.json` + `app.wasm`.
 */
export function buildUniversalUapp(spec = {}) {
  const appId = spec.appId ?? 'com.omnios.universal.app';
  const name = spec.name ?? 'OmniOS Universal App';
  const version = spec.version ?? '1.0.0';
  const wasmEntry = spec.wasmEntry ?? 'app.wasm';
  const permissions = Array.isArray(spec.permissions)
    ? [...spec.permissions]
    : ['omni:ui.window'];
  const intents = Array.isArray(spec.intents) ? spec.intents : [];

  const wasmBytes = spec.wasmBytes instanceof Uint8Array
    ? spec.wasmBytes
    : buildUniversalWasm(spec);

  if (!WebAssembly.validate(wasmBytes)) {
    throw new FormatError('Cannot package invalid WebAssembly module into .uapp', {
      code: ERROR_CODES.E_INVALID_WASM,
      format: 'universal-uapp',
    });
  }

  const manifest = {
    schemaVersion: 1,
    appId,
    name,
    version,
    description: spec.description ?? `${name} (OmniOS Universal WebAssembly/WASI package)`,
    platform: 'universal',
    arch: 'wasm',
    wasmEntry,
    entryPoint: spec.entryPoint ?? '_start',
    permissions,
    intents,
  };
  if (Array.isArray(spec.preopens)) {
    manifest.preopens = spec.preopens;
  }

  const manifestJson = `${JSON.stringify(manifest, null, 2)}\n`;
  const zipBytes = createZip([
    { name: 'omnios.manifest.json', data: manifestJson },
    { name: wasmEntry, data: wasmBytes },
  ]);

  return {
    bytes: zipBytes,
    wasmBytes,
    manifest,
  };
}

/**
 * Deterministically builds the sample `packages/universal-canvas.uapp` ("OmniCanvas Studio").
 */
export function buildUniversalCanvasSample(outputPath = null) {
  const spec = {
    appId: 'com.omnios.universal.canvas',
    name: 'OmniCanvas Studio',
    version: '1.0.0',
    description: 'Interactive cross-platform WebAssembly/WASI 2D vector canvas studio for OmniOS',
    permissions: [
      'omni:ui.window',
      'omni:clipboard.write',
      'omni:notifications.post',
      'wasi:fd_read',
      'wasi:fd_write',
    ],
    intents: [
      {
        actions: ['view', 'edit'],
        extensions: ['.canvas', '.svg'],
        mimeTypes: ['image/svg+xml', 'application/x-omnios-canvas'],
        schemes: ['omnicanvas'],
      },
    ],
    stdoutMessage: 'OmniCanvas Studio (Universal WASM/WASI) initialized\n',
    readClock: true,
    clockPrefix: 'BOOT_CLOCK_NS=',
    window: {
      title: 'OmniCanvas Studio',
      width: 720,
      height: 480,
      clearColor: '#0f172a',
      interactive: true,
      shapes: [
        { op: 'rect', x: 16, y: 16, w: 688, h: 48, color: '#1e293b' },
        { op: 'rect', x: 16, y: 80, w: 688, h: 384, color: '#111827' },
        { op: 'line', x1: 360, y1: 80, x2: 360, y2: 464, strokeWidth: 1, color: '#334155' },
        { op: 'line', x1: 16, y1: 272, x2: 704, y2: 272, strokeWidth: 1, color: '#334155' },
        { op: 'circle', cx: 220, cy: 240, r: 42, color: '#38bdf8' },
        { op: 'circle', cx: 500, cy: 240, r: 34, color: '#f472b6' },
        { op: 'rect', x: 320, y: 204, w: 80, h: 72, color: '#34d399' },
        { op: 'line', x1: 220, y1: 240, x2: 500, y2: 240, strokeWidth: 2, color: '#fbbf24' },
        {
          op: 'text',
          x: 32,
          y: 46,
          text: 'OmniCanvas Studio — Universal WebAssembly / WASI 2D Surface',
          color: '#f8fafc',
          fontSize: 16,
        },
        {
          op: 'text',
          x: 32,
          y: 448,
          text: 'Click anywhere on canvas or press toolbar actions to plot live WASM vector nodes',
          color: '#94a3b8',
          fontSize: 12,
        },
      ],
      uiTree: {
        type: 'vbox',
        id: 'canvas-root',
        children: [
          {
            type: 'hbox',
            id: 'canvas-toolbar',
            children: [
              { type: 'text', id: 'brand', text: 'OmniCanvas Studio (WASM)' },
              { type: 'button', id: 'btn-add-node', text: 'Add Node', action: 'btn-add-node' },
              { type: 'button', id: 'btn-clear', text: 'Clear Canvas', action: 'btn-clear' },
            ],
          },
          {
            type: 'canvas',
            id: 'main-canvas',
            width: 720,
            height: 480,
          },
        ],
      },
    },
  };

  const result = buildUniversalUapp(spec);
  if (outputPath) {
    const resolved = path.resolve(outputPath);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, result.bytes);
  }
  return result;
}

// CLI entrypoint: `node sdk/universal-builder.mjs [outputPath]`
const isMain =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const target = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.join(repoRoot, 'packages', 'universal-canvas.uapp');
  const built = buildUniversalCanvasSample(target);
  console.log(
    JSON.stringify({
      ok: true,
      outputPath: target,
      appId: built.manifest.appId,
      name: built.manifest.name,
      uappBytes: built.bytes.byteLength,
      wasmBytes: built.wasmBytes.byteLength,
      wasmValid: WebAssembly.validate(built.wasmBytes),
    })
  );
}
