/**
 * OmniOS Universal WebAssembly / WASI Runtime (`F-056`)
 * Implements Contract 5 `IPlatformRuntime` (`platform = 'universal'`, `arch = 'wasm'`).
 * Zero external dependencies, zero `node:fs` imports.
 */

import crypto from 'node:crypto';
import {
  FormatError,
  OmniOSError,
  UnresolvedImportError,
  ERROR_CODES,
} from '../../common/errors.mjs';
import { BinaryReader, decodeUleb128 } from '../../common/binary.mjs';
import { readZip } from '../../pkg/zip.mjs';
import {
  WASI_CONSTANTS,
  WasiExitSignal,
  createWasiBridge,
} from './wasi-bridge.mjs';

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: false });
const ROOT_VFS_CTX = Object.freeze({ uid: 0, gid: 0 });

const WASM_SECTION_NAMES = Object.freeze({
  0: 'custom',
  1: 'type',
  2: 'import',
  3: 'function',
  4: 'table',
  5: 'memory',
  6: 'global',
  7: 'export',
  8: 'start',
  9: 'element',
  10: 'code',
  11: 'data',
  12: 'datacount',
});

/**
 * Deterministic 32-bit FNV-1a hash used to map UI target/action IDs into `i32` event arguments.
 */
export function hashEventTarget(str) {
  if (typeof str !== 'string' || str.length === 0) return 0;
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash | 0;
}

function toUint8Array(input) {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new FormatError('Expected binary buffer (Uint8Array / ArrayBuffer)', {
    code: ERROR_CODES.E_INVALID_WASM,
    format: 'wasm',
  });
}

function isZipSignature(bytes) {
  return (
    bytes.byteLength >= 4 &&
    bytes[0] === 0x50 &&
    bytes[1] === 0x4b &&
    (bytes[2] === 0x03 || bytes[2] === 0x05 || bytes[2] === 0x07) &&
    (bytes[3] === 0x04 || bytes[3] === 0x06 || bytes[3] === 0x08)
  );
}

function sanitizeAppIdSegment(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .trim()
    .replace(/\.[^.]+$/, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

function deriveAppIdFromFilename(filenameHint, bytes) {
  const base = typeof filenameHint === 'string' ? filenameHint.split('/').pop() ?? '' : '';
  const clean = sanitizeAppIdSegment(base);
  if (clean.length > 0 && /^[A-Za-z0-9]/.test(clean)) {
    return `universal.${clean.toLowerCase()}`;
  }
  const digest = crypto.createHash('sha256').update(bytes).digest('hex').slice(0, 12);
  return `universal.wasm.${digest}`;
}

function normalizeManifestIntents(rawIntents) {
  if (!Array.isArray(rawIntents)) return [];
  const out = [];
  for (const item of rawIntents) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const desc = {};
    if (Array.isArray(item.actions)) desc.actions = item.actions.filter((v) => typeof v === 'string');
    else if (typeof item.action === 'string') desc.actions = [item.action];
    if (Array.isArray(item.schemes)) desc.schemes = item.schemes.filter((v) => typeof v === 'string');
    else if (typeof item.scheme === 'string') desc.schemes = [item.scheme];
    if (Array.isArray(item.extensions)) desc.extensions = item.extensions.filter((v) => typeof v === 'string');
    else if (typeof item.extension === 'string') desc.extensions = [item.extension];
    if (Array.isArray(item.mimeTypes)) desc.mimeTypes = item.mimeTypes.filter((v) => typeof v === 'string');
    else if (typeof item.mimeType === 'string') desc.mimeTypes = [item.mimeType];
    if (Array.isArray(item.hosts)) desc.hosts = item.hosts.filter((v) => typeof v === 'string');
    if (Array.isArray(item.categories)) desc.categories = item.categories.filter((v) => typeof v === 'string');
    if (typeof item.priority === 'number' && Number.isFinite(item.priority)) {
      desc.priority = item.priority;
    }
    if (Object.keys(desc).length > 0) {
      out.push(desc);
    }
  }
  return out;
}

/**
 * Validates and parses a WebAssembly v1 (`\0asm`) binary, extracting authentic section headers,
 * imports, and exports via `WebAssembly.validate` and `WebAssembly.Module`.
 */
export function parseWasmBinary(input) {
  const bytes = toUint8Array(input);
  if (bytes.byteLength < 8) {
    throw new FormatError('WebAssembly binary truncated (< 8 bytes)', {
      code: ERROR_CODES.E_INVALID_WASM,
      format: 'wasm',
      offset: 0,
    });
  }
  if (bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
    throw new FormatError('Invalid WebAssembly magic header (expected \\0asm)', {
      code: ERROR_CODES.E_INVALID_WASM,
      format: 'wasm',
      offset: 0,
    });
  }
  const reader = new BinaryReader(bytes, { littleEndian: true });
  reader.skip(4);
  const version = reader.u32le();
  if (version !== 1) {
    throw new FormatError(`Unsupported WebAssembly binary version: ${version}`, {
      code: ERROR_CODES.E_INVALID_WASM,
      format: 'wasm',
      offset: 4,
    });
  }

  let valid = false;
  try {
    valid = WebAssembly.validate(bytes);
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new FormatError('WebAssembly binary failed WebAssembly.validate()', {
      code: ERROR_CODES.E_INVALID_WASM,
      format: 'wasm',
    });
  }

  // Parse authentic WASM section headers
  const sections = [];
  let pos = 8;
  while (pos < bytes.byteLength) {
    const sectionOffset = pos;
    const sectionId = bytes[pos++];
    if (pos >= bytes.byteLength) {
      throw new FormatError('Truncated WebAssembly section size', {
        code: ERROR_CODES.E_INVALID_WASM,
        format: 'wasm',
        offset: pos,
      });
    }
    const szDec = decodeUleb128(bytes, pos);
    const sectionSize = szDec.value;
    const payloadStart = szDec.nextOffset;
    if (payloadStart + sectionSize > bytes.byteLength) {
      throw new FormatError(`WebAssembly section ${sectionId} exceeds binary bounds`, {
        code: ERROR_CODES.E_INVALID_WASM,
        format: 'wasm',
        offset: sectionOffset,
      });
    }
    const rec = {
      id: sectionId,
      name: WASM_SECTION_NAMES[sectionId] ?? `section_${sectionId}`,
      offset: sectionOffset,
      payloadOffset: payloadStart,
      size: sectionSize,
    };
    if (sectionId === 0 && sectionSize > 0) {
      try {
        const nameLenDec = decodeUleb128(bytes, payloadStart);
        if (nameLenDec.nextOffset + nameLenDec.value <= payloadStart + sectionSize) {
          rec.customName = TEXT_DECODER.decode(
            bytes.subarray(nameLenDec.nextOffset, nameLenDec.nextOffset + nameLenDec.value)
          );
        }
      } catch {
        // Ignore malformed custom section name
      }
    }
    sections.push(rec);
    pos = payloadStart + sectionSize;
  }

  let mod;
  try {
    mod = new WebAssembly.Module(bytes);
  } catch (err) {
    throw new FormatError(`Failed to compile WebAssembly.Module: ${err?.message ?? err}`, {
      code: ERROR_CODES.E_INVALID_WASM,
      format: 'wasm',
      cause: err instanceof Error ? err : undefined,
    });
  }

  const imports = WebAssembly.Module.imports(mod).map((imp) => ({
    module: imp.module,
    name: imp.name,
    kind: imp.kind,
  }));
  const exports = WebAssembly.Module.exports(mod).map((exp) => ({
    name: exp.name,
    kind: exp.kind,
  }));

  return {
    version,
    sections,
    imports,
    exports,
    module: mod,
  };
}

function mapEventToOmniArgs(evt) {
  const EV = WASI_CONSTANTS.OMNI_EVENT;
  const rawType = typeof evt?.type === 'string' ? evt.type.toLowerCase() : '';

  let typeCode = EV.ACTION;
  switch (rawType) {
    case 'click':
      typeCode = EV.CLICK;
      break;
    case 'action':
      typeCode = EV.ACTION;
      break;
    case 'keydown':
      typeCode = EV.KEYDOWN;
      break;
    case 'input':
    case 'text':
      typeCode = EV.INPUT;
      break;
    case 'pointer_down':
    case 'pointerdown':
    case 'mousedown':
      typeCode = EV.POINTER_DOWN;
      break;
    case 'pointer_move':
    case 'pointermove':
    case 'mousemove':
      typeCode = EV.POINTER_MOVE;
      break;
    case 'pointer_up':
    case 'pointerup':
    case 'mouseup':
      typeCode = EV.POINTER_UP;
      break;
    case 'menu_action':
      typeCode = EV.MENU_ACTION;
      break;
    case 'intent':
      typeCode = EV.INTENT;
      break;
    case 'window_close':
      typeCode = EV.WINDOW_CLOSE;
      break;
    case 'notification_action':
      typeCode = EV.NOTIFICATION_ACTION;
      break;
    default:
      typeCode = EV.ACTION;
      break;
  }

  let arg1 = 0;
  let arg2 = 0;
  if (typeof evt?.x === 'number' && Number.isFinite(evt.x)) {
    arg1 = Math.round(evt.x) | 0;
    arg2 = typeof evt?.y === 'number' && Number.isFinite(evt.y) ? (Math.round(evt.y) | 0) : 0;
  } else if (typeCode === EV.KEYDOWN) {
    if (typeof evt?.keyCode === 'number' && Number.isFinite(evt.keyCode)) {
      arg1 = evt.keyCode | 0;
    } else if (typeof evt?.key === 'string' && evt.key.length > 0) {
      arg1 = evt.key.charCodeAt(0) | 0;
    }
    arg2 = typeof evt?.modifiers === 'number' ? (evt.modifiers | 0) : 0;
  } else {
    const target =
      typeof evt?.targetId === 'string' && evt.targetId.length > 0
        ? evt.targetId
        : typeof evt?.actionId === 'string' && evt.actionId.length > 0
          ? evt.actionId
          : typeof evt?.action === 'string' && evt.action.length > 0
            ? evt.action
            : typeof evt?.intent?.action === 'string'
              ? evt.intent.action
              : '';
    if (target.length > 0) {
      arg1 = hashEventTarget(target);
      arg2 =
        typeof evt?.value === 'number' && Number.isFinite(evt.value)
          ? (evt.value | 0)
          : target.length;
    } else if (typeof evt?.arg1 === 'number') {
      arg1 = evt.arg1 | 0;
      arg2 = typeof evt?.arg2 === 'number' ? (evt.arg2 | 0) : 0;
    }
  }

  return { typeCode, arg1, arg2 };
}

function tryDeliverJsonEvent(instance, bridge, evt) {
  const onJson = instance.exports.omni_on_event_json;
  if (typeof onJson !== 'function') return;

  let jsonBytes;
  try {
    jsonBytes = TEXT_ENCODER.encode(JSON.stringify(evt ?? {}));
  } catch {
    return;
  }

  let ptr = null;
  let cap = 0;
  const allocFn = instance.exports.omni_alloc;
  if (typeof allocFn === 'function') {
    const allocated = allocFn(jsonBytes.byteLength);
    if (typeof allocated === 'number' && allocated >= 0) {
      ptr = allocated >>> 0;
      cap = jsonBytes.byteLength;
    }
  } else if (instance.exports.omni_event_buf !== undefined) {
    const bufExp = instance.exports.omni_event_buf;
    const capExp = instance.exports.omni_event_buf_cap;
    const rawPtr =
      bufExp instanceof WebAssembly.Global
        ? Number(bufExp.value)
        : typeof bufExp === 'function'
          ? Number(bufExp())
          : null;
    const rawCap =
      capExp instanceof WebAssembly.Global
        ? Number(capExp.value)
        : typeof capExp === 'function'
          ? Number(capExp())
          : 4096;
    if (typeof rawPtr === 'number' && Number.isFinite(rawPtr) && rawPtr >= 0) {
      ptr = rawPtr >>> 0;
      cap = typeof rawCap === 'number' && Number.isFinite(rawCap) && rawCap > 0 ? (rawCap >>> 0) : 4096;
    }
  }

  if (ptr === null || cap === 0) return;
  const writeLen = Math.min(jsonBytes.byteLength, cap);
  const mem = bridge.checkMem(ptr, writeLen);
  if (!mem) return;
  mem.u8.set(jsonBytes.subarray(0, writeLen), mem.p);
  onJson(mem.p, writeLen);
}

/**
 * Synchronous WebAssembly execution context implementing Contract 5 `IExecutionContext`.
 */
class WasmExecutionContext {
  constructor({ pcb, appRecord, services, instance, bridge, memory, initialIntent = null }) {
    this._pcb = pcb;
    this._appRecord = appRecord;
    this._services = services ?? {};
    this._processManager = this._services.processManager ?? this._services.kernel?.processManager ?? null;
    this._instance = instance;
    this._bridge = bridge;
    this._memory = memory;

    this._started = false;
    this._disposed = false;
    this._exited = false;
    this._exitCode = 0;
    this._instructionsExecuted = 0;
    this._pc = 0;
    this._eventQueue = [];

    if (initialIntent !== null && initialIntent !== undefined) {
      this._eventQueue.push({ type: 'intent', intent: initialIntent });
    }
  }

  _resolveEntryFn() {
    const exp = this._instance?.exports;
    if (!exp) return null;
    if (typeof exp._start === 'function') return exp._start;
    if (typeof exp.main === 'function') return exp.main;
    const customEntry = this._appRecord?.entryPoint;
    if (typeof customEntry === 'string' && customEntry.length > 0 && typeof exp[customEntry] === 'function') {
      return exp[customEntry];
    }
    return null;
  }

  _hasEventLoop() {
    if (this._bridge.getWindows().length > 0) return true;
    const exp = this._instance?.exports;
    return Boolean(
      exp && (typeof exp.omni_on_event === 'function' || typeof exp.omni_on_event_json === 'function')
    );
  }

  _chargeOps(budget, baseOps, syscallsDelta) {
    const safeBudget = typeof budget === 'number' && Number.isFinite(budget) && budget >= 1
      ? Math.floor(budget)
      : 1;
    const raw = baseOps + Math.max(0, syscallsDelta) * 4;
    const cost = Math.max(1, Math.min(safeBudget, raw));
    this._instructionsExecuted += cost;
    this._pc += 1;
    return cost;
  }

  step(instructionBudget = 4096) {
    if (this._disposed || this._exited) {
      return {
        status: 'EXITED',
        instructionsExecuted: 0,
        exitCode: this._exitCode,
      };
    }

    // 1. First tick: invoke `_start` (or `main`)
    if (!this._started) {
      this._started = true;
      const entryFn = this._resolveEntryFn();
      if (!entryFn) {
        this._exited = true;
        this._exitCode = 0;
        const ops = this._chargeOps(instructionBudget, 1, 0);
        return {
          status: 'EXITED',
          instructionsExecuted: ops,
          exitCode: 0,
        };
      }

      const syscallsBefore = this._bridge.syscallCount;
      let retVal;
      try {
        retVal = entryFn();
      } catch (err) {
        const ops = this._chargeOps(instructionBudget, 16, this._bridge.syscallCount - syscallsBefore);
        if (err instanceof WasiExitSignal) {
          this._exited = true;
          this._exitCode = err.exitCode;
          return {
            status: 'EXITED',
            instructionsExecuted: ops,
            exitCode: err.exitCode,
          };
        }
        this._exited = true;
        return {
          status: 'FAULT',
          instructionsExecuted: ops,
          fault: err,
        };
      }

      const ops = this._chargeOps(instructionBudget, 16, this._bridge.syscallCount - syscallsBefore);
      if (this._bridge.exited) {
        this._exited = true;
        this._exitCode = this._bridge.exitCode;
        return {
          status: 'EXITED',
          instructionsExecuted: ops,
          exitCode: this._exitCode,
        };
      }

      if (this._hasEventLoop()) {
        if (this._eventQueue.length > 0) {
          return { status: 'YIELD', instructionsExecuted: ops };
        }
        return {
          status: 'BLOCKED',
          instructionsExecuted: ops,
          waitReason: 'ui_event',
        };
      }

      this._exited = true;
      this._exitCode = typeof retVal === 'number' && Number.isInteger(retVal) ? retVal : 0;
      return {
        status: 'EXITED',
        instructionsExecuted: ops,
        exitCode: this._exitCode,
      };
    }

    // 2. Subsequent ticks: drain queued UI / Canvas / Intent events
    if (this._eventQueue.length === 0) {
      return {
        status: 'BLOCKED',
        instructionsExecuted: 0,
        waitReason: 'ui_event',
      };
    }

    const evt = this._eventQueue.shift();
    const syscallsBefore = this._bridge.syscallCount;
    const isWindowClose = evt?.type === 'window_close';

    try {
      tryDeliverJsonEvent(this._instance, this._bridge, evt);
      const onEvent = this._instance?.exports?.omni_on_event;
      if (typeof onEvent === 'function') {
        const { typeCode, arg1, arg2 } = mapEventToOmniArgs(evt);
        onEvent(typeCode, arg1, arg2);
      }
    } catch (err) {
      const ops = this._chargeOps(instructionBudget, 8, this._bridge.syscallCount - syscallsBefore);
      if (err instanceof WasiExitSignal) {
        this._exited = true;
        this._exitCode = err.exitCode;
        return {
          status: 'EXITED',
          instructionsExecuted: ops,
          exitCode: err.exitCode,
        };
      }
      this._exited = true;
      return {
        status: 'FAULT',
        instructionsExecuted: ops,
        fault: err,
      };
    }

    const ops = this._chargeOps(instructionBudget, 8, this._bridge.syscallCount - syscallsBefore);
    if (isWindowClose || this._bridge.exited) {
      this._exited = true;
      this._exitCode = this._bridge.exited ? this._bridge.exitCode : 0;
      return {
        status: 'EXITED',
        instructionsExecuted: ops,
        exitCode: this._exitCode,
      };
    }

    if (this._eventQueue.length > 0) {
      return {
        status: 'YIELD',
        instructionsExecuted: ops,
      };
    }
    return {
      status: 'BLOCKED',
      instructionsExecuted: ops,
      waitReason: 'ui_event',
    };
  }

  deliverEvent(event) {
    if (this._disposed || this._exited) return;
    this._eventQueue.push(event);
    if (
      this._pcb?.state === 'BLOCKED' &&
      this._processManager &&
      typeof this._processManager.wake === 'function'
    ) {
      try {
        this._processManager.wake(this._pcb.pid);
      } catch {
        // Ignore wake failure if process transitioned concurrently
      }
    }
  }

  getDebugState() {
    let memoryBytes = 0;
    try {
      if (this._memory instanceof WebAssembly.Memory) {
        memoryBytes = this._memory.buffer.byteLength;
      }
    } catch {
      memoryBytes = 0;
    }
    return {
      arch: 'wasm',
      pc: this._pc,
      sp: 0,
      registers: {
        memoryPages: Math.floor(memoryBytes / 65536),
        memoryBytes,
        openFds: this._bridge.getOpenFdCount(),
        windows: this._bridge.getWindows().length,
      },
      instructionsExecuted: this._instructionsExecuted,
      lastSyscall: this._bridge.lastSyscall,
      stackTop: 0,
    };
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    this._eventQueue.length = 0;
    this._bridge.dispose();
  }
}

export class UniversalWasmRuntime {
  constructor(opts = {}) {
    this.platform = 'universal';
    this.arch = 'wasm';
    this._cpuRegistry = opts.cpuRegistry ?? null;
  }

  inspectPackage(bytesInput, filenameHint = '', detection = null) {
    const bytes = toUint8Array(bytesInput);
    const isUapp = detection?.format === 'universal-uapp' || isZipSignature(bytes);

    if (isUapp) {
      const archive = readZip(bytes);
      const manifestText = archive.readText('omnios.manifest.json');
      if (manifestText === null) {
        throw new FormatError('Universal .uapp archive missing exact root entry "omnios.manifest.json"', {
          code: ERROR_CODES.E_INVALID_WASM,
          format: 'universal-uapp',
        });
      }

      let manifest;
      try {
        manifest = JSON.parse(manifestText);
      } catch (err) {
        throw new FormatError(`Invalid JSON in omnios.manifest.json: ${err?.message ?? err}`, {
          code: ERROR_CODES.E_INVALID_WASM,
          format: 'universal-uapp',
          cause: err instanceof Error ? err : undefined,
        });
      }
      if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
        throw new FormatError('omnios.manifest.json must be a JSON object', {
          code: ERROR_CODES.E_INVALID_WASM,
          format: 'universal-uapp',
        });
      }

      const candidateEntry =
        typeof manifest.wasmEntry === 'string' && manifest.wasmEntry.length > 0
          ? manifest.wasmEntry
          : typeof manifest.entry === 'string' && manifest.entry.endsWith('.wasm')
            ? manifest.entry
            : typeof manifest.binary === 'string' && manifest.binary.length > 0
              ? manifest.binary
              : null;

      let wasmEntry = candidateEntry && archive.has(candidateEntry) ? candidateEntry : null;
      if (!wasmEntry) {
        if (archive.has('app.wasm')) {
          wasmEntry = 'app.wasm';
        } else if (archive.has('main.wasm')) {
          wasmEntry = 'main.wasm';
        } else {
          const found = archive.entryList.find(
            (e) => !e.isDirectory && e.name.toLowerCase().endsWith('.wasm')
          );
          wasmEntry = found ? found.name : null;
        }
      }
      if (!wasmEntry) {
        throw new FormatError('Universal .uapp archive missing .wasm binary entry', {
          code: ERROR_CODES.E_INVALID_WASM,
          format: 'universal-uapp',
        });
      }

      const wasmBytes = archive.readBytes(wasmEntry);
      const parsed = parseWasmBinary(wasmBytes);

      const appId =
        typeof manifest.appId === 'string' && manifest.appId.trim().length > 0
          ? manifest.appId.trim()
          : typeof manifest.id === 'string' && manifest.id.trim().length > 0
            ? manifest.id.trim()
            : deriveAppIdFromFilename(filenameHint, bytes);
      const name =
        typeof manifest.name === 'string' && manifest.name.trim().length > 0
          ? manifest.name.trim()
          : appId;
      const version =
        typeof manifest.version === 'string' && manifest.version.trim().length > 0
          ? manifest.version.trim()
          : '1.0.0';

      const exportNames = new Set(parsed.exports.filter((e) => e.kind === 'function').map((e) => e.name));
      const entryPoint =
        typeof manifest.entryPoint === 'string' && manifest.entryPoint.trim().length > 0
          ? manifest.entryPoint.trim()
          : exportNames.has('_start')
            ? '_start'
            : exportNames.has('main')
              ? 'main'
              : wasmEntry;

      const permissions = Array.isArray(manifest.permissions)
        ? manifest.permissions.filter((p) => typeof p === 'string' && p.trim().length > 0)
        : [];
      const intents = normalizeManifestIntents(manifest.intents);

      return {
        format: 'universal-uapp',
        platform: 'universal',
        arch: 'wasm',
        appId,
        name,
        version,
        entryPoint,
        permissions,
        intents,
        sectionsOrClasses: parsed.sections.map((s) => ({
          id: s.id,
          name: s.customName ? `custom:${s.customName}` : s.name,
          offset: s.offset,
          size: s.size,
        })),
        importsOrMethods: parsed.imports.map((imp) => ({
          module: imp.module,
          name: imp.name,
          kind: imp.kind,
          fullName: `${imp.module}.${imp.name}`,
        })),
        rawMetadata: {
          manifest,
          wasmEntry,
          exports: parsed.exports,
          imports: parsed.imports,
          sections: parsed.sections,
        },
      };
    }

    // Raw `.wasm` module
    const parsed = parseWasmBinary(bytes);
    const appId = deriveAppIdFromFilename(filenameHint, bytes);
    const exportNames = new Set(parsed.exports.filter((e) => e.kind === 'function').map((e) => e.name));
    const entryPoint = exportNames.has('_start') ? '_start' : exportNames.has('main') ? 'main' : '';

    return {
      format: 'universal-wasm',
      platform: 'universal',
      arch: 'wasm',
      appId,
      name: appId,
      version: '1.0.0',
      entryPoint,
      permissions: [],
      intents: [],
      sectionsOrClasses: parsed.sections.map((s) => ({
        id: s.id,
        name: s.customName ? `custom:${s.customName}` : s.name,
        offset: s.offset,
        size: s.size,
      })),
      importsOrMethods: parsed.imports.map((imp) => ({
        module: imp.module,
        name: imp.name,
        kind: imp.kind,
        fullName: `${imp.module}.${imp.name}`,
      })),
      rawMetadata: {
        manifest: null,
        wasmEntry: '.package.bin',
        exports: parsed.exports,
        imports: parsed.imports,
        sections: parsed.sections,
      },
    };
  }

  installPackage(inspection, _bytes, services = {}) {
    if (services?.vfs && inspection?.dataDir) {
      try {
        services.vfs.stat(inspection.dataDir, ROOT_VFS_CTX);
      } catch {
        try {
          services.vfs.mkdir(inspection.dataDir, {
            recursive: true,
            mode: 0o700,
            ...ROOT_VFS_CTX,
          });
          if (typeof services.vfs.chown === 'function' && typeof inspection.uid === 'number') {
            services.vfs.chown(
              inspection.dataDir,
              inspection.uid,
              inspection.gid ?? inspection.uid,
              ROOT_VFS_CTX
            );
          }
        } catch {
          // PackageManager manages dataDir creation/rollback
        }
      }
    }

    return {
      ...inspection,
      metadata: {
        ...(inspection?.rawMetadata ?? {}),
      },
    };
  }

  _loadWasmBytes(appRecord, services) {
    const vfs = services?.vfs;
    if (!vfs) {
      throw new OmniOSError('UniversalWasmRuntime requires VFS service to load binary', {
        code: ERROR_CODES.EINVAL,
      });
    }

    const installDir = appRecord.installDir;
    const isUapp = appRecord.format === 'universal-uapp';
    const wasmEntry = appRecord.metadata?.wasmEntry || 'app.wasm';

    if (isUapp) {
      const extractedPath = `${installDir}/${wasmEntry}`;
      try {
        return toUint8Array(vfs.readFile(extractedPath, ROOT_VFS_CTX));
      } catch (err) {
        if (err?.code !== ERROR_CODES.ENOENT) throw err;
        // Fallback: extract from archived `.package.bin`
        const pkgBytes = toUint8Array(vfs.readFile(`${installDir}/.package.bin`, ROOT_VFS_CTX));
        const archive = readZip(pkgBytes);
        const entryBytes = archive.readBytes(wasmEntry);
        if (!entryBytes) {
          throw new FormatError(`Missing WASM entry "${wasmEntry}" in ${appRecord.appId}`, {
            code: ERROR_CODES.E_INVALID_WASM,
            format: 'universal-uapp',
          });
        }
        return entryBytes;
      }
    }

    return toUint8Array(vfs.readFile(`${installDir}/.package.bin`, ROOT_VFS_CTX));
  }

  createExecutionContext(pcb, appRecord, services = {}, launchOptions = {}) {
    const wasmBytes = this._loadWasmBytes(appRecord, services);
    const parsed = parseWasmBinary(wasmBytes);

    const launchArgs = Array.isArray(launchOptions.args)
      ? launchOptions.args
      : Array.isArray(pcb?.args)
        ? pcb.args
        : [];
    const args = [appRecord.appId, ...launchArgs.map((a) => String(a))];
    const env = {
      HOME: appRecord.dataDir ?? '/tmp',
      PWD: '.',
      APP_ID: appRecord.appId,
      OMNIOS_PLATFORM: 'universal',
      ...(pcb?.env ?? {}),
      ...(launchOptions.env ?? {}),
    };

    const bridge = createWasiBridge({
      pcb,
      appRecord,
      services,
      args,
      env,
    });

    const importObject = bridge.getImportObject();
    let importedMemory = null;
    const needsEnvMem = parsed.imports.some(
      (imp) => imp.module === 'env' && imp.name === 'memory' && imp.kind === 'memory'
    );
    if (needsEnvMem) {
      importedMemory = new WebAssembly.Memory({ initial: 1, maximum: 256 });
      importObject.env = { ...(importObject.env ?? {}), memory: importedMemory };
    }

    let instance;
    try {
      instance = new WebAssembly.Instance(parsed.module, importObject);
    } catch (err) {
      bridge.dispose();
      if (err instanceof WebAssembly.LinkError) {
        throw new UnresolvedImportError(`WebAssembly link failed: ${err.message}`, {
          code: ERROR_CODES.E_UNRESOLVED_IMPORT,
          cause: err,
        });
      }
      throw new FormatError(`WebAssembly instantiation failed: ${err?.message ?? err}`, {
        code: ERROR_CODES.E_INVALID_WASM,
        format: 'wasm',
        cause: err instanceof Error ? err : undefined,
      });
    }

    const memory = instance.exports.memory instanceof WebAssembly.Memory
      ? instance.exports.memory
      : importedMemory;
    if (memory) {
      bridge.setMemory(memory);
    }

    return new WasmExecutionContext({
      pcb,
      appRecord,
      services,
      instance,
      bridge,
      memory,
      initialIntent: launchOptions.intent ?? null,
    });
  }
}

export function createUniversalRuntime(opts = {}) {
  return new UniversalWasmRuntime(opts);
}

/**
 * Registers the `'wasm'` architecture factory in OmniOS `CpuRegistry`.
 */
export function registerWasmCpu(cpuRegistry) {
  if (!cpuRegistry || typeof cpuRegistry.register !== 'function') {
    throw new OmniOSError('registerWasmCpu requires a CpuRegistry instance', {
      code: ERROR_CODES.EINVAL,
    });
  }

  const factory = (opts = {}) => {
    const runtime = new UniversalWasmRuntime({ cpuRegistry });
    if (opts.wasmBytes) {
      const parsed = parseWasmBinary(opts.wasmBytes);
      const bridge = createWasiBridge({
        pcb: opts.pcb ?? null,
        appRecord: opts.appRecord ?? { appId: 'universal.wasm', dataDir: '/tmp' },
        services: opts.services ?? {},
        args: opts.args ?? [],
        env: opts.env ?? {},
        preopens: opts.preopens ?? null,
      });
      const imports = opts.imports ?? bridge.getImportObject();
      const instance = new WebAssembly.Instance(parsed.module, imports);
      const memory = instance.exports.memory instanceof WebAssembly.Memory ? instance.exports.memory : null;
      if (memory) bridge.setMemory(memory);
      return new WasmExecutionContext({
        pcb: opts.pcb ?? null,
        appRecord: opts.appRecord ?? { appId: 'universal.wasm', entryPoint: '_start' },
        services: opts.services ?? {},
        instance,
        bridge,
        memory,
      });
    }
    return {
      arch: 'wasm',
      runtime,
      validate(bytes) {
        return WebAssembly.validate(toUint8Array(bytes));
      },
      parse(bytes) {
        return parseWasmBinary(bytes);
      },
      createContext(pcb, appRecord, services, launchOptions) {
        return runtime.createExecutionContext(pcb, appRecord, services, launchOptions);
      },
    };
  };

  cpuRegistry.register('wasm', factory);
  return factory;
}
