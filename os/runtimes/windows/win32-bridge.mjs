/**
 * OmniOS Win32 Core Subsystem API Bridge (`os/runtimes/windows/win32-bridge.mjs`)
 * - 100% synchronous thunk bridge supporting BOTH Win64 (PE32+ RCX/RDX/R8/R9 + 32B shadow + stack)
 *   AND Win32 x86 (PE32 __stdcall / __cdecl) calling conventions
 * - Full API surface across `kernel32`, `user32`, `gdi32`, `advapi32`, `shell32`, `ucrtbase`/`msvcrt`
 * - Wired directly to M1 AddressSpace/ProcessManager and M2 VFS, UnifiedConfigStore.registry,
 *   Compositor (retained uiTree + GDI drawOps), SharedClipboard, NotificationCenter, IntentRouter,
 *   and PermissionBroker (enforcing SCOPE.md Landmines #2 & #3)
 */

import {
  OmniOSError,
  MemoryFaultError,
  VfsError,
  ERROR_CODES,
  WIN32_ERROR,
  posixCodeToWin32,
} from '../../common/errors.mjs';
import { PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC } from '../../kernel/vmm.mjs';
import { isPathWithinRoot, normalizePosixPath } from '../../vfs/path-translator.mjs';

const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const UTF16LE_DECODER = new TextDecoder('utf-16le', { fatal: false });

const MAX_WIN32_FILE_BYTES = 32 * 1024 * 1024; // 32 MiB hard per-file cap
const MEM_OP_CHUNK_BYTES = 64 * 1024;          // 64 KiB bounded chunk size for memory ops
const MAX_PRINTF_OUTPUT_BYTES = 65536;         // 64 KiB max formatted printf/sprintf/snprintf output
const MAX_PRINTF_SPECS = 256;                  // Max format specifiers per printf/sprintf/snprintf call
const MAX_GDI_TEXT_CHARS = 16384;              // 16 KiB max chars read/retained per TextOut/DrawText call
const MAX_DRAW_OPS = 1024;                     // Max retained drawOps per DC / per Window
const MAX_DRAW_OPS_BYTES = 512 * 1024;         // 512 KiB cumulative drawOp bytes per DC / per Window
const MAX_BRIDGE_DRAW_OPS_BYTES = 2 * 1024 * 1024; // 2 MiB bridge-wide cumulative drawOp bytes (ALL DCs + windows)
const MAX_WIN32_DC_HANDLES = 64;               // Max concurrent live DC handles per bridge
const MAX_LISTBOX_ITEMS = 4096;                // Max items per LISTBOX control
const MAX_LISTBOX_BYTES = 256 * 1024;          // 256 KiB cumulative string bytes per LISTBOX
const MAX_BRIDGE_LISTBOX_BYTES = 1 * 1024 * 1024; // 1 MiB bridge-wide cumulative LISTBOX string bytes
const MAX_MESSAGE_QUEUE = 4096;                // Max queued Win32 messages
const MAX_WINDOW_TEXT_CHARS = 65536;           // 64 KiB max window/control text length
const MAX_BRIDGE_WINDOW_TEXT_BYTES = 1 * 1024 * 1024; // 1 MiB bridge-wide cumulative window/control text bytes
const MAX_WINDOW_CLASS_NAME = 256;             // Win32 WNDCLASS 256-char class name cap
const MAX_WIN32_HANDLES = 4096;                // Max open Win32 handles (files, DCs, GDI, reg, find)
const MAX_WIN32_FIND_HANDLES = 64;             // Max concurrent FindFirstFile handles
const MAX_WIN32_REG_HANDLES = 256;             // Max concurrent open registry key handles
const MAX_WIN32_WINDOWS = 512;                 // Max live HWNDs (top-level + child controls)
const MAX_WIN32_CHILD_CONTROLS = 256;          // Max child controls per parent window
const MAX_WINDOW_CLASSES = 512;                // Max registered WNDCLASS entries
const MAX_WIN32_ENV_ENTRIES = 1024;            // Max Win32 environment variables
const MAX_WIN32_ENV_BYTES = 256 * 1024;        // 256 KiB cumulative Win32 env UTF-16 bytes
const MAX_WIN32_MODULES = 256;                 // Max tracked HMODULE entries
const MAX_MODULE_NAME_CHARS = 256;             // Max tracked module name length
const MAX_REG_VALUE_BYTES = 256 * 1024;        // 256 KiB max single registry value payload
const MAX_REG_KEY_PATH_CHARS = 1024;           // Max registry key path length
const MAX_REG_VALUE_NAME_CHARS = 1024;         // Max registry value name length
export const MAX_BRIDGE_REG_WRITE_BYTES = 4 * 1024 * 1024; // 4 MiB cumulative non-root registry write bytes per process
export const MAX_BRIDGE_REG_READ_BYTES = 32 * 1024 * 1024; // 32 MiB cumulative non-root registry SQLite read bytes per process (1:1 symmetric with Android MAX_PREF_READ_BYTES)
export const MAX_BRIDGE_REG_VALUES = 512;             // Max cumulative non-root registry writes/key creations per process
export const MAX_BRIDGE_REG_KEY_ROWS = 515;           // Max cumulative non-root SQLite registry_keys rows created per process
const MAX_BRIDGE_REG_CACHE_BYTES = 8 * 1024 * 1024;   // 8 MiB bridge-wide cap on live-invalidated registry read caches
const MAX_BRIDGE_REG_EXISTS_ENTRIES = 4096;           // Max cached registry key-existence probes per bridge
const MAX_BRIDGE_VFS_WRITE_BYTES = 16 * 1024 * 1024; // 16 MiB cumulative non-root VFS write bytes per process
export const MAX_BRIDGE_VFS_PHYSICAL_WRITE_BYTES = 32 * 1024 * 1024; // 32 MiB cumulative non-root physical SQLite VFS blob rewrite bytes per process
export const MAX_BRIDGE_VFS_PHYSICAL_READ_BYTES = 64 * 1024 * 1024; // 64 MiB cumulative non-root physical SQLite VFS blob read bytes per process
const MAX_BRIDGE_READ_CACHE_BYTES = 32 * 1024 * 1024; // 32 MiB bridge-wide cap on per-handle cached file snapshots
const MAX_BRIDGE_READDIR_CACHE_BYTES = 4 * 1024 * 1024; // 4 MiB bridge-wide cap on tick-local VFS readdir snapshots
const MAX_BRIDGE_VFS_CREATE_OPS = 1024;        // Max cumulative non-root VFS file/dir creation ops per process
const MAX_PERMISSION_AUDIT_EVENTS = 256;       // Max total PermissionBroker.checkPermission() calls per process
const MAX_PERMISSION_PROMPT_CALLS = 16;        // Max 'prompt'-policy PermissionBroker.checkPermission() calls per process
const MAX_PERMISSION_CONTEXT_PATH_CHARS = 256; // Max context.path chars forwarded to PermissionBroker
const MAX_MSGBOX_TEXT_CHARS = 4096;            // Max MessageBox body chars
const MAX_MSGBOX_CAPTION_CHARS = 256;          // Max MessageBox caption chars
const MAX_FIND_PATH_CHARS = 4096;              // Max FindFirstFileA/W pattern/path length
const ERROR_FILENAME_EXCED_RANGE = WIN32_ERROR.ERROR_FILENAME_EXCED_RANGE ?? 206;

export const WIN32_CONSTANTS = Object.freeze({
  STD_INPUT_HANDLE: 0xfffffff6,  // -10
  STD_OUTPUT_HANDLE: 0xfffffff5, // -11
  STD_ERROR_HANDLE: 0xfffffff4,  // -12

  CREATE_NEW: 1,
  CREATE_ALWAYS: 2,
  OPEN_EXISTING: 3,
  OPEN_ALWAYS: 4,
  TRUNCATE_EXISTING: 5,

  GENERIC_READ: 0x80000000,
  GENERIC_WRITE: 0x40000000,
  GENERIC_EXECUTE: 0x20000000,
  GENERIC_ALL: 0x10000000,
  FILE_READ_DATA: 0x0001,
  FILE_WRITE_DATA: 0x0002,
  FILE_APPEND_DATA: 0x0004,

  FILE_BEGIN: 0,
  FILE_CURRENT: 1,
  FILE_END: 2,

  FILE_ATTRIBUTE_DIRECTORY: 0x10,
  FILE_ATTRIBUTE_NORMAL: 0x80,
  INVALID_FILE_ATTRIBUTES: 0xffffffff,
  MOVEFILE_REPLACE_EXISTING: 0x1,

  PAGE_NOACCESS: 0x01,
  PAGE_READONLY: 0x02,
  PAGE_READWRITE: 0x04,
  PAGE_EXECUTE: 0x10,
  PAGE_EXECUTE_READ: 0x20,
  PAGE_EXECUTE_READWRITE: 0x40,

  HEAP_ZERO_MEMORY: 0x08,

  WM_CREATE: 0x0001,
  WM_DESTROY: 0x0002,
  WM_SIZE: 0x0005,
  WM_SETTEXT: 0x000c,
  WM_GETTEXT: 0x000d,
  WM_GETTEXTLENGTH: 0x000e,
  WM_PAINT: 0x000f,
  WM_CLOSE: 0x0010,
  WM_QUIT: 0x0012,
  WM_KEYDOWN: 0x0100,
  WM_CHAR: 0x0102,
  WM_COMMAND: 0x0111,
  WM_LBUTTONDOWN: 0x0201,
  LB_ADDSTRING: 0x0180,
  LB_INSERTSTRING: 0x0181,
  LB_DELETESTRING: 0x0182,
  LB_RESETCONTENT: 0x0184,

  IDOK: 1,
  IDCANCEL: 2,
  IDYES: 6,
  IDNO: 7,

  CF_TEXT: 1,
  CF_UNICODETEXT: 13,

  HKEY_CLASSES_ROOT: 0x80000000,
  HKEY_CURRENT_USER: 0x80000001,
  HKEY_LOCAL_MACHINE: 0x80000002,
  HKEY_USERS: 0x80000003,
  HKEY_CURRENT_CONFIG: 0x80000005,

  REG_NONE: 0,
  REG_SZ: 1,
  REG_EXPAND_SZ: 2,
  REG_BINARY: 3,
  REG_DWORD: 4,
  REG_MULTI_SZ: 7,
  REG_QWORD: 11,
});

const ROOT_HKEY_TO_HIVE = Object.freeze({
  0x80000000: 'HKCR',
  0x80000001: 'HKCU',
  0x80000002: 'HKLM',
  0x80000003: 'HKU',
  0x80000005: 'HKCC',
});

const REG_NUM_TO_TYPE = Object.freeze({
  1: 'REG_SZ',
  2: 'REG_EXPAND_SZ',
  3: 'REG_BINARY',
  4: 'REG_DWORD',
  7: 'REG_MULTI_SZ',
  11: 'REG_QWORD',
});

const REG_TYPE_TO_NUM = Object.freeze({
  REG_SZ: 1,
  REG_EXPAND_SZ: 2,
  REG_BINARY: 3,
  REG_DWORD: 4,
  REG_MULTI_SZ: 7,
  REG_QWORD: 11,
});

const STOCK_OBJECTS = Object.freeze({
  0: { kind: 'brush', color: '#ffffff' }, // WHITE_BRUSH
  1: { kind: 'brush', color: '#c0c0c0' }, // LTGRAY_BRUSH
  2: { kind: 'brush', color: '#808080' }, // GRAY_BRUSH
  3: { kind: 'brush', color: '#404040' }, // DKGRAY_BRUSH
  4: { kind: 'brush', color: '#000000' }, // BLACK_BRUSH
  5: { kind: 'brush', color: 'transparent' }, // NULL_BRUSH
  6: { kind: 'pen', color: '#ffffff', width: 1 }, // WHITE_PEN
  7: { kind: 'pen', color: '#000000', width: 1 }, // BLACK_PEN
  8: { kind: 'pen', color: 'transparent', width: 0 }, // NULL_PEN
  17: { kind: 'font', font: '14px sans-serif' }, // DEFAULT_GUI_FONT
});

function colorRefToHex(cr) {
  const v = Number(BigInt(cr) & 0xffffffn);
  const r = v & 0xff;
  const g = (v >> 8) & 0xff;
  const b = (v >> 16) & 0xff;
  return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
}

function winProtectToVmmPerms(flProtect) {
  const p = Number(BigInt(flProtect) & 0xffn);
  if (p === WIN32_CONSTANTS.PAGE_NOACCESS) return PROT_NONE;
  if (p === WIN32_CONSTANTS.PAGE_READONLY) return PROT_READ;
  if (p === WIN32_CONSTANTS.PAGE_READWRITE) return PROT_READ | PROT_WRITE;
  if (p === WIN32_CONSTANTS.PAGE_EXECUTE) return PROT_EXEC | PROT_READ;
  if (p === WIN32_CONSTANTS.PAGE_EXECUTE_READ) return PROT_READ | PROT_EXEC;
  if (p === WIN32_CONSTANTS.PAGE_EXECUTE_READWRITE) return PROT_READ | PROT_WRITE | PROT_EXEC;
  return PROT_READ | PROT_WRITE;
}

function matchWildcardLower(s, p) {
  const sLen = s.length;
  const pLen = p.length;
  let si = 0;
  let pi = 0;
  let starIdx = -1;
  let matchIdx = 0;
  while (si < sLen) {
    if (pi < pLen) {
      const pc = p.charCodeAt(pi);
      if (pc === 63 || pc === s.charCodeAt(si)) {
        si++;
        pi++;
        continue;
      }
      if (pc === 42) {
        starIdx = pi++;
        matchIdx = si;
        continue;
      }
    }
    if (starIdx !== -1) {
      pi = starIdx + 1;
      si = ++matchIdx;
    } else {
      return false;
    }
  }
  while (pi < pLen && p.charCodeAt(pi) === 42) pi++;
  return pi === pLen;
}

function matchWildcardCI(name, pattern) {
  return matchWildcardLower(String(name).toLowerCase(), String(pattern).toLowerCase());
}

function compileWildcardMatcherLower(p) {
  if (!p.includes('?')) {
    if (!p.includes('*')) {
      return (s) => s === p;
    }
    const parts = p.split('*');
    const prefix = parts[0];
    const suffix = parts[parts.length - 1];
    let minLen = prefix.length + suffix.length;
    const middle = [];
    for (let i = 1; i < parts.length - 1; i += 1) {
      const part = parts[i];
      if (part.length > 0) {
        middle.push(part);
        minLen += part.length;
      }
    }
    const prefixLen = prefix.length;
    const suffixLen = suffix.length;
    const midLen = middle.length;
    return (s) => {
      const sLen = s.length;
      if (sLen < minLen) return false;
      if (prefixLen > 0 && !s.startsWith(prefix)) return false;
      if (suffixLen > 0 && !s.endsWith(suffix)) return false;
      if (midLen === 0) return true;
      let pos = prefixLen;
      const limit = sLen - suffixLen;
      for (let i = 0; i < midLen; i += 1) {
        const part = middle[i];
        const idx = s.indexOf(part, pos);
        if (idx === -1 || idx + part.length > limit) return false;
        pos = idx + part.length;
      }
      return true;
    };
  }
  const pLen = p.length;
  const firstCode = pLen > 0 ? p.charCodeAt(0) : -1;
  const lastCode = pLen > 0 ? p.charCodeAt(pLen - 1) : -1;
  const checkFirst = firstCode !== -1 && firstCode !== 42 && firstCode !== 63;
  const checkLast = lastCode !== -1 && lastCode !== 42 && lastCode !== 63;
  let minNonStarLen = 0;
  let lastLit = '';
  let curStart = -1;
  for (let i = 0; i < pLen; i += 1) {
    const c = p.charCodeAt(i);
    if (c !== 42) minNonStarLen += 1;
    if (c !== 42 && c !== 63) {
      if (curStart === -1) curStart = i;
    } else if (curStart !== -1) {
      const lit = p.slice(curStart, i);
      if (lit.length >= lastLit.length) lastLit = lit;
      curStart = -1;
    }
  }
  if (curStart !== -1) {
    const lit = p.slice(curStart, pLen);
    if (lit.length >= lastLit.length) lastLit = lit;
  }
  return (s) => {
    const sLen = s.length;
    if (sLen < minNonStarLen) return false;
    if (checkFirst && s.charCodeAt(0) !== firstCode) return false;
    if (checkLast && s.charCodeAt(sLen - 1) !== lastCode) return false;
    if (lastLit.length > 0 && s.indexOf(lastLit) === -1) return false;
    return matchWildcardLower(s, p);
  };
}

function encodeUtf16LE(str, nullTerminate = true) {
  const s = nullTerminate ? `${str}\0` : String(str);
  const buf = Buffer.from(s, 'utf16le');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function encodeUtf8Bytes(str, nullTerminate = false) {
  const s = nullTerminate ? `${str}\0` : String(str);
  const buf = Buffer.from(s, 'utf8');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function decodeUtf16LE(bytes) {
  let end = bytes.byteLength - (bytes.byteLength % 2);
  for (let i = 0; i + 1 < end; i += 2) {
    if (bytes[i] === 0 && bytes[i + 1] === 0) {
      end = i;
      break;
    }
  }
  return UTF16LE_DECODER.decode(bytes.subarray(0, end));
}

function normalizeDllName(dll) {
  const clean = String(dll || '').trim().toLowerCase();
  if (clean.endsWith('.dll')) return clean;
  return clean ? `${clean}.dll` : '';
}

function isCdeclDll(dllLower) {
  return (
    dllLower === 'msvcrt.dll' ||
    dllLower === 'ucrtbase.dll' ||
    dllLower.startsWith('api-ms-win-crt-') ||
    dllLower.startsWith('vcruntime')
  );
}

function regUtf8Max(str) {
  if (!str) return 0;
  const orig = UTF8_ENCODER.encode(str).byteLength;
  const lower = str.toLowerCase();
  if (lower === str) return orig;
  return Math.max(orig, UTF8_ENCODER.encode(lower).byteLength);
}

function normalizeRegKeyNorm(keyPath) {
  return String(keyPath ?? '')
    .replace(/\//g, '\\')
    .replace(/^\\+|\\+$/g, '')
    .replace(/\\+/g, '\\')
    .toLowerCase();
}

let globalRegCreateKeyGen = 0;

export class Win32Bridge {
  constructor({ pcb, appRecord, pe = null, services = {}, launchOptions = {} } = {}) {
    this.pcb = pcb;
    this.appRecord = appRecord ?? {};
    this.pe = pe;
    this.services = services;
    this.launchOptions = launchOptions;

    this.is64 = pe ? pe.is64 : (pcb?.arch !== 'x86');
    this.ptrSize = this.is64 ? 8 : 4;
    this.invalidHandle = this.is64 ? 0xffffffffffffffffn : 0xffffffffn;

    this.thunkBase = this.is64 ? 0x7fff00000000n : 0x7f000000n;
    this.thunkStride = 0x10n;
    this.thunkEnd = this.is64 ? 0x7fff00ffffffn : 0x7f0fffffn;
    this.thunkRange = { start: this.thunkBase, end: this.thunkEnd };

    this._nextThunkIdx = 1n;
    this._thunksByKey = new Map(); // "dll!fn" -> BigInt VA
    this._thunksByVa = new Map();  // BigInt VA -> { dll, name, ordinal, fn, argCount, isCdecl }

    this.cpu = null;
    this.mappedImage = null;
    this.lastError = WIN32_ERROR.ERROR_SUCCESS;
    this.cwd = pcb?.cwd || appRecord?.dataDir || '/home/user';

    // Environment variables (case-insensitive lookup map preserving original key)
    this.env = new Map();
    const defaultEnv = {
      OS: 'Windows_NT',
      SYSTEMROOT: 'C:\\Windows',
      WINDIR: 'C:\\Windows',
      TEMP: 'C:\\Temp',
      TMP: 'C:\\Temp',
      USERPROFILE: 'C:\\Users\\user',
      HOMEDRIVE: 'C:',
      HOMEPATH: '\\Users\\user',
      COMPUTERNAME: 'OMNIOS',
      USERNAME: 'user',
      PATH: 'C:\\Windows\\System32;C:\\Windows',
      ...(pcb?.env ?? {}),
      ...(launchOptions?.env ?? {}),
    };
    for (const [k, v] of Object.entries(defaultEnv)) {
      this.env.set(k.toUpperCase(), { name: k, value: String(v) });
    }

    // Standard handles
    this.STD_IN = 0x10n;
    this.STD_OUT = 0x11n;
    this.STD_ERR = 0x12n;

    // Handle tables & bridge-wide aggregate resource counters
    this._nextHandle = 0x100n;
    this._handles = new Map(); // BigInt -> { kind: 'file'|'find'|'reg'|'gdi'|'dc'|'global', ... }
    this._dcHandleCount = 0;
    this._findHandleCount = 0;
    this._regHandleCount = 0;
    this._totalDrawOpBytes = 0;
    this._totalListboxBytes = 0;
    this._totalWindowTextBytes = 0;
    this._regWriteBytes = 0;
    this._regWriteCount = 0;
    this._regKeyRowsCreated = 0;
    this._regReadBytes = 0;
    this._regEnumCache = new Map();       // `${hive}\0${keyNorm}` -> { res, subkeys, valueNames, valueEntries, costBytes, totalBytes, cacheKey }
    this._regValCache = new Map();        // `${hive}\0${keyNorm}\0${valNorm}` -> { rec, byteLenA, byteLenW, bytesA, bytesW, costBytes, totalBytes, cacheKey }
    this._regKeyExistsCache = new Map();  // `${hive}\0${keyNorm}` -> boolean
    this._regCacheBytes = 0;
    this._localRegSetValueDepth = 0;
    this._lastGlobalRegCreateKeyGen = globalRegCreateKeyGen;
    this._lastRegKeysSig = null;
    this._regCacheNeedsTickCheck = false;
    this._vfsWriteBytes = 0;
    this._vfsPhysicalWriteBytes = 0;
    this._vfsPhysicalReadBytes = 0;
    this._vfsWriteGen = new Map();    // canonicalPathLower -> monotonic write generation counter
    this._vfsInoWriteGen = new Map(); // ino -> monotonic write generation counter
    this._readCacheBytes = 0;
    this._readdirCache = new Map();   // `${uid}\0${sandboxRoot}\0${pathLower}` -> { entries, costBytes, maskCache }
    this._readdirCacheBytes = 0;
    this._symlinkResolveCache = new Map(); // canonicalPathLower -> { effectivePath, touchesSharedUser }
    this._vfsCreateOps = 0;
    this._permAuditCount = 0;
    this._permPromptCount = 0;
    this._permAuditedKeys = new Set();
    this._activeThunkCleanupBytes = 0;
    this._stockHandles = new Map(); // stockIndex -> BigInt handle (singleton stock GDI objects)
    this._modules = new Map(); // dllLower -> BigInt HMODULE
    this._modulesByHandle = new Map();
    this._nextModuleHandle = this.is64 ? 0x7ff800000000n : 0x70000000n;

    // Live cross-process invalidation for Registry read caches (detached cleanly in dispose())
    this._hasConfigChangeListener = false;
    this._unsubConfigChanged = null;
    this._onConfigChanged = (evt) => {
      const includeKeyExists = this._localRegSetValueDepth === 0 || Boolean(evt?.origin?.deletedKey);
      this._invalidateRegCache({ includeKeyExists });
    };
    const eventBus = services?.eventBus;
    if (eventBus && typeof eventBus.on === 'function') {
      try {
        const unsub = eventBus.on('config:changed', this._onConfigChanged);
        this._hasConfigChangeListener = true;
        this._unsubConfigChanged = () => {
          if (typeof unsub === 'function') {
            unsub();
          } else if (typeof eventBus.off === 'function') {
            eventBus.off('config:changed', this._onConfigChanged);
          }
        };
      } catch (err) {
        void err;
      }
    }

    // Windowing & Message Loop state
    this._windowClasses = new Map(); // lowerClassName -> { className, wndProcVa, style, hbrBackground }
    this._nextAtom = 0xc000n;
    this._nextHwnd = 0x10000n;
    this._windows = new Map(); // BigInt hwnd -> WindowRecord
    this._windowsByCompositorId = new Map(); // windowId -> BigInt hwnd
    this._dirtySurfaceHwnds = new Set(); // Set<BigInt hwnd> pending coalesced compositor updateSurface()
    this._messageQueue = []; // Array<{ hwnd, message, wParam, lParam, time, pt }>
    this._clipboardOpen = false;
    this._clipboardOwner = 0n;
    this._globalAllocs = new Map(); // BigInt va -> { size }
    this._cmdLineAnsiVa = null;
    this._cmdLineWideVa = null;
    this._startMs = Date.now();
    this._disposed = false;

    this._apiTable = this._buildApiTable();
  }

  attachCpu(cpu, mappedImage = null) {
    this.cpu = cpu;
    this.mappedImage = mappedImage;
  }

  get uid() {
    return this.pcb?.uid ?? 1000;
  }

  get addressSpace() {
    return this.cpu ? this.cpu.addressSpace : this.pcb?.addressSpace;
  }

  // ============================================================================
  // Import Registration & Thunk Dispatch
  // ============================================================================

  _allocHandle(record) {
    if (record?.kind === 'dc') {
      if (this._dcHandleCount >= MAX_WIN32_DC_HANDLES) {
        this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
        return null;
      }
    } else if (record?.kind === 'find') {
      if (this._findHandleCount >= MAX_WIN32_FIND_HANDLES) {
        this.lastError = WIN32_ERROR.ERROR_TOO_MANY_OPEN_FILES;
        return null;
      }
    } else if (record?.kind === 'reg') {
      if (this._regHandleCount >= MAX_WIN32_REG_HANDLES) {
        this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
        return null;
      }
    }
    if (this._handles.size >= MAX_WIN32_HANDLES) {
      this.lastError = WIN32_ERROR.ERROR_TOO_MANY_OPEN_FILES;
      return null;
    }
    const h = this._nextHandle;
    this._nextHandle += 4n;
    this._handles.set(h, record);
    if (record?.kind === 'dc') this._dcHandleCount += 1;
    else if (record?.kind === 'find') this._findHandleCount += 1;
    else if (record?.kind === 'reg') this._regHandleCount += 1;
    return h;
  }

  _deleteHandle(h) {
    const rec = this._handles.get(h);
    if (!rec) return false;
    this._handles.delete(h);
    if (rec.kind === 'dc') {
      this._dcHandleCount = Math.max(0, this._dcHandleCount - 1);
      if (rec.drawOpBytes > 0) {
        this._totalDrawOpBytes = Math.max(0, this._totalDrawOpBytes - rec.drawOpBytes);
        rec.drawOpBytes = 0;
      }
      if (Array.isArray(rec.drawOps)) {
        rec.drawOps.length = 0;
      }
    } else if (rec.kind === 'find') {
      this._findHandleCount = Math.max(0, this._findHandleCount - 1);
      rec.matches = null;
    } else if (rec.kind === 'reg') {
      this._regHandleCount = Math.max(0, this._regHandleCount - 1);
    } else if (rec.kind === 'file' && rec._readCache) {
      this._clearFileReadCache(rec);
    }
    return true;
  }

  _getOrCreateModule(dllLower) {
    const rawNorm = normalizeDllName(dllLower);
    const norm = rawNorm.length > MAX_MODULE_NAME_CHARS ? rawNorm.slice(0, MAX_MODULE_NAME_CHARS) : rawNorm;
    if (this._modules.has(norm)) return this._modules.get(norm);
    if (this._modules.size >= MAX_WIN32_MODULES) {
      this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
      return 0n;
    }
    const h = this._nextModuleHandle;
    this._nextModuleHandle += 0x100000n;
    this._modules.set(norm, h);
    this._modulesByHandle.set(h, norm);
    return h;
  }

  _totalEnvBytes() {
    let total = 0;
    for (const entry of this.env.values()) {
      total += (entry.name.length + entry.value.length) * 2 + 32;
    }
    return total;
  }

  _setWinEnv(name, value) {
    const key = name.toUpperCase();
    if (value === null) {
      this.env.delete(key);
      return true;
    }
    const existing = this.env.get(key);
    if (!existing && this.env.size >= MAX_WIN32_ENV_ENTRIES) {
      this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
      return false;
    }
    const existingBytes = existing ? (existing.name.length + existing.value.length) * 2 + 32 : 0;
    const nextBytes = (name.length + value.length) * 2 + 32;
    if (this._totalEnvBytes() - existingBytes + nextBytes > MAX_WIN32_ENV_BYTES) {
      this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
      return false;
    }
    this.env.set(key, { name, value });
    return true;
  }

  registerImport(dllName, funcName, ordinal = null) {
    const dllLower = normalizeDllName(dllName);
    const symKey = funcName ? funcName.toLowerCase() : `#${ordinal}`;
    const fullKey = `${dllLower}!${symKey}`;

    if (this._thunksByKey.has(fullKey)) {
      return this._thunksByKey.get(fullKey);
    }

    const va = this.thunkBase + this._nextThunkIdx * this.thunkStride;
    this._nextThunkIdx += 1n;

    const entry = this._lookupApi(dllLower, symKey);
    const thunkRecord = {
      va,
      dll: dllLower,
      name: funcName ?? `#${ordinal}`,
      ordinal,
      handler: entry ? entry.fn : null,
      argCount: entry ? entry.argc : 0,
      isCdecl: entry ? Boolean(entry.cdecl) : isCdeclDll(dllLower),
    };

    this._thunksByKey.set(fullKey, va);
    this._thunksByVa.set(va, thunkRecord);
    return va;
  }

  _lookupApi(dllLower, fnLower) {
    const dllMap = this._apiTable[dllLower];
    if (dllMap && Object.prototype.hasOwnProperty.call(dllMap, fnLower)) {
      return dllMap[fnLower];
    }
    // Forwarder / CRT aliases across kernelbase, ucrtbase, msvcrt, etc.
    if (dllLower === 'kernelbase.dll' || dllLower.startsWith('api-ms-win-core-')) {
      const k = this._apiTable['kernel32.dll'];
      if (k && Object.prototype.hasOwnProperty.call(k, fnLower)) return k[fnLower];
    }
    if (dllLower === 'ucrtbase.dll' || dllLower.startsWith('api-ms-win-crt-') || dllLower.startsWith('vcruntime')) {
      const c = this._apiTable['msvcrt.dll'];
      if (c && Object.prototype.hasOwnProperty.call(c, fnLower)) return c[fnLower];
    }
    if (dllLower === 'ntdll.dll') {
      const k = this._apiTable['kernel32.dll'];
      if (k && Object.prototype.hasOwnProperty.call(k, fnLower)) return k[fnLower];
    }
    return null;
  }

  _readSingleArg(cpu, index) {
    if (this.is64) {
      if (index === 0) return cpu.regs[1];
      if (index === 1) return cpu.regs[2];
      if (index === 2) return cpu.regs[8];
      if (index === 3) return cpu.regs[9];
      const sp = cpu.regs[4];
      return cpu.readMem(sp + 0x28n + BigInt((index - 4) * 8), 8);
    }
    const sp = cpu.regs[4] & 0xffffffffn;
    return cpu.readMem(sp + 4n + BigInt(index * 4), 4);
  }

  _readArgs(cpu, count) {
    const args = new Array(count);
    for (let i = 0; i < count; i++) {
      args[i] = this._readSingleArg(cpu, i);
    }
    return args;
  }

  handleThunk(thunkVa, cpu) {
    this.cpu = cpu;
    const rec = this._thunksByVa.get(thunkVa);
    if (!rec) {
      return {
        status: 'FAULT',
        fault: new OmniOSError(`Unknown Win32 thunk VA 0x${thunkVa.toString(16)}`, {
          code: ERROR_CODES.E_UNIMPLEMENTED_API,
          signal: 'SIGILL',
        }),
      };
    }

    cpu.lastSyscall = `${rec.dll}!${rec.name}`;

    if (!rec.handler) {
      this.lastError = WIN32_ERROR.ERROR_CALL_NOT_IMPLEMENTED;
      cpu.setReg64(0, 0n);
      return {
        status: 'CONTINUE',
        stackCleanupBytes: this.is64 || rec.isCdecl ? 0 : rec.argCount * 4,
      };
    }

    const args = this._readArgs(cpu, rec.argCount);
    const prevCleanup = this._activeThunkCleanupBytes;
    this._activeThunkCleanupBytes = this.is64 || rec.isCdecl ? 0 : rec.argCount * 4;
    let res;
    try {
      res = rec.handler(args, cpu);
    } finally {
      this._activeThunkCleanupBytes = prevCleanup;
    }

    // Special control return objects ({ status: 'EXITED' | 'BLOCKED' | 'FAULT' | 'CALLBACK_REDIRECT' })
    if (res && typeof res === 'object' && typeof res.status === 'string') {
      return res;
    }

    const retVal = typeof res === 'bigint'
      ? res
      : BigInt(Math.trunc(Number(res ?? 0)));
    cpu.setReg64(0, this.is64 ? BigInt.asUintN(64, retVal) : BigInt.asUintN(32, retVal));

    return {
      status: 'CONTINUE',
      stackCleanupBytes: this.is64 || rec.isCdecl ? 0 : rec.argCount * 4,
    };
  }

  // ============================================================================
  // Safe Memory & String Helpers (never over-reads across page boundaries)
  // ============================================================================

  _readCString(va, maxLen = 32768) {
    const addr = this.is64 ? va : (va & 0xffffffffn);
    if (addr === 0n) return null;
    const limit = Math.max(0, Math.trunc(Number(maxLen)));
    if (limit === 0) return '';
    const chunks = [];
    let collected = 0;
    let cur = addr;
    while (collected < limit) {
      const pageRem = 4096 - Number(cur & 0xfffn);
      const chunkLen = Math.min(limit - collected, pageRem);
      const chunk = this.addressSpace.read(cur, chunkLen);
      const nulIdx = chunk.indexOf(0);
      if (nulIdx !== -1) {
        if (nulIdx > 0) {
          chunks.push(chunk.subarray(0, nulIdx));
          collected += nulIdx;
        }
        break;
      }
      chunks.push(chunk);
      collected += chunk.byteLength;
      cur += BigInt(chunk.byteLength);
    }
    if (collected === 0) return '';
    if (chunks.length === 1) return UTF8_DECODER.decode(chunks[0]);
    const merged = new Uint8Array(collected);
    let off = 0;
    for (let i = 0; i < chunks.length; i++) {
      merged.set(chunks[i], off);
      off += chunks[i].byteLength;
    }
    return UTF8_DECODER.decode(merged);
  }

  _readWString(va, maxChars = 16384) {
    const addr = this.is64 ? va : (va & 0xffffffffn);
    if (addr === 0n) return null;
    const maxBytes = Math.max(0, Math.trunc(Number(maxChars))) * 2;
    if (maxBytes === 0) return '';
    const chunks = [];
    let collectedBytes = 0;
    let cur = addr;
    while (collectedBytes < maxBytes) {
      const remBytes = maxBytes - collectedBytes;
      const pageRem = 4096 - Number(cur & 0xfffn);
      if (pageRem === 1) {
        // Odd-aligned UTF-16LE code unit straddling a page boundary
        const pair = this.addressSpace.read(cur, 2);
        if (pair[0] === 0 && pair[1] === 0) break;
        chunks.push(pair);
        collectedBytes += 2;
        cur += 2n;
        continue;
      }
      const chunkLen = Math.min(remBytes, pageRem & ~1);
      const chunk = this.addressSpace.read(cur, chunkLen);
      let nulByteIdx = -1;
      for (let j = 0; j < chunk.byteLength; j += 2) {
        if (chunk[j] === 0 && chunk[j + 1] === 0) {
          nulByteIdx = j;
          break;
        }
      }
      if (nulByteIdx !== -1) {
        if (nulByteIdx > 0) {
          chunks.push(chunk.subarray(0, nulByteIdx));
          collectedBytes += nulByteIdx;
        }
        break;
      }
      chunks.push(chunk);
      collectedBytes += chunk.byteLength;
      cur += BigInt(chunk.byteLength);
    }
    if (collectedBytes === 0) return '';
    if (chunks.length === 1) return UTF16LE_DECODER.decode(chunks[0]);
    const merged = new Uint8Array(collectedBytes);
    let off = 0;
    for (let i = 0; i < chunks.length; i++) {
      merged.set(chunks[i], off);
      off += chunks[i].byteLength;
    }
    return UTF16LE_DECODER.decode(merged);
  }

  _readString(va, isWide, maxLen) {
    if (isWide) {
      return maxLen === undefined ? this._readWString(va) : this._readWString(va, maxLen);
    }
    return maxLen === undefined ? this._readCString(va) : this._readCString(va, maxLen);
  }

  _writeCString(va, str, maxBytes = Infinity) {
    const addr = this.is64 ? va : (va & 0xffffffffn);
    if (addr === 0n || maxBytes <= 0) return 0;
    const enc = UTF8_ENCODER.encode(String(str ?? ''));
    const maxData = Number.isFinite(maxBytes) ? Math.max(0, maxBytes - 1) : enc.byteLength;
    const copyLen = Math.min(enc.byteLength, maxData);
    const out = new Uint8Array(copyLen + 1);
    out.set(enc.subarray(0, copyLen), 0);
    out[copyLen] = 0;
    this.addressSpace.write(addr, out);
    return copyLen;
  }

  _writeWString(va, str, maxChars = Infinity) {
    const addr = this.is64 ? va : (va & 0xffffffffn);
    if (addr === 0n || maxChars <= 0) return 0;
    const s = String(str ?? '');
    const maxData = Number.isFinite(maxChars) ? Math.max(0, maxChars - 1) : s.length;
    const copyChars = Math.min(s.length, maxData);
    const out = encodeUtf16LE(s.slice(0, copyChars), true);
    this.addressSpace.write(addr, out);
    return copyChars;
  }

  _writeU32(va, val) {
    if (va === 0n) return;
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, Number(BigInt(val) & 0xffffffffn), true);
    this.addressSpace.write(this.is64 ? va : (va & 0xffffffffn), buf);
  }

  _writeU64(va, val) {
    if (va === 0n) return;
    const buf = new Uint8Array(8);
    new DataView(buf.buffer).setBigUint64(0, BigInt.asUintN(64, BigInt(val)), true);
    this.addressSpace.write(this.is64 ? va : (va & 0xffffffffn), buf);
  }

  _writePtr(va, val) {
    if (this.is64) this._writeU64(va, val);
    else this._writeU32(va, val);
  }

  _readU32(va) {
    const b = this.addressSpace.read(this.is64 ? va : (va & 0xffffffffn), 4);
    return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true);
  }

  _readI32(va) {
    const b = this.addressSpace.read(this.is64 ? va : (va & 0xffffffffn), 4);
    return new DataView(b.buffer, b.byteOffset, 4).getInt32(0, true);
  }

  _readPtr(va) {
    const b = this.addressSpace.read(this.is64 ? va : (va & 0xffffffffn), this.ptrSize);
    const dv = new DataView(b.buffer, b.byteOffset, this.ptrSize);
    return this.is64 ? dv.getBigUint64(0, true) : BigInt(dv.getUint32(0, true));
  }

  // ============================================================================
  // Synchronous Permission & VFS Sandbox Enforcement (SCOPE.md Landmines #2 & #3)
  // ============================================================================

  _checkCapSync(capability, context = null) {
    const permissions = this.services.permissions;
    const appId = this.pcb?.appId || this.appRecord?.appId || `pid-${this.pcb?.pid ?? 0}`;
    const uid = this.pcb?.uid ?? 1000;

    if (!permissions || uid === 0) {
      return true;
    }

    let sanitizedContext;
    if (context && typeof context === 'object') {
      sanitizedContext = {};
      if (typeof context.path === 'string') {
        sanitizedContext.path =
          context.path.length > MAX_PERMISSION_CONTEXT_PATH_CHARS
            ? context.path.slice(0, MAX_PERMISSION_CONTEXT_PATH_CHARS)
            : context.path;
      }
      if (typeof context.mode === 'string') {
        sanitizedContext.mode = context.mode.slice(0, 32);
      }
    }

    let state = null;
    if (typeof permissions.getPolicyOverride === 'function') {
      const ov = permissions.getPolicyOverride();
      if (typeof ov === 'string') state = ov;
    } else if (typeof permissions._policyOverride === 'string') {
      state = permissions._policyOverride;
    } else if (typeof permissions._policyOverride === 'function') {
      try {
        const ovRes = permissions._policyOverride({
          appId,
          pid: this.pcb?.pid ?? null,
          platform: 'windows',
          capability,
          nativePermission: null,
          context: sanitizedContext ?? null,
        });
        if (ovRes === 'allow' || ovRes === 'deny' || ovRes === 'prompt') {
          state = ovRes;
        }
      } catch (err) {
        void err;
        state = 'deny';
      }
    }

    if (state === null && typeof permissions.getGrant === 'function') {
      const grant = permissions.getGrant(appId, capability);
      if (grant && typeof grant.state === 'string') {
        state = grant.state;
      }
    }

    if (state === null && typeof permissions.getDefaultPolicy === 'function') {
      state = permissions.getDefaultPolicy(capability);
    } else if (state === null && permissions._defaultPolicies) {
      state = permissions._defaultPolicies[capability] ?? 'deny';
    }

    const effectivePolicy =
      state === 'allow' || state === 'deny' || state === 'prompt' ? state : 'deny';

    // Throttled & deduplicated fire-and-forget audit entry (executes synchronously before first await
    // for allow/deny; caps total audit writes and 'prompt' pending entries per process to prevent host OOM
    // and unbounded omnios.sqlite security_audit growth).
    if (typeof permissions.checkPermission === 'function') {
      const isPrompt = effectivePolicy === 'prompt';
      const dedupKey = `${capability}:${effectivePolicy}`;
      const alreadyAudited = this._permAuditedKeys.has(dedupKey);
      const withinTotalCap = this._permAuditCount < MAX_PERMISSION_AUDIT_EVENTS;
      const allowedPrompt =
        !isPrompt || (this._permPromptCount < MAX_PERMISSION_PROMPT_CALLS && !alreadyAudited);

      if (withinTotalCap && allowedPrompt) {
        this._permAuditCount += 1;
        if (isPrompt) {
          this._permPromptCount += 1;
        }
        this._permAuditedKeys.add(dedupKey);
        const hasInteractivePrompt =
          typeof permissions.hasInteractivePromptConsumer === 'function'
            ? permissions.hasInteractivePromptConsumer()
            : typeof permissions._promptHandler === 'function';
        try {
          const req = {
            appId,
            pid: this.pcb?.pid ?? null,
            platform: 'windows',
            capability,
          };
          if (sanitizedContext) {
            req.context = sanitizedContext;
          }
          if (!hasInteractivePrompt) {
            req.timeoutMs = 0;
          }
          const p = permissions.checkPermission(req);
          if (p && typeof p.catch === 'function') {
            p.catch((err) => {
              void err;
            });
          }
        } catch (err) {
          void err;
        }
      }
    }

    if (effectivePolicy === 'deny') return false;
    if (effectivePolicy === 'allow') return true;
    // 'prompt' in synchronous context: allow only for interactive desktop user UID 1000, fail closed for sandboxed UIDs
    return uid === 1000;
  }

  _maxWin32FileBytes() {
    const vfsLimit = this.services?.vfs?.maxStorageBytes;
    if (typeof vfsLimit === 'number' && Number.isFinite(vfsLimit) && vfsLimit > 0) {
      return Math.min(MAX_WIN32_FILE_BYTES, Math.floor(vfsLimit));
    }
    return MAX_WIN32_FILE_BYTES;
  }

  _maxMemOpBytes() {
    const as = this.addressSpace;
    const limit = as?.maxMemoryBytes ?? as?.maxBytes ?? (64 * 1024 * 1024);
    if (typeof limit === 'number' && Number.isFinite(limit) && limit > 0) {
      return Math.floor(limit);
    }
    return 64 * 1024 * 1024;
  }

  _normalizeMemOpLen(rawLen, address, opName) {
    const nBig = typeof rawLen === 'bigint'
      ? (this.is64 ? BigInt.asUintN(64, rawLen) : (rawLen & 0xffffffffn))
      : BigInt(Math.max(0, Math.trunc(Number(rawLen) || 0)));
    if (nBig === 0n) return 0;
    const maxBytes = BigInt(this._maxMemOpBytes());
    if (nBig > maxBytes) {
      throw new MemoryFaultError(
        `${opName} length (${nBig}) exceeds process memory limit (${maxBytes})`,
        {
          code: ERROR_CODES.EFAULT,
          signal: 'SIGSEGV',
          faultType: 'MEMORY_OP_LIMIT',
          address,
          pid: this.pcb?.pid ?? null,
        }
      );
    }
    return Number(nBig);
  }

  _memFill(dst, byteVal, rawLen, opName = 'memset') {
    const dstAddr = this.is64 ? dst : (dst & 0xffffffffn);
    const n = this._normalizeMemOpLen(rawLen, dstAddr, opName);
    if (n === 0) return;
    const chunkLen = Math.min(n, MEM_OP_CHUNK_BYTES);
    const chunk = new Uint8Array(chunkLen);
    const fillByte = byteVal & 0xff;
    if (fillByte !== 0) chunk.fill(fillByte);
    let remaining = n;
    let cursor = dstAddr;
    while (remaining > 0) {
      const step = Math.min(remaining, chunkLen);
      this.addressSpace.write(cursor, step === chunkLen ? chunk : chunk.subarray(0, step));
      cursor += BigInt(step);
      remaining -= step;
    }
  }

  _memCopy(dst, src, rawLen, allowOverlap = false, opName = 'memcpy') {
    const dstAddr = this.is64 ? dst : (dst & 0xffffffffn);
    const srcAddr = this.is64 ? src : (src & 0xffffffffn);
    const n = this._normalizeMemOpLen(rawLen, dstAddr, opName);
    if (n === 0) return;
    const nBig = BigInt(n);
    if (allowOverlap && dstAddr > srcAddr && dstAddr < srcAddr + nBig) {
      // Backward chunked copy preserves overlapping source bytes with O(1) host RAM
      let remaining = n;
      while (remaining > 0) {
        const step = Math.min(remaining, MEM_OP_CHUNK_BYTES);
        const offset = BigInt(remaining - step);
        const data = this.addressSpace.read(srcAddr + offset, step);
        this.addressSpace.write(dstAddr + offset, data);
        remaining -= step;
      }
    } else {
      let offset = 0;
      while (offset < n) {
        const step = Math.min(n - offset, MEM_OP_CHUNK_BYTES);
        const offBig = BigInt(offset);
        const data = this.addressSpace.read(srcAddr + offBig, step);
        this.addressSpace.write(dstAddr + offBig, data);
        offset += step;
      }
    }
  }

  _memCmp(p1, p2, rawLen) {
    const a1 = this.is64 ? p1 : (p1 & 0xffffffffn);
    const a2 = this.is64 ? p2 : (p2 & 0xffffffffn);
    const n = this._normalizeMemOpLen(rawLen, a1, 'memcmp');
    if (n === 0) return 0n;
    let offset = 0;
    while (offset < n) {
      const step = Math.min(n - offset, MEM_OP_CHUNK_BYTES);
      const offBig = BigInt(offset);
      const b1 = this.addressSpace.read(a1 + offBig, step);
      const b2 = this.addressSpace.read(a2 + offBig, step);
      for (let i = 0; i < step; i++) {
        if (b1[i] !== b2[i]) return BigInt(b1[i] - b2[i]);
      }
      offset += step;
    }
    return 0n;
  }

  _ownAppRoot(appId) {
    if (!appId || typeof appId !== 'string') return null;
    if (appId.includes('/') || appId.includes('\\') || appId === '.' || appId === '..') {
      return null;
    }
    return `/var/appdata/windows/${appId}`;
  }

  _resolveSymlinkTarget(canonicalPath) {
    const vfs = this.services.vfs;
    const ciOpts = { caseInsensitive: true };
    let touchesSharedUser = isPathWithinRoot(canonicalPath, '/home/user', ciOpts);
    if (!vfs || typeof vfs.lstat !== 'function' || typeof vfs.readlink !== 'function') {
      return { effectivePath: canonicalPath, touchesSharedUser };
    }
    const cacheKey = String(canonicalPath).toLowerCase();
    const cached = this._symlinkResolveCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    // Read-only metadata walk as root with Windows case-insensitive lookup semantics;
    // resolved symlink target strings are NEVER leaked back to the guest.
    const metaCtx = { uid: 0, gid: 0, platform: 'posix', caseInsensitive: true };
    let current = '/';
    let queue = canonicalPath === '/' ? [] : canonicalPath.split('/').filter(Boolean);
    let hopsRemaining = 40;
    const saveCache = (res) => {
      if (this._symlinkResolveCache.size >= 256) {
        this._symlinkResolveCache.clear();
      }
      this._symlinkResolveCache.set(cacheKey, res);
      return res;
    };

    while (queue.length > 0) {
      const seg = queue.shift();
      const next = current === '/' ? `/${seg}` : `${current}/${seg}`;
      if (isPathWithinRoot(next, '/home/user', ciOpts)) {
        touchesSharedUser = true;
      }

      let st;
      try {
        st = vfs.lstat(next, metaCtx);
      } catch (err) {
        if (err?.code === ERROR_CODES.ENOENT || err?.code === ERROR_CODES.ENOTDIR) {
          const remainder = queue.length > 0 ? `${seg}/${queue.join('/')}` : seg;
          const projected = normalizePosixPath(
            current === '/' ? `/${remainder}` : `${current}/${remainder}`
          );
          if (isPathWithinRoot(projected, '/home/user', ciOpts)) {
            touchesSharedUser = true;
          }
          return saveCache({ effectivePath: projected, touchesSharedUser });
        }
        throw new VfsError('Access denied resolving path', {
          code: ERROR_CODES.EACCES,
        });
      }

      if (st?.type === 'symlink') {
        hopsRemaining -= 1;
        if (hopsRemaining < 0) {
          throw new VfsError('Too many levels of symbolic links', {
            code: ERROR_CODES.ELOOP,
          });
        }
        let target;
        try {
          target = vfs.readlink(next, metaCtx);
        } catch (err) {
          void err;
          throw new VfsError('Access denied resolving symbolic link', {
            code: ERROR_CODES.EACCES,
          });
        }
        if (typeof target !== 'string' || target.length === 0) {
          throw new VfsError('Invalid symbolic link target', {
            code: ERROR_CODES.EACCES,
          });
        }
        let expandedBase;
        let fullExpanded;
        try {
          expandedBase = target.startsWith('/')
            ? normalizePosixPath(target)
            : normalizePosixPath(current === '/' ? `/${target}` : `${current}/${target}`);
          fullExpanded =
            queue.length > 0
              ? normalizePosixPath(
                  expandedBase === '/'
                    ? `/${queue.join('/')}`
                    : `${expandedBase}/${queue.join('/')}`
                )
              : expandedBase;
        } catch (normErr) {
          void normErr;
          throw new VfsError('Too many levels of symbolic links', {
            code: ERROR_CODES.ELOOP,
          });
        }
        if (
          isPathWithinRoot(expandedBase, '/home/user', ciOpts) ||
          isPathWithinRoot(fullExpanded, '/home/user', ciOpts)
        ) {
          touchesSharedUser = true;
        }
        current = '/';
        queue = fullExpanded === '/' ? [] : fullExpanded.split('/').filter(Boolean);
        continue;
      }

      current = next;
    }

    if (isPathWithinRoot(current, '/home/user', ciOpts)) {
      touchesSharedUser = true;
    }
    return saveCache({ effectivePath: current, touchesSharedUser });
  }

  _resolveVfsPath(winPath, accessMode = 'read') {
    const vfs = this.services.vfs;
    if (!vfs) {
      throw new VfsError('VFS service is not available', { code: ERROR_CODES.EIO });
    }
    if (typeof winPath !== 'string' || winPath.length === 0) {
      throw new VfsError('Invalid Windows path', { code: ERROR_CODES.EINVAL, path: String(winPath ?? '') });
    }

    const uid = this.pcb?.uid ?? 1000;
    const gid = this.pcb?.gid ?? 1000;
    const appId = this.pcb?.appId || this.appRecord?.appId || '';
    const isSandboxed = uid >= 10000;
    const ownAppRoot = this._ownAppRoot(appId);
    const ciOpts = { caseInsensitive: true };

    const rawStripped =
      winPath.startsWith('\\\\?\\') || winPath.startsWith('//?/')
        ? winPath.slice(4)
        : winPath;
    const isAbsoluteWinPath =
      /^[a-zA-Z]:/.test(rawStripped) ||
      rawStripped.startsWith('\\') ||
      rawStripped.startsWith('/');

    if (isSandboxed && !isAbsoluteWinPath) {
      // Relative path from sandboxed process must not traverse out of its cwd's allowed root
      let cwdRoot = null;
      if (isPathWithinRoot(this.cwd, '/home/user', ciOpts)) cwdRoot = '/home/user';
      else if (ownAppRoot && isPathWithinRoot(this.cwd, ownAppRoot, ciOpts)) cwdRoot = ownAppRoot;
      else if (isPathWithinRoot(this.cwd, '/tmp', ciOpts)) cwdRoot = '/tmp';
      if (!cwdRoot) {
        throw new VfsError(`Sandbox access denied for relative path from ${this.cwd}`, {
          code: ERROR_CODES.EACCES,
          path: winPath,
          details: { violation: ERROR_CODES.E_SANDBOX_VIOLATION },
        });
      }
      vfs.pathTranslator.toCanonical(winPath, {
        platform: 'windows',
        cwd: this.cwd,
        appId,
        sandboxRoot: cwdRoot,
      });
    }

    const translated = vfs.pathTranslator.toCanonical(winPath, {
      platform: 'windows',
      cwd: this.cwd,
      appId,
    });
    const canonicalPath = translated.canonicalPath;
    const isLexicalSharedUser = isPathWithinRoot(canonicalPath, '/home/user', ciOpts);
    const isOwnApp = ownAppRoot ? isPathWithinRoot(canonicalPath, ownAppRoot, ciOpts) : false;
    const isTmp = isPathWithinRoot(canonicalPath, '/tmp', ciOpts);

    if (isSandboxed) {
      // Explicit canonical-root allowlist for unprivileged Windows processes (uid >= 10000):
      // ONLY /home/user (PermissionBroker-gated), own /var/appdata/windows/<appId>, and /tmp!
      let targetRoot = null;
      if (isLexicalSharedUser) targetRoot = '/home/user';
      else if (isOwnApp) targetRoot = ownAppRoot;
      else if (isTmp) targetRoot = '/tmp';

      if (!targetRoot) {
        throw new VfsError(`Sandbox access denied: ${canonicalPath}`, {
          code: ERROR_CODES.EACCES,
          path: winPath,
          details: { violation: ERROR_CODES.E_SANDBOX_VIOLATION, canonicalPath },
        });
      }

      // Reject any `..` segment escaping above the target allowed root (even if path re-enters it)
      vfs.pathTranslator.toCanonical(winPath, {
        platform: 'windows',
        cwd: this.cwd,
        appId,
        sandboxRoot: targetRoot,
      });
    }

    // For ANY non-root process (uid !== 0, including desktop uid=1000), resolve symlinks along
    // the path so /tmp (or other) symlinks into /home/user can NEVER bypass PermissionBroker!
    let effectivePath = canonicalPath;
    let touchesSharedUser = isLexicalSharedUser;
    if (uid !== 0) {
      const resolved = this._resolveSymlinkTarget(canonicalPath);
      effectivePath = resolved.effectivePath;
      touchesSharedUser = isLexicalSharedUser || resolved.touchesSharedUser;
    }

    const isSharedUser =
      isLexicalSharedUser ||
      touchesSharedUser ||
      isPathWithinRoot(effectivePath, '/home/user', ciOpts);

    if (isSharedUser) {
      const checkRead = accessMode === 'read' || accessMode === 'readwrite' || accessMode === 'meta';
      const checkWrite = accessMode === 'write' || accessMode === 'readwrite';
      if (checkRead && !this._checkCapSync('fs.read.user', { path: canonicalPath, mode: accessMode })) {
        throw new VfsError(`Permission denied (fs.read.user) accessing ${canonicalPath}`, {
          code: ERROR_CODES.EACCES,
          path: winPath,
        });
      }
      if (checkWrite && !this._checkCapSync('fs.write.user', { path: canonicalPath, mode: accessMode })) {
        throw new VfsError(`Permission denied (fs.write.user) accessing ${canonicalPath}`, {
          code: ERROR_CODES.EACCES,
          path: winPath,
        });
      }
      if (isLexicalSharedUser) {
        const effUid = uid === 0 ? 0 : 1000;
        const effGid = gid === 0 ? 0 : 1000;
        return {
          canonicalPath,
          isSharedUser: true,
          vfsCtx: {
            uid: effUid,
            gid: effGid,
            pid: this.pcb?.pid,
            platform: 'windows',
            appId,
            cwd: this.cwd,
            sandboxRoot: '/home/user',
          },
        };
      }
      // Indirect symlink entry into /home/user from outside /home/user:
      // - Keep lexical sandboxRoot (/tmp or ownAppRoot) for uid >= 10000 so VFS still blocks escaping it.
      // - Return isSharedUser: true so OPEN_ALWAYS write checks still apply for desktop uid = 1000.
      const vfsCtx = {
        uid,
        gid,
        pid: this.pcb?.pid,
        platform: 'windows',
        appId,
        cwd: this.cwd,
      };
      if (isSandboxed) {
        vfsCtx.sandboxRoot = isOwnApp ? ownAppRoot : '/tmp';
      }
      return {
        canonicalPath,
        isSharedUser: true,
        vfsCtx,
      };
    }

    // NEVER elevate for /root, /etc, /system, /var/appdata/*, /proc, /dev, /tmp!
    const vfsCtx = {
      uid,
      gid,
      pid: this.pcb?.pid,
      platform: 'windows',
      appId,
      cwd: this.cwd,
    };
    if (isSandboxed) {
      vfsCtx.sandboxRoot = isOwnApp ? ownAppRoot : '/tmp';
    }
    return {
      canonicalPath,
      isSharedUser: false,
      vfsCtx,
    };
  }

  _setErrorFromException(err) {
    const code = err?.code;
    if (code === ERROR_CODES.E_PATH_TRAVERSAL || code === ERROR_CODES.E_SANDBOX_VIOLATION) {
      this.lastError = WIN32_ERROR.ERROR_ACCESS_DENIED;
    } else if (
      code === ERROR_CODES.E_MEMORY_QUOTA ||
      code === ERROR_CODES.E_WINDOW_QUOTA ||
      code === ERROR_CODES.ENOMEM
    ) {
      this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
    } else if (typeof code === 'string') {
      this.lastError = posixCodeToWin32(code);
    } else {
      this.lastError = WIN32_ERROR.ERROR_INVALID_FUNCTION;
    }
  }

  _consumeVfsWriteQuota(byteCount, physicalBytes = byteCount) {
    if (this.uid === 0) return true;
    const add = Number.isFinite(byteCount) && byteCount > 0 ? Math.trunc(byteCount) : 0;
    const physAdd = Number.isFinite(physicalBytes) && physicalBytes > 0 ? Math.trunc(physicalBytes) : 0;
    if (
      this._vfsWriteBytes + add > MAX_BRIDGE_VFS_WRITE_BYTES ||
      this._vfsPhysicalWriteBytes + physAdd > MAX_BRIDGE_VFS_PHYSICAL_WRITE_BYTES
    ) {
      this.lastError = WIN32_ERROR.ERROR_DISK_FULL;
      return false;
    }
    this._vfsWriteBytes += add;
    this._vfsPhysicalWriteBytes += physAdd;
    return true;
  }

  _checkVfsCreateQuota(count = 1) {
    if (this.uid === 0) return true;
    const add = Number.isFinite(count) && count > 0 ? Math.trunc(count) : 0;
    if (add === 0) return true;
    if (this._vfsCreateOps + add > MAX_BRIDGE_VFS_CREATE_OPS) {
      this.lastError = WIN32_ERROR.ERROR_DISK_FULL;
      return false;
    }
    return true;
  }

  _recordVfsCreateQuota(count = 1) {
    if (this.uid === 0) return;
    const add = Number.isFinite(count) && count > 0 ? Math.trunc(count) : 0;
    if (add > 0) {
      this._vfsCreateOps += add;
    }
  }

  _checkVfsReadQuota(byteCount) {
    if (this.uid === 0) return true;
    const add = Number.isFinite(byteCount) && byteCount > 0 ? Math.trunc(byteCount) : 0;
    if (add === 0) return true;
    if (this._vfsPhysicalReadBytes + add > MAX_BRIDGE_VFS_PHYSICAL_READ_BYTES) {
      this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
      return false;
    }
    return true;
  }

  _recordVfsReadQuota(byteCount) {
    if (this.uid === 0) return;
    const add = Number.isFinite(byteCount) && byteCount > 0 ? Math.trunc(byteCount) : 0;
    if (add > 0) {
      this._vfsPhysicalReadBytes += add;
    }
  }

  _bumpVfsWriteGen(canonicalPath, ino = null) {
    if (typeof canonicalPath === 'string' && canonicalPath.length > 0) {
      const key = canonicalPath.toLowerCase();
      this._vfsWriteGen.set(key, (this._vfsWriteGen.get(key) ?? 0) + 1);
    }
    if (typeof ino === 'number' && Number.isFinite(ino) && ino > 0) {
      this._vfsInoWriteGen.set(ino, (this._vfsInoWriteGen.get(ino) ?? 0) + 1);
    }
    this._invalidateReaddirCache();
  }

  _invalidateReaddirCache() {
    this._readdirCache.clear();
    this._readdirCacheBytes = 0;
    this._symlinkResolveCache.clear();
  }

  _readdirCached(canonicalPath, vfsCtx) {
    const cacheKey = `${vfsCtx?.uid ?? this.uid}\0${vfsCtx?.sandboxRoot ?? ''}\0${String(canonicalPath).toLowerCase()}`;
    const cached = this._readdirCache.get(cacheKey);
    if (cached) {
      return { quotaExceeded: false, entries: cached.entries, cacheEntry: cached };
    }
    if (this.uid !== 0 && this._vfsPhysicalReadBytes >= MAX_BRIDGE_VFS_PHYSICAL_READ_BYTES) {
      this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
      return { quotaExceeded: true, entries: null, cacheEntry: null };
    }
    const rawEntries = this.services.vfs.readdir(canonicalPath, vfsCtx);
    const list = Array.isArray(rawEntries) ? rawEntries : [];
    const entries = new Array(list.length);
    let nameBytes = 0;
    for (let i = 0; i < list.length; i += 1) {
      const e = list[i];
      const name = typeof e?.name === 'string' ? e.name : '';
      if (name.length > 0) {
        nameBytes += Buffer.byteLength(name, 'utf8');
      }
      entries[i] = { name, nameLower: name.toLowerCase(), type: e?.type, size: e?.size ?? 0 };
    }
    const scanCost = Math.max(256, entries.length * 256 + nameBytes);
    if (this.uid !== 0) {
      this._recordVfsReadQuota(scanCost);
      if (this._vfsPhysicalReadBytes > MAX_BRIDGE_VFS_PHYSICAL_READ_BYTES) {
        this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
        return { quotaExceeded: true, entries: null, cacheEntry: null };
      }
    }
    let cacheEntry = null;
    if (scanCost <= MAX_BRIDGE_READDIR_CACHE_BYTES) {
      if (this._readdirCacheBytes + scanCost > MAX_BRIDGE_READDIR_CACHE_BYTES) {
        this._invalidateReaddirCache();
      }
      cacheEntry = { entries, costBytes: scanCost, maskCache: new Map() };
      this._readdirCache.set(cacheKey, cacheEntry);
      this._readdirCacheBytes += scanCost;
    }
    return { quotaExceeded: false, entries, cacheEntry };
  }

  _clearFileReadCache(rec) {
    if (!rec || !rec._readCache) return;
    const sz = rec._readCache.bytes?.byteLength ?? 0;
    rec._readCache = null;
    if (sz > 0) {
      this._readCacheBytes = Math.max(0, this._readCacheBytes - sz);
    }
  }

  _setFileReadCache(rec, entry) {
    if (!rec || !entry || !(entry.bytes instanceof Uint8Array)) return;
    if (rec._readCache) {
      this._clearFileReadCache(rec);
    }
    const sz = entry.bytes.byteLength;
    if (sz > MAX_BRIDGE_READ_CACHE_BYTES) return;
    if (this._readCacheBytes + sz > MAX_BRIDGE_READ_CACHE_BYTES) {
      for (const other of this._handles.values()) {
        if (other && other.kind === 'file' && other !== rec && other._readCache) {
          this._clearFileReadCache(other);
          if (this._readCacheBytes + sz <= MAX_BRIDGE_READ_CACHE_BYTES) break;
        }
      }
    }
    if (this._readCacheBytes + sz > MAX_BRIDGE_READ_CACHE_BYTES) return;
    rec._readCache = entry;
    this._readCacheBytes += sz;
  }

  // ============================================================================
  // Window & Compositor Helpers
  // ============================================================================

  _buildUiTree(win) {
    const children = [];
    for (const childHwnd of win.childHwnds) {
      const ctrl = this._windows.get(childHwnd);
      if (!ctrl) continue;
      const cls = ctrl.className.toUpperCase();
      let type = 'view';
      if (cls === 'BUTTON') type = 'button';
      else if (cls === 'STATIC') type = 'text';
      else if (cls === 'EDIT') type = 'input';
      else if (cls === 'LISTBOX') type = 'list';

      children.push({
        id: `ctrl-${ctrl.controlId}`,
        type,
        controlId: ctrl.controlId,
        hwnd: `0x${ctrl.hwnd.toString(16)}`,
        className: ctrl.className,
        text: ctrl.text,
        value: ctrl.text,
        label: ctrl.text,
        action: `command:${ctrl.controlId}`,
        items: ctrl.items ? [...ctrl.items] : undefined,
        bounds: { x: ctrl.x, y: ctrl.y, width: ctrl.width, height: ctrl.height },
      });
    }
    return {
      id: `win-root-${win.hwnd.toString(16)}`,
      type: 'window',
      title: win.text,
      children,
    };
  }

  _syncWindowSurface(win, extraPatch = {}) {
    const compositor = this.services.compositor;
    if (!compositor || !win.windowId) return;
    this._dirtySurfaceHwnds.delete(win.hwnd);
    const hasExplicitDrawOps = Boolean(
      extraPatch && Object.prototype.hasOwnProperty.call(extraPatch, 'drawOps')
    );
    const patch = {
      title: win.text,
      uiTree: this._buildUiTree(win),
      ...extraPatch,
    };
    if (win.drawOpsDirty) {
      if (!hasExplicitDrawOps) {
        patch.drawOps = win.drawOps;
      }
      win.drawOpsDirty = false;
    }
    try {
      compositor.updateSurface(win.windowId, patch);
    } catch (err) {
      void err;
    }
  }

  _markWindowSurfaceDirty(win, { drawOpsDirty = false } = {}) {
    if (!win || win.destroyed || !win.windowId || !this.services.compositor) return;
    if (drawOpsDirty) {
      win.drawOpsDirty = true;
    }
    if (this.cpu && typeof this.cpu.isInStep === 'function' && this.cpu.isInStep()) {
      this._dirtySurfaceHwnds.add(win.hwnd);
      return;
    }
    const patch = win.drawOpsDirty ? { drawOps: win.drawOps } : {};
    win.drawOpsDirty = false;
    this._syncWindowSurface(win, patch);
  }

  _flushSingleWindowSurfaceIfDirty(win) {
    if (!win || win.destroyed || !win.windowId || !this._dirtySurfaceHwnds.has(win.hwnd)) return;
    this._syncWindowSurface(win);
  }

  flushCompositorSurfacesIfDirty() {
    this._invalidateReaddirCache();
    if (this._regEnumCache.size > 0 || this._regKeyExistsCache.size > 0) {
      this._checkRegCreateKeyCoherency();
    }
    this._regCacheNeedsTickCheck = true;
    if (this._dirtySurfaceHwnds.size === 0) return;
    const compositor = this.services.compositor;
    if (!compositor) {
      this._dirtySurfaceHwnds.clear();
      return;
    }
    const pending = Array.from(this._dirtySurfaceHwnds);
    this._dirtySurfaceHwnds.clear();
    for (let i = 0; i < pending.length; i += 1) {
      const win = this._windows.get(pending[i]);
      if (!win || win.destroyed || !win.windowId) continue;
      const patch = win.drawOpsDirty ? { drawOps: win.drawOps } : {};
      win.drawOpsDirty = false;
      this._syncWindowSurface(win, patch);
    }
  }

  _findTopLevelOwner(win) {
    let cur = win;
    const seen = new Set();
    while (cur && cur.parentHwnd && cur.parentHwnd !== 0n) {
      if (seen.has(cur.hwnd)) break;
      seen.add(cur.hwnd);
      const next = this._windows.get(cur.parentHwnd);
      if (!next) break;
      cur = next;
    }
    return cur ?? null;
  }

  _setWindowText(win, rawText, { rejectOnEmpty = false } = {}) {
    if (!win) return false;
    const str = typeof rawText === 'string' ? rawText : String(rawText ?? '');
    const clamped = str.length > MAX_WINDOW_TEXT_CHARS ? str.slice(0, MAX_WINDOW_TEXT_CHARS) : str;
    const oldBytes = win.textBytes ?? (typeof win.text === 'string' ? win.text.length * 2 : 0);
    const newBytes = clamped.length * 2;
    const baseWithoutOld = Math.max(0, this._totalWindowTextBytes - oldBytes);
    const availableBytes = Math.max(0, MAX_BRIDGE_WINDOW_TEXT_BYTES - baseWithoutOld);
    if (clamped === win.text && newBytes <= availableBytes) {
      return true;
    }

    let finalText = clamped;
    if (newBytes > availableBytes) {
      if (rejectOnEmpty && availableBytes < 2 && newBytes > 0) {
        this.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
        return false;
      }
      const allowedChars = Math.floor(availableBytes / 2);
      finalText = clamped.slice(0, allowedChars);
    }

    const finalBytes = finalText.length * 2;
    win.text = finalText;
    win.textBytes = finalBytes;
    this._totalWindowTextBytes = baseWithoutOld + finalBytes;
    return true;
  }

  _estimateDrawOpBytes(op) {
    if (!op || typeof op !== 'object') return 64;
    let bytes = 64;
    if (typeof op.text === 'string') bytes += op.text.length * 2;
    if (typeof op.font === 'string') bytes += op.font.length * 2;
    return bytes;
  }

  _evictDrawOpsFrom(obj, bytesToFree) {
    if (!obj || !Array.isArray(obj.drawOps) || obj.drawOps.length === 0 || bytesToFree <= 0) {
      return 0;
    }
    let freed = 0;
    let dropCount = 0;
    const len = obj.drawOps.length;
    while (dropCount < len && freed < bytesToFree) {
      freed += this._estimateDrawOpBytes(obj.drawOps[dropCount]);
      dropCount += 1;
    }
    if (dropCount === 0) return 0;
    const prevBytes = typeof obj.drawOpBytes === 'number' ? obj.drawOpBytes : 0;
    obj.drawOps.splice(0, dropCount);
    const nextBytes = obj.drawOps.length === 0 ? 0 : Math.max(0, prevBytes - freed);
    const delta = Math.max(0, prevBytes - nextBytes);
    obj.drawOpBytes = nextBytes;
    this._totalDrawOpBytes = Math.max(0, this._totalDrawOpBytes - delta);
    return delta;
  }

  _appendDrawOp(target, rawOp) {
    if (!target || !Array.isArray(target.drawOps)) return false;
    let op = rawOp;
    if (op && typeof op.text === 'string' && op.text.length > MAX_GDI_TEXT_CHARS) {
      op = { ...op, text: op.text.slice(0, MAX_GDI_TEXT_CHARS) };
    }
    const opBytes = this._estimateDrawOpBytes(op);
    if (opBytes > MAX_DRAW_OPS_BYTES || opBytes > MAX_BRIDGE_DRAW_OPS_BYTES) {
      return false;
    }
    if (typeof target.drawOpBytes !== 'number') {
      let sum = 0;
      for (let i = 0; i < target.drawOps.length; i++) {
        sum += this._estimateDrawOpBytes(target.drawOps[i]);
      }
      target.drawOpBytes = sum;
      this._totalDrawOpBytes += sum;
    }

    let evicted = false;
    // 1. Per-target limits (MAX_DRAW_OPS and MAX_DRAW_OPS_BYTES)
    if (
      target.drawOps.length >= MAX_DRAW_OPS ||
      target.drawOpBytes + opBytes > MAX_DRAW_OPS_BYTES
    ) {
      const targetMaxOps = Math.max(0, Math.floor(MAX_DRAW_OPS * 0.75) - 1);
      const targetMaxBytes = Math.max(
        0,
        Math.min(MAX_DRAW_OPS_BYTES - opBytes, Math.floor(MAX_DRAW_OPS_BYTES * 0.75))
      );
      const curLen = target.drawOps.length;
      const prevBytes = target.drawOpBytes;
      let curBytes = prevBytes;
      let dropCount = 0;
      while (
        dropCount < curLen &&
        (curLen - dropCount > targetMaxOps || curBytes > targetMaxBytes)
      ) {
        curBytes -= this._estimateDrawOpBytes(target.drawOps[dropCount]);
        dropCount += 1;
      }
      if (dropCount > 0) {
        target.drawOps.splice(0, dropCount);
        const nextBytes = target.drawOps.length === 0 ? 0 : Math.max(0, curBytes);
        const delta = Math.max(0, prevBytes - nextBytes);
        target.drawOpBytes = nextBytes;
        this._totalDrawOpBytes = Math.max(0, this._totalDrawOpBytes - delta);
        evicted = true;
      }
    }

    // 2. Bridge-wide aggregate drawOp byte cap (MAX_BRIDGE_DRAW_OPS_BYTES across ALL DCs + windows)
    if (this._totalDrawOpBytes + opBytes > MAX_BRIDGE_DRAW_OPS_BYTES) {
      const bridgeGoal = Math.max(
        0,
        Math.min(MAX_BRIDGE_DRAW_OPS_BYTES - opBytes, Math.floor(MAX_BRIDGE_DRAW_OPS_BYTES * 0.75))
      );
      let needed = Math.max(
        this._totalDrawOpBytes + opBytes - MAX_BRIDGE_DRAW_OPS_BYTES,
        this._totalDrawOpBytes - bridgeGoal
      );

      // 2a. Evict oldest ops from target first
      if (needed > 0 && target.drawOps.length > 0) {
        const freed = this._evictDrawOpsFrom(target, needed);
        if (freed > 0) {
          evicted = true;
          needed -= freed;
        }
      }

      // 2b. Evict oldest ops from other live DCs (e.g. unassociated GetDC(0) / BeginPaint DCs)
      if (needed > 0) {
        for (const rec of this._handles.values()) {
          if (rec && rec.kind === 'dc' && rec !== target && rec.drawOpBytes > 0) {
            const freed = this._evictDrawOpsFrom(rec, needed);
            needed -= freed;
            if (needed <= 0) break;
          }
        }
      }

      // 2c. Evict oldest ops from other live windows (syncing Compositor surface if visible)
      if (needed > 0) {
        for (const win of this._windows.values()) {
          if (win && win !== target && win.drawOpBytes > 0) {
            const freed = this._evictDrawOpsFrom(win, needed);
            if (freed > 0 && win.windowId) {
              this._markWindowSurfaceDirty(win, { drawOpsDirty: true });
            }
            needed -= freed;
            if (needed <= 0) break;
          }
        }
      }
    }

    // Final hard invariant: NEVER exceed MAX_BRIDGE_DRAW_OPS_BYTES
    if (this._totalDrawOpBytes + opBytes > MAX_BRIDGE_DRAW_OPS_BYTES) {
      return evicted;
    }

    target.drawOps.push(op);
    target.drawOpBytes += opBytes;
    this._totalDrawOpBytes += opBytes;
    return evicted;
  }

  _enqueueMessage(msg, { force = false } = {}) {
    const code = Number(msg.message ?? 0);
    if (this._messageQueue.length >= MAX_MESSAGE_QUEUE) {
      if (force || code === WIN32_CONSTANTS.WM_QUIT || code === WIN32_CONSTANTS.WM_CLOSE) {
        this._messageQueue.shift();
      } else {
        this.lastError = 1816; // ERROR_NOT_ENOUGH_QUOTA
        return false;
      }
    }
    this._messageQueue.push({
      hwnd: msg.hwnd ?? 0n,
      message: code,
      wParam: BigInt(msg.wParam ?? 0n),
      lParam: BigInt(msg.lParam ?? 0n),
      time: (Date.now() - this._startMs) >>> 0,
      ptX: msg.ptX ?? 0,
      ptY: msg.ptY ?? 0,
    });
    this._wakeIfBlocked();
    return true;
  }

  _wakeIfBlocked() {
    if (this.services.processManager && typeof this.services.processManager.wake === 'function') {
      try {
        this.services.processManager.wake(this.pcb.pid);
      } catch (err) {
        void err;
      }
    }
  }

  _writeMsgStruct(va, msg) {
    if (this.is64) {
      // Win64 MSG (48 bytes)
      const buf = new Uint8Array(48);
      const dv = new DataView(buf.buffer);
      dv.setBigUint64(0, msg.hwnd, true);
      dv.setUint32(8, msg.message >>> 0, true);
      dv.setBigUint64(16, BigInt.asUintN(64, msg.wParam), true);
      dv.setBigUint64(24, BigInt.asUintN(64, msg.lParam), true);
      dv.setUint32(32, msg.time >>> 0, true);
      dv.setInt32(36, msg.ptX | 0, true);
      dv.setInt32(40, msg.ptY | 0, true);
      this.addressSpace.write(va, buf);
    } else {
      // Win32 x86 MSG (28 bytes)
      const buf = new Uint8Array(28);
      const dv = new DataView(buf.buffer);
      dv.setUint32(0, Number(msg.hwnd & 0xffffffffn), true);
      dv.setUint32(4, msg.message >>> 0, true);
      dv.setUint32(8, Number(msg.wParam & 0xffffffffn), true);
      dv.setUint32(12, Number(msg.lParam & 0xffffffffn), true);
      dv.setUint32(16, msg.time >>> 0, true);
      dv.setInt32(20, msg.ptX | 0, true);
      dv.setInt32(24, msg.ptY | 0, true);
      this.addressSpace.write(va & 0xffffffffn, buf);
    }
  }

  _readMsgStruct(va) {
    if (this.is64) {
      const b = this.addressSpace.read(va, 48);
      const dv = new DataView(b.buffer, b.byteOffset, 48);
      return {
        hwnd: dv.getBigUint64(0, true),
        message: dv.getUint32(8, true),
        wParam: dv.getBigUint64(16, true),
        lParam: dv.getBigUint64(24, true),
        time: dv.getUint32(32, true),
        ptX: dv.getInt32(36, true),
        ptY: dv.getInt32(40, true),
      };
    }
    const b = this.addressSpace.read(va & 0xffffffffn, 28);
    const dv = new DataView(b.buffer, b.byteOffset, 28);
    return {
      hwnd: BigInt(dv.getUint32(0, true)),
      message: dv.getUint32(4, true),
      wParam: BigInt(dv.getUint32(8, true)),
      lParam: BigInt(dv.getUint32(12, true)),
      time: dv.getUint32(16, true),
      ptX: dv.getInt32(20, true),
      ptY: dv.getInt32(24, true),
    };
  }

  _dispatchWndProc(win, message, wParam, lParam, { onReturn = null, fromThunk = true } = {}) {
    if (!win || !win.wndProcVa || win.wndProcVa === 0n || !this.cpu) {
      const defRet = this._defWindowProc(win ? win.hwnd : 0n, message, wParam, lParam);
      if (defRet && typeof defRet === 'object' && typeof defRet.status === 'string') {
        return defRet;
      }
      return typeof onReturn === 'function' ? onReturn(defRet, this.cpu) : defRet;
    }
    const args = [win.hwnd, BigInt(message >>> 0), BigInt(wParam), BigInt(lParam)];
    const abi = this.is64 ? 'win64' : 'stdcall';
    if (typeof this.cpu.isInStep === 'function' && this.cpu.isInStep()) {
      const stackCleanupBytes = fromThunk ? (this._activeThunkCleanupBytes ?? 0) : 0;
      return this.cpu.enterCooperativeCallback(win.wndProcVa, args, {
        abi,
        fromThunk,
        stackCleanupBytes,
        onReturn,
      });
    }
    const res = this.cpu.callFunction(win.wndProcVa, args, { abi, maxInstructions: 100000 });
    return typeof onReturn === 'function' ? onReturn(res.returnValue, this.cpu) : res.returnValue;
  }

  _invokeWndProc(win, message, wParam, lParam) {
    return this._dispatchWndProc(win, message, wParam, lParam);
  }

  _defWindowProc(hwnd, msg, wParam, lParam) {
    void wParam;
    void lParam;
    const m = Number(BigInt(msg) & 0xffffffffn);
    if (m === WIN32_CONSTANTS.WM_CLOSE) {
      return this._destroyWindow(hwnd, { returnValue: 0n, fromThunk: true });
    }
    if (m === WIN32_CONSTANTS.WM_PAINT) {
      const win = this._windows.get(hwnd);
      if (win) win.needsPaint = false;
      return 0n;
    }
    return 0n;
  }

  _finalizeDestroyWindow(hwnd) {
    const win = this._windows.get(hwnd);
    if (!win) return;

    // Collect win + all descendant windows iteratively so grandchildren cannot orphan resources
    const toDestroy = [];
    const destroyedSet = new Set();
    const queue = [hwnd];
    while (queue.length > 0) {
      const curHwnd = queue.shift();
      if (destroyedSet.has(curHwnd)) continue;
      const curWin = this._windows.get(curHwnd);
      if (!curWin) continue;
      destroyedSet.add(curHwnd);
      toDestroy.push(curWin);
      if (Array.isArray(curWin.childHwnds)) {
        for (const ch of curWin.childHwnds) {
          if (!destroyedSet.has(ch)) queue.push(ch);
        }
      }
    }

    // Release any live DCs associated with windows being destroyed
    const dcHandlesToDelete = [];
    for (const [h, rec] of this._handles.entries()) {
      if (rec && rec.kind === 'dc' && rec.win && destroyedSet.has(rec.win.hwnd)) {
        dcHandlesToDelete.push(h);
      }
    }
    for (const h of dcHandlesToDelete) {
      this._deleteHandle(h);
    }

    // Detach root destroyed window from its parent's child list if applicable
    if (win.parentHwnd && win.parentHwnd !== 0n) {
      const parent = this._windows.get(win.parentHwnd);
      if (parent && Array.isArray(parent.childHwnds)) {
        const idx = parent.childHwnds.indexOf(hwnd);
        if (idx !== -1) parent.childHwnds.splice(idx, 1);
        const root = this._findTopLevelOwner(parent);
        if (root && !destroyedSet.has(root.hwnd)) {
          this._markWindowSurfaceDirty(root);
        }
      }
    }

    for (const w of toDestroy) {
      w.destroyed = true;
      this._dirtySurfaceHwnds.delete(w.hwnd);
      if (w.windowId && this.services.compositor) {
        try {
          this.services.compositor.closeWindow(w.windowId, { notifyProcess: false, reason: 'DestroyWindow' });
        } catch (err) {
          void err;
        }
        this._windowsByCompositorId.delete(w.windowId);
        w.windowId = null;
      }
      if (w.drawOpBytes > 0) {
        this._totalDrawOpBytes = Math.max(0, this._totalDrawOpBytes - w.drawOpBytes);
        w.drawOpBytes = 0;
      }
      if (Array.isArray(w.drawOps)) w.drawOps.length = 0;
      if (w.listboxBytes > 0) {
        this._totalListboxBytes = Math.max(0, this._totalListboxBytes - w.listboxBytes);
        w.listboxBytes = 0;
      }
      if (Array.isArray(w.items)) w.items.length = 0;
      const textBytes = w.textBytes ?? (typeof w.text === 'string' ? w.text.length * 2 : 0);
      if (textBytes > 0) {
        this._totalWindowTextBytes = Math.max(0, this._totalWindowTextBytes - textBytes);
      }
      w.text = '';
      w.textBytes = 0;
      if (Array.isArray(w.childHwnds)) w.childHwnds.length = 0;
      this._windows.delete(w.hwnd);
    }
  }

  _destroyWindow(hwnd, { returnValue = 1n, fromThunk = true } = {}) {
    const win = this._windows.get(hwnd);
    if (!win || win.destroyed) return 0n;
    if (win.windowId) {
      this._flushSingleWindowSurfaceIfDirty(win);
    }
    win.destroyed = true;
    // Send WM_DESTROY to WNDPROC before closing compositor window & releasing records
    if (win.wndProcVa && win.wndProcVa !== 0n && this.cpu) {
      return this._dispatchWndProc(win, WIN32_CONSTANTS.WM_DESTROY, 0n, 0n, {
        fromThunk,
        onReturn: () => {
          this._finalizeDestroyWindow(hwnd);
          return returnValue;
        },
      });
    }
    this._finalizeDestroyWindow(hwnd);
    return returnValue;
  }

  /**
   * Deliver a Compositor input event into the Win32 message queue and wake the process.
   */
  deliverEvent(event) {
    if (!event || typeof event !== 'object') return;
    let targetHwnd = 0n;
    if (event.windowId && this._windowsByCompositorId.has(event.windowId)) {
      targetHwnd = this._windowsByCompositorId.get(event.windowId);
    } else {
      for (const w of this._windows.values()) {
        if (w.parentHwnd === 0n && !w.destroyed) {
          targetHwnd = w.hwnd;
          break;
        }
      }
    }

    const win = this._windows.get(targetHwnd);
    const type = String(event.type || '').toLowerCase();

    if (type === 'window_close' || type === 'close') {
      this._enqueueMessage({ hwnd: targetHwnd, message: WIN32_CONSTANTS.WM_CLOSE, wParam: 0n, lParam: 0n }, { force: true });
      return;
    }

    if (type === 'paint') {
      if (win) win.needsPaint = true;
      this._enqueueMessage({ hwnd: targetHwnd, message: WIN32_CONSTANTS.WM_PAINT, wParam: 0n, lParam: 0n }, { force: true });
      return;
    }

    if (type === 'input' || type === 'change' || type === 'text_input') {
      const ctrl = this._findChildControl(win, event);
      const rawText = event.value !== undefined ? String(event.value) : String(event.text ?? '');
      if (ctrl) {
        this._setWindowText(ctrl, rawText, { rejectOnEmpty: false });
        if (win) this._syncWindowSurface(win);
        const wParam = BigInt(((0x0300 << 16) | (ctrl.controlId & 0xffff)) >>> 0); // EN_CHANGE
        this._enqueueMessage({ hwnd: targetHwnd, message: WIN32_CONSTANTS.WM_COMMAND, wParam, lParam: ctrl.hwnd }, { force: true });
      }
      return;
    }

    if (type === 'click' || type === 'action') {
      const ctrl = this._findChildControl(win, event);
      if (ctrl) {
        const wParam = BigInt(ctrl.controlId & 0xffff); // BN_CLICKED (0) << 16 | controlId
        this._enqueueMessage({ hwnd: targetHwnd, message: WIN32_CONSTANTS.WM_COMMAND, wParam, lParam: ctrl.hwnd }, { force: true });
        return;
      }
      const x = Math.trunc(Number(event.x ?? 0)) & 0xffff;
      const y = Math.trunc(Number(event.y ?? 0)) & 0xffff;
      this._enqueueMessage({
        hwnd: targetHwnd,
        message: WIN32_CONSTANTS.WM_LBUTTONDOWN,
        wParam: 1n,
        lParam: BigInt(((y << 16) | x) >>> 0),
        ptX: x,
        ptY: y,
      }, { force: true });
      return;
    }

    if (type === 'keydown' || type === 'key') {
      const keyCode = Number(event.keyCode ?? (typeof event.key === 'string' && event.key.length === 1 ? event.key.charCodeAt(0) : 0));
      this._enqueueMessage({ hwnd: targetHwnd, message: WIN32_CONSTANTS.WM_KEYDOWN, wParam: BigInt(keyCode & 0xff), lParam: 1n }, { force: true });
      if (typeof event.key === 'string' && event.key.length === 1) {
        this._enqueueMessage({ hwnd: targetHwnd, message: WIN32_CONSTANTS.WM_CHAR, wParam: BigInt(event.key.charCodeAt(0)), lParam: 1n }, { force: true });
      }
      return;
    }

    // Raw Win32 message injection support
    if (type === 'wm' && typeof event.message === 'number') {
      this._enqueueMessage({
        hwnd: targetHwnd,
        message: event.message,
        wParam: BigInt(event.wParam ?? 0),
        lParam: BigInt(event.lParam ?? 0),
      }, { force: true });
    }
  }

  _findChildControl(parentWin, event) {
    if (!parentWin) return null;
    let targetCtrlId = null;
    if (Number.isInteger(event.controlId)) {
      targetCtrlId = event.controlId;
    } else if (typeof event.action === 'string' && event.action.startsWith('command:')) {
      const parsed = parseInt(event.action.slice(8), 10);
      if (Number.isInteger(parsed)) targetCtrlId = parsed;
    } else if (typeof event.targetId === 'string' && event.targetId.startsWith('ctrl-')) {
      const parsed = parseInt(event.targetId.slice(5), 10);
      if (Number.isInteger(parsed)) targetCtrlId = parsed;
    } else if (typeof event.id === 'string' && event.id.startsWith('ctrl-')) {
      const parsed = parseInt(event.id.slice(5), 10);
      if (Number.isInteger(parsed)) targetCtrlId = parsed;
    }

    for (const childHwnd of parentWin.childHwnds) {
      const ctrl = this._windows.get(childHwnd);
      if (!ctrl) continue;
      if (targetCtrlId !== null && ctrl.controlId === targetCtrlId) return ctrl;
      if (event.label && ctrl.text === event.label) return ctrl;
    }
    return null;
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    if (this._unsubConfigChanged) {
      try {
        this._unsubConfigChanged();
      } catch (err) {
        void err;
      }
      this._unsubConfigChanged = null;
    }
    this._hasConfigChangeListener = false;
    this._invalidateRegCache({ includeKeyExists: true });
    this._invalidateReaddirCache();
    if (this.services.compositor) {
      for (const win of this._windows.values()) {
        if (win.windowId) {
          try {
            this.services.compositor.closeWindow(win.windowId, { notifyProcess: false, reason: 'dispose' });
          } catch (err) {
            void err;
          }
        }
      }
    }
    this._windows.clear();
    this._windowsByCompositorId.clear();
    this._dirtySurfaceHwnds.clear();
    this._windowClasses.clear();
    for (const rec of this._handles.values()) {
      if (rec && rec.kind === 'file' && rec._readCache) {
        rec._readCache = null;
      }
    }
    this._handles.clear();
    this._readCacheBytes = 0;
    this._vfsWriteGen.clear();
    this._vfsInoWriteGen.clear();
    this._dcHandleCount = 0;
    this._findHandleCount = 0;
    this._regHandleCount = 0;
    this._totalDrawOpBytes = 0;
    this._totalListboxBytes = 0;
    this._totalWindowTextBytes = 0;
    this._stockHandles.clear();
    this._globalAllocs.clear();
    this._modules.clear();
    this._modulesByHandle.clear();
    this._permAuditedKeys.clear();
    this._messageQueue.length = 0;
  }

  // ============================================================================
  // Registry Root & Path Resolution Helper
  // ============================================================================

  _resolveRegHandle(rawHKey) {
    const masked32 = Number(BigInt(rawHKey) & 0xffffffffn);
    if (Object.prototype.hasOwnProperty.call(ROOT_HKEY_TO_HIVE, masked32)) {
      return { hive: ROOT_HKEY_TO_HIVE[masked32], keyPath: '', isRoot: true, deleted: false };
    }
    const rec = this._handles.get(this.is64 ? rawHKey : BigInt(masked32));
    if (rec && rec.kind === 'reg') {
      return { hive: rec.hive, keyPath: rec.keyPath, isRoot: false, deleted: Boolean(rec.deleted) };
    }
    return null;
  }

  _markDeletedRegHandles(hive, fullPath) {
    const deletedNorm = normalizeRegKeyNorm(fullPath);
    if (!deletedNorm) return;
    const isSubtreeMatch = (recNorm, targetNorm) =>
      recNorm === targetNorm || recNorm.startsWith(`${targetNorm}\\`);
    const classesPrefix = 'software\\classes';
    const classesPrefixSlash = 'software\\classes\\';

    for (const rec of this._handles.values()) {
      if (!rec || rec.kind !== 'reg' || rec.deleted || !rec.keyPath) continue;
      const recNorm = normalizeRegKeyNorm(rec.keyPath);
      if (!recNorm) continue;

      if (rec.hive === hive && isSubtreeMatch(recNorm, deletedNorm)) {
        rec.deleted = true;
        continue;
      }

      // Cross-hive write-target aliasing between HKCR and HKCU\Software\Classes (non-root)
      // or HKLM\Software\Classes (root)
      const aliasHive = this.uid === 0 ? 'HKLM' : 'HKCU';
      if (hive === 'HKCR' && rec.hive === aliasHive) {
        const aliasedTarget = `${classesPrefixSlash}${deletedNorm}`;
        if (isSubtreeMatch(recNorm, aliasedTarget)) {
          rec.deleted = true;
        }
      } else if (hive === aliasHive && rec.hive === 'HKCR') {
        if (deletedNorm === 'software' || deletedNorm === classesPrefix) {
          rec.deleted = true;
        } else if (deletedNorm.startsWith(classesPrefixSlash)) {
          const suffix = deletedNorm.slice(classesPrefixSlash.length);
          if (suffix && isSubtreeMatch(recNorm, suffix)) {
            rec.deleted = true;
          }
        }
      }
    }
  }

  _regCtx() {
    return {
      uid: this.pcb?.uid ?? 1000,
      appId: this.pcb?.appId || this.appRecord?.appId || `pid-${this.pcb?.pid ?? 0}`,
      pid: this.pcb?.pid ?? null,
    };
  }

  _regVirtPrefixBytes(hive, regCtx = null) {
    if (this.uid === 0) return 0;
    if (hive === 'HKLM') {
      const ctx = regCtx ?? this._regCtx();
      const appId = typeof ctx?.appId === 'string' ? ctx.appId : '';
      // UnifiedConfigStore VirtualStore persists `MACHINE\app_<hex(utf8(appId))>\`
      const actualVirtPrefixUtf8Bytes = 13 + UTF8_ENCODER.encode(appId).byteLength * 2;
      return Math.max(64, actualVirtPrefixUtf8Bytes);
    }
    if (hive === 'HKCR') {
      // UnifiedConfigStore persists non-root HKCR under HKCU `Software\Classes\` (17 bytes)
      return UTF8_ENCODER.encode('Software\\Classes\\').byteLength;
    }
    return 0;
  }

  _readRegKeysSignature() {
    const storage = this.services?.kernel?.storage ?? this.services?.configStore?._storage;
    if (!storage || typeof storage.get !== 'function' || storage.isOpen === false) {
      return null;
    }
    try {
      const row = storage.get(
        'SELECT COUNT(*) AS cnt, COALESCE(MAX(rowid), 0) AS maxRow FROM registry_keys'
      );
      return `${row?.cnt ?? 0}:${row?.maxRow ?? 0}`;
    } catch (err) {
      void err;
      return null;
    }
  }

  _chargeRegReadQuota(byteCount) {
    if (this.uid === 0) return true;
    const add = Number.isFinite(byteCount) && byteCount > 0 ? Math.trunc(byteCount) : 0;
    if (add === 0) return true;
    if (this._regReadBytes + add > MAX_BRIDGE_REG_READ_BYTES) {
      return false;
    }
    this._regReadBytes += add;
    return true;
  }

  _evictRegCacheToFit(neededBytes, preserveEnumKey = null, preserveValKey = null) {
    if (this._regCacheBytes + neededBytes <= MAX_BRIDGE_REG_CACHE_BYTES) return true;
    for (const [k, v] of this._regValCache.entries()) {
      if (k === preserveValKey) continue;
      this._regValCache.delete(k);
      this._regCacheBytes = Math.max(0, this._regCacheBytes - (v.totalBytes ?? v.costBytes ?? 0));
      if (this._regCacheBytes + neededBytes <= MAX_BRIDGE_REG_CACHE_BYTES) return true;
    }
    for (const [k, v] of this._regEnumCache.entries()) {
      if (k === preserveEnumKey) continue;
      this._regEnumCache.delete(k);
      this._regCacheBytes = Math.max(0, this._regCacheBytes - (v.totalBytes ?? v.costBytes ?? 0));
      if (this._regCacheBytes + neededBytes <= MAX_BRIDGE_REG_CACHE_BYTES) return true;
    }
    return this._regCacheBytes + neededBytes <= MAX_BRIDGE_REG_CACHE_BYTES;
  }

  _clearRegDataCaches() {
    this._regEnumCache.clear();
    this._regValCache.clear();
    this._regCacheBytes = 0;
  }

  _invalidateRegCache({ includeKeyExists = true } = {}) {
    this._clearRegDataCaches();
    if (includeKeyExists) {
      this._regKeyExistsCache.clear();
      this._lastGlobalRegCreateKeyGen = globalRegCreateKeyGen;
      this._lastRegKeysSig = null;
    }
  }

  _checkRegCreateKeyCoherency() {
    if (!this._hasConfigChangeListener) {
      this._invalidateRegCache({ includeKeyExists: true });
      return;
    }
    const sig = this._readRegKeysSignature();
    if (
      globalRegCreateKeyGen !== this._lastGlobalRegCreateKeyGen ||
      sig === null ||
      this._lastRegKeysSig === null ||
      sig !== this._lastRegKeysSig
    ) {
      this._invalidateRegCache({ includeKeyExists: true });
      this._lastGlobalRegCreateKeyGen = globalRegCreateKeyGen;
      this._lastRegKeysSig = sig;
    }
  }

  _ensureRegCacheCoherentForTick() {
    const genChanged = globalRegCreateKeyGen !== this._lastGlobalRegCreateKeyGen;
    if (!this._regCacheNeedsTickCheck && !genChanged) return;
    this._regCacheNeedsTickCheck = false;
    if (this._regEnumCache.size === 0 && this._regKeyExistsCache.size === 0) {
      this._lastGlobalRegCreateKeyGen = globalRegCreateKeyGen;
      this._lastRegKeysSig = null;
      return;
    }
    this._checkRegCreateKeyCoherency();
  }

  _clearNegativeRegKeyExists() {
    for (const [k, v] of this._regKeyExistsCache.entries()) {
      if (!v) this._regKeyExistsCache.delete(k);
    }
  }

  _setRegKeyExistsCache(hive, normPath, exists) {
    if (this._regKeyExistsCache.size >= MAX_BRIDGE_REG_EXISTS_ENTRIES) {
      this._regKeyExistsCache.clear();
    }
    this._regKeyExistsCache.set(`${hive}\0${normPath}`, Boolean(exists));
  }

  _markRegKeyChainExists(hive, fullPath) {
    const norm = normalizeRegKeyNorm(fullPath);
    if (!norm) return;
    const markPrefixChain = (targetHive, pathStr) => {
      const segs = pathStr.split('\\').filter(Boolean);
      let acc = '';
      for (let i = 0; i < segs.length; i += 1) {
        acc = i === 0 ? segs[i] : `${acc}\\${segs[i]}`;
        this._setRegKeyExistsCache(targetHive, acc, true);
      }
    };
    markPrefixChain(hive, norm);
    if (hive === 'HKCR') {
      const targetHive = this.uid === 0 ? 'HKLM' : 'HKCU';
      markPrefixChain(targetHive, `software\\classes\\${norm}`);
    } else if (
      ((this.uid !== 0 && hive === 'HKCU') || (this.uid === 0 && hive === 'HKLM')) &&
      norm.startsWith('software\\classes\\')
    ) {
      const suffix = norm.slice('software\\classes\\'.length);
      if (suffix) markPrefixChain('HKCR', suffix);
    }
  }

  _estimateRegValueDataBytes(rec) {
    if (!rec) return 0;
    const type = rec.type;
    const data = rec.data;
    if (type === 'REG_MULTI_SZ' && Array.isArray(data)) {
      let bytes = data.length * 64;
      for (let i = 0; i < data.length; i += 1) {
        bytes += String(data[i] ?? '').length * 2;
      }
      return bytes;
    }
    if (type === 'REG_SZ' || type === 'REG_EXPAND_SZ') {
      return String(data ?? '').length * 2;
    }
    if (type === 'REG_DWORD' || type === 'REG_QWORD') {
      return 16;
    }
    if (data instanceof Uint8Array || ArrayBuffer.isView(data)) {
      return data.byteLength;
    }
    return String(data ?? '').length * 2;
  }

  _isSafeCacheableRegKeyPath(keyPath) {
    if (typeof keyPath !== 'string' || keyPath.includes('\0') || keyPath.length > 4096) {
      return false;
    }
    if (keyPath === '') return true;
    const cleaned = keyPath.replace(/\//g, '\\').replace(/^\\+|\\+$/g, '').replace(/\\+/g, '\\');
    if (!cleaned) return true;
    const segs = cleaned.split('\\');
    if (segs.length > 64) return false;
    for (let i = 0; i < segs.length; i += 1) {
      const s = segs[i];
      if (s.length > 255) return false;
      if (this.uid !== 0 && (s === '.' || s === '..')) return false;
    }
    return true;
  }

  _regEnumKeyCached(hive, keyPath, regCtx = null) {
    this._ensureRegCacheCoherentForTick();
    const ctx = regCtx ?? this._regCtx();
    const cacheable = this._isSafeCacheableRegKeyPath(keyPath);
    const normPath = cacheable ? normalizeRegKeyNorm(keyPath) : '';
    const cacheKey = cacheable ? `${hive}\0${normPath}` : '';
    if (cacheable) {
      const cached = this._regEnumCache.get(cacheKey);
      if (cached) {
        return { quotaExceeded: false, ...cached };
      }
    }
    if (this.uid !== 0 && this._regReadBytes >= MAX_BRIDGE_REG_READ_BYTES) {
      return { quotaExceeded: true, res: null, subkeys: [], valueNames: [], valueEntries: null };
    }
    const res = this.services.configStore.registry.enumKey(hive, keyPath, ctx);
    const subkeys = Array.isArray(res?.subkeys) ? res.subkeys : [];
    const valuesObj = res?.values && typeof res.values === 'object' ? res.values : {};
    const valueNames = Object.keys(valuesObj);
    const valueEntries = Object.create(null);
    let costBytes = 256;
    for (let i = 0; i < subkeys.length; i += 1) {
      costBytes += Buffer.byteLength(String(subkeys[i] ?? ''), 'utf8') + 16;
    }
    for (let i = 0; i < valueNames.length; i += 1) {
      const vn = valueNames[i];
      const rec = valuesObj[vn];
      costBytes += Buffer.byteLength(vn, 'utf8') + 32 + this._estimateRegValueDataBytes(rec);
      valueEntries[vn] = {
        rec,
        byteLenA: null,
        byteLenW: null,
        bytesA: null,
        bytesW: null,
        ownerEnumKey: null,
        ownerEnumEntry: null,
      };
    }
    if (this.uid !== 0) {
      this._regReadBytes += costBytes;
      if (this._regReadBytes > MAX_BRIDGE_REG_READ_BYTES) {
        return { quotaExceeded: true, res: null, subkeys: [], valueNames: [], valueEntries: null };
      }
    }
    const entry = { res, subkeys, valueNames, valueEntries, costBytes, totalBytes: costBytes, cacheKey: null };
    if (cacheable) {
      if (this._lastRegKeysSig === null) {
        this._lastGlobalRegCreateKeyGen = globalRegCreateKeyGen;
        this._lastRegKeysSig = this._readRegKeysSignature();
      }
      this._setRegKeyExistsCache(hive, normPath, Boolean(res?.exists));
      if (costBytes <= MAX_BRIDGE_REG_CACHE_BYTES && this._evictRegCacheToFit(costBytes)) {
        entry.cacheKey = cacheKey;
        for (let i = 0; i < valueNames.length; i += 1) {
          const ve = valueEntries[valueNames[i]];
          ve.ownerEnumKey = cacheKey;
          ve.ownerEnumEntry = entry;
        }
        this._regEnumCache.set(cacheKey, entry);
        this._regCacheBytes += costBytes;
      }
    }
    return { quotaExceeded: false, ...entry };
  }

  _regKeyExists(hive, keyPath, regCtx = null) {
    this._ensureRegCacheCoherentForTick();
    const ctx = regCtx ?? this._regCtx();
    if (this._isSafeCacheableRegKeyPath(keyPath)) {
      const normPath = normalizeRegKeyNorm(keyPath);
      const cached = this._regKeyExistsCache.get(`${hive}\0${normPath}`);
      if (cached !== undefined) {
        return { quotaExceeded: false, exists: cached };
      }
    }
    const enumWrap = this._regEnumKeyCached(hive, keyPath, ctx);
    if (enumWrap.quotaExceeded) {
      return { quotaExceeded: true, exists: false };
    }
    return { quotaExceeded: false, exists: Boolean(enumWrap.res?.exists) };
  }

  _regGetValueCached(hive, keyPath, valName, regCtx = null) {
    const ctx = regCtx ?? this._regCtx();
    const safeVal =
      valName === null ||
      valName === undefined ||
      (typeof valName === 'string' && !valName.includes('\0') && valName.length <= 4096);
    const cacheable = this._isSafeCacheableRegKeyPath(keyPath) && safeVal;
    const normPath = cacheable ? normalizeRegKeyNorm(keyPath) : '';
    const normVal = cacheable ? String(valName ?? '').toLowerCase() : '';
    const cacheKey = cacheable ? `${hive}\0${normPath}\0${normVal}` : '';
    if (cacheable) {
      const cached = this._regValCache.get(cacheKey);
      if (cached) {
        return { quotaExceeded: false, entry: cached };
      }
    }
    if (this.uid !== 0 && this._regReadBytes >= MAX_BRIDGE_REG_READ_BYTES) {
      return { quotaExceeded: true, entry: null };
    }
    const rec = this.services.configStore.registry.getValue(hive, keyPath, valName, ctx);
    const costBytes =
      256 +
      Buffer.byteLength(String(valName ?? ''), 'utf8') +
      this._estimateRegValueDataBytes(rec);
    if (this.uid !== 0) {
      this._regReadBytes += costBytes;
      if (this._regReadBytes > MAX_BRIDGE_REG_READ_BYTES) {
        return { quotaExceeded: true, entry: null };
      }
    }
    const entry = {
      rec,
      byteLenA: null,
      byteLenW: null,
      bytesA: null,
      bytesW: null,
      costBytes,
      totalBytes: costBytes,
      cacheKey: null,
    };
    if (cacheable && costBytes <= MAX_BRIDGE_REG_CACHE_BYTES && this._evictRegCacheToFit(costBytes)) {
      entry.cacheKey = cacheKey;
      this._regValCache.set(cacheKey, entry);
      this._regCacheBytes += costBytes;
    }
    return { quotaExceeded: false, entry };
  }

  _measureMissingRegKeyChain(hive, fullPath, regCtx = null, { maxRows = Infinity, maxBytes = Infinity } = {}) {
    const segments = String(fullPath ?? '')
      .replace(/\//g, '\\')
      .replace(/^\\+|\\+$/g, '')
      .split(/\\+/)
      .filter(Boolean);
    const n = segments.length;
    if (n === 0) {
      return { missingRows: 0, chainBytes: 0, quotaExceeded: false };
    }
    const ctx = regCtx ?? this._regCtx();
    const extraPrefixUtf8 = this._regVirtPrefixBytes(hive, ctx);

    // Always run full-leaf validation probe FIRST so UnifiedConfigStore validates depth (<=64),
    // segment lengths (<=255), and `..` traversal identically.
    const leafCheck = this._regKeyExists(hive, segments.join('\\'), ctx);
    if (leafCheck.quotaExceeded) {
      return { missingRows: 0, chainBytes: 0, quotaExceeded: true };
    }

    // Non-root HKCR writes strictly into HKCU\Software\Classes\<keyPath>, NEVER __VIRTUALSTORE__ or global HKLM.
    // Probing the actual write target prevents HKLM\Software\Classes VirtualStore shadowing bypasses.
    const isNonRootHkcr = this.uid !== 0 && hive === 'HKCR';
    let quotaExceeded = false;
    const existsAt = (len) => {
      if (isNonRootHkcr) {
        if (len <= 62) {
          const p = this._regKeyExists(
            'HKCU',
            `Software\\Classes\\${segments.slice(0, len).join('\\')}`,
            ctx
          );
          if (p.quotaExceeded) {
            quotaExceeded = true;
            return false;
          }
          return Boolean(p.exists);
        }
        if (len === 63) {
          const p62 = this._regEnumKeyCached(
            'HKCU',
            `Software\\Classes\\${segments.slice(0, 62).join('\\')}`,
            ctx
          );
          if (p62.quotaExceeded) {
            quotaExceeded = true;
            return false;
          }
          const targetLower = segments[62].toLowerCase();
          return Boolean(
            p62.res &&
            p62.res.exists &&
            Array.isArray(p62.subkeys) &&
            p62.subkeys.some((s) => s.toLowerCase() === targetLower)
          );
        }
        // len >= 64: conservatively treat leaf as missing (avoids 66-segment HKCU depth error, charges <= 1 row)
        return false;
      }
      if (len === n) {
        return Boolean(leafCheck.exists);
      }
      const probe = this._regKeyExists(hive, segments.slice(0, len).join('\\'), ctx);
      if (probe.quotaExceeded) {
        quotaExceeded = true;
        return false;
      }
      return Boolean(probe.exists);
    };

    const leafExists = existsAt(n);
    if (quotaExceeded) {
      return { missingRows: 0, chainBytes: 0, quotaExceeded: true };
    }
    if (leafExists) {
      return { missingRows: 0, chainBytes: 0, quotaExceeded: false };
    }

    // Because _ensureKeyChain/_regDeleteKey keep registry_keys prefix-closed, existence is monotone in prefix length
    let existingDepth = 0;
    if (n > 1) {
      const prevExists = existsAt(n - 1);
      if (quotaExceeded) {
        return { missingRows: 0, chainBytes: 0, quotaExceeded: true };
      }
      if (prevExists) {
        existingDepth = n - 1;
      } else if (n > 2) {
        const firstExists = existsAt(1);
        if (quotaExceeded) {
          return { missingRows: 0, chainBytes: 0, quotaExceeded: true };
        }
        if (!firstExists) {
          existingDepth = 0;
        } else {
          let lo = 1;
          let hi = n - 1;
          while (lo + 1 < hi) {
            const mid = (lo + hi) >>> 1;
            const midExists = existsAt(mid);
            if (quotaExceeded) {
              return { missingRows: 0, chainBytes: 0, quotaExceeded: true };
            }
            if (midExists) lo = mid;
            else hi = mid;
          }
          existingDepth = lo;
        }
      }
    }

    let missingRows = 0;
    let chainBytes = 0;
    let prefixUtf8 = 0;
    for (let i = 0; i < n; i += 1) {
      const segBytes = regUtf8Max(segments[i]);
      prefixUtf8 += i === 0 ? segBytes : (1 + segBytes);
      if (i + 1 > existingDepth) {
        missingRows += 1;
        // Accounts for key_path_norm, key_path_orig, parent_path_norm, PRIMARY KEY + parent B-tree indexes & 4 KiB page fill slack (including astral UTF-8)
        chainBytes += 6 * (extraPrefixUtf8 + prefixUtf8) + 320;
        if (missingRows > maxRows || chainBytes > maxBytes) {
          break;
        }
      }
    }
    return { missingRows, chainBytes, quotaExceeded: false };
  }

  // ============================================================================
  // Win32 API Dispatch Tables (`kernel32`, `user32`, `gdi32`, `advapi32`, `shell32`, `msvcrt`)
  // ============================================================================

  _buildApiTable() {
    const b = this;

    // ---- Shared Kernel32 File/Console Implementations ----
    const createFileImpl = (args, isWide) => {
      const [lpFileName, dwDesiredAccess, _dwShareMode, _lpSec, dwCreationDisposition] = args;
      const rawName = b._readString(lpFileName, isWide);
      if (!rawName) {
        b.lastError = WIN32_ERROR.ERROR_INVALID_NAME;
        return b.invalidHandle;
      }

      const upper = rawName.toUpperCase();
      if (upper === 'CONOUT$') return b.STD_OUT;
      if (upper === 'CONIN$') return b.STD_IN;
      if (upper === 'NUL') {
        const hNul = b._allocHandle({ kind: 'nul' });
        return hNul ?? b.invalidHandle;
      }

      const access = Number(dwDesiredAccess & 0xffffffffn) >>> 0;
      const disp = Number(dwCreationDisposition & 0xffffffffn) >>> 0;
      const readMask =
        WIN32_CONSTANTS.GENERIC_READ |
        WIN32_CONSTANTS.GENERIC_ALL |
        WIN32_CONSTANTS.FILE_READ_DATA;
      const writeMask =
        WIN32_CONSTANTS.GENERIC_WRITE |
        WIN32_CONSTANTS.GENERIC_ALL |
        WIN32_CONSTANTS.FILE_WRITE_DATA |
        WIN32_CONSTANTS.FILE_APPEND_DATA;

      const wantsRead = (access & readMask) !== 0;
      const hasWriteAccess = (access & writeMask) !== 0;
      const willDefinitelyWrite =
        hasWriteAccess ||
        disp === WIN32_CONSTANTS.CREATE_NEW ||
        disp === WIN32_CONSTANTS.CREATE_ALWAYS ||
        disp === WIN32_CONSTANTS.TRUNCATE_EXISTING;

      let resolveMode = 'read';
      if (wantsRead && willDefinitelyWrite) {
        resolveMode = 'readwrite';
      } else if (willDefinitelyWrite) {
        resolveMode = 'write';
      } else {
        resolveMode = 'read';
      }

      try {
        const { canonicalPath, vfsCtx, isSharedUser } = b._resolveVfsPath(rawName, resolveMode);
        const vfs = b.services.vfs;
        let exists = false;
        let existingIno = null;
        try {
          const st = vfs.stat(canonicalPath, vfsCtx);
          if (st.type === 'dir') {
            b.lastError = WIN32_ERROR.ERROR_ACCESS_DENIED;
            return b.invalidHandle;
          }
          exists = true;
          existingIno = st?.ino ?? null;
        } catch (stErr) {
          if (stErr?.code !== ERROR_CODES.ENOENT) throw stErr;
        }

        if (disp === WIN32_CONSTANTS.CREATE_NEW) {
          if (exists) {
            b.lastError = WIN32_ERROR.ERROR_FILE_EXISTS;
            return b.invalidHandle;
          }
          if (!b._checkVfsCreateQuota(1)) {
            return b.invalidHandle;
          }
          const written = vfs.writeFile(canonicalPath, new Uint8Array(0), vfsCtx);
          b._bumpVfsWriteGen(canonicalPath, written?.ino ?? existingIno);
          b._recordVfsCreateQuota(1);
          b.lastError = WIN32_ERROR.ERROR_SUCCESS;
        } else if (disp === WIN32_CONSTANTS.CREATE_ALWAYS) {
          if (!exists && !b._checkVfsCreateQuota(1)) {
            return b.invalidHandle;
          }
          const written = vfs.writeFile(canonicalPath, new Uint8Array(0), vfsCtx);
          b._bumpVfsWriteGen(canonicalPath, written?.ino ?? existingIno);
          if (!exists) {
            b._recordVfsCreateQuota(1);
          }
          b.lastError = exists ? WIN32_ERROR.ERROR_ALREADY_EXISTS : WIN32_ERROR.ERROR_SUCCESS;
        } else if (disp === WIN32_CONSTANTS.OPEN_EXISTING) {
          if (!exists) {
            b.lastError = WIN32_ERROR.ERROR_FILE_NOT_FOUND;
            return b.invalidHandle;
          }
          b.lastError = WIN32_ERROR.ERROR_SUCCESS;
        } else if (disp === WIN32_CONSTANTS.OPEN_ALWAYS) {
          if (!exists) {
            if (isSharedUser && !willDefinitelyWrite && !b._checkCapSync('fs.write.user', { path: canonicalPath, mode: 'write' })) {
              b.lastError = WIN32_ERROR.ERROR_ACCESS_DENIED;
              return b.invalidHandle;
            }
            if (!b._checkVfsCreateQuota(1)) {
              return b.invalidHandle;
            }
            const written = vfs.writeFile(canonicalPath, new Uint8Array(0), vfsCtx);
            b._bumpVfsWriteGen(canonicalPath, written?.ino ?? existingIno);
            b._recordVfsCreateQuota(1);
            b.lastError = WIN32_ERROR.ERROR_SUCCESS;
          } else {
            b.lastError = WIN32_ERROR.ERROR_ALREADY_EXISTS;
          }
        } else if (disp === WIN32_CONSTANTS.TRUNCATE_EXISTING) {
          if (!exists) {
            b.lastError = WIN32_ERROR.ERROR_FILE_NOT_FOUND;
            return b.invalidHandle;
          }
          const written = vfs.writeFile(canonicalPath, new Uint8Array(0), vfsCtx);
          b._bumpVfsWriteGen(canonicalPath, written?.ino ?? existingIno);
          b.lastError = WIN32_ERROR.ERROR_SUCCESS;
        } else {
          b.lastError = WIN32_ERROR.ERROR_INVALID_PARAMETER;
          return b.invalidHandle;
        }

        const hFile = b._allocHandle({
          kind: 'file',
          winPath: rawName,
          canonicalPath,
          vfsCtx,
          pos: 0,
          access,
          canRead: wantsRead,
          canWrite: hasWriteAccess,
          _readCache: null,
        });
        return hFile ?? b.invalidHandle;
      } catch (err) {
        b._setErrorFromException(err);
        return b.invalidHandle;
      }
    };

    const writeConsoleImpl = (args, isWide) => {
      const [hConsole, lpBuf, nChars, lpWritten] = args;
      const count = Number(nChars & 0xffffffffn) >>> 0;
      const byteLen = isWide ? count * 2 : count;
      const baseAddr = b.is64 ? lpBuf : (lpBuf & 0xffffffffn);
      const safeByteLen = b._normalizeMemOpLen(byteLen, baseAddr, 'WriteConsole');
      const pm = b.services.processManager;
      const chunkBytes = isWide ? (MEM_OP_CHUNK_BYTES & ~1) : MEM_OP_CHUNK_BYTES;
      let offset = 0;
      while (offset < safeByteLen) {
        const step = Math.min(safeByteLen - offset, chunkBytes);
        const raw = b.addressSpace.read(baseAddr + BigInt(offset), step);
        const text = isWide ? UTF16LE_DECODER.decode(raw) : UTF8_DECODER.decode(raw);
        if (hConsole === b.STD_ERR) {
          pm?.writeStderr?.(b.pcb.pid, text);
        } else {
          pm?.writeStdout?.(b.pcb.pid, text);
        }
        offset += step;
      }
      if (lpWritten !== 0n) b._writeU32(lpWritten, count);
      b.lastError = WIN32_ERROR.ERROR_SUCCESS;
      return 1n;
    };

    const readConsoleImpl = (args, isWide) => {
      const [_hConsole, lpBuf, nChars, lpRead] = args;
      const maxChars = Number(nChars & 0xffffffffn);
      const pm = b.services.processManager;
      const str = pm?.readStdin?.(b.pcb.pid, maxChars, { encoding: 'utf8', consume: true }) ?? '';
      const chars = str.slice(0, maxChars);
      if (isWide) {
        const enc = encodeUtf16LE(chars, false);
        if (enc.byteLength > 0) b.addressSpace.write(lpBuf, enc);
      } else {
        const enc = UTF8_ENCODER.encode(chars);
        if (enc.byteLength > 0) b.addressSpace.write(lpBuf, enc.subarray(0, maxChars));
      }
      if (lpRead !== 0n) b._writeU32(lpRead, chars.length);
      b.lastError = WIN32_ERROR.ERROR_SUCCESS;
      return 1n;
    };

    const writeFindData = (lpFindData, name, stat, isWide) => {
      const attrs = stat.type === 'dir' ? WIN32_CONSTANTS.FILE_ATTRIBUTE_DIRECTORY : WIN32_CONSTANTS.FILE_ATTRIBUTE_NORMAL;
      const size = stat.size ?? 0;
      const structSize = isWide ? 592 : 320;
      const buf = new Uint8Array(structSize);
      const dv = new DataView(buf.buffer);
      dv.setUint32(0, attrs, true);
      dv.setUint32(28, Math.floor(size / 0x100000000), true); // nFileSizeHigh
      dv.setUint32(32, size >>> 0, true); // nFileSizeLow
      if (isWide) {
        const enc = encodeUtf16LE(name.slice(0, 259), true);
        buf.set(enc, 44);
      } else {
        const enc = UTF8_ENCODER.encode(name.slice(0, 259));
        buf.set(enc, 44);
      }
      b.addressSpace.write(lpFindData, buf);
    };

    const findFirstFileImpl = (args, isWide) => {
      const [lpFileName, lpFindData] = args;
      const patternPath = b._readString(lpFileName, isWide, MAX_FIND_PATH_CHARS + 1);
      if (!patternPath) {
        b.lastError = WIN32_ERROR.ERROR_INVALID_NAME;
        return b.invalidHandle;
      }
      if (
        patternPath.length > MAX_FIND_PATH_CHARS ||
        (!isWide && Buffer.byteLength(patternPath, 'utf8') > MAX_FIND_PATH_CHARS)
      ) {
        b.lastError = ERROR_FILENAME_EXCED_RANGE;
        return b.invalidHandle;
      }
      const norm = patternPath.replace(/\//g, '\\');
      const lastSlash = norm.lastIndexOf('\\');
      const dirPart = lastSlash === -1 ? '.' : (norm.slice(0, lastSlash) || '\\');
      const maskPart = lastSlash === -1 ? norm : norm.slice(lastSlash + 1);
      const mask = maskPart || '*';
      try {
        const { canonicalPath, vfsCtx } = b._resolveVfsPath(dirPart, 'read');
        const { quotaExceeded, entries, cacheEntry } = b._readdirCached(canonicalPath, vfsCtx);
        if (quotaExceeded) {
          return b.invalidHandle;
        }
        let matches;
        if (mask === '*') {
          matches = entries;
        } else {
          const maskLower = mask.toLowerCase().replace(/\*+/g, '*');
          if (maskLower === '*') {
            matches = entries;
          } else {
            const cachedMatches = cacheEntry?.maskCache?.get(maskLower);
            if (cachedMatches) {
              matches = cachedMatches;
            } else {
              if (maskLower !== '*.*') {
                const filterCost = Math.max(64, entries.length * 64 + maskLower.length * 8);
                if (!b._checkVfsReadQuota(filterCost)) {
                  return b.invalidHandle;
                }
                b._recordVfsReadQuota(filterCost);
              }
              const matcher = compileWildcardMatcherLower(maskLower);
              matches = entries.filter((e) => matcher(e.nameLower));
              if (cacheEntry && cacheEntry.maskCache) {
                if (cacheEntry.maskCache.size >= 32 && maskLower === '*.*') {
                  const oldestKey = cacheEntry.maskCache.keys().next().value;
                  if (oldestKey !== undefined) cacheEntry.maskCache.delete(oldestKey);
                }
                if (cacheEntry.maskCache.size < 32) {
                  cacheEntry.maskCache.set(maskLower, matches);
                }
              }
            }
          }
        }
        if (matches.length === 0) {
          b.lastError = WIN32_ERROR.ERROR_FILE_NOT_FOUND;
          return b.invalidHandle;
        }
        const hFind = b._allocHandle({ kind: 'find', matches, index: 1 });
        if (hFind === null) return b.invalidHandle;
        writeFindData(lpFindData, matches[0].name, matches[0], isWide);
        b.lastError = WIN32_ERROR.ERROR_SUCCESS;
        return hFind;
      } catch (err) {
        b._setErrorFromException(err);
        return b.invalidHandle;
      }
    };

    const findNextFileImpl = (args, isWide) => {
      const [hFind, lpFindData] = args;
      const rec = b._handles.get(hFind);
      if (!rec || rec.kind !== 'find') {
        b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
        return 0n;
      }
      if (rec.index >= rec.matches.length) {
        b.lastError = WIN32_ERROR.ERROR_NO_MORE_ITEMS;
        return 0n;
      }
      const item = rec.matches[rec.index++];
      writeFindData(lpFindData, item.name, item, isWide);
      b.lastError = WIN32_ERROR.ERROR_SUCCESS;
      return 1n;
    };

    const moveFileImpl = (lpOld, lpNew, isWide, replaceExisting) => {
      try {
        const oldPath = b._readString(lpOld, isWide);
        const newPath = b._readString(lpNew, isWide);
        const src = b._resolveVfsPath(oldPath, 'readwrite');
        const dst = b._resolveVfsPath(newPath, 'write');
        const vfs = b.services.vfs;

        const srcStat = vfs.lstat(src.canonicalPath, src.vfsCtx);
        const sameRoot =
          src.vfsCtx.sandboxRoot === dst.vfsCtx.sandboxRoot &&
          src.vfsCtx.uid === dst.vfsCtx.uid;

        let dstStat = null;
        try {
          dstStat = vfs.lstat(dst.canonicalPath, dst.vfsCtx);
        } catch (stErr) {
          if (stErr?.code !== ERROR_CODES.ENOENT) throw stErr;
        }

        if (sameRoot) {
          if (dstStat && !replaceExisting && src.canonicalPath.toLowerCase() !== dst.canonicalPath.toLowerCase()) {
            b.lastError = WIN32_ERROR.ERROR_ALREADY_EXISTS;
            return 0n;
          }
          vfs.rename(src.canonicalPath, dst.canonicalPath, dst.vfsCtx);
          b._bumpVfsWriteGen(src.canonicalPath, srcStat?.ino ?? null);
          b._bumpVfsWriteGen(dst.canonicalPath, dstStat?.ino ?? null);
          b.lastError = WIN32_ERROR.ERROR_SUCCESS;
          return 1n;
        }

        // Cross-root move between distinct allowed roots:
        // Enforce replacement flag, reject symlinks/directories, check size cap, copy + unlink safely.
        if (dstStat) {
          if (!replaceExisting) {
            b.lastError = WIN32_ERROR.ERROR_ALREADY_EXISTS;
            return 0n;
          }
          if (dstStat.type === 'dir') {
            throw new VfsError(`Cannot overwrite directory: ${dst.canonicalPath}`, {
              code: ERROR_CODES.EISDIR,
              path: dst.canonicalPath,
            });
          }
        }

        if (srcStat.type !== 'file') {
          throw new VfsError(`Cross-root move only supports regular files (got ${srcStat.type})`, {
            code: ERROR_CODES.EACCES,
            path: src.canonicalPath,
          });
        }

        const maxBytes = b._maxWin32FileBytes();
        if (typeof srcStat.size === 'number' && srcStat.size > maxBytes) {
          throw new VfsError(`File size (${srcStat.size}) exceeds maximum allowed (${maxBytes})`, {
            code: ERROR_CODES.ENOSPC,
            path: src.canonicalPath,
          });
        }
        if (!dstStat && !b._checkVfsCreateQuota(1)) {
          return 0n;
        }
        if (
          b.uid !== 0 &&
          typeof srcStat.size === 'number' &&
          (b._vfsWriteBytes + srcStat.size > MAX_BRIDGE_VFS_WRITE_BYTES ||
            b._vfsPhysicalWriteBytes + srcStat.size > MAX_BRIDGE_VFS_PHYSICAL_WRITE_BYTES)
        ) {
          b.lastError = WIN32_ERROR.ERROR_DISK_FULL;
          return 0n;
        }
        if (typeof srcStat.size === 'number' && !b._checkVfsReadQuota(srcStat.size)) {
          return 0n;
        }

        const data = vfs.readFile(src.canonicalPath, src.vfsCtx);
        b._recordVfsReadQuota(data.byteLength);
        if (data.byteLength > maxBytes) {
          throw new VfsError(`File size (${data.byteLength}) exceeds maximum allowed (${maxBytes})`, {
            code: ERROR_CODES.ENOSPC,
            path: src.canonicalPath,
          });
        }
        if (!b._consumeVfsWriteQuota(data.byteLength, data.byteLength)) {
          return 0n;
        }

        if (dstStat?.type === 'symlink') {
          vfs.unlink(dst.canonicalPath, dst.vfsCtx);
        }
        const written = vfs.writeFile(dst.canonicalPath, data, dst.vfsCtx);
        b._bumpVfsWriteGen(dst.canonicalPath, written?.ino ?? dstStat?.ino ?? null);
        if (!dstStat) {
          b._recordVfsCreateQuota(1);
        }
        try {
          vfs.unlink(src.canonicalPath, src.vfsCtx);
          b._bumpVfsWriteGen(src.canonicalPath, srcStat?.ino ?? null);
        } catch (unlinkErr) {
          if (!dstStat) {
            try {
              vfs.unlink(dst.canonicalPath, dst.vfsCtx);
              b._bumpVfsWriteGen(dst.canonicalPath, written?.ino ?? null);
            } catch (cleanupErr) {
              void cleanupErr;
            }
          }
          throw unlinkErr;
        }

        b.lastError = WIN32_ERROR.ERROR_SUCCESS;
        return 1n;
      } catch (err) {
        b._setErrorFromException(err);
        return 0n;
      }
    };

    const copyFileImpl = (lpOld, lpNew, bFailIfExists, isWide) => {
      try {
        const src = b._resolveVfsPath(b._readString(lpOld, isWide), 'read');
        const dst = b._resolveVfsPath(b._readString(lpNew, isWide), 'write');
        const vfs = b.services.vfs;
        const srcStat = vfs.stat(src.canonicalPath, src.vfsCtx);
        const maxBytes = b._maxWin32FileBytes();
        if (typeof srcStat.size === 'number' && srcStat.size > maxBytes) {
          throw new VfsError(`File size (${srcStat.size}) exceeds maximum allowed (${maxBytes})`, {
            code: ERROR_CODES.ENOSPC,
            path: src.canonicalPath,
          });
        }
        let dstExists = false;
        let dstIno = null;
        try {
          const dstSt = vfs.lstat(dst.canonicalPath, dst.vfsCtx);
          dstExists = true;
          dstIno = dstSt?.ino ?? null;
        } catch (stErr) {
          if (stErr?.code !== ERROR_CODES.ENOENT) throw stErr;
        }
        if (bFailIfExists !== 0n && dstExists) {
          b.lastError = WIN32_ERROR.ERROR_FILE_EXISTS;
          return 0n;
        }
        if (!dstExists && !b._checkVfsCreateQuota(1)) {
          return 0n;
        }
        if (
          b.uid !== 0 &&
          typeof srcStat.size === 'number' &&
          (b._vfsWriteBytes + srcStat.size > MAX_BRIDGE_VFS_WRITE_BYTES ||
            b._vfsPhysicalWriteBytes + srcStat.size > MAX_BRIDGE_VFS_PHYSICAL_WRITE_BYTES)
        ) {
          b.lastError = WIN32_ERROR.ERROR_DISK_FULL;
          return 0n;
        }
        if (typeof srcStat.size === 'number' && !b._checkVfsReadQuota(srcStat.size)) {
          return 0n;
        }
        const data = vfs.readFile(src.canonicalPath, src.vfsCtx);
        b._recordVfsReadQuota(data.byteLength);
        if (!b._consumeVfsWriteQuota(data.byteLength, data.byteLength)) {
          return 0n;
        }
        const written = vfs.writeFile(dst.canonicalPath, data, dst.vfsCtx);
        b._bumpVfsWriteGen(dst.canonicalPath, written?.ino ?? dstIno);
        if (!dstExists) {
          b._recordVfsCreateQuota(1);
        }
        b.lastError = WIN32_ERROR.ERROR_SUCCESS;
        return 1n;
      } catch (err) {
        b._setErrorFromException(err);
        return 0n;
      }
    };

    // ---- Shared User32 Implementations ----
    const registerClassExImpl = (args, isWide) => {
      const [lpwcx] = args;
      if (lpwcx === 0n) {
        b.lastError = WIN32_ERROR.ERROR_INVALID_PARAMETER;
        return 0n;
      }
      let style, wndProcVa, hbrBackground, classNamePtr;
      if (b.is64) {
        const raw = b.addressSpace.read(lpwcx, 80);
        const dv = new DataView(raw.buffer, raw.byteOffset, 80);
        style = dv.getUint32(4, true);
        wndProcVa = dv.getBigUint64(8, true);
        hbrBackground = dv.getBigUint64(48, true);
        classNamePtr = dv.getBigUint64(64, true);
      } else {
        const raw = b.addressSpace.read(lpwcx & 0xffffffffn, 48);
        const dv = new DataView(raw.buffer, raw.byteOffset, 48);
        style = dv.getUint32(4, true);
        wndProcVa = BigInt(dv.getUint32(8, true));
        hbrBackground = BigInt(dv.getUint32(32, true));
        classNamePtr = BigInt(dv.getUint32(40, true));
      }
      const rawClassName = isWide
        ? (b._readWString(classNamePtr, MAX_WINDOW_CLASS_NAME) ?? '')
        : (b._readCString(classNamePtr, MAX_WINDOW_CLASS_NAME) ?? '');
      const className = rawClassName.slice(0, MAX_WINDOW_CLASS_NAME) || `WinClass_${b._nextAtom}`;
      const classKey = className.toLowerCase();
      if (!b._windowClasses.has(classKey) && b._windowClasses.size >= MAX_WINDOW_CLASSES) {
        b.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
        return 0n;
      }
      const atom = b._nextAtom++;
      b._windowClasses.set(classKey, {
        atom,
        className,
        wndProcVa,
        style,
        hbrBackground,
      });
      b.lastError = WIN32_ERROR.ERROR_SUCCESS;
      return atom;
    };

    const registerClassImpl = (args, isWide) => {
      const [lpwc] = args;
      if (lpwc === 0n) return 0n;
      let style, wndProcVa, hbrBackground, classNamePtr;
      if (b.is64) {
        const raw = b.addressSpace.read(lpwc, 72);
        const dv = new DataView(raw.buffer, raw.byteOffset, 72);
        style = dv.getUint32(0, true);
        wndProcVa = dv.getBigUint64(8, true);
        hbrBackground = dv.getBigUint64(48, true);
        classNamePtr = dv.getBigUint64(64, true);
      } else {
        const raw = b.addressSpace.read(lpwc & 0xffffffffn, 40);
        const dv = new DataView(raw.buffer, raw.byteOffset, 40);
        style = dv.getUint32(0, true);
        wndProcVa = BigInt(dv.getUint32(4, true));
        hbrBackground = BigInt(dv.getUint32(28, true));
        classNamePtr = BigInt(dv.getUint32(36, true));
      }
      const rawClassName = isWide
        ? (b._readWString(classNamePtr, MAX_WINDOW_CLASS_NAME) ?? '')
        : (b._readCString(classNamePtr, MAX_WINDOW_CLASS_NAME) ?? '');
      const className = rawClassName.slice(0, MAX_WINDOW_CLASS_NAME) || `WinClass_${b._nextAtom}`;
      const classKey = className.toLowerCase();
      if (!b._windowClasses.has(classKey) && b._windowClasses.size >= MAX_WINDOW_CLASSES) {
        b.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
        return 0n;
      }
      const atom = b._nextAtom++;
      b._windowClasses.set(classKey, { atom, className, wndProcVa, style, hbrBackground });
      return atom;
    };

    const createWindowExImpl = (args, isWide) => {
      const [
        dwExStyle, lpClassName, lpWindowName, dwStyle,
        xArg, yArg, wArg, hArg,
        hWndParent, hMenu, _hInstance, _lpParam,
      ] = args;

      if (b._windows.size >= MAX_WIN32_WINDOWS) {
        b.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
        return 0n;
      }

      const rawClassName = isWide
        ? (b._readWString(lpClassName, MAX_WINDOW_CLASS_NAME) ?? '')
        : (b._readCString(lpClassName, MAX_WINDOW_CLASS_NAME) ?? '');
      const className = rawClassName.slice(0, MAX_WINDOW_CLASS_NAME) || 'STATIC';
      const rawWindowName = isWide
        ? (b._readWString(lpWindowName, MAX_WINDOW_TEXT_CHARS) ?? '')
        : (b._readCString(lpWindowName, MAX_WINDOW_TEXT_CHARS) ?? '');
      const rawX = Number(BigInt.asIntN(32, xArg));
      const rawY = Number(BigInt.asIntN(32, yArg));
      const rawW = Number(BigInt.asIntN(32, wArg));
      const rawH = Number(BigInt.asIntN(32, hArg));
      const CW_USEDEFAULT = -2147483648;
      const x = rawX === CW_USEDEFAULT ? 100 : rawX;
      const y = rawY === CW_USEDEFAULT ? 80 : rawY;
      const width = rawW === CW_USEDEFAULT || rawW <= 0 ? 640 : rawW;
      const height = rawH === CW_USEDEFAULT || rawH <= 0 ? 440 : rawH;

      const parentHwnd = b.is64 ? hWndParent : (hWndParent & 0xffffffffn);
      if (parentHwnd !== 0n) {
        const parentCheck = b._windows.get(parentHwnd);
        if (!parentCheck || parentCheck.destroyed) {
          b.lastError = 1400; // ERROR_INVALID_WINDOW_HANDLE
          return 0n;
        }
        if (parentCheck.childHwnds.length >= MAX_WIN32_CHILD_CONTROLS) {
          b.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
          return 0n;
        }
      }

      const hwnd = b._nextHwnd;
      b._nextHwnd += 0x10n;

      const cls = b._windowClasses.get(className.toLowerCase()) ?? null;
      const controlId = Number(hMenu & 0xffffn);

      const winRec = {
        hwnd,
        parentHwnd,
        controlId,
        className,
        text: '',
        textBytes: 0,
        style: Number(dwStyle & 0xffffffffn),
        exStyle: Number(dwExStyle & 0xffffffffn),
        x,
        y,
        width,
        height,
        wndProcVa: cls ? cls.wndProcVa : 0n,
        windowId: null,
        childHwnds: [],
        drawOps: [],
        drawOpBytes: 0,
        drawOpsDirty: false,
        items: className.toUpperCase() === 'LISTBOX' ? [] : null,
        listboxBytes: 0,
        needsPaint: parentHwnd === 0n,
        visible: (Number(dwStyle & 0xffffffffn) & 0x10000000) !== 0,
        destroyed: false,
      };

      b._setWindowText(winRec, rawWindowName, { rejectOnEmpty: false });
      b._windows.set(hwnd, winRec);

      if (parentHwnd === 0n) {
        // Top-level window -> create live M2 Compositor window!
        if (b.services.compositor) {
          let compWin;
          try {
            compWin = b.services.compositor.createWindow(b.pcb.pid, {
              appId: b.pcb.appId || b.appRecord.appId || 'windows-app',
              platform: 'windows',
              title: winRec.text || className,
              width,
              height,
              x,
              y,
              chromeStyle: 'windows',
              uiTree: b._buildUiTree(winRec),
              drawOps: [],
            });
          } catch (err) {
            b._windows.delete(hwnd);
            if (winRec.textBytes > 0) {
              b._totalWindowTextBytes = Math.max(0, b._totalWindowTextBytes - winRec.textBytes);
              winRec.text = '';
              winRec.textBytes = 0;
            }
            b._setErrorFromException(err);
            return 0n;
          }
          winRec.windowId = compWin.windowId;
          b._windowsByCompositorId.set(compWin.windowId, hwnd);
        }

        // Send WM_CREATE to WNDPROC (allows app to create child controls inside WM_CREATE!)
        if (winRec.wndProcVa !== 0n) {
          return b._dispatchWndProc(winRec, WIN32_CONSTANTS.WM_CREATE, 0n, 0n, {
            onReturn: (ret) => {
              if (BigInt.asIntN(32, ret) === -1n) {
                return b._destroyWindow(hwnd, { returnValue: 0n, fromThunk: false });
              }
              b._syncWindowSurface(winRec);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return hwnd;
            },
          });
        }
        // Note: compositor.createWindow() above already initialized title & uiTree when wndProcVa === 0n.
      } else {
        // Child control ("BUTTON", "STATIC", "EDIT", "LISTBOX") -> attach to parent & mark dirty for coalesced sync!
        const parent = b._windows.get(parentHwnd);
        if (parent) {
          parent.childHwnds.push(hwnd);
          const root = b._findTopLevelOwner(parent);
          if (root) b._markWindowSurfaceDirty(root);
        }
      }

      b.lastError = WIN32_ERROR.ERROR_SUCCESS;
      return hwnd;
    };

    const messageBoxImpl = (args, isWide) => {
      const [_hWnd, lpText, lpCaption, _uType] = args;
      const text = (isWide
        ? (b._readWString(lpText, MAX_MSGBOX_TEXT_CHARS) ?? '')
        : (b._readCString(lpText, MAX_MSGBOX_TEXT_CHARS) ?? '')
      ).slice(0, MAX_MSGBOX_TEXT_CHARS);
      const rawCaption = isWide
        ? (b._readWString(lpCaption, MAX_MSGBOX_CAPTION_CHARS) || '')
        : (b._readCString(lpCaption, MAX_MSGBOX_CAPTION_CHARS) || '');
      const caption = (rawCaption || b.appRecord?.name || b.pcb?.name || 'Windows MessageBox').slice(
        0,
        MAX_MSGBOX_CAPTION_CHARS
      );
      if (b.services.notifications && typeof b.services.notifications.post === 'function') {
        try {
          b.services.notifications.post({
            appId: b.pcb?.appId || b.appRecord?.appId || `pid-${b.pcb?.pid ?? 0}`,
            platform: 'windows',
            title: caption,
            body: text,
            category: 'dialog',
            priority: 'normal',
          });
        } catch (err) {
          void err;
        }
      }
      b.lastError = WIN32_ERROR.ERROR_SUCCESS;
      return BigInt(WIN32_CONSTANTS.IDOK);
    };

    // ---- Shared Advapi32 Registry Implementations ----
    const regOpenKeyExImpl = (args, isWide) => {
      const [hKey, lpSubKey, _ulOptions, _samDesired, phkResult] = args;
      const base = b._resolveRegHandle(hKey);
      if (!base || !b.services.configStore) {
        return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
      }
      if (base.deleted) {
        return BigInt(WIN32_ERROR.ERROR_KEY_DELETED ?? 1018);
      }
      const sub = lpSubKey !== 0n
        ? (isWide
            ? (b._readWString(lpSubKey, MAX_REG_KEY_PATH_CHARS + 1) || '')
            : (b._readCString(lpSubKey, MAX_REG_KEY_PATH_CHARS + 1) || ''))
        : '';
      const fullPath = base.keyPath && sub ? `${base.keyPath}\\${sub}` : (base.keyPath || sub);
      if (fullPath.length > MAX_REG_KEY_PATH_CHARS) {
        return BigInt(WIN32_ERROR.ERROR_INVALID_PARAMETER);
      }
      try {
        const keyCheck = b._regKeyExists(base.hive, fullPath, b._regCtx());
        if (keyCheck.quotaExceeded) {
          return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
        }
        if (!keyCheck.exists && fullPath !== '') {
          return BigInt(WIN32_ERROR.ERROR_FILE_NOT_FOUND);
        }
        const handle = b._allocHandle({ kind: 'reg', hive: base.hive, keyPath: fullPath, deleted: false });
        if (handle === null) return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
        b._writePtr(phkResult, handle);
        return BigInt(WIN32_ERROR.ERROR_SUCCESS);
      } catch (err) {
        return BigInt(posixCodeToWin32(err?.code));
      }
    };

    const regCreateKeyExImpl = (args, isWide) => {
      const [hKey, lpSubKey, _reserved, _lpClass, _dwOpts, _sam, _lpSec, phkResult, lpdwDisp] = args;
      const base = b._resolveRegHandle(hKey);
      if (!base || !b.services.configStore) {
        return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
      }
      if (base.deleted) {
        return BigInt(WIN32_ERROR.ERROR_KEY_DELETED ?? 1018);
      }
      const sub = lpSubKey !== 0n
        ? (isWide
            ? (b._readWString(lpSubKey, MAX_REG_KEY_PATH_CHARS + 1) || '')
            : (b._readCString(lpSubKey, MAX_REG_KEY_PATH_CHARS + 1) || ''))
        : '';
      const fullPath = base.keyPath && sub ? `${base.keyPath}\\${sub}` : (base.keyPath || sub);
      if (fullPath.length > MAX_REG_KEY_PATH_CHARS) {
        return BigInt(WIN32_ERROR.ERROR_INVALID_PARAMETER);
      }
      try {
        const regCtx = b._regCtx();
        // Prevent resurrecting deleted parent key chains via stale open handles
        if (base.keyPath !== '') {
          const parentCheck = b._regKeyExists(base.hive, base.keyPath, regCtx);
          if (parentCheck.quotaExceeded) {
            return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
          }
          if (!parentCheck.exists) {
            return BigInt(WIN32_ERROR.ERROR_KEY_DELETED ?? 1018);
          }
        }
        let missingRows = 0;
        let writeBytes = 0;
        if (fullPath !== '' && b.uid !== 0) {
          if (b._regWriteCount + 1 > MAX_BRIDGE_REG_VALUES) {
            return BigInt(WIN32_ERROR.ERROR_DISK_FULL);
          }
          const remRows = MAX_BRIDGE_REG_KEY_ROWS - b._regKeyRowsCreated;
          const remBytes = MAX_BRIDGE_REG_WRITE_BYTES - b._regWriteBytes;
          const measured = b._measureMissingRegKeyChain(base.hive, fullPath, regCtx, {
            maxRows: remRows,
            maxBytes: remBytes,
          });
          if (measured.quotaExceeded) {
            return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
          }
          missingRows = measured.missingRows;
          writeBytes = missingRows > 0
            ? measured.chainBytes
            : (Math.max(fullPath.length * 2, regUtf8Max(fullPath)) + 64);
          if (
            b._regKeyRowsCreated + missingRows > MAX_BRIDGE_REG_KEY_ROWS ||
            b._regWriteBytes + writeBytes > MAX_BRIDGE_REG_WRITE_BYTES
          ) {
            return BigInt(WIN32_ERROR.ERROR_DISK_FULL);
          }
        }
        let created = false;
        if (fullPath !== '') {
          const res = b.services.configStore.registry.createKey(base.hive, fullPath, regCtx);
          created = Boolean(res.created);
          if (created) {
            globalRegCreateKeyGen += 1;
            b._clearRegDataCaches();
            b._clearNegativeRegKeyExists();
          }
          b._markRegKeyChainExists(base.hive, fullPath);
          if (created) {
            b._lastGlobalRegCreateKeyGen = globalRegCreateKeyGen;
            b._lastRegKeysSig = b._readRegKeysSignature();
          }
          if (b.uid !== 0) {
            b._regWriteCount += 1;
            b._regKeyRowsCreated += missingRows;
            b._regWriteBytes += writeBytes;
          }
        }
        const handle = b._allocHandle({ kind: 'reg', hive: base.hive, keyPath: fullPath, deleted: false });
        if (handle === null) return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
        b._writePtr(phkResult, handle);
        if (lpdwDisp !== 0n) {
          b._writeU32(lpdwDisp, created ? 1 : 2); // REG_CREATED_NEW_KEY=1, REG_OPENED_EXISTING_KEY=2
        }
        return BigInt(WIN32_ERROR.ERROR_SUCCESS);
      } catch (err) {
        return BigInt(posixCodeToWin32(err?.code));
      }
    };

    const regSetValueExImpl = (args, isWide) => {
      const [hKey, lpValueName, _reserved, dwType, lpData, cbData] = args;
      const target = b._resolveRegHandle(hKey);
      if (!target || !b.services.configStore) {
        return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
      }
      if (target.deleted) {
        return BigInt(WIN32_ERROR.ERROR_KEY_DELETED ?? 1018);
      }
      const valName = lpValueName !== 0n
        ? (isWide
            ? (b._readWString(lpValueName, MAX_REG_VALUE_NAME_CHARS + 1) ?? '')
            : (b._readCString(lpValueName, MAX_REG_VALUE_NAME_CHARS + 1) ?? ''))
        : '';
      if (valName.length > MAX_REG_VALUE_NAME_CHARS) {
        return BigInt(WIN32_ERROR.ERROR_INVALID_PARAMETER);
      }
      const numType = Number(dwType & 0xffffffffn);
      const typeName = REG_NUM_TO_TYPE[numType] ?? 'REG_BINARY';
      const byteLen = Number(cbData & 0xffffffffn) >>> 0;
      if (byteLen > MAX_REG_VALUE_BYTES) {
        return BigInt(WIN32_ERROR.ERROR_INVALID_PARAMETER);
      }
      const regCtx = b._regCtx();
      let missingRows = 0;
      let chainBytes = 0;
      try {
        // Prevent resurrecting deleted ancestor key chains via stale open handles
        if (target.keyPath !== '') {
          const targetCheck = b._regKeyExists(target.hive, target.keyPath, regCtx);
          if (targetCheck.quotaExceeded) {
            return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
          }
          if (!targetCheck.exists) {
            return BigInt(WIN32_ERROR.ERROR_KEY_DELETED ?? 1018);
          }
        }
        // Charge missing HKCU\Software\Classes write-target rows on non-root HKCR CoW setValue
        if (b.uid !== 0 && target.hive === 'HKCR' && target.keyPath !== '') {
          const remRows = MAX_BRIDGE_REG_KEY_ROWS - b._regKeyRowsCreated;
          const remBytes = MAX_BRIDGE_REG_WRITE_BYTES - b._regWriteBytes;
          const measured = b._measureMissingRegKeyChain('HKCR', target.keyPath, regCtx, {
            maxRows: remRows,
            maxBytes: remBytes,
          });
          if (measured.quotaExceeded) {
            return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
          }
          missingRows = measured.missingRows;
          chainBytes = measured.chainBytes;
        }
      } catch (err) {
        return BigInt(posixCodeToWin32(err?.code));
      }
      const safeLen = byteLen > 0 && lpData !== 0n
        ? b._normalizeMemOpLen(byteLen, b.is64 ? lpData : (lpData & 0xffffffffn), 'RegSetValueEx')
        : 0;
      const keyPathUtf8 = regUtf8Max(target.keyPath);
      const valNameUtf8 = regUtf8Max(valName);
      const virtPrefixBytes = b._regVirtPrefixBytes(target.hive, regCtx);
      const keyMetaBytes = (keyPathUtf8 + virtPrefixBytes) * 3 + valNameUtf8 * 4 + 128;
      // Fast non-mutating pre-check before reading guest addressSpace
      if (b.uid !== 0) {
        if (
          b._regWriteCount + 1 > MAX_BRIDGE_REG_VALUES ||
          b._regKeyRowsCreated + missingRows > MAX_BRIDGE_REG_KEY_ROWS ||
          b._regWriteBytes + safeLen + keyMetaBytes + chainBytes > MAX_BRIDGE_REG_WRITE_BYTES
        ) {
          return BigInt(WIN32_ERROR.ERROR_DISK_FULL);
        }
      }
      const raw = safeLen > 0 ? b.addressSpace.read(lpData, safeLen) : new Uint8Array(0);

      let data;
      if (typeName === 'REG_SZ' || typeName === 'REG_EXPAND_SZ') {
        if (isWide) {
          data = decodeUtf16LE(raw);
        } else {
          let end = raw.byteLength;
          while (end > 0 && raw[end - 1] === 0) end -= 1;
          data = UTF8_DECODER.decode(raw.subarray(0, end));
        }
      } else if (typeName === 'REG_DWORD') {
        if (raw.byteLength < 4) return BigInt(WIN32_ERROR.ERROR_INVALID_PARAMETER);
        data = new DataView(raw.buffer, raw.byteOffset, 4).getUint32(0, true);
      } else if (typeName === 'REG_QWORD') {
        if (raw.byteLength < 8) return BigInt(WIN32_ERROR.ERROR_INVALID_PARAMETER);
        data = new DataView(raw.buffer, raw.byteOffset, 8).getBigUint64(0, true);
      } else if (typeName === 'REG_MULTI_SZ') {
        const full = isWide ? UTF16LE_DECODER.decode(raw) : UTF8_DECODER.decode(raw);
        data = full.split('\0').filter((s) => s.length > 0);
      } else {
        data = raw.slice();
      }

      // Compute exact post-decode serialized UTF-8 / JSON / BLOB byte size persisted by UnifiedConfigStore
      let serializedDataBytes;
      if (typeName === 'REG_MULTI_SZ') {
        serializedDataBytes = UTF8_ENCODER.encode(JSON.stringify(data)).byteLength;
      } else if (typeName === 'REG_SZ' || typeName === 'REG_EXPAND_SZ') {
        serializedDataBytes = UTF8_ENCODER.encode(String(data)).byteLength;
      } else if (typeName === 'REG_DWORD' || typeName === 'REG_QWORD') {
        serializedDataBytes = 8;
      } else {
        serializedDataBytes = raw.byteLength;
      }
      const effectivePayloadBytes = Math.max(safeLen, serializedDataBytes);
      const writeBytes = effectivePayloadBytes + keyMetaBytes + chainBytes;
      if (b.uid !== 0) {
        if (
          serializedDataBytes > MAX_REG_VALUE_BYTES * 2 ||
          b._regWriteCount + 1 > MAX_BRIDGE_REG_VALUES ||
          b._regKeyRowsCreated + missingRows > MAX_BRIDGE_REG_KEY_ROWS ||
          b._regWriteBytes + writeBytes > MAX_BRIDGE_REG_WRITE_BYTES
        ) {
          return BigInt(WIN32_ERROR.ERROR_DISK_FULL);
        }
      }

      try {
        b._localRegSetValueDepth += 1;
        try {
          b.services.configStore.registry.setValue(target.hive, target.keyPath, valName, typeName, data, regCtx);
        } finally {
          b._localRegSetValueDepth -= 1;
        }
        b._clearRegDataCaches();
        b._clearNegativeRegKeyExists();
        b._markRegKeyChainExists(target.hive, target.keyPath);
        if (missingRows > 0) {
          globalRegCreateKeyGen += 1;
          b._lastGlobalRegCreateKeyGen = globalRegCreateKeyGen;
          b._lastRegKeysSig = b._readRegKeysSignature();
        }
        if (b.uid !== 0) {
          b._regWriteCount += 1;
          b._regKeyRowsCreated += missingRows;
          b._regWriteBytes += writeBytes;
        }
        return BigInt(WIN32_ERROR.ERROR_SUCCESS);
      } catch (err) {
        return BigInt(posixCodeToWin32(err?.code));
      }
    };

    const regDeleteKeyImpl = (args, isWide) => {
      const [hKey, lpSubKey] = args;
      const target = b._resolveRegHandle(hKey);
      if (!target || !b.services.configStore) {
        return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
      }
      if (target.deleted) {
        return BigInt(WIN32_ERROR.ERROR_KEY_DELETED ?? 1018);
      }
      const sub = lpSubKey !== 0n
        ? (isWide ? (b._readWString(lpSubKey) ?? '') : (b._readCString(lpSubKey) ?? ''))
        : '';
      const fullPath = target.keyPath && sub ? `${target.keyPath}\\${sub}` : (target.keyPath || sub);
      try {
        const ok = b.services.configStore.registry.deleteKey(target.hive, fullPath, b._regCtx());
        if (ok) {
          b._markDeletedRegHandles(target.hive, fullPath);
          b._invalidateRegCache({ includeKeyExists: true });
        }
        return BigInt(ok ? WIN32_ERROR.ERROR_SUCCESS : WIN32_ERROR.ERROR_FILE_NOT_FOUND);
      } catch (err) {
        return BigInt(posixCodeToWin32(err?.code));
      }
    };

    const getRegValueByteLength = (entry, isWide) => {
      const rec = entry.rec;
      const typeNum = REG_TYPE_TO_NUM[rec.type] ?? WIN32_CONSTANTS.REG_BINARY;
      const cachedLen = isWide ? entry.byteLenW : entry.byteLenA;
      if (cachedLen !== null && cachedLen !== undefined) {
        return { typeNum, byteLength: cachedLen };
      }
      let byteLength = 0;
      if (rec.type === 'REG_SZ' || rec.type === 'REG_EXPAND_SZ') {
        const s = String(rec.data ?? '');
        byteLength = isWide ? (s.length + 1) * 2 : (Buffer.byteLength(s, 'utf8') + 1);
      } else if (rec.type === 'REG_DWORD') {
        byteLength = 4;
      } else if (rec.type === 'REG_QWORD') {
        byteLength = 8;
      } else if (rec.type === 'REG_MULTI_SZ') {
        const arr = Array.isArray(rec.data) ? rec.data : [];
        if (arr.length === 0) {
          byteLength = isWide ? 4 : 2;
        } else if (isWide) {
          let chars = arr.length + 1;
          for (let i = 0; i < arr.length; i += 1) {
            chars += String(arr[i] ?? '').length;
          }
          byteLength = chars * 2;
        } else {
          let bytes = arr.length + 1;
          for (let i = 0; i < arr.length; i += 1) {
            bytes += Buffer.byteLength(String(arr[i] ?? ''), 'utf8');
          }
          byteLength = bytes;
        }
      } else {
        byteLength = rec.data instanceof Uint8Array ? rec.data.byteLength : 0;
      }
      if (isWide) entry.byteLenW = byteLength;
      else entry.byteLenA = byteLength;
      return { typeNum, byteLength };
    };

    const serializeRegValueBytes = (rec, isWide) => {
      const typeNum = REG_TYPE_TO_NUM[rec.type] ?? WIN32_CONSTANTS.REG_BINARY;
      let outBytes;
      if (rec.type === 'REG_SZ' || rec.type === 'REG_EXPAND_SZ') {
        const s = String(rec.data ?? '');
        outBytes = isWide ? encodeUtf16LE(s, true) : encodeUtf8Bytes(s, true);
      } else if (rec.type === 'REG_DWORD') {
        outBytes = new Uint8Array(4);
        new DataView(outBytes.buffer).setUint32(0, Number(rec.data) >>> 0, true);
      } else if (rec.type === 'REG_QWORD') {
        outBytes = new Uint8Array(8);
        new DataView(outBytes.buffer).setBigUint64(0, BigInt.asUintN(64, BigInt(rec.data)), true);
      } else if (rec.type === 'REG_MULTI_SZ') {
        const joined = `${(Array.isArray(rec.data) ? rec.data : []).join('\0')}\0\0`;
        outBytes = isWide ? encodeUtf16LE(joined, false) : encodeUtf8Bytes(joined, false);
      } else {
        outBytes = rec.data instanceof Uint8Array ? rec.data : new Uint8Array(0);
      }
      return { typeNum, outBytes };
    };

    const getCachedSerializedRegValue = (entry, isWide) => {
      const rec = entry.rec;
      const typeNum = REG_TYPE_TO_NUM[rec.type] ?? WIN32_CONSTANTS.REG_BINARY;
      const cached = isWide ? entry.bytesW : entry.bytesA;
      if (cached instanceof Uint8Array) {
        return { typeNum, outBytes: cached };
      }
      const { outBytes } = serializeRegValueBytes(rec, isWide);
      if (isWide) {
        if (entry.byteLenW === null || entry.byteLenW === undefined) entry.byteLenW = outBytes.byteLength;
      } else if (entry.byteLenA === null || entry.byteLenA === undefined) {
        entry.byteLenA = outBytes.byteLength;
      }
      const inValCache = Boolean(entry.cacheKey && b._regValCache.get(entry.cacheKey) === entry);
      const inEnumCache = Boolean(
        entry.ownerEnumKey && b._regEnumCache.get(entry.ownerEnumKey) === entry.ownerEnumEntry
      );
      if (inValCache || inEnumCache) {
        const extraBytes = rec.type === 'REG_BINARY' && outBytes === rec.data ? 0 : outBytes.byteLength;
        const canStore =
          extraBytes === 0 ||
          (extraBytes <= MAX_BRIDGE_REG_CACHE_BYTES &&
            b._evictRegCacheToFit(
              extraBytes,
              inEnumCache ? entry.ownerEnumKey : null,
              inValCache ? entry.cacheKey : null
            ));
        if (canStore) {
          if (isWide) entry.bytesW = outBytes;
          else entry.bytesA = outBytes;
          if (extraBytes > 0) {
            b._regCacheBytes += extraBytes;
            if (inEnumCache && entry.ownerEnumEntry) {
              entry.ownerEnumEntry.totalBytes = (entry.ownerEnumEntry.totalBytes ?? entry.ownerEnumEntry.costBytes ?? 0) + extraBytes;
            } else {
              entry.totalBytes = (entry.totalBytes ?? entry.costBytes ?? 0) + extraBytes;
            }
          }
        }
      }
      return { typeNum, outBytes };
    };

    const regQueryValueExImpl = (args, isWide) => {
      const [hKey, lpValueName, _lpReserved, lpType, lpData, lpcbData] = args;
      const target = b._resolveRegHandle(hKey);
      if (!target || !b.services.configStore) {
        return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
      }
      const valName = lpValueName !== 0n ? (b._readString(lpValueName, isWide) ?? '') : '';
      try {
        const qRes = b._regGetValueCached(target.hive, target.keyPath, valName, b._regCtx());
        if (qRes.quotaExceeded) return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
        const entry = qRes.entry;
        if (!entry || !entry.rec) return BigInt(WIN32_ERROR.ERROR_FILE_NOT_FOUND);
        const { typeNum, byteLength } = getRegValueByteLength(entry, isWide);
        if (lpType !== 0n) b._writeU32(lpType, typeNum);
        if (lpData === 0n) {
          if (lpcbData !== 0n) b._writeU32(lpcbData, byteLength);
          return BigInt(WIN32_ERROR.ERROR_SUCCESS);
        }
        if (lpcbData !== 0n) {
          const cap = b._readU32(lpcbData);
          if (cap < byteLength) {
            const probeCharge = Math.max(64, Math.min(cap, byteLength));
            if (!b._chargeRegReadQuota(probeCharge)) {
              return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
            }
            b._writeU32(lpcbData, byteLength);
            return BigInt(WIN32_ERROR.ERROR_MORE_DATA);
          }
          if (!b._chargeRegReadQuota(byteLength)) {
            return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
          }
          const { outBytes } = getCachedSerializedRegValue(entry, isWide);
          b.addressSpace.write(lpData, outBytes);
          b._writeU32(lpcbData, outBytes.byteLength);
        } else {
          if (!b._chargeRegReadQuota(byteLength)) {
            return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
          }
          const { outBytes } = getCachedSerializedRegValue(entry, isWide);
          b.addressSpace.write(lpData, outBytes);
        }
        return BigInt(WIN32_ERROR.ERROR_SUCCESS);
      } catch (err) {
        return BigInt(posixCodeToWin32(err?.code));
      }
    };

    // ---- Shared GDI Drawing Helper ----
    const getDc = (hDC) => {
      const rec = b._handles.get(hDC);
      return rec && rec.kind === 'dc' ? rec : null;
    };

    const flushDirectDc = (dc) => {
      if (dc && dc.direct && dc.win && dc.drawOps.length > 0) {
        const ops = dc.drawOps.splice(0);
        const drainedBytes = dc.drawOpBytes ?? 0;
        dc.drawOpBytes = 0;
        if (drainedBytes > 0) {
          b._totalDrawOpBytes = Math.max(0, b._totalDrawOpBytes - drainedBytes);
        }
        for (let i = 0; i < ops.length; i++) {
          b._appendDrawOp(dc.win, ops[i]);
        }
        b._markWindowSurfaceDirty(dc.win, { drawOpsDirty: true });
      }
    };

    // ---- Shared C printf/sprintf formatter (bounded output & specifiers; lazy variadic arg reading) ----
    const formatPrintf = (fmt, nextArg, maxOutputBytes = MAX_PRINTF_OUTPUT_BYTES) => {
      const rawLimit = Number(maxOutputBytes);
      const limit = Number.isFinite(rawLimit)
        ? Math.max(0, Math.min(MAX_PRINTF_OUTPUT_BYTES, Math.trunc(rawLimit)))
        : MAX_PRINTF_OUTPUT_BYTES;
      if (limit === 0 || !fmt) return '';

      const parts = [];
      let outLen = 0;
      let specCount = 0;

      const appendPiece = (piece) => {
        if (!piece || outLen >= limit) return;
        const rem = limit - outLen;
        if (piece.length <= rem) {
          parts.push(piece);
          outLen += piece.length;
        } else {
          parts.push(piece.slice(0, rem));
          outLen = limit;
        }
      };

      for (let i = 0; i < fmt.length && outLen < limit; i++) {
        if (fmt[i] !== '%' || i + 1 >= fmt.length) {
          const nextPct = fmt.indexOf('%', i + 1);
          const litEnd = nextPct === -1 ? fmt.length : nextPct;
          appendPiece(fmt.slice(i, litEnd));
          i = litEnd - 1;
          continue;
        }
        i += 1;
        if (fmt[i] === '%') {
          appendPiece('%');
          continue;
        }
        if (specCount >= MAX_PRINTF_SPECS) {
          break;
        }
        specCount += 1;

        // Parse flags, width, precision, and length modifiers (strictly clamped to remaining output budget)
        let leftAlign = false;
        let zeroPad = false;
        while (
          i < fmt.length &&
          (fmt[i] === '-' || fmt[i] === '+' || fmt[i] === ' ' || fmt[i] === '#' || fmt[i] === '0')
        ) {
          if (fmt[i] === '-') leftAlign = true;
          if (fmt[i] === '0') zeroPad = true;
          i += 1;
        }
        let width = 0;
        if (i < fmt.length && fmt[i] === '*') {
          const wVal = Number(BigInt.asIntN(32, nextArg()));
          if (wVal < 0) {
            leftAlign = true;
            width = Math.min(limit, -wVal);
          } else {
            width = Math.min(limit, wVal);
          }
          i += 1;
        } else {
          while (i < fmt.length && fmt[i] >= '0' && fmt[i] <= '9') {
            width = Math.min(limit, width * 10 + (fmt.charCodeAt(i) - 48));
            i += 1;
          }
        }
        let precision = -1;
        if (i < fmt.length && fmt[i] === '.') {
          i += 1;
          precision = 0;
          if (i < fmt.length && fmt[i] === '*') {
            const pVal = Number(BigInt.asIntN(32, nextArg()));
            precision = pVal < 0 ? -1 : Math.min(limit, pVal);
            i += 1;
          } else {
            while (i < fmt.length && fmt[i] >= '0' && fmt[i] <= '9') {
              precision = Math.min(limit, precision * 10 + (fmt.charCodeAt(i) - 48));
              i += 1;
            }
          }
        }
        let isLong = false;
        let isLongLong = false;
        while (
          i < fmt.length &&
          (fmt[i] === 'h' || fmt[i] === 'l' || fmt[i] === 'L' || fmt[i] === 'z' || fmt[i] === 'j')
        ) {
          if (fmt[i] === 'l') {
            if (isLong) isLongLong = true;
            else isLong = true;
          }
          i += 1;
        }

        const spec = fmt[i] ?? '';
        const remaining = limit - outLen;
        let rendered = '';

        if (spec === 's' || spec === 'S') {
          const val = nextArg();
          const wantWide = spec === 'S' || (spec === 's' && isLong && !isLongLong);
          const baseReadCap = Math.min(wantWide ? 16384 : 32768, Math.max(1, remaining + 1));
          const readCap = precision >= 0 ? Math.min(baseReadCap, precision) : baseReadCap;
          let strVal;
          if (val === 0n) {
            strVal = '(null)';
          } else if (readCap === 0) {
            strVal = '';
          } else {
            strVal = wantWide
              ? (b._readWString(val, readCap) ?? '(null)')
              : (b._readCString(val, readCap) ?? '(null)');
          }
          if (precision >= 0 && strVal.length > precision) {
            strVal = strVal.slice(0, precision);
          }
          rendered = strVal;
        } else if (spec === 'd' || spec === 'i') {
          const n = isLongLong ? BigInt.asIntN(64, nextArg()) : BigInt.asIntN(32, nextArg());
          rendered = n.toString(10);
        } else if (spec === 'u') {
          const n = isLongLong ? BigInt.asUintN(64, nextArg()) : (nextArg() & 0xffffffffn);
          rendered = n.toString(10);
        } else if (spec === 'x') {
          const n = isLongLong ? BigInt.asUintN(64, nextArg()) : (nextArg() & 0xffffffffn);
          rendered = n.toString(16);
        } else if (spec === 'X') {
          const n = isLongLong ? BigInt.asUintN(64, nextArg()) : (nextArg() & 0xffffffffn);
          rendered = n.toString(16).toUpperCase();
        } else if (spec === 'p') {
          rendered = `0x${nextArg().toString(16)}`;
        } else if (spec === 'c') {
          rendered = String.fromCharCode(Number(nextArg() & 0xffn));
        } else {
          rendered = `%${spec}`;
        }

        const clampedWidth = Math.min(width, remaining);
        if (clampedWidth > rendered.length) {
          const padLen = Math.min(clampedWidth - rendered.length, Math.max(0, remaining - rendered.length));
          const padChar =
            !leftAlign && zeroPad && (spec === 'd' || spec === 'i' || spec === 'u' || spec === 'x' || spec === 'X')
              ? '0'
              : ' ';
          if (leftAlign) {
            rendered = rendered + padChar.repeat(padLen);
          } else if (padChar === '0' && rendered.startsWith('-')) {
            rendered = `-${'0'.repeat(padLen)}${rendered.slice(1)}`;
          } else {
            rendered = padChar.repeat(padLen) + rendered;
          }
        }
        appendPiece(rendered);
      }
      return parts.join('');
    };

    return {
      // ======================================================================
      // kernel32.dll
      // ======================================================================
      'kernel32.dll': {
        getstdhandle: {
          argc: 1,
          fn: ([nStdHandle]) => {
            const code = Number(nStdHandle & 0xffffffffn);
            if (code === WIN32_CONSTANTS.STD_INPUT_HANDLE) return b.STD_IN;
            if (code === WIN32_CONSTANTS.STD_OUTPUT_HANDLE) return b.STD_OUT;
            if (code === WIN32_CONSTANTS.STD_ERROR_HANDLE) return b.STD_ERR;
            b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
            return b.invalidHandle;
          },
        },
        writeconsolea: { argc: 5, fn: (args) => writeConsoleImpl(args, false) },
        writeconsolew: { argc: 5, fn: (args) => writeConsoleImpl(args, true) },
        readconsolea: { argc: 5, fn: (args) => readConsoleImpl(args, false) },
        readconsolew: { argc: 5, fn: (args) => readConsoleImpl(args, true) },
        allocconsole: { argc: 0, fn: () => 1n },
        freeconsole: { argc: 0, fn: () => 1n },
        getconsolemode: {
          argc: 2,
          fn: ([_h, lpMode]) => { if (lpMode !== 0n) b._writeU32(lpMode, 0x0007); return 1n; },
        },
        setconsolemode: { argc: 2, fn: () => 1n },
        getconsoleoutputcp: { argc: 0, fn: () => 65001n },
        setconsoletitlea: { argc: 1, fn: () => 1n },
        setconsoletitlew: { argc: 1, fn: () => 1n },

        createfilea: { argc: 7, fn: (args) => createFileImpl(args, false) },
        createfilew: { argc: 7, fn: (args) => createFileImpl(args, true) },
        readfile: {
          argc: 5,
          fn: ([hFile, lpBuf, nToRead, lpRead]) => {
            const maxBytes = Number(nToRead & 0xffffffffn) >>> 0;
            if (hFile === b.STD_IN) {
              const data = b.services.processManager?.readStdin?.(b.pcb.pid, maxBytes, { encoding: 'bytes', consume: true });
              const bytes = data instanceof Uint8Array ? data : UTF8_ENCODER.encode(String(data ?? ''));
              const n = Math.min(bytes.byteLength, maxBytes);
              if (n > 0) b.addressSpace.write(lpBuf, bytes.subarray(0, n));
              if (lpRead !== 0n) b._writeU32(lpRead, n);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            }
            const rec = b._handles.get(hFile);
            if (!rec) {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0n;
            }
            if (rec.kind === 'nul') {
              if (lpRead !== 0n) b._writeU32(lpRead, 0);
              return 1n;
            }
            if (rec.kind !== 'file') {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0n;
            }
            if (!rec.canRead) {
              b.lastError = WIN32_ERROR.ERROR_ACCESS_DENIED;
              return 0n;
            }
            // Real Win32 0-byte ReadFile semantics: immediate O(1) no-op with ZERO VFS/SQLite read
            if (maxBytes === 0) {
              if (lpRead !== 0n) b._writeU32(lpRead, 0);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            }
            try {
              const isVirtualMount =
                rec.canonicalPath === '/proc' ||
                rec.canonicalPath.startsWith('/proc/') ||
                rec.canonicalPath === '/dev' ||
                rec.canonicalPath.startsWith('/dev/');
              const curStat = b.services.vfs.stat(rec.canonicalPath, rec.vfsCtx);
              const curSize = typeof curStat?.size === 'number' && Number.isFinite(curStat.size) ? curStat.size : 0;

              // O(1) EOF fast-path avoids full SQLite blob read when file pointer is already at/past EOF
              if (!isVirtualMount && rec.pos >= curSize) {
                if (lpRead !== 0n) b._writeU32(lpRead, 0);
                b.lastError = WIN32_ERROR.ERROR_SUCCESS;
                return 1n;
              }

              let bytes = null;
              if (!isVirtualMount && curStat?.type === 'file') {
                const curMtimeMs = curStat?.mtimeMs ?? 0;
                const curCtimeMs = curStat?.ctimeMs ?? 0;
                const curIno = curStat?.ino ?? null;
                const pathKey = rec.canonicalPath.toLowerCase();
                const curWriteGen = b._vfsWriteGen.get(pathKey) ?? 0;
                const curInoGen = curIno !== null ? (b._vfsInoWriteGen.get(curIno) ?? 0) : 0;
                const cached = rec._readCache;
                if (
                  cached &&
                  cached.size === curSize &&
                  cached.mtimeMs === curMtimeMs &&
                  cached.ctimeMs === curCtimeMs &&
                  cached.ino === curIno &&
                  cached.writeGen === curWriteGen &&
                  cached.inoGen === curInoGen
                ) {
                  bytes = cached.bytes;
                } else {
                  if (cached) {
                    b._clearFileReadCache(rec);
                  }
                  if (!b._checkVfsReadQuota(curSize)) {
                    return 0n;
                  }
                  const all = b.services.vfs.readFile(rec.canonicalPath, rec.vfsCtx);
                  bytes = all instanceof Uint8Array ? all : UTF8_ENCODER.encode(String(all));
                  b._recordVfsReadQuota(bytes.byteLength);
                  b._setFileReadCache(rec, {
                    bytes,
                    size: curSize,
                    mtimeMs: curMtimeMs,
                    ctimeMs: curCtimeMs,
                    ino: curIno,
                    writeGen: curWriteGen,
                    inoGen: curInoGen,
                  });
                }
              } else {
                if (!b._checkVfsReadQuota(curSize)) {
                  return 0n;
                }
                const all = b.services.vfs.readFile(rec.canonicalPath, rec.vfsCtx);
                bytes = all instanceof Uint8Array ? all : UTF8_ENCODER.encode(String(all));
                b._recordVfsReadQuota(bytes.byteLength);
              }

              const avail = Math.max(0, bytes.byteLength - rec.pos);
              const n = Math.min(avail, maxBytes);
              if (n > 0) {
                b.addressSpace.write(lpBuf, bytes.subarray(rec.pos, rec.pos + n));
                rec.pos += n;
              }
              if (lpRead !== 0n) b._writeU32(lpRead, n);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        writefile: {
          argc: 5,
          fn: ([hFile, lpBuf, nToWrite, lpWritten]) => {
            const count = Number(nToWrite & 0xffffffffn) >>> 0;
            if (hFile === b.STD_OUT || hFile === b.STD_ERR) {
              const baseAddr = b.is64 ? lpBuf : (lpBuf & 0xffffffffn);
              const safeCount = b._normalizeMemOpLen(count, baseAddr, 'WriteFile');
              let offset = 0;
              while (offset < safeCount) {
                const step = Math.min(safeCount - offset, MEM_OP_CHUNK_BYTES);
                const payload = b.addressSpace.read(baseAddr + BigInt(offset), step);
                const text = UTF8_DECODER.decode(payload);
                if (hFile === b.STD_ERR) b.services.processManager?.writeStderr?.(b.pcb.pid, text);
                else b.services.processManager?.writeStdout?.(b.pcb.pid, text);
                offset += step;
              }
              if (lpWritten !== 0n) b._writeU32(lpWritten, safeCount);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            }
            const rec = b._handles.get(hFile);
            if (!rec) {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0n;
            }
            if (rec.kind === 'nul') {
              if (lpWritten !== 0n) b._writeU32(lpWritten, count);
              return 1n;
            }
            if (rec.kind !== 'file') {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0n;
            }
            if (!rec.canWrite) {
              b.lastError = WIN32_ERROR.ERROR_ACCESS_DENIED;
              return 0n;
            }
            // Real Win32 0-byte WriteFile semantics: no-op (never extends EOF to rec.pos or writes VFS)
            if (count === 0) {
              if (lpWritten !== 0n) b._writeU32(lpWritten, 0);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            }
            const maxFileBytes = b._maxWin32FileBytes();
            if (
              !Number.isSafeInteger(rec.pos) ||
              rec.pos < 0 ||
              !Number.isSafeInteger(count) ||
              count > maxFileBytes ||
              rec.pos > maxFileBytes - count
            ) {
              b.lastError = WIN32_ERROR.ERROR_DISK_FULL;
              return 0n;
            }
            // Fast non-mutating pre-check before reading guest addressSpace or VFS blob
            if (
              b.uid !== 0 &&
              (b._vfsWriteBytes + count > MAX_BRIDGE_VFS_WRITE_BYTES ||
                b._vfsPhysicalWriteBytes + rec.pos + count > MAX_BRIDGE_VFS_PHYSICAL_WRITE_BYTES)
            ) {
              b.lastError = WIN32_ERROR.ERROR_DISK_FULL;
              return 0n;
            }
            const payload = b.addressSpace.read(b.is64 ? lpBuf : (lpBuf & 0xffffffffn), count);
            try {
              // O(1) stat pre-check prevents reading multi-MiB blobs from SQLite on rejected writes
              const curStat = b.services.vfs.stat(rec.canonicalPath, rec.vfsCtx);
              const curSize = typeof curStat?.size === 'number' && Number.isFinite(curStat.size) ? curStat.size : 0;
              const estNextLen = Math.max(curSize, rec.pos + count);
              if (estNextLen > maxFileBytes) {
                b.lastError = WIN32_ERROR.ERROR_DISK_FULL;
                return 0n;
              }
              const estGrowth = Math.max(0, estNextLen - curSize);
              const estCharge = Math.max(count, estGrowth);
              if (
                b.uid !== 0 &&
                (b._vfsWriteBytes + estCharge > MAX_BRIDGE_VFS_WRITE_BYTES ||
                  b._vfsPhysicalWriteBytes + estNextLen > MAX_BRIDGE_VFS_PHYSICAL_WRITE_BYTES)
              ) {
                b.lastError = WIN32_ERROR.ERROR_DISK_FULL;
                return 0n;
              }
              let existing;
              if (curStat?.type === 'file' && (curSize === 0 || (rec.pos === 0 && count >= curSize))) {
                existing = new Uint8Array(0);
              } else {
                if (!b._checkVfsReadQuota(curSize)) {
                  return 0n;
                }
                const existingRaw = b.services.vfs.readFile(rec.canonicalPath, rec.vfsCtx);
                existing = existingRaw instanceof Uint8Array ? existingRaw : UTF8_ENCODER.encode(String(existingRaw));
                b._recordVfsReadQuota(existing.byteLength);
              }
              const nextLen = Math.max(existing.byteLength, rec.pos + count);
              if (nextLen > maxFileBytes) {
                b.lastError = WIN32_ERROR.ERROR_DISK_FULL;
                return 0n;
              }
              const growth = Math.max(0, nextLen - existing.byteLength);
              const chargeBytes = Math.max(count, growth);
              if (!b._consumeVfsWriteQuota(chargeBytes, nextLen)) {
                return 0n;
              }
              const nextBuf = new Uint8Array(nextLen);
              nextBuf.set(existing, 0);
              nextBuf.set(payload, rec.pos);
              const written = b.services.vfs.writeFile(rec.canonicalPath, nextBuf, rec.vfsCtx);
              b._bumpVfsWriteGen(rec.canonicalPath, written?.ino ?? curStat?.ino ?? null);
              if (rec._readCache) b._clearFileReadCache(rec);
              rec.pos += count;
              if (lpWritten !== 0n) b._writeU32(lpWritten, count);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        setfilepointer: {
          argc: 4,
          fn: ([hFile, lDist, lpDistHigh, dwMoveMethod]) => {
            const rec = b._handles.get(hFile);
            if (!rec || rec.kind !== 'file') {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0xffffffffn;
            }
            try {
              const distLo = Number(BigInt.asIntN(32, lDist));
              const distHi = lpDistHigh !== 0n ? b._readI32(lpDistHigh) : 0;
              const delta = lpDistHigh !== 0n ? (distHi * 0x100000000 + (distLo >>> 0)) : distLo;
              const method = Number(dwMoveMethod & 0xffffffffn);
              let basePos = 0;
              if (method === WIN32_CONSTANTS.FILE_CURRENT) basePos = rec.pos;
              else if (method === WIN32_CONSTANTS.FILE_END) {
                basePos = b.services.vfs.stat(rec.canonicalPath, rec.vfsCtx).size;
              }
              const nextPos = Math.max(0, basePos + delta);
              rec.pos = nextPos;
              if (lpDistHigh !== 0n) b._writeU32(lpDistHigh, Math.floor(nextPos / 0x100000000));
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return BigInt(nextPos >>> 0);
            } catch (err) {
              b._setErrorFromException(err);
              return 0xffffffffn;
            }
          },
        },
        setfilepointerex: {
          argc: 4,
          fn: ([hFile, liDist, lpNewPtr, dwMoveMethod]) => {
            const rec = b._handles.get(hFile);
            if (!rec || rec.kind !== 'file') {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0n;
            }
            try {
              const deltaBig = BigInt.asIntN(64, liDist);
              const method = Number(dwMoveMethod & 0xffffffffn);
              let basePosBig = 0n;
              if (method === WIN32_CONSTANTS.FILE_CURRENT) {
                basePosBig = Number.isSafeInteger(rec.pos) ? BigInt(rec.pos) : BigInt(Math.max(0, Math.trunc(rec.pos)));
              } else if (method === WIN32_CONSTANTS.FILE_END) {
                basePosBig = BigInt(b.services.vfs.stat(rec.canonicalPath, rec.vfsCtx).size);
              }
              const nextPosBig = basePosBig + deltaBig < 0n ? 0n : (basePosBig + deltaBig);
              rec.pos = nextPosBig <= BigInt(Number.MAX_SAFE_INTEGER)
                ? Number(nextPosBig)
                : Number.MAX_SAFE_INTEGER + 1;
              if (lpNewPtr !== 0n) b._writeU64(lpNewPtr, nextPosBig);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        getfilesize: {
          argc: 2,
          fn: ([hFile, lpHigh]) => {
            const rec = b._handles.get(hFile);
            if (!rec || rec.kind !== 'file') {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0xffffffffn;
            }
            try {
              const sz = b.services.vfs.stat(rec.canonicalPath, rec.vfsCtx).size;
              if (lpHigh !== 0n) b._writeU32(lpHigh, Math.floor(sz / 0x100000000));
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return BigInt(sz >>> 0);
            } catch (err) {
              b._setErrorFromException(err);
              return 0xffffffffn;
            }
          },
        },
        getfilesizeex: {
          argc: 2,
          fn: ([hFile, lpSize]) => {
            const rec = b._handles.get(hFile);
            if (!rec || rec.kind !== 'file') {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0n;
            }
            try {
              const sz = b.services.vfs.stat(rec.canonicalPath, rec.vfsCtx).size;
              if (lpSize !== 0n) b._writeU64(lpSize, BigInt(sz));
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        flushfilebuffers: { argc: 1, fn: () => 1n },
        setendoffile: {
          argc: 1,
          fn: ([hFile]) => {
            const rec = b._handles.get(hFile);
            if (!rec || rec.kind !== 'file') {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0n;
            }
            if (!rec.canWrite) {
              b.lastError = WIN32_ERROR.ERROR_ACCESS_DENIED;
              return 0n;
            }
            const maxFileBytes = b._maxWin32FileBytes();
            if (!Number.isSafeInteger(rec.pos) || rec.pos < 0 || rec.pos > maxFileBytes) {
              b.lastError = WIN32_ERROR.ERROR_DISK_FULL;
              return 0n;
            }
            try {
              // O(1) stat pre-check prevents reading multi-MiB blobs on no-op or quota-exceeded SetEndOfFile
              const curStat = b.services.vfs.stat(rec.canonicalPath, rec.vfsCtx);
              const curSize = typeof curStat?.size === 'number' && Number.isFinite(curStat.size) ? curStat.size : 0;
              if (rec.pos === curSize) {
                b.lastError = WIN32_ERROR.ERROR_SUCCESS;
                return 1n;
              }
              const estGrowth = Math.max(0, rec.pos - curSize);
              if (
                b.uid !== 0 &&
                (b._vfsWriteBytes + estGrowth > MAX_BRIDGE_VFS_WRITE_BYTES ||
                  b._vfsPhysicalWriteBytes + rec.pos > MAX_BRIDGE_VFS_PHYSICAL_WRITE_BYTES)
              ) {
                b.lastError = WIN32_ERROR.ERROR_DISK_FULL;
                return 0n;
              }
              let out;
              if (rec.pos === 0) {
                // Zero-truncation discards 100% of existing bytes: skip SQLite blob read entirely
                out = new Uint8Array(0);
              } else {
                if (!b._checkVfsReadQuota(curSize)) {
                  return 0n;
                }
                const cur = b.services.vfs.readFile(rec.canonicalPath, rec.vfsCtx);
                const bytes = cur instanceof Uint8Array ? cur : UTF8_ENCODER.encode(String(cur));
                b._recordVfsReadQuota(bytes.byteLength);
                if (rec.pos === bytes.byteLength) {
                  b.lastError = WIN32_ERROR.ERROR_SUCCESS;
                  return 1n;
                }
                const growth = Math.max(0, rec.pos - bytes.byteLength);
                if (!b._consumeVfsWriteQuota(growth, rec.pos)) {
                  return 0n;
                }
                out = new Uint8Array(rec.pos);
                out.set(bytes.subarray(0, Math.min(bytes.byteLength, rec.pos)), 0);
              }
              const written = b.services.vfs.writeFile(rec.canonicalPath, out, rec.vfsCtx);
              b._bumpVfsWriteGen(rec.canonicalPath, written?.ino ?? curStat?.ino ?? null);
              if (rec._readCache) b._clearFileReadCache(rec);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        closehandle: {
          argc: 1,
          fn: ([h]) => {
            if (h === b.STD_IN || h === b.STD_OUT || h === b.STD_ERR) return 1n;
            if (!b._deleteHandle(h)) {
              b.lastError = WIN32_ERROR.ERROR_INVALID_HANDLE;
              return 0n;
            }
            b.lastError = WIN32_ERROR.ERROR_SUCCESS;
            return 1n;
          },
        },
        deletefilea: {
          argc: 1,
          fn: ([lpName]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readCString(lpName), 'write');
              let ino = null;
              try {
                ino = b.services.vfs.lstat(canonicalPath, vfsCtx)?.ino ?? null;
              } catch (stErr) {
                void stErr;
              }
              b.services.vfs.unlink(canonicalPath, vfsCtx);
              b._bumpVfsWriteGen(canonicalPath, ino);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        deletefilew: {
          argc: 1,
          fn: ([lpName]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readWString(lpName), 'write');
              let ino = null;
              try {
                ino = b.services.vfs.lstat(canonicalPath, vfsCtx)?.ino ?? null;
              } catch (stErr) {
                void stErr;
              }
              b.services.vfs.unlink(canonicalPath, vfsCtx);
              b._bumpVfsWriteGen(canonicalPath, ino);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        movefilea: {
          argc: 2,
          fn: ([lpOld, lpNew]) => moveFileImpl(lpOld, lpNew, false, false),
        },
        movefilew: {
          argc: 2,
          fn: ([lpOld, lpNew]) => moveFileImpl(lpOld, lpNew, true, false),
        },
        movefileexa: {
          argc: 3,
          fn: ([lpOld, lpNew, dwFlags]) =>
            moveFileImpl(
              lpOld,
              lpNew,
              false,
              (Number(dwFlags & 0xffffffffn) & WIN32_CONSTANTS.MOVEFILE_REPLACE_EXISTING) !== 0
            ),
        },
        movefileexw: {
          argc: 3,
          fn: ([lpOld, lpNew, dwFlags]) =>
            moveFileImpl(
              lpOld,
              lpNew,
              true,
              (Number(dwFlags & 0xffffffffn) & WIN32_CONSTANTS.MOVEFILE_REPLACE_EXISTING) !== 0
            ),
        },
        copyfilea: {
          argc: 3,
          fn: ([lpOld, lpNew, bFailIfExists]) => copyFileImpl(lpOld, lpNew, bFailIfExists, false),
        },
        copyfilew: {
          argc: 3,
          fn: ([lpOld, lpNew, bFailIfExists]) => copyFileImpl(lpOld, lpNew, bFailIfExists, true),
        },
        createdirectorya: {
          argc: 2,
          fn: ([lpPath]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readCString(lpPath), 'write');
              if (!b._checkVfsCreateQuota(1)) {
                return 0n;
              }
              b.services.vfs.mkdir(canonicalPath, vfsCtx);
              b._bumpVfsWriteGen(canonicalPath);
              b._recordVfsCreateQuota(1);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        createdirectoryw: {
          argc: 2,
          fn: ([lpPath]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readWString(lpPath), 'write');
              if (!b._checkVfsCreateQuota(1)) {
                return 0n;
              }
              b.services.vfs.mkdir(canonicalPath, vfsCtx);
              b._bumpVfsWriteGen(canonicalPath);
              b._recordVfsCreateQuota(1);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        removedirectorya: {
          argc: 1,
          fn: ([lpPath]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readCString(lpPath), 'write');
              b.services.vfs.rmdir(canonicalPath, vfsCtx);
              b._bumpVfsWriteGen(canonicalPath);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        removedirectoryw: {
          argc: 1,
          fn: ([lpPath]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readWString(lpPath), 'write');
              b.services.vfs.rmdir(canonicalPath, vfsCtx);
              b._bumpVfsWriteGen(canonicalPath);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        getfileattributesa: {
          argc: 1,
          fn: ([lpPath]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readCString(lpPath), 'read');
              const st = b.services.vfs.stat(canonicalPath, vfsCtx);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return BigInt(st.type === 'dir' ? WIN32_CONSTANTS.FILE_ATTRIBUTE_DIRECTORY : WIN32_CONSTANTS.FILE_ATTRIBUTE_NORMAL);
            } catch (err) {
              b._setErrorFromException(err);
              return BigInt(WIN32_CONSTANTS.INVALID_FILE_ATTRIBUTES);
            }
          },
        },
        getfileattributesw: {
          argc: 1,
          fn: ([lpPath]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readWString(lpPath), 'read');
              const st = b.services.vfs.stat(canonicalPath, vfsCtx);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return BigInt(st.type === 'dir' ? WIN32_CONSTANTS.FILE_ATTRIBUTE_DIRECTORY : WIN32_CONSTANTS.FILE_ATTRIBUTE_NORMAL);
            } catch (err) {
              b._setErrorFromException(err);
              return BigInt(WIN32_CONSTANTS.INVALID_FILE_ATTRIBUTES);
            }
          },
        },
        findfirstfilea: { argc: 2, fn: (args) => findFirstFileImpl(args, false) },
        findfirstfilew: { argc: 2, fn: (args) => findFirstFileImpl(args, true) },
        findnextfilea: { argc: 2, fn: (args) => findNextFileImpl(args, false) },
        findnextfilew: { argc: 2, fn: (args) => findNextFileImpl(args, true) },
        findclose: {
          argc: 1,
          fn: ([h]) => {
            const rec = b._handles.get(h);
            if (rec && rec.kind === 'find') b._deleteHandle(h);
            return 1n;
          },
        },
        getcurrentdirectorya: {
          argc: 2,
          fn: ([nBufLen, lpBuf]) => {
            const winCwd = b.services.vfs?.pathTranslator?.toPlatform?.(b.cwd, 'windows') || 'C:\\Users\\user';
            const max = Number(nBufLen & 0xffffffffn);
            if (max === 0 || lpBuf === 0n) return BigInt(winCwd.length + 1);
            return BigInt(b._writeCString(lpBuf, winCwd, max));
          },
        },
        getcurrentdirectoryw: {
          argc: 2,
          fn: ([nBufLen, lpBuf]) => {
            const winCwd = b.services.vfs?.pathTranslator?.toPlatform?.(b.cwd, 'windows') || 'C:\\Users\\user';
            const max = Number(nBufLen & 0xffffffffn);
            if (max === 0 || lpBuf === 0n) return BigInt(winCwd.length + 1);
            return BigInt(b._writeWString(lpBuf, winCwd, max));
          },
        },
        setcurrentdirectorya: {
          argc: 1,
          fn: ([lpPath]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readCString(lpPath), 'read');
              const st = b.services.vfs.stat(canonicalPath, vfsCtx);
              if (st.type !== 'dir') {
                b.lastError = WIN32_ERROR.ERROR_DIRECTORY;
                return 0n;
              }
              b.cwd = canonicalPath;
              if (b.pcb) b.pcb.cwd = canonicalPath;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        setcurrentdirectoryw: {
          argc: 1,
          fn: ([lpPath]) => {
            try {
              const { canonicalPath, vfsCtx } = b._resolveVfsPath(b._readWString(lpPath), 'read');
              const st = b.services.vfs.stat(canonicalPath, vfsCtx);
              if (st.type !== 'dir') {
                b.lastError = WIN32_ERROR.ERROR_DIRECTORY;
                return 0n;
              }
              b.cwd = canonicalPath;
              if (b.pcb) b.pcb.cwd = canonicalPath;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        gettemppatha: {
          argc: 2,
          fn: ([nBufLen, lpBuf]) => {
            const tp = 'C:\\Temp\\';
            const max = Number(nBufLen & 0xffffffffn);
            if (max === 0 || lpBuf === 0n) return BigInt(tp.length + 1);
            return BigInt(b._writeCString(lpBuf, tp, max));
          },
        },
        gettemppathw: {
          argc: 2,
          fn: ([nBufLen, lpBuf]) => {
            const tp = 'C:\\Temp\\';
            const max = Number(nBufLen & 0xffffffffn);
            if (max === 0 || lpBuf === 0n) return BigInt(tp.length + 1);
            return BigInt(b._writeWString(lpBuf, tp, max));
          },
        },

        // Memory (M1 AddressSpace)
        virtualalloc: {
          argc: 4,
          fn: ([lpAddr, dwSize, _flType, flProtect]) => {
            const sz = Math.max(4096, Number(dwSize & 0xffffffffn));
            const perms = winProtectToVmmPerms(flProtect);
            try {
              const base = b.addressSpace.mmap(lpAddr === 0n ? 0 : lpAddr, sz, perms, 'win32:VirtualAlloc');
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return BigInt(base);
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        virtualfree: {
          argc: 3,
          fn: ([lpAddr, dwSize]) => {
            try {
              const sz = Math.max(4096, Number(dwSize & 0xffffffffn));
              b.addressSpace.munmap(lpAddr, sz);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        virtualprotect: {
          argc: 4,
          fn: ([lpAddr, dwSize, flNewProtect, lpOldProtect]) => {
            try {
              const sz = Math.max(4096, Number(dwSize & 0xffffffffn));
              const perms = winProtectToVmmPerms(flNewProtect);
              b.addressSpace.mprotect(lpAddr, sz, perms);
              if (lpOldProtect !== 0n) b._writeU32(lpOldProtect, WIN32_CONSTANTS.PAGE_READWRITE);
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        getprocessheap: { argc: 0, fn: () => 0x00001000n },
        heapalloc: {
          argc: 3,
          fn: ([_hHeap, dwFlags, dwBytes]) => {
            const sz = Math.max(1, Number(dwBytes & 0xffffffffn) >>> 0);
            try {
              const ptr = BigInt(b.addressSpace.alloc(sz));
              if ((Number(dwFlags & 0xffffffffn) & WIN32_CONSTANTS.HEAP_ZERO_MEMORY) !== 0) {
                b._memFill(ptr, 0, BigInt(sz), 'HeapAlloc');
              }
              b._globalAllocs.set(ptr, { size: sz });
              return ptr;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        heaprealloc: {
          argc: 4,
          fn: ([_hHeap, _dwFlags, lpMem, dwBytes]) => {
            const sz = Math.max(1, Number(dwBytes & 0xffffffffn) >>> 0);
            try {
              const ptr = BigInt(b.addressSpace.realloc(lpMem, sz));
              b._globalAllocs.delete(lpMem);
              b._globalAllocs.set(ptr, { size: sz });
              return ptr;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        heapfree: {
          argc: 3,
          fn: ([_hHeap, _dwFlags, lpMem]) => {
            if (lpMem === 0n) return 1n;
            try {
              b.addressSpace.free(lpMem);
              b._globalAllocs.delete(lpMem);
              return 1n;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        heapsize: {
          argc: 3,
          fn: ([_hHeap, _dwFlags, lpMem]) => BigInt(b._globalAllocs.get(lpMem)?.size ?? 0),
        },
        globalalloc: {
          argc: 2,
          fn: ([uFlags, dwBytes]) => {
            const sz = Math.max(1, Number(dwBytes & 0xffffffffn) >>> 0);
            try {
              const ptr = BigInt(b.addressSpace.alloc(sz));
              if ((Number(uFlags & 0xffffffffn) & 0x40) !== 0) { // GMEM_ZEROINIT
                b._memFill(ptr, 0, BigInt(sz), 'GlobalAlloc');
              }
              b._globalAllocs.set(ptr, { size: sz });
              return ptr;
            } catch (err) {
              b._setErrorFromException(err);
              return 0n;
            }
          },
        },
        globallock: { argc: 1, fn: ([hMem]) => hMem },
        globalunlock: { argc: 1, fn: () => 1n },
        globalfree: {
          argc: 1,
          fn: ([hMem]) => {
            if (hMem !== 0n && b._globalAllocs.has(hMem)) {
              try {
                b.addressSpace.free(hMem);
              } catch (err) {
                void err;
              }
              b._globalAllocs.delete(hMem);
            }
            return 0n; // GlobalFree returns NULL on success!
          },
        },
        globalsize: {
          argc: 1,
          fn: ([hMem]) => BigInt(b._globalAllocs.get(hMem)?.size ?? 0),
        },
        localalloc: {
          argc: 2,
          fn: ([uFlags, dwBytes]) => {
            const sz = Math.max(1, Number(dwBytes & 0xffffffffn) >>> 0);
            try {
              const ptr = BigInt(b.addressSpace.alloc(sz));
              if ((Number(uFlags & 0xffffffffn) & 0x40) !== 0) { // LMEM_ZEROINIT
                b._memFill(ptr, 0, BigInt(sz), 'LocalAlloc');
              }
              b._globalAllocs.set(ptr, { size: sz });
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return ptr;
            } catch (err) {
              b._setErrorFromException(err);
              if (b.lastError === WIN32_ERROR.ERROR_INVALID_FUNCTION) {
                b.lastError = WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY;
              }
              return 0n;
            }
          },
        },
        locallock: { argc: 1, fn: ([hMem]) => hMem },
        localunlock: { argc: 1, fn: () => 1n },
        localfree: {
          argc: 1,
          fn: ([hMem]) => {
            if (hMem !== 0n && b._globalAllocs.has(hMem)) {
              try { b.addressSpace.free(hMem); } catch (err) { void err; }
              b._globalAllocs.delete(hMem);
            }
            return 0n;
          },
        },

        // Process, Module, Time, Error, Encoding
        exitprocess: {
          argc: 1,
          fn: ([uExitCode]) => {
            b.flushCompositorSurfacesIfDirty();
            return {
              status: 'EXITED',
              exitCode: Number(BigInt.asIntN(32, uExitCode)),
            };
          },
        },
        getcurrentprocess: { argc: 0, fn: () => b.invalidHandle },
        getcurrentprocessid: { argc: 0, fn: () => BigInt(b.pcb?.pid ?? 1) },
        getcurrentthreadid: { argc: 0, fn: () => BigInt((b.pcb?.pid ?? 1) * 100 + 1) },
        getcommandlinea: {
          argc: 0,
          fn: () => {
            if (b._cmdLineAnsiVa === null) {
              const argv = [b.appRecord?.name || 'app.exe', ...(b.pcb?.args ?? [])];
              const str = argv.map((a) => (a.includes(' ') ? `"${a}"` : a)).join(' ');
              const enc = UTF8_ENCODER.encode(str);
              const ptr = BigInt(b.addressSpace.alloc(enc.byteLength + 1));
              b._writeCString(ptr, str);
              b._cmdLineAnsiVa = ptr;
            }
            return b._cmdLineAnsiVa;
          },
        },
        getcommandlinew: {
          argc: 0,
          fn: () => {
            if (b._cmdLineWideVa === null) {
              const argv = [b.appRecord?.name || 'app.exe', ...(b.pcb?.args ?? [])];
              const str = argv.map((a) => (a.includes(' ') ? `"${a}"` : a)).join(' ');
              const enc = encodeUtf16LE(str, true);
              const ptr = BigInt(b.addressSpace.alloc(enc.byteLength));
              b.addressSpace.write(ptr, enc);
              b._cmdLineWideVa = ptr;
            }
            return b._cmdLineWideVa;
          },
        },
        getenvironmentvariablea: {
          argc: 3,
          fn: ([lpName, lpBuf, nSize]) => {
            const key = (b._readCString(lpName) || '').toUpperCase();
            const entry = b.env.get(key);
            if (!entry) {
              b.lastError = 203; // ERROR_ENVVAR_NOT_FOUND
              return 0n;
            }
            const cap = Number(nSize & 0xffffffffn);
            if (cap < entry.value.length + 1 || lpBuf === 0n) {
              return BigInt(entry.value.length + 1);
            }
            return BigInt(b._writeCString(lpBuf, entry.value, cap));
          },
        },
        getenvironmentvariablew: {
          argc: 3,
          fn: ([lpName, lpBuf, nSize]) => {
            const key = (b._readWString(lpName) || '').toUpperCase();
            const entry = b.env.get(key);
            if (!entry) {
              b.lastError = 203;
              return 0n;
            }
            const cap = Number(nSize & 0xffffffffn);
            if (cap < entry.value.length + 1 || lpBuf === 0n) {
              return BigInt(entry.value.length + 1);
            }
            return BigInt(b._writeWString(lpBuf, entry.value, cap));
          },
        },
        setenvironmentvariablea: {
          argc: 2,
          fn: ([lpName, lpVal]) => {
            const name = b._readCString(lpName);
            if (!name) return 0n;
            const val = lpVal === 0n ? null : (b._readCString(lpVal) ?? '');
            return b._setWinEnv(name, val) ? 1n : 0n;
          },
        },
        setenvironmentvariablew: {
          argc: 2,
          fn: ([lpName, lpVal]) => {
            const name = b._readWString(lpName);
            if (!name) return 0n;
            const val = lpVal === 0n ? null : (b._readWString(lpVal) ?? '');
            return b._setWinEnv(name, val) ? 1n : 0n;
          },
        },
        getmodulehandlea: {
          argc: 1,
          fn: ([lpName]) => {
            if (lpName === 0n) return b.mappedImage?.loadBase ?? (b.is64 ? 0x140000000n : 0x400000n);
            return b._getOrCreateModule(b._readCString(lpName));
          },
        },
        getmodulehandlew: {
          argc: 1,
          fn: ([lpName]) => {
            if (lpName === 0n) return b.mappedImage?.loadBase ?? (b.is64 ? 0x140000000n : 0x400000n);
            return b._getOrCreateModule(b._readWString(lpName));
          },
        },
        getmodulefilenamea: {
          argc: 3,
          fn: ([_hMod, lpBuf, nSize]) => {
            const name = `C:\\Program Files\\${b.appRecord?.name || 'app.exe'}`;
            return BigInt(b._writeCString(lpBuf, name, Number(nSize & 0xffffffffn)));
          },
        },
        getmodulefilenamew: {
          argc: 3,
          fn: ([_hMod, lpBuf, nSize]) => {
            const name = `C:\\Program Files\\${b.appRecord?.name || 'app.exe'}`;
            return BigInt(b._writeWString(lpBuf, name, Number(nSize & 0xffffffffn)));
          },
        },
        loadlibrarya: { argc: 1, fn: ([lpName]) => b._getOrCreateModule(b._readCString(lpName)) },
        loadlibraryw: { argc: 1, fn: ([lpName]) => b._getOrCreateModule(b._readWString(lpName)) },
        getprocaddress: {
          argc: 2,
          fn: ([hMod, lpProcName]) => {
            const dllLower = b._modulesByHandle.get(hMod) || 'kernel32.dll';
            const fnName = lpProcName > 0xffffn ? b._readCString(lpProcName) : null;
            const ordinal = lpProcName <= 0xffffn ? Number(lpProcName) : null;
            if (!fnName && ordinal === null) {
              b.lastError = WIN32_ERROR.ERROR_PROC_NOT_FOUND;
              return 0n;
            }
            const entry = fnName ? b._lookupApi(dllLower, fnName.toLowerCase()) : null;
            if (!entry) {
              b.lastError = WIN32_ERROR.ERROR_PROC_NOT_FOUND;
              return 0n;
            }
            return b.registerImport(dllLower, fnName, ordinal);
          },
        },
        getlasterror: { argc: 0, fn: () => BigInt(b.lastError >>> 0) },
        setlasterror: { argc: 1, fn: ([dwErr]) => { b.lastError = Number(dwErr & 0xffffffffn); return 0n; } },
        gettickcount: { argc: 0, fn: () => BigInt((Date.now() - b._startMs) >>> 0) },
        gettickcount64: { argc: 0, fn: () => BigInt(Date.now() - b._startMs) },
        queryperformancecounter: {
          argc: 1,
          fn: ([lpCount]) => {
            const ticks = BigInt(Date.now() - b._startMs) * 10000n;
            b._writeU64(lpCount, ticks);
            return 1n;
          },
        },
        queryperformancefrequency: {
          argc: 1,
          fn: ([lpFreq]) => {
            b._writeU64(lpFreq, 10000000n);
            return 1n;
          },
        },
        getsystemtime: {
          argc: 1,
          fn: ([lpSt]) => {
            const d = new Date();
            const buf = new Uint8Array(16);
            const dv = new DataView(buf.buffer);
            dv.setUint16(0, d.getUTCFullYear(), true);
            dv.setUint16(2, d.getUTCMonth() + 1, true);
            dv.setUint16(4, d.getUTCDay(), true);
            dv.setUint16(6, d.getUTCDate(), true);
            dv.setUint16(8, d.getUTCHours(), true);
            dv.setUint16(10, d.getUTCMinutes(), true);
            dv.setUint16(12, d.getUTCSeconds(), true);
            dv.setUint16(14, d.getUTCMilliseconds(), true);
            b.addressSpace.write(lpSt, buf);
            return 0n;
          },
        },
        getlocaltime: {
          argc: 1,
          fn: ([lpSt]) => {
            const d = new Date();
            const buf = new Uint8Array(16);
            const dv = new DataView(buf.buffer);
            dv.setUint16(0, d.getFullYear(), true);
            dv.setUint16(2, d.getMonth() + 1, true);
            dv.setUint16(4, d.getDay(), true);
            dv.setUint16(6, d.getDate(), true);
            dv.setUint16(8, d.getHours(), true);
            dv.setUint16(10, d.getMinutes(), true);
            dv.setUint16(12, d.getSeconds(), true);
            dv.setUint16(14, d.getMilliseconds(), true);
            b.addressSpace.write(lpSt, buf);
            return 0n;
          },
        },
        getsystemtimeasfiletime: {
          argc: 1,
          fn: ([lpFt]) => {
            // Windows FILETIME: 100ns intervals since 1601-01-01
            const ft = (BigInt(Date.now()) + 11644473600000n) * 10000n;
            b._writeU64(lpFt, ft);
            return 0n;
          },
        },
        sleep: { argc: 1, fn: () => 0n },
        multibytetowidechar: {
          argc: 6,
          fn: ([_cp, _flags, lpMb, cbMb, lpWc, cchWc]) => {
            const cap = Number(BigInt.asIntN(32, cchWc));
            if (cap < 0) {
              b.lastError = WIN32_ERROR.ERROR_INVALID_PARAMETER;
              return 0n;
            }
            if (cap > 0) {
              b._normalizeMemOpLen(cap * 2, lpWc, 'MultiByteToWideChar');
            }
            const lenArg = Number(BigInt.asIntN(32, cbMb));
            let str = '';
            if (lenArg < 0) {
              str = b._readCString(lpMb) ?? '';
            } else if (lenArg > 0) {
              const readLen = b._normalizeMemOpLen(lenArg, lpMb, 'MultiByteToWideChar');
              str = UTF8_DECODER.decode(b.addressSpace.read(lpMb, readLen));
            }
            const includeNull = lenArg < 0;
            const required = str.length + (includeNull ? 1 : 0);
            if (cap === 0 || lpWc === 0n) {
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return BigInt(required);
            }
            const copy = Math.min(str.length, cap - (includeNull ? 1 : 0));
            const out = encodeUtf16LE(str.slice(0, copy), includeNull);
            b.addressSpace.write(lpWc, out);
            b.lastError = WIN32_ERROR.ERROR_SUCCESS;
            return BigInt(copy + (includeNull ? 1 : 0));
          },
        },
        widechartomultibyte: {
          argc: 8,
          fn: ([_cp, _flags, lpWc, cchWc, lpMb, cbMb]) => {
            const cap = Number(BigInt.asIntN(32, cbMb));
            if (cap < 0) {
              b.lastError = WIN32_ERROR.ERROR_INVALID_PARAMETER;
              return 0n;
            }
            if (cap > 0) {
              b._normalizeMemOpLen(cap, lpMb, 'WideCharToMultiByte');
            }
            const lenArg = Number(BigInt.asIntN(32, cchWc));
            let str = '';
            if (lenArg < 0) {
              str = b._readWString(lpWc) ?? '';
            } else if (lenArg > 0) {
              const readBytes = b._normalizeMemOpLen(lenArg * 2, lpWc, 'WideCharToMultiByte');
              str = UTF16LE_DECODER.decode(b.addressSpace.read(lpWc, readBytes));
            }
            const enc = UTF8_ENCODER.encode(str);
            const includeNull = lenArg < 0;
            const required = enc.byteLength + (includeNull ? 1 : 0);
            if (cap === 0 || lpMb === 0n) {
              b.lastError = WIN32_ERROR.ERROR_SUCCESS;
              return BigInt(required);
            }
            const copy = Math.min(enc.byteLength, cap - (includeNull ? 1 : 0));
            const out = new Uint8Array(copy + (includeNull ? 1 : 0));
            out.set(enc.subarray(0, copy), 0);
            b.addressSpace.write(lpMb, out);
            b.lastError = WIN32_ERROR.ERROR_SUCCESS;
            return BigInt(out.byteLength);
          },
        },
        lstrlena: { argc: 1, fn: ([s]) => BigInt((b._readCString(s) ?? '').length) },
        lstrlenw: { argc: 1, fn: ([s]) => BigInt((b._readWString(s) ?? '').length) },
        lstrcpya: { argc: 2, fn: ([dst, src]) => { b._writeCString(dst, b._readCString(src) ?? ''); return dst; } },
        lstrcpyw: { argc: 2, fn: ([dst, src]) => { b._writeWString(dst, b._readWString(src) ?? ''); return dst; } },
        lstrcata: {
          argc: 2,
          fn: ([dst, src]) => {
            const merged = (b._readCString(dst) ?? '') + (b._readCString(src) ?? '');
            b._writeCString(dst, merged);
            return dst;
          },
        },
        lstrcatw: {
          argc: 2,
          fn: ([dst, src]) => {
            const merged = (b._readWString(dst) ?? '') + (b._readWString(src) ?? '');
            b._writeWString(dst, merged);
            return dst;
          },
        },
        lstrcmpa: {
          argc: 2,
          fn: ([a, c]) => {
            const s1 = b._readCString(a) ?? '';
            const s2 = b._readCString(c) ?? '';
            return s1 < s2 ? -1n : (s1 > s2 ? 1n : 0n);
          },
        },
        lstrcmpw: {
          argc: 2,
          fn: ([a, c]) => {
            const s1 = b._readWString(a) ?? '';
            const s2 = b._readWString(c) ?? '';
            return s1 < s2 ? -1n : (s1 > s2 ? 1n : 0n);
          },
        },
        rtlzeromemory: {
          argc: 2,
          fn: ([dst, len]) => {
            b._memFill(dst, 0, len, 'RtlZeroMemory');
            return 0n;
          },
        },
        rtlmovememory: {
          argc: 3,
          fn: ([dst, src, len]) => {
            b._memCopy(dst, src, len, true, 'RtlMoveMemory');
            return 0n;
          },
        },
        rtlcopymemory: {
          argc: 3,
          fn: ([dst, src, len]) => {
            b._memCopy(dst, src, len, false, 'RtlCopyMemory');
            return 0n;
          },
        },
      },

      // ======================================================================
      // user32.dll
      // ======================================================================
      'user32.dll': {
        messageboxa: { argc: 4, fn: (args) => messageBoxImpl(args, false) },
        messageboxw: { argc: 4, fn: (args) => messageBoxImpl(args, true) },
        registerclassexa: { argc: 1, fn: (args) => registerClassExImpl(args, false) },
        registerclassexw: { argc: 1, fn: (args) => registerClassExImpl(args, true) },
        registerclassa: { argc: 1, fn: (args) => registerClassImpl(args, false) },
        registerclassw: { argc: 1, fn: (args) => registerClassImpl(args, true) },
        createwindowexa: { argc: 12, fn: (args) => createWindowExImpl(args, false) },
        createwindowexw: { argc: 12, fn: (args) => createWindowExImpl(args, true) },
        showwindow: {
          argc: 2,
          fn: ([hWnd, nCmdShow]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            const prev = win.visible ? 1n : 0n;
            win.visible = Number(nCmdShow & 0xffffffffn) !== 0;
            if (win.visible) win.needsPaint = true;
            return prev;
          },
        },
        updatewindow: {
          argc: 1,
          fn: ([hWnd]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            if (win.needsPaint) {
              win.needsPaint = false;
              return b._dispatchWndProc(win, WIN32_CONSTANTS.WM_PAINT, 0n, 0n, {
                onReturn: () => 1n,
              });
            }
            return 1n;
          },
        },
        destroywindow: {
          argc: 1,
          fn: ([hWnd]) => b._destroyWindow(hWnd, { returnValue: 1n, fromThunk: true }),
        },
        setwindowtexta: {
          argc: 2,
          fn: ([hWnd, lpStr]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            const prevText = win.text;
            const nextText = b._readCString(lpStr, MAX_WINDOW_TEXT_CHARS) ?? '';
            if (!b._setWindowText(win, nextText, { rejectOnEmpty: true })) {
              return 0n;
            }
            if (win.text !== prevText) {
              const root = b._findTopLevelOwner(win);
              if (root) b._markWindowSurfaceDirty(root);
            }
            return 1n;
          },
        },
        setwindowtextw: {
          argc: 2,
          fn: ([hWnd, lpStr]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            const prevText = win.text;
            const nextText = b._readWString(lpStr, MAX_WINDOW_TEXT_CHARS) ?? '';
            if (!b._setWindowText(win, nextText, { rejectOnEmpty: true })) {
              return 0n;
            }
            if (win.text !== prevText) {
              const root = b._findTopLevelOwner(win);
              if (root) b._markWindowSurfaceDirty(root);
            }
            return 1n;
          },
        },
        getwindowtexta: {
          argc: 3,
          fn: ([hWnd, lpStr, nMax]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            return BigInt(b._writeCString(lpStr, win.text, Number(nMax & 0xffffffffn)));
          },
        },
        getwindowtextw: {
          argc: 3,
          fn: ([hWnd, lpStr, nMax]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            return BigInt(b._writeWString(lpStr, win.text, Number(nMax & 0xffffffffn)));
          },
        },
        getwindowtextlengtha: { argc: 1, fn: ([hWnd]) => BigInt((b._windows.get(hWnd)?.text ?? '').length) },
        getwindowtextlengthw: { argc: 1, fn: ([hWnd]) => BigInt((b._windows.get(hWnd)?.text ?? '').length) },
        getdlgitem: {
          argc: 2,
          fn: ([hDlg, nId]) => {
            const parent = b._windows.get(hDlg);
            const targetId = Number(nId & 0xffffn);
            if (!parent) return 0n;
            for (const ch of parent.childHwnds) {
              const ctrl = b._windows.get(ch);
              if (ctrl && ctrl.controlId === targetId) return ctrl.hwnd;
            }
            return 0n;
          },
        },
        getclientrect: {
          argc: 2,
          fn: ([hWnd, lpRect]) => {
            const win = b._windows.get(hWnd);
            if (!win || lpRect === 0n) return 0n;
            const buf = new Uint8Array(16);
            const dv = new DataView(buf.buffer);
            dv.setInt32(0, 0, true);
            dv.setInt32(4, 0, true);
            dv.setInt32(8, win.width, true);
            dv.setInt32(12, win.height, true);
            b.addressSpace.write(lpRect, buf);
            return 1n;
          },
        },
        getmessagea: {
          argc: 4,
          fn: ([lpMsg]) => {
            if (b._messageQueue.length === 0) {
              // Synthesize WM_PAINT if any visible top-level window needs painting
              for (const w of b._windows.values()) {
                if (w.parentHwnd === 0n && !w.destroyed && w.needsPaint) {
                  w.needsPaint = false;
                  b._enqueueMessage({ hwnd: w.hwnd, message: WIN32_CONSTANTS.WM_PAINT, wParam: 0n, lParam: 0n });
                  break;
                }
              }
            }
            if (b._messageQueue.length === 0) {
              // Flush pending compositor surfaces once right before blocking cleanly!
              b.flushCompositorSurfacesIfDirty();
              // Block cleanly keeping RIP at GetMessage thunk until Compositor/PostMessage wakes us!
              return { status: 'BLOCKED', waitReason: 'message' };
            }
            const msg = b._messageQueue.shift();
            b._writeMsgStruct(lpMsg, msg);
            return msg.message === WIN32_CONSTANTS.WM_QUIT ? 0n : 1n;
          },
        },
        getmessagew: {
          argc: 4,
          fn: ([lpMsg]) => {
            if (b._messageQueue.length === 0) {
              for (const w of b._windows.values()) {
                if (w.parentHwnd === 0n && !w.destroyed && w.needsPaint) {
                  w.needsPaint = false;
                  b._enqueueMessage({ hwnd: w.hwnd, message: WIN32_CONSTANTS.WM_PAINT, wParam: 0n, lParam: 0n });
                  break;
                }
              }
            }
            if (b._messageQueue.length === 0) {
              b.flushCompositorSurfacesIfDirty();
              return { status: 'BLOCKED', waitReason: 'message' };
            }
            const msg = b._messageQueue.shift();
            b._writeMsgStruct(lpMsg, msg);
            return msg.message === WIN32_CONSTANTS.WM_QUIT ? 0n : 1n;
          },
        },
        peekmessagea: {
          argc: 5,
          fn: ([lpMsg, _hWnd, _min, _max, wRemove]) => {
            if (b._messageQueue.length === 0) return 0n;
            const msg = (Number(wRemove & 1n) !== 0) ? b._messageQueue.shift() : b._messageQueue[0];
            b._writeMsgStruct(lpMsg, msg);
            return 1n;
          },
        },
        peekmessagew: {
          argc: 5,
          fn: ([lpMsg, _hWnd, _min, _max, wRemove]) => {
            if (b._messageQueue.length === 0) return 0n;
            const msg = (Number(wRemove & 1n) !== 0) ? b._messageQueue.shift() : b._messageQueue[0];
            b._writeMsgStruct(lpMsg, msg);
            return 1n;
          },
        },
        translatemessage: { argc: 1, fn: () => 1n },
        dispatchmessagea: {
          argc: 1,
          fn: ([lpMsg]) => {
            const msg = b._readMsgStruct(lpMsg);
            const win = b._windows.get(msg.hwnd);
            return b._dispatchWndProc(win, msg.message, msg.wParam, msg.lParam);
          },
        },
        dispatchmessagew: {
          argc: 1,
          fn: ([lpMsg]) => {
            const msg = b._readMsgStruct(lpMsg);
            const win = b._windows.get(msg.hwnd);
            return b._dispatchWndProc(win, msg.message, msg.wParam, msg.lParam);
          },
        },
        defwindowproca: { argc: 4, fn: ([h, m, w, l]) => b._defWindowProc(h, m, w, l) },
        defwindowprocw: { argc: 4, fn: ([h, m, w, l]) => b._defWindowProc(h, m, w, l) },
        sendmessagea: {
          argc: 4,
          fn: ([hWnd, uMsg, wParam, lParam]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            const m = Number(uMsg & 0xffffffffn);
            if (m === WIN32_CONSTANTS.WM_SETTEXT) {
              const prevText = win.text;
              const nextText = b._readCString(lParam, MAX_WINDOW_TEXT_CHARS) ?? '';
              if (!b._setWindowText(win, nextText, { rejectOnEmpty: true })) {
                return 0n;
              }
              if (win.text !== prevText) {
                const root = b._findTopLevelOwner(win);
                if (root) b._markWindowSurfaceDirty(root);
              }
              return 1n;
            }
            if (m === WIN32_CONSTANTS.WM_GETTEXT) {
              return BigInt(b._writeCString(lParam, win.text, Number(wParam & 0xffffffffn)));
            }
            if (m === WIN32_CONSTANTS.WM_GETTEXTLENGTH) {
              return BigInt(win.text.length);
            }
            if (Array.isArray(win.items)) {
              if (m === WIN32_CONSTANTS.LB_ADDSTRING || m === WIN32_CONSTANTS.LB_INSERTSTRING) {
                const s = b._readCString(lParam, MAX_WINDOW_TEXT_CHARS) ?? '';
                const itemBytes = s.length * 2 + 32;
                const curBytes = win.listboxBytes ?? 0;
                if (
                  win.items.length >= MAX_LISTBOX_ITEMS ||
                  curBytes + itemBytes > MAX_LISTBOX_BYTES ||
                  b._totalListboxBytes + itemBytes > MAX_BRIDGE_LISTBOX_BYTES
                ) {
                  return -2n; // LB_ERRSPACE
                }
                let idx;
                if (m === WIN32_CONSTANTS.LB_INSERTSTRING) {
                  const reqIdx = Number(BigInt.asIntN(32, wParam));
                  idx = reqIdx < 0 || reqIdx >= win.items.length ? win.items.length : reqIdx;
                  win.items.splice(idx, 0, s);
                } else {
                  win.items.push(s);
                  idx = win.items.length - 1;
                }
                win.listboxBytes = curBytes + itemBytes;
                b._totalListboxBytes += itemBytes;
                const root = b._findTopLevelOwner(win);
                if (root) b._markWindowSurfaceDirty(root);
                return BigInt(idx);
              }
              if (m === WIN32_CONSTANTS.LB_DELETESTRING) {
                const idx = Number(BigInt.asIntN(32, wParam));
                if (idx < 0 || idx >= win.items.length) return -1n; // LB_ERR
                const [removed] = win.items.splice(idx, 1);
                const removedBytes = (typeof removed === 'string' ? removed.length * 2 : 0) + 32;
                const prevBytes = win.listboxBytes ?? 0;
                const nextBytes = win.items.length === 0 ? 0 : Math.max(0, prevBytes - removedBytes);
                const delta = Math.max(0, prevBytes - nextBytes);
                win.listboxBytes = nextBytes;
                b._totalListboxBytes = Math.max(0, b._totalListboxBytes - delta);
                const root = b._findTopLevelOwner(win);
                if (root) b._markWindowSurfaceDirty(root);
                return BigInt(win.items.length);
              }
              if (m === WIN32_CONSTANTS.LB_RESETCONTENT) {
                const prevBytes = win.listboxBytes ?? 0;
                win.items.length = 0;
                win.listboxBytes = 0;
                b._totalListboxBytes = Math.max(0, b._totalListboxBytes - prevBytes);
                const root = b._findTopLevelOwner(win);
                if (root) b._markWindowSurfaceDirty(root);
                return 0n;
              }
            }
            return b._dispatchWndProc(win, m, wParam, lParam);
          },
        },
        sendmessagew: {
          argc: 4,
          fn: ([hWnd, uMsg, wParam, lParam]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            const m = Number(uMsg & 0xffffffffn);
            if (m === WIN32_CONSTANTS.WM_SETTEXT) {
              const prevText = win.text;
              const nextText = b._readWString(lParam, MAX_WINDOW_TEXT_CHARS) ?? '';
              if (!b._setWindowText(win, nextText, { rejectOnEmpty: true })) {
                return 0n;
              }
              if (win.text !== prevText) {
                const root = b._findTopLevelOwner(win);
                if (root) b._markWindowSurfaceDirty(root);
              }
              return 1n;
            }
            if (m === WIN32_CONSTANTS.WM_GETTEXT) {
              return BigInt(b._writeWString(lParam, win.text, Number(wParam & 0xffffffffn)));
            }
            if (m === WIN32_CONSTANTS.WM_GETTEXTLENGTH) {
              return BigInt(win.text.length);
            }
            if (Array.isArray(win.items)) {
              if (m === WIN32_CONSTANTS.LB_ADDSTRING || m === WIN32_CONSTANTS.LB_INSERTSTRING) {
                const s = b._readWString(lParam, MAX_WINDOW_TEXT_CHARS) ?? '';
                const itemBytes = s.length * 2 + 32;
                const curBytes = win.listboxBytes ?? 0;
                if (
                  win.items.length >= MAX_LISTBOX_ITEMS ||
                  curBytes + itemBytes > MAX_LISTBOX_BYTES ||
                  b._totalListboxBytes + itemBytes > MAX_BRIDGE_LISTBOX_BYTES
                ) {
                  return -2n; // LB_ERRSPACE
                }
                let idx;
                if (m === WIN32_CONSTANTS.LB_INSERTSTRING) {
                  const reqIdx = Number(BigInt.asIntN(32, wParam));
                  idx = reqIdx < 0 || reqIdx >= win.items.length ? win.items.length : reqIdx;
                  win.items.splice(idx, 0, s);
                } else {
                  win.items.push(s);
                  idx = win.items.length - 1;
                }
                win.listboxBytes = curBytes + itemBytes;
                b._totalListboxBytes += itemBytes;
                const root = b._findTopLevelOwner(win);
                if (root) b._markWindowSurfaceDirty(root);
                return BigInt(idx);
              }
              if (m === WIN32_CONSTANTS.LB_DELETESTRING) {
                const idx = Number(BigInt.asIntN(32, wParam));
                if (idx < 0 || idx >= win.items.length) return -1n; // LB_ERR
                const [removed] = win.items.splice(idx, 1);
                const removedBytes = (typeof removed === 'string' ? removed.length * 2 : 0) + 32;
                const prevBytes = win.listboxBytes ?? 0;
                const nextBytes = win.items.length === 0 ? 0 : Math.max(0, prevBytes - removedBytes);
                const delta = Math.max(0, prevBytes - nextBytes);
                win.listboxBytes = nextBytes;
                b._totalListboxBytes = Math.max(0, b._totalListboxBytes - delta);
                const root = b._findTopLevelOwner(win);
                if (root) b._markWindowSurfaceDirty(root);
                return BigInt(win.items.length);
              }
              if (m === WIN32_CONSTANTS.LB_RESETCONTENT) {
                const prevBytes = win.listboxBytes ?? 0;
                win.items.length = 0;
                win.listboxBytes = 0;
                b._totalListboxBytes = Math.max(0, b._totalListboxBytes - prevBytes);
                const root = b._findTopLevelOwner(win);
                if (root) b._markWindowSurfaceDirty(root);
                return 0n;
              }
            }
            return b._dispatchWndProc(win, m, wParam, lParam);
          },
        },
        postmessagea: {
          argc: 4,
          fn: ([hWnd, uMsg, wParam, lParam]) => (
            b._enqueueMessage({ hwnd: hWnd, message: Number(uMsg & 0xffffffffn), wParam, lParam })
              ? 1n
              : 0n
          ),
        },
        postmessagew: {
          argc: 4,
          fn: ([hWnd, uMsg, wParam, lParam]) => (
            b._enqueueMessage({ hwnd: hWnd, message: Number(uMsg & 0xffffffffn), wParam, lParam })
              ? 1n
              : 0n
          ),
        },
        postquitmessage: {
          argc: 1,
          fn: ([nExitCode]) => {
            b._enqueueMessage(
              { hwnd: 0n, message: WIN32_CONSTANTS.WM_QUIT, wParam: nExitCode, lParam: 0n },
              { force: true }
            );
            return 0n;
          },
        },
        beginpaint: {
          argc: 2,
          fn: ([hWnd, lpPaint]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            const hdc = b._allocHandle({
              kind: 'dc',
              win,
              direct: false,
              drawOps: [],
              drawOpBytes: 0,
              brushColor: '#ffffff',
              penColor: '#000000',
              penWidth: 1,
              textColor: '#000000',
              bkColor: '#ffffff',
              font: '14px sans-serif',
              curX: 0,
              curY: 0,
            });
            if (hdc === null) return 0n;
            if (lpPaint !== 0n) {
              const psSize = b.is64 ? 72 : 64;
              const buf = new Uint8Array(psSize);
              const dv = new DataView(buf.buffer);
              if (b.is64) {
                dv.setBigUint64(0, hdc, true);
                dv.setUint32(8, 1, true); // fErase
                dv.setInt32(12, 0, true);
                dv.setInt32(16, 0, true);
                dv.setInt32(20, win.width, true);
                dv.setInt32(24, win.height, true);
              } else {
                dv.setUint32(0, Number(hdc & 0xffffffffn), true);
                dv.setUint32(4, 1, true);
                dv.setInt32(8, 0, true);
                dv.setInt32(12, 0, true);
                dv.setInt32(16, win.width, true);
                dv.setInt32(20, win.height, true);
              }
              b.addressSpace.write(lpPaint, buf);
            }
            return hdc;
          },
        },
        endpaint: {
          argc: 2,
          fn: ([hWnd, lpPaint]) => {
            const win = b._windows.get(hWnd);
            if (lpPaint !== 0n) {
              const hdc = b._readPtr(lpPaint);
              const dc = getDc(hdc);
              if (dc) {
                if (win) {
                  const oldWinBytes = win.drawOpBytes ?? 0;
                  if (oldWinBytes > 0) {
                    b._totalDrawOpBytes = Math.max(0, b._totalDrawOpBytes - oldWinBytes);
                  }
                  win.drawOps = dc.drawOps.slice();
                  win.drawOpBytes = dc.drawOpBytes ?? 0;
                  // Ownership transferred to win; zero dc before _deleteHandle to avoid double subtraction
                  dc.drawOps.length = 0;
                  dc.drawOpBytes = 0;
                  win.needsPaint = false;
                  b._markWindowSurfaceDirty(win, { drawOpsDirty: true });
                }
                b._deleteHandle(hdc);
              }
            }
            return 1n;
          },
        },
        getdc: {
          argc: 1,
          fn: ([hWnd]) => {
            const win = b._windows.get(hWnd) ?? null;
            const hdc = b._allocHandle({
              kind: 'dc',
              win,
              direct: true,
              drawOps: [],
              drawOpBytes: 0,
              brushColor: '#ffffff',
              penColor: '#000000',
              penWidth: 1,
              textColor: '#000000',
              bkColor: '#ffffff',
              font: '14px sans-serif',
              curX: 0,
              curY: 0,
            });
            return hdc ?? 0n;
          },
        },
        getwindowdc: {
          argc: 1,
          fn: ([hWnd]) => {
            const win = b._windows.get(hWnd) ?? null;
            const hdc = b._allocHandle({
              kind: 'dc',
              win,
              direct: true,
              drawOps: [],
              drawOpBytes: 0,
              brushColor: '#ffffff',
              penColor: '#000000',
              penWidth: 1,
              textColor: '#000000',
              bkColor: '#ffffff',
              font: '14px sans-serif',
              curX: 0,
              curY: 0,
            });
            return hdc ?? 0n;
          },
        },
        releasedc: {
          argc: 2,
          fn: ([_hWnd, hDC]) => {
            if (getDc(hDC)) {
              b._deleteHandle(hDC);
            }
            return 1n;
          },
        },
        invalidaterect: {
          argc: 3,
          fn: ([hWnd]) => {
            const win = b._windows.get(hWnd);
            if (!win) return 0n;
            win.needsPaint = true;
            const hasPendingPaint = b._messageQueue.some(
              (m) => m.hwnd === hWnd && m.message === WIN32_CONSTANTS.WM_PAINT
            );
            if (!hasPendingPaint) {
              b._enqueueMessage({ hwnd: hWnd, message: WIN32_CONSTANTS.WM_PAINT, wParam: 0n, lParam: 0n });
            }
            return 1n;
          },
        },
        fillrect: {
          argc: 3,
          fn: ([hDC, lpRect, hbr]) => {
            const dc = getDc(hDC);
            if (!dc || lpRect === 0n) return 0n;
            const raw = b.addressSpace.read(lpRect, 16);
            const dv = new DataView(raw.buffer, raw.byteOffset, 16);
            const left = dv.getInt32(0, true);
            const top = dv.getInt32(4, true);
            const right = dv.getInt32(8, true);
            const bottom = dv.getInt32(12, true);
            const gdi = b._handles.get(hbr);
            const fill = gdi?.color ?? dc.brushColor;
            b._appendDrawOp(dc, {
              op: 'rect',
              x: left,
              y: top,
              width: Math.max(0, right - left),
              height: Math.max(0, bottom - top),
              fill,
            });
            flushDirectDc(dc);
            return 1n;
          },
        },
        drawtexta: {
          argc: 5,
          fn: ([hDC, lpText, cch, lpRect]) => {
            const dc = getDc(hDC);
            if (!dc || lpText === 0n) return 0n;
            const len = Number(BigInt.asIntN(32, cch));
            let text = '';
            if (len > 0) {
              const clamped = Math.min(len, MAX_GDI_TEXT_CHARS);
              const safeLen = b._normalizeMemOpLen(clamped, b.is64 ? lpText : (lpText & 0xffffffffn), 'DrawTextA');
              text = UTF8_DECODER.decode(b.addressSpace.read(lpText, safeLen));
            } else if (len < 0) {
              text = b._readCString(lpText, MAX_GDI_TEXT_CHARS) ?? '';
            }
            let x = 0;
            let y = 0;
            if (lpRect !== 0n) {
              const r = b.addressSpace.read(lpRect, 16);
              const dv = new DataView(r.buffer, r.byteOffset, 16);
              x = dv.getInt32(0, true);
              y = dv.getInt32(4, true);
            }
            b._appendDrawOp(dc, { op: 'text', x, y, text, color: dc.textColor, font: dc.font });
            flushDirectDc(dc);
            return 16n;
          },
        },
        drawtextw: {
          argc: 5,
          fn: ([hDC, lpText, cch, lpRect]) => {
            const dc = getDc(hDC);
            if (!dc || lpText === 0n) return 0n;
            const len = Number(BigInt.asIntN(32, cch));
            let text = '';
            if (len > 0) {
              const clamped = Math.min(len, MAX_GDI_TEXT_CHARS);
              const safeBytes = b._normalizeMemOpLen(clamped * 2, b.is64 ? lpText : (lpText & 0xffffffffn), 'DrawTextW');
              text = UTF16LE_DECODER.decode(b.addressSpace.read(lpText, safeBytes));
            } else if (len < 0) {
              text = b._readWString(lpText, MAX_GDI_TEXT_CHARS) ?? '';
            }
            let x = 0;
            let y = 0;
            if (lpRect !== 0n) {
              const r = b.addressSpace.read(lpRect, 16);
              const dv = new DataView(r.buffer, r.byteOffset, 16);
              x = dv.getInt32(0, true);
              y = dv.getInt32(4, true);
            }
            b._appendDrawOp(dc, { op: 'text', x, y, text, color: dc.textColor, font: dc.font });
            flushDirectDc(dc);
            return 16n;
          },
        },

        // Clipboard (-> M2 SharedClipboard)
        openclipboard: {
          argc: 1,
          fn: ([hWnd]) => {
            b._clipboardOpen = true;
            b._clipboardOwner = hWnd;
            return 1n;
          },
        },
        emptyclipboard: { argc: 0, fn: () => 1n },
        setclipboarddata: {
          argc: 2,
          fn: ([uFormat, hMem]) => {
            if (!b._checkCapSync('clipboard.write')) {
              b.lastError = WIN32_ERROR.ERROR_ACCESS_DENIED;
              return 0n;
            }
            const fmt = Number(uFormat & 0xffffffffn);
            const text = fmt === WIN32_CONSTANTS.CF_UNICODETEXT
              ? (b._readWString(hMem) ?? '')
              : (b._readCString(hMem) ?? '');
            if (b.services.clipboard) {
              b.services.clipboard.set({
                text,
                sourceAppId: b.pcb?.appId || b.appRecord?.appId || 'windows-app',
                sourcePlatform: 'windows',
              });
            }
            b.lastError = WIN32_ERROR.ERROR_SUCCESS;
            return hMem;
          },
        },
        getclipboarddata: {
          argc: 1,
          fn: ([uFormat]) => {
            if (!b._checkCapSync('clipboard.read')) {
              b.lastError = WIN32_ERROR.ERROR_ACCESS_DENIED;
              return 0n;
            }
            const text = b.services.clipboard?.get?.('text/plain');
            if (typeof text !== 'string') return 0n;
            const fmt = Number(uFormat & 0xffffffffn);
            if (fmt === WIN32_CONSTANTS.CF_UNICODETEXT) {
              const enc = encodeUtf16LE(text, true);
              const ptr = BigInt(b.addressSpace.alloc(enc.byteLength));
              b.addressSpace.write(ptr, enc);
              return ptr;
            }
            const enc = UTF8_ENCODER.encode(text);
            const ptr = BigInt(b.addressSpace.alloc(enc.byteLength + 1));
            b._writeCString(ptr, text);
            return ptr;
          },
        },
        closeclipboard: {
          argc: 0,
          fn: () => {
            b._clipboardOpen = false;
            return 1n;
          },
        },
      },

      // ======================================================================
      // gdi32.dll
      // ======================================================================
      'gdi32.dll': {
        createsolidbrush: {
          argc: 1,
          fn: ([cr]) => b._allocHandle({ kind: 'gdi', objType: 'brush', color: colorRefToHex(cr) }) ?? 0n,
        },
        createpen: {
          argc: 3,
          fn: ([_style, cWidth, cr]) => b._allocHandle({
            kind: 'gdi',
            objType: 'pen',
            width: Math.max(1, Number(cWidth & 0xffffffffn)),
            color: colorRefToHex(cr),
          }) ?? 0n,
        },
        createfonta: {
          argc: 14,
          fn: (args) => {
            const height = Math.abs(Number(BigInt.asIntN(32, args[0]))) || 14;
            const rawFace = args[13] !== 0n ? (b._readCString(args[13], 128) || 'sans-serif') : 'sans-serif';
            const face = rawFace.slice(0, 128);
            return b._allocHandle({ kind: 'gdi', objType: 'font', font: `${height}px ${face}` }) ?? 0n;
          },
        },
        createfontw: {
          argc: 14,
          fn: (args) => {
            const height = Math.abs(Number(BigInt.asIntN(32, args[0]))) || 14;
            const rawFace = args[13] !== 0n ? (b._readWString(args[13], 128) || 'sans-serif') : 'sans-serif';
            const face = rawFace.slice(0, 128);
            return b._allocHandle({ kind: 'gdi', objType: 'font', font: `${height}px ${face}` }) ?? 0n;
          },
        },
        getstockobject: {
          argc: 1,
          fn: ([idx]) => {
            const i = Number(idx & 0xffffffffn);
            const stockKey = Object.prototype.hasOwnProperty.call(STOCK_OBJECTS, i) ? i : 0;
            const existing = b._stockHandles.get(stockKey);
            if (existing !== undefined && b._handles.has(existing)) {
              return existing;
            }
            const stock = STOCK_OBJECTS[stockKey];
            const h = b._allocHandle({ kind: 'gdi', objType: stock.kind, ...stock, stock: true });
            if (h !== null) {
              b._stockHandles.set(stockKey, h);
              return h;
            }
            return 0n;
          },
        },
        selectobject: {
          argc: 2,
          fn: ([hDC, hObj]) => {
            const dc = getDc(hDC);
            const obj = b._handles.get(hObj);
            if (!dc || !obj || obj.kind !== 'gdi') return 0n;
            if (obj.objType === 'brush') dc.brushColor = obj.color;
            else if (obj.objType === 'pen') { dc.penColor = obj.color; dc.penWidth = obj.width ?? 1; }
            else if (obj.objType === 'font') dc.font = obj.font;
            return hObj;
          },
        },
        createcompatibledc: {
          argc: 1,
          fn: () => {
            const hdc = b._allocHandle({
              kind: 'dc',
              win: null,
              direct: false,
              drawOps: [],
              drawOpBytes: 0,
              brushColor: '#ffffff',
              penColor: '#000000',
              penWidth: 1,
              textColor: '#000000',
              bkColor: '#ffffff',
              font: '14px sans-serif',
              curX: 0,
              curY: 0,
            });
            return hdc ?? 0n;
          },
        },
        deletedc: {
          argc: 1,
          fn: ([hDC]) => (getDc(hDC) && b._deleteHandle(hDC) ? 1n : 0n),
        },
        deleteobject: {
          argc: 1,
          fn: ([hObj]) => {
            const obj = b._handles.get(hObj);
            if (obj && obj.kind === 'gdi' && !obj.stock) b._deleteHandle(hObj);
            return 1n;
          },
        },
        settextcolor: {
          argc: 2,
          fn: ([hDC, cr]) => {
            const dc = getDc(hDC);
            if (!dc) return 0xffffffffn;
            dc.textColor = colorRefToHex(cr);
            return cr;
          },
        },
        setbkcolor: {
          argc: 2,
          fn: ([hDC, cr]) => {
            const dc = getDc(hDC);
            if (!dc) return 0xffffffffn;
            dc.bkColor = colorRefToHex(cr);
            return cr;
          },
        },
        setbkmode: { argc: 2, fn: () => 1n },
        textouta: {
          argc: 5,
          fn: ([hDC, xArg, yArg, lpStr, cch]) => {
            const dc = getDc(hDC);
            if (!dc || lpStr === 0n) return 0n;
            const len = Number(BigInt.asIntN(32, cch));
            let text = '';
            if (len > 0) {
              const clamped = Math.min(len, MAX_GDI_TEXT_CHARS);
              const safeLen = b._normalizeMemOpLen(clamped, b.is64 ? lpStr : (lpStr & 0xffffffffn), 'TextOutA');
              text = UTF8_DECODER.decode(b.addressSpace.read(lpStr, safeLen));
            } else if (len < 0) {
              text = b._readCString(lpStr, MAX_GDI_TEXT_CHARS) ?? '';
            }
            b._appendDrawOp(dc, {
              op: 'text',
              x: Number(BigInt.asIntN(32, xArg)),
              y: Number(BigInt.asIntN(32, yArg)),
              text,
              color: dc.textColor,
              font: dc.font,
            });
            flushDirectDc(dc);
            return 1n;
          },
        },
        textoutw: {
          argc: 5,
          fn: ([hDC, xArg, yArg, lpStr, cch]) => {
            const dc = getDc(hDC);
            if (!dc || lpStr === 0n) return 0n;
            const len = Number(BigInt.asIntN(32, cch));
            let text = '';
            if (len > 0) {
              const clamped = Math.min(len, MAX_GDI_TEXT_CHARS);
              const safeBytes = b._normalizeMemOpLen(clamped * 2, b.is64 ? lpStr : (lpStr & 0xffffffffn), 'TextOutW');
              text = UTF16LE_DECODER.decode(b.addressSpace.read(lpStr, safeBytes));
            } else if (len < 0) {
              text = b._readWString(lpStr, MAX_GDI_TEXT_CHARS) ?? '';
            }
            b._appendDrawOp(dc, {
              op: 'text',
              x: Number(BigInt.asIntN(32, xArg)),
              y: Number(BigInt.asIntN(32, yArg)),
              text,
              color: dc.textColor,
              font: dc.font,
            });
            flushDirectDc(dc);
            return 1n;
          },
        },
        rectangle: {
          argc: 5,
          fn: ([hDC, l, t, r, bot]) => {
            const dc = getDc(hDC);
            if (!dc) return 0n;
            const left = Number(BigInt.asIntN(32, l));
            const top = Number(BigInt.asIntN(32, t));
            const right = Number(BigInt.asIntN(32, r));
            const bottom = Number(BigInt.asIntN(32, bot));
            b._appendDrawOp(dc, {
              op: 'rect',
              x: left,
              y: top,
              width: Math.max(0, right - left),
              height: Math.max(0, bottom - top),
              fill: dc.brushColor,
              stroke: dc.penColor,
              lineWidth: dc.penWidth,
            });
            flushDirectDc(dc);
            return 1n;
          },
        },
        ellipse: {
          argc: 5,
          fn: ([hDC, l, t, r, bot]) => {
            const dc = getDc(hDC);
            if (!dc) return 0n;
            const left = Number(BigInt.asIntN(32, l));
            const top = Number(BigInt.asIntN(32, t));
            const right = Number(BigInt.asIntN(32, r));
            const bottom = Number(BigInt.asIntN(32, bot));
            b._appendDrawOp(dc, {
              op: 'ellipse',
              cx: (left + right) / 2,
              cy: (top + bottom) / 2,
              rx: Math.abs(right - left) / 2,
              ry: Math.abs(bottom - top) / 2,
              fill: dc.brushColor,
              stroke: dc.penColor,
              lineWidth: dc.penWidth,
            });
            flushDirectDc(dc);
            return 1n;
          },
        },
        movetoex: {
          argc: 4,
          fn: ([hDC, xArg, yArg, lpPt]) => {
            const dc = getDc(hDC);
            if (!dc) return 0n;
            if (lpPt !== 0n) {
              const buf = new Uint8Array(8);
              const dv = new DataView(buf.buffer);
              dv.setInt32(0, dc.curX, true);
              dv.setInt32(4, dc.curY, true);
              b.addressSpace.write(lpPt, buf);
            }
            dc.curX = Number(BigInt.asIntN(32, xArg));
            dc.curY = Number(BigInt.asIntN(32, yArg));
            return 1n;
          },
        },
        lineto: {
          argc: 3,
          fn: ([hDC, xArg, yArg]) => {
            const dc = getDc(hDC);
            if (!dc) return 0n;
            const x2 = Number(BigInt.asIntN(32, xArg));
            const y2 = Number(BigInt.asIntN(32, yArg));
            b._appendDrawOp(dc, {
              op: 'line',
              x1: dc.curX,
              y1: dc.curY,
              x2,
              y2,
              stroke: dc.penColor,
              lineWidth: dc.penWidth,
            });
            dc.curX = x2;
            dc.curY = y2;
            flushDirectDc(dc);
            return 1n;
          },
        },
        setpixel: {
          argc: 4,
          fn: ([hDC, xArg, yArg, cr]) => {
            const dc = getDc(hDC);
            if (!dc) return 0xffffffffn;
            b._appendDrawOp(dc, {
              op: 'rect',
              x: Number(BigInt.asIntN(32, xArg)),
              y: Number(BigInt.asIntN(32, yArg)),
              width: 1,
              height: 1,
              fill: colorRefToHex(cr),
            });
            flushDirectDc(dc);
            return cr;
          },
        },
      },

      // ======================================================================
      // advapi32.dll (Windows Registry -> M2 UnifiedConfigStore.registry)
      // ======================================================================
      'advapi32.dll': {
        regopenkeyexa: { argc: 5, fn: (args) => regOpenKeyExImpl(args, false) },
        regopenkeyexw: { argc: 5, fn: (args) => regOpenKeyExImpl(args, true) },
        regcreatekeyexa: { argc: 9, fn: (args) => regCreateKeyExImpl(args, false) },
        regcreatekeyexw: { argc: 9, fn: (args) => regCreateKeyExImpl(args, true) },
        regsetvalueexa: { argc: 6, fn: (args) => regSetValueExImpl(args, false) },
        regsetvalueexw: { argc: 6, fn: (args) => regSetValueExImpl(args, true) },
        regqueryvalueexa: { argc: 6, fn: (args) => regQueryValueExImpl(args, false) },
        regqueryvalueexw: { argc: 6, fn: (args) => regQueryValueExImpl(args, true) },
        regdeletevaluea: {
          argc: 2,
          fn: ([hKey, lpValName]) => {
            const target = b._resolveRegHandle(hKey);
            if (!target || !b.services.configStore) return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
            if (target.deleted) return BigInt(WIN32_ERROR.ERROR_KEY_DELETED ?? 1018);
            try {
              const ok = b.services.configStore.registry.deleteValue(
                target.hive, target.keyPath, b._readCString(lpValName) ?? '', b._regCtx()
              );
              if (ok) b._clearRegDataCaches();
              return BigInt(ok ? WIN32_ERROR.ERROR_SUCCESS : WIN32_ERROR.ERROR_FILE_NOT_FOUND);
            } catch (err) {
              return BigInt(posixCodeToWin32(err?.code));
            }
          },
        },
        regdeletevaluew: {
          argc: 2,
          fn: ([hKey, lpValName]) => {
            const target = b._resolveRegHandle(hKey);
            if (!target || !b.services.configStore) return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
            if (target.deleted) return BigInt(WIN32_ERROR.ERROR_KEY_DELETED ?? 1018);
            try {
              const ok = b.services.configStore.registry.deleteValue(
                target.hive, target.keyPath, b._readWString(lpValName) ?? '', b._regCtx()
              );
              if (ok) b._clearRegDataCaches();
              return BigInt(ok ? WIN32_ERROR.ERROR_SUCCESS : WIN32_ERROR.ERROR_FILE_NOT_FOUND);
            } catch (err) {
              return BigInt(posixCodeToWin32(err?.code));
            }
          },
        },
        regdeletekeya: { argc: 2, fn: (args) => regDeleteKeyImpl(args, false) },
        regdeletekeyw: { argc: 2, fn: (args) => regDeleteKeyImpl(args, true) },
        regenumkeyexa: {
          argc: 8,
          fn: ([hKey, dwIndex, lpName, lpcchName]) => {
            const target = b._resolveRegHandle(hKey);
            if (!target || !b.services.configStore) return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
            try {
              const idx = Number(dwIndex & 0xffffffffn) >>> 0;
              const enumWrap = b._regEnumKeyCached(target.hive, target.keyPath, b._regCtx());
              if (enumWrap.quotaExceeded) return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
              const subkeys = enumWrap.subkeys ?? [];
              if (idx >= subkeys.length) return BigInt(WIN32_ERROR.ERROR_NO_MORE_ITEMS);
              const name = subkeys[idx];
              const cap = lpcchName !== 0n ? b._readU32(lpcchName) : 256;
              const written = b._writeCString(lpName, name, cap);
              if (lpcchName !== 0n) b._writeU32(lpcchName, written);
              return BigInt(WIN32_ERROR.ERROR_SUCCESS);
            } catch (err) {
              return BigInt(posixCodeToWin32(err?.code));
            }
          },
        },
        regenumkeyexw: {
          argc: 8,
          fn: ([hKey, dwIndex, lpName, lpcchName]) => {
            const target = b._resolveRegHandle(hKey);
            if (!target || !b.services.configStore) return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
            try {
              const idx = Number(dwIndex & 0xffffffffn) >>> 0;
              const enumWrap = b._regEnumKeyCached(target.hive, target.keyPath, b._regCtx());
              if (enumWrap.quotaExceeded) return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
              const subkeys = enumWrap.subkeys ?? [];
              if (idx >= subkeys.length) return BigInt(WIN32_ERROR.ERROR_NO_MORE_ITEMS);
              const name = subkeys[idx];
              const cap = lpcchName !== 0n ? b._readU32(lpcchName) : 256;
              const written = b._writeWString(lpName, name, cap);
              if (lpcchName !== 0n) b._writeU32(lpcchName, written);
              return BigInt(WIN32_ERROR.ERROR_SUCCESS);
            } catch (err) {
              return BigInt(posixCodeToWin32(err?.code));
            }
          },
        },
        regenumvaluea: {
          argc: 8,
          fn: ([hKey, dwIndex, lpValName, lpcchName, _lpRes, lpType, lpData, lpcbData]) => {
            const target = b._resolveRegHandle(hKey);
            if (!target || !b.services.configStore) return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
            if (lpData !== 0n && lpcbData === 0n) return BigInt(WIN32_ERROR.ERROR_INVALID_PARAMETER);
            try {
              const idx = Number(dwIndex & 0xffffffffn) >>> 0;
              const enumWrap = b._regEnumKeyCached(target.hive, target.keyPath, b._regCtx());
              if (enumWrap.quotaExceeded) return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
              const keys = enumWrap.valueNames ?? [];
              if (idx >= keys.length) return BigInt(WIN32_ERROR.ERROR_NO_MORE_ITEMS);
              const valName = keys[idx];
              const valEntry = enumWrap.valueEntries[valName];
              const { typeNum, byteLength } = getRegValueByteLength(valEntry, false);
              if (lpData !== 0n) {
                const dataCap = b._readU32(lpcbData);
                if (dataCap < byteLength) {
                  const probeCharge = Math.max(64, Math.min(dataCap, byteLength));
                  if (!b._chargeRegReadQuota(probeCharge)) {
                    return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
                  }
                  const cap = lpcchName !== 0n ? b._readU32(lpcchName) : 256;
                  const written = b._writeCString(lpValName, valName, cap);
                  if (lpcchName !== 0n) b._writeU32(lpcchName, written);
                  if (lpType !== 0n) b._writeU32(lpType, typeNum);
                  b._writeU32(lpcbData, byteLength);
                  return BigInt(WIN32_ERROR.ERROR_MORE_DATA);
                }
                if (!b._chargeRegReadQuota(byteLength)) {
                  return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
                }
                const cap = lpcchName !== 0n ? b._readU32(lpcchName) : 256;
                const written = b._writeCString(lpValName, valName, cap);
                if (lpcchName !== 0n) b._writeU32(lpcchName, written);
                if (lpType !== 0n) b._writeU32(lpType, typeNum);
                const { outBytes } = getCachedSerializedRegValue(valEntry, false);
                b.addressSpace.write(lpData, outBytes);
                b._writeU32(lpcbData, outBytes.byteLength);
                return BigInt(WIN32_ERROR.ERROR_SUCCESS);
              }
              const cap = lpcchName !== 0n ? b._readU32(lpcchName) : 256;
              const written = b._writeCString(lpValName, valName, cap);
              if (lpcchName !== 0n) b._writeU32(lpcchName, written);
              if (lpType !== 0n) b._writeU32(lpType, typeNum);
              if (lpcbData !== 0n) b._writeU32(lpcbData, byteLength);
              return BigInt(WIN32_ERROR.ERROR_SUCCESS);
            } catch (err) {
              return BigInt(posixCodeToWin32(err?.code));
            }
          },
        },
        regenumvaluew: {
          argc: 8,
          fn: ([hKey, dwIndex, lpValName, lpcchName, _lpRes, lpType, lpData, lpcbData]) => {
            const target = b._resolveRegHandle(hKey);
            if (!target || !b.services.configStore) return BigInt(WIN32_ERROR.ERROR_INVALID_HANDLE);
            if (lpData !== 0n && lpcbData === 0n) return BigInt(WIN32_ERROR.ERROR_INVALID_PARAMETER);
            try {
              const idx = Number(dwIndex & 0xffffffffn) >>> 0;
              const enumWrap = b._regEnumKeyCached(target.hive, target.keyPath, b._regCtx());
              if (enumWrap.quotaExceeded) return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
              const keys = enumWrap.valueNames ?? [];
              if (idx >= keys.length) return BigInt(WIN32_ERROR.ERROR_NO_MORE_ITEMS);
              const valName = keys[idx];
              const valEntry = enumWrap.valueEntries[valName];
              const { typeNum, byteLength } = getRegValueByteLength(valEntry, true);
              if (lpData !== 0n) {
                const dataCap = b._readU32(lpcbData);
                if (dataCap < byteLength) {
                  const probeCharge = Math.max(64, Math.min(dataCap, byteLength));
                  if (!b._chargeRegReadQuota(probeCharge)) {
                    return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
                  }
                  const cap = lpcchName !== 0n ? b._readU32(lpcchName) : 256;
                  const written = b._writeWString(lpValName, valName, cap);
                  if (lpcchName !== 0n) b._writeU32(lpcchName, written);
                  if (lpType !== 0n) b._writeU32(lpType, typeNum);
                  b._writeU32(lpcbData, byteLength);
                  return BigInt(WIN32_ERROR.ERROR_MORE_DATA);
                }
                if (!b._chargeRegReadQuota(byteLength)) {
                  return BigInt(WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY);
                }
                const cap = lpcchName !== 0n ? b._readU32(lpcchName) : 256;
                const written = b._writeWString(lpValName, valName, cap);
                if (lpcchName !== 0n) b._writeU32(lpcchName, written);
                if (lpType !== 0n) b._writeU32(lpType, typeNum);
                const { outBytes } = getCachedSerializedRegValue(valEntry, true);
                b.addressSpace.write(lpData, outBytes);
                b._writeU32(lpcbData, outBytes.byteLength);
                return BigInt(WIN32_ERROR.ERROR_SUCCESS);
              }
              const cap = lpcchName !== 0n ? b._readU32(lpcchName) : 256;
              const written = b._writeWString(lpValName, valName, cap);
              if (lpcchName !== 0n) b._writeU32(lpcchName, written);
              if (lpType !== 0n) b._writeU32(lpType, typeNum);
              if (lpcbData !== 0n) b._writeU32(lpcbData, byteLength);
              return BigInt(WIN32_ERROR.ERROR_SUCCESS);
            } catch (err) {
              return BigInt(posixCodeToWin32(err?.code));
            }
          },
        },
        regclosekey: {
          argc: 1,
          fn: ([hKey]) => {
            const rec = b._handles.get(hKey);
            if (rec && rec.kind === 'reg') b._deleteHandle(hKey);
            return BigInt(WIN32_ERROR.ERROR_SUCCESS);
          },
        },
      },

      // ======================================================================
      // shell32.dll (-> M2 IntentRouter, strictly synchronous fire-and-forget!)
      // ======================================================================
      'shell32.dll': {
        shellexecutea: {
          argc: 6,
          fn: ([_hwnd, lpOp, lpFile, lpParams, lpDir]) => {
            const op = lpOp !== 0n ? (b._readCString(lpOp, 64) || 'view') : 'view';
            const file = lpFile !== 0n ? (b._readCString(lpFile, 1024) || '') : '';
            const params = lpParams !== 0n ? (b._readCString(lpParams, 4096) || '') : '';
            const dir = lpDir !== 0n ? (b._readCString(lpDir, 1024) || '') : '';
            if (b.services.intentRouter && typeof b.services.intentRouter.dispatch === 'function') {
              try {
                const res = b.services.intentRouter.dispatch({
                  action: op === 'open' ? 'view' : op,
                  uri: file,
                  extras: { parameters: params, directory: dir },
                  sourcePid: b.pcb?.pid ?? null,
                });
                if (res && typeof res.catch === 'function') {
                  res.catch((err) => { void err; });
                }
              } catch (err) {
                void err;
              }
            }
            return 33n; // > 32 means success in Win32 ShellExecute
          },
        },
        shellexecutew: {
          argc: 6,
          fn: ([_hwnd, lpOp, lpFile, lpParams, lpDir]) => {
            const op = lpOp !== 0n ? (b._readWString(lpOp, 64) || 'view') : 'view';
            const file = lpFile !== 0n ? (b._readWString(lpFile, 1024) || '') : '';
            const params = lpParams !== 0n ? (b._readWString(lpParams, 4096) || '') : '';
            const dir = lpDir !== 0n ? (b._readWString(lpDir, 1024) || '') : '';
            if (b.services.intentRouter && typeof b.services.intentRouter.dispatch === 'function') {
              try {
                const res = b.services.intentRouter.dispatch({
                  action: op === 'open' ? 'view' : op,
                  uri: file,
                  extras: { parameters: params, directory: dir },
                  sourcePid: b.pcb?.pid ?? null,
                });
                if (res && typeof res.catch === 'function') {
                  res.catch((err) => { void err; });
                }
              } catch (err) {
                void err;
              }
            }
            return 33n;
          },
        },
      },

      // ======================================================================
      // msvcrt.dll / ucrtbase.dll (__cdecl essentials)
      // ======================================================================
      'msvcrt.dll': {
        puts: {
          argc: 1,
          cdecl: true,
          fn: ([lpStr]) => {
            const s = `${b._readCString(lpStr) ?? ''}\n`;
            b.services.processManager?.writeStdout?.(b.pcb.pid, s);
            return BigInt(s.length);
          },
        },
        printf: {
          argc: 1,
          cdecl: true,
          fn: ([lpFmt], cpu) => {
            const fmt = b._readCString(lpFmt) ?? '';
            let varArgIdx = 1;
            const formatted = formatPrintf(fmt, () => b._readSingleArg(cpu, varArgIdx++), MAX_PRINTF_OUTPUT_BYTES);
            b.services.processManager?.writeStdout?.(b.pcb.pid, formatted);
            return BigInt(formatted.length);
          },
        },
        sprintf: {
          argc: 2,
          cdecl: true,
          fn: ([dst, lpFmt], cpu) => {
            const fmt = b._readCString(lpFmt) ?? '';
            let varArgIdx = 2;
            const formatted = formatPrintf(fmt, () => b._readSingleArg(cpu, varArgIdx++), MAX_PRINTF_OUTPUT_BYTES);
            return BigInt(b._writeCString(dst, formatted));
          },
        },
        snprintf: {
          argc: 3,
          cdecl: true,
          fn: ([dst, maxArg, lpFmt], cpu) => {
            const max = Number(maxArg & 0xffffffffn) >>> 0;
            const fmt = b._readCString(lpFmt) ?? '';
            let varArgIdx = 3;
            const formatted = formatPrintf(
              fmt,
              () => b._readSingleArg(cpu, varArgIdx++),
              Math.min(MAX_PRINTF_OUTPUT_BYTES, max)
            );
            b._writeCString(dst, formatted, max);
            return BigInt(formatted.length);
          },
        },
        _snprintf: {
          argc: 3,
          cdecl: true,
          fn: ([dst, maxArg, lpFmt], cpu) => {
            const max = Number(maxArg & 0xffffffffn) >>> 0;
            const fmt = b._readCString(lpFmt) ?? '';
            let varArgIdx = 3;
            const formatted = formatPrintf(
              fmt,
              () => b._readSingleArg(cpu, varArgIdx++),
              Math.min(MAX_PRINTF_OUTPUT_BYTES, max)
            );
            b._writeCString(dst, formatted, max);
            return BigInt(formatted.length);
          },
        },
        malloc: {
          argc: 1,
          cdecl: true,
          fn: ([sz]) => {
            try { return BigInt(b.addressSpace.alloc(Math.max(1, Number(sz & 0xffffffffn) >>> 0))); }
            catch (err) { void err; return 0n; }
          },
        },
        calloc: {
          argc: 2,
          cdecl: true,
          fn: ([nmemb, sz]) => {
            const total = Math.max(1, (Number(nmemb & 0xffffffffn) >>> 0) * (Number(sz & 0xffffffffn) >>> 0));
            if (!Number.isSafeInteger(total)) return 0n;
            try {
              const ptr = BigInt(b.addressSpace.alloc(total));
              b._memFill(ptr, 0, BigInt(total), 'calloc');
              return ptr;
            } catch (err) {
              void err;
              return 0n;
            }
          },
        },
        realloc: {
          argc: 2,
          cdecl: true,
          fn: ([ptr, sz]) => {
            const size = Math.max(1, Number(sz & 0xffffffffn) >>> 0);
            try {
              if (ptr === 0n) return BigInt(b.addressSpace.alloc(size));
              return BigInt(b.addressSpace.realloc(ptr, size));
            } catch (err) {
              void err;
              return 0n;
            }
          },
        },
        free: {
          argc: 1,
          cdecl: true,
          fn: ([ptr]) => {
            if (ptr !== 0n) {
              try { b.addressSpace.free(ptr); } catch (err) { void err; }
            }
            return 0n;
          },
        },
        strlen: { argc: 1, cdecl: true, fn: ([s]) => BigInt((b._readCString(s) ?? '').length) },
        strcpy: { argc: 2, cdecl: true, fn: ([dst, src]) => { b._writeCString(dst, b._readCString(src) ?? ''); return dst; } },
        strncpy: {
          argc: 3,
          cdecl: true,
          fn: ([dst, src, nArg]) => {
            const dstAddr = b.is64 ? dst : (dst & 0xffffffffn);
            const n = b._normalizeMemOpLen(nArg, dstAddr, 'strncpy');
            if (n === 0) return dst;
            const s = UTF8_ENCODER.encode(b._readCString(src, n) ?? '');
            const copyLen = Math.min(s.byteLength, n);
            if (copyLen > 0) {
              b.addressSpace.write(dstAddr, s.subarray(0, copyLen));
            }
            if (n > copyLen) {
              b._memFill(dstAddr + BigInt(copyLen), 0, BigInt(n - copyLen), 'strncpy');
            }
            return dst;
          },
        },
        strcat: {
          argc: 2,
          cdecl: true,
          fn: ([dst, src]) => {
            b._writeCString(dst, (b._readCString(dst) ?? '') + (b._readCString(src) ?? ''));
            return dst;
          },
        },
        strcmp: {
          argc: 2,
          cdecl: true,
          fn: ([p1, p2]) => {
            const s1 = b._readCString(p1) ?? '';
            const s2 = b._readCString(p2) ?? '';
            return s1 < s2 ? -1n : (s1 > s2 ? 1n : 0n);
          },
        },
        strncmp: {
          argc: 3,
          cdecl: true,
          fn: ([p1, p2, nArg]) => {
            const n = Number(nArg & 0xffffffffn) >>> 0;
            const s1 = (b._readCString(p1, Math.min(n, 65536)) ?? '').slice(0, n);
            const s2 = (b._readCString(p2, Math.min(n, 65536)) ?? '').slice(0, n);
            return s1 < s2 ? -1n : (s1 > s2 ? 1n : 0n);
          },
        },
        memcpy: {
          argc: 3,
          cdecl: true,
          fn: ([dst, src, nArg]) => {
            b._memCopy(dst, src, nArg, false, 'memcpy');
            return dst;
          },
        },
        memmove: {
          argc: 3,
          cdecl: true,
          fn: ([dst, src, nArg]) => {
            b._memCopy(dst, src, nArg, true, 'memmove');
            return dst;
          },
        },
        memset: {
          argc: 3,
          cdecl: true,
          fn: ([dst, ch, nArg]) => {
            b._memFill(dst, Number(ch & 0xffn), nArg, 'memset');
            return dst;
          },
        },
        memcmp: {
          argc: 3,
          cdecl: true,
          fn: ([p1, p2, nArg]) => b._memCmp(p1, p2, nArg),
        },
        atoi: {
          argc: 1,
          cdecl: true,
          fn: ([lpStr]) => {
            const n = parseInt(b._readCString(lpStr) ?? '0', 10);
            return BigInt(Number.isFinite(n) ? (n | 0) : 0);
          },
        },
        exit: {
          argc: 1,
          cdecl: true,
          fn: ([code]) => {
            b.flushCompositorSurfacesIfDirty();
            return { status: 'EXITED', exitCode: Number(BigInt.asIntN(32, code)) };
          },
        },
        _exit: {
          argc: 1,
          cdecl: true,
          fn: ([code]) => {
            b.flushCompositorSurfacesIfDirty();
            return { status: 'EXITED', exitCode: Number(BigInt.asIntN(32, code)) };
          },
        },
      },
    };
  }
}

export function createWin32Bridge(opts = {}) {
  return new Win32Bridge(opts);
}
