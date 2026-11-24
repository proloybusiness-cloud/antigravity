/**
 * OmniOS Android Framework API & Lifecycle Bridge (`os/runtimes/android/framework-bridge.mjs`, F-040)
 * Wires real Dalvik VM invocations to live M2 OmniOS services:
 * - Activity lifecycle (`onCreate`..`onDestroy`), `setContentView(View|resId)` with AXML/XML layout inflation
 * - Android Views (`View`/`ViewGroup`/`LinearLayout`/`FrameLayout`/`ScrollView`/`TextView`/`Button`/`EditText`/`ImageView`)
 *   -> M2 `Compositor` semantic `uiTree` + live click/input routing back to Dalvik VM
 * - `SharedPreferences` & `Editor` -> M2 `UnifiedConfigStore.sharedPrefs`
 * - `Intent` & `Uri` -> M2 `IntentRouter`
 * - `Toast` & `NotificationManager` -> M2 `NotificationCenter` (always non-empty `title`)
 * - `ClipboardManager` & `ClipData` -> M2 `SharedClipboard`
 * - `android.util.Log` -> `ProcessManager.writeStdout` + `KernelEventBus`
 * - `ContentResolver`, `Service`, `Resources`, `Environment`, `java.io.File`/`FileInputStream`/`FileOutputStream`
 *   -> M2 `VFS` + `PathTranslator` enforcing strict `/data/data/<pkg>` sandbox and permission-gated `/sdcard` mediation
 * - Core `java.lang.*` & `java.util.*` classes
 * - 100% SYNCHRONOUS during `step()` (zero Promises returned to Scheduler; pure VFS-backed I/O).
 */

import { DalvikGuestException } from '../../cpu/dalvik.mjs';
import { QuotaExceededError, ERROR_CODES } from '../../common/errors.mjs';
import { parseXmlOrAxml, RES_VALUE_TYPES } from './axml-parser.mjs';
import { mapNativePermission } from '../../security/permissions.mjs';
import { isPathWithinRoot } from '../../vfs/path-translator.mjs';

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: false });
const EMPTY_UINT8 = new Uint8Array(0);
const EMPTY_STR_ARR = Object.freeze([]);
const SMALL_INT_STRINGS = Object.freeze(Array.from({ length: 4096 }, (_, i) => String(i)));
const SMALL_ASCII_CHARS = Object.freeze(Array.from({ length: 128 }, (_, i) => String.fromCharCode(i)));

export const ANDROID_CLASS_DESCRIPTORS = Object.freeze({
  OBJECT: 'Ljava/lang/Object;',
  STRING: 'Ljava/lang/String;',
  STRING_BUILDER: 'Ljava/lang/StringBuilder;',
  ACTIVITY: 'Landroid/app/Activity;',
  SERVICE: 'Landroid/app/Service;',
  CONTEXT: 'Landroid/content/Context;',
  CONTEXT_WRAPPER: 'Landroid/content/ContextWrapper;',
  INTENT: 'Landroid/content/Intent;',
  URI: 'Landroid/net/Uri;',
  BUNDLE: 'Landroid/os/Bundle;',
  ENVIRONMENT: 'Landroid/os/Environment;',
  SHARED_PREFS: 'Landroid/content/SharedPreferences;',
  SHARED_PREFS_EDITOR: 'Landroid/content/SharedPreferences$Editor;',
  CLIPBOARD_MANAGER: 'Landroid/content/ClipboardManager;',
  CLIP_DATA: 'Landroid/content/ClipData;',
  CLIP_DATA_ITEM: 'Landroid/content/ClipData$Item;',
  CONTENT_RESOLVER: 'Landroid/content/ContentResolver;',
  CONTENT_VALUES: 'Landroid/content/ContentValues;',
  CURSOR: 'Landroid/database/Cursor;',
  RESOURCES: 'Landroid/content/res/Resources;',
  NOTIFICATION_MANAGER: 'Landroid/app/NotificationManager;',
  NOTIFICATION: 'Landroid/app/Notification;',
  NOTIFICATION_BUILDER: 'Landroid/app/Notification$Builder;',
  TOAST: 'Landroid/widget/Toast;',
  LOG: 'Landroid/util/Log;',
  VIEW: 'Landroid/view/View;',
  VIEW_GROUP: 'Landroid/view/ViewGroup;',
  LINEAR_LAYOUT: 'Landroid/widget/LinearLayout;',
  FRAME_LAYOUT: 'Landroid/widget/FrameLayout;',
  SCROLL_VIEW: 'Landroid/widget/ScrollView;',
  TEXT_VIEW: 'Landroid/widget/TextView;',
  BUTTON: 'Landroid/widget/Button;',
  EDIT_TEXT: 'Landroid/widget/EditText;',
  IMAGE_VIEW: 'Landroid/widget/ImageView;',
  FILE: 'Ljava/io/File;',
  FILE_OUTPUT_STREAM: 'Ljava/io/FileOutputStream;',
  FILE_INPUT_STREAM: 'Ljava/io/FileInputStream;',
});

const VIEW_SHORT_TO_DESC = Object.freeze({
  View: ANDROID_CLASS_DESCRIPTORS.VIEW,
  ViewGroup: ANDROID_CLASS_DESCRIPTORS.VIEW_GROUP,
  LinearLayout: ANDROID_CLASS_DESCRIPTORS.LINEAR_LAYOUT,
  FrameLayout: ANDROID_CLASS_DESCRIPTORS.FRAME_LAYOUT,
  ScrollView: ANDROID_CLASS_DESCRIPTORS.SCROLL_VIEW,
  TextView: ANDROID_CLASS_DESCRIPTORS.TEXT_VIEW,
  Button: ANDROID_CLASS_DESCRIPTORS.BUTTON,
  EditText: ANDROID_CLASS_DESCRIPTORS.EDIT_TEXT,
  ImageView: ANDROID_CLASS_DESCRIPTORS.IMAGE_VIEW,
});

function descriptorToClassName(desc) {
  if (typeof desc !== 'string') return 'java.lang.Object';
  if (desc.startsWith('L') && desc.endsWith(';')) {
    return desc.slice(1, -1).replace(/\//g, '.');
  }
  return desc;
}

function classNameToDescriptor(name) {
  if (typeof name !== 'string' || name.length === 0) return 'Ljava/lang/Object;';
  if (name.startsWith('L') && name.endsWith(';')) return name;
  return `L${name.replace(/\./g, '/')};`;
}

function toJsString(val) {
  if (val === null || val === undefined) return 'null';
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'boolean' || typeof val === 'bigint') return String(val);
  if (typeof val === 'object') {
    if (
      val.classType === ANDROID_CLASS_DESCRIPTORS.STRING ||
      val.classType === ANDROID_CLASS_DESCRIPTORS.STRING_BUILDER ||
      val.classType === 'Ljava/lang/StringBuffer;'
    ) {
      return String(val.native?.text ?? '');
    }
    if (val.classType === 'Ljava/lang/Integer;' || val.classType === 'Ljava/lang/Long;' || val.classType === 'Ljava/lang/Float;' || val.classType === 'Ljava/lang/Double;' || val.classType === 'Ljava/lang/Boolean;') {
      return String(val.native?.value ?? '');
    }
    if (val.classType === ANDROID_CLASS_DESCRIPTORS.URI) {
      return String(val.native?.raw ?? '');
    }
    if (val.classType === ANDROID_CLASS_DESCRIPTORS.FILE) {
      return String(val.native?.path ?? '');
    }
    if (typeof val.fields?.detailMessage === 'string') {
      return `${descriptorToClassName(val.classType)}: ${val.fields.detailMessage}`;
    }
    return `${descriptorToClassName(val.classType)}@${val.id ?? 0}`;
  }
  return String(val);
}

function sanitizeFilenameSegment(name) {
  if (typeof name !== 'string' || name.length === 0 || name.includes('/') || name.includes('\\') || name.includes('..') || name.includes('\0')) {
    return null;
  }
  return name;
}

const INT32_MIN = -2147483648;
const INT32_MAX = 2147483647;
const INT64_MIN = -9223372036854775808n;
const INT64_MAX = 9223372036854775807n;
const MAX_VIEW_DEPTH = 256;
const MAX_FIND_VIEW_CACHE_ENTRIES = 4096;
const MAX_BRIDGE_LOGS = 2048;
const MAX_LOG_TAG_CHARS = 256;
const MAX_LOG_MESSAGE_CHARS = 4096;
const MAX_BRIDGE_TOASTS = 512;
const MAX_TOAST_TEXT_CHARS = 4096;
const MAX_BRIDGE_DISPATCHED_INTENTS = 512;
const MAX_BRIDGE_DISPATCHED_INTENT_KEYS = 4096;
const MAX_DISPATCHED_INTENT_SINGLE_KEYS = 64;
const MAX_NOTIFICATION_IDS = 512;
const MAX_NOTIF_TEXT_CHARS = 4096;
const MAX_PREF_WRITE_BYTES = 4 * 1024 * 1024;
export const MAX_PREF_READ_BYTES = 32 * 1024 * 1024;
const MAX_PREF_KEYS = 512;
const MAX_PREF_SINGLE_VALUE_BYTES = 256 * 1024;
const MAX_FALLBACK_PREF_NAMES = 64;
const MAX_SP_CACHE_NAMESPACES = 16;
const MAX_SP_CACHE_KEYS_PER_NS = 128;
const MAX_SP_TICK_CACHE_BYTES = 1024 * 1024;
const MAX_VFS_WRITE_BYTES = 16 * 1024 * 1024;
export const MAX_VFS_PHYSICAL_WRITE_BYTES = 32 * 1024 * 1024;
export const MAX_VFS_PHYSICAL_READ_BYTES = 64 * 1024 * 1024;
export const MAX_SERVICE_READ_BYTES = 32 * 1024 * 1024;
export const MAX_VFS_CREATE_OPS = 1024;
const MAX_READDIR_CACHE_BYTES = 4 * 1024 * 1024;
const MAX_READDIR_CACHE_ENTRIES = 256;
const MAX_STAT_CACHE_ENTRIES = 256;
const MAX_NON_EMPTY_DIR_CACHE_ENTRIES = 256;
const VFS_STAT_READ_COST = 4096;
const MAX_CLIPBOARD_TEXT_CHARS = 256 * 1024;
export const MAX_PERMISSION_AUDIT_EVENTS = 256;
export const MAX_PERMISSION_PROMPT_CALLS = 16;
const MAX_PERMISSION_AUDIT_PER_DECISION = 16;
const SHARED_PREFS_MISSING = Symbol('SHARED_PREFS_MISSING');
const CLIPBOARD_MISSING = Symbol('CLIPBOARD_MISSING');
const VFS_STAT_ENOENT = Symbol('VFS_STAT_ENOENT');
const VFS_READDIR_NULL = Symbol('VFS_READDIR_NULL');

function estimateSpValueSizes(v) {
  if (v === null || v === undefined || v === SHARED_PREFS_MISSING) {
    return { vmBytes: 0, physicalBytes: 16 };
  }
  if (typeof v === 'string') {
    return { vmBytes: v.length * 2, physicalBytes: Math.max(16, v.length + 16) };
  }
  if (Array.isArray(v) || v instanceof Set) {
    let vmBytes = 0;
    let physicalBytes = 32;
    for (const s of v) {
      const str = typeof s === 'string' ? s : String(s ?? '');
      vmBytes += str.length * 2 + 16;
      physicalBytes += str.length + 16;
    }
    return { vmBytes, physicalBytes };
  }
  const s = String(v);
  return { vmBytes: s.length * 2, physicalBytes: Math.max(16, s.length + 16) };
}

function pushBounded(arr, item, maxLen) {
  if (arr.length >= maxLen) {
    arr.splice(0, Math.max(1, maxLen >> 2));
  }
  arr.push(item);
}

function minHeapSiftUp(nodes, seqs, idx) {
  let i = idx;
  const node = nodes[i];
  const seq = seqs[i];
  while (i > 0) {
    const parent = (i - 1) >> 1;
    if (seqs[parent] <= seq) break;
    nodes[i] = nodes[parent];
    seqs[i] = seqs[parent];
    i = parent;
  }
  nodes[i] = node;
  seqs[i] = seq;
}

function minHeapSiftDown(nodes, seqs, idx) {
  const len = nodes.length;
  let i = idx;
  const node = nodes[i];
  const seq = seqs[i];
  while (true) {
    const left = (i << 1) + 1;
    if (left >= len) break;
    const right = left + 1;
    let smallest = left;
    let smallestSeq = seqs[left];
    if (right < len && seqs[right] < smallestSeq) {
      smallest = right;
      smallestSeq = seqs[right];
    }
    if (seq <= smallestSeq) break;
    nodes[i] = nodes[smallest];
    seqs[i] = smallestSeq;
    i = smallest;
  }
  nodes[i] = node;
  seqs[i] = seq;
}

function minHeapBuildFromSet(set) {
  const n = set.size;
  const nodes = new Array(n);
  const seqs = new Array(n);
  let i = 0;
  for (const item of set) {
    nodes[i] = item;
    seqs[i] = item.native?._attachSeq ?? 0;
    i += 1;
  }
  for (let p = (n >> 1) - 1; p >= 0; p -= 1) {
    minHeapSiftDown(nodes, seqs, p);
  }
  return { nodes, seqs };
}

function minHeapPop(nodes, seqs) {
  const lastNode = nodes.pop();
  const lastSeq = seqs.pop();
  if (nodes.length > 0) {
    nodes[0] = lastNode;
    seqs[0] = lastSeq;
    minHeapSiftDown(nodes, seqs, 0);
  }
}

function capString(str, maxChars) {
  const s = String(str ?? '');
  return s.length > maxChars ? s.slice(0, maxChars) : s;
}

function sanitizePermissionContext(context) {
  if (!context || typeof context !== 'object') return undefined;
  const out = Object.create(null);
  let fieldCount = 0;
  for (const [k, v] of Object.entries(context)) {
    if (fieldCount >= 16) break;
    const safeKey = capString(k, 64);
    if (typeof v === 'string') {
      out[safeKey] = capString(v, 256);
    } else if (typeof v === 'number' || typeof v === 'boolean' || v === null) {
      out[safeKey] = v;
    } else if (v !== undefined) {
      out[safeKey] = capString(String(v), 256);
    }
    fieldCount += 1;
  }
  return out;
}

function utf8ByteLength(str) {
  let bytes = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code <= 0x7f) {
      bytes += 1;
    } else if (code <= 0x7ff) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const next = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

function parseJavaLong(raw, radix = 10) {
  if (raw === null || raw === undefined) return null;
  if (!Number.isInteger(radix) || radix < 2 || radix > 36) return null;
  const s = toJsString(raw).trim();
  if (s.length === 0) return null;
  let idx = 0;
  let negative = false;
  if (s[0] === '-') {
    negative = true;
    idx = 1;
  } else if (s[0] === '+') {
    idx = 1;
  }
  if (idx >= s.length) return null;
  const bigRadix = BigInt(radix);
  let acc = 0n;
  for (; idx < s.length; idx++) {
    const code = s.charCodeAt(idx);
    let digit = -1;
    if (code >= 48 && code <= 57) digit = code - 48;
    else if (code >= 65 && code <= 90) digit = code - 55;
    else if (code >= 97 && code <= 122) digit = code - 87;
    if (digit < 0 || digit >= radix) return null;
    acc = acc * bigRadix + BigInt(digit);
    if (!negative && acc > INT64_MAX) return null;
    if (negative && acc > 9223372036854775808n) return null;
  }
  return negative ? -acc : acc;
}

function parseJavaInt(raw, radix = 10) {
  const big = parseJavaLong(raw, radix);
  if (big === null || big < BigInt(INT32_MIN) || big > BigInt(INT32_MAX)) return null;
  return Number(big) | 0;
}

function safeToLong(val, fallback = 0n) {
  if (typeof val === 'bigint') return BigInt.asIntN(64, val);
  if (typeof val === 'number') {
    if (Number.isNaN(val)) return fallback;
    if (val >= 9223372036854775808.0) return INT64_MAX;
    if (val <= -9223372036854775808.0) return INT64_MIN;
    return BigInt.asIntN(64, BigInt(Math.trunc(val)));
  }
  if (typeof val === 'boolean') return val ? 1n : 0n;
  if (typeof val === 'string') {
    const parsed = parseJavaLong(val, 10);
    return parsed !== null ? parsed : fallback;
  }
  return fallback;
}

function safeToInt(val, fallback = 0) {
  if (typeof val === 'number' && Number.isFinite(val)) return Math.trunc(val) | 0;
  if (typeof val === 'bigint') return Number(BigInt.asIntN(32, val));
  if (typeof val === 'boolean') return val ? 1 : 0;
  if (typeof val === 'string') {
    const parsed = parseJavaInt(val, 10);
    return parsed !== null ? parsed : fallback;
  }
  return fallback;
}

function safeToFloatOrDouble(val, fallback = 0) {
  if (typeof val === 'number') return Number.isNaN(val) ? fallback : val;
  if (typeof val === 'bigint') return Number(val);
  if (typeof val === 'boolean') return val ? 1 : 0;
  if (typeof val === 'string') {
    const trimmed = val.trim();
    if (trimmed.length === 0) return fallback;
    const n = Number(trimmed);
    return Number.isNaN(n) ? fallback : n;
  }
  return fallback;
}

function toMathNumber(val) {
  if (typeof val === 'number') return val;
  if (typeof val === 'bigint') return Number(val);
  if (typeof val === 'boolean') return val ? 1 : 0;
  if (val === null || val === undefined) return 0;
  if (typeof val === 'string') return Number(val);
  return NaN;
}

export class AndroidFrameworkBridge {
  constructor({
    vm,
    apk,
    pcb,
    appRecord,
    services = {},
    launchOptions = {},
    enqueueCallback = null,
    beginTeardown = null,
    onFinish = null,
  }) {
    this.vm = vm;
    this.apk = apk;
    this.pcb = pcb;
    this.appRecord = appRecord;
    this.services = services;
    this.launchOptions = launchOptions;
    this._enqueueCallback = typeof enqueueCallback === 'function' ? enqueueCallback : () => {};
    this._beginTeardown = typeof beginTeardown === 'function' ? beginTeardown : null;
    this._onFinish = typeof onFinish === 'function' ? onFinish : () => {};

    this.packageName = apk?.packageName || appRecord?.appId || 'com.omnios.android';
    this.appLabel = apk?.label || appRecord?.name || this.packageName;
    this.appDataDir = appRecord?.dataDir || `/var/appdata/android/${this.packageName}`;

    this.activity = null;
    this.activityState = 'CREATED';
    this.rootView = null;
    this.windowId = null;
    this.windowTitle = this.appLabel;
    this.finished = false;
    this._finishing = false;
    this._surfaceDirty = false;

    this.logs = [];
    this.toasts = [];
    this.dispatchedIntents = [];
    this._dispatchedIntentExtraKeys = 0;
    this.contentStore = new Map();
    this.runningServices = new Map();
    this._fallbackSharedPrefs = new Map();
    this._fallbackPrefTotalKeys = 0;
    this._prefWriteBytes = 0;
    this._prefWriteOps = 0;
    this._prefReadBytes = 0;
    this._vfsWriteBytes = 0;
    this._vfsPhysicalWriteBytes = 0;
    this._vfsPhysicalReadBytes = 0;
    this._clipboardReadBytes = 0;
    this._settingsReadBytes = 0;
    this._vfsCreateOps = 0;
    this._permAuditCalls = 0;
    this._permPromptCalls = 0;
    this._permAuditedDecisions = new Map();
    this._notificationIds = new Map();
    this._nextViewSeq = 1;

    // Tick-scoped & event-invalidated read caches / size estimators (S9-2)
    this._spTickKeyCache = new Map();
    this._spTickKeyCacheBytes = 0;
    this._spTickAllCache = new Map();
    this._spTickAllCacheBytes = 0;
    this._spTickContainsCache = new Map();
    this._spEstimatedNsBytes = new Map();
    this._spEstimatedKeyBytes = new Map();
    this._clipboardTickText = CLIPBOARD_MISSING;
    this._clipboardEstimatedBytes = null;
    this._settingsTickRows = null;
    this._settingsEstimatedVmBytes = null;
    // Bounded tick-local & local-write-invalidated directory scan, stat, and ENOTEMPTY caches (W10-3 / S12-3 / S13-3)
    this._readdirCache = new Map();
    this._readdirCacheBytes = 0;
    this._statCache = new Map();
    this._nonEmptyDirCache = new Map();
    // JLS §5.1.7 IntegerCache [-128, 127] frozen boxed singletons (bounded <= 256 entries)
    this._integerCache = new Map();
    // Tracks base-10 Integer.toString heap charges against retainable VM pointer slot capacity
    this._intDecStrChargedBytes = 0;
    this._intDecStrChargedCount = 0;
    // Attached-only & per-tree-root versioned View.findViewById() acceleration (S11-2 / S12-2)
    this._viewsById = new Map();
    this._findViewCache = new Map();
    this._findViewCacheSize = 0;
    this._nextAttachSeq = 1;
    this._eventUnsubscribers = [];
    this._hasConfigChangeListener = false;
    this._hasClipboardChangeListener = false;

    const eventBus = services?.eventBus;
    if (eventBus && typeof eventBus.on === 'function') {
      try {
        const onConfigChanged = () => {
          this._invalidateSpCache(null);
          this._invalidateSettingsCache();
        };
        const unsubCfg = eventBus.on('config:changed', onConfigChanged);
        this._hasConfigChangeListener = true;
        this._eventUnsubscribers.push(() => {
          if (typeof unsubCfg === 'function') unsubCfg();
          else if (typeof eventBus.off === 'function') eventBus.off('config:changed', onConfigChanged);
        });
      } catch (err) {
        this._recordInternalLog('W', 'AndroidBridge', `config:changed subscription skipped: ${err?.message ?? err}`);
      }
      try {
        const onClipboardChanged = () => {
          this._invalidateClipboardCache();
        };
        const unsubClip = eventBus.on('clipboard:changed', onClipboardChanged);
        this._hasClipboardChangeListener = true;
        this._eventUnsubscribers.push(() => {
          if (typeof unsubClip === 'function') unsubClip();
          else if (typeof eventBus.off === 'function') eventBus.off('clipboard:changed', onClipboardChanged);
        });
      } catch (err) {
        this._recordInternalLog('W', 'AndroidBridge', `clipboard:changed subscription skipped: ${err?.message ?? err}`);
      }
    }

    // Static System.out / System.err PrintStream & host framework singleton objects (bootstrap infrastructure)
    const noCharge = { charge: false };
    this._stdoutStream = vm.createObject('Ljava/io/PrintStream;', null, { channel: 'stdout' }, noCharge);
    this._stderrStream = vm.createObject('Ljava/io/PrintStream;', null, { channel: 'stderr' }, noCharge);
    this._clipboardManager = vm.createObject(ANDROID_CLASS_DESCRIPTORS.CLIPBOARD_MANAGER, null, {}, noCharge);
    this._notificationManager = vm.createObject(ANDROID_CLASS_DESCRIPTORS.NOTIFICATION_MANAGER, null, {}, noCharge);
    this._contentResolver = vm.createObject(ANDROID_CLASS_DESCRIPTORS.CONTENT_RESOLVER, null, {}, noCharge);
    this._resourcesObj = vm.createObject(ANDROID_CLASS_DESCRIPTORS.RESOURCES, null, {}, noCharge);

    // Create initial launch Intent
    this.launchIntent = this._createIntentFromLaunch(launchOptions?.intent ?? null, noCharge);
  }

  beginTick() {
    this._spTickKeyCache.clear();
    this._spTickKeyCacheBytes = 0;
    this._spTickAllCache.clear();
    this._spTickAllCacheBytes = 0;
    this._clipboardTickText = CLIPBOARD_MISSING;
    this._settingsTickRows = null;
    this._invalidateVfsReadCaches();
    if (!this._hasConfigChangeListener) {
      this._spTickContainsCache.clear();
      this._spEstimatedNsBytes.clear();
      this._spEstimatedKeyBytes.clear();
      this._settingsEstimatedVmBytes = null;
    }
    if (!this._hasClipboardChangeListener) {
      this._clipboardEstimatedBytes = null;
    }
  }

  _invalidateSpCache(prefName = null) {
    if (prefName === null) {
      this._spTickKeyCache.clear();
      this._spTickKeyCacheBytes = 0;
      this._spTickAllCache.clear();
      this._spTickAllCacheBytes = 0;
      this._spTickContainsCache.clear();
      this._spEstimatedNsBytes.clear();
      this._spEstimatedKeyBytes.clear();
      return;
    }
    this._spTickKeyCache.delete(prefName);
    const oldAll = this._spTickAllCache.get(prefName);
    if (oldAll) {
      this._spTickAllCacheBytes = Math.max(0, this._spTickAllCacheBytes - (oldAll.physicalBytes || 0));
      this._spTickAllCache.delete(prefName);
    }
    this._spTickContainsCache.delete(prefName);
    this._spEstimatedNsBytes.delete(prefName);
    this._spEstimatedKeyBytes.delete(prefName);
  }

  _invalidateSettingsCache() {
    this._settingsTickRows = null;
    this._settingsEstimatedVmBytes = null;
  }

  _invalidateClipboardCache() {
    this._clipboardTickText = CLIPBOARD_MISSING;
    this._clipboardEstimatedBytes = null;
  }

  _invalidateReaddirCache() {
    this._readdirCache.clear();
    this._readdirCacheBytes = 0;
  }

  _invalidateStatCache() {
    this._statCache.clear();
  }

  _invalidateVfsReadCaches() {
    this._readdirCache.clear();
    this._readdirCacheBytes = 0;
    this._statCache.clear();
    this._nonEmptyDirCache.clear();
  }

  _putReaddirCache(cacheKey, entry, entryBytes) {
    if (this._readdirCache.has(cacheKey)) {
      const prev = this._readdirCache.get(cacheKey);
      if (prev !== VFS_READDIR_NULL && prev?.cacheEntryBytes) {
        this._readdirCacheBytes = Math.max(0, this._readdirCacheBytes - prev.cacheEntryBytes);
      }
      this._readdirCache.delete(cacheKey);
    }
    while (
      this._readdirCache.size >= MAX_READDIR_CACHE_ENTRIES ||
      (entryBytes > 0 &&
        this._readdirCache.size > 0 &&
        this._readdirCacheBytes + entryBytes > MAX_READDIR_CACHE_BYTES)
    ) {
      const oldestKey = this._readdirCache.keys().next().value;
      const oldestVal = this._readdirCache.get(oldestKey);
      if (oldestVal !== VFS_READDIR_NULL && oldestVal?.cacheEntryBytes) {
        this._readdirCacheBytes = Math.max(0, this._readdirCacheBytes - oldestVal.cacheEntryBytes);
      }
      this._readdirCache.delete(oldestKey);
    }
    if (entryBytes <= MAX_READDIR_CACHE_BYTES) {
      this._readdirCache.set(cacheKey, entry);
      this._readdirCacheBytes += entryBytes;
    }
  }

  _detachEventListeners() {
    if (this._eventUnsubscribers.length === 0) return;
    const unsubs = this._eventUnsubscribers.splice(0, this._eventUnsubscribers.length);
    for (const fn of unsubs) {
      try {
        fn();
      } catch (err) {
        this._recordInternalLog('W', 'AndroidBridge', `Event unsubscribe ignored: ${err?.message ?? err}`);
      }
    }
    this._hasConfigChangeListener = false;
    this._hasClipboardChangeListener = false;
  }

  dispose() {
    this._surfaceDirty = false;
    this._detachEventListeners();
    this._invalidateSpCache(null);
    this._invalidateSettingsCache();
    this._invalidateClipboardCache();
    this._invalidateVfsReadCaches();
    this._integerCache.clear();
    this._intDecStrChargedBytes = 0;
    this._intDecStrChargedCount = 0;
    if (this.rootView?.native) {
      this.rootView.native._zeroIdHeap = null;
      if (this.rootView.native.childrenById) {
        this.rootView.native.childrenById.clear();
      }
    }
    this.rootView = null;
    this._viewsById.clear();
    this._findViewCache.clear();
    this._findViewCacheSize = 0;
  }

  _createIntentFromLaunch(rawIntent, createOpts = null) {
    const intentObj = this.vm.createObject(
      ANDROID_CLASS_DESCRIPTORS.INTENT,
      null,
      {
        action: rawIntent?.action ?? 'android.intent.action.MAIN',
        dataUri: rawIntent?.uri ?? null,
        mimeType: rawIntent?.mimeType ?? null,
        flags: 0,
        targetPackage: this.packageName,
        targetClass: this.apk?.launcherActivity || '',
        extras: Object.create(null),
      },
      createOpts
    );
    if (rawIntent && typeof rawIntent.extras === 'object' && rawIntent.extras !== null) {
      for (const [k, v] of Object.entries(rawIntent.extras)) {
        intentObj.native.extras[k] = v;
      }
    }
    return intentObj;
  }

  _throwGuest(classType, message) {
    throw new DalvikGuestException(this.vm.createException(classType, capString(message, 512)));
  }

  _estimateGuestStringLength(val) {
    if (val === null || val === undefined) return 4;
    if (typeof val === 'string') return val.length;
    if (typeof val === 'number' || typeof val === 'boolean' || typeof val === 'bigint') return 24;
    if (typeof val === 'object') {
      if (
        val.classType === ANDROID_CLASS_DESCRIPTORS.STRING ||
        val.classType === ANDROID_CLASS_DESCRIPTORS.STRING_BUILDER ||
        val.classType === 'Ljava/lang/StringBuffer;'
      ) {
        return typeof val.native?.text === 'string' ? val.native.text.length : 0;
      }
      if (val.classType === ANDROID_CLASS_DESCRIPTORS.URI) {
        return typeof val.native?.raw === 'string' ? val.native.raw.length : 0;
      }
      if (val.classType === ANDROID_CLASS_DESCRIPTORS.FILE) {
        return typeof val.native?.path === 'string' ? val.native.path.length : 0;
      }
      const rawDesc = typeof val.classType === 'string' ? val.classType : '';
      const descNameLen =
        rawDesc.startsWith('L') && rawDesc.endsWith(';') ? Math.max(0, rawDesc.length - 2) : rawDesc.length || 16;
      if (typeof val.fields?.detailMessage === 'string') {
        return descNameLen + 2 + val.fields.detailMessage.length;
      }
      return descNameLen + 12;
    }
    return 32;
  }

  _chargeNewPrimitiveString(str, reason = 'String allocation') {
    const cost = Math.max(32, str.length * 2);
    this.vm.chargeHeap(cost, reason);
    return str;
  }

  _formatIntString(v, radix = 10, reason = 'Integer.toString') {
    if (radix === 10 && v >= 0 && v < SMALL_INT_STRINGS.length) {
      return SMALL_INT_STRINGS[v];
    }
    if (radix === 10) {
      const str = String(v);
      // Every VM heap slot capable of retaining a String (arrays >= 8 B/slot, fields/containers >= 16-128 B/slot)
      // contributes at least 8 B to non-string allocatedHeapBytes, bounding live non-GC'd base-10 int strings.
      const nonStrHeapBytes = Math.max(0, (this.vm?.allocatedHeapBytes ?? 0) - this._intDecStrChargedBytes);
      const maxRetainableSlots = Math.floor(nonStrHeapBytes / 8);
      if (this._intDecStrChargedCount < maxRetainableSlots) {
        const cost = Math.max(32, str.length * 2);
        this.vm.chargeHeap(cost, reason);
        this._intDecStrChargedBytes += cost;
        this._intDecStrChargedCount += 1;
      }
      return str;
    }
    const str = radix >= 2 && radix <= 36 ? v.toString(radix) : String(v);
    return this._chargeNewPrimitiveString(str, reason);
  }

  _formatLongString(v, radix = 10, reason = 'Long.toString') {
    if (radix === 10 && v >= 0n && v < 4096n) {
      return SMALL_INT_STRINGS[Number(v)];
    }
    const str = radix >= 2 && radix <= 36 && radix !== 10 ? v.toString(radix) : String(v);
    return this._chargeNewPrimitiveString(str, reason);
  }

  _coerceGuestString(val, reason = 'String coercion') {
    if (val === null || val === undefined) return 'null';
    if (typeof val === 'string') return val;
    if (typeof val === 'boolean') return val ? 'true' : 'false';
    if (typeof val === 'number') {
      if (Number.isInteger(val) && val >= 0 && val < SMALL_INT_STRINGS.length && !Object.is(val, -0)) {
        return SMALL_INT_STRINGS[val];
      }
      return this._chargeNewPrimitiveString(String(val), reason);
    }
    if (typeof val === 'bigint') {
      if (val >= 0n && val < 4096n) {
        return SMALL_INT_STRINGS[Number(val)];
      }
      return this._chargeNewPrimitiveString(String(val), reason);
    }
    if (typeof val === 'object') {
      if (val.classType === 'Ljava/lang/Integer;' || val.classType === 'Ljava/lang/Long;') {
        const inner = val.native?.value;
        if (typeof inner === 'number' && Number.isInteger(inner) && inner >= 0 && inner < SMALL_INT_STRINGS.length && !Object.is(inner, -0)) {
          return SMALL_INT_STRINGS[inner];
        }
        if (typeof inner === 'bigint' && inner >= 0n && inner < 4096n) {
          return SMALL_INT_STRINGS[Number(inner)];
        }
        return this._chargeNewPrimitiveString(String(inner ?? ''), reason);
      }
      if (val.classType === 'Ljava/lang/Float;' || val.classType === 'Ljava/lang/Double;') {
        return this._chargeNewPrimitiveString(String(val.native?.value ?? ''), reason);
      }
      if (val.classType === 'Ljava/lang/Boolean;') {
        return val.native?.value ? 'true' : 'false';
      }
      if (typeof val.fields?.detailMessage === 'string') {
        const rawDesc = typeof val.classType === 'string' ? val.classType : '';
        const descNameLen =
          rawDesc.startsWith('L') && rawDesc.endsWith(';') ? Math.max(0, rawDesc.length - 2) : rawDesc.length || 16;
        const detail = val.fields.detailMessage;
        const projectedLen = descNameLen + 2 + detail.length;
        this.vm.chargeHeap(projectedLen * 2, reason);
        const className = descriptorToClassName(val.classType);
        return `${className}: ${detail}`;
      }
      const estLen = this._estimateGuestStringLength(val);
      if (estLen > 512) {
        this.vm.checkHeapBudget(estLen * 2, reason);
      }
      const res = toJsString(val);
      if (res.length > 0) {
        this.vm.chargeHeap(res.length * 2, reason);
      }
      return res;
    }
    return this._chargeNewPrimitiveString(String(val), reason);
  }

  _translateHostServiceError(err, label) {
    if (err instanceof DalvikGuestException) throw err;
    const code = err?.code;
    if (code === 'EACCES' || code === 'EPERM' || code === 'E_SANDBOX_VIOLATION') {
      this._throwGuest('Ljava/lang/SecurityException;', `${label}: ${err?.message ?? err}`);
    }
    if (code === 'EQUOTA' || err?.name === 'QuotaExceededError') {
      this._throwGuest('Ljava/lang/OutOfMemoryError;', `${label}: ${err?.message ?? err}`);
    }
    this._throwGuest('Ljava/lang/RuntimeException;', `${label}: ${err?.message ?? err}`);
  }

  _requireInstanceReceiver(receiver, expectedLabel) {
    if (!receiver || typeof receiver !== 'object' || receiver.__dalvikType !== 'instance') {
      this._throwGuest(
        'Ljava/lang/ClassCastException;',
        `Expected ${expectedLabel} instance receiver, got ${capString(this.vm.getObjectType(receiver) ?? typeof receiver, 128)}`
      );
    }
    return receiver;
  }

  // ===========================================================================
  // Synchronous Permission Mediation (Landmine #2 & #3 — never return Promise!)
  // ===========================================================================

  _checkPermissionSync(capability, nativePermission = null, context = null) {
    const permissions = this.services?.permissions;
    if (!permissions) {
      return { granted: true, policy: 'allow' };
    }

    let resolvedCap = capability;
    if (!resolvedCap && nativePermission) {
      resolvedCap = mapNativePermission(nativePermission, 'android');
    }
    if (!resolvedCap) {
      return { granted: false, policy: 'deny' };
    }

    // Root UID 0 bypasses capability gate
    if (this.pcb?.uid === 0) {
      return { granted: true, policy: 'allow' };
    }

    let policy = null;
    try {
      const grant = typeof permissions.getGrant === 'function' ? permissions.getGrant(this.packageName, resolvedCap) : null;
      if (grant && typeof grant.state === 'string') {
        policy = grant.state;
      } else if (typeof permissions.getDefaultPolicy === 'function') {
        policy = permissions.getDefaultPolicy(resolvedCap);
      }
    } catch (err) {
      this._recordInternalLog('W', 'PermissionBroker', `Sync policy read fallback: ${err?.message ?? err}`);
      policy = 'deny';
    }

    const effectivePolicy = policy ?? 'deny';
    const granted = effectivePolicy === 'allow';

    // Pure read-only permission query (e.g. Activity.checkSelfPermission()):
    // NEVER spawn PermissionBroker prompts, timers, or security_audit rows.
    if (context?.checkOnly === true) {
      return { granted, policy: effectivePolicy, capability: resolvedCap };
    }

    // Write bounded SQLite audit row synchronously via checkPermission (with timeoutMs: 0 so prompt never hangs)
    if (typeof permissions.checkPermission === 'function') {
      const decisionKey = `${resolvedCap}|${effectivePolicy}`;
      const priorCount = this._permAuditedDecisions.get(decisionKey) ?? 0;
      const perDecisionLimit = effectivePolicy === 'prompt' ? 1 : MAX_PERMISSION_AUDIT_PER_DECISION;
      const underGlobalAuditCap = this._permAuditCalls < MAX_PERMISSION_AUDIT_EVENTS;
      const underPromptCap = effectivePolicy !== 'prompt' || this._permPromptCalls < MAX_PERMISSION_PROMPT_CALLS;
      if (underGlobalAuditCap && underPromptCap && priorCount < perDecisionLimit) {
        this._permAuditCalls += 1;
        if (effectivePolicy === 'prompt') {
          this._permPromptCalls += 1;
        }
        this._permAuditedDecisions.set(decisionKey, priorCount + 1);
        const auditContext = sanitizePermissionContext(context);
        const hasInteractivePrompt =
          typeof permissions.hasInteractivePromptConsumer === 'function'
            ? permissions.hasInteractivePromptConsumer()
            : typeof permissions._promptHandler === 'function';
        try {
          const req = {
            appId: this.packageName,
            pid: this.pcb?.pid ?? null,
            platform: 'android',
            capability: resolvedCap,
            nativePermission: nativePermission ? capString(nativePermission, 256) : null,
            context: auditContext,
          };
          if (!hasInteractivePrompt) {
            req.timeoutMs = 0;
          }
          const p = permissions.checkPermission(req);
          if (p && typeof p.catch === 'function') {
            p.catch((err) => {
              this._recordInternalLog('W', 'PermissionBroker', `Audit error ignored: ${err?.message ?? err}`);
            });
          }
        } catch (err) {
          this._recordInternalLog('W', 'PermissionBroker', `Audit invocation error: ${err?.message ?? err}`);
        }
      }
    }

    return { granted, policy: effectivePolicy, capability: resolvedCap };
  }

  // ===========================================================================
  // Sandboxed VFS Resolution & `/sdcard` Mediation (Landmine #2)
  // ===========================================================================

  _resolveVfsAccess(rawPath, mode /* 'read' | 'write' */) {
    const vfs = this.services?.vfs;
    if (!vfs) {
      this._throwGuest('Ljava/io/IOException;', 'VFS service is unavailable');
    }

    const pathStr = String(rawPath ?? '');
    if (pathStr.length === 0 || pathStr.includes('\0')) {
      this._throwGuest('Ljava/io/IOException;', `Invalid path: ${capString(pathStr, 256)}`);
    }

    let translated;
    try {
      translated = vfs.pathTranslator.toCanonical(pathStr, {
        platform: 'android',
        cwd: this.appDataDir,
        appId: this.packageName,
      });
    } catch (err) {
      const code = err?.code;
      if (code === 'EACCES' || code === 'E_PATH_TRAVERSAL' || code === 'EPERM') {
        this._throwGuest('Ljava/lang/SecurityException;', err.message);
      }
      this._throwGuest('Ljava/io/IOException;', err?.message ?? `Invalid path: ${capString(pathStr, 256)}`);
    }

    const canonical = translated.canonicalPath;
    const isAppPrivate = isPathWithinRoot(canonical, this.appDataDir);
    const isSharedUser = isPathWithinRoot(canonical, '/home/user');
    const uid = this.pcb?.uid ?? 10000;
    const gid = this.pcb?.gid ?? 10000;
    const isRoot = uid === 0;

    if (isAppPrivate) {
      return {
        vfs,
        canonicalPath: canonical,
        ctx: {
          pid: this.pcb?.pid ?? null,
          uid,
          gid,
          platform: 'android',
          appId: this.packageName,
          cwd: this.appDataDir,
          ...(!isRoot ? { sandboxRoot: this.appDataDir, strictSandbox: true } : {}),
        },
      };
    }

    if (isSharedUser) {
      const cap = mode === 'write' ? 'fs.write.user' : 'fs.read.user';
      const nativePerm =
        mode === 'write'
          ? 'android.permission.WRITE_EXTERNAL_STORAGE'
          : 'android.permission.READ_EXTERNAL_STORAGE';
      const decision = this._checkPermissionSync(cap, nativePerm, { path: capString(canonical, 256), mode });
      if (!decision.granted) {
        this._throwGuest(
          'Ljava/lang/SecurityException;',
          `Permission denied (${nativePerm} -> ${cap}: ${decision.policy}) for ${capString(pathStr, 256)}`
        );
      }
      const mediatedUid = isRoot ? 0 : 1000;
      const mediatedGid = this.pcb?.gid === 0 ? 0 : 1000;
      return {
        vfs,
        canonicalPath: canonical,
        ctx: {
          pid: this.pcb?.pid ?? null,
          uid: mediatedUid,
          gid: mediatedGid,
          platform: 'android',
          appId: this.packageName,
          cwd: '/home/user',
          sandboxRoot: '/home/user',
          ...(!isRoot ? { strictSandbox: true } : {}),
        },
      };
    }

    // All other paths (/root, /etc, /system, /apps, /var/appdata/<other>, /proc, /dev):
    // Fail closed immediately for any unprivileged Android context regardless of UserManager registration.
    if (!isRoot) {
      this._throwGuest(
        'Ljava/lang/SecurityException;',
        `Sandbox access denied: ${capString(pathStr, 256)} (${capString(canonical, 256)}) is outside app sandbox ${this.appDataDir}`
      );
    }

    return {
      vfs,
      canonicalPath: canonical,
      ctx: {
        pid: this.pcb?.pid ?? null,
        uid,
        gid,
        platform: 'android',
        appId: this.packageName,
        cwd: this.appDataDir,
      },
    };
  }

  _translateVfsError(err, rawPath) {
    const safePath = capString(rawPath, 256);
    const code = err?.code;
    if (code === 'EACCES' || code === 'EPERM' || code === 'E_PATH_TRAVERSAL' || code === 'E_SANDBOX_VIOLATION') {
      this._throwGuest('Ljava/lang/SecurityException;', err.message || `Access denied: ${safePath}`);
    }
    if (code === 'ENOENT') {
      this._throwGuest('Ljava/io/FileNotFoundException;', err.message || `File not found: ${safePath}`);
    }
    this._throwGuest('Ljava/io/IOException;', err?.message ?? `I/O error on ${safePath}`);
  }

  _statCached(
    access,
    rawPath,
    { quotaException = 'Ljava/lang/SecurityException;', canonicalPath = null } = {}
  ) {
    const targetPath = canonicalPath ?? access.canonicalPath;
    const cacheKey = `${access.ctx.uid}:${access.ctx.gid}:${targetPath}`;
    if (this._statCache.has(cacheKey)) {
      const cached = this._statCache.get(cacheKey);
      return { stat: cached === VFS_STAT_ENOENT ? null : cached, fromCache: true };
    }
    const isRoot = this.pcb?.uid === 0;
    if (!isRoot && this._vfsPhysicalReadBytes + VFS_STAT_READ_COST > MAX_VFS_PHYSICAL_READ_BYTES) {
      this._throwGuest(
        quotaException,
        `Read quota exceeded: physical VFS read budget (${this._vfsPhysicalReadBytes + VFS_STAT_READ_COST}/${MAX_VFS_PHYSICAL_READ_BYTES} bytes)`
      );
    }
    let st = null;
    try {
      st = access.vfs.stat(targetPath, { ...access.ctx });
    } catch (err) {
      if (err?.code === 'ENOENT' || err?.code === 'ENOTDIR') {
        st = null;
      } else {
        if (!isRoot) {
          this._vfsPhysicalReadBytes += err?.code === 'ELOOP' ? 16 * VFS_STAT_READ_COST : VFS_STAT_READ_COST;
        }
        this._translateVfsError(err, rawPath);
      }
    }
    if (!isRoot) {
      this._vfsPhysicalReadBytes += VFS_STAT_READ_COST;
    }
    if (!this._statCache.has(cacheKey) && this._statCache.size >= MAX_STAT_CACHE_ENTRIES) {
      const oldestKey = this._statCache.keys().next().value;
      this._statCache.delete(oldestKey);
    }
    this._statCache.set(cacheKey, st === null ? VFS_STAT_ENOENT : st);
    return { stat: st, fromCache: false };
  }

  // ===========================================================================
  // Centralized Native Container Backing Initializers (S11-1B / R1-1)
  // Atomically charge VM heap strictly BEFORE allocating native containers,
  // shared across both <init> constructors and lazy _handle*() entry points.
  // ===========================================================================

  _ensureIntentNative(receiver) {
    this._requireInstanceReceiver(receiver, 'android.content.Intent');
    if (!receiver.native) {
      this.vm.chargeHeap(384, 'Intent native');
      receiver.native = {
        action: null,
        dataUri: null,
        mimeType: null,
        flags: 0,
        targetPackage: null,
        targetClass: null,
        extras: Object.create(null),
      };
    } else if (
      typeof receiver.native !== 'object' ||
      !receiver.native.extras ||
      typeof receiver.native.extras !== 'object' ||
      Array.isArray(receiver.native.extras)
    ) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not an Intent`);
    }
    return receiver.native;
  }

  _ensureBundleNative(receiver) {
    this._requireInstanceReceiver(receiver, 'android.os.Bundle');
    if (!receiver.native) {
      this.vm.chargeHeap(256, 'Bundle native');
      receiver.native = { map: Object.create(null) };
    } else if (
      typeof receiver.native !== 'object' ||
      !receiver.native.map ||
      typeof receiver.native.map !== 'object' ||
      receiver.native.map instanceof Map ||
      Array.isArray(receiver.native.map)
    ) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a Bundle`);
    }
    return receiver.native;
  }

  _ensureContentValuesNative(receiver) {
    this._requireInstanceReceiver(receiver, 'android.content.ContentValues');
    if (!receiver.native) {
      this.vm.chargeHeap(256, 'ContentValues native');
      receiver.native = { map: Object.create(null) };
    } else if (
      typeof receiver.native !== 'object' ||
      !receiver.native.map ||
      typeof receiver.native.map !== 'object' ||
      receiver.native.map instanceof Map ||
      Array.isArray(receiver.native.map)
    ) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a ContentValues`);
    }
    return receiver.native;
  }

  _ensureHashMapNative(receiver) {
    this._requireInstanceReceiver(receiver, 'java.util.Map');
    if (!receiver.native) {
      this.vm.chargeHeap(256, 'HashMap native');
      receiver.native = { map: new Map() };
    } else if (typeof receiver.native !== 'object' || !(receiver.native.map instanceof Map)) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a Map`);
    }
    return receiver.native;
  }

  _ensureHashSetNative(receiver) {
    this._requireInstanceReceiver(receiver, 'java.util.Set');
    if (!receiver.native) {
      this.vm.chargeHeap(256, 'HashSet native');
      receiver.native = { set: new Set() };
    } else if (typeof receiver.native !== 'object' || !(receiver.native.set instanceof Set)) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a Set`);
    }
    return receiver.native;
  }

  _ensureArrayListNative(receiver) {
    this._requireInstanceReceiver(receiver, 'java.util.List');
    if (!receiver.native) {
      this.vm.chargeHeap(128, 'ArrayList native');
      receiver.native = { items: [] };
    } else if (typeof receiver.native !== 'object' || !Array.isArray(receiver.native.items)) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a List`);
    }
    return receiver.native;
  }

  _ensureNotificationBuilderNative(receiver, channelId = 'default') {
    this._requireInstanceReceiver(receiver, 'android.app.Notification$Builder');
    if (!receiver.native) {
      this.vm.chargeHeap(128, 'Notification.Builder native');
      receiver.native = { title: this.appLabel, body: '', priority: 'normal', channelId };
    } else if (typeof receiver.native !== 'object' || typeof receiver.native.title !== 'string') {
      this._throwGuest(
        'Ljava/lang/ClassCastException;',
        `Receiver ${receiver.classType} is not a Notification.Builder`
      );
    }
    return receiver.native;
  }

  _ensureStringBuilderNative(receiver, classType = ANDROID_CLASS_DESCRIPTORS.STRING_BUILDER) {
    this._requireInstanceReceiver(receiver, classType);
    if (!receiver.native) {
      const label = classType === 'Ljava/lang/StringBuffer;' ? 'StringBuffer' : 'StringBuilder';
      this.vm.chargeHeap(128, `${label} native`);
      receiver.native = { text: '' };
    } else if (typeof receiver.native !== 'object' || typeof receiver.native.text !== 'string') {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a ${classType}`);
    }
    return receiver.native;
  }

  // ===========================================================================
  // Android Views, Layout Inflation & Live Compositor Surface Sync
  // ===========================================================================

  _getViewTreeRoot(viewObj) {
    let cur = viewObj;
    let hops = 0;
    while (cur && hops <= MAX_VIEW_DEPTH + 1) {
      const parent = cur.native?.parent;
      if (!parent) break;
      cur = parent;
      hops += 1;
    }
    if (hops > 4) {
      this._chargeFindViewWork(hops);
    }
    return cur;
  }

  _dropTreeCache(treeRoot) {
    if (!treeRoot) return;
    const entry = this._findViewCache.get(treeRoot);
    if (!entry) return;
    let removed = 0;
    for (const byNode of entry.byId.values()) {
      removed += byNode.size;
    }
    this._findViewCacheSize = Math.max(0, this._findViewCacheSize - removed);
    this._findViewCache.delete(treeRoot);
  }

  _bumpTreeVersion(treeRoot) {
    if (!treeRoot?.native) return;
    treeRoot.native._treeVersion = (treeRoot.native._treeVersion | 0) + 1;
    this._dropTreeCache(treeRoot);
  }

  _invalidateTreeCacheId(treeRoot, id) {
    if (!treeRoot) return;
    const entry = this._findViewCache.get(treeRoot);
    if (!entry) return;
    const key = id | 0;
    const byNode = entry.byId.get(key);
    if (byNode) {
      this._findViewCacheSize = Math.max(0, this._findViewCacheSize - byNode.size);
      entry.byId.delete(key);
      if (entry.byId.size === 0) {
        this._findViewCache.delete(treeRoot);
      }
    }
  }

  _chargeFindViewWork(visited) {
    if (visited <= 0 || !this.vm) return;
    if (typeof this.vm.chargeExternalWork === 'function') {
      this.vm.chargeExternalWork(visited);
      return;
    }
    this.vm.totalInstructionsExecuted += visited;
    if (this.vm.totalInstructionsExecuted >= this.vm.maxTotalInstructions) {
      throw new QuotaExceededError(
        `Dalvik VM exceeded total instruction quota (${this.vm.maxTotalInstructions})`,
        {
          code: ERROR_CODES.E_CPU_QUOTA,
          quotaType: 'cpu',
          limit: this.vm.maxTotalInstructions,
          actual: this.vm.totalInstructionsExecuted,
          pid: this.vm.pid,
          signal: 'SIGXCPU',
        }
      );
    }
  }

  _minHeapPush(set, heap, child, seq) {
    const { nodes, seqs } = heap;
    if (nodes.length > 0 && nodes[0] === child && seqs[0] === seq) {
      return heap;
    }
    nodes.push(child);
    seqs.push(seq);
    minHeapSiftUp(nodes, seqs, nodes.length - 1);
    if (nodes.length > set.size * 2 + 64) {
      this._chargeFindViewWork(set.size);
      return minHeapBuildFromSet(set);
    }
    return heap;
  }

  _minHeapPeek(set, heap) {
    const { nodes, seqs } = heap;
    let stalePops = 0;
    let charged = 0;
    while (nodes.length > 0) {
      const topNode = nodes[0];
      const topSeq = seqs[0];
      if (set.has(topNode) && (topNode.native?._attachSeq ?? 0) === topSeq) {
        if (stalePops > 64 && stalePops > charged) {
          this._chargeFindViewWork(stalePops - charged);
        }
        return topNode;
      }
      minHeapPop(nodes, seqs);
      stalePops += 1;
      if (stalePops > 64 && stalePops - charged >= 64) {
        this._chargeFindViewWork(stalePops - charged);
        charged = stalePops;
      }
    }
    if (stalePops > 64 && stalePops > charged) {
      this._chargeFindViewWork(stalePops - charged);
    }
    if (set.size > 0) {
      this._chargeFindViewWork(set.size);
      const rebuilt = minHeapBuildFromSet(set);
      heap.nodes = rebuilt.nodes;
      heap.seqs = rebuilt.seqs;
      return heap.nodes[0] ?? null;
    }
    return null;
  }

  _addToViewsById(viewObj, id) {
    const key = id | 0;
    if (key === 0) return;
    const curEntry = this._viewsById.get(key);
    if (!curEntry) {
      this._viewsById.set(key, viewObj);
    } else if (curEntry instanceof Set) {
      curEntry.add(viewObj);
    } else if (curEntry !== viewObj) {
      this._viewsById.set(key, new Set([curEntry, viewObj]));
    }
  }

  _removeFromViewsById(viewObj, id) {
    const key = id | 0;
    if (key === 0) return;
    const oldEntry = this._viewsById.get(key);
    if (oldEntry === viewObj) {
      this._viewsById.delete(key);
    } else if (oldEntry instanceof Set) {
      oldEntry.delete(viewObj);
      if (oldEntry.size === 0) {
        this._viewsById.delete(key);
      } else if (oldEntry.size === 1) {
        this._viewsById.set(key, oldEntry.values().next().value);
      }
    }
  }

  _addChildById(parentNative, id, child) {
    const key = id | 0;
    if (key === 0) return;
    if (!parentNative.childrenById) {
      parentNative.childrenById = new Map();
    }
    const existing = parentNative.childrenById.get(key);
    if (!existing) {
      parentNative.childrenById.set(key, child);
      return;
    }
    if (existing === child) return;
    const childSeq = child.native?._attachSeq ?? 0;
    if (existing.__dalvikType === 'instance') {
      const existingSeq = existing.native?._attachSeq ?? 0;
      const set = new Set();
      let maxSeq;
      if (existingSeq <= childSeq) {
        set.add(existing);
        set.add(child);
        maxSeq = childSeq;
      } else {
        set.add(child);
        set.add(existing);
        maxSeq = existingSeq;
      }
      parentNative.childrenById.set(key, { set, heap: null, maxSeq });
      return;
    }
    if (!existing.set.has(child)) {
      if (existing.heap) {
        existing.set.add(child);
        if (childSeq > existing.maxSeq) existing.maxSeq = childSeq;
        existing.heap = this._minHeapPush(existing.set, existing.heap, child, childSeq);
      } else if (existing.set.size > 0 && childSeq < existing.maxSeq) {
        if (existing.set.size > 64) {
          this._chargeFindViewWork(existing.set.size);
        }
        existing.set.add(child);
        existing.heap = minHeapBuildFromSet(existing.set);
      } else {
        existing.maxSeq = childSeq;
        existing.set.add(child);
      }
    }
  }

  _removeChildById(parentNative, id, child) {
    const key = id | 0;
    if (key === 0 || !parentNative.childrenById) return;
    const existing = parentNative.childrenById.get(key);
    if (!existing) return;
    if (existing === child) {
      parentNative.childrenById.delete(key);
      return;
    }
    if (existing.set) {
      existing.set.delete(child);
      if (existing.set.size === 0) {
        existing.heap = null;
        parentNative.childrenById.delete(key);
      } else if (existing.set.size === 1) {
        existing.heap = null;
        parentNative.childrenById.set(key, existing.set.values().next().value);
      }
    }
  }

  _getFirstDirectChildById(parentNative, wantId) {
    const map = parentNative?.childrenById;
    if (!map) return null;
    const entry = map.get(wantId | 0);
    if (!entry) return null;
    if (entry.__dalvikType === 'instance') return entry;
    const set = entry.set;
    if (!set || set.size === 0) return null;
    if (set.size === 1) {
      entry.heap = null;
      const only = set.values().next().value;
      entry.maxSeq = only.native?._attachSeq ?? 0;
      return only;
    }
    if (entry.heap) {
      return this._minHeapPeek(set, entry.heap);
    }
    return set.values().next().value;
  }

  _addZeroIdChild(parentNative, child) {
    if (!parentNative.zeroIdChildren) {
      parentNative.zeroIdChildren = new Set();
      parentNative._maxZeroIdSeq = 0;
      parentNative._zeroIdHeap = null;
    }
    const set = parentNative.zeroIdChildren;
    if (set.has(child)) return;
    const seq = child.native?._attachSeq ?? 0;
    if (parentNative._zeroIdHeap) {
      set.add(child);
      if (seq > (parentNative._maxZeroIdSeq ?? 0)) parentNative._maxZeroIdSeq = seq;
      parentNative._zeroIdHeap = this._minHeapPush(set, parentNative._zeroIdHeap, child, seq);
    } else if (set.size > 0 && seq < (parentNative._maxZeroIdSeq ?? 0)) {
      if (set.size > 64) {
        this._chargeFindViewWork(set.size);
      }
      set.add(child);
      parentNative._zeroIdHeap = minHeapBuildFromSet(set);
    } else {
      parentNative._maxZeroIdSeq = seq;
      set.add(child);
    }
  }

  _removeZeroIdChild(parentNative, child) {
    const set = parentNative.zeroIdChildren;
    if (!set) return;
    set.delete(child);
    if (set.size === 0) {
      parentNative._maxZeroIdSeq = 0;
      parentNative._zeroIdHeap = null;
    } else if (set.size === 1) {
      parentNative._zeroIdHeap = null;
      const only = set.values().next().value;
      parentNative._maxZeroIdSeq = only.native?._attachSeq ?? 0;
    }
  }

  _getFirstZeroIdChild(parentNative) {
    const set = parentNative?.zeroIdChildren;
    if (!set || set.size === 0) return null;
    if (set.size === 1) {
      parentNative._zeroIdHeap = null;
      const only = set.values().next().value;
      parentNative._maxZeroIdSeq = only.native?._attachSeq ?? 0;
      return only;
    }
    if (parentNative._zeroIdHeap) {
      return this._minHeapPeek(set, parentNative._zeroIdHeap);
    }
    return set.values().next().value;
  }

  _addNonLeafChild(parentNative, child) {
    if (!parentNative.nonLeafChildren) {
      parentNative.nonLeafChildren = new Set();
      parentNative._maxNonLeafSeq = 0;
      parentNative._nonLeafOrderDirty = false;
    }
    if (parentNative.nonLeafChildren.has(child)) return;
    const seq = child.native?._attachSeq ?? 0;
    if (parentNative.nonLeafChildren.size > 0 && seq < (parentNative._maxNonLeafSeq ?? 0)) {
      parentNative._nonLeafOrderDirty = true;
    } else {
      parentNative._maxNonLeafSeq = seq;
    }
    parentNative.nonLeafChildren.add(child);
  }

  _removeNonLeafChild(parentNative, child) {
    const set = parentNative.nonLeafChildren;
    if (!set) return;
    set.delete(child);
    if (set.size === 0) {
      parentNative._maxNonLeafSeq = 0;
      parentNative._nonLeafOrderDirty = false;
    }
  }

  _getOrderedNonLeafChildren(parentNative) {
    const set = parentNative?.nonLeafChildren;
    if (!set || set.size === 0) return null;
    if (set.size === 1) {
      parentNative._nonLeafOrderDirty = false;
      const only = set.values().next().value;
      parentNative._maxNonLeafSeq = only.native?._attachSeq ?? 0;
      return set;
    }
    if (parentNative._nonLeafOrderDirty) {
      // Pre-charge exact O(N log N) sort work STRICTLY BEFORE allocating/sorting!
      const sortWork = Math.ceil(set.size * Math.max(1, Math.log2(set.size + 1)));
      this._chargeFindViewWork(sortWork);
      const sorted = Array.from(set).sort(
        (a, b) => (a.native?._attachSeq ?? 0) - (b.native?._attachSeq ?? 0)
      );
      parentNative.nonLeafChildren = new Set(sorted);
      parentNative._maxNonLeafSeq = sorted[sorted.length - 1].native?._attachSeq ?? 0;
      parentNative._nonLeafOrderDirty = false;
      return parentNative.nonLeafChildren;
    }
    return set;
  }

  _propagateZeroIdCount(startNode, delta) {
    if (!delta) return;
    let cur = startNode;
    let steps = 0;
    while (cur && steps <= MAX_VIEW_DEPTH + 1) {
      const cn = cur.native;
      if (!cn) break;
      const prev = typeof cn.subtreeZeroIdCount === 'number' ? cn.subtreeZeroIdCount : 0;
      const next = prev + delta;
      const clamped = next > 0 ? next : 0;
      cn.subtreeZeroIdCount = clamped;
      const parent = cn.parent;
      if (parent?.native) {
        if (prev <= 0 && clamped > 0) {
          this._addZeroIdChild(parent.native, cur);
        } else if (prev > 0 && clamped <= 0) {
          this._removeZeroIdChild(parent.native, cur);
        }
      }
      cur = parent;
      steps += 1;
    }
    if (steps > 4) {
      this._chargeFindViewWork(steps);
    }
  }

  _propagateSubtreeMetrics(startNode, sizeDelta, nonLeafDelta) {
    if (!sizeDelta && !nonLeafDelta) return;
    let cur = startNode;
    let steps = 0;
    while (cur && steps <= MAX_VIEW_DEPTH + 1) {
      const cn = cur.native;
      if (!cn) break;
      if (sizeDelta) {
        const nextSize = (typeof cn.subtreeSize === 'number' ? cn.subtreeSize : 1) + sizeDelta;
        cn.subtreeSize = nextSize > 1 ? nextSize : 1;
      }
      if (nonLeafDelta) {
        const nextNl = (typeof cn.subtreeNonLeafCount === 'number' ? cn.subtreeNonLeafCount : 0) + nonLeafDelta;
        cn.subtreeNonLeafCount = nextNl > 0 ? nextNl : 0;
      }
      cur = cn.parent;
      steps += 1;
    }
    if (steps > 4) {
      this._chargeFindViewWork(steps);
    }
  }

  _ensureViewNative(viewObj, classType) {
    this._requireInstanceReceiver(viewObj, 'android.view.View');
    if (!viewObj.native) {
      this.vm.chargeHeap(384, 'View native');
      viewObj.native = {
        uid: this._nextViewSeq++,
        id: 0,
        idName: null,
        className: descriptorToClassName(classType || viewObj.classType),
        text: '',
        hint: '',
        tag: null,
        orientation: 'vertical',
        visibility: 0, // VISIBLE
        backgroundColor: null,
        textColor: null,
        textSize: null,
        padding: null,
        parent: null,
        children: [],
        subtreeHeight: 0,
        childHeightCounts: null,
        subtreeZeroIdCount: 1,
        subtreeSize: 1,
        subtreeNonLeafCount: 0,
        zeroIdChildren: null,
        _maxZeroIdSeq: 0,
        _zeroIdHeap: null,
        childrenById: null,
        nonLeafChildren: null,
        _maxNonLeafSeq: 0,
        _nonLeafOrderDirty: false,
        _treeVersion: 0,
        _attachSeq: 0,
        onClickListener: null,
        onClickMethodName: null,
      };
    } else {
      if (typeof viewObj.native !== 'object' || !Array.isArray(viewObj.native.children)) {
        this._throwGuest(
          'Ljava/lang/ClassCastException;',
          `Receiver ${viewObj.classType} is not a valid android.view.View`
        );
      }
      if (viewObj.native.parent === undefined) {
        viewObj.native.parent = null;
      }
      if (typeof viewObj.native.subtreeHeight !== 'number') {
        viewObj.native.subtreeHeight = 0;
      }
      if (viewObj.native.childHeightCounts === undefined) {
        viewObj.native.childHeightCounts = null;
      }
      if (typeof viewObj.native.subtreeZeroIdCount !== 'number') {
        viewObj.native.subtreeZeroIdCount = safeToInt(viewObj.native.id) === 0 ? 1 : 0;
      }
      if (typeof viewObj.native.subtreeSize !== 'number') {
        viewObj.native.subtreeSize = 1;
      }
      if (typeof viewObj.native.subtreeNonLeafCount !== 'number') {
        viewObj.native.subtreeNonLeafCount = viewObj.native.children.length > 0 ? 1 : 0;
      }
      if (viewObj.native.zeroIdChildren === undefined) {
        viewObj.native.zeroIdChildren = null;
        viewObj.native._maxZeroIdSeq = 0;
        viewObj.native._zeroIdHeap = null;
      }
      if (viewObj.native.childrenById === undefined) {
        viewObj.native.childrenById = null;
      }
      if (viewObj.native.nonLeafChildren === undefined) {
        viewObj.native.nonLeafChildren = null;
        viewObj.native._maxNonLeafSeq = 0;
        viewObj.native._nonLeafOrderDirty = false;
      }
      if (typeof viewObj.native._treeVersion !== 'number') {
        viewObj.native._treeVersion = 0;
      }
      if (typeof viewObj.native._attachSeq !== 'number') {
        viewObj.native._attachSeq = 0;
      }
    }
    return viewObj.native;
  }

  _computeSubtreeHeightFromMap(counts) {
    if (!counts || counts.size === 0) return 0;
    let maxH = -1;
    for (const h of counts.keys()) {
      if (h > maxH) maxH = h;
    }
    return maxH >= 0 ? maxH + 1 : 0;
  }

  _propagateViewHeightChange(startParent, oldChildHeight, newChildHeight) {
    let cur = startParent;
    let prevH = oldChildHeight;
    let nextH = newChildHeight;
    let steps = 0;
    let mapScanWork = 0;
    while (cur && prevH !== nextH && steps <= MAX_VIEW_DEPTH + 1) {
      steps += 1;
      const cn = cur.native;
      if (!cn) break;
      if (!cn.childHeightCounts) {
        cn.childHeightCounts = new Map();
      }
      if (prevH >= 0) {
        const oldCnt = cn.childHeightCounts.get(prevH) || 0;
        if (oldCnt <= 1) cn.childHeightCounts.delete(prevH);
        else cn.childHeightCounts.set(prevH, oldCnt - 1);
      }
      if (nextH >= 0) {
        cn.childHeightCounts.set(nextH, (cn.childHeightCounts.get(nextH) || 0) + 1);
      }
      const curOldH = typeof cn.subtreeHeight === 'number' ? cn.subtreeHeight : 0;
      let curNewH;
      if (nextH >= 0 && nextH + 1 > curOldH) {
        curNewH = nextH + 1;
      } else if (prevH >= 0 && prevH + 1 === curOldH && !cn.childHeightCounts.has(prevH)) {
        mapScanWork += cn.childHeightCounts.size;
        curNewH = this._computeSubtreeHeightFromMap(cn.childHeightCounts);
      } else {
        curNewH = curOldH;
      }
      if (curNewH === curOldH) break;
      cn.subtreeHeight = curNewH;
      prevH = curOldH;
      nextH = curNewH;
      cur = cn.parent;
    }
    const totalWork = steps + mapScanWork;
    if (totalWork > 4) {
      this._chargeFindViewWork(totalWork);
    }
  }

  _createViewObject(classType, opts = {}) {
    this.vm.checkHeapBudget(128 + 384, 'View creation');
    const obj = this.vm.createObject(classType);
    const n = this._ensureViewNative(obj, classType);
    if (opts.id !== undefined) {
      const nextId = safeToInt(opts.id);
      const prevId = n.id;
      n.id = nextId;
      if (nextId !== prevId) {
        if (prevId === 0 && nextId !== 0) {
          n.subtreeZeroIdCount = Math.max(0, (n.subtreeZeroIdCount || 0) - 1);
        } else if (prevId !== 0 && nextId === 0) {
          n.subtreeZeroIdCount = (n.subtreeZeroIdCount || 0) + 1;
        }
      }
    }
    if (opts.idName) n.idName = opts.idName;
    if (opts.text !== undefined && opts.text !== null) n.text = String(opts.text);
    if (opts.hint !== undefined && opts.hint !== null) n.hint = String(opts.hint);
    if (opts.tag !== undefined) n.tag = opts.tag;
    if (opts.orientation) n.orientation = opts.orientation;
    if (opts.visibility !== undefined) n.visibility = safeToInt(opts.visibility);
    if (opts.backgroundColor !== undefined) n.backgroundColor = opts.backgroundColor;
    if (opts.textColor !== undefined) n.textColor = opts.textColor;
    if (opts.textSize !== undefined) n.textSize = opts.textSize;
    if (opts.padding !== undefined) n.padding = opts.padding;
    if (opts.onClickMethodName) n.onClickMethodName = opts.onClickMethodName;
    return obj;
  }

  _inflateXmlNode(xmlNode, depth = 0) {
    if (depth > MAX_VIEW_DEPTH) {
      this._throwGuest('Ljava/lang/IllegalStateException;', `View layout depth exceeded maximum (${MAX_VIEW_DEPTH})`);
    }
    const rawTag = xmlNode.tag || 'View';
    const classType =
      VIEW_SHORT_TO_DESC[rawTag] ??
      (rawTag.includes('.') ? classNameToDescriptor(rawTag) : ANDROID_CLASS_DESCRIPTORS.VIEW);

    let viewId = 0;
    let idName = null;

    // Look for android:id in typedAttrs first so we preserve numeric TYPE_REFERENCE ID!
    const typedId = (xmlNode.typedAttrs ?? []).find((a) => a.name === 'id');
    if (typedId) {
      if (
        (typedId.dataType === RES_VALUE_TYPES.TYPE_REFERENCE || typedId.dataType === RES_VALUE_TYPES.TYPE_INT_DEC) &&
        typedId.data !== 0
      ) {
        viewId = safeToInt(typedId.data);
        const entry = this.apk?.resources?.resolve?.(viewId >>> 0);
        if (entry?.keyName) idName = entry.keyName;
      } else if (typeof typedId.rawValue === 'string') {
        const refMatch = /^@\+?id\/(.+)$/.exec(typedId.rawValue);
        if (refMatch) {
          idName = refMatch[1];
          const lookedUp = this.apk?.resources?.getIdByName?.(`@id/${idName}`);
          if (lookedUp !== null && lookedUp !== undefined) viewId = safeToInt(lookedUp);
        }
      }
    }

    const getStrAttr = (name) => {
      const val = xmlNode.attrs?.[`android:${name}`] ?? xmlNode.attrs?.[name];
      if (val === undefined || val === null) return undefined;
      if (typeof val === 'string' && val.startsWith('@') && this.apk?.resources) {
        const res = this.apk.resources.getString(val);
        if (res !== null) return res;
      }
      return val;
    };

    const rawOrient = getStrAttr('orientation');
    const orientation =
      rawOrient === 0 || rawOrient === '0' || rawOrient === 'horizontal' ? 'horizontal' : 'vertical';

    const rawVis = getStrAttr('visibility');
    let visibility = 0;
    if (rawVis === 'invisible' || rawVis === 4) visibility = 4;
    else if (rawVis === 'gone' || rawVis === 8) visibility = 8;

    const viewObj = this._createViewObject(classType, {
      id: viewId,
      idName,
      text: getStrAttr('text') ?? '',
      hint: getStrAttr('hint') ?? '',
      tag: getStrAttr('tag') ?? null,
      orientation,
      visibility,
      backgroundColor: getStrAttr('background') ?? null,
      textColor: getStrAttr('textColor') ?? null,
      textSize: getStrAttr('textSize') ?? null,
      padding: getStrAttr('padding') ?? null,
      onClickMethodName: getStrAttr('onClick') ?? null,
    });

    for (const childNode of xmlNode.children ?? []) {
      const childView = this._inflateXmlNode(childNode, depth + 1);
      childView.native.parent = viewObj;
      childView.native._attachSeq = this._nextAttachSeq++;
      viewObj.native.children.push(childView);
      const childId = safeToInt(childView.native.id);
      if (childId !== 0) {
        this._addToViewsById(childView, childId);
        this._addChildById(viewObj.native, childId, childView);
      }
      const ch = typeof childView.native.subtreeHeight === 'number' ? childView.native.subtreeHeight : 0;
      if (childView.native.subtreeZeroIdCount > 0) {
        viewObj.native.subtreeZeroIdCount = (viewObj.native.subtreeZeroIdCount || 0) + childView.native.subtreeZeroIdCount;
        this._addZeroIdChild(viewObj.native, childView);
      }
      viewObj.native.subtreeSize += typeof childView.native.subtreeSize === 'number' ? childView.native.subtreeSize : 1;
      viewObj.native.subtreeNonLeafCount +=
        typeof childView.native.subtreeNonLeafCount === 'number' ? childView.native.subtreeNonLeafCount : 0;
      if (childView.native.children.length > 0) {
        this._addNonLeafChild(viewObj.native, childView);
      }
      if (!viewObj.native.childHeightCounts) {
        viewObj.native.childHeightCounts = new Map();
      }
      viewObj.native.childHeightCounts.set(ch, (viewObj.native.childHeightCounts.get(ch) || 0) + 1);
      if (ch + 1 > viewObj.native.subtreeHeight) {
        viewObj.native.subtreeHeight = ch + 1;
      }
    }

    if (viewObj.native.children.length > 0) {
      viewObj.native.subtreeNonLeafCount += 1;
    }

    return viewObj;
  }

  _inflateLayoutById(resId) {
    const idU32 = safeToInt(resId) >>> 0;
    const layoutPath = this.apk?.resources?.getLayoutPath?.(idU32);
    if (!layoutPath) {
      this._throwGuest('Ljava/lang/RuntimeException;', `Layout resource not found: 0x${idU32.toString(16)}`);
    }
    const rawBytes = this.apk?.res?.get(layoutPath);
    if (!rawBytes) {
      this._throwGuest('Ljava/lang/RuntimeException;', `Layout file missing in APK: ${layoutPath}`);
    }
    const remainingVmBytes = Math.max(
      0,
      (this.vm?.maxMemoryBytes ?? 16 * 1024 * 1024) -
        (this.vm?.allocatedHeapBytes ?? 0) -
        (this.vm?.activeStackBytes ?? 0)
    );
    const maxInputBytes = Math.min(2 * 1024 * 1024, Math.max(4096, remainingVmBytes * 4));
    const maxElements = Math.min(16384, Math.max(32, Math.floor(remainingVmBytes / 32)));
    const maxAttributes = Math.min(65536, Math.max(128, Math.floor(remainingVmBytes / 8)));
    const maxTextBytes = Math.min(2 * 1024 * 1024, Math.max(4096, remainingVmBytes * 2));
    if (rawBytes.byteLength > maxInputBytes) {
      this._throwGuest(
        'Ljava/lang/OutOfMemoryError;',
        `Layout ${layoutPath} (${rawBytes.byteLength} bytes) exceeds VM inflation budget (${maxInputBytes} bytes)`
      );
    }
    let parsed;
    try {
      parsed = parseXmlOrAxml(rawBytes, {
        resources: this.apk.resources,
        maxInputBytes,
        maxElements,
        maxAttributes,
        maxTextBytes,
      });
    } catch (err) {
      this._throwGuest(
        'Landroid/view/InflateException;',
        `Failed to inflate layout ${layoutPath}: ${err?.message ?? err}`
      );
    }
    if (!parsed || !parsed.root) {
      this._throwGuest('Landroid/view/InflateException;', `Failed to inflate layout ${layoutPath}: empty XML root`);
    }
    return this._inflateXmlNode(parsed.root, 0);
  }

  _serializeViewNode(viewObj, visited = new Set(), depth = 0) {
    if (!viewObj || typeof viewObj !== 'object' || !viewObj.native || typeof viewObj.native !== 'object') return null;
    if (depth > MAX_VIEW_DEPTH || visited.has(viewObj)) return null;
    visited.add(viewObj);
    const n = viewObj.native;
    let nodeType = 'container';
    if (n.className === 'android.widget.Button') nodeType = 'button';
    else if (n.className === 'android.widget.EditText') nodeType = 'input';
    else if (n.className === 'android.widget.TextView') nodeType = 'text';
    else if (n.className === 'android.widget.ImageView') nodeType = 'image';
    else if (n.className === 'android.widget.ScrollView') nodeType = 'scroll';

    const uiId = n.idName || (n.id ? `view_${n.id}` : `v_${n.uid}`);
    const out = {
      id: uiId,
      viewId: n.id,
      type: nodeType,
      androidClass: n.className,
      text: n.text,
      visible: n.visibility === 0,
      clickable: Boolean(n.onClickListener || n.onClickMethodName || nodeType === 'button'),
    };
    if (nodeType === 'input') {
      out.value = n.text;
      if (n.hint) out.placeholder = n.hint;
    }
    if (nodeType === 'container' || nodeType === 'scroll') {
      out.orientation = n.orientation;
    }
    if (n.tag !== null && n.tag !== undefined) out.tag = String(n.tag);
    if (n.backgroundColor !== null) out.backgroundColor = n.backgroundColor;
    if (n.textColor !== null) out.textColor = n.textColor;
    if (n.textSize !== null) out.textSize = n.textSize;
    if (Array.isArray(n.children) && n.children.length > 0 && depth < MAX_VIEW_DEPTH) {
      const serializedChildren = [];
      for (const c of n.children) {
        const childOut = this._serializeViewNode(c, visited, depth + 1);
        if (childOut) serializedChildren.push(childOut);
      }
      if (serializedChildren.length > 0) {
        out.children = serializedChildren;
      }
    }
    return out;
  }

  _syncCompositorSurface({ immediate = false } = {}) {
    const compositor = this.services?.compositor;
    if (!compositor || this.finished) return;
    if (!this.rootView) return;
    if (this._finishing && !this.windowId) return;

    if (!this.windowId) {
      const uiTree = this._serializeViewNode(this.rootView);
      const rawTitle = (this.windowTitle && this.windowTitle.trim()) || this.appLabel || this.packageName;
      const title = capString(rawTitle, 512);
      try {
        const win = compositor.createWindow(this.pcb.pid, {
          appId: this.packageName,
          platform: 'android',
          title,
          width: 420,
          height: 700,
          chromeStyle: 'android',
          uiTree,
        });
        this.windowId = win.windowId;
        this._surfaceDirty = false;
      } catch (err) {
        this._translateHostServiceError(err, 'Compositor.createWindow');
      }
      return;
    }

    this._surfaceDirty = true;
    if (immediate) {
      this.flushCompositorSurfaceIfDirty();
    }
  }

  flushCompositorSurfaceIfDirty() {
    if (!this._surfaceDirty) return;
    this._surfaceDirty = false;
    const compositor = this.services?.compositor;
    if (!compositor || this.finished || !this.windowId || !this.rootView) return;
    const uiTree = this._serializeViewNode(this.rootView);
    const rawTitle = (this.windowTitle && this.windowTitle.trim()) || this.appLabel || this.packageName;
    const title = capString(rawTitle, 512);
    try {
      compositor.updateSurface(this.windowId, {
        title,
        uiTree,
      });
    } catch (err) {
      this._recordInternalLog('W', 'Compositor', `Surface update skipped: ${err?.message ?? err}`);
    }
  }

  _isDescendantOf(candidate, root) {
    let cur = candidate?.native?.parent ?? null;
    let hops = 1;
    while (cur !== null && cur !== root && hops < MAX_VIEW_DEPTH) {
      cur = cur.native?.parent ?? null;
      hops += 1;
    }
    if (hops > 1) {
      this._chargeFindViewWork(hops);
    }
    return cur === root;
  }

  _pathFromRootToDescendant(candidate, root) {
    const revPath = [];
    let cur = candidate;
    let hops = 0;
    while (cur && hops < MAX_VIEW_DEPTH) {
      const parent = cur.native?.parent;
      if (!parent) return null;
      revPath.push(cur);
      if (parent === root) return revPath;
      cur = parent;
      hops += 1;
    }
    return null;
  }

  _isEarlierPreOrder(revPathA, revPathB) {
    let ia = revPathA.length - 1;
    let ib = revPathB.length - 1;
    while (ia >= 0 && ib >= 0) {
      const nodeA = revPathA[ia];
      const nodeB = revPathB[ib];
      if (nodeA !== nodeB) {
        return (nodeA.native?._attachSeq ?? 0) < (nodeB.native?._attachSeq ?? 0);
      }
      ia -= 1;
      ib -= 1;
    }
    return revPathA.length < revPathB.length;
  }

  _cacheFindViewResult(treeRoot, viewObj, wantId, result) {
    if (!treeRoot?.native) return result;
    if (this._findViewCacheSize >= MAX_FIND_VIEW_CACHE_ENTRIES) {
      this._findViewCache.clear();
      this._findViewCacheSize = 0;
    }
    const version = treeRoot.native._treeVersion | 0;
    let treeCache = this._findViewCache.get(treeRoot);
    if (!treeCache || treeCache.version !== version) {
      if (treeCache) {
        this._dropTreeCache(treeRoot);
      }
      treeCache = { version, byId: new Map() };
      this._findViewCache.set(treeRoot, treeCache);
    }
    let byNode = treeCache.byId.get(wantId);
    if (!byNode) {
      byNode = new Map();
      treeCache.byId.set(wantId, byNode);
    }
    if (!byNode.has(viewObj)) {
      this._findViewCacheSize += 1;
    }
    byNode.set(viewObj, result);
    return result;
  }

  _findViewById(viewObj, targetId) {
    if (!viewObj || typeof viewObj !== 'object' || !viewObj.native || typeof viewObj.native !== 'object') return null;
    const wantId = safeToInt(targetId);
    if (safeToInt(viewObj.native.id) === wantId) return viewObj;
    const rootChildren = viewObj.native.children;
    if (!Array.isArray(rootChildren) || rootChildren.length === 0) return null;

    const treeRoot = this._getViewTreeRoot(viewObj);
    const treeVersion = treeRoot?.native?._treeVersion | 0;
    const treeCache = this._findViewCache.get(treeRoot);
    if (treeCache && treeCache.version === treeVersion) {
      const byNode = treeCache.byId.get(wantId);
      if (byNode && byNode.has(viewObj)) {
        return byNode.get(viewObj);
      }
    }

    if (wantId === 0) {
      if ((viewObj.native.subtreeZeroIdCount | 0) <= 0) {
        return this._cacheFindViewResult(treeRoot, viewObj, 0, null);
      }
      let cur = viewObj;
      let depth = 0;
      let found = null;
      while (cur && depth < MAX_VIEW_DEPTH) {
        const firstZeroChild = this._getFirstZeroIdChild(cur.native);
        if (!firstZeroChild) break;
        depth += 1;
        if (safeToInt(firstZeroChild.native.id) === 0) {
          found = firstZeroChild;
          break;
        }
        cur = firstZeroChild;
      }
      if (depth > 4) {
        this._chargeFindViewWork(depth);
      }
      return this._cacheFindViewResult(treeRoot, viewObj, 0, found);
    }

    const entry = this._viewsById.get(wantId);
    if (!entry) {
      return this._cacheFindViewResult(treeRoot, viewObj, wantId, null);
    }

    if (!(entry instanceof Set)) {
      const hit = this._isDescendantOf(entry, viewObj) ? entry : null;
      return this._cacheFindViewResult(treeRoot, viewObj, wantId, hit);
    }

    const candidates = entry;
    if (candidates.size === 0) {
      return this._cacheFindViewResult(treeRoot, viewObj, wantId, null);
    }

    if (candidates.size === 1) {
      const only = candidates.values().next().value;
      const hit = this._isDescendantOf(only, viewObj) ? only : null;
      return this._cacheFindViewResult(treeRoot, viewObj, wantId, hit);
    }

    // Flat ViewGroup fast path: zero non-leaf children -> O(1) direct childrenById lookup!
    const rootNonLeaves = viewObj.native.nonLeafChildren;
    if (!rootNonLeaves || rootNonLeaves.size === 0) {
      const directHit = this._getFirstDirectChildById(viewObj.native, wantId);
      return this._cacheFindViewResult(treeRoot, viewObj, wantId, directHit);
    }

    // Choose optimal path: only select candidate scan when candidates * 16 <= subtreeNonLeaves (R1-6)
    const subtreeNonLeaves = Math.max(1, viewObj.native.subtreeNonLeafCount | 0);
    const subtreeSize = Math.max(1, viewObj.native.subtreeSize | 0);
    if (candidates.size > 0 && candidates.size * 16 <= subtreeNonLeaves && candidates.size < subtreeSize) {
      let bestNode = null;
      let bestRevPath = null;
      let pendingWork = 0;
      for (const cand of candidates) {
        if (cand === viewObj) continue;
        // Zero-alloc ancestor walk first; only allocate revPath on confirmed descendants!
        let cur = cand.native?.parent ?? null;
        let hops = 1;
        while (cur !== null && cur !== viewObj && hops < MAX_VIEW_DEPTH) {
          cur = cur.native?.parent ?? null;
          hops += 1;
        }
        pendingWork += hops;
        if (pendingWork >= 64) {
          this._chargeFindViewWork(pendingWork);
          pendingWork = 0;
        }
        if (cur !== viewObj) continue;
        const revPath = this._pathFromRootToDescendant(cand, viewObj);
        if (!revPath) continue;
        pendingWork += revPath.length;
        if (pendingWork >= 64) {
          this._chargeFindViewWork(pendingWork);
          pendingWork = 0;
        }
        if (!bestNode || this._isEarlierPreOrder(revPath, bestRevPath)) {
          bestNode = cand;
          bestRevPath = revPath;
        }
      }
      if (pendingWork > 0) {
        this._chargeFindViewWork(pendingWork);
      }
      return this._cacheFindViewResult(treeRoot, viewObj, wantId, bestNode);
    }

    // Pre-order DFS over ONLY non-leaf containers, using O(1) childrenById at every level
    // and strict _attachSeq comparison against directMatch to preserve exact Android pre-order DFS.
    const stack = [];
    const pushFrame = (node) => {
      const dm = this._getFirstDirectChildById(node.native, wantId);
      const dmSeq = dm ? (dm.native._attachSeq ?? 0) : Infinity;
      const nls = this._getOrderedNonLeafChildren(node.native);
      stack.push({
        directMatch: dm,
        directMatchSeq: dmSeq,
        nlIter: nls ? nls.values() : null,
      });
    };
    pushFrame(viewObj);
    let visited = 1;
    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      if (top.nlIter && stack.length < MAX_VIEW_DEPTH) {
        const nextStep = top.nlIter.next();
        if (!nextStep.done) {
          const nl = nextStep.value;
          const nlSeq = nl.native?._attachSeq ?? 0;
          if (nlSeq >= top.directMatchSeq) {
            if (visited > 0) this._chargeFindViewWork(visited);
            return this._cacheFindViewResult(treeRoot, viewObj, wantId, top.directMatch);
          }
          visited += 1;
          if ((visited & 63) === 0) {
            this._chargeFindViewWork(64);
            visited = 0;
          }
          pushFrame(nl);
          continue;
        }
      }
      if (top.directMatch) {
        if (visited > 0) this._chargeFindViewWork(visited);
        return this._cacheFindViewResult(treeRoot, viewObj, wantId, top.directMatch);
      }
      stack.pop();
    }
    if (visited > 0) this._chargeFindViewWork(visited);
    return this._cacheFindViewResult(treeRoot, viewObj, wantId, null);
  }

  _findViewByEvent(viewObj, event) {
    if (!viewObj || typeof viewObj !== 'object' || !viewObj.native || typeof viewObj.native !== 'object') return null;
    const target = event?.targetId ?? event?.id ?? event?.action ?? null;
    const numericId = typeof event?.viewId === 'number' ? safeToInt(event.viewId) : null;

    const search = (node, mode, visited, depth) => {
      if (!node || typeof node !== 'object' || !node.native || typeof node.native !== 'object') return null;
      if (depth > MAX_VIEW_DEPTH || visited.has(node)) return null;
      visited.add(node);
      const n = node.native;
      const uiId = n.idName || (n.id ? `view_${n.id}` : `v_${n.uid}`);
      if (mode === 'exact') {
        if (numericId !== null && safeToInt(n.id) === numericId) return node;
        if (target !== null && (n.idName === target || uiId === target || String(n.id) === String(target))) {
          return node;
        }
      } else if (mode === 'tag_or_text') {
        if (target !== null && (n.tag === target || n.text === target)) {
          return node;
        }
      }
      if (depth >= MAX_VIEW_DEPTH || !Array.isArray(n.children)) return null;
      for (const child of n.children) {
        const hit = search(child, mode, visited, depth + 1);
        if (hit) return hit;
      }
      return null;
    };

    return search(viewObj, 'exact', new Set(), 0) ?? search(viewObj, 'tag_or_text', new Set(), 0);
  }

  /**
   * Handles incoming Compositor UI / Intent / Window events and queues real Dalvik callbacks.
   */
  handleEvent(event) {
    if (!event || typeof event !== 'object') return;
    if (this.finished || this._finishing) return;
    const type = event.type;

    if (type === 'window_close') {
      this._finishActivity();
      return;
    }

    if (type === 'intent' && event.intent) {
      const newIntent = this._createIntentFromLaunch(event.intent);
      this.launchIntent = newIntent;
      if (this.activity) {
        this.activity.native.intent = newIntent;
        const onNewIntent = this.vm.findMethod(
          this.activity.classType,
          'onNewIntent(Landroid/content/Intent;)V',
          { includeSuper: true }
        );
        if (onNewIntent && onNewIntent.code) {
          this._enqueueCallback({
            classType: this.activity.classType,
            signature: 'onNewIntent(Landroid/content/Intent;)V',
            args: [newIntent],
            receiver: this.activity,
          });
        }
      }
      return;
    }

    if (!this.rootView) return;

    if (type === 'input' || type === 'change' || type === 'text_input') {
      const targetView = this._findViewByEvent(this.rootView, event);
      if (targetView) {
        const nextText = String(event.value ?? event.text ?? '');
        if (nextText !== targetView.native.text) {
          targetView.native.text = nextText;
          this._syncCompositorSurface({ immediate: true });
        }
      }
      return;
    }

    if (type === 'keydown') {
      const targetView = this._findViewByEvent(this.rootView, event);
      if (targetView && targetView.native.className === 'android.widget.EditText') {
        const key = String(event.key ?? '');
        const prevText = targetView.native.text;
        if (key === 'Backspace') {
          targetView.native.text = targetView.native.text.slice(0, -1);
        } else if (key.length === 1) {
          targetView.native.text += key;
        }
        if (targetView.native.text !== prevText) {
          this._syncCompositorSurface({ immediate: true });
        }
      }
      return;
    }

    if (type === 'click' || type === 'action') {
      const targetView = this._findViewByEvent(this.rootView, event);
      if (!targetView) return;
      const n = targetView.native;
      if (n.onClickListener) {
        this._enqueueCallback({
          classType: n.onClickListener.classType,
          signature: 'onClick(Landroid/view/View;)V',
          args: [targetView],
          receiver: n.onClickListener,
        });
      } else if (n.onClickMethodName && this.activity) {
        this._enqueueCallback({
          classType: this.activity.classType,
          signature: `${n.onClickMethodName}(Landroid/view/View;)V`,
          args: [targetView],
          receiver: this.activity,
        });
      }
    }
  }

  _finalizeActivityFinish() {
    if (this.finished) return;
    this.finished = true;
    this._finishing = false;
    this._surfaceDirty = false;
    this.activityState = 'DESTROYED';
    this._detachEventListeners();
    if (this.windowId && this.services?.compositor) {
      const wid = this.windowId;
      this.windowId = null;
      try {
        this.services.compositor.closeWindow(wid, { notifyProcess: false, reason: 'activity_finished' });
      } catch (err) {
        this._recordInternalLog('W', 'Activity', `Window close ignored: ${err?.message ?? err}`);
      }
    }
    this._onFinish();
  }

  _finishActivity() {
    if (this.finished || this._finishing) return;
    this._finishing = true;

    const teardownCalls = [];
    if (this.activity) {
      const actClass = this.activity.classType;
      const stages = [
        { sig: 'onPause()V', phase: 'PAUSED' },
        { sig: 'onStop()V', phase: 'STOPPED' },
        { sig: 'onDestroy()V', phase: 'DESTROYED' },
      ];
      for (const stage of stages) {
        const m = this.vm.findMethod(actClass, stage.sig, { includeSuper: true });
        if (m && m.code) {
          teardownCalls.push({
            classType: actClass,
            signature: stage.sig,
            args: [],
            receiver: this.activity,
            phase: stage.phase,
          });
        }
      }
    }

    if (teardownCalls.length === 0) {
      this._finalizeActivityFinish();
      return;
    }

    if (this._beginTeardown) {
      this._beginTeardown(teardownCalls);
    } else {
      for (const call of teardownCalls) {
        this._enqueueCallback(call);
      }
    }
  }

  // ===========================================================================
  // Logging Helper
  // ===========================================================================

  _recordInternalLog(level, tag, message) {
    const storedTag = capString(tag ?? 'Android', MAX_LOG_TAG_CHARS);
    const storedMessage = capString(message ?? '', MAX_LOG_MESSAGE_CHARS);
    const entry = {
      level,
      tag: storedTag,
      message: storedMessage,
      pid: this.pcb?.pid ?? null,
      appId: this.packageName,
      ts: new Date().toISOString(),
    };
    pushBounded(this.logs, entry, MAX_BRIDGE_LOGS);
    const line = `[LOG/${level}] ${entry.tag}: ${entry.message}\n`;
    try {
      this.services?.processManager?.writeStdout?.(this.pcb.pid, line);
    } catch (err) {
      // Process may already be shutting down; retain log in memory buffer.
      entry.stdoutError = err?.message ?? 'stdout_unavailable';
    }
    try {
      this.services?.eventBus?.emit?.('android:log', entry);
    } catch (err) {
      entry.busError = err?.message ?? 'bus_unavailable';
    }
    return line.length;
  }

  // ===========================================================================
  // Static Field Lookup for Framework Classes
  // ===========================================================================

  getStaticField(classType, fieldName, fieldType) {
    if (classType === 'Ljava/lang/System;') {
      if (fieldName === 'out') return this._stdoutStream;
      if (fieldName === 'err') return this._stderrStream;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.INTENT) {
      const constants = {
        ACTION_MAIN: 'android.intent.action.MAIN',
        ACTION_VIEW: 'android.intent.action.VIEW',
        ACTION_SEND: 'android.intent.action.SEND',
        ACTION_EDIT: 'android.intent.action.EDIT',
        EXTRA_TEXT: 'android.intent.extra.TEXT',
        EXTRA_SUBJECT: 'android.intent.extra.SUBJECT',
        CATEGORY_LAUNCHER: 'android.intent.category.LAUNCHER',
        CATEGORY_DEFAULT: 'android.intent.category.DEFAULT',
        FLAG_ACTIVITY_NEW_TASK: 0x10000000,
        FLAG_ACTIVITY_CLEAR_TOP: 0x04000000,
        FLAG_ACTIVITY_SINGLE_TOP: 0x20000000,
      };
      if (Object.prototype.hasOwnProperty.call(constants, fieldName)) return constants[fieldName];
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.CONTEXT) {
      const ctxConsts = {
        MODE_PRIVATE: 0,
        MODE_APPEND: 32768,
        CLIPBOARD_SERVICE: 'clipboard',
        NOTIFICATION_SERVICE: 'notification',
      };
      if (Object.prototype.hasOwnProperty.call(ctxConsts, fieldName)) return ctxConsts[fieldName];
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.VIEW) {
      if (fieldName === 'VISIBLE') return 0;
      if (fieldName === 'INVISIBLE') return 4;
      if (fieldName === 'GONE') return 8;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.LINEAR_LAYOUT) {
      if (fieldName === 'HORIZONTAL') return 0;
      if (fieldName === 'VERTICAL') return 1;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.TOAST) {
      if (fieldName === 'LENGTH_SHORT') return 0;
      if (fieldName === 'LENGTH_LONG') return 1;
    }
    if (fieldType === 'J') return 0n;
    if (fieldType?.startsWith('L') || fieldType?.startsWith('[')) return null;
    return 0;
  }

  // ===========================================================================
  // Primary Dalvik -> Framework Invocation Dispatch
  // ===========================================================================

  invoke({ classType, declaredClassType, methodName, descriptor, receiver, args }) {
    // 1. java.lang.Object / Class / Throwable / Exceptions
    if (methodName === '<init>') {
      return this._handleConstructor(classType, declaredClassType, descriptor, receiver, args);
    }

    // java.lang.String
    if (classType === 'Ljava/lang/String;' || declaredClassType === 'Ljava/lang/String;') {
      return this._handleString(methodName, descriptor, receiver, args);
    }

    // java.lang.StringBuilder / StringBuffer
    if (classType === 'Ljava/lang/StringBuilder;' || classType === 'Ljava/lang/StringBuffer;') {
      return this._handleStringBuilder(classType, methodName, descriptor, receiver, args);
    }

    // Boxed primitives & Math & System & PrintStream
    if (classType === 'Ljava/lang/Integer;') return this._handleInteger(methodName, descriptor, receiver, args);
    if (classType === 'Ljava/lang/Long;') return this._handleLong(methodName, descriptor, receiver, args);
    if (classType === 'Ljava/lang/Float;' || classType === 'Ljava/lang/Double;') {
      return this._handleFloatDouble(classType, methodName, descriptor, receiver, args);
    }
    if (classType === 'Ljava/lang/Boolean;') return this._handleBoolean(methodName, receiver, args);
    if (classType === 'Ljava/lang/Math;') return this._handleMath(methodName, descriptor, args);
    if (classType === 'Ljava/lang/System;') return this._handleSystem(methodName, args);
    if (classType === 'Ljava/io/PrintStream;') return this._handlePrintStream(methodName, receiver, args);

    // Collections
    if (classType === 'Ljava/util/ArrayList;' || declaredClassType === 'Ljava/util/List;') {
      return this._handleArrayList(methodName, descriptor, receiver, args);
    }
    if (classType === 'Ljava/util/HashMap;' || declaredClassType === 'Ljava/util/Map;') {
      return this._handleHashMap(methodName, receiver, args);
    }
    if (classType === 'Ljava/util/HashSet;' || declaredClassType === 'Ljava/util/Set;') {
      return this._handleHashSet(methodName, receiver, args);
    }

    // File I/O & Environment
    if (classType === ANDROID_CLASS_DESCRIPTORS.ENVIRONMENT) return this._handleEnvironment(methodName, args);
    if (classType === ANDROID_CLASS_DESCRIPTORS.FILE) return this._handleFile(methodName, receiver, args);
    if (classType === ANDROID_CLASS_DESCRIPTORS.FILE_OUTPUT_STREAM) {
      return this._handleFileOutputStream(methodName, receiver, args);
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.FILE_INPUT_STREAM) {
      return this._handleFileInputStream(methodName, receiver, args);
    }

    // Android Framework Classes
    if (classType === ANDROID_CLASS_DESCRIPTORS.LOG) return this._handleLog(methodName, args);
    if (classType === ANDROID_CLASS_DESCRIPTORS.TOAST) return this._handleToast(methodName, receiver, args);
    if (classType === ANDROID_CLASS_DESCRIPTORS.BUNDLE) return this._handleBundle(methodName, receiver, args);
    if (classType === ANDROID_CLASS_DESCRIPTORS.URI) return this._handleUri(methodName, receiver, args);
    if (classType === ANDROID_CLASS_DESCRIPTORS.INTENT) return this._handleIntent(methodName, receiver, args);
    if (
      classType === ANDROID_CLASS_DESCRIPTORS.SHARED_PREFS ||
      declaredClassType === ANDROID_CLASS_DESCRIPTORS.SHARED_PREFS
    ) {
      return this._handleSharedPrefs(methodName, receiver, args);
    }
    if (
      classType === ANDROID_CLASS_DESCRIPTORS.SHARED_PREFS_EDITOR ||
      declaredClassType === ANDROID_CLASS_DESCRIPTORS.SHARED_PREFS_EDITOR
    ) {
      return this._handleSharedPrefsEditor(methodName, receiver, args);
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.CLIP_DATA) return this._handleClipData(methodName, receiver, args);
    if (classType === ANDROID_CLASS_DESCRIPTORS.CLIP_DATA_ITEM) {
      if (methodName === 'getText' || methodName === 'coerceToText') return receiver?.native?.text ?? '';
      return this._coerceGuestString(receiver?.native?.text ?? '', 'ClipData.Item');
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.CLIPBOARD_MANAGER) {
      return this._handleClipboardManager(methodName, args);
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.NOTIFICATION_BUILDER) {
      return this._handleNotificationBuilder(methodName, receiver, args);
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.NOTIFICATION_MANAGER) {
      return this._handleNotificationManager(methodName, args);
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.CONTENT_VALUES) {
      return this._handleContentValues(methodName, receiver, args);
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.CONTENT_RESOLVER) {
      return this._handleContentResolver(methodName, receiver, args);
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.CURSOR) {
      return this._handleCursor(methodName, receiver, args);
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.RESOURCES) {
      return this._handleResources(methodName, args);
    }

    // Android Views & Widgets (matches subclasses like Button -> TextView -> View)
    if (
      this.vm.isAssignableTo(classType, ANDROID_CLASS_DESCRIPTORS.VIEW) ||
      this.vm.isAssignableTo(declaredClassType, ANDROID_CLASS_DESCRIPTORS.VIEW)
    ) {
      return this._handleView(methodName, receiver, args);
    }

    // Android Activity / Service / Context (matches app subclasses like MainActivity -> Activity -> Context)
    if (
      this.vm.isAssignableTo(classType, ANDROID_CLASS_DESCRIPTORS.CONTEXT) ||
      this.vm.isAssignableTo(declaredClassType, ANDROID_CLASS_DESCRIPTORS.CONTEXT)
    ) {
      return this._handleActivityOrContext(methodName, receiver, args);
    }

    // java.lang.Throwable methods
    if (this.vm.isAssignableTo(classType, 'Ljava/lang/Throwable;')) {
      if (methodName === 'getMessage') return receiver?.fields?.detailMessage ?? null;
      if (methodName === 'toString') return this._coerceGuestString(receiver, 'Throwable.toString');
    }

    // java.lang.Class methods
    if (classType === 'Ljava/lang/Class;') {
      const rawTarget = receiver?.targetType ?? 'Ljava/lang/Object;';
      const rawLen =
        typeof rawTarget === 'string' && rawTarget.startsWith('L') && rawTarget.endsWith(';')
          ? Math.max(0, rawTarget.length - 2)
          : String(rawTarget).length;
      if (methodName === 'getName') {
        if (rawLen > 0) this.vm.checkHeapBudget(rawLen * 2, 'Class.getName');
        const full = descriptorToClassName(rawTarget);
        if (full.length > 0) this.vm.chargeHeap(full.length * 2, 'Class.getName');
        return full;
      }
      if (methodName === 'getSimpleName') {
        const lastSlash = typeof rawTarget === 'string' ? rawTarget.lastIndexOf('/') : -1;
        const estSimpleLen = lastSlash >= 0 ? Math.max(0, rawTarget.length - lastSlash - 2) : rawLen;
        if (estSimpleLen > 0) this.vm.checkHeapBudget(estSimpleLen * 2, 'Class.getSimpleName');
        const full = descriptorToClassName(rawTarget);
        const simple = full.split('.').pop() ?? full;
        if (simple.length > 0) this.vm.chargeHeap(simple.length * 2, 'Class.getSimpleName');
        return simple;
      }
      if (methodName === 'toString') {
        this.vm.checkHeapBudget((rawLen + 6) * 2, 'Class.toString');
        const full = descriptorToClassName(rawTarget);
        const out = `class ${full}`;
        this.vm.chargeHeap(out.length * 2, 'Class.toString');
        return out;
      }
    }

    // java.lang.Object base methods
    if (methodName === 'toString') return this._coerceGuestString(receiver, 'Object.toString');
    if (methodName === 'equals') return receiver === args[0];
    if (methodName === 'hashCode') return receiver?.id ?? 0;
    if (methodName === 'getClass') return this.vm.createClassObject(this.vm.getObjectType(receiver));

    // Graceful diagnostic log for non-critical unshimmed API
    this._recordInternalLog('W', 'AndroidBridge', `Unimplemented API stubbed: ${classType}->${methodName}${descriptor}`);
    return null;
  }

  _handleConstructor(classType, declaredClassType, descriptor, receiver, args) {
    this._requireInstanceReceiver(receiver, classType || declaredClassType || 'Object');
    if (classType === 'Ljava/lang/String;' || declaredClassType === 'Ljava/lang/String;') {
      // String([B), String([BII), String([C), String([CII), or String(Ljava/lang/String;)
      if (args[0]?.__dalvikType === 'array') {
        const arr = args[0];
        const off = args.length >= 3 ? safeToInt(args[1]) : 0;
        const len = args.length >= 3 ? safeToInt(args[2]) : arr.length;
        if (off < 0 || len < 0 || off + len > arr.length) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `String(array, off, len) out of bounds (off=${off}, len=${len}, length=${arr.length})`
          );
        }
        this.vm.chargeHeap(len * 2, 'String constructor');
        if (arr.elementType === 'C') {
          let text = '';
          const chunkSize = 8192;
          for (let i = 0; i < len; i += chunkSize) {
            const end = Math.min(len, i + chunkSize);
            const codes = new Array(end - i);
            for (let j = i; j < end; j++) codes[j - i] = safeToInt(arr.data[off + j]) & 0xffff;
            text += String.fromCharCode(...codes);
          }
          receiver.native = { text };
        } else {
          const bytes = new Uint8Array(len);
          for (let i = 0; i < len; i++) bytes[i] = safeToInt(arr.data[off + i]) & 0xff;
          receiver.native = { text: TEXT_DECODER.decode(bytes) };
        }
      } else if (args.length > 0) {
        let s;
        if (typeof args[0] === 'string') {
          s = args[0];
          if (s.length > 0) {
            this.vm.chargeHeap(s.length * 2, 'String constructor');
          }
        } else {
          s = this._coerceGuestString(args[0], 'String constructor');
        }
        receiver.native = { text: s };
      } else {
        receiver.native = { text: '' };
      }
      return;
    }
    if (classType === 'Ljava/lang/StringBuilder;' || classType === 'Ljava/lang/StringBuffer;') {
      const label = classType === 'Ljava/lang/StringBuffer;' ? 'StringBuffer' : 'StringBuilder';
      let init = '';
      if (args.length > 0 && (descriptor === '(I)V' || typeof args[0] === 'number' || typeof args[0] === 'bigint')) {
        const cap = safeToInt(args[0]);
        if (cap < 0) {
          this._throwGuest('Ljava/lang/NegativeArraySizeException;', `Negative ${label} capacity: ${cap}`);
        }
        this.vm.checkHeapBudget((receiver.native ? 0 : 128) + cap * 2, `${label}(int)`);
      } else if (
        args.length > 0 &&
        args[0] !== null &&
        args[0] !== undefined &&
        (typeof args[0] === 'string' ||
          args[0]?.classType === ANDROID_CLASS_DESCRIPTORS.STRING ||
          args[0]?.classType === ANDROID_CLASS_DESCRIPTORS.STRING_BUILDER ||
          args[0]?.classType === 'Ljava/lang/StringBuffer;')
      ) {
        init = toJsString(args[0]);
      }
      const baseCost = receiver.native ? 0 : 128;
      if (baseCost + init.length * 2 > 0) {
        this.vm.checkHeapBudget(baseCost + init.length * 2, `${label} constructor`);
      }
      const n = this._ensureStringBuilderNative(receiver, classType);
      if (init.length > 0) {
        this.vm.chargeHeap(init.length * 2, `${label} constructor`);
      }
      n.text = init;
      return;
    }
    if (classType === 'Ljava/util/ArrayList;') {
      if (args.length === 1 && (descriptor === '(I)V' || typeof args[0] === 'number' || typeof args[0] === 'bigint')) {
        const cap = safeToInt(args[0]);
        if (cap < 0) {
          this._throwGuest('Ljava/lang/IllegalArgumentException;', `Illegal ArrayList capacity: ${cap}`);
        }
        this.vm.checkHeapBudget((receiver.native ? 0 : 128) + cap * 8, 'ArrayList(int)');
        const n = this._ensureArrayListNative(receiver);
        n.items.length = 0;
        return;
      }
      if (args.length === 1 && args[0] && typeof args[0] === 'object') {
        if (Array.isArray(args[0].native?.items)) {
          const src = args[0].native.items;
          const baseCost = receiver.native ? 0 : 128;
          this.vm.checkHeapBudget(baseCost + src.length * 16, 'ArrayList(Collection)');
          const n = this._ensureArrayListNative(receiver);
          if (src.length > 0) {
            this.vm.chargeHeap(src.length * 16, 'ArrayList(Collection)');
          }
          const copy = new Array(src.length);
          for (let i = 0; i < src.length; i++) copy[i] = src[i];
          n.items = copy;
          return;
        }
        if (args[0].native?.set instanceof Set) {
          const srcSet = args[0].native.set;
          const baseCost = receiver.native ? 0 : 128;
          this.vm.checkHeapBudget(baseCost + srcSet.size * 16, 'ArrayList(Collection)');
          const n = this._ensureArrayListNative(receiver);
          if (srcSet.size > 0) {
            this.vm.chargeHeap(srcSet.size * 16, 'ArrayList(Collection)');
          }
          const copy = new Array(srcSet.size);
          let k = 0;
          for (const item of srcSet) copy[k++] = item;
          n.items = copy;
          return;
        }
      }
      const n = this._ensureArrayListNative(receiver);
      n.items.length = 0;
      return;
    }
    if (classType === 'Ljava/util/HashMap;') {
      if (args.length >= 1 && (descriptor?.startsWith('(I') || typeof args[0] === 'number' || typeof args[0] === 'bigint')) {
        const cap = safeToInt(args[0]);
        if (cap < 0) {
          this._throwGuest('Ljava/lang/IllegalArgumentException;', `Illegal HashMap capacity: ${cap}`);
        }
        this.vm.checkHeapBudget((receiver.native ? 0 : 256) + cap * 16, 'HashMap(int)');
      }
      const n = this._ensureHashMapNative(receiver);
      n.map.clear();
      return;
    }
    if (classType === 'Ljava/util/HashSet;') {
      if (args.length >= 1 && (descriptor?.startsWith('(I') || typeof args[0] === 'number' || typeof args[0] === 'bigint')) {
        const cap = safeToInt(args[0]);
        if (cap < 0) {
          this._throwGuest('Ljava/lang/IllegalArgumentException;', `Illegal HashSet capacity: ${cap}`);
        }
        this.vm.checkHeapBudget((receiver.native ? 0 : 256) + cap * 16, 'HashSet(int)');
      }
      const n = this._ensureHashSetNative(receiver);
      n.set.clear();
      return;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.BUNDLE) {
      this._ensureBundleNative(receiver);
      return;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.CONTENT_VALUES) {
      this._ensureContentValuesNative(receiver);
      return;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.INTENT) {
      let action = null;
      let dataUri = null;
      let targetPackage = null;
      let targetClass = null;
      if (args.length === 1 && typeof args[0] === 'string') {
        action = args[0];
      } else if (args.length === 2 && typeof args[0] === 'string') {
        action = args[0];
        dataUri = args[1] ? this._coerceGuestString(args[1], 'Intent constructor') : null;
      } else if (args.length === 2 && args[1]?.__dalvikType === 'class') {
        targetPackage = this.packageName;
        targetClass = descriptorToClassName(args[1].targetType);
      }
      const native = this._ensureIntentNative(receiver);
      native.action = action;
      native.dataUri = dataUri;
      native.mimeType = null;
      native.flags = 0;
      native.targetPackage = targetPackage;
      native.targetClass = targetClass;
      return;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.FILE) {
      let path = '';
      if (args.length === 1) {
        path = this._coerceGuestString(args[0], 'File constructor');
      } else if (args.length === 2) {
        const parentEst = args[0] ? this._estimateGuestStringLength(args[0]) : 0;
        const childEst = this._estimateGuestStringLength(args[1]);
        this.vm.checkHeapBudget((parentEst + childEst + 1) * 2, 'File constructor');
        const parent = args[0] ? toJsString(args[0]) : '';
        const child = toJsString(args[1]);
        const joinedLen = parent.length + child.length + (parent.endsWith('/') ? 0 : 1);
        if (joinedLen > 0) {
          this.vm.chargeHeap(joinedLen * 2, 'File constructor');
        }
        path = parent.endsWith('/') ? `${parent}${child}` : `${parent}/${child}`;
      }
      receiver.native = { path };
      return;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.FILE_OUTPUT_STREAM) {
      if (args[0] === null || args[0] === undefined) {
        this._throwGuest('Ljava/lang/NullPointerException;', 'FileOutputStream path is null');
      }
      const path = this._coerceGuestString(args[0], 'FileOutputStream');
      const append = Boolean(args[1]);
      this.vm.checkHeapBudget(256, 'FileOutputStream');
      // Authorize write & sandbox immediately on stream open for BOTH append=false & append=true!
      const access = this._resolveVfsAccess(path, 'write');
      const isRoot = this.pcb?.uid === 0;
      if (!append && !isRoot && this._vfsPhysicalWriteBytes + VFS_STAT_READ_COST > MAX_VFS_PHYSICAL_WRITE_BYTES) {
        this._throwGuest(
          'Ljava/io/IOException;',
          `Disk full: physical VFS write quota exceeded (${this._vfsPhysicalWriteBytes + VFS_STAT_READ_COST}/${MAX_VFS_PHYSICAL_WRITE_BYTES} bytes)`
        );
      }
      const { stat: statResult } = this._statCached(access, path, { quotaException: 'Ljava/io/IOException;' });
      const existed = statResult !== null;
      const existingSize =
        existed && typeof statResult?.size === 'number' && Number.isFinite(statResult.size) && statResult.size > 0
          ? statResult.size
          : 0;
      if (existed && statResult?.type === 'dir') {
        this._throwGuest('Ljava/io/FileNotFoundException;', `Is a directory: ${capString(path, 256)}`);
      }
      if (!existed && !isRoot && this._vfsCreateOps >= MAX_VFS_CREATE_OPS) {
        this._throwGuest(
          'Ljava/io/IOException;',
          `No space left on device: process VFS file/directory creation quota exceeded (${this._vfsCreateOps}/${MAX_VFS_CREATE_OPS})`
        );
      }
      let currentFileSize = 0;
      if (append && existed) {
        // Avoid quadratic SQLite blob rewrite on append open of existing file; enforce write permissions directly.
        if (access.canonicalPath === '/proc' || access.canonicalPath.startsWith('/proc/')) {
          this._throwGuest('Ljava/lang/SecurityException;', `Read-only virtual mount /proc: ${capString(path, 256)}`);
        }
        if (typeof access.vfs.userManager?.canWrite === 'function') {
          let allowed = false;
          try {
            allowed = access.vfs.userManager.canWrite({ uid: access.ctx.uid, gid: access.ctx.gid }, statResult);
          } catch (err) {
            this._translateVfsError(err, path);
          }
          if (!allowed) {
            this._throwGuest('Ljava/lang/SecurityException;', `Permission denied writing file: ${capString(path, 256)}`);
          }
        }
        currentFileSize = existingSize;
      } else {
        if (!isRoot && this._vfsPhysicalWriteBytes + VFS_STAT_READ_COST > MAX_VFS_PHYSICAL_WRITE_BYTES) {
          this._throwGuest(
            'Ljava/io/IOException;',
            `Disk full: physical VFS write quota exceeded (${this._vfsPhysicalWriteBytes + VFS_STAT_READ_COST}/${MAX_VFS_PHYSICAL_WRITE_BYTES} bytes)`
          );
        }
        try {
          access.vfs.writeFile(access.canonicalPath, EMPTY_UINT8, {
            append: false,
            mode: 0o644,
            ...access.ctx,
          });
          if (!isRoot) {
            this._vfsPhysicalWriteBytes += VFS_STAT_READ_COST;
          }
          this._invalidateVfsReadCaches();
          if (!isRoot && !existed) {
            this._vfsCreateOps += 1;
          }
        } catch (err) {
          if (!isRoot) {
            this._vfsPhysicalWriteBytes += VFS_STAT_READ_COST;
          }
          this._translateVfsError(err, path);
        }
        currentFileSize = 0;
      }
      this.vm.chargeHeap(256, 'FileOutputStream');
      receiver.native = { path, append, access, hasWritten: false, closed: false, currentFileSize };
      return;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.FILE_INPUT_STREAM) {
      if (args[0] === null || args[0] === undefined) {
        this._throwGuest('Ljava/lang/NullPointerException;', 'FileInputStream path is null');
      }
      const path = this._coerceGuestString(args[0], 'FileInputStream');
      this.vm.checkHeapBudget(256, 'FileInputStream');
      const access = this._resolveVfsAccess(path, 'read');
      const isRoot = this.pcb?.uid === 0;
      const { stat: st, fromCache } = this._statCached(access, path, {
        quotaException: 'Ljava/io/IOException;',
      });
      if (!st) {
        this._throwGuest('Ljava/io/FileNotFoundException;', `File not found: ${capString(path, 256)}`);
      }
      if (st?.type === 'dir') {
        this._throwGuest('Ljava/io/FileNotFoundException;', `Is a directory: ${capString(path, 256)}`);
      }
      const fileSize = typeof st?.size === 'number' && Number.isFinite(st.size) && st.size > 0 ? st.size : 0;
      const isProcPath = access.canonicalPath === '/proc' || access.canonicalPath.startsWith('/proc/');
      if (fileSize === 0 && !isProcPath) {
        if (typeof access.vfs.userManager?.canRead === 'function') {
          let allowed = false;
          try {
            allowed = access.vfs.userManager.canRead({ uid: access.ctx.uid, gid: access.ctx.gid }, st);
          } catch (err) {
            this._translateVfsError(err, path);
          }
          if (!allowed) {
            this._throwGuest('Ljava/lang/SecurityException;', `Permission denied reading file: ${capString(path, 256)}`);
          }
        }
        this.vm.chargeHeap(256, 'FileInputStream');
        receiver.native = { path, bytes: EMPTY_UINT8, pos: 0, closed: false };
        return;
      }
      // Enforce VM heap quota & physical VFS read quota BEFORE reading file bytes into host RAM.
      // _statCached() already charged VFS_STAT_READ_COST when !fromCache; pre-check exact incremental delta.
      this.vm.checkHeapBudget(256 + fileSize, 'FileInputStream');
      const minReadDelta = fromCache
        ? Math.max(VFS_STAT_READ_COST, fileSize)
        : Math.max(0, fileSize - VFS_STAT_READ_COST);
      if (!isRoot && this._vfsPhysicalReadBytes + minReadDelta > MAX_VFS_PHYSICAL_READ_BYTES) {
        this._throwGuest(
          'Ljava/io/IOException;',
          `Read quota exceeded: physical VFS read budget (${this._vfsPhysicalReadBytes + minReadDelta}/${MAX_VFS_PHYSICAL_READ_BYTES} bytes)`
        );
      }
      let data;
      try {
        data = access.vfs.readFile(access.canonicalPath, { ...access.ctx });
      } catch (err) {
        if (!isRoot && fromCache) {
          this._vfsPhysicalReadBytes += err?.code === 'ELOOP' ? 16 * VFS_STAT_READ_COST : VFS_STAT_READ_COST;
        }
        this._translateVfsError(err, path);
      }
      const bytes = data instanceof Uint8Array ? data : TEXT_ENCODER.encode(String(data ?? ''));
      if (!isRoot) {
        this._vfsPhysicalReadBytes += fromCache
          ? Math.max(VFS_STAT_READ_COST, bytes.byteLength)
          : Math.max(0, bytes.byteLength - VFS_STAT_READ_COST);
      }
      this.vm.chargeHeap(256 + bytes.byteLength, 'FileInputStream');
      receiver.native = { path, bytes, pos: 0, closed: false };
      return;
    }
    if (classType === ANDROID_CLASS_DESCRIPTORS.NOTIFICATION_BUILDER) {
      const n = this._ensureNotificationBuilderNative(receiver, args[1] ?? 'default');
      n.channelId = args[1] ?? 'default';
      return;
    }
    if (this.vm.isAssignableTo(classType, ANDROID_CLASS_DESCRIPTORS.VIEW)) {
      this._ensureViewNative(receiver, classType);
      return;
    }
    if (this.vm.isAssignableTo(classType, ANDROID_CLASS_DESCRIPTORS.CONTEXT)) {
      if (!receiver.native) {
        receiver.native = { title: this.appLabel, intent: this.launchIntent };
      }
      return;
    }
    if (this.vm.isAssignableTo(classType, 'Ljava/lang/Throwable;')) {
      if (Object.isFrozen(receiver) || (receiver.fields && Object.isFrozen(receiver.fields))) {
        return;
      }
      let msg = '';
      if (args.length > 0 && args[0] !== null && args[0] !== undefined) {
        msg = this._coerceGuestString(args[0], 'Throwable constructor');
      }
      const needsFieldsObj = !receiver.fields || typeof receiver.fields !== 'object';
      const isNewProp = needsFieldsObj || !('detailMessage' in receiver.fields);
      const addBytes = (needsFieldsObj ? 128 : 0) + (isNewProp ? 128 : 0);
      if (addBytes > 0) {
        this.vm.chargeHeap(addBytes, 'Throwable constructor');
      }
      if (needsFieldsObj) {
        receiver.fields = Object.create(null);
      }
      receiver.fields.detailMessage = msg;
    }
  }

  _handleString(methodName, descriptor, receiver, args) {
    if (methodName === 'valueOf') {
      if (descriptor === '(C)Ljava/lang/String;') {
        const code = safeToInt(args[0]) & 0xffff;
        if (code < SMALL_ASCII_CHARS.length) return SMALL_ASCII_CHARS[code];
        return this._chargeNewPrimitiveString(String.fromCharCode(code), 'String.valueOf');
      }
      if (args[0]?.__dalvikType === 'array' && args[0].elementType === 'C') {
        const arr = args[0];
        const off = args.length >= 3 ? safeToInt(args[1]) : 0;
        const len = args.length >= 3 ? safeToInt(args[2]) : arr.length;
        if (off < 0 || len < 0 || off + len > arr.length) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `String.valueOf(char[], off, len) out of bounds (off=${off}, len=${len}, length=${arr.length})`
          );
        }
        this.vm.chargeHeap(len * 2, 'String.valueOf');
        let text = '';
        const chunkSize = 8192;
        for (let i = 0; i < len; i += chunkSize) {
          const end = Math.min(len, i + chunkSize);
          const codes = new Array(end - i);
          for (let j = i; j < end; j++) codes[j - i] = safeToInt(arr.data[off + j]) & 0xffff;
          text += String.fromCharCode(...codes);
        }
        return text;
      }
      return this._coerceGuestString(args[0], 'String.valueOf');
    }
    if (methodName === 'format') {
      const fmt = toJsString(args[0]);
      const arr = args[1]?.__dalvikType === 'array' ? args[1].data : [];
      const n = fmt.length;
      const unwrapBoxed = (v) =>
        v && typeof v === 'object' && v.__dalvikType === 'instance' && v.native && 'value' in v.native
          ? v.native.value
          : v;

      // Deterministic single-pass O(N) format parser & renderer (zero regex backtracking)
      const parts = [];
      let lastIdx = 0;
      let idx = 0;
      let projectedChars = 0;
      let p = 0;
      while (p < n) {
        const pct = fmt.indexOf('%', p);
        if (pct === -1) break;
        let j = pct + 1;
        if (j < n && fmt.charCodeAt(j) === 37) {
          const literalLen = pct - lastIdx;
          projectedChars += literalLen + 1;
          this.vm.checkHeapBudget(projectedChars * 2, 'String.format');
          if (literalLen > 0) parts.push(fmt.slice(lastIdx, pct));
          parts.push('%');
          lastIdx = j + 1;
          p = lastIdx;
          continue;
        }
        let argPos = 0;
        let leftAlign = false;
        let zeroPad = false;
        let plusSign = false;
        let spaceSign = false;
        let width = 0;
        let hasPrec = false;
        let prec = 0;
        let sawLeadingZero = false;
        let sawWidthNonZero = false;
        const numStart = j;
        let numVal = 0;
        while (j < n) {
          const c = fmt.charCodeAt(j);
          if (c < 48 || c > 57) break;
          const d = c - 48;
          if (j === numStart && d === 0) sawLeadingZero = true;
          if (d !== 0) sawWidthNonZero = true;
          if (numVal < 1_000_000_000) numVal = numVal * 10 + d;
          j += 1;
        }
        const consumeFlags = () => {
          while (j < n) {
            const c = fmt.charCodeAt(j);
            if (c === 45) leftAlign = true;
            else if (c === 48) zeroPad = true;
            else if (c === 43) plusSign = true;
            else if (c === 32) spaceSign = true;
            else if (c !== 35 && c !== 44 && c !== 40) break;
            j += 1;
          }
        };
        const consumeWidth = () => {
          while (j < n) {
            const c = fmt.charCodeAt(j);
            if (c < 48 || c > 57) break;
            if (width < 1_000_000_000) width = width * 10 + (c - 48);
            j += 1;
          }
        };
        if (j > numStart && j < n && fmt.charCodeAt(j) === 36) {
          // Positional index (digits + '$'); next come flags and width
          argPos = numVal;
          j += 1;
          consumeFlags();
          consumeWidth();
        } else if (sawWidthNonZero) {
          if (sawLeadingZero) zeroPad = true;
          width = numVal;
        } else {
          // Zero or more '0' flags scanned so far; consume remaining flags then width digits
          if (sawLeadingZero) zeroPad = true;
          consumeFlags();
          consumeWidth();
        }
        if (j < n && fmt.charCodeAt(j) === 46) {
          hasPrec = true;
          j += 1;
          while (j < n) {
            const c = fmt.charCodeAt(j);
            if (c < 48 || c > 57) break;
            if (prec < 1_000_000_000) prec = prec * 10 + (c - 48);
            j += 1;
          }
        }
        const conv = j < n ? fmt.charCodeAt(j) : 0;
        if ((conv >= 65 && conv <= 90) || (conv >= 97 && conv <= 122)) {
          const maxSpec = width > prec ? width : prec;
          if (maxSpec > 1_048_576 || maxSpec * 2 > this.vm.maxMemoryBytes) {
            this.vm.chargeHeap(maxSpec * 2, 'String.format');
          }
          const spec = fmt[j];
          const isKnownSpec =
            spec === 's' || spec === 'S' || spec === 'd' || spec === 'f' ||
            spec === 'o' || spec === 'x' || spec === 'X' || spec === 'c' || spec === 'b';
          if (isKnownSpec) {
            const rawVal = argPos > 0 ? arr[argPos - 1] : arr[idx++];
            const unwrapped = unwrapBoxed(rawVal);
            let rep;
            let isNumeric = false;
            if (spec === 's' || spec === 'S') {
              const estLen = this._estimateGuestStringLength(rawVal);
              const cappedEst = hasPrec ? Math.min(estLen, prec) : estLen;
              this.vm.checkHeapBudget((projectedChars + Math.max(cappedEst, width)) * 2, 'String.format');
              rep = toJsString(rawVal);
              if (hasPrec && rep.length > prec) rep = rep.slice(0, prec);
              if (spec === 'S') rep = rep.toUpperCase();
            } else if (spec === 'd') {
              isNumeric = true;
              if (typeof unwrapped === 'bigint') {
                rep = unwrapped.toString(10);
              } else {
                rep = String(safeToInt(unwrapped));
              }
              if (!rep.startsWith('-')) {
                if (plusSign) rep = `+${rep}`;
                else if (spaceSign) rep = ` ${rep}`;
              }
            } else if (spec === 'x' || spec === 'X') {
              isNumeric = true;
              rep = typeof unwrapped === 'bigint'
                ? BigInt.asUintN(64, unwrapped).toString(16)
                : (safeToInt(unwrapped) >>> 0).toString(16);
              if (spec === 'X') rep = rep.toUpperCase();
            } else if (spec === 'o') {
              isNumeric = true;
              rep = typeof unwrapped === 'bigint'
                ? BigInt.asUintN(64, unwrapped).toString(8)
                : (safeToInt(unwrapped) >>> 0).toString(8);
            } else if (spec === 'f') {
              isNumeric = true;
              const num = safeToFloatOrDouble(unwrapped, 0);
              const digits = hasPrec ? Math.min(prec, 100) : 6;
              rep = Number.isFinite(num) ? num.toFixed(digits) : String(num);
              if (!rep.startsWith('-')) {
                if (plusSign) rep = `+${rep}`;
                else if (spaceSign) rep = ` ${rep}`;
              }
            } else if (spec === 'c') {
              rep = String.fromCharCode(safeToInt(unwrapped) & 0xffff);
            } else {
              rep = unwrapped ? 'true' : 'false';
            }

            const literalLen = pct - lastIdx;
            const outLen = Math.max(rep.length, width);
            projectedChars += literalLen + outLen;
            this.vm.checkHeapBudget(projectedChars * 2, 'String.format');

            if (width > rep.length) {
              const padCount = width - rep.length;
              if (leftAlign) {
                rep = rep + ' '.repeat(padCount);
              } else if (zeroPad && isNumeric) {
                if (rep.startsWith('-') || rep.startsWith('+') || rep.startsWith(' ')) {
                  rep = rep[0] + '0'.repeat(padCount) + rep.slice(1);
                } else {
                  rep = '0'.repeat(padCount) + rep;
                }
              } else {
                rep = ' '.repeat(padCount) + rep;
              }
            }
            if (literalLen > 0) parts.push(fmt.slice(lastIdx, pct));
            parts.push(rep);
            lastIdx = j + 1;
          }
          p = j + 1;
        } else {
          // None of fmt[pct+1..j-1] is '%', so advancing p = j guarantees strict O(N) scanning
          p = j;
        }
      }
      const tailLen = n - lastIdx;
      projectedChars += tailLen;
      this.vm.chargeHeap(projectedChars * 2, 'String.format');
      if (tailLen > 0) parts.push(fmt.slice(lastIdx));
      return parts.join('');
    }
    if (
      typeof receiver !== 'string' &&
      !(
        receiver &&
        typeof receiver === 'object' &&
        receiver.__dalvikType === 'instance' &&
        receiver.classType === ANDROID_CLASS_DESCRIPTORS.STRING
      )
    ) {
      this._throwGuest(
        'Ljava/lang/ClassCastException;',
        `Expected java.lang.String receiver, got ${this.vm.getObjectType(receiver) ?? typeof receiver}`
      );
    }
    const str = typeof receiver === 'string' ? receiver : String(receiver?.native?.text ?? '');
    switch (methodName) {
      case 'length': return str.length;
      case 'isEmpty': return str.length === 0;
      case 'charAt': {
        const i = safeToInt(args[0]);
        if (i < 0 || i >= str.length) {
          this._throwGuest('Ljava/lang/StringIndexOutOfBoundsException;', `String.charAt(${i}) out of bounds (length ${str.length})`);
        }
        return str.charCodeAt(i);
      }
      case 'substring':
      case 'subSequence': {
        const begin = safeToInt(args[0]);
        const end = args.length >= 2 ? safeToInt(args[1]) : str.length;
        if (begin < 0 || end > str.length || begin > end) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `String.${methodName}(${begin}, ${end}) out of bounds for length ${str.length}`
          );
        }
        const subLen = end - begin;
        if (subLen > 0) {
          this.vm.chargeHeap(subLen * 2, `String.${methodName}`);
        }
        return str.substring(begin, end);
      }
      case 'concat': {
        if (args[0] === null || args[0] === undefined) {
          this._throwGuest('Ljava/lang/NullPointerException;', 'String.concat(null)');
        }
        const suffix = toJsString(args[0]);
        const projectedLen = str.length + suffix.length;
        this.vm.chargeHeap(projectedLen * 2, 'String.concat');
        return str + suffix;
      }
      case 'repeat': {
        const count = safeToInt(args[0]);
        if (count < 0) {
          this._throwGuest('Ljava/lang/IllegalArgumentException;', `String.repeat negative count: ${count}`);
        }
        if (count === 0 || str.length === 0) return '';
        const projectedLen = str.length * count;
        this.vm.chargeHeap(projectedLen * 2, 'String.repeat');
        return str.repeat(count);
      }
      case 'equals':
        return (
          (typeof args[0] === 'string' || args[0]?.classType === ANDROID_CLASS_DESCRIPTORS.STRING) &&
          str === toJsString(args[0])
        );
      case 'equalsIgnoreCase':
        return (
          (typeof args[0] === 'string' || args[0]?.classType === ANDROID_CLASS_DESCRIPTORS.STRING) &&
          str.toLowerCase() === toJsString(args[0]).toLowerCase()
        );
      case 'contains': return str.includes(toJsString(args[0]));
      case 'startsWith': {
        const prefix = toJsString(args[0]);
        if (args.length >= 2) {
          const toffset = safeToInt(args[1]);
          return toffset >= 0 && toffset <= str.length && str.startsWith(prefix, toffset);
        }
        return str.startsWith(prefix);
      }
      case 'endsWith': return str.endsWith(toJsString(args[0]));
      case 'indexOf': {
        const isChar = descriptor?.startsWith('(I') || typeof args[0] === 'number' || typeof args[0] === 'bigint';
        const needle = isChar ? String.fromCharCode(safeToInt(args[0]) & 0xffff) : toJsString(args[0]);
        const fromIdx = args.length >= 2 ? Math.max(0, safeToInt(args[1])) : 0;
        return str.indexOf(needle, fromIdx);
      }
      case 'lastIndexOf': {
        const isChar = descriptor?.startsWith('(I') || typeof args[0] === 'number' || typeof args[0] === 'bigint';
        const needle = isChar ? String.fromCharCode(safeToInt(args[0]) & 0xffff) : toJsString(args[0]);
        if (args.length >= 2) {
          const fromIdx = safeToInt(args[1]);
          if (fromIdx < 0) return -1;
          return str.lastIndexOf(needle, fromIdx);
        }
        return str.lastIndexOf(needle);
      }
      case 'trim':
      case 'strip': {
        if (str.length > 0) this.vm.checkHeapBudget(str.length * 2, `String.${methodName}`);
        const out = str.trim();
        if (out.length > 0) this.vm.chargeHeap(out.length * 2, `String.${methodName}`);
        return out;
      }
      case 'toLowerCase': {
        if (str.length > 0) this.vm.checkHeapBudget(str.length * 2, 'String.toLowerCase');
        const out = str.toLowerCase();
        if (out.length > 0) this.vm.chargeHeap(out.length * 2, 'String.toLowerCase');
        return out;
      }
      case 'toUpperCase': {
        if (str.length > 0) this.vm.checkHeapBudget(str.length * 2, 'String.toUpperCase');
        const out = str.toUpperCase();
        if (out.length > 0) this.vm.chargeHeap(out.length * 2, 'String.toUpperCase');
        return out;
      }
      case 'replace': {
        const isCharOverload = descriptor === '(CC)Ljava/lang/String;';
        if (!isCharOverload && (args[0] === null || args[0] === undefined || args[1] === null || args[1] === undefined)) {
          this._throwGuest('Ljava/lang/NullPointerException;', 'String.replace null argument');
        }
        const target = isCharOverload ? String.fromCharCode(safeToInt(args[0]) & 0xffff) : toJsString(args[0]);
        const replacement = isCharOverload ? String.fromCharCode(safeToInt(args[1]) & 0xffff) : toJsString(args[1]);
        let projectedLen;
        if (target.length === 0) {
          projectedLen = str.length + (str.length + 1) * replacement.length;
        } else {
          let count = 0;
          let pos = 0;
          while ((pos = str.indexOf(target, pos)) !== -1) {
            count += 1;
            pos += target.length;
          }
          projectedLen = str.length + count * (replacement.length - target.length);
        }
        this.vm.chargeHeap(projectedLen * 2, 'String.replace');
        if (target.length === 0) {
          if (str.length === 0) return replacement;
          const out = new Array(str.length * 2 + 1);
          out[0] = replacement;
          for (let i = 0; i < str.length; i++) {
            out[i * 2 + 1] = str[i];
            out[i * 2 + 2] = replacement;
          }
          return out.join('');
        }
        return str.split(target).join(replacement);
      }
      case 'split': {
        const delim = toJsString(args[0]);
        let count = 0;
        if (delim.length === 0) {
          count = str.length;
        } else {
          let pos = 0;
          while ((pos = str.indexOf(delim, pos)) !== -1) {
            count += 1;
            pos += delim.length;
          }
        }
        const projectedParts = delim.length === 0 ? count : count + 1;
        const remainingChars = Math.max(0, str.length - count * delim.length);
        const arrHdr = projectedParts === 0 ? 128 : 256;
        this.vm.checkHeapBudget(arrHdr + projectedParts * 8 + remainingChars * 2, 'String.split');
        const parts = str.split(delim);
        const arr = this.vm.createArray('[Ljava/lang/String;', parts.length);
        if (remainingChars > 0) {
          this.vm.chargeHeap(remainingChars * 2, 'String.split');
        }
        for (let i = 0; i < parts.length; i++) arr.data[i] = parts[i];
        return arr;
      }
      case 'toCharArray': {
        const arr = this.vm.createArray('[C', str.length);
        for (let i = 0; i < str.length; i++) arr.data[i] = str.charCodeAt(i);
        return arr;
      }
      case 'getChars': {
        const srcBegin = safeToInt(args[0]);
        const srcEnd = safeToInt(args[1]);
        const dst = args[2];
        const dstBegin = safeToInt(args[3]);
        if (!dst || dst.__dalvikType !== 'array' || dst.elementType !== 'C') {
          this._throwGuest('Ljava/lang/NullPointerException;', 'String.getChars destination char[] is null');
        }
        if (
          srcBegin < 0 ||
          srcEnd < 0 ||
          srcBegin > srcEnd ||
          srcEnd > str.length ||
          dstBegin < 0 ||
          dstBegin + (srcEnd - srcBegin) > dst.length
        ) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `String.getChars(${srcBegin}, ${srcEnd}, dst, ${dstBegin}) out of bounds (length ${str.length})`
          );
        }
        const count = srcEnd - srcBegin;
        if (count > 0) {
          this.vm.chargeHeap(count * 2, 'String.getChars');
          for (let i = 0; i < count; i++) dst.data[dstBegin + i] = str.charCodeAt(srcBegin + i);
        }
        return;
      }
      case 'getBytes': {
        // Pre-check UTF-8 byte budget BEFORE calling TEXT_ENCODER.encode(str) (UTF-8 is always >= str.length bytes)
        const minArrHdr = str.length === 0 ? 128 : 256;
        this.vm.checkHeapBudget(minArrHdr + str.length, 'String.getBytes');
        if (
          minArrHdr + str.length * 3 > this.vm.maxSingleArrayBytes ||
          this.vm.allocatedHeapBytes + (this.vm.activeStackBytes || 0) + minArrHdr + str.length * 3 > this.vm.maxMemoryBytes
        ) {
          const exactUtf8Len = utf8ByteLength(str);
          this.vm.checkHeapBudget((exactUtf8Len === 0 ? 128 : 256) + exactUtf8Len, 'String.getBytes');
        }
        const encoded = TEXT_ENCODER.encode(str);
        const arr = this.vm.createArray('[B', encoded.byteLength);
        for (let i = 0; i < encoded.byteLength; i++) arr.data[i] = (encoded[i] << 24) >> 24;
        return arr;
      }
      case 'toString': return str;
      case 'hashCode': {
        let h = 0;
        for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
        return h;
      }
      default: return str;
    }
  }

  _handleStringBuilder(classType, methodName, descriptor, receiver, args) {
    const native = this._ensureStringBuilderNative(receiver, classType);
    const label = classType === 'Ljava/lang/StringBuffer;' ? 'StringBuffer' : 'StringBuilder';
    const cur = native.text;
    switch (methodName) {
      case 'append': {
        let added;
        if (args[0]?.__dalvikType === 'array' && args[0].elementType === 'C') {
          const arr = args[0];
          const off = args.length >= 3 ? safeToInt(args[1]) : 0;
          const len = args.length >= 3 ? safeToInt(args[2]) : arr.length;
          if (off < 0 || len < 0 || off + len > arr.length) {
            this._throwGuest(
              'Ljava/lang/StringIndexOutOfBoundsException;',
              `${label}.append(char[], ${off}, ${len}) out of bounds (length ${arr.length})`
            );
          }
          const projectedBytes = (cur.length + len) * 2;
          if (projectedBytes > this.vm.maxSingleArrayBytes || projectedBytes > this.vm.maxMemoryBytes) {
            this._throwGuest(
              'Ljava/lang/OutOfMemoryError;',
              `${label}.append (${projectedBytes} bytes) exceeds VM heap budget (${this.vm.allocatedHeapBytes}/${this.vm.maxMemoryBytes} bytes)`
            );
          }
          this.vm.chargeHeap(len * 2, `${label}.append`);
          let text = '';
          const chunkSize = 8192;
          for (let i = 0; i < len; i += chunkSize) {
            const end = Math.min(len, i + chunkSize);
            const codes = new Array(end - i);
            for (let j = i; j < end; j++) codes[j - i] = safeToInt(arr.data[off + j]) & 0xffff;
            text += String.fromCharCode(...codes);
          }
          receiver.native.text = cur + text;
          return receiver;
        }
        const val = args[0];
        if (!(descriptor && descriptor.startsWith('(C)'))) {
          const estAdded = this._estimateGuestStringLength(val);
          const estProjectedBytes = (cur.length + estAdded) * 2;
          if (estProjectedBytes > this.vm.maxSingleArrayBytes || estProjectedBytes > this.vm.maxMemoryBytes) {
            this._throwGuest(
              'Ljava/lang/OutOfMemoryError;',
              `${label}.append (${estProjectedBytes} bytes) exceeds VM heap budget (${this.vm.allocatedHeapBytes}/${this.vm.maxMemoryBytes} bytes)`
            );
          }
          this.vm.checkHeapBudget(estAdded * 2, `${label}.append`);
        }
        added =
          descriptor && descriptor.startsWith('(C)')
            ? String.fromCharCode(safeToInt(val) & 0xffff)
            : toJsString(val);
        const projectedBytes = (cur.length + added.length) * 2;
        if (projectedBytes > this.vm.maxSingleArrayBytes || projectedBytes > this.vm.maxMemoryBytes) {
          this._throwGuest(
            'Ljava/lang/OutOfMemoryError;',
            `${label}.append (${projectedBytes} bytes) exceeds VM heap budget (${this.vm.allocatedHeapBytes}/${this.vm.maxMemoryBytes} bytes)`
          );
        }
        this.vm.chargeHeap(added.length * 2, `${label}.append`);
        receiver.native.text = cur + added;
        return receiver;
      }
      case 'insert': {
        const offset = safeToInt(args[0]);
        if (offset < 0 || offset > cur.length) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `${label}.insert offset ${offset} out of bounds (length ${cur.length})`
          );
        }
        if (!(descriptor && descriptor.startsWith('(IC)'))) {
          const estAdded = this._estimateGuestStringLength(args[1]);
          const estProjectedBytes = (cur.length + estAdded) * 2;
          if (estProjectedBytes > this.vm.maxSingleArrayBytes || estProjectedBytes > this.vm.maxMemoryBytes) {
            this._throwGuest(
              'Ljava/lang/OutOfMemoryError;',
              `${label}.insert (${estProjectedBytes} bytes) exceeds VM heap budget (${this.vm.allocatedHeapBytes}/${this.vm.maxMemoryBytes} bytes)`
            );
          }
        }
        const added =
          descriptor && descriptor.startsWith('(IC)')
            ? String.fromCharCode(safeToInt(args[1]) & 0xffff)
            : toJsString(args[1]);
        if (added.length === 0) return receiver;
        const newLen = cur.length + added.length;
        const projectedBytes = newLen * 2;
        if (projectedBytes > this.vm.maxSingleArrayBytes || projectedBytes > this.vm.maxMemoryBytes) {
          this._throwGuest(
            'Ljava/lang/OutOfMemoryError;',
            `${label}.insert (${projectedBytes} bytes) exceeds VM heap budget (${this.vm.allocatedHeapBytes}/${this.vm.maxMemoryBytes} bytes)`
          );
        }
        const chargeLen = offset < cur.length ? Math.max(newLen, 1) : added.length;
        this.vm.chargeHeap(chargeLen * 2, `${label}.insert`);
        receiver.native.text = cur.slice(0, offset) + added + cur.slice(offset);
        return receiver;
      }
      case 'length': return cur.length;
      case 'capacity': return Math.max(16, cur.length);
      case 'ensureCapacity': {
        const minCap = safeToInt(args[0]);
        if (minCap > 0) {
          this.vm.checkHeapBudget(minCap * 2, `${label}.ensureCapacity`);
        }
        return;
      }
      case 'setLength': {
        const newLen = safeToInt(args[0]);
        if (newLen < 0) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `${label}.setLength(${newLen}) negative length`
          );
        }
        if (newLen > cur.length) {
          const growth = newLen - cur.length;
          const projectedBytes = newLen * 2;
          if (projectedBytes > this.vm.maxSingleArrayBytes || projectedBytes > this.vm.maxMemoryBytes) {
            this._throwGuest(
              'Ljava/lang/OutOfMemoryError;',
              `${label}.setLength (${projectedBytes} bytes) exceeds VM heap budget (${this.vm.allocatedHeapBytes}/${this.vm.maxMemoryBytes} bytes)`
            );
          }
          this.vm.chargeHeap(growth * 2, `${label}.setLength`);
          receiver.native.text = cur + '\0'.repeat(growth);
        } else if (newLen < cur.length) {
          if (newLen > 0) {
            this.vm.chargeHeap(newLen * 2, `${label}.setLength`);
          }
          receiver.native.text = newLen > 0 ? cur.slice(0, newLen) : '';
        }
        return;
      }
      case 'delete': {
        const start = safeToInt(args[0]);
        const rawEnd = safeToInt(args[1]);
        const len = cur.length;
        if (start < 0 || start > len || start > rawEnd) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `${label}.delete(${start}, ${rawEnd}) out of bounds (length ${len})`
          );
        }
        const end = Math.min(rawEnd, len);
        if (end > start) {
          const newLen = len - (end - start);
          this.vm.chargeHeap(Math.max(newLen, 1) * 2, `${label}.delete`);
          receiver.native.text = cur.slice(0, start) + cur.slice(end);
        }
        return receiver;
      }
      case 'deleteCharAt': {
        const idx = safeToInt(args[0]);
        if (idx < 0 || idx >= cur.length) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `${label}.deleteCharAt(${idx}) out of bounds (length ${cur.length})`
          );
        }
        const newLen = cur.length - 1;
        this.vm.chargeHeap(Math.max(newLen, 1) * 2, `${label}.deleteCharAt`);
        receiver.native.text = cur.slice(0, idx) + cur.slice(idx + 1);
        return receiver;
      }
      case 'replace': {
        const start = safeToInt(args[0]);
        const rawEnd = safeToInt(args[1]);
        const len = cur.length;
        if (start < 0 || start > len || start > rawEnd) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `${label}.replace(${start}, ${rawEnd}) out of bounds (length ${len})`
          );
        }
        if (args[2] === null || args[2] === undefined) {
          this._throwGuest('Ljava/lang/NullPointerException;', `${label}.replace null string`);
        }
        const end = Math.min(rawEnd, len);
        const estRepLen = this._estimateGuestStringLength(args[2]);
        const estNewLen = len - (end - start) + estRepLen;
        this.vm.checkHeapBudget(Math.max(estNewLen, 1) * 2, `${label}.replace`);
        const rep = toJsString(args[2]);
        const newLen = len - (end - start) + rep.length;
        const projectedBytes = newLen * 2;
        if (projectedBytes > this.vm.maxSingleArrayBytes || projectedBytes > this.vm.maxMemoryBytes) {
          this._throwGuest(
            'Ljava/lang/OutOfMemoryError;',
            `${label}.replace (${projectedBytes} bytes) exceeds VM heap budget (${this.vm.allocatedHeapBytes}/${this.vm.maxMemoryBytes} bytes)`
          );
        }
        this.vm.chargeHeap(Math.max(newLen, 1) * 2, `${label}.replace`);
        receiver.native.text = cur.slice(0, start) + rep + cur.slice(end);
        return receiver;
      }
      case 'charAt': {
        const idx = safeToInt(args[0]);
        if (idx < 0 || idx >= cur.length) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `${label}.charAt(${idx}) out of bounds (length ${cur.length})`
          );
        }
        return cur.charCodeAt(idx);
      }
      case 'setCharAt': {
        const idx = safeToInt(args[0]);
        if (idx < 0 || idx >= cur.length) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `${label}.setCharAt(${idx}) out of bounds (length ${cur.length})`
          );
        }
        const ch = String.fromCharCode(safeToInt(args[1]) & 0xffff);
        this.vm.chargeHeap(Math.max(cur.length, 1) * 2, `${label}.setCharAt`);
        receiver.native.text = cur.slice(0, idx) + ch + cur.slice(idx + 1);
        return;
      }
      case 'substring':
      case 'subSequence': {
        const start = safeToInt(args[0]);
        const end = args.length >= 2 ? safeToInt(args[1]) : cur.length;
        if (start < 0 || end > cur.length || start > end) {
          this._throwGuest(
            'Ljava/lang/StringIndexOutOfBoundsException;',
            `${label}.${methodName}(${start}, ${end}) out of bounds (length ${cur.length})`
          );
        }
        const subLen = end - start;
        if (subLen > 0) {
          this.vm.chargeHeap(subLen * 2, `${label}.${methodName}`);
        }
        return cur.substring(start, end);
      }
      case 'getChars': {
        const srcBegin = safeToInt(args[0]);
        const srcEnd = safeToInt(args[1]);
        const dst = args[2];
        const dstBegin = safeToInt(args[3]);
        if (!dst || dst.__dalvikType !== 'array' || dst.elementType !== 'C') {
          this._throwGuest('Ljava/lang/NullPointerException;', `${label}.getChars destination char[] is null`);
        }
        if (
          srcBegin < 0 ||
          srcEnd < 0 ||
          srcBegin > srcEnd ||
          srcEnd > cur.length ||
          dstBegin < 0 ||
          dstBegin + (srcEnd - srcBegin) > dst.length
        ) {
          this._throwGuest(
            'Ljava/lang/IndexOutOfBoundsException;',
            `${label}.getChars(${srcBegin}, ${srcEnd}, dst, ${dstBegin}) out of bounds (length ${cur.length})`
          );
        }
        const count = srcEnd - srcBegin;
        if (count > 0) {
          this.vm.chargeHeap(count * 2, `${label}.getChars`);
          for (let i = 0; i < count; i++) dst.data[dstBegin + i] = cur.charCodeAt(srcBegin + i);
        }
        return;
      }
      case 'reverse': {
        if (cur.length > 0) {
          this.vm.chargeHeap(Math.max(cur.length, 1) * 2, `${label}.reverse`);
          const chars = new Array(cur.length);
          for (let i = 0; i < cur.length; i++) chars[cur.length - 1 - i] = cur[i];
          receiver.native.text = chars.join('');
        }
        return receiver;
      }
      case 'indexOf': {
        const needle = toJsString(args[0]);
        const fromIdx = args.length >= 2 ? Math.max(0, safeToInt(args[1])) : 0;
        return cur.indexOf(needle, fromIdx);
      }
      case 'lastIndexOf': {
        const needle = toJsString(args[0]);
        if (args.length >= 2) {
          const fromIdx = safeToInt(args[1]);
          if (fromIdx < 0) return -1;
          return cur.lastIndexOf(needle, fromIdx);
        }
        return cur.lastIndexOf(needle);
      }
      case 'toString': {
        if (cur.length > 0) {
          this.vm.chargeHeap(cur.length * 2, `${label}.toString`);
        }
        return cur;
      }
      default: return receiver;
    }
  }

  _handleInteger(methodName, descriptor, receiver, args) {
    if (methodName === 'parseInt') {
      const radix = args.length > 1 ? safeToInt(args[1], 10) : 10;
      const parsed = parseJavaInt(args[0], radix);
      if (parsed === null) {
        this._throwGuest(
          'Ljava/lang/NumberFormatException;',
          `For input string: "${capString(toJsString(args[0]), 256)}"`
        );
      }
      return parsed;
    }
    if (methodName === 'toString') {
      if (args.length === 0 && receiver) {
        return this._formatIntString(safeToInt(receiver.native?.value), 10, 'Integer.toString');
      }
      const v = safeToInt(args[0]);
      const radix = args.length >= 2 ? safeToInt(args[1], 10) : 10;
      return this._formatIntString(v, radix >= 2 && radix <= 36 ? radix : 10, 'Integer.toString');
    }
    if (methodName === 'toHexString') {
      return this._chargeNewPrimitiveString((safeToInt(args[0]) >>> 0).toString(16), 'Integer.toHexString');
    }
    if (methodName === 'toBinaryString') {
      return this._chargeNewPrimitiveString((safeToInt(args[0]) >>> 0).toString(2), 'Integer.toBinaryString');
    }
    if (methodName === 'toOctalString') {
      return this._chargeNewPrimitiveString((safeToInt(args[0]) >>> 0).toString(8), 'Integer.toOctalString');
    }
    if (methodName === 'valueOf') {
      const isPrimitive =
        descriptor === '(I)Ljava/lang/Integer;' ||
        (descriptor === null && (typeof args[0] === 'number' || typeof args[0] === 'bigint'));
      const v = isPrimitive ? safeToInt(args[0]) : this._handleInteger('parseInt', null, null, args);
      if (v >= -128 && v <= 127) {
        let cached = this._integerCache.get(v);
        if (!cached) {
          const nativeVal = Object.freeze({ value: v });
          cached = Object.freeze(
            this.vm.createObject('Ljava/lang/Integer;', null, nativeVal, { charge: false })
          );
          this._integerCache.set(v, cached);
        }
        return cached;
      }
      return this.vm.createObject('Ljava/lang/Integer;', null, { value: v });
    }
    if (methodName === 'intValue') return safeToInt(receiver?.native?.value, 0);
    return 0;
  }

  _handleLong(methodName, descriptor, receiver, args) {
    if (methodName === 'parseLong') {
      const radix = args.length > 1 ? safeToInt(args[1], 10) : 10;
      const parsed = parseJavaLong(args[0], radix);
      if (parsed === null) {
        this._throwGuest(
          'Ljava/lang/NumberFormatException;',
          `Invalid long: "${capString(toJsString(args[0]), 256)}"`
        );
      }
      return parsed;
    }
    if (methodName === 'toString') {
      const v = args.length === 0 ? safeToLong(receiver?.native?.value, 0n) : safeToLong(args[0], 0n);
      const radix = args.length >= 2 ? safeToInt(args[1], 10) : 10;
      return this._formatLongString(v, radix >= 2 && radix <= 36 ? radix : 10, 'Long.toString');
    }
    if (methodName === 'toHexString') {
      return this._chargeNewPrimitiveString(BigInt.asUintN(64, safeToLong(args[0], 0n)).toString(16), 'Long.toHexString');
    }
    if (methodName === 'toBinaryString') {
      return this._chargeNewPrimitiveString(BigInt.asUintN(64, safeToLong(args[0], 0n)).toString(2), 'Long.toBinaryString');
    }
    if (methodName === 'toOctalString') {
      return this._chargeNewPrimitiveString(BigInt.asUintN(64, safeToLong(args[0], 0n)).toString(8), 'Long.toOctalString');
    }
    if (methodName === 'valueOf') {
      let v;
      if (descriptor === '(J)Ljava/lang/Long;' || typeof args[0] === 'bigint') {
        v = safeToLong(args[0], 0n);
      } else {
        v = this._handleLong('parseLong', null, null, args);
      }
      return this.vm.createObject('Ljava/lang/Long;', null, { value: v });
    }
    if (methodName === 'longValue') return safeToLong(receiver?.native?.value, 0n);
    return 0n;
  }

  _handleFloatDouble(classType, methodName, descriptor, receiver, args) {
    if (methodName === 'parseFloat' || methodName === 'parseDouble') {
      if (args[0] === null || args[0] === undefined) {
        this._throwGuest('Ljava/lang/NullPointerException;', `${methodName}(null)`);
      }
      let s = toJsString(args[0]).trim();
      if (s.length === 0) {
        this._throwGuest('Ljava/lang/NumberFormatException;', `Empty float/double string`);
      }
      if (s === 'NaN' || s === '+NaN' || s === '-NaN') return NaN;
      if (s === 'Infinity' || s === '+Infinity') return Infinity;
      if (s === '-Infinity') return -Infinity;
      if (/[fFdD]$/.test(s) && !/^0[xX]/.test(s)) {
        s = s.slice(0, -1);
      }
      const v = s.length > 0 ? Number(s) : NaN;
      if (Number.isNaN(v)) {
        this._throwGuest(
          'Ljava/lang/NumberFormatException;',
          `Invalid number: "${capString(toJsString(args[0]), 256)}"`
        );
      }
      return classType === 'Ljava/lang/Float;' ? Math.fround(v) : v;
    }
    if (methodName === 'toString') {
      const str = String(args.length === 0 ? (receiver?.native?.value ?? 0) : args[0]);
      return this._chargeNewPrimitiveString(str, `${descriptorToClassName(classType)}.toString`);
    }
    if (methodName === 'valueOf') {
      const isPrimitive =
        descriptor === '(F)Ljava/lang/Float;' ||
        descriptor === '(D)Ljava/lang/Double;' ||
        typeof args[0] === 'number' ||
        typeof args[0] === 'bigint';
      const v = isPrimitive
        ? classType === 'Ljava/lang/Float;'
          ? Math.fround(toMathNumber(args[0]))
          : toMathNumber(args[0])
        : this._handleFloatDouble(classType, classType === 'Ljava/lang/Float;' ? 'parseFloat' : 'parseDouble', null, null, args);
      return this.vm.createObject(classType, null, { value: v });
    }
    if (methodName === 'floatValue' || methodName === 'doubleValue') return toMathNumber(receiver?.native?.value ?? 0);
    return 0;
  }

  _handleBoolean(methodName, receiver, args) {
    if (methodName === 'parseBoolean') return toJsString(args[0]).toLowerCase() === 'true';
    if (methodName === 'toString') return String(Boolean(args.length === 0 ? receiver?.native?.value : args[0]));
    if (methodName === 'valueOf') return this.vm.createObject('Ljava/lang/Boolean;', null, { value: Boolean(args[0]) });
    if (methodName === 'booleanValue') return Boolean(receiver?.native?.value);
    return false;
  }

  _handleMath(methodName, descriptor, args) {
    switch (methodName) {
      case 'abs': {
        if (typeof args[0] === 'bigint') {
          return args[0] < 0n ? BigInt.asIntN(64, -args[0]) : args[0];
        }
        if (descriptor === '(I)I') {
          const iv = safeToInt(args[0]);
          return (iv < 0 ? -iv : iv) | 0;
        }
        return Math.abs(toMathNumber(args[0]));
      }
      case 'min': {
        if (typeof args[0] === 'bigint' && typeof args[1] === 'bigint') {
          return args[0] < args[1] ? args[0] : args[1];
        }
        return Math.min(toMathNumber(args[0]), toMathNumber(args[1]));
      }
      case 'max': {
        if (typeof args[0] === 'bigint' && typeof args[1] === 'bigint') {
          return args[0] > args[1] ? args[0] : args[1];
        }
        return Math.max(toMathNumber(args[0]), toMathNumber(args[1]));
      }
      case 'sqrt': return Math.sqrt(toMathNumber(args[0]));
      case 'pow': return Math.pow(toMathNumber(args[0]), toMathNumber(args[1]));
      case 'floor': return Math.floor(toMathNumber(args[0]));
      case 'ceil': return Math.ceil(toMathNumber(args[0]));
      case 'sin': return Math.sin(toMathNumber(args[0]));
      case 'cos': return Math.cos(toMathNumber(args[0]));
      case 'tan': return Math.tan(toMathNumber(args[0]));
      case 'log': return Math.log(toMathNumber(args[0]));
      case 'exp': return Math.exp(toMathNumber(args[0]));
      case 'round': {
        const x = toMathNumber(args[0]);
        if (descriptor === '(F)I') {
          if (Number.isNaN(x)) return 0;
          if (x >= INT32_MAX) return INT32_MAX;
          if (x <= INT32_MIN) return INT32_MIN;
          const r = Math.round(x);
          if (r >= INT32_MAX) return INT32_MAX;
          if (r <= INT32_MIN) return INT32_MIN;
          return r | 0;
        }
        // Java Math.round(double) -> long (J)
        if (Number.isNaN(x)) return 0n;
        if (x >= 9223372036854775808.0) return INT64_MAX;
        if (x <= -9223372036854775808.0) return INT64_MIN;
        const r = Math.round(x);
        if (r >= 9223372036854775808.0) return INT64_MAX;
        if (r <= -9223372036854775808.0) return INT64_MIN;
        return BigInt(r);
      }
      default: return 0;
    }
  }

  _handleSystem(methodName, args) {
    if (methodName === 'currentTimeMillis') return BigInt(Date.now());
    if (methodName === 'nanoTime') return BigInt(Date.now()) * 1_000_000n;
    if (methodName === 'getProperty') {
      const k = toJsString(args[0]);
      if (k === 'os.name') return 'OmniOS-Android';
      if (k === 'line.separator') return '\n';
      return args[1] ?? null;
    }
    if (methodName === 'arraycopy') {
      const [src, srcPosRaw, dst, dstPosRaw, lenRaw] = args;
      if (src === null || src === undefined || dst === null || dst === undefined) {
        this._throwGuest('Ljava/lang/NullPointerException;', 'System.arraycopy null array');
      }
      if (src.__dalvikType !== 'array' || dst.__dalvikType !== 'array') {
        this._throwGuest('Ljava/lang/ArrayStoreException;', 'System.arraycopy argument is not an array');
      }
      const srcPos = safeToInt(srcPosRaw);
      const dstPos = safeToInt(dstPosRaw);
      const len = safeToInt(lenRaw);
      if (
        srcPos < 0 ||
        dstPos < 0 ||
        len < 0 ||
        srcPos + len > src.length ||
        dstPos + len > dst.length
      ) {
        this._throwGuest(
          'Ljava/lang/IndexOutOfBoundsException;',
          `System.arraycopy out of bounds (srcPos=${srcPos}, dstPos=${dstPos}, len=${len}, srcLen=${src.length}, dstLen=${dst.length})`
        );
      }
      const srcIsRef = src.elementType.startsWith('L') || src.elementType.startsWith('[');
      const dstIsRef = dst.elementType.startsWith('L') || dst.elementType.startsWith('[');
      if (srcIsRef !== dstIsRef || (!srcIsRef && src.elementType !== dst.elementType)) {
        this._throwGuest(
          'Ljava/lang/ArrayStoreException;',
          `Incompatible array types in System.arraycopy: ${src.classType} -> ${dst.classType}`
        );
      }
      if (srcIsRef && dstIsRef && dst.elementType !== 'Ljava/lang/Object;') {
        for (let i = 0; i < len; i++) {
          const elem = src.data[srcPos + i];
          if (elem !== null && elem !== undefined) {
            const elemType = this.vm.getObjectType(elem);
            if (!this.vm.isAssignableTo(elemType, dst.elementType)) {
              this._throwGuest(
                'Ljava/lang/ArrayStoreException;',
                `Cannot store ${elemType} into ${dst.classType} at offset ${dstPos + i}`
              );
            }
          }
        }
      }
      if (src === dst && dstPos > srcPos) {
        for (let i = len - 1; i >= 0; i--) {
          dst.data[dstPos + i] = src.data[srcPos + i];
        }
      } else {
        for (let i = 0; i < len; i++) {
          dst.data[dstPos + i] = src.data[srcPos + i];
        }
      }
      return;
    }
    return null;
  }

  _handlePrintStream(methodName, receiver, args) {
    this._requireInstanceReceiver(receiver, 'java.io.PrintStream');
    if (receiver.native && (typeof receiver.native !== 'object' || typeof receiver.native.channel !== 'string')) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a PrintStream`);
    }
    let text = '';
    if (args.length > 0) {
      const arg0 = args[0];
      if (typeof arg0 === 'number' || typeof arg0 === 'bigint' || typeof arg0 === 'boolean') {
        text = String(arg0);
      } else {
        text = this._coerceGuestString(arg0, 'PrintStream');
      }
    }
    const out = methodName === 'println' ? `${text}\n` : text;
    try {
      if (receiver?.native?.channel === 'stderr') {
        this.services?.processManager?.writeStderr?.(this.pcb.pid, out);
      } else {
        this.services?.processManager?.writeStdout?.(this.pcb.pid, out);
      }
    } catch (err) {
      this._recordInternalLog('W', 'PrintStream', `Stream write skipped: ${err?.message ?? err}`);
    }
  }

  _handleArrayList(methodName, descriptor, receiver, args) {
    const items = this._ensureArrayListNative(receiver).items;
    switch (methodName) {
      case 'add': {
        if (args.length === 2) {
          const idx = safeToInt(args[0]);
          if (idx < 0 || idx > items.length) {
            this._throwGuest(
              'Ljava/lang/IndexOutOfBoundsException;',
              `ArrayList.add index ${idx} out of bounds for size ${items.length}`
            );
          }
          this.vm.chargeHeap(items.length === 0 ? 128 : 16, 'ArrayList.add');
          items.splice(idx, 0, args[1]);
          return;
        }
        this.vm.chargeHeap(items.length === 0 ? 128 : 16, 'ArrayList.add');
        items.push(args[0]);
        return true;
      }
      case 'addAll': {
        const hasIndex = args.length >= 2;
        const idx = hasIndex ? safeToInt(args[0]) : items.length;
        const col = hasIndex ? args[1] : args[0];
        if (hasIndex && (idx < 0 || idx > items.length)) {
          this._throwGuest(
            'Ljava/lang/IndexOutOfBoundsException;',
            `ArrayList.addAll index ${idx} out of bounds for size ${items.length}`
          );
        }
        if (col === null || col === undefined) {
          this._throwGuest('Ljava/lang/NullPointerException;', 'ArrayList.addAll(null)');
        }
        let addLen = 0;
        let srcArray = null;
        let srcSet = null;
        if (Array.isArray(col.native?.items)) {
          srcArray = col.native.items;
          addLen = srcArray.length;
        } else if (col.native?.set instanceof Set) {
          srcSet = col.native.set;
          addLen = srcSet.size;
        } else {
          return false;
        }
        if (addLen === 0) return false;
        this.vm.chargeHeap(addLen * 16, 'ArrayList.addAll');
        const snap = new Array(addLen);
        if (srcArray) {
          for (let i = 0; i < addLen; i++) snap[i] = srcArray[i];
        } else {
          let k = 0;
          for (const item of srcSet) snap[k++] = item;
        }
        if (hasIndex) {
          const oldLen = items.length;
          items.length = oldLen + addLen;
          for (let i = oldLen - 1; i >= idx; i--) items[i + addLen] = items[i];
          for (let i = 0; i < addLen; i++) items[idx + i] = snap[i];
        } else {
          for (let i = 0; i < addLen; i++) items.push(snap[i]);
        }
        return true;
      }
      case 'get': {
        const idx = safeToInt(args[0]);
        if (idx < 0 || idx >= items.length) {
          this._throwGuest(
            'Ljava/lang/IndexOutOfBoundsException;',
            `ArrayList.get index ${idx} out of bounds for size ${items.length}`
          );
        }
        return items[idx] ?? null;
      }
      case 'set': {
        const idx = safeToInt(args[0]);
        if (idx < 0 || idx >= items.length) {
          this._throwGuest(
            'Ljava/lang/IndexOutOfBoundsException;',
            `ArrayList.set index ${idx} out of bounds for size ${items.length}`
          );
        }
        const prev = items[idx];
        items[idx] = args[1];
        return prev ?? null;
      }
      case 'remove': {
        const isObjectOverload = typeof descriptor === 'string' && descriptor.startsWith('(Ljava/lang/Object;)');
        if (isObjectOverload) {
          const pos = items.indexOf(args[0]);
          if (pos === -1) return false;
          items.splice(pos, 1);
          return true;
        }
        const idx = safeToInt(args[0]);
        if (idx < 0 || idx >= items.length) {
          this._throwGuest(
            'Ljava/lang/IndexOutOfBoundsException;',
            `ArrayList.remove index ${idx} out of bounds for size ${items.length}`
          );
        }
        return items.splice(idx, 1)[0] ?? null;
      }
      case 'subList': {
        const fromIdx = safeToInt(args[0]);
        const toIdx = safeToInt(args[1]);
        if (fromIdx < 0 || toIdx > items.length) {
          this._throwGuest(
            'Ljava/lang/IndexOutOfBoundsException;',
            `ArrayList.subList(${fromIdx}, ${toIdx}) out of bounds for size ${items.length}`
          );
        }
        if (fromIdx > toIdx) {
          this._throwGuest(
            'Ljava/lang/IllegalArgumentException;',
            `ArrayList.subList fromIndex(${fromIdx}) > toIndex(${toIdx})`
          );
        }
        const subLen = toIdx - fromIdx;
        const nativeBytes = 128 + subLen * 16;
        this.vm.checkHeapBudget(128 + nativeBytes, 'ArrayList.subList');
        this.vm.chargeHeap(nativeBytes, 'ArrayList.subList');
        return this.vm.createObject('Ljava/util/ArrayList;', null, { items: items.slice(fromIdx, toIdx) });
      }
      case 'ensureCapacity': {
        const minCap = safeToInt(args[0]);
        if (minCap > 0) {
          this.vm.checkHeapBudget(minCap * 8, 'ArrayList.ensureCapacity');
        }
        return;
      }
      case 'toArray': {
        const arr = this.vm.createArray('[Ljava/lang/Object;', items.length);
        for (let i = 0; i < items.length; i++) arr.data[i] = items[i] ?? null;
        return arr;
      }
      case 'indexOf': return items.indexOf(args[0]);
      case 'lastIndexOf': return items.lastIndexOf(args[0]);
      case 'size': return items.length;
      case 'isEmpty': return items.length === 0;
      case 'clear': items.length = 0; return;
      case 'contains': return items.includes(args[0]);
      default: return null;
    }
  }

  _handleHashMap(methodName, receiver, args) {
    const map = this._ensureHashMapNative(receiver).map;
    switch (methodName) {
      case 'put': {
        const hadKey = map.has(args[0]);
        if (!hadKey) {
          this.vm.chargeHeap(128, 'HashMap.put');
        }
        const prev = hadKey ? map.get(args[0]) : null;
        map.set(args[0], args[1]);
        return prev;
      }
      case 'putAll': {
        const other = args[0];
        if (other === null || other === undefined) {
          this._throwGuest('Ljava/lang/NullPointerException;', 'HashMap.putAll(null)');
        }
        const otherMap = other?.native?.map;
        if (otherMap instanceof Map) {
          let newCount = 0;
          for (const k of otherMap.keys()) {
            if (!map.has(k)) newCount += 1;
          }
          if (newCount > 0) {
            this.vm.chargeHeap(newCount * 128, 'HashMap.putAll');
          }
          for (const [k, v] of otherMap.entries()) {
            map.set(k, v);
          }
        }
        return;
      }
      case 'get': return map.get(args[0]) ?? null;
      case 'remove': { const prev = map.get(args[0]) ?? null; map.delete(args[0]); return prev; }
      case 'containsKey': return map.has(args[0]);
      case 'containsValue': {
        for (const v of map.values()) {
          if (v === args[0]) return true;
        }
        return false;
      }
      case 'size': return map.size;
      case 'isEmpty': return map.size === 0;
      case 'clear': map.clear(); return;
      default: return null;
    }
  }

  _handleHashSet(methodName, receiver, args) {
    const set = this._ensureHashSetNative(receiver).set;
    switch (methodName) {
      case 'add': {
        if (set.has(args[0])) return false;
        this.vm.chargeHeap(set.size < 256 ? 32 : 96, 'HashSet.add');
        set.add(args[0]);
        return true;
      }
      case 'remove': return set.delete(args[0]);
      case 'contains': return set.has(args[0]);
      case 'size': return set.size;
      case 'isEmpty': return set.size === 0;
      case 'clear': set.clear(); return;
      case 'toArray': {
        const arr = this.vm.createArray('[Ljava/lang/Object;', set.size);
        let i = 0;
        for (const item of set.values()) arr.data[i++] = item ?? null;
        return arr;
      }
      default: return null;
    }
  }

  _handleEnvironment(methodName, args) {
    if (methodName === 'getExternalStorageDirectory') {
      return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.FILE, null, { path: '/sdcard' });
    }
    if (methodName === 'getExternalStoragePublicDirectory') {
      const sub = args[0]
        ? this._coerceGuestString(args[0], 'Environment.getExternalStoragePublicDirectory')
        : 'Documents';
      if (sub.length > 0) {
        this.vm.chargeHeap((sub.length + 8) * 2, 'Environment.getExternalStoragePublicDirectory');
      }
      return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.FILE, null, { path: `/sdcard/${sub}` });
    }
    if (methodName === 'getDataDirectory') {
      return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.FILE, null, { path: `/data/data/${this.packageName}` });
    }
    return null;
  }

  _handleFile(methodName, receiver, args) {
    this._requireInstanceReceiver(receiver, 'java.io.File');
    if (receiver.native && (typeof receiver.native !== 'object' || typeof receiver.native.path !== 'string')) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a File`);
    }
    const path = receiver.native?.path ?? '';
    switch (methodName) {
      case 'getPath':
      case 'getAbsolutePath':
        return path;
      case 'getName': {
        let end = path.length;
        while (end > 0 && path.charCodeAt(end - 1) === 47) end -= 1;
        if (end === 0) return '';
        let start = end - 1;
        while (start > 0 && path.charCodeAt(start - 1) !== 47) start -= 1;
        if (start === 0 && end === path.length) return path;
        const name = path.slice(start, end);
        if (name.length > 0) {
          this.vm.chargeHeap(name.length * 2, 'File.getName');
        }
        return name;
      }
      case 'exists': {
        const access = this._resolveVfsAccess(path, 'read');
        const { stat } = this._statCached(access, path, { quotaException: 'Ljava/lang/SecurityException;' });
        return stat !== null;
      }
      case 'isDirectory': {
        const access = this._resolveVfsAccess(path, 'read');
        const { stat } = this._statCached(access, path, { quotaException: 'Ljava/lang/SecurityException;' });
        return stat?.type === 'dir';
      }
      case 'isFile': {
        const access = this._resolveVfsAccess(path, 'read');
        const { stat } = this._statCached(access, path, { quotaException: 'Ljava/lang/SecurityException;' });
        return stat?.type === 'file';
      }
      case 'length': {
        const access = this._resolveVfsAccess(path, 'read');
        const { stat } = this._statCached(access, path, { quotaException: 'Ljava/lang/SecurityException;' });
        return stat ? safeToLong(stat.size ?? 0, 0n) : 0n;
      }
      case 'createNewFile': {
        const access = this._resolveVfsAccess(path, 'write');
        const isRoot = this.pcb?.uid === 0;
        const { stat } = this._statCached(access, path, { quotaException: 'Ljava/io/IOException;' });
        if (stat !== null) return false;
        if (!isRoot && this._vfsCreateOps >= MAX_VFS_CREATE_OPS) {
          this._throwGuest(
            'Ljava/io/IOException;',
            `No space left on device: process VFS file/directory creation quota exceeded (${this._vfsCreateOps}/${MAX_VFS_CREATE_OPS})`
          );
        }
        if (!isRoot && this._vfsPhysicalWriteBytes + VFS_STAT_READ_COST > MAX_VFS_PHYSICAL_WRITE_BYTES) {
          this._throwGuest(
            'Ljava/io/IOException;',
            `Disk full: physical VFS write quota exceeded (${this._vfsPhysicalWriteBytes + VFS_STAT_READ_COST}/${MAX_VFS_PHYSICAL_WRITE_BYTES} bytes)`
          );
        }
        try {
          access.vfs.writeFile(access.canonicalPath, EMPTY_UINT8, {
            append: false,
            mode: 0o644,
            ...access.ctx,
          });
          if (!isRoot) {
            this._vfsPhysicalWriteBytes += VFS_STAT_READ_COST;
          }
          this._invalidateVfsReadCaches();
          if (!isRoot) {
            this._vfsCreateOps += 1;
          }
          return true;
        } catch (err) {
          if (!isRoot) {
            this._vfsPhysicalWriteBytes += VFS_STAT_READ_COST;
          }
          this._translateVfsError(err, path);
          return false;
        }
      }
      case 'mkdir':
      case 'mkdirs': {
        const access = this._resolveVfsAccess(path, 'write');
        const isRoot = this.pcb?.uid === 0;
        const recursive = methodName === 'mkdirs';
        let missingDirs = 1;
        if (!isRoot) {
          if (recursive) {
            const sandboxRoot = access.ctx.sandboxRoot || this.appDataDir;
            const relParts =
              access.canonicalPath.length > sandboxRoot.length && access.canonicalPath.startsWith(sandboxRoot)
                ? access.canonicalPath.slice(sandboxRoot.length).split('/').filter(Boolean)
                : [];
            missingDirs = 0;
            let cur = sandboxRoot;
            for (let i = 0; i < relParts.length; i++) {
              cur = `${cur}/${relParts[i]}`;
              const { stat: st } = this._statCached(access, path, {
                quotaException: 'Ljava/lang/SecurityException;',
                canonicalPath: cur,
              });
              if (st === null) {
                missingDirs = relParts.length - i;
                break;
              }
              if (st.type !== 'dir') {
                return false;
              }
            }
            if (missingDirs === 0) return false;
          } else {
            const { stat: st } = this._statCached(access, path, { quotaException: 'Ljava/lang/SecurityException;' });
            if (st !== null) return false;
          }
          if (this._vfsCreateOps + missingDirs > MAX_VFS_CREATE_OPS) {
            return false;
          }
          const writeCost = Math.max(1, missingDirs) * VFS_STAT_READ_COST;
          if (this._vfsPhysicalWriteBytes + writeCost > MAX_VFS_PHYSICAL_WRITE_BYTES) {
            return false;
          }
        }
        try {
          const res = access.vfs.mkdir(access.canonicalPath, {
            recursive,
            mode: 0o755,
            ...access.ctx,
          });
          const created = res?.created !== false;
          if (!isRoot) {
            this._vfsPhysicalWriteBytes += (created ? Math.max(1, missingDirs) : 1) * VFS_STAT_READ_COST;
          }
          if (created) {
            this._invalidateVfsReadCaches();
          }
          if (!isRoot && created) {
            this._vfsCreateOps += missingDirs;
          }
          return created;
        } catch (err) {
          if (!isRoot) {
            this._vfsPhysicalWriteBytes += VFS_STAT_READ_COST;
          }
          if (err?.code === 'EEXIST') return false;
          this._translateVfsError(err, path);
          return false;
        }
      }
      case 'delete': {
        const access = this._resolveVfsAccess(path, 'write');
        const isRoot = this.pcb?.uid === 0;
        const dirKey = `${access.ctx.uid}:${access.ctx.gid}:${access.canonicalPath}`;
        if (this._nonEmptyDirCache.has(dirKey)) {
          this._throwGuest('Ljava/io/IOException;', this._nonEmptyDirCache.get(dirKey));
        }
        if (!isRoot && this._vfsPhysicalWriteBytes + VFS_STAT_READ_COST > MAX_VFS_PHYSICAL_WRITE_BYTES) {
          this._throwGuest(
            'Ljava/io/IOException;',
            `Disk full: physical VFS write quota exceeded (${this._vfsPhysicalWriteBytes + VFS_STAT_READ_COST}/${MAX_VFS_PHYSICAL_WRITE_BYTES} bytes)`
          );
        }
        const { stat: st } = this._statCached(access, path, { quotaException: 'Ljava/lang/SecurityException;' });
        if (st === null) return false;
        try {
          if (st.type === 'dir') access.vfs.rmdir(access.canonicalPath, access.ctx);
          else access.vfs.unlink(access.canonicalPath, access.ctx);
          if (!isRoot) {
            this._vfsPhysicalWriteBytes += VFS_STAT_READ_COST;
          }
          this._invalidateVfsReadCaches();
          return true;
        } catch (err) {
          if (!isRoot) {
            this._vfsPhysicalWriteBytes += VFS_STAT_READ_COST;
          }
          if (err?.code === 'ENOTEMPTY' && st.type === 'dir') {
            const msg = capString(err?.message ?? `Directory not empty: ${access.canonicalPath}`, 256);
            if (!this._nonEmptyDirCache.has(dirKey) && this._nonEmptyDirCache.size >= MAX_NON_EMPTY_DIR_CACHE_ENTRIES) {
              const oldestKey = this._nonEmptyDirCache.keys().next().value;
              this._nonEmptyDirCache.delete(oldestKey);
            }
            this._nonEmptyDirCache.set(dirKey, msg);
          }
          if (err?.code === 'ENOENT') return false;
          this._translateVfsError(err, path);
          return false;
        }
      }
      case 'list': {
        const access = this._resolveVfsAccess(path, 'read');
        const isRoot = this.pcb?.uid === 0;
        const cacheKey = `${access.ctx.uid}:${access.ctx.gid}:${access.canonicalPath}`;
        let cached = null;
        if (this._readdirCache.has(cacheKey)) {
          const hit = this._readdirCache.get(cacheKey);
          if (hit === VFS_READDIR_NULL) return null;
          cached = hit;
        }
        if (!cached) {
          // Symmetric W10-3 / S13-3: enforce non-root physical VFS read quota BEFORE vfs.readdir()
          if (!isRoot && this._vfsPhysicalReadBytes + VFS_STAT_READ_COST > MAX_VFS_PHYSICAL_READ_BYTES) {
            return null;
          }
          let entries;
          try {
            entries = access.vfs.readdir(access.canonicalPath, access.ctx);
          } catch (err) {
            if (!isRoot) {
              this._vfsPhysicalReadBytes += err?.code === 'ELOOP' ? 16 * VFS_STAT_READ_COST : VFS_STAT_READ_COST;
            }
            if (err?.code === 'ENOENT' || err?.code === 'ENOTDIR') {
              this._putReaddirCache(cacheKey, VFS_READDIR_NULL, 0);
              return null;
            }
            this._translateVfsError(err, path);
            return null;
          }
          const names = new Array(entries.length);
          let nameBytes = 0;
          let utf8Bytes = 0;
          for (let i = 0; i < entries.length; i++) {
            const name = typeof entries[i] === 'string' ? entries[i] : String(entries[i]?.name ?? '');
            names[i] = name;
            nameBytes += name.length * 2;
            utf8Bytes += utf8ByteLength(name);
          }
          const scanCost = Math.max(VFS_STAT_READ_COST, entries.length * 256 + utf8Bytes);
          if (!isRoot) {
            this._vfsPhysicalReadBytes += scanCost;
            if (this._vfsPhysicalReadBytes > MAX_VFS_PHYSICAL_READ_BYTES) {
              return null;
            }
          }
          const cacheEntryBytes = Math.max(256, entries.length * 64 + nameBytes);
          cached = { names, nameBytes, scanCost, cacheEntryBytes };
          this._putReaddirCache(cacheKey, cached, cacheEntryBytes);
        }
        const { names, nameBytes } = cached;
        const arrHdr = names.length === 0 ? 128 : 256;
        this.vm.checkHeapBudget(arrHdr + names.length * 8 + nameBytes, 'File.list');
        const arr = this.vm.createArray('[Ljava/lang/String;', names.length);
        if (nameBytes > 0) {
          this.vm.chargeHeap(nameBytes, 'File.list');
        }
        for (let i = 0; i < names.length; i++) {
          arr.data[i] = names[i];
        }
        return arr;
      }
      default:
        return null;
    }
  }

  _handleFileOutputStream(methodName, receiver, args) {
    this._requireInstanceReceiver(receiver, 'java.io.FileOutputStream');
    const n = receiver.native;
    if (!n) this._throwGuest('Ljava/io/IOException;', 'Stream not initialized');
    if (typeof n !== 'object' || !n.access || typeof n.access.vfs?.writeFile !== 'function') {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a FileOutputStream`);
    }
    if (methodName === 'write') {
      if (n.closed) this._throwGuest('Ljava/io/IOException;', 'Stream closed');
      const isRoot = this.pcb?.uid === 0;
      let chunk;
      if (args.length === 1 && (typeof args[0] === 'number' || typeof args[0] === 'bigint')) {
        chunk = new Uint8Array([safeToInt(args[0]) & 0xff]);
      } else if (args[0] === null || args[0] === undefined) {
        this._throwGuest('Ljava/lang/NullPointerException;', 'write buffer is null');
      } else if (args[0]?.__dalvikType === 'array') {
        const arr = args[0];
        const off = args.length >= 3 ? safeToInt(args[1]) : 0;
        const len = args.length >= 3 ? safeToInt(args[2]) : arr.length;
        if (off < 0 || len < 0 || off + len > arr.length) {
          this._throwGuest(
            'Ljava/lang/IndexOutOfBoundsException;',
            `FileOutputStream.write out of bounds (off=${off}, len=${len}, length=${arr.length})`
          );
        }
        if (len === 0) return;
        if (!isRoot && this._vfsWriteBytes + len > MAX_VFS_WRITE_BYTES) {
          this._throwGuest(
            'Ljava/io/IOException;',
            `No space left on device: process VFS write quota exceeded (${this._vfsWriteBytes + len}/${MAX_VFS_WRITE_BYTES} bytes)`
          );
        }
        chunk = new Uint8Array(len);
        for (let i = 0; i < len; i++) chunk[i] = safeToInt(arr.data[off + i]) & 0xff;
      } else {
        const text = this._coerceGuestString(args[0], 'FileOutputStream.write');
        if (text.length === 0) return;
        if (!isRoot && this._vfsWriteBytes + text.length > MAX_VFS_WRITE_BYTES) {
          this._throwGuest(
            'Ljava/io/IOException;',
            `No space left on device: process VFS write quota exceeded (${this._vfsWriteBytes + text.length}/${MAX_VFS_WRITE_BYTES} bytes)`
          );
        }
        chunk = TEXT_ENCODER.encode(text);
      }
      if (chunk.byteLength === 0) return;
      if (!isRoot && this._vfsWriteBytes + chunk.byteLength > MAX_VFS_WRITE_BYTES) {
        this._throwGuest(
          'Ljava/io/IOException;',
          `No space left on device: process VFS write quota exceeded (${this._vfsWriteBytes + chunk.byteLength}/${MAX_VFS_WRITE_BYTES} bytes)`
        );
      }
      const useAppend = Boolean(n.append || n.hasWritten);
      let existingSize = typeof n.currentFileSize === 'number' && n.currentFileSize >= 0 ? n.currentFileSize : 0;
      if (!isRoot && useAppend) {
        const { stat: st } = this._statCached(n.access, n.path, { quotaException: 'Ljava/io/IOException;' });
        if (st === null) {
          existingSize = 0;
        } else if (typeof st?.size === 'number' && Number.isFinite(st.size) && st.size >= 0) {
          existingSize = st.size;
        }
      }
      const nextSize = useAppend ? existingSize + chunk.byteLength : chunk.byteLength;
      if (!isRoot && this._vfsPhysicalWriteBytes + nextSize > MAX_VFS_PHYSICAL_WRITE_BYTES) {
        this._throwGuest(
          'Ljava/io/IOException;',
          `Disk full: physical VFS rewrite quota exceeded (${this._vfsPhysicalWriteBytes + nextSize}/${MAX_VFS_PHYSICAL_WRITE_BYTES} bytes)`
        );
      }
      try {
        n.access.vfs.writeFile(n.access.canonicalPath, chunk, {
          append: useAppend,
          mode: 0o644,
          ...n.access.ctx,
        });
        this._invalidateVfsReadCaches();
        n.hasWritten = true;
        n.currentFileSize = nextSize;
        this._vfsWriteBytes += chunk.byteLength;
        if (!isRoot) {
          this._vfsPhysicalWriteBytes += nextSize;
        }
      } catch (err) {
        if (!isRoot) {
          this._vfsPhysicalWriteBytes += VFS_STAT_READ_COST;
        }
        this._translateVfsError(err, n.path);
      }
      return;
    }
    if (methodName === 'flush') return;
    if (methodName === 'close') {
      n.closed = true;
    }
  }

  _handleFileInputStream(methodName, receiver, args) {
    this._requireInstanceReceiver(receiver, 'java.io.FileInputStream');
    const n = receiver.native;
    if (!n) this._throwGuest('Ljava/io/IOException;', 'Stream not initialized');
    if (typeof n !== 'object' || !(n.bytes instanceof Uint8Array)) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a FileInputStream`);
    }
    if (methodName === 'available') return Math.max(0, n.bytes.byteLength - n.pos);
    if (methodName === 'close') {
      n.closed = true;
      return;
    }
    if (methodName === 'read') {
      if (n.closed) this._throwGuest('Ljava/io/IOException;', 'Stream closed');
      if (args.length === 0) {
        if (n.pos >= n.bytes.byteLength) return -1;
        return n.bytes[n.pos++];
      }
      const arr = args[0];
      if (!arr || arr.__dalvikType !== 'array') {
        this._throwGuest('Ljava/lang/NullPointerException;', 'read buffer is null');
      }
      if (arr.elementType !== 'B') {
        this._throwGuest('Ljava/lang/ClassCastException;', `FileInputStream.read requires byte[], got ${arr.classType}`);
      }
      const off = args.length >= 3 ? safeToInt(args[1]) : 0;
      const maxLen = args.length >= 3 ? safeToInt(args[2]) : arr.length;
      if (off < 0 || maxLen < 0 || off + maxLen > arr.length) {
        this._throwGuest(
          'Ljava/lang/IndexOutOfBoundsException;',
          `FileInputStream.read out of bounds (off=${off}, len=${maxLen}, length=${arr.length})`
        );
      }
      if (maxLen === 0) return 0;
      if (n.pos >= n.bytes.byteLength) return -1;
      const count = Math.min(maxLen, n.bytes.byteLength - n.pos);
      for (let i = 0; i < count; i++) {
        arr.data[off + i] = (n.bytes[n.pos++] << 24) >> 24;
      }
      return count;
    }
    return -1;
  }

  _handleLog(methodName, args) {
    const levelMap = { v: 'V', d: 'D', i: 'I', w: 'W', e: 'E', wtf: 'F' };
    const lvl = levelMap[methodName] ?? 'I';
    return this._recordInternalLog(
      lvl,
      this._coerceGuestString(args[0], 'Log'),
      this._coerceGuestString(args[1], 'Log')
    );
  }

  _handleToast(methodName, receiver, args) {
    if (methodName === 'makeText') {
      let text = '';
      if (typeof args[1] === 'number') {
        text = this.apk?.resources?.getString?.(safeToInt(args[1]) >>> 0) ?? String(args[1]);
        if (text.length > 0) {
          this.vm.chargeHeap(text.length * 2, 'Toast.makeText');
        }
      } else {
        text = this._coerceGuestString(args[1], 'Toast.makeText');
      }
      const duration = safeToInt(args[2]);
      return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.TOAST, null, { text, duration });
    }
    if (methodName === 'show') {
      this._requireInstanceReceiver(receiver, 'android.widget.Toast');
      if (receiver.native && (typeof receiver.native !== 'object' || typeof receiver.native.text !== 'string')) {
        this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a Toast`);
      }
      const text = capString(receiver.native?.text ?? '', MAX_TOAST_TEXT_CHARS);
      pushBounded(this.toasts, { text, ts: new Date().toISOString() }, MAX_BRIDGE_TOASTS);
      if (this.services?.notifications) {
        try {
          this.services.notifications.post({
            appId: this.packageName,
            platform: 'android',
            title: capString(this.appLabel || this.packageName, 256),
            body: text,
            category: 'toast',
            priority: 'normal',
          });
        } catch (err) {
          this._recordInternalLog('W', 'Toast', `Notification post skipped: ${err?.message ?? err}`);
        }
      }
      return;
    }
    this._requireInstanceReceiver(receiver, 'android.widget.Toast');
    return null;
  }

  _handleBundle(methodName, receiver, args) {
    const map = this._ensureBundleNative(receiver).map;
    const isMutatingPut = methodName.startsWith('put');
    const key =
      args[0] !== undefined
        ? isMutatingPut
          ? this._coerceGuestString(args[0], `Bundle.${methodName}`)
          : toJsString(args[0])
        : '';
    const has = Object.prototype.hasOwnProperty.call(map, key);
    switch (methodName) {
      case 'putString': {
        const val =
          args[1] !== null && args[1] !== undefined
            ? this._coerceGuestString(args[1], 'Bundle.putString')
            : null;
        if (!has) this.vm.chargeHeap(96, 'Bundle.putString');
        map[key] = val;
        return;
      }
      case 'getString':
      case 'getCharSequence': {
        if (has && map[key] !== null && map[key] !== undefined) {
          return this._coerceGuestString(map[key], `Bundle.${methodName}`);
        }
        if (args[1] === null || args[1] === undefined) return null;
        return this._coerceGuestString(args[1], `Bundle.${methodName}`);
      }
      case 'putInt':
        if (!has) this.vm.chargeHeap(96, 'Bundle.putInt');
        map[key] = safeToInt(args[1]);
        return;
      case 'getInt': {
        const def = safeToInt(args[1]);
        return has ? safeToInt(map[key], def) : def;
      }
      case 'putLong':
        if (!has) this.vm.chargeHeap(96, 'Bundle.putLong');
        map[key] = safeToLong(args[1], 0n);
        return;
      case 'getLong': {
        const def = safeToLong(args[1], 0n);
        return has ? safeToLong(map[key], def) : def;
      }
      case 'putFloat':
        if (!has) this.vm.chargeHeap(96, 'Bundle.putFloat');
        map[key] = toMathNumber(args[1] ?? 0);
        return;
      case 'getFloat': {
        const def = safeToFloatOrDouble(args[1], 0);
        return has ? safeToFloatOrDouble(map[key], def) : def;
      }
      case 'putDouble':
        if (!has) this.vm.chargeHeap(96, 'Bundle.putDouble');
        map[key] = toMathNumber(args[1] ?? 0);
        return;
      case 'getDouble': {
        const def = safeToFloatOrDouble(args[1], 0);
        return has ? safeToFloatOrDouble(map[key], def) : def;
      }
      case 'putBoolean':
        if (!has) this.vm.chargeHeap(96, 'Bundle.putBoolean');
        map[key] = Boolean(args[1]);
        return;
      case 'getBoolean':
        return has ? Boolean(map[key]) : Boolean(args[1]);
      case 'get':
        return has ? map[key] : null;
      case 'remove':
        if (has) delete map[key];
        return;
      case 'containsKey':
        return has;
      default: return null;
    }
  }

  _handleUri(methodName, receiver, args) {
    if (methodName === 'parse') {
      const raw = this._coerceGuestString(args[0], 'Uri.parse');
      let scheme = null;
      let host = null;
      let path = raw;
      const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)/.exec(raw);
      if (m) {
        scheme = m[1];
        host = m[2];
        path = m[3] || '/';
      } else {
        const colon = raw.indexOf(':');
        if (colon > 0) {
          scheme = raw.slice(0, colon);
          path = raw.slice(colon + 1);
        }
      }
      const slicedChars =
        (scheme ? scheme.length : 0) +
        (host ? host.length : 0) +
        (path !== raw && path ? path.length : 0);
      const nativeBytes = 128 + slicedChars * 2;
      this.vm.checkHeapBudget(128 + nativeBytes, 'Uri.parse');
      this.vm.chargeHeap(nativeBytes, 'Uri.parse');
      return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.URI, null, { raw, scheme, host, path });
    }
    this._requireInstanceReceiver(receiver, 'android.net.Uri');
    if (receiver.native && (typeof receiver.native !== 'object' || typeof receiver.native.raw !== 'string')) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a Uri`);
    }
    if (methodName === 'getScheme') return receiver.native?.scheme ?? null;
    if (methodName === 'getHost') return receiver.native?.host ?? null;
    if (methodName === 'getPath') return receiver.native?.path ?? null;
    if (methodName === 'toString') return receiver.native?.raw ?? '';
    return null;
  }

  _handleIntent(methodName, receiver, args) {
    if (methodName === 'createChooser') {
      return args[0];
    }
    const n = this._ensureIntentNative(receiver);
    switch (methodName) {
      case 'setAction':
        n.action = args[0] !== null && args[0] !== undefined ? this._coerceGuestString(args[0], 'Intent.setAction') : null;
        return receiver;
      case 'getAction': return n.action;
      case 'setData':
        n.dataUri = args[0] ? this._coerceGuestString(args[0], 'Intent.setData') : null;
        return receiver;
      case 'getData':
        return n.dataUri ? this._handleUri('parse', null, [n.dataUri]) : null;
      case 'getDataString': return n.dataUri;
      case 'setType':
        n.mimeType = args[0] !== null && args[0] !== undefined ? this._coerceGuestString(args[0], 'Intent.setType') : null;
        return receiver;
      case 'getType': return n.mimeType;
      case 'setFlags': n.flags = safeToInt(args[0]); return receiver;
      case 'addFlags': n.flags = (safeToInt(n.flags) | safeToInt(args[0])) | 0; return receiver;
      case 'getFlags': return safeToInt(n.flags);
      case 'setPackage':
        n.targetPackage = args[0] !== null && args[0] !== undefined ? this._coerceGuestString(args[0], 'Intent.setPackage') : null;
        return receiver;
      case 'getPackage': return n.targetPackage;
      case 'setClassName':
        n.targetPackage = this._coerceGuestString(args[0], 'Intent.setClassName');
        n.targetClass = this._coerceGuestString(args[1], 'Intent.setClassName');
        return receiver;
      case 'putExtra': {
        const k = this._coerceGuestString(args[0], 'Intent.putExtra');
        if (!Object.prototype.hasOwnProperty.call(n.extras, k)) {
          this.vm.chargeHeap(96, 'Intent.putExtra');
        }
        n.extras[k] = args[1];
        return receiver;
      }
      case 'hasExtra': {
        const k = toJsString(args[0]);
        return Object.prototype.hasOwnProperty.call(n.extras, k);
      }
      case 'removeExtra': {
        const k = toJsString(args[0]);
        if (Object.prototype.hasOwnProperty.call(n.extras, k)) delete n.extras[k];
        return;
      }
      case 'getStringExtra':
      case 'getCharSequenceExtra': {
        const k = toJsString(args[0]);
        return Object.prototype.hasOwnProperty.call(n.extras, k) && n.extras[k] !== null && n.extras[k] !== undefined
          ? this._coerceGuestString(n.extras[k], `Intent.${methodName}`)
          : null;
      }
      case 'getIntExtra': {
        const k = toJsString(args[0]);
        const def = safeToInt(args[1]);
        return Object.prototype.hasOwnProperty.call(n.extras, k) ? safeToInt(n.extras[k], def) : def;
      }
      case 'getLongExtra': {
        const k = toJsString(args[0]);
        const def = safeToLong(args[1], 0n);
        return Object.prototype.hasOwnProperty.call(n.extras, k) ? safeToLong(n.extras[k], def) : def;
      }
      case 'getFloatExtra':
      case 'getDoubleExtra': {
        const k = toJsString(args[0]);
        const def = safeToFloatOrDouble(args[1], 0);
        return Object.prototype.hasOwnProperty.call(n.extras, k) ? safeToFloatOrDouble(n.extras[k], def) : def;
      }
      case 'getBooleanExtra': {
        const k = toJsString(args[0]);
        return Object.prototype.hasOwnProperty.call(n.extras, k) ? Boolean(n.extras[k]) : Boolean(args[1]);
      }
      case 'getExtras': {
        const keyCount = Object.keys(n.extras).length;
        const nativeBytes = 256 + keyCount * 96;
        this.vm.checkHeapBudget(128 + nativeBytes, 'Intent.getExtras');
        this.vm.chargeHeap(nativeBytes, 'Intent.getExtras');
        const copy = Object.assign(Object.create(null), n.extras);
        return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.BUNDLE, null, { map: copy });
      }
      default: return receiver;
    }
  }

  _handleSharedPrefs(methodName, receiver, args) {
    this._requireInstanceReceiver(receiver, 'android.content.SharedPreferences');
    if (receiver.native && (typeof receiver.native !== 'object' || typeof receiver.native.prefName !== 'string')) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${capString(receiver.classType, 128)} is not a SharedPreferences`);
    }
    const prefName = receiver.native?.prefName ?? 'default';
    const sp = this.services?.configStore?.sharedPrefs;
    const isRoot = this.pcb?.uid === 0;

    const recordKeyVmEstimate = (key, vmBytes) => {
      let nsMap = this._spEstimatedKeyBytes.get(prefName);
      if (!nsMap) {
        if (this._spEstimatedKeyBytes.size >= MAX_SP_CACHE_NAMESPACES) return;
        nsMap = new Map();
        this._spEstimatedKeyBytes.set(prefName, nsMap);
      }
      if (nsMap.has(key) || nsMap.size < MAX_SP_CACHE_KEYS_PER_NS) {
        nsMap.set(key, vmBytes);
      }
    };

    const recordContainsCache = (key, present) => {
      let nsMap = this._spTickContainsCache.get(prefName);
      if (!nsMap) {
        if (this._spTickContainsCache.size >= MAX_SP_CACHE_NAMESPACES) return;
        nsMap = new Map();
        this._spTickContainsCache.set(prefName, nsMap);
      }
      if (nsMap.has(key) || nsMap.size < MAX_SP_CACHE_KEYS_PER_NS) {
        nsMap.set(key, present);
      }
    };

    const readValCached = (key, { retainValue = true } = {}) => {
      if (!sp) {
        const map = this._fallbackSharedPrefs.get(prefName);
        return map && map.has(key) ? map.get(key) : SHARED_PREFS_MISSING;
      }
      const tickNs = this._spTickKeyCache.get(prefName);
      if (tickNs && tickNs.has(key)) {
        return tickNs.get(key);
      }
      if (!isRoot && this._prefReadBytes >= MAX_PREF_READ_BYTES) {
        this._throwGuest(
          'Ljava/lang/SecurityException;',
          `SharedPreferences cumulative read quota exceeded (${this._prefReadBytes}/${MAX_PREF_READ_BYTES} bytes)`
        );
      }
      let rawVal;
      try {
        rawVal = sp.get(this.packageName, prefName, key, SHARED_PREFS_MISSING);
      } catch (err) {
        this._translateHostServiceError(err, 'SharedPreferences.get');
      }
      const { vmBytes, physicalBytes } = estimateSpValueSizes(rawVal);
      const rowPhysBytes = Math.max(16, key.length + physicalBytes);
      if (!isRoot) {
        this._prefReadBytes += rowPhysBytes;
      }
      recordKeyVmEstimate(key, vmBytes);
      recordContainsCache(key, rawVal !== SHARED_PREFS_MISSING);

      const remainingVm = this.vm.maxMemoryBytes - (this.vm.allocatedHeapBytes + this.vm.activeStackBytes);
      if (
        retainValue &&
        (vmBytes === 0 || vmBytes <= remainingVm) &&
        this._spTickKeyCacheBytes + rowPhysBytes <= MAX_SP_TICK_CACHE_BYTES
      ) {
        let nsMap = this._spTickKeyCache.get(prefName);
        if (!nsMap && this._spTickKeyCache.size < MAX_SP_CACHE_NAMESPACES) {
          nsMap = new Map();
          this._spTickKeyCache.set(prefName, nsMap);
        }
        if (nsMap && (nsMap.has(key) || nsMap.size < MAX_SP_CACHE_KEYS_PER_NS)) {
          nsMap.set(key, rawVal);
          this._spTickKeyCacheBytes += rowPhysBytes;
        }
      }
      return rawVal;
    };

    switch (methodName) {
      case 'getString': {
        const key = toJsString(args[0]);
        const knownBytes = this._spEstimatedKeyBytes.get(prefName)?.get(key);
        if (typeof knownBytes === 'number' && knownBytes > 0) {
          this.vm.checkHeapBudget(knownBytes, 'SharedPreferences.getString');
        }
        const v = readValCached(key, { retainValue: true });
        if (v === SHARED_PREFS_MISSING) {
          const defVal = args[1];
          if (defVal === null || defVal === undefined) return null;
          return this._coerceGuestString(defVal, 'SharedPreferences.getString');
        }
        if (v === null || v === undefined) return null;
        const str = String(v);
        if (str.length > 0) {
          this.vm.chargeHeap(str.length * 2, 'SharedPreferences.getString');
        }
        return str;
      }
      case 'getStringSet': {
        const key = toJsString(args[0]);
        const knownBytes = this._spEstimatedKeyBytes.get(prefName)?.get(key);
        if (typeof knownBytes === 'number' && knownBytes > 0) {
          this.vm.checkHeapBudget(128 + 256 + knownBytes, 'SharedPreferences.getStringSet');
        }
        const v = readValCached(key, { retainValue: true });
        if (v === SHARED_PREFS_MISSING) {
          return args[1] ?? null;
        }
        if (v === null || v === undefined) return null;
        const items = Array.isArray(v) ? v : v instanceof Set ? Array.from(v) : [String(v)];
        let totalBytes = 256;
        for (const item of items) {
          const s = String(item ?? '');
          totalBytes += s.length * 2 + 16;
        }
        this.vm.checkHeapBudget(128 + totalBytes, 'SharedPreferences.getStringSet');
        this.vm.chargeHeap(totalBytes, 'SharedPreferences.getStringSet');
        const set = new Set();
        for (const item of items) {
          set.add(String(item ?? ''));
        }
        return this.vm.createObject('Ljava/util/HashSet;', null, { set });
      }
      case 'getInt': {
        const def = safeToInt(args[1]);
        const v = readValCached(toJsString(args[0]), { retainValue: true });
        return v === SHARED_PREFS_MISSING ? def : safeToInt(v, def);
      }
      case 'getLong': {
        const def = safeToLong(args[1], 0n);
        const v = readValCached(toJsString(args[0]), { retainValue: true });
        return v === SHARED_PREFS_MISSING ? def : safeToLong(v, def);
      }
      case 'getFloat': {
        const def = safeToFloatOrDouble(args[1], 0);
        const v = readValCached(toJsString(args[0]), { retainValue: true });
        return v === SHARED_PREFS_MISSING ? def : safeToFloatOrDouble(v, def);
      }
      case 'getDouble': {
        const def = safeToFloatOrDouble(args[1], 0);
        const v = readValCached(toJsString(args[0]), { retainValue: true });
        return v === SHARED_PREFS_MISSING ? def : safeToFloatOrDouble(v, def);
      }
      case 'getBoolean': {
        const def = Boolean(args[1]);
        const v = readValCached(toJsString(args[0]), { retainValue: true });
        return v === SHARED_PREFS_MISSING ? def : Boolean(v);
      }
      case 'contains': {
        const key = toJsString(args[0]);
        if (!key || key.includes('\0')) return false;
        const cachedPresent = this._spTickContainsCache.get(prefName)?.get(key);
        if (typeof cachedPresent === 'boolean') return cachedPresent;
        const cachedNs = this._spTickKeyCache.get(prefName);
        if (cachedNs && cachedNs.has(key)) {
          return cachedNs.get(key) !== SHARED_PREFS_MISSING;
        }
        return readValCached(key, { retainValue: false }) !== SHARED_PREFS_MISSING;
      }
      case 'getAll': {
        this.vm.checkHeapBudget(128 + 256, 'SharedPreferences.getAll');
        const knownNsBytes = this._spEstimatedNsBytes.get(prefName);
        if (typeof knownNsBytes === 'number' && knownNsBytes > 0) {
          this.vm.checkHeapBudget(128 + knownNsBytes, 'SharedPreferences.getAll');
        }
        const cachedAll = this._spTickAllCache.get(prefName);
        if (cachedAll) {
          this.vm.checkHeapBudget(128 + cachedAll.totalVmBytes, 'SharedPreferences.getAll');
          this.vm.chargeHeap(cachedAll.totalVmBytes, 'SharedPreferences.getAll');
          return this.vm.createObject('Ljava/util/HashMap;', null, { map: new Map(cachedAll.entries) });
        }

        let all;
        if (sp) {
          if (!isRoot && this._prefReadBytes >= MAX_PREF_READ_BYTES) {
            this._throwGuest(
              'Ljava/lang/SecurityException;',
              `SharedPreferences cumulative read quota exceeded (${this._prefReadBytes}/${MAX_PREF_READ_BYTES} bytes)`
            );
          }
          try {
            all = sp.getAll(this.packageName, prefName);
          } catch (err) {
            this._translateHostServiceError(err, 'SharedPreferences.getAll');
          }
        } else {
          all = Object.fromEntries(this._fallbackSharedPrefs.get(prefName) ?? []);
        }

        const entries = Object.entries(all);
        let totalBytes = 256;
        let physicalBytes = 64;
        for (const [k, v] of entries) {
          let valBytes = 16;
          let valPhys = 16;
          if (typeof v === 'string') {
            valBytes = v.length * 2;
            valPhys = Math.max(16, v.length + 16);
          } else if (Array.isArray(v)) {
            valBytes = 32;
            valPhys = 32;
            for (const s of v) {
              const sLen = typeof s === 'string' ? s.length : 0;
              valBytes += typeof s === 'string' ? sLen * 2 + 16 : 16;
              valPhys += sLen + 16;
            }
          } else if (v instanceof Set) {
            valBytes = 32;
            valPhys = 32;
            for (const s of v) {
              const sLen = typeof s === 'string' ? s.length : 0;
              valBytes += typeof s === 'string' ? sLen * 2 + 16 : 16;
              valPhys += sLen + 16;
            }
          }
          totalBytes += k.length * 2 + valBytes + 32;
          physicalBytes += k.length + valPhys;
        }
        if (sp && !isRoot) {
          this._prefReadBytes += physicalBytes;
        }
        if (this._spEstimatedNsBytes.has(prefName) || this._spEstimatedNsBytes.size < MAX_SP_CACHE_NAMESPACES) {
          this._spEstimatedNsBytes.set(prefName, totalBytes);
        }
        this.vm.checkHeapBudget(128 + totalBytes, 'SharedPreferences.getAll');
        this.vm.chargeHeap(totalBytes, 'SharedPreferences.getAll');
        if (
          sp &&
          this._spTickAllCache.size < MAX_SP_CACHE_NAMESPACES &&
          this._spTickAllCacheBytes + physicalBytes <= MAX_SP_TICK_CACHE_BYTES
        ) {
          this._spTickAllCache.set(prefName, { entries, totalVmBytes: totalBytes, physicalBytes });
          this._spTickAllCacheBytes += physicalBytes;
        }
        return this.vm.createObject('Ljava/util/HashMap;', null, { map: new Map(entries) });
      }
      case 'edit':
        this.vm.checkHeapBudget(128 + 128, 'SharedPreferences.edit');
        this.vm.chargeHeap(128, 'SharedPreferences.edit');
        return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.SHARED_PREFS_EDITOR, null, {
          prefName,
          ops: [],
        });
      default:
        return null;
    }
  }

  _handleSharedPrefsEditor(methodName, receiver, args) {
    this._requireInstanceReceiver(receiver, 'android.content.SharedPreferences$Editor');
    const n = receiver.native;
    if (!n) return receiver;
    if (typeof n !== 'object' || !Array.isArray(n.ops)) {
      this._throwGuest(
        'Ljava/lang/ClassCastException;',
        `Receiver ${receiver.classType} is not a SharedPreferences.Editor`
      );
    }
    switch (methodName) {
      case 'putString': {
        this.vm.chargeHeap(128, 'SharedPreferences.Editor');
        const key = this._coerceGuestString(args[0], 'SharedPreferences.Editor');
        const value = this._coerceGuestString(args[1], 'SharedPreferences.Editor');
        n.ops.push({ op: 'put', key, type: 'string', value });
        return receiver;
      }
      case 'putStringSet': {
        const rawSet = args[1];
        const srcSet = rawSet?.native?.set instanceof Set ? rawSet.native.set : null;
        const srcArr = !srcSet && Array.isArray(rawSet?.native?.items) ? rawSet.native.items : null;
        const count = srcSet ? srcSet.size : srcArr ? srcArr.length : 0;
        const opAndArrBytes = count > 0 ? 256 + count * 32 : 128;
        this.vm.checkHeapBudget(opAndArrBytes, 'SharedPreferences.Editor');
        let estStrBytes = typeof args[0] === 'string' ? 0 : this._estimateGuestStringLength(args[0]) * 2;
        if (estStrBytes > 0) {
          this.vm.checkHeapBudget(opAndArrBytes + estStrBytes, 'SharedPreferences.Editor');
        }
        if (count > 0) {
          const usedBytes = (this.vm.allocatedHeapBytes ?? 0) + (this.vm.activeStackBytes ?? 0);
          const heapRemaining = Number.isFinite(this.vm.maxMemoryBytes)
            ? Math.max(0, this.vm.maxMemoryBytes - usedBytes)
            : Infinity;
          const singleCap = Number.isFinite(this.vm.maxSingleArrayBytes)
            ? this.vm.maxSingleArrayBytes
            : Infinity;
          const remaining = Math.min(heapRemaining, singleCap);
          const iter = srcSet ?? srcArr;
          let scanned = 0;
          for (const item of iter) {
            scanned += 1;
            if ((scanned & 63) === 0) {
              this.vm.chargeExternalWork(64);
            }
            if (typeof item !== 'string') {
              estStrBytes += Math.max(32, this._estimateGuestStringLength(item) * 2);
              if (opAndArrBytes + estStrBytes > remaining) {
                const rem = scanned & 63;
                if (rem > 0) {
                  this.vm.chargeExternalWork(rem);
                }
                this.vm.checkHeapBudget(opAndArrBytes + estStrBytes, 'SharedPreferences.Editor');
              }
            }
          }
          const rem = scanned & 63;
          if (rem > 0) {
            this.vm.chargeExternalWork(rem);
          }
        }
        if (estStrBytes > 0) {
          this.vm.checkHeapBudget(opAndArrBytes + estStrBytes, 'SharedPreferences.Editor');
        }
        this.vm.chargeHeap(opAndArrBytes, 'SharedPreferences.Editor');
        const key = this._coerceGuestString(args[0], 'SharedPreferences.Editor');
        if (rawSet === null || rawSet === undefined) {
          n.ops.push({ op: 'remove', key });
          return receiver;
        }
        if (count === 0) {
          n.ops.push({ op: 'put', key, type: 'stringSet', value: EMPTY_STR_ARR });
          return receiver;
        }
        if (count > 64) {
          this.vm.chargeExternalWork(count);
        }
        const copied = new Array(count);
        let idx = 0;
        if (srcSet) {
          for (const item of srcSet) {
            copied[idx++] = this._coerceGuestString(item, 'SharedPreferences.Editor');
          }
        } else {
          for (let i = 0; i < srcArr.length; i += 1) {
            copied[idx++] = this._coerceGuestString(srcArr[i], 'SharedPreferences.Editor');
          }
        }
        n.ops.push({ op: 'put', key, type: 'stringSet', value: copied });
        return receiver;
      }
      case 'putInt': {
        this.vm.chargeHeap(128, 'SharedPreferences.Editor');
        const key = this._coerceGuestString(args[0], 'SharedPreferences.Editor');
        n.ops.push({ op: 'put', key, type: 'int', value: safeToInt(args[1]) });
        return receiver;
      }
      case 'putLong': {
        this.vm.chargeHeap(128, 'SharedPreferences.Editor');
        const key = this._coerceGuestString(args[0], 'SharedPreferences.Editor');
        n.ops.push({ op: 'put', key, type: 'long', value: safeToLong(args[1], 0n) });
        return receiver;
      }
      case 'putFloat': {
        this.vm.chargeHeap(128, 'SharedPreferences.Editor');
        const key = this._coerceGuestString(args[0], 'SharedPreferences.Editor');
        n.ops.push({ op: 'put', key, type: 'float', value: toMathNumber(args[1] ?? 0) });
        return receiver;
      }
      case 'putBoolean': {
        this.vm.chargeHeap(128, 'SharedPreferences.Editor');
        const key = this._coerceGuestString(args[0], 'SharedPreferences.Editor');
        n.ops.push({ op: 'put', key, type: 'boolean', value: Boolean(args[1]) });
        return receiver;
      }
      case 'remove': {
        this.vm.chargeHeap(128, 'SharedPreferences.Editor');
        const key = this._coerceGuestString(args[0], 'SharedPreferences.Editor');
        n.ops.push({ op: 'remove', key });
        return receiver;
      }
      case 'clear':
        this.vm.chargeHeap(128, 'SharedPreferences.Editor');
        n.ops.push({ op: 'clear' });
        return receiver;
      case 'commit':
      case 'apply': {
        const isRoot = this.pcb?.uid === 0;
        const prefNameStr = String(n.prefName ?? '');
        const rawPrefNameBytes = utf8ByteLength(prefNameStr);
        if (!isRoot && rawPrefNameBytes > MAX_PREF_SINGLE_VALUE_BYTES) {
          n.ops = [];
          if (methodName === 'commit') return false;
          this._throwGuest(
            'Ljava/lang/SecurityException;',
            `SharedPreferences name size (${rawPrefNameBytes} bytes) exceeds sandbox quota (${MAX_PREF_SINGLE_VALUE_BYTES} bytes)`
          );
        }
        const prefNameUtf8Bytes = Math.max(
          rawPrefNameBytes,
          TEXT_ENCODER.encode(prefNameStr).byteLength
        );
        const pkgNameUtf8Bytes = TEXT_ENCODER.encode(this.packageName).byteLength;
        let batchWriteOps = 0;
        let batchWriteBytes = 0;
        for (const op of n.ops) {
          if (op.op === 'put') {
            const keyStr = String(op.key ?? '');
            const rawKeyBytes = utf8ByteLength(keyStr);
            if (!isRoot && prefNameUtf8Bytes + rawKeyBytes > MAX_PREF_SINGLE_VALUE_BYTES) {
              n.ops = [];
              if (methodName === 'commit') return false;
              this._throwGuest(
                'Ljava/lang/SecurityException;',
                `SharedPreferences entry size (${prefNameUtf8Bytes + rawKeyBytes} bytes) exceeds sandbox quota (${MAX_PREF_SINGLE_VALUE_BYTES} bytes)`
              );
            }
            const serializedKeyUtf8Bytes = TEXT_ENCODER.encode(JSON.stringify(keyStr)).byteLength;
            const keyBytes = Math.max(rawKeyBytes, serializedKeyUtf8Bytes);

            let valBytes = 16;
            if (op.type === 'string') {
              const valStr = String(op.value ?? '');
              const rawValBytes = utf8ByteLength(valStr);
              if (!isRoot && prefNameUtf8Bytes + keyBytes + rawValBytes > MAX_PREF_SINGLE_VALUE_BYTES) {
                n.ops = [];
                if (methodName === 'commit') return false;
                this._throwGuest(
                  'Ljava/lang/SecurityException;',
                  `SharedPreferences entry size (${prefNameUtf8Bytes + keyBytes + rawValBytes} bytes) exceeds sandbox quota (${MAX_PREF_SINGLE_VALUE_BYTES} bytes)`
                );
              }
              const serializedValUtf8Bytes = TEXT_ENCODER.encode(JSON.stringify(valStr)).byteLength;
              valBytes = Math.max(rawValBytes, serializedValUtf8Bytes);
            } else {
              const serializedVal =
                typeof op.value === 'bigint' ? JSON.stringify(op.value.toString()) : JSON.stringify(op.value ?? null);
              valBytes = Math.max(16, TEXT_ENCODER.encode(serializedVal ?? 'null').byteLength);
            }

            const singleEntryBytes = prefNameUtf8Bytes + keyBytes + valBytes;
            if (!isRoot && singleEntryBytes > MAX_PREF_SINGLE_VALUE_BYTES) {
              n.ops = [];
              if (methodName === 'commit') return false;
              this._throwGuest(
                'Ljava/lang/SecurityException;',
                `SharedPreferences entry size (${singleEntryBytes} bytes) exceeds sandbox quota (${MAX_PREF_SINGLE_VALUE_BYTES} bytes)`
              );
            }
            batchWriteOps += 1;
            // Charge SQLite row + PK index + scope index B-tree page footprint (prefName/pkg 4x, key 3x, JSON value 1x)
            batchWriteBytes += prefNameUtf8Bytes * 4 + keyBytes * 3 + valBytes + pkgNameUtf8Bytes * 4 + 128;
          }
        }
        if (
          !isRoot &&
          (this._prefWriteOps + batchWriteOps > MAX_PREF_KEYS ||
            this._prefWriteBytes + batchWriteBytes > MAX_PREF_WRITE_BYTES)
        ) {
          n.ops = [];
          if (methodName === 'commit') return false;
          this._throwGuest(
            'Ljava/lang/SecurityException;',
            `SharedPreferences cumulative write quota exceeded (ops=${this._prefWriteOps + batchWriteOps}/${MAX_PREF_KEYS}, bytes=${this._prefWriteBytes + batchWriteBytes}/${MAX_PREF_WRITE_BYTES})`
          );
        }

        const sp = this.services?.configStore?.sharedPrefs;
        if (sp) {
          try {
            sp.edit(this.packageName, n.prefName, n.ops, {
              uid: this.pcb?.uid,
              appId: this.packageName,
              pid: this.pcb?.pid,
            });
          } catch (err) {
            this._translateHostServiceError(err, 'SharedPreferences.Editor');
          }
        } else {
          let map = this._fallbackSharedPrefs.get(n.prefName);
          if (!map) {
            if (!isRoot && this._fallbackSharedPrefs.size >= MAX_FALLBACK_PREF_NAMES) {
              n.ops = [];
              if (methodName === 'commit') return false;
              this._throwGuest(
                'Ljava/lang/SecurityException;',
                `SharedPreferences namespace count exceeds sandbox limit (${MAX_FALLBACK_PREF_NAMES})`
              );
            }
            map = new Map();
            this._fallbackSharedPrefs.set(n.prefName, map);
          }
          for (const op of n.ops) {
            if (op.op === 'clear') {
              this._fallbackPrefTotalKeys = Math.max(0, this._fallbackPrefTotalKeys - map.size);
              map.clear();
            } else if (op.op === 'remove') {
              if (map.delete(op.key)) {
                this._fallbackPrefTotalKeys = Math.max(0, this._fallbackPrefTotalKeys - 1);
              }
            } else if (op.op === 'put') {
              if (!map.has(op.key)) {
                if (!isRoot && this._fallbackPrefTotalKeys >= MAX_PREF_KEYS) {
                  n.ops = [];
                  if (methodName === 'commit') return false;
                  this._throwGuest(
                    'Ljava/lang/SecurityException;',
                    `SharedPreferences total keys exceed sandbox limit (${MAX_PREF_KEYS})`
                  );
                }
                this._fallbackPrefTotalKeys += 1;
              }
              map.set(op.key, op.value);
            }
          }
        }
        this._prefWriteOps += batchWriteOps;
        this._prefWriteBytes += batchWriteBytes;
        this._invalidateSpCache(n.prefName);
        n.ops = [];
        return methodName === 'commit' ? true : undefined;
      }
      default:
        return receiver;
    }
  }

  _handleClipData(methodName, receiver, args) {
    if (methodName === 'newPlainText') {
      const label = this._coerceGuestString(args[0], 'ClipData.newPlainText');
      const text = this._coerceGuestString(args[1], 'ClipData.newPlainText');
      this.vm.checkHeapBudget(128 + 128, 'ClipData.newPlainText');
      this.vm.chargeHeap(128, 'ClipData.newPlainText');
      return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.CLIP_DATA, null, { label, text });
    }
    this._requireInstanceReceiver(receiver, 'android.content.ClipData');
    if (receiver.native && (typeof receiver.native !== 'object' || typeof receiver.native.text !== 'string')) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a ClipData`);
    }
    if (methodName === 'getItemAt') {
      const idx = safeToInt(args[0]);
      if (idx !== 0) {
        this._throwGuest('Ljava/lang/IndexOutOfBoundsException;', `ClipData.getItemAt(${idx}) out of bounds (count=1)`);
      }
      return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.CLIP_DATA_ITEM, null, {
        text: receiver.native?.text ?? '',
      });
    }
    if (methodName === 'getItemCount') return 1;
    return null;
  }

  _handleClipboardManager(methodName, args) {
    const cb = this.services?.clipboard;
    const isRoot = this.pcb?.uid === 0;
    if (methodName === 'setPrimaryClip') {
      const text =
        typeof args[0]?.native?.text === 'string'
          ? args[0].native.text
          : this._coerceGuestString(args[0], 'ClipboardManager.setPrimaryClip');
      if (!isRoot && text.length > MAX_CLIPBOARD_TEXT_CHARS) {
        this._throwGuest(
          'Ljava/lang/OutOfMemoryError;',
          `Clipboard text length (${text.length} chars) exceeds sandbox limit (${MAX_CLIPBOARD_TEXT_CHARS})`
        );
      }
      if (cb) {
        try {
          cb.set({ text, sourceAppId: this.packageName, sourcePlatform: 'android' });
        } catch (err) {
          this._translateHostServiceError(err, 'ClipboardManager.setPrimaryClip');
        }
      }
      this._invalidateClipboardCache();
      return;
    }
    if (methodName === 'setText') {
      const text = this._coerceGuestString(args[0], 'ClipboardManager.setText');
      if (!isRoot && text.length > MAX_CLIPBOARD_TEXT_CHARS) {
        this._throwGuest(
          'Ljava/lang/OutOfMemoryError;',
          `Clipboard text length (${text.length} chars) exceeds sandbox limit (${MAX_CLIPBOARD_TEXT_CHARS})`
        );
      }
      if (cb) {
        try {
          cb.set({ text, sourceAppId: this.packageName, sourcePlatform: 'android' });
        } catch (err) {
          this._translateHostServiceError(err, 'ClipboardManager.setText');
        }
      }
      this._invalidateClipboardCache();
      return;
    }
    const readClipboardText = (label) => {
      if (typeof this._clipboardEstimatedBytes === 'number' && this._clipboardEstimatedBytes > 0) {
        this.vm.checkHeapBudget(this._clipboardEstimatedBytes, label);
      }
      if (this._clipboardTickText !== CLIPBOARD_MISSING) {
        return this._clipboardTickText;
      }
      let text = null;
      if (cb) {
        if (!isRoot && this._clipboardReadBytes >= MAX_SERVICE_READ_BYTES) {
          this._throwGuest(
            'Ljava/lang/SecurityException;',
            `Clipboard cumulative read quota exceeded (${this._clipboardReadBytes}/${MAX_SERVICE_READ_BYTES} bytes)`
          );
        }
        try {
          text = cb.get('text/plain');
        } catch (err) {
          this._translateHostServiceError(err, label);
        }
      }
      const normalized = text === null || text === undefined ? null : String(text);
      const estBytes = normalized === null ? 0 : normalized.length * 2;
      if (cb && !isRoot) {
        this._clipboardReadBytes += Math.max(16, estBytes);
      }
      this._clipboardEstimatedBytes = estBytes;
      const remainingVm = this.vm.maxMemoryBytes - (this.vm.allocatedHeapBytes + this.vm.activeStackBytes);
      if (estBytes === 0 || (estBytes <= remainingVm && estBytes <= MAX_SP_TICK_CACHE_BYTES)) {
        this._clipboardTickText = normalized;
      }
      return normalized;
    };
    if (methodName === 'getPrimaryClip') {
      const str = readClipboardText('ClipboardManager.getPrimaryClip');
      if (str === null) return null;
      if (str.length > 0) {
        this.vm.chargeHeap(str.length * 2, 'ClipboardManager.getPrimaryClip');
      }
      return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.CLIP_DATA, null, {
        label: 'clipboard',
        text: str,
      });
    }
    if (methodName === 'getText') {
      const str = readClipboardText('ClipboardManager.getText');
      if (str === null) return null;
      if (str.length > 0) {
        this.vm.chargeHeap(str.length * 2, 'ClipboardManager.getText');
      }
      return str;
    }
    if (methodName === 'hasPrimaryClip') {
      if (!cb) return false;
      try {
        return cb.get('text/plain') !== null;
      } catch (err) {
        this._translateHostServiceError(err, 'ClipboardManager.hasPrimaryClip');
      }
    }
    return null;
  }

  _handleNotificationBuilder(methodName, receiver, args) {
    const n = this._ensureNotificationBuilderNative(receiver);
    switch (methodName) {
      case 'setContentTitle':
        n.title = this._coerceGuestString(args[0], 'Notification.Builder.setContentTitle');
        return receiver;
      case 'setContentText':
        n.body = this._coerceGuestString(args[0], 'Notification.Builder.setContentText');
        return receiver;
      case 'setPriority': {
        const p = safeToInt(args[0]);
        n.priority = p >= 2 ? 'urgent' : p === 1 ? 'high' : p < 0 ? 'low' : 'normal';
        return receiver;
      }
      case 'setSmallIcon': n.icon = args[0]; return receiver;
      case 'build':
        this.vm.checkHeapBudget(128 + 128, 'Notification.Builder.build');
        this.vm.chargeHeap(128, 'Notification.Builder.build');
        return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.NOTIFICATION, null, { ...n });
      default: return receiver;
    }
  }

  _handleNotificationManager(methodName, args) {
    const nc = this.services?.notifications;
    if (methodName === 'notify') {
      const id = safeToInt(args[0]);
      const notif = args[1]?.native ?? { title: this.appLabel, body: '' };
      if (nc) {
        let posted;
        try {
          const rawTitle = (typeof notif.title === 'string' && notif.title.trim()) || this.appLabel || this.packageName;
          posted = nc.post({
            appId: this.packageName,
            platform: 'android',
            title: capString(rawTitle, 256),
            body: capString(notif.body ?? '', MAX_NOTIF_TEXT_CHARS),
            priority: notif.priority ?? 'normal',
            category: 'notification',
            data: { androidNotificationId: id },
          });
        } catch (err) {
          this._translateHostServiceError(err, 'NotificationManager.notify');
        }
        if (posted?.id !== undefined) {
          if (!this._notificationIds.has(id) && this._notificationIds.size >= MAX_NOTIFICATION_IDS) {
            const oldestKey = this._notificationIds.keys().next().value;
            this._notificationIds.delete(oldestKey);
          }
          this._notificationIds.set(id, posted.id);
        }
      }
      return;
    }
    if (methodName === 'cancel') {
      const id = safeToInt(args[0]);
      const osNotifId = this._notificationIds.get(id);
      this._notificationIds.delete(id);
      if (osNotifId && nc?.dismiss) {
        try {
          nc.dismiss(osNotifId);
        } catch (err) {
          if (err?.code !== 'ENOENT') {
            this._recordInternalLog('W', 'NotificationManager', `Cancel ignored: ${err?.message ?? err}`);
          }
        }
      }
    }
  }

  _handleContentValues(methodName, receiver, args) {
    const map = this._ensureContentValuesNative(receiver).map;
    const k =
      args[0] !== undefined
        ? methodName === 'put'
          ? this._coerceGuestString(args[0], 'ContentValues.put')
          : toJsString(args[0])
        : '';
    const has = Object.prototype.hasOwnProperty.call(map, k);
    if (methodName === 'put') {
      if (!has) this.vm.chargeHeap(96, 'ContentValues.put');
      map[k] = args[1];
      return;
    }
    if (methodName === 'containsKey') return has;
    if (methodName === 'get' || methodName === 'getAsString') {
      if (!has) return null;
      const v = map[k];
      return v === undefined || v === null
        ? null
        : methodName === 'getAsString'
          ? this._coerceGuestString(v, 'ContentValues.getAsString')
          : v;
    }
    return null;
  }

  _handleContentResolver(methodName, receiver, args) {
    this._requireInstanceReceiver(receiver, 'android.content.ContentResolver');
    const uri = methodName === 'insert' ? this._coerceGuestString(args[0], 'ContentResolver.insert') : toJsString(args[0]);
    if (methodName === 'insert') {
      const srcMap = args[1]?.native?.map;
      const keyCount = srcMap ? Object.keys(srcMap).length : 0;
      const isNewUri = !this.contentStore.has(uri);
      const existingRows = this.contentStore.get(uri);
      const rowId = (existingRows ? existingRows.length : 0) + 1;
      const resultUriStr = `${uri}/${rowId}`;
      const uriCost = isNewUri ? 16 + uri.length * 2 : 0;
      this.vm.chargeHeap(
        uriCost + resultUriStr.length * 2 + 256 + keyCount * 96,
        'ContentResolver.insert'
      );
      let rows = existingRows;
      if (!rows) {
        rows = [];
        this.contentStore.set(uri, rows);
      }
      const row = srcMap ? Object.assign(Object.create(null), srcMap) : Object.create(null);
      row._id = rowId;
      rows.push(row);
      return this._handleUri('parse', null, [resultUriStr]);
    }
    if (methodName === 'query') {
      let rows = this.contentStore.get(uri) ?? [];
      let fromSystemConfig = false;
      if (uri.startsWith('content://com.omnios.settings') && this.services?.configStore?.system?.getAll) {
        const isRoot = this.pcb?.uid === 0;
        this.vm.checkHeapBudget(128 + 256, 'ContentResolver.query');
        if (typeof this._settingsEstimatedVmBytes === 'number' && this._settingsEstimatedVmBytes > 0) {
          this.vm.checkHeapBudget(128 + this._settingsEstimatedVmBytes, 'ContentResolver.query');
        }
        fromSystemConfig = true;
        if (this._settingsTickRows !== null) {
          rows = this._settingsTickRows;
        } else {
          if (!isRoot && this._settingsReadBytes >= MAX_SERVICE_READ_BYTES) {
            this._throwGuest(
              'Ljava/lang/SecurityException;',
              `Settings ContentResolver cumulative read quota exceeded (${this._settingsReadBytes}/${MAX_SERVICE_READ_BYTES} bytes)`
            );
          }
          let sys;
          try {
            sys = this.services.configStore.system.getAll();
          } catch (err) {
            this._translateHostServiceError(err, 'ContentResolver.query');
          }
          rows = Object.entries(sys).map(([key, value]) => Object.assign(Object.create(null), { key, value: String(value) }));
          let totalProps = 0;
          let stringBytes = 0;
          for (const r of rows) {
            const entries = Object.entries(r);
            totalProps += entries.length;
            for (const [rk, rv] of entries) {
              stringBytes += rk.length * 2 + (typeof rv === 'string' ? rv.length * 2 : 0);
            }
          }
          const totalVmBytes = 256 + rows.length * 128 + totalProps * 16 + stringBytes;
          const physicalBytes = Math.max(64, stringBytes);
          if (!isRoot) {
            this._settingsReadBytes += physicalBytes;
          }
          this._settingsEstimatedVmBytes = totalVmBytes;
          this.vm.checkHeapBudget(128 + totalVmBytes, 'ContentResolver.query');
          this.vm.chargeHeap(totalVmBytes, 'ContentResolver.query');
          if (physicalBytes <= MAX_SP_TICK_CACHE_BYTES) {
            this._settingsTickRows = rows;
          }
          return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.CURSOR, null, {
            rows: rows.map((r) => Object.assign(Object.create(null), r)),
            columns: rows.length > 0 ? Object.keys(rows[0]) : [],
            pos: -1,
          });
        }
      }
      let totalVmBytes = 256;
      if (rows.length > 0) {
        let totalProps = 0;
        let stringBytes = 0;
        for (const r of rows) {
          const entries = Object.entries(r);
          totalProps += entries.length;
          if (fromSystemConfig) {
            for (const [rk, rv] of entries) {
              stringBytes += rk.length * 2 + (typeof rv === 'string' ? rv.length * 2 : 0);
            }
          }
        }
        totalVmBytes += rows.length * 128 + totalProps * 16 + stringBytes;
      }
      this.vm.checkHeapBudget(128 + totalVmBytes, 'ContentResolver.query');
      this.vm.chargeHeap(totalVmBytes, 'ContentResolver.query');
      return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.CURSOR, null, {
        rows: rows.map((r) => Object.assign(Object.create(null), r)),
        columns: rows.length > 0 ? Object.keys(rows[0]) : [],
        pos: -1,
      });
    }
    if (methodName === 'update') {
      const rows = this.contentStore.get(uri) ?? [];
      const values = args[1]?.native?.map ?? Object.create(null);
      const keys = Object.keys(values);
      if (rows.length > 0 && keys.length > 0) {
        let newSlots = 0;
        for (const r of rows) {
          for (const k of keys) {
            if (!Object.prototype.hasOwnProperty.call(r, k)) newSlots += 1;
          }
        }
        if (newSlots > 0) {
          this.vm.chargeHeap(newSlots * 96, 'ContentResolver.update');
        }
        for (const r of rows) Object.assign(r, values);
      }
      return rows.length;
    }
    if (methodName === 'delete') {
      const rows = this.contentStore.get(uri);
      if (!rows) return 0;
      const count = rows.length;
      this.contentStore.delete(uri);
      return count;
    }
    return null;
  }

  _handleCursor(methodName, receiver, args) {
    this._requireInstanceReceiver(receiver, 'android.database.Cursor');
    const n = receiver.native;
    if (!n) return methodName === 'getCount' ? 0 : methodName === 'getColumnIndex' ? -1 : false;
    if (typeof n !== 'object' || !Array.isArray(n.rows) || !Array.isArray(n.columns)) {
      this._throwGuest('Ljava/lang/ClassCastException;', `Receiver ${receiver.classType} is not a Cursor`);
    }
    switch (methodName) {
      case 'getCount': return n.rows.length;
      case 'moveToFirst': n.pos = n.rows.length > 0 ? 0 : -1; return n.pos >= 0;
      case 'moveToNext':
        if (n.pos + 1 < n.rows.length) { n.pos += 1; return true; }
        return false;
      case 'getColumnIndex': return n.columns.indexOf(toJsString(args[0]));
      case 'getString': {
        const row = n.rows[n.pos];
        const colIdx = safeToInt(args[0]);
        const col = colIdx >= 0 && colIdx < n.columns.length ? n.columns[colIdx] : null;
        if (!row || !col || !Object.prototype.hasOwnProperty.call(row, col)) return null;
        const val = row[col];
        if (val === null || val === undefined) return '';
        if (typeof val === 'string') return val;
        return this._coerceGuestString(val, 'Cursor.getString');
      }
      case 'getInt': {
        const row = n.rows[n.pos];
        const colIdx = safeToInt(args[0]);
        const col = colIdx >= 0 && colIdx < n.columns.length ? n.columns[colIdx] : null;
        return row && col && Object.prototype.hasOwnProperty.call(row, col) ? safeToInt(row[col], 0) : 0;
      }
      case 'getLong': {
        const row = n.rows[n.pos];
        const colIdx = safeToInt(args[0]);
        const col = colIdx >= 0 && colIdx < n.columns.length ? n.columns[colIdx] : null;
        return row && col && Object.prototype.hasOwnProperty.call(row, col) ? safeToLong(row[col], 0n) : 0n;
      }
      case 'close': return;
      default: return null;
    }
  }

  _handleResources(methodName, args) {
    if (methodName === 'getString' || methodName === 'getText') {
      const resId = safeToInt(args[0]) >>> 0;
      const res = this.apk?.resources?.getString?.(resId) ?? '';
      if (res.length > 0) {
        this.vm.chargeHeap(res.length * 2, `Resources.${methodName}`);
      }
      return res;
    }
    if (methodName === 'getIdentifier') {
      const [name, defType] = args.map(toJsString);
      return this.apk?.resources?.getIdByName?.(`@${defType}/${name}`) ?? 0;
    }
    return null;
  }

  _handleView(methodName, receiver, args) {
    const n = this._ensureViewNative(receiver, receiver.classType);
    switch (methodName) {
      case 'setId': {
        const nextId = safeToInt(args[0]);
        const prevId = n.id;
        const prevIdName = n.idName;
        n.id = nextId;
        if (nextId !== prevId) {
          if (n.parent) {
            this._removeFromViewsById(receiver, prevId);
            this._addToViewsById(receiver, nextId);
            if (n.parent.native) {
              this._removeChildById(n.parent.native, prevId, receiver);
              this._addChildById(n.parent.native, nextId, receiver);
            }
          }
          if (prevId === 0 && nextId !== 0) {
            this._propagateZeroIdCount(receiver, -1);
          } else if (prevId !== 0 && nextId === 0) {
            this._propagateZeroIdCount(receiver, 1);
          }
          if (n.parent) {
            const treeRoot = this._getViewTreeRoot(n.parent);
            this._invalidateTreeCacheId(treeRoot, prevId);
            this._invalidateTreeCacheId(treeRoot, nextId);
          }
        }
        if (!n.idName && this.apk?.resources) {
          const resolved = this.apk.resources.resolve(n.id >>> 0);
          if (resolved?.keyName) n.idName = resolved.keyName;
        }
        if (n.id !== prevId || n.idName !== prevIdName) {
          this._syncCompositorSurface();
        }
        return;
      }
      case 'getId': return safeToInt(n.id);
      case 'setTag': n.tag = args[0]; return;
      case 'getTag': return n.tag;
      case 'setText': {
        let nextText;
        if (typeof args[0] === 'number') {
          const res = this.apk?.resources?.getString?.(safeToInt(args[0]) >>> 0) ?? String(args[0]);
          if (res.length > 0) {
            this.vm.chargeHeap(res.length * 2, 'View.setText');
          }
          nextText = res;
        } else {
          nextText = args[0] === null || args[0] === undefined ? '' : this._coerceGuestString(args[0], 'View.setText');
        }
        if (nextText !== n.text) {
          n.text = nextText;
          this._syncCompositorSurface();
        }
        return;
      }
      case 'getText': return n.text;
      case 'setHint': {
        const nextHint = this._coerceGuestString(args[0], 'View.setHint');
        if (nextHint !== n.hint) {
          n.hint = nextHint;
          this._syncCompositorSurface();
        }
        return;
      }
      case 'getHint': return n.hint;
      case 'setTextSize': {
        const nextSize = toMathNumber(args[0]);
        if (!Object.is(nextSize, n.textSize)) {
          n.textSize = nextSize;
          this._syncCompositorSurface();
        }
        return;
      }
      case 'setTextColor': {
        const nextColor = `#${(safeToInt(args[0]) >>> 0).toString(16).padStart(8, '0')}`;
        if (nextColor !== n.textColor) {
          n.textColor = nextColor;
          this._syncCompositorSurface();
        }
        return;
      }
      case 'setBackgroundColor': {
        const nextBg = `#${(safeToInt(args[0]) >>> 0).toString(16).padStart(8, '0')}`;
        if (nextBg !== n.backgroundColor) {
          n.backgroundColor = nextBg;
          this._syncCompositorSurface();
        }
        return;
      }
      case 'setVisibility': {
        const nextVis = safeToInt(args[0]);
        if (nextVis !== n.visibility) {
          n.visibility = nextVis;
          this._syncCompositorSurface();
        }
        return;
      }
      case 'getVisibility': return safeToInt(n.visibility);
      case 'setPadding': {
        const p0 = safeToInt(args[0]);
        const p1 = safeToInt(args[1]);
        const p2 = safeToInt(args[2]);
        const p3 = safeToInt(args[3]);
        const cur = n.padding;
        if (!Array.isArray(cur) || cur[0] !== p0 || cur[1] !== p1 || cur[2] !== p2 || cur[3] !== p3) {
          n.padding = [p0, p1, p2, p3];
          this._syncCompositorSurface();
        }
        return;
      }
      case 'setOrientation': {
        const nextOrient = safeToInt(args[0]) === 0 ? 'horizontal' : 'vertical';
        if (nextOrient !== n.orientation) {
          n.orientation = nextOrient;
          this._syncCompositorSurface();
        }
        return;
      }
      case 'addView': {
        const child = args[0];
        if (child === null || child === undefined) {
          this._throwGuest('Ljava/lang/IllegalArgumentException;', 'Cannot add a null child view to a ViewGroup');
        }
        if (
          typeof child !== 'object' ||
          !this.vm.isAssignableTo(this.vm.getObjectType(child), ANDROID_CLASS_DESCRIPTORS.VIEW)
        ) {
          this._throwGuest('Ljava/lang/IllegalArgumentException;', 'Child passed to ViewGroup.addView is not a View');
        }
        const childNative = this._ensureViewNative(child, child.classType);
        if (child === receiver) {
          this._throwGuest('Ljava/lang/IllegalStateException;', 'Cannot add a ViewGroup as a child of itself');
        }
        if (childNative.parent !== null && childNative.parent !== undefined) {
          this._throwGuest(
            'Ljava/lang/IllegalStateException;',
            'The specified child already has a parent. You must call removeView() on the child\'s parent first.'
          );
        }
        // Walk ancestor chain of receiver (O(depth <= MAX_VIEW_DEPTH)) to detect cycles & measure depth.
        // Because childNative.parent === null is enforced above and parent pointers are maintained exclusively
        // by ViewGroup methods, walking receiver -> parent is both necessary and sufficient for cycle detection.
        let receiverDepth = 0;
        let cur = receiver;
        while (cur) {
          if (cur === child) {
            if (receiverDepth > 4) {
              this._chargeFindViewWork(receiverDepth);
            }
            this._throwGuest(
              'Ljava/lang/IllegalStateException;',
              'Cannot add an ancestor view as a child (cyclic View hierarchy)'
            );
          }
          const parent = cur.native?.parent;
          if (!parent) break;
          receiverDepth += 1;
          if (receiverDepth > MAX_VIEW_DEPTH) {
            this._chargeFindViewWork(receiverDepth);
            this._throwGuest(
              'Ljava/lang/IllegalStateException;',
              `View hierarchy exceeds maximum depth of ${MAX_VIEW_DEPTH}`
            );
          }
          cur = parent;
        }
        if (receiverDepth > 4) {
          this._chargeFindViewWork(receiverDepth);
        }
        const treeRoot = cur;
        const childHeight = typeof childNative.subtreeHeight === 'number' ? childNative.subtreeHeight : 0;
        if (receiverDepth + 1 + childHeight > MAX_VIEW_DEPTH) {
          this._throwGuest(
            'Ljava/lang/IllegalStateException;',
            `View hierarchy exceeds maximum depth of ${MAX_VIEW_DEPTH}`
          );
        }
        const wasReceiverLeaf = n.children.length === 0;
        const isChildLeaf = childNative.children.length === 0;
        const childId = safeToInt(childNative.id);
        const containerInitBytes =
          (n.childHeightCounts === null ? 256 : 0) +
          (childId !== 0 && n.childrenById === null ? 256 : 0) +
          (childNative.subtreeZeroIdCount > 0 && n.zeroIdChildren === null ? 256 : 0);
        this.vm.chargeHeap(32 + containerInitBytes, 'ViewGroup.addView');
        const childSize = typeof childNative.subtreeSize === 'number' ? childNative.subtreeSize : 1;
        const childNl =
          typeof childNative.subtreeNonLeafCount === 'number'
            ? childNative.subtreeNonLeafCount
            : isChildLeaf
              ? 0
              : 1;
        this._dropTreeCache(child);
        childNative.parent = receiver;
        childNative._attachSeq = this._nextAttachSeq++;
        n.children.push(child);
        if (childId !== 0) {
          this._addToViewsById(child, childId);
          this._addChildById(n, childId, child);
        }
        if (!isChildLeaf) {
          this._addNonLeafChild(n, child);
        }
        if (wasReceiverLeaf && n.parent?.native) {
          this._addNonLeafChild(n.parent.native, receiver);
        }
        this._propagateViewHeightChange(receiver, -1, childHeight);
        this._propagateSubtreeMetrics(receiver, childSize, childNl + (wasReceiverLeaf ? 1 : 0));
        if (childNative.subtreeZeroIdCount > 0) {
          this._addZeroIdChild(n, child);
          this._propagateZeroIdCount(receiver, childNative.subtreeZeroIdCount);
        }
        if (isChildLeaf) {
          this._invalidateTreeCacheId(treeRoot, childId);
        } else {
          this._bumpTreeVersion(treeRoot);
        }
        this._syncCompositorSurface();
        return;
      }
      case 'removeView': {
        const child = args[0];
        if (!child || typeof child !== 'object' || child.native?.parent !== receiver) {
          return;
        }
        const idx = n.children.lastIndexOf(child);
        if (idx !== -1) {
          const work = n.children.length - idx;
          if (work > 64) {
            this._chargeFindViewWork(work);
          }
          if (idx === n.children.length - 1) n.children.pop();
          else n.children.splice(idx, 1);
          const childNative = child?.native;
          const childHeight = typeof childNative?.subtreeHeight === 'number' ? childNative.subtreeHeight : 0;
          const childZeros = typeof childNative?.subtreeZeroIdCount === 'number' ? childNative.subtreeZeroIdCount : 0;
          const isChildLeaf = !childNative || !Array.isArray(childNative.children) || childNative.children.length === 0;
          const childId = childNative ? safeToInt(childNative.id) : 0;
          const childSize = typeof childNative?.subtreeSize === 'number' ? childNative.subtreeSize : 1;
          const childNl =
            typeof childNative?.subtreeNonLeafCount === 'number'
              ? childNative.subtreeNonLeafCount
              : isChildLeaf
                ? 0
                : 1;
          const becameReceiverLeaf = n.children.length === 0;
          if (childId !== 0) {
            this._removeFromViewsById(child, childId);
            this._removeChildById(n, childId, child);
          }
          if (!isChildLeaf) {
            this._removeNonLeafChild(n, child);
          }
          if (becameReceiverLeaf && n.parent?.native) {
            this._removeNonLeafChild(n.parent.native, receiver);
          }
          if (childZeros > 0) {
            this._removeZeroIdChild(n, child);
          }
          if (childNative && childNative.parent === receiver) {
            childNative.parent = null;
            childNative._attachSeq = 0;
            childNative._treeVersion = (childNative._treeVersion | 0) + 1;
          }
          this._propagateViewHeightChange(receiver, childHeight, -1);
          this._propagateSubtreeMetrics(receiver, -childSize, -(childNl + (becameReceiverLeaf ? 1 : 0)));
          if (childZeros > 0) {
            this._propagateZeroIdCount(receiver, -childZeros);
          }
          const treeRoot = this._getViewTreeRoot(receiver);
          if (isChildLeaf) {
            this._invalidateTreeCacheId(treeRoot, childId);
          } else {
            this._bumpTreeVersion(treeRoot);
          }
          this._syncCompositorSurface();
        }
        return;
      }
      case 'removeViewAt': {
        const idx = safeToInt(args[0]);
        if (idx < 0 || idx >= n.children.length) {
          this._throwGuest(
            'Ljava/lang/IndexOutOfBoundsException;',
            `ViewGroup.removeViewAt(${idx}) out of bounds (count=${n.children.length})`
          );
        }
        const shiftWork = n.children.length - 1 - idx;
        if (shiftWork > 64) {
          this._chargeFindViewWork(shiftWork);
        }
        const removed = idx === n.children.length - 1 ? n.children.pop() : n.children.splice(idx, 1)[0];
        const removedNative = removed?.native;
        const removedHeight = typeof removedNative?.subtreeHeight === 'number' ? removedNative.subtreeHeight : 0;
        const removedZeros = typeof removedNative?.subtreeZeroIdCount === 'number' ? removedNative.subtreeZeroIdCount : 0;
        const isRemovedLeaf =
          !removedNative || !Array.isArray(removedNative.children) || removedNative.children.length === 0;
        const removedId = removedNative ? safeToInt(removedNative.id) : 0;
        const removedSize = typeof removedNative?.subtreeSize === 'number' ? removedNative.subtreeSize : 1;
        const removedNl =
          typeof removedNative?.subtreeNonLeafCount === 'number'
            ? removedNative.subtreeNonLeafCount
            : isRemovedLeaf
              ? 0
              : 1;
        const becameReceiverLeaf = n.children.length === 0;
        if (removedId !== 0) {
          this._removeFromViewsById(removed, removedId);
          this._removeChildById(n, removedId, removed);
        }
        if (!isRemovedLeaf) {
          this._removeNonLeafChild(n, removed);
        }
        if (becameReceiverLeaf && n.parent?.native) {
          this._removeNonLeafChild(n.parent.native, receiver);
        }
        if (removedZeros > 0) {
          this._removeZeroIdChild(n, removed);
        }
        if (removedNative && removedNative.parent === receiver) {
          removedNative.parent = null;
          removedNative._attachSeq = 0;
          removedNative._treeVersion = (removedNative._treeVersion | 0) + 1;
        }
        this._propagateViewHeightChange(receiver, removedHeight, -1);
        this._propagateSubtreeMetrics(receiver, -removedSize, -(removedNl + (becameReceiverLeaf ? 1 : 0)));
        if (removedZeros > 0) {
          this._propagateZeroIdCount(receiver, -removedZeros);
        }
        const treeRoot = this._getViewTreeRoot(receiver);
        if (isRemovedLeaf) {
          this._invalidateTreeCacheId(treeRoot, removedId);
        } else {
          this._bumpTreeVersion(treeRoot);
        }
        this._syncCompositorSurface();
        return;
      }
      case 'removeAllViews':
        if (n.children.length > 0) {
          if (n.children.length > 64) {
            this._chargeFindViewWork(n.children.length);
          }
          const oldH = typeof n.subtreeHeight === 'number' ? n.subtreeHeight : 0;
          const selfZero = safeToInt(n.id) === 0 ? 1 : 0;
          const prevZeros = typeof n.subtreeZeroIdCount === 'number' ? n.subtreeZeroIdCount : selfZero;
          const removedZeros = Math.max(0, prevZeros - selfZero);
          const removedSize = Math.max(0, (typeof n.subtreeSize === 'number' ? n.subtreeSize : 1) - 1);
          const removedNl = typeof n.subtreeNonLeafCount === 'number' ? n.subtreeNonLeafCount : 1;
          for (const c of n.children) {
            if (c?.native && c.native.parent === receiver) {
              const cid = safeToInt(c.native.id);
              if (cid !== 0) {
                this._removeFromViewsById(c, cid);
              }
              c.native.parent = null;
              c.native._attachSeq = 0;
              c.native._treeVersion = (c.native._treeVersion | 0) + 1;
            }
          }
          n.children = [];
          n.childHeightCounts = null;
          n.subtreeHeight = 0;
          n.subtreeZeroIdCount = selfZero;
          n.subtreeSize = 1;
          n.subtreeNonLeafCount = 0;
          n.zeroIdChildren = null;
          n._maxZeroIdSeq = 0;
          n._zeroIdHeap = null;
          n.childrenById = null;
          n.nonLeafChildren = null;
          n._maxNonLeafSeq = 0;
          n._nonLeafOrderDirty = false;
          if (n.parent?.native) {
            this._removeNonLeafChild(n.parent.native, receiver);
            if (prevZeros > 0 && selfZero === 0) {
              this._removeZeroIdChild(n.parent.native, receiver);
            }
          }
          if (oldH !== 0 && n.parent) {
            this._propagateViewHeightChange(n.parent, oldH, 0);
          }
          if ((removedSize > 0 || removedNl > 0) && n.parent) {
            this._propagateSubtreeMetrics(n.parent, -removedSize, -removedNl);
          }
          if (removedZeros > 0 && n.parent) {
            this._propagateZeroIdCount(n.parent, -removedZeros);
          }
          this._bumpTreeVersion(this._getViewTreeRoot(receiver));
          this._syncCompositorSurface();
        }
        return;
      case 'getParent': return n.parent ?? null;
      case 'getChildCount': return n.children.length;
      case 'getChildAt': {
        const idx = safeToInt(args[0]);
        return idx >= 0 && idx < n.children.length ? n.children[idx] : null;
      }
      case 'setOnClickListener': {
        const nextListener = args[0] ?? null;
        if (nextListener !== n.onClickListener) {
          n.onClickListener = nextListener;
          this._syncCompositorSurface();
        }
        return;
      }
      case 'performClick':
        if (n.onClickListener && typeof n.onClickListener === 'object' && n.onClickListener.__dalvikType === 'instance') {
          const ok = this._enqueueCallback({
            classType: n.onClickListener.classType,
            signature: 'onClick(Landroid/view/View;)V',
            args: [receiver],
            receiver: n.onClickListener,
          });
          if (ok === false) {
            this._throwGuest('Ljava/lang/OutOfMemoryError;', 'Pending UI callback queue limit exceeded');
          }
          return true;
        }
        return false;
      case 'findViewById':
        return this._findViewById(receiver, safeToInt(args[0]));
      default:
        return null;
    }
  }

  _handleActivityOrContext(methodName, receiver, args) {
    switch (methodName) {
      // Base lifecycle super.* no-ops
      case 'onCreate':
      case 'onStart':
      case 'onResume':
      case 'onPause':
      case 'onStop':
      case 'onRestart':
      case 'onDestroy':
      case 'onNewIntent':
        return;

      case 'setContentView': {
        const arg = args[0];
        if (typeof arg === 'number' || typeof arg === 'bigint') {
          this.rootView = this._inflateLayoutById(safeToInt(arg));
        } else if (arg === null || arg === undefined) {
          this.rootView = null;
        } else {
          if (
            typeof arg !== 'object' ||
            arg.__dalvikType !== 'instance' ||
            !this.vm.isAssignableTo(this.vm.getObjectType(arg), ANDROID_CLASS_DESCRIPTORS.VIEW)
          ) {
            this._throwGuest(
              'Ljava/lang/ClassCastException;',
              `setContentView requires an android.view.View, got ${this.vm.getObjectType(arg) ?? typeof arg}`
            );
          }
          this._ensureViewNative(arg, arg.classType);
          this.rootView = arg;
        }
        this._syncCompositorSurface();
        return;
      }

      case 'findViewById':
        return this._findViewById(this.rootView, safeToInt(args[0]));

      case 'setTitle': {
        const nextTitle = this._coerceGuestString(args[0], 'Activity.setTitle');
        if (nextTitle !== this.windowTitle) {
          this.windowTitle = nextTitle;
          this._syncCompositorSurface();
        }
        return;
      }

      case 'getTitle':
        return this.windowTitle;

      case 'getIntent':
        return receiver?.native?.intent ?? this.launchIntent;

      case 'setIntent':
        if (receiver?.native) receiver.native.intent = args[0];
        this.launchIntent = args[0];
        return;

      case 'getPackageName':
        return this.packageName;

      case 'getFilesDir':
        return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.FILE, null, {
          path: `/data/data/${this.packageName}/files`,
        });

      case 'getCacheDir':
        return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.FILE, null, {
          path: `/data/data/${this.packageName}/cache`,
        });

      case 'openFileOutput': {
        const rawName = toJsString(args[0]);
        const filename = sanitizeFilenameSegment(rawName);
        if (!filename) {
          this._throwGuest('Ljava/lang/IllegalArgumentException;', `Invalid file name: ${capString(rawName, 256)}`);
        }
        const mode = safeToInt(args[1]);
        const append = (mode & 32768) !== 0;
        const fullPath = `/data/data/${this.packageName}/files/${filename}`;
        const fos = this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.FILE_OUTPUT_STREAM);
        this._handleConstructor(
          ANDROID_CLASS_DESCRIPTORS.FILE_OUTPUT_STREAM,
          ANDROID_CLASS_DESCRIPTORS.FILE_OUTPUT_STREAM,
          '(Ljava/lang/String;Z)V',
          fos,
          [fullPath, append]
        );
        return fos;
      }

      case 'openFileInput': {
        const rawName = toJsString(args[0]);
        const filename = sanitizeFilenameSegment(rawName);
        if (!filename) {
          this._throwGuest('Ljava/lang/IllegalArgumentException;', `Invalid file name: ${capString(rawName, 256)}`);
        }
        const fullPath = `/data/data/${this.packageName}/files/${filename}`;
        const fis = this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.FILE_INPUT_STREAM);
        this._handleConstructor(
          ANDROID_CLASS_DESCRIPTORS.FILE_INPUT_STREAM,
          ANDROID_CLASS_DESCRIPTORS.FILE_INPUT_STREAM,
          '(Ljava/lang/String;)V',
          fis,
          [fullPath]
        );
        return fis;
      }

      case 'getSharedPreferences': {
        const prefName = this._coerceGuestString(args[0], 'Context.getSharedPreferences');
        return this.vm.createObject(ANDROID_CLASS_DESCRIPTORS.SHARED_PREFS, null, { prefName });
      }

      case 'getSystemService': {
        const svcName = toJsString(args[0]);
        if (svcName === 'clipboard') return this._clipboardManager;
        if (svcName === 'notification') return this._notificationManager;
        return null;
      }

      case 'getContentResolver':
        return this._contentResolver;

      case 'getResources':
        return this._resourcesObj;

      case 'getString': {
        const resId = safeToInt(args[0]) >>> 0;
        const res = this.apk?.resources?.getString?.(resId) ?? '';
        if (res.length > 0) {
          this.vm.chargeHeap(res.length * 2, 'Context.getString');
        }
        return res;
      }

      case 'checkSelfPermission': {
        const nativePerm = toJsString(args[0]);
        const decision = this._checkPermissionSync(null, nativePerm, { checkOnly: true });
        return decision.granted ? 0 : -1;
      }

      case 'runOnUiThread': {
        const runnable = args[0];
        if (runnable !== null && runnable !== undefined) {
          if (typeof runnable !== 'object' || runnable.__dalvikType !== 'instance') {
            this._throwGuest(
              'Ljava/lang/ClassCastException;',
              `runOnUiThread requires a Runnable instance, got ${this.vm.getObjectType(runnable) ?? typeof runnable}`
            );
          }
          const ok = this._enqueueCallback({
            classType: runnable.classType,
            signature: 'run()V',
            args: [],
            receiver: runnable,
          });
          if (ok === false) {
            this._throwGuest('Ljava/lang/OutOfMemoryError;', 'Pending UI callback queue limit exceeded');
          }
        }
        return;
      }

      case 'startActivity': {
        const intentObj = args[0];
        if (intentObj === null || intentObj === undefined) {
          this._throwGuest('Ljava/lang/NullPointerException;', 'startActivity(null)');
        }
        if (
          typeof intentObj !== 'object' ||
          intentObj.__dalvikType !== 'instance' ||
          !this.vm.isAssignableTo(this.vm.getObjectType(intentObj), ANDROID_CLASS_DESCRIPTORS.INTENT)
        ) {
          this._throwGuest(
            'Ljava/lang/ClassCastException;',
            `startActivity requires an android.content.Intent, got ${this.vm.getObjectType(intentObj) ?? typeof intentObj}`
          );
        }
        if (!intentObj.native || typeof intentObj.native !== 'object') {
          this._throwGuest('Ljava/lang/NullPointerException;', 'startActivity Intent not initialized');
        }
        const n = intentObj.native;
        const extraKeys = Object.keys(n.extras);
        if (extraKeys.length > 0) {
          this.vm.checkHeapBudget(extraKeys.length * 16, 'startActivity');
        }
        const dispatchPayload = {
          action: n.action,
          uri: n.dataUri,
          mimeType: n.mimeType,
          extras: { ...n.extras },
          sourcePid: this.pcb?.pid ?? null,
          preferredAppId: n.targetPackage && n.targetPackage !== this.packageName ? n.targetPackage : null,
        };
        const storedExtras = Object.create(null);
        const storedKeyLimit = Math.min(extraKeys.length, MAX_DISPATCHED_INTENT_SINGLE_KEYS);
        for (let k = 0; k < storedKeyLimit; k++) {
          const key = extraKeys[k];
          const val = n.extras[key];
          storedExtras[capString(key, 256)] = typeof val === 'string' ? capString(val, 4096) : val;
        }
        const storedKeyCount = Object.keys(storedExtras).length;
        const storedRecord = {
          action: n.action !== null ? capString(n.action, 4096) : null,
          uri: n.dataUri !== null ? capString(n.dataUri, 4096) : null,
          mimeType: n.mimeType !== null ? capString(n.mimeType, 4096) : null,
          extras: storedExtras,
          sourcePid: dispatchPayload.sourcePid,
          preferredAppId: dispatchPayload.preferredAppId,
          ts: new Date().toISOString(),
        };
        if (this.dispatchedIntents.length >= MAX_BRIDGE_DISPATCHED_INTENTS) {
          const dropCount = Math.max(1, MAX_BRIDGE_DISPATCHED_INTENTS >> 2);
          const dropped = this.dispatchedIntents.splice(0, dropCount);
          for (const item of dropped) {
            this._dispatchedIntentExtraKeys = Math.max(
              0,
              this._dispatchedIntentExtraKeys - Object.keys(item.extras ?? {}).length
            );
          }
        }
        while (
          this.dispatchedIntents.length > 0 &&
          this._dispatchedIntentExtraKeys + storedKeyCount > MAX_BRIDGE_DISPATCHED_INTENT_KEYS
        ) {
          const oldest = this.dispatchedIntents.shift();
          this._dispatchedIntentExtraKeys = Math.max(
            0,
            this._dispatchedIntentExtraKeys - Object.keys(oldest.extras ?? {}).length
          );
        }
        this.dispatchedIntents.push(storedRecord);
        this._dispatchedIntentExtraKeys += storedKeyCount;

        const router = this.services?.intentRouter;
        if (router && typeof router.dispatch === 'function') {
          let res;
          try {
            res = router.dispatch(dispatchPayload);
          } catch (err) {
            this._translateHostServiceError(err, 'IntentRouter.dispatch');
          }
          if (res && typeof res.then === 'function') {
            // Landmine #3: never propagate Promise out of synchronous step()!
            res.catch((err) => {
              this._recordInternalLog('W', 'IntentRouter', `Async intent launch error: ${err?.message ?? err}`);
            });
            return;
          }
          if (res?.status === 'NO_HANDLER') {
            this._throwGuest(
              'Landroid/content/ActivityNotFoundException;',
              `No Activity found to handle Intent { act=${capString(n.action, 128)} dat=${capString(n.dataUri, 128)} typ=${capString(n.mimeType, 128)} }`
            );
          }
        }
        return;
      }

      case 'startService': {
        const intentObj = args[0];
        const targetClass = intentObj?.native?.targetClass;
        if (targetClass) {
          const desc = classNameToDescriptor(targetClass);
          if (this.vm.classesByName.has(desc)) {
            let svcObj = this.runningServices.get(desc);
            if (!svcObj) {
              svcObj = this.vm.createObject(desc, null, { title: targetClass });
              this.runningServices.set(desc, svcObj);
              if (this.vm.findMethod(desc, '<init>()V', { includeSuper: false })?.code) {
                const okInit = this._enqueueCallback({ classType: desc, signature: '<init>()V', args: [], receiver: svcObj });
                if (okInit === false) {
                  this._throwGuest('Ljava/lang/OutOfMemoryError;', 'Pending Service callback queue limit exceeded');
                }
              }
              const onCreate = this.vm.findMethod(desc, 'onCreate()V', { includeSuper: true });
              if (onCreate?.code) {
                const okCreate = this._enqueueCallback({ classType: desc, signature: 'onCreate()V', args: [], receiver: svcObj });
                if (okCreate === false) {
                  this._throwGuest('Ljava/lang/OutOfMemoryError;', 'Pending Service callback queue limit exceeded');
                }
              }
            }
            const onStart = this.vm.findMethod(desc, 'onStartCommand(Landroid/content/Intent;II)I', {
              includeSuper: true,
            });
            if (onStart?.code) {
              const okStart = this._enqueueCallback({
                classType: desc,
                signature: 'onStartCommand(Landroid/content/Intent;II)I',
                args: [intentObj, 0, 1],
                receiver: svcObj,
              });
              if (okStart === false) {
                this._throwGuest('Ljava/lang/OutOfMemoryError;', 'Pending Service callback queue limit exceeded');
              }
            }
          }
        }
        return null;
      }

      case 'stopService': {
        const intentObj = args[0];
        const targetClass = intentObj?.native?.targetClass;
        if (targetClass) {
          const desc = classNameToDescriptor(targetClass);
          const svcObj = this.runningServices.get(desc);
          if (svcObj) {
            this.runningServices.delete(desc);
            const onDestroy = this.vm.findMethod(desc, 'onDestroy()V', { includeSuper: true });
            if (onDestroy?.code) {
              const okDestroy = this._enqueueCallback({ classType: desc, signature: 'onDestroy()V', args: [], receiver: svcObj });
              if (okDestroy === false) {
                this._throwGuest('Ljava/lang/OutOfMemoryError;', 'Pending Service callback queue limit exceeded');
              }
            }
            return true;
          }
        }
        return false;
      }

      case 'stopSelf': {
        if (receiver) {
          this.runningServices.delete(receiver.classType);
          const onDestroy = this.vm.findMethod(receiver.classType, 'onDestroy()V', { includeSuper: true });
          if (onDestroy?.code) {
            const okDestroy = this._enqueueCallback({
              classType: receiver.classType,
              signature: 'onDestroy()V',
              args: [],
              receiver,
            });
            if (okDestroy === false) {
              this._throwGuest('Ljava/lang/OutOfMemoryError;', 'Pending Service callback queue limit exceeded');
            }
          }
        }
        return;
      }

      case 'finish':
        this._finishActivity();
        return;

      default:
        return null;
    }
  }
}

export function createAndroidFrameworkBridge(opts) {
  return new AndroidFrameworkBridge(opts);
}
